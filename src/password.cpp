#include "fcrypt.hpp"

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <limits>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <fcntl.h>
#include <io.h>
#else
#include <termios.h>
#include <unistd.h>
#endif

namespace fcrypt {
namespace {

bool stdin_is_console() {
#ifdef _WIN32
    DWORD mode = 0;
    return GetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), &mode) != 0;
#else
    return ::isatty(STDIN_FILENO) != 0;
#endif
}

SecureBuffer read_line_from_stdin() {
    SecureBuffer result;
    result.reserve(MAX_PASSWORD_BYTES + 1);

    int ch = 0;
    bool terminated = false;
    while ((ch = std::cin.get()) != std::char_traits<char>::eof()) {
        if (ch == '\n') {
            terminated = true;
            break;
        }
        if (ch == '\r') {
            continue;
        }
        if (result.size() >= MAX_PASSWORD_BYTES) {
            throw Error("Пароль слишком длинный (не более " +
                        std::to_string(MAX_PASSWORD_BYTES) + " байт).");
        }
        result.push_back(static_cast<unsigned char>(ch));
    }
    if (std::cin.bad()) {
        throw Error("Ошибка чтения пароля.");
    }
    if (!terminated && result.empty()) {
        throw Error("Пароль не введён.");
    }
    if (result.empty()) {
        throw Error("Пароль не может быть пустым.");
    }
    return result;
}

#ifdef _WIN32
HANDLE g_saved_console = INVALID_HANDLE_VALUE;
DWORD g_saved_input_mode = 0;

BOOL WINAPI restore_console_on_exit(DWORD event) {
    (void)event;
    if (g_saved_console != INVALID_HANDLE_VALUE) {
        SetConsoleMode(g_saved_console, g_saved_input_mode);
        g_saved_console = INVALID_HANDLE_VALUE;
    }
    return FALSE; // Continue with the default handler.
}

class ConsoleEchoGuard {
public:
    ConsoleEchoGuard() = default;
    ConsoleEchoGuard(const ConsoleEchoGuard&) = delete;
    ConsoleEchoGuard& operator=(const ConsoleEchoGuard&) = delete;

    ~ConsoleEchoGuard() { restore(); }

    void disable_echo() {
        handle_ = GetStdHandle(STD_INPUT_HANDLE);
        if (handle_ == INVALID_HANDLE_VALUE ||
            !GetConsoleMode(handle_, &original_mode_)) {
            throw Error("Не удалось получить режим консоли.");
        }
        if (!SetConsoleMode(handle_,
                            original_mode_ &
                                ~static_cast<DWORD>(ENABLE_ECHO_INPUT))) {
            throw Error("Не удалось отключить отображение пароля.");
        }
        active_ = true;
        g_saved_console = handle_;
        g_saved_input_mode = original_mode_;
        SetConsoleCtrlHandler(restore_console_on_exit, TRUE);
    }

    void restore() noexcept {
        if (!active_) {
            return;
        }
        SetConsoleCtrlHandler(restore_console_on_exit, FALSE);
        if (handle_ != INVALID_HANDLE_VALUE) {
            SetConsoleMode(handle_, original_mode_);
        }
        if (g_saved_console == handle_) {
            g_saved_console = INVALID_HANDLE_VALUE;
        }
        active_ = false;
    }

private:
    HANDLE handle_ = INVALID_HANDLE_VALUE;
    DWORD original_mode_ = 0;
    bool active_ = false;
};

SecureBuffer read_password_windows_console(const std::string& prompt) {
    std::cerr << prompt;
    std::cerr.flush();

    ConsoleEchoGuard guard;
    guard.disable_echo();

    wchar_t buffer[MAX_PASSWORD_BYTES + 8]{};
    DWORD chars_read = 0;
    const BOOL ok = ReadConsoleW(GetStdHandle(STD_INPUT_HANDLE),
                                 buffer,
                                 static_cast<DWORD>(MAX_PASSWORD_BYTES + 3),
                                 &chars_read,
                                 nullptr);
    const DWORD read_error = ok ? 0 : GetLastError();

    std::cerr << '\n';
    std::cerr.flush();

    if (!ok) {
        SecureZeroMemory(buffer, sizeof(buffer));
        throw Error("Не удалось прочитать пароль (код Windows " +
                    std::to_string(read_error) + ").");
    }
    if (chars_read >= MAX_PASSWORD_BYTES + 3) {
        SecureZeroMemory(buffer, sizeof(buffer));
        throw Error("Пароль слишком длинный (не более " +
                    std::to_string(MAX_PASSWORD_BYTES) + " байт).");
    }

    DWORD length = chars_read;
    while (length > 0 && (buffer[length - 1] == L'\r' ||
                          buffer[length - 1] == L'\n')) {
        --length;
    }

    SecureBuffer result;
    if (length > 0) {
        const int utf8_size = WideCharToMultiByte(
            CP_UTF8, WC_ERR_INVALID_CHARS, buffer, static_cast<int>(length),
            nullptr, 0, nullptr, nullptr);
        if (utf8_size <= 0) {
            SecureZeroMemory(buffer, sizeof(buffer));
            throw Error("Пароль содержит недопустимые символы Unicode.");
        }
        if (static_cast<std::size_t>(utf8_size) > MAX_PASSWORD_BYTES) {
            SecureZeroMemory(buffer, sizeof(buffer));
            throw Error("Пароль слишком длинный (не более " +
                        std::to_string(MAX_PASSWORD_BYTES) + " байт UTF-8).");
        }
        result.reserve(MAX_PASSWORD_BYTES);
        for (int i = 0; i < utf8_size; ++i) {
            result.push_back(0); // Capacity reserved above.
        }
        if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, buffer,
                                static_cast<int>(length),
                                reinterpret_cast<char*>(result.data()),
                                utf8_size, nullptr, nullptr) != utf8_size) {
            SecureZeroMemory(buffer, sizeof(buffer));
            throw Error("Не удалось преобразовать пароль в UTF-8.");
        }
    }

    SecureZeroMemory(buffer, sizeof(buffer));
    if (result.empty()) {
        throw Error("Пароль не может быть пустым.");
    }
    return result;
}
#endif

#ifndef _WIN32
class TermiosGuard {
public:
    TermiosGuard() = default;
    TermiosGuard(const TermiosGuard&) = delete;
    TermiosGuard& operator=(const TermiosGuard&) = delete;

    ~TermiosGuard() { restore(); }

    void disable_echo() {
        if (tcgetattr(STDIN_FILENO, &original_) != 0) {
            throw Error("Не удалось получить настройки терминала.");
        }
        termios hidden = original_;
        hidden.c_lflag &= static_cast<tcflag_t>(~ECHO);
        if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &hidden) != 0) {
            throw Error("Не удалось отключить отображение пароля.");
        }
        active_ = true;
    }

    void restore() noexcept {
        if (active_) {
            tcsetattr(STDIN_FILENO, TCSAFLUSH, &original_);
            active_ = false;
        }
    }

private:
    termios original_{};
    bool active_ = false;
};
#endif

} // namespace

SecureBuffer read_password_interactive(const std::string& prompt) {
    if (!stdin_is_console()) {
        throw Error("Нет интерактивного терминала для ввода пароля.\n"
                    "Для автоматизации используйте --password-stdin.");
    }

#ifdef _WIN32
    return read_password_windows_console(prompt);
#else
    std::cerr << prompt;
    std::cerr.flush();

    TermiosGuard guard;
    guard.disable_echo();
    try {
        SecureBuffer password = read_line_from_stdin();
        std::fputc('\n', stderr);
        std::fflush(stderr);
        return password;
    } catch (...) {
        std::fputc('\n', stderr);
        std::fflush(stderr);
        throw;
    }
#endif
}

SecureBuffer read_password_stdin() {
    if (stdin_is_console()) {
        throw Error("--password-stdin нельзя использовать в интерактивном терминале.\n"
                    "Запустите без этого флага, чтобы ввести пароль скрыто.");
    }
#ifdef _WIN32
    // Binary mode avoids CRLF translation and Ctrl+Z being treated as EOF.
    if (_setmode(_fileno(stdin), _O_BINARY) == -1) {
        throw Error("Не удалось переключить stdin в двоичный режим.");
    }
#endif
    return read_line_from_stdin();
}

std::size_t utf8_character_count(const SecureBuffer& text) {
    std::size_t count = 0;
    for (std::size_t i = 0; i < text.size(); ++i) {
        if ((text[i] & 0xc0) != 0x80) {
            ++count;
        }
    }
    return count;
}

bool constant_time_equal(const SecureBuffer& a, const SecureBuffer& b) {
    if (a.size() != b.size()) {
        return false;
    }
    if (a.empty()) {
        return true;
    }
    return CRYPTO_memcmp(a.data(), b.data(), a.size()) == 0;
}

} // namespace fcrypt
