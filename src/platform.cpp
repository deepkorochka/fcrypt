#include "fcrypt.hpp"

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <cwchar>
#include <system_error>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <fcntl.h>
#include <io.h>
#include <sys/stat.h>
#else
#include <fcntl.h>
#include <unistd.h>
#endif

namespace fcrypt {
namespace {

std::string error_text(int code) {
    return std::system_category().message(code);
}

std::string windows_error_text(unsigned long code) {
#ifdef _WIN32
    return std::system_category().message(static_cast<int>(code));
#else
    (void)code;
    return {};
#endif
}

fs::path normalized_absolute(const fs::path& path) {
    std::error_code ec;
    fs::path absolute = fs::absolute(path, ec);
    if (ec) {
        absolute = path;
    }
    fs::path canonical = fs::weakly_canonical(absolute, ec);
    if (ec) {
        canonical = absolute.lexically_normal();
    }
    return canonical;
}

} // namespace

std::string path_to_utf8(const fs::path& path) {
    const auto text = path.u8string();
    return std::string(reinterpret_cast<const char*>(text.data()), text.size());
}

std::string random_hex(std::size_t byte_count) {
    const SecureBuffer bytes = random_bytes(byte_count);
    static const char digits[] = "0123456789abcdef";
    std::string result;
    result.reserve(byte_count * 2);
    for (std::size_t i = 0; i < bytes.size(); ++i) {
        result.push_back(digits[(bytes[i] >> 4) & 0x0f]);
        result.push_back(digits[bytes[i] & 0x0f]);
    }
    return result;
}

bool paths_refer_to_same_file(const fs::path& a, const fs::path& b) {
    std::error_code ec;
    if (fs::exists(a, ec) && fs::exists(b, ec)) {
        const bool equivalent = fs::equivalent(a, b, ec);
        if (!ec && equivalent) {
            return true;
        }
        ec.clear();
    }

    const fs::path first = normalized_absolute(a);
    const fs::path second = normalized_absolute(b);
#ifdef _WIN32
    return _wcsicmp(first.c_str(), second.c_str()) == 0;
#else
    return first == second;
#endif
}

void ensure_output_is_available(const fs::path& input,
                                const fs::path& output,
                                bool force) {
    std::error_code ec;
    if (input.empty()) {
        throw Error("Не указан входной файл.");
    }
    if (output.empty()) {
        throw Error("Не указан выходной файл.");
    }
    if (!fs::exists(input, ec)) {
        throw Error("Входной файл не найден: " + path_to_utf8(input));
    }
    ec.clear();
    if (!fs::is_regular_file(input, ec)) {
        throw Error("Входной путь не является обычным файлом: " +
                    path_to_utf8(input));
    }
    if (paths_refer_to_same_file(input, output)) {
        throw Error("Входной и выходной файлы должны быть разными.");
    }

    fs::path parent = output.parent_path();
    if (parent.empty()) {
        parent = fs::current_path(ec);
        if (ec) {
            throw Error("Не удалось определить текущий каталог.");
        }
    }
    ec.clear();
    if (!fs::is_directory(parent, ec)) {
        throw Error("Каталог для выходного файла не существует: " +
                    path_to_utf8(parent));
    }

    ec.clear();
    if (fs::exists(output, ec)) {
        if (fs::is_directory(output, ec)) {
            throw Error("Выходной путь является каталогом: " +
                        path_to_utf8(output));
        }
        if (!force) {
            throw Error("Выходной файл уже существует: " +
                        path_to_utf8(output) +
                        "\nИспользуйте --force, чтобы заменить его.");
        }
    }
}

FILE* open_input_file(const fs::path& path) {
    FILE* file = nullptr;
#ifdef _WIN32
    file = _wfopen(path.c_str(), L"rb");
#else
    file = std::fopen(path.c_str(), "rb");
#endif
    if (file == nullptr) {
        const int code = errno;
        throw Error("Не удалось открыть входной файл " + path_to_utf8(path) +
                    ": " + error_text(code));
    }
    return file;
}

CreatedFile create_temp_file(const fs::path& directory) {
    fs::path dir = directory;
    if (dir.empty()) {
        dir = fs::current_path();
    }

    for (int attempt = 0; attempt < 32; ++attempt) {
        const fs::path candidate =
            dir / fs::path(".fcrypt-" + random_hex(12) + ".tmp");

        int fd = -1;
#ifdef _WIN32
        fd = _wopen(candidate.c_str(),
                    _O_WRONLY | _O_CREAT | _O_EXCL | _O_BINARY,
                    _S_IREAD | _S_IWRITE);
#else
        int flags = O_WRONLY | O_CREAT | O_EXCL;
#ifdef O_CLOEXEC
        flags |= O_CLOEXEC;
#endif
        fd = ::open(candidate.c_str(), flags, 0600);
#endif
        if (fd < 0) {
            const int code = errno;
            if (code == EEXIST) {
                continue;
            }
            throw Error("Не удалось создать временный файл в каталоге " +
                        path_to_utf8(dir) + ": " + error_text(code));
        }

        FILE* file = nullptr;
#ifdef _WIN32
        file = _fdopen(fd, "wb");
#else
        file = ::fdopen(fd, "wb");
#endif
        if (file == nullptr) {
            const int code = errno;
#ifdef _WIN32
            _close(fd);
#else
            ::close(fd);
#endif
            std::error_code ignored;
            fs::remove(candidate, ignored);
            throw Error("Не удалось открыть временный файл: " +
                        error_text(code));
        }
        return CreatedFile{candidate, file};
    }
    throw Error("Не удалось создать уникальный временный файл в каталоге " +
                path_to_utf8(dir) + ".");
}

void close_input_file(FILE*& file) {
    if (file != nullptr) {
        std::fclose(file);
        file = nullptr;
    }
}

void close_output_file(FILE*& file) {
    if (file == nullptr) {
        return;
    }
    FILE* current = file;
    file = nullptr;

    if (std::fflush(current) != 0) {
        const int code = errno;
        std::fclose(current);
        throw Error("Ошибка записи выходного файла: " + error_text(code));
    }

#ifdef _WIN32
    if (_commit(_fileno(current)) != 0) {
        const int code = errno;
        std::fclose(current);
        throw Error("Не удалось сбросить данные на диск: " + error_text(code));
    }
#else
    if (::fsync(fileno(current)) != 0) {
        const int code = errno;
        std::fclose(current);
        throw Error("Не удалось сбросить данные на диск: " + error_text(code));
    }
#endif

    if (std::fclose(current) != 0) {
        const int code = errno;
        throw Error("Не удалось закрыть выходной файл: " + error_text(code));
    }
}

void atomic_replace(const fs::path& temp_path,
                    const fs::path& destination,
                    bool force) {
#ifdef _WIN32
    DWORD flags = MOVEFILE_WRITE_THROUGH;
    if (force) {
        flags |= MOVEFILE_REPLACE_EXISTING;
    }
    if (!MoveFileExW(temp_path.c_str(), destination.c_str(), flags)) {
        const DWORD code = GetLastError();
        throw Error("Не удалось переименовать выходной файл: " +
                    windows_error_text(code) + " (код Windows " +
                    std::to_string(code) + ").");
    }
#else
    std::error_code ec;
    if (!force && fs::exists(destination, ec)) {
        throw Error("Выходной файл уже существует: " +
                    path_to_utf8(destination));
    }
    ec.clear();
    fs::rename(temp_path, destination, ec);
    if (ec) {
        throw Error("Не удалось переименовать выходной файл: " + ec.message());
    }
#endif
}

void set_console_utf8() {
#ifdef _WIN32
    struct ConsoleEncodingRestore {
        UINT output = 0;
        UINT input = 0;
        bool saved = false;

        ~ConsoleEncodingRestore() {
            if (!saved) {
                return;
            }
            if (output != 0) {
                SetConsoleOutputCP(output);
            }
            if (input != 0) {
                SetConsoleCP(input);
            }
        }
    };
    static ConsoleEncodingRestore restore;

    if (!restore.saved) {
        restore.output = GetConsoleOutputCP();
        restore.input = GetConsoleCP();
        restore.saved = true;
    }
    if (restore.output != 0) {
        SetConsoleOutputCP(CP_UTF8);
    }
    if (restore.input != 0) {
        SetConsoleCP(CP_UTF8);
    }
#endif
}

} // namespace fcrypt
