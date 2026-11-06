#include "fcrypt.hpp"

#include <algorithm>
#include <charconv>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <limits>
#include <optional>
#include <string>
#include <vector>

namespace fcrypt {
namespace {

constexpr const char* PROGRAM_NAME = "fcrypt";
constexpr const char* PROGRAM_VERSION = "1.0.0";
constexpr std::size_t MIN_PASSWORD_CHARACTERS = 12;

struct Argument {
    fs::path path;
    std::string text;
};

enum class Mode {
    Encrypt,
    Decrypt
};

struct Options {
    Mode mode = Mode::Encrypt;
    fs::path input;
    fs::path output;
    bool output_set = false;
    bool force = false;
    bool password_stdin = false;
    bool allow_weak_password = false;
    KdfParams kdf;
};

std::string ascii_lower(std::string text) {
    for (char& ch : text) {
        if (ch >= 'A' && ch <= 'Z') {
            ch = static_cast<char>(ch - 'A' + 'a');
        }
    }
    return text;
}

void print_usage(std::ostream& out) {
    out <<
        "fcrypt " << PROGRAM_VERSION << " — аутентифицированное шифрование файлов\n"
        "\n"
        "Использование:\n"
        "  fcrypt encrypt <входной_файл> [-o <выходной_файл>] [параметры]\n"
        "  fcrypt decrypt <входной_файл> [-o <выходной_файл>] [параметры]\n"
        "  fcrypt --help\n"
        "\n"
        "Команды:\n"
        "  encrypt, e   зашифровать файл\n"
        "  decrypt, d   расшифровать файл\n"
        "\n"
        "Параметры:\n"
        "  -o, --output <файл>       выходной файл\n"
        "  -f, --force               заменить существующий выходной файл\n"
        "      --password-stdin      прочитать пароль одной строкой из stdin\n"
        "                            (только для автоматизации, без подтверждения)\n"
        "      --allow-weak-password разрешить пароль короче 12 символов\n"
        "      --kdf-memory <МиБ>    память Argon2id: 8..1024 (по умолчанию 256)\n"
        "      --kdf-time <N>        итерации Argon2id: 1..16 (по умолчанию 3)\n"
        "      --kdf-lanes <N>       параллелизм Argon2id: 1..16 (по умолчанию 4)\n"
        "  -h, --help                показать эту справку\n"
        "      --version             показать версию\n"
        "\n"
        "По умолчанию:\n"
        "  encrypt: <файл>.fcrypt\n"
        "  decrypt: имя без .fcrypt либо <файл>.decrypted\n"
        "\n"
        "Безопасность:\n"
        "  • Argon2id + ChaCha20-Poly1305; ключ выводится только из пароля.\n"
        "  • Пароль и данные невозможно восстановить при забытом пароле.\n"
        "  • Исходный файл не удаляется автоматически.\n"
        "  • Метаданные (точный размер файла) не скрываются.\n";
}

std::uint32_t parse_uint(const std::string& text,
                         std::uint32_t minimum,
                         std::uint32_t maximum,
                         const std::string& option_name) {
    std::uint32_t value = 0;
    const char* begin = text.data();
    const char* end = text.data() + text.size();
    const auto result = std::from_chars(begin, end, value);
    if (result.ec != std::errc() || result.ptr != end ||
        value < minimum || value > maximum) {
        throw Error("Недопустимое значение " + option_name + ": " + text +
                    " (допустимо " + std::to_string(minimum) + ".." +
                    std::to_string(maximum) + ").");
    }
    return value;
}

Options parse_options(const std::vector<Argument>& args) {
    if (args.size() < 2) {
        print_usage(std::cout);
        throw Error("Не указана команда.");
    }

    const std::string command = ascii_lower(args[1].text);
    if (command == "--help" || command == "-h" || command == "help") {
        print_usage(std::cout);
        std::exit(0);
    }
    if (command == "--version" || command == "version") {
        std::cout << PROGRAM_NAME << " " << PROGRAM_VERSION << "\n";
        std::exit(0);
    }

    Options options;
    if (command == "encrypt" || command == "e" || command == "enc") {
        options.mode = Mode::Encrypt;
    } else if (command == "decrypt" || command == "d" ||
               command == "dec") {
        options.mode = Mode::Decrypt;
    } else {
        throw Error("Неизвестная команда: " + args[1].text);
    }

    bool options_ended = false;
    for (std::size_t i = 2; i < args.size(); ++i) {
        const std::string& text = args[i].text;

        if (!options_ended && text == "--") {
            options_ended = true;
            continue;
        }

        if (!options_ended && (text == "-h" || text == "--help")) {
            print_usage(std::cout);
            std::exit(0);
        }
        if (!options_ended && (text == "-f" || text == "--force")) {
            options.force = true;
            continue;
        }
        if (!options_ended && text == "--password-stdin") {
            options.password_stdin = true;
            continue;
        }
        if (!options_ended && text == "--allow-weak-password") {
            options.allow_weak_password = true;
            continue;
        }
        if (!options_ended && (text == "-o" || text == "--output")) {
            if (i + 1 >= args.size()) {
                throw Error("После " + text + " требуется путь к файлу.");
            }
            options.output = args[++i].path;
            options.output_set = true;
            continue;
        }
        if (!options_ended &&
            (text == "--kdf-memory" || text == "--kdf-time" ||
             text == "--kdf-lanes")) {
            if (options.mode != Mode::Encrypt) {
                throw Error("Параметры KDF задаются только при шифровании; "
                            "при расшифровке они берутся из файла.");
            }
            if (i + 1 >= args.size()) {
                throw Error("После " + text + " требуется число.");
            }
            const std::string& value = args[++i].text;
            if (text == "--kdf-memory") {
                options.kdf.memory_kib =
                    parse_uint(value, 8, 1024, "памяти (МиБ)") * 1024;
            } else if (text == "--kdf-time") {
                options.kdf.iterations =
                    parse_uint(value, MIN_KDF_ITERATIONS,
                               MAX_KDF_ITERATIONS, "итераций");
            } else {
                options.kdf.lanes =
                    parse_uint(value, MIN_KDF_LANES, MAX_KDF_LANES,
                               "параллелизма");
            }
            continue;
        }

        if (!options_ended && !text.empty() && text[0] == '-') {
            throw Error("Неизвестный параметр: " + text);
        }

        if (options.input.empty()) {
            options.input = args[i].path;
        } else {
            throw Error("Указано несколько входных файлов.");
        }
    }

    if (options.input.empty()) {
        throw Error("Не указан входной файл.");
    }
    if (options.mode == Mode::Decrypt && options.allow_weak_password) {
        throw Error("Параметр --allow-weak-password используется только при шифровании.");
    }
    if (options.mode == Mode::Encrypt) {
        if (static_cast<std::uint64_t>(options.kdf.memory_kib) <
            8ull * options.kdf.lanes) {
            throw Error("Слишком мало памяти Argon2id для выбранного "
                        "параллелизма (нужно не менее 8 КиБ на поток).");
        }
    }

    if (!options.output_set) {
        if (options.mode == Mode::Encrypt) {
            options.output = options.input;
            options.output += fs::path(".fcrypt");
        } else {
            const std::string extension =
                ascii_lower(path_to_utf8(options.input.extension()));
            if (extension == ".fcrypt") {
                options.output = options.input;
                options.output.replace_extension();
                if (options.output.filename().empty()) {
                    options.output = options.input;
                    options.output += fs::path(".decrypted");
                }
            } else {
                options.output = options.input;
                options.output += fs::path(".decrypted");
            }
        }
    }

    return options;
}

std::string human_size(std::uint64_t bytes) {
    constexpr std::uint64_t KiB = 1024;
    constexpr std::uint64_t MiB = 1024 * 1024;
    constexpr std::uint64_t GiB = 1024ull * 1024ull * 1024ull;
    if (bytes >= GiB) {
        return std::to_string(bytes / GiB) + " ГиБ";
    }
    if (bytes >= MiB) {
        return std::to_string(bytes / MiB) + " МиБ";
    }
    if (bytes >= KiB) {
        return std::to_string(bytes / KiB) + " КиБ";
    }
    return std::to_string(bytes) + " Б";
}

SecureBuffer obtain_password(const Options& options) {
    if (options.password_stdin) {
        return read_password_stdin();
    }

    SecureBuffer password = read_password_interactive("Пароль: ");
    if (options.mode == Mode::Encrypt) {
        SecureBuffer confirmation =
            read_password_interactive("Повторите пароль: ");
        if (!constant_time_equal(password, confirmation)) {
            throw Error("Пароли не совпадают.");
        }
    }
    return password;
}

int run(const std::vector<Argument>& args) {
    Options options = parse_options(args);
    ensure_output_is_available(options.input, options.output, options.force);

    SecureBuffer password = obtain_password(options);
    if (options.mode == Mode::Encrypt) {
        if (!options.allow_weak_password &&
            utf8_character_count(password) < MIN_PASSWORD_CHARACTERS) {
            throw Error("Пароль должен содержать не менее " +
                        std::to_string(MIN_PASSWORD_CHARACTERS) +
                        " символов.\n"
                        "Используйте длинную парольную фразу. Если это "
                        "осознанное решение,\n"
                        "добавьте --allow-weak-password (не рекомендуется).");
        }
    }

    const char* action =
        options.mode == Mode::Encrypt ? "Шифрование" : "Расшифровка";
    std::cerr << action << ": " << path_to_utf8(options.input) << "\n";
    std::cerr << "Вычисление ключа Argon2id...\n";
    std::cerr.flush();

    OperationResult result;
    if (options.mode == Mode::Encrypt) {
        result = encrypt_file(options.input, options.output, password,
                              options.kdf, options.force);
    } else {
        result = decrypt_file(options.input, options.output, password,
                              options.force);
    }

    std::cout << "\nГотово.\n"
              << "  Вход:  " << path_to_utf8(options.input)
              << " (" << human_size(result.input_size) << ")\n"
              << "  Выход: " << path_to_utf8(options.output)
              << " (" << human_size(result.output_size) << ")\n";

    if (options.mode == Mode::Encrypt) {
        std::cout << "\nИсходный файл не удалён. После проверки расшифровки "
                     "удалите его.\n";
    }
    return 0;
}

#ifndef _WIN32
std::vector<Argument> make_arguments(int argc, char** argv) {
    std::vector<Argument> result;
    result.reserve(static_cast<std::size_t>(argc));
    for (int i = 0; i < argc; ++i) {
        const fs::path path(argv[i]);
        result.push_back(Argument{path, path_to_utf8(path)});
    }
    return result;
}
#else
std::vector<Argument> make_arguments(int argc, wchar_t** argv) {
    std::vector<Argument> result;
    result.reserve(static_cast<std::size_t>(argc));
    for (int i = 0; i < argc; ++i) {
        const fs::path path(argv[i]);
        result.push_back(Argument{path, path_to_utf8(path)});
    }
    return result;
}
#endif

int main_impl(const std::vector<Argument>& args) {
    try {
        initialize_crypto();
        return run(args);
    } catch (const AuthenticationError& error) {
        std::cerr << "\nОшибка: " << error.what() << "\n";
        std::cerr << "Файл не был создан. Проверьте пароль и целостность "
                     "файла.\n";
        return 2;
    } catch (const Error& error) {
        std::cerr << "\nОшибка: " << error.what() << "\n";
        return 1;
    } catch (const std::exception& error) {
        std::cerr << "\nНепредвиденная ошибка: " << error.what() << "\n";
        return 1;
    } catch (...) {
        std::cerr << "\nНепредвиденная ошибка.\n";
        return 1;
    }
}

} // namespace
} // namespace fcrypt

#ifdef _WIN32
int wmain(int argc, wchar_t** argv) {
    fcrypt::set_console_utf8();
    return fcrypt::main_impl(fcrypt::make_arguments(argc, argv));
}
#else
int main(int argc, char** argv) {
    return fcrypt::main_impl(fcrypt::make_arguments(argc, argv));
}
#endif
