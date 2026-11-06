#include "fcrypt.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <system_error>
#include <vector>

namespace fcrypt {
namespace {

void read_exact(FILE* file,
                unsigned char* destination,
                std::size_t size,
                bool allow_eof_at_start = false) {
    std::size_t offset = 0;
    while (offset < size) {
        const std::size_t count =
            std::fread(destination + offset, 1, size - offset, file);
        if (count == 0) {
            if (std::ferror(file)) {
                throw Error("Ошибка чтения входного файла.");
            }
            if (offset == 0 && allow_eof_at_start) {
                return;
            }
            throw Error("Входной файл неожиданно закончился.");
        }
        offset += count;
    }
}

void write_exact(FILE* file, const unsigned char* source, std::size_t size) {
    std::size_t offset = 0;
    while (offset < size) {
        const std::size_t count =
            std::fwrite(source + offset, 1, size - offset, file);
        if (count == 0) {
            const int code = errno;
            throw Error("Ошибка записи выходного файла: " +
                        std::system_category().message(code));
        }
        offset += count;
    }
}

std::uint64_t regular_file_size(const fs::path& path) {
    std::error_code ec;
    const std::uintmax_t size = fs::file_size(path, ec);
    if (ec) {
        throw Error("Не удалось определить размер файла " +
                    path_to_utf8(path) + ": " + ec.message());
    }
    return static_cast<std::uint64_t>(size);
}

class InputFile {
public:
    explicit InputFile(const fs::path& path) : file_(open_input_file(path)) {}
    InputFile(const InputFile&) = delete;
    InputFile& operator=(const InputFile&) = delete;
    ~InputFile() { close_input_file(file_); }

    FILE* get() const noexcept { return file_; }

private:
    FILE* file_ = nullptr;
};

class TempOutput {
public:
    explicit TempOutput(const fs::path& directory) {
        CreatedFile created = create_temp_file(directory);
        path_ = created.path;
        file_ = created.file;
    }

    TempOutput(const TempOutput&) = delete;
    TempOutput& operator=(const TempOutput&) = delete;

    ~TempOutput() {
        if (file_ != nullptr) {
            std::fclose(file_);
            file_ = nullptr;
        }
        if (!committed_ && !path_.empty()) {
            std::error_code ignored;
            fs::remove(path_, ignored);
        }
    }

    FILE* get() const noexcept { return file_; }

    void commit(const fs::path& destination, bool force) {
        close_output_file(file_);
        atomic_replace(path_, destination, force);
        committed_ = true;
    }

private:
    fs::path path_;
    FILE* file_ = nullptr;
    bool committed_ = false;
};

fs::path output_directory(const fs::path& output) {
    fs::path parent = output.parent_path();
    if (parent.empty()) {
        return fs::current_path();
    }
    return parent;
}

bool input_has_more_data(FILE* file) {
    const int extra = std::fgetc(file);
    if (extra != EOF) {
        return true;
    }
    if (std::ferror(file)) {
        throw Error("Ошибка чтения входного файла.");
    }
    return false;
}

} // namespace

OperationResult encrypt_file(const fs::path& input,
                             const fs::path& output,
                             const SecureBuffer& password,
                             const KdfParams& kdf,
                             bool force) {
    ensure_output_is_available(input, output, force);

    Header header;
    header.memory_kib = kdf.memory_kib;
    header.iterations = kdf.iterations;
    header.lanes = kdf.lanes;
    header.chunk_size = DEFAULT_CHUNK_SIZE;
    header.plaintext_size = regular_file_size(input);

    const SecureBuffer salt = random_bytes(SALT_SIZE);
    const SecureBuffer nonce_prefix = random_bytes(NONCE_PREFIX_SIZE);
    std::copy(salt.data(), salt.data() + salt.size(), header.salt.begin());
    std::copy(nonce_prefix.data(), nonce_prefix.data() + nonce_prefix.size(),
              header.nonce_prefix.begin());

    // This validates all header/KDF parameters before any work is done.
    const auto header_bytes = serialize_header(header);
    const std::uint64_t expected_output_size = encrypted_file_size(header);

    InputFile input_file(input);
    const SecureBuffer key = derive_file_key(password, header);

    TempOutput temp(output_directory(output));
    write_exact(temp.get(), header_bytes.data(), header_bytes.size());

    SecureBuffer plaintext(header.chunk_size);
    std::vector<unsigned char> ciphertext(header.chunk_size + TAG_SIZE);

    std::uint64_t remaining = header.plaintext_size;
    std::uint32_t chunk_index = 0;
    for (;;) {
        const std::size_t length =
            remaining > header.chunk_size
                ? static_cast<std::size_t>(header.chunk_size)
                : static_cast<std::size_t>(remaining);
        const bool final_chunk = remaining <= header.chunk_size;

        read_exact(input_file.get(), plaintext.data(), length);

        std::array<unsigned char, TAG_SIZE> tag{};
        encrypt_chunk(key, header, header_bytes, chunk_index, final_chunk,
                      plaintext.data(), length, ciphertext.data(), tag);
        write_exact(temp.get(), ciphertext.data(), length);
        write_exact(temp.get(), tag.data(), tag.size());

        remaining -= length;
        ++chunk_index;
        if (final_chunk) {
            break;
        }
    }

    if (input_has_more_data(input_file.get())) {
        throw Error("Входной файл изменился во время шифрования.");
    }

    temp.commit(output, force);
    return OperationResult{header.plaintext_size, expected_output_size};
}

OperationResult decrypt_file(const fs::path& input,
                             const fs::path& output,
                             const SecureBuffer& password,
                             bool force) {
    ensure_output_is_available(input, output, force);

    const std::uint64_t encrypted_size = regular_file_size(input);
    if (encrypted_size < HEADER_SIZE) {
        throw Error("Файл слишком мал и не является корректным файлом fcrypt.");
    }

    InputFile input_file(input);
    std::array<unsigned char, HEADER_SIZE> header_bytes{};
    read_exact(input_file.get(), header_bytes.data(), header_bytes.size());
    const Header header = parse_header(header_bytes);

    const std::uint64_t expected_encrypted_size = encrypted_file_size(header);
    if (encrypted_size != expected_encrypted_size) {
        throw Error("Файл повреждён: размер не соответствует заголовку.");
    }

    const SecureBuffer key = derive_file_key(password, header);
    TempOutput temp(output_directory(output));

    SecureBuffer plaintext(header.chunk_size);
    std::vector<unsigned char> ciphertext(header.chunk_size);

    std::uint64_t remaining = header.plaintext_size;
    std::uint32_t chunk_index = 0;
    for (;;) {
        const std::size_t length =
            remaining > header.chunk_size
                ? static_cast<std::size_t>(header.chunk_size)
                : static_cast<std::size_t>(remaining);
        const bool final_chunk = remaining <= header.chunk_size;

        read_exact(input_file.get(), ciphertext.data(), length);
        std::array<unsigned char, TAG_SIZE> tag{};
        read_exact(input_file.get(), tag.data(), tag.size());

        decrypt_chunk(key, header, header_bytes, chunk_index, final_chunk,
                      ciphertext.data(), length, tag, plaintext.data());
        write_exact(temp.get(), plaintext.data(), length);

        remaining -= length;
        ++chunk_index;
        if (final_chunk) {
            break;
        }
    }

    if (input_has_more_data(input_file.get())) {
        throw Error("Файл повреждён: обнаружены лишние данные.");
    }

    temp.commit(output, force);
    return OperationResult{encrypted_size, header.plaintext_size};
}

} // namespace fcrypt
