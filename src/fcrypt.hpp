#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <stdexcept>
#include <string>
#include <vector>

#include <openssl/crypto.h>

namespace fcrypt {

namespace fs = std::filesystem;

// Public format constants. The format is fixed for version 1.
constexpr std::size_t KEY_SIZE = 32;
constexpr std::size_t SALT_SIZE = 32;
constexpr std::size_t NONCE_PREFIX_SIZE = 8;
constexpr std::size_t TAG_SIZE = 16;
constexpr std::size_t HEADER_SIZE = 80;

constexpr std::uint32_t DEFAULT_CHUNK_SIZE = 1024 * 1024;
constexpr std::uint32_t MIN_CHUNK_SIZE = 64 * 1024;
constexpr std::uint32_t MAX_CHUNK_SIZE = 16 * 1024 * 1024;

constexpr std::uint32_t MIN_KDF_MEMORY_KIB = 8 * 1024;
constexpr std::uint32_t MAX_KDF_MEMORY_KIB = 1024 * 1024;
constexpr std::uint32_t MIN_KDF_ITERATIONS = 1;
constexpr std::uint32_t MAX_KDF_ITERATIONS = 16;
constexpr std::uint32_t MIN_KDF_LANES = 1;
constexpr std::uint32_t MAX_KDF_LANES = 16;

constexpr std::uint32_t DEFAULT_KDF_MEMORY_KIB = 256 * 1024;
constexpr std::uint32_t DEFAULT_KDF_ITERATIONS = 3;
constexpr std::uint32_t DEFAULT_KDF_LANES = 4;

constexpr std::size_t MAX_PASSWORD_BYTES = 1024;

class Error : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

// Bad password, modified ciphertext, or a broken authentication tag.
class AuthenticationError : public Error {
public:
    using Error::Error;
};

// A byte buffer that is wiped on destruction. Secret data must not be copied;
// use references or move semantics.
class SecureBuffer {
public:
    SecureBuffer() = default;
    explicit SecureBuffer(std::size_t size) : data_(size) {}

    SecureBuffer(const SecureBuffer&) = delete;
    SecureBuffer& operator=(const SecureBuffer&) = delete;

    SecureBuffer(SecureBuffer&& other) noexcept = default;
    SecureBuffer& operator=(SecureBuffer&& other) noexcept {
        if (this != &other) {
            wipe();
            data_ = std::move(other.data_);
        }
        return *this;
    }

    ~SecureBuffer() { wipe(); }

    unsigned char* data() noexcept { return data_.data(); }
    const unsigned char* data() const noexcept { return data_.data(); }
    std::size_t size() const noexcept { return data_.size(); }
    bool empty() const noexcept { return data_.empty(); }
    unsigned char& operator[](std::size_t i) noexcept { return data_[i]; }
    const unsigned char& operator[](std::size_t i) const noexcept { return data_[i]; }

    void resize(std::size_t size) {
        if (size > data_.capacity()) {
            // Growing a secret buffer can leave an un-wiped copy behind.
            throw Error("internal error: secure buffer growth");
        }
        data_.resize(size);
    }

    void reserve(std::size_t capacity) { data_.reserve(capacity); }

    void push_back(unsigned char value) {
        if (data_.size() == data_.capacity()) {
            throw Error("internal error: secure buffer growth");
        }
        data_.push_back(value);
    }

    // Wipe the entire allocation, including bytes left behind by a resize.
    void wipe() noexcept {
        if (!data_.empty()) {
            OPENSSL_cleanse(data_.data(), data_.capacity());
        }
        data_.clear();
    }

private:
    std::vector<unsigned char> data_;
};

struct KdfParams {
    std::uint32_t memory_kib = DEFAULT_KDF_MEMORY_KIB;
    std::uint32_t iterations = DEFAULT_KDF_ITERATIONS;
    std::uint32_t lanes = DEFAULT_KDF_LANES;
};

struct Header {
    std::uint32_t memory_kib = DEFAULT_KDF_MEMORY_KIB;
    std::uint32_t iterations = DEFAULT_KDF_ITERATIONS;
    std::uint32_t lanes = DEFAULT_KDF_LANES;
    std::uint32_t chunk_size = DEFAULT_CHUNK_SIZE;
    std::uint64_t plaintext_size = 0;
    std::array<unsigned char, SALT_SIZE> salt{};
    std::array<unsigned char, NONCE_PREFIX_SIZE> nonce_prefix{};
};

struct OperationResult {
    std::uint64_t input_size = 0;
    std::uint64_t output_size = 0;
};

// crypto.cpp
void initialize_crypto();
SecureBuffer random_bytes(std::size_t count);
SecureBuffer derive_file_key(const SecureBuffer& password, const Header& header);
void encrypt_chunk(const SecureBuffer& key,
                   const Header& header,
                   const std::array<unsigned char, HEADER_SIZE>& header_bytes,
                   std::uint32_t chunk_index,
                   bool final_chunk,
                   const unsigned char* plaintext,
                   std::size_t plaintext_size,
                   unsigned char* ciphertext,
                   std::array<unsigned char, TAG_SIZE>& tag);
void decrypt_chunk(const SecureBuffer& key,
                   const Header& header,
                   const std::array<unsigned char, HEADER_SIZE>& header_bytes,
                   std::uint32_t chunk_index,
                   bool final_chunk,
                   const unsigned char* ciphertext,
                   std::size_t plaintext_size,
                   const std::array<unsigned char, TAG_SIZE>& tag,
                   unsigned char* plaintext);

// format.cpp
std::array<unsigned char, HEADER_SIZE> serialize_header(const Header& header);
Header parse_header(const std::array<unsigned char, HEADER_SIZE>& bytes);
std::uint64_t chunk_count(std::uint64_t plaintext_size, std::uint32_t chunk_size);
std::uint64_t encrypted_file_size(const Header& header);

// filecrypt.cpp
OperationResult encrypt_file(const fs::path& input,
                             const fs::path& output,
                             const SecureBuffer& password,
                             const KdfParams& kdf,
                             bool force);

OperationResult decrypt_file(const fs::path& input,
                             const fs::path& output,
                             const SecureBuffer& password,
                             bool force);

// password.cpp
SecureBuffer read_password_interactive(const std::string& prompt);
SecureBuffer read_password_stdin();
std::size_t utf8_character_count(const SecureBuffer& text);
bool constant_time_equal(const SecureBuffer& a, const SecureBuffer& b);

// platform.cpp
std::string path_to_utf8(const fs::path& path);
std::string random_hex(std::size_t byte_count);
bool paths_refer_to_same_file(const fs::path& a, const fs::path& b);
void ensure_output_is_available(const fs::path& input,
                                const fs::path& output,
                                bool force);
struct CreatedFile {
    fs::path path;
    std::FILE* file = nullptr;
};
CreatedFile create_temp_file(const fs::path& directory);
FILE* open_input_file(const fs::path& path);
void close_output_file(std::FILE*& file);
void close_input_file(std::FILE*& file);
void atomic_replace(const fs::path& temp_path,
                    const fs::path& destination,
                    bool force);
void set_console_utf8();

} // namespace fcrypt
