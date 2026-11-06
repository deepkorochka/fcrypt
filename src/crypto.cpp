#include "fcrypt.hpp"

#include <algorithm>
#include <array>
#include <climits>
#include <cstring>
#include <limits>
#include <memory>
#include <string>

#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/rand.h>
#include <openssl/thread.h>

namespace fcrypt {
namespace {

constexpr const char* AEAD_NAME = "ChaCha20-Poly1305";
constexpr std::size_t NONCE_SIZE = 12;
constexpr std::size_t AAD_SIZE = HEADER_SIZE + 8 + 1 + 4;
constexpr unsigned char ARGON2_ASSOCIATED_DATA[] = "fcrypt/v1/argon2id/file-key";

std::string openssl_error_string() {
    const unsigned long code = ERR_get_error();
    if (code == 0) {
        return "неизвестная ошибка OpenSSL";
    }
    char text[256];
    ERR_error_string_n(code, text, sizeof(text));
    ERR_clear_error();
    return std::string(text);
}

void put_u32_be(unsigned char* out, std::uint32_t value) {
    out[0] = static_cast<unsigned char>((value >> 24) & 0xff);
    out[1] = static_cast<unsigned char>((value >> 16) & 0xff);
    out[2] = static_cast<unsigned char>((value >> 8) & 0xff);
    out[3] = static_cast<unsigned char>(value & 0xff);
}

void put_u64_be(unsigned char* out, std::uint64_t value) {
    for (int i = 7; i >= 0; --i) {
        out[7 - i] = static_cast<unsigned char>((value >> (i * 8)) & 0xff);
    }
}

std::array<unsigned char, NONCE_SIZE> make_nonce(
    const Header& header, std::uint32_t chunk_index) {
    std::array<unsigned char, NONCE_SIZE> nonce{};
    std::copy(header.nonce_prefix.begin(), header.nonce_prefix.end(),
              nonce.begin());
    put_u32_be(nonce.data() + NONCE_PREFIX_SIZE, chunk_index);
    return nonce;
}

std::array<unsigned char, AAD_SIZE> make_aad(
    const std::array<unsigned char, HEADER_SIZE>& header_bytes,
    std::uint32_t chunk_index,
    bool final_chunk,
    std::size_t plaintext_size) {
    if (plaintext_size > std::numeric_limits<std::uint32_t>::max()) {
        throw Error("Внутренняя ошибка: слишком большой блок.");
    }
    std::array<unsigned char, AAD_SIZE> aad{};
    std::copy(header_bytes.begin(), header_bytes.end(), aad.begin());
    put_u64_be(aad.data() + HEADER_SIZE, static_cast<std::uint64_t>(chunk_index));
    aad[HEADER_SIZE + 8] = final_chunk ? 1 : 0;
    put_u32_be(aad.data() + HEADER_SIZE + 9,
               static_cast<std::uint32_t>(plaintext_size));
    return aad;
}

class ThreadPoolSetting {
public:
    explicit ThreadPoolSetting(std::uint32_t requested) {
        if (requested > 1 && OSSL_set_max_threads(nullptr, requested) == 1) {
            enabled_ = true;
        }
    }

    ~ThreadPoolSetting() {
        if (enabled_) {
            OSSL_set_max_threads(nullptr, 0);
        }
    }

    ThreadPoolSetting(const ThreadPoolSetting&) = delete;
    ThreadPoolSetting& operator=(const ThreadPoolSetting&) = delete;

    bool enabled() const noexcept { return enabled_; }

private:
    bool enabled_ = false;
};

class AeadCipher {
public:
    explicit AeadCipher(const SecureBuffer& key)
        : key_(key.data()) {
        if (key.size() != KEY_SIZE) {
            throw Error("Внутренняя ошибка: неверная длина ключа.");
        }

        ERR_clear_error();
        cipher_ = EVP_CIPHER_fetch(nullptr, AEAD_NAME, nullptr);
        if (cipher_ == nullptr) {
            throw Error("Не удалось загрузить " + std::string(AEAD_NAME) +
                        ": " + openssl_error_string());
        }
        ctx_ = EVP_CIPHER_CTX_new();
        if (ctx_ == nullptr) {
            EVP_CIPHER_free(cipher_);
            cipher_ = nullptr;
            throw Error("Не удалось создать криптографический контекст.");
        }
    }

    AeadCipher(const AeadCipher&) = delete;
    AeadCipher& operator=(const AeadCipher&) = delete;

    ~AeadCipher() {
        EVP_CIPHER_CTX_free(ctx_);
        EVP_CIPHER_free(cipher_);
    }

    void encrypt(const Header& header,
                 const std::array<unsigned char, HEADER_SIZE>& header_bytes,
                 std::uint32_t chunk_index,
                 bool final_chunk,
                 const unsigned char* plaintext,
                 std::size_t plaintext_size,
                 unsigned char* ciphertext,
                 std::array<unsigned char, TAG_SIZE>& tag) {
        const auto nonce = make_nonce(header, chunk_index);
        const auto aad = make_aad(header_bytes, chunk_index, final_chunk,
                                  plaintext_size);
        if (plaintext_size > static_cast<std::size_t>(INT_MAX)) {
            throw Error("Внутренняя ошибка: слишком большой блок.");
        }

        ERR_clear_error();
        if (EVP_EncryptInit_ex2(ctx_, cipher_, key_, nonce.data(), nullptr) != 1) {
            throw Error("Ошибка инициализации шифрования: " +
                        openssl_error_string());
        }

        int length = 0;
        if (EVP_EncryptUpdate(ctx_, nullptr, &length, aad.data(),
                              static_cast<int>(aad.size())) != 1) {
            throw Error("Ошибка аутентификации заголовка: " +
                        openssl_error_string());
        }

        int total = 0;
        if (plaintext_size != 0) {
            if (EVP_EncryptUpdate(ctx_, ciphertext, &length, plaintext,
                                  static_cast<int>(plaintext_size)) != 1) {
                throw Error("Ошибка шифрования: " + openssl_error_string());
            }
            total = length;
        }

        int final_length = 0;
        if (EVP_EncryptFinal_ex(ctx_, ciphertext + total, &final_length) != 1) {
            throw Error("Ошибка завершения шифрования: " +
                        openssl_error_string());
        }
        total += final_length;

        if (total != static_cast<int>(plaintext_size)) {
            throw Error("Внутренняя ошибка: неверная длина шифротекста.");
        }
        if (EVP_CIPHER_CTX_ctrl(ctx_, EVP_CTRL_AEAD_GET_TAG,
                                static_cast<int>(TAG_SIZE), tag.data()) != 1) {
            throw Error("Не удалось получить тег аутентификации.");
        }
    }

    void decrypt(const Header& header,
                 const std::array<unsigned char, HEADER_SIZE>& header_bytes,
                 std::uint32_t chunk_index,
                 bool final_chunk,
                 const unsigned char* ciphertext,
                 std::size_t plaintext_size,
                 const std::array<unsigned char, TAG_SIZE>& tag,
                 unsigned char* plaintext) {
        const auto nonce = make_nonce(header, chunk_index);
        const auto aad = make_aad(header_bytes, chunk_index, final_chunk,
                                  plaintext_size);
        if (plaintext_size > static_cast<std::size_t>(INT_MAX)) {
            throw Error("Внутренняя ошибка: слишком большой блок.");
        }

        ERR_clear_error();
        if (EVP_DecryptInit_ex2(ctx_, cipher_, key_, nonce.data(), nullptr) != 1) {
            throw AuthenticationError("Неверный пароль или файл повреждён.");
        }

        int length = 0;
        if (EVP_DecryptUpdate(ctx_, nullptr, &length, aad.data(),
                              static_cast<int>(aad.size())) != 1) {
            ERR_clear_error();
            throw AuthenticationError("Неверный пароль или файл повреждён.");
        }

        int total = 0;
        if (plaintext_size != 0) {
            if (EVP_DecryptUpdate(ctx_, plaintext, &length, ciphertext,
                                  static_cast<int>(plaintext_size)) != 1) {
                ERR_clear_error();
                throw AuthenticationError("Неверный пароль или файл повреждён.");
            }
            total = length;
        }

        if (EVP_CIPHER_CTX_ctrl(ctx_, EVP_CTRL_AEAD_SET_TAG,
                                static_cast<int>(TAG_SIZE),
                                const_cast<unsigned char*>(tag.data())) != 1) {
            ERR_clear_error();
            throw Error("Не удалось установить тег аутентификации.");
        }

        int final_length = 0;
        if (EVP_DecryptFinal_ex(ctx_, plaintext + total, &final_length) != 1) {
            ERR_clear_error();
            throw AuthenticationError("Неверный пароль или файл повреждён.");
        }
        total += final_length;

        if (total != static_cast<int>(plaintext_size)) {
            throw AuthenticationError("Неверный пароль или файл повреждён.");
        }
    }

private:
    const unsigned char* key_ = nullptr;
    EVP_CIPHER* cipher_ = nullptr;
    EVP_CIPHER_CTX* ctx_ = nullptr;
};

} // namespace

void initialize_crypto() {
    ERR_clear_error();
    if (OPENSSL_init_crypto(OPENSSL_INIT_NO_LOAD_CONFIG, nullptr) != 1) {
        throw Error("Не удалось инициализировать OpenSSL: " +
                    openssl_error_string());
    }
}

SecureBuffer random_bytes(std::size_t count) {
    if (count == 0 || count > static_cast<std::size_t>(INT_MAX)) {
        throw Error("Внутренняя ошибка: неверный размер случайных данных.");
    }
    SecureBuffer result(count);
    if (RAND_bytes(result.data(), static_cast<int>(count)) != 1) {
        throw Error("Криптографический генератор случайных чисел недоступен.");
    }
    return result;
}

SecureBuffer derive_file_key(const SecureBuffer& password,
                             const Header& header) {
    if (password.empty()) {
        throw Error("Пароль не может быть пустым.");
    }
    if (password.size() > MAX_PASSWORD_BYTES) {
        throw Error("Пароль слишком длинный.");
    }

    std::uint32_t memory_kib = header.memory_kib;
    std::uint32_t iterations = header.iterations;
    std::uint32_t lanes = header.lanes;
    std::uint32_t version = 0x13;
    std::uint32_t threads = lanes > 1 ? lanes : 1;
    std::uint32_t early_clean = 1;

    ThreadPoolSetting thread_setting(threads);
    if (!thread_setting.enabled()) {
        threads = 1;
    }

    SecureBuffer key(KEY_SIZE);
    EVP_KDF* kdf = nullptr;
    EVP_KDF_CTX* ctx = nullptr;

    ERR_clear_error();
    kdf = EVP_KDF_fetch(nullptr, "ARGON2ID", nullptr);
    if (kdf == nullptr) {
        throw Error("Argon2id недоступен. Требуется OpenSSL 3.2 или новее.");
    }
    ctx = EVP_KDF_CTX_new(kdf);
    if (ctx == nullptr) {
        EVP_KDF_free(kdf);
        throw Error("Не удалось создать контекст Argon2id.");
    }

    OSSL_PARAM params[10];
    std::size_t index = 0;
    params[index++] = OSSL_PARAM_construct_uint32(
        OSSL_KDF_PARAM_ARGON2_MEMCOST, &memory_kib);
    params[index++] = OSSL_PARAM_construct_uint32(
        OSSL_KDF_PARAM_ITER, &iterations);
    params[index++] = OSSL_PARAM_construct_uint32(
        OSSL_KDF_PARAM_ARGON2_LANES, &lanes);
    params[index++] = OSSL_PARAM_construct_uint32(
        OSSL_KDF_PARAM_ARGON2_VERSION, &version);
    params[index++] = OSSL_PARAM_construct_uint32(
        OSSL_KDF_PARAM_THREADS, &threads);
    params[index++] = OSSL_PARAM_construct_uint32(
        OSSL_KDF_PARAM_EARLY_CLEAN, &early_clean);
    params[index++] = OSSL_PARAM_construct_octet_string(
        OSSL_KDF_PARAM_SALT, const_cast<unsigned char*>(header.salt.data()),
        header.salt.size());
    params[index++] = OSSL_PARAM_construct_octet_string(
        OSSL_KDF_PARAM_PASSWORD, const_cast<unsigned char*>(password.data()),
        password.size());
    params[index++] = OSSL_PARAM_construct_octet_string(
        OSSL_KDF_PARAM_ARGON2_AD,
        const_cast<unsigned char*>(ARGON2_ASSOCIATED_DATA),
        sizeof(ARGON2_ASSOCIATED_DATA) - 1);
    params[index++] = OSSL_PARAM_construct_end();

    const int ok = EVP_KDF_derive(ctx, key.data(), key.size(), params);
    if (ok != 1) {
        const std::string details = openssl_error_string();
        EVP_KDF_CTX_free(ctx);
        EVP_KDF_free(kdf);
        throw Error("Не удалось вычислить ключ Argon2id: " + details);
    }

    EVP_KDF_CTX_free(ctx);
    EVP_KDF_free(kdf);
    return key;
}

void encrypt_chunk(const SecureBuffer& key,
                   const Header& header,
                   const std::array<unsigned char, HEADER_SIZE>& header_bytes,
                   std::uint32_t chunk_index,
                   bool final_chunk,
                   const unsigned char* plaintext,
                   std::size_t plaintext_size,
                   unsigned char* ciphertext,
                   std::array<unsigned char, TAG_SIZE>& tag) {
    AeadCipher cipher(key);
    cipher.encrypt(header, header_bytes, chunk_index, final_chunk, plaintext,
                   plaintext_size, ciphertext, tag);
}

void decrypt_chunk(const SecureBuffer& key,
                   const Header& header,
                   const std::array<unsigned char, HEADER_SIZE>& header_bytes,
                   std::uint32_t chunk_index,
                   bool final_chunk,
                   const unsigned char* ciphertext,
                   std::size_t plaintext_size,
                   const std::array<unsigned char, TAG_SIZE>& tag,
                   unsigned char* plaintext) {
    AeadCipher cipher(key);
    cipher.decrypt(header, header_bytes, chunk_index, final_chunk, ciphertext,
                   plaintext_size, tag, plaintext);
}

} // namespace fcrypt
