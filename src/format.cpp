#include "fcrypt.hpp"

#include <algorithm>
#include <cstring>
#include <limits>

namespace fcrypt {
namespace {

constexpr std::array<unsigned char, 8> MAGIC = {
    'F', 'C', 'R', 'Y', 'P', 'T', '0', '1'
};
constexpr std::uint16_t CIPHER_CHACHA20_POLY1305 = 1;
constexpr std::uint16_t KDF_ARGON2ID = 1;
constexpr std::uint32_t ARGON2_VERSION_19 = 0x13;

constexpr std::size_t OFF_CIPHER = 8;
constexpr std::size_t OFF_KDF = 10;
constexpr std::size_t OFF_KDF_VERSION = 12;
constexpr std::size_t OFF_MEMORY = 16;
constexpr std::size_t OFF_ITERATIONS = 20;
constexpr std::size_t OFF_LANES = 24;
constexpr std::size_t OFF_CHUNK_SIZE = 28;
constexpr std::size_t OFF_PLAINTEXT_SIZE = 32;
constexpr std::size_t OFF_SALT = 40;
constexpr std::size_t OFF_NONCE = 72;

void put_u16(unsigned char* out, std::uint16_t value) {
    out[0] = static_cast<unsigned char>((value >> 8) & 0xff);
    out[1] = static_cast<unsigned char>(value & 0xff);
}

void put_u32(unsigned char* out, std::uint32_t value) {
    out[0] = static_cast<unsigned char>((value >> 24) & 0xff);
    out[1] = static_cast<unsigned char>((value >> 16) & 0xff);
    out[2] = static_cast<unsigned char>((value >> 8) & 0xff);
    out[3] = static_cast<unsigned char>(value & 0xff);
}

void put_u64(unsigned char* out, std::uint64_t value) {
    for (int i = 7; i >= 0; --i) {
        out[7 - i] = static_cast<unsigned char>((value >> (i * 8)) & 0xff);
    }
}

std::uint16_t get_u16(const unsigned char* in) {
    return static_cast<std::uint16_t>(
        (static_cast<std::uint16_t>(in[0]) << 8) |
        static_cast<std::uint16_t>(in[1]));
}

std::uint32_t get_u32(const unsigned char* in) {
    return (static_cast<std::uint32_t>(in[0]) << 24) |
           (static_cast<std::uint32_t>(in[1]) << 16) |
           (static_cast<std::uint32_t>(in[2]) << 8) |
           static_cast<std::uint32_t>(in[3]);
}

std::uint64_t get_u64(const unsigned char* in) {
    std::uint64_t result = 0;
    for (int i = 0; i < 8; ++i) {
        result = (result << 8) | static_cast<std::uint64_t>(in[i]);
    }
    return result;
}

void validate_kdf_params(std::uint32_t memory_kib,
                         std::uint32_t iterations,
                         std::uint32_t lanes) {
    if (memory_kib < MIN_KDF_MEMORY_KIB ||
        memory_kib > MAX_KDF_MEMORY_KIB ||
        iterations < MIN_KDF_ITERATIONS ||
        iterations > MAX_KDF_ITERATIONS ||
        lanes < MIN_KDF_LANES ||
        lanes > MAX_KDF_LANES) {
        throw Error("Недопустимые параметры Argon2id.");
    }
    // Argon2 requires at least 8 blocks (1 KiB each) per lane.
    if (static_cast<std::uint64_t>(memory_kib) < 8ull * lanes) {
        throw Error("Недопустимые параметры Argon2id: слишком мало памяти для выбранного числа потоков.");
    }
}

} // namespace

std::uint64_t chunk_count(std::uint64_t plaintext_size,
                          std::uint32_t chunk_size) {
    if (chunk_size == 0) {
        throw Error("Недопустимый размер блока.");
    }
    if (plaintext_size == 0) {
        return 1; // Even an empty file has one authenticated (empty) chunk.
    }
    return (plaintext_size - 1) / chunk_size + 1;
}

std::uint64_t encrypted_file_size(const Header& header) {
    const std::uint64_t chunks = chunk_count(header.plaintext_size,
                                             header.chunk_size);
    if (chunks > static_cast<std::uint64_t>(std::numeric_limits<std::uint32_t>::max())) {
        throw Error("Файл слишком велик для этого формата.");
    }

    const std::uint64_t overhead = chunks * static_cast<std::uint64_t>(TAG_SIZE);
    if (header.plaintext_size >
        std::numeric_limits<std::uint64_t>::max() - HEADER_SIZE - overhead) {
        throw Error("Файл слишком велик для этого формата.");
    }
    return static_cast<std::uint64_t>(HEADER_SIZE) +
           header.plaintext_size + overhead;
}

std::array<unsigned char, HEADER_SIZE> serialize_header(const Header& header) {
    validate_kdf_params(header.memory_kib, header.iterations, header.lanes);
    if (header.chunk_size < MIN_CHUNK_SIZE ||
        header.chunk_size > MAX_CHUNK_SIZE) {
        throw Error("Недопустимый размер блока.");
    }
    if (chunk_count(header.plaintext_size, header.chunk_size) >
        static_cast<std::uint64_t>(std::numeric_limits<std::uint32_t>::max())) {
        throw Error("Файл слишком велик для этого формата.");
    }

    std::array<unsigned char, HEADER_SIZE> out{};
    std::copy(MAGIC.begin(), MAGIC.end(), out.begin());
    put_u16(out.data() + OFF_CIPHER, CIPHER_CHACHA20_POLY1305);
    put_u16(out.data() + OFF_KDF, KDF_ARGON2ID);
    put_u32(out.data() + OFF_KDF_VERSION, ARGON2_VERSION_19);
    put_u32(out.data() + OFF_MEMORY, header.memory_kib);
    put_u32(out.data() + OFF_ITERATIONS, header.iterations);
    put_u32(out.data() + OFF_LANES, header.lanes);
    put_u32(out.data() + OFF_CHUNK_SIZE, header.chunk_size);
    put_u64(out.data() + OFF_PLAINTEXT_SIZE, header.plaintext_size);
    std::copy(header.salt.begin(), header.salt.end(),
              out.begin() + static_cast<std::ptrdiff_t>(OFF_SALT));
    std::copy(header.nonce_prefix.begin(), header.nonce_prefix.end(),
              out.begin() + static_cast<std::ptrdiff_t>(OFF_NONCE));
    return out;
}

Header parse_header(const std::array<unsigned char, HEADER_SIZE>& bytes) {
    const bool magic_ok = std::equal(MAGIC.begin(), MAGIC.end(), bytes.begin());
    if (!magic_ok) {
        bool prefix_ok = true;
        for (std::size_t i = 0; i < 6; ++i) {
            if (bytes[i] != MAGIC[i]) {
                prefix_ok = false;
                break;
            }
        }
        if (prefix_ok) {
            throw Error("Неподдерживаемая версия формата fcrypt.");
        }
        throw Error("Это не файл fcrypt или его заголовок повреждён.");
    }

    if (get_u16(bytes.data() + OFF_CIPHER) != CIPHER_CHACHA20_POLY1305) {
        throw Error("Неподдерживаемый алгоритм шифрования.");
    }
    if (get_u16(bytes.data() + OFF_KDF) != KDF_ARGON2ID) {
        throw Error("Неподдерживаемый алгоритм формирования ключа.");
    }
    if (get_u32(bytes.data() + OFF_KDF_VERSION) != ARGON2_VERSION_19) {
        throw Error("Неподдерживаемая версия Argon2.");
    }

    Header header;
    header.memory_kib = get_u32(bytes.data() + OFF_MEMORY);
    header.iterations = get_u32(bytes.data() + OFF_ITERATIONS);
    header.lanes = get_u32(bytes.data() + OFF_LANES);
    header.chunk_size = get_u32(bytes.data() + OFF_CHUNK_SIZE);
    header.plaintext_size = get_u64(bytes.data() + OFF_PLAINTEXT_SIZE);

    validate_kdf_params(header.memory_kib, header.iterations, header.lanes);
    if (header.chunk_size < MIN_CHUNK_SIZE ||
        header.chunk_size > MAX_CHUNK_SIZE) {
        throw Error("Повреждённый заголовок: недопустимый размер блока.");
    }
    if (chunk_count(header.plaintext_size, header.chunk_size) >
        static_cast<std::uint64_t>(std::numeric_limits<std::uint32_t>::max())) {
        throw Error("Повреждённый заголовок: слишком большое значение размера.");
    }

    std::copy(bytes.begin() + static_cast<std::ptrdiff_t>(OFF_SALT),
              bytes.begin() + static_cast<std::ptrdiff_t>(OFF_SALT + SALT_SIZE),
              header.salt.begin());
    std::copy(bytes.begin() + static_cast<std::ptrdiff_t>(OFF_NONCE),
              bytes.begin() + static_cast<std::ptrdiff_t>(OFF_NONCE + NONCE_PREFIX_SIZE),
              header.nonce_prefix.begin());
    return header;
}

} // namespace fcrypt
