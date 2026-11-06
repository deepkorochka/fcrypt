cmake_minimum_required(VERSION 3.16)

project(fcrypt VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(FCRYPT_STATIC "Link the executable and OpenSSL statically (MinGW builds)" OFF)

if(FCRYPT_STATIC)
    set(OPENSSL_USE_STATIC_LIBS TRUE)
endif()

find_package(OpenSSL 3.2 REQUIRED COMPONENTS Crypto)

add_executable(fcrypt
    src/main.cpp
    src/crypto.cpp
    src/format.cpp
    src/filecrypt.cpp
    src/password.cpp
    src/platform.cpp
)

target_link_libraries(fcrypt PRIVATE OpenSSL::Crypto)
target_compile_features(fcrypt PRIVATE cxx_std_17)

if(MSVC)
    target_compile_options(fcrypt PRIVATE /W4 /utf-8)
    target_compile_definitions(fcrypt PRIVATE NOMINMAX WIN32_LEAN_AND_MEAN _WIN32_WINNT=0x0601)
else()
    target_compile_options(fcrypt PRIVATE
        -Wall -Wextra -Wpedantic -Wshadow -Wformat=2
    )
endif()

if(WIN32)
    target_compile_definitions(fcrypt PRIVATE WIN32_LEAN_AND_MEAN _WIN32_WINNT=0x0601)
    target_link_libraries(fcrypt PRIVATE bcrypt ws2_32 crypt32 user32 advapi32)
endif()

if(MINGW)
    target_link_options(fcrypt PRIVATE -municode)
    if(FCRYPT_STATIC)
        target_link_options(fcrypt PRIVATE
            -static
            -static-libgcc
            -static-libstdc++
        )
    endif()
endif()

set_target_properties(fcrypt PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)
