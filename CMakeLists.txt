cmake_minimum_required(VERSION 3.16)

set(BPFTOOL bpftool CACHE STRING "bpftool executable")
set(PATCHELF patchelf CACHE STRING "patchelf executable")

project(scion-bpf)

find_package(Boost REQUIRED COMPONENTS json)
find_package(Threads REQUIRED)

if (NOT CMAKE_C_COMPILER_ID STREQUAL "Clang")
    message(FATAL_ERROR
        "BPF source files must be compiled by clang.\n"
        "Specify '-DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++' on the command line."
    )
endif()

add_compile_options(-Wall -Werror -march=native)

# Create a copy of libbpf.so with an explicit dependency on libelf patched in, so Python's ctypes
# module loads the library correctly.
add_custom_target(libbpfpy ALL DEPENDS libbpf.so.0.6.0)
add_custom_command(
    OUTPUT libbpf.so.0.6.0
    COMMAND patchelf ${CMAKE_SOURCE_DIR}/libbpf/src/libbpf.so.0.6.0 --add-needed libelf.so.1
    --output ${CMAKE_CURRENT_BINARY_DIR}/libbpf.so.0.6.0
)

add_subdirectory(libbpfpp)
add_subdirectory(aes)
add_subdirectory(br)
