cmake_minimum_required(VERSION 3.16)

project(aes)

# AES library (native)
add_library(aes STATIC
    src/aes.c
    src/aes_hw_accel.c
)
target_include_directories(aes PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)

# Tests for the AES library (native)
add_executable(aes-test
    src/test/aes_test.cpp
)
target_compile_features(aes-test PRIVATE cxx_std_20)
target_link_libraries(aes-test PRIVATE aes)

# Very basic AES run time measurement (native)
add_executable(aes-benchmark
    src/tools/aes_benchmark.cpp
)
target_compile_features(aes-benchmark PRIVATE cxx_std_20)
target_link_libraries(aes-benchmark PRIVATE aes)

# Loaded for AES tests in XDP (native)
add_executable(xdp-loader
    src/xdp_loader.cpp
)
target_compile_features(xdp-loader PRIVATE cxx_std_20)
target_link_libraries(xdp-loader PRIVATE bpfpp)
target_link_libraries(xdp-loader PRIVATE aes)
target_link_libraries(xdp-loader PRIVATE Threads::Threads)

# AES in XDP (BPF)
add_library(xdp_aes_objs OBJECT # compile without linking
    src/bpf/xdp_aes.c
    src/aes.c
)
target_compile_options(xdp_aes_objs PRIVATE -target bpf -O2 -g)
target_include_directories(xdp_aes_objs PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_include_directories(xdp_aes_objs PRIVATE ${CMAKE_SOURCE_DIR}/libbpf/src)
target_include_directories(xdp_aes_objs PRIVATE ${CMAKE_SOURCE_DIR}/include)

add_custom_target(xdp_aes ALL DEPENDS xdp_aes.o) # custom target for linking
add_dependencies(xdp_aes xdp_aes_objs)
add_custom_command(
    OUTPUT xdp_aes.o
    COMMAND ${BPFTOOL} gen object xdp_aes.o "$<TARGET_OBJECTS:xdp_aes_objs>"
    COMMAND_EXPAND_LISTS
    DEPENDS src/bpf/xdp_aes.c src/aes.c
)
