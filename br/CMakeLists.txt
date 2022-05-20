cmake_minimum_required(VERSION 3.16)

project(xdp-br)

set(ENABLE_IPV4 ON CACHE BOOL "Enable IPv4 support")
set(ENABLE_IPV6 ON CACHE BOOL "Enable IPv6 support")
set(ENABLE_SCION_PATH ON CACHE BOOL "Enable support for standard SCION paths")
set(ENABLE_HF_CHECK ON CACHE BOOL "Enable cryptographic hop field verification")

# XDP Border Router Loader
add_executable(br-loader
    src/br_loader.cpp
    src/config.cpp
    src/ifindex.cpp
    src/maps.cpp
    src/stats.cpp
)
target_compile_features(br-loader PRIVATE cxx_std_20)
target_include_directories(br-loader PRIVATE ${CMAKE_SOURCE_DIR}/include)
target_include_directories(br-loader PRIVATE ${CMAKE_SOURCE_DIR}/dependencies)
target_link_libraries(br-loader PRIVATE bpfpp)
target_link_libraries(br-loader PRIVATE aes)
target_link_libraries(br-loader PRIVATE Boost::json)
target_link_libraries(br-loader PRIVATE Threads::Threads)

# XDP Border Router (BPF)
set(XDP_BR_SRC src/bpf/xdp.c)
if(ENABLE_HF_CHECK)
    list(APPEND XDP_BR_SRC ${CMAKE_SOURCE_DIR}/aes/src/aes.c)
endif()
add_library(xdp_br_objs OBJECT # compile without linking
    ${XDP_BR_SRC}
)
target_compile_options(xdp_br_objs PRIVATE -target bpf -O2 -g)
target_include_directories(xdp_br_objs PRIVATE ${CMAKE_SOURCE_DIR}/libbpf/src)
target_include_directories(xdp_br_objs PRIVATE ${CMAKE_SOURCE_DIR}/include)
target_include_directories(xdp_br_objs PRIVATE ${CMAKE_SOURCE_DIR}/aes/include)

add_custom_target(xdp_br ALL DEPENDS xdp_br.o) # custom target for linking
add_dependencies(xdp_br xdp_br_objs)
add_custom_command(
    OUTPUT xdp_br.o
    COMMAND ${BPFTOOL} gen object xdp_br.o "$<TARGET_OBJECTS:xdp_br_objs>"
    COMMAND_EXPAND_LISTS
    DEPENDS "$<TARGET_OBJECTS:xdp_br_objs>"
)

# Configure optional features
if(ENABLE_IPV4)
    target_compile_definitions(br-loader PUBLIC ENABLE_IPV4)
    target_compile_definitions(xdp_br_objs PUBLIC ENABLE_IPV4)
endif()
if(ENABLE_IPV6)
    target_compile_definitions(br-loader PUBLIC ENABLE_IPV6)
    target_compile_definitions(xdp_br_objs PUBLIC ENABLE_IPV6)
endif()
if(ENABLE_SCION_PATH)
    target_compile_definitions(br-loader PUBLIC ENABLE_SCION_PATH)
    target_compile_definitions(xdp_br_objs PUBLIC ENABLE_SCION_PATH)
endif()
if(ENABLE_HF_CHECK)
    target_compile_definitions(br-loader PUBLIC ENABLE_HF_CHECK)
    target_compile_definitions(xdp_br_objs PUBLIC ENABLE_HF_CHECK)
endif()

# XDP Pass Program (BPF)
add_library(xdp_pass_objs OBJECT
    src/bpf/xdp_pass.c
)
target_compile_options(xdp_pass_objs PRIVATE -target bpf -O2 -g)

add_custom_target(xdp_pass ALL DEPENDS xdp_pass.c.o) # copy object file(s) to output directory
add_dependencies(xdp_pass xdp_pass_objs)
add_custom_command(
    OUTPUT xdp_pass.c.o
    COMMAND ${CMAKE_COMMAND} -E copy_if_different "$<TARGET_OBJECTS:xdp_pass_objs>"
    ${CMAKE_CURRENT_BINARY_DIR}
    COMMAND_EXPAND_LISTS
    DEPENDS "$<TARGET_OBJECTS:xdp_pass_objs>"
)
