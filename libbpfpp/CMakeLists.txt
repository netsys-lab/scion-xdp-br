cmake_minimum_required(VERSION 3.16)

project(libbpfpp)

# Import libbpf as cmake target
add_library(libbpf SHARED IMPORTED GLOBAL)
target_include_directories(libbpf INTERFACE ${CMAKE_SOURCE_DIR}/libbpf/src)
set_target_properties(libbpf PROPERTIES IMPORTED_LOCATION ${CMAKE_SOURCE_DIR}/libbpf/src/libbpf.so)

# C++ wrapper for some parts of libbpf (libbpfpp)
add_library(bpfpp OBJECT
    src/error.cpp
    src/map.cpp
    src/util.cpp
)
target_compile_features(bpfpp PUBLIC cxx_std_17)
target_include_directories(bpfpp PUBLIC ${PROJECT_SOURCE_DIR}/include)
target_link_libraries(bpfpp PUBLIC libbpf)
target_link_libraries(bpfpp PUBLIC elf)
