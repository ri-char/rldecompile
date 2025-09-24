cmake_minimum_required(VERSION 3.15)
cmake_policy(SET CMP0091 NEW)

project(function-range-dump)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
add_compile_options(
  "$<$<CXX_COMPILER_ID:GNU,Clang,AppleClang>:-fno-rtti;-Wall>"
  "$<$<AND:$<CXX_COMPILER_ID:GNU>,$<CONFIG:DEBUG>>:-fno-omit-frame-pointer>"
)


find_package(LLVM REQUIRED CONFIG)
find_package(Clang REQUIRED)
find_package(nlohmann_json 3.12.0 REQUIRED)

separate_arguments(LLVM_DEFINITIONS_LIST NATIVE_COMMAND ${LLVM_DEFINITIONS})
add_definitions(${LLVM_DEFINITIONS_LIST})
include_directories(${LLVM_INCLUDE_DIRS} ${CLANG_INCLUDE_DIRS})

include_directories(${PROJECT_SOURCE_DIR}/src)
aux_source_directory(${PROJECT_SOURCE_DIR}/src  src)

add_library(FunctionRange SHARED ${src})
target_link_libraries(FunctionRange PRIVATE nlohmann_json::nlohmann_json)
