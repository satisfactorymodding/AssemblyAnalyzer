cmake_minimum_required(VERSION 3.12)
project(AssemblyAnalyzer)

set(CMAKE_CXX_STANDARD 17)

option(ZYDIS_BUILD_TOOLS "" OFF)
option(ZYDIS_BUILD_EXAMPLES "" OFF)
add_subdirectory("dependencies/zydis")

file(GLOB source_list "src/*")
add_library(AssemblyAnalyzer STATIC ${source_list})
target_compile_definitions(AssemblyAnalyzer PRIVATE BUILDING_ASSEMBLY_ANALYZER)

target_link_libraries(AssemblyAnalyzer PRIVATE "Zydis")