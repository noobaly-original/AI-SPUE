cmake_minimum_required(VERSION 3.21)

project(
    ModA_Outdated_1_6_1170
    VERSION 1.2.0
    LANGUAGES CXX
)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(CommonLibSSE CONFIG REQUIRED)

add_commonlibsse_plugin(
    ${PROJECT_NAME}
    AUTHOR "ModAuthor"
    SOURCES
        src/main.cpp
)

target_compile_options(${PROJECT_NAME} PRIVATE /W4 /WX /utf-8)
target_precompile_headers(${PROJECT_NAME} PRIVATE src/PCH.h)
