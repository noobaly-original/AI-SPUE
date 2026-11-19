cmake_minimum_required(VERSION 3.21)

project(
    ModB_RawSKSE_Legacy
    VERSION 1.0.0
    LANGUAGES CXX
)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(${PROJECT_NAME} SHARED
    src/main.cpp
    src/versionlibdb.h
)

target_include_directories(${PROJECT_NAME} PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/src"
    "$ENV{SKSE_SDK_ROOT}/skse64"
)
