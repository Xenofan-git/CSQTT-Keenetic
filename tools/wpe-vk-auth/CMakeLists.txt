cmake_minimum_required(VERSION 3.20)
project(wpe-vk-auth C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

find_package(PkgConfig REQUIRED)
pkg_check_modules(WPE REQUIRED IMPORTED_TARGET wpe-webkit-2.0)
pkg_check_modules(WPE_PLATFORM REQUIRED IMPORTED_TARGET wpe-platform-2.0)

add_executable(wpe-vk-auth src/main.c)
target_link_libraries(wpe-vk-auth PRIVATE PkgConfig::WPE PkgConfig::WPE_PLATFORM)
