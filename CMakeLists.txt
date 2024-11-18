cmake_minimum_required(VERSION 3.12)
project(apfree-wifidog 
  VERSION 1.0.0
  DESCRIPTION "ApFree WiFiDog"
  LANGUAGES C)

# Set C standard and module path
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake/Modules" ${CMAKE_MODULE_PATH})

# Options
option(AW_DEBUG "Build with debug support" ON)
option(AW_FW3 "Build with iptables support" OFF)

# Required packages
include(FindPackageHandleStandardArgs)

# Find and include dependencies
find_package(LibEvent REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(JSON-C REQUIRED)
find_package(UCI REQUIRED)

# Set installation directory
if(NOT DEFINED LIB_INSTALL_DIR)
    set(LIB_INSTALL_DIR lib)
endif()

# Include directories
include_directories(
    ${JSON-C_INCLUDE_DIR}
    ${UCI_INCLUDE_DIR}
)

# Add subdirectories
add_subdirectory(src)
