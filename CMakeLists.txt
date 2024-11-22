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
find_package(PkgConfig REQUIRED)

# Find and include dependencies
find_package(LibEvent REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(JSON-C REQUIRED)
find_package(UCI REQUIRED)

if (NOT AW_FW3)
    pkg_check_modules(NFTABLES REQUIRED libnftables)
    if(NFTABLES_FOUND)
     include_directories(${NFTABLES_INCLUDE_DIRS})
     link_directories(${NFTABLES_LIBRARY_DIRS})
     set(NFTABLES_LIBRARIES ${NFTABLES_LIBRARIES})
    else()
     message(FATAL_ERROR "libnftables not found")
    endif()
endif()

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
