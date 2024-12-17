cmake_minimum_required(VERSION 3.12)

project(apfree-wifidog 
  VERSION 1.0.0
  DESCRIPTION "ApFree WiFiDog"
  LANGUAGES C)

INCLUDE(GNUInstallDirs)

# Set C standard and module path
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Options
option(AW_DEBUG "Build with debug support" OFF)
option(AW_FW3 "Build with iptables support" OFF)

# Find requried headers file
find_package(PkgConfig REQUIRED)

find_path(UCI_INCLUDE_DIRS uci.h)

# Find dependencies using pkg-config
pkg_check_modules(LIBEVENT REQUIRED libevent)
pkg_check_modules(OPENSSL REQUIRED openssl)
pkg_check_modules(JSONC REQUIRED json-c)
pkg_check_modules(MOSQUITTO REQUIRED libmosquitto)
pkg_check_modules(NFQUEUE REQUIRED libnetfilter_queue)


if (NOT AW_FW3)
  pkg_check_modules(NFTNL REQUIRED libnftnl)
  pkg_check_modules(MNL REQUIRED libmnl)
endif()

# Set installation directory
if(NOT DEFINED LIB_INSTALL_DIR)
    set(LIB_INSTALL_DIR lib)
endif()

# Include directories
include_directories(
    ${JSONC_INCLUDE_DIRS}
    ${UCI_INCLUDE_DIRS}
    ${LIBEVENT_INCLUDE_DIRS}
    ${OPENSSL_INCLUDE_DIRS}
)

# Add subdirectories
add_subdirectory(src)
