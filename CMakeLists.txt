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
option(AW_VPP "Build with VPP support" OFF)
option(ENABLE_XDPI_FEATURE "Enable xDPI protocol detection and session tracking" ON)

# VPP-specific variables (added)
if(AW_VPP)
  set(VPP_INCLUDE_DIR "" CACHE PATH "Path to VPP include directory")
  set(VPP_LIBRARY_DIR "" CACHE PATH "Path to VPP library directory")
  
  message(STATUS "VPP_INCLUDE_DIR: ${VPP_INCLUDE_DIR}")
  message(STATUS "VPP_LIBRARY_DIR: ${VPP_LIBRARY_DIR}")
endif()

# Find requried headers file
find_package(PkgConfig REQUIRED)

find_path(UCI_INCLUDE_DIRS uci.h)
if(NOT UCI_INCLUDE_DIRS)
    message(FATAL_ERROR "UCI headers not found. Please install libuci-dev.")
endif()

# Find dependencies using pkg-config
pkg_check_modules(LIBEVENT REQUIRED libevent)
pkg_check_modules(OPENSSL REQUIRED openssl)
pkg_check_modules(JSONC REQUIRED json-c)
pkg_check_modules(MOSQUITTO REQUIRED libmosquitto)
pkg_check_modules(NFQUEUE REQUIRED libnetfilter_queue)
pkg_check_modules(BPF REQUIRED libbpf)


if (NOT AW_FW3)
  pkg_check_modules(NFTNL REQUIRED libnftnl)
  pkg_check_modules(MNL REQUIRED libmnl)
endif()

# Set installation directory
if(NOT DEFINED LIB_INSTALL_DIR)
    set(LIB_INSTALL_DIR lib)
endif()

if (AW_VPP)
  # Add VPP includes and libraries (modified)
  include_directories(${VPP_INCLUDE_DIR})
  link_directories(${VPP_LIBRARY_DIR})

  find_library(VPPINFRA_LIB vppinfra PATHS ${VPP_LIBRARY_DIR})
  find_library(VLIBMEMORYCLIENT_LIB vlibmemoryclient PATHS ${VPP_LIBRARY_DIR})
  find_library(VLIBAPI_LIB vlibapi PATHS ${VPP_LIBRARY_DIR})
  find_library(SVM_LIB svm PATHS ${VPP_LIBRARY_DIR})
  find_library(VPPAPICLIENT_LIB vppapiclient PATHS ${VPP_LIBRARY_DIR})

  # Define VPP libraries to link
  set(VPP_LIBS
    ${VPPINFRA_LIB}
    ${VLIBMEMORYCLIENT_LIB}
    ${VLIBAPI_LIB}
    ${SVM_LIB}
    ${VPPAPICLIENT_LIB}
  )
endif()

# Include directories
include_directories(
    ${JSONC_INCLUDE_DIRS}
    ${UCI_INCLUDE_DIRS}
    ${LIBEVENT_INCLUDE_DIRS}
    ${OPENSSL_INCLUDE_DIRS}
    ${MOSQUITTO_INCLUDE_DIRS}
)

# Add subdirectories
add_subdirectory(src)
add_subdirectory(ebpf)
