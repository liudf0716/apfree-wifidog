cmake_minimum_required(VERSION 2.8.12)
project(ApFreeWiFidog C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/Modules/")

option(AW_DEBUG		"Build debug"	ON)
option(AW_WEBSSH	"Build with web ssh support"	OFF)
option(AW_FW3   "Build with fw3 support"	OFF)

find_package(LibEvent)
if(NOT LibEvent_FOUND)
  message(FATAL_ERROR "libevent2 not found!")
endif(NOT LibEvent_FOUND)

find_package(OpenSSL)
if(NOT OPENSSL_FOUND)
  message(FATAL_ERROR "OpenSSL not found!")
endif(NOT OPENSSL_FOUND)

find_package(JSON-C REQUIRED)
include_directories(${JSON-C_INCLUDE_DIR})

find_package(UCI REQUIRED)
include_directories(${UCI_INCLUDE_DIR})

if(LIB_INSTALL_DIR)
else()
  set(LIB_INSTALL_DIR lib)
endif()

add_subdirectory(src)
