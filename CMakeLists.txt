cmake_minimum_required(VERSION 2.6)

project(ApFreeWiFidog C)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/Modules/")

find_package(CURL)
if(NOT CURL_FOUND)
  message(FATAL_ERROR "libcurl not found!")
endif(NOT CURL_FOUND)

find_package(LibEvent)
if(NOT LibEvent_FOUND)
  message(FATAL_ERROR "libevent2 not found!")
endif(NOT LibEvent_FOUND)

find_package(OpenSSL)
if(NOT OPENSSL_FOUND)
  message(FATAL_ERROR "OpenSSL not found!")
endif(NOT OPENSSL_FOUND)

if(LIB_INSTALL_DIR)
else()
  set(LIB_INSTALL_DIR lib)
endif()

add_subdirectory(src)
add_subdirectory(libhttpd)
