cmake_minimum_required(VERSION 3.12)

project(apfree-wifidog 
  VERSION 1.0.0
  DESCRIPTION "ApFree WiFiDog"
  LANGUAGES C)

INCLUDE(GNUInstallDirs)

# Set C standard and module path
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Prefer locally installed libraries (source-built deps land in /usr/local)
set(ENV{PKG_CONFIG_PATH} "/usr/local/lib/pkgconfig:/usr/local/lib64/pkgconfig:/usr/lib/pkgconfig:/usr/lib/x86_64-linux-gnu/pkgconfig:$ENV{PKG_CONFIG_PATH}")

set(_AW_APT_UPDATED FALSE)

function(aw_apt_update_once)
  if(_AW_APT_UPDATED)
    return()
  endif()
  find_program(APT_GET_EXECUTABLE apt-get)
  if(NOT APT_GET_EXECUTABLE)
    return()
  endif()
  message(STATUS "Updating apt package lists...")
  execute_process(
    COMMAND sudo ${APT_GET_EXECUTABLE} update
    RESULT_VARIABLE APT_UPDATE_RESULT
  )
  if(NOT APT_UPDATE_RESULT EQUAL 0)
    message(WARNING "apt-get update failed; will still try to install packages")
  endif()
  set(_AW_APT_UPDATED TRUE PARENT_SCOPE)
endfunction()

function(try_apt_install)
  if(NOT ARGN)
    return()
  endif()
  find_program(APT_GET_EXECUTABLE apt-get)
  if(NOT APT_GET_EXECUTABLE)
    message(STATUS "apt-get not found; skip auto-install of: ${ARGN}")
    return()
  endif()
  aw_apt_update_once()
  message(STATUS "Installing via apt: ${ARGN}")
  execute_process(
    COMMAND sudo ${APT_GET_EXECUTABLE} install -y ${ARGN}
    RESULT_VARIABLE INSTALL_RESULT
  )
  if(NOT INSTALL_RESULT EQUAL 0)
    message(WARNING "Failed to auto-install ${ARGN}. Please install manually: sudo apt-get install ${ARGN}")
  else()
    message(STATUS "Successfully installed ${ARGN}")
  endif()
endfunction()

function(aw_refresh_pkg PREFIX)
  foreach(_s FOUND INCLUDE_DIRS INCLUDEDIR LIBRARY_DIRS LIBRARIES
           LDFLAGS LDFLAGS_OTHER CFLAGS CFLAGS_OTHER VERSION MODULE_NAME)
    unset(${PREFIX}_${_s} CACHE)
    unset(${PREFIX}_${_s})
  endforeach()
endfunction()

# Install every missing pkg-config module in one apt transaction
function(check_and_install_system_dependencies)
  set(PKG_MAPPING
    "libevent:libevent-dev"
    "openssl:libssl-dev"
    "json-c:libjson-c-dev"
    "libmosquitto:libmosquitto-dev"
    "libnetfilter_queue:libnetfilter-queue-dev"
    "libbpf:libbpf-dev"
    "libnftnl:libnftnl-dev"
    "libmnl:libmnl-dev"
  )

  find_program(PKG_CONFIG_EXECUTABLE pkg-config)
  set(MISSING_DEB)
  foreach(PKG_PAIR ${PKG_MAPPING})
    string(REPLACE ":" ";" PKG_SPLIT ${PKG_PAIR})
    list(GET PKG_SPLIT 0 PKG_NAME)
    list(GET PKG_SPLIT 1 DEB_NAME)

    set(PKG_FOUND 1)
    if(PKG_CONFIG_EXECUTABLE)
      execute_process(
        COMMAND ${PKG_CONFIG_EXECUTABLE} --exists ${PKG_NAME}
        RESULT_VARIABLE PKG_FOUND
        OUTPUT_QUIET
        ERROR_QUIET
      )
    endif()

    if(NOT PKG_FOUND EQUAL 0)
      message(STATUS "Missing library: ${PKG_NAME} (${DEB_NAME})")
      list(APPEND MISSING_DEB ${DEB_NAME})
    endif()
  endforeach()

  if(NOT PKG_CONFIG_EXECUTABLE)
    list(APPEND MISSING_DEB pkg-config)
  endif()

  find_program(GIT_EXECUTABLE git)
  if(NOT GIT_EXECUTABLE)
    list(APPEND MISSING_DEB git)
  endif()

  if(MISSING_DEB)
    list(REMOVE_DUPLICATES MISSING_DEB)
    try_apt_install(${MISSING_DEB})
  else()
    message(STATUS "All packaged dependencies are present")
  endif()
endfunction()

function(aw_ensure_pkg PREFIX PC_NAME DEB_NAME)
  cmake_parse_arguments(A "OPTIONAL" "" "" ${ARGN})
  pkg_check_modules(${PREFIX} QUIET ${PC_NAME})
  if(${PREFIX}_FOUND)
    return()
  endif()

  message(STATUS "${PC_NAME} not found. Attempting to install ${DEB_NAME}...")
  try_apt_install(${DEB_NAME})
  aw_refresh_pkg(${PREFIX})
  pkg_check_modules(${PREFIX} QUIET ${PC_NAME})
  if(${PREFIX}_FOUND)
    message(STATUS "Found ${PC_NAME} after install")
    return()
  endif()

  if(A_OPTIONAL)
    message(WARNING "${PC_NAME} not found. Optional feature disabled. Install: sudo apt-get install ${DEB_NAME}")
  else()
    message(FATAL_ERROR "${PC_NAME} not found. Install with: sudo apt-get install ${DEB_NAME}")
  endif()
endfunction()

# Function to build and install libubox from source
function(build_and_install_libubox)
  find_path(LIBUBOX_INCLUDE_DIRS libubox/uloop.h)
  
  if(NOT LIBUBOX_INCLUDE_DIRS)
    message(STATUS "libubox not found. Building and installing from source...")
    
    set(LIBUBOX_BUILD_DIR "/tmp/libubox-build")
    set(LIBUBOX_INSTALL_PREFIX "/usr/local")
    
    # Create build directory
    file(MAKE_DIRECTORY ${LIBUBOX_BUILD_DIR})
    
    # Clone the repository if not exists
    if(NOT EXISTS "${LIBUBOX_BUILD_DIR}/CMakeLists.txt")
      message(STATUS "Cloning libubox from GitHub...")
      execute_process(
        COMMAND git clone https://github.com/git-openwrt-org-mirror/libubox.git ${LIBUBOX_BUILD_DIR}
        RESULT_VARIABLE CLONE_RESULT
      )
      
      if(NOT CLONE_RESULT EQUAL 0)
        message(FATAL_ERROR "Failed to clone libubox from GitHub")
      endif()
    endif()
    
    # Build and install
    message(STATUS "Building libubox...")
    execute_process(
      COMMAND cmake -DCMAKE_INSTALL_PREFIX=${LIBUBOX_INSTALL_PREFIX} -DBUILD_LUA=OFF -DBUILD_EXAMPLES=OFF .
      WORKING_DIRECTORY ${LIBUBOX_BUILD_DIR}
      RESULT_VARIABLE CMAKE_RESULT
    )
    
    if(NOT CMAKE_RESULT EQUAL 0)
      message(FATAL_ERROR "Failed to configure libubox")
    endif()
    
    execute_process(
      COMMAND make
      WORKING_DIRECTORY ${LIBUBOX_BUILD_DIR}
      RESULT_VARIABLE MAKE_RESULT
    )
    
    if(NOT MAKE_RESULT EQUAL 0)
      message(FATAL_ERROR "Failed to build libubox")
    endif()
    
    message(STATUS "Installing libubox...")
    execute_process(
      COMMAND sudo make install
      WORKING_DIRECTORY ${LIBUBOX_BUILD_DIR}
      RESULT_VARIABLE INSTALL_RESULT
    )
    
    if(NOT INSTALL_RESULT EQUAL 0)
      message(FATAL_ERROR "Failed to install libubox")
    endif()
    
    set(ENV{PKG_CONFIG_PATH} "${LIBUBOX_INSTALL_PREFIX}/lib/pkgconfig:$ENV{PKG_CONFIG_PATH}")
    execute_process(COMMAND sudo ldconfig OUTPUT_QUIET ERROR_QUIET)
    message(STATUS "Successfully installed libubox")
  endif()
endfunction()

# Function to build and install libuci from source
function(build_and_install_libuci)
  find_path(LIBUCI_INCLUDE_DIRS uci.h)
  
  if(NOT LIBUCI_INCLUDE_DIRS)
    message(STATUS "libuci not found. Building and installing from source...")
    
    # First ensure libubox is installed
    build_and_install_libubox()
    
    set(LIBUCI_BUILD_DIR "/tmp/libuci-build")
    set(LIBUCI_INSTALL_PREFIX "/usr/local")
    
    # Create build directory
    file(MAKE_DIRECTORY ${LIBUCI_BUILD_DIR})
    
    # Clone the repository if not exists
    if(NOT EXISTS "${LIBUCI_BUILD_DIR}/CMakeLists.txt")
      message(STATUS "Cloning libuci from GitHub...")
      execute_process(
        COMMAND git clone https://github.com/git-openwrt-org-mirror/uci.git ${LIBUCI_BUILD_DIR}
        RESULT_VARIABLE CLONE_RESULT
      )
      
      if(NOT CLONE_RESULT EQUAL 0)
        message(FATAL_ERROR "Failed to clone libuci from GitHub")
      endif()
    endif()
    
    # Build and install
    message(STATUS "Building libuci...")
    execute_process(
      COMMAND cmake -DCMAKE_INSTALL_PREFIX=${LIBUCI_INSTALL_PREFIX} -DCMAKE_PREFIX_PATH=${LIBUCI_INSTALL_PREFIX} -DBUILD_LUA=OFF -DBUILD_EXAMPLES=OFF .
      WORKING_DIRECTORY ${LIBUCI_BUILD_DIR}
      RESULT_VARIABLE CMAKE_RESULT
    )
    
    if(NOT CMAKE_RESULT EQUAL 0)
      message(FATAL_ERROR "Failed to configure libuci")
    endif()
    
    execute_process(
      COMMAND make
      WORKING_DIRECTORY ${LIBUCI_BUILD_DIR}
      RESULT_VARIABLE MAKE_RESULT
    )
    
    if(NOT MAKE_RESULT EQUAL 0)
      message(FATAL_ERROR "Failed to build libuci")
    endif()
    
    message(STATUS "Installing libuci...")
    execute_process(
      COMMAND sudo make install
      WORKING_DIRECTORY ${LIBUCI_BUILD_DIR}
      RESULT_VARIABLE INSTALL_RESULT
    )
    
    if(NOT INSTALL_RESULT EQUAL 0)
      message(FATAL_ERROR "Failed to install libuci")
    endif()
    
    set(ENV{PKG_CONFIG_PATH} "${LIBUCI_INSTALL_PREFIX}/lib/pkgconfig:$ENV{PKG_CONFIG_PATH}")
    execute_process(COMMAND sudo ldconfig OUTPUT_QUIET ERROR_QUIET)
    message(STATUS "Successfully installed libuci")
  endif()
endfunction()

# Function to build and install libmosquitto from source
function(build_and_install_libmosquitto)
  message(STATUS "libmosquitto not found. Building and installing from source...")

  set(MOSQUITTO_BUILD_DIR "/tmp/libmosquitto-build")
  set(MOSQUITTO_INSTALL_PREFIX "/usr/local")

  file(MAKE_DIRECTORY ${MOSQUITTO_BUILD_DIR})

  if(NOT EXISTS "${MOSQUITTO_BUILD_DIR}/CMakeLists.txt")
    message(STATUS "Cloning mosquitto from GitHub...")
    execute_process(
      COMMAND git clone --depth 1 --branch v2.0.20 https://github.com/eclipse-mosquitto/mosquitto.git ${MOSQUITTO_BUILD_DIR}
      RESULT_VARIABLE CLONE_RESULT
    )

    if(NOT CLONE_RESULT EQUAL 0)
      message(FATAL_ERROR "Failed to clone mosquitto from GitHub")
    endif()
  endif()

  message(STATUS "Building libmosquitto...")
  execute_process(
    COMMAND cmake
      -DCMAKE_INSTALL_PREFIX=${MOSQUITTO_INSTALL_PREFIX}
      -DWITH_DOCS=OFF
      -DDOCUMENTATION=OFF
      -DWITH_CJSON=OFF
      -DWITH_BROKER=OFF
      -DWITH_CLIENTS=OFF
      -DWITH_APPS=OFF
      -DWITH_PLUGINS=OFF
      -DWITH_TLS=ON
      .
    WORKING_DIRECTORY ${MOSQUITTO_BUILD_DIR}
    RESULT_VARIABLE CMAKE_RESULT
  )

  if(NOT CMAKE_RESULT EQUAL 0)
    message(FATAL_ERROR "Failed to configure mosquitto")
  endif()

  execute_process(
    COMMAND make
    WORKING_DIRECTORY ${MOSQUITTO_BUILD_DIR}
    RESULT_VARIABLE MAKE_RESULT
  )

  if(NOT MAKE_RESULT EQUAL 0)
    message(FATAL_ERROR "Failed to build mosquitto")
  endif()

  message(STATUS "Installing libmosquitto...")
  execute_process(
    COMMAND sudo make install
    WORKING_DIRECTORY ${MOSQUITTO_BUILD_DIR}
    RESULT_VARIABLE INSTALL_RESULT
  )

  if(NOT INSTALL_RESULT EQUAL 0)
    message(FATAL_ERROR "Failed to install mosquitto")
  endif()

  set(ENV{PKG_CONFIG_PATH} "${MOSQUITTO_INSTALL_PREFIX}/lib/pkgconfig:$ENV{PKG_CONFIG_PATH}")
  execute_process(COMMAND sudo ldconfig OUTPUT_QUIET ERROR_QUIET)
  message(STATUS "Successfully installed libmosquitto")
endfunction()

# Call the function to check and install dependencies
check_and_install_system_dependencies()

# Build and install libuci and its dependency libubox from source if needed
build_and_install_libuci()

# Options
option(AW_DEBUG "Build with debug support" OFF)
option(AW_FW3 "Build with iptables support" OFF)
option(AW_VPP "Build with VPP support" OFF)
option(ENABLE_XDPI_FEATURE "Enable xDPI protocol detection and session tracking" ON)
option(ENABLE_REMOTE_SHELL "Enable MQTT/WebSocket remote shell operation" OFF)

# VPP-specific variables (added)
if(AW_VPP)
  set(VPP_INCLUDE_DIR "" CACHE PATH "Path to VPP include directory")
  set(VPP_LIBRARY_DIR "" CACHE PATH "Path to VPP library directory")
  
  message(STATUS "VPP_INCLUDE_DIR: ${VPP_INCLUDE_DIR}")
  message(STATUS "VPP_LIBRARY_DIR: ${VPP_LIBRARY_DIR}")
endif()

# Find requried headers file
find_package(PkgConfig REQUIRED)

# Add /usr/local to the search path for locally installed libraries
set(CMAKE_PREFIX_PATH /usr/local ${CMAKE_PREFIX_PATH})
set(CMAKE_LIBRARY_PATH /usr/local/lib ${CMAKE_LIBRARY_PATH})

find_path(UCI_INCLUDE_DIRS uci.h HINTS /usr/local/include /usr/include)
if(NOT UCI_INCLUDE_DIRS)
    message(STATUS "UCI headers not found. Attempting to build and install from source...")
    build_and_install_libuci()
    # Try finding again after installation
    find_path(UCI_INCLUDE_DIRS uci.h HINTS /usr/local/include /usr/include)
    if(NOT UCI_INCLUDE_DIRS)
        message(FATAL_ERROR "UCI headers still not found after build and install. Please check the installation.")
    endif()
endif()

# Find dependencies; install via apt (and source for mosquitto) if missing
aw_ensure_pkg(LIBEVENT libevent libevent-dev)
aw_ensure_pkg(OPENSSL openssl libssl-dev)
aw_ensure_pkg(JSONC json-c libjson-c-dev)

pkg_check_modules(MOSQUITTO QUIET libmosquitto)
if(NOT MOSQUITTO_FOUND)
  message(STATUS "libmosquitto not found via pkg-config")
  try_apt_install(libmosquitto-dev)
  aw_refresh_pkg(MOSQUITTO)
  pkg_check_modules(MOSQUITTO QUIET libmosquitto)
endif()
if(NOT MOSQUITTO_FOUND)
  build_and_install_libmosquitto()
  aw_refresh_pkg(MOSQUITTO)
  pkg_check_modules(MOSQUITTO QUIET libmosquitto)
endif()
if(NOT MOSQUITTO_FOUND)
  find_path(MOSQUITTO_INCLUDE_DIRS mosquitto.h HINTS /usr/local/include /usr/include)
  find_library(MOSQUITTO_LIBRARIES mosquitto HINTS /usr/local/lib /usr/lib /usr/lib/x86_64-linux-gnu)
  if(MOSQUITTO_INCLUDE_DIRS AND MOSQUITTO_LIBRARIES)
    set(MOSQUITTO_FOUND TRUE)
    message(STATUS "Found libmosquitto: ${MOSQUITTO_LIBRARIES}")
  endif()
endif()
if(NOT MOSQUITTO_FOUND)
  message(FATAL_ERROR "libmosquitto not found. Install with: sudo apt-get install libmosquitto-dev")
endif()

aw_ensure_pkg(NFQUEUE libnetfilter_queue libnetfilter-queue-dev)

aw_ensure_pkg(BPF libbpf libbpf-dev OPTIONAL)
if(BPF_FOUND)
  message(STATUS "libbpf found - enabling eBPF features")
  set(HAVE_LIBBPF 1 CACHE INTERNAL "libbpf available")
else()
  message(WARNING "libbpf not found - eBPF-related features will be disabled. Install with: sudo apt-get install libbpf-dev to enable them")
  set(HAVE_LIBBPF 0 CACHE INTERNAL "libbpf available")
endif()

if (NOT AW_FW3)
  aw_ensure_pkg(NFTNL libnftnl libnftnl-dev)
  aw_ensure_pkg(MNL libmnl libmnl-dev)
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

# Project include directory (compat headers, local headers)
include_directories(${CMAKE_SOURCE_DIR}/include)

enable_testing()

# Add subdirectories
add_subdirectory(src)
