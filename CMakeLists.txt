cmake_minimum_required(VERSION 3.12)

project(apfree-wifidog 
  VERSION 1.0.0
  DESCRIPTION "ApFree WiFiDog"
  LANGUAGES C)

INCLUDE(GNUInstallDirs)

# Set C standard and module path
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Function to check and install missing dependencies on Ubuntu 22.04+
function(check_and_install_ubuntu_dependencies)
  # Check if running on Ubuntu 22.04+
  if(EXISTS "/etc/os-release")
    file(READ "/etc/os-release" OS_RELEASE)
    string(REGEX MATCH "VERSION_ID=\"([0-9]+)\.([0-9]+)\"" _ "${OS_RELEASE}")
    if(CMAKE_MATCH_1 AND CMAKE_MATCH_2)
      set(VERSION_MAJOR ${CMAKE_MATCH_1})
      set(VERSION_MINOR ${CMAKE_MATCH_2})
      
      # Check if Ubuntu and version >= 22.04
      if(OS_RELEASE MATCHES "Ubuntu" AND (VERSION_MAJOR GREATER 22 OR (VERSION_MAJOR EQUAL 22 AND VERSION_MINOR GREATER_EQUAL 4)))
        message(STATUS "Detected Ubuntu ${VERSION_MAJOR}.${VERSION_MINOR} - Will auto-install missing dependencies")
        
        # List of Ubuntu packages corresponding to development libraries
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
        
        # Check and install each dependency
        foreach(PKG_PAIR ${PKG_MAPPING})
          string(REPLACE ":" ";" PKG_SPLIT ${PKG_PAIR})
          list(GET PKG_SPLIT 0 PKG_NAME)
          list(GET PKG_SPLIT 1 DEB_NAME)
          
          # Use pkg-config to check if library exists
          execute_process(
            COMMAND pkg-config --exists ${PKG_NAME}
            RESULT_VARIABLE PKG_FOUND
            OUTPUT_QUIET
            ERROR_QUIET
          )
          
          if(NOT PKG_FOUND EQUAL 0)
            message(STATUS "Missing library: ${PKG_NAME} (${DEB_NAME})")
            message(STATUS "Installing via apt: ${DEB_NAME}")
            
            # Try to install the package
            execute_process(
              COMMAND sudo apt-get update
              OUTPUT_QUIET
              ERROR_QUIET
            )
            
            execute_process(
              COMMAND sudo apt-get install -y ${DEB_NAME}
              RESULT_VARIABLE INSTALL_RESULT
              OUTPUT_QUIET
              ERROR_QUIET
            )
            
            if(NOT INSTALL_RESULT EQUAL 0)
              message(WARNING "Failed to auto-install ${DEB_NAME}. Please install manually: sudo apt-get install ${DEB_NAME}")
            else()
              message(STATUS "Successfully installed ${DEB_NAME}")
            endif()
          endif()
        endforeach()
      endif()
    endif()
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
    
    # Update pkg-config path
    set(ENV{PKG_CONFIG_PATH} "${LIBUBOX_INSTALL_PREFIX}/lib/pkgconfig:$ENV{PKG_CONFIG_PATH}")
    
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
    
    # Update pkg-config path
    set(ENV{PKG_CONFIG_PATH} "${LIBUCI_INSTALL_PREFIX}/lib/pkgconfig:$ENV{PKG_CONFIG_PATH}")
    
    message(STATUS "Successfully installed libuci")
  endif()
endfunction()

# Call the function to check and install dependencies
check_and_install_ubuntu_dependencies()

# Build and install libuci and its dependency libubox from source if needed
build_and_install_libuci()

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

# Find dependencies using pkg-config
pkg_check_modules(LIBEVENT REQUIRED libevent)
if(NOT LIBEVENT_FOUND)
  message(FATAL_ERROR "libevent not found. Install with: sudo apt-get install libevent-dev")
endif()

pkg_check_modules(OPENSSL REQUIRED openssl)
if(NOT OPENSSL_FOUND)
  message(FATAL_ERROR "openssl not found. Install with: sudo apt-get install libssl-dev")
endif()

pkg_check_modules(JSONC REQUIRED json-c)
if(NOT JSONC_FOUND)
  message(FATAL_ERROR "json-c not found. Install with: sudo apt-get install libjson-c-dev")
endif()

pkg_check_modules(MOSQUITTO REQUIRED libmosquitto)
if(NOT MOSQUITTO_FOUND)
  message(FATAL_ERROR "libmosquitto not found. Install with: sudo apt-get install libmosquitto-dev")
endif()

pkg_check_modules(NFQUEUE REQUIRED libnetfilter_queue)
if(NOT NFQUEUE_FOUND)
  message(FATAL_ERROR "libnetfilter_queue not found. Install with: sudo apt-get install libnetfilter-queue-dev")
endif()

pkg_check_modules(BPF REQUIRED libbpf)
if(NOT BPF_FOUND)
  message(FATAL_ERROR "libbpf not found. Install with: sudo apt-get install libbpf-dev")
endif()


if (NOT AW_FW3)
  pkg_check_modules(NFTNL REQUIRED libnftnl)
  if(NOT NFTNL_FOUND)
    message(FATAL_ERROR "libnftnl not found. Install with: sudo apt-get install libnftnl-dev")
  endif()
  
  pkg_check_modules(MNL REQUIRED libmnl)
  if(NOT MNL_FOUND)
    message(FATAL_ERROR "libmnl not found. Install with: sudo apt-get install libmnl-dev")
  endif()
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
