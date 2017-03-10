# ------------------------------------------------------------------------------
# CMake Includes
# ------------------------------------------------------------------------------

if(NOT CMAKE_TOOLCHAIN_FILE)
    include("${CMAKE_INSTALL_PREFIX}/cmake/CMakeFlags_Native.txt")
endif()

include("${CMAKE_INSTALL_PREFIX}/cmake/CMakeGlobal_Includes.txt")

# ------------------------------------------------------------------------------
# Custom Flags
# ------------------------------------------------------------------------------

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fno-rtti")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fno-exceptions")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fno-sized-deallocation")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fno-use-cxa-atexit")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fno-stack-protector")

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-rtti")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-exceptions")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-sized-deallocation")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-use-cxa-atexit")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-main")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-return-type")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-stack-protector")

# ------------------------------------------------------------------------------
# Targets
# ------------------------------------------------------------------------------

add_library(bfcrt SHARED crt.cpp start_x64.asm)
add_library(bfcrt_static STATIC crt.cpp start_x64.asm)

# ------------------------------------------------------------------------------
# Install
# ------------------------------------------------------------------------------

install(TARGETS bfcrt DESTINATION ${BAREFLANK_SYSROOT_PATH}/lib)
install(TARGETS bfcrt_static DESTINATION ${BAREFLANK_SYSROOT_PATH}/lib)
