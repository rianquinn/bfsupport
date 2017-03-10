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
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-stack-protector")

if(CYGWIN OR WIN32)
    set(CMAKE_SHARED_LINKER_FLAGS "--fuse-ld=gold")
endif()

# ------------------------------------------------------------------------------
# Targets
# ------------------------------------------------------------------------------

add_library(dummy_lib2 SHARED dummy_lib2.cpp)
add_library(dummy_lib2_static STATIC dummy_lib2.cpp)

# ------------------------------------------------------------------------------
# Install
# ------------------------------------------------------------------------------

install(TARGETS dummy_lib2 DESTINATION ${BAREFLANK_SYSROOT_PATH}/lib)
install(TARGETS dummy_lib2_static DESTINATION ${BAREFLANK_SYSROOT_PATH}/lib)
