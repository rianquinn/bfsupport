# ------------------------------------------------------------------------------
# CMake Includes
# ------------------------------------------------------------------------------

include("${CMAKE_INSTALL_PREFIX}/cmake/CMakeGlobal_Includes.txt")

# ------------------------------------------------------------------------------
# Exports
# ------------------------------------------------------------------------------

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DCOMPILING_DUMMY")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DCOMPILING_DUMMY")

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

# This does not work on cygwin when cross compiling the sysroot because 
# we set the system to Linux in the toolchain file
# if(NOT CYGWIN AND NOT WIN32)
#     set(CMAKE_SHARED_LINKER_FLAGS "--fuse-ld=gold")
# endif()

# ------------------------------------------------------------------------------
# Targets
# ------------------------------------------------------------------------------

add_library(lib2 OBJECT dummy_lib2.cpp)
add_library(dummy_lib2 SHARED $<TARGET_OBJECTS:lib2>)
add_library(dummy_lib2_static STATIC $<TARGET_OBJECTS:lib2>)

# ------------------------------------------------------------------------------
# Install
# ------------------------------------------------------------------------------

install(TARGETS dummy_lib2 DESTINATION ${BAREFLANK_SYSROOT_PATH}/lib)
install(TARGETS dummy_lib2_static DESTINATION ${BAREFLANK_SYSROOT_PATH}/lib)
