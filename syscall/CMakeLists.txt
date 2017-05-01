# ------------------------------------------------------------------------------
# CMake Includes
# ------------------------------------------------------------------------------

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

# ------------------------------------------------------------------------------
# Targets
# ------------------------------------------------------------------------------

add_library(syscall OBJECT syscall.cpp)
add_library(bfsyscall SHARED $<TARGET_OBJECTS:syscall>)
add_library(bfsyscall_static STATIC $<TARGET_OBJECTS:syscall>)

# ------------------------------------------------------------------------------
# Install
# ------------------------------------------------------------------------------

install(TARGETS bfsyscall DESTINATION ${BAREFLANK_SYSROOT_PATH}/lib)
install(TARGETS bfsyscall_static DESTINATION ${BAREFLANK_SYSROOT_PATH}/lib)
