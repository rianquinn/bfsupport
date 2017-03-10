# cmake -DCMAKE_TOOLCHAIN_FILE=~/bfprefix/cmake/CMakeToolchain_VMM.txt ..

cmake_minimum_required(VERSION 3.4)
project(bfsupport C CXX)

if(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
    set(CMAKE_INSTALL_PREFIX "$ENV{HOME}/bfprefix" CACHE PATH "default bareflank prefix" FORCE)
endif()

include("${CMAKE_INSTALL_PREFIX}/cmake/CMakeGlobal_Project.txt")

# ------------------------------------------------------------------------------
# Subdirectories
# ------------------------------------------------------------------------------

add_subdirectory(crt)
add_subdirectory(syscall)
add_subdirectory(pthread)
add_subdirectory(dummy_lib1)
add_subdirectory(dummy_lib2)
add_subdirectory(dummy_main)
