#CMake 2.6 is the minimal supported version of CMake
cmake_minimum_required (VERSION 2.6)

project(HAPviewer)

#Set the version of HAPviewer
set(VERSION 2.0)

#Use CMAKE_CXX_FLAGS_DEBUG per default. Can be changed to Release, RelWithDebInfo, MinSizeRel
#http://www.cmake.org/Wiki/CMake_Useful_Variables#Compilers_and_Tools
set(CMAKE_BUILD_TYPE Debug)

#Exit if someone tries to contaminates the source directory with an in-source build
if (${CMAKE_SOURCE_DIR} STREQUAL ${CMAKE_BINARY_DIR})
	message (FATAL_ERROR "Please do out-of-source builds.\nCleanup: \"rm -rf CMake CMakeCache.txt  CMakeFiles/\"")
endif()

#include our own FindXY.cmake files
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${PROJECT_SOURCE_DIR}/cmake/modules/general/")

#include aditional files if we are using a _really_ old version of cmake (2.6.x)
if(${CMAKE_MAJOR_VERSION} EQUAL 2 AND ${CMAKE_MINOR_VERSION} EQUAL 6)
	set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${PROJECT_SOURCE_DIR}/cmake/modules/v2.6/")
endif()

#Place all binaries in bin/ 
set(EXECUTABLE_OUTPUT_PATH ${CMAKE_BINARY_DIR}/bin)

#Option to perform nightly, continuous, and experimental tests incl. submission to cdash
option (HAPVIEWER_ENABLE_TESTING "Enable continuous testing and reporting to a CDash server" OFF)
if (HAPVIEWER_ENABLE_TESTING)
	include(CTest)
	enable_testing()
endif()

#include the directory with the HAPviewer/hapviz sources
add_subdirectory(src)

#Allows to build the doxygen documentation via "make doc"
option (HAPVIEWER_ENABLE_DOC "Enable \"make doc\" to build the doxygen documentation" ON)
if (HAPVIEWER_ENABLE_DOC)
	set(DOXYGEN_FIND_REQUIRED true)
	find_package(Doxygen)
	if (DOXYGEN_FOUND STREQUAL "NO")
		message(FATAL_ERROR "You neeed Doxygen in order to generate the documentation")
	endif()
	add_subdirectory(doc)
endif()
