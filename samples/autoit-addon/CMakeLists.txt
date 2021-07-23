cmake_minimum_required(VERSION 3.5)

# Name of the project (will be the name of the plugin)
project(autoit_addon)

set(DEFAULT_BUILD_TYPE "Release")

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  message(STATUS "Setting build type to '${DEFAULT_BUILD_TYPE}' as none was specified.")
  set(CMAKE_BUILD_TYPE "${DEFAULT_BUILD_TYPE}" CACHE STRING "Choose the type of build." FORCE)
  # Set the possible values of build type for cmake-gui
  set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS "Debug" "Release" "MinSizeRel" "RelWithDebInfo")
endif()

add_definitions(-DAUTOIT_MODULE_NAME=${PROJECT_NAME})
add_definitions("-DAUTOIT_EXPORTS=__declspec(dllexport)")

include(OpenCVConfig.cmake)

set(SOURCE_FILES
  addon.h
  addon.cpp
)

# Build a shared library named as the project
add_library(${PROJECT_NAME} SHARED ${SOURCE_FILES})

# Include files to build an autoit emgucv addon
target_include_directories(${PROJECT_NAME} PRIVATE ${OpenCV_INCLUDE_DIRS})

# Library files to link to an autoit emgucv addon
target_link_libraries(${PROJECT_NAME} ${OpenCV_INCLUDE_LIBS})
