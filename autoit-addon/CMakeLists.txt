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

set(SOURCE_FILES
  addon.cpp
)

# Include directories
set(__OpenCV_INCLUDE_DIRS
  "${CMAKE_SOURCE_DIR}/../libemgucv-includes/3rdparty"
  "${CMAKE_SOURCE_DIR}/../libemgucv-includes/build_x64"
  "${CMAKE_SOURCE_DIR}/../libemgucv-includes/Emgu.CV.Extern"
  "${CMAKE_SOURCE_DIR}/../libemgucv-includes/opencv"
  "${CMAKE_SOURCE_DIR}/../libemgucv-includes/opencv_contrib"
)
set(OpenCV_INCLUDE_DIRS "")
foreach(d ${__OpenCV_INCLUDE_DIRS})
  get_filename_component(__d "${d}" REALPATH)
  if(NOT EXISTS "${__d}")
    if(NOT OpenCV_FIND_QUIETLY)
      message(WARNING "OpenCV: Include directory doesn't exist: '${d}'. OpenCV installation may be broken. Skip...")
    endif()
  else()
    list(APPEND OpenCV_INCLUDE_DIRS "${__d}")
  endif()
endforeach()
unset(__d)

# Library directories
set(__OpenCV_LIBRARY_DIRS
  "${CMAKE_SOURCE_DIR}/../libemgucv-windesktop-4.5.2.4673/libs/x64"
)
set(OpenCV_LIBRARY_DIRS "")
foreach(f ${__OpenCV_LIBRARY_DIRS})
  get_filename_component(__f "${f}" REALPATH)
  if(NOT EXISTS "${__f}")
    if(NOT OpenCV_FIND_QUIETLY)
      message(WARNING "OpenCV: Include library doesn't exist: '${f}'. OpenCV installation may be broken. Skip...")
    endif()
  else()
    list(APPEND OpenCV_LIBRARY_DIRS "${__f}")
  endif()
endforeach()
unset(__f)

# Library files
set(OpenCV_LIBS
  "cvextern.lib"
)

# Build a shared library named as the project
add_library(${PROJECT_NAME} SHARED ${SOURCE_FILES})

# Include files to build an autoit emgucv addon
target_include_directories(${PROJECT_NAME} PRIVATE ${OpenCV_INCLUDE_DIRS})

# Library files to link to an autoit emgucv addon
target_link_directories(${PROJECT_NAME} PRIVATE ${OpenCV_LIBRARY_DIRS})
target_link_libraries(${PROJECT_NAME} PRIVATE ${OpenCV_LIBS})
