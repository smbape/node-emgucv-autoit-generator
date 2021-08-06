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

if(CMAKE_COMPILER_IS_GNUCXX)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-unused-function")
endif()

file(GLOB project_srcs "./*.cpp")
source_group("Src" FILES ${project_srcs})
file(GLOB project_hdrs "./*.h*")
source_group("Include" FILES ${project_hdrs})

# Build a shared library named as the project
add_library(${PROJECT_NAME} SHARED ${project_srcs} ${project_hdrs})

# Include directories
set(__PROJECT_INCLUDE_DIRS
  "${CMAKE_CURRENT_SOURCE_DIR}/../libemgucv-includes/3rdparty"
  "${CMAKE_CURRENT_SOURCE_DIR}/../libemgucv-includes/build_x64"
  "${CMAKE_CURRENT_SOURCE_DIR}/../libemgucv-includes/Emgu.CV.Extern"
  "${CMAKE_CURRENT_SOURCE_DIR}/../libemgucv-includes/opencv"
  "${CMAKE_CURRENT_SOURCE_DIR}/../libemgucv-includes/opencv_contrib"
)
set(PROJECT_INCLUDE_DIRS "")
foreach(d ${__PROJECT_INCLUDE_DIRS})
  get_filename_component(__d "${d}" REALPATH)
  if(NOT EXISTS "${__d}")
    if(NOT OpenCV_FIND_QUIETLY)
      message(WARNING "OpenCV: Include directory doesn't exist: '${d}'. OpenCV installation may be broken. Skip...")
    endif()
  else()
    list(APPEND PROJECT_INCLUDE_DIRS "${__d}")
  endif()
endforeach()
unset(__d)

# Library directories
file(GLOB __PROJECT_LIBRARY_DIRS "../libemgucv-windesktop-4.*")
set(PROJECT_LIBRARY_DIRS "")
foreach(f ${__PROJECT_LIBRARY_DIRS})
  get_filename_component(__f "${f}/libs/x64" REALPATH)
  if(EXISTS "${__f}")
    list(APPEND PROJECT_LIBRARY_DIRS "${__f}")
  endif()
endforeach()
unset(__f)

# Add the required include directories for compiling:
target_include_directories(${PROJECT_NAME} PRIVATE ${PROJECT_INCLUDE_DIRS})

# Add the required libraries for linking:
target_link_directories(${PROJECT_NAME} PRIVATE ${PROJECT_LIBRARY_DIRS})
target_link_libraries(${PROJECT_NAME} PRIVATE "cvextern.lib")
