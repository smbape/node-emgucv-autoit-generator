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
add_definitions(-DAUTOITAPI_EXPORTS)

if(CMAKE_COMPILER_IS_GNUCXX)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-unused-function")
endif()

# Source headers
file(GLOB project_hdrs "./*.h*")
source_group("Include" FILES ${project_hdrs})

# Source files
file(GLOB project_srcs "./*.cpp")
source_group("Src" FILES ${project_srcs})

# Build a shared library named as the project
add_library(${PROJECT_NAME} SHARED ${project_srcs} ${project_hdrs})

# Include directories
set(__project_include_dirs
  "${CMAKE_CURRENT_SOURCE_DIR}/../libemgucv-includes/3rdparty"
  "${CMAKE_CURRENT_SOURCE_DIR}/../libemgucv-includes/build_x64"
  "${CMAKE_CURRENT_SOURCE_DIR}/../libemgucv-includes/Emgu.CV.Extern"
  "${CMAKE_CURRENT_SOURCE_DIR}/../libemgucv-includes/opencv"
  "${CMAKE_CURRENT_SOURCE_DIR}/../libemgucv-includes/opencv_contrib"
)
set(project_include_dirs "")
foreach(d ${__project_include_dirs})
  get_filename_component(__d "${d}" REALPATH)
  if(NOT EXISTS "${__d}")
    if(NOT OpenCV_FIND_QUIETLY)
      message(WARNING "OpenCV: Include directory doesn't exist: '${d}'. OpenCV installation may be broken. Skip...")
    endif()
  else()
    list(APPEND project_include_dirs "${__d}")
  endif()
endforeach()
unset(__d)

# Library directories
file(GLOB __project_library_dirs "../libemgucv-windesktop-4.*")
set(project_library_dirs "")
foreach(f ${__project_library_dirs})
  get_filename_component(__f "${f}/libs/x64" REALPATH)
  if(EXISTS "${__f}")
    list(APPEND project_library_dirs "${__f}")
  endif()
endforeach()
unset(__f)

# Add the required include directories for compiling:
target_include_directories(${PROJECT_NAME} PRIVATE ${project_include_dirs})

# Add the required libraries for linking:
target_link_directories(${PROJECT_NAME} PRIVATE ${project_library_dirs})
target_link_libraries(${PROJECT_NAME} PRIVATE "cvextern.lib")
