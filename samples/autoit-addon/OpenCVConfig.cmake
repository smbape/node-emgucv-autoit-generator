# Include directories
set(__OpenCV_INCLUDE_DIRS
  "${CMAKE_SOURCE_DIR}/../../libemgucv-includes/3rdparty"
  "${CMAKE_SOURCE_DIR}/../../libemgucv-includes/build_x64"
  "${CMAKE_SOURCE_DIR}/../../libemgucv-includes/Emgu.CV.Extern"
  "${CMAKE_SOURCE_DIR}/../../libemgucv-includes/opencv"
  "${CMAKE_SOURCE_DIR}/../../libemgucv-includes/opencv_contrib"
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

# Library files
set(__OpenCV_INCLUDE_LIBS
  "${CMAKE_SOURCE_DIR}/../../libemgucv-windesktop-4.5.2.4673/libs/x64/cvextern.lib"
)

set(OpenCV_INCLUDE_LIBS "")
foreach(f ${__OpenCV_INCLUDE_LIBS})
  get_filename_component(__f "${f}" REALPATH)
  if(NOT EXISTS "${__f}")
    if(NOT OpenCV_FIND_QUIETLY)
      message(WARNING "OpenCV: Include library doesn't exist: '${f}'. OpenCV installation may be broken. Skip...")
    endif()
  else()
    list(APPEND OpenCV_INCLUDE_LIBS "${__f}")
  endif()
endforeach()
unset(__f)
