//----------------------------------------------------------------------------
//
//  Copyright (C) 2004-2021 by EMGU Corporation. All rights reserved.
//
//  Vector of VideoCapture
//
//  This file is automatically generated, do not modify.
//----------------------------------------------------------------------------


#pragma once
#ifndef EMGU_VECTOR_VideoCapture_H
#define EMGU_VECTOR_VideoCapture_H

#include "vectors_c.h"

#include "videoio_c_extra.h"

#if defined(HAVE_OPENCV_VIDEOIO)

//----------------------------------------------------------------------------
//
//  Vector of VideoCapture
//
//----------------------------------------------------------------------------
CVAPI(std::vector< cv::VideoCapture >*) VectorOfVideoCaptureCreate();

CVAPI(std::vector< cv::VideoCapture >*) VectorOfVideoCaptureCreateSize(int size);

CVAPI(int) VectorOfVideoCaptureGetSize(std::vector< cv::VideoCapture >* v);

CVAPI(void) VectorOfVideoCapturePush(std::vector< cv::VideoCapture >* v, cv::VideoCapture* value);

//CVAPI(void) VectorOfVideoCapturePushMulti(std::vector< cv::VideoCapture >* v, cv::VideoCapture* values, int count);

CVAPI(void) VectorOfVideoCapturePushVector(std::vector< cv::VideoCapture >* v, std::vector< cv::VideoCapture >* other);

CVAPI(cv::VideoCapture*) VectorOfVideoCaptureGetStartAddress(std::vector< cv::VideoCapture >* v);

CVAPI(void*) VectorOfVideoCaptureGetEndAddress(std::vector< cv::VideoCapture >* v);

CVAPI(void) VectorOfVideoCaptureClear(std::vector< cv::VideoCapture >* v);

CVAPI(void) VectorOfVideoCaptureRelease(std::vector< cv::VideoCapture >** v);

CVAPI(void) VectorOfVideoCaptureCopyData(std::vector< cv::VideoCapture >* v,  cv::VideoCapture* data);

CVAPI(cv::VideoCapture*) VectorOfVideoCaptureGetStartAddress(std::vector< cv::VideoCapture >* v);

CVAPI(void*) VectorOfVideoCaptureGetEndAddress(std::vector< cv::VideoCapture >* v);

CVAPI(void) VectorOfVideoCaptureGetItemPtr(std::vector<  cv::VideoCapture >* vec, int index,  cv::VideoCapture** element);

#if false
CVAPI(cv::_InputArray*) cveInputArrayFromVectorOfVideoCapture(std::vector< cv::VideoCapture >* vec);

CVAPI(cv::_OutputArray*) cveOutputArrayFromVectorOfVideoCapture(std::vector< cv::VideoCapture >* vec);

CVAPI(cv::_InputOutputArray*) cveInputOutputArrayFromVectorOfVideoCapture(std::vector< cv::VideoCapture >* vec);
#endif

CVAPI(int) VectorOfVideoCaptureSizeOfItemInBytes();

#else

CVAPI(void *) VectorOfVideoCaptureCreate();

CVAPI(void *) VectorOfVideoCaptureCreateSize(int size);

CVAPI(int) VectorOfVideoCaptureGetSize(void* v);

CVAPI(void) VectorOfVideoCapturePush(void* v, void* value);

//CVAPI(void) VectorOfVideoCapturePushMulti(std::vector< cv::VideoCapture >* v, cv::VideoCapture* values, int count);

CVAPI(void) VectorOfVideoCapturePushVector(void* v, void* other);

CVAPI(void) VectorOfVideoCaptureClear(void* v);

CVAPI(void) VectorOfVideoCaptureRelease(void** v);

CVAPI(void) VectorOfVideoCaptureCopyData(void* v, void* data);

CVAPI(void*) VectorOfVideoCaptureGetStartAddress(void* v);

CVAPI(void) VectorOfVideoCaptureGetItemPtr(void* vec, int index,  void** element);

#if false
CVAPI(cv::_InputArray*) cveInputArrayFromVectorOfVideoCapture(void* vec);

CVAPI(cv::_OutputArray*) cveOutputArrayFromVectorOfVideoCapture(void* vec);

CVAPI(cv::_InputOutputArray*) cveInputOutputArrayFromVectorOfVideoCapture(void* vec);
#endif

CVAPI(int) VectorOfVideoCaptureSizeOfItemInBytes();

static inline CV_NORETURN void throw_no_vector() { CV_Error(cv::Error::StsBadFunc, "The library is compiled without VectorOfVideoCapture support"); }

#endif

#endif
