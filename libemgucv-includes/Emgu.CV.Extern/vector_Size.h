//----------------------------------------------------------------------------
//
//  Copyright (C) 2004-2021 by EMGU Corporation. All rights reserved.
//
//  Vector of Size
//
//  This file is automatically generated, do not modify.
//----------------------------------------------------------------------------


#pragma once
#ifndef EMGU_VECTOR_Size_H
#define EMGU_VECTOR_Size_H

#include "vectors_c.h"

#if 1



//----------------------------------------------------------------------------
//
//  Vector of Size
//
//----------------------------------------------------------------------------
CVAPI(std::vector< cv::Size >*) VectorOfSizeCreate();

CVAPI(std::vector< cv::Size >*) VectorOfSizeCreateSize(int size);

CVAPI(int) VectorOfSizeGetSize(std::vector< cv::Size >* v);

CVAPI(void) VectorOfSizePush(std::vector< cv::Size >* v, cv::Size* value);

CVAPI(void) VectorOfSizePushMulti(std::vector< cv::Size >* v, cv::Size* values, int count);

CVAPI(void) VectorOfSizePushVector(std::vector< cv::Size >* v, std::vector< cv::Size >* other);

CVAPI(void) VectorOfSizeClear(std::vector< cv::Size >* v);

CVAPI(void) VectorOfSizeRelease(std::vector< cv::Size >** v);

CVAPI(void) VectorOfSizeCopyData(std::vector< cv::Size >* v,  cv::Size* data);

CVAPI(cv::Size*) VectorOfSizeGetStartAddress(std::vector< cv::Size >* v);

CVAPI(void*) VectorOfSizeGetEndAddress(std::vector< cv::Size >* v);

CVAPI(void) VectorOfSizeGetItem(std::vector<  cv::Size >* vec, int index,  cv::Size* element);

CVAPI(void) VectorOfSizeGetItemPtr(std::vector<  cv::Size >* vec, int index,  cv::Size** element);

#if true
CVAPI(cv::_InputArray*) cveInputArrayFromVectorOfSize(std::vector< cv::Size >* vec);

CVAPI(cv::_OutputArray*) cveOutputArrayFromVectorOfSize(std::vector< cv::Size >* vec);

CVAPI(cv::_InputOutputArray*) cveInputOutputArrayFromVectorOfSize(std::vector< cv::Size >* vec);
#endif

CVAPI(int) VectorOfSizeSizeOfItemInBytes();

#else

static inline CV_NORETURN void throw_no_vector() { CV_Error(cv::Error::StsBadFunc, "The library is compiled without VectorOfSize support"); }

CVAPI(void*) VectorOfSizeCreate();

CVAPI(void*) VectorOfSizeCreateSize(int size);

CVAPI(int) VectorOfSizeGetSize(void* v);

CVAPI(void) VectorOfSizePush(void* v, void* value);

CVAPI(void) VectorOfSizePushMulti(void* v, void* values, int count);

CVAPI(void) VectorOfSizePushVector(void* v, void* other);

CVAPI(void) VectorOfSizeClear(void* v);

CVAPI(void) VectorOfSizeRelease(void** v);

CVAPI(void) VectorOfSizeCopyData(void* v,  void* data);

CVAPI(void*) VectorOfSizeGetStartAddress(void* v);

CVAPI(void) VectorOfSizeGetItem(void* vec, int index, void* element);

CVAPI(void) VectorOfSizeGetItemPtr(void* vec, int index, void** element);

#if true
CVAPI(cv::_InputArray*) cveInputArrayFromVectorOfSize(void* vec);

CVAPI(cv::_OutputArray*) cveOutputArrayFromVectorOfSize(void* vec);

CVAPI(cv::_InputOutputArray*) cveInputOutputArrayFromVectorOfSize(void* vec);
#endif

CVAPI(int) VectorOfSizeSizeOfItemInBytes();
#endif


#endif
