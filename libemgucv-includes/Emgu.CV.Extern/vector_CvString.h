//----------------------------------------------------------------------------
//
//  Copyright (C) 2004-2021 by EMGU Corporation. All rights reserved.
//
//  Vector of CvString
//
//  This file is automatically generated, do not modify.
//----------------------------------------------------------------------------


#pragma once
#ifndef EMGU_VECTOR_CvString_H
#define EMGU_VECTOR_CvString_H

#include "vectors_c.h"



#if 1

//----------------------------------------------------------------------------
//
//  Vector of CvString
//
//----------------------------------------------------------------------------
CVAPI(std::vector< cv::String >*) VectorOfCvStringCreate();

CVAPI(std::vector< cv::String >*) VectorOfCvStringCreateSize(int size);

CVAPI(int) VectorOfCvStringGetSize(std::vector< cv::String >* v);

CVAPI(void) VectorOfCvStringPush(std::vector< cv::String >* v, cv::String* value);

//CVAPI(void) VectorOfCvStringPushMulti(std::vector< cv::String >* v, cv::String* values, int count);

CVAPI(void) VectorOfCvStringPushVector(std::vector< cv::String >* v, std::vector< cv::String >* other);

CVAPI(cv::String*) VectorOfCvStringGetStartAddress(std::vector< cv::String >* v);

CVAPI(void*) VectorOfCvStringGetEndAddress(std::vector< cv::String >* v);

CVAPI(void) VectorOfCvStringClear(std::vector< cv::String >* v);

CVAPI(void) VectorOfCvStringRelease(std::vector< cv::String >** v);

CVAPI(void) VectorOfCvStringCopyData(std::vector< cv::String >* v,  cv::String* data);

CVAPI(cv::String*) VectorOfCvStringGetStartAddress(std::vector< cv::String >* v);

CVAPI(void*) VectorOfCvStringGetEndAddress(std::vector< cv::String >* v);

CVAPI(void) VectorOfCvStringGetItemPtr(std::vector<  cv::String >* vec, int index,  cv::String** element);

#if true
CVAPI(cv::_InputArray*) cveInputArrayFromVectorOfCvString(std::vector< cv::String >* vec);

CVAPI(cv::_OutputArray*) cveOutputArrayFromVectorOfCvString(std::vector< cv::String >* vec);

CVAPI(cv::_InputOutputArray*) cveInputOutputArrayFromVectorOfCvString(std::vector< cv::String >* vec);
#endif

CVAPI(int) VectorOfCvStringSizeOfItemInBytes();

#else

CVAPI(void *) VectorOfCvStringCreate();

CVAPI(void *) VectorOfCvStringCreateSize(int size);

CVAPI(int) VectorOfCvStringGetSize(void* v);

CVAPI(void) VectorOfCvStringPush(void* v, void* value);

//CVAPI(void) VectorOfCvStringPushMulti(std::vector< cv::String >* v, cv::String* values, int count);

CVAPI(void) VectorOfCvStringPushVector(void* v, void* other);

CVAPI(void) VectorOfCvStringClear(void* v);

CVAPI(void) VectorOfCvStringRelease(void** v);

CVAPI(void) VectorOfCvStringCopyData(void* v, void* data);

CVAPI(void*) VectorOfCvStringGetStartAddress(void* v);

CVAPI(void) VectorOfCvStringGetItemPtr(void* vec, int index,  void** element);

#if true
CVAPI(cv::_InputArray*) cveInputArrayFromVectorOfCvString(void* vec);

CVAPI(cv::_OutputArray*) cveOutputArrayFromVectorOfCvString(void* vec);

CVAPI(cv::_InputOutputArray*) cveInputOutputArrayFromVectorOfCvString(void* vec);
#endif

CVAPI(int) VectorOfCvStringSizeOfItemInBytes();

static inline CV_NORETURN void throw_no_vector() { CV_Error(cv::Error::StsBadFunc, "The library is compiled without VectorOfCvString support"); }

#endif

#endif
