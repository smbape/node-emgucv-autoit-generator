//----------------------------------------------------------------------------
//
//  Copyright (C) 2004-2021 by EMGU Corporation. All rights reserved.
//
//  Vector of Byte
//
//  This file is automatically generated, do not modify.
//----------------------------------------------------------------------------


#pragma once
#ifndef EMGU_VECTOR_Byte_H
#define EMGU_VECTOR_Byte_H

#include "vectors_c.h"

#if 1



//----------------------------------------------------------------------------
//
//  Vector of Byte
//
//----------------------------------------------------------------------------
CVAPI(std::vector< unsigned char >*) VectorOfByteCreate();

CVAPI(std::vector< unsigned char >*) VectorOfByteCreateSize(int size);

CVAPI(int) VectorOfByteGetSize(std::vector< unsigned char >* v);

CVAPI(void) VectorOfBytePush(std::vector< unsigned char >* v, unsigned char* value);

CVAPI(void) VectorOfBytePushMulti(std::vector< unsigned char >* v, unsigned char* values, int count);

CVAPI(void) VectorOfBytePushVector(std::vector< unsigned char >* v, std::vector< unsigned char >* other);

CVAPI(void) VectorOfByteClear(std::vector< unsigned char >* v);

CVAPI(void) VectorOfByteRelease(std::vector< unsigned char >** v);

CVAPI(void) VectorOfByteCopyData(std::vector< unsigned char >* v,  unsigned char* data);

CVAPI(unsigned char*) VectorOfByteGetStartAddress(std::vector< unsigned char >* v);

CVAPI(void*) VectorOfByteGetEndAddress(std::vector< unsigned char >* v);

CVAPI(void) VectorOfByteGetItem(std::vector<  unsigned char >* vec, int index,  unsigned char* element);

CVAPI(void) VectorOfByteGetItemPtr(std::vector<  unsigned char >* vec, int index,  unsigned char** element);

#if true
CVAPI(cv::_InputArray*) cveInputArrayFromVectorOfByte(std::vector< unsigned char >* vec);

CVAPI(cv::_OutputArray*) cveOutputArrayFromVectorOfByte(std::vector< unsigned char >* vec);

CVAPI(cv::_InputOutputArray*) cveInputOutputArrayFromVectorOfByte(std::vector< unsigned char >* vec);
#endif

CVAPI(int) VectorOfByteSizeOfItemInBytes();

#else

static inline CV_NORETURN void throw_no_vector() { CV_Error(cv::Error::StsBadFunc, "The library is compiled without VectorOfByte support"); }

CVAPI(void*) VectorOfByteCreate();

CVAPI(void*) VectorOfByteCreateSize(int size);

CVAPI(int) VectorOfByteGetSize(void* v);

CVAPI(void) VectorOfBytePush(void* v, void* value);

CVAPI(void) VectorOfBytePushMulti(void* v, void* values, int count);

CVAPI(void) VectorOfBytePushVector(void* v, void* other);

CVAPI(void) VectorOfByteClear(void* v);

CVAPI(void) VectorOfByteRelease(void** v);

CVAPI(void) VectorOfByteCopyData(void* v,  void* data);

CVAPI(void*) VectorOfByteGetStartAddress(void* v);

CVAPI(void) VectorOfByteGetItem(void* vec, int index, void* element);

CVAPI(void) VectorOfByteGetItemPtr(void* vec, int index, void** element);

#if true
CVAPI(cv::_InputArray*) cveInputArrayFromVectorOfByte(void* vec);

CVAPI(cv::_OutputArray*) cveOutputArrayFromVectorOfByte(void* vec);

CVAPI(cv::_InputOutputArray*) cveInputOutputArrayFromVectorOfByte(void* vec);
#endif

CVAPI(int) VectorOfByteSizeOfItemInBytes();
#endif


#endif
