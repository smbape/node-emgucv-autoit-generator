//----------------------------------------------------------------------------
//
//  Copyright (C) 2004-2021 by EMGU Corporation. All rights reserved.
//
//  Vector of VectorOfPointF
//
//  This file is automatically generated, do not modify.
//----------------------------------------------------------------------------


#pragma once
#ifndef EMGU_VECTOR_VectorOfPointF_H
#define EMGU_VECTOR_VectorOfPointF_H

#include "vectors_c.h"



#if 1

//----------------------------------------------------------------------------
//
//  Vector of VectorOfPointF
//
//----------------------------------------------------------------------------
CVAPI(std::vector< std::vector< cv::Point2f > >*) VectorOfVectorOfPointFCreate();

CVAPI(std::vector< std::vector< cv::Point2f > >*) VectorOfVectorOfPointFCreateSize(int size);

CVAPI(int) VectorOfVectorOfPointFGetSize(std::vector< std::vector< cv::Point2f > >* v);

CVAPI(void) VectorOfVectorOfPointFPush(std::vector< std::vector< cv::Point2f > >* v, std::vector< cv::Point2f >* value);

//CVAPI(void) VectorOfVectorOfPointFPushMulti(std::vector< std::vector< cv::Point2f > >* v, std::vector< cv::Point2f >* values, int count);

CVAPI(void) VectorOfVectorOfPointFPushVector(std::vector< std::vector< cv::Point2f > >* v, std::vector< std::vector< cv::Point2f > >* other);

CVAPI(std::vector< cv::Point2f >*) VectorOfVectorOfPointFGetStartAddress(std::vector< std::vector< cv::Point2f > >* v);

CVAPI(void*) VectorOfVectorOfPointFGetEndAddress(std::vector< std::vector< cv::Point2f > >* v);

CVAPI(void) VectorOfVectorOfPointFClear(std::vector< std::vector< cv::Point2f > >* v);

CVAPI(void) VectorOfVectorOfPointFRelease(std::vector< std::vector< cv::Point2f > >** v);

CVAPI(void) VectorOfVectorOfPointFCopyData(std::vector< std::vector< cv::Point2f > >* v,  std::vector< cv::Point2f >* data);

CVAPI(std::vector< cv::Point2f >*) VectorOfVectorOfPointFGetStartAddress(std::vector< std::vector< cv::Point2f > >* v);

CVAPI(void*) VectorOfVectorOfPointFGetEndAddress(std::vector< std::vector< cv::Point2f > >* v);

CVAPI(void) VectorOfVectorOfPointFGetItemPtr(std::vector<  std::vector< cv::Point2f > >* vec, int index,  std::vector< cv::Point2f >** element);

#if true
CVAPI(cv::_InputArray*) cveInputArrayFromVectorOfVectorOfPointF(std::vector< std::vector< cv::Point2f > >* vec);

CVAPI(cv::_OutputArray*) cveOutputArrayFromVectorOfVectorOfPointF(std::vector< std::vector< cv::Point2f > >* vec);

CVAPI(cv::_InputOutputArray*) cveInputOutputArrayFromVectorOfVectorOfPointF(std::vector< std::vector< cv::Point2f > >* vec);
#endif

CVAPI(int) VectorOfVectorOfPointFSizeOfItemInBytes();

#else

CVAPI(void *) VectorOfVectorOfPointFCreate();

CVAPI(void *) VectorOfVectorOfPointFCreateSize(int size);

CVAPI(int) VectorOfVectorOfPointFGetSize(void* v);

CVAPI(void) VectorOfVectorOfPointFPush(void* v, void* value);

//CVAPI(void) VectorOfVectorOfPointFPushMulti(std::vector< std::vector< cv::Point2f > >* v, std::vector< cv::Point2f >* values, int count);

CVAPI(void) VectorOfVectorOfPointFPushVector(void* v, void* other);

CVAPI(void) VectorOfVectorOfPointFClear(void* v);

CVAPI(void) VectorOfVectorOfPointFRelease(void** v);

CVAPI(void) VectorOfVectorOfPointFCopyData(void* v, void* data);

CVAPI(void*) VectorOfVectorOfPointFGetStartAddress(void* v);

CVAPI(void) VectorOfVectorOfPointFGetItemPtr(void* vec, int index,  void** element);

#if true
CVAPI(cv::_InputArray*) cveInputArrayFromVectorOfVectorOfPointF(void* vec);

CVAPI(cv::_OutputArray*) cveOutputArrayFromVectorOfVectorOfPointF(void* vec);

CVAPI(cv::_InputOutputArray*) cveInputOutputArrayFromVectorOfVectorOfPointF(void* vec);
#endif

CVAPI(int) VectorOfVectorOfPointFSizeOfItemInBytes();

static inline CV_NORETURN void throw_no_vector() { CV_Error(cv::Error::StsBadFunc, "The library is compiled without VectorOfVectorOfPointF support"); }

#endif

#endif
