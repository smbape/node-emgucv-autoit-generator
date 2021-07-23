//----------------------------------------------------------------------------
//
//  Copyright (C) 2004-2021 by EMGU Corporation. All rights reserved.
//
//----------------------------------------------------------------------------

#pragma once
#ifndef EMGU_CUDAWARPING_C_H
#define EMGU_CUDAWARPING_C_H

#include "opencv2/opencv_modules.hpp"
#include "opencv2/core/core_c.h"

#ifdef HAVE_OPENCV_CUDAWARPING
#include "opencv2/cudaarithm.hpp"
#include "opencv2/cudawarping.hpp"
#include "opencv2/core/cuda.hpp"
#include "opencv2/core/types_c.h"
#include "emgu_c.h"
#else
static inline CV_NORETURN void throw_no_cudawarping() { CV_Error(cv::Error::StsBadFunc, "The library is compiled without CUDA Warping support"); }
#endif

CVAPI(void) cudaPyrDown(cv::_InputArray* src, cv::_OutputArray* dst, cv::cuda::Stream* stream);

CVAPI(void) cudaPyrUp(cv::_InputArray* src, cv::_OutputArray* dst, cv::cuda::Stream* stream);

CVAPI(void) cudaWarpAffine(cv::_InputArray* src, cv::_OutputArray* dst, cv::_InputArray* M, CvSize* dSize, int flags, int borderMode, CvScalar* borderValue, cv::cuda::Stream* stream);

CVAPI(void) cudaWarpPerspective(cv::_InputArray* src, cv::_OutputArray* dst,  cv::_InputArray* M, CvSize* size, int flags, int borderMode, CvScalar* borderValue, cv::cuda::Stream* stream);

CVAPI(void) cudaRemap(cv::_InputArray* src, cv::_OutputArray* dst, cv::_InputArray* xmap, cv::_InputArray* ymap, int interpolation, int borderMode, CvScalar* borderValue, cv::cuda::Stream* stream);

CVAPI(void) cudaResize(cv::_InputArray* src, cv::_OutputArray* dst, CvSize* dsize, double fx, double fy, int interpolation, cv::cuda::Stream* stream);

CVAPI(void) cudaRotate(cv::_InputArray* src, cv::_OutputArray* dst, CvSize* dSize, double angle, double xShift, double yShift, int interpolation, cv::cuda::Stream* s);

#endif