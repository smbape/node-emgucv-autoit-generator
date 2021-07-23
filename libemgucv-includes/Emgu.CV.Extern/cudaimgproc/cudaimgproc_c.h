//----------------------------------------------------------------------------
//
//  Copyright (C) 2004-2021 by EMGU Corporation. All rights reserved.
//
//----------------------------------------------------------------------------

#pragma once
#ifndef EMGU_CUDAIMGPROC_C_H
#define EMGU_CUDAIMGPROC_C_H

#include "opencv2/opencv_modules.hpp"
#include "opencv2/core/core_c.h"

#ifdef HAVE_OPENCV_CUDAIMGPROC

#include "opencv2/cudaimgproc.hpp"
#include "opencv2/core/cuda.hpp"
#include "opencv2/core/types_c.h"
#include "emgu_c.h"

#else
static inline CV_NORETURN void throw_no_cudaimgproc() { CV_Error(cv::Error::StsBadFunc, "The library is compiled without CUDA Imgproc support"); }

namespace cv
{
	namespace cuda
	{
		class CornernessCriteria
		{
		};

		class CLAHE
		{
		};

		class CannyEdgeDetector
		{
		};

		class CornersDetector
		{
		};

		class TemplateMatching
		{
		};

		class HoughLinesDetector
		{
		};

		class HoughSegmentDetector
		{
		};

		class HoughCirclesDetector
		{
		};
	}
}
#endif

CVAPI(void) cudaBlendLinear(
   cv::_InputArray* img1, cv::_InputArray* img2, 
   cv::_InputArray* weights1, cv::_InputArray* weights2, 
   cv::_OutputArray* result, cv::cuda::Stream* stream);
   
CVAPI(void) cudaCvtColor(cv::_InputArray* src, cv::_OutputArray* dst, int code, int dcn, cv::cuda::Stream* stream);

CVAPI(void) cudaDemosaicing(cv::_InputArray* src, cv::_OutputArray* dst, int code, int dcn, cv::cuda::Stream* stream);

CVAPI(void) cudaSwapChannels(cv::_InputOutputArray* image, const int* dstOrder, cv::cuda::Stream* stream);

CVAPI(void) cudaAlphaComp(cv::_InputArray* img1, cv::_InputArray* img2, cv::_OutputArray* dst, int alphaOp, cv::cuda::Stream* stream);

CVAPI(void) cudaMeanShiftFiltering(cv::_InputArray* src, cv::_OutputArray* dst, int sp, int sr,
   CvTermCriteria* criteria, cv::cuda::Stream* stream);

CVAPI(void) cudaMeanShiftProc(cv::_InputArray* src, cv::_OutputArray* dstr, cv::_OutputArray* dstsp, int sp, int sr,
   CvTermCriteria* criteria, cv::cuda::Stream* stream);

CVAPI(void) cudaMeanShiftSegmentation(cv::_InputArray* src, cv::_OutputArray* dst, int sp, int sr, int minsize,
   CvTermCriteria* criteria, cv::cuda::Stream* stream);

CVAPI(void) cudaCalcHist(cv::_InputArray* src, cv::_OutputArray* hist, cv::cuda::Stream* stream);

CVAPI(void) cudaEqualizeHist(cv::_InputArray* src, cv::_OutputArray* dst, cv::cuda::Stream* stream);

CVAPI(void) cudaHistEven(cv::_InputArray* src, cv::_OutputArray* hist, int histSize, int lowerLevel, int upperLevel, cv::cuda::Stream* stream);

CVAPI(void) cudaHistRange(cv::_InputArray* src, cv::_OutputArray* hist, cv::_InputArray* levels, cv::cuda::Stream* stream);

CVAPI(void) cudaBilateralFilter(cv::_InputArray* src, cv::_OutputArray* dst, int kernelSize, float sigmaColor, float sigmaSpatial, int borderMode, cv::cuda::Stream* stream);

//----------------------------------------------------------------------------
//
//  CudaCornernessCriteria
//
//----------------------------------------------------------------------------
CVAPI(cv::cuda::CornernessCriteria*) cudaCreateHarrisCorner(int srcType, int blockSize, int ksize, double k, int borderType, cv::Ptr<cv::cuda::CornernessCriteria>** sharedPtr);
CVAPI(cv::cuda::CornernessCriteria*) cudaCreateMinEigenValCorner(int srcType, int blockSize, int ksize, int borderType, cv::Ptr<cv::cuda::CornernessCriteria>** sharedPtr);
CVAPI(void) cudaCornernessCriteriaCompute(cv::Ptr<cv::cuda::CornernessCriteria>* detector, cv::_InputArray* src, cv::_OutputArray* dst,  cv::cuda::Stream* stream);
CVAPI(void) cudaCornernessCriteriaRelease(cv::Ptr<cv::cuda::CornernessCriteria>** detector);

//----------------------------------------------------------------------------
//
//  CudaCLAHE
//
//----------------------------------------------------------------------------
CVAPI(cv::cuda::CLAHE*) cudaCLAHECreate(double clipLimit, CvSize* tileGridSize, cv::Ptr<cv::cuda::CLAHE>** sharedPtr);
CVAPI(void) cudaCLAHEApply(cv::cuda::CLAHE* clahe, cv::_InputArray* src, cv::_OutputArray* dst,  cv::cuda::Stream* stream);
CVAPI(void) cudaCLAHERelease(cv::Ptr<cv::cuda::CLAHE>** clahe);

//----------------------------------------------------------------------------
//
//  CannyEdgeDetector
//
//----------------------------------------------------------------------------
CVAPI(cv::cuda::CannyEdgeDetector*) cudaCreateCannyEdgeDetector(double lowThreshold, double highThreshold, int apertureSize, bool L2gradient, cv::Ptr<cv::cuda::CannyEdgeDetector>** sharedPtr);

CVAPI(void) cudaCannyEdgeDetectorDetect(cv::cuda::CannyEdgeDetector* detector, cv::_InputArray* src, cv::_OutputArray* edges, cv::cuda::Stream* stream);

CVAPI(void) cudaCannyEdgeDetectorRelease(cv::Ptr<cv::cuda::CannyEdgeDetector>** detector);

//----------------------------------------------------------------------------
//
//  CudaGoodFeaturesToTrackDetector
//
//----------------------------------------------------------------------------
CVAPI(cv::cuda::CornersDetector*) cudaGoodFeaturesToTrackDetectorCreate(int srcType, int maxCorners, double qualityLevel, double minDistance, int blockSize, bool useHarrisDetector, double harrisK, cv::Ptr<cv::cuda::CornersDetector>** sharedPtr);
CVAPI(void) cudaCornersDetectorDetect(cv::cuda::CornersDetector* detector, cv::_InputArray* image, cv::_OutputArray* corners, cv::_InputArray* mask, cv::cuda::Stream* stream);
CVAPI(void) cudaCornersDetectorRelease(cv::Ptr<cv::cuda::CornersDetector>** detector);


//----------------------------------------------------------------------------
//
//  CudaTemplateMatching
//
//----------------------------------------------------------------------------
CVAPI(cv::cuda::TemplateMatching*) cudaTemplateMatchingCreate(int srcType, int method, CvSize* blockSize, cv::Ptr<cv::cuda::TemplateMatching>** sharedPtr);
CVAPI(void) cudaTemplateMatchingRelease(cv::Ptr<cv::cuda::TemplateMatching>** tm);
CVAPI(void) cudaTemplateMatchingMatch(cv::cuda::TemplateMatching* tm, cv::_InputArray* image, cv::_InputArray* templ, cv::_OutputArray* result, cv::cuda::Stream* stream);

//----------------------------------------------------------------------------
//
//  CudaHoughLinesDetector
//
//----------------------------------------------------------------------------
CVAPI(cv::cuda::HoughLinesDetector*) cudaHoughLinesDetectorCreate(float rho, float theta, int threshold, bool doSort, int maxLines, cv::Ptr<cv::cuda::HoughLinesDetector>** sharedPtr);
CVAPI(void) cudaHoughLinesDetectorDetect(cv::cuda::HoughLinesDetector* detector, cv::_InputArray* src, cv::_OutputArray* lines, cv::cuda::Stream* stream);
CVAPI(void) cudaHoughLinesDetectorRelease(cv::Ptr<cv::cuda::HoughLinesDetector>** detector);

//----------------------------------------------------------------------------
//
//  CudaHoughSegmentDetector
//
//----------------------------------------------------------------------------
CVAPI(cv::cuda::HoughSegmentDetector*) cudaHoughSegmentDetectorCreate(float rho, float theta, int minLineLength, int maxLineGap, int maxLines, cv::Ptr<cv::cuda::HoughSegmentDetector>** sharedPtr);
CVAPI(void) cudaHoughSegmentDetectorDetect(cv::cuda::HoughSegmentDetector* detector, cv::_InputArray* src, cv::_OutputArray* lines, cv::cuda::Stream* stream);
CVAPI(void) cudaHoughSegmentDetectorRelease(cv::Ptr<cv::cuda::HoughSegmentDetector>** detector);

//----------------------------------------------------------------------------
//
//  CudaHoughCircleDetector
//
//----------------------------------------------------------------------------
CVAPI(cv::cuda::HoughCirclesDetector*) cudaHoughCirclesDetectorCreate(float dp, float minDist, int cannyThreshold, int votesThreshold, int minRadius, int maxRadius, int maxCircles, cv::Ptr<cv::cuda::HoughCirclesDetector>** sharedPtr);
CVAPI(void) cudaHoughCirclesDetectorDetect(cv::cuda::HoughCirclesDetector* detector, cv::_InputArray* src, cv::_OutputArray* circles, cv::cuda::Stream* stream);
CVAPI(void) cudaHoughCirclesDetectorRelease(cv::Ptr<cv::cuda::HoughCirclesDetector>** detector);

CVAPI(void) cudaGammaCorrection(cv::_InputArray* src, cv::_OutputArray* dst, bool forward, cv::cuda::Stream* stream);
#endif