//----------------------------------------------------------------------------
//
//  Copyright (C) 2004-2021 by EMGU Corporation. All rights reserved.
//
//----------------------------------------------------------------------------

#pragma once
#ifndef EMGU_ARUCO_C_H
#define EMGU_ARUCO_C_H

#include "opencv2/opencv_modules.hpp"
#include "opencv2/core/core_c.h"

#ifdef HAVE_OPENCV_ARUCO

#include "opencv2/aruco.hpp"
#include "opencv2/aruco/charuco.hpp"

#else

static inline CV_NORETURN void throw_no_aruco() { CV_Error(cv::Error::StsBadFunc, "The library is compiled without Aruco support"); }

namespace cv
{
	namespace aruco
	{
		class Dictionary
		{

		};

		class DetectorParameters
		{

		};

		class Board
		{
			
		};
		
		class GridBoard
		{
			
		};

		class CharucoBoard
		{
			
		};
	}
}

#endif

CVAPI(cv::aruco::Dictionary*) cveArucoGetPredefinedDictionary(int name, cv::Ptr<cv::aruco::Dictionary>** sharedPtr);
CVAPI(cv::aruco::Dictionary*) cveArucoDictionaryCreate1(int nMarkers, int markerSize, cv::Ptr<cv::aruco::Dictionary>** sharedPtr);
CVAPI(cv::aruco::Dictionary*) cveArucoDictionaryCreate2(int nMarkers, int markerSize, cv::Ptr<cv::aruco::Dictionary>* baseDictionary, cv::Ptr<cv::aruco::Dictionary>** sharedPtr);
CVAPI(void) cveArucoDictionaryRelease(cv::aruco::Dictionary** dict, cv::Ptr<cv::aruco::Dictionary>** sharedPtr);

CVAPI(void) cveArucoDrawMarker(cv::aruco::Dictionary* dictionary, int id, int sidePixels, cv::_OutputArray* img, int borderBits);

CVAPI(void) cveArucoDrawAxis(cv::_InputOutputArray* image, cv::_InputArray* cameraMatrix, cv::_InputArray* distCoeffs, cv::_InputArray* rvec, cv::_InputArray* tvec, float length);

CVAPI(void) cveArucoDetectMarkers(
   cv::_InputArray* image, cv::aruco::Dictionary* dictionary, cv::_OutputArray* corners,
   cv::_OutputArray* ids, cv::aruco::DetectorParameters* parameters,
   cv::_OutputArray* rejectedImgPoints);

CVAPI(void) cveArucoEstimatePoseSingleMarkers(cv::_InputArray* corners, float markerLength,
   cv::_InputArray* cameraMatrix, cv::_InputArray* distCoeffs,
   cv::_OutputArray* rvecs, cv::_OutputArray* tvecs);

CVAPI(cv::aruco::GridBoard*) cveArucoGridBoardCreate(
	int markersX, int markersY, float markerLength, float markerSeparation,
	cv::aruco::Dictionary* dictionary, int firstMarker, cv::aruco::Board** boardPtr, cv::Ptr<cv::aruco::GridBoard>** sharedPtr);

CVAPI(void) cveArucoGridBoardDraw(cv::aruco::GridBoard* gridBoard, CvSize* outSize, cv::_OutputArray* img, int marginSize, int borderBits);

CVAPI(void) cveArucoGridBoardRelease(cv::aruco::GridBoard** gridBoard, cv::Ptr<cv::aruco::GridBoard>** sharedPtr);

CVAPI(cv::aruco::CharucoBoard*) cveCharucoBoardCreate(
   int squaresX, int squaresY, float squareLength, float markerLength,
   cv::aruco::Dictionary* dictionary, cv::aruco::Board** boardPtr, cv::Ptr<cv::aruco::CharucoBoard>** sharedPtr);
CVAPI(void) cveCharucoBoardDraw(cv::aruco::CharucoBoard* charucoBoard, CvSize* outSize, cv::_OutputArray* img, int marginSize, int borderBits);
CVAPI(void) cveCharucoBoardRelease(cv::aruco::CharucoBoard** charucoBoard, cv::Ptr<cv::aruco::CharucoBoard>** sharedPtr);

CVAPI(void) cveArucoRefineDetectedMarkers(
   cv::_InputArray* image, cv::aruco::Board* board, cv::_InputOutputArray* detectedCorners,
   cv::_InputOutputArray* detectedIds, cv::_InputOutputArray* rejectedCorners,
   cv::_InputArray* cameraMatrix, cv::_InputArray* distCoeffs,
   float minRepDistance, float errorCorrectionRate, bool checkAllOrders,
   cv::_OutputArray* recoveredIdxs, cv::aruco::DetectorParameters* parameters);

CVAPI(void) cveArucoDrawDetectedMarkers(
   cv::_InputOutputArray* image, cv::_InputArray* corners,
   cv::_InputArray* ids, CvScalar* borderColor);

CVAPI(double) cveArucoCalibrateCameraAruco(
	cv::_InputArray* corners, cv::_InputArray* ids, cv::_InputArray* counter, cv::aruco::Board* board,
	CvSize* imageSize, cv::_InputOutputArray* cameraMatrix, cv::_InputOutputArray* distCoeffs,
	cv::_OutputArray* rvecs, cv::_OutputArray* tvecs,
	cv::_OutputArray* stdDeviationsIntrinsics,
	cv::_OutputArray* stdDeviationsExtrinsics,
	cv::_OutputArray* perViewErrors,
	int flags, CvTermCriteria* criteria);

CVAPI(double) cveArucoCalibrateCameraCharuco(
	cv::_InputArray* charucoCorners,
	cv::_InputArray* charucoIds,
	cv::aruco::CharucoBoard* board,
	CvSize* imageSize,
	cv::_InputOutputArray* cameraMatrix,
	cv::_InputOutputArray* distCoeffs,
	cv::_OutputArray* rvecs,
	cv::_OutputArray* tvecs,
	cv::_OutputArray* stdDeviationsIntrinsics,
	cv::_OutputArray* stdDeviationsExtrinsics,
	cv::_OutputArray* perViewErrors,
	int flags,
	CvTermCriteria* criteria);

CVAPI(void) cveArucoDetectorParametersGetDefault(cv::aruco::DetectorParameters* parameters);

CVAPI(int) cveArucoInterpolateCornersCharuco(
	cv::_InputArray* markerCorners, 
	cv::_InputArray* markerIds,
	cv::_InputArray* image, 
	cv::aruco::CharucoBoard* board,
	cv::_OutputArray* charucoCorners, 
	cv::_OutputArray* charucoIds,
	cv::_InputArray* cameraMatrix,
	cv::_InputArray* distCoeffs, 
	int minMarkers);

CVAPI(void) cveArucoDrawDetectedCornersCharuco(
	cv::_InputOutputArray* image, 
	cv::_InputArray* charucoCorners,
	cv::_InputArray* charucoIds,
	CvScalar* cornerColor);

CVAPI(bool) cveArucoEstimatePoseCharucoBoard(
	cv::_InputArray* charucoCorners, 
	cv::_InputArray* charucoIds,
	cv::aruco::CharucoBoard* board, 
	cv::_InputArray* cameraMatrix,
	cv::_InputArray* distCoeffs, 
	cv::_InputOutputArray* rvec, 
	cv::_InputOutputArray* tvec,
	bool useExtrinsicGuess);


CVAPI(void) cveArucoDetectCharucoDiamond(
	cv::_InputArray* image,
	cv::_InputArray* markerCorners,
	cv::_InputArray* markerIds,
	float squareMarkerLengthRate,
	cv::_OutputArray* diamondCorners,
	cv::_OutputArray* diamondIds,
	cv::_InputArray* cameraMatrix,
	cv::_InputArray* distCoeffs);

CVAPI(void) cveArucoDrawDetectedDiamonds(
	cv::_InputOutputArray* image, 
	cv::_InputArray* diamondCorners,
	cv::_InputArray* diamondIds,
	CvScalar* borderColor);

CVAPI(void) cveArucoDrawCharucoDiamond(
	cv::aruco::Dictionary* dictionary, 
	int* ids, 
	int squareLength,
	int markerLength, 
	cv::_OutputArray* img, 
	int marginSize,
	int borderBits);

CVAPI(void) cveArucoDrawPlanarBoard(
	cv::aruco::Board* board, 
	CvSize* outSize, 
	cv::_OutputArray* img,
	int marginSize, 
	int borderBits);

CVAPI(int) cveArucoEstimatePoseBoard(
	cv::_InputArray* corners, 
	cv::_InputArray* ids, 
	cv::aruco::Board* board,
	cv::_InputArray* cameraMatrix, 
	cv::_InputArray* distCoeffs, 
	cv::_InputOutputArray* rvec,
	cv::_InputOutputArray* tvec, 
	bool useExtrinsicGuess);

CVAPI(void) cveArucoGetBoardObjectAndImagePoints(
	cv::aruco::Board* board, 
	cv::_InputArray* detectedCorners,
	cv::_InputArray* detectedIds, 
	cv::_OutputArray* objPoints, 
	cv::_OutputArray* imgPoints);

#endif