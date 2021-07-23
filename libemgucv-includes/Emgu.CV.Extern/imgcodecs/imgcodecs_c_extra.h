//----------------------------------------------------------------------------
//
//  Copyright (C) 2004-2021 by EMGU Corporation. All rights reserved.
//
//----------------------------------------------------------------------------

#pragma once
#ifndef EMGU_IMGCODECS_C_H
#define EMGU_IMGCODECS_C_H

#include "opencv2/core/core_c.h"
#include "opencv2/imgcodecs/imgcodecs.hpp"

CVAPI(bool) cveHaveImageReader(cv::String* filename);
CVAPI(bool) cveHaveImageWriter(cv::String* filename);

CVAPI(bool) cveImwrite(cv::String* filename, cv::_InputArray* img, std::vector<int>* params);
CVAPI(bool) cveImwritemulti(cv::String* filename, cv::_InputArray* img, std::vector<int>* params);

CVAPI(void) cveImread(cv::String* fileName, int flags, cv::Mat* result);
CVAPI(bool) cveImreadmulti(const cv::String* filename, std::vector<cv::Mat>* mats, int flags);

CVAPI(void) cveImdecode(cv::_InputArray* buf, int flags, cv::Mat* dst);
CVAPI(bool) cveImencode(cv::String* ext, cv::_InputArray* img, std::vector< unsigned char >* buf, std::vector< int >* params);

#endif