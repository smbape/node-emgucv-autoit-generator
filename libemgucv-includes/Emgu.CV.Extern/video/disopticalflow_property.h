#include "video_c.h"
CVAPI(int) cveDISOpticalFlowGetFinestScale(cv::DISOpticalFlow* obj);
CVAPI(void) cveDISOpticalFlowSetFinestScale(cv::DISOpticalFlow* obj, int value);     
     
CVAPI(int) cveDISOpticalFlowGetPatchSize(cv::DISOpticalFlow* obj);
CVAPI(void) cveDISOpticalFlowSetPatchSize(cv::DISOpticalFlow* obj, int value);     
     
CVAPI(int) cveDISOpticalFlowGetPatchStride(cv::DISOpticalFlow* obj);
CVAPI(void) cveDISOpticalFlowSetPatchStride(cv::DISOpticalFlow* obj, int value);     
     
CVAPI(int) cveDISOpticalFlowGetGradientDescentIterations(cv::DISOpticalFlow* obj);
CVAPI(void) cveDISOpticalFlowSetGradientDescentIterations(cv::DISOpticalFlow* obj, int value);     
     
CVAPI(int) cveDISOpticalFlowGetVariationalRefinementIterations(cv::DISOpticalFlow* obj);
CVAPI(void) cveDISOpticalFlowSetVariationalRefinementIterations(cv::DISOpticalFlow* obj, int value);     
     
CVAPI(float) cveDISOpticalFlowGetVariationalRefinementAlpha(cv::DISOpticalFlow* obj);
CVAPI(void) cveDISOpticalFlowSetVariationalRefinementAlpha(cv::DISOpticalFlow* obj, float value);     
     
CVAPI(float) cveDISOpticalFlowGetVariationalRefinementDelta(cv::DISOpticalFlow* obj);
CVAPI(void) cveDISOpticalFlowSetVariationalRefinementDelta(cv::DISOpticalFlow* obj, float value);     
     
CVAPI(float) cveDISOpticalFlowGetVariationalRefinementGamma(cv::DISOpticalFlow* obj);
CVAPI(void) cveDISOpticalFlowSetVariationalRefinementGamma(cv::DISOpticalFlow* obj, float value);     
     
CVAPI(bool) cveDISOpticalFlowGetUseMeanNormalization(cv::DISOpticalFlow* obj);
CVAPI(void) cveDISOpticalFlowSetUseMeanNormalization(cv::DISOpticalFlow* obj, bool value);     
     
CVAPI(bool) cveDISOpticalFlowGetUseSpatialPropagation(cv::DISOpticalFlow* obj);
CVAPI(void) cveDISOpticalFlowSetUseSpatialPropagation(cv::DISOpticalFlow* obj, bool value);     
     