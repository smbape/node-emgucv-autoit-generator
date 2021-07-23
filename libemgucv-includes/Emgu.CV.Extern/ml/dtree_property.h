#include "ml_c.h"
CVAPI(int) cveDTreesGetMaxCategories(cv::ml::DTrees* obj);
CVAPI(void) cveDTreesSetMaxCategories(cv::ml::DTrees* obj, int value);     
     
CVAPI(int) cveDTreesGetMaxDepth(cv::ml::DTrees* obj);
CVAPI(void) cveDTreesSetMaxDepth(cv::ml::DTrees* obj, int value);     
     
CVAPI(int) cveDTreesGetMinSampleCount(cv::ml::DTrees* obj);
CVAPI(void) cveDTreesSetMinSampleCount(cv::ml::DTrees* obj, int value);     
     
CVAPI(int) cveDTreesGetCVFolds(cv::ml::DTrees* obj);
CVAPI(void) cveDTreesSetCVFolds(cv::ml::DTrees* obj, int value);     
     
CVAPI(bool) cveDTreesGetUseSurrogates(cv::ml::DTrees* obj);
CVAPI(void) cveDTreesSetUseSurrogates(cv::ml::DTrees* obj, bool value);     
     
CVAPI(bool) cveDTreesGetUse1SERule(cv::ml::DTrees* obj);
CVAPI(void) cveDTreesSetUse1SERule(cv::ml::DTrees* obj, bool value);     
     
CVAPI(bool) cveDTreesGetTruncatePrunedTree(cv::ml::DTrees* obj);
CVAPI(void) cveDTreesSetTruncatePrunedTree(cv::ml::DTrees* obj, bool value);     
     
CVAPI(float) cveDTreesGetRegressionAccuracy(cv::ml::DTrees* obj);
CVAPI(void) cveDTreesSetRegressionAccuracy(cv::ml::DTrees* obj, float value);     
     