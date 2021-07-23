#include "ml_c.h"
CVAPI(int) cveBoostGetMaxCategories(cv::ml::Boost* obj);
CVAPI(void) cveBoostSetMaxCategories(cv::ml::Boost* obj, int value);     
     
CVAPI(int) cveBoostGetMaxDepth(cv::ml::Boost* obj);
CVAPI(void) cveBoostSetMaxDepth(cv::ml::Boost* obj, int value);     
     
CVAPI(int) cveBoostGetMinSampleCount(cv::ml::Boost* obj);
CVAPI(void) cveBoostSetMinSampleCount(cv::ml::Boost* obj, int value);     
     
CVAPI(int) cveBoostGetCVFolds(cv::ml::Boost* obj);
CVAPI(void) cveBoostSetCVFolds(cv::ml::Boost* obj, int value);     
     
CVAPI(bool) cveBoostGetUseSurrogates(cv::ml::Boost* obj);
CVAPI(void) cveBoostSetUseSurrogates(cv::ml::Boost* obj, bool value);     
     
CVAPI(bool) cveBoostGetUse1SERule(cv::ml::Boost* obj);
CVAPI(void) cveBoostSetUse1SERule(cv::ml::Boost* obj, bool value);     
     
CVAPI(bool) cveBoostGetTruncatePrunedTree(cv::ml::Boost* obj);
CVAPI(void) cveBoostSetTruncatePrunedTree(cv::ml::Boost* obj, bool value);     
     
CVAPI(float) cveBoostGetRegressionAccuracy(cv::ml::Boost* obj);
CVAPI(void) cveBoostSetRegressionAccuracy(cv::ml::Boost* obj, float value);     
     