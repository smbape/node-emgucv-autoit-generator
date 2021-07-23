#include "ml_c.h"
CVAPI(int) cveRTreesGetMaxCategories(cv::ml::RTrees* obj);
CVAPI(void) cveRTreesSetMaxCategories(cv::ml::RTrees* obj, int value);     
     
CVAPI(int) cveRTreesGetMaxDepth(cv::ml::RTrees* obj);
CVAPI(void) cveRTreesSetMaxDepth(cv::ml::RTrees* obj, int value);     
     
CVAPI(int) cveRTreesGetMinSampleCount(cv::ml::RTrees* obj);
CVAPI(void) cveRTreesSetMinSampleCount(cv::ml::RTrees* obj, int value);     
     
CVAPI(int) cveRTreesGetCVFolds(cv::ml::RTrees* obj);
CVAPI(void) cveRTreesSetCVFolds(cv::ml::RTrees* obj, int value);     
     
CVAPI(bool) cveRTreesGetUseSurrogates(cv::ml::RTrees* obj);
CVAPI(void) cveRTreesSetUseSurrogates(cv::ml::RTrees* obj, bool value);     
     
CVAPI(bool) cveRTreesGetUse1SERule(cv::ml::RTrees* obj);
CVAPI(void) cveRTreesSetUse1SERule(cv::ml::RTrees* obj, bool value);     
     
CVAPI(bool) cveRTreesGetTruncatePrunedTree(cv::ml::RTrees* obj);
CVAPI(void) cveRTreesSetTruncatePrunedTree(cv::ml::RTrees* obj, bool value);     
     
CVAPI(float) cveRTreesGetRegressionAccuracy(cv::ml::RTrees* obj);
CVAPI(void) cveRTreesSetRegressionAccuracy(cv::ml::RTrees* obj, float value);     
     
CVAPI(bool) cveRTreesGetCalculateVarImportance(cv::ml::RTrees* obj);
CVAPI(void) cveRTreesSetCalculateVarImportance(cv::ml::RTrees* obj, bool value);     
     
CVAPI(int) cveRTreesGetActiveVarCount(cv::ml::RTrees* obj);
CVAPI(void) cveRTreesSetActiveVarCount(cv::ml::RTrees* obj, int value);     
     
CVAPI(void) cveRTreesGetTermCriteria(cv::ml::RTrees* obj, CvTermCriteria* value);
CVAPI(void) cveRTreesSetTermCriteria(cv::ml::RTrees* obj, CvTermCriteria* value);     
     