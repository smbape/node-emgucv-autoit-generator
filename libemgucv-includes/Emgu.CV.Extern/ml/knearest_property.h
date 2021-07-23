#include "ml_c.h"
CVAPI(int) cveKNearestGetDefaultK(cv::ml::KNearest* obj);
CVAPI(void) cveKNearestSetDefaultK(cv::ml::KNearest* obj, int value);     
     
CVAPI(bool) cveKNearestGetIsClassifier(cv::ml::KNearest* obj);
CVAPI(void) cveKNearestSetIsClassifier(cv::ml::KNearest* obj, bool value);     
     
CVAPI(int) cveKNearestGetEmax(cv::ml::KNearest* obj);
CVAPI(void) cveKNearestSetEmax(cv::ml::KNearest* obj, int value);     
     
CVAPI(int) cveKNearestGetAlgorithmType(cv::ml::KNearest* obj);
CVAPI(void) cveKNearestSetAlgorithmType(cv::ml::KNearest* obj, int value);     
     