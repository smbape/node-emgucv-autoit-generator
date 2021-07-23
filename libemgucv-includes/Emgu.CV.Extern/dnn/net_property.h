#include "dnn_c.h"
CVAPI(void) cveNetSetPreferableBackend(cv::dnn::Net* obj, int value);     
     
CVAPI(void) cveNetSetPreferableTarget(cv::dnn::Net* obj, int value);     
     
CVAPI(void) cveNetEnableFusion(cv::dnn::Net* obj, bool value);     
     
CVAPI(bool) cveNetEmpty(cv::dnn::Net* obj);  
     
CVAPI(void) cveNetSetHalideScheduler(cv::dnn::Net* obj, cv::String* str);  
     