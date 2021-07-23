#include "dnn_c.h"
CVAPI(void) cveLayerGetName(cv::dnn::Layer* obj, cv::String* str);   
     
CVAPI(void) cveLayerGetType(cv::dnn::Layer* obj, cv::String* str);   
     
CVAPI(int) cveLayerGetPreferableTarget(cv::dnn::Layer* obj);
     