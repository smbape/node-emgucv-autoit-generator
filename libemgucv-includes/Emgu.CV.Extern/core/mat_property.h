#include "mat_c.h"
CVAPI(bool) cveMatIsContinuous(cv::Mat* obj);  
     
CVAPI(bool) cveMatIsSubmatrix(cv::Mat* obj);  
     
CVAPI(int) cveMatDepth(cv::Mat* obj);  
     
CVAPI(bool) cveMatIsEmpty(cv::Mat* obj);  
     
CVAPI(int) cveMatNumberOfChannels(cv::Mat* obj);  
     
CVAPI(void) cveMatPopBack(cv::Mat* obj, int value);     
     
CVAPI(void) cveMatPushBack(cv::Mat* obj, cv::Mat* value);     
     
CVAPI(size_t) cveMatTotal(cv::Mat* obj);  
     
CVAPI(int) cveMatGetDims(cv::Mat* obj);
     