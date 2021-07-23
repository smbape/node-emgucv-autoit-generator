#include "videoio_c_extra.h"
CVAPI(bool) cveVideoCaptureIsOpened(cv::VideoCapture* obj);  
     
CVAPI(bool) cveVideoCaptureGetExceptionMode(cv::VideoCapture* obj);
CVAPI(void) cveVideoCaptureSetExceptionMode(cv::VideoCapture* obj, bool value);     
     