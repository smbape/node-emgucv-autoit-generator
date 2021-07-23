#include "cudaobjdetect_c.h"
CVAPI(bool) cveCudaHOGGetGammaCorrection(void* obj);
CVAPI(void) cveCudaHOGSetGammaCorrection(void* obj, bool value);     
     
CVAPI(double) cveCudaHOGGetWinSigma(void* obj);
CVAPI(void) cveCudaHOGSetWinSigma(void* obj, double value);     
     
CVAPI(int) cveCudaHOGGetNumLevels(void* obj);
CVAPI(void) cveCudaHOGSetNumLevels(void* obj, int value);     
     
CVAPI(int) cveCudaHOGGetGroupThreshold(void* obj);
CVAPI(void) cveCudaHOGSetGroupThreshold(void* obj, int value);     
     
CVAPI(double) cveCudaHOGGetHitThreshold(void* obj);
CVAPI(void) cveCudaHOGSetHitThreshold(void* obj, double value);     
     
CVAPI(double) cveCudaHOGGetScaleFactor(void* obj);
CVAPI(void) cveCudaHOGSetScaleFactor(void* obj, double value);     
     
CVAPI(double) cveCudaHOGGetL2HysThreshold(void* obj);
CVAPI(void) cveCudaHOGSetL2HysThreshold(void* obj, double value);     
     
CVAPI(int) cveCudaHOGGetDescriptorFormat(void* obj);  
     
CVAPI(size_t) cveCudaHOGGetDescriptorSize(void* obj);  
     
CVAPI(void) cveCudaHOGGetWinStride(void* obj, CvSize* value);
CVAPI(void) cveCudaHOGSetWinStride(void* obj, CvSize* value);     
     
CVAPI(size_t) cveCudaHOGGetBlockHistogramSize(void* obj);  
     