#include "cudaimgproc_c.h"
CVAPI(float) cveCudaHoughLinesDetectorGetRho(void* obj);
CVAPI(void) cveCudaHoughLinesDetectorSetRho(void* obj, float value);     
     
CVAPI(float) cveCudaHoughLinesDetectorGetTheta(void* obj);
CVAPI(void) cveCudaHoughLinesDetectorSetTheta(void* obj, float value);     
     
CVAPI(int) cveCudaHoughLinesDetectorGetThreshold(void* obj);
CVAPI(void) cveCudaHoughLinesDetectorSetThreshold(void* obj, int value);     
     
CVAPI(bool) cveCudaHoughLinesDetectorGetDoSort(void* obj);
CVAPI(void) cveCudaHoughLinesDetectorSetDoSort(void* obj, bool value);     
     
CVAPI(int) cveCudaHoughLinesDetectorGetMaxLines(void* obj);
CVAPI(void) cveCudaHoughLinesDetectorSetMaxLines(void* obj, int value);     
     