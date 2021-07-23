#include "cudaobjdetect_c.h"
CVAPI(double) cveCudaCascadeClassifierGetScaleFactor(void* obj);
CVAPI(void) cveCudaCascadeClassifierSetScaleFactor(void* obj, double value);     
     
CVAPI(int) cveCudaCascadeClassifierGetMinNeighbors(void* obj);
CVAPI(void) cveCudaCascadeClassifierSetMinNeighbors(void* obj, int value);     
     
CVAPI(int) cveCudaCascadeClassifierGetMaxNumObjects(void* obj);
CVAPI(void) cveCudaCascadeClassifierSetMaxNumObjects(void* obj, int value);     
     
CVAPI(bool) cveCudaCascadeClassifierGetFindLargestObject(void* obj);
CVAPI(void) cveCudaCascadeClassifierSetFindLargestObject(void* obj, bool value);     
     
CVAPI(void) cveCudaCascadeClassifierGetMaxObjectSize(void* obj, CvSize* value);
CVAPI(void) cveCudaCascadeClassifierSetMaxObjectSize(void* obj, CvSize* value);     
     
CVAPI(void) cveCudaCascadeClassifierGetMinObjectSize(void* obj, CvSize* value);
CVAPI(void) cveCudaCascadeClassifierSetMinObjectSize(void* obj, CvSize* value);     
     
CVAPI(void) cveCudaCascadeClassifierGetClassifierSize(void* obj, CvSize* value);
     