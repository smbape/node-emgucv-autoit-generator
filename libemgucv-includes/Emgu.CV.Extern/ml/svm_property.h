#include "ml_c.h"
CVAPI(int) cveSVMGetType(cv::ml::SVM* obj);
CVAPI(void) cveSVMSetType(cv::ml::SVM* obj, int value);     
     
CVAPI(double) cveSVMGetGamma(cv::ml::SVM* obj);
CVAPI(void) cveSVMSetGamma(cv::ml::SVM* obj, double value);     
     
CVAPI(double) cveSVMGetCoef0(cv::ml::SVM* obj);
CVAPI(void) cveSVMSetCoef0(cv::ml::SVM* obj, double value);     
     
CVAPI(double) cveSVMGetDegree(cv::ml::SVM* obj);
CVAPI(void) cveSVMSetDegree(cv::ml::SVM* obj, double value);     
     
CVAPI(double) cveSVMGetC(cv::ml::SVM* obj);
CVAPI(void) cveSVMSetC(cv::ml::SVM* obj, double value);     
     
CVAPI(double) cveSVMGetNu(cv::ml::SVM* obj);
CVAPI(void) cveSVMSetNu(cv::ml::SVM* obj, double value);     
     
CVAPI(double) cveSVMGetP(cv::ml::SVM* obj);
CVAPI(void) cveSVMSetP(cv::ml::SVM* obj, double value);     
     
CVAPI(void) cveSVMSetKernel(cv::ml::SVM* obj, int value);     
     
CVAPI(void) cveSVMGetTermCriteria(cv::ml::SVM* obj, CvTermCriteria* value);
CVAPI(void) cveSVMSetTermCriteria(cv::ml::SVM* obj, CvTermCriteria* value);     
     
CVAPI(int) cveSVMGetKernelType(cv::ml::SVM* obj);  
     