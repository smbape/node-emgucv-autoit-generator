#include "ml_c.h"
CVAPI(int) cveSVMSGDGetType(cv::ml::SVMSGD* obj);
CVAPI(void) cveSVMSGDSetType(cv::ml::SVMSGD* obj, int value);     
     
CVAPI(int) cveSVMSGDGetMargin(cv::ml::SVMSGD* obj);
CVAPI(void) cveSVMSGDSetMargin(cv::ml::SVMSGD* obj, int value);     
     
CVAPI(float) cveSVMSGDGetMarginRegularization(cv::ml::SVMSGD* obj);
CVAPI(void) cveSVMSGDSetMarginRegularization(cv::ml::SVMSGD* obj, float value);     
     
CVAPI(float) cveSVMSGDGetInitialStepSize(cv::ml::SVMSGD* obj);
CVAPI(void) cveSVMSGDSetInitialStepSize(cv::ml::SVMSGD* obj, float value);     
     
CVAPI(float) cveSVMSGDGetStepDecreasingPower(cv::ml::SVMSGD* obj);
CVAPI(void) cveSVMSGDSetStepDecreasingPower(cv::ml::SVMSGD* obj, float value);     
     
CVAPI(void) cveSVMSGDGetTermCriteria(cv::ml::SVMSGD* obj, CvTermCriteria* value);
CVAPI(void) cveSVMSGDSetTermCriteria(cv::ml::SVMSGD* obj, CvTermCriteria* value);     
     