#include "ml_c.h"
CVAPI(void) cveANN_MLPGetTermCriteria(cv::ml::ANN_MLP* obj, CvTermCriteria* value);
CVAPI(void) cveANN_MLPSetTermCriteria(cv::ml::ANN_MLP* obj, CvTermCriteria* value);     
     
CVAPI(double) cveANN_MLPGetBackpropWeightScale(cv::ml::ANN_MLP* obj);
CVAPI(void) cveANN_MLPSetBackpropWeightScale(cv::ml::ANN_MLP* obj, double value);     
     
CVAPI(double) cveANN_MLPGetBackpropMomentumScale(cv::ml::ANN_MLP* obj);
CVAPI(void) cveANN_MLPSetBackpropMomentumScale(cv::ml::ANN_MLP* obj, double value);     
     
CVAPI(double) cveANN_MLPGetRpropDW0(cv::ml::ANN_MLP* obj);
CVAPI(void) cveANN_MLPSetRpropDW0(cv::ml::ANN_MLP* obj, double value);     
     
CVAPI(double) cveANN_MLPGetRpropDWPlus(cv::ml::ANN_MLP* obj);
CVAPI(void) cveANN_MLPSetRpropDWPlus(cv::ml::ANN_MLP* obj, double value);     
     
CVAPI(double) cveANN_MLPGetRpropDWMinus(cv::ml::ANN_MLP* obj);
CVAPI(void) cveANN_MLPSetRpropDWMinus(cv::ml::ANN_MLP* obj, double value);     
     
CVAPI(double) cveANN_MLPGetRpropDWMin(cv::ml::ANN_MLP* obj);
CVAPI(void) cveANN_MLPSetRpropDWMin(cv::ml::ANN_MLP* obj, double value);     
     
CVAPI(double) cveANN_MLPGetRpropDWMax(cv::ml::ANN_MLP* obj);
CVAPI(void) cveANN_MLPSetRpropDWMax(cv::ml::ANN_MLP* obj, double value);     
     
CVAPI(double) cveANN_MLPGetAnnealInitialT(cv::ml::ANN_MLP* obj);
CVAPI(void) cveANN_MLPSetAnnealInitialT(cv::ml::ANN_MLP* obj, double value);     
     
CVAPI(double) cveANN_MLPGetAnnealFinalT(cv::ml::ANN_MLP* obj);
CVAPI(void) cveANN_MLPSetAnnealFinalT(cv::ml::ANN_MLP* obj, double value);     
     
CVAPI(double) cveANN_MLPGetAnnealCoolingRatio(cv::ml::ANN_MLP* obj);
CVAPI(void) cveANN_MLPSetAnnealCoolingRatio(cv::ml::ANN_MLP* obj, double value);     
     
CVAPI(int) cveANN_MLPGetAnnealItePerStep(cv::ml::ANN_MLP* obj);
CVAPI(void) cveANN_MLPSetAnnealItePerStep(cv::ml::ANN_MLP* obj, int value);     
     