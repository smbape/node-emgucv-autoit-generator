#include "ml_c.h"
CVAPI(int) cveEMGetClustersNumber(cv::ml::EM* obj);
CVAPI(void) cveEMSetClustersNumber(cv::ml::EM* obj, int value);     
     
CVAPI(int) cveEMGetCovarianceMatrixType(cv::ml::EM* obj);
CVAPI(void) cveEMSetCovarianceMatrixType(cv::ml::EM* obj, int value);     
     
CVAPI(void) cveEMGetTermCriteria(cv::ml::EM* obj, CvTermCriteria* value);
CVAPI(void) cveEMSetTermCriteria(cv::ml::EM* obj, CvTermCriteria* value);     
     