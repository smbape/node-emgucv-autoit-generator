#include "ml_c.h"
CVAPI(double) cveLogisticRegressionGetLearningRate(cv::ml::LogisticRegression* obj);
CVAPI(void) cveLogisticRegressionSetLearningRate(cv::ml::LogisticRegression* obj, double value);     
     
CVAPI(int) cveLogisticRegressionGetIterations(cv::ml::LogisticRegression* obj);
CVAPI(void) cveLogisticRegressionSetIterations(cv::ml::LogisticRegression* obj, int value);     
     
CVAPI(int) cveLogisticRegressionGetRegularization(cv::ml::LogisticRegression* obj);
CVAPI(void) cveLogisticRegressionSetRegularization(cv::ml::LogisticRegression* obj, int value);     
     
CVAPI(int) cveLogisticRegressionGetTrainMethod(cv::ml::LogisticRegression* obj);
CVAPI(void) cveLogisticRegressionSetTrainMethod(cv::ml::LogisticRegression* obj, int value);     
     
CVAPI(int) cveLogisticRegressionGetMiniBatchSize(cv::ml::LogisticRegression* obj);
CVAPI(void) cveLogisticRegressionSetMiniBatchSize(cv::ml::LogisticRegression* obj, int value);     
     
CVAPI(void) cveLogisticRegressionGetTermCriteria(cv::ml::LogisticRegression* obj, CvTermCriteria* value);
CVAPI(void) cveLogisticRegressionSetTermCriteria(cv::ml::LogisticRegression* obj, CvTermCriteria* value);     
     