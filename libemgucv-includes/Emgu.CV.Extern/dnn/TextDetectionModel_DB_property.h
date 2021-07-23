#include "dnn_c.h"
CVAPI(float) cveTextDetectionModel_DBGetBinaryThreshold(cv::dnn::TextDetectionModel_DB* obj);
CVAPI(void) cveTextDetectionModel_DBSetBinaryThreshold(cv::dnn::TextDetectionModel_DB* obj, float value);     
     
CVAPI(float) cveTextDetectionModel_DBGetPolygonThreshold(cv::dnn::TextDetectionModel_DB* obj);
CVAPI(void) cveTextDetectionModel_DBSetPolygonThreshold(cv::dnn::TextDetectionModel_DB* obj, float value);     
     
CVAPI(double) cveTextDetectionModel_DBGetUnclipRatio(cv::dnn::TextDetectionModel_DB* obj);
CVAPI(void) cveTextDetectionModel_DBSetUnclipRatio(cv::dnn::TextDetectionModel_DB* obj, double value);     
     
CVAPI(int) cveTextDetectionModel_DBGetMaxCandidates(cv::dnn::TextDetectionModel_DB* obj);
CVAPI(void) cveTextDetectionModel_DBSetMaxCandidates(cv::dnn::TextDetectionModel_DB* obj, int value);     
     