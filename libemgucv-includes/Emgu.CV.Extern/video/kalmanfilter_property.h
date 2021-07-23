#include "video_c.h"
CVAPI(cv::Mat*) cveKalmanFilterGetStatePre(cv::KalmanFilter* obj);
     
CVAPI(cv::Mat*) cveKalmanFilterGetStatePost(cv::KalmanFilter* obj);
     
CVAPI(cv::Mat*) cveKalmanFilterGetTransitionMatrix(cv::KalmanFilter* obj);
     
CVAPI(cv::Mat*) cveKalmanFilterGetControlMatrix(cv::KalmanFilter* obj);
     
CVAPI(cv::Mat*) cveKalmanFilterGetMeasurementMatrix(cv::KalmanFilter* obj);
     
CVAPI(cv::Mat*) cveKalmanFilterGetProcessNoiseCov(cv::KalmanFilter* obj);
     
CVAPI(cv::Mat*) cveKalmanFilterGetMeasurementNoiseCov(cv::KalmanFilter* obj);
     
CVAPI(cv::Mat*) cveKalmanFilterGetErrorCovPre(cv::KalmanFilter* obj);
     
CVAPI(cv::Mat*) cveKalmanFilterGetGain(cv::KalmanFilter* obj);
     
CVAPI(cv::Mat*) cveKalmanFilterGetErrorCovPost(cv::KalmanFilter* obj);
     