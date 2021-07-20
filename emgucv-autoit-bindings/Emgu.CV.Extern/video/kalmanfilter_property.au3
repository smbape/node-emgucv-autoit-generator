#include-once
#include "..\..\CVEUtils.au3"

Func _cveKalmanFilterGetStatePre($obj)
    ; CVAPI(cv::Mat*) cveKalmanFilterGetStatePre(cv::KalmanFilter* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveKalmanFilterGetStatePre", "ptr", $obj), "cveKalmanFilterGetStatePre", @error)
EndFunc   ;==>_cveKalmanFilterGetStatePre

Func _cveKalmanFilterGetStatePost($obj)
    ; CVAPI(cv::Mat*) cveKalmanFilterGetStatePost(cv::KalmanFilter* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveKalmanFilterGetStatePost", "ptr", $obj), "cveKalmanFilterGetStatePost", @error)
EndFunc   ;==>_cveKalmanFilterGetStatePost

Func _cveKalmanFilterGetTransitionMatrix($obj)
    ; CVAPI(cv::Mat*) cveKalmanFilterGetTransitionMatrix(cv::KalmanFilter* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveKalmanFilterGetTransitionMatrix", "ptr", $obj), "cveKalmanFilterGetTransitionMatrix", @error)
EndFunc   ;==>_cveKalmanFilterGetTransitionMatrix

Func _cveKalmanFilterGetControlMatrix($obj)
    ; CVAPI(cv::Mat*) cveKalmanFilterGetControlMatrix(cv::KalmanFilter* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveKalmanFilterGetControlMatrix", "ptr", $obj), "cveKalmanFilterGetControlMatrix", @error)
EndFunc   ;==>_cveKalmanFilterGetControlMatrix

Func _cveKalmanFilterGetMeasurementMatrix($obj)
    ; CVAPI(cv::Mat*) cveKalmanFilterGetMeasurementMatrix(cv::KalmanFilter* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveKalmanFilterGetMeasurementMatrix", "ptr", $obj), "cveKalmanFilterGetMeasurementMatrix", @error)
EndFunc   ;==>_cveKalmanFilterGetMeasurementMatrix

Func _cveKalmanFilterGetProcessNoiseCov($obj)
    ; CVAPI(cv::Mat*) cveKalmanFilterGetProcessNoiseCov(cv::KalmanFilter* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveKalmanFilterGetProcessNoiseCov", "ptr", $obj), "cveKalmanFilterGetProcessNoiseCov", @error)
EndFunc   ;==>_cveKalmanFilterGetProcessNoiseCov

Func _cveKalmanFilterGetMeasurementNoiseCov($obj)
    ; CVAPI(cv::Mat*) cveKalmanFilterGetMeasurementNoiseCov(cv::KalmanFilter* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveKalmanFilterGetMeasurementNoiseCov", "ptr", $obj), "cveKalmanFilterGetMeasurementNoiseCov", @error)
EndFunc   ;==>_cveKalmanFilterGetMeasurementNoiseCov

Func _cveKalmanFilterGetErrorCovPre($obj)
    ; CVAPI(cv::Mat*) cveKalmanFilterGetErrorCovPre(cv::KalmanFilter* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveKalmanFilterGetErrorCovPre", "ptr", $obj), "cveKalmanFilterGetErrorCovPre", @error)
EndFunc   ;==>_cveKalmanFilterGetErrorCovPre

Func _cveKalmanFilterGetGain($obj)
    ; CVAPI(cv::Mat*) cveKalmanFilterGetGain(cv::KalmanFilter* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveKalmanFilterGetGain", "ptr", $obj), "cveKalmanFilterGetGain", @error)
EndFunc   ;==>_cveKalmanFilterGetGain

Func _cveKalmanFilterGetErrorCovPost($obj)
    ; CVAPI(cv::Mat*) cveKalmanFilterGetErrorCovPost(cv::KalmanFilter* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveKalmanFilterGetErrorCovPost", "ptr", $obj), "cveKalmanFilterGetErrorCovPost", @error)
EndFunc   ;==>_cveKalmanFilterGetErrorCovPost