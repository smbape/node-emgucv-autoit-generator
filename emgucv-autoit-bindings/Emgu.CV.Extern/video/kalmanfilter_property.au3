#include-once
#include "..\..\CVEUtils.au3"

Func _cveKalmanFilterGetStatePre(ByRef $obj)
    ; CVAPI(cv::Mat*) cveKalmanFilterGetStatePre(cv::KalmanFilter* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveKalmanFilterGetStatePre", "ptr", $obj), "cveKalmanFilterGetStatePre", @error)
EndFunc   ;==>_cveKalmanFilterGetStatePre

Func _cveKalmanFilterGetStatePost(ByRef $obj)
    ; CVAPI(cv::Mat*) cveKalmanFilterGetStatePost(cv::KalmanFilter* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveKalmanFilterGetStatePost", "ptr", $obj), "cveKalmanFilterGetStatePost", @error)
EndFunc   ;==>_cveKalmanFilterGetStatePost

Func _cveKalmanFilterGetTransitionMatrix(ByRef $obj)
    ; CVAPI(cv::Mat*) cveKalmanFilterGetTransitionMatrix(cv::KalmanFilter* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveKalmanFilterGetTransitionMatrix", "ptr", $obj), "cveKalmanFilterGetTransitionMatrix", @error)
EndFunc   ;==>_cveKalmanFilterGetTransitionMatrix

Func _cveKalmanFilterGetControlMatrix(ByRef $obj)
    ; CVAPI(cv::Mat*) cveKalmanFilterGetControlMatrix(cv::KalmanFilter* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveKalmanFilterGetControlMatrix", "ptr", $obj), "cveKalmanFilterGetControlMatrix", @error)
EndFunc   ;==>_cveKalmanFilterGetControlMatrix

Func _cveKalmanFilterGetMeasurementMatrix(ByRef $obj)
    ; CVAPI(cv::Mat*) cveKalmanFilterGetMeasurementMatrix(cv::KalmanFilter* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveKalmanFilterGetMeasurementMatrix", "ptr", $obj), "cveKalmanFilterGetMeasurementMatrix", @error)
EndFunc   ;==>_cveKalmanFilterGetMeasurementMatrix

Func _cveKalmanFilterGetProcessNoiseCov(ByRef $obj)
    ; CVAPI(cv::Mat*) cveKalmanFilterGetProcessNoiseCov(cv::KalmanFilter* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveKalmanFilterGetProcessNoiseCov", "ptr", $obj), "cveKalmanFilterGetProcessNoiseCov", @error)
EndFunc   ;==>_cveKalmanFilterGetProcessNoiseCov

Func _cveKalmanFilterGetMeasurementNoiseCov(ByRef $obj)
    ; CVAPI(cv::Mat*) cveKalmanFilterGetMeasurementNoiseCov(cv::KalmanFilter* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveKalmanFilterGetMeasurementNoiseCov", "ptr", $obj), "cveKalmanFilterGetMeasurementNoiseCov", @error)
EndFunc   ;==>_cveKalmanFilterGetMeasurementNoiseCov

Func _cveKalmanFilterGetErrorCovPre(ByRef $obj)
    ; CVAPI(cv::Mat*) cveKalmanFilterGetErrorCovPre(cv::KalmanFilter* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveKalmanFilterGetErrorCovPre", "ptr", $obj), "cveKalmanFilterGetErrorCovPre", @error)
EndFunc   ;==>_cveKalmanFilterGetErrorCovPre

Func _cveKalmanFilterGetGain(ByRef $obj)
    ; CVAPI(cv::Mat*) cveKalmanFilterGetGain(cv::KalmanFilter* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveKalmanFilterGetGain", "ptr", $obj), "cveKalmanFilterGetGain", @error)
EndFunc   ;==>_cveKalmanFilterGetGain

Func _cveKalmanFilterGetErrorCovPost(ByRef $obj)
    ; CVAPI(cv::Mat*) cveKalmanFilterGetErrorCovPost(cv::KalmanFilter* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveKalmanFilterGetErrorCovPost", "ptr", $obj), "cveKalmanFilterGetErrorCovPost", @error)
EndFunc   ;==>_cveKalmanFilterGetErrorCovPost