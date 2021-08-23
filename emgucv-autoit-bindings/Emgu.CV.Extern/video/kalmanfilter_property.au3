#include-once
#include "..\..\CVEUtils.au3"

Func _cveKalmanFilterGetStatePre($obj)
    ; CVAPI(cv::Mat*) cveKalmanFilterGetStatePre(cv::KalmanFilter* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveKalmanFilterGetStatePre", $sObjDllType, $obj), "cveKalmanFilterGetStatePre", @error)
EndFunc   ;==>_cveKalmanFilterGetStatePre

Func _cveKalmanFilterGetStatePost($obj)
    ; CVAPI(cv::Mat*) cveKalmanFilterGetStatePost(cv::KalmanFilter* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveKalmanFilterGetStatePost", $sObjDllType, $obj), "cveKalmanFilterGetStatePost", @error)
EndFunc   ;==>_cveKalmanFilterGetStatePost

Func _cveKalmanFilterGetTransitionMatrix($obj)
    ; CVAPI(cv::Mat*) cveKalmanFilterGetTransitionMatrix(cv::KalmanFilter* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveKalmanFilterGetTransitionMatrix", $sObjDllType, $obj), "cveKalmanFilterGetTransitionMatrix", @error)
EndFunc   ;==>_cveKalmanFilterGetTransitionMatrix

Func _cveKalmanFilterGetControlMatrix($obj)
    ; CVAPI(cv::Mat*) cveKalmanFilterGetControlMatrix(cv::KalmanFilter* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveKalmanFilterGetControlMatrix", $sObjDllType, $obj), "cveKalmanFilterGetControlMatrix", @error)
EndFunc   ;==>_cveKalmanFilterGetControlMatrix

Func _cveKalmanFilterGetMeasurementMatrix($obj)
    ; CVAPI(cv::Mat*) cveKalmanFilterGetMeasurementMatrix(cv::KalmanFilter* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveKalmanFilterGetMeasurementMatrix", $sObjDllType, $obj), "cveKalmanFilterGetMeasurementMatrix", @error)
EndFunc   ;==>_cveKalmanFilterGetMeasurementMatrix

Func _cveKalmanFilterGetProcessNoiseCov($obj)
    ; CVAPI(cv::Mat*) cveKalmanFilterGetProcessNoiseCov(cv::KalmanFilter* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveKalmanFilterGetProcessNoiseCov", $sObjDllType, $obj), "cveKalmanFilterGetProcessNoiseCov", @error)
EndFunc   ;==>_cveKalmanFilterGetProcessNoiseCov

Func _cveKalmanFilterGetMeasurementNoiseCov($obj)
    ; CVAPI(cv::Mat*) cveKalmanFilterGetMeasurementNoiseCov(cv::KalmanFilter* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveKalmanFilterGetMeasurementNoiseCov", $sObjDllType, $obj), "cveKalmanFilterGetMeasurementNoiseCov", @error)
EndFunc   ;==>_cveKalmanFilterGetMeasurementNoiseCov

Func _cveKalmanFilterGetErrorCovPre($obj)
    ; CVAPI(cv::Mat*) cveKalmanFilterGetErrorCovPre(cv::KalmanFilter* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveKalmanFilterGetErrorCovPre", $sObjDllType, $obj), "cveKalmanFilterGetErrorCovPre", @error)
EndFunc   ;==>_cveKalmanFilterGetErrorCovPre

Func _cveKalmanFilterGetGain($obj)
    ; CVAPI(cv::Mat*) cveKalmanFilterGetGain(cv::KalmanFilter* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveKalmanFilterGetGain", $sObjDllType, $obj), "cveKalmanFilterGetGain", @error)
EndFunc   ;==>_cveKalmanFilterGetGain

Func _cveKalmanFilterGetErrorCovPost($obj)
    ; CVAPI(cv::Mat*) cveKalmanFilterGetErrorCovPost(cv::KalmanFilter* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveKalmanFilterGetErrorCovPost", $sObjDllType, $obj), "cveKalmanFilterGetErrorCovPost", @error)
EndFunc   ;==>_cveKalmanFilterGetErrorCovPost