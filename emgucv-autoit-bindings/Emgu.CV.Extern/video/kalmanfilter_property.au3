#include-once
#include "..\..\CVEUtils.au3"

Func _cveKalmanFilterGetStatePre($obj)
    ; CVAPI(cv::Mat*) cveKalmanFilterGetStatePre(cv::KalmanFilter* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveKalmanFilterGetStatePre", $bObjDllType, $obj), "cveKalmanFilterGetStatePre", @error)
EndFunc   ;==>_cveKalmanFilterGetStatePre

Func _cveKalmanFilterGetStatePost($obj)
    ; CVAPI(cv::Mat*) cveKalmanFilterGetStatePost(cv::KalmanFilter* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveKalmanFilterGetStatePost", $bObjDllType, $obj), "cveKalmanFilterGetStatePost", @error)
EndFunc   ;==>_cveKalmanFilterGetStatePost

Func _cveKalmanFilterGetTransitionMatrix($obj)
    ; CVAPI(cv::Mat*) cveKalmanFilterGetTransitionMatrix(cv::KalmanFilter* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveKalmanFilterGetTransitionMatrix", $bObjDllType, $obj), "cveKalmanFilterGetTransitionMatrix", @error)
EndFunc   ;==>_cveKalmanFilterGetTransitionMatrix

Func _cveKalmanFilterGetControlMatrix($obj)
    ; CVAPI(cv::Mat*) cveKalmanFilterGetControlMatrix(cv::KalmanFilter* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveKalmanFilterGetControlMatrix", $bObjDllType, $obj), "cveKalmanFilterGetControlMatrix", @error)
EndFunc   ;==>_cveKalmanFilterGetControlMatrix

Func _cveKalmanFilterGetMeasurementMatrix($obj)
    ; CVAPI(cv::Mat*) cveKalmanFilterGetMeasurementMatrix(cv::KalmanFilter* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveKalmanFilterGetMeasurementMatrix", $bObjDllType, $obj), "cveKalmanFilterGetMeasurementMatrix", @error)
EndFunc   ;==>_cveKalmanFilterGetMeasurementMatrix

Func _cveKalmanFilterGetProcessNoiseCov($obj)
    ; CVAPI(cv::Mat*) cveKalmanFilterGetProcessNoiseCov(cv::KalmanFilter* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveKalmanFilterGetProcessNoiseCov", $bObjDllType, $obj), "cveKalmanFilterGetProcessNoiseCov", @error)
EndFunc   ;==>_cveKalmanFilterGetProcessNoiseCov

Func _cveKalmanFilterGetMeasurementNoiseCov($obj)
    ; CVAPI(cv::Mat*) cveKalmanFilterGetMeasurementNoiseCov(cv::KalmanFilter* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveKalmanFilterGetMeasurementNoiseCov", $bObjDllType, $obj), "cveKalmanFilterGetMeasurementNoiseCov", @error)
EndFunc   ;==>_cveKalmanFilterGetMeasurementNoiseCov

Func _cveKalmanFilterGetErrorCovPre($obj)
    ; CVAPI(cv::Mat*) cveKalmanFilterGetErrorCovPre(cv::KalmanFilter* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveKalmanFilterGetErrorCovPre", $bObjDllType, $obj), "cveKalmanFilterGetErrorCovPre", @error)
EndFunc   ;==>_cveKalmanFilterGetErrorCovPre

Func _cveKalmanFilterGetGain($obj)
    ; CVAPI(cv::Mat*) cveKalmanFilterGetGain(cv::KalmanFilter* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveKalmanFilterGetGain", $bObjDllType, $obj), "cveKalmanFilterGetGain", @error)
EndFunc   ;==>_cveKalmanFilterGetGain

Func _cveKalmanFilterGetErrorCovPost($obj)
    ; CVAPI(cv::Mat*) cveKalmanFilterGetErrorCovPost(cv::KalmanFilter* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveKalmanFilterGetErrorCovPost", $bObjDllType, $obj), "cveKalmanFilterGetErrorCovPost", @error)
EndFunc   ;==>_cveKalmanFilterGetErrorCovPost