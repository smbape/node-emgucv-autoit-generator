#include-once
#include "..\..\CVEUtils.au3"

Func _cveBackgroundSubtractorKNNGetHistory($obj)
    ; CVAPI(int) cveBackgroundSubtractorKNNGetHistory(cv::BackgroundSubtractorKNN* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveBackgroundSubtractorKNNGetHistory", $bObjDllType, $obj), "cveBackgroundSubtractorKNNGetHistory", @error)
EndFunc   ;==>_cveBackgroundSubtractorKNNGetHistory

Func _cveBackgroundSubtractorKNNSetHistory($obj, $value)
    ; CVAPI(void) cveBackgroundSubtractorKNNSetHistory(cv::BackgroundSubtractorKNN* obj, int value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBackgroundSubtractorKNNSetHistory", $bObjDllType, $obj, "int", $value), "cveBackgroundSubtractorKNNSetHistory", @error)
EndFunc   ;==>_cveBackgroundSubtractorKNNSetHistory

Func _cveBackgroundSubtractorKNNGetNSamples($obj)
    ; CVAPI(int) cveBackgroundSubtractorKNNGetNSamples(cv::BackgroundSubtractorKNN* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveBackgroundSubtractorKNNGetNSamples", $bObjDllType, $obj), "cveBackgroundSubtractorKNNGetNSamples", @error)
EndFunc   ;==>_cveBackgroundSubtractorKNNGetNSamples

Func _cveBackgroundSubtractorKNNSetNSamples($obj, $value)
    ; CVAPI(void) cveBackgroundSubtractorKNNSetNSamples(cv::BackgroundSubtractorKNN* obj, int value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBackgroundSubtractorKNNSetNSamples", $bObjDllType, $obj, "int", $value), "cveBackgroundSubtractorKNNSetNSamples", @error)
EndFunc   ;==>_cveBackgroundSubtractorKNNSetNSamples

Func _cveBackgroundSubtractorKNNGetDist2Threshold($obj)
    ; CVAPI(double) cveBackgroundSubtractorKNNGetDist2Threshold(cv::BackgroundSubtractorKNN* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveBackgroundSubtractorKNNGetDist2Threshold", $bObjDllType, $obj), "cveBackgroundSubtractorKNNGetDist2Threshold", @error)
EndFunc   ;==>_cveBackgroundSubtractorKNNGetDist2Threshold

Func _cveBackgroundSubtractorKNNSetDist2Threshold($obj, $value)
    ; CVAPI(void) cveBackgroundSubtractorKNNSetDist2Threshold(cv::BackgroundSubtractorKNN* obj, double value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBackgroundSubtractorKNNSetDist2Threshold", $bObjDllType, $obj, "double", $value), "cveBackgroundSubtractorKNNSetDist2Threshold", @error)
EndFunc   ;==>_cveBackgroundSubtractorKNNSetDist2Threshold

Func _cveBackgroundSubtractorKNNGetKNNSamples($obj)
    ; CVAPI(int) cveBackgroundSubtractorKNNGetKNNSamples(cv::BackgroundSubtractorKNN* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveBackgroundSubtractorKNNGetKNNSamples", $bObjDllType, $obj), "cveBackgroundSubtractorKNNGetKNNSamples", @error)
EndFunc   ;==>_cveBackgroundSubtractorKNNGetKNNSamples

Func _cveBackgroundSubtractorKNNSetKNNSamples($obj, $value)
    ; CVAPI(void) cveBackgroundSubtractorKNNSetKNNSamples(cv::BackgroundSubtractorKNN* obj, int value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBackgroundSubtractorKNNSetKNNSamples", $bObjDllType, $obj, "int", $value), "cveBackgroundSubtractorKNNSetKNNSamples", @error)
EndFunc   ;==>_cveBackgroundSubtractorKNNSetKNNSamples

Func _cveBackgroundSubtractorKNNGetDetectShadows($obj)
    ; CVAPI(bool) cveBackgroundSubtractorKNNGetDetectShadows(cv::BackgroundSubtractorKNN* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveBackgroundSubtractorKNNGetDetectShadows", $bObjDllType, $obj), "cveBackgroundSubtractorKNNGetDetectShadows", @error)
EndFunc   ;==>_cveBackgroundSubtractorKNNGetDetectShadows

Func _cveBackgroundSubtractorKNNSetDetectShadows($obj, $value)
    ; CVAPI(void) cveBackgroundSubtractorKNNSetDetectShadows(cv::BackgroundSubtractorKNN* obj, bool value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBackgroundSubtractorKNNSetDetectShadows", $bObjDllType, $obj, "boolean", $value), "cveBackgroundSubtractorKNNSetDetectShadows", @error)
EndFunc   ;==>_cveBackgroundSubtractorKNNSetDetectShadows

Func _cveBackgroundSubtractorKNNGetShadowValue($obj)
    ; CVAPI(int) cveBackgroundSubtractorKNNGetShadowValue(cv::BackgroundSubtractorKNN* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveBackgroundSubtractorKNNGetShadowValue", $bObjDllType, $obj), "cveBackgroundSubtractorKNNGetShadowValue", @error)
EndFunc   ;==>_cveBackgroundSubtractorKNNGetShadowValue

Func _cveBackgroundSubtractorKNNSetShadowValue($obj, $value)
    ; CVAPI(void) cveBackgroundSubtractorKNNSetShadowValue(cv::BackgroundSubtractorKNN* obj, int value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBackgroundSubtractorKNNSetShadowValue", $bObjDllType, $obj, "int", $value), "cveBackgroundSubtractorKNNSetShadowValue", @error)
EndFunc   ;==>_cveBackgroundSubtractorKNNSetShadowValue

Func _cveBackgroundSubtractorKNNGetShadowThreshold($obj)
    ; CVAPI(double) cveBackgroundSubtractorKNNGetShadowThreshold(cv::BackgroundSubtractorKNN* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveBackgroundSubtractorKNNGetShadowThreshold", $bObjDllType, $obj), "cveBackgroundSubtractorKNNGetShadowThreshold", @error)
EndFunc   ;==>_cveBackgroundSubtractorKNNGetShadowThreshold

Func _cveBackgroundSubtractorKNNSetShadowThreshold($obj, $value)
    ; CVAPI(void) cveBackgroundSubtractorKNNSetShadowThreshold(cv::BackgroundSubtractorKNN* obj, double value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBackgroundSubtractorKNNSetShadowThreshold", $bObjDllType, $obj, "double", $value), "cveBackgroundSubtractorKNNSetShadowThreshold", @error)
EndFunc   ;==>_cveBackgroundSubtractorKNNSetShadowThreshold