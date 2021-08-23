#include-once
#include "..\..\CVEUtils.au3"

Func _cveBackgroundSubtractorKNNGetHistory($obj)
    ; CVAPI(int) cveBackgroundSubtractorKNNGetHistory(cv::BackgroundSubtractorKNN* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveBackgroundSubtractorKNNGetHistory", $sObjDllType, $obj), "cveBackgroundSubtractorKNNGetHistory", @error)
EndFunc   ;==>_cveBackgroundSubtractorKNNGetHistory

Func _cveBackgroundSubtractorKNNSetHistory($obj, $value)
    ; CVAPI(void) cveBackgroundSubtractorKNNSetHistory(cv::BackgroundSubtractorKNN* obj, int value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBackgroundSubtractorKNNSetHistory", $sObjDllType, $obj, "int", $value), "cveBackgroundSubtractorKNNSetHistory", @error)
EndFunc   ;==>_cveBackgroundSubtractorKNNSetHistory

Func _cveBackgroundSubtractorKNNGetNSamples($obj)
    ; CVAPI(int) cveBackgroundSubtractorKNNGetNSamples(cv::BackgroundSubtractorKNN* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveBackgroundSubtractorKNNGetNSamples", $sObjDllType, $obj), "cveBackgroundSubtractorKNNGetNSamples", @error)
EndFunc   ;==>_cveBackgroundSubtractorKNNGetNSamples

Func _cveBackgroundSubtractorKNNSetNSamples($obj, $value)
    ; CVAPI(void) cveBackgroundSubtractorKNNSetNSamples(cv::BackgroundSubtractorKNN* obj, int value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBackgroundSubtractorKNNSetNSamples", $sObjDllType, $obj, "int", $value), "cveBackgroundSubtractorKNNSetNSamples", @error)
EndFunc   ;==>_cveBackgroundSubtractorKNNSetNSamples

Func _cveBackgroundSubtractorKNNGetDist2Threshold($obj)
    ; CVAPI(double) cveBackgroundSubtractorKNNGetDist2Threshold(cv::BackgroundSubtractorKNN* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveBackgroundSubtractorKNNGetDist2Threshold", $sObjDllType, $obj), "cveBackgroundSubtractorKNNGetDist2Threshold", @error)
EndFunc   ;==>_cveBackgroundSubtractorKNNGetDist2Threshold

Func _cveBackgroundSubtractorKNNSetDist2Threshold($obj, $value)
    ; CVAPI(void) cveBackgroundSubtractorKNNSetDist2Threshold(cv::BackgroundSubtractorKNN* obj, double value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBackgroundSubtractorKNNSetDist2Threshold", $sObjDllType, $obj, "double", $value), "cveBackgroundSubtractorKNNSetDist2Threshold", @error)
EndFunc   ;==>_cveBackgroundSubtractorKNNSetDist2Threshold

Func _cveBackgroundSubtractorKNNGetKNNSamples($obj)
    ; CVAPI(int) cveBackgroundSubtractorKNNGetKNNSamples(cv::BackgroundSubtractorKNN* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveBackgroundSubtractorKNNGetKNNSamples", $sObjDllType, $obj), "cveBackgroundSubtractorKNNGetKNNSamples", @error)
EndFunc   ;==>_cveBackgroundSubtractorKNNGetKNNSamples

Func _cveBackgroundSubtractorKNNSetKNNSamples($obj, $value)
    ; CVAPI(void) cveBackgroundSubtractorKNNSetKNNSamples(cv::BackgroundSubtractorKNN* obj, int value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBackgroundSubtractorKNNSetKNNSamples", $sObjDllType, $obj, "int", $value), "cveBackgroundSubtractorKNNSetKNNSamples", @error)
EndFunc   ;==>_cveBackgroundSubtractorKNNSetKNNSamples

Func _cveBackgroundSubtractorKNNGetDetectShadows($obj)
    ; CVAPI(bool) cveBackgroundSubtractorKNNGetDetectShadows(cv::BackgroundSubtractorKNN* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveBackgroundSubtractorKNNGetDetectShadows", $sObjDllType, $obj), "cveBackgroundSubtractorKNNGetDetectShadows", @error)
EndFunc   ;==>_cveBackgroundSubtractorKNNGetDetectShadows

Func _cveBackgroundSubtractorKNNSetDetectShadows($obj, $value)
    ; CVAPI(void) cveBackgroundSubtractorKNNSetDetectShadows(cv::BackgroundSubtractorKNN* obj, bool value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBackgroundSubtractorKNNSetDetectShadows", $sObjDllType, $obj, "boolean", $value), "cveBackgroundSubtractorKNNSetDetectShadows", @error)
EndFunc   ;==>_cveBackgroundSubtractorKNNSetDetectShadows

Func _cveBackgroundSubtractorKNNGetShadowValue($obj)
    ; CVAPI(int) cveBackgroundSubtractorKNNGetShadowValue(cv::BackgroundSubtractorKNN* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveBackgroundSubtractorKNNGetShadowValue", $sObjDllType, $obj), "cveBackgroundSubtractorKNNGetShadowValue", @error)
EndFunc   ;==>_cveBackgroundSubtractorKNNGetShadowValue

Func _cveBackgroundSubtractorKNNSetShadowValue($obj, $value)
    ; CVAPI(void) cveBackgroundSubtractorKNNSetShadowValue(cv::BackgroundSubtractorKNN* obj, int value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBackgroundSubtractorKNNSetShadowValue", $sObjDllType, $obj, "int", $value), "cveBackgroundSubtractorKNNSetShadowValue", @error)
EndFunc   ;==>_cveBackgroundSubtractorKNNSetShadowValue

Func _cveBackgroundSubtractorKNNGetShadowThreshold($obj)
    ; CVAPI(double) cveBackgroundSubtractorKNNGetShadowThreshold(cv::BackgroundSubtractorKNN* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveBackgroundSubtractorKNNGetShadowThreshold", $sObjDllType, $obj), "cveBackgroundSubtractorKNNGetShadowThreshold", @error)
EndFunc   ;==>_cveBackgroundSubtractorKNNGetShadowThreshold

Func _cveBackgroundSubtractorKNNSetShadowThreshold($obj, $value)
    ; CVAPI(void) cveBackgroundSubtractorKNNSetShadowThreshold(cv::BackgroundSubtractorKNN* obj, double value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBackgroundSubtractorKNNSetShadowThreshold", $sObjDllType, $obj, "double", $value), "cveBackgroundSubtractorKNNSetShadowThreshold", @error)
EndFunc   ;==>_cveBackgroundSubtractorKNNSetShadowThreshold