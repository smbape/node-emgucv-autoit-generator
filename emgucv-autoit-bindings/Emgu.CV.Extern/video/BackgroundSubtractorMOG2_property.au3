#include-once
#include "..\..\CVEUtils.au3"

Func _cveBackgroundSubtractorMOG2GetHistory($obj)
    ; CVAPI(int) cveBackgroundSubtractorMOG2GetHistory(cv::BackgroundSubtractorMOG2* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveBackgroundSubtractorMOG2GetHistory", $sObjDllType, $obj), "cveBackgroundSubtractorMOG2GetHistory", @error)
EndFunc   ;==>_cveBackgroundSubtractorMOG2GetHistory

Func _cveBackgroundSubtractorMOG2SetHistory($obj, $value)
    ; CVAPI(void) cveBackgroundSubtractorMOG2SetHistory(cv::BackgroundSubtractorMOG2* obj, int value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBackgroundSubtractorMOG2SetHistory", $sObjDllType, $obj, "int", $value), "cveBackgroundSubtractorMOG2SetHistory", @error)
EndFunc   ;==>_cveBackgroundSubtractorMOG2SetHistory

Func _cveBackgroundSubtractorMOG2GetDetectShadows($obj)
    ; CVAPI(bool) cveBackgroundSubtractorMOG2GetDetectShadows(cv::BackgroundSubtractorMOG2* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveBackgroundSubtractorMOG2GetDetectShadows", $sObjDllType, $obj), "cveBackgroundSubtractorMOG2GetDetectShadows", @error)
EndFunc   ;==>_cveBackgroundSubtractorMOG2GetDetectShadows

Func _cveBackgroundSubtractorMOG2SetDetectShadows($obj, $value)
    ; CVAPI(void) cveBackgroundSubtractorMOG2SetDetectShadows(cv::BackgroundSubtractorMOG2* obj, bool value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBackgroundSubtractorMOG2SetDetectShadows", $sObjDllType, $obj, "boolean", $value), "cveBackgroundSubtractorMOG2SetDetectShadows", @error)
EndFunc   ;==>_cveBackgroundSubtractorMOG2SetDetectShadows

Func _cveBackgroundSubtractorMOG2GetShadowValue($obj)
    ; CVAPI(int) cveBackgroundSubtractorMOG2GetShadowValue(cv::BackgroundSubtractorMOG2* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveBackgroundSubtractorMOG2GetShadowValue", $sObjDllType, $obj), "cveBackgroundSubtractorMOG2GetShadowValue", @error)
EndFunc   ;==>_cveBackgroundSubtractorMOG2GetShadowValue

Func _cveBackgroundSubtractorMOG2SetShadowValue($obj, $value)
    ; CVAPI(void) cveBackgroundSubtractorMOG2SetShadowValue(cv::BackgroundSubtractorMOG2* obj, int value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBackgroundSubtractorMOG2SetShadowValue", $sObjDllType, $obj, "int", $value), "cveBackgroundSubtractorMOG2SetShadowValue", @error)
EndFunc   ;==>_cveBackgroundSubtractorMOG2SetShadowValue

Func _cveBackgroundSubtractorMOG2GetShadowThreshold($obj)
    ; CVAPI(double) cveBackgroundSubtractorMOG2GetShadowThreshold(cv::BackgroundSubtractorMOG2* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveBackgroundSubtractorMOG2GetShadowThreshold", $sObjDllType, $obj), "cveBackgroundSubtractorMOG2GetShadowThreshold", @error)
EndFunc   ;==>_cveBackgroundSubtractorMOG2GetShadowThreshold

Func _cveBackgroundSubtractorMOG2SetShadowThreshold($obj, $value)
    ; CVAPI(void) cveBackgroundSubtractorMOG2SetShadowThreshold(cv::BackgroundSubtractorMOG2* obj, double value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBackgroundSubtractorMOG2SetShadowThreshold", $sObjDllType, $obj, "double", $value), "cveBackgroundSubtractorMOG2SetShadowThreshold", @error)
EndFunc   ;==>_cveBackgroundSubtractorMOG2SetShadowThreshold

Func _cveBackgroundSubtractorMOG2GetNMixtures($obj)
    ; CVAPI(int) cveBackgroundSubtractorMOG2GetNMixtures(cv::BackgroundSubtractorMOG2* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveBackgroundSubtractorMOG2GetNMixtures", $sObjDllType, $obj), "cveBackgroundSubtractorMOG2GetNMixtures", @error)
EndFunc   ;==>_cveBackgroundSubtractorMOG2GetNMixtures

Func _cveBackgroundSubtractorMOG2SetNMixtures($obj, $value)
    ; CVAPI(void) cveBackgroundSubtractorMOG2SetNMixtures(cv::BackgroundSubtractorMOG2* obj, int value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBackgroundSubtractorMOG2SetNMixtures", $sObjDllType, $obj, "int", $value), "cveBackgroundSubtractorMOG2SetNMixtures", @error)
EndFunc   ;==>_cveBackgroundSubtractorMOG2SetNMixtures

Func _cveBackgroundSubtractorMOG2GetBackgroundRatio($obj)
    ; CVAPI(double) cveBackgroundSubtractorMOG2GetBackgroundRatio(cv::BackgroundSubtractorMOG2* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveBackgroundSubtractorMOG2GetBackgroundRatio", $sObjDllType, $obj), "cveBackgroundSubtractorMOG2GetBackgroundRatio", @error)
EndFunc   ;==>_cveBackgroundSubtractorMOG2GetBackgroundRatio

Func _cveBackgroundSubtractorMOG2SetBackgroundRatio($obj, $value)
    ; CVAPI(void) cveBackgroundSubtractorMOG2SetBackgroundRatio(cv::BackgroundSubtractorMOG2* obj, double value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBackgroundSubtractorMOG2SetBackgroundRatio", $sObjDllType, $obj, "double", $value), "cveBackgroundSubtractorMOG2SetBackgroundRatio", @error)
EndFunc   ;==>_cveBackgroundSubtractorMOG2SetBackgroundRatio

Func _cveBackgroundSubtractorMOG2GetVarThreshold($obj)
    ; CVAPI(double) cveBackgroundSubtractorMOG2GetVarThreshold(cv::BackgroundSubtractorMOG2* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveBackgroundSubtractorMOG2GetVarThreshold", $sObjDllType, $obj), "cveBackgroundSubtractorMOG2GetVarThreshold", @error)
EndFunc   ;==>_cveBackgroundSubtractorMOG2GetVarThreshold

Func _cveBackgroundSubtractorMOG2SetVarThreshold($obj, $value)
    ; CVAPI(void) cveBackgroundSubtractorMOG2SetVarThreshold(cv::BackgroundSubtractorMOG2* obj, double value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBackgroundSubtractorMOG2SetVarThreshold", $sObjDllType, $obj, "double", $value), "cveBackgroundSubtractorMOG2SetVarThreshold", @error)
EndFunc   ;==>_cveBackgroundSubtractorMOG2SetVarThreshold

Func _cveBackgroundSubtractorMOG2GetVarThresholdGen($obj)
    ; CVAPI(double) cveBackgroundSubtractorMOG2GetVarThresholdGen(cv::BackgroundSubtractorMOG2* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveBackgroundSubtractorMOG2GetVarThresholdGen", $sObjDllType, $obj), "cveBackgroundSubtractorMOG2GetVarThresholdGen", @error)
EndFunc   ;==>_cveBackgroundSubtractorMOG2GetVarThresholdGen

Func _cveBackgroundSubtractorMOG2SetVarThresholdGen($obj, $value)
    ; CVAPI(void) cveBackgroundSubtractorMOG2SetVarThresholdGen(cv::BackgroundSubtractorMOG2* obj, double value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBackgroundSubtractorMOG2SetVarThresholdGen", $sObjDllType, $obj, "double", $value), "cveBackgroundSubtractorMOG2SetVarThresholdGen", @error)
EndFunc   ;==>_cveBackgroundSubtractorMOG2SetVarThresholdGen

Func _cveBackgroundSubtractorMOG2GetVarInit($obj)
    ; CVAPI(double) cveBackgroundSubtractorMOG2GetVarInit(cv::BackgroundSubtractorMOG2* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveBackgroundSubtractorMOG2GetVarInit", $sObjDllType, $obj), "cveBackgroundSubtractorMOG2GetVarInit", @error)
EndFunc   ;==>_cveBackgroundSubtractorMOG2GetVarInit

Func _cveBackgroundSubtractorMOG2SetVarInit($obj, $value)
    ; CVAPI(void) cveBackgroundSubtractorMOG2SetVarInit(cv::BackgroundSubtractorMOG2* obj, double value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBackgroundSubtractorMOG2SetVarInit", $sObjDllType, $obj, "double", $value), "cveBackgroundSubtractorMOG2SetVarInit", @error)
EndFunc   ;==>_cveBackgroundSubtractorMOG2SetVarInit

Func _cveBackgroundSubtractorMOG2GetVarMin($obj)
    ; CVAPI(double) cveBackgroundSubtractorMOG2GetVarMin(cv::BackgroundSubtractorMOG2* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveBackgroundSubtractorMOG2GetVarMin", $sObjDllType, $obj), "cveBackgroundSubtractorMOG2GetVarMin", @error)
EndFunc   ;==>_cveBackgroundSubtractorMOG2GetVarMin

Func _cveBackgroundSubtractorMOG2SetVarMin($obj, $value)
    ; CVAPI(void) cveBackgroundSubtractorMOG2SetVarMin(cv::BackgroundSubtractorMOG2* obj, double value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBackgroundSubtractorMOG2SetVarMin", $sObjDllType, $obj, "double", $value), "cveBackgroundSubtractorMOG2SetVarMin", @error)
EndFunc   ;==>_cveBackgroundSubtractorMOG2SetVarMin

Func _cveBackgroundSubtractorMOG2GetVarMax($obj)
    ; CVAPI(double) cveBackgroundSubtractorMOG2GetVarMax(cv::BackgroundSubtractorMOG2* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveBackgroundSubtractorMOG2GetVarMax", $sObjDllType, $obj), "cveBackgroundSubtractorMOG2GetVarMax", @error)
EndFunc   ;==>_cveBackgroundSubtractorMOG2GetVarMax

Func _cveBackgroundSubtractorMOG2SetVarMax($obj, $value)
    ; CVAPI(void) cveBackgroundSubtractorMOG2SetVarMax(cv::BackgroundSubtractorMOG2* obj, double value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBackgroundSubtractorMOG2SetVarMax", $sObjDllType, $obj, "double", $value), "cveBackgroundSubtractorMOG2SetVarMax", @error)
EndFunc   ;==>_cveBackgroundSubtractorMOG2SetVarMax

Func _cveBackgroundSubtractorMOG2GetComplexityReductionThreshold($obj)
    ; CVAPI(double) cveBackgroundSubtractorMOG2GetComplexityReductionThreshold(cv::BackgroundSubtractorMOG2* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveBackgroundSubtractorMOG2GetComplexityReductionThreshold", $sObjDllType, $obj), "cveBackgroundSubtractorMOG2GetComplexityReductionThreshold", @error)
EndFunc   ;==>_cveBackgroundSubtractorMOG2GetComplexityReductionThreshold

Func _cveBackgroundSubtractorMOG2SetComplexityReductionThreshold($obj, $value)
    ; CVAPI(void) cveBackgroundSubtractorMOG2SetComplexityReductionThreshold(cv::BackgroundSubtractorMOG2* obj, double value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBackgroundSubtractorMOG2SetComplexityReductionThreshold", $sObjDllType, $obj, "double", $value), "cveBackgroundSubtractorMOG2SetComplexityReductionThreshold", @error)
EndFunc   ;==>_cveBackgroundSubtractorMOG2SetComplexityReductionThreshold