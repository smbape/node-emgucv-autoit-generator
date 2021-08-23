#include-once
#include "..\..\CVEUtils.au3"

Func _cveDTreesGetMaxCategories($obj)
    ; CVAPI(int) cveDTreesGetMaxCategories(cv::ml::DTrees* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveDTreesGetMaxCategories", $sObjDllType, $obj), "cveDTreesGetMaxCategories", @error)
EndFunc   ;==>_cveDTreesGetMaxCategories

Func _cveDTreesSetMaxCategories($obj, $value)
    ; CVAPI(void) cveDTreesSetMaxCategories(cv::ml::DTrees* obj, int value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDTreesSetMaxCategories", $sObjDllType, $obj, "int", $value), "cveDTreesSetMaxCategories", @error)
EndFunc   ;==>_cveDTreesSetMaxCategories

Func _cveDTreesGetMaxDepth($obj)
    ; CVAPI(int) cveDTreesGetMaxDepth(cv::ml::DTrees* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveDTreesGetMaxDepth", $sObjDllType, $obj), "cveDTreesGetMaxDepth", @error)
EndFunc   ;==>_cveDTreesGetMaxDepth

Func _cveDTreesSetMaxDepth($obj, $value)
    ; CVAPI(void) cveDTreesSetMaxDepth(cv::ml::DTrees* obj, int value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDTreesSetMaxDepth", $sObjDllType, $obj, "int", $value), "cveDTreesSetMaxDepth", @error)
EndFunc   ;==>_cveDTreesSetMaxDepth

Func _cveDTreesGetMinSampleCount($obj)
    ; CVAPI(int) cveDTreesGetMinSampleCount(cv::ml::DTrees* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveDTreesGetMinSampleCount", $sObjDllType, $obj), "cveDTreesGetMinSampleCount", @error)
EndFunc   ;==>_cveDTreesGetMinSampleCount

Func _cveDTreesSetMinSampleCount($obj, $value)
    ; CVAPI(void) cveDTreesSetMinSampleCount(cv::ml::DTrees* obj, int value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDTreesSetMinSampleCount", $sObjDllType, $obj, "int", $value), "cveDTreesSetMinSampleCount", @error)
EndFunc   ;==>_cveDTreesSetMinSampleCount

Func _cveDTreesGetCVFolds($obj)
    ; CVAPI(int) cveDTreesGetCVFolds(cv::ml::DTrees* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveDTreesGetCVFolds", $sObjDllType, $obj), "cveDTreesGetCVFolds", @error)
EndFunc   ;==>_cveDTreesGetCVFolds

Func _cveDTreesSetCVFolds($obj, $value)
    ; CVAPI(void) cveDTreesSetCVFolds(cv::ml::DTrees* obj, int value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDTreesSetCVFolds", $sObjDllType, $obj, "int", $value), "cveDTreesSetCVFolds", @error)
EndFunc   ;==>_cveDTreesSetCVFolds

Func _cveDTreesGetUseSurrogates($obj)
    ; CVAPI(bool) cveDTreesGetUseSurrogates(cv::ml::DTrees* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveDTreesGetUseSurrogates", $sObjDllType, $obj), "cveDTreesGetUseSurrogates", @error)
EndFunc   ;==>_cveDTreesGetUseSurrogates

Func _cveDTreesSetUseSurrogates($obj, $value)
    ; CVAPI(void) cveDTreesSetUseSurrogates(cv::ml::DTrees* obj, bool value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDTreesSetUseSurrogates", $sObjDllType, $obj, "boolean", $value), "cveDTreesSetUseSurrogates", @error)
EndFunc   ;==>_cveDTreesSetUseSurrogates

Func _cveDTreesGetUse1SERule($obj)
    ; CVAPI(bool) cveDTreesGetUse1SERule(cv::ml::DTrees* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveDTreesGetUse1SERule", $sObjDllType, $obj), "cveDTreesGetUse1SERule", @error)
EndFunc   ;==>_cveDTreesGetUse1SERule

Func _cveDTreesSetUse1SERule($obj, $value)
    ; CVAPI(void) cveDTreesSetUse1SERule(cv::ml::DTrees* obj, bool value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDTreesSetUse1SERule", $sObjDllType, $obj, "boolean", $value), "cveDTreesSetUse1SERule", @error)
EndFunc   ;==>_cveDTreesSetUse1SERule

Func _cveDTreesGetTruncatePrunedTree($obj)
    ; CVAPI(bool) cveDTreesGetTruncatePrunedTree(cv::ml::DTrees* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveDTreesGetTruncatePrunedTree", $sObjDllType, $obj), "cveDTreesGetTruncatePrunedTree", @error)
EndFunc   ;==>_cveDTreesGetTruncatePrunedTree

Func _cveDTreesSetTruncatePrunedTree($obj, $value)
    ; CVAPI(void) cveDTreesSetTruncatePrunedTree(cv::ml::DTrees* obj, bool value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDTreesSetTruncatePrunedTree", $sObjDllType, $obj, "boolean", $value), "cveDTreesSetTruncatePrunedTree", @error)
EndFunc   ;==>_cveDTreesSetTruncatePrunedTree

Func _cveDTreesGetRegressionAccuracy($obj)
    ; CVAPI(float) cveDTreesGetRegressionAccuracy(cv::ml::DTrees* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cveDTreesGetRegressionAccuracy", $sObjDllType, $obj), "cveDTreesGetRegressionAccuracy", @error)
EndFunc   ;==>_cveDTreesGetRegressionAccuracy

Func _cveDTreesSetRegressionAccuracy($obj, $value)
    ; CVAPI(void) cveDTreesSetRegressionAccuracy(cv::ml::DTrees* obj, float value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDTreesSetRegressionAccuracy", $sObjDllType, $obj, "float", $value), "cveDTreesSetRegressionAccuracy", @error)
EndFunc   ;==>_cveDTreesSetRegressionAccuracy