#include-once
#include "..\..\CVEUtils.au3"

Func _cveDTreesGetMaxCategories($obj)
    ; CVAPI(int) cveDTreesGetMaxCategories(cv::ml::DTrees* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveDTreesGetMaxCategories", $bObjDllType, $obj), "cveDTreesGetMaxCategories", @error)
EndFunc   ;==>_cveDTreesGetMaxCategories

Func _cveDTreesSetMaxCategories($obj, $value)
    ; CVAPI(void) cveDTreesSetMaxCategories(cv::ml::DTrees* obj, int value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDTreesSetMaxCategories", $bObjDllType, $obj, "int", $value), "cveDTreesSetMaxCategories", @error)
EndFunc   ;==>_cveDTreesSetMaxCategories

Func _cveDTreesGetMaxDepth($obj)
    ; CVAPI(int) cveDTreesGetMaxDepth(cv::ml::DTrees* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveDTreesGetMaxDepth", $bObjDllType, $obj), "cveDTreesGetMaxDepth", @error)
EndFunc   ;==>_cveDTreesGetMaxDepth

Func _cveDTreesSetMaxDepth($obj, $value)
    ; CVAPI(void) cveDTreesSetMaxDepth(cv::ml::DTrees* obj, int value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDTreesSetMaxDepth", $bObjDllType, $obj, "int", $value), "cveDTreesSetMaxDepth", @error)
EndFunc   ;==>_cveDTreesSetMaxDepth

Func _cveDTreesGetMinSampleCount($obj)
    ; CVAPI(int) cveDTreesGetMinSampleCount(cv::ml::DTrees* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveDTreesGetMinSampleCount", $bObjDllType, $obj), "cveDTreesGetMinSampleCount", @error)
EndFunc   ;==>_cveDTreesGetMinSampleCount

Func _cveDTreesSetMinSampleCount($obj, $value)
    ; CVAPI(void) cveDTreesSetMinSampleCount(cv::ml::DTrees* obj, int value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDTreesSetMinSampleCount", $bObjDllType, $obj, "int", $value), "cveDTreesSetMinSampleCount", @error)
EndFunc   ;==>_cveDTreesSetMinSampleCount

Func _cveDTreesGetCVFolds($obj)
    ; CVAPI(int) cveDTreesGetCVFolds(cv::ml::DTrees* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveDTreesGetCVFolds", $bObjDllType, $obj), "cveDTreesGetCVFolds", @error)
EndFunc   ;==>_cveDTreesGetCVFolds

Func _cveDTreesSetCVFolds($obj, $value)
    ; CVAPI(void) cveDTreesSetCVFolds(cv::ml::DTrees* obj, int value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDTreesSetCVFolds", $bObjDllType, $obj, "int", $value), "cveDTreesSetCVFolds", @error)
EndFunc   ;==>_cveDTreesSetCVFolds

Func _cveDTreesGetUseSurrogates($obj)
    ; CVAPI(bool) cveDTreesGetUseSurrogates(cv::ml::DTrees* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveDTreesGetUseSurrogates", $bObjDllType, $obj), "cveDTreesGetUseSurrogates", @error)
EndFunc   ;==>_cveDTreesGetUseSurrogates

Func _cveDTreesSetUseSurrogates($obj, $value)
    ; CVAPI(void) cveDTreesSetUseSurrogates(cv::ml::DTrees* obj, bool value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDTreesSetUseSurrogates", $bObjDllType, $obj, "boolean", $value), "cveDTreesSetUseSurrogates", @error)
EndFunc   ;==>_cveDTreesSetUseSurrogates

Func _cveDTreesGetUse1SERule($obj)
    ; CVAPI(bool) cveDTreesGetUse1SERule(cv::ml::DTrees* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveDTreesGetUse1SERule", $bObjDllType, $obj), "cveDTreesGetUse1SERule", @error)
EndFunc   ;==>_cveDTreesGetUse1SERule

Func _cveDTreesSetUse1SERule($obj, $value)
    ; CVAPI(void) cveDTreesSetUse1SERule(cv::ml::DTrees* obj, bool value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDTreesSetUse1SERule", $bObjDllType, $obj, "boolean", $value), "cveDTreesSetUse1SERule", @error)
EndFunc   ;==>_cveDTreesSetUse1SERule

Func _cveDTreesGetTruncatePrunedTree($obj)
    ; CVAPI(bool) cveDTreesGetTruncatePrunedTree(cv::ml::DTrees* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveDTreesGetTruncatePrunedTree", $bObjDllType, $obj), "cveDTreesGetTruncatePrunedTree", @error)
EndFunc   ;==>_cveDTreesGetTruncatePrunedTree

Func _cveDTreesSetTruncatePrunedTree($obj, $value)
    ; CVAPI(void) cveDTreesSetTruncatePrunedTree(cv::ml::DTrees* obj, bool value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDTreesSetTruncatePrunedTree", $bObjDllType, $obj, "boolean", $value), "cveDTreesSetTruncatePrunedTree", @error)
EndFunc   ;==>_cveDTreesSetTruncatePrunedTree

Func _cveDTreesGetRegressionAccuracy($obj)
    ; CVAPI(float) cveDTreesGetRegressionAccuracy(cv::ml::DTrees* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cveDTreesGetRegressionAccuracy", $bObjDllType, $obj), "cveDTreesGetRegressionAccuracy", @error)
EndFunc   ;==>_cveDTreesGetRegressionAccuracy

Func _cveDTreesSetRegressionAccuracy($obj, $value)
    ; CVAPI(void) cveDTreesSetRegressionAccuracy(cv::ml::DTrees* obj, float value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDTreesSetRegressionAccuracy", $bObjDllType, $obj, "float", $value), "cveDTreesSetRegressionAccuracy", @error)
EndFunc   ;==>_cveDTreesSetRegressionAccuracy