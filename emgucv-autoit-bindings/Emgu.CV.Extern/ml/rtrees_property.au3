#include-once
#include "..\..\CVEUtils.au3"

Func _cveRTreesGetMaxCategories($obj)
    ; CVAPI(int) cveRTreesGetMaxCategories(cv::ml::RTrees* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveRTreesGetMaxCategories", $sObjDllType, $obj), "cveRTreesGetMaxCategories", @error)
EndFunc   ;==>_cveRTreesGetMaxCategories

Func _cveRTreesSetMaxCategories($obj, $value)
    ; CVAPI(void) cveRTreesSetMaxCategories(cv::ml::RTrees* obj, int value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveRTreesSetMaxCategories", $sObjDllType, $obj, "int", $value), "cveRTreesSetMaxCategories", @error)
EndFunc   ;==>_cveRTreesSetMaxCategories

Func _cveRTreesGetMaxDepth($obj)
    ; CVAPI(int) cveRTreesGetMaxDepth(cv::ml::RTrees* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveRTreesGetMaxDepth", $sObjDllType, $obj), "cveRTreesGetMaxDepth", @error)
EndFunc   ;==>_cveRTreesGetMaxDepth

Func _cveRTreesSetMaxDepth($obj, $value)
    ; CVAPI(void) cveRTreesSetMaxDepth(cv::ml::RTrees* obj, int value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveRTreesSetMaxDepth", $sObjDllType, $obj, "int", $value), "cveRTreesSetMaxDepth", @error)
EndFunc   ;==>_cveRTreesSetMaxDepth

Func _cveRTreesGetMinSampleCount($obj)
    ; CVAPI(int) cveRTreesGetMinSampleCount(cv::ml::RTrees* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveRTreesGetMinSampleCount", $sObjDllType, $obj), "cveRTreesGetMinSampleCount", @error)
EndFunc   ;==>_cveRTreesGetMinSampleCount

Func _cveRTreesSetMinSampleCount($obj, $value)
    ; CVAPI(void) cveRTreesSetMinSampleCount(cv::ml::RTrees* obj, int value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveRTreesSetMinSampleCount", $sObjDllType, $obj, "int", $value), "cveRTreesSetMinSampleCount", @error)
EndFunc   ;==>_cveRTreesSetMinSampleCount

Func _cveRTreesGetCVFolds($obj)
    ; CVAPI(int) cveRTreesGetCVFolds(cv::ml::RTrees* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveRTreesGetCVFolds", $sObjDllType, $obj), "cveRTreesGetCVFolds", @error)
EndFunc   ;==>_cveRTreesGetCVFolds

Func _cveRTreesSetCVFolds($obj, $value)
    ; CVAPI(void) cveRTreesSetCVFolds(cv::ml::RTrees* obj, int value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveRTreesSetCVFolds", $sObjDllType, $obj, "int", $value), "cveRTreesSetCVFolds", @error)
EndFunc   ;==>_cveRTreesSetCVFolds

Func _cveRTreesGetUseSurrogates($obj)
    ; CVAPI(bool) cveRTreesGetUseSurrogates(cv::ml::RTrees* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveRTreesGetUseSurrogates", $sObjDllType, $obj), "cveRTreesGetUseSurrogates", @error)
EndFunc   ;==>_cveRTreesGetUseSurrogates

Func _cveRTreesSetUseSurrogates($obj, $value)
    ; CVAPI(void) cveRTreesSetUseSurrogates(cv::ml::RTrees* obj, bool value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveRTreesSetUseSurrogates", $sObjDllType, $obj, "boolean", $value), "cveRTreesSetUseSurrogates", @error)
EndFunc   ;==>_cveRTreesSetUseSurrogates

Func _cveRTreesGetUse1SERule($obj)
    ; CVAPI(bool) cveRTreesGetUse1SERule(cv::ml::RTrees* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveRTreesGetUse1SERule", $sObjDllType, $obj), "cveRTreesGetUse1SERule", @error)
EndFunc   ;==>_cveRTreesGetUse1SERule

Func _cveRTreesSetUse1SERule($obj, $value)
    ; CVAPI(void) cveRTreesSetUse1SERule(cv::ml::RTrees* obj, bool value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveRTreesSetUse1SERule", $sObjDllType, $obj, "boolean", $value), "cveRTreesSetUse1SERule", @error)
EndFunc   ;==>_cveRTreesSetUse1SERule

Func _cveRTreesGetTruncatePrunedTree($obj)
    ; CVAPI(bool) cveRTreesGetTruncatePrunedTree(cv::ml::RTrees* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveRTreesGetTruncatePrunedTree", $sObjDllType, $obj), "cveRTreesGetTruncatePrunedTree", @error)
EndFunc   ;==>_cveRTreesGetTruncatePrunedTree

Func _cveRTreesSetTruncatePrunedTree($obj, $value)
    ; CVAPI(void) cveRTreesSetTruncatePrunedTree(cv::ml::RTrees* obj, bool value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveRTreesSetTruncatePrunedTree", $sObjDllType, $obj, "boolean", $value), "cveRTreesSetTruncatePrunedTree", @error)
EndFunc   ;==>_cveRTreesSetTruncatePrunedTree

Func _cveRTreesGetRegressionAccuracy($obj)
    ; CVAPI(float) cveRTreesGetRegressionAccuracy(cv::ml::RTrees* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cveRTreesGetRegressionAccuracy", $sObjDllType, $obj), "cveRTreesGetRegressionAccuracy", @error)
EndFunc   ;==>_cveRTreesGetRegressionAccuracy

Func _cveRTreesSetRegressionAccuracy($obj, $value)
    ; CVAPI(void) cveRTreesSetRegressionAccuracy(cv::ml::RTrees* obj, float value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveRTreesSetRegressionAccuracy", $sObjDllType, $obj, "float", $value), "cveRTreesSetRegressionAccuracy", @error)
EndFunc   ;==>_cveRTreesSetRegressionAccuracy

Func _cveRTreesGetCalculateVarImportance($obj)
    ; CVAPI(bool) cveRTreesGetCalculateVarImportance(cv::ml::RTrees* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveRTreesGetCalculateVarImportance", $sObjDllType, $obj), "cveRTreesGetCalculateVarImportance", @error)
EndFunc   ;==>_cveRTreesGetCalculateVarImportance

Func _cveRTreesSetCalculateVarImportance($obj, $value)
    ; CVAPI(void) cveRTreesSetCalculateVarImportance(cv::ml::RTrees* obj, bool value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveRTreesSetCalculateVarImportance", $sObjDllType, $obj, "boolean", $value), "cveRTreesSetCalculateVarImportance", @error)
EndFunc   ;==>_cveRTreesSetCalculateVarImportance

Func _cveRTreesGetActiveVarCount($obj)
    ; CVAPI(int) cveRTreesGetActiveVarCount(cv::ml::RTrees* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveRTreesGetActiveVarCount", $sObjDllType, $obj), "cveRTreesGetActiveVarCount", @error)
EndFunc   ;==>_cveRTreesGetActiveVarCount

Func _cveRTreesSetActiveVarCount($obj, $value)
    ; CVAPI(void) cveRTreesSetActiveVarCount(cv::ml::RTrees* obj, int value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveRTreesSetActiveVarCount", $sObjDllType, $obj, "int", $value), "cveRTreesSetActiveVarCount", @error)
EndFunc   ;==>_cveRTreesSetActiveVarCount

Func _cveRTreesGetTermCriteria($obj, $value)
    ; CVAPI(void) cveRTreesGetTermCriteria(cv::ml::RTrees* obj, CvTermCriteria* value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    Local $sValueDllType
    If IsDllStruct($value) Then
        $sValueDllType = "struct*"
    Else
        $sValueDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveRTreesGetTermCriteria", $sObjDllType, $obj, $sValueDllType, $value), "cveRTreesGetTermCriteria", @error)
EndFunc   ;==>_cveRTreesGetTermCriteria

Func _cveRTreesSetTermCriteria($obj, $value)
    ; CVAPI(void) cveRTreesSetTermCriteria(cv::ml::RTrees* obj, CvTermCriteria* value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    Local $sValueDllType
    If IsDllStruct($value) Then
        $sValueDllType = "struct*"
    Else
        $sValueDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveRTreesSetTermCriteria", $sObjDllType, $obj, $sValueDllType, $value), "cveRTreesSetTermCriteria", @error)
EndFunc   ;==>_cveRTreesSetTermCriteria