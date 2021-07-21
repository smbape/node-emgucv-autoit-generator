#include-once
#include "..\..\CVEUtils.au3"

Func _cveRTreesGetMaxCategories($obj)
    ; CVAPI(int) cveRTreesGetMaxCategories(cv::ml::RTrees* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveRTreesGetMaxCategories", $bObjDllType, $obj), "cveRTreesGetMaxCategories", @error)
EndFunc   ;==>_cveRTreesGetMaxCategories

Func _cveRTreesSetMaxCategories($obj, $value)
    ; CVAPI(void) cveRTreesSetMaxCategories(cv::ml::RTrees* obj, int value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveRTreesSetMaxCategories", $bObjDllType, $obj, "int", $value), "cveRTreesSetMaxCategories", @error)
EndFunc   ;==>_cveRTreesSetMaxCategories

Func _cveRTreesGetMaxDepth($obj)
    ; CVAPI(int) cveRTreesGetMaxDepth(cv::ml::RTrees* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveRTreesGetMaxDepth", $bObjDllType, $obj), "cveRTreesGetMaxDepth", @error)
EndFunc   ;==>_cveRTreesGetMaxDepth

Func _cveRTreesSetMaxDepth($obj, $value)
    ; CVAPI(void) cveRTreesSetMaxDepth(cv::ml::RTrees* obj, int value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveRTreesSetMaxDepth", $bObjDllType, $obj, "int", $value), "cveRTreesSetMaxDepth", @error)
EndFunc   ;==>_cveRTreesSetMaxDepth

Func _cveRTreesGetMinSampleCount($obj)
    ; CVAPI(int) cveRTreesGetMinSampleCount(cv::ml::RTrees* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveRTreesGetMinSampleCount", $bObjDllType, $obj), "cveRTreesGetMinSampleCount", @error)
EndFunc   ;==>_cveRTreesGetMinSampleCount

Func _cveRTreesSetMinSampleCount($obj, $value)
    ; CVAPI(void) cveRTreesSetMinSampleCount(cv::ml::RTrees* obj, int value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveRTreesSetMinSampleCount", $bObjDllType, $obj, "int", $value), "cveRTreesSetMinSampleCount", @error)
EndFunc   ;==>_cveRTreesSetMinSampleCount

Func _cveRTreesGetCVFolds($obj)
    ; CVAPI(int) cveRTreesGetCVFolds(cv::ml::RTrees* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveRTreesGetCVFolds", $bObjDllType, $obj), "cveRTreesGetCVFolds", @error)
EndFunc   ;==>_cveRTreesGetCVFolds

Func _cveRTreesSetCVFolds($obj, $value)
    ; CVAPI(void) cveRTreesSetCVFolds(cv::ml::RTrees* obj, int value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveRTreesSetCVFolds", $bObjDllType, $obj, "int", $value), "cveRTreesSetCVFolds", @error)
EndFunc   ;==>_cveRTreesSetCVFolds

Func _cveRTreesGetUseSurrogates($obj)
    ; CVAPI(bool) cveRTreesGetUseSurrogates(cv::ml::RTrees* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveRTreesGetUseSurrogates", $bObjDllType, $obj), "cveRTreesGetUseSurrogates", @error)
EndFunc   ;==>_cveRTreesGetUseSurrogates

Func _cveRTreesSetUseSurrogates($obj, $value)
    ; CVAPI(void) cveRTreesSetUseSurrogates(cv::ml::RTrees* obj, bool value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveRTreesSetUseSurrogates", $bObjDllType, $obj, "boolean", $value), "cveRTreesSetUseSurrogates", @error)
EndFunc   ;==>_cveRTreesSetUseSurrogates

Func _cveRTreesGetUse1SERule($obj)
    ; CVAPI(bool) cveRTreesGetUse1SERule(cv::ml::RTrees* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveRTreesGetUse1SERule", $bObjDllType, $obj), "cveRTreesGetUse1SERule", @error)
EndFunc   ;==>_cveRTreesGetUse1SERule

Func _cveRTreesSetUse1SERule($obj, $value)
    ; CVAPI(void) cveRTreesSetUse1SERule(cv::ml::RTrees* obj, bool value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveRTreesSetUse1SERule", $bObjDllType, $obj, "boolean", $value), "cveRTreesSetUse1SERule", @error)
EndFunc   ;==>_cveRTreesSetUse1SERule

Func _cveRTreesGetTruncatePrunedTree($obj)
    ; CVAPI(bool) cveRTreesGetTruncatePrunedTree(cv::ml::RTrees* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveRTreesGetTruncatePrunedTree", $bObjDllType, $obj), "cveRTreesGetTruncatePrunedTree", @error)
EndFunc   ;==>_cveRTreesGetTruncatePrunedTree

Func _cveRTreesSetTruncatePrunedTree($obj, $value)
    ; CVAPI(void) cveRTreesSetTruncatePrunedTree(cv::ml::RTrees* obj, bool value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveRTreesSetTruncatePrunedTree", $bObjDllType, $obj, "boolean", $value), "cveRTreesSetTruncatePrunedTree", @error)
EndFunc   ;==>_cveRTreesSetTruncatePrunedTree

Func _cveRTreesGetRegressionAccuracy($obj)
    ; CVAPI(float) cveRTreesGetRegressionAccuracy(cv::ml::RTrees* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cveRTreesGetRegressionAccuracy", $bObjDllType, $obj), "cveRTreesGetRegressionAccuracy", @error)
EndFunc   ;==>_cveRTreesGetRegressionAccuracy

Func _cveRTreesSetRegressionAccuracy($obj, $value)
    ; CVAPI(void) cveRTreesSetRegressionAccuracy(cv::ml::RTrees* obj, float value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveRTreesSetRegressionAccuracy", $bObjDllType, $obj, "float", $value), "cveRTreesSetRegressionAccuracy", @error)
EndFunc   ;==>_cveRTreesSetRegressionAccuracy

Func _cveRTreesGetCalculateVarImportance($obj)
    ; CVAPI(bool) cveRTreesGetCalculateVarImportance(cv::ml::RTrees* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveRTreesGetCalculateVarImportance", $bObjDllType, $obj), "cveRTreesGetCalculateVarImportance", @error)
EndFunc   ;==>_cveRTreesGetCalculateVarImportance

Func _cveRTreesSetCalculateVarImportance($obj, $value)
    ; CVAPI(void) cveRTreesSetCalculateVarImportance(cv::ml::RTrees* obj, bool value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveRTreesSetCalculateVarImportance", $bObjDllType, $obj, "boolean", $value), "cveRTreesSetCalculateVarImportance", @error)
EndFunc   ;==>_cveRTreesSetCalculateVarImportance

Func _cveRTreesGetActiveVarCount($obj)
    ; CVAPI(int) cveRTreesGetActiveVarCount(cv::ml::RTrees* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveRTreesGetActiveVarCount", $bObjDllType, $obj), "cveRTreesGetActiveVarCount", @error)
EndFunc   ;==>_cveRTreesGetActiveVarCount

Func _cveRTreesSetActiveVarCount($obj, $value)
    ; CVAPI(void) cveRTreesSetActiveVarCount(cv::ml::RTrees* obj, int value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveRTreesSetActiveVarCount", $bObjDllType, $obj, "int", $value), "cveRTreesSetActiveVarCount", @error)
EndFunc   ;==>_cveRTreesSetActiveVarCount

Func _cveRTreesGetTermCriteria($obj, $value)
    ; CVAPI(void) cveRTreesGetTermCriteria(cv::ml::RTrees* obj, CvTermCriteria* value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    Local $bValueDllType
    If VarGetType($value) == "DLLStruct" Then
        $bValueDllType = "struct*"
    Else
        $bValueDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveRTreesGetTermCriteria", $bObjDllType, $obj, $bValueDllType, $value), "cveRTreesGetTermCriteria", @error)
EndFunc   ;==>_cveRTreesGetTermCriteria

Func _cveRTreesSetTermCriteria($obj, $value)
    ; CVAPI(void) cveRTreesSetTermCriteria(cv::ml::RTrees* obj, CvTermCriteria* value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    Local $bValueDllType
    If VarGetType($value) == "DLLStruct" Then
        $bValueDllType = "struct*"
    Else
        $bValueDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveRTreesSetTermCriteria", $bObjDllType, $obj, $bValueDllType, $value), "cveRTreesSetTermCriteria", @error)
EndFunc   ;==>_cveRTreesSetTermCriteria