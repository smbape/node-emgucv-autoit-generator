#include-once
#include "..\..\CVEUtils.au3"

Func _cveRTreesGetMaxCategories($obj)
    ; CVAPI(int) cveRTreesGetMaxCategories(cv::ml::RTrees* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveRTreesGetMaxCategories", "ptr", $obj), "cveRTreesGetMaxCategories", @error)
EndFunc   ;==>_cveRTreesGetMaxCategories

Func _cveRTreesSetMaxCategories($obj, $value)
    ; CVAPI(void) cveRTreesSetMaxCategories(cv::ml::RTrees* obj, int value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveRTreesSetMaxCategories", "ptr", $obj, "int", $value), "cveRTreesSetMaxCategories", @error)
EndFunc   ;==>_cveRTreesSetMaxCategories

Func _cveRTreesGetMaxDepth($obj)
    ; CVAPI(int) cveRTreesGetMaxDepth(cv::ml::RTrees* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveRTreesGetMaxDepth", "ptr", $obj), "cveRTreesGetMaxDepth", @error)
EndFunc   ;==>_cveRTreesGetMaxDepth

Func _cveRTreesSetMaxDepth($obj, $value)
    ; CVAPI(void) cveRTreesSetMaxDepth(cv::ml::RTrees* obj, int value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveRTreesSetMaxDepth", "ptr", $obj, "int", $value), "cveRTreesSetMaxDepth", @error)
EndFunc   ;==>_cveRTreesSetMaxDepth

Func _cveRTreesGetMinSampleCount($obj)
    ; CVAPI(int) cveRTreesGetMinSampleCount(cv::ml::RTrees* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveRTreesGetMinSampleCount", "ptr", $obj), "cveRTreesGetMinSampleCount", @error)
EndFunc   ;==>_cveRTreesGetMinSampleCount

Func _cveRTreesSetMinSampleCount($obj, $value)
    ; CVAPI(void) cveRTreesSetMinSampleCount(cv::ml::RTrees* obj, int value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveRTreesSetMinSampleCount", "ptr", $obj, "int", $value), "cveRTreesSetMinSampleCount", @error)
EndFunc   ;==>_cveRTreesSetMinSampleCount

Func _cveRTreesGetCVFolds($obj)
    ; CVAPI(int) cveRTreesGetCVFolds(cv::ml::RTrees* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveRTreesGetCVFolds", "ptr", $obj), "cveRTreesGetCVFolds", @error)
EndFunc   ;==>_cveRTreesGetCVFolds

Func _cveRTreesSetCVFolds($obj, $value)
    ; CVAPI(void) cveRTreesSetCVFolds(cv::ml::RTrees* obj, int value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveRTreesSetCVFolds", "ptr", $obj, "int", $value), "cveRTreesSetCVFolds", @error)
EndFunc   ;==>_cveRTreesSetCVFolds

Func _cveRTreesGetUseSurrogates($obj)
    ; CVAPI(bool) cveRTreesGetUseSurrogates(cv::ml::RTrees* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveRTreesGetUseSurrogates", "ptr", $obj), "cveRTreesGetUseSurrogates", @error)
EndFunc   ;==>_cveRTreesGetUseSurrogates

Func _cveRTreesSetUseSurrogates($obj, $value)
    ; CVAPI(void) cveRTreesSetUseSurrogates(cv::ml::RTrees* obj, bool value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveRTreesSetUseSurrogates", "ptr", $obj, "boolean", $value), "cveRTreesSetUseSurrogates", @error)
EndFunc   ;==>_cveRTreesSetUseSurrogates

Func _cveRTreesGetUse1SERule($obj)
    ; CVAPI(bool) cveRTreesGetUse1SERule(cv::ml::RTrees* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveRTreesGetUse1SERule", "ptr", $obj), "cveRTreesGetUse1SERule", @error)
EndFunc   ;==>_cveRTreesGetUse1SERule

Func _cveRTreesSetUse1SERule($obj, $value)
    ; CVAPI(void) cveRTreesSetUse1SERule(cv::ml::RTrees* obj, bool value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveRTreesSetUse1SERule", "ptr", $obj, "boolean", $value), "cveRTreesSetUse1SERule", @error)
EndFunc   ;==>_cveRTreesSetUse1SERule

Func _cveRTreesGetTruncatePrunedTree($obj)
    ; CVAPI(bool) cveRTreesGetTruncatePrunedTree(cv::ml::RTrees* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveRTreesGetTruncatePrunedTree", "ptr", $obj), "cveRTreesGetTruncatePrunedTree", @error)
EndFunc   ;==>_cveRTreesGetTruncatePrunedTree

Func _cveRTreesSetTruncatePrunedTree($obj, $value)
    ; CVAPI(void) cveRTreesSetTruncatePrunedTree(cv::ml::RTrees* obj, bool value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveRTreesSetTruncatePrunedTree", "ptr", $obj, "boolean", $value), "cveRTreesSetTruncatePrunedTree", @error)
EndFunc   ;==>_cveRTreesSetTruncatePrunedTree

Func _cveRTreesGetRegressionAccuracy($obj)
    ; CVAPI(float) cveRTreesGetRegressionAccuracy(cv::ml::RTrees* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cveRTreesGetRegressionAccuracy", "ptr", $obj), "cveRTreesGetRegressionAccuracy", @error)
EndFunc   ;==>_cveRTreesGetRegressionAccuracy

Func _cveRTreesSetRegressionAccuracy($obj, $value)
    ; CVAPI(void) cveRTreesSetRegressionAccuracy(cv::ml::RTrees* obj, float value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveRTreesSetRegressionAccuracy", "ptr", $obj, "float", $value), "cveRTreesSetRegressionAccuracy", @error)
EndFunc   ;==>_cveRTreesSetRegressionAccuracy

Func _cveRTreesGetCalculateVarImportance($obj)
    ; CVAPI(bool) cveRTreesGetCalculateVarImportance(cv::ml::RTrees* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveRTreesGetCalculateVarImportance", "ptr", $obj), "cveRTreesGetCalculateVarImportance", @error)
EndFunc   ;==>_cveRTreesGetCalculateVarImportance

Func _cveRTreesSetCalculateVarImportance($obj, $value)
    ; CVAPI(void) cveRTreesSetCalculateVarImportance(cv::ml::RTrees* obj, bool value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveRTreesSetCalculateVarImportance", "ptr", $obj, "boolean", $value), "cveRTreesSetCalculateVarImportance", @error)
EndFunc   ;==>_cveRTreesSetCalculateVarImportance

Func _cveRTreesGetActiveVarCount($obj)
    ; CVAPI(int) cveRTreesGetActiveVarCount(cv::ml::RTrees* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveRTreesGetActiveVarCount", "ptr", $obj), "cveRTreesGetActiveVarCount", @error)
EndFunc   ;==>_cveRTreesGetActiveVarCount

Func _cveRTreesSetActiveVarCount($obj, $value)
    ; CVAPI(void) cveRTreesSetActiveVarCount(cv::ml::RTrees* obj, int value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveRTreesSetActiveVarCount", "ptr", $obj, "int", $value), "cveRTreesSetActiveVarCount", @error)
EndFunc   ;==>_cveRTreesSetActiveVarCount

Func _cveRTreesGetTermCriteria($obj, $value)
    ; CVAPI(void) cveRTreesGetTermCriteria(cv::ml::RTrees* obj, CvTermCriteria* value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveRTreesGetTermCriteria", "ptr", $obj, "struct*", $value), "cveRTreesGetTermCriteria", @error)
EndFunc   ;==>_cveRTreesGetTermCriteria

Func _cveRTreesSetTermCriteria($obj, $value)
    ; CVAPI(void) cveRTreesSetTermCriteria(cv::ml::RTrees* obj, CvTermCriteria* value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveRTreesSetTermCriteria", "ptr", $obj, "struct*", $value), "cveRTreesSetTermCriteria", @error)
EndFunc   ;==>_cveRTreesSetTermCriteria