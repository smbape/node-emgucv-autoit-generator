#include-once
#include "..\..\CVEUtils.au3"

Func _cveDTreesGetMaxCategories($obj)
    ; CVAPI(int) cveDTreesGetMaxCategories(cv::ml::DTrees* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveDTreesGetMaxCategories", "ptr", $obj), "cveDTreesGetMaxCategories", @error)
EndFunc   ;==>_cveDTreesGetMaxCategories

Func _cveDTreesSetMaxCategories($obj, $value)
    ; CVAPI(void) cveDTreesSetMaxCategories(cv::ml::DTrees* obj, int value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDTreesSetMaxCategories", "ptr", $obj, "int", $value), "cveDTreesSetMaxCategories", @error)
EndFunc   ;==>_cveDTreesSetMaxCategories

Func _cveDTreesGetMaxDepth($obj)
    ; CVAPI(int) cveDTreesGetMaxDepth(cv::ml::DTrees* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveDTreesGetMaxDepth", "ptr", $obj), "cveDTreesGetMaxDepth", @error)
EndFunc   ;==>_cveDTreesGetMaxDepth

Func _cveDTreesSetMaxDepth($obj, $value)
    ; CVAPI(void) cveDTreesSetMaxDepth(cv::ml::DTrees* obj, int value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDTreesSetMaxDepth", "ptr", $obj, "int", $value), "cveDTreesSetMaxDepth", @error)
EndFunc   ;==>_cveDTreesSetMaxDepth

Func _cveDTreesGetMinSampleCount($obj)
    ; CVAPI(int) cveDTreesGetMinSampleCount(cv::ml::DTrees* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveDTreesGetMinSampleCount", "ptr", $obj), "cveDTreesGetMinSampleCount", @error)
EndFunc   ;==>_cveDTreesGetMinSampleCount

Func _cveDTreesSetMinSampleCount($obj, $value)
    ; CVAPI(void) cveDTreesSetMinSampleCount(cv::ml::DTrees* obj, int value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDTreesSetMinSampleCount", "ptr", $obj, "int", $value), "cveDTreesSetMinSampleCount", @error)
EndFunc   ;==>_cveDTreesSetMinSampleCount

Func _cveDTreesGetCVFolds($obj)
    ; CVAPI(int) cveDTreesGetCVFolds(cv::ml::DTrees* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveDTreesGetCVFolds", "ptr", $obj), "cveDTreesGetCVFolds", @error)
EndFunc   ;==>_cveDTreesGetCVFolds

Func _cveDTreesSetCVFolds($obj, $value)
    ; CVAPI(void) cveDTreesSetCVFolds(cv::ml::DTrees* obj, int value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDTreesSetCVFolds", "ptr", $obj, "int", $value), "cveDTreesSetCVFolds", @error)
EndFunc   ;==>_cveDTreesSetCVFolds

Func _cveDTreesGetUseSurrogates($obj)
    ; CVAPI(bool) cveDTreesGetUseSurrogates(cv::ml::DTrees* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveDTreesGetUseSurrogates", "ptr", $obj), "cveDTreesGetUseSurrogates", @error)
EndFunc   ;==>_cveDTreesGetUseSurrogates

Func _cveDTreesSetUseSurrogates($obj, $value)
    ; CVAPI(void) cveDTreesSetUseSurrogates(cv::ml::DTrees* obj, bool value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDTreesSetUseSurrogates", "ptr", $obj, "boolean", $value), "cveDTreesSetUseSurrogates", @error)
EndFunc   ;==>_cveDTreesSetUseSurrogates

Func _cveDTreesGetUse1SERule($obj)
    ; CVAPI(bool) cveDTreesGetUse1SERule(cv::ml::DTrees* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveDTreesGetUse1SERule", "ptr", $obj), "cveDTreesGetUse1SERule", @error)
EndFunc   ;==>_cveDTreesGetUse1SERule

Func _cveDTreesSetUse1SERule($obj, $value)
    ; CVAPI(void) cveDTreesSetUse1SERule(cv::ml::DTrees* obj, bool value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDTreesSetUse1SERule", "ptr", $obj, "boolean", $value), "cveDTreesSetUse1SERule", @error)
EndFunc   ;==>_cveDTreesSetUse1SERule

Func _cveDTreesGetTruncatePrunedTree($obj)
    ; CVAPI(bool) cveDTreesGetTruncatePrunedTree(cv::ml::DTrees* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveDTreesGetTruncatePrunedTree", "ptr", $obj), "cveDTreesGetTruncatePrunedTree", @error)
EndFunc   ;==>_cveDTreesGetTruncatePrunedTree

Func _cveDTreesSetTruncatePrunedTree($obj, $value)
    ; CVAPI(void) cveDTreesSetTruncatePrunedTree(cv::ml::DTrees* obj, bool value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDTreesSetTruncatePrunedTree", "ptr", $obj, "boolean", $value), "cveDTreesSetTruncatePrunedTree", @error)
EndFunc   ;==>_cveDTreesSetTruncatePrunedTree

Func _cveDTreesGetRegressionAccuracy($obj)
    ; CVAPI(float) cveDTreesGetRegressionAccuracy(cv::ml::DTrees* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cveDTreesGetRegressionAccuracy", "ptr", $obj), "cveDTreesGetRegressionAccuracy", @error)
EndFunc   ;==>_cveDTreesGetRegressionAccuracy

Func _cveDTreesSetRegressionAccuracy($obj, $value)
    ; CVAPI(void) cveDTreesSetRegressionAccuracy(cv::ml::DTrees* obj, float value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDTreesSetRegressionAccuracy", "ptr", $obj, "float", $value), "cveDTreesSetRegressionAccuracy", @error)
EndFunc   ;==>_cveDTreesSetRegressionAccuracy