#include-once
#include "..\..\CVEUtils.au3"

Func _cveBoostGetMaxCategories($obj)
    ; CVAPI(int) cveBoostGetMaxCategories(cv::ml::Boost* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveBoostGetMaxCategories", "ptr", $obj), "cveBoostGetMaxCategories", @error)
EndFunc   ;==>_cveBoostGetMaxCategories

Func _cveBoostSetMaxCategories($obj, $value)
    ; CVAPI(void) cveBoostSetMaxCategories(cv::ml::Boost* obj, int value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBoostSetMaxCategories", "ptr", $obj, "int", $value), "cveBoostSetMaxCategories", @error)
EndFunc   ;==>_cveBoostSetMaxCategories

Func _cveBoostGetMaxDepth($obj)
    ; CVAPI(int) cveBoostGetMaxDepth(cv::ml::Boost* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveBoostGetMaxDepth", "ptr", $obj), "cveBoostGetMaxDepth", @error)
EndFunc   ;==>_cveBoostGetMaxDepth

Func _cveBoostSetMaxDepth($obj, $value)
    ; CVAPI(void) cveBoostSetMaxDepth(cv::ml::Boost* obj, int value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBoostSetMaxDepth", "ptr", $obj, "int", $value), "cveBoostSetMaxDepth", @error)
EndFunc   ;==>_cveBoostSetMaxDepth

Func _cveBoostGetMinSampleCount($obj)
    ; CVAPI(int) cveBoostGetMinSampleCount(cv::ml::Boost* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveBoostGetMinSampleCount", "ptr", $obj), "cveBoostGetMinSampleCount", @error)
EndFunc   ;==>_cveBoostGetMinSampleCount

Func _cveBoostSetMinSampleCount($obj, $value)
    ; CVAPI(void) cveBoostSetMinSampleCount(cv::ml::Boost* obj, int value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBoostSetMinSampleCount", "ptr", $obj, "int", $value), "cveBoostSetMinSampleCount", @error)
EndFunc   ;==>_cveBoostSetMinSampleCount

Func _cveBoostGetCVFolds($obj)
    ; CVAPI(int) cveBoostGetCVFolds(cv::ml::Boost* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveBoostGetCVFolds", "ptr", $obj), "cveBoostGetCVFolds", @error)
EndFunc   ;==>_cveBoostGetCVFolds

Func _cveBoostSetCVFolds($obj, $value)
    ; CVAPI(void) cveBoostSetCVFolds(cv::ml::Boost* obj, int value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBoostSetCVFolds", "ptr", $obj, "int", $value), "cveBoostSetCVFolds", @error)
EndFunc   ;==>_cveBoostSetCVFolds

Func _cveBoostGetUseSurrogates($obj)
    ; CVAPI(bool) cveBoostGetUseSurrogates(cv::ml::Boost* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveBoostGetUseSurrogates", "ptr", $obj), "cveBoostGetUseSurrogates", @error)
EndFunc   ;==>_cveBoostGetUseSurrogates

Func _cveBoostSetUseSurrogates($obj, $value)
    ; CVAPI(void) cveBoostSetUseSurrogates(cv::ml::Boost* obj, bool value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBoostSetUseSurrogates", "ptr", $obj, "boolean", $value), "cveBoostSetUseSurrogates", @error)
EndFunc   ;==>_cveBoostSetUseSurrogates

Func _cveBoostGetUse1SERule($obj)
    ; CVAPI(bool) cveBoostGetUse1SERule(cv::ml::Boost* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveBoostGetUse1SERule", "ptr", $obj), "cveBoostGetUse1SERule", @error)
EndFunc   ;==>_cveBoostGetUse1SERule

Func _cveBoostSetUse1SERule($obj, $value)
    ; CVAPI(void) cveBoostSetUse1SERule(cv::ml::Boost* obj, bool value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBoostSetUse1SERule", "ptr", $obj, "boolean", $value), "cveBoostSetUse1SERule", @error)
EndFunc   ;==>_cveBoostSetUse1SERule

Func _cveBoostGetTruncatePrunedTree($obj)
    ; CVAPI(bool) cveBoostGetTruncatePrunedTree(cv::ml::Boost* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveBoostGetTruncatePrunedTree", "ptr", $obj), "cveBoostGetTruncatePrunedTree", @error)
EndFunc   ;==>_cveBoostGetTruncatePrunedTree

Func _cveBoostSetTruncatePrunedTree($obj, $value)
    ; CVAPI(void) cveBoostSetTruncatePrunedTree(cv::ml::Boost* obj, bool value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBoostSetTruncatePrunedTree", "ptr", $obj, "boolean", $value), "cveBoostSetTruncatePrunedTree", @error)
EndFunc   ;==>_cveBoostSetTruncatePrunedTree

Func _cveBoostGetRegressionAccuracy($obj)
    ; CVAPI(float) cveBoostGetRegressionAccuracy(cv::ml::Boost* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cveBoostGetRegressionAccuracy", "ptr", $obj), "cveBoostGetRegressionAccuracy", @error)
EndFunc   ;==>_cveBoostGetRegressionAccuracy

Func _cveBoostSetRegressionAccuracy($obj, $value)
    ; CVAPI(void) cveBoostSetRegressionAccuracy(cv::ml::Boost* obj, float value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBoostSetRegressionAccuracy", "ptr", $obj, "float", $value), "cveBoostSetRegressionAccuracy", @error)
EndFunc   ;==>_cveBoostSetRegressionAccuracy