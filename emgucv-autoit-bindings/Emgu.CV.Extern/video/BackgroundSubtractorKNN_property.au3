#include-once
#include <..\..\CVEUtils.au3>

Func _cveBackgroundSubtractorKNNGetHistory(ByRef $obj)
    ; CVAPI(int) cveBackgroundSubtractorKNNGetHistory(cv::BackgroundSubtractorKNN* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveBackgroundSubtractorKNNGetHistory", "ptr", $obj), "cveBackgroundSubtractorKNNGetHistory", @error)
EndFunc   ;==>_cveBackgroundSubtractorKNNGetHistory

Func _cveBackgroundSubtractorKNNSetHistory(ByRef $obj, $value)
    ; CVAPI(void) cveBackgroundSubtractorKNNSetHistory(cv::BackgroundSubtractorKNN* obj, int value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBackgroundSubtractorKNNSetHistory", "ptr", $obj, "int", $value), "cveBackgroundSubtractorKNNSetHistory", @error)
EndFunc   ;==>_cveBackgroundSubtractorKNNSetHistory

Func _cveBackgroundSubtractorKNNGetNSamples(ByRef $obj)
    ; CVAPI(int) cveBackgroundSubtractorKNNGetNSamples(cv::BackgroundSubtractorKNN* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveBackgroundSubtractorKNNGetNSamples", "ptr", $obj), "cveBackgroundSubtractorKNNGetNSamples", @error)
EndFunc   ;==>_cveBackgroundSubtractorKNNGetNSamples

Func _cveBackgroundSubtractorKNNSetNSamples(ByRef $obj, $value)
    ; CVAPI(void) cveBackgroundSubtractorKNNSetNSamples(cv::BackgroundSubtractorKNN* obj, int value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBackgroundSubtractorKNNSetNSamples", "ptr", $obj, "int", $value), "cveBackgroundSubtractorKNNSetNSamples", @error)
EndFunc   ;==>_cveBackgroundSubtractorKNNSetNSamples

Func _cveBackgroundSubtractorKNNGetDist2Threshold(ByRef $obj)
    ; CVAPI(double) cveBackgroundSubtractorKNNGetDist2Threshold(cv::BackgroundSubtractorKNN* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveBackgroundSubtractorKNNGetDist2Threshold", "ptr", $obj), "cveBackgroundSubtractorKNNGetDist2Threshold", @error)
EndFunc   ;==>_cveBackgroundSubtractorKNNGetDist2Threshold

Func _cveBackgroundSubtractorKNNSetDist2Threshold(ByRef $obj, $value)
    ; CVAPI(void) cveBackgroundSubtractorKNNSetDist2Threshold(cv::BackgroundSubtractorKNN* obj, double value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBackgroundSubtractorKNNSetDist2Threshold", "ptr", $obj, "double", $value), "cveBackgroundSubtractorKNNSetDist2Threshold", @error)
EndFunc   ;==>_cveBackgroundSubtractorKNNSetDist2Threshold

Func _cveBackgroundSubtractorKNNGetKNNSamples(ByRef $obj)
    ; CVAPI(int) cveBackgroundSubtractorKNNGetKNNSamples(cv::BackgroundSubtractorKNN* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveBackgroundSubtractorKNNGetKNNSamples", "ptr", $obj), "cveBackgroundSubtractorKNNGetKNNSamples", @error)
EndFunc   ;==>_cveBackgroundSubtractorKNNGetKNNSamples

Func _cveBackgroundSubtractorKNNSetKNNSamples(ByRef $obj, $value)
    ; CVAPI(void) cveBackgroundSubtractorKNNSetKNNSamples(cv::BackgroundSubtractorKNN* obj, int value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBackgroundSubtractorKNNSetKNNSamples", "ptr", $obj, "int", $value), "cveBackgroundSubtractorKNNSetKNNSamples", @error)
EndFunc   ;==>_cveBackgroundSubtractorKNNSetKNNSamples

Func _cveBackgroundSubtractorKNNGetDetectShadows(ByRef $obj)
    ; CVAPI(bool) cveBackgroundSubtractorKNNGetDetectShadows(cv::BackgroundSubtractorKNN* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveBackgroundSubtractorKNNGetDetectShadows", "ptr", $obj), "cveBackgroundSubtractorKNNGetDetectShadows", @error)
EndFunc   ;==>_cveBackgroundSubtractorKNNGetDetectShadows

Func _cveBackgroundSubtractorKNNSetDetectShadows(ByRef $obj, $value)
    ; CVAPI(void) cveBackgroundSubtractorKNNSetDetectShadows(cv::BackgroundSubtractorKNN* obj, bool value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBackgroundSubtractorKNNSetDetectShadows", "ptr", $obj, "boolean", $value), "cveBackgroundSubtractorKNNSetDetectShadows", @error)
EndFunc   ;==>_cveBackgroundSubtractorKNNSetDetectShadows

Func _cveBackgroundSubtractorKNNGetShadowValue(ByRef $obj)
    ; CVAPI(int) cveBackgroundSubtractorKNNGetShadowValue(cv::BackgroundSubtractorKNN* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveBackgroundSubtractorKNNGetShadowValue", "ptr", $obj), "cveBackgroundSubtractorKNNGetShadowValue", @error)
EndFunc   ;==>_cveBackgroundSubtractorKNNGetShadowValue

Func _cveBackgroundSubtractorKNNSetShadowValue(ByRef $obj, $value)
    ; CVAPI(void) cveBackgroundSubtractorKNNSetShadowValue(cv::BackgroundSubtractorKNN* obj, int value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBackgroundSubtractorKNNSetShadowValue", "ptr", $obj, "int", $value), "cveBackgroundSubtractorKNNSetShadowValue", @error)
EndFunc   ;==>_cveBackgroundSubtractorKNNSetShadowValue

Func _cveBackgroundSubtractorKNNGetShadowThreshold(ByRef $obj)
    ; CVAPI(double) cveBackgroundSubtractorKNNGetShadowThreshold(cv::BackgroundSubtractorKNN* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveBackgroundSubtractorKNNGetShadowThreshold", "ptr", $obj), "cveBackgroundSubtractorKNNGetShadowThreshold", @error)
EndFunc   ;==>_cveBackgroundSubtractorKNNGetShadowThreshold

Func _cveBackgroundSubtractorKNNSetShadowThreshold(ByRef $obj, $value)
    ; CVAPI(void) cveBackgroundSubtractorKNNSetShadowThreshold(cv::BackgroundSubtractorKNN* obj, double value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBackgroundSubtractorKNNSetShadowThreshold", "ptr", $obj, "double", $value), "cveBackgroundSubtractorKNNSetShadowThreshold", @error)
EndFunc   ;==>_cveBackgroundSubtractorKNNSetShadowThreshold