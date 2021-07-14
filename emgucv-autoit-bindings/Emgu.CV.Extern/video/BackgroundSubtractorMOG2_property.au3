#include-once
#include <..\..\CVEUtils.au3>

Func _cveBackgroundSubtractorMOG2GetHistory(ByRef $obj)
    ; CVAPI(int) cveBackgroundSubtractorMOG2GetHistory(cv::BackgroundSubtractorMOG2* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveBackgroundSubtractorMOG2GetHistory", "ptr", $obj), "cveBackgroundSubtractorMOG2GetHistory", @error)
EndFunc   ;==>_cveBackgroundSubtractorMOG2GetHistory

Func _cveBackgroundSubtractorMOG2SetHistory(ByRef $obj, $value)
    ; CVAPI(void) cveBackgroundSubtractorMOG2SetHistory(cv::BackgroundSubtractorMOG2* obj, int value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBackgroundSubtractorMOG2SetHistory", "ptr", $obj, "int", $value), "cveBackgroundSubtractorMOG2SetHistory", @error)
EndFunc   ;==>_cveBackgroundSubtractorMOG2SetHistory

Func _cveBackgroundSubtractorMOG2GetDetectShadows(ByRef $obj)
    ; CVAPI(bool) cveBackgroundSubtractorMOG2GetDetectShadows(cv::BackgroundSubtractorMOG2* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveBackgroundSubtractorMOG2GetDetectShadows", "ptr", $obj), "cveBackgroundSubtractorMOG2GetDetectShadows", @error)
EndFunc   ;==>_cveBackgroundSubtractorMOG2GetDetectShadows

Func _cveBackgroundSubtractorMOG2SetDetectShadows(ByRef $obj, $value)
    ; CVAPI(void) cveBackgroundSubtractorMOG2SetDetectShadows(cv::BackgroundSubtractorMOG2* obj, bool value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBackgroundSubtractorMOG2SetDetectShadows", "ptr", $obj, "boolean", $value), "cveBackgroundSubtractorMOG2SetDetectShadows", @error)
EndFunc   ;==>_cveBackgroundSubtractorMOG2SetDetectShadows

Func _cveBackgroundSubtractorMOG2GetShadowValue(ByRef $obj)
    ; CVAPI(int) cveBackgroundSubtractorMOG2GetShadowValue(cv::BackgroundSubtractorMOG2* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveBackgroundSubtractorMOG2GetShadowValue", "ptr", $obj), "cveBackgroundSubtractorMOG2GetShadowValue", @error)
EndFunc   ;==>_cveBackgroundSubtractorMOG2GetShadowValue

Func _cveBackgroundSubtractorMOG2SetShadowValue(ByRef $obj, $value)
    ; CVAPI(void) cveBackgroundSubtractorMOG2SetShadowValue(cv::BackgroundSubtractorMOG2* obj, int value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBackgroundSubtractorMOG2SetShadowValue", "ptr", $obj, "int", $value), "cveBackgroundSubtractorMOG2SetShadowValue", @error)
EndFunc   ;==>_cveBackgroundSubtractorMOG2SetShadowValue

Func _cveBackgroundSubtractorMOG2GetShadowThreshold(ByRef $obj)
    ; CVAPI(double) cveBackgroundSubtractorMOG2GetShadowThreshold(cv::BackgroundSubtractorMOG2* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveBackgroundSubtractorMOG2GetShadowThreshold", "ptr", $obj), "cveBackgroundSubtractorMOG2GetShadowThreshold", @error)
EndFunc   ;==>_cveBackgroundSubtractorMOG2GetShadowThreshold

Func _cveBackgroundSubtractorMOG2SetShadowThreshold(ByRef $obj, $value)
    ; CVAPI(void) cveBackgroundSubtractorMOG2SetShadowThreshold(cv::BackgroundSubtractorMOG2* obj, double value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBackgroundSubtractorMOG2SetShadowThreshold", "ptr", $obj, "double", $value), "cveBackgroundSubtractorMOG2SetShadowThreshold", @error)
EndFunc   ;==>_cveBackgroundSubtractorMOG2SetShadowThreshold

Func _cveBackgroundSubtractorMOG2GetNMixtures(ByRef $obj)
    ; CVAPI(int) cveBackgroundSubtractorMOG2GetNMixtures(cv::BackgroundSubtractorMOG2* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveBackgroundSubtractorMOG2GetNMixtures", "ptr", $obj), "cveBackgroundSubtractorMOG2GetNMixtures", @error)
EndFunc   ;==>_cveBackgroundSubtractorMOG2GetNMixtures

Func _cveBackgroundSubtractorMOG2SetNMixtures(ByRef $obj, $value)
    ; CVAPI(void) cveBackgroundSubtractorMOG2SetNMixtures(cv::BackgroundSubtractorMOG2* obj, int value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBackgroundSubtractorMOG2SetNMixtures", "ptr", $obj, "int", $value), "cveBackgroundSubtractorMOG2SetNMixtures", @error)
EndFunc   ;==>_cveBackgroundSubtractorMOG2SetNMixtures

Func _cveBackgroundSubtractorMOG2GetBackgroundRatio(ByRef $obj)
    ; CVAPI(double) cveBackgroundSubtractorMOG2GetBackgroundRatio(cv::BackgroundSubtractorMOG2* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveBackgroundSubtractorMOG2GetBackgroundRatio", "ptr", $obj), "cveBackgroundSubtractorMOG2GetBackgroundRatio", @error)
EndFunc   ;==>_cveBackgroundSubtractorMOG2GetBackgroundRatio

Func _cveBackgroundSubtractorMOG2SetBackgroundRatio(ByRef $obj, $value)
    ; CVAPI(void) cveBackgroundSubtractorMOG2SetBackgroundRatio(cv::BackgroundSubtractorMOG2* obj, double value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBackgroundSubtractorMOG2SetBackgroundRatio", "ptr", $obj, "double", $value), "cveBackgroundSubtractorMOG2SetBackgroundRatio", @error)
EndFunc   ;==>_cveBackgroundSubtractorMOG2SetBackgroundRatio

Func _cveBackgroundSubtractorMOG2GetVarThreshold(ByRef $obj)
    ; CVAPI(double) cveBackgroundSubtractorMOG2GetVarThreshold(cv::BackgroundSubtractorMOG2* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveBackgroundSubtractorMOG2GetVarThreshold", "ptr", $obj), "cveBackgroundSubtractorMOG2GetVarThreshold", @error)
EndFunc   ;==>_cveBackgroundSubtractorMOG2GetVarThreshold

Func _cveBackgroundSubtractorMOG2SetVarThreshold(ByRef $obj, $value)
    ; CVAPI(void) cveBackgroundSubtractorMOG2SetVarThreshold(cv::BackgroundSubtractorMOG2* obj, double value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBackgroundSubtractorMOG2SetVarThreshold", "ptr", $obj, "double", $value), "cveBackgroundSubtractorMOG2SetVarThreshold", @error)
EndFunc   ;==>_cveBackgroundSubtractorMOG2SetVarThreshold

Func _cveBackgroundSubtractorMOG2GetVarThresholdGen(ByRef $obj)
    ; CVAPI(double) cveBackgroundSubtractorMOG2GetVarThresholdGen(cv::BackgroundSubtractorMOG2* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveBackgroundSubtractorMOG2GetVarThresholdGen", "ptr", $obj), "cveBackgroundSubtractorMOG2GetVarThresholdGen", @error)
EndFunc   ;==>_cveBackgroundSubtractorMOG2GetVarThresholdGen

Func _cveBackgroundSubtractorMOG2SetVarThresholdGen(ByRef $obj, $value)
    ; CVAPI(void) cveBackgroundSubtractorMOG2SetVarThresholdGen(cv::BackgroundSubtractorMOG2* obj, double value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBackgroundSubtractorMOG2SetVarThresholdGen", "ptr", $obj, "double", $value), "cveBackgroundSubtractorMOG2SetVarThresholdGen", @error)
EndFunc   ;==>_cveBackgroundSubtractorMOG2SetVarThresholdGen

Func _cveBackgroundSubtractorMOG2GetVarInit(ByRef $obj)
    ; CVAPI(double) cveBackgroundSubtractorMOG2GetVarInit(cv::BackgroundSubtractorMOG2* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveBackgroundSubtractorMOG2GetVarInit", "ptr", $obj), "cveBackgroundSubtractorMOG2GetVarInit", @error)
EndFunc   ;==>_cveBackgroundSubtractorMOG2GetVarInit

Func _cveBackgroundSubtractorMOG2SetVarInit(ByRef $obj, $value)
    ; CVAPI(void) cveBackgroundSubtractorMOG2SetVarInit(cv::BackgroundSubtractorMOG2* obj, double value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBackgroundSubtractorMOG2SetVarInit", "ptr", $obj, "double", $value), "cveBackgroundSubtractorMOG2SetVarInit", @error)
EndFunc   ;==>_cveBackgroundSubtractorMOG2SetVarInit

Func _cveBackgroundSubtractorMOG2GetVarMin(ByRef $obj)
    ; CVAPI(double) cveBackgroundSubtractorMOG2GetVarMin(cv::BackgroundSubtractorMOG2* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveBackgroundSubtractorMOG2GetVarMin", "ptr", $obj), "cveBackgroundSubtractorMOG2GetVarMin", @error)
EndFunc   ;==>_cveBackgroundSubtractorMOG2GetVarMin

Func _cveBackgroundSubtractorMOG2SetVarMin(ByRef $obj, $value)
    ; CVAPI(void) cveBackgroundSubtractorMOG2SetVarMin(cv::BackgroundSubtractorMOG2* obj, double value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBackgroundSubtractorMOG2SetVarMin", "ptr", $obj, "double", $value), "cveBackgroundSubtractorMOG2SetVarMin", @error)
EndFunc   ;==>_cveBackgroundSubtractorMOG2SetVarMin

Func _cveBackgroundSubtractorMOG2GetVarMax(ByRef $obj)
    ; CVAPI(double) cveBackgroundSubtractorMOG2GetVarMax(cv::BackgroundSubtractorMOG2* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveBackgroundSubtractorMOG2GetVarMax", "ptr", $obj), "cveBackgroundSubtractorMOG2GetVarMax", @error)
EndFunc   ;==>_cveBackgroundSubtractorMOG2GetVarMax

Func _cveBackgroundSubtractorMOG2SetVarMax(ByRef $obj, $value)
    ; CVAPI(void) cveBackgroundSubtractorMOG2SetVarMax(cv::BackgroundSubtractorMOG2* obj, double value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBackgroundSubtractorMOG2SetVarMax", "ptr", $obj, "double", $value), "cveBackgroundSubtractorMOG2SetVarMax", @error)
EndFunc   ;==>_cveBackgroundSubtractorMOG2SetVarMax

Func _cveBackgroundSubtractorMOG2GetComplexityReductionThreshold(ByRef $obj)
    ; CVAPI(double) cveBackgroundSubtractorMOG2GetComplexityReductionThreshold(cv::BackgroundSubtractorMOG2* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveBackgroundSubtractorMOG2GetComplexityReductionThreshold", "ptr", $obj), "cveBackgroundSubtractorMOG2GetComplexityReductionThreshold", @error)
EndFunc   ;==>_cveBackgroundSubtractorMOG2GetComplexityReductionThreshold

Func _cveBackgroundSubtractorMOG2SetComplexityReductionThreshold(ByRef $obj, $value)
    ; CVAPI(void) cveBackgroundSubtractorMOG2SetComplexityReductionThreshold(cv::BackgroundSubtractorMOG2* obj, double value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBackgroundSubtractorMOG2SetComplexityReductionThreshold", "ptr", $obj, "double", $value), "cveBackgroundSubtractorMOG2SetComplexityReductionThreshold", @error)
EndFunc   ;==>_cveBackgroundSubtractorMOG2SetComplexityReductionThreshold