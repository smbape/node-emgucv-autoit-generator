#include-once
#include "..\..\CVEUtils.au3"

Func _cveSimpleBlobDetectorParamsGetThresholdStep(ByRef $obj)
    ; CVAPI(float) cveSimpleBlobDetectorParamsGetThresholdStep(cv::SimpleBlobDetector::Params* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cveSimpleBlobDetectorParamsGetThresholdStep", "ptr", $obj), "cveSimpleBlobDetectorParamsGetThresholdStep", @error)
EndFunc   ;==>_cveSimpleBlobDetectorParamsGetThresholdStep

Func _cveSimpleBlobDetectorParamsSetThresholdStep(ByRef $obj, $value)
    ; CVAPI(void) cveSimpleBlobDetectorParamsSetThresholdStep(cv::SimpleBlobDetector::Params* obj, float value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSimpleBlobDetectorParamsSetThresholdStep", "ptr", $obj, "float", $value), "cveSimpleBlobDetectorParamsSetThresholdStep", @error)
EndFunc   ;==>_cveSimpleBlobDetectorParamsSetThresholdStep

Func _cveSimpleBlobDetectorParamsGetMinThreshold(ByRef $obj)
    ; CVAPI(float) cveSimpleBlobDetectorParamsGetMinThreshold(cv::SimpleBlobDetector::Params* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cveSimpleBlobDetectorParamsGetMinThreshold", "ptr", $obj), "cveSimpleBlobDetectorParamsGetMinThreshold", @error)
EndFunc   ;==>_cveSimpleBlobDetectorParamsGetMinThreshold

Func _cveSimpleBlobDetectorParamsSetMinThreshold(ByRef $obj, $value)
    ; CVAPI(void) cveSimpleBlobDetectorParamsSetMinThreshold(cv::SimpleBlobDetector::Params* obj, float value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSimpleBlobDetectorParamsSetMinThreshold", "ptr", $obj, "float", $value), "cveSimpleBlobDetectorParamsSetMinThreshold", @error)
EndFunc   ;==>_cveSimpleBlobDetectorParamsSetMinThreshold

Func _cveSimpleBlobDetectorParamsGetMaxThreshold(ByRef $obj)
    ; CVAPI(float) cveSimpleBlobDetectorParamsGetMaxThreshold(cv::SimpleBlobDetector::Params* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cveSimpleBlobDetectorParamsGetMaxThreshold", "ptr", $obj), "cveSimpleBlobDetectorParamsGetMaxThreshold", @error)
EndFunc   ;==>_cveSimpleBlobDetectorParamsGetMaxThreshold

Func _cveSimpleBlobDetectorParamsSetMaxThreshold(ByRef $obj, $value)
    ; CVAPI(void) cveSimpleBlobDetectorParamsSetMaxThreshold(cv::SimpleBlobDetector::Params* obj, float value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSimpleBlobDetectorParamsSetMaxThreshold", "ptr", $obj, "float", $value), "cveSimpleBlobDetectorParamsSetMaxThreshold", @error)
EndFunc   ;==>_cveSimpleBlobDetectorParamsSetMaxThreshold

Func _cveSimpleBlobDetectorParamsGetMinDistBetweenBlobs(ByRef $obj)
    ; CVAPI(float) cveSimpleBlobDetectorParamsGetMinDistBetweenBlobs(cv::SimpleBlobDetector::Params* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cveSimpleBlobDetectorParamsGetMinDistBetweenBlobs", "ptr", $obj), "cveSimpleBlobDetectorParamsGetMinDistBetweenBlobs", @error)
EndFunc   ;==>_cveSimpleBlobDetectorParamsGetMinDistBetweenBlobs

Func _cveSimpleBlobDetectorParamsSetMinDistBetweenBlobs(ByRef $obj, $value)
    ; CVAPI(void) cveSimpleBlobDetectorParamsSetMinDistBetweenBlobs(cv::SimpleBlobDetector::Params* obj, float value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSimpleBlobDetectorParamsSetMinDistBetweenBlobs", "ptr", $obj, "float", $value), "cveSimpleBlobDetectorParamsSetMinDistBetweenBlobs", @error)
EndFunc   ;==>_cveSimpleBlobDetectorParamsSetMinDistBetweenBlobs

Func _cveSimpleBlobDetectorParamsGetFilterByColor(ByRef $obj)
    ; CVAPI(bool) cveSimpleBlobDetectorParamsGetFilterByColor(cv::SimpleBlobDetector::Params* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveSimpleBlobDetectorParamsGetFilterByColor", "ptr", $obj), "cveSimpleBlobDetectorParamsGetFilterByColor", @error)
EndFunc   ;==>_cveSimpleBlobDetectorParamsGetFilterByColor

Func _cveSimpleBlobDetectorParamsSetFilterByColor(ByRef $obj, $value)
    ; CVAPI(void) cveSimpleBlobDetectorParamsSetFilterByColor(cv::SimpleBlobDetector::Params* obj, bool value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSimpleBlobDetectorParamsSetFilterByColor", "ptr", $obj, "boolean", $value), "cveSimpleBlobDetectorParamsSetFilterByColor", @error)
EndFunc   ;==>_cveSimpleBlobDetectorParamsSetFilterByColor

Func _cveSimpleBlobDetectorParamsGetblobColor(ByRef $obj)
    ; CVAPI(uchar) cveSimpleBlobDetectorParamsGetblobColor(cv::SimpleBlobDetector::Params* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "uchar:cdecl", "cveSimpleBlobDetectorParamsGetblobColor", "ptr", $obj), "cveSimpleBlobDetectorParamsGetblobColor", @error)
EndFunc   ;==>_cveSimpleBlobDetectorParamsGetblobColor

Func _cveSimpleBlobDetectorParamsSetblobColor(ByRef $obj, $value)
    ; CVAPI(void) cveSimpleBlobDetectorParamsSetblobColor(cv::SimpleBlobDetector::Params* obj, uchar value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSimpleBlobDetectorParamsSetblobColor", "ptr", $obj, "uchar", $value), "cveSimpleBlobDetectorParamsSetblobColor", @error)
EndFunc   ;==>_cveSimpleBlobDetectorParamsSetblobColor

Func _cveSimpleBlobDetectorParamsGetFilterByArea(ByRef $obj)
    ; CVAPI(bool) cveSimpleBlobDetectorParamsGetFilterByArea(cv::SimpleBlobDetector::Params* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveSimpleBlobDetectorParamsGetFilterByArea", "ptr", $obj), "cveSimpleBlobDetectorParamsGetFilterByArea", @error)
EndFunc   ;==>_cveSimpleBlobDetectorParamsGetFilterByArea

Func _cveSimpleBlobDetectorParamsSetFilterByArea(ByRef $obj, $value)
    ; CVAPI(void) cveSimpleBlobDetectorParamsSetFilterByArea(cv::SimpleBlobDetector::Params* obj, bool value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSimpleBlobDetectorParamsSetFilterByArea", "ptr", $obj, "boolean", $value), "cveSimpleBlobDetectorParamsSetFilterByArea", @error)
EndFunc   ;==>_cveSimpleBlobDetectorParamsSetFilterByArea

Func _cveSimpleBlobDetectorParamsGetMinArea(ByRef $obj)
    ; CVAPI(float) cveSimpleBlobDetectorParamsGetMinArea(cv::SimpleBlobDetector::Params* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cveSimpleBlobDetectorParamsGetMinArea", "ptr", $obj), "cveSimpleBlobDetectorParamsGetMinArea", @error)
EndFunc   ;==>_cveSimpleBlobDetectorParamsGetMinArea

Func _cveSimpleBlobDetectorParamsSetMinArea(ByRef $obj, $value)
    ; CVAPI(void) cveSimpleBlobDetectorParamsSetMinArea(cv::SimpleBlobDetector::Params* obj, float value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSimpleBlobDetectorParamsSetMinArea", "ptr", $obj, "float", $value), "cveSimpleBlobDetectorParamsSetMinArea", @error)
EndFunc   ;==>_cveSimpleBlobDetectorParamsSetMinArea

Func _cveSimpleBlobDetectorParamsGetMaxArea(ByRef $obj)
    ; CVAPI(float) cveSimpleBlobDetectorParamsGetMaxArea(cv::SimpleBlobDetector::Params* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cveSimpleBlobDetectorParamsGetMaxArea", "ptr", $obj), "cveSimpleBlobDetectorParamsGetMaxArea", @error)
EndFunc   ;==>_cveSimpleBlobDetectorParamsGetMaxArea

Func _cveSimpleBlobDetectorParamsSetMaxArea(ByRef $obj, $value)
    ; CVAPI(void) cveSimpleBlobDetectorParamsSetMaxArea(cv::SimpleBlobDetector::Params* obj, float value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSimpleBlobDetectorParamsSetMaxArea", "ptr", $obj, "float", $value), "cveSimpleBlobDetectorParamsSetMaxArea", @error)
EndFunc   ;==>_cveSimpleBlobDetectorParamsSetMaxArea

Func _cveSimpleBlobDetectorParamsGetFilterByCircularity(ByRef $obj)
    ; CVAPI(bool) cveSimpleBlobDetectorParamsGetFilterByCircularity(cv::SimpleBlobDetector::Params* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveSimpleBlobDetectorParamsGetFilterByCircularity", "ptr", $obj), "cveSimpleBlobDetectorParamsGetFilterByCircularity", @error)
EndFunc   ;==>_cveSimpleBlobDetectorParamsGetFilterByCircularity

Func _cveSimpleBlobDetectorParamsSetFilterByCircularity(ByRef $obj, $value)
    ; CVAPI(void) cveSimpleBlobDetectorParamsSetFilterByCircularity(cv::SimpleBlobDetector::Params* obj, bool value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSimpleBlobDetectorParamsSetFilterByCircularity", "ptr", $obj, "boolean", $value), "cveSimpleBlobDetectorParamsSetFilterByCircularity", @error)
EndFunc   ;==>_cveSimpleBlobDetectorParamsSetFilterByCircularity

Func _cveSimpleBlobDetectorParamsGetMinCircularity(ByRef $obj)
    ; CVAPI(float) cveSimpleBlobDetectorParamsGetMinCircularity(cv::SimpleBlobDetector::Params* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cveSimpleBlobDetectorParamsGetMinCircularity", "ptr", $obj), "cveSimpleBlobDetectorParamsGetMinCircularity", @error)
EndFunc   ;==>_cveSimpleBlobDetectorParamsGetMinCircularity

Func _cveSimpleBlobDetectorParamsSetMinCircularity(ByRef $obj, $value)
    ; CVAPI(void) cveSimpleBlobDetectorParamsSetMinCircularity(cv::SimpleBlobDetector::Params* obj, float value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSimpleBlobDetectorParamsSetMinCircularity", "ptr", $obj, "float", $value), "cveSimpleBlobDetectorParamsSetMinCircularity", @error)
EndFunc   ;==>_cveSimpleBlobDetectorParamsSetMinCircularity

Func _cveSimpleBlobDetectorParamsGetMaxCircularity(ByRef $obj)
    ; CVAPI(float) cveSimpleBlobDetectorParamsGetMaxCircularity(cv::SimpleBlobDetector::Params* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cveSimpleBlobDetectorParamsGetMaxCircularity", "ptr", $obj), "cveSimpleBlobDetectorParamsGetMaxCircularity", @error)
EndFunc   ;==>_cveSimpleBlobDetectorParamsGetMaxCircularity

Func _cveSimpleBlobDetectorParamsSetMaxCircularity(ByRef $obj, $value)
    ; CVAPI(void) cveSimpleBlobDetectorParamsSetMaxCircularity(cv::SimpleBlobDetector::Params* obj, float value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSimpleBlobDetectorParamsSetMaxCircularity", "ptr", $obj, "float", $value), "cveSimpleBlobDetectorParamsSetMaxCircularity", @error)
EndFunc   ;==>_cveSimpleBlobDetectorParamsSetMaxCircularity

Func _cveSimpleBlobDetectorParamsGetFilterByInertia(ByRef $obj)
    ; CVAPI(bool) cveSimpleBlobDetectorParamsGetFilterByInertia(cv::SimpleBlobDetector::Params* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveSimpleBlobDetectorParamsGetFilterByInertia", "ptr", $obj), "cveSimpleBlobDetectorParamsGetFilterByInertia", @error)
EndFunc   ;==>_cveSimpleBlobDetectorParamsGetFilterByInertia

Func _cveSimpleBlobDetectorParamsSetFilterByInertia(ByRef $obj, $value)
    ; CVAPI(void) cveSimpleBlobDetectorParamsSetFilterByInertia(cv::SimpleBlobDetector::Params* obj, bool value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSimpleBlobDetectorParamsSetFilterByInertia", "ptr", $obj, "boolean", $value), "cveSimpleBlobDetectorParamsSetFilterByInertia", @error)
EndFunc   ;==>_cveSimpleBlobDetectorParamsSetFilterByInertia

Func _cveSimpleBlobDetectorParamsGetMinInertiaRatio(ByRef $obj)
    ; CVAPI(float) cveSimpleBlobDetectorParamsGetMinInertiaRatio(cv::SimpleBlobDetector::Params* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cveSimpleBlobDetectorParamsGetMinInertiaRatio", "ptr", $obj), "cveSimpleBlobDetectorParamsGetMinInertiaRatio", @error)
EndFunc   ;==>_cveSimpleBlobDetectorParamsGetMinInertiaRatio

Func _cveSimpleBlobDetectorParamsSetMinInertiaRatio(ByRef $obj, $value)
    ; CVAPI(void) cveSimpleBlobDetectorParamsSetMinInertiaRatio(cv::SimpleBlobDetector::Params* obj, float value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSimpleBlobDetectorParamsSetMinInertiaRatio", "ptr", $obj, "float", $value), "cveSimpleBlobDetectorParamsSetMinInertiaRatio", @error)
EndFunc   ;==>_cveSimpleBlobDetectorParamsSetMinInertiaRatio

Func _cveSimpleBlobDetectorParamsGetMaxInertiaRatio(ByRef $obj)
    ; CVAPI(float) cveSimpleBlobDetectorParamsGetMaxInertiaRatio(cv::SimpleBlobDetector::Params* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cveSimpleBlobDetectorParamsGetMaxInertiaRatio", "ptr", $obj), "cveSimpleBlobDetectorParamsGetMaxInertiaRatio", @error)
EndFunc   ;==>_cveSimpleBlobDetectorParamsGetMaxInertiaRatio

Func _cveSimpleBlobDetectorParamsSetMaxInertiaRatio(ByRef $obj, $value)
    ; CVAPI(void) cveSimpleBlobDetectorParamsSetMaxInertiaRatio(cv::SimpleBlobDetector::Params* obj, float value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSimpleBlobDetectorParamsSetMaxInertiaRatio", "ptr", $obj, "float", $value), "cveSimpleBlobDetectorParamsSetMaxInertiaRatio", @error)
EndFunc   ;==>_cveSimpleBlobDetectorParamsSetMaxInertiaRatio

Func _cveSimpleBlobDetectorParamsGetFilterByConvexity(ByRef $obj)
    ; CVAPI(bool) cveSimpleBlobDetectorParamsGetFilterByConvexity(cv::SimpleBlobDetector::Params* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveSimpleBlobDetectorParamsGetFilterByConvexity", "ptr", $obj), "cveSimpleBlobDetectorParamsGetFilterByConvexity", @error)
EndFunc   ;==>_cveSimpleBlobDetectorParamsGetFilterByConvexity

Func _cveSimpleBlobDetectorParamsSetFilterByConvexity(ByRef $obj, $value)
    ; CVAPI(void) cveSimpleBlobDetectorParamsSetFilterByConvexity(cv::SimpleBlobDetector::Params* obj, bool value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSimpleBlobDetectorParamsSetFilterByConvexity", "ptr", $obj, "boolean", $value), "cveSimpleBlobDetectorParamsSetFilterByConvexity", @error)
EndFunc   ;==>_cveSimpleBlobDetectorParamsSetFilterByConvexity

Func _cveSimpleBlobDetectorParamsGetMinConvexity(ByRef $obj)
    ; CVAPI(float) cveSimpleBlobDetectorParamsGetMinConvexity(cv::SimpleBlobDetector::Params* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cveSimpleBlobDetectorParamsGetMinConvexity", "ptr", $obj), "cveSimpleBlobDetectorParamsGetMinConvexity", @error)
EndFunc   ;==>_cveSimpleBlobDetectorParamsGetMinConvexity

Func _cveSimpleBlobDetectorParamsSetMinConvexity(ByRef $obj, $value)
    ; CVAPI(void) cveSimpleBlobDetectorParamsSetMinConvexity(cv::SimpleBlobDetector::Params* obj, float value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSimpleBlobDetectorParamsSetMinConvexity", "ptr", $obj, "float", $value), "cveSimpleBlobDetectorParamsSetMinConvexity", @error)
EndFunc   ;==>_cveSimpleBlobDetectorParamsSetMinConvexity

Func _cveSimpleBlobDetectorParamsGetMaxConvexity(ByRef $obj)
    ; CVAPI(float) cveSimpleBlobDetectorParamsGetMaxConvexity(cv::SimpleBlobDetector::Params* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cveSimpleBlobDetectorParamsGetMaxConvexity", "ptr", $obj), "cveSimpleBlobDetectorParamsGetMaxConvexity", @error)
EndFunc   ;==>_cveSimpleBlobDetectorParamsGetMaxConvexity

Func _cveSimpleBlobDetectorParamsSetMaxConvexity(ByRef $obj, $value)
    ; CVAPI(void) cveSimpleBlobDetectorParamsSetMaxConvexity(cv::SimpleBlobDetector::Params* obj, float value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSimpleBlobDetectorParamsSetMaxConvexity", "ptr", $obj, "float", $value), "cveSimpleBlobDetectorParamsSetMaxConvexity", @error)
EndFunc   ;==>_cveSimpleBlobDetectorParamsSetMaxConvexity

Func _cveSimpleBlobDetectorParamsGetMinRepeatability(ByRef $obj)
    ; CVAPI(size_t) cveSimpleBlobDetectorParamsGetMinRepeatability(cv::SimpleBlobDetector::Params* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ulong_ptr:cdecl", "cveSimpleBlobDetectorParamsGetMinRepeatability", "ptr", $obj), "cveSimpleBlobDetectorParamsGetMinRepeatability", @error)
EndFunc   ;==>_cveSimpleBlobDetectorParamsGetMinRepeatability

Func _cveSimpleBlobDetectorParamsSetMinRepeatability(ByRef $obj, $value)
    ; CVAPI(void) cveSimpleBlobDetectorParamsSetMinRepeatability(cv::SimpleBlobDetector::Params* obj, size_t value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSimpleBlobDetectorParamsSetMinRepeatability", "ptr", $obj, "ulong_ptr", $value), "cveSimpleBlobDetectorParamsSetMinRepeatability", @error)
EndFunc   ;==>_cveSimpleBlobDetectorParamsSetMinRepeatability