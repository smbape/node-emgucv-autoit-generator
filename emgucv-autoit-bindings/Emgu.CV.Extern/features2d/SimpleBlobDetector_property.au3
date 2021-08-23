#include-once
#include "..\..\CVEUtils.au3"

Func _cveSimpleBlobDetectorParamsGetThresholdStep($obj)
    ; CVAPI(float) cveSimpleBlobDetectorParamsGetThresholdStep(cv::SimpleBlobDetector::Params* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cveSimpleBlobDetectorParamsGetThresholdStep", $sObjDllType, $obj), "cveSimpleBlobDetectorParamsGetThresholdStep", @error)
EndFunc   ;==>_cveSimpleBlobDetectorParamsGetThresholdStep

Func _cveSimpleBlobDetectorParamsSetThresholdStep($obj, $value)
    ; CVAPI(void) cveSimpleBlobDetectorParamsSetThresholdStep(cv::SimpleBlobDetector::Params* obj, float value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSimpleBlobDetectorParamsSetThresholdStep", $sObjDllType, $obj, "float", $value), "cveSimpleBlobDetectorParamsSetThresholdStep", @error)
EndFunc   ;==>_cveSimpleBlobDetectorParamsSetThresholdStep

Func _cveSimpleBlobDetectorParamsGetMinThreshold($obj)
    ; CVAPI(float) cveSimpleBlobDetectorParamsGetMinThreshold(cv::SimpleBlobDetector::Params* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cveSimpleBlobDetectorParamsGetMinThreshold", $sObjDllType, $obj), "cveSimpleBlobDetectorParamsGetMinThreshold", @error)
EndFunc   ;==>_cveSimpleBlobDetectorParamsGetMinThreshold

Func _cveSimpleBlobDetectorParamsSetMinThreshold($obj, $value)
    ; CVAPI(void) cveSimpleBlobDetectorParamsSetMinThreshold(cv::SimpleBlobDetector::Params* obj, float value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSimpleBlobDetectorParamsSetMinThreshold", $sObjDllType, $obj, "float", $value), "cveSimpleBlobDetectorParamsSetMinThreshold", @error)
EndFunc   ;==>_cveSimpleBlobDetectorParamsSetMinThreshold

Func _cveSimpleBlobDetectorParamsGetMaxThreshold($obj)
    ; CVAPI(float) cveSimpleBlobDetectorParamsGetMaxThreshold(cv::SimpleBlobDetector::Params* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cveSimpleBlobDetectorParamsGetMaxThreshold", $sObjDllType, $obj), "cveSimpleBlobDetectorParamsGetMaxThreshold", @error)
EndFunc   ;==>_cveSimpleBlobDetectorParamsGetMaxThreshold

Func _cveSimpleBlobDetectorParamsSetMaxThreshold($obj, $value)
    ; CVAPI(void) cveSimpleBlobDetectorParamsSetMaxThreshold(cv::SimpleBlobDetector::Params* obj, float value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSimpleBlobDetectorParamsSetMaxThreshold", $sObjDllType, $obj, "float", $value), "cveSimpleBlobDetectorParamsSetMaxThreshold", @error)
EndFunc   ;==>_cveSimpleBlobDetectorParamsSetMaxThreshold

Func _cveSimpleBlobDetectorParamsGetMinDistBetweenBlobs($obj)
    ; CVAPI(float) cveSimpleBlobDetectorParamsGetMinDistBetweenBlobs(cv::SimpleBlobDetector::Params* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cveSimpleBlobDetectorParamsGetMinDistBetweenBlobs", $sObjDllType, $obj), "cveSimpleBlobDetectorParamsGetMinDistBetweenBlobs", @error)
EndFunc   ;==>_cveSimpleBlobDetectorParamsGetMinDistBetweenBlobs

Func _cveSimpleBlobDetectorParamsSetMinDistBetweenBlobs($obj, $value)
    ; CVAPI(void) cveSimpleBlobDetectorParamsSetMinDistBetweenBlobs(cv::SimpleBlobDetector::Params* obj, float value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSimpleBlobDetectorParamsSetMinDistBetweenBlobs", $sObjDllType, $obj, "float", $value), "cveSimpleBlobDetectorParamsSetMinDistBetweenBlobs", @error)
EndFunc   ;==>_cveSimpleBlobDetectorParamsSetMinDistBetweenBlobs

Func _cveSimpleBlobDetectorParamsGetFilterByColor($obj)
    ; CVAPI(bool) cveSimpleBlobDetectorParamsGetFilterByColor(cv::SimpleBlobDetector::Params* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveSimpleBlobDetectorParamsGetFilterByColor", $sObjDllType, $obj), "cveSimpleBlobDetectorParamsGetFilterByColor", @error)
EndFunc   ;==>_cveSimpleBlobDetectorParamsGetFilterByColor

Func _cveSimpleBlobDetectorParamsSetFilterByColor($obj, $value)
    ; CVAPI(void) cveSimpleBlobDetectorParamsSetFilterByColor(cv::SimpleBlobDetector::Params* obj, bool value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSimpleBlobDetectorParamsSetFilterByColor", $sObjDllType, $obj, "boolean", $value), "cveSimpleBlobDetectorParamsSetFilterByColor", @error)
EndFunc   ;==>_cveSimpleBlobDetectorParamsSetFilterByColor

Func _cveSimpleBlobDetectorParamsGetblobColor($obj)
    ; CVAPI(uchar) cveSimpleBlobDetectorParamsGetblobColor(cv::SimpleBlobDetector::Params* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "byte:cdecl", "cveSimpleBlobDetectorParamsGetblobColor", $sObjDllType, $obj), "cveSimpleBlobDetectorParamsGetblobColor", @error)
EndFunc   ;==>_cveSimpleBlobDetectorParamsGetblobColor

Func _cveSimpleBlobDetectorParamsSetblobColor($obj, $value)
    ; CVAPI(void) cveSimpleBlobDetectorParamsSetblobColor(cv::SimpleBlobDetector::Params* obj, uchar value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSimpleBlobDetectorParamsSetblobColor", $sObjDllType, $obj, "byte", $value), "cveSimpleBlobDetectorParamsSetblobColor", @error)
EndFunc   ;==>_cveSimpleBlobDetectorParamsSetblobColor

Func _cveSimpleBlobDetectorParamsGetFilterByArea($obj)
    ; CVAPI(bool) cveSimpleBlobDetectorParamsGetFilterByArea(cv::SimpleBlobDetector::Params* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveSimpleBlobDetectorParamsGetFilterByArea", $sObjDllType, $obj), "cveSimpleBlobDetectorParamsGetFilterByArea", @error)
EndFunc   ;==>_cveSimpleBlobDetectorParamsGetFilterByArea

Func _cveSimpleBlobDetectorParamsSetFilterByArea($obj, $value)
    ; CVAPI(void) cveSimpleBlobDetectorParamsSetFilterByArea(cv::SimpleBlobDetector::Params* obj, bool value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSimpleBlobDetectorParamsSetFilterByArea", $sObjDllType, $obj, "boolean", $value), "cveSimpleBlobDetectorParamsSetFilterByArea", @error)
EndFunc   ;==>_cveSimpleBlobDetectorParamsSetFilterByArea

Func _cveSimpleBlobDetectorParamsGetMinArea($obj)
    ; CVAPI(float) cveSimpleBlobDetectorParamsGetMinArea(cv::SimpleBlobDetector::Params* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cveSimpleBlobDetectorParamsGetMinArea", $sObjDllType, $obj), "cveSimpleBlobDetectorParamsGetMinArea", @error)
EndFunc   ;==>_cveSimpleBlobDetectorParamsGetMinArea

Func _cveSimpleBlobDetectorParamsSetMinArea($obj, $value)
    ; CVAPI(void) cveSimpleBlobDetectorParamsSetMinArea(cv::SimpleBlobDetector::Params* obj, float value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSimpleBlobDetectorParamsSetMinArea", $sObjDllType, $obj, "float", $value), "cveSimpleBlobDetectorParamsSetMinArea", @error)
EndFunc   ;==>_cveSimpleBlobDetectorParamsSetMinArea

Func _cveSimpleBlobDetectorParamsGetMaxArea($obj)
    ; CVAPI(float) cveSimpleBlobDetectorParamsGetMaxArea(cv::SimpleBlobDetector::Params* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cveSimpleBlobDetectorParamsGetMaxArea", $sObjDllType, $obj), "cveSimpleBlobDetectorParamsGetMaxArea", @error)
EndFunc   ;==>_cveSimpleBlobDetectorParamsGetMaxArea

Func _cveSimpleBlobDetectorParamsSetMaxArea($obj, $value)
    ; CVAPI(void) cveSimpleBlobDetectorParamsSetMaxArea(cv::SimpleBlobDetector::Params* obj, float value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSimpleBlobDetectorParamsSetMaxArea", $sObjDllType, $obj, "float", $value), "cveSimpleBlobDetectorParamsSetMaxArea", @error)
EndFunc   ;==>_cveSimpleBlobDetectorParamsSetMaxArea

Func _cveSimpleBlobDetectorParamsGetFilterByCircularity($obj)
    ; CVAPI(bool) cveSimpleBlobDetectorParamsGetFilterByCircularity(cv::SimpleBlobDetector::Params* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveSimpleBlobDetectorParamsGetFilterByCircularity", $sObjDllType, $obj), "cveSimpleBlobDetectorParamsGetFilterByCircularity", @error)
EndFunc   ;==>_cveSimpleBlobDetectorParamsGetFilterByCircularity

Func _cveSimpleBlobDetectorParamsSetFilterByCircularity($obj, $value)
    ; CVAPI(void) cveSimpleBlobDetectorParamsSetFilterByCircularity(cv::SimpleBlobDetector::Params* obj, bool value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSimpleBlobDetectorParamsSetFilterByCircularity", $sObjDllType, $obj, "boolean", $value), "cveSimpleBlobDetectorParamsSetFilterByCircularity", @error)
EndFunc   ;==>_cveSimpleBlobDetectorParamsSetFilterByCircularity

Func _cveSimpleBlobDetectorParamsGetMinCircularity($obj)
    ; CVAPI(float) cveSimpleBlobDetectorParamsGetMinCircularity(cv::SimpleBlobDetector::Params* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cveSimpleBlobDetectorParamsGetMinCircularity", $sObjDllType, $obj), "cveSimpleBlobDetectorParamsGetMinCircularity", @error)
EndFunc   ;==>_cveSimpleBlobDetectorParamsGetMinCircularity

Func _cveSimpleBlobDetectorParamsSetMinCircularity($obj, $value)
    ; CVAPI(void) cveSimpleBlobDetectorParamsSetMinCircularity(cv::SimpleBlobDetector::Params* obj, float value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSimpleBlobDetectorParamsSetMinCircularity", $sObjDllType, $obj, "float", $value), "cveSimpleBlobDetectorParamsSetMinCircularity", @error)
EndFunc   ;==>_cveSimpleBlobDetectorParamsSetMinCircularity

Func _cveSimpleBlobDetectorParamsGetMaxCircularity($obj)
    ; CVAPI(float) cveSimpleBlobDetectorParamsGetMaxCircularity(cv::SimpleBlobDetector::Params* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cveSimpleBlobDetectorParamsGetMaxCircularity", $sObjDllType, $obj), "cveSimpleBlobDetectorParamsGetMaxCircularity", @error)
EndFunc   ;==>_cveSimpleBlobDetectorParamsGetMaxCircularity

Func _cveSimpleBlobDetectorParamsSetMaxCircularity($obj, $value)
    ; CVAPI(void) cveSimpleBlobDetectorParamsSetMaxCircularity(cv::SimpleBlobDetector::Params* obj, float value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSimpleBlobDetectorParamsSetMaxCircularity", $sObjDllType, $obj, "float", $value), "cveSimpleBlobDetectorParamsSetMaxCircularity", @error)
EndFunc   ;==>_cveSimpleBlobDetectorParamsSetMaxCircularity

Func _cveSimpleBlobDetectorParamsGetFilterByInertia($obj)
    ; CVAPI(bool) cveSimpleBlobDetectorParamsGetFilterByInertia(cv::SimpleBlobDetector::Params* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveSimpleBlobDetectorParamsGetFilterByInertia", $sObjDllType, $obj), "cveSimpleBlobDetectorParamsGetFilterByInertia", @error)
EndFunc   ;==>_cveSimpleBlobDetectorParamsGetFilterByInertia

Func _cveSimpleBlobDetectorParamsSetFilterByInertia($obj, $value)
    ; CVAPI(void) cveSimpleBlobDetectorParamsSetFilterByInertia(cv::SimpleBlobDetector::Params* obj, bool value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSimpleBlobDetectorParamsSetFilterByInertia", $sObjDllType, $obj, "boolean", $value), "cveSimpleBlobDetectorParamsSetFilterByInertia", @error)
EndFunc   ;==>_cveSimpleBlobDetectorParamsSetFilterByInertia

Func _cveSimpleBlobDetectorParamsGetMinInertiaRatio($obj)
    ; CVAPI(float) cveSimpleBlobDetectorParamsGetMinInertiaRatio(cv::SimpleBlobDetector::Params* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cveSimpleBlobDetectorParamsGetMinInertiaRatio", $sObjDllType, $obj), "cveSimpleBlobDetectorParamsGetMinInertiaRatio", @error)
EndFunc   ;==>_cveSimpleBlobDetectorParamsGetMinInertiaRatio

Func _cveSimpleBlobDetectorParamsSetMinInertiaRatio($obj, $value)
    ; CVAPI(void) cveSimpleBlobDetectorParamsSetMinInertiaRatio(cv::SimpleBlobDetector::Params* obj, float value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSimpleBlobDetectorParamsSetMinInertiaRatio", $sObjDllType, $obj, "float", $value), "cveSimpleBlobDetectorParamsSetMinInertiaRatio", @error)
EndFunc   ;==>_cveSimpleBlobDetectorParamsSetMinInertiaRatio

Func _cveSimpleBlobDetectorParamsGetMaxInertiaRatio($obj)
    ; CVAPI(float) cveSimpleBlobDetectorParamsGetMaxInertiaRatio(cv::SimpleBlobDetector::Params* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cveSimpleBlobDetectorParamsGetMaxInertiaRatio", $sObjDllType, $obj), "cveSimpleBlobDetectorParamsGetMaxInertiaRatio", @error)
EndFunc   ;==>_cveSimpleBlobDetectorParamsGetMaxInertiaRatio

Func _cveSimpleBlobDetectorParamsSetMaxInertiaRatio($obj, $value)
    ; CVAPI(void) cveSimpleBlobDetectorParamsSetMaxInertiaRatio(cv::SimpleBlobDetector::Params* obj, float value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSimpleBlobDetectorParamsSetMaxInertiaRatio", $sObjDllType, $obj, "float", $value), "cveSimpleBlobDetectorParamsSetMaxInertiaRatio", @error)
EndFunc   ;==>_cveSimpleBlobDetectorParamsSetMaxInertiaRatio

Func _cveSimpleBlobDetectorParamsGetFilterByConvexity($obj)
    ; CVAPI(bool) cveSimpleBlobDetectorParamsGetFilterByConvexity(cv::SimpleBlobDetector::Params* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveSimpleBlobDetectorParamsGetFilterByConvexity", $sObjDllType, $obj), "cveSimpleBlobDetectorParamsGetFilterByConvexity", @error)
EndFunc   ;==>_cveSimpleBlobDetectorParamsGetFilterByConvexity

Func _cveSimpleBlobDetectorParamsSetFilterByConvexity($obj, $value)
    ; CVAPI(void) cveSimpleBlobDetectorParamsSetFilterByConvexity(cv::SimpleBlobDetector::Params* obj, bool value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSimpleBlobDetectorParamsSetFilterByConvexity", $sObjDllType, $obj, "boolean", $value), "cveSimpleBlobDetectorParamsSetFilterByConvexity", @error)
EndFunc   ;==>_cveSimpleBlobDetectorParamsSetFilterByConvexity

Func _cveSimpleBlobDetectorParamsGetMinConvexity($obj)
    ; CVAPI(float) cveSimpleBlobDetectorParamsGetMinConvexity(cv::SimpleBlobDetector::Params* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cveSimpleBlobDetectorParamsGetMinConvexity", $sObjDllType, $obj), "cveSimpleBlobDetectorParamsGetMinConvexity", @error)
EndFunc   ;==>_cveSimpleBlobDetectorParamsGetMinConvexity

Func _cveSimpleBlobDetectorParamsSetMinConvexity($obj, $value)
    ; CVAPI(void) cveSimpleBlobDetectorParamsSetMinConvexity(cv::SimpleBlobDetector::Params* obj, float value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSimpleBlobDetectorParamsSetMinConvexity", $sObjDllType, $obj, "float", $value), "cveSimpleBlobDetectorParamsSetMinConvexity", @error)
EndFunc   ;==>_cveSimpleBlobDetectorParamsSetMinConvexity

Func _cveSimpleBlobDetectorParamsGetMaxConvexity($obj)
    ; CVAPI(float) cveSimpleBlobDetectorParamsGetMaxConvexity(cv::SimpleBlobDetector::Params* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cveSimpleBlobDetectorParamsGetMaxConvexity", $sObjDllType, $obj), "cveSimpleBlobDetectorParamsGetMaxConvexity", @error)
EndFunc   ;==>_cveSimpleBlobDetectorParamsGetMaxConvexity

Func _cveSimpleBlobDetectorParamsSetMaxConvexity($obj, $value)
    ; CVAPI(void) cveSimpleBlobDetectorParamsSetMaxConvexity(cv::SimpleBlobDetector::Params* obj, float value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSimpleBlobDetectorParamsSetMaxConvexity", $sObjDllType, $obj, "float", $value), "cveSimpleBlobDetectorParamsSetMaxConvexity", @error)
EndFunc   ;==>_cveSimpleBlobDetectorParamsSetMaxConvexity

Func _cveSimpleBlobDetectorParamsGetMinRepeatability($obj)
    ; CVAPI(size_t) cveSimpleBlobDetectorParamsGetMinRepeatability(cv::SimpleBlobDetector::Params* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ulong_ptr:cdecl", "cveSimpleBlobDetectorParamsGetMinRepeatability", $sObjDllType, $obj), "cveSimpleBlobDetectorParamsGetMinRepeatability", @error)
EndFunc   ;==>_cveSimpleBlobDetectorParamsGetMinRepeatability

Func _cveSimpleBlobDetectorParamsSetMinRepeatability($obj, $value)
    ; CVAPI(void) cveSimpleBlobDetectorParamsSetMinRepeatability(cv::SimpleBlobDetector::Params* obj, size_t value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSimpleBlobDetectorParamsSetMinRepeatability", $sObjDllType, $obj, "ulong_ptr", $value), "cveSimpleBlobDetectorParamsSetMinRepeatability", @error)
EndFunc   ;==>_cveSimpleBlobDetectorParamsSetMinRepeatability