#include-once
#include "..\..\CVEUtils.au3"

Func _cveNetSetPreferableBackend(ByRef $obj, $value)
    ; CVAPI(void) cveNetSetPreferableBackend(cv::dnn::Net* obj, int value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveNetSetPreferableBackend", "ptr", $obj, "int", $value), "cveNetSetPreferableBackend", @error)
EndFunc   ;==>_cveNetSetPreferableBackend

Func _cveNetSetPreferableTarget(ByRef $obj, $value)
    ; CVAPI(void) cveNetSetPreferableTarget(cv::dnn::Net* obj, int value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveNetSetPreferableTarget", "ptr", $obj, "int", $value), "cveNetSetPreferableTarget", @error)
EndFunc   ;==>_cveNetSetPreferableTarget

Func _cveNetEnableFusion(ByRef $obj, $value)
    ; CVAPI(void) cveNetEnableFusion(cv::dnn::Net* obj, bool value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveNetEnableFusion", "ptr", $obj, "boolean", $value), "cveNetEnableFusion", @error)
EndFunc   ;==>_cveNetEnableFusion

Func _cveNetEmpty(ByRef $obj)
    ; CVAPI(bool) cveNetEmpty(cv::dnn::Net* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveNetEmpty", "ptr", $obj), "cveNetEmpty", @error)
EndFunc   ;==>_cveNetEmpty

Func _cveNetSetHalideScheduler(ByRef $obj, $str)
    ; CVAPI(void) cveNetSetHalideScheduler(cv::dnn::Net* obj, cv::String* str);

    Local $bStrIsString = VarGetType($str) == "String"
    If $bStrIsString Then
        $str = _cveStringCreateFromStr($str)
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveNetSetHalideScheduler", "ptr", $obj, "ptr", $str), "cveNetSetHalideScheduler", @error)

    If $bStrIsString Then
        _cveStringRelease($str)
    EndIf
EndFunc   ;==>_cveNetSetHalideScheduler