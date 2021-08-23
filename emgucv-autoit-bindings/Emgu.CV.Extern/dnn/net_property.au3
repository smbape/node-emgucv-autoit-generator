#include-once
#include "..\..\CVEUtils.au3"

Func _cveNetSetPreferableBackend($obj, $value)
    ; CVAPI(void) cveNetSetPreferableBackend(cv::dnn::Net* obj, int value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveNetSetPreferableBackend", $sObjDllType, $obj, "int", $value), "cveNetSetPreferableBackend", @error)
EndFunc   ;==>_cveNetSetPreferableBackend

Func _cveNetSetPreferableTarget($obj, $value)
    ; CVAPI(void) cveNetSetPreferableTarget(cv::dnn::Net* obj, int value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveNetSetPreferableTarget", $sObjDllType, $obj, "int", $value), "cveNetSetPreferableTarget", @error)
EndFunc   ;==>_cveNetSetPreferableTarget

Func _cveNetEnableFusion($obj, $value)
    ; CVAPI(void) cveNetEnableFusion(cv::dnn::Net* obj, bool value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveNetEnableFusion", $sObjDllType, $obj, "boolean", $value), "cveNetEnableFusion", @error)
EndFunc   ;==>_cveNetEnableFusion

Func _cveNetEmpty($obj)
    ; CVAPI(bool) cveNetEmpty(cv::dnn::Net* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveNetEmpty", $sObjDllType, $obj), "cveNetEmpty", @error)
EndFunc   ;==>_cveNetEmpty

Func _cveNetSetHalideScheduler($obj, $str)
    ; CVAPI(void) cveNetSetHalideScheduler(cv::dnn::Net* obj, cv::String* str);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    Local $bStrIsString = VarGetType($str) == "String"
    If $bStrIsString Then
        $str = _cveStringCreateFromStr($str)
    EndIf

    Local $sStrDllType
    If IsDllStruct($str) Then
        $sStrDllType = "struct*"
    Else
        $sStrDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveNetSetHalideScheduler", $sObjDllType, $obj, $sStrDllType, $str), "cveNetSetHalideScheduler", @error)

    If $bStrIsString Then
        _cveStringRelease($str)
    EndIf
EndFunc   ;==>_cveNetSetHalideScheduler