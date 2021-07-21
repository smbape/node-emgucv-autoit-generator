#include-once
#include "..\..\CVEUtils.au3"

Func _cveNetSetPreferableBackend($obj, $value)
    ; CVAPI(void) cveNetSetPreferableBackend(cv::dnn::Net* obj, int value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveNetSetPreferableBackend", $bObjDllType, $obj, "int", $value), "cveNetSetPreferableBackend", @error)
EndFunc   ;==>_cveNetSetPreferableBackend

Func _cveNetSetPreferableTarget($obj, $value)
    ; CVAPI(void) cveNetSetPreferableTarget(cv::dnn::Net* obj, int value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveNetSetPreferableTarget", $bObjDllType, $obj, "int", $value), "cveNetSetPreferableTarget", @error)
EndFunc   ;==>_cveNetSetPreferableTarget

Func _cveNetEnableFusion($obj, $value)
    ; CVAPI(void) cveNetEnableFusion(cv::dnn::Net* obj, bool value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveNetEnableFusion", $bObjDllType, $obj, "boolean", $value), "cveNetEnableFusion", @error)
EndFunc   ;==>_cveNetEnableFusion

Func _cveNetEmpty($obj)
    ; CVAPI(bool) cveNetEmpty(cv::dnn::Net* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveNetEmpty", $bObjDllType, $obj), "cveNetEmpty", @error)
EndFunc   ;==>_cveNetEmpty

Func _cveNetSetHalideScheduler($obj, $str)
    ; CVAPI(void) cveNetSetHalideScheduler(cv::dnn::Net* obj, cv::String* str);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    Local $bStrIsString = VarGetType($str) == "String"
    If $bStrIsString Then
        $str = _cveStringCreateFromStr($str)
    EndIf

    Local $bStrDllType
    If VarGetType($str) == "DLLStruct" Then
        $bStrDllType = "struct*"
    Else
        $bStrDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveNetSetHalideScheduler", $bObjDllType, $obj, $bStrDllType, $str), "cveNetSetHalideScheduler", @error)

    If $bStrIsString Then
        _cveStringRelease($str)
    EndIf
EndFunc   ;==>_cveNetSetHalideScheduler