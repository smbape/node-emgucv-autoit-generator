#include-once
#include "..\..\CVEUtils.au3"

Func _cveMSERGetPass2Only($obj)
    ; CVAPI(bool) cveMSERGetPass2Only(cv::MSER* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveMSERGetPass2Only", $bObjDllType, $obj), "cveMSERGetPass2Only", @error)
EndFunc   ;==>_cveMSERGetPass2Only

Func _cveMSERSetPass2Only($obj, $value)
    ; CVAPI(void) cveMSERSetPass2Only(cv::MSER* obj, bool value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMSERSetPass2Only", $bObjDllType, $obj, "boolean", $value), "cveMSERSetPass2Only", @error)
EndFunc   ;==>_cveMSERSetPass2Only

Func _cveMSERGetDelta($obj)
    ; CVAPI(int) cveMSERGetDelta(cv::MSER* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveMSERGetDelta", $bObjDllType, $obj), "cveMSERGetDelta", @error)
EndFunc   ;==>_cveMSERGetDelta

Func _cveMSERSetDelta($obj, $value)
    ; CVAPI(void) cveMSERSetDelta(cv::MSER* obj, int value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMSERSetDelta", $bObjDllType, $obj, "int", $value), "cveMSERSetDelta", @error)
EndFunc   ;==>_cveMSERSetDelta

Func _cveMSERGetMinArea($obj)
    ; CVAPI(int) cveMSERGetMinArea(cv::MSER* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveMSERGetMinArea", $bObjDllType, $obj), "cveMSERGetMinArea", @error)
EndFunc   ;==>_cveMSERGetMinArea

Func _cveMSERSetMinArea($obj, $value)
    ; CVAPI(void) cveMSERSetMinArea(cv::MSER* obj, int value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMSERSetMinArea", $bObjDllType, $obj, "int", $value), "cveMSERSetMinArea", @error)
EndFunc   ;==>_cveMSERSetMinArea

Func _cveMSERGetMaxArea($obj)
    ; CVAPI(int) cveMSERGetMaxArea(cv::MSER* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveMSERGetMaxArea", $bObjDllType, $obj), "cveMSERGetMaxArea", @error)
EndFunc   ;==>_cveMSERGetMaxArea

Func _cveMSERSetMaxArea($obj, $value)
    ; CVAPI(void) cveMSERSetMaxArea(cv::MSER* obj, int value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMSERSetMaxArea", $bObjDllType, $obj, "int", $value), "cveMSERSetMaxArea", @error)
EndFunc   ;==>_cveMSERSetMaxArea