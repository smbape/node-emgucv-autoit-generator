#include-once
#include "..\..\CVEUtils.au3"

Func _cveCudaCascadeClassifierGetScaleFactor($obj)
    ; CVAPI(double) cveCudaCascadeClassifierGetScaleFactor(void* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveCudaCascadeClassifierGetScaleFactor", $bObjDllType, $obj), "cveCudaCascadeClassifierGetScaleFactor", @error)
EndFunc   ;==>_cveCudaCascadeClassifierGetScaleFactor

Func _cveCudaCascadeClassifierSetScaleFactor($obj, $value)
    ; CVAPI(void) cveCudaCascadeClassifierSetScaleFactor(void* obj, double value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCudaCascadeClassifierSetScaleFactor", $bObjDllType, $obj, "double", $value), "cveCudaCascadeClassifierSetScaleFactor", @error)
EndFunc   ;==>_cveCudaCascadeClassifierSetScaleFactor

Func _cveCudaCascadeClassifierGetMinNeighbors($obj)
    ; CVAPI(int) cveCudaCascadeClassifierGetMinNeighbors(void* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveCudaCascadeClassifierGetMinNeighbors", $bObjDllType, $obj), "cveCudaCascadeClassifierGetMinNeighbors", @error)
EndFunc   ;==>_cveCudaCascadeClassifierGetMinNeighbors

Func _cveCudaCascadeClassifierSetMinNeighbors($obj, $value)
    ; CVAPI(void) cveCudaCascadeClassifierSetMinNeighbors(void* obj, int value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCudaCascadeClassifierSetMinNeighbors", $bObjDllType, $obj, "int", $value), "cveCudaCascadeClassifierSetMinNeighbors", @error)
EndFunc   ;==>_cveCudaCascadeClassifierSetMinNeighbors

Func _cveCudaCascadeClassifierGetMaxNumObjects($obj)
    ; CVAPI(int) cveCudaCascadeClassifierGetMaxNumObjects(void* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveCudaCascadeClassifierGetMaxNumObjects", $bObjDllType, $obj), "cveCudaCascadeClassifierGetMaxNumObjects", @error)
EndFunc   ;==>_cveCudaCascadeClassifierGetMaxNumObjects

Func _cveCudaCascadeClassifierSetMaxNumObjects($obj, $value)
    ; CVAPI(void) cveCudaCascadeClassifierSetMaxNumObjects(void* obj, int value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCudaCascadeClassifierSetMaxNumObjects", $bObjDllType, $obj, "int", $value), "cveCudaCascadeClassifierSetMaxNumObjects", @error)
EndFunc   ;==>_cveCudaCascadeClassifierSetMaxNumObjects

Func _cveCudaCascadeClassifierGetFindLargestObject($obj)
    ; CVAPI(bool) cveCudaCascadeClassifierGetFindLargestObject(void* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveCudaCascadeClassifierGetFindLargestObject", $bObjDllType, $obj), "cveCudaCascadeClassifierGetFindLargestObject", @error)
EndFunc   ;==>_cveCudaCascadeClassifierGetFindLargestObject

Func _cveCudaCascadeClassifierSetFindLargestObject($obj, $value)
    ; CVAPI(void) cveCudaCascadeClassifierSetFindLargestObject(void* obj, bool value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCudaCascadeClassifierSetFindLargestObject", $bObjDllType, $obj, "boolean", $value), "cveCudaCascadeClassifierSetFindLargestObject", @error)
EndFunc   ;==>_cveCudaCascadeClassifierSetFindLargestObject

Func _cveCudaCascadeClassifierGetMaxObjectSize($obj, $value)
    ; CVAPI(void) cveCudaCascadeClassifierGetMaxObjectSize(void* obj, CvSize* value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    Local $bValueDllType
    If VarGetType($value) == "DLLStruct" Then
        $bValueDllType = "struct*"
    Else
        $bValueDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCudaCascadeClassifierGetMaxObjectSize", $bObjDllType, $obj, $bValueDllType, $value), "cveCudaCascadeClassifierGetMaxObjectSize", @error)
EndFunc   ;==>_cveCudaCascadeClassifierGetMaxObjectSize

Func _cveCudaCascadeClassifierSetMaxObjectSize($obj, $value)
    ; CVAPI(void) cveCudaCascadeClassifierSetMaxObjectSize(void* obj, CvSize* value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    Local $bValueDllType
    If VarGetType($value) == "DLLStruct" Then
        $bValueDllType = "struct*"
    Else
        $bValueDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCudaCascadeClassifierSetMaxObjectSize", $bObjDllType, $obj, $bValueDllType, $value), "cveCudaCascadeClassifierSetMaxObjectSize", @error)
EndFunc   ;==>_cveCudaCascadeClassifierSetMaxObjectSize

Func _cveCudaCascadeClassifierGetMinObjectSize($obj, $value)
    ; CVAPI(void) cveCudaCascadeClassifierGetMinObjectSize(void* obj, CvSize* value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    Local $bValueDllType
    If VarGetType($value) == "DLLStruct" Then
        $bValueDllType = "struct*"
    Else
        $bValueDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCudaCascadeClassifierGetMinObjectSize", $bObjDllType, $obj, $bValueDllType, $value), "cveCudaCascadeClassifierGetMinObjectSize", @error)
EndFunc   ;==>_cveCudaCascadeClassifierGetMinObjectSize

Func _cveCudaCascadeClassifierSetMinObjectSize($obj, $value)
    ; CVAPI(void) cveCudaCascadeClassifierSetMinObjectSize(void* obj, CvSize* value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    Local $bValueDllType
    If VarGetType($value) == "DLLStruct" Then
        $bValueDllType = "struct*"
    Else
        $bValueDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCudaCascadeClassifierSetMinObjectSize", $bObjDllType, $obj, $bValueDllType, $value), "cveCudaCascadeClassifierSetMinObjectSize", @error)
EndFunc   ;==>_cveCudaCascadeClassifierSetMinObjectSize

Func _cveCudaCascadeClassifierGetClassifierSize($obj, $value)
    ; CVAPI(void) cveCudaCascadeClassifierGetClassifierSize(void* obj, CvSize* value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    Local $bValueDllType
    If VarGetType($value) == "DLLStruct" Then
        $bValueDllType = "struct*"
    Else
        $bValueDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCudaCascadeClassifierGetClassifierSize", $bObjDllType, $obj, $bValueDllType, $value), "cveCudaCascadeClassifierGetClassifierSize", @error)
EndFunc   ;==>_cveCudaCascadeClassifierGetClassifierSize