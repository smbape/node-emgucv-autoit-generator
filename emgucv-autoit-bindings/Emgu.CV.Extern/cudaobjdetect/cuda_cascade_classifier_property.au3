#include-once
#include "..\..\CVEUtils.au3"

Func _cveCudaCascadeClassifierGetScaleFactor($obj)
    ; CVAPI(double) cveCudaCascadeClassifierGetScaleFactor(void* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveCudaCascadeClassifierGetScaleFactor", $sObjDllType, $obj), "cveCudaCascadeClassifierGetScaleFactor", @error)
EndFunc   ;==>_cveCudaCascadeClassifierGetScaleFactor

Func _cveCudaCascadeClassifierSetScaleFactor($obj, $value)
    ; CVAPI(void) cveCudaCascadeClassifierSetScaleFactor(void* obj, double value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCudaCascadeClassifierSetScaleFactor", $sObjDllType, $obj, "double", $value), "cveCudaCascadeClassifierSetScaleFactor", @error)
EndFunc   ;==>_cveCudaCascadeClassifierSetScaleFactor

Func _cveCudaCascadeClassifierGetMinNeighbors($obj)
    ; CVAPI(int) cveCudaCascadeClassifierGetMinNeighbors(void* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveCudaCascadeClassifierGetMinNeighbors", $sObjDllType, $obj), "cveCudaCascadeClassifierGetMinNeighbors", @error)
EndFunc   ;==>_cveCudaCascadeClassifierGetMinNeighbors

Func _cveCudaCascadeClassifierSetMinNeighbors($obj, $value)
    ; CVAPI(void) cveCudaCascadeClassifierSetMinNeighbors(void* obj, int value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCudaCascadeClassifierSetMinNeighbors", $sObjDllType, $obj, "int", $value), "cveCudaCascadeClassifierSetMinNeighbors", @error)
EndFunc   ;==>_cveCudaCascadeClassifierSetMinNeighbors

Func _cveCudaCascadeClassifierGetMaxNumObjects($obj)
    ; CVAPI(int) cveCudaCascadeClassifierGetMaxNumObjects(void* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveCudaCascadeClassifierGetMaxNumObjects", $sObjDllType, $obj), "cveCudaCascadeClassifierGetMaxNumObjects", @error)
EndFunc   ;==>_cveCudaCascadeClassifierGetMaxNumObjects

Func _cveCudaCascadeClassifierSetMaxNumObjects($obj, $value)
    ; CVAPI(void) cveCudaCascadeClassifierSetMaxNumObjects(void* obj, int value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCudaCascadeClassifierSetMaxNumObjects", $sObjDllType, $obj, "int", $value), "cveCudaCascadeClassifierSetMaxNumObjects", @error)
EndFunc   ;==>_cveCudaCascadeClassifierSetMaxNumObjects

Func _cveCudaCascadeClassifierGetFindLargestObject($obj)
    ; CVAPI(bool) cveCudaCascadeClassifierGetFindLargestObject(void* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveCudaCascadeClassifierGetFindLargestObject", $sObjDllType, $obj), "cveCudaCascadeClassifierGetFindLargestObject", @error)
EndFunc   ;==>_cveCudaCascadeClassifierGetFindLargestObject

Func _cveCudaCascadeClassifierSetFindLargestObject($obj, $value)
    ; CVAPI(void) cveCudaCascadeClassifierSetFindLargestObject(void* obj, bool value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCudaCascadeClassifierSetFindLargestObject", $sObjDllType, $obj, "boolean", $value), "cveCudaCascadeClassifierSetFindLargestObject", @error)
EndFunc   ;==>_cveCudaCascadeClassifierSetFindLargestObject

Func _cveCudaCascadeClassifierGetMaxObjectSize($obj, $value)
    ; CVAPI(void) cveCudaCascadeClassifierGetMaxObjectSize(void* obj, CvSize* value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    Local $sValueDllType
    If IsDllStruct($value) Then
        $sValueDllType = "struct*"
    Else
        $sValueDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCudaCascadeClassifierGetMaxObjectSize", $sObjDllType, $obj, $sValueDllType, $value), "cveCudaCascadeClassifierGetMaxObjectSize", @error)
EndFunc   ;==>_cveCudaCascadeClassifierGetMaxObjectSize

Func _cveCudaCascadeClassifierSetMaxObjectSize($obj, $value)
    ; CVAPI(void) cveCudaCascadeClassifierSetMaxObjectSize(void* obj, CvSize* value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    Local $sValueDllType
    If IsDllStruct($value) Then
        $sValueDllType = "struct*"
    Else
        $sValueDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCudaCascadeClassifierSetMaxObjectSize", $sObjDllType, $obj, $sValueDllType, $value), "cveCudaCascadeClassifierSetMaxObjectSize", @error)
EndFunc   ;==>_cveCudaCascadeClassifierSetMaxObjectSize

Func _cveCudaCascadeClassifierGetMinObjectSize($obj, $value)
    ; CVAPI(void) cveCudaCascadeClassifierGetMinObjectSize(void* obj, CvSize* value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    Local $sValueDllType
    If IsDllStruct($value) Then
        $sValueDllType = "struct*"
    Else
        $sValueDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCudaCascadeClassifierGetMinObjectSize", $sObjDllType, $obj, $sValueDllType, $value), "cveCudaCascadeClassifierGetMinObjectSize", @error)
EndFunc   ;==>_cveCudaCascadeClassifierGetMinObjectSize

Func _cveCudaCascadeClassifierSetMinObjectSize($obj, $value)
    ; CVAPI(void) cveCudaCascadeClassifierSetMinObjectSize(void* obj, CvSize* value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    Local $sValueDllType
    If IsDllStruct($value) Then
        $sValueDllType = "struct*"
    Else
        $sValueDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCudaCascadeClassifierSetMinObjectSize", $sObjDllType, $obj, $sValueDllType, $value), "cveCudaCascadeClassifierSetMinObjectSize", @error)
EndFunc   ;==>_cveCudaCascadeClassifierSetMinObjectSize

Func _cveCudaCascadeClassifierGetClassifierSize($obj, $value)
    ; CVAPI(void) cveCudaCascadeClassifierGetClassifierSize(void* obj, CvSize* value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    Local $sValueDllType
    If IsDllStruct($value) Then
        $sValueDllType = "struct*"
    Else
        $sValueDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCudaCascadeClassifierGetClassifierSize", $sObjDllType, $obj, $sValueDllType, $value), "cveCudaCascadeClassifierGetClassifierSize", @error)
EndFunc   ;==>_cveCudaCascadeClassifierGetClassifierSize