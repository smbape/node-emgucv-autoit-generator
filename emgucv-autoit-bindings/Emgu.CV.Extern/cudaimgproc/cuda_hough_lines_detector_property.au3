#include-once
#include "..\..\CVEUtils.au3"

Func _cveCudaHoughLinesDetectorGetRho($obj)
    ; CVAPI(float) cveCudaHoughLinesDetectorGetRho(void* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cveCudaHoughLinesDetectorGetRho", $bObjDllType, $obj), "cveCudaHoughLinesDetectorGetRho", @error)
EndFunc   ;==>_cveCudaHoughLinesDetectorGetRho

Func _cveCudaHoughLinesDetectorSetRho($obj, $value)
    ; CVAPI(void) cveCudaHoughLinesDetectorSetRho(void* obj, float value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCudaHoughLinesDetectorSetRho", $bObjDllType, $obj, "float", $value), "cveCudaHoughLinesDetectorSetRho", @error)
EndFunc   ;==>_cveCudaHoughLinesDetectorSetRho

Func _cveCudaHoughLinesDetectorGetTheta($obj)
    ; CVAPI(float) cveCudaHoughLinesDetectorGetTheta(void* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cveCudaHoughLinesDetectorGetTheta", $bObjDllType, $obj), "cveCudaHoughLinesDetectorGetTheta", @error)
EndFunc   ;==>_cveCudaHoughLinesDetectorGetTheta

Func _cveCudaHoughLinesDetectorSetTheta($obj, $value)
    ; CVAPI(void) cveCudaHoughLinesDetectorSetTheta(void* obj, float value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCudaHoughLinesDetectorSetTheta", $bObjDllType, $obj, "float", $value), "cveCudaHoughLinesDetectorSetTheta", @error)
EndFunc   ;==>_cveCudaHoughLinesDetectorSetTheta

Func _cveCudaHoughLinesDetectorGetThreshold($obj)
    ; CVAPI(int) cveCudaHoughLinesDetectorGetThreshold(void* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveCudaHoughLinesDetectorGetThreshold", $bObjDllType, $obj), "cveCudaHoughLinesDetectorGetThreshold", @error)
EndFunc   ;==>_cveCudaHoughLinesDetectorGetThreshold

Func _cveCudaHoughLinesDetectorSetThreshold($obj, $value)
    ; CVAPI(void) cveCudaHoughLinesDetectorSetThreshold(void* obj, int value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCudaHoughLinesDetectorSetThreshold", $bObjDllType, $obj, "int", $value), "cveCudaHoughLinesDetectorSetThreshold", @error)
EndFunc   ;==>_cveCudaHoughLinesDetectorSetThreshold

Func _cveCudaHoughLinesDetectorGetDoSort($obj)
    ; CVAPI(bool) cveCudaHoughLinesDetectorGetDoSort(void* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveCudaHoughLinesDetectorGetDoSort", $bObjDllType, $obj), "cveCudaHoughLinesDetectorGetDoSort", @error)
EndFunc   ;==>_cveCudaHoughLinesDetectorGetDoSort

Func _cveCudaHoughLinesDetectorSetDoSort($obj, $value)
    ; CVAPI(void) cveCudaHoughLinesDetectorSetDoSort(void* obj, bool value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCudaHoughLinesDetectorSetDoSort", $bObjDllType, $obj, "boolean", $value), "cveCudaHoughLinesDetectorSetDoSort", @error)
EndFunc   ;==>_cveCudaHoughLinesDetectorSetDoSort

Func _cveCudaHoughLinesDetectorGetMaxLines($obj)
    ; CVAPI(int) cveCudaHoughLinesDetectorGetMaxLines(void* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveCudaHoughLinesDetectorGetMaxLines", $bObjDllType, $obj), "cveCudaHoughLinesDetectorGetMaxLines", @error)
EndFunc   ;==>_cveCudaHoughLinesDetectorGetMaxLines

Func _cveCudaHoughLinesDetectorSetMaxLines($obj, $value)
    ; CVAPI(void) cveCudaHoughLinesDetectorSetMaxLines(void* obj, int value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCudaHoughLinesDetectorSetMaxLines", $bObjDllType, $obj, "int", $value), "cveCudaHoughLinesDetectorSetMaxLines", @error)
EndFunc   ;==>_cveCudaHoughLinesDetectorSetMaxLines