#include-once
#include "..\..\CVEUtils.au3"

Func _cveCudaHoughLinesDetectorGetRho($obj)
    ; CVAPI(float) cveCudaHoughLinesDetectorGetRho(void* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cveCudaHoughLinesDetectorGetRho", $sObjDllType, $obj), "cveCudaHoughLinesDetectorGetRho", @error)
EndFunc   ;==>_cveCudaHoughLinesDetectorGetRho

Func _cveCudaHoughLinesDetectorSetRho($obj, $value)
    ; CVAPI(void) cveCudaHoughLinesDetectorSetRho(void* obj, float value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCudaHoughLinesDetectorSetRho", $sObjDllType, $obj, "float", $value), "cveCudaHoughLinesDetectorSetRho", @error)
EndFunc   ;==>_cveCudaHoughLinesDetectorSetRho

Func _cveCudaHoughLinesDetectorGetTheta($obj)
    ; CVAPI(float) cveCudaHoughLinesDetectorGetTheta(void* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cveCudaHoughLinesDetectorGetTheta", $sObjDllType, $obj), "cveCudaHoughLinesDetectorGetTheta", @error)
EndFunc   ;==>_cveCudaHoughLinesDetectorGetTheta

Func _cveCudaHoughLinesDetectorSetTheta($obj, $value)
    ; CVAPI(void) cveCudaHoughLinesDetectorSetTheta(void* obj, float value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCudaHoughLinesDetectorSetTheta", $sObjDllType, $obj, "float", $value), "cveCudaHoughLinesDetectorSetTheta", @error)
EndFunc   ;==>_cveCudaHoughLinesDetectorSetTheta

Func _cveCudaHoughLinesDetectorGetThreshold($obj)
    ; CVAPI(int) cveCudaHoughLinesDetectorGetThreshold(void* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveCudaHoughLinesDetectorGetThreshold", $sObjDllType, $obj), "cveCudaHoughLinesDetectorGetThreshold", @error)
EndFunc   ;==>_cveCudaHoughLinesDetectorGetThreshold

Func _cveCudaHoughLinesDetectorSetThreshold($obj, $value)
    ; CVAPI(void) cveCudaHoughLinesDetectorSetThreshold(void* obj, int value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCudaHoughLinesDetectorSetThreshold", $sObjDllType, $obj, "int", $value), "cveCudaHoughLinesDetectorSetThreshold", @error)
EndFunc   ;==>_cveCudaHoughLinesDetectorSetThreshold

Func _cveCudaHoughLinesDetectorGetDoSort($obj)
    ; CVAPI(bool) cveCudaHoughLinesDetectorGetDoSort(void* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveCudaHoughLinesDetectorGetDoSort", $sObjDllType, $obj), "cveCudaHoughLinesDetectorGetDoSort", @error)
EndFunc   ;==>_cveCudaHoughLinesDetectorGetDoSort

Func _cveCudaHoughLinesDetectorSetDoSort($obj, $value)
    ; CVAPI(void) cveCudaHoughLinesDetectorSetDoSort(void* obj, bool value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCudaHoughLinesDetectorSetDoSort", $sObjDllType, $obj, "boolean", $value), "cveCudaHoughLinesDetectorSetDoSort", @error)
EndFunc   ;==>_cveCudaHoughLinesDetectorSetDoSort

Func _cveCudaHoughLinesDetectorGetMaxLines($obj)
    ; CVAPI(int) cveCudaHoughLinesDetectorGetMaxLines(void* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveCudaHoughLinesDetectorGetMaxLines", $sObjDllType, $obj), "cveCudaHoughLinesDetectorGetMaxLines", @error)
EndFunc   ;==>_cveCudaHoughLinesDetectorGetMaxLines

Func _cveCudaHoughLinesDetectorSetMaxLines($obj, $value)
    ; CVAPI(void) cveCudaHoughLinesDetectorSetMaxLines(void* obj, int value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCudaHoughLinesDetectorSetMaxLines", $sObjDllType, $obj, "int", $value), "cveCudaHoughLinesDetectorSetMaxLines", @error)
EndFunc   ;==>_cveCudaHoughLinesDetectorSetMaxLines