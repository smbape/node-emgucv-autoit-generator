#include-once
#include "..\..\CVEUtils.au3"

Func _cveCudaHOGGetGammaCorrection($obj)
    ; CVAPI(bool) cveCudaHOGGetGammaCorrection(void* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveCudaHOGGetGammaCorrection", $bObjDllType, $obj), "cveCudaHOGGetGammaCorrection", @error)
EndFunc   ;==>_cveCudaHOGGetGammaCorrection

Func _cveCudaHOGSetGammaCorrection($obj, $value)
    ; CVAPI(void) cveCudaHOGSetGammaCorrection(void* obj, bool value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCudaHOGSetGammaCorrection", $bObjDllType, $obj, "boolean", $value), "cveCudaHOGSetGammaCorrection", @error)
EndFunc   ;==>_cveCudaHOGSetGammaCorrection

Func _cveCudaHOGGetWinSigma($obj)
    ; CVAPI(double) cveCudaHOGGetWinSigma(void* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveCudaHOGGetWinSigma", $bObjDllType, $obj), "cveCudaHOGGetWinSigma", @error)
EndFunc   ;==>_cveCudaHOGGetWinSigma

Func _cveCudaHOGSetWinSigma($obj, $value)
    ; CVAPI(void) cveCudaHOGSetWinSigma(void* obj, double value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCudaHOGSetWinSigma", $bObjDllType, $obj, "double", $value), "cveCudaHOGSetWinSigma", @error)
EndFunc   ;==>_cveCudaHOGSetWinSigma

Func _cveCudaHOGGetNumLevels($obj)
    ; CVAPI(int) cveCudaHOGGetNumLevels(void* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveCudaHOGGetNumLevels", $bObjDllType, $obj), "cveCudaHOGGetNumLevels", @error)
EndFunc   ;==>_cveCudaHOGGetNumLevels

Func _cveCudaHOGSetNumLevels($obj, $value)
    ; CVAPI(void) cveCudaHOGSetNumLevels(void* obj, int value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCudaHOGSetNumLevels", $bObjDllType, $obj, "int", $value), "cveCudaHOGSetNumLevels", @error)
EndFunc   ;==>_cveCudaHOGSetNumLevels

Func _cveCudaHOGGetGroupThreshold($obj)
    ; CVAPI(int) cveCudaHOGGetGroupThreshold(void* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveCudaHOGGetGroupThreshold", $bObjDllType, $obj), "cveCudaHOGGetGroupThreshold", @error)
EndFunc   ;==>_cveCudaHOGGetGroupThreshold

Func _cveCudaHOGSetGroupThreshold($obj, $value)
    ; CVAPI(void) cveCudaHOGSetGroupThreshold(void* obj, int value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCudaHOGSetGroupThreshold", $bObjDllType, $obj, "int", $value), "cveCudaHOGSetGroupThreshold", @error)
EndFunc   ;==>_cveCudaHOGSetGroupThreshold

Func _cveCudaHOGGetHitThreshold($obj)
    ; CVAPI(double) cveCudaHOGGetHitThreshold(void* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveCudaHOGGetHitThreshold", $bObjDllType, $obj), "cveCudaHOGGetHitThreshold", @error)
EndFunc   ;==>_cveCudaHOGGetHitThreshold

Func _cveCudaHOGSetHitThreshold($obj, $value)
    ; CVAPI(void) cveCudaHOGSetHitThreshold(void* obj, double value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCudaHOGSetHitThreshold", $bObjDllType, $obj, "double", $value), "cveCudaHOGSetHitThreshold", @error)
EndFunc   ;==>_cveCudaHOGSetHitThreshold

Func _cveCudaHOGGetScaleFactor($obj)
    ; CVAPI(double) cveCudaHOGGetScaleFactor(void* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveCudaHOGGetScaleFactor", $bObjDllType, $obj), "cveCudaHOGGetScaleFactor", @error)
EndFunc   ;==>_cveCudaHOGGetScaleFactor

Func _cveCudaHOGSetScaleFactor($obj, $value)
    ; CVAPI(void) cveCudaHOGSetScaleFactor(void* obj, double value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCudaHOGSetScaleFactor", $bObjDllType, $obj, "double", $value), "cveCudaHOGSetScaleFactor", @error)
EndFunc   ;==>_cveCudaHOGSetScaleFactor

Func _cveCudaHOGGetL2HysThreshold($obj)
    ; CVAPI(double) cveCudaHOGGetL2HysThreshold(void* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveCudaHOGGetL2HysThreshold", $bObjDllType, $obj), "cveCudaHOGGetL2HysThreshold", @error)
EndFunc   ;==>_cveCudaHOGGetL2HysThreshold

Func _cveCudaHOGSetL2HysThreshold($obj, $value)
    ; CVAPI(void) cveCudaHOGSetL2HysThreshold(void* obj, double value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCudaHOGSetL2HysThreshold", $bObjDllType, $obj, "double", $value), "cveCudaHOGSetL2HysThreshold", @error)
EndFunc   ;==>_cveCudaHOGSetL2HysThreshold

Func _cveCudaHOGGetDescriptorFormat($obj)
    ; CVAPI(int) cveCudaHOGGetDescriptorFormat(void* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveCudaHOGGetDescriptorFormat", $bObjDllType, $obj), "cveCudaHOGGetDescriptorFormat", @error)
EndFunc   ;==>_cveCudaHOGGetDescriptorFormat

Func _cveCudaHOGGetDescriptorSize($obj)
    ; CVAPI(size_t) cveCudaHOGGetDescriptorSize(void* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ulong_ptr:cdecl", "cveCudaHOGGetDescriptorSize", $bObjDllType, $obj), "cveCudaHOGGetDescriptorSize", @error)
EndFunc   ;==>_cveCudaHOGGetDescriptorSize

Func _cveCudaHOGGetWinStride($obj, $value)
    ; CVAPI(void) cveCudaHOGGetWinStride(void* obj, CvSize* value);

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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCudaHOGGetWinStride", $bObjDllType, $obj, $bValueDllType, $value), "cveCudaHOGGetWinStride", @error)
EndFunc   ;==>_cveCudaHOGGetWinStride

Func _cveCudaHOGSetWinStride($obj, $value)
    ; CVAPI(void) cveCudaHOGSetWinStride(void* obj, CvSize* value);

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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCudaHOGSetWinStride", $bObjDllType, $obj, $bValueDllType, $value), "cveCudaHOGSetWinStride", @error)
EndFunc   ;==>_cveCudaHOGSetWinStride

Func _cveCudaHOGGetBlockHistogramSize($obj)
    ; CVAPI(size_t) cveCudaHOGGetBlockHistogramSize(void* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ulong_ptr:cdecl", "cveCudaHOGGetBlockHistogramSize", $bObjDllType, $obj), "cveCudaHOGGetBlockHistogramSize", @error)
EndFunc   ;==>_cveCudaHOGGetBlockHistogramSize