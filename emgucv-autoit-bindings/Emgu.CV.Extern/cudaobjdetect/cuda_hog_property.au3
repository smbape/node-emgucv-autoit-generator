#include-once
#include "..\..\CVEUtils.au3"

Func _cveCudaHOGGetGammaCorrection($obj)
    ; CVAPI(bool) cveCudaHOGGetGammaCorrection(void* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveCudaHOGGetGammaCorrection", $sObjDllType, $obj), "cveCudaHOGGetGammaCorrection", @error)
EndFunc   ;==>_cveCudaHOGGetGammaCorrection

Func _cveCudaHOGSetGammaCorrection($obj, $value)
    ; CVAPI(void) cveCudaHOGSetGammaCorrection(void* obj, bool value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCudaHOGSetGammaCorrection", $sObjDllType, $obj, "boolean", $value), "cveCudaHOGSetGammaCorrection", @error)
EndFunc   ;==>_cveCudaHOGSetGammaCorrection

Func _cveCudaHOGGetWinSigma($obj)
    ; CVAPI(double) cveCudaHOGGetWinSigma(void* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveCudaHOGGetWinSigma", $sObjDllType, $obj), "cveCudaHOGGetWinSigma", @error)
EndFunc   ;==>_cveCudaHOGGetWinSigma

Func _cveCudaHOGSetWinSigma($obj, $value)
    ; CVAPI(void) cveCudaHOGSetWinSigma(void* obj, double value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCudaHOGSetWinSigma", $sObjDllType, $obj, "double", $value), "cveCudaHOGSetWinSigma", @error)
EndFunc   ;==>_cveCudaHOGSetWinSigma

Func _cveCudaHOGGetNumLevels($obj)
    ; CVAPI(int) cveCudaHOGGetNumLevels(void* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveCudaHOGGetNumLevels", $sObjDllType, $obj), "cveCudaHOGGetNumLevels", @error)
EndFunc   ;==>_cveCudaHOGGetNumLevels

Func _cveCudaHOGSetNumLevels($obj, $value)
    ; CVAPI(void) cveCudaHOGSetNumLevels(void* obj, int value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCudaHOGSetNumLevels", $sObjDllType, $obj, "int", $value), "cveCudaHOGSetNumLevels", @error)
EndFunc   ;==>_cveCudaHOGSetNumLevels

Func _cveCudaHOGGetGroupThreshold($obj)
    ; CVAPI(int) cveCudaHOGGetGroupThreshold(void* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveCudaHOGGetGroupThreshold", $sObjDllType, $obj), "cveCudaHOGGetGroupThreshold", @error)
EndFunc   ;==>_cveCudaHOGGetGroupThreshold

Func _cveCudaHOGSetGroupThreshold($obj, $value)
    ; CVAPI(void) cveCudaHOGSetGroupThreshold(void* obj, int value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCudaHOGSetGroupThreshold", $sObjDllType, $obj, "int", $value), "cveCudaHOGSetGroupThreshold", @error)
EndFunc   ;==>_cveCudaHOGSetGroupThreshold

Func _cveCudaHOGGetHitThreshold($obj)
    ; CVAPI(double) cveCudaHOGGetHitThreshold(void* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveCudaHOGGetHitThreshold", $sObjDllType, $obj), "cveCudaHOGGetHitThreshold", @error)
EndFunc   ;==>_cveCudaHOGGetHitThreshold

Func _cveCudaHOGSetHitThreshold($obj, $value)
    ; CVAPI(void) cveCudaHOGSetHitThreshold(void* obj, double value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCudaHOGSetHitThreshold", $sObjDllType, $obj, "double", $value), "cveCudaHOGSetHitThreshold", @error)
EndFunc   ;==>_cveCudaHOGSetHitThreshold

Func _cveCudaHOGGetScaleFactor($obj)
    ; CVAPI(double) cveCudaHOGGetScaleFactor(void* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveCudaHOGGetScaleFactor", $sObjDllType, $obj), "cveCudaHOGGetScaleFactor", @error)
EndFunc   ;==>_cveCudaHOGGetScaleFactor

Func _cveCudaHOGSetScaleFactor($obj, $value)
    ; CVAPI(void) cveCudaHOGSetScaleFactor(void* obj, double value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCudaHOGSetScaleFactor", $sObjDllType, $obj, "double", $value), "cveCudaHOGSetScaleFactor", @error)
EndFunc   ;==>_cveCudaHOGSetScaleFactor

Func _cveCudaHOGGetL2HysThreshold($obj)
    ; CVAPI(double) cveCudaHOGGetL2HysThreshold(void* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveCudaHOGGetL2HysThreshold", $sObjDllType, $obj), "cveCudaHOGGetL2HysThreshold", @error)
EndFunc   ;==>_cveCudaHOGGetL2HysThreshold

Func _cveCudaHOGSetL2HysThreshold($obj, $value)
    ; CVAPI(void) cveCudaHOGSetL2HysThreshold(void* obj, double value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCudaHOGSetL2HysThreshold", $sObjDllType, $obj, "double", $value), "cveCudaHOGSetL2HysThreshold", @error)
EndFunc   ;==>_cveCudaHOGSetL2HysThreshold

Func _cveCudaHOGGetDescriptorFormat($obj)
    ; CVAPI(int) cveCudaHOGGetDescriptorFormat(void* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveCudaHOGGetDescriptorFormat", $sObjDllType, $obj), "cveCudaHOGGetDescriptorFormat", @error)
EndFunc   ;==>_cveCudaHOGGetDescriptorFormat

Func _cveCudaHOGGetDescriptorSize($obj)
    ; CVAPI(size_t) cveCudaHOGGetDescriptorSize(void* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ulong_ptr:cdecl", "cveCudaHOGGetDescriptorSize", $sObjDllType, $obj), "cveCudaHOGGetDescriptorSize", @error)
EndFunc   ;==>_cveCudaHOGGetDescriptorSize

Func _cveCudaHOGGetWinStride($obj, $value)
    ; CVAPI(void) cveCudaHOGGetWinStride(void* obj, CvSize* value);

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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCudaHOGGetWinStride", $sObjDllType, $obj, $sValueDllType, $value), "cveCudaHOGGetWinStride", @error)
EndFunc   ;==>_cveCudaHOGGetWinStride

Func _cveCudaHOGSetWinStride($obj, $value)
    ; CVAPI(void) cveCudaHOGSetWinStride(void* obj, CvSize* value);

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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCudaHOGSetWinStride", $sObjDllType, $obj, $sValueDllType, $value), "cveCudaHOGSetWinStride", @error)
EndFunc   ;==>_cveCudaHOGSetWinStride

Func _cveCudaHOGGetBlockHistogramSize($obj)
    ; CVAPI(size_t) cveCudaHOGGetBlockHistogramSize(void* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ulong_ptr:cdecl", "cveCudaHOGGetBlockHistogramSize", $sObjDllType, $obj), "cveCudaHOGGetBlockHistogramSize", @error)
EndFunc   ;==>_cveCudaHOGGetBlockHistogramSize