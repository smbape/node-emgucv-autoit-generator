#include-once
#include <..\..\CVEUtils.au3>

Func _cveCudaHOGGetGammaCorrection(ByRef $obj)
    ; CVAPI(bool) cveCudaHOGGetGammaCorrection(void* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveCudaHOGGetGammaCorrection", "struct*", $obj), "cveCudaHOGGetGammaCorrection", @error)
EndFunc   ;==>_cveCudaHOGGetGammaCorrection

Func _cveCudaHOGSetGammaCorrection(ByRef $obj, $value)
    ; CVAPI(void) cveCudaHOGSetGammaCorrection(void* obj, bool value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCudaHOGSetGammaCorrection", "struct*", $obj, "boolean", $value), "cveCudaHOGSetGammaCorrection", @error)
EndFunc   ;==>_cveCudaHOGSetGammaCorrection

Func _cveCudaHOGGetWinSigma(ByRef $obj)
    ; CVAPI(double) cveCudaHOGGetWinSigma(void* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveCudaHOGGetWinSigma", "struct*", $obj), "cveCudaHOGGetWinSigma", @error)
EndFunc   ;==>_cveCudaHOGGetWinSigma

Func _cveCudaHOGSetWinSigma(ByRef $obj, $value)
    ; CVAPI(void) cveCudaHOGSetWinSigma(void* obj, double value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCudaHOGSetWinSigma", "struct*", $obj, "double", $value), "cveCudaHOGSetWinSigma", @error)
EndFunc   ;==>_cveCudaHOGSetWinSigma

Func _cveCudaHOGGetNumLevels(ByRef $obj)
    ; CVAPI(int) cveCudaHOGGetNumLevels(void* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveCudaHOGGetNumLevels", "struct*", $obj), "cveCudaHOGGetNumLevels", @error)
EndFunc   ;==>_cveCudaHOGGetNumLevels

Func _cveCudaHOGSetNumLevels(ByRef $obj, $value)
    ; CVAPI(void) cveCudaHOGSetNumLevels(void* obj, int value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCudaHOGSetNumLevels", "struct*", $obj, "int", $value), "cveCudaHOGSetNumLevels", @error)
EndFunc   ;==>_cveCudaHOGSetNumLevels

Func _cveCudaHOGGetGroupThreshold(ByRef $obj)
    ; CVAPI(int) cveCudaHOGGetGroupThreshold(void* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveCudaHOGGetGroupThreshold", "struct*", $obj), "cveCudaHOGGetGroupThreshold", @error)
EndFunc   ;==>_cveCudaHOGGetGroupThreshold

Func _cveCudaHOGSetGroupThreshold(ByRef $obj, $value)
    ; CVAPI(void) cveCudaHOGSetGroupThreshold(void* obj, int value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCudaHOGSetGroupThreshold", "struct*", $obj, "int", $value), "cveCudaHOGSetGroupThreshold", @error)
EndFunc   ;==>_cveCudaHOGSetGroupThreshold

Func _cveCudaHOGGetHitThreshold(ByRef $obj)
    ; CVAPI(double) cveCudaHOGGetHitThreshold(void* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveCudaHOGGetHitThreshold", "struct*", $obj), "cveCudaHOGGetHitThreshold", @error)
EndFunc   ;==>_cveCudaHOGGetHitThreshold

Func _cveCudaHOGSetHitThreshold(ByRef $obj, $value)
    ; CVAPI(void) cveCudaHOGSetHitThreshold(void* obj, double value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCudaHOGSetHitThreshold", "struct*", $obj, "double", $value), "cveCudaHOGSetHitThreshold", @error)
EndFunc   ;==>_cveCudaHOGSetHitThreshold

Func _cveCudaHOGGetScaleFactor(ByRef $obj)
    ; CVAPI(double) cveCudaHOGGetScaleFactor(void* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveCudaHOGGetScaleFactor", "struct*", $obj), "cveCudaHOGGetScaleFactor", @error)
EndFunc   ;==>_cveCudaHOGGetScaleFactor

Func _cveCudaHOGSetScaleFactor(ByRef $obj, $value)
    ; CVAPI(void) cveCudaHOGSetScaleFactor(void* obj, double value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCudaHOGSetScaleFactor", "struct*", $obj, "double", $value), "cveCudaHOGSetScaleFactor", @error)
EndFunc   ;==>_cveCudaHOGSetScaleFactor

Func _cveCudaHOGGetL2HysThreshold(ByRef $obj)
    ; CVAPI(double) cveCudaHOGGetL2HysThreshold(void* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveCudaHOGGetL2HysThreshold", "struct*", $obj), "cveCudaHOGGetL2HysThreshold", @error)
EndFunc   ;==>_cveCudaHOGGetL2HysThreshold

Func _cveCudaHOGSetL2HysThreshold(ByRef $obj, $value)
    ; CVAPI(void) cveCudaHOGSetL2HysThreshold(void* obj, double value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCudaHOGSetL2HysThreshold", "struct*", $obj, "double", $value), "cveCudaHOGSetL2HysThreshold", @error)
EndFunc   ;==>_cveCudaHOGSetL2HysThreshold

Func _cveCudaHOGGetDescriptorFormat(ByRef $obj)
    ; CVAPI(int) cveCudaHOGGetDescriptorFormat(void* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveCudaHOGGetDescriptorFormat", "struct*", $obj), "cveCudaHOGGetDescriptorFormat", @error)
EndFunc   ;==>_cveCudaHOGGetDescriptorFormat

Func _cveCudaHOGGetDescriptorSize(ByRef $obj)
    ; CVAPI(size_t) cveCudaHOGGetDescriptorSize(void* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ulong_ptr:cdecl", "cveCudaHOGGetDescriptorSize", "struct*", $obj), "cveCudaHOGGetDescriptorSize", @error)
EndFunc   ;==>_cveCudaHOGGetDescriptorSize

Func _cveCudaHOGGetWinStride(ByRef $obj, ByRef $value)
    ; CVAPI(void) cveCudaHOGGetWinStride(void* obj, CvSize* value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCudaHOGGetWinStride", "struct*", $obj, "struct*", $value), "cveCudaHOGGetWinStride", @error)
EndFunc   ;==>_cveCudaHOGGetWinStride

Func _cveCudaHOGSetWinStride(ByRef $obj, ByRef $value)
    ; CVAPI(void) cveCudaHOGSetWinStride(void* obj, CvSize* value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCudaHOGSetWinStride", "struct*", $obj, "struct*", $value), "cveCudaHOGSetWinStride", @error)
EndFunc   ;==>_cveCudaHOGSetWinStride

Func _cveCudaHOGGetBlockHistogramSize(ByRef $obj)
    ; CVAPI(size_t) cveCudaHOGGetBlockHistogramSize(void* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ulong_ptr:cdecl", "cveCudaHOGGetBlockHistogramSize", "struct*", $obj), "cveCudaHOGGetBlockHistogramSize", @error)
EndFunc   ;==>_cveCudaHOGGetBlockHistogramSize