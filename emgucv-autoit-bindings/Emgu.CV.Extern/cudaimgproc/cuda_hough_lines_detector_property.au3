#include-once
#include <..\..\CVEUtils.au3>

Func _cveCudaHoughLinesDetectorGetRho(ByRef $obj)
    ; CVAPI(float) cveCudaHoughLinesDetectorGetRho(void* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cveCudaHoughLinesDetectorGetRho", "struct*", $obj), "cveCudaHoughLinesDetectorGetRho", @error)
EndFunc   ;==>_cveCudaHoughLinesDetectorGetRho

Func _cveCudaHoughLinesDetectorSetRho(ByRef $obj, $value)
    ; CVAPI(void) cveCudaHoughLinesDetectorSetRho(void* obj, float value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCudaHoughLinesDetectorSetRho", "struct*", $obj, "float", $value), "cveCudaHoughLinesDetectorSetRho", @error)
EndFunc   ;==>_cveCudaHoughLinesDetectorSetRho

Func _cveCudaHoughLinesDetectorGetTheta(ByRef $obj)
    ; CVAPI(float) cveCudaHoughLinesDetectorGetTheta(void* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cveCudaHoughLinesDetectorGetTheta", "struct*", $obj), "cveCudaHoughLinesDetectorGetTheta", @error)
EndFunc   ;==>_cveCudaHoughLinesDetectorGetTheta

Func _cveCudaHoughLinesDetectorSetTheta(ByRef $obj, $value)
    ; CVAPI(void) cveCudaHoughLinesDetectorSetTheta(void* obj, float value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCudaHoughLinesDetectorSetTheta", "struct*", $obj, "float", $value), "cveCudaHoughLinesDetectorSetTheta", @error)
EndFunc   ;==>_cveCudaHoughLinesDetectorSetTheta

Func _cveCudaHoughLinesDetectorGetThreshold(ByRef $obj)
    ; CVAPI(int) cveCudaHoughLinesDetectorGetThreshold(void* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveCudaHoughLinesDetectorGetThreshold", "struct*", $obj), "cveCudaHoughLinesDetectorGetThreshold", @error)
EndFunc   ;==>_cveCudaHoughLinesDetectorGetThreshold

Func _cveCudaHoughLinesDetectorSetThreshold(ByRef $obj, $value)
    ; CVAPI(void) cveCudaHoughLinesDetectorSetThreshold(void* obj, int value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCudaHoughLinesDetectorSetThreshold", "struct*", $obj, "int", $value), "cveCudaHoughLinesDetectorSetThreshold", @error)
EndFunc   ;==>_cveCudaHoughLinesDetectorSetThreshold

Func _cveCudaHoughLinesDetectorGetDoSort(ByRef $obj)
    ; CVAPI(bool) cveCudaHoughLinesDetectorGetDoSort(void* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveCudaHoughLinesDetectorGetDoSort", "struct*", $obj), "cveCudaHoughLinesDetectorGetDoSort", @error)
EndFunc   ;==>_cveCudaHoughLinesDetectorGetDoSort

Func _cveCudaHoughLinesDetectorSetDoSort(ByRef $obj, $value)
    ; CVAPI(void) cveCudaHoughLinesDetectorSetDoSort(void* obj, bool value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCudaHoughLinesDetectorSetDoSort", "struct*", $obj, "boolean", $value), "cveCudaHoughLinesDetectorSetDoSort", @error)
EndFunc   ;==>_cveCudaHoughLinesDetectorSetDoSort

Func _cveCudaHoughLinesDetectorGetMaxLines(ByRef $obj)
    ; CVAPI(int) cveCudaHoughLinesDetectorGetMaxLines(void* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveCudaHoughLinesDetectorGetMaxLines", "struct*", $obj), "cveCudaHoughLinesDetectorGetMaxLines", @error)
EndFunc   ;==>_cveCudaHoughLinesDetectorGetMaxLines

Func _cveCudaHoughLinesDetectorSetMaxLines(ByRef $obj, $value)
    ; CVAPI(void) cveCudaHoughLinesDetectorSetMaxLines(void* obj, int value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCudaHoughLinesDetectorSetMaxLines", "struct*", $obj, "int", $value), "cveCudaHoughLinesDetectorSetMaxLines", @error)
EndFunc   ;==>_cveCudaHoughLinesDetectorSetMaxLines