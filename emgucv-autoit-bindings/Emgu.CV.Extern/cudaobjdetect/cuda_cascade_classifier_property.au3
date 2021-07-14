#include-once
#include <..\..\CVEUtils.au3>

Func _cveCudaCascadeClassifierGetScaleFactor(ByRef $obj)
    ; CVAPI(double) cveCudaCascadeClassifierGetScaleFactor(void* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveCudaCascadeClassifierGetScaleFactor", "struct*", $obj), "cveCudaCascadeClassifierGetScaleFactor", @error)
EndFunc   ;==>_cveCudaCascadeClassifierGetScaleFactor

Func _cveCudaCascadeClassifierSetScaleFactor(ByRef $obj, $value)
    ; CVAPI(void) cveCudaCascadeClassifierSetScaleFactor(void* obj, double value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCudaCascadeClassifierSetScaleFactor", "struct*", $obj, "double", $value), "cveCudaCascadeClassifierSetScaleFactor", @error)
EndFunc   ;==>_cveCudaCascadeClassifierSetScaleFactor

Func _cveCudaCascadeClassifierGetMinNeighbors(ByRef $obj)
    ; CVAPI(int) cveCudaCascadeClassifierGetMinNeighbors(void* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveCudaCascadeClassifierGetMinNeighbors", "struct*", $obj), "cveCudaCascadeClassifierGetMinNeighbors", @error)
EndFunc   ;==>_cveCudaCascadeClassifierGetMinNeighbors

Func _cveCudaCascadeClassifierSetMinNeighbors(ByRef $obj, $value)
    ; CVAPI(void) cveCudaCascadeClassifierSetMinNeighbors(void* obj, int value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCudaCascadeClassifierSetMinNeighbors", "struct*", $obj, "int", $value), "cveCudaCascadeClassifierSetMinNeighbors", @error)
EndFunc   ;==>_cveCudaCascadeClassifierSetMinNeighbors

Func _cveCudaCascadeClassifierGetMaxNumObjects(ByRef $obj)
    ; CVAPI(int) cveCudaCascadeClassifierGetMaxNumObjects(void* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveCudaCascadeClassifierGetMaxNumObjects", "struct*", $obj), "cveCudaCascadeClassifierGetMaxNumObjects", @error)
EndFunc   ;==>_cveCudaCascadeClassifierGetMaxNumObjects

Func _cveCudaCascadeClassifierSetMaxNumObjects(ByRef $obj, $value)
    ; CVAPI(void) cveCudaCascadeClassifierSetMaxNumObjects(void* obj, int value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCudaCascadeClassifierSetMaxNumObjects", "struct*", $obj, "int", $value), "cveCudaCascadeClassifierSetMaxNumObjects", @error)
EndFunc   ;==>_cveCudaCascadeClassifierSetMaxNumObjects

Func _cveCudaCascadeClassifierGetFindLargestObject(ByRef $obj)
    ; CVAPI(bool) cveCudaCascadeClassifierGetFindLargestObject(void* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveCudaCascadeClassifierGetFindLargestObject", "struct*", $obj), "cveCudaCascadeClassifierGetFindLargestObject", @error)
EndFunc   ;==>_cveCudaCascadeClassifierGetFindLargestObject

Func _cveCudaCascadeClassifierSetFindLargestObject(ByRef $obj, $value)
    ; CVAPI(void) cveCudaCascadeClassifierSetFindLargestObject(void* obj, bool value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCudaCascadeClassifierSetFindLargestObject", "struct*", $obj, "boolean", $value), "cveCudaCascadeClassifierSetFindLargestObject", @error)
EndFunc   ;==>_cveCudaCascadeClassifierSetFindLargestObject

Func _cveCudaCascadeClassifierGetMaxObjectSize(ByRef $obj, ByRef $value)
    ; CVAPI(void) cveCudaCascadeClassifierGetMaxObjectSize(void* obj, CvSize* value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCudaCascadeClassifierGetMaxObjectSize", "struct*", $obj, "struct*", $value), "cveCudaCascadeClassifierGetMaxObjectSize", @error)
EndFunc   ;==>_cveCudaCascadeClassifierGetMaxObjectSize

Func _cveCudaCascadeClassifierSetMaxObjectSize(ByRef $obj, ByRef $value)
    ; CVAPI(void) cveCudaCascadeClassifierSetMaxObjectSize(void* obj, CvSize* value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCudaCascadeClassifierSetMaxObjectSize", "struct*", $obj, "struct*", $value), "cveCudaCascadeClassifierSetMaxObjectSize", @error)
EndFunc   ;==>_cveCudaCascadeClassifierSetMaxObjectSize

Func _cveCudaCascadeClassifierGetMinObjectSize(ByRef $obj, ByRef $value)
    ; CVAPI(void) cveCudaCascadeClassifierGetMinObjectSize(void* obj, CvSize* value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCudaCascadeClassifierGetMinObjectSize", "struct*", $obj, "struct*", $value), "cveCudaCascadeClassifierGetMinObjectSize", @error)
EndFunc   ;==>_cveCudaCascadeClassifierGetMinObjectSize

Func _cveCudaCascadeClassifierSetMinObjectSize(ByRef $obj, ByRef $value)
    ; CVAPI(void) cveCudaCascadeClassifierSetMinObjectSize(void* obj, CvSize* value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCudaCascadeClassifierSetMinObjectSize", "struct*", $obj, "struct*", $value), "cveCudaCascadeClassifierSetMinObjectSize", @error)
EndFunc   ;==>_cveCudaCascadeClassifierSetMinObjectSize

Func _cveCudaCascadeClassifierGetClassifierSize(ByRef $obj, ByRef $value)
    ; CVAPI(void) cveCudaCascadeClassifierGetClassifierSize(void* obj, CvSize* value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCudaCascadeClassifierGetClassifierSize", "struct*", $obj, "struct*", $value), "cveCudaCascadeClassifierGetClassifierSize", @error)
EndFunc   ;==>_cveCudaCascadeClassifierGetClassifierSize