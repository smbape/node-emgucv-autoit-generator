#include-once
#include <..\..\CVEUtils.au3>

Func _cveMSERGetPass2Only(ByRef $obj)
    ; CVAPI(bool) cveMSERGetPass2Only(cv::MSER* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveMSERGetPass2Only", "ptr", $obj), "cveMSERGetPass2Only", @error)
EndFunc   ;==>_cveMSERGetPass2Only

Func _cveMSERSetPass2Only(ByRef $obj, $value)
    ; CVAPI(void) cveMSERSetPass2Only(cv::MSER* obj, bool value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMSERSetPass2Only", "ptr", $obj, "boolean", $value), "cveMSERSetPass2Only", @error)
EndFunc   ;==>_cveMSERSetPass2Only

Func _cveMSERGetDelta(ByRef $obj)
    ; CVAPI(int) cveMSERGetDelta(cv::MSER* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveMSERGetDelta", "ptr", $obj), "cveMSERGetDelta", @error)
EndFunc   ;==>_cveMSERGetDelta

Func _cveMSERSetDelta(ByRef $obj, $value)
    ; CVAPI(void) cveMSERSetDelta(cv::MSER* obj, int value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMSERSetDelta", "ptr", $obj, "int", $value), "cveMSERSetDelta", @error)
EndFunc   ;==>_cveMSERSetDelta

Func _cveMSERGetMinArea(ByRef $obj)
    ; CVAPI(int) cveMSERGetMinArea(cv::MSER* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveMSERGetMinArea", "ptr", $obj), "cveMSERGetMinArea", @error)
EndFunc   ;==>_cveMSERGetMinArea

Func _cveMSERSetMinArea(ByRef $obj, $value)
    ; CVAPI(void) cveMSERSetMinArea(cv::MSER* obj, int value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMSERSetMinArea", "ptr", $obj, "int", $value), "cveMSERSetMinArea", @error)
EndFunc   ;==>_cveMSERSetMinArea

Func _cveMSERGetMaxArea(ByRef $obj)
    ; CVAPI(int) cveMSERGetMaxArea(cv::MSER* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveMSERGetMaxArea", "ptr", $obj), "cveMSERGetMaxArea", @error)
EndFunc   ;==>_cveMSERGetMaxArea

Func _cveMSERSetMaxArea(ByRef $obj, $value)
    ; CVAPI(void) cveMSERSetMaxArea(cv::MSER* obj, int value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMSERSetMaxArea", "ptr", $obj, "int", $value), "cveMSERSetMaxArea", @error)
EndFunc   ;==>_cveMSERSetMaxArea