#include-once
#include <..\..\CVEUtils.au3>

Func _cveSimpleWBGetInputMin(ByRef $obj)
    ; CVAPI(float) cveSimpleWBGetInputMin(cv::xphoto::SimpleWB* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cveSimpleWBGetInputMin", "ptr", $obj), "cveSimpleWBGetInputMin", @error)
EndFunc   ;==>_cveSimpleWBGetInputMin

Func _cveSimpleWBSetInputMin(ByRef $obj, $value)
    ; CVAPI(void) cveSimpleWBSetInputMin(cv::xphoto::SimpleWB* obj, float value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSimpleWBSetInputMin", "ptr", $obj, "float", $value), "cveSimpleWBSetInputMin", @error)
EndFunc   ;==>_cveSimpleWBSetInputMin

Func _cveSimpleWBGetInputMax(ByRef $obj)
    ; CVAPI(float) cveSimpleWBGetInputMax(cv::xphoto::SimpleWB* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cveSimpleWBGetInputMax", "ptr", $obj), "cveSimpleWBGetInputMax", @error)
EndFunc   ;==>_cveSimpleWBGetInputMax

Func _cveSimpleWBSetInputMax(ByRef $obj, $value)
    ; CVAPI(void) cveSimpleWBSetInputMax(cv::xphoto::SimpleWB* obj, float value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSimpleWBSetInputMax", "ptr", $obj, "float", $value), "cveSimpleWBSetInputMax", @error)
EndFunc   ;==>_cveSimpleWBSetInputMax

Func _cveSimpleWBGetOutputMin(ByRef $obj)
    ; CVAPI(float) cveSimpleWBGetOutputMin(cv::xphoto::SimpleWB* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cveSimpleWBGetOutputMin", "ptr", $obj), "cveSimpleWBGetOutputMin", @error)
EndFunc   ;==>_cveSimpleWBGetOutputMin

Func _cveSimpleWBSetOutputMin(ByRef $obj, $value)
    ; CVAPI(void) cveSimpleWBSetOutputMin(cv::xphoto::SimpleWB* obj, float value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSimpleWBSetOutputMin", "ptr", $obj, "float", $value), "cveSimpleWBSetOutputMin", @error)
EndFunc   ;==>_cveSimpleWBSetOutputMin

Func _cveSimpleWBGetOutputMax(ByRef $obj)
    ; CVAPI(float) cveSimpleWBGetOutputMax(cv::xphoto::SimpleWB* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cveSimpleWBGetOutputMax", "ptr", $obj), "cveSimpleWBGetOutputMax", @error)
EndFunc   ;==>_cveSimpleWBGetOutputMax

Func _cveSimpleWBSetOutputMax(ByRef $obj, $value)
    ; CVAPI(void) cveSimpleWBSetOutputMax(cv::xphoto::SimpleWB* obj, float value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSimpleWBSetOutputMax", "ptr", $obj, "float", $value), "cveSimpleWBSetOutputMax", @error)
EndFunc   ;==>_cveSimpleWBSetOutputMax

Func _cveSimpleWBGetP(ByRef $obj)
    ; CVAPI(float) cveSimpleWBGetP(cv::xphoto::SimpleWB* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cveSimpleWBGetP", "ptr", $obj), "cveSimpleWBGetP", @error)
EndFunc   ;==>_cveSimpleWBGetP

Func _cveSimpleWBSetP(ByRef $obj, $value)
    ; CVAPI(void) cveSimpleWBSetP(cv::xphoto::SimpleWB* obj, float value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSimpleWBSetP", "ptr", $obj, "float", $value), "cveSimpleWBSetP", @error)
EndFunc   ;==>_cveSimpleWBSetP