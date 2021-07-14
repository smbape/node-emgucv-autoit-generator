#include-once
#include <..\..\CVEUtils.au3>

Func _cveTonemapMantiukGetSaturation(ByRef $obj)
    ; CVAPI(float) cveTonemapMantiukGetSaturation(cv::TonemapMantiuk* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cveTonemapMantiukGetSaturation", "ptr", $obj), "cveTonemapMantiukGetSaturation", @error)
EndFunc   ;==>_cveTonemapMantiukGetSaturation

Func _cveTonemapMantiukSetSaturation(ByRef $obj, $value)
    ; CVAPI(void) cveTonemapMantiukSetSaturation(cv::TonemapMantiuk* obj, float value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveTonemapMantiukSetSaturation", "ptr", $obj, "float", $value), "cveTonemapMantiukSetSaturation", @error)
EndFunc   ;==>_cveTonemapMantiukSetSaturation

Func _cveTonemapMantiukGetScale(ByRef $obj)
    ; CVAPI(float) cveTonemapMantiukGetScale(cv::TonemapMantiuk* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cveTonemapMantiukGetScale", "ptr", $obj), "cveTonemapMantiukGetScale", @error)
EndFunc   ;==>_cveTonemapMantiukGetScale

Func _cveTonemapMantiukSetScale(ByRef $obj, $value)
    ; CVAPI(void) cveTonemapMantiukSetScale(cv::TonemapMantiuk* obj, float value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveTonemapMantiukSetScale", "ptr", $obj, "float", $value), "cveTonemapMantiukSetScale", @error)
EndFunc   ;==>_cveTonemapMantiukSetScale