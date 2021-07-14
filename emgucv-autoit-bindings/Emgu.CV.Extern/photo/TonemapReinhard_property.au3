#include-once
#include "..\..\CVEUtils.au3"

Func _cveTonemapReinhardGetIntensity(ByRef $obj)
    ; CVAPI(float) cveTonemapReinhardGetIntensity(cv::TonemapReinhard* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cveTonemapReinhardGetIntensity", "ptr", $obj), "cveTonemapReinhardGetIntensity", @error)
EndFunc   ;==>_cveTonemapReinhardGetIntensity

Func _cveTonemapReinhardSetIntensity(ByRef $obj, $value)
    ; CVAPI(void) cveTonemapReinhardSetIntensity(cv::TonemapReinhard* obj, float value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveTonemapReinhardSetIntensity", "ptr", $obj, "float", $value), "cveTonemapReinhardSetIntensity", @error)
EndFunc   ;==>_cveTonemapReinhardSetIntensity

Func _cveTonemapReinhardGetLightAdaptation(ByRef $obj)
    ; CVAPI(float) cveTonemapReinhardGetLightAdaptation(cv::TonemapReinhard* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cveTonemapReinhardGetLightAdaptation", "ptr", $obj), "cveTonemapReinhardGetLightAdaptation", @error)
EndFunc   ;==>_cveTonemapReinhardGetLightAdaptation

Func _cveTonemapReinhardSetLightAdaptation(ByRef $obj, $value)
    ; CVAPI(void) cveTonemapReinhardSetLightAdaptation(cv::TonemapReinhard* obj, float value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveTonemapReinhardSetLightAdaptation", "ptr", $obj, "float", $value), "cveTonemapReinhardSetLightAdaptation", @error)
EndFunc   ;==>_cveTonemapReinhardSetLightAdaptation

Func _cveTonemapReinhardGetColorAdaptation(ByRef $obj)
    ; CVAPI(float) cveTonemapReinhardGetColorAdaptation(cv::TonemapReinhard* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cveTonemapReinhardGetColorAdaptation", "ptr", $obj), "cveTonemapReinhardGetColorAdaptation", @error)
EndFunc   ;==>_cveTonemapReinhardGetColorAdaptation

Func _cveTonemapReinhardSetColorAdaptation(ByRef $obj, $value)
    ; CVAPI(void) cveTonemapReinhardSetColorAdaptation(cv::TonemapReinhard* obj, float value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveTonemapReinhardSetColorAdaptation", "ptr", $obj, "float", $value), "cveTonemapReinhardSetColorAdaptation", @error)
EndFunc   ;==>_cveTonemapReinhardSetColorAdaptation