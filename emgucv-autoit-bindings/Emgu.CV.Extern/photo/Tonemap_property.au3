#include-once
#include <..\..\CVEUtils.au3>

Func _cveTonemapGetGamma(ByRef $obj)
    ; CVAPI(float) cveTonemapGetGamma(cv::Tonemap* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cveTonemapGetGamma", "ptr", $obj), "cveTonemapGetGamma", @error)
EndFunc   ;==>_cveTonemapGetGamma

Func _cveTonemapSetGamma(ByRef $obj, $value)
    ; CVAPI(void) cveTonemapSetGamma(cv::Tonemap* obj, float value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveTonemapSetGamma", "ptr", $obj, "float", $value), "cveTonemapSetGamma", @error)
EndFunc   ;==>_cveTonemapSetGamma