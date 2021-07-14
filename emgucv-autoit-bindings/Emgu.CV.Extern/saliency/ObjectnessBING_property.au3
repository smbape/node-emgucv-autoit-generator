#include-once
#include "..\..\CVEUtils.au3"

Func _cveObjectnessBINGGetW(ByRef $obj)
    ; CVAPI(int) cveObjectnessBINGGetW(cv::saliency::ObjectnessBING* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveObjectnessBINGGetW", "ptr", $obj), "cveObjectnessBINGGetW", @error)
EndFunc   ;==>_cveObjectnessBINGGetW

Func _cveObjectnessBINGSetW(ByRef $obj, $value)
    ; CVAPI(void) cveObjectnessBINGSetW(cv::saliency::ObjectnessBING* obj, int value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveObjectnessBINGSetW", "ptr", $obj, "int", $value), "cveObjectnessBINGSetW", @error)
EndFunc   ;==>_cveObjectnessBINGSetW

Func _cveObjectnessBINGGetNSS(ByRef $obj)
    ; CVAPI(int) cveObjectnessBINGGetNSS(cv::saliency::ObjectnessBING* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveObjectnessBINGGetNSS", "ptr", $obj), "cveObjectnessBINGGetNSS", @error)
EndFunc   ;==>_cveObjectnessBINGGetNSS

Func _cveObjectnessBINGSetNSS(ByRef $obj, $value)
    ; CVAPI(void) cveObjectnessBINGSetNSS(cv::saliency::ObjectnessBING* obj, int value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveObjectnessBINGSetNSS", "ptr", $obj, "int", $value), "cveObjectnessBINGSetNSS", @error)
EndFunc   ;==>_cveObjectnessBINGSetNSS