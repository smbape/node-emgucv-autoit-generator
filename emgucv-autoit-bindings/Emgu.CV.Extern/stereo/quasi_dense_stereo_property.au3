#include-once
#include "..\..\CVEUtils.au3"

Func _cveQuasiDenseStereoGetParam(ByRef $obj)
    ; CVAPI(cv::stereo::PropagationParameters) cveQuasiDenseStereoGetParam(cv::stereo::QuasiDenseStereo* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "cv::stereo::PropagationParameters:cdecl", "cveQuasiDenseStereoGetParam", "ptr", $obj), "cveQuasiDenseStereoGetParam", @error)
EndFunc   ;==>_cveQuasiDenseStereoGetParam

Func _cveQuasiDenseStereoSetParam(ByRef $obj, $value)
    ; CVAPI(void) cveQuasiDenseStereoSetParam(cv::stereo::QuasiDenseStereo* obj, cv::stereo::PropagationParameters value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveQuasiDenseStereoSetParam", "ptr", $obj, "cv::stereo::PropagationParameters", $value), "cveQuasiDenseStereoSetParam", @error)
EndFunc   ;==>_cveQuasiDenseStereoSetParam