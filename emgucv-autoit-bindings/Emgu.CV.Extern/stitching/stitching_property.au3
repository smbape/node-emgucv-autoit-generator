#include-once
#include <..\..\CVEUtils.au3>

Func _cveStitcherWorkScale(ByRef $obj)
    ; CVAPI(double) cveStitcherWorkScale(cv::Stitcher* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveStitcherWorkScale", "ptr", $obj), "cveStitcherWorkScale", @error)
EndFunc   ;==>_cveStitcherWorkScale