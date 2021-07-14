#include-once
#include <..\..\CVEUtils.au3>

Func _cveQRCodeDetectorSetEpsX(ByRef $obj, $value)
    ; CVAPI(void) cveQRCodeDetectorSetEpsX(cv::QRCodeDetector* obj, double value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveQRCodeDetectorSetEpsX", "ptr", $obj, "double", $value), "cveQRCodeDetectorSetEpsX", @error)
EndFunc   ;==>_cveQRCodeDetectorSetEpsX

Func _cveQRCodeDetectorSetEpsY(ByRef $obj, $value)
    ; CVAPI(void) cveQRCodeDetectorSetEpsY(cv::QRCodeDetector* obj, double value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveQRCodeDetectorSetEpsY", "ptr", $obj, "double", $value), "cveQRCodeDetectorSetEpsY", @error)
EndFunc   ;==>_cveQRCodeDetectorSetEpsY