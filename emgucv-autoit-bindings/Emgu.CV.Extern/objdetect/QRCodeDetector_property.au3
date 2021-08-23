#include-once
#include "..\..\CVEUtils.au3"

Func _cveQRCodeDetectorSetEpsX($obj, $value)
    ; CVAPI(void) cveQRCodeDetectorSetEpsX(cv::QRCodeDetector* obj, double value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveQRCodeDetectorSetEpsX", $sObjDllType, $obj, "double", $value), "cveQRCodeDetectorSetEpsX", @error)
EndFunc   ;==>_cveQRCodeDetectorSetEpsX

Func _cveQRCodeDetectorSetEpsY($obj, $value)
    ; CVAPI(void) cveQRCodeDetectorSetEpsY(cv::QRCodeDetector* obj, double value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveQRCodeDetectorSetEpsY", $sObjDllType, $obj, "double", $value), "cveQRCodeDetectorSetEpsY", @error)
EndFunc   ;==>_cveQRCodeDetectorSetEpsY