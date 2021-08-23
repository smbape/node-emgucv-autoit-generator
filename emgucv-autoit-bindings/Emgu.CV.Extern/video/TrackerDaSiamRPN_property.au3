#include-once
#include "..\..\CVEUtils.au3"

Func _cveTrackerDaSiamRPNGetTrackingScore($obj)
    ; CVAPI(float) cveTrackerDaSiamRPNGetTrackingScore(cv::TrackerDaSiamRPN* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cveTrackerDaSiamRPNGetTrackingScore", $sObjDllType, $obj), "cveTrackerDaSiamRPNGetTrackingScore", @error)
EndFunc   ;==>_cveTrackerDaSiamRPNGetTrackingScore