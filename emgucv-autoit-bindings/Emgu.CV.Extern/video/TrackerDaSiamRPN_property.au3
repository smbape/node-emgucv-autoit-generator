#include-once
#include "..\..\CVEUtils.au3"

Func _cveTrackerDaSiamRPNGetTrackingScore($obj)
    ; CVAPI(float) cveTrackerDaSiamRPNGetTrackingScore(cv::TrackerDaSiamRPN* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cveTrackerDaSiamRPNGetTrackingScore", $bObjDllType, $obj), "cveTrackerDaSiamRPNGetTrackingScore", @error)
EndFunc   ;==>_cveTrackerDaSiamRPNGetTrackingScore