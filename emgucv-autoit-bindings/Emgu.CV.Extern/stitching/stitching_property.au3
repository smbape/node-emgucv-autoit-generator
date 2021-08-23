#include-once
#include "..\..\CVEUtils.au3"

Func _cveStitcherWorkScale($obj)
    ; CVAPI(double) cveStitcherWorkScale(cv::Stitcher* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveStitcherWorkScale", $sObjDllType, $obj), "cveStitcherWorkScale", @error)
EndFunc   ;==>_cveStitcherWorkScale