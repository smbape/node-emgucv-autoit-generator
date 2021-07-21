#include-once
#include "..\..\CVEUtils.au3"

Func _cveStitcherWorkScale($obj)
    ; CVAPI(double) cveStitcherWorkScale(cv::Stitcher* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveStitcherWorkScale", $bObjDllType, $obj), "cveStitcherWorkScale", @error)
EndFunc   ;==>_cveStitcherWorkScale