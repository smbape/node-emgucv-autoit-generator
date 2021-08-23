#include-once
#include "..\..\CVEUtils.au3"

Func _cveLineIteratorGetCount($obj)
    ; CVAPI(int) cveLineIteratorGetCount(cv::LineIterator* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveLineIteratorGetCount", $sObjDllType, $obj), "cveLineIteratorGetCount", @error)
EndFunc   ;==>_cveLineIteratorGetCount

Func _cveLineIteratorSetCount($obj, $value)
    ; CVAPI(void) cveLineIteratorSetCount(cv::LineIterator* obj, int value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveLineIteratorSetCount", $sObjDllType, $obj, "int", $value), "cveLineIteratorSetCount", @error)
EndFunc   ;==>_cveLineIteratorSetCount