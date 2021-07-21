#include-once
#include "..\..\CVEUtils.au3"

Func _cveLineIteratorGetCount($obj)
    ; CVAPI(int) cveLineIteratorGetCount(cv::LineIterator* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveLineIteratorGetCount", $bObjDllType, $obj), "cveLineIteratorGetCount", @error)
EndFunc   ;==>_cveLineIteratorGetCount

Func _cveLineIteratorSetCount($obj, $value)
    ; CVAPI(void) cveLineIteratorSetCount(cv::LineIterator* obj, int value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveLineIteratorSetCount", $bObjDllType, $obj, "int", $value), "cveLineIteratorSetCount", @error)
EndFunc   ;==>_cveLineIteratorSetCount