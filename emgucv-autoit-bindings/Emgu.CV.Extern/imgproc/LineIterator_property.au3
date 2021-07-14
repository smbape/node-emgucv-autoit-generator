#include-once
#include <..\..\CVEUtils.au3>

Func _cveLineIteratorGetCount(ByRef $obj)
    ; CVAPI(int) cveLineIteratorGetCount(cv::LineIterator* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveLineIteratorGetCount", "ptr", $obj), "cveLineIteratorGetCount", @error)
EndFunc   ;==>_cveLineIteratorGetCount

Func _cveLineIteratorSetCount(ByRef $obj, $value)
    ; CVAPI(void) cveLineIteratorSetCount(cv::LineIterator* obj, int value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveLineIteratorSetCount", "ptr", $obj, "int", $value), "cveLineIteratorSetCount", @error)
EndFunc   ;==>_cveLineIteratorSetCount