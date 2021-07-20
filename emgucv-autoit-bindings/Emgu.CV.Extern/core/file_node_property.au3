#include-once
#include "..\..\CVEUtils.au3"

Func _cveFileNodeIsNamed($obj)
    ; CVAPI(bool) cveFileNodeIsNamed(cv::FileNode* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveFileNodeIsNamed", "ptr", $obj), "cveFileNodeIsNamed", @error)
EndFunc   ;==>_cveFileNodeIsNamed

Func _cveFileNodeIsEmpty($obj)
    ; CVAPI(bool) cveFileNodeIsEmpty(cv::FileNode* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveFileNodeIsEmpty", "ptr", $obj), "cveFileNodeIsEmpty", @error)
EndFunc   ;==>_cveFileNodeIsEmpty

Func _cveFileNodeIsNone($obj)
    ; CVAPI(bool) cveFileNodeIsNone(cv::FileNode* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveFileNodeIsNone", "ptr", $obj), "cveFileNodeIsNone", @error)
EndFunc   ;==>_cveFileNodeIsNone

Func _cveFileNodeIsSeq($obj)
    ; CVAPI(bool) cveFileNodeIsSeq(cv::FileNode* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveFileNodeIsSeq", "ptr", $obj), "cveFileNodeIsSeq", @error)
EndFunc   ;==>_cveFileNodeIsSeq

Func _cveFileNodeIsMap($obj)
    ; CVAPI(bool) cveFileNodeIsMap(cv::FileNode* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveFileNodeIsMap", "ptr", $obj), "cveFileNodeIsMap", @error)
EndFunc   ;==>_cveFileNodeIsMap

Func _cveFileNodeIsInt($obj)
    ; CVAPI(bool) cveFileNodeIsInt(cv::FileNode* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveFileNodeIsInt", "ptr", $obj), "cveFileNodeIsInt", @error)
EndFunc   ;==>_cveFileNodeIsInt

Func _cveFileNodeIsReal($obj)
    ; CVAPI(bool) cveFileNodeIsReal(cv::FileNode* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveFileNodeIsReal", "ptr", $obj), "cveFileNodeIsReal", @error)
EndFunc   ;==>_cveFileNodeIsReal

Func _cveFileNodeIsString($obj)
    ; CVAPI(bool) cveFileNodeIsString(cv::FileNode* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveFileNodeIsString", "ptr", $obj), "cveFileNodeIsString", @error)
EndFunc   ;==>_cveFileNodeIsString