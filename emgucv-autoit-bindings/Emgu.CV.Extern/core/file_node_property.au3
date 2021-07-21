#include-once
#include "..\..\CVEUtils.au3"

Func _cveFileNodeIsNamed($obj)
    ; CVAPI(bool) cveFileNodeIsNamed(cv::FileNode* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveFileNodeIsNamed", $bObjDllType, $obj), "cveFileNodeIsNamed", @error)
EndFunc   ;==>_cveFileNodeIsNamed

Func _cveFileNodeIsEmpty($obj)
    ; CVAPI(bool) cveFileNodeIsEmpty(cv::FileNode* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveFileNodeIsEmpty", $bObjDllType, $obj), "cveFileNodeIsEmpty", @error)
EndFunc   ;==>_cveFileNodeIsEmpty

Func _cveFileNodeIsNone($obj)
    ; CVAPI(bool) cveFileNodeIsNone(cv::FileNode* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveFileNodeIsNone", $bObjDllType, $obj), "cveFileNodeIsNone", @error)
EndFunc   ;==>_cveFileNodeIsNone

Func _cveFileNodeIsSeq($obj)
    ; CVAPI(bool) cveFileNodeIsSeq(cv::FileNode* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveFileNodeIsSeq", $bObjDllType, $obj), "cveFileNodeIsSeq", @error)
EndFunc   ;==>_cveFileNodeIsSeq

Func _cveFileNodeIsMap($obj)
    ; CVAPI(bool) cveFileNodeIsMap(cv::FileNode* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveFileNodeIsMap", $bObjDllType, $obj), "cveFileNodeIsMap", @error)
EndFunc   ;==>_cveFileNodeIsMap

Func _cveFileNodeIsInt($obj)
    ; CVAPI(bool) cveFileNodeIsInt(cv::FileNode* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveFileNodeIsInt", $bObjDllType, $obj), "cveFileNodeIsInt", @error)
EndFunc   ;==>_cveFileNodeIsInt

Func _cveFileNodeIsReal($obj)
    ; CVAPI(bool) cveFileNodeIsReal(cv::FileNode* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveFileNodeIsReal", $bObjDllType, $obj), "cveFileNodeIsReal", @error)
EndFunc   ;==>_cveFileNodeIsReal

Func _cveFileNodeIsString($obj)
    ; CVAPI(bool) cveFileNodeIsString(cv::FileNode* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveFileNodeIsString", $bObjDllType, $obj), "cveFileNodeIsString", @error)
EndFunc   ;==>_cveFileNodeIsString