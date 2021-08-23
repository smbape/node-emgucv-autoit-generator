#include-once
#include "..\..\CVEUtils.au3"

Func _cveFileNodeIsNamed($obj)
    ; CVAPI(bool) cveFileNodeIsNamed(cv::FileNode* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveFileNodeIsNamed", $sObjDllType, $obj), "cveFileNodeIsNamed", @error)
EndFunc   ;==>_cveFileNodeIsNamed

Func _cveFileNodeIsEmpty($obj)
    ; CVAPI(bool) cveFileNodeIsEmpty(cv::FileNode* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveFileNodeIsEmpty", $sObjDllType, $obj), "cveFileNodeIsEmpty", @error)
EndFunc   ;==>_cveFileNodeIsEmpty

Func _cveFileNodeIsNone($obj)
    ; CVAPI(bool) cveFileNodeIsNone(cv::FileNode* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveFileNodeIsNone", $sObjDllType, $obj), "cveFileNodeIsNone", @error)
EndFunc   ;==>_cveFileNodeIsNone

Func _cveFileNodeIsSeq($obj)
    ; CVAPI(bool) cveFileNodeIsSeq(cv::FileNode* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveFileNodeIsSeq", $sObjDllType, $obj), "cveFileNodeIsSeq", @error)
EndFunc   ;==>_cveFileNodeIsSeq

Func _cveFileNodeIsMap($obj)
    ; CVAPI(bool) cveFileNodeIsMap(cv::FileNode* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveFileNodeIsMap", $sObjDllType, $obj), "cveFileNodeIsMap", @error)
EndFunc   ;==>_cveFileNodeIsMap

Func _cveFileNodeIsInt($obj)
    ; CVAPI(bool) cveFileNodeIsInt(cv::FileNode* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveFileNodeIsInt", $sObjDllType, $obj), "cveFileNodeIsInt", @error)
EndFunc   ;==>_cveFileNodeIsInt

Func _cveFileNodeIsReal($obj)
    ; CVAPI(bool) cveFileNodeIsReal(cv::FileNode* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveFileNodeIsReal", $sObjDllType, $obj), "cveFileNodeIsReal", @error)
EndFunc   ;==>_cveFileNodeIsReal

Func _cveFileNodeIsString($obj)
    ; CVAPI(bool) cveFileNodeIsString(cv::FileNode* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveFileNodeIsString", $sObjDllType, $obj), "cveFileNodeIsString", @error)
EndFunc   ;==>_cveFileNodeIsString