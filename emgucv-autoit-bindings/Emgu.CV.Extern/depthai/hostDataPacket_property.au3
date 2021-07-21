#include-once
#include "..\..\CVEUtils.au3"

Func _cveHostDataPacketGetStreamName($obj, $str)
    ; CVAPI(void) cveHostDataPacketGetStreamName(HostDataPacket* obj, cv::String* str);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    Local $bStrIsString = VarGetType($str) == "String"
    If $bStrIsString Then
        $str = _cveStringCreateFromStr($str)
    EndIf

    Local $bStrDllType
    If VarGetType($str) == "DLLStruct" Then
        $bStrDllType = "struct*"
    Else
        $bStrDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveHostDataPacketGetStreamName", $bObjDllType, $obj, $bStrDllType, $str), "cveHostDataPacketGetStreamName", @error)

    If $bStrIsString Then
        _cveStringRelease($str)
    EndIf
EndFunc   ;==>_cveHostDataPacketGetStreamName

Func _cveHostDataPacketSize($obj)
    ; CVAPI(int) cveHostDataPacketSize(HostDataPacket* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveHostDataPacketSize", $bObjDllType, $obj), "cveHostDataPacketSize", @error)
EndFunc   ;==>_cveHostDataPacketSize

Func _cveHostDataPacketGetData($obj)
    ; CVAPI(const unsigned char*) cveHostDataPacketGetData(HostDataPacket* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveHostDataPacketGetData", $bObjDllType, $obj), "cveHostDataPacketGetData", @error)
EndFunc   ;==>_cveHostDataPacketGetData

Func _cveHostDataPacketGetElemSize($obj)
    ; CVAPI(int) cveHostDataPacketGetElemSize(HostDataPacket* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveHostDataPacketGetElemSize", $bObjDllType, $obj), "cveHostDataPacketGetElemSize", @error)
EndFunc   ;==>_cveHostDataPacketGetElemSize