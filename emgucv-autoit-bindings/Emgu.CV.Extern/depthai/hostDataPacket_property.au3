#include-once
#include "..\..\CVEUtils.au3"

Func _cveHostDataPacketGetStreamName($obj, $str)
    ; CVAPI(void) cveHostDataPacketGetStreamName(HostDataPacket* obj, cv::String* str);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    Local $bStrIsString = VarGetType($str) == "String"
    If $bStrIsString Then
        $str = _cveStringCreateFromStr($str)
    EndIf

    Local $sStrDllType
    If IsDllStruct($str) Then
        $sStrDllType = "struct*"
    Else
        $sStrDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveHostDataPacketGetStreamName", $sObjDllType, $obj, $sStrDllType, $str), "cveHostDataPacketGetStreamName", @error)

    If $bStrIsString Then
        _cveStringRelease($str)
    EndIf
EndFunc   ;==>_cveHostDataPacketGetStreamName

Func _cveHostDataPacketSize($obj)
    ; CVAPI(int) cveHostDataPacketSize(HostDataPacket* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveHostDataPacketSize", $sObjDllType, $obj), "cveHostDataPacketSize", @error)
EndFunc   ;==>_cveHostDataPacketSize

Func _cveHostDataPacketGetData($obj)
    ; CVAPI(const unsigned char*) cveHostDataPacketGetData(HostDataPacket* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveHostDataPacketGetData", $sObjDllType, $obj), "cveHostDataPacketGetData", @error)
EndFunc   ;==>_cveHostDataPacketGetData

Func _cveHostDataPacketGetElemSize($obj)
    ; CVAPI(int) cveHostDataPacketGetElemSize(HostDataPacket* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveHostDataPacketGetElemSize", $sObjDllType, $obj), "cveHostDataPacketGetElemSize", @error)
EndFunc   ;==>_cveHostDataPacketGetElemSize