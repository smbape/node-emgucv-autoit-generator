#include-once
#include <..\..\CVEUtils.au3>

Func _cveHostDataPacketGetStreamName(ByRef $obj, $str)
    ; CVAPI(void) cveHostDataPacketGetStreamName(HostDataPacket* obj, cv::String* str);

    Local $bStrIsString = VarGetType($str) == "String"
    If $bStrIsString Then
        $str = _cveStringCreateFromStr($str)
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveHostDataPacketGetStreamName", "struct*", $obj, "ptr", $str), "cveHostDataPacketGetStreamName", @error)

    If $bStrIsString Then
        _cveStringRelease($str)
    EndIf
EndFunc   ;==>_cveHostDataPacketGetStreamName

Func _cveHostDataPacketSize(ByRef $obj)
    ; CVAPI(int) cveHostDataPacketSize(HostDataPacket* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveHostDataPacketSize", "struct*", $obj), "cveHostDataPacketSize", @error)
EndFunc   ;==>_cveHostDataPacketSize

Func _cveHostDataPacketGetData(ByRef $obj)
    ; CVAPI(const unsigned char*) cveHostDataPacketGetData(HostDataPacket* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveHostDataPacketGetData", "struct*", $obj), "cveHostDataPacketGetData", @error)
EndFunc   ;==>_cveHostDataPacketGetData

Func _cveHostDataPacketGetElemSize(ByRef $obj)
    ; CVAPI(int) cveHostDataPacketGetElemSize(HostDataPacket* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveHostDataPacketGetElemSize", "struct*", $obj), "cveHostDataPacketGetElemSize", @error)
EndFunc   ;==>_cveHostDataPacketGetElemSize