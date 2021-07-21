#include-once
#include "..\..\CVEUtils.au3"

Func _cveDeviceIsUsb3($obj)
    ; CVAPI(bool) cveDeviceIsUsb3(Device* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveDeviceIsUsb3", $bObjDllType, $obj), "cveDeviceIsUsb3", @error)
EndFunc   ;==>_cveDeviceIsUsb3

Func _cveDeviceIsEepromLoaded($obj)
    ; CVAPI(bool) cveDeviceIsEepromLoaded(Device* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveDeviceIsEepromLoaded", $bObjDllType, $obj), "cveDeviceIsEepromLoaded", @error)
EndFunc   ;==>_cveDeviceIsEepromLoaded

Func _cveDeviceIsRgbConnected($obj)
    ; CVAPI(bool) cveDeviceIsRgbConnected(Device* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveDeviceIsRgbConnected", $bObjDllType, $obj), "cveDeviceIsRgbConnected", @error)
EndFunc   ;==>_cveDeviceIsRgbConnected

Func _cveDeviceIsLeftConnected($obj)
    ; CVAPI(bool) cveDeviceIsLeftConnected(Device* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveDeviceIsLeftConnected", $bObjDllType, $obj), "cveDeviceIsLeftConnected", @error)
EndFunc   ;==>_cveDeviceIsLeftConnected

Func _cveDeviceIsRightConnected($obj)
    ; CVAPI(bool) cveDeviceIsRightConnected(Device* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveDeviceIsRightConnected", $bObjDllType, $obj), "cveDeviceIsRightConnected", @error)
EndFunc   ;==>_cveDeviceIsRightConnected