#include-once
#include "..\..\CVEUtils.au3"

Func _cveDeviceIsUsb3($obj)
    ; CVAPI(bool) cveDeviceIsUsb3(Device* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveDeviceIsUsb3", $sObjDllType, $obj), "cveDeviceIsUsb3", @error)
EndFunc   ;==>_cveDeviceIsUsb3

Func _cveDeviceIsEepromLoaded($obj)
    ; CVAPI(bool) cveDeviceIsEepromLoaded(Device* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveDeviceIsEepromLoaded", $sObjDllType, $obj), "cveDeviceIsEepromLoaded", @error)
EndFunc   ;==>_cveDeviceIsEepromLoaded

Func _cveDeviceIsRgbConnected($obj)
    ; CVAPI(bool) cveDeviceIsRgbConnected(Device* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveDeviceIsRgbConnected", $sObjDllType, $obj), "cveDeviceIsRgbConnected", @error)
EndFunc   ;==>_cveDeviceIsRgbConnected

Func _cveDeviceIsLeftConnected($obj)
    ; CVAPI(bool) cveDeviceIsLeftConnected(Device* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveDeviceIsLeftConnected", $sObjDllType, $obj), "cveDeviceIsLeftConnected", @error)
EndFunc   ;==>_cveDeviceIsLeftConnected

Func _cveDeviceIsRightConnected($obj)
    ; CVAPI(bool) cveDeviceIsRightConnected(Device* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveDeviceIsRightConnected", $sObjDllType, $obj), "cveDeviceIsRightConnected", @error)
EndFunc   ;==>_cveDeviceIsRightConnected