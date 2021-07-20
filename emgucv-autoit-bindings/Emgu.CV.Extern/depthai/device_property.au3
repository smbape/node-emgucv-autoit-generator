#include-once
#include "..\..\CVEUtils.au3"

Func _cveDeviceIsUsb3($obj)
    ; CVAPI(bool) cveDeviceIsUsb3(Device* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveDeviceIsUsb3", "struct*", $obj), "cveDeviceIsUsb3", @error)
EndFunc   ;==>_cveDeviceIsUsb3

Func _cveDeviceIsEepromLoaded($obj)
    ; CVAPI(bool) cveDeviceIsEepromLoaded(Device* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveDeviceIsEepromLoaded", "struct*", $obj), "cveDeviceIsEepromLoaded", @error)
EndFunc   ;==>_cveDeviceIsEepromLoaded

Func _cveDeviceIsRgbConnected($obj)
    ; CVAPI(bool) cveDeviceIsRgbConnected(Device* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveDeviceIsRgbConnected", "struct*", $obj), "cveDeviceIsRgbConnected", @error)
EndFunc   ;==>_cveDeviceIsRgbConnected

Func _cveDeviceIsLeftConnected($obj)
    ; CVAPI(bool) cveDeviceIsLeftConnected(Device* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveDeviceIsLeftConnected", "struct*", $obj), "cveDeviceIsLeftConnected", @error)
EndFunc   ;==>_cveDeviceIsLeftConnected

Func _cveDeviceIsRightConnected($obj)
    ; CVAPI(bool) cveDeviceIsRightConnected(Device* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveDeviceIsRightConnected", "struct*", $obj), "cveDeviceIsRightConnected", @error)
EndFunc   ;==>_cveDeviceIsRightConnected