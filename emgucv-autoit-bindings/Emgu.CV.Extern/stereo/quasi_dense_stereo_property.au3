#include-once
#include "..\..\CVEUtils.au3"

Func _cveQuasiDenseStereoGetParam($obj)
    ; CVAPI(cv::stereo::PropagationParameters) cveQuasiDenseStereoGetParam(cv::stereo::QuasiDenseStereo* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveQuasiDenseStereoGetParam", $sObjDllType, $obj), "cveQuasiDenseStereoGetParam", @error)
EndFunc   ;==>_cveQuasiDenseStereoGetParam

Func _cveQuasiDenseStereoSetParam($obj, $value)
    ; CVAPI(void) cveQuasiDenseStereoSetParam(cv::stereo::QuasiDenseStereo* obj, cv::stereo::PropagationParameters value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveQuasiDenseStereoSetParam", $sObjDllType, $obj, "int", $value), "cveQuasiDenseStereoSetParam", @error)
EndFunc   ;==>_cveQuasiDenseStereoSetParam