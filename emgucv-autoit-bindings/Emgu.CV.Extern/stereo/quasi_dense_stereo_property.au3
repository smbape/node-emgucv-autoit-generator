#include-once
#include "..\..\CVEUtils.au3"

Func _cveQuasiDenseStereoGetParam($obj)
    ; CVAPI(cv::stereo::PropagationParameters) cveQuasiDenseStereoGetParam(cv::stereo::QuasiDenseStereo* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "cv::stereo::PropagationParameters:cdecl", "cveQuasiDenseStereoGetParam", $bObjDllType, $obj), "cveQuasiDenseStereoGetParam", @error)
EndFunc   ;==>_cveQuasiDenseStereoGetParam

Func _cveQuasiDenseStereoSetParam($obj, $value)
    ; CVAPI(void) cveQuasiDenseStereoSetParam(cv::stereo::QuasiDenseStereo* obj, cv::stereo::PropagationParameters value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveQuasiDenseStereoSetParam", $bObjDllType, $obj, "cv::stereo::PropagationParameters", $value), "cveQuasiDenseStereoSetParam", @error)
EndFunc   ;==>_cveQuasiDenseStereoSetParam