#include-once
#include "..\..\CVEUtils.au3"

Func _cveTonemapGetGamma($obj)
    ; CVAPI(float) cveTonemapGetGamma(cv::Tonemap* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cveTonemapGetGamma", $sObjDllType, $obj), "cveTonemapGetGamma", @error)
EndFunc   ;==>_cveTonemapGetGamma

Func _cveTonemapSetGamma($obj, $value)
    ; CVAPI(void) cveTonemapSetGamma(cv::Tonemap* obj, float value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveTonemapSetGamma", $sObjDllType, $obj, "float", $value), "cveTonemapSetGamma", @error)
EndFunc   ;==>_cveTonemapSetGamma