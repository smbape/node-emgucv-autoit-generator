#include-once
#include "..\..\CVEUtils.au3"

Func _cveTonemapGetGamma($obj)
    ; CVAPI(float) cveTonemapGetGamma(cv::Tonemap* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cveTonemapGetGamma", $bObjDllType, $obj), "cveTonemapGetGamma", @error)
EndFunc   ;==>_cveTonemapGetGamma

Func _cveTonemapSetGamma($obj, $value)
    ; CVAPI(void) cveTonemapSetGamma(cv::Tonemap* obj, float value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveTonemapSetGamma", $bObjDllType, $obj, "float", $value), "cveTonemapSetGamma", @error)
EndFunc   ;==>_cveTonemapSetGamma