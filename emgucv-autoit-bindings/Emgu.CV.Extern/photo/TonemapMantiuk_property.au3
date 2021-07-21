#include-once
#include "..\..\CVEUtils.au3"

Func _cveTonemapMantiukGetSaturation($obj)
    ; CVAPI(float) cveTonemapMantiukGetSaturation(cv::TonemapMantiuk* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cveTonemapMantiukGetSaturation", $bObjDllType, $obj), "cveTonemapMantiukGetSaturation", @error)
EndFunc   ;==>_cveTonemapMantiukGetSaturation

Func _cveTonemapMantiukSetSaturation($obj, $value)
    ; CVAPI(void) cveTonemapMantiukSetSaturation(cv::TonemapMantiuk* obj, float value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveTonemapMantiukSetSaturation", $bObjDllType, $obj, "float", $value), "cveTonemapMantiukSetSaturation", @error)
EndFunc   ;==>_cveTonemapMantiukSetSaturation

Func _cveTonemapMantiukGetScale($obj)
    ; CVAPI(float) cveTonemapMantiukGetScale(cv::TonemapMantiuk* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cveTonemapMantiukGetScale", $bObjDllType, $obj), "cveTonemapMantiukGetScale", @error)
EndFunc   ;==>_cveTonemapMantiukGetScale

Func _cveTonemapMantiukSetScale($obj, $value)
    ; CVAPI(void) cveTonemapMantiukSetScale(cv::TonemapMantiuk* obj, float value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveTonemapMantiukSetScale", $bObjDllType, $obj, "float", $value), "cveTonemapMantiukSetScale", @error)
EndFunc   ;==>_cveTonemapMantiukSetScale