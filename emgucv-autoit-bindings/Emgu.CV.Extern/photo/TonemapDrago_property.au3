#include-once
#include "..\..\CVEUtils.au3"

Func _cveTonemapDragoGetSaturation($obj)
    ; CVAPI(float) cveTonemapDragoGetSaturation(cv::TonemapDrago* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cveTonemapDragoGetSaturation", $bObjDllType, $obj), "cveTonemapDragoGetSaturation", @error)
EndFunc   ;==>_cveTonemapDragoGetSaturation

Func _cveTonemapDragoSetSaturation($obj, $value)
    ; CVAPI(void) cveTonemapDragoSetSaturation(cv::TonemapDrago* obj, float value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveTonemapDragoSetSaturation", $bObjDllType, $obj, "float", $value), "cveTonemapDragoSetSaturation", @error)
EndFunc   ;==>_cveTonemapDragoSetSaturation

Func _cveTonemapDragoGetBias($obj)
    ; CVAPI(float) cveTonemapDragoGetBias(cv::TonemapDrago* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cveTonemapDragoGetBias", $bObjDllType, $obj), "cveTonemapDragoGetBias", @error)
EndFunc   ;==>_cveTonemapDragoGetBias

Func _cveTonemapDragoSetBias($obj, $value)
    ; CVAPI(void) cveTonemapDragoSetBias(cv::TonemapDrago* obj, float value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveTonemapDragoSetBias", $bObjDllType, $obj, "float", $value), "cveTonemapDragoSetBias", @error)
EndFunc   ;==>_cveTonemapDragoSetBias