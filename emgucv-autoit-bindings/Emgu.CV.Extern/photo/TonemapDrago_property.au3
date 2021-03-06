#include-once
#include "..\..\CVEUtils.au3"

Func _cveTonemapDragoGetSaturation($obj)
    ; CVAPI(float) cveTonemapDragoGetSaturation(cv::TonemapDrago* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cveTonemapDragoGetSaturation", $sObjDllType, $obj), "cveTonemapDragoGetSaturation", @error)
EndFunc   ;==>_cveTonemapDragoGetSaturation

Func _cveTonemapDragoSetSaturation($obj, $value)
    ; CVAPI(void) cveTonemapDragoSetSaturation(cv::TonemapDrago* obj, float value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveTonemapDragoSetSaturation", $sObjDllType, $obj, "float", $value), "cveTonemapDragoSetSaturation", @error)
EndFunc   ;==>_cveTonemapDragoSetSaturation

Func _cveTonemapDragoGetBias($obj)
    ; CVAPI(float) cveTonemapDragoGetBias(cv::TonemapDrago* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cveTonemapDragoGetBias", $sObjDllType, $obj), "cveTonemapDragoGetBias", @error)
EndFunc   ;==>_cveTonemapDragoGetBias

Func _cveTonemapDragoSetBias($obj, $value)
    ; CVAPI(void) cveTonemapDragoSetBias(cv::TonemapDrago* obj, float value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveTonemapDragoSetBias", $sObjDllType, $obj, "float", $value), "cveTonemapDragoSetBias", @error)
EndFunc   ;==>_cveTonemapDragoSetBias