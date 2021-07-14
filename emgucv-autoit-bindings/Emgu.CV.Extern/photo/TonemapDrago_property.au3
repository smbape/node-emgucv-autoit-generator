#include-once
#include <..\..\CVEUtils.au3>

Func _cveTonemapDragoGetSaturation(ByRef $obj)
    ; CVAPI(float) cveTonemapDragoGetSaturation(cv::TonemapDrago* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cveTonemapDragoGetSaturation", "ptr", $obj), "cveTonemapDragoGetSaturation", @error)
EndFunc   ;==>_cveTonemapDragoGetSaturation

Func _cveTonemapDragoSetSaturation(ByRef $obj, $value)
    ; CVAPI(void) cveTonemapDragoSetSaturation(cv::TonemapDrago* obj, float value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveTonemapDragoSetSaturation", "ptr", $obj, "float", $value), "cveTonemapDragoSetSaturation", @error)
EndFunc   ;==>_cveTonemapDragoSetSaturation

Func _cveTonemapDragoGetBias(ByRef $obj)
    ; CVAPI(float) cveTonemapDragoGetBias(cv::TonemapDrago* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cveTonemapDragoGetBias", "ptr", $obj), "cveTonemapDragoGetBias", @error)
EndFunc   ;==>_cveTonemapDragoGetBias

Func _cveTonemapDragoSetBias(ByRef $obj, $value)
    ; CVAPI(void) cveTonemapDragoSetBias(cv::TonemapDrago* obj, float value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveTonemapDragoSetBias", "ptr", $obj, "float", $value), "cveTonemapDragoSetBias", @error)
EndFunc   ;==>_cveTonemapDragoSetBias