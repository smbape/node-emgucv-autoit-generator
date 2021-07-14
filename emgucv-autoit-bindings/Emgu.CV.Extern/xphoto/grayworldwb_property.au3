#include-once
#include "..\..\CVEUtils.au3"

Func _cveGrayworldWBGetSaturationThreshold(ByRef $obj)
    ; CVAPI(float) cveGrayworldWBGetSaturationThreshold(cv::xphoto::GrayworldWB* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cveGrayworldWBGetSaturationThreshold", "ptr", $obj), "cveGrayworldWBGetSaturationThreshold", @error)
EndFunc   ;==>_cveGrayworldWBGetSaturationThreshold

Func _cveGrayworldWBSetSaturationThreshold(ByRef $obj, $value)
    ; CVAPI(void) cveGrayworldWBSetSaturationThreshold(cv::xphoto::GrayworldWB* obj, float value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveGrayworldWBSetSaturationThreshold", "ptr", $obj, "float", $value), "cveGrayworldWBSetSaturationThreshold", @error)
EndFunc   ;==>_cveGrayworldWBSetSaturationThreshold