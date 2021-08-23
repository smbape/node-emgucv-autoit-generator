#include-once
#include "..\..\CVEUtils.au3"

Func _cveGrayworldWBGetSaturationThreshold($obj)
    ; CVAPI(float) cveGrayworldWBGetSaturationThreshold(cv::xphoto::GrayworldWB* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cveGrayworldWBGetSaturationThreshold", $sObjDllType, $obj), "cveGrayworldWBGetSaturationThreshold", @error)
EndFunc   ;==>_cveGrayworldWBGetSaturationThreshold

Func _cveGrayworldWBSetSaturationThreshold($obj, $value)
    ; CVAPI(void) cveGrayworldWBSetSaturationThreshold(cv::xphoto::GrayworldWB* obj, float value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveGrayworldWBSetSaturationThreshold", $sObjDllType, $obj, "float", $value), "cveGrayworldWBSetSaturationThreshold", @error)
EndFunc   ;==>_cveGrayworldWBSetSaturationThreshold