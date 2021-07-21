#include-once
#include "..\..\CVEUtils.au3"

Func _cveGrayworldWBGetSaturationThreshold($obj)
    ; CVAPI(float) cveGrayworldWBGetSaturationThreshold(cv::xphoto::GrayworldWB* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cveGrayworldWBGetSaturationThreshold", $bObjDllType, $obj), "cveGrayworldWBGetSaturationThreshold", @error)
EndFunc   ;==>_cveGrayworldWBGetSaturationThreshold

Func _cveGrayworldWBSetSaturationThreshold($obj, $value)
    ; CVAPI(void) cveGrayworldWBSetSaturationThreshold(cv::xphoto::GrayworldWB* obj, float value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveGrayworldWBSetSaturationThreshold", $bObjDllType, $obj, "float", $value), "cveGrayworldWBSetSaturationThreshold", @error)
EndFunc   ;==>_cveGrayworldWBSetSaturationThreshold