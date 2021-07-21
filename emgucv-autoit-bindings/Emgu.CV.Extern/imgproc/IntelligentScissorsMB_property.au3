#include-once
#include "..\..\CVEUtils.au3"

Func _cveIntelligentScissorsMBSetEdgeFeatureZeroCrossingParameters($obj, $value)
    ; CVAPI(void) cveIntelligentScissorsMBSetEdgeFeatureZeroCrossingParameters(cv::segmentation::IntelligentScissorsMB* obj, float value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveIntelligentScissorsMBSetEdgeFeatureZeroCrossingParameters", $bObjDllType, $obj, "float", $value), "cveIntelligentScissorsMBSetEdgeFeatureZeroCrossingParameters", @error)
EndFunc   ;==>_cveIntelligentScissorsMBSetEdgeFeatureZeroCrossingParameters

Func _cveIntelligentScissorsMBSetGradientMagnitudeMaxLimit($obj, $value)
    ; CVAPI(void) cveIntelligentScissorsMBSetGradientMagnitudeMaxLimit(cv::segmentation::IntelligentScissorsMB* obj, float value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveIntelligentScissorsMBSetGradientMagnitudeMaxLimit", $bObjDllType, $obj, "float", $value), "cveIntelligentScissorsMBSetGradientMagnitudeMaxLimit", @error)
EndFunc   ;==>_cveIntelligentScissorsMBSetGradientMagnitudeMaxLimit