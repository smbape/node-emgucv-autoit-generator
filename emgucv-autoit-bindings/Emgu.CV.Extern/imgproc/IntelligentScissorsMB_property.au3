#include-once
#include "..\..\CVEUtils.au3"

Func _cveIntelligentScissorsMBSetEdgeFeatureZeroCrossingParameters($obj, $value)
    ; CVAPI(void) cveIntelligentScissorsMBSetEdgeFeatureZeroCrossingParameters(cv::segmentation::IntelligentScissorsMB* obj, float value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveIntelligentScissorsMBSetEdgeFeatureZeroCrossingParameters", $sObjDllType, $obj, "float", $value), "cveIntelligentScissorsMBSetEdgeFeatureZeroCrossingParameters", @error)
EndFunc   ;==>_cveIntelligentScissorsMBSetEdgeFeatureZeroCrossingParameters

Func _cveIntelligentScissorsMBSetGradientMagnitudeMaxLimit($obj, $value)
    ; CVAPI(void) cveIntelligentScissorsMBSetGradientMagnitudeMaxLimit(cv::segmentation::IntelligentScissorsMB* obj, float value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveIntelligentScissorsMBSetGradientMagnitudeMaxLimit", $sObjDllType, $obj, "float", $value), "cveIntelligentScissorsMBSetGradientMagnitudeMaxLimit", @error)
EndFunc   ;==>_cveIntelligentScissorsMBSetGradientMagnitudeMaxLimit