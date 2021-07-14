#include-once
#include <..\..\CVEUtils.au3>

Func _cveIntelligentScissorsMBSetEdgeFeatureZeroCrossingParameters(ByRef $obj, $value)
    ; CVAPI(void) cveIntelligentScissorsMBSetEdgeFeatureZeroCrossingParameters(cv::segmentation::IntelligentScissorsMB* obj, float value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveIntelligentScissorsMBSetEdgeFeatureZeroCrossingParameters", "ptr", $obj, "float", $value), "cveIntelligentScissorsMBSetEdgeFeatureZeroCrossingParameters", @error)
EndFunc   ;==>_cveIntelligentScissorsMBSetEdgeFeatureZeroCrossingParameters

Func _cveIntelligentScissorsMBSetGradientMagnitudeMaxLimit(ByRef $obj, $value)
    ; CVAPI(void) cveIntelligentScissorsMBSetGradientMagnitudeMaxLimit(cv::segmentation::IntelligentScissorsMB* obj, float value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveIntelligentScissorsMBSetGradientMagnitudeMaxLimit", "ptr", $obj, "float", $value), "cveIntelligentScissorsMBSetGradientMagnitudeMaxLimit", @error)
EndFunc   ;==>_cveIntelligentScissorsMBSetGradientMagnitudeMaxLimit