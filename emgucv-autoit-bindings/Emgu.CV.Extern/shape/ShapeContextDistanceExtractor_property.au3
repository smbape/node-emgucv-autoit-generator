#include-once
#include <..\..\CVEUtils.au3>

Func _cveShapeContextDistanceExtractorGetIterations(ByRef $obj)
    ; CVAPI(int) cveShapeContextDistanceExtractorGetIterations(cv::ShapeContextDistanceExtractor* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveShapeContextDistanceExtractorGetIterations", "ptr", $obj), "cveShapeContextDistanceExtractorGetIterations", @error)
EndFunc   ;==>_cveShapeContextDistanceExtractorGetIterations

Func _cveShapeContextDistanceExtractorSetIterations(ByRef $obj, $value)
    ; CVAPI(void) cveShapeContextDistanceExtractorSetIterations(cv::ShapeContextDistanceExtractor* obj, int value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveShapeContextDistanceExtractorSetIterations", "ptr", $obj, "int", $value), "cveShapeContextDistanceExtractorSetIterations", @error)
EndFunc   ;==>_cveShapeContextDistanceExtractorSetIterations

Func _cveShapeContextDistanceExtractorGetAngularBins(ByRef $obj)
    ; CVAPI(int) cveShapeContextDistanceExtractorGetAngularBins(cv::ShapeContextDistanceExtractor* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveShapeContextDistanceExtractorGetAngularBins", "ptr", $obj), "cveShapeContextDistanceExtractorGetAngularBins", @error)
EndFunc   ;==>_cveShapeContextDistanceExtractorGetAngularBins

Func _cveShapeContextDistanceExtractorSetAngularBins(ByRef $obj, $value)
    ; CVAPI(void) cveShapeContextDistanceExtractorSetAngularBins(cv::ShapeContextDistanceExtractor* obj, int value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveShapeContextDistanceExtractorSetAngularBins", "ptr", $obj, "int", $value), "cveShapeContextDistanceExtractorSetAngularBins", @error)
EndFunc   ;==>_cveShapeContextDistanceExtractorSetAngularBins

Func _cveShapeContextDistanceExtractorGetRadialBins(ByRef $obj)
    ; CVAPI(int) cveShapeContextDistanceExtractorGetRadialBins(cv::ShapeContextDistanceExtractor* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveShapeContextDistanceExtractorGetRadialBins", "ptr", $obj), "cveShapeContextDistanceExtractorGetRadialBins", @error)
EndFunc   ;==>_cveShapeContextDistanceExtractorGetRadialBins

Func _cveShapeContextDistanceExtractorSetRadialBins(ByRef $obj, $value)
    ; CVAPI(void) cveShapeContextDistanceExtractorSetRadialBins(cv::ShapeContextDistanceExtractor* obj, int value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveShapeContextDistanceExtractorSetRadialBins", "ptr", $obj, "int", $value), "cveShapeContextDistanceExtractorSetRadialBins", @error)
EndFunc   ;==>_cveShapeContextDistanceExtractorSetRadialBins

Func _cveShapeContextDistanceExtractorGetInnerRadius(ByRef $obj)
    ; CVAPI(float) cveShapeContextDistanceExtractorGetInnerRadius(cv::ShapeContextDistanceExtractor* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cveShapeContextDistanceExtractorGetInnerRadius", "ptr", $obj), "cveShapeContextDistanceExtractorGetInnerRadius", @error)
EndFunc   ;==>_cveShapeContextDistanceExtractorGetInnerRadius

Func _cveShapeContextDistanceExtractorSetInnerRadius(ByRef $obj, $value)
    ; CVAPI(void) cveShapeContextDistanceExtractorSetInnerRadius(cv::ShapeContextDistanceExtractor* obj, float value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveShapeContextDistanceExtractorSetInnerRadius", "ptr", $obj, "float", $value), "cveShapeContextDistanceExtractorSetInnerRadius", @error)
EndFunc   ;==>_cveShapeContextDistanceExtractorSetInnerRadius

Func _cveShapeContextDistanceExtractorGetOuterRadius(ByRef $obj)
    ; CVAPI(float) cveShapeContextDistanceExtractorGetOuterRadius(cv::ShapeContextDistanceExtractor* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cveShapeContextDistanceExtractorGetOuterRadius", "ptr", $obj), "cveShapeContextDistanceExtractorGetOuterRadius", @error)
EndFunc   ;==>_cveShapeContextDistanceExtractorGetOuterRadius

Func _cveShapeContextDistanceExtractorSetOuterRadius(ByRef $obj, $value)
    ; CVAPI(void) cveShapeContextDistanceExtractorSetOuterRadius(cv::ShapeContextDistanceExtractor* obj, float value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveShapeContextDistanceExtractorSetOuterRadius", "ptr", $obj, "float", $value), "cveShapeContextDistanceExtractorSetOuterRadius", @error)
EndFunc   ;==>_cveShapeContextDistanceExtractorSetOuterRadius

Func _cveShapeContextDistanceExtractorGetRotationInvariant(ByRef $obj)
    ; CVAPI(bool) cveShapeContextDistanceExtractorGetRotationInvariant(cv::ShapeContextDistanceExtractor* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveShapeContextDistanceExtractorGetRotationInvariant", "ptr", $obj), "cveShapeContextDistanceExtractorGetRotationInvariant", @error)
EndFunc   ;==>_cveShapeContextDistanceExtractorGetRotationInvariant

Func _cveShapeContextDistanceExtractorSetRotationInvariant(ByRef $obj, $value)
    ; CVAPI(void) cveShapeContextDistanceExtractorSetRotationInvariant(cv::ShapeContextDistanceExtractor* obj, bool value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveShapeContextDistanceExtractorSetRotationInvariant", "ptr", $obj, "boolean", $value), "cveShapeContextDistanceExtractorSetRotationInvariant", @error)
EndFunc   ;==>_cveShapeContextDistanceExtractorSetRotationInvariant

Func _cveShapeContextDistanceExtractorGetShapeContextWeight(ByRef $obj)
    ; CVAPI(float) cveShapeContextDistanceExtractorGetShapeContextWeight(cv::ShapeContextDistanceExtractor* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cveShapeContextDistanceExtractorGetShapeContextWeight", "ptr", $obj), "cveShapeContextDistanceExtractorGetShapeContextWeight", @error)
EndFunc   ;==>_cveShapeContextDistanceExtractorGetShapeContextWeight

Func _cveShapeContextDistanceExtractorSetShapeContextWeight(ByRef $obj, $value)
    ; CVAPI(void) cveShapeContextDistanceExtractorSetShapeContextWeight(cv::ShapeContextDistanceExtractor* obj, float value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveShapeContextDistanceExtractorSetShapeContextWeight", "ptr", $obj, "float", $value), "cveShapeContextDistanceExtractorSetShapeContextWeight", @error)
EndFunc   ;==>_cveShapeContextDistanceExtractorSetShapeContextWeight

Func _cveShapeContextDistanceExtractorGetImageAppearanceWeight(ByRef $obj)
    ; CVAPI(float) cveShapeContextDistanceExtractorGetImageAppearanceWeight(cv::ShapeContextDistanceExtractor* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cveShapeContextDistanceExtractorGetImageAppearanceWeight", "ptr", $obj), "cveShapeContextDistanceExtractorGetImageAppearanceWeight", @error)
EndFunc   ;==>_cveShapeContextDistanceExtractorGetImageAppearanceWeight

Func _cveShapeContextDistanceExtractorSetImageAppearanceWeight(ByRef $obj, $value)
    ; CVAPI(void) cveShapeContextDistanceExtractorSetImageAppearanceWeight(cv::ShapeContextDistanceExtractor* obj, float value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveShapeContextDistanceExtractorSetImageAppearanceWeight", "ptr", $obj, "float", $value), "cveShapeContextDistanceExtractorSetImageAppearanceWeight", @error)
EndFunc   ;==>_cveShapeContextDistanceExtractorSetImageAppearanceWeight

Func _cveShapeContextDistanceExtractorGetBendingEnergyWeight(ByRef $obj)
    ; CVAPI(float) cveShapeContextDistanceExtractorGetBendingEnergyWeight(cv::ShapeContextDistanceExtractor* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cveShapeContextDistanceExtractorGetBendingEnergyWeight", "ptr", $obj), "cveShapeContextDistanceExtractorGetBendingEnergyWeight", @error)
EndFunc   ;==>_cveShapeContextDistanceExtractorGetBendingEnergyWeight

Func _cveShapeContextDistanceExtractorSetBendingEnergyWeight(ByRef $obj, $value)
    ; CVAPI(void) cveShapeContextDistanceExtractorSetBendingEnergyWeight(cv::ShapeContextDistanceExtractor* obj, float value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveShapeContextDistanceExtractorSetBendingEnergyWeight", "ptr", $obj, "float", $value), "cveShapeContextDistanceExtractorSetBendingEnergyWeight", @error)
EndFunc   ;==>_cveShapeContextDistanceExtractorSetBendingEnergyWeight

Func _cveShapeContextDistanceExtractorGetStdDev(ByRef $obj)
    ; CVAPI(float) cveShapeContextDistanceExtractorGetStdDev(cv::ShapeContextDistanceExtractor* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cveShapeContextDistanceExtractorGetStdDev", "ptr", $obj), "cveShapeContextDistanceExtractorGetStdDev", @error)
EndFunc   ;==>_cveShapeContextDistanceExtractorGetStdDev

Func _cveShapeContextDistanceExtractorSetStdDev(ByRef $obj, $value)
    ; CVAPI(void) cveShapeContextDistanceExtractorSetStdDev(cv::ShapeContextDistanceExtractor* obj, float value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveShapeContextDistanceExtractorSetStdDev", "ptr", $obj, "float", $value), "cveShapeContextDistanceExtractorSetStdDev", @error)
EndFunc   ;==>_cveShapeContextDistanceExtractorSetStdDev