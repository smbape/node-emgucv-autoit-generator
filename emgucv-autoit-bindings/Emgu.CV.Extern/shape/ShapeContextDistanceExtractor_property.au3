#include-once
#include "..\..\CVEUtils.au3"

Func _cveShapeContextDistanceExtractorGetIterations($obj)
    ; CVAPI(int) cveShapeContextDistanceExtractorGetIterations(cv::ShapeContextDistanceExtractor* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveShapeContextDistanceExtractorGetIterations", $sObjDllType, $obj), "cveShapeContextDistanceExtractorGetIterations", @error)
EndFunc   ;==>_cveShapeContextDistanceExtractorGetIterations

Func _cveShapeContextDistanceExtractorSetIterations($obj, $value)
    ; CVAPI(void) cveShapeContextDistanceExtractorSetIterations(cv::ShapeContextDistanceExtractor* obj, int value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveShapeContextDistanceExtractorSetIterations", $sObjDllType, $obj, "int", $value), "cveShapeContextDistanceExtractorSetIterations", @error)
EndFunc   ;==>_cveShapeContextDistanceExtractorSetIterations

Func _cveShapeContextDistanceExtractorGetAngularBins($obj)
    ; CVAPI(int) cveShapeContextDistanceExtractorGetAngularBins(cv::ShapeContextDistanceExtractor* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveShapeContextDistanceExtractorGetAngularBins", $sObjDllType, $obj), "cveShapeContextDistanceExtractorGetAngularBins", @error)
EndFunc   ;==>_cveShapeContextDistanceExtractorGetAngularBins

Func _cveShapeContextDistanceExtractorSetAngularBins($obj, $value)
    ; CVAPI(void) cveShapeContextDistanceExtractorSetAngularBins(cv::ShapeContextDistanceExtractor* obj, int value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveShapeContextDistanceExtractorSetAngularBins", $sObjDllType, $obj, "int", $value), "cveShapeContextDistanceExtractorSetAngularBins", @error)
EndFunc   ;==>_cveShapeContextDistanceExtractorSetAngularBins

Func _cveShapeContextDistanceExtractorGetRadialBins($obj)
    ; CVAPI(int) cveShapeContextDistanceExtractorGetRadialBins(cv::ShapeContextDistanceExtractor* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveShapeContextDistanceExtractorGetRadialBins", $sObjDllType, $obj), "cveShapeContextDistanceExtractorGetRadialBins", @error)
EndFunc   ;==>_cveShapeContextDistanceExtractorGetRadialBins

Func _cveShapeContextDistanceExtractorSetRadialBins($obj, $value)
    ; CVAPI(void) cveShapeContextDistanceExtractorSetRadialBins(cv::ShapeContextDistanceExtractor* obj, int value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveShapeContextDistanceExtractorSetRadialBins", $sObjDllType, $obj, "int", $value), "cveShapeContextDistanceExtractorSetRadialBins", @error)
EndFunc   ;==>_cveShapeContextDistanceExtractorSetRadialBins

Func _cveShapeContextDistanceExtractorGetInnerRadius($obj)
    ; CVAPI(float) cveShapeContextDistanceExtractorGetInnerRadius(cv::ShapeContextDistanceExtractor* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cveShapeContextDistanceExtractorGetInnerRadius", $sObjDllType, $obj), "cveShapeContextDistanceExtractorGetInnerRadius", @error)
EndFunc   ;==>_cveShapeContextDistanceExtractorGetInnerRadius

Func _cveShapeContextDistanceExtractorSetInnerRadius($obj, $value)
    ; CVAPI(void) cveShapeContextDistanceExtractorSetInnerRadius(cv::ShapeContextDistanceExtractor* obj, float value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveShapeContextDistanceExtractorSetInnerRadius", $sObjDllType, $obj, "float", $value), "cveShapeContextDistanceExtractorSetInnerRadius", @error)
EndFunc   ;==>_cveShapeContextDistanceExtractorSetInnerRadius

Func _cveShapeContextDistanceExtractorGetOuterRadius($obj)
    ; CVAPI(float) cveShapeContextDistanceExtractorGetOuterRadius(cv::ShapeContextDistanceExtractor* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cveShapeContextDistanceExtractorGetOuterRadius", $sObjDllType, $obj), "cveShapeContextDistanceExtractorGetOuterRadius", @error)
EndFunc   ;==>_cveShapeContextDistanceExtractorGetOuterRadius

Func _cveShapeContextDistanceExtractorSetOuterRadius($obj, $value)
    ; CVAPI(void) cveShapeContextDistanceExtractorSetOuterRadius(cv::ShapeContextDistanceExtractor* obj, float value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveShapeContextDistanceExtractorSetOuterRadius", $sObjDllType, $obj, "float", $value), "cveShapeContextDistanceExtractorSetOuterRadius", @error)
EndFunc   ;==>_cveShapeContextDistanceExtractorSetOuterRadius

Func _cveShapeContextDistanceExtractorGetRotationInvariant($obj)
    ; CVAPI(bool) cveShapeContextDistanceExtractorGetRotationInvariant(cv::ShapeContextDistanceExtractor* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveShapeContextDistanceExtractorGetRotationInvariant", $sObjDllType, $obj), "cveShapeContextDistanceExtractorGetRotationInvariant", @error)
EndFunc   ;==>_cveShapeContextDistanceExtractorGetRotationInvariant

Func _cveShapeContextDistanceExtractorSetRotationInvariant($obj, $value)
    ; CVAPI(void) cveShapeContextDistanceExtractorSetRotationInvariant(cv::ShapeContextDistanceExtractor* obj, bool value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveShapeContextDistanceExtractorSetRotationInvariant", $sObjDllType, $obj, "boolean", $value), "cveShapeContextDistanceExtractorSetRotationInvariant", @error)
EndFunc   ;==>_cveShapeContextDistanceExtractorSetRotationInvariant

Func _cveShapeContextDistanceExtractorGetShapeContextWeight($obj)
    ; CVAPI(float) cveShapeContextDistanceExtractorGetShapeContextWeight(cv::ShapeContextDistanceExtractor* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cveShapeContextDistanceExtractorGetShapeContextWeight", $sObjDllType, $obj), "cveShapeContextDistanceExtractorGetShapeContextWeight", @error)
EndFunc   ;==>_cveShapeContextDistanceExtractorGetShapeContextWeight

Func _cveShapeContextDistanceExtractorSetShapeContextWeight($obj, $value)
    ; CVAPI(void) cveShapeContextDistanceExtractorSetShapeContextWeight(cv::ShapeContextDistanceExtractor* obj, float value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveShapeContextDistanceExtractorSetShapeContextWeight", $sObjDllType, $obj, "float", $value), "cveShapeContextDistanceExtractorSetShapeContextWeight", @error)
EndFunc   ;==>_cveShapeContextDistanceExtractorSetShapeContextWeight

Func _cveShapeContextDistanceExtractorGetImageAppearanceWeight($obj)
    ; CVAPI(float) cveShapeContextDistanceExtractorGetImageAppearanceWeight(cv::ShapeContextDistanceExtractor* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cveShapeContextDistanceExtractorGetImageAppearanceWeight", $sObjDllType, $obj), "cveShapeContextDistanceExtractorGetImageAppearanceWeight", @error)
EndFunc   ;==>_cveShapeContextDistanceExtractorGetImageAppearanceWeight

Func _cveShapeContextDistanceExtractorSetImageAppearanceWeight($obj, $value)
    ; CVAPI(void) cveShapeContextDistanceExtractorSetImageAppearanceWeight(cv::ShapeContextDistanceExtractor* obj, float value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveShapeContextDistanceExtractorSetImageAppearanceWeight", $sObjDllType, $obj, "float", $value), "cveShapeContextDistanceExtractorSetImageAppearanceWeight", @error)
EndFunc   ;==>_cveShapeContextDistanceExtractorSetImageAppearanceWeight

Func _cveShapeContextDistanceExtractorGetBendingEnergyWeight($obj)
    ; CVAPI(float) cveShapeContextDistanceExtractorGetBendingEnergyWeight(cv::ShapeContextDistanceExtractor* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cveShapeContextDistanceExtractorGetBendingEnergyWeight", $sObjDllType, $obj), "cveShapeContextDistanceExtractorGetBendingEnergyWeight", @error)
EndFunc   ;==>_cveShapeContextDistanceExtractorGetBendingEnergyWeight

Func _cveShapeContextDistanceExtractorSetBendingEnergyWeight($obj, $value)
    ; CVAPI(void) cveShapeContextDistanceExtractorSetBendingEnergyWeight(cv::ShapeContextDistanceExtractor* obj, float value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveShapeContextDistanceExtractorSetBendingEnergyWeight", $sObjDllType, $obj, "float", $value), "cveShapeContextDistanceExtractorSetBendingEnergyWeight", @error)
EndFunc   ;==>_cveShapeContextDistanceExtractorSetBendingEnergyWeight

Func _cveShapeContextDistanceExtractorGetStdDev($obj)
    ; CVAPI(float) cveShapeContextDistanceExtractorGetStdDev(cv::ShapeContextDistanceExtractor* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cveShapeContextDistanceExtractorGetStdDev", $sObjDllType, $obj), "cveShapeContextDistanceExtractorGetStdDev", @error)
EndFunc   ;==>_cveShapeContextDistanceExtractorGetStdDev

Func _cveShapeContextDistanceExtractorSetStdDev($obj, $value)
    ; CVAPI(void) cveShapeContextDistanceExtractorSetStdDev(cv::ShapeContextDistanceExtractor* obj, float value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveShapeContextDistanceExtractorSetStdDev", $sObjDllType, $obj, "float", $value), "cveShapeContextDistanceExtractorSetStdDev", @error)
EndFunc   ;==>_cveShapeContextDistanceExtractorSetStdDev