#include-once
#include "..\..\CVEUtils.au3"

Func _cveShapeContextDistanceExtractorGetIterations($obj)
    ; CVAPI(int) cveShapeContextDistanceExtractorGetIterations(cv::ShapeContextDistanceExtractor* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveShapeContextDistanceExtractorGetIterations", $bObjDllType, $obj), "cveShapeContextDistanceExtractorGetIterations", @error)
EndFunc   ;==>_cveShapeContextDistanceExtractorGetIterations

Func _cveShapeContextDistanceExtractorSetIterations($obj, $value)
    ; CVAPI(void) cveShapeContextDistanceExtractorSetIterations(cv::ShapeContextDistanceExtractor* obj, int value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveShapeContextDistanceExtractorSetIterations", $bObjDllType, $obj, "int", $value), "cveShapeContextDistanceExtractorSetIterations", @error)
EndFunc   ;==>_cveShapeContextDistanceExtractorSetIterations

Func _cveShapeContextDistanceExtractorGetAngularBins($obj)
    ; CVAPI(int) cveShapeContextDistanceExtractorGetAngularBins(cv::ShapeContextDistanceExtractor* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveShapeContextDistanceExtractorGetAngularBins", $bObjDllType, $obj), "cveShapeContextDistanceExtractorGetAngularBins", @error)
EndFunc   ;==>_cveShapeContextDistanceExtractorGetAngularBins

Func _cveShapeContextDistanceExtractorSetAngularBins($obj, $value)
    ; CVAPI(void) cveShapeContextDistanceExtractorSetAngularBins(cv::ShapeContextDistanceExtractor* obj, int value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveShapeContextDistanceExtractorSetAngularBins", $bObjDllType, $obj, "int", $value), "cveShapeContextDistanceExtractorSetAngularBins", @error)
EndFunc   ;==>_cveShapeContextDistanceExtractorSetAngularBins

Func _cveShapeContextDistanceExtractorGetRadialBins($obj)
    ; CVAPI(int) cveShapeContextDistanceExtractorGetRadialBins(cv::ShapeContextDistanceExtractor* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveShapeContextDistanceExtractorGetRadialBins", $bObjDllType, $obj), "cveShapeContextDistanceExtractorGetRadialBins", @error)
EndFunc   ;==>_cveShapeContextDistanceExtractorGetRadialBins

Func _cveShapeContextDistanceExtractorSetRadialBins($obj, $value)
    ; CVAPI(void) cveShapeContextDistanceExtractorSetRadialBins(cv::ShapeContextDistanceExtractor* obj, int value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveShapeContextDistanceExtractorSetRadialBins", $bObjDllType, $obj, "int", $value), "cveShapeContextDistanceExtractorSetRadialBins", @error)
EndFunc   ;==>_cveShapeContextDistanceExtractorSetRadialBins

Func _cveShapeContextDistanceExtractorGetInnerRadius($obj)
    ; CVAPI(float) cveShapeContextDistanceExtractorGetInnerRadius(cv::ShapeContextDistanceExtractor* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cveShapeContextDistanceExtractorGetInnerRadius", $bObjDllType, $obj), "cveShapeContextDistanceExtractorGetInnerRadius", @error)
EndFunc   ;==>_cveShapeContextDistanceExtractorGetInnerRadius

Func _cveShapeContextDistanceExtractorSetInnerRadius($obj, $value)
    ; CVAPI(void) cveShapeContextDistanceExtractorSetInnerRadius(cv::ShapeContextDistanceExtractor* obj, float value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveShapeContextDistanceExtractorSetInnerRadius", $bObjDllType, $obj, "float", $value), "cveShapeContextDistanceExtractorSetInnerRadius", @error)
EndFunc   ;==>_cveShapeContextDistanceExtractorSetInnerRadius

Func _cveShapeContextDistanceExtractorGetOuterRadius($obj)
    ; CVAPI(float) cveShapeContextDistanceExtractorGetOuterRadius(cv::ShapeContextDistanceExtractor* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cveShapeContextDistanceExtractorGetOuterRadius", $bObjDllType, $obj), "cveShapeContextDistanceExtractorGetOuterRadius", @error)
EndFunc   ;==>_cveShapeContextDistanceExtractorGetOuterRadius

Func _cveShapeContextDistanceExtractorSetOuterRadius($obj, $value)
    ; CVAPI(void) cveShapeContextDistanceExtractorSetOuterRadius(cv::ShapeContextDistanceExtractor* obj, float value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveShapeContextDistanceExtractorSetOuterRadius", $bObjDllType, $obj, "float", $value), "cveShapeContextDistanceExtractorSetOuterRadius", @error)
EndFunc   ;==>_cveShapeContextDistanceExtractorSetOuterRadius

Func _cveShapeContextDistanceExtractorGetRotationInvariant($obj)
    ; CVAPI(bool) cveShapeContextDistanceExtractorGetRotationInvariant(cv::ShapeContextDistanceExtractor* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveShapeContextDistanceExtractorGetRotationInvariant", $bObjDllType, $obj), "cveShapeContextDistanceExtractorGetRotationInvariant", @error)
EndFunc   ;==>_cveShapeContextDistanceExtractorGetRotationInvariant

Func _cveShapeContextDistanceExtractorSetRotationInvariant($obj, $value)
    ; CVAPI(void) cveShapeContextDistanceExtractorSetRotationInvariant(cv::ShapeContextDistanceExtractor* obj, bool value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveShapeContextDistanceExtractorSetRotationInvariant", $bObjDllType, $obj, "boolean", $value), "cveShapeContextDistanceExtractorSetRotationInvariant", @error)
EndFunc   ;==>_cveShapeContextDistanceExtractorSetRotationInvariant

Func _cveShapeContextDistanceExtractorGetShapeContextWeight($obj)
    ; CVAPI(float) cveShapeContextDistanceExtractorGetShapeContextWeight(cv::ShapeContextDistanceExtractor* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cveShapeContextDistanceExtractorGetShapeContextWeight", $bObjDllType, $obj), "cveShapeContextDistanceExtractorGetShapeContextWeight", @error)
EndFunc   ;==>_cveShapeContextDistanceExtractorGetShapeContextWeight

Func _cveShapeContextDistanceExtractorSetShapeContextWeight($obj, $value)
    ; CVAPI(void) cveShapeContextDistanceExtractorSetShapeContextWeight(cv::ShapeContextDistanceExtractor* obj, float value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveShapeContextDistanceExtractorSetShapeContextWeight", $bObjDllType, $obj, "float", $value), "cveShapeContextDistanceExtractorSetShapeContextWeight", @error)
EndFunc   ;==>_cveShapeContextDistanceExtractorSetShapeContextWeight

Func _cveShapeContextDistanceExtractorGetImageAppearanceWeight($obj)
    ; CVAPI(float) cveShapeContextDistanceExtractorGetImageAppearanceWeight(cv::ShapeContextDistanceExtractor* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cveShapeContextDistanceExtractorGetImageAppearanceWeight", $bObjDllType, $obj), "cveShapeContextDistanceExtractorGetImageAppearanceWeight", @error)
EndFunc   ;==>_cveShapeContextDistanceExtractorGetImageAppearanceWeight

Func _cveShapeContextDistanceExtractorSetImageAppearanceWeight($obj, $value)
    ; CVAPI(void) cveShapeContextDistanceExtractorSetImageAppearanceWeight(cv::ShapeContextDistanceExtractor* obj, float value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveShapeContextDistanceExtractorSetImageAppearanceWeight", $bObjDllType, $obj, "float", $value), "cveShapeContextDistanceExtractorSetImageAppearanceWeight", @error)
EndFunc   ;==>_cveShapeContextDistanceExtractorSetImageAppearanceWeight

Func _cveShapeContextDistanceExtractorGetBendingEnergyWeight($obj)
    ; CVAPI(float) cveShapeContextDistanceExtractorGetBendingEnergyWeight(cv::ShapeContextDistanceExtractor* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cveShapeContextDistanceExtractorGetBendingEnergyWeight", $bObjDllType, $obj), "cveShapeContextDistanceExtractorGetBendingEnergyWeight", @error)
EndFunc   ;==>_cveShapeContextDistanceExtractorGetBendingEnergyWeight

Func _cveShapeContextDistanceExtractorSetBendingEnergyWeight($obj, $value)
    ; CVAPI(void) cveShapeContextDistanceExtractorSetBendingEnergyWeight(cv::ShapeContextDistanceExtractor* obj, float value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveShapeContextDistanceExtractorSetBendingEnergyWeight", $bObjDllType, $obj, "float", $value), "cveShapeContextDistanceExtractorSetBendingEnergyWeight", @error)
EndFunc   ;==>_cveShapeContextDistanceExtractorSetBendingEnergyWeight

Func _cveShapeContextDistanceExtractorGetStdDev($obj)
    ; CVAPI(float) cveShapeContextDistanceExtractorGetStdDev(cv::ShapeContextDistanceExtractor* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cveShapeContextDistanceExtractorGetStdDev", $bObjDllType, $obj), "cveShapeContextDistanceExtractorGetStdDev", @error)
EndFunc   ;==>_cveShapeContextDistanceExtractorGetStdDev

Func _cveShapeContextDistanceExtractorSetStdDev($obj, $value)
    ; CVAPI(void) cveShapeContextDistanceExtractorSetStdDev(cv::ShapeContextDistanceExtractor* obj, float value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveShapeContextDistanceExtractorSetStdDev", $bObjDllType, $obj, "float", $value), "cveShapeContextDistanceExtractorSetStdDev", @error)
EndFunc   ;==>_cveShapeContextDistanceExtractorSetStdDev