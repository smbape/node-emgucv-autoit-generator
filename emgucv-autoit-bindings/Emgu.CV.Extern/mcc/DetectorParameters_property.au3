#include-once
#include "..\..\CVEUtils.au3"

Func _cveDetectorParametersGetAdaptiveThreshWinSizeMin($obj)
    ; CVAPI(int) cveDetectorParametersGetAdaptiveThreshWinSizeMin(cv::mcc::DetectorParameters* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveDetectorParametersGetAdaptiveThreshWinSizeMin", $sObjDllType, $obj), "cveDetectorParametersGetAdaptiveThreshWinSizeMin", @error)
EndFunc   ;==>_cveDetectorParametersGetAdaptiveThreshWinSizeMin

Func _cveDetectorParametersSetAdaptiveThreshWinSizeMin($obj, $value)
    ; CVAPI(void) cveDetectorParametersSetAdaptiveThreshWinSizeMin(cv::mcc::DetectorParameters* obj, int value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDetectorParametersSetAdaptiveThreshWinSizeMin", $sObjDllType, $obj, "int", $value), "cveDetectorParametersSetAdaptiveThreshWinSizeMin", @error)
EndFunc   ;==>_cveDetectorParametersSetAdaptiveThreshWinSizeMin

Func _cveDetectorParametersGetAdaptiveThreshWinSizeMax($obj)
    ; CVAPI(int) cveDetectorParametersGetAdaptiveThreshWinSizeMax(cv::mcc::DetectorParameters* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveDetectorParametersGetAdaptiveThreshWinSizeMax", $sObjDllType, $obj), "cveDetectorParametersGetAdaptiveThreshWinSizeMax", @error)
EndFunc   ;==>_cveDetectorParametersGetAdaptiveThreshWinSizeMax

Func _cveDetectorParametersSetAdaptiveThreshWinSizeMax($obj, $value)
    ; CVAPI(void) cveDetectorParametersSetAdaptiveThreshWinSizeMax(cv::mcc::DetectorParameters* obj, int value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDetectorParametersSetAdaptiveThreshWinSizeMax", $sObjDllType, $obj, "int", $value), "cveDetectorParametersSetAdaptiveThreshWinSizeMax", @error)
EndFunc   ;==>_cveDetectorParametersSetAdaptiveThreshWinSizeMax

Func _cveDetectorParametersGetAdaptiveThreshWinSizeStep($obj)
    ; CVAPI(int) cveDetectorParametersGetAdaptiveThreshWinSizeStep(cv::mcc::DetectorParameters* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveDetectorParametersGetAdaptiveThreshWinSizeStep", $sObjDllType, $obj), "cveDetectorParametersGetAdaptiveThreshWinSizeStep", @error)
EndFunc   ;==>_cveDetectorParametersGetAdaptiveThreshWinSizeStep

Func _cveDetectorParametersSetAdaptiveThreshWinSizeStep($obj, $value)
    ; CVAPI(void) cveDetectorParametersSetAdaptiveThreshWinSizeStep(cv::mcc::DetectorParameters* obj, int value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDetectorParametersSetAdaptiveThreshWinSizeStep", $sObjDllType, $obj, "int", $value), "cveDetectorParametersSetAdaptiveThreshWinSizeStep", @error)
EndFunc   ;==>_cveDetectorParametersSetAdaptiveThreshWinSizeStep

Func _cveDetectorParametersGetAdaptiveThreshConstant($obj)
    ; CVAPI(double) cveDetectorParametersGetAdaptiveThreshConstant(cv::mcc::DetectorParameters* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveDetectorParametersGetAdaptiveThreshConstant", $sObjDllType, $obj), "cveDetectorParametersGetAdaptiveThreshConstant", @error)
EndFunc   ;==>_cveDetectorParametersGetAdaptiveThreshConstant

Func _cveDetectorParametersSetAdaptiveThreshConstant($obj, $value)
    ; CVAPI(void) cveDetectorParametersSetAdaptiveThreshConstant(cv::mcc::DetectorParameters* obj, double value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDetectorParametersSetAdaptiveThreshConstant", $sObjDllType, $obj, "double", $value), "cveDetectorParametersSetAdaptiveThreshConstant", @error)
EndFunc   ;==>_cveDetectorParametersSetAdaptiveThreshConstant

Func _cveDetectorParametersGetMinContoursAreaRate($obj)
    ; CVAPI(double) cveDetectorParametersGetMinContoursAreaRate(cv::mcc::DetectorParameters* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveDetectorParametersGetMinContoursAreaRate", $sObjDllType, $obj), "cveDetectorParametersGetMinContoursAreaRate", @error)
EndFunc   ;==>_cveDetectorParametersGetMinContoursAreaRate

Func _cveDetectorParametersSetMinContoursAreaRate($obj, $value)
    ; CVAPI(void) cveDetectorParametersSetMinContoursAreaRate(cv::mcc::DetectorParameters* obj, double value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDetectorParametersSetMinContoursAreaRate", $sObjDllType, $obj, "double", $value), "cveDetectorParametersSetMinContoursAreaRate", @error)
EndFunc   ;==>_cveDetectorParametersSetMinContoursAreaRate

Func _cveDetectorParametersGetMinContoursArea($obj)
    ; CVAPI(double) cveDetectorParametersGetMinContoursArea(cv::mcc::DetectorParameters* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveDetectorParametersGetMinContoursArea", $sObjDllType, $obj), "cveDetectorParametersGetMinContoursArea", @error)
EndFunc   ;==>_cveDetectorParametersGetMinContoursArea

Func _cveDetectorParametersSetMinContoursArea($obj, $value)
    ; CVAPI(void) cveDetectorParametersSetMinContoursArea(cv::mcc::DetectorParameters* obj, double value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDetectorParametersSetMinContoursArea", $sObjDllType, $obj, "double", $value), "cveDetectorParametersSetMinContoursArea", @error)
EndFunc   ;==>_cveDetectorParametersSetMinContoursArea

Func _cveDetectorParametersGetConfidenceThreshold($obj)
    ; CVAPI(double) cveDetectorParametersGetConfidenceThreshold(cv::mcc::DetectorParameters* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveDetectorParametersGetConfidenceThreshold", $sObjDllType, $obj), "cveDetectorParametersGetConfidenceThreshold", @error)
EndFunc   ;==>_cveDetectorParametersGetConfidenceThreshold

Func _cveDetectorParametersSetConfidenceThreshold($obj, $value)
    ; CVAPI(void) cveDetectorParametersSetConfidenceThreshold(cv::mcc::DetectorParameters* obj, double value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDetectorParametersSetConfidenceThreshold", $sObjDllType, $obj, "double", $value), "cveDetectorParametersSetConfidenceThreshold", @error)
EndFunc   ;==>_cveDetectorParametersSetConfidenceThreshold

Func _cveDetectorParametersGetMinContourSolidity($obj)
    ; CVAPI(double) cveDetectorParametersGetMinContourSolidity(cv::mcc::DetectorParameters* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveDetectorParametersGetMinContourSolidity", $sObjDllType, $obj), "cveDetectorParametersGetMinContourSolidity", @error)
EndFunc   ;==>_cveDetectorParametersGetMinContourSolidity

Func _cveDetectorParametersSetMinContourSolidity($obj, $value)
    ; CVAPI(void) cveDetectorParametersSetMinContourSolidity(cv::mcc::DetectorParameters* obj, double value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDetectorParametersSetMinContourSolidity", $sObjDllType, $obj, "double", $value), "cveDetectorParametersSetMinContourSolidity", @error)
EndFunc   ;==>_cveDetectorParametersSetMinContourSolidity

Func _cveDetectorParametersGetFindCandidatesApproxPolyDPEpsMultiplier($obj)
    ; CVAPI(double) cveDetectorParametersGetFindCandidatesApproxPolyDPEpsMultiplier(cv::mcc::DetectorParameters* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveDetectorParametersGetFindCandidatesApproxPolyDPEpsMultiplier", $sObjDllType, $obj), "cveDetectorParametersGetFindCandidatesApproxPolyDPEpsMultiplier", @error)
EndFunc   ;==>_cveDetectorParametersGetFindCandidatesApproxPolyDPEpsMultiplier

Func _cveDetectorParametersSetFindCandidatesApproxPolyDPEpsMultiplier($obj, $value)
    ; CVAPI(void) cveDetectorParametersSetFindCandidatesApproxPolyDPEpsMultiplier(cv::mcc::DetectorParameters* obj, double value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDetectorParametersSetFindCandidatesApproxPolyDPEpsMultiplier", $sObjDllType, $obj, "double", $value), "cveDetectorParametersSetFindCandidatesApproxPolyDPEpsMultiplier", @error)
EndFunc   ;==>_cveDetectorParametersSetFindCandidatesApproxPolyDPEpsMultiplier

Func _cveDetectorParametersGetBorderWidth($obj)
    ; CVAPI(int) cveDetectorParametersGetBorderWidth(cv::mcc::DetectorParameters* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveDetectorParametersGetBorderWidth", $sObjDllType, $obj), "cveDetectorParametersGetBorderWidth", @error)
EndFunc   ;==>_cveDetectorParametersGetBorderWidth

Func _cveDetectorParametersSetBorderWidth($obj, $value)
    ; CVAPI(void) cveDetectorParametersSetBorderWidth(cv::mcc::DetectorParameters* obj, int value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDetectorParametersSetBorderWidth", $sObjDllType, $obj, "int", $value), "cveDetectorParametersSetBorderWidth", @error)
EndFunc   ;==>_cveDetectorParametersSetBorderWidth

Func _cveDetectorParametersGetB0factor($obj)
    ; CVAPI(float) cveDetectorParametersGetB0factor(cv::mcc::DetectorParameters* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cveDetectorParametersGetB0factor", $sObjDllType, $obj), "cveDetectorParametersGetB0factor", @error)
EndFunc   ;==>_cveDetectorParametersGetB0factor

Func _cveDetectorParametersSetB0factor($obj, $value)
    ; CVAPI(void) cveDetectorParametersSetB0factor(cv::mcc::DetectorParameters* obj, float value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDetectorParametersSetB0factor", $sObjDllType, $obj, "float", $value), "cveDetectorParametersSetB0factor", @error)
EndFunc   ;==>_cveDetectorParametersSetB0factor

Func _cveDetectorParametersGetMaxError($obj)
    ; CVAPI(float) cveDetectorParametersGetMaxError(cv::mcc::DetectorParameters* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cveDetectorParametersGetMaxError", $sObjDllType, $obj), "cveDetectorParametersGetMaxError", @error)
EndFunc   ;==>_cveDetectorParametersGetMaxError

Func _cveDetectorParametersSetMaxError($obj, $value)
    ; CVAPI(void) cveDetectorParametersSetMaxError(cv::mcc::DetectorParameters* obj, float value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDetectorParametersSetMaxError", $sObjDllType, $obj, "float", $value), "cveDetectorParametersSetMaxError", @error)
EndFunc   ;==>_cveDetectorParametersSetMaxError

Func _cveDetectorParametersGetMinContourPointsAllowed($obj)
    ; CVAPI(int) cveDetectorParametersGetMinContourPointsAllowed(cv::mcc::DetectorParameters* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveDetectorParametersGetMinContourPointsAllowed", $sObjDllType, $obj), "cveDetectorParametersGetMinContourPointsAllowed", @error)
EndFunc   ;==>_cveDetectorParametersGetMinContourPointsAllowed

Func _cveDetectorParametersSetMinContourPointsAllowed($obj, $value)
    ; CVAPI(void) cveDetectorParametersSetMinContourPointsAllowed(cv::mcc::DetectorParameters* obj, int value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDetectorParametersSetMinContourPointsAllowed", $sObjDllType, $obj, "int", $value), "cveDetectorParametersSetMinContourPointsAllowed", @error)
EndFunc   ;==>_cveDetectorParametersSetMinContourPointsAllowed

Func _cveDetectorParametersGetMinContourLengthAllowed($obj)
    ; CVAPI(int) cveDetectorParametersGetMinContourLengthAllowed(cv::mcc::DetectorParameters* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveDetectorParametersGetMinContourLengthAllowed", $sObjDllType, $obj), "cveDetectorParametersGetMinContourLengthAllowed", @error)
EndFunc   ;==>_cveDetectorParametersGetMinContourLengthAllowed

Func _cveDetectorParametersSetMinContourLengthAllowed($obj, $value)
    ; CVAPI(void) cveDetectorParametersSetMinContourLengthAllowed(cv::mcc::DetectorParameters* obj, int value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDetectorParametersSetMinContourLengthAllowed", $sObjDllType, $obj, "int", $value), "cveDetectorParametersSetMinContourLengthAllowed", @error)
EndFunc   ;==>_cveDetectorParametersSetMinContourLengthAllowed

Func _cveDetectorParametersGetMinInterContourDistance($obj)
    ; CVAPI(int) cveDetectorParametersGetMinInterContourDistance(cv::mcc::DetectorParameters* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveDetectorParametersGetMinInterContourDistance", $sObjDllType, $obj), "cveDetectorParametersGetMinInterContourDistance", @error)
EndFunc   ;==>_cveDetectorParametersGetMinInterContourDistance

Func _cveDetectorParametersSetMinInterContourDistance($obj, $value)
    ; CVAPI(void) cveDetectorParametersSetMinInterContourDistance(cv::mcc::DetectorParameters* obj, int value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDetectorParametersSetMinInterContourDistance", $sObjDllType, $obj, "int", $value), "cveDetectorParametersSetMinInterContourDistance", @error)
EndFunc   ;==>_cveDetectorParametersSetMinInterContourDistance

Func _cveDetectorParametersGetMinInterCheckerDistance($obj)
    ; CVAPI(int) cveDetectorParametersGetMinInterCheckerDistance(cv::mcc::DetectorParameters* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveDetectorParametersGetMinInterCheckerDistance", $sObjDllType, $obj), "cveDetectorParametersGetMinInterCheckerDistance", @error)
EndFunc   ;==>_cveDetectorParametersGetMinInterCheckerDistance

Func _cveDetectorParametersSetMinInterCheckerDistance($obj, $value)
    ; CVAPI(void) cveDetectorParametersSetMinInterCheckerDistance(cv::mcc::DetectorParameters* obj, int value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDetectorParametersSetMinInterCheckerDistance", $sObjDllType, $obj, "int", $value), "cveDetectorParametersSetMinInterCheckerDistance", @error)
EndFunc   ;==>_cveDetectorParametersSetMinInterCheckerDistance

Func _cveDetectorParametersGetMinImageSize($obj)
    ; CVAPI(int) cveDetectorParametersGetMinImageSize(cv::mcc::DetectorParameters* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveDetectorParametersGetMinImageSize", $sObjDllType, $obj), "cveDetectorParametersGetMinImageSize", @error)
EndFunc   ;==>_cveDetectorParametersGetMinImageSize

Func _cveDetectorParametersSetMinImageSize($obj, $value)
    ; CVAPI(void) cveDetectorParametersSetMinImageSize(cv::mcc::DetectorParameters* obj, int value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDetectorParametersSetMinImageSize", $sObjDllType, $obj, "int", $value), "cveDetectorParametersSetMinImageSize", @error)
EndFunc   ;==>_cveDetectorParametersSetMinImageSize

Func _cveDetectorParametersGetMinGroupSize($obj)
    ; CVAPI(unsigned) cveDetectorParametersGetMinGroupSize(cv::mcc::DetectorParameters* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "uint:cdecl", "cveDetectorParametersGetMinGroupSize", $sObjDllType, $obj), "cveDetectorParametersGetMinGroupSize", @error)
EndFunc   ;==>_cveDetectorParametersGetMinGroupSize

Func _cveDetectorParametersSetMinGroupSize($obj, $value)
    ; CVAPI(void) cveDetectorParametersSetMinGroupSize(cv::mcc::DetectorParameters* obj, unsigned value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDetectorParametersSetMinGroupSize", $sObjDllType, $obj, "uint", $value), "cveDetectorParametersSetMinGroupSize", @error)
EndFunc   ;==>_cveDetectorParametersSetMinGroupSize