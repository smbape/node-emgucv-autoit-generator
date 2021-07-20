#include-once
#include "..\..\CVEUtils.au3"

Func _cveDetectorParametersGetAdaptiveThreshWinSizeMin($obj)
    ; CVAPI(int) cveDetectorParametersGetAdaptiveThreshWinSizeMin(cv::mcc::DetectorParameters* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveDetectorParametersGetAdaptiveThreshWinSizeMin", "ptr", $obj), "cveDetectorParametersGetAdaptiveThreshWinSizeMin", @error)
EndFunc   ;==>_cveDetectorParametersGetAdaptiveThreshWinSizeMin

Func _cveDetectorParametersSetAdaptiveThreshWinSizeMin($obj, $value)
    ; CVAPI(void) cveDetectorParametersSetAdaptiveThreshWinSizeMin(cv::mcc::DetectorParameters* obj, int value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDetectorParametersSetAdaptiveThreshWinSizeMin", "ptr", $obj, "int", $value), "cveDetectorParametersSetAdaptiveThreshWinSizeMin", @error)
EndFunc   ;==>_cveDetectorParametersSetAdaptiveThreshWinSizeMin

Func _cveDetectorParametersGetAdaptiveThreshWinSizeMax($obj)
    ; CVAPI(int) cveDetectorParametersGetAdaptiveThreshWinSizeMax(cv::mcc::DetectorParameters* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveDetectorParametersGetAdaptiveThreshWinSizeMax", "ptr", $obj), "cveDetectorParametersGetAdaptiveThreshWinSizeMax", @error)
EndFunc   ;==>_cveDetectorParametersGetAdaptiveThreshWinSizeMax

Func _cveDetectorParametersSetAdaptiveThreshWinSizeMax($obj, $value)
    ; CVAPI(void) cveDetectorParametersSetAdaptiveThreshWinSizeMax(cv::mcc::DetectorParameters* obj, int value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDetectorParametersSetAdaptiveThreshWinSizeMax", "ptr", $obj, "int", $value), "cveDetectorParametersSetAdaptiveThreshWinSizeMax", @error)
EndFunc   ;==>_cveDetectorParametersSetAdaptiveThreshWinSizeMax

Func _cveDetectorParametersGetAdaptiveThreshWinSizeStep($obj)
    ; CVAPI(int) cveDetectorParametersGetAdaptiveThreshWinSizeStep(cv::mcc::DetectorParameters* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveDetectorParametersGetAdaptiveThreshWinSizeStep", "ptr", $obj), "cveDetectorParametersGetAdaptiveThreshWinSizeStep", @error)
EndFunc   ;==>_cveDetectorParametersGetAdaptiveThreshWinSizeStep

Func _cveDetectorParametersSetAdaptiveThreshWinSizeStep($obj, $value)
    ; CVAPI(void) cveDetectorParametersSetAdaptiveThreshWinSizeStep(cv::mcc::DetectorParameters* obj, int value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDetectorParametersSetAdaptiveThreshWinSizeStep", "ptr", $obj, "int", $value), "cveDetectorParametersSetAdaptiveThreshWinSizeStep", @error)
EndFunc   ;==>_cveDetectorParametersSetAdaptiveThreshWinSizeStep

Func _cveDetectorParametersGetAdaptiveThreshConstant($obj)
    ; CVAPI(double) cveDetectorParametersGetAdaptiveThreshConstant(cv::mcc::DetectorParameters* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveDetectorParametersGetAdaptiveThreshConstant", "ptr", $obj), "cveDetectorParametersGetAdaptiveThreshConstant", @error)
EndFunc   ;==>_cveDetectorParametersGetAdaptiveThreshConstant

Func _cveDetectorParametersSetAdaptiveThreshConstant($obj, $value)
    ; CVAPI(void) cveDetectorParametersSetAdaptiveThreshConstant(cv::mcc::DetectorParameters* obj, double value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDetectorParametersSetAdaptiveThreshConstant", "ptr", $obj, "double", $value), "cveDetectorParametersSetAdaptiveThreshConstant", @error)
EndFunc   ;==>_cveDetectorParametersSetAdaptiveThreshConstant

Func _cveDetectorParametersGetMinContoursAreaRate($obj)
    ; CVAPI(double) cveDetectorParametersGetMinContoursAreaRate(cv::mcc::DetectorParameters* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveDetectorParametersGetMinContoursAreaRate", "ptr", $obj), "cveDetectorParametersGetMinContoursAreaRate", @error)
EndFunc   ;==>_cveDetectorParametersGetMinContoursAreaRate

Func _cveDetectorParametersSetMinContoursAreaRate($obj, $value)
    ; CVAPI(void) cveDetectorParametersSetMinContoursAreaRate(cv::mcc::DetectorParameters* obj, double value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDetectorParametersSetMinContoursAreaRate", "ptr", $obj, "double", $value), "cveDetectorParametersSetMinContoursAreaRate", @error)
EndFunc   ;==>_cveDetectorParametersSetMinContoursAreaRate

Func _cveDetectorParametersGetMinContoursArea($obj)
    ; CVAPI(double) cveDetectorParametersGetMinContoursArea(cv::mcc::DetectorParameters* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveDetectorParametersGetMinContoursArea", "ptr", $obj), "cveDetectorParametersGetMinContoursArea", @error)
EndFunc   ;==>_cveDetectorParametersGetMinContoursArea

Func _cveDetectorParametersSetMinContoursArea($obj, $value)
    ; CVAPI(void) cveDetectorParametersSetMinContoursArea(cv::mcc::DetectorParameters* obj, double value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDetectorParametersSetMinContoursArea", "ptr", $obj, "double", $value), "cveDetectorParametersSetMinContoursArea", @error)
EndFunc   ;==>_cveDetectorParametersSetMinContoursArea

Func _cveDetectorParametersGetConfidenceThreshold($obj)
    ; CVAPI(double) cveDetectorParametersGetConfidenceThreshold(cv::mcc::DetectorParameters* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveDetectorParametersGetConfidenceThreshold", "ptr", $obj), "cveDetectorParametersGetConfidenceThreshold", @error)
EndFunc   ;==>_cveDetectorParametersGetConfidenceThreshold

Func _cveDetectorParametersSetConfidenceThreshold($obj, $value)
    ; CVAPI(void) cveDetectorParametersSetConfidenceThreshold(cv::mcc::DetectorParameters* obj, double value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDetectorParametersSetConfidenceThreshold", "ptr", $obj, "double", $value), "cveDetectorParametersSetConfidenceThreshold", @error)
EndFunc   ;==>_cveDetectorParametersSetConfidenceThreshold

Func _cveDetectorParametersGetMinContourSolidity($obj)
    ; CVAPI(double) cveDetectorParametersGetMinContourSolidity(cv::mcc::DetectorParameters* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveDetectorParametersGetMinContourSolidity", "ptr", $obj), "cveDetectorParametersGetMinContourSolidity", @error)
EndFunc   ;==>_cveDetectorParametersGetMinContourSolidity

Func _cveDetectorParametersSetMinContourSolidity($obj, $value)
    ; CVAPI(void) cveDetectorParametersSetMinContourSolidity(cv::mcc::DetectorParameters* obj, double value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDetectorParametersSetMinContourSolidity", "ptr", $obj, "double", $value), "cveDetectorParametersSetMinContourSolidity", @error)
EndFunc   ;==>_cveDetectorParametersSetMinContourSolidity

Func _cveDetectorParametersGetFindCandidatesApproxPolyDPEpsMultiplier($obj)
    ; CVAPI(double) cveDetectorParametersGetFindCandidatesApproxPolyDPEpsMultiplier(cv::mcc::DetectorParameters* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveDetectorParametersGetFindCandidatesApproxPolyDPEpsMultiplier", "ptr", $obj), "cveDetectorParametersGetFindCandidatesApproxPolyDPEpsMultiplier", @error)
EndFunc   ;==>_cveDetectorParametersGetFindCandidatesApproxPolyDPEpsMultiplier

Func _cveDetectorParametersSetFindCandidatesApproxPolyDPEpsMultiplier($obj, $value)
    ; CVAPI(void) cveDetectorParametersSetFindCandidatesApproxPolyDPEpsMultiplier(cv::mcc::DetectorParameters* obj, double value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDetectorParametersSetFindCandidatesApproxPolyDPEpsMultiplier", "ptr", $obj, "double", $value), "cveDetectorParametersSetFindCandidatesApproxPolyDPEpsMultiplier", @error)
EndFunc   ;==>_cveDetectorParametersSetFindCandidatesApproxPolyDPEpsMultiplier

Func _cveDetectorParametersGetBorderWidth($obj)
    ; CVAPI(int) cveDetectorParametersGetBorderWidth(cv::mcc::DetectorParameters* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveDetectorParametersGetBorderWidth", "ptr", $obj), "cveDetectorParametersGetBorderWidth", @error)
EndFunc   ;==>_cveDetectorParametersGetBorderWidth

Func _cveDetectorParametersSetBorderWidth($obj, $value)
    ; CVAPI(void) cveDetectorParametersSetBorderWidth(cv::mcc::DetectorParameters* obj, int value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDetectorParametersSetBorderWidth", "ptr", $obj, "int", $value), "cveDetectorParametersSetBorderWidth", @error)
EndFunc   ;==>_cveDetectorParametersSetBorderWidth

Func _cveDetectorParametersGetB0factor($obj)
    ; CVAPI(float) cveDetectorParametersGetB0factor(cv::mcc::DetectorParameters* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cveDetectorParametersGetB0factor", "ptr", $obj), "cveDetectorParametersGetB0factor", @error)
EndFunc   ;==>_cveDetectorParametersGetB0factor

Func _cveDetectorParametersSetB0factor($obj, $value)
    ; CVAPI(void) cveDetectorParametersSetB0factor(cv::mcc::DetectorParameters* obj, float value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDetectorParametersSetB0factor", "ptr", $obj, "float", $value), "cveDetectorParametersSetB0factor", @error)
EndFunc   ;==>_cveDetectorParametersSetB0factor

Func _cveDetectorParametersGetMaxError($obj)
    ; CVAPI(float) cveDetectorParametersGetMaxError(cv::mcc::DetectorParameters* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cveDetectorParametersGetMaxError", "ptr", $obj), "cveDetectorParametersGetMaxError", @error)
EndFunc   ;==>_cveDetectorParametersGetMaxError

Func _cveDetectorParametersSetMaxError($obj, $value)
    ; CVAPI(void) cveDetectorParametersSetMaxError(cv::mcc::DetectorParameters* obj, float value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDetectorParametersSetMaxError", "ptr", $obj, "float", $value), "cveDetectorParametersSetMaxError", @error)
EndFunc   ;==>_cveDetectorParametersSetMaxError

Func _cveDetectorParametersGetMinContourPointsAllowed($obj)
    ; CVAPI(int) cveDetectorParametersGetMinContourPointsAllowed(cv::mcc::DetectorParameters* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveDetectorParametersGetMinContourPointsAllowed", "ptr", $obj), "cveDetectorParametersGetMinContourPointsAllowed", @error)
EndFunc   ;==>_cveDetectorParametersGetMinContourPointsAllowed

Func _cveDetectorParametersSetMinContourPointsAllowed($obj, $value)
    ; CVAPI(void) cveDetectorParametersSetMinContourPointsAllowed(cv::mcc::DetectorParameters* obj, int value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDetectorParametersSetMinContourPointsAllowed", "ptr", $obj, "int", $value), "cveDetectorParametersSetMinContourPointsAllowed", @error)
EndFunc   ;==>_cveDetectorParametersSetMinContourPointsAllowed

Func _cveDetectorParametersGetMinContourLengthAllowed($obj)
    ; CVAPI(int) cveDetectorParametersGetMinContourLengthAllowed(cv::mcc::DetectorParameters* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveDetectorParametersGetMinContourLengthAllowed", "ptr", $obj), "cveDetectorParametersGetMinContourLengthAllowed", @error)
EndFunc   ;==>_cveDetectorParametersGetMinContourLengthAllowed

Func _cveDetectorParametersSetMinContourLengthAllowed($obj, $value)
    ; CVAPI(void) cveDetectorParametersSetMinContourLengthAllowed(cv::mcc::DetectorParameters* obj, int value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDetectorParametersSetMinContourLengthAllowed", "ptr", $obj, "int", $value), "cveDetectorParametersSetMinContourLengthAllowed", @error)
EndFunc   ;==>_cveDetectorParametersSetMinContourLengthAllowed

Func _cveDetectorParametersGetMinInterContourDistance($obj)
    ; CVAPI(int) cveDetectorParametersGetMinInterContourDistance(cv::mcc::DetectorParameters* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveDetectorParametersGetMinInterContourDistance", "ptr", $obj), "cveDetectorParametersGetMinInterContourDistance", @error)
EndFunc   ;==>_cveDetectorParametersGetMinInterContourDistance

Func _cveDetectorParametersSetMinInterContourDistance($obj, $value)
    ; CVAPI(void) cveDetectorParametersSetMinInterContourDistance(cv::mcc::DetectorParameters* obj, int value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDetectorParametersSetMinInterContourDistance", "ptr", $obj, "int", $value), "cveDetectorParametersSetMinInterContourDistance", @error)
EndFunc   ;==>_cveDetectorParametersSetMinInterContourDistance

Func _cveDetectorParametersGetMinInterCheckerDistance($obj)
    ; CVAPI(int) cveDetectorParametersGetMinInterCheckerDistance(cv::mcc::DetectorParameters* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveDetectorParametersGetMinInterCheckerDistance", "ptr", $obj), "cveDetectorParametersGetMinInterCheckerDistance", @error)
EndFunc   ;==>_cveDetectorParametersGetMinInterCheckerDistance

Func _cveDetectorParametersSetMinInterCheckerDistance($obj, $value)
    ; CVAPI(void) cveDetectorParametersSetMinInterCheckerDistance(cv::mcc::DetectorParameters* obj, int value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDetectorParametersSetMinInterCheckerDistance", "ptr", $obj, "int", $value), "cveDetectorParametersSetMinInterCheckerDistance", @error)
EndFunc   ;==>_cveDetectorParametersSetMinInterCheckerDistance

Func _cveDetectorParametersGetMinImageSize($obj)
    ; CVAPI(int) cveDetectorParametersGetMinImageSize(cv::mcc::DetectorParameters* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveDetectorParametersGetMinImageSize", "ptr", $obj), "cveDetectorParametersGetMinImageSize", @error)
EndFunc   ;==>_cveDetectorParametersGetMinImageSize

Func _cveDetectorParametersSetMinImageSize($obj, $value)
    ; CVAPI(void) cveDetectorParametersSetMinImageSize(cv::mcc::DetectorParameters* obj, int value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDetectorParametersSetMinImageSize", "ptr", $obj, "int", $value), "cveDetectorParametersSetMinImageSize", @error)
EndFunc   ;==>_cveDetectorParametersSetMinImageSize

Func _cveDetectorParametersGetMinGroupSize($obj)
    ; CVAPI(unsigned) cveDetectorParametersGetMinGroupSize(cv::mcc::DetectorParameters* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "unsigned:cdecl", "cveDetectorParametersGetMinGroupSize", "ptr", $obj), "cveDetectorParametersGetMinGroupSize", @error)
EndFunc   ;==>_cveDetectorParametersGetMinGroupSize

Func _cveDetectorParametersSetMinGroupSize($obj, $value)
    ; CVAPI(void) cveDetectorParametersSetMinGroupSize(cv::mcc::DetectorParameters* obj, unsigned value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDetectorParametersSetMinGroupSize", "ptr", $obj, "unsigned", $value), "cveDetectorParametersSetMinGroupSize", @error)
EndFunc   ;==>_cveDetectorParametersSetMinGroupSize