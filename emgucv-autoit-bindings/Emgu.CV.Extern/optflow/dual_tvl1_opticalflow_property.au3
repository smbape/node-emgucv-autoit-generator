#include-once
#include "..\..\CVEUtils.au3"

Func _cveDualTVL1OpticalFlowGetTau(ByRef $obj)
    ; CVAPI(double) cveDualTVL1OpticalFlowGetTau(cv::optflow::DualTVL1OpticalFlow* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveDualTVL1OpticalFlowGetTau", "ptr", $obj), "cveDualTVL1OpticalFlowGetTau", @error)
EndFunc   ;==>_cveDualTVL1OpticalFlowGetTau

Func _cveDualTVL1OpticalFlowSetTau(ByRef $obj, $value)
    ; CVAPI(void) cveDualTVL1OpticalFlowSetTau(cv::optflow::DualTVL1OpticalFlow* obj, double value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDualTVL1OpticalFlowSetTau", "ptr", $obj, "double", $value), "cveDualTVL1OpticalFlowSetTau", @error)
EndFunc   ;==>_cveDualTVL1OpticalFlowSetTau

Func _cveDualTVL1OpticalFlowGetLambda(ByRef $obj)
    ; CVAPI(double) cveDualTVL1OpticalFlowGetLambda(cv::optflow::DualTVL1OpticalFlow* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveDualTVL1OpticalFlowGetLambda", "ptr", $obj), "cveDualTVL1OpticalFlowGetLambda", @error)
EndFunc   ;==>_cveDualTVL1OpticalFlowGetLambda

Func _cveDualTVL1OpticalFlowSetLambda(ByRef $obj, $value)
    ; CVAPI(void) cveDualTVL1OpticalFlowSetLambda(cv::optflow::DualTVL1OpticalFlow* obj, double value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDualTVL1OpticalFlowSetLambda", "ptr", $obj, "double", $value), "cveDualTVL1OpticalFlowSetLambda", @error)
EndFunc   ;==>_cveDualTVL1OpticalFlowSetLambda

Func _cveDualTVL1OpticalFlowGetTheta(ByRef $obj)
    ; CVAPI(double) cveDualTVL1OpticalFlowGetTheta(cv::optflow::DualTVL1OpticalFlow* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveDualTVL1OpticalFlowGetTheta", "ptr", $obj), "cveDualTVL1OpticalFlowGetTheta", @error)
EndFunc   ;==>_cveDualTVL1OpticalFlowGetTheta

Func _cveDualTVL1OpticalFlowSetTheta(ByRef $obj, $value)
    ; CVAPI(void) cveDualTVL1OpticalFlowSetTheta(cv::optflow::DualTVL1OpticalFlow* obj, double value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDualTVL1OpticalFlowSetTheta", "ptr", $obj, "double", $value), "cveDualTVL1OpticalFlowSetTheta", @error)
EndFunc   ;==>_cveDualTVL1OpticalFlowSetTheta

Func _cveDualTVL1OpticalFlowGetGamma(ByRef $obj)
    ; CVAPI(double) cveDualTVL1OpticalFlowGetGamma(cv::optflow::DualTVL1OpticalFlow* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveDualTVL1OpticalFlowGetGamma", "ptr", $obj), "cveDualTVL1OpticalFlowGetGamma", @error)
EndFunc   ;==>_cveDualTVL1OpticalFlowGetGamma

Func _cveDualTVL1OpticalFlowSetGamma(ByRef $obj, $value)
    ; CVAPI(void) cveDualTVL1OpticalFlowSetGamma(cv::optflow::DualTVL1OpticalFlow* obj, double value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDualTVL1OpticalFlowSetGamma", "ptr", $obj, "double", $value), "cveDualTVL1OpticalFlowSetGamma", @error)
EndFunc   ;==>_cveDualTVL1OpticalFlowSetGamma

Func _cveDualTVL1OpticalFlowGetScalesNumber(ByRef $obj)
    ; CVAPI(int) cveDualTVL1OpticalFlowGetScalesNumber(cv::optflow::DualTVL1OpticalFlow* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveDualTVL1OpticalFlowGetScalesNumber", "ptr", $obj), "cveDualTVL1OpticalFlowGetScalesNumber", @error)
EndFunc   ;==>_cveDualTVL1OpticalFlowGetScalesNumber

Func _cveDualTVL1OpticalFlowSetScalesNumber(ByRef $obj, $value)
    ; CVAPI(void) cveDualTVL1OpticalFlowSetScalesNumber(cv::optflow::DualTVL1OpticalFlow* obj, int value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDualTVL1OpticalFlowSetScalesNumber", "ptr", $obj, "int", $value), "cveDualTVL1OpticalFlowSetScalesNumber", @error)
EndFunc   ;==>_cveDualTVL1OpticalFlowSetScalesNumber

Func _cveDualTVL1OpticalFlowGetWarpingsNumber(ByRef $obj)
    ; CVAPI(int) cveDualTVL1OpticalFlowGetWarpingsNumber(cv::optflow::DualTVL1OpticalFlow* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveDualTVL1OpticalFlowGetWarpingsNumber", "ptr", $obj), "cveDualTVL1OpticalFlowGetWarpingsNumber", @error)
EndFunc   ;==>_cveDualTVL1OpticalFlowGetWarpingsNumber

Func _cveDualTVL1OpticalFlowSetWarpingsNumber(ByRef $obj, $value)
    ; CVAPI(void) cveDualTVL1OpticalFlowSetWarpingsNumber(cv::optflow::DualTVL1OpticalFlow* obj, int value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDualTVL1OpticalFlowSetWarpingsNumber", "ptr", $obj, "int", $value), "cveDualTVL1OpticalFlowSetWarpingsNumber", @error)
EndFunc   ;==>_cveDualTVL1OpticalFlowSetWarpingsNumber

Func _cveDualTVL1OpticalFlowGetEpsilon(ByRef $obj)
    ; CVAPI(double) cveDualTVL1OpticalFlowGetEpsilon(cv::optflow::DualTVL1OpticalFlow* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveDualTVL1OpticalFlowGetEpsilon", "ptr", $obj), "cveDualTVL1OpticalFlowGetEpsilon", @error)
EndFunc   ;==>_cveDualTVL1OpticalFlowGetEpsilon

Func _cveDualTVL1OpticalFlowSetEpsilon(ByRef $obj, $value)
    ; CVAPI(void) cveDualTVL1OpticalFlowSetEpsilon(cv::optflow::DualTVL1OpticalFlow* obj, double value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDualTVL1OpticalFlowSetEpsilon", "ptr", $obj, "double", $value), "cveDualTVL1OpticalFlowSetEpsilon", @error)
EndFunc   ;==>_cveDualTVL1OpticalFlowSetEpsilon

Func _cveDualTVL1OpticalFlowGetInnerIterations(ByRef $obj)
    ; CVAPI(int) cveDualTVL1OpticalFlowGetInnerIterations(cv::optflow::DualTVL1OpticalFlow* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveDualTVL1OpticalFlowGetInnerIterations", "ptr", $obj), "cveDualTVL1OpticalFlowGetInnerIterations", @error)
EndFunc   ;==>_cveDualTVL1OpticalFlowGetInnerIterations

Func _cveDualTVL1OpticalFlowSetInnerIterations(ByRef $obj, $value)
    ; CVAPI(void) cveDualTVL1OpticalFlowSetInnerIterations(cv::optflow::DualTVL1OpticalFlow* obj, int value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDualTVL1OpticalFlowSetInnerIterations", "ptr", $obj, "int", $value), "cveDualTVL1OpticalFlowSetInnerIterations", @error)
EndFunc   ;==>_cveDualTVL1OpticalFlowSetInnerIterations

Func _cveDualTVL1OpticalFlowGetOuterIterations(ByRef $obj)
    ; CVAPI(int) cveDualTVL1OpticalFlowGetOuterIterations(cv::optflow::DualTVL1OpticalFlow* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveDualTVL1OpticalFlowGetOuterIterations", "ptr", $obj), "cveDualTVL1OpticalFlowGetOuterIterations", @error)
EndFunc   ;==>_cveDualTVL1OpticalFlowGetOuterIterations

Func _cveDualTVL1OpticalFlowSetOuterIterations(ByRef $obj, $value)
    ; CVAPI(void) cveDualTVL1OpticalFlowSetOuterIterations(cv::optflow::DualTVL1OpticalFlow* obj, int value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDualTVL1OpticalFlowSetOuterIterations", "ptr", $obj, "int", $value), "cveDualTVL1OpticalFlowSetOuterIterations", @error)
EndFunc   ;==>_cveDualTVL1OpticalFlowSetOuterIterations

Func _cveDualTVL1OpticalFlowGetUseInitialFlow(ByRef $obj)
    ; CVAPI(bool) cveDualTVL1OpticalFlowGetUseInitialFlow(cv::optflow::DualTVL1OpticalFlow* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveDualTVL1OpticalFlowGetUseInitialFlow", "ptr", $obj), "cveDualTVL1OpticalFlowGetUseInitialFlow", @error)
EndFunc   ;==>_cveDualTVL1OpticalFlowGetUseInitialFlow

Func _cveDualTVL1OpticalFlowSetUseInitialFlow(ByRef $obj, $value)
    ; CVAPI(void) cveDualTVL1OpticalFlowSetUseInitialFlow(cv::optflow::DualTVL1OpticalFlow* obj, bool value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDualTVL1OpticalFlowSetUseInitialFlow", "ptr", $obj, "boolean", $value), "cveDualTVL1OpticalFlowSetUseInitialFlow", @error)
EndFunc   ;==>_cveDualTVL1OpticalFlowSetUseInitialFlow

Func _cveDualTVL1OpticalFlowGetScaleStep(ByRef $obj)
    ; CVAPI(double) cveDualTVL1OpticalFlowGetScaleStep(cv::optflow::DualTVL1OpticalFlow* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveDualTVL1OpticalFlowGetScaleStep", "ptr", $obj), "cveDualTVL1OpticalFlowGetScaleStep", @error)
EndFunc   ;==>_cveDualTVL1OpticalFlowGetScaleStep

Func _cveDualTVL1OpticalFlowSetScaleStep(ByRef $obj, $value)
    ; CVAPI(void) cveDualTVL1OpticalFlowSetScaleStep(cv::optflow::DualTVL1OpticalFlow* obj, double value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDualTVL1OpticalFlowSetScaleStep", "ptr", $obj, "double", $value), "cveDualTVL1OpticalFlowSetScaleStep", @error)
EndFunc   ;==>_cveDualTVL1OpticalFlowSetScaleStep

Func _cveDualTVL1OpticalFlowGetMedianFiltering(ByRef $obj)
    ; CVAPI(int) cveDualTVL1OpticalFlowGetMedianFiltering(cv::optflow::DualTVL1OpticalFlow* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveDualTVL1OpticalFlowGetMedianFiltering", "ptr", $obj), "cveDualTVL1OpticalFlowGetMedianFiltering", @error)
EndFunc   ;==>_cveDualTVL1OpticalFlowGetMedianFiltering

Func _cveDualTVL1OpticalFlowSetMedianFiltering(ByRef $obj, $value)
    ; CVAPI(void) cveDualTVL1OpticalFlowSetMedianFiltering(cv::optflow::DualTVL1OpticalFlow* obj, int value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDualTVL1OpticalFlowSetMedianFiltering", "ptr", $obj, "int", $value), "cveDualTVL1OpticalFlowSetMedianFiltering", @error)
EndFunc   ;==>_cveDualTVL1OpticalFlowSetMedianFiltering