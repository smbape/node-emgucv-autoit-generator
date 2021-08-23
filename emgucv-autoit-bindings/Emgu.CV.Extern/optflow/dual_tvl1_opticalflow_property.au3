#include-once
#include "..\..\CVEUtils.au3"

Func _cveDualTVL1OpticalFlowGetTau($obj)
    ; CVAPI(double) cveDualTVL1OpticalFlowGetTau(cv::optflow::DualTVL1OpticalFlow* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveDualTVL1OpticalFlowGetTau", $sObjDllType, $obj), "cveDualTVL1OpticalFlowGetTau", @error)
EndFunc   ;==>_cveDualTVL1OpticalFlowGetTau

Func _cveDualTVL1OpticalFlowSetTau($obj, $value)
    ; CVAPI(void) cveDualTVL1OpticalFlowSetTau(cv::optflow::DualTVL1OpticalFlow* obj, double value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDualTVL1OpticalFlowSetTau", $sObjDllType, $obj, "double", $value), "cveDualTVL1OpticalFlowSetTau", @error)
EndFunc   ;==>_cveDualTVL1OpticalFlowSetTau

Func _cveDualTVL1OpticalFlowGetLambda($obj)
    ; CVAPI(double) cveDualTVL1OpticalFlowGetLambda(cv::optflow::DualTVL1OpticalFlow* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveDualTVL1OpticalFlowGetLambda", $sObjDllType, $obj), "cveDualTVL1OpticalFlowGetLambda", @error)
EndFunc   ;==>_cveDualTVL1OpticalFlowGetLambda

Func _cveDualTVL1OpticalFlowSetLambda($obj, $value)
    ; CVAPI(void) cveDualTVL1OpticalFlowSetLambda(cv::optflow::DualTVL1OpticalFlow* obj, double value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDualTVL1OpticalFlowSetLambda", $sObjDllType, $obj, "double", $value), "cveDualTVL1OpticalFlowSetLambda", @error)
EndFunc   ;==>_cveDualTVL1OpticalFlowSetLambda

Func _cveDualTVL1OpticalFlowGetTheta($obj)
    ; CVAPI(double) cveDualTVL1OpticalFlowGetTheta(cv::optflow::DualTVL1OpticalFlow* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveDualTVL1OpticalFlowGetTheta", $sObjDllType, $obj), "cveDualTVL1OpticalFlowGetTheta", @error)
EndFunc   ;==>_cveDualTVL1OpticalFlowGetTheta

Func _cveDualTVL1OpticalFlowSetTheta($obj, $value)
    ; CVAPI(void) cveDualTVL1OpticalFlowSetTheta(cv::optflow::DualTVL1OpticalFlow* obj, double value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDualTVL1OpticalFlowSetTheta", $sObjDllType, $obj, "double", $value), "cveDualTVL1OpticalFlowSetTheta", @error)
EndFunc   ;==>_cveDualTVL1OpticalFlowSetTheta

Func _cveDualTVL1OpticalFlowGetGamma($obj)
    ; CVAPI(double) cveDualTVL1OpticalFlowGetGamma(cv::optflow::DualTVL1OpticalFlow* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveDualTVL1OpticalFlowGetGamma", $sObjDllType, $obj), "cveDualTVL1OpticalFlowGetGamma", @error)
EndFunc   ;==>_cveDualTVL1OpticalFlowGetGamma

Func _cveDualTVL1OpticalFlowSetGamma($obj, $value)
    ; CVAPI(void) cveDualTVL1OpticalFlowSetGamma(cv::optflow::DualTVL1OpticalFlow* obj, double value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDualTVL1OpticalFlowSetGamma", $sObjDllType, $obj, "double", $value), "cveDualTVL1OpticalFlowSetGamma", @error)
EndFunc   ;==>_cveDualTVL1OpticalFlowSetGamma

Func _cveDualTVL1OpticalFlowGetScalesNumber($obj)
    ; CVAPI(int) cveDualTVL1OpticalFlowGetScalesNumber(cv::optflow::DualTVL1OpticalFlow* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveDualTVL1OpticalFlowGetScalesNumber", $sObjDllType, $obj), "cveDualTVL1OpticalFlowGetScalesNumber", @error)
EndFunc   ;==>_cveDualTVL1OpticalFlowGetScalesNumber

Func _cveDualTVL1OpticalFlowSetScalesNumber($obj, $value)
    ; CVAPI(void) cveDualTVL1OpticalFlowSetScalesNumber(cv::optflow::DualTVL1OpticalFlow* obj, int value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDualTVL1OpticalFlowSetScalesNumber", $sObjDllType, $obj, "int", $value), "cveDualTVL1OpticalFlowSetScalesNumber", @error)
EndFunc   ;==>_cveDualTVL1OpticalFlowSetScalesNumber

Func _cveDualTVL1OpticalFlowGetWarpingsNumber($obj)
    ; CVAPI(int) cveDualTVL1OpticalFlowGetWarpingsNumber(cv::optflow::DualTVL1OpticalFlow* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveDualTVL1OpticalFlowGetWarpingsNumber", $sObjDllType, $obj), "cveDualTVL1OpticalFlowGetWarpingsNumber", @error)
EndFunc   ;==>_cveDualTVL1OpticalFlowGetWarpingsNumber

Func _cveDualTVL1OpticalFlowSetWarpingsNumber($obj, $value)
    ; CVAPI(void) cveDualTVL1OpticalFlowSetWarpingsNumber(cv::optflow::DualTVL1OpticalFlow* obj, int value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDualTVL1OpticalFlowSetWarpingsNumber", $sObjDllType, $obj, "int", $value), "cveDualTVL1OpticalFlowSetWarpingsNumber", @error)
EndFunc   ;==>_cveDualTVL1OpticalFlowSetWarpingsNumber

Func _cveDualTVL1OpticalFlowGetEpsilon($obj)
    ; CVAPI(double) cveDualTVL1OpticalFlowGetEpsilon(cv::optflow::DualTVL1OpticalFlow* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveDualTVL1OpticalFlowGetEpsilon", $sObjDllType, $obj), "cveDualTVL1OpticalFlowGetEpsilon", @error)
EndFunc   ;==>_cveDualTVL1OpticalFlowGetEpsilon

Func _cveDualTVL1OpticalFlowSetEpsilon($obj, $value)
    ; CVAPI(void) cveDualTVL1OpticalFlowSetEpsilon(cv::optflow::DualTVL1OpticalFlow* obj, double value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDualTVL1OpticalFlowSetEpsilon", $sObjDllType, $obj, "double", $value), "cveDualTVL1OpticalFlowSetEpsilon", @error)
EndFunc   ;==>_cveDualTVL1OpticalFlowSetEpsilon

Func _cveDualTVL1OpticalFlowGetInnerIterations($obj)
    ; CVAPI(int) cveDualTVL1OpticalFlowGetInnerIterations(cv::optflow::DualTVL1OpticalFlow* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveDualTVL1OpticalFlowGetInnerIterations", $sObjDllType, $obj), "cveDualTVL1OpticalFlowGetInnerIterations", @error)
EndFunc   ;==>_cveDualTVL1OpticalFlowGetInnerIterations

Func _cveDualTVL1OpticalFlowSetInnerIterations($obj, $value)
    ; CVAPI(void) cveDualTVL1OpticalFlowSetInnerIterations(cv::optflow::DualTVL1OpticalFlow* obj, int value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDualTVL1OpticalFlowSetInnerIterations", $sObjDllType, $obj, "int", $value), "cveDualTVL1OpticalFlowSetInnerIterations", @error)
EndFunc   ;==>_cveDualTVL1OpticalFlowSetInnerIterations

Func _cveDualTVL1OpticalFlowGetOuterIterations($obj)
    ; CVAPI(int) cveDualTVL1OpticalFlowGetOuterIterations(cv::optflow::DualTVL1OpticalFlow* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveDualTVL1OpticalFlowGetOuterIterations", $sObjDllType, $obj), "cveDualTVL1OpticalFlowGetOuterIterations", @error)
EndFunc   ;==>_cveDualTVL1OpticalFlowGetOuterIterations

Func _cveDualTVL1OpticalFlowSetOuterIterations($obj, $value)
    ; CVAPI(void) cveDualTVL1OpticalFlowSetOuterIterations(cv::optflow::DualTVL1OpticalFlow* obj, int value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDualTVL1OpticalFlowSetOuterIterations", $sObjDllType, $obj, "int", $value), "cveDualTVL1OpticalFlowSetOuterIterations", @error)
EndFunc   ;==>_cveDualTVL1OpticalFlowSetOuterIterations

Func _cveDualTVL1OpticalFlowGetUseInitialFlow($obj)
    ; CVAPI(bool) cveDualTVL1OpticalFlowGetUseInitialFlow(cv::optflow::DualTVL1OpticalFlow* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveDualTVL1OpticalFlowGetUseInitialFlow", $sObjDllType, $obj), "cveDualTVL1OpticalFlowGetUseInitialFlow", @error)
EndFunc   ;==>_cveDualTVL1OpticalFlowGetUseInitialFlow

Func _cveDualTVL1OpticalFlowSetUseInitialFlow($obj, $value)
    ; CVAPI(void) cveDualTVL1OpticalFlowSetUseInitialFlow(cv::optflow::DualTVL1OpticalFlow* obj, bool value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDualTVL1OpticalFlowSetUseInitialFlow", $sObjDllType, $obj, "boolean", $value), "cveDualTVL1OpticalFlowSetUseInitialFlow", @error)
EndFunc   ;==>_cveDualTVL1OpticalFlowSetUseInitialFlow

Func _cveDualTVL1OpticalFlowGetScaleStep($obj)
    ; CVAPI(double) cveDualTVL1OpticalFlowGetScaleStep(cv::optflow::DualTVL1OpticalFlow* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveDualTVL1OpticalFlowGetScaleStep", $sObjDllType, $obj), "cveDualTVL1OpticalFlowGetScaleStep", @error)
EndFunc   ;==>_cveDualTVL1OpticalFlowGetScaleStep

Func _cveDualTVL1OpticalFlowSetScaleStep($obj, $value)
    ; CVAPI(void) cveDualTVL1OpticalFlowSetScaleStep(cv::optflow::DualTVL1OpticalFlow* obj, double value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDualTVL1OpticalFlowSetScaleStep", $sObjDllType, $obj, "double", $value), "cveDualTVL1OpticalFlowSetScaleStep", @error)
EndFunc   ;==>_cveDualTVL1OpticalFlowSetScaleStep

Func _cveDualTVL1OpticalFlowGetMedianFiltering($obj)
    ; CVAPI(int) cveDualTVL1OpticalFlowGetMedianFiltering(cv::optflow::DualTVL1OpticalFlow* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveDualTVL1OpticalFlowGetMedianFiltering", $sObjDllType, $obj), "cveDualTVL1OpticalFlowGetMedianFiltering", @error)
EndFunc   ;==>_cveDualTVL1OpticalFlowGetMedianFiltering

Func _cveDualTVL1OpticalFlowSetMedianFiltering($obj, $value)
    ; CVAPI(void) cveDualTVL1OpticalFlowSetMedianFiltering(cv::optflow::DualTVL1OpticalFlow* obj, int value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDualTVL1OpticalFlowSetMedianFiltering", $sObjDllType, $obj, "int", $value), "cveDualTVL1OpticalFlowSetMedianFiltering", @error)
EndFunc   ;==>_cveDualTVL1OpticalFlowSetMedianFiltering