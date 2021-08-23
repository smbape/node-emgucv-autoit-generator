#include-once
#include "..\..\CVEUtils.au3"

Func _cveDISOpticalFlowGetFinestScale($obj)
    ; CVAPI(int) cveDISOpticalFlowGetFinestScale(cv::DISOpticalFlow* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveDISOpticalFlowGetFinestScale", $sObjDllType, $obj), "cveDISOpticalFlowGetFinestScale", @error)
EndFunc   ;==>_cveDISOpticalFlowGetFinestScale

Func _cveDISOpticalFlowSetFinestScale($obj, $value)
    ; CVAPI(void) cveDISOpticalFlowSetFinestScale(cv::DISOpticalFlow* obj, int value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDISOpticalFlowSetFinestScale", $sObjDllType, $obj, "int", $value), "cveDISOpticalFlowSetFinestScale", @error)
EndFunc   ;==>_cveDISOpticalFlowSetFinestScale

Func _cveDISOpticalFlowGetPatchSize($obj)
    ; CVAPI(int) cveDISOpticalFlowGetPatchSize(cv::DISOpticalFlow* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveDISOpticalFlowGetPatchSize", $sObjDllType, $obj), "cveDISOpticalFlowGetPatchSize", @error)
EndFunc   ;==>_cveDISOpticalFlowGetPatchSize

Func _cveDISOpticalFlowSetPatchSize($obj, $value)
    ; CVAPI(void) cveDISOpticalFlowSetPatchSize(cv::DISOpticalFlow* obj, int value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDISOpticalFlowSetPatchSize", $sObjDllType, $obj, "int", $value), "cveDISOpticalFlowSetPatchSize", @error)
EndFunc   ;==>_cveDISOpticalFlowSetPatchSize

Func _cveDISOpticalFlowGetPatchStride($obj)
    ; CVAPI(int) cveDISOpticalFlowGetPatchStride(cv::DISOpticalFlow* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveDISOpticalFlowGetPatchStride", $sObjDllType, $obj), "cveDISOpticalFlowGetPatchStride", @error)
EndFunc   ;==>_cveDISOpticalFlowGetPatchStride

Func _cveDISOpticalFlowSetPatchStride($obj, $value)
    ; CVAPI(void) cveDISOpticalFlowSetPatchStride(cv::DISOpticalFlow* obj, int value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDISOpticalFlowSetPatchStride", $sObjDllType, $obj, "int", $value), "cveDISOpticalFlowSetPatchStride", @error)
EndFunc   ;==>_cveDISOpticalFlowSetPatchStride

Func _cveDISOpticalFlowGetGradientDescentIterations($obj)
    ; CVAPI(int) cveDISOpticalFlowGetGradientDescentIterations(cv::DISOpticalFlow* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveDISOpticalFlowGetGradientDescentIterations", $sObjDllType, $obj), "cveDISOpticalFlowGetGradientDescentIterations", @error)
EndFunc   ;==>_cveDISOpticalFlowGetGradientDescentIterations

Func _cveDISOpticalFlowSetGradientDescentIterations($obj, $value)
    ; CVAPI(void) cveDISOpticalFlowSetGradientDescentIterations(cv::DISOpticalFlow* obj, int value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDISOpticalFlowSetGradientDescentIterations", $sObjDllType, $obj, "int", $value), "cveDISOpticalFlowSetGradientDescentIterations", @error)
EndFunc   ;==>_cveDISOpticalFlowSetGradientDescentIterations

Func _cveDISOpticalFlowGetVariationalRefinementIterations($obj)
    ; CVAPI(int) cveDISOpticalFlowGetVariationalRefinementIterations(cv::DISOpticalFlow* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveDISOpticalFlowGetVariationalRefinementIterations", $sObjDllType, $obj), "cveDISOpticalFlowGetVariationalRefinementIterations", @error)
EndFunc   ;==>_cveDISOpticalFlowGetVariationalRefinementIterations

Func _cveDISOpticalFlowSetVariationalRefinementIterations($obj, $value)
    ; CVAPI(void) cveDISOpticalFlowSetVariationalRefinementIterations(cv::DISOpticalFlow* obj, int value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDISOpticalFlowSetVariationalRefinementIterations", $sObjDllType, $obj, "int", $value), "cveDISOpticalFlowSetVariationalRefinementIterations", @error)
EndFunc   ;==>_cveDISOpticalFlowSetVariationalRefinementIterations

Func _cveDISOpticalFlowGetVariationalRefinementAlpha($obj)
    ; CVAPI(float) cveDISOpticalFlowGetVariationalRefinementAlpha(cv::DISOpticalFlow* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cveDISOpticalFlowGetVariationalRefinementAlpha", $sObjDllType, $obj), "cveDISOpticalFlowGetVariationalRefinementAlpha", @error)
EndFunc   ;==>_cveDISOpticalFlowGetVariationalRefinementAlpha

Func _cveDISOpticalFlowSetVariationalRefinementAlpha($obj, $value)
    ; CVAPI(void) cveDISOpticalFlowSetVariationalRefinementAlpha(cv::DISOpticalFlow* obj, float value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDISOpticalFlowSetVariationalRefinementAlpha", $sObjDllType, $obj, "float", $value), "cveDISOpticalFlowSetVariationalRefinementAlpha", @error)
EndFunc   ;==>_cveDISOpticalFlowSetVariationalRefinementAlpha

Func _cveDISOpticalFlowGetVariationalRefinementDelta($obj)
    ; CVAPI(float) cveDISOpticalFlowGetVariationalRefinementDelta(cv::DISOpticalFlow* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cveDISOpticalFlowGetVariationalRefinementDelta", $sObjDllType, $obj), "cveDISOpticalFlowGetVariationalRefinementDelta", @error)
EndFunc   ;==>_cveDISOpticalFlowGetVariationalRefinementDelta

Func _cveDISOpticalFlowSetVariationalRefinementDelta($obj, $value)
    ; CVAPI(void) cveDISOpticalFlowSetVariationalRefinementDelta(cv::DISOpticalFlow* obj, float value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDISOpticalFlowSetVariationalRefinementDelta", $sObjDllType, $obj, "float", $value), "cveDISOpticalFlowSetVariationalRefinementDelta", @error)
EndFunc   ;==>_cveDISOpticalFlowSetVariationalRefinementDelta

Func _cveDISOpticalFlowGetVariationalRefinementGamma($obj)
    ; CVAPI(float) cveDISOpticalFlowGetVariationalRefinementGamma(cv::DISOpticalFlow* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cveDISOpticalFlowGetVariationalRefinementGamma", $sObjDllType, $obj), "cveDISOpticalFlowGetVariationalRefinementGamma", @error)
EndFunc   ;==>_cveDISOpticalFlowGetVariationalRefinementGamma

Func _cveDISOpticalFlowSetVariationalRefinementGamma($obj, $value)
    ; CVAPI(void) cveDISOpticalFlowSetVariationalRefinementGamma(cv::DISOpticalFlow* obj, float value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDISOpticalFlowSetVariationalRefinementGamma", $sObjDllType, $obj, "float", $value), "cveDISOpticalFlowSetVariationalRefinementGamma", @error)
EndFunc   ;==>_cveDISOpticalFlowSetVariationalRefinementGamma

Func _cveDISOpticalFlowGetUseMeanNormalization($obj)
    ; CVAPI(bool) cveDISOpticalFlowGetUseMeanNormalization(cv::DISOpticalFlow* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveDISOpticalFlowGetUseMeanNormalization", $sObjDllType, $obj), "cveDISOpticalFlowGetUseMeanNormalization", @error)
EndFunc   ;==>_cveDISOpticalFlowGetUseMeanNormalization

Func _cveDISOpticalFlowSetUseMeanNormalization($obj, $value)
    ; CVAPI(void) cveDISOpticalFlowSetUseMeanNormalization(cv::DISOpticalFlow* obj, bool value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDISOpticalFlowSetUseMeanNormalization", $sObjDllType, $obj, "boolean", $value), "cveDISOpticalFlowSetUseMeanNormalization", @error)
EndFunc   ;==>_cveDISOpticalFlowSetUseMeanNormalization

Func _cveDISOpticalFlowGetUseSpatialPropagation($obj)
    ; CVAPI(bool) cveDISOpticalFlowGetUseSpatialPropagation(cv::DISOpticalFlow* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveDISOpticalFlowGetUseSpatialPropagation", $sObjDllType, $obj), "cveDISOpticalFlowGetUseSpatialPropagation", @error)
EndFunc   ;==>_cveDISOpticalFlowGetUseSpatialPropagation

Func _cveDISOpticalFlowSetUseSpatialPropagation($obj, $value)
    ; CVAPI(void) cveDISOpticalFlowSetUseSpatialPropagation(cv::DISOpticalFlow* obj, bool value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDISOpticalFlowSetUseSpatialPropagation", $sObjDllType, $obj, "boolean", $value), "cveDISOpticalFlowSetUseSpatialPropagation", @error)
EndFunc   ;==>_cveDISOpticalFlowSetUseSpatialPropagation