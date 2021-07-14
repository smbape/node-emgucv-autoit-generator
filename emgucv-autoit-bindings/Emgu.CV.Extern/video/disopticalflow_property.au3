#include-once
#include <..\..\CVEUtils.au3>

Func _cveDISOpticalFlowGetFinestScale(ByRef $obj)
    ; CVAPI(int) cveDISOpticalFlowGetFinestScale(cv::DISOpticalFlow* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveDISOpticalFlowGetFinestScale", "ptr", $obj), "cveDISOpticalFlowGetFinestScale", @error)
EndFunc   ;==>_cveDISOpticalFlowGetFinestScale

Func _cveDISOpticalFlowSetFinestScale(ByRef $obj, $value)
    ; CVAPI(void) cveDISOpticalFlowSetFinestScale(cv::DISOpticalFlow* obj, int value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDISOpticalFlowSetFinestScale", "ptr", $obj, "int", $value), "cveDISOpticalFlowSetFinestScale", @error)
EndFunc   ;==>_cveDISOpticalFlowSetFinestScale

Func _cveDISOpticalFlowGetPatchSize(ByRef $obj)
    ; CVAPI(int) cveDISOpticalFlowGetPatchSize(cv::DISOpticalFlow* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveDISOpticalFlowGetPatchSize", "ptr", $obj), "cveDISOpticalFlowGetPatchSize", @error)
EndFunc   ;==>_cveDISOpticalFlowGetPatchSize

Func _cveDISOpticalFlowSetPatchSize(ByRef $obj, $value)
    ; CVAPI(void) cveDISOpticalFlowSetPatchSize(cv::DISOpticalFlow* obj, int value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDISOpticalFlowSetPatchSize", "ptr", $obj, "int", $value), "cveDISOpticalFlowSetPatchSize", @error)
EndFunc   ;==>_cveDISOpticalFlowSetPatchSize

Func _cveDISOpticalFlowGetPatchStride(ByRef $obj)
    ; CVAPI(int) cveDISOpticalFlowGetPatchStride(cv::DISOpticalFlow* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveDISOpticalFlowGetPatchStride", "ptr", $obj), "cveDISOpticalFlowGetPatchStride", @error)
EndFunc   ;==>_cveDISOpticalFlowGetPatchStride

Func _cveDISOpticalFlowSetPatchStride(ByRef $obj, $value)
    ; CVAPI(void) cveDISOpticalFlowSetPatchStride(cv::DISOpticalFlow* obj, int value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDISOpticalFlowSetPatchStride", "ptr", $obj, "int", $value), "cveDISOpticalFlowSetPatchStride", @error)
EndFunc   ;==>_cveDISOpticalFlowSetPatchStride

Func _cveDISOpticalFlowGetGradientDescentIterations(ByRef $obj)
    ; CVAPI(int) cveDISOpticalFlowGetGradientDescentIterations(cv::DISOpticalFlow* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveDISOpticalFlowGetGradientDescentIterations", "ptr", $obj), "cveDISOpticalFlowGetGradientDescentIterations", @error)
EndFunc   ;==>_cveDISOpticalFlowGetGradientDescentIterations

Func _cveDISOpticalFlowSetGradientDescentIterations(ByRef $obj, $value)
    ; CVAPI(void) cveDISOpticalFlowSetGradientDescentIterations(cv::DISOpticalFlow* obj, int value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDISOpticalFlowSetGradientDescentIterations", "ptr", $obj, "int", $value), "cveDISOpticalFlowSetGradientDescentIterations", @error)
EndFunc   ;==>_cveDISOpticalFlowSetGradientDescentIterations

Func _cveDISOpticalFlowGetVariationalRefinementIterations(ByRef $obj)
    ; CVAPI(int) cveDISOpticalFlowGetVariationalRefinementIterations(cv::DISOpticalFlow* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveDISOpticalFlowGetVariationalRefinementIterations", "ptr", $obj), "cveDISOpticalFlowGetVariationalRefinementIterations", @error)
EndFunc   ;==>_cveDISOpticalFlowGetVariationalRefinementIterations

Func _cveDISOpticalFlowSetVariationalRefinementIterations(ByRef $obj, $value)
    ; CVAPI(void) cveDISOpticalFlowSetVariationalRefinementIterations(cv::DISOpticalFlow* obj, int value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDISOpticalFlowSetVariationalRefinementIterations", "ptr", $obj, "int", $value), "cveDISOpticalFlowSetVariationalRefinementIterations", @error)
EndFunc   ;==>_cveDISOpticalFlowSetVariationalRefinementIterations

Func _cveDISOpticalFlowGetVariationalRefinementAlpha(ByRef $obj)
    ; CVAPI(float) cveDISOpticalFlowGetVariationalRefinementAlpha(cv::DISOpticalFlow* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cveDISOpticalFlowGetVariationalRefinementAlpha", "ptr", $obj), "cveDISOpticalFlowGetVariationalRefinementAlpha", @error)
EndFunc   ;==>_cveDISOpticalFlowGetVariationalRefinementAlpha

Func _cveDISOpticalFlowSetVariationalRefinementAlpha(ByRef $obj, $value)
    ; CVAPI(void) cveDISOpticalFlowSetVariationalRefinementAlpha(cv::DISOpticalFlow* obj, float value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDISOpticalFlowSetVariationalRefinementAlpha", "ptr", $obj, "float", $value), "cveDISOpticalFlowSetVariationalRefinementAlpha", @error)
EndFunc   ;==>_cveDISOpticalFlowSetVariationalRefinementAlpha

Func _cveDISOpticalFlowGetVariationalRefinementDelta(ByRef $obj)
    ; CVAPI(float) cveDISOpticalFlowGetVariationalRefinementDelta(cv::DISOpticalFlow* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cveDISOpticalFlowGetVariationalRefinementDelta", "ptr", $obj), "cveDISOpticalFlowGetVariationalRefinementDelta", @error)
EndFunc   ;==>_cveDISOpticalFlowGetVariationalRefinementDelta

Func _cveDISOpticalFlowSetVariationalRefinementDelta(ByRef $obj, $value)
    ; CVAPI(void) cveDISOpticalFlowSetVariationalRefinementDelta(cv::DISOpticalFlow* obj, float value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDISOpticalFlowSetVariationalRefinementDelta", "ptr", $obj, "float", $value), "cveDISOpticalFlowSetVariationalRefinementDelta", @error)
EndFunc   ;==>_cveDISOpticalFlowSetVariationalRefinementDelta

Func _cveDISOpticalFlowGetVariationalRefinementGamma(ByRef $obj)
    ; CVAPI(float) cveDISOpticalFlowGetVariationalRefinementGamma(cv::DISOpticalFlow* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cveDISOpticalFlowGetVariationalRefinementGamma", "ptr", $obj), "cveDISOpticalFlowGetVariationalRefinementGamma", @error)
EndFunc   ;==>_cveDISOpticalFlowGetVariationalRefinementGamma

Func _cveDISOpticalFlowSetVariationalRefinementGamma(ByRef $obj, $value)
    ; CVAPI(void) cveDISOpticalFlowSetVariationalRefinementGamma(cv::DISOpticalFlow* obj, float value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDISOpticalFlowSetVariationalRefinementGamma", "ptr", $obj, "float", $value), "cveDISOpticalFlowSetVariationalRefinementGamma", @error)
EndFunc   ;==>_cveDISOpticalFlowSetVariationalRefinementGamma

Func _cveDISOpticalFlowGetUseMeanNormalization(ByRef $obj)
    ; CVAPI(bool) cveDISOpticalFlowGetUseMeanNormalization(cv::DISOpticalFlow* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveDISOpticalFlowGetUseMeanNormalization", "ptr", $obj), "cveDISOpticalFlowGetUseMeanNormalization", @error)
EndFunc   ;==>_cveDISOpticalFlowGetUseMeanNormalization

Func _cveDISOpticalFlowSetUseMeanNormalization(ByRef $obj, $value)
    ; CVAPI(void) cveDISOpticalFlowSetUseMeanNormalization(cv::DISOpticalFlow* obj, bool value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDISOpticalFlowSetUseMeanNormalization", "ptr", $obj, "boolean", $value), "cveDISOpticalFlowSetUseMeanNormalization", @error)
EndFunc   ;==>_cveDISOpticalFlowSetUseMeanNormalization

Func _cveDISOpticalFlowGetUseSpatialPropagation(ByRef $obj)
    ; CVAPI(bool) cveDISOpticalFlowGetUseSpatialPropagation(cv::DISOpticalFlow* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveDISOpticalFlowGetUseSpatialPropagation", "ptr", $obj), "cveDISOpticalFlowGetUseSpatialPropagation", @error)
EndFunc   ;==>_cveDISOpticalFlowGetUseSpatialPropagation

Func _cveDISOpticalFlowSetUseSpatialPropagation(ByRef $obj, $value)
    ; CVAPI(void) cveDISOpticalFlowSetUseSpatialPropagation(cv::DISOpticalFlow* obj, bool value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDISOpticalFlowSetUseSpatialPropagation", "ptr", $obj, "boolean", $value), "cveDISOpticalFlowSetUseSpatialPropagation", @error)
EndFunc   ;==>_cveDISOpticalFlowSetUseSpatialPropagation