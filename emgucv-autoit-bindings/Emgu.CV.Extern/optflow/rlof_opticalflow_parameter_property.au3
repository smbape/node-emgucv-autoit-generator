#include-once
#include "..\..\CVEUtils.au3"

Func _cveRLOFOpticalFlowParameterGetNormSigma0($obj)
    ; CVAPI(float) cveRLOFOpticalFlowParameterGetNormSigma0(cv::optflow::RLOFOpticalFlowParameter* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cveRLOFOpticalFlowParameterGetNormSigma0", $bObjDllType, $obj), "cveRLOFOpticalFlowParameterGetNormSigma0", @error)
EndFunc   ;==>_cveRLOFOpticalFlowParameterGetNormSigma0

Func _cveRLOFOpticalFlowParameterSetNormSigma0($obj, $value)
    ; CVAPI(void) cveRLOFOpticalFlowParameterSetNormSigma0(cv::optflow::RLOFOpticalFlowParameter* obj, float value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveRLOFOpticalFlowParameterSetNormSigma0", $bObjDllType, $obj, "float", $value), "cveRLOFOpticalFlowParameterSetNormSigma0", @error)
EndFunc   ;==>_cveRLOFOpticalFlowParameterSetNormSigma0

Func _cveRLOFOpticalFlowParameterGetNormSigma1($obj)
    ; CVAPI(float) cveRLOFOpticalFlowParameterGetNormSigma1(cv::optflow::RLOFOpticalFlowParameter* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cveRLOFOpticalFlowParameterGetNormSigma1", $bObjDllType, $obj), "cveRLOFOpticalFlowParameterGetNormSigma1", @error)
EndFunc   ;==>_cveRLOFOpticalFlowParameterGetNormSigma1

Func _cveRLOFOpticalFlowParameterSetNormSigma1($obj, $value)
    ; CVAPI(void) cveRLOFOpticalFlowParameterSetNormSigma1(cv::optflow::RLOFOpticalFlowParameter* obj, float value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveRLOFOpticalFlowParameterSetNormSigma1", $bObjDllType, $obj, "float", $value), "cveRLOFOpticalFlowParameterSetNormSigma1", @error)
EndFunc   ;==>_cveRLOFOpticalFlowParameterSetNormSigma1

Func _cveRLOFOpticalFlowParameterGetSolver($obj)
    ; CVAPI(cv::optflow::SolverType) cveRLOFOpticalFlowParameterGetSolver(cv::optflow::RLOFOpticalFlowParameter* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "cv::optflow::SolverType:cdecl", "cveRLOFOpticalFlowParameterGetSolver", $bObjDllType, $obj), "cveRLOFOpticalFlowParameterGetSolver", @error)
EndFunc   ;==>_cveRLOFOpticalFlowParameterGetSolver

Func _cveRLOFOpticalFlowParameterSetSolver($obj, $value)
    ; CVAPI(void) cveRLOFOpticalFlowParameterSetSolver(cv::optflow::RLOFOpticalFlowParameter* obj, cv::optflow::SolverType value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveRLOFOpticalFlowParameterSetSolver", $bObjDllType, $obj, "cv::optflow::SolverType", $value), "cveRLOFOpticalFlowParameterSetSolver", @error)
EndFunc   ;==>_cveRLOFOpticalFlowParameterSetSolver

Func _cveRLOFOpticalFlowParameterGetSupportRegion($obj)
    ; CVAPI(cv::optflow::SupportRegionType) cveRLOFOpticalFlowParameterGetSupportRegion(cv::optflow::RLOFOpticalFlowParameter* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "cv::optflow::SupportRegionType:cdecl", "cveRLOFOpticalFlowParameterGetSupportRegion", $bObjDllType, $obj), "cveRLOFOpticalFlowParameterGetSupportRegion", @error)
EndFunc   ;==>_cveRLOFOpticalFlowParameterGetSupportRegion

Func _cveRLOFOpticalFlowParameterSetSupportRegion($obj, $value)
    ; CVAPI(void) cveRLOFOpticalFlowParameterSetSupportRegion(cv::optflow::RLOFOpticalFlowParameter* obj, cv::optflow::SupportRegionType value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveRLOFOpticalFlowParameterSetSupportRegion", $bObjDllType, $obj, "cv::optflow::SupportRegionType", $value), "cveRLOFOpticalFlowParameterSetSupportRegion", @error)
EndFunc   ;==>_cveRLOFOpticalFlowParameterSetSupportRegion

Func _cveRLOFOpticalFlowParameterGetSmallWinSize($obj)
    ; CVAPI(int) cveRLOFOpticalFlowParameterGetSmallWinSize(cv::optflow::RLOFOpticalFlowParameter* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveRLOFOpticalFlowParameterGetSmallWinSize", $bObjDllType, $obj), "cveRLOFOpticalFlowParameterGetSmallWinSize", @error)
EndFunc   ;==>_cveRLOFOpticalFlowParameterGetSmallWinSize

Func _cveRLOFOpticalFlowParameterSetSmallWinSize($obj, $value)
    ; CVAPI(void) cveRLOFOpticalFlowParameterSetSmallWinSize(cv::optflow::RLOFOpticalFlowParameter* obj, int value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveRLOFOpticalFlowParameterSetSmallWinSize", $bObjDllType, $obj, "int", $value), "cveRLOFOpticalFlowParameterSetSmallWinSize", @error)
EndFunc   ;==>_cveRLOFOpticalFlowParameterSetSmallWinSize

Func _cveRLOFOpticalFlowParameterGetLargeWinSize($obj)
    ; CVAPI(int) cveRLOFOpticalFlowParameterGetLargeWinSize(cv::optflow::RLOFOpticalFlowParameter* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveRLOFOpticalFlowParameterGetLargeWinSize", $bObjDllType, $obj), "cveRLOFOpticalFlowParameterGetLargeWinSize", @error)
EndFunc   ;==>_cveRLOFOpticalFlowParameterGetLargeWinSize

Func _cveRLOFOpticalFlowParameterSetLargeWinSize($obj, $value)
    ; CVAPI(void) cveRLOFOpticalFlowParameterSetLargeWinSize(cv::optflow::RLOFOpticalFlowParameter* obj, int value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveRLOFOpticalFlowParameterSetLargeWinSize", $bObjDllType, $obj, "int", $value), "cveRLOFOpticalFlowParameterSetLargeWinSize", @error)
EndFunc   ;==>_cveRLOFOpticalFlowParameterSetLargeWinSize

Func _cveRLOFOpticalFlowParameterGetCrossSegmentationThreshold($obj)
    ; CVAPI(int) cveRLOFOpticalFlowParameterGetCrossSegmentationThreshold(cv::optflow::RLOFOpticalFlowParameter* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveRLOFOpticalFlowParameterGetCrossSegmentationThreshold", $bObjDllType, $obj), "cveRLOFOpticalFlowParameterGetCrossSegmentationThreshold", @error)
EndFunc   ;==>_cveRLOFOpticalFlowParameterGetCrossSegmentationThreshold

Func _cveRLOFOpticalFlowParameterSetCrossSegmentationThreshold($obj, $value)
    ; CVAPI(void) cveRLOFOpticalFlowParameterSetCrossSegmentationThreshold(cv::optflow::RLOFOpticalFlowParameter* obj, int value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveRLOFOpticalFlowParameterSetCrossSegmentationThreshold", $bObjDllType, $obj, "int", $value), "cveRLOFOpticalFlowParameterSetCrossSegmentationThreshold", @error)
EndFunc   ;==>_cveRLOFOpticalFlowParameterSetCrossSegmentationThreshold

Func _cveRLOFOpticalFlowParameterGetMaxLevel($obj)
    ; CVAPI(int) cveRLOFOpticalFlowParameterGetMaxLevel(cv::optflow::RLOFOpticalFlowParameter* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveRLOFOpticalFlowParameterGetMaxLevel", $bObjDllType, $obj), "cveRLOFOpticalFlowParameterGetMaxLevel", @error)
EndFunc   ;==>_cveRLOFOpticalFlowParameterGetMaxLevel

Func _cveRLOFOpticalFlowParameterSetMaxLevel($obj, $value)
    ; CVAPI(void) cveRLOFOpticalFlowParameterSetMaxLevel(cv::optflow::RLOFOpticalFlowParameter* obj, int value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveRLOFOpticalFlowParameterSetMaxLevel", $bObjDllType, $obj, "int", $value), "cveRLOFOpticalFlowParameterSetMaxLevel", @error)
EndFunc   ;==>_cveRLOFOpticalFlowParameterSetMaxLevel

Func _cveRLOFOpticalFlowParameterGetUseInitialFlow($obj)
    ; CVAPI(bool) cveRLOFOpticalFlowParameterGetUseInitialFlow(cv::optflow::RLOFOpticalFlowParameter* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveRLOFOpticalFlowParameterGetUseInitialFlow", $bObjDllType, $obj), "cveRLOFOpticalFlowParameterGetUseInitialFlow", @error)
EndFunc   ;==>_cveRLOFOpticalFlowParameterGetUseInitialFlow

Func _cveRLOFOpticalFlowParameterSetUseInitialFlow($obj, $value)
    ; CVAPI(void) cveRLOFOpticalFlowParameterSetUseInitialFlow(cv::optflow::RLOFOpticalFlowParameter* obj, bool value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveRLOFOpticalFlowParameterSetUseInitialFlow", $bObjDllType, $obj, "boolean", $value), "cveRLOFOpticalFlowParameterSetUseInitialFlow", @error)
EndFunc   ;==>_cveRLOFOpticalFlowParameterSetUseInitialFlow

Func _cveRLOFOpticalFlowParameterGetUseIlluminationModel($obj)
    ; CVAPI(bool) cveRLOFOpticalFlowParameterGetUseIlluminationModel(cv::optflow::RLOFOpticalFlowParameter* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveRLOFOpticalFlowParameterGetUseIlluminationModel", $bObjDllType, $obj), "cveRLOFOpticalFlowParameterGetUseIlluminationModel", @error)
EndFunc   ;==>_cveRLOFOpticalFlowParameterGetUseIlluminationModel

Func _cveRLOFOpticalFlowParameterSetUseIlluminationModel($obj, $value)
    ; CVAPI(void) cveRLOFOpticalFlowParameterSetUseIlluminationModel(cv::optflow::RLOFOpticalFlowParameter* obj, bool value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveRLOFOpticalFlowParameterSetUseIlluminationModel", $bObjDllType, $obj, "boolean", $value), "cveRLOFOpticalFlowParameterSetUseIlluminationModel", @error)
EndFunc   ;==>_cveRLOFOpticalFlowParameterSetUseIlluminationModel

Func _cveRLOFOpticalFlowParameterGetUseGlobalMotionPrior($obj)
    ; CVAPI(bool) cveRLOFOpticalFlowParameterGetUseGlobalMotionPrior(cv::optflow::RLOFOpticalFlowParameter* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveRLOFOpticalFlowParameterGetUseGlobalMotionPrior", $bObjDllType, $obj), "cveRLOFOpticalFlowParameterGetUseGlobalMotionPrior", @error)
EndFunc   ;==>_cveRLOFOpticalFlowParameterGetUseGlobalMotionPrior

Func _cveRLOFOpticalFlowParameterSetUseGlobalMotionPrior($obj, $value)
    ; CVAPI(void) cveRLOFOpticalFlowParameterSetUseGlobalMotionPrior(cv::optflow::RLOFOpticalFlowParameter* obj, bool value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveRLOFOpticalFlowParameterSetUseGlobalMotionPrior", $bObjDllType, $obj, "boolean", $value), "cveRLOFOpticalFlowParameterSetUseGlobalMotionPrior", @error)
EndFunc   ;==>_cveRLOFOpticalFlowParameterSetUseGlobalMotionPrior

Func _cveRLOFOpticalFlowParameterGetMaxIteration($obj)
    ; CVAPI(int) cveRLOFOpticalFlowParameterGetMaxIteration(cv::optflow::RLOFOpticalFlowParameter* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveRLOFOpticalFlowParameterGetMaxIteration", $bObjDllType, $obj), "cveRLOFOpticalFlowParameterGetMaxIteration", @error)
EndFunc   ;==>_cveRLOFOpticalFlowParameterGetMaxIteration

Func _cveRLOFOpticalFlowParameterSetMaxIteration($obj, $value)
    ; CVAPI(void) cveRLOFOpticalFlowParameterSetMaxIteration(cv::optflow::RLOFOpticalFlowParameter* obj, int value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveRLOFOpticalFlowParameterSetMaxIteration", $bObjDllType, $obj, "int", $value), "cveRLOFOpticalFlowParameterSetMaxIteration", @error)
EndFunc   ;==>_cveRLOFOpticalFlowParameterSetMaxIteration

Func _cveRLOFOpticalFlowParameterGetMinEigenValue($obj)
    ; CVAPI(float) cveRLOFOpticalFlowParameterGetMinEigenValue(cv::optflow::RLOFOpticalFlowParameter* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cveRLOFOpticalFlowParameterGetMinEigenValue", $bObjDllType, $obj), "cveRLOFOpticalFlowParameterGetMinEigenValue", @error)
EndFunc   ;==>_cveRLOFOpticalFlowParameterGetMinEigenValue

Func _cveRLOFOpticalFlowParameterSetMinEigenValue($obj, $value)
    ; CVAPI(void) cveRLOFOpticalFlowParameterSetMinEigenValue(cv::optflow::RLOFOpticalFlowParameter* obj, float value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveRLOFOpticalFlowParameterSetMinEigenValue", $bObjDllType, $obj, "float", $value), "cveRLOFOpticalFlowParameterSetMinEigenValue", @error)
EndFunc   ;==>_cveRLOFOpticalFlowParameterSetMinEigenValue

Func _cveRLOFOpticalFlowParameterGetGlobalMotionRansacThreshold($obj)
    ; CVAPI(float) cveRLOFOpticalFlowParameterGetGlobalMotionRansacThreshold(cv::optflow::RLOFOpticalFlowParameter* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cveRLOFOpticalFlowParameterGetGlobalMotionRansacThreshold", $bObjDllType, $obj), "cveRLOFOpticalFlowParameterGetGlobalMotionRansacThreshold", @error)
EndFunc   ;==>_cveRLOFOpticalFlowParameterGetGlobalMotionRansacThreshold

Func _cveRLOFOpticalFlowParameterSetGlobalMotionRansacThreshold($obj, $value)
    ; CVAPI(void) cveRLOFOpticalFlowParameterSetGlobalMotionRansacThreshold(cv::optflow::RLOFOpticalFlowParameter* obj, float value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveRLOFOpticalFlowParameterSetGlobalMotionRansacThreshold", $bObjDllType, $obj, "float", $value), "cveRLOFOpticalFlowParameterSetGlobalMotionRansacThreshold", @error)
EndFunc   ;==>_cveRLOFOpticalFlowParameterSetGlobalMotionRansacThreshold