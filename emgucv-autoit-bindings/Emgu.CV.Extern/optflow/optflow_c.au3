#include-once
#include "..\..\CVEUtils.au3"

Func _cveUpdateMotionHistory($silhouette, $mhi, $timestamp, $duration)
    ; CVAPI(void) cveUpdateMotionHistory(cv::_InputArray* silhouette, cv::_InputOutputArray* mhi, double timestamp, double duration);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveUpdateMotionHistory", "ptr", $silhouette, "ptr", $mhi, "double", $timestamp, "double", $duration), "cveUpdateMotionHistory", @error)
EndFunc   ;==>_cveUpdateMotionHistory

Func _cveUpdateMotionHistoryMat($matSilhouette, $matMhi, $timestamp, $duration)
    ; cveUpdateMotionHistory using cv::Mat instead of _*Array

    Local $iArrSilhouette, $vectorOfMatSilhouette, $iArrSilhouetteSize
    Local $bSilhouetteIsArray = VarGetType($matSilhouette) == "Array"

    If $bSilhouetteIsArray Then
        $vectorOfMatSilhouette = _VectorOfMatCreate()

        $iArrSilhouetteSize = UBound($matSilhouette)
        For $i = 0 To $iArrSilhouetteSize - 1
            _VectorOfMatPush($vectorOfMatSilhouette, $matSilhouette[$i])
        Next

        $iArrSilhouette = _cveInputArrayFromVectorOfMat($vectorOfMatSilhouette)
    Else
        $iArrSilhouette = _cveInputArrayFromMat($matSilhouette)
    EndIf

    Local $ioArrMhi, $vectorOfMatMhi, $iArrMhiSize
    Local $bMhiIsArray = VarGetType($matMhi) == "Array"

    If $bMhiIsArray Then
        $vectorOfMatMhi = _VectorOfMatCreate()

        $iArrMhiSize = UBound($matMhi)
        For $i = 0 To $iArrMhiSize - 1
            _VectorOfMatPush($vectorOfMatMhi, $matMhi[$i])
        Next

        $ioArrMhi = _cveInputOutputArrayFromVectorOfMat($vectorOfMatMhi)
    Else
        $ioArrMhi = _cveInputOutputArrayFromMat($matMhi)
    EndIf

    _cveUpdateMotionHistory($iArrSilhouette, $ioArrMhi, $timestamp, $duration)

    If $bMhiIsArray Then
        _VectorOfMatRelease($vectorOfMatMhi)
    EndIf

    _cveInputOutputArrayRelease($ioArrMhi)

    If $bSilhouetteIsArray Then
        _VectorOfMatRelease($vectorOfMatSilhouette)
    EndIf

    _cveInputArrayRelease($iArrSilhouette)
EndFunc   ;==>_cveUpdateMotionHistoryMat

Func _cveCalcMotionGradient($mhi, $mask, $orientation, $delta1, $delta2, $apertureSize)
    ; CVAPI(void) cveCalcMotionGradient(cv::_InputArray* mhi, cv::_OutputArray* mask, cv::_OutputArray* orientation, double delta1, double delta2, int apertureSize);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCalcMotionGradient", "ptr", $mhi, "ptr", $mask, "ptr", $orientation, "double", $delta1, "double", $delta2, "int", $apertureSize), "cveCalcMotionGradient", @error)
EndFunc   ;==>_cveCalcMotionGradient

Func _cveCalcMotionGradientMat($matMhi, $matMask, $matOrientation, $delta1, $delta2, $apertureSize)
    ; cveCalcMotionGradient using cv::Mat instead of _*Array

    Local $iArrMhi, $vectorOfMatMhi, $iArrMhiSize
    Local $bMhiIsArray = VarGetType($matMhi) == "Array"

    If $bMhiIsArray Then
        $vectorOfMatMhi = _VectorOfMatCreate()

        $iArrMhiSize = UBound($matMhi)
        For $i = 0 To $iArrMhiSize - 1
            _VectorOfMatPush($vectorOfMatMhi, $matMhi[$i])
        Next

        $iArrMhi = _cveInputArrayFromVectorOfMat($vectorOfMatMhi)
    Else
        $iArrMhi = _cveInputArrayFromMat($matMhi)
    EndIf

    Local $oArrMask, $vectorOfMatMask, $iArrMaskSize
    Local $bMaskIsArray = VarGetType($matMask) == "Array"

    If $bMaskIsArray Then
        $vectorOfMatMask = _VectorOfMatCreate()

        $iArrMaskSize = UBound($matMask)
        For $i = 0 To $iArrMaskSize - 1
            _VectorOfMatPush($vectorOfMatMask, $matMask[$i])
        Next

        $oArrMask = _cveOutputArrayFromVectorOfMat($vectorOfMatMask)
    Else
        $oArrMask = _cveOutputArrayFromMat($matMask)
    EndIf

    Local $oArrOrientation, $vectorOfMatOrientation, $iArrOrientationSize
    Local $bOrientationIsArray = VarGetType($matOrientation) == "Array"

    If $bOrientationIsArray Then
        $vectorOfMatOrientation = _VectorOfMatCreate()

        $iArrOrientationSize = UBound($matOrientation)
        For $i = 0 To $iArrOrientationSize - 1
            _VectorOfMatPush($vectorOfMatOrientation, $matOrientation[$i])
        Next

        $oArrOrientation = _cveOutputArrayFromVectorOfMat($vectorOfMatOrientation)
    Else
        $oArrOrientation = _cveOutputArrayFromMat($matOrientation)
    EndIf

    _cveCalcMotionGradient($iArrMhi, $oArrMask, $oArrOrientation, $delta1, $delta2, $apertureSize)

    If $bOrientationIsArray Then
        _VectorOfMatRelease($vectorOfMatOrientation)
    EndIf

    _cveOutputArrayRelease($oArrOrientation)

    If $bMaskIsArray Then
        _VectorOfMatRelease($vectorOfMatMask)
    EndIf

    _cveOutputArrayRelease($oArrMask)

    If $bMhiIsArray Then
        _VectorOfMatRelease($vectorOfMatMhi)
    EndIf

    _cveInputArrayRelease($iArrMhi)
EndFunc   ;==>_cveCalcMotionGradientMat

Func _cveCalcGlobalOrientation($orientation, $mask, $mhi, $timestamp, $duration)
    ; CVAPI(void) cveCalcGlobalOrientation(cv::_InputArray* orientation, cv::_InputArray* mask, cv::_InputArray* mhi, double timestamp, double duration);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCalcGlobalOrientation", "ptr", $orientation, "ptr", $mask, "ptr", $mhi, "double", $timestamp, "double", $duration), "cveCalcGlobalOrientation", @error)
EndFunc   ;==>_cveCalcGlobalOrientation

Func _cveCalcGlobalOrientationMat($matOrientation, $matMask, $matMhi, $timestamp, $duration)
    ; cveCalcGlobalOrientation using cv::Mat instead of _*Array

    Local $iArrOrientation, $vectorOfMatOrientation, $iArrOrientationSize
    Local $bOrientationIsArray = VarGetType($matOrientation) == "Array"

    If $bOrientationIsArray Then
        $vectorOfMatOrientation = _VectorOfMatCreate()

        $iArrOrientationSize = UBound($matOrientation)
        For $i = 0 To $iArrOrientationSize - 1
            _VectorOfMatPush($vectorOfMatOrientation, $matOrientation[$i])
        Next

        $iArrOrientation = _cveInputArrayFromVectorOfMat($vectorOfMatOrientation)
    Else
        $iArrOrientation = _cveInputArrayFromMat($matOrientation)
    EndIf

    Local $iArrMask, $vectorOfMatMask, $iArrMaskSize
    Local $bMaskIsArray = VarGetType($matMask) == "Array"

    If $bMaskIsArray Then
        $vectorOfMatMask = _VectorOfMatCreate()

        $iArrMaskSize = UBound($matMask)
        For $i = 0 To $iArrMaskSize - 1
            _VectorOfMatPush($vectorOfMatMask, $matMask[$i])
        Next

        $iArrMask = _cveInputArrayFromVectorOfMat($vectorOfMatMask)
    Else
        $iArrMask = _cveInputArrayFromMat($matMask)
    EndIf

    Local $iArrMhi, $vectorOfMatMhi, $iArrMhiSize
    Local $bMhiIsArray = VarGetType($matMhi) == "Array"

    If $bMhiIsArray Then
        $vectorOfMatMhi = _VectorOfMatCreate()

        $iArrMhiSize = UBound($matMhi)
        For $i = 0 To $iArrMhiSize - 1
            _VectorOfMatPush($vectorOfMatMhi, $matMhi[$i])
        Next

        $iArrMhi = _cveInputArrayFromVectorOfMat($vectorOfMatMhi)
    Else
        $iArrMhi = _cveInputArrayFromMat($matMhi)
    EndIf

    _cveCalcGlobalOrientation($iArrOrientation, $iArrMask, $iArrMhi, $timestamp, $duration)

    If $bMhiIsArray Then
        _VectorOfMatRelease($vectorOfMatMhi)
    EndIf

    _cveInputArrayRelease($iArrMhi)

    If $bMaskIsArray Then
        _VectorOfMatRelease($vectorOfMatMask)
    EndIf

    _cveInputArrayRelease($iArrMask)

    If $bOrientationIsArray Then
        _VectorOfMatRelease($vectorOfMatOrientation)
    EndIf

    _cveInputArrayRelease($iArrOrientation)
EndFunc   ;==>_cveCalcGlobalOrientationMat

Func _cveSegmentMotion($mhi, $segmask, $boundingRects, $timestamp, $segThresh)
    ; CVAPI(void) cveSegmentMotion(cv::_InputArray* mhi, cv::_OutputArray* segmask, std::vector< cv::Rect >* boundingRects, double timestamp, double segThresh);

    Local $vecBoundingRects, $iArrBoundingRectsSize
    Local $bBoundingRectsIsArray = VarGetType($boundingRects) == "Array"

    If $bBoundingRectsIsArray Then
        $vecBoundingRects = _VectorOfRectCreate()

        $iArrBoundingRectsSize = UBound($boundingRects)
        For $i = 0 To $iArrBoundingRectsSize - 1
            _VectorOfRectPush($vecBoundingRects, $boundingRects[$i])
        Next
    Else
        $vecBoundingRects = $boundingRects
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSegmentMotion", "ptr", $mhi, "ptr", $segmask, "ptr", $vecBoundingRects, "double", $timestamp, "double", $segThresh), "cveSegmentMotion", @error)

    If $bBoundingRectsIsArray Then
        _VectorOfRectRelease($vecBoundingRects)
    EndIf
EndFunc   ;==>_cveSegmentMotion

Func _cveSegmentMotionMat($matMhi, $matSegmask, $boundingRects, $timestamp, $segThresh)
    ; cveSegmentMotion using cv::Mat instead of _*Array

    Local $iArrMhi, $vectorOfMatMhi, $iArrMhiSize
    Local $bMhiIsArray = VarGetType($matMhi) == "Array"

    If $bMhiIsArray Then
        $vectorOfMatMhi = _VectorOfMatCreate()

        $iArrMhiSize = UBound($matMhi)
        For $i = 0 To $iArrMhiSize - 1
            _VectorOfMatPush($vectorOfMatMhi, $matMhi[$i])
        Next

        $iArrMhi = _cveInputArrayFromVectorOfMat($vectorOfMatMhi)
    Else
        $iArrMhi = _cveInputArrayFromMat($matMhi)
    EndIf

    Local $oArrSegmask, $vectorOfMatSegmask, $iArrSegmaskSize
    Local $bSegmaskIsArray = VarGetType($matSegmask) == "Array"

    If $bSegmaskIsArray Then
        $vectorOfMatSegmask = _VectorOfMatCreate()

        $iArrSegmaskSize = UBound($matSegmask)
        For $i = 0 To $iArrSegmaskSize - 1
            _VectorOfMatPush($vectorOfMatSegmask, $matSegmask[$i])
        Next

        $oArrSegmask = _cveOutputArrayFromVectorOfMat($vectorOfMatSegmask)
    Else
        $oArrSegmask = _cveOutputArrayFromMat($matSegmask)
    EndIf

    _cveSegmentMotion($iArrMhi, $oArrSegmask, $boundingRects, $timestamp, $segThresh)

    If $bSegmaskIsArray Then
        _VectorOfMatRelease($vectorOfMatSegmask)
    EndIf

    _cveOutputArrayRelease($oArrSegmask)

    If $bMhiIsArray Then
        _VectorOfMatRelease($vectorOfMatMhi)
    EndIf

    _cveInputArrayRelease($iArrMhi)
EndFunc   ;==>_cveSegmentMotionMat

Func _cveOptFlowDeepFlowCreate($algorithm, $sharedPtr)
    ; CVAPI(cv::DenseOpticalFlow*) cveOptFlowDeepFlowCreate(cv::Algorithm** algorithm, cv::Ptr<cv::DenseOpticalFlow>** sharedPtr);

    Local $bAlgorithmDllType
    If VarGetType($algorithm) == "DLLStruct" Then
        $bAlgorithmDllType = "struct*"
    Else
        $bAlgorithmDllType = "ptr*"
    EndIf

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveOptFlowDeepFlowCreate", $bAlgorithmDllType, $algorithm, $bSharedPtrDllType, $sharedPtr), "cveOptFlowDeepFlowCreate", @error)
EndFunc   ;==>_cveOptFlowDeepFlowCreate

Func _cveOptFlowPCAFlowCreate($algorithm, $sharedPtr)
    ; CVAPI(cv::DenseOpticalFlow*) cveOptFlowPCAFlowCreate(cv::Algorithm** algorithm, cv::Ptr<cv::DenseOpticalFlow>** sharedPtr);

    Local $bAlgorithmDllType
    If VarGetType($algorithm) == "DLLStruct" Then
        $bAlgorithmDllType = "struct*"
    Else
        $bAlgorithmDllType = "ptr*"
    EndIf

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveOptFlowPCAFlowCreate", $bAlgorithmDllType, $algorithm, $bSharedPtrDllType, $sharedPtr), "cveOptFlowPCAFlowCreate", @error)
EndFunc   ;==>_cveOptFlowPCAFlowCreate

Func _cveDenseOpticalFlowCreateDualTVL1($denseOpticalFlow, $algorithm, $sharedPtr)
    ; CVAPI(cv::optflow::DualTVL1OpticalFlow*) cveDenseOpticalFlowCreateDualTVL1(cv::DenseOpticalFlow** denseOpticalFlow, cv::Algorithm** algorithm, cv::Ptr<cv::optflow::DualTVL1OpticalFlow>** sharedPtr);

    Local $bDenseOpticalFlowDllType
    If VarGetType($denseOpticalFlow) == "DLLStruct" Then
        $bDenseOpticalFlowDllType = "struct*"
    Else
        $bDenseOpticalFlowDllType = "ptr*"
    EndIf

    Local $bAlgorithmDllType
    If VarGetType($algorithm) == "DLLStruct" Then
        $bAlgorithmDllType = "struct*"
    Else
        $bAlgorithmDllType = "ptr*"
    EndIf

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveDenseOpticalFlowCreateDualTVL1", $bDenseOpticalFlowDllType, $denseOpticalFlow, $bAlgorithmDllType, $algorithm, $bSharedPtrDllType, $sharedPtr), "cveDenseOpticalFlowCreateDualTVL1", @error)
EndFunc   ;==>_cveDenseOpticalFlowCreateDualTVL1

Func _cveDualTVL1OpticalFlowRelease($sharedPtr)
    ; CVAPI(void) cveDualTVL1OpticalFlowRelease(cv::Ptr<cv::optflow::DualTVL1OpticalFlow>** sharedPtr);

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDualTVL1OpticalFlowRelease", $bSharedPtrDllType, $sharedPtr), "cveDualTVL1OpticalFlowRelease", @error)
EndFunc   ;==>_cveDualTVL1OpticalFlowRelease

Func _cveRLOFOpticalFlowParameterCreate()
    ; CVAPI(cv::optflow::RLOFOpticalFlowParameter*) cveRLOFOpticalFlowParameterCreate();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveRLOFOpticalFlowParameterCreate"), "cveRLOFOpticalFlowParameterCreate", @error)
EndFunc   ;==>_cveRLOFOpticalFlowParameterCreate

Func _cveRLOFOpticalFlowParameterRelease($p)
    ; CVAPI(void) cveRLOFOpticalFlowParameterRelease(cv::optflow::RLOFOpticalFlowParameter** p);

    Local $bPDllType
    If VarGetType($p) == "DLLStruct" Then
        $bPDllType = "struct*"
    Else
        $bPDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveRLOFOpticalFlowParameterRelease", $bPDllType, $p), "cveRLOFOpticalFlowParameterRelease", @error)
EndFunc   ;==>_cveRLOFOpticalFlowParameterRelease

Func _cveDenseRLOFOpticalFlowCreate($rlofParameter, $forwardBackwardThreshold, $gridStep, $interpType, $epicK, $epicSigma, $epicLambda, $usePostProc, $fgsLambda, $fgsSigma, $denseOpticalFlow, $algorithm, $sharedPtr)
    ; CVAPI(cv::optflow::DenseRLOFOpticalFlow*) cveDenseRLOFOpticalFlowCreate(cv::optflow::RLOFOpticalFlowParameter* rlofParameter, float forwardBackwardThreshold, CvSize* gridStep, int interpType, int epicK, float epicSigma, float epicLambda, bool usePostProc, float fgsLambda, float fgsSigma, cv::DenseOpticalFlow** denseOpticalFlow, cv::Algorithm** algorithm, cv::Ptr<cv::optflow::DenseRLOFOpticalFlow>** sharedPtr);

    Local $bDenseOpticalFlowDllType
    If VarGetType($denseOpticalFlow) == "DLLStruct" Then
        $bDenseOpticalFlowDllType = "struct*"
    Else
        $bDenseOpticalFlowDllType = "ptr*"
    EndIf

    Local $bAlgorithmDllType
    If VarGetType($algorithm) == "DLLStruct" Then
        $bAlgorithmDllType = "struct*"
    Else
        $bAlgorithmDllType = "ptr*"
    EndIf

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveDenseRLOFOpticalFlowCreate", "ptr", $rlofParameter, "float", $forwardBackwardThreshold, "struct*", $gridStep, "int", $interpType, "int", $epicK, "float", $epicSigma, "float", $epicLambda, "boolean", $usePostProc, "float", $fgsLambda, "float", $fgsSigma, $bDenseOpticalFlowDllType, $denseOpticalFlow, $bAlgorithmDllType, $algorithm, $bSharedPtrDllType, $sharedPtr), "cveDenseRLOFOpticalFlowCreate", @error)
EndFunc   ;==>_cveDenseRLOFOpticalFlowCreate

Func _cveDenseRLOFOpticalFlowRelease($sharedPtr)
    ; CVAPI(void) cveDenseRLOFOpticalFlowRelease(cv::Ptr<cv::optflow::DenseRLOFOpticalFlow>** sharedPtr);

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDenseRLOFOpticalFlowRelease", $bSharedPtrDllType, $sharedPtr), "cveDenseRLOFOpticalFlowRelease", @error)
EndFunc   ;==>_cveDenseRLOFOpticalFlowRelease

Func _cveSparseRLOFOpticalFlowCreate($rlofParameter, $forwardBackwardThreshold, $sparseOpticalFlow, $algorithm, $sharedPtr)
    ; CVAPI(cv::optflow::SparseRLOFOpticalFlow*) cveSparseRLOFOpticalFlowCreate(cv::optflow::RLOFOpticalFlowParameter* rlofParameter, float forwardBackwardThreshold, cv::SparseOpticalFlow** sparseOpticalFlow, cv::Algorithm** algorithm, cv::Ptr<cv::optflow::SparseRLOFOpticalFlow>** sharedPtr);

    Local $bSparseOpticalFlowDllType
    If VarGetType($sparseOpticalFlow) == "DLLStruct" Then
        $bSparseOpticalFlowDllType = "struct*"
    Else
        $bSparseOpticalFlowDllType = "ptr*"
    EndIf

    Local $bAlgorithmDllType
    If VarGetType($algorithm) == "DLLStruct" Then
        $bAlgorithmDllType = "struct*"
    Else
        $bAlgorithmDllType = "ptr*"
    EndIf

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveSparseRLOFOpticalFlowCreate", "ptr", $rlofParameter, "float", $forwardBackwardThreshold, $bSparseOpticalFlowDllType, $sparseOpticalFlow, $bAlgorithmDllType, $algorithm, $bSharedPtrDllType, $sharedPtr), "cveSparseRLOFOpticalFlowCreate", @error)
EndFunc   ;==>_cveSparseRLOFOpticalFlowCreate

Func _cveSparseRLOFOpticalFlowRelease($sharedPtr)
    ; CVAPI(void) cveSparseRLOFOpticalFlowRelease(cv::Ptr<cv::optflow::SparseRLOFOpticalFlow>** sharedPtr);

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSparseRLOFOpticalFlowRelease", $bSharedPtrDllType, $sharedPtr), "cveSparseRLOFOpticalFlowRelease", @error)
EndFunc   ;==>_cveSparseRLOFOpticalFlowRelease