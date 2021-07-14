#include-once
#include "..\..\CVEUtils.au3"

Func _cudaBackgroundSubtractorGMGCreate($initializationFrames, $decisionThreshold, ByRef $sharedPtr)
    ; CVAPI(cv::cuda::BackgroundSubtractorGMG*) cudaBackgroundSubtractorGMGCreate(int initializationFrames, double decisionThreshold, cv::Ptr<cv::cuda::BackgroundSubtractorGMG>** sharedPtr);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cudaBackgroundSubtractorGMGCreate", "int", $initializationFrames, "double", $decisionThreshold, "ptr*", $sharedPtr), "cudaBackgroundSubtractorGMGCreate", @error)
EndFunc   ;==>_cudaBackgroundSubtractorGMGCreate

Func _cudaBackgroundSubtractorGMGApply(ByRef $gmg, ByRef $frame, ByRef $fgMask, $learningRate, ByRef $stream)
    ; CVAPI(void) cudaBackgroundSubtractorGMGApply(cv::cuda::BackgroundSubtractorGMG* gmg, cv::_InputArray* frame, cv::_OutputArray* fgMask, double learningRate, cv::cuda::Stream* stream);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaBackgroundSubtractorGMGApply", "ptr", $gmg, "ptr", $frame, "ptr", $fgMask, "double", $learningRate, "ptr", $stream), "cudaBackgroundSubtractorGMGApply", @error)
EndFunc   ;==>_cudaBackgroundSubtractorGMGApply

Func _cudaBackgroundSubtractorGMGApplyMat(ByRef $gmg, ByRef $matFrame, ByRef $matFgMask, $learningRate, ByRef $stream)
    ; cudaBackgroundSubtractorGMGApply using cv::Mat instead of _*Array

    Local $iArrFrame, $vectorOfMatFrame, $iArrFrameSize
    Local $bFrameIsArray = VarGetType($matFrame) == "Array"

    If $bFrameIsArray Then
        $vectorOfMatFrame = _VectorOfMatCreate()

        $iArrFrameSize = UBound($matFrame)
        For $i = 0 To $iArrFrameSize - 1
            _VectorOfMatPush($vectorOfMatFrame, $matFrame[$i])
        Next

        $iArrFrame = _cveInputArrayFromVectorOfMat($vectorOfMatFrame)
    Else
        $iArrFrame = _cveInputArrayFromMat($matFrame)
    EndIf

    Local $oArrFgMask, $vectorOfMatFgMask, $iArrFgMaskSize
    Local $bFgMaskIsArray = VarGetType($matFgMask) == "Array"

    If $bFgMaskIsArray Then
        $vectorOfMatFgMask = _VectorOfMatCreate()

        $iArrFgMaskSize = UBound($matFgMask)
        For $i = 0 To $iArrFgMaskSize - 1
            _VectorOfMatPush($vectorOfMatFgMask, $matFgMask[$i])
        Next

        $oArrFgMask = _cveOutputArrayFromVectorOfMat($vectorOfMatFgMask)
    Else
        $oArrFgMask = _cveOutputArrayFromMat($matFgMask)
    EndIf

    _cudaBackgroundSubtractorGMGApply($gmg, $iArrFrame, $oArrFgMask, $learningRate, $stream)

    If $bFgMaskIsArray Then
        _VectorOfMatRelease($vectorOfMatFgMask)
    EndIf

    _cveOutputArrayRelease($oArrFgMask)

    If $bFrameIsArray Then
        _VectorOfMatRelease($vectorOfMatFrame)
    EndIf

    _cveInputArrayRelease($iArrFrame)
EndFunc   ;==>_cudaBackgroundSubtractorGMGApplyMat

Func _cudaBackgroundSubtractorGMGRelease(ByRef $gmg)
    ; CVAPI(void) cudaBackgroundSubtractorGMGRelease(cv::Ptr<cv::cuda::BackgroundSubtractorGMG>** gmg);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaBackgroundSubtractorGMGRelease", "ptr*", $gmg), "cudaBackgroundSubtractorGMGRelease", @error)
EndFunc   ;==>_cudaBackgroundSubtractorGMGRelease

Func _cudaBackgroundSubtractorFGDCreate($Lc, $N1c, $N2c, $Lcc, $N1cc, $N2cc, $isObjWithoutHoles, $performMorphing, $alpha1, $alpha2, $alpha3, $delta, $T, $minArea, ByRef $sharedPtr)
    ; CVAPI(cv::cuda::BackgroundSubtractorFGD*) cudaBackgroundSubtractorFGDCreate(int Lc, int N1c, int N2c, int Lcc, int N1cc, int N2cc, bool isObjWithoutHoles, int performMorphing, float alpha1, float alpha2, float alpha3, float delta, float T, float minArea, cv::Ptr<cv::cuda::BackgroundSubtractorFGD>** sharedPtr);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cudaBackgroundSubtractorFGDCreate", "int", $Lc, "int", $N1c, "int", $N2c, "int", $Lcc, "int", $N1cc, "int", $N2cc, "boolean", $isObjWithoutHoles, "int", $performMorphing, "float", $alpha1, "float", $alpha2, "float", $alpha3, "float", $delta, "float", $T, "float", $minArea, "ptr*", $sharedPtr), "cudaBackgroundSubtractorFGDCreate", @error)
EndFunc   ;==>_cudaBackgroundSubtractorFGDCreate

Func _cudaBackgroundSubtractorFGDApply(ByRef $fgd, ByRef $frame, ByRef $fgMask, $learningRate)
    ; CVAPI(void) cudaBackgroundSubtractorFGDApply(cv::cuda::BackgroundSubtractorFGD* fgd, cv::_InputArray* frame, cv::_OutputArray* fgMask, double learningRate);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaBackgroundSubtractorFGDApply", "ptr", $fgd, "ptr", $frame, "ptr", $fgMask, "double", $learningRate), "cudaBackgroundSubtractorFGDApply", @error)
EndFunc   ;==>_cudaBackgroundSubtractorFGDApply

Func _cudaBackgroundSubtractorFGDApplyMat(ByRef $fgd, ByRef $matFrame, ByRef $matFgMask, $learningRate)
    ; cudaBackgroundSubtractorFGDApply using cv::Mat instead of _*Array

    Local $iArrFrame, $vectorOfMatFrame, $iArrFrameSize
    Local $bFrameIsArray = VarGetType($matFrame) == "Array"

    If $bFrameIsArray Then
        $vectorOfMatFrame = _VectorOfMatCreate()

        $iArrFrameSize = UBound($matFrame)
        For $i = 0 To $iArrFrameSize - 1
            _VectorOfMatPush($vectorOfMatFrame, $matFrame[$i])
        Next

        $iArrFrame = _cveInputArrayFromVectorOfMat($vectorOfMatFrame)
    Else
        $iArrFrame = _cveInputArrayFromMat($matFrame)
    EndIf

    Local $oArrFgMask, $vectorOfMatFgMask, $iArrFgMaskSize
    Local $bFgMaskIsArray = VarGetType($matFgMask) == "Array"

    If $bFgMaskIsArray Then
        $vectorOfMatFgMask = _VectorOfMatCreate()

        $iArrFgMaskSize = UBound($matFgMask)
        For $i = 0 To $iArrFgMaskSize - 1
            _VectorOfMatPush($vectorOfMatFgMask, $matFgMask[$i])
        Next

        $oArrFgMask = _cveOutputArrayFromVectorOfMat($vectorOfMatFgMask)
    Else
        $oArrFgMask = _cveOutputArrayFromMat($matFgMask)
    EndIf

    _cudaBackgroundSubtractorFGDApply($fgd, $iArrFrame, $oArrFgMask, $learningRate)

    If $bFgMaskIsArray Then
        _VectorOfMatRelease($vectorOfMatFgMask)
    EndIf

    _cveOutputArrayRelease($oArrFgMask)

    If $bFrameIsArray Then
        _VectorOfMatRelease($vectorOfMatFrame)
    EndIf

    _cveInputArrayRelease($iArrFrame)
EndFunc   ;==>_cudaBackgroundSubtractorFGDApplyMat

Func _cudaBackgroundSubtractorFGDRelease(ByRef $fgd)
    ; CVAPI(void) cudaBackgroundSubtractorFGDRelease(cv::Ptr<cv::cuda::BackgroundSubtractorFGD>** fgd);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaBackgroundSubtractorFGDRelease", "ptr*", $fgd), "cudaBackgroundSubtractorFGDRelease", @error)
EndFunc   ;==>_cudaBackgroundSubtractorFGDRelease