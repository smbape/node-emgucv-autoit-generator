#include-once
#include <..\..\CVEUtils.au3>

Func _cudaBackgroundSubtractorMOGCreate($history, $nmixtures, $backgroundRatio, $noiseSigma, ByRef $bgSubtractor, ByRef $algorithm, ByRef $sharedPtr)
    ; CVAPI(cv::cuda::BackgroundSubtractorMOG*) cudaBackgroundSubtractorMOGCreate(int history, int nmixtures, double backgroundRatio, double noiseSigma, cv::BackgroundSubtractor** bgSubtractor, cv::Algorithm** algorithm, cv::Ptr<cv::cuda::BackgroundSubtractorMOG>** sharedPtr);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cudaBackgroundSubtractorMOGCreate", "int", $history, "int", $nmixtures, "double", $backgroundRatio, "double", $noiseSigma, "ptr*", $bgSubtractor, "ptr*", $algorithm, "ptr*", $sharedPtr), "cudaBackgroundSubtractorMOGCreate", @error)
EndFunc   ;==>_cudaBackgroundSubtractorMOGCreate

Func _cudaBackgroundSubtractorMOGApply(ByRef $mog, ByRef $frame, ByRef $fgMask, $learningRate, ByRef $stream)
    ; CVAPI(void) cudaBackgroundSubtractorMOGApply(cv::cuda::BackgroundSubtractorMOG* mog, cv::_InputArray* frame, cv::_OutputArray* fgMask, double learningRate, cv::cuda::Stream* stream);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaBackgroundSubtractorMOGApply", "ptr", $mog, "ptr", $frame, "ptr", $fgMask, "double", $learningRate, "ptr", $stream), "cudaBackgroundSubtractorMOGApply", @error)
EndFunc   ;==>_cudaBackgroundSubtractorMOGApply

Func _cudaBackgroundSubtractorMOGApplyMat(ByRef $mog, ByRef $matFrame, ByRef $matFgMask, $learningRate, ByRef $stream)
    ; cudaBackgroundSubtractorMOGApply using cv::Mat instead of _*Array

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

    _cudaBackgroundSubtractorMOGApply($mog, $iArrFrame, $oArrFgMask, $learningRate, $stream)

    If $bFgMaskIsArray Then
        _VectorOfMatRelease($vectorOfMatFgMask)
    EndIf

    _cveOutputArrayRelease($oArrFgMask)

    If $bFrameIsArray Then
        _VectorOfMatRelease($vectorOfMatFrame)
    EndIf

    _cveInputArrayRelease($iArrFrame)
EndFunc   ;==>_cudaBackgroundSubtractorMOGApplyMat

Func _cudaBackgroundSubtractorMOGRelease(ByRef $mog)
    ; CVAPI(void) cudaBackgroundSubtractorMOGRelease(cv::Ptr<cv::cuda::BackgroundSubtractorMOG>** mog);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaBackgroundSubtractorMOGRelease", "ptr*", $mog), "cudaBackgroundSubtractorMOGRelease", @error)
EndFunc   ;==>_cudaBackgroundSubtractorMOGRelease

Func _cudaBackgroundSubtractorMOG2Create($history, $varThreshold, $detectShadows, ByRef $bgSubtractor, ByRef $algorithm, ByRef $sharedPtr)
    ; CVAPI(cv::cuda::BackgroundSubtractorMOG2*) cudaBackgroundSubtractorMOG2Create(int history, double varThreshold, bool detectShadows, cv::BackgroundSubtractor** bgSubtractor, cv::Algorithm** algorithm, cv::Ptr<cv::cuda::BackgroundSubtractorMOG2>** sharedPtr);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cudaBackgroundSubtractorMOG2Create", "int", $history, "double", $varThreshold, "boolean", $detectShadows, "ptr*", $bgSubtractor, "ptr*", $algorithm, "ptr*", $sharedPtr), "cudaBackgroundSubtractorMOG2Create", @error)
EndFunc   ;==>_cudaBackgroundSubtractorMOG2Create

Func _cudaBackgroundSubtractorMOG2Apply(ByRef $mog, ByRef $frame, ByRef $fgMask, $learningRate, ByRef $stream)
    ; CVAPI(void) cudaBackgroundSubtractorMOG2Apply(cv::cuda::BackgroundSubtractorMOG2* mog, cv::_InputArray* frame, cv::_OutputArray* fgMask, double learningRate, cv::cuda::Stream* stream);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaBackgroundSubtractorMOG2Apply", "ptr", $mog, "ptr", $frame, "ptr", $fgMask, "double", $learningRate, "ptr", $stream), "cudaBackgroundSubtractorMOG2Apply", @error)
EndFunc   ;==>_cudaBackgroundSubtractorMOG2Apply

Func _cudaBackgroundSubtractorMOG2ApplyMat(ByRef $mog, ByRef $matFrame, ByRef $matFgMask, $learningRate, ByRef $stream)
    ; cudaBackgroundSubtractorMOG2Apply using cv::Mat instead of _*Array

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

    _cudaBackgroundSubtractorMOG2Apply($mog, $iArrFrame, $oArrFgMask, $learningRate, $stream)

    If $bFgMaskIsArray Then
        _VectorOfMatRelease($vectorOfMatFgMask)
    EndIf

    _cveOutputArrayRelease($oArrFgMask)

    If $bFrameIsArray Then
        _VectorOfMatRelease($vectorOfMatFrame)
    EndIf

    _cveInputArrayRelease($iArrFrame)
EndFunc   ;==>_cudaBackgroundSubtractorMOG2ApplyMat

Func _cudaBackgroundSubtractorMOG2Release(ByRef $mog)
    ; CVAPI(void) cudaBackgroundSubtractorMOG2Release(cv::Ptr<cv::cuda::BackgroundSubtractorMOG2>** mog);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaBackgroundSubtractorMOG2Release", "ptr*", $mog), "cudaBackgroundSubtractorMOG2Release", @error)
EndFunc   ;==>_cudaBackgroundSubtractorMOG2Release