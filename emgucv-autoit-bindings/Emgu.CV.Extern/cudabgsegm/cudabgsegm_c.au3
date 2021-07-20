#include-once
#include "..\..\CVEUtils.au3"

Func _cudaBackgroundSubtractorMOGCreate($history, $nmixtures, $backgroundRatio, $noiseSigma, $bgSubtractor, $algorithm, $sharedPtr)
    ; CVAPI(cv::cuda::BackgroundSubtractorMOG*) cudaBackgroundSubtractorMOGCreate(int history, int nmixtures, double backgroundRatio, double noiseSigma, cv::BackgroundSubtractor** bgSubtractor, cv::Algorithm** algorithm, cv::Ptr<cv::cuda::BackgroundSubtractorMOG>** sharedPtr);

    Local $bBgSubtractorDllType
    If VarGetType($bgSubtractor) == "DLLStruct" Then
        $bBgSubtractorDllType = "struct*"
    Else
        $bBgSubtractorDllType = "ptr*"
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
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cudaBackgroundSubtractorMOGCreate", "int", $history, "int", $nmixtures, "double", $backgroundRatio, "double", $noiseSigma, $bBgSubtractorDllType, $bgSubtractor, $bAlgorithmDllType, $algorithm, $bSharedPtrDllType, $sharedPtr), "cudaBackgroundSubtractorMOGCreate", @error)
EndFunc   ;==>_cudaBackgroundSubtractorMOGCreate

Func _cudaBackgroundSubtractorMOGApply($mog, $frame, $fgMask, $learningRate, $stream)
    ; CVAPI(void) cudaBackgroundSubtractorMOGApply(cv::cuda::BackgroundSubtractorMOG* mog, cv::_InputArray* frame, cv::_OutputArray* fgMask, double learningRate, cv::cuda::Stream* stream);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaBackgroundSubtractorMOGApply", "ptr", $mog, "ptr", $frame, "ptr", $fgMask, "double", $learningRate, "ptr", $stream), "cudaBackgroundSubtractorMOGApply", @error)
EndFunc   ;==>_cudaBackgroundSubtractorMOGApply

Func _cudaBackgroundSubtractorMOGApplyMat($mog, $matFrame, $matFgMask, $learningRate, $stream)
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

Func _cudaBackgroundSubtractorMOGRelease($mog)
    ; CVAPI(void) cudaBackgroundSubtractorMOGRelease(cv::Ptr<cv::cuda::BackgroundSubtractorMOG>** mog);

    Local $bMogDllType
    If VarGetType($mog) == "DLLStruct" Then
        $bMogDllType = "struct*"
    Else
        $bMogDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaBackgroundSubtractorMOGRelease", $bMogDllType, $mog), "cudaBackgroundSubtractorMOGRelease", @error)
EndFunc   ;==>_cudaBackgroundSubtractorMOGRelease

Func _cudaBackgroundSubtractorMOG2Create($history, $varThreshold, $detectShadows, $bgSubtractor, $algorithm, $sharedPtr)
    ; CVAPI(cv::cuda::BackgroundSubtractorMOG2*) cudaBackgroundSubtractorMOG2Create(int history, double varThreshold, bool detectShadows, cv::BackgroundSubtractor** bgSubtractor, cv::Algorithm** algorithm, cv::Ptr<cv::cuda::BackgroundSubtractorMOG2>** sharedPtr);

    Local $bBgSubtractorDllType
    If VarGetType($bgSubtractor) == "DLLStruct" Then
        $bBgSubtractorDllType = "struct*"
    Else
        $bBgSubtractorDllType = "ptr*"
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
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cudaBackgroundSubtractorMOG2Create", "int", $history, "double", $varThreshold, "boolean", $detectShadows, $bBgSubtractorDllType, $bgSubtractor, $bAlgorithmDllType, $algorithm, $bSharedPtrDllType, $sharedPtr), "cudaBackgroundSubtractorMOG2Create", @error)
EndFunc   ;==>_cudaBackgroundSubtractorMOG2Create

Func _cudaBackgroundSubtractorMOG2Apply($mog, $frame, $fgMask, $learningRate, $stream)
    ; CVAPI(void) cudaBackgroundSubtractorMOG2Apply(cv::cuda::BackgroundSubtractorMOG2* mog, cv::_InputArray* frame, cv::_OutputArray* fgMask, double learningRate, cv::cuda::Stream* stream);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaBackgroundSubtractorMOG2Apply", "ptr", $mog, "ptr", $frame, "ptr", $fgMask, "double", $learningRate, "ptr", $stream), "cudaBackgroundSubtractorMOG2Apply", @error)
EndFunc   ;==>_cudaBackgroundSubtractorMOG2Apply

Func _cudaBackgroundSubtractorMOG2ApplyMat($mog, $matFrame, $matFgMask, $learningRate, $stream)
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

Func _cudaBackgroundSubtractorMOG2Release($mog)
    ; CVAPI(void) cudaBackgroundSubtractorMOG2Release(cv::Ptr<cv::cuda::BackgroundSubtractorMOG2>** mog);

    Local $bMogDllType
    If VarGetType($mog) == "DLLStruct" Then
        $bMogDllType = "struct*"
    Else
        $bMogDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaBackgroundSubtractorMOG2Release", $bMogDllType, $mog), "cudaBackgroundSubtractorMOG2Release", @error)
EndFunc   ;==>_cudaBackgroundSubtractorMOG2Release