#include-once
#include "..\..\CVEUtils.au3"

Func _cudaBackgroundSubtractorMOGCreate($history, $nmixtures, $backgroundRatio, $noiseSigma, $bgSubtractor, $algorithm, $sharedPtr)
    ; CVAPI(cv::cuda::BackgroundSubtractorMOG*) cudaBackgroundSubtractorMOGCreate(int history, int nmixtures, double backgroundRatio, double noiseSigma, cv::BackgroundSubtractor** bgSubtractor, cv::Algorithm** algorithm, cv::Ptr<cv::cuda::BackgroundSubtractorMOG>** sharedPtr);

    Local $sBgSubtractorDllType
    If IsDllStruct($bgSubtractor) Then
        $sBgSubtractorDllType = "struct*"
    ElseIf $bgSubtractor == Null Then
        $sBgSubtractorDllType = "ptr"
    Else
        $sBgSubtractorDllType = "ptr*"
    EndIf

    Local $sAlgorithmDllType
    If IsDllStruct($algorithm) Then
        $sAlgorithmDllType = "struct*"
    ElseIf $algorithm == Null Then
        $sAlgorithmDllType = "ptr"
    Else
        $sAlgorithmDllType = "ptr*"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cudaBackgroundSubtractorMOGCreate", "int", $history, "int", $nmixtures, "double", $backgroundRatio, "double", $noiseSigma, $sBgSubtractorDllType, $bgSubtractor, $sAlgorithmDllType, $algorithm, $sSharedPtrDllType, $sharedPtr), "cudaBackgroundSubtractorMOGCreate", @error)
EndFunc   ;==>_cudaBackgroundSubtractorMOGCreate

Func _cudaBackgroundSubtractorMOGApply($mog, $frame, $fgMask, $learningRate, $stream)
    ; CVAPI(void) cudaBackgroundSubtractorMOGApply(cv::cuda::BackgroundSubtractorMOG* mog, cv::_InputArray* frame, cv::_OutputArray* fgMask, double learningRate, cv::cuda::Stream* stream);

    Local $sMogDllType
    If IsDllStruct($mog) Then
        $sMogDllType = "struct*"
    Else
        $sMogDllType = "ptr"
    EndIf

    Local $sFrameDllType
    If IsDllStruct($frame) Then
        $sFrameDllType = "struct*"
    Else
        $sFrameDllType = "ptr"
    EndIf

    Local $sFgMaskDllType
    If IsDllStruct($fgMask) Then
        $sFgMaskDllType = "struct*"
    Else
        $sFgMaskDllType = "ptr"
    EndIf

    Local $sStreamDllType
    If IsDllStruct($stream) Then
        $sStreamDllType = "struct*"
    Else
        $sStreamDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaBackgroundSubtractorMOGApply", $sMogDllType, $mog, $sFrameDllType, $frame, $sFgMaskDllType, $fgMask, "double", $learningRate, $sStreamDllType, $stream), "cudaBackgroundSubtractorMOGApply", @error)
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

    Local $sMogDllType
    If IsDllStruct($mog) Then
        $sMogDllType = "struct*"
    ElseIf $mog == Null Then
        $sMogDllType = "ptr"
    Else
        $sMogDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaBackgroundSubtractorMOGRelease", $sMogDllType, $mog), "cudaBackgroundSubtractorMOGRelease", @error)
EndFunc   ;==>_cudaBackgroundSubtractorMOGRelease

Func _cudaBackgroundSubtractorMOG2Create($history, $varThreshold, $detectShadows, $bgSubtractor, $algorithm, $sharedPtr)
    ; CVAPI(cv::cuda::BackgroundSubtractorMOG2*) cudaBackgroundSubtractorMOG2Create(int history, double varThreshold, bool detectShadows, cv::BackgroundSubtractor** bgSubtractor, cv::Algorithm** algorithm, cv::Ptr<cv::cuda::BackgroundSubtractorMOG2>** sharedPtr);

    Local $sBgSubtractorDllType
    If IsDllStruct($bgSubtractor) Then
        $sBgSubtractorDllType = "struct*"
    ElseIf $bgSubtractor == Null Then
        $sBgSubtractorDllType = "ptr"
    Else
        $sBgSubtractorDllType = "ptr*"
    EndIf

    Local $sAlgorithmDllType
    If IsDllStruct($algorithm) Then
        $sAlgorithmDllType = "struct*"
    ElseIf $algorithm == Null Then
        $sAlgorithmDllType = "ptr"
    Else
        $sAlgorithmDllType = "ptr*"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cudaBackgroundSubtractorMOG2Create", "int", $history, "double", $varThreshold, "boolean", $detectShadows, $sBgSubtractorDllType, $bgSubtractor, $sAlgorithmDllType, $algorithm, $sSharedPtrDllType, $sharedPtr), "cudaBackgroundSubtractorMOG2Create", @error)
EndFunc   ;==>_cudaBackgroundSubtractorMOG2Create

Func _cudaBackgroundSubtractorMOG2Apply($mog, $frame, $fgMask, $learningRate, $stream)
    ; CVAPI(void) cudaBackgroundSubtractorMOG2Apply(cv::cuda::BackgroundSubtractorMOG2* mog, cv::_InputArray* frame, cv::_OutputArray* fgMask, double learningRate, cv::cuda::Stream* stream);

    Local $sMogDllType
    If IsDllStruct($mog) Then
        $sMogDllType = "struct*"
    Else
        $sMogDllType = "ptr"
    EndIf

    Local $sFrameDllType
    If IsDllStruct($frame) Then
        $sFrameDllType = "struct*"
    Else
        $sFrameDllType = "ptr"
    EndIf

    Local $sFgMaskDllType
    If IsDllStruct($fgMask) Then
        $sFgMaskDllType = "struct*"
    Else
        $sFgMaskDllType = "ptr"
    EndIf

    Local $sStreamDllType
    If IsDllStruct($stream) Then
        $sStreamDllType = "struct*"
    Else
        $sStreamDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaBackgroundSubtractorMOG2Apply", $sMogDllType, $mog, $sFrameDllType, $frame, $sFgMaskDllType, $fgMask, "double", $learningRate, $sStreamDllType, $stream), "cudaBackgroundSubtractorMOG2Apply", @error)
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

    Local $sMogDllType
    If IsDllStruct($mog) Then
        $sMogDllType = "struct*"
    ElseIf $mog == Null Then
        $sMogDllType = "ptr"
    Else
        $sMogDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaBackgroundSubtractorMOG2Release", $sMogDllType, $mog), "cudaBackgroundSubtractorMOG2Release", @error)
EndFunc   ;==>_cudaBackgroundSubtractorMOG2Release