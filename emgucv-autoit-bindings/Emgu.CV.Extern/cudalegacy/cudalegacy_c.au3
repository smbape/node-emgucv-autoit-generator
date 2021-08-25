#include-once
#include "..\..\CVEUtils.au3"

Func _cudaBackgroundSubtractorGMGCreate($initializationFrames, $decisionThreshold, $sharedPtr)
    ; CVAPI(cv::cuda::BackgroundSubtractorGMG*) cudaBackgroundSubtractorGMGCreate(int initializationFrames, double decisionThreshold, cv::Ptr<cv::cuda::BackgroundSubtractorGMG>** sharedPtr);

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cudaBackgroundSubtractorGMGCreate", "int", $initializationFrames, "double", $decisionThreshold, $sSharedPtrDllType, $sharedPtr), "cudaBackgroundSubtractorGMGCreate", @error)
EndFunc   ;==>_cudaBackgroundSubtractorGMGCreate

Func _cudaBackgroundSubtractorGMGApply($gmg, $frame, $fgMask, $learningRate, $stream)
    ; CVAPI(void) cudaBackgroundSubtractorGMGApply(cv::cuda::BackgroundSubtractorGMG* gmg, cv::_InputArray* frame, cv::_OutputArray* fgMask, double learningRate, cv::cuda::Stream* stream);

    Local $sGmgDllType
    If IsDllStruct($gmg) Then
        $sGmgDllType = "struct*"
    Else
        $sGmgDllType = "ptr"
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaBackgroundSubtractorGMGApply", $sGmgDllType, $gmg, $sFrameDllType, $frame, $sFgMaskDllType, $fgMask, "double", $learningRate, $sStreamDllType, $stream), "cudaBackgroundSubtractorGMGApply", @error)
EndFunc   ;==>_cudaBackgroundSubtractorGMGApply

Func _cudaBackgroundSubtractorGMGApplyTyped($gmg, $typeOfFrame, $frame, $typeOfFgMask, $fgMask, $learningRate, $stream)

    Local $iArrFrame, $vectorFrame, $iArrFrameSize
    Local $bFrameIsArray = IsArray($frame)
    Local $bFrameCreate = IsDllStruct($frame) And $typeOfFrame == "Scalar"

    If $typeOfFrame == Default Then
        $iArrFrame = $frame
    ElseIf $bFrameIsArray Then
        $vectorFrame = Call("_VectorOf" & $typeOfFrame & "Create")

        $iArrFrameSize = UBound($frame)
        For $i = 0 To $iArrFrameSize - 1
            Call("_VectorOf" & $typeOfFrame & "Push", $vectorFrame, $frame[$i])
        Next

        $iArrFrame = Call("_cveInputArrayFromVectorOf" & $typeOfFrame, $vectorFrame)
    Else
        If $bFrameCreate Then
            $frame = Call("_cve" & $typeOfFrame & "Create", $frame)
        EndIf
        $iArrFrame = Call("_cveInputArrayFrom" & $typeOfFrame, $frame)
    EndIf

    Local $oArrFgMask, $vectorFgMask, $iArrFgMaskSize
    Local $bFgMaskIsArray = IsArray($fgMask)
    Local $bFgMaskCreate = IsDllStruct($fgMask) And $typeOfFgMask == "Scalar"

    If $typeOfFgMask == Default Then
        $oArrFgMask = $fgMask
    ElseIf $bFgMaskIsArray Then
        $vectorFgMask = Call("_VectorOf" & $typeOfFgMask & "Create")

        $iArrFgMaskSize = UBound($fgMask)
        For $i = 0 To $iArrFgMaskSize - 1
            Call("_VectorOf" & $typeOfFgMask & "Push", $vectorFgMask, $fgMask[$i])
        Next

        $oArrFgMask = Call("_cveOutputArrayFromVectorOf" & $typeOfFgMask, $vectorFgMask)
    Else
        If $bFgMaskCreate Then
            $fgMask = Call("_cve" & $typeOfFgMask & "Create", $fgMask)
        EndIf
        $oArrFgMask = Call("_cveOutputArrayFrom" & $typeOfFgMask, $fgMask)
    EndIf

    _cudaBackgroundSubtractorGMGApply($gmg, $iArrFrame, $oArrFgMask, $learningRate, $stream)

    If $bFgMaskIsArray Then
        Call("_VectorOf" & $typeOfFgMask & "Release", $vectorFgMask)
    EndIf

    If $typeOfFgMask <> Default Then
        _cveOutputArrayRelease($oArrFgMask)
        If $bFgMaskCreate Then
            Call("_cve" & $typeOfFgMask & "Release", $fgMask)
        EndIf
    EndIf

    If $bFrameIsArray Then
        Call("_VectorOf" & $typeOfFrame & "Release", $vectorFrame)
    EndIf

    If $typeOfFrame <> Default Then
        _cveInputArrayRelease($iArrFrame)
        If $bFrameCreate Then
            Call("_cve" & $typeOfFrame & "Release", $frame)
        EndIf
    EndIf
EndFunc   ;==>_cudaBackgroundSubtractorGMGApplyTyped

Func _cudaBackgroundSubtractorGMGApplyMat($gmg, $frame, $fgMask, $learningRate, $stream)
    ; cudaBackgroundSubtractorGMGApply using cv::Mat instead of _*Array
    _cudaBackgroundSubtractorGMGApplyTyped($gmg, "Mat", $frame, "Mat", $fgMask, $learningRate, $stream)
EndFunc   ;==>_cudaBackgroundSubtractorGMGApplyMat

Func _cudaBackgroundSubtractorGMGRelease($gmg)
    ; CVAPI(void) cudaBackgroundSubtractorGMGRelease(cv::Ptr<cv::cuda::BackgroundSubtractorGMG>** gmg);

    Local $sGmgDllType
    If IsDllStruct($gmg) Then
        $sGmgDllType = "struct*"
    ElseIf $gmg == Null Then
        $sGmgDllType = "ptr"
    Else
        $sGmgDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaBackgroundSubtractorGMGRelease", $sGmgDllType, $gmg), "cudaBackgroundSubtractorGMGRelease", @error)
EndFunc   ;==>_cudaBackgroundSubtractorGMGRelease

Func _cudaBackgroundSubtractorFGDCreate($Lc, $N1c, $N2c, $Lcc, $N1cc, $N2cc, $isObjWithoutHoles, $performMorphing, $alpha1, $alpha2, $alpha3, $delta, $T, $minArea, $sharedPtr)
    ; CVAPI(cv::cuda::BackgroundSubtractorFGD*) cudaBackgroundSubtractorFGDCreate(int Lc, int N1c, int N2c, int Lcc, int N1cc, int N2cc, bool isObjWithoutHoles, int performMorphing, float alpha1, float alpha2, float alpha3, float delta, float T, float minArea, cv::Ptr<cv::cuda::BackgroundSubtractorFGD>** sharedPtr);

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cudaBackgroundSubtractorFGDCreate", "int", $Lc, "int", $N1c, "int", $N2c, "int", $Lcc, "int", $N1cc, "int", $N2cc, "boolean", $isObjWithoutHoles, "int", $performMorphing, "float", $alpha1, "float", $alpha2, "float", $alpha3, "float", $delta, "float", $T, "float", $minArea, $sSharedPtrDllType, $sharedPtr), "cudaBackgroundSubtractorFGDCreate", @error)
EndFunc   ;==>_cudaBackgroundSubtractorFGDCreate

Func _cudaBackgroundSubtractorFGDApply($fgd, $frame, $fgMask, $learningRate)
    ; CVAPI(void) cudaBackgroundSubtractorFGDApply(cv::cuda::BackgroundSubtractorFGD* fgd, cv::_InputArray* frame, cv::_OutputArray* fgMask, double learningRate);

    Local $sFgdDllType
    If IsDllStruct($fgd) Then
        $sFgdDllType = "struct*"
    Else
        $sFgdDllType = "ptr"
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaBackgroundSubtractorFGDApply", $sFgdDllType, $fgd, $sFrameDllType, $frame, $sFgMaskDllType, $fgMask, "double", $learningRate), "cudaBackgroundSubtractorFGDApply", @error)
EndFunc   ;==>_cudaBackgroundSubtractorFGDApply

Func _cudaBackgroundSubtractorFGDApplyTyped($fgd, $typeOfFrame, $frame, $typeOfFgMask, $fgMask, $learningRate)

    Local $iArrFrame, $vectorFrame, $iArrFrameSize
    Local $bFrameIsArray = IsArray($frame)
    Local $bFrameCreate = IsDllStruct($frame) And $typeOfFrame == "Scalar"

    If $typeOfFrame == Default Then
        $iArrFrame = $frame
    ElseIf $bFrameIsArray Then
        $vectorFrame = Call("_VectorOf" & $typeOfFrame & "Create")

        $iArrFrameSize = UBound($frame)
        For $i = 0 To $iArrFrameSize - 1
            Call("_VectorOf" & $typeOfFrame & "Push", $vectorFrame, $frame[$i])
        Next

        $iArrFrame = Call("_cveInputArrayFromVectorOf" & $typeOfFrame, $vectorFrame)
    Else
        If $bFrameCreate Then
            $frame = Call("_cve" & $typeOfFrame & "Create", $frame)
        EndIf
        $iArrFrame = Call("_cveInputArrayFrom" & $typeOfFrame, $frame)
    EndIf

    Local $oArrFgMask, $vectorFgMask, $iArrFgMaskSize
    Local $bFgMaskIsArray = IsArray($fgMask)
    Local $bFgMaskCreate = IsDllStruct($fgMask) And $typeOfFgMask == "Scalar"

    If $typeOfFgMask == Default Then
        $oArrFgMask = $fgMask
    ElseIf $bFgMaskIsArray Then
        $vectorFgMask = Call("_VectorOf" & $typeOfFgMask & "Create")

        $iArrFgMaskSize = UBound($fgMask)
        For $i = 0 To $iArrFgMaskSize - 1
            Call("_VectorOf" & $typeOfFgMask & "Push", $vectorFgMask, $fgMask[$i])
        Next

        $oArrFgMask = Call("_cveOutputArrayFromVectorOf" & $typeOfFgMask, $vectorFgMask)
    Else
        If $bFgMaskCreate Then
            $fgMask = Call("_cve" & $typeOfFgMask & "Create", $fgMask)
        EndIf
        $oArrFgMask = Call("_cveOutputArrayFrom" & $typeOfFgMask, $fgMask)
    EndIf

    _cudaBackgroundSubtractorFGDApply($fgd, $iArrFrame, $oArrFgMask, $learningRate)

    If $bFgMaskIsArray Then
        Call("_VectorOf" & $typeOfFgMask & "Release", $vectorFgMask)
    EndIf

    If $typeOfFgMask <> Default Then
        _cveOutputArrayRelease($oArrFgMask)
        If $bFgMaskCreate Then
            Call("_cve" & $typeOfFgMask & "Release", $fgMask)
        EndIf
    EndIf

    If $bFrameIsArray Then
        Call("_VectorOf" & $typeOfFrame & "Release", $vectorFrame)
    EndIf

    If $typeOfFrame <> Default Then
        _cveInputArrayRelease($iArrFrame)
        If $bFrameCreate Then
            Call("_cve" & $typeOfFrame & "Release", $frame)
        EndIf
    EndIf
EndFunc   ;==>_cudaBackgroundSubtractorFGDApplyTyped

Func _cudaBackgroundSubtractorFGDApplyMat($fgd, $frame, $fgMask, $learningRate)
    ; cudaBackgroundSubtractorFGDApply using cv::Mat instead of _*Array
    _cudaBackgroundSubtractorFGDApplyTyped($fgd, "Mat", $frame, "Mat", $fgMask, $learningRate)
EndFunc   ;==>_cudaBackgroundSubtractorFGDApplyMat

Func _cudaBackgroundSubtractorFGDRelease($fgd)
    ; CVAPI(void) cudaBackgroundSubtractorFGDRelease(cv::Ptr<cv::cuda::BackgroundSubtractorFGD>** fgd);

    Local $sFgdDllType
    If IsDllStruct($fgd) Then
        $sFgdDllType = "struct*"
    ElseIf $fgd == Null Then
        $sFgdDllType = "ptr"
    Else
        $sFgdDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaBackgroundSubtractorFGDRelease", $sFgdDllType, $fgd), "cudaBackgroundSubtractorFGDRelease", @error)
EndFunc   ;==>_cudaBackgroundSubtractorFGDRelease