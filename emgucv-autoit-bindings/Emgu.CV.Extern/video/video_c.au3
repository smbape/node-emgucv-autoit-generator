#include-once
#include "..\..\CVEUtils.au3"

Func _cveBackgroundSubtractorMOG2Create($history, $varThreshold, $bShadowDetection, $bgSubtractor, $algorithm, $sharedPtr)
    ; CVAPI(cv::BackgroundSubtractorMOG2*) cveBackgroundSubtractorMOG2Create(int history, float varThreshold, bool bShadowDetection, cv::BackgroundSubtractor** bgSubtractor, cv::Algorithm** algorithm, cv::Ptr<cv::BackgroundSubtractorMOG2>** sharedPtr);

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
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveBackgroundSubtractorMOG2Create", "int", $history, "float", $varThreshold, "boolean", $bShadowDetection, $sBgSubtractorDllType, $bgSubtractor, $sAlgorithmDllType, $algorithm, $sSharedPtrDllType, $sharedPtr), "cveBackgroundSubtractorMOG2Create", @error)
EndFunc   ;==>_cveBackgroundSubtractorMOG2Create

Func _cveBackgroundSubtractorMOG2Release($bgSubtractor, $sharedPtr)
    ; CVAPI(void) cveBackgroundSubtractorMOG2Release(cv::BackgroundSubtractorMOG2** bgSubtractor, cv::Ptr<cv::BackgroundSubtractorMOG2>** sharedPtr);

    Local $sBgSubtractorDllType
    If IsDllStruct($bgSubtractor) Then
        $sBgSubtractorDllType = "struct*"
    ElseIf $bgSubtractor == Null Then
        $sBgSubtractorDllType = "ptr"
    Else
        $sBgSubtractorDllType = "ptr*"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBackgroundSubtractorMOG2Release", $sBgSubtractorDllType, $bgSubtractor, $sSharedPtrDllType, $sharedPtr), "cveBackgroundSubtractorMOG2Release", @error)
EndFunc   ;==>_cveBackgroundSubtractorMOG2Release

Func _cveBackgroundSubtractorUpdate($bgSubtractor, $image, $fgmask, $learningRate)
    ; CVAPI(void) cveBackgroundSubtractorUpdate(cv::BackgroundSubtractor* bgSubtractor, cv::_InputArray* image, cv::_OutputArray* fgmask, double learningRate);

    Local $sBgSubtractorDllType
    If IsDllStruct($bgSubtractor) Then
        $sBgSubtractorDllType = "struct*"
    Else
        $sBgSubtractorDllType = "ptr"
    EndIf

    Local $sImageDllType
    If IsDllStruct($image) Then
        $sImageDllType = "struct*"
    Else
        $sImageDllType = "ptr"
    EndIf

    Local $sFgmaskDllType
    If IsDllStruct($fgmask) Then
        $sFgmaskDllType = "struct*"
    Else
        $sFgmaskDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBackgroundSubtractorUpdate", $sBgSubtractorDllType, $bgSubtractor, $sImageDllType, $image, $sFgmaskDllType, $fgmask, "double", $learningRate), "cveBackgroundSubtractorUpdate", @error)
EndFunc   ;==>_cveBackgroundSubtractorUpdate

Func _cveBackgroundSubtractorUpdateTyped($bgSubtractor, $typeOfImage, $image, $typeOfFgmask, $fgmask, $learningRate)

    Local $iArrImage, $vectorImage, $iArrImageSize
    Local $bImageIsArray = IsArray($image)
    Local $bImageCreate = IsDllStruct($image) And $typeOfImage == "Scalar"

    If $typeOfImage == Default Then
        $iArrImage = $image
    ElseIf $bImageIsArray Then
        $vectorImage = Call("_VectorOf" & $typeOfImage & "Create")

        $iArrImageSize = UBound($image)
        For $i = 0 To $iArrImageSize - 1
            Call("_VectorOf" & $typeOfImage & "Push", $vectorImage, $image[$i])
        Next

        $iArrImage = Call("_cveInputArrayFromVectorOf" & $typeOfImage, $vectorImage)
    Else
        If $bImageCreate Then
            $image = Call("_cve" & $typeOfImage & "Create", $image)
        EndIf
        $iArrImage = Call("_cveInputArrayFrom" & $typeOfImage, $image)
    EndIf

    Local $oArrFgmask, $vectorFgmask, $iArrFgmaskSize
    Local $bFgmaskIsArray = IsArray($fgmask)
    Local $bFgmaskCreate = IsDllStruct($fgmask) And $typeOfFgmask == "Scalar"

    If $typeOfFgmask == Default Then
        $oArrFgmask = $fgmask
    ElseIf $bFgmaskIsArray Then
        $vectorFgmask = Call("_VectorOf" & $typeOfFgmask & "Create")

        $iArrFgmaskSize = UBound($fgmask)
        For $i = 0 To $iArrFgmaskSize - 1
            Call("_VectorOf" & $typeOfFgmask & "Push", $vectorFgmask, $fgmask[$i])
        Next

        $oArrFgmask = Call("_cveOutputArrayFromVectorOf" & $typeOfFgmask, $vectorFgmask)
    Else
        If $bFgmaskCreate Then
            $fgmask = Call("_cve" & $typeOfFgmask & "Create", $fgmask)
        EndIf
        $oArrFgmask = Call("_cveOutputArrayFrom" & $typeOfFgmask, $fgmask)
    EndIf

    _cveBackgroundSubtractorUpdate($bgSubtractor, $iArrImage, $oArrFgmask, $learningRate)

    If $bFgmaskIsArray Then
        Call("_VectorOf" & $typeOfFgmask & "Release", $vectorFgmask)
    EndIf

    If $typeOfFgmask <> Default Then
        _cveOutputArrayRelease($oArrFgmask)
        If $bFgmaskCreate Then
            Call("_cve" & $typeOfFgmask & "Release", $fgmask)
        EndIf
    EndIf

    If $bImageIsArray Then
        Call("_VectorOf" & $typeOfImage & "Release", $vectorImage)
    EndIf

    If $typeOfImage <> Default Then
        _cveInputArrayRelease($iArrImage)
        If $bImageCreate Then
            Call("_cve" & $typeOfImage & "Release", $image)
        EndIf
    EndIf
EndFunc   ;==>_cveBackgroundSubtractorUpdateTyped

Func _cveBackgroundSubtractorUpdateMat($bgSubtractor, $image, $fgmask, $learningRate)
    ; cveBackgroundSubtractorUpdate using cv::Mat instead of _*Array
    _cveBackgroundSubtractorUpdateTyped($bgSubtractor, "Mat", $image, "Mat", $fgmask, $learningRate)
EndFunc   ;==>_cveBackgroundSubtractorUpdateMat

Func _cveBackgroundSubtractorGetBackgroundImage($bgSubtractor, $backgroundImage)
    ; CVAPI(void) cveBackgroundSubtractorGetBackgroundImage(cv::BackgroundSubtractor* bgSubtractor, cv::_OutputArray* backgroundImage);

    Local $sBgSubtractorDllType
    If IsDllStruct($bgSubtractor) Then
        $sBgSubtractorDllType = "struct*"
    Else
        $sBgSubtractorDllType = "ptr"
    EndIf

    Local $sBackgroundImageDllType
    If IsDllStruct($backgroundImage) Then
        $sBackgroundImageDllType = "struct*"
    Else
        $sBackgroundImageDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBackgroundSubtractorGetBackgroundImage", $sBgSubtractorDllType, $bgSubtractor, $sBackgroundImageDllType, $backgroundImage), "cveBackgroundSubtractorGetBackgroundImage", @error)
EndFunc   ;==>_cveBackgroundSubtractorGetBackgroundImage

Func _cveBackgroundSubtractorGetBackgroundImageTyped($bgSubtractor, $typeOfBackgroundImage, $backgroundImage)

    Local $oArrBackgroundImage, $vectorBackgroundImage, $iArrBackgroundImageSize
    Local $bBackgroundImageIsArray = IsArray($backgroundImage)
    Local $bBackgroundImageCreate = IsDllStruct($backgroundImage) And $typeOfBackgroundImage == "Scalar"

    If $typeOfBackgroundImage == Default Then
        $oArrBackgroundImage = $backgroundImage
    ElseIf $bBackgroundImageIsArray Then
        $vectorBackgroundImage = Call("_VectorOf" & $typeOfBackgroundImage & "Create")

        $iArrBackgroundImageSize = UBound($backgroundImage)
        For $i = 0 To $iArrBackgroundImageSize - 1
            Call("_VectorOf" & $typeOfBackgroundImage & "Push", $vectorBackgroundImage, $backgroundImage[$i])
        Next

        $oArrBackgroundImage = Call("_cveOutputArrayFromVectorOf" & $typeOfBackgroundImage, $vectorBackgroundImage)
    Else
        If $bBackgroundImageCreate Then
            $backgroundImage = Call("_cve" & $typeOfBackgroundImage & "Create", $backgroundImage)
        EndIf
        $oArrBackgroundImage = Call("_cveOutputArrayFrom" & $typeOfBackgroundImage, $backgroundImage)
    EndIf

    _cveBackgroundSubtractorGetBackgroundImage($bgSubtractor, $oArrBackgroundImage)

    If $bBackgroundImageIsArray Then
        Call("_VectorOf" & $typeOfBackgroundImage & "Release", $vectorBackgroundImage)
    EndIf

    If $typeOfBackgroundImage <> Default Then
        _cveOutputArrayRelease($oArrBackgroundImage)
        If $bBackgroundImageCreate Then
            Call("_cve" & $typeOfBackgroundImage & "Release", $backgroundImage)
        EndIf
    EndIf
EndFunc   ;==>_cveBackgroundSubtractorGetBackgroundImageTyped

Func _cveBackgroundSubtractorGetBackgroundImageMat($bgSubtractor, $backgroundImage)
    ; cveBackgroundSubtractorGetBackgroundImage using cv::Mat instead of _*Array
    _cveBackgroundSubtractorGetBackgroundImageTyped($bgSubtractor, "Mat", $backgroundImage)
EndFunc   ;==>_cveBackgroundSubtractorGetBackgroundImageMat

Func _cveBackgroundSubtractorKNNCreate($history, $dist2Threshold, $detectShadows, $bgSubtractor, $algorithm, $sharedPtr)
    ; CVAPI(cv::BackgroundSubtractorKNN*) cveBackgroundSubtractorKNNCreate(int history, double dist2Threshold, bool detectShadows, cv::BackgroundSubtractor** bgSubtractor, cv::Algorithm** algorithm, cv::Ptr<cv::BackgroundSubtractorKNN>** sharedPtr);

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
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveBackgroundSubtractorKNNCreate", "int", $history, "double", $dist2Threshold, "boolean", $detectShadows, $sBgSubtractorDllType, $bgSubtractor, $sAlgorithmDllType, $algorithm, $sSharedPtrDllType, $sharedPtr), "cveBackgroundSubtractorKNNCreate", @error)
EndFunc   ;==>_cveBackgroundSubtractorKNNCreate

Func _cveBackgroundSubtractorKNNRelease($bgSubtractor, $sharedPtr)
    ; CVAPI(void) cveBackgroundSubtractorKNNRelease(cv::BackgroundSubtractorKNN** bgSubtractor, cv::Ptr<cv::BackgroundSubtractorKNN>** sharedPtr);

    Local $sBgSubtractorDllType
    If IsDllStruct($bgSubtractor) Then
        $sBgSubtractorDllType = "struct*"
    ElseIf $bgSubtractor == Null Then
        $sBgSubtractorDllType = "ptr"
    Else
        $sBgSubtractorDllType = "ptr*"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBackgroundSubtractorKNNRelease", $sBgSubtractorDllType, $bgSubtractor, $sSharedPtrDllType, $sharedPtr), "cveBackgroundSubtractorKNNRelease", @error)
EndFunc   ;==>_cveBackgroundSubtractorKNNRelease

Func _cveFarnebackOpticalFlowCreate($numLevels, $pyrScale, $fastPyramids, $winSize, $numIters, $polyN, $polySigma, $flags, $denseOpticalFlow, $algorithm, $sharedPtr)
    ; CVAPI(cv::FarnebackOpticalFlow*) cveFarnebackOpticalFlowCreate(int numLevels, double pyrScale, bool fastPyramids, int winSize, int numIters, int polyN, double polySigma, int flags, cv::DenseOpticalFlow** denseOpticalFlow, cv::Algorithm** algorithm, cv::Ptr<cv::FarnebackOpticalFlow>** sharedPtr);

    Local $sDenseOpticalFlowDllType
    If IsDllStruct($denseOpticalFlow) Then
        $sDenseOpticalFlowDllType = "struct*"
    ElseIf $denseOpticalFlow == Null Then
        $sDenseOpticalFlowDllType = "ptr"
    Else
        $sDenseOpticalFlowDllType = "ptr*"
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
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveFarnebackOpticalFlowCreate", "int", $numLevels, "double", $pyrScale, "boolean", $fastPyramids, "int", $winSize, "int", $numIters, "int", $polyN, "double", $polySigma, "int", $flags, $sDenseOpticalFlowDllType, $denseOpticalFlow, $sAlgorithmDllType, $algorithm, $sSharedPtrDllType, $sharedPtr), "cveFarnebackOpticalFlowCreate", @error)
EndFunc   ;==>_cveFarnebackOpticalFlowCreate

Func _cveFarnebackOpticalFlowRelease($flow, $sharedPtr)
    ; CVAPI(void) cveFarnebackOpticalFlowRelease(cv::FarnebackOpticalFlow** flow, cv::Ptr<cv::FarnebackOpticalFlow>** sharedPtr);

    Local $sFlowDllType
    If IsDllStruct($flow) Then
        $sFlowDllType = "struct*"
    ElseIf $flow == Null Then
        $sFlowDllType = "ptr"
    Else
        $sFlowDllType = "ptr*"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFarnebackOpticalFlowRelease", $sFlowDllType, $flow, $sSharedPtrDllType, $sharedPtr), "cveFarnebackOpticalFlowRelease", @error)
EndFunc   ;==>_cveFarnebackOpticalFlowRelease

Func _cveDenseOpticalFlowCalc($dof, $i0, $i1, $flow)
    ; CVAPI(void) cveDenseOpticalFlowCalc(cv::DenseOpticalFlow* dof, cv::_InputArray* i0, cv::_InputArray* i1, cv::_InputOutputArray* flow);

    Local $sDofDllType
    If IsDllStruct($dof) Then
        $sDofDllType = "struct*"
    Else
        $sDofDllType = "ptr"
    EndIf

    Local $sI0DllType
    If IsDllStruct($i0) Then
        $sI0DllType = "struct*"
    Else
        $sI0DllType = "ptr"
    EndIf

    Local $sI1DllType
    If IsDllStruct($i1) Then
        $sI1DllType = "struct*"
    Else
        $sI1DllType = "ptr"
    EndIf

    Local $sFlowDllType
    If IsDllStruct($flow) Then
        $sFlowDllType = "struct*"
    Else
        $sFlowDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDenseOpticalFlowCalc", $sDofDllType, $dof, $sI0DllType, $i0, $sI1DllType, $i1, $sFlowDllType, $flow), "cveDenseOpticalFlowCalc", @error)
EndFunc   ;==>_cveDenseOpticalFlowCalc

Func _cveDenseOpticalFlowCalcTyped($dof, $typeOfI0, $i0, $typeOfI1, $i1, $typeOfFlow, $flow)

    Local $iArrI0, $vectorI0, $iArrI0Size
    Local $bI0IsArray = IsArray($i0)
    Local $bI0Create = IsDllStruct($i0) And $typeOfI0 == "Scalar"

    If $typeOfI0 == Default Then
        $iArrI0 = $i0
    ElseIf $bI0IsArray Then
        $vectorI0 = Call("_VectorOf" & $typeOfI0 & "Create")

        $iArrI0Size = UBound($i0)
        For $i = 0 To $iArrI0Size - 1
            Call("_VectorOf" & $typeOfI0 & "Push", $vectorI0, $i0[$i])
        Next

        $iArrI0 = Call("_cveInputArrayFromVectorOf" & $typeOfI0, $vectorI0)
    Else
        If $bI0Create Then
            $i0 = Call("_cve" & $typeOfI0 & "Create", $i0)
        EndIf
        $iArrI0 = Call("_cveInputArrayFrom" & $typeOfI0, $i0)
    EndIf

    Local $iArrI1, $vectorI1, $iArrI1Size
    Local $bI1IsArray = IsArray($i1)
    Local $bI1Create = IsDllStruct($i1) And $typeOfI1 == "Scalar"

    If $typeOfI1 == Default Then
        $iArrI1 = $i1
    ElseIf $bI1IsArray Then
        $vectorI1 = Call("_VectorOf" & $typeOfI1 & "Create")

        $iArrI1Size = UBound($i1)
        For $i = 0 To $iArrI1Size - 1
            Call("_VectorOf" & $typeOfI1 & "Push", $vectorI1, $i1[$i])
        Next

        $iArrI1 = Call("_cveInputArrayFromVectorOf" & $typeOfI1, $vectorI1)
    Else
        If $bI1Create Then
            $i1 = Call("_cve" & $typeOfI1 & "Create", $i1)
        EndIf
        $iArrI1 = Call("_cveInputArrayFrom" & $typeOfI1, $i1)
    EndIf

    Local $ioArrFlow, $vectorFlow, $iArrFlowSize
    Local $bFlowIsArray = IsArray($flow)
    Local $bFlowCreate = IsDllStruct($flow) And $typeOfFlow == "Scalar"

    If $typeOfFlow == Default Then
        $ioArrFlow = $flow
    ElseIf $bFlowIsArray Then
        $vectorFlow = Call("_VectorOf" & $typeOfFlow & "Create")

        $iArrFlowSize = UBound($flow)
        For $i = 0 To $iArrFlowSize - 1
            Call("_VectorOf" & $typeOfFlow & "Push", $vectorFlow, $flow[$i])
        Next

        $ioArrFlow = Call("_cveInputOutputArrayFromVectorOf" & $typeOfFlow, $vectorFlow)
    Else
        If $bFlowCreate Then
            $flow = Call("_cve" & $typeOfFlow & "Create", $flow)
        EndIf
        $ioArrFlow = Call("_cveInputOutputArrayFrom" & $typeOfFlow, $flow)
    EndIf

    _cveDenseOpticalFlowCalc($dof, $iArrI0, $iArrI1, $ioArrFlow)

    If $bFlowIsArray Then
        Call("_VectorOf" & $typeOfFlow & "Release", $vectorFlow)
    EndIf

    If $typeOfFlow <> Default Then
        _cveInputOutputArrayRelease($ioArrFlow)
        If $bFlowCreate Then
            Call("_cve" & $typeOfFlow & "Release", $flow)
        EndIf
    EndIf

    If $bI1IsArray Then
        Call("_VectorOf" & $typeOfI1 & "Release", $vectorI1)
    EndIf

    If $typeOfI1 <> Default Then
        _cveInputArrayRelease($iArrI1)
        If $bI1Create Then
            Call("_cve" & $typeOfI1 & "Release", $i1)
        EndIf
    EndIf

    If $bI0IsArray Then
        Call("_VectorOf" & $typeOfI0 & "Release", $vectorI0)
    EndIf

    If $typeOfI0 <> Default Then
        _cveInputArrayRelease($iArrI0)
        If $bI0Create Then
            Call("_cve" & $typeOfI0 & "Release", $i0)
        EndIf
    EndIf
EndFunc   ;==>_cveDenseOpticalFlowCalcTyped

Func _cveDenseOpticalFlowCalcMat($dof, $i0, $i1, $flow)
    ; cveDenseOpticalFlowCalc using cv::Mat instead of _*Array
    _cveDenseOpticalFlowCalcTyped($dof, "Mat", $i0, "Mat", $i1, "Mat", $flow)
EndFunc   ;==>_cveDenseOpticalFlowCalcMat

Func _cveDenseOpticalFlowRelease($sharedPtr)
    ; CVAPI(void) cveDenseOpticalFlowRelease(cv::Ptr<cv::DenseOpticalFlow>** sharedPtr);

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDenseOpticalFlowRelease", $sSharedPtrDllType, $sharedPtr), "cveDenseOpticalFlowRelease", @error)
EndFunc   ;==>_cveDenseOpticalFlowRelease

Func _cveSparseOpticalFlowCalc($sof, $prevImg, $nextImg, $prevPts, $nextPts, $status, $err)
    ; CVAPI(void) cveSparseOpticalFlowCalc(cv::SparseOpticalFlow* sof, cv::_InputArray* prevImg, cv::_InputArray* nextImg, cv::_InputArray* prevPts, cv::_InputOutputArray* nextPts, cv::_OutputArray* status, cv::_OutputArray* err);

    Local $sSofDllType
    If IsDllStruct($sof) Then
        $sSofDllType = "struct*"
    Else
        $sSofDllType = "ptr"
    EndIf

    Local $sPrevImgDllType
    If IsDllStruct($prevImg) Then
        $sPrevImgDllType = "struct*"
    Else
        $sPrevImgDllType = "ptr"
    EndIf

    Local $sNextImgDllType
    If IsDllStruct($nextImg) Then
        $sNextImgDllType = "struct*"
    Else
        $sNextImgDllType = "ptr"
    EndIf

    Local $sPrevPtsDllType
    If IsDllStruct($prevPts) Then
        $sPrevPtsDllType = "struct*"
    Else
        $sPrevPtsDllType = "ptr"
    EndIf

    Local $sNextPtsDllType
    If IsDllStruct($nextPts) Then
        $sNextPtsDllType = "struct*"
    Else
        $sNextPtsDllType = "ptr"
    EndIf

    Local $sStatusDllType
    If IsDllStruct($status) Then
        $sStatusDllType = "struct*"
    Else
        $sStatusDllType = "ptr"
    EndIf

    Local $sErrDllType
    If IsDllStruct($err) Then
        $sErrDllType = "struct*"
    Else
        $sErrDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSparseOpticalFlowCalc", $sSofDllType, $sof, $sPrevImgDllType, $prevImg, $sNextImgDllType, $nextImg, $sPrevPtsDllType, $prevPts, $sNextPtsDllType, $nextPts, $sStatusDllType, $status, $sErrDllType, $err), "cveSparseOpticalFlowCalc", @error)
EndFunc   ;==>_cveSparseOpticalFlowCalc

Func _cveSparseOpticalFlowCalcTyped($sof, $typeOfPrevImg, $prevImg, $typeOfNextImg, $nextImg, $typeOfPrevPts, $prevPts, $typeOfNextPts, $nextPts, $typeOfStatus, $status, $typeOfErr, $err)

    Local $iArrPrevImg, $vectorPrevImg, $iArrPrevImgSize
    Local $bPrevImgIsArray = IsArray($prevImg)
    Local $bPrevImgCreate = IsDllStruct($prevImg) And $typeOfPrevImg == "Scalar"

    If $typeOfPrevImg == Default Then
        $iArrPrevImg = $prevImg
    ElseIf $bPrevImgIsArray Then
        $vectorPrevImg = Call("_VectorOf" & $typeOfPrevImg & "Create")

        $iArrPrevImgSize = UBound($prevImg)
        For $i = 0 To $iArrPrevImgSize - 1
            Call("_VectorOf" & $typeOfPrevImg & "Push", $vectorPrevImg, $prevImg[$i])
        Next

        $iArrPrevImg = Call("_cveInputArrayFromVectorOf" & $typeOfPrevImg, $vectorPrevImg)
    Else
        If $bPrevImgCreate Then
            $prevImg = Call("_cve" & $typeOfPrevImg & "Create", $prevImg)
        EndIf
        $iArrPrevImg = Call("_cveInputArrayFrom" & $typeOfPrevImg, $prevImg)
    EndIf

    Local $iArrNextImg, $vectorNextImg, $iArrNextImgSize
    Local $bNextImgIsArray = IsArray($nextImg)
    Local $bNextImgCreate = IsDllStruct($nextImg) And $typeOfNextImg == "Scalar"

    If $typeOfNextImg == Default Then
        $iArrNextImg = $nextImg
    ElseIf $bNextImgIsArray Then
        $vectorNextImg = Call("_VectorOf" & $typeOfNextImg & "Create")

        $iArrNextImgSize = UBound($nextImg)
        For $i = 0 To $iArrNextImgSize - 1
            Call("_VectorOf" & $typeOfNextImg & "Push", $vectorNextImg, $nextImg[$i])
        Next

        $iArrNextImg = Call("_cveInputArrayFromVectorOf" & $typeOfNextImg, $vectorNextImg)
    Else
        If $bNextImgCreate Then
            $nextImg = Call("_cve" & $typeOfNextImg & "Create", $nextImg)
        EndIf
        $iArrNextImg = Call("_cveInputArrayFrom" & $typeOfNextImg, $nextImg)
    EndIf

    Local $iArrPrevPts, $vectorPrevPts, $iArrPrevPtsSize
    Local $bPrevPtsIsArray = IsArray($prevPts)
    Local $bPrevPtsCreate = IsDllStruct($prevPts) And $typeOfPrevPts == "Scalar"

    If $typeOfPrevPts == Default Then
        $iArrPrevPts = $prevPts
    ElseIf $bPrevPtsIsArray Then
        $vectorPrevPts = Call("_VectorOf" & $typeOfPrevPts & "Create")

        $iArrPrevPtsSize = UBound($prevPts)
        For $i = 0 To $iArrPrevPtsSize - 1
            Call("_VectorOf" & $typeOfPrevPts & "Push", $vectorPrevPts, $prevPts[$i])
        Next

        $iArrPrevPts = Call("_cveInputArrayFromVectorOf" & $typeOfPrevPts, $vectorPrevPts)
    Else
        If $bPrevPtsCreate Then
            $prevPts = Call("_cve" & $typeOfPrevPts & "Create", $prevPts)
        EndIf
        $iArrPrevPts = Call("_cveInputArrayFrom" & $typeOfPrevPts, $prevPts)
    EndIf

    Local $ioArrNextPts, $vectorNextPts, $iArrNextPtsSize
    Local $bNextPtsIsArray = IsArray($nextPts)
    Local $bNextPtsCreate = IsDllStruct($nextPts) And $typeOfNextPts == "Scalar"

    If $typeOfNextPts == Default Then
        $ioArrNextPts = $nextPts
    ElseIf $bNextPtsIsArray Then
        $vectorNextPts = Call("_VectorOf" & $typeOfNextPts & "Create")

        $iArrNextPtsSize = UBound($nextPts)
        For $i = 0 To $iArrNextPtsSize - 1
            Call("_VectorOf" & $typeOfNextPts & "Push", $vectorNextPts, $nextPts[$i])
        Next

        $ioArrNextPts = Call("_cveInputOutputArrayFromVectorOf" & $typeOfNextPts, $vectorNextPts)
    Else
        If $bNextPtsCreate Then
            $nextPts = Call("_cve" & $typeOfNextPts & "Create", $nextPts)
        EndIf
        $ioArrNextPts = Call("_cveInputOutputArrayFrom" & $typeOfNextPts, $nextPts)
    EndIf

    Local $oArrStatus, $vectorStatus, $iArrStatusSize
    Local $bStatusIsArray = IsArray($status)
    Local $bStatusCreate = IsDllStruct($status) And $typeOfStatus == "Scalar"

    If $typeOfStatus == Default Then
        $oArrStatus = $status
    ElseIf $bStatusIsArray Then
        $vectorStatus = Call("_VectorOf" & $typeOfStatus & "Create")

        $iArrStatusSize = UBound($status)
        For $i = 0 To $iArrStatusSize - 1
            Call("_VectorOf" & $typeOfStatus & "Push", $vectorStatus, $status[$i])
        Next

        $oArrStatus = Call("_cveOutputArrayFromVectorOf" & $typeOfStatus, $vectorStatus)
    Else
        If $bStatusCreate Then
            $status = Call("_cve" & $typeOfStatus & "Create", $status)
        EndIf
        $oArrStatus = Call("_cveOutputArrayFrom" & $typeOfStatus, $status)
    EndIf

    Local $oArrErr, $vectorErr, $iArrErrSize
    Local $bErrIsArray = IsArray($err)
    Local $bErrCreate = IsDllStruct($err) And $typeOfErr == "Scalar"

    If $typeOfErr == Default Then
        $oArrErr = $err
    ElseIf $bErrIsArray Then
        $vectorErr = Call("_VectorOf" & $typeOfErr & "Create")

        $iArrErrSize = UBound($err)
        For $i = 0 To $iArrErrSize - 1
            Call("_VectorOf" & $typeOfErr & "Push", $vectorErr, $err[$i])
        Next

        $oArrErr = Call("_cveOutputArrayFromVectorOf" & $typeOfErr, $vectorErr)
    Else
        If $bErrCreate Then
            $err = Call("_cve" & $typeOfErr & "Create", $err)
        EndIf
        $oArrErr = Call("_cveOutputArrayFrom" & $typeOfErr, $err)
    EndIf

    _cveSparseOpticalFlowCalc($sof, $iArrPrevImg, $iArrNextImg, $iArrPrevPts, $ioArrNextPts, $oArrStatus, $oArrErr)

    If $bErrIsArray Then
        Call("_VectorOf" & $typeOfErr & "Release", $vectorErr)
    EndIf

    If $typeOfErr <> Default Then
        _cveOutputArrayRelease($oArrErr)
        If $bErrCreate Then
            Call("_cve" & $typeOfErr & "Release", $err)
        EndIf
    EndIf

    If $bStatusIsArray Then
        Call("_VectorOf" & $typeOfStatus & "Release", $vectorStatus)
    EndIf

    If $typeOfStatus <> Default Then
        _cveOutputArrayRelease($oArrStatus)
        If $bStatusCreate Then
            Call("_cve" & $typeOfStatus & "Release", $status)
        EndIf
    EndIf

    If $bNextPtsIsArray Then
        Call("_VectorOf" & $typeOfNextPts & "Release", $vectorNextPts)
    EndIf

    If $typeOfNextPts <> Default Then
        _cveInputOutputArrayRelease($ioArrNextPts)
        If $bNextPtsCreate Then
            Call("_cve" & $typeOfNextPts & "Release", $nextPts)
        EndIf
    EndIf

    If $bPrevPtsIsArray Then
        Call("_VectorOf" & $typeOfPrevPts & "Release", $vectorPrevPts)
    EndIf

    If $typeOfPrevPts <> Default Then
        _cveInputArrayRelease($iArrPrevPts)
        If $bPrevPtsCreate Then
            Call("_cve" & $typeOfPrevPts & "Release", $prevPts)
        EndIf
    EndIf

    If $bNextImgIsArray Then
        Call("_VectorOf" & $typeOfNextImg & "Release", $vectorNextImg)
    EndIf

    If $typeOfNextImg <> Default Then
        _cveInputArrayRelease($iArrNextImg)
        If $bNextImgCreate Then
            Call("_cve" & $typeOfNextImg & "Release", $nextImg)
        EndIf
    EndIf

    If $bPrevImgIsArray Then
        Call("_VectorOf" & $typeOfPrevImg & "Release", $vectorPrevImg)
    EndIf

    If $typeOfPrevImg <> Default Then
        _cveInputArrayRelease($iArrPrevImg)
        If $bPrevImgCreate Then
            Call("_cve" & $typeOfPrevImg & "Release", $prevImg)
        EndIf
    EndIf
EndFunc   ;==>_cveSparseOpticalFlowCalcTyped

Func _cveSparseOpticalFlowCalcMat($sof, $prevImg, $nextImg, $prevPts, $nextPts, $status, $err)
    ; cveSparseOpticalFlowCalc using cv::Mat instead of _*Array
    _cveSparseOpticalFlowCalcTyped($sof, "Mat", $prevImg, "Mat", $nextImg, "Mat", $prevPts, "Mat", $nextPts, "Mat", $status, "Mat", $err)
EndFunc   ;==>_cveSparseOpticalFlowCalcMat

Func _cveSparsePyrLKOpticalFlowCreate($winSize, $maxLevel, $crit, $flags, $minEigThreshold, $sparseOpticalFlow, $algorithm, $sharedPtr)
    ; CVAPI(cv::SparsePyrLKOpticalFlow*) cveSparsePyrLKOpticalFlowCreate(CvSize* winSize, int maxLevel, CvTermCriteria* crit, int flags, double minEigThreshold, cv::SparseOpticalFlow** sparseOpticalFlow, cv::Algorithm** algorithm, cv::Ptr<cv::SparsePyrLKOpticalFlow>** sharedPtr);

    Local $sWinSizeDllType
    If IsDllStruct($winSize) Then
        $sWinSizeDllType = "struct*"
    Else
        $sWinSizeDllType = "ptr"
    EndIf

    Local $sCritDllType
    If IsDllStruct($crit) Then
        $sCritDllType = "struct*"
    Else
        $sCritDllType = "ptr"
    EndIf

    Local $sSparseOpticalFlowDllType
    If IsDllStruct($sparseOpticalFlow) Then
        $sSparseOpticalFlowDllType = "struct*"
    ElseIf $sparseOpticalFlow == Null Then
        $sSparseOpticalFlowDllType = "ptr"
    Else
        $sSparseOpticalFlowDllType = "ptr*"
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
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveSparsePyrLKOpticalFlowCreate", $sWinSizeDllType, $winSize, "int", $maxLevel, $sCritDllType, $crit, "int", $flags, "double", $minEigThreshold, $sSparseOpticalFlowDllType, $sparseOpticalFlow, $sAlgorithmDllType, $algorithm, $sSharedPtrDllType, $sharedPtr), "cveSparsePyrLKOpticalFlowCreate", @error)
EndFunc   ;==>_cveSparsePyrLKOpticalFlowCreate

Func _cveSparsePyrLKOpticalFlowRelease($flow, $sharedPtr)
    ; CVAPI(void) cveSparsePyrLKOpticalFlowRelease(cv::SparsePyrLKOpticalFlow** flow, cv::Ptr<cv::SparsePyrLKOpticalFlow>** sharedPtr);

    Local $sFlowDllType
    If IsDllStruct($flow) Then
        $sFlowDllType = "struct*"
    ElseIf $flow == Null Then
        $sFlowDllType = "ptr"
    Else
        $sFlowDllType = "ptr*"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSparsePyrLKOpticalFlowRelease", $sFlowDllType, $flow, $sSharedPtrDllType, $sharedPtr), "cveSparsePyrLKOpticalFlowRelease", @error)
EndFunc   ;==>_cveSparsePyrLKOpticalFlowRelease

Func _cveCalcOpticalFlowFarneback($prev, $next, $flow, $pyrScale, $levels, $winSize, $iterations, $polyN, $polySigma, $flags)
    ; CVAPI(void) cveCalcOpticalFlowFarneback(cv::_InputArray* prev, cv::_InputArray* next, cv::_InputOutputArray* flow, double pyrScale, int levels, int winSize, int iterations, int polyN, double polySigma, int flags);

    Local $sPrevDllType
    If IsDllStruct($prev) Then
        $sPrevDllType = "struct*"
    Else
        $sPrevDllType = "ptr"
    EndIf

    Local $sNextDllType
    If IsDllStruct($next) Then
        $sNextDllType = "struct*"
    Else
        $sNextDllType = "ptr"
    EndIf

    Local $sFlowDllType
    If IsDllStruct($flow) Then
        $sFlowDllType = "struct*"
    Else
        $sFlowDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCalcOpticalFlowFarneback", $sPrevDllType, $prev, $sNextDllType, $next, $sFlowDllType, $flow, "double", $pyrScale, "int", $levels, "int", $winSize, "int", $iterations, "int", $polyN, "double", $polySigma, "int", $flags), "cveCalcOpticalFlowFarneback", @error)
EndFunc   ;==>_cveCalcOpticalFlowFarneback

Func _cveCalcOpticalFlowFarnebackTyped($typeOfPrev, $prev, $typeOfNext, $next, $typeOfFlow, $flow, $pyrScale, $levels, $winSize, $iterations, $polyN, $polySigma, $flags)

    Local $iArrPrev, $vectorPrev, $iArrPrevSize
    Local $bPrevIsArray = IsArray($prev)
    Local $bPrevCreate = IsDllStruct($prev) And $typeOfPrev == "Scalar"

    If $typeOfPrev == Default Then
        $iArrPrev = $prev
    ElseIf $bPrevIsArray Then
        $vectorPrev = Call("_VectorOf" & $typeOfPrev & "Create")

        $iArrPrevSize = UBound($prev)
        For $i = 0 To $iArrPrevSize - 1
            Call("_VectorOf" & $typeOfPrev & "Push", $vectorPrev, $prev[$i])
        Next

        $iArrPrev = Call("_cveInputArrayFromVectorOf" & $typeOfPrev, $vectorPrev)
    Else
        If $bPrevCreate Then
            $prev = Call("_cve" & $typeOfPrev & "Create", $prev)
        EndIf
        $iArrPrev = Call("_cveInputArrayFrom" & $typeOfPrev, $prev)
    EndIf

    Local $iArrNext, $vectorNext, $iArrNextSize
    Local $bNextIsArray = IsArray($next)
    Local $bNextCreate = IsDllStruct($next) And $typeOfNext == "Scalar"

    If $typeOfNext == Default Then
        $iArrNext = $next
    ElseIf $bNextIsArray Then
        $vectorNext = Call("_VectorOf" & $typeOfNext & "Create")

        $iArrNextSize = UBound($next)
        For $i = 0 To $iArrNextSize - 1
            Call("_VectorOf" & $typeOfNext & "Push", $vectorNext, $next[$i])
        Next

        $iArrNext = Call("_cveInputArrayFromVectorOf" & $typeOfNext, $vectorNext)
    Else
        If $bNextCreate Then
            $next = Call("_cve" & $typeOfNext & "Create", $next)
        EndIf
        $iArrNext = Call("_cveInputArrayFrom" & $typeOfNext, $next)
    EndIf

    Local $ioArrFlow, $vectorFlow, $iArrFlowSize
    Local $bFlowIsArray = IsArray($flow)
    Local $bFlowCreate = IsDllStruct($flow) And $typeOfFlow == "Scalar"

    If $typeOfFlow == Default Then
        $ioArrFlow = $flow
    ElseIf $bFlowIsArray Then
        $vectorFlow = Call("_VectorOf" & $typeOfFlow & "Create")

        $iArrFlowSize = UBound($flow)
        For $i = 0 To $iArrFlowSize - 1
            Call("_VectorOf" & $typeOfFlow & "Push", $vectorFlow, $flow[$i])
        Next

        $ioArrFlow = Call("_cveInputOutputArrayFromVectorOf" & $typeOfFlow, $vectorFlow)
    Else
        If $bFlowCreate Then
            $flow = Call("_cve" & $typeOfFlow & "Create", $flow)
        EndIf
        $ioArrFlow = Call("_cveInputOutputArrayFrom" & $typeOfFlow, $flow)
    EndIf

    _cveCalcOpticalFlowFarneback($iArrPrev, $iArrNext, $ioArrFlow, $pyrScale, $levels, $winSize, $iterations, $polyN, $polySigma, $flags)

    If $bFlowIsArray Then
        Call("_VectorOf" & $typeOfFlow & "Release", $vectorFlow)
    EndIf

    If $typeOfFlow <> Default Then
        _cveInputOutputArrayRelease($ioArrFlow)
        If $bFlowCreate Then
            Call("_cve" & $typeOfFlow & "Release", $flow)
        EndIf
    EndIf

    If $bNextIsArray Then
        Call("_VectorOf" & $typeOfNext & "Release", $vectorNext)
    EndIf

    If $typeOfNext <> Default Then
        _cveInputArrayRelease($iArrNext)
        If $bNextCreate Then
            Call("_cve" & $typeOfNext & "Release", $next)
        EndIf
    EndIf

    If $bPrevIsArray Then
        Call("_VectorOf" & $typeOfPrev & "Release", $vectorPrev)
    EndIf

    If $typeOfPrev <> Default Then
        _cveInputArrayRelease($iArrPrev)
        If $bPrevCreate Then
            Call("_cve" & $typeOfPrev & "Release", $prev)
        EndIf
    EndIf
EndFunc   ;==>_cveCalcOpticalFlowFarnebackTyped

Func _cveCalcOpticalFlowFarnebackMat($prev, $next, $flow, $pyrScale, $levels, $winSize, $iterations, $polyN, $polySigma, $flags)
    ; cveCalcOpticalFlowFarneback using cv::Mat instead of _*Array
    _cveCalcOpticalFlowFarnebackTyped("Mat", $prev, "Mat", $next, "Mat", $flow, $pyrScale, $levels, $winSize, $iterations, $polyN, $polySigma, $flags)
EndFunc   ;==>_cveCalcOpticalFlowFarnebackMat

Func _cveCalcOpticalFlowPyrLK($prevImg, $nextImg, $prevPts, $nextPts, $status, $err, $winSize, $maxLevel, $criteria, $flags, $minEigenThreshold)
    ; CVAPI(void) cveCalcOpticalFlowPyrLK(cv::_InputArray* prevImg, cv::_InputArray* nextImg, cv::_InputArray* prevPts, cv::_InputOutputArray* nextPts, cv::_OutputArray* status, cv::_OutputArray* err, CvSize* winSize, int maxLevel, CvTermCriteria* criteria, int flags, double minEigenThreshold);

    Local $sPrevImgDllType
    If IsDllStruct($prevImg) Then
        $sPrevImgDllType = "struct*"
    Else
        $sPrevImgDllType = "ptr"
    EndIf

    Local $sNextImgDllType
    If IsDllStruct($nextImg) Then
        $sNextImgDllType = "struct*"
    Else
        $sNextImgDllType = "ptr"
    EndIf

    Local $sPrevPtsDllType
    If IsDllStruct($prevPts) Then
        $sPrevPtsDllType = "struct*"
    Else
        $sPrevPtsDllType = "ptr"
    EndIf

    Local $sNextPtsDllType
    If IsDllStruct($nextPts) Then
        $sNextPtsDllType = "struct*"
    Else
        $sNextPtsDllType = "ptr"
    EndIf

    Local $sStatusDllType
    If IsDllStruct($status) Then
        $sStatusDllType = "struct*"
    Else
        $sStatusDllType = "ptr"
    EndIf

    Local $sErrDllType
    If IsDllStruct($err) Then
        $sErrDllType = "struct*"
    Else
        $sErrDllType = "ptr"
    EndIf

    Local $sWinSizeDllType
    If IsDllStruct($winSize) Then
        $sWinSizeDllType = "struct*"
    Else
        $sWinSizeDllType = "ptr"
    EndIf

    Local $sCriteriaDllType
    If IsDllStruct($criteria) Then
        $sCriteriaDllType = "struct*"
    Else
        $sCriteriaDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCalcOpticalFlowPyrLK", $sPrevImgDllType, $prevImg, $sNextImgDllType, $nextImg, $sPrevPtsDllType, $prevPts, $sNextPtsDllType, $nextPts, $sStatusDllType, $status, $sErrDllType, $err, $sWinSizeDllType, $winSize, "int", $maxLevel, $sCriteriaDllType, $criteria, "int", $flags, "double", $minEigenThreshold), "cveCalcOpticalFlowPyrLK", @error)
EndFunc   ;==>_cveCalcOpticalFlowPyrLK

Func _cveCalcOpticalFlowPyrLKTyped($typeOfPrevImg, $prevImg, $typeOfNextImg, $nextImg, $typeOfPrevPts, $prevPts, $typeOfNextPts, $nextPts, $typeOfStatus, $status, $typeOfErr, $err, $winSize, $maxLevel, $criteria, $flags, $minEigenThreshold)

    Local $iArrPrevImg, $vectorPrevImg, $iArrPrevImgSize
    Local $bPrevImgIsArray = IsArray($prevImg)
    Local $bPrevImgCreate = IsDllStruct($prevImg) And $typeOfPrevImg == "Scalar"

    If $typeOfPrevImg == Default Then
        $iArrPrevImg = $prevImg
    ElseIf $bPrevImgIsArray Then
        $vectorPrevImg = Call("_VectorOf" & $typeOfPrevImg & "Create")

        $iArrPrevImgSize = UBound($prevImg)
        For $i = 0 To $iArrPrevImgSize - 1
            Call("_VectorOf" & $typeOfPrevImg & "Push", $vectorPrevImg, $prevImg[$i])
        Next

        $iArrPrevImg = Call("_cveInputArrayFromVectorOf" & $typeOfPrevImg, $vectorPrevImg)
    Else
        If $bPrevImgCreate Then
            $prevImg = Call("_cve" & $typeOfPrevImg & "Create", $prevImg)
        EndIf
        $iArrPrevImg = Call("_cveInputArrayFrom" & $typeOfPrevImg, $prevImg)
    EndIf

    Local $iArrNextImg, $vectorNextImg, $iArrNextImgSize
    Local $bNextImgIsArray = IsArray($nextImg)
    Local $bNextImgCreate = IsDllStruct($nextImg) And $typeOfNextImg == "Scalar"

    If $typeOfNextImg == Default Then
        $iArrNextImg = $nextImg
    ElseIf $bNextImgIsArray Then
        $vectorNextImg = Call("_VectorOf" & $typeOfNextImg & "Create")

        $iArrNextImgSize = UBound($nextImg)
        For $i = 0 To $iArrNextImgSize - 1
            Call("_VectorOf" & $typeOfNextImg & "Push", $vectorNextImg, $nextImg[$i])
        Next

        $iArrNextImg = Call("_cveInputArrayFromVectorOf" & $typeOfNextImg, $vectorNextImg)
    Else
        If $bNextImgCreate Then
            $nextImg = Call("_cve" & $typeOfNextImg & "Create", $nextImg)
        EndIf
        $iArrNextImg = Call("_cveInputArrayFrom" & $typeOfNextImg, $nextImg)
    EndIf

    Local $iArrPrevPts, $vectorPrevPts, $iArrPrevPtsSize
    Local $bPrevPtsIsArray = IsArray($prevPts)
    Local $bPrevPtsCreate = IsDllStruct($prevPts) And $typeOfPrevPts == "Scalar"

    If $typeOfPrevPts == Default Then
        $iArrPrevPts = $prevPts
    ElseIf $bPrevPtsIsArray Then
        $vectorPrevPts = Call("_VectorOf" & $typeOfPrevPts & "Create")

        $iArrPrevPtsSize = UBound($prevPts)
        For $i = 0 To $iArrPrevPtsSize - 1
            Call("_VectorOf" & $typeOfPrevPts & "Push", $vectorPrevPts, $prevPts[$i])
        Next

        $iArrPrevPts = Call("_cveInputArrayFromVectorOf" & $typeOfPrevPts, $vectorPrevPts)
    Else
        If $bPrevPtsCreate Then
            $prevPts = Call("_cve" & $typeOfPrevPts & "Create", $prevPts)
        EndIf
        $iArrPrevPts = Call("_cveInputArrayFrom" & $typeOfPrevPts, $prevPts)
    EndIf

    Local $ioArrNextPts, $vectorNextPts, $iArrNextPtsSize
    Local $bNextPtsIsArray = IsArray($nextPts)
    Local $bNextPtsCreate = IsDllStruct($nextPts) And $typeOfNextPts == "Scalar"

    If $typeOfNextPts == Default Then
        $ioArrNextPts = $nextPts
    ElseIf $bNextPtsIsArray Then
        $vectorNextPts = Call("_VectorOf" & $typeOfNextPts & "Create")

        $iArrNextPtsSize = UBound($nextPts)
        For $i = 0 To $iArrNextPtsSize - 1
            Call("_VectorOf" & $typeOfNextPts & "Push", $vectorNextPts, $nextPts[$i])
        Next

        $ioArrNextPts = Call("_cveInputOutputArrayFromVectorOf" & $typeOfNextPts, $vectorNextPts)
    Else
        If $bNextPtsCreate Then
            $nextPts = Call("_cve" & $typeOfNextPts & "Create", $nextPts)
        EndIf
        $ioArrNextPts = Call("_cveInputOutputArrayFrom" & $typeOfNextPts, $nextPts)
    EndIf

    Local $oArrStatus, $vectorStatus, $iArrStatusSize
    Local $bStatusIsArray = IsArray($status)
    Local $bStatusCreate = IsDllStruct($status) And $typeOfStatus == "Scalar"

    If $typeOfStatus == Default Then
        $oArrStatus = $status
    ElseIf $bStatusIsArray Then
        $vectorStatus = Call("_VectorOf" & $typeOfStatus & "Create")

        $iArrStatusSize = UBound($status)
        For $i = 0 To $iArrStatusSize - 1
            Call("_VectorOf" & $typeOfStatus & "Push", $vectorStatus, $status[$i])
        Next

        $oArrStatus = Call("_cveOutputArrayFromVectorOf" & $typeOfStatus, $vectorStatus)
    Else
        If $bStatusCreate Then
            $status = Call("_cve" & $typeOfStatus & "Create", $status)
        EndIf
        $oArrStatus = Call("_cveOutputArrayFrom" & $typeOfStatus, $status)
    EndIf

    Local $oArrErr, $vectorErr, $iArrErrSize
    Local $bErrIsArray = IsArray($err)
    Local $bErrCreate = IsDllStruct($err) And $typeOfErr == "Scalar"

    If $typeOfErr == Default Then
        $oArrErr = $err
    ElseIf $bErrIsArray Then
        $vectorErr = Call("_VectorOf" & $typeOfErr & "Create")

        $iArrErrSize = UBound($err)
        For $i = 0 To $iArrErrSize - 1
            Call("_VectorOf" & $typeOfErr & "Push", $vectorErr, $err[$i])
        Next

        $oArrErr = Call("_cveOutputArrayFromVectorOf" & $typeOfErr, $vectorErr)
    Else
        If $bErrCreate Then
            $err = Call("_cve" & $typeOfErr & "Create", $err)
        EndIf
        $oArrErr = Call("_cveOutputArrayFrom" & $typeOfErr, $err)
    EndIf

    _cveCalcOpticalFlowPyrLK($iArrPrevImg, $iArrNextImg, $iArrPrevPts, $ioArrNextPts, $oArrStatus, $oArrErr, $winSize, $maxLevel, $criteria, $flags, $minEigenThreshold)

    If $bErrIsArray Then
        Call("_VectorOf" & $typeOfErr & "Release", $vectorErr)
    EndIf

    If $typeOfErr <> Default Then
        _cveOutputArrayRelease($oArrErr)
        If $bErrCreate Then
            Call("_cve" & $typeOfErr & "Release", $err)
        EndIf
    EndIf

    If $bStatusIsArray Then
        Call("_VectorOf" & $typeOfStatus & "Release", $vectorStatus)
    EndIf

    If $typeOfStatus <> Default Then
        _cveOutputArrayRelease($oArrStatus)
        If $bStatusCreate Then
            Call("_cve" & $typeOfStatus & "Release", $status)
        EndIf
    EndIf

    If $bNextPtsIsArray Then
        Call("_VectorOf" & $typeOfNextPts & "Release", $vectorNextPts)
    EndIf

    If $typeOfNextPts <> Default Then
        _cveInputOutputArrayRelease($ioArrNextPts)
        If $bNextPtsCreate Then
            Call("_cve" & $typeOfNextPts & "Release", $nextPts)
        EndIf
    EndIf

    If $bPrevPtsIsArray Then
        Call("_VectorOf" & $typeOfPrevPts & "Release", $vectorPrevPts)
    EndIf

    If $typeOfPrevPts <> Default Then
        _cveInputArrayRelease($iArrPrevPts)
        If $bPrevPtsCreate Then
            Call("_cve" & $typeOfPrevPts & "Release", $prevPts)
        EndIf
    EndIf

    If $bNextImgIsArray Then
        Call("_VectorOf" & $typeOfNextImg & "Release", $vectorNextImg)
    EndIf

    If $typeOfNextImg <> Default Then
        _cveInputArrayRelease($iArrNextImg)
        If $bNextImgCreate Then
            Call("_cve" & $typeOfNextImg & "Release", $nextImg)
        EndIf
    EndIf

    If $bPrevImgIsArray Then
        Call("_VectorOf" & $typeOfPrevImg & "Release", $vectorPrevImg)
    EndIf

    If $typeOfPrevImg <> Default Then
        _cveInputArrayRelease($iArrPrevImg)
        If $bPrevImgCreate Then
            Call("_cve" & $typeOfPrevImg & "Release", $prevImg)
        EndIf
    EndIf
EndFunc   ;==>_cveCalcOpticalFlowPyrLKTyped

Func _cveCalcOpticalFlowPyrLKMat($prevImg, $nextImg, $prevPts, $nextPts, $status, $err, $winSize, $maxLevel, $criteria, $flags, $minEigenThreshold)
    ; cveCalcOpticalFlowPyrLK using cv::Mat instead of _*Array
    _cveCalcOpticalFlowPyrLKTyped("Mat", $prevImg, "Mat", $nextImg, "Mat", $prevPts, "Mat", $nextPts, "Mat", $status, "Mat", $err, $winSize, $maxLevel, $criteria, $flags, $minEigenThreshold)
EndFunc   ;==>_cveCalcOpticalFlowPyrLKMat

Func _cveCamShift($probImage, $window, $criteria, $result)
    ; CVAPI(void) cveCamShift(cv::_InputArray* probImage, CvRect* window, CvTermCriteria* criteria, CvBox2D* result);

    Local $sProbImageDllType
    If IsDllStruct($probImage) Then
        $sProbImageDllType = "struct*"
    Else
        $sProbImageDllType = "ptr"
    EndIf

    Local $sWindowDllType
    If IsDllStruct($window) Then
        $sWindowDllType = "struct*"
    Else
        $sWindowDllType = "ptr"
    EndIf

    Local $sCriteriaDllType
    If IsDllStruct($criteria) Then
        $sCriteriaDllType = "struct*"
    Else
        $sCriteriaDllType = "ptr"
    EndIf

    Local $sResultDllType
    If IsDllStruct($result) Then
        $sResultDllType = "struct*"
    Else
        $sResultDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCamShift", $sProbImageDllType, $probImage, $sWindowDllType, $window, $sCriteriaDllType, $criteria, $sResultDllType, $result), "cveCamShift", @error)
EndFunc   ;==>_cveCamShift

Func _cveCamShiftTyped($typeOfProbImage, $probImage, $window, $criteria, $result)

    Local $iArrProbImage, $vectorProbImage, $iArrProbImageSize
    Local $bProbImageIsArray = IsArray($probImage)
    Local $bProbImageCreate = IsDllStruct($probImage) And $typeOfProbImage == "Scalar"

    If $typeOfProbImage == Default Then
        $iArrProbImage = $probImage
    ElseIf $bProbImageIsArray Then
        $vectorProbImage = Call("_VectorOf" & $typeOfProbImage & "Create")

        $iArrProbImageSize = UBound($probImage)
        For $i = 0 To $iArrProbImageSize - 1
            Call("_VectorOf" & $typeOfProbImage & "Push", $vectorProbImage, $probImage[$i])
        Next

        $iArrProbImage = Call("_cveInputArrayFromVectorOf" & $typeOfProbImage, $vectorProbImage)
    Else
        If $bProbImageCreate Then
            $probImage = Call("_cve" & $typeOfProbImage & "Create", $probImage)
        EndIf
        $iArrProbImage = Call("_cveInputArrayFrom" & $typeOfProbImage, $probImage)
    EndIf

    _cveCamShift($iArrProbImage, $window, $criteria, $result)

    If $bProbImageIsArray Then
        Call("_VectorOf" & $typeOfProbImage & "Release", $vectorProbImage)
    EndIf

    If $typeOfProbImage <> Default Then
        _cveInputArrayRelease($iArrProbImage)
        If $bProbImageCreate Then
            Call("_cve" & $typeOfProbImage & "Release", $probImage)
        EndIf
    EndIf
EndFunc   ;==>_cveCamShiftTyped

Func _cveCamShiftMat($probImage, $window, $criteria, $result)
    ; cveCamShift using cv::Mat instead of _*Array
    _cveCamShiftTyped("Mat", $probImage, $window, $criteria, $result)
EndFunc   ;==>_cveCamShiftMat

Func _cveMeanShift($probImage, $window, $criteria)
    ; CVAPI(int) cveMeanShift(cv::_InputArray* probImage, CvRect* window, CvTermCriteria* criteria);

    Local $sProbImageDllType
    If IsDllStruct($probImage) Then
        $sProbImageDllType = "struct*"
    Else
        $sProbImageDllType = "ptr"
    EndIf

    Local $sWindowDllType
    If IsDllStruct($window) Then
        $sWindowDllType = "struct*"
    Else
        $sWindowDllType = "ptr"
    EndIf

    Local $sCriteriaDllType
    If IsDllStruct($criteria) Then
        $sCriteriaDllType = "struct*"
    Else
        $sCriteriaDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveMeanShift", $sProbImageDllType, $probImage, $sWindowDllType, $window, $sCriteriaDllType, $criteria), "cveMeanShift", @error)
EndFunc   ;==>_cveMeanShift

Func _cveMeanShiftTyped($typeOfProbImage, $probImage, $window, $criteria)

    Local $iArrProbImage, $vectorProbImage, $iArrProbImageSize
    Local $bProbImageIsArray = IsArray($probImage)
    Local $bProbImageCreate = IsDllStruct($probImage) And $typeOfProbImage == "Scalar"

    If $typeOfProbImage == Default Then
        $iArrProbImage = $probImage
    ElseIf $bProbImageIsArray Then
        $vectorProbImage = Call("_VectorOf" & $typeOfProbImage & "Create")

        $iArrProbImageSize = UBound($probImage)
        For $i = 0 To $iArrProbImageSize - 1
            Call("_VectorOf" & $typeOfProbImage & "Push", $vectorProbImage, $probImage[$i])
        Next

        $iArrProbImage = Call("_cveInputArrayFromVectorOf" & $typeOfProbImage, $vectorProbImage)
    Else
        If $bProbImageCreate Then
            $probImage = Call("_cve" & $typeOfProbImage & "Create", $probImage)
        EndIf
        $iArrProbImage = Call("_cveInputArrayFrom" & $typeOfProbImage, $probImage)
    EndIf

    Local $retval = _cveMeanShift($iArrProbImage, $window, $criteria)

    If $bProbImageIsArray Then
        Call("_VectorOf" & $typeOfProbImage & "Release", $vectorProbImage)
    EndIf

    If $typeOfProbImage <> Default Then
        _cveInputArrayRelease($iArrProbImage)
        If $bProbImageCreate Then
            Call("_cve" & $typeOfProbImage & "Release", $probImage)
        EndIf
    EndIf

    Return $retval
EndFunc   ;==>_cveMeanShiftTyped

Func _cveMeanShiftMat($probImage, $window, $criteria)
    ; cveMeanShift using cv::Mat instead of _*Array
    Local $retval = _cveMeanShiftTyped("Mat", $probImage, $window, $criteria)

    Return $retval
EndFunc   ;==>_cveMeanShiftMat

Func _cveBuildOpticalFlowPyramid($img, $pyramid, $winSize, $maxLevel, $withDerivatives = true, $pyrBorder = $CV_BORDER_REFLECT_101, $derivBorder = $CV_BORDER_CONSTANT, $tryReuseInputImage = true)
    ; CVAPI(int) cveBuildOpticalFlowPyramid(cv::_InputArray* img, cv::_OutputArray* pyramid, CvSize* winSize, int maxLevel, bool withDerivatives, int pyrBorder, int derivBorder, bool tryReuseInputImage);

    Local $sImgDllType
    If IsDllStruct($img) Then
        $sImgDllType = "struct*"
    Else
        $sImgDllType = "ptr"
    EndIf

    Local $sPyramidDllType
    If IsDllStruct($pyramid) Then
        $sPyramidDllType = "struct*"
    Else
        $sPyramidDllType = "ptr"
    EndIf

    Local $sWinSizeDllType
    If IsDllStruct($winSize) Then
        $sWinSizeDllType = "struct*"
    Else
        $sWinSizeDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveBuildOpticalFlowPyramid", $sImgDllType, $img, $sPyramidDllType, $pyramid, $sWinSizeDllType, $winSize, "int", $maxLevel, "boolean", $withDerivatives, "int", $pyrBorder, "int", $derivBorder, "boolean", $tryReuseInputImage), "cveBuildOpticalFlowPyramid", @error)
EndFunc   ;==>_cveBuildOpticalFlowPyramid

Func _cveBuildOpticalFlowPyramidTyped($typeOfImg, $img, $typeOfPyramid, $pyramid, $winSize, $maxLevel, $withDerivatives = true, $pyrBorder = $CV_BORDER_REFLECT_101, $derivBorder = $CV_BORDER_CONSTANT, $tryReuseInputImage = true)

    Local $iArrImg, $vectorImg, $iArrImgSize
    Local $bImgIsArray = IsArray($img)
    Local $bImgCreate = IsDllStruct($img) And $typeOfImg == "Scalar"

    If $typeOfImg == Default Then
        $iArrImg = $img
    ElseIf $bImgIsArray Then
        $vectorImg = Call("_VectorOf" & $typeOfImg & "Create")

        $iArrImgSize = UBound($img)
        For $i = 0 To $iArrImgSize - 1
            Call("_VectorOf" & $typeOfImg & "Push", $vectorImg, $img[$i])
        Next

        $iArrImg = Call("_cveInputArrayFromVectorOf" & $typeOfImg, $vectorImg)
    Else
        If $bImgCreate Then
            $img = Call("_cve" & $typeOfImg & "Create", $img)
        EndIf
        $iArrImg = Call("_cveInputArrayFrom" & $typeOfImg, $img)
    EndIf

    Local $oArrPyramid, $vectorPyramid, $iArrPyramidSize
    Local $bPyramidIsArray = IsArray($pyramid)
    Local $bPyramidCreate = IsDllStruct($pyramid) And $typeOfPyramid == "Scalar"

    If $typeOfPyramid == Default Then
        $oArrPyramid = $pyramid
    ElseIf $bPyramidIsArray Then
        $vectorPyramid = Call("_VectorOf" & $typeOfPyramid & "Create")

        $iArrPyramidSize = UBound($pyramid)
        For $i = 0 To $iArrPyramidSize - 1
            Call("_VectorOf" & $typeOfPyramid & "Push", $vectorPyramid, $pyramid[$i])
        Next

        $oArrPyramid = Call("_cveOutputArrayFromVectorOf" & $typeOfPyramid, $vectorPyramid)
    Else
        If $bPyramidCreate Then
            $pyramid = Call("_cve" & $typeOfPyramid & "Create", $pyramid)
        EndIf
        $oArrPyramid = Call("_cveOutputArrayFrom" & $typeOfPyramid, $pyramid)
    EndIf

    Local $retval = _cveBuildOpticalFlowPyramid($iArrImg, $oArrPyramid, $winSize, $maxLevel, $withDerivatives, $pyrBorder, $derivBorder, $tryReuseInputImage)

    If $bPyramidIsArray Then
        Call("_VectorOf" & $typeOfPyramid & "Release", $vectorPyramid)
    EndIf

    If $typeOfPyramid <> Default Then
        _cveOutputArrayRelease($oArrPyramid)
        If $bPyramidCreate Then
            Call("_cve" & $typeOfPyramid & "Release", $pyramid)
        EndIf
    EndIf

    If $bImgIsArray Then
        Call("_VectorOf" & $typeOfImg & "Release", $vectorImg)
    EndIf

    If $typeOfImg <> Default Then
        _cveInputArrayRelease($iArrImg)
        If $bImgCreate Then
            Call("_cve" & $typeOfImg & "Release", $img)
        EndIf
    EndIf

    Return $retval
EndFunc   ;==>_cveBuildOpticalFlowPyramidTyped

Func _cveBuildOpticalFlowPyramidMat($img, $pyramid, $winSize, $maxLevel, $withDerivatives = true, $pyrBorder = $CV_BORDER_REFLECT_101, $derivBorder = $CV_BORDER_CONSTANT, $tryReuseInputImage = true)
    ; cveBuildOpticalFlowPyramid using cv::Mat instead of _*Array
    Local $retval = _cveBuildOpticalFlowPyramidTyped("Mat", $img, "Mat", $pyramid, $winSize, $maxLevel, $withDerivatives, $pyrBorder, $derivBorder, $tryReuseInputImage)

    Return $retval
EndFunc   ;==>_cveBuildOpticalFlowPyramidMat

Func _cveFindTransformECC($templateImage, $inputImage, $warpMatrix, $motionType, $criteria, $inputMask)
    ; CVAPI(double) cveFindTransformECC(cv::_InputArray* templateImage, cv::_InputArray* inputImage, cv::_InputOutputArray* warpMatrix, int motionType, CvTermCriteria* criteria, cv::_InputArray* inputMask);

    Local $sTemplateImageDllType
    If IsDllStruct($templateImage) Then
        $sTemplateImageDllType = "struct*"
    Else
        $sTemplateImageDllType = "ptr"
    EndIf

    Local $sInputImageDllType
    If IsDllStruct($inputImage) Then
        $sInputImageDllType = "struct*"
    Else
        $sInputImageDllType = "ptr"
    EndIf

    Local $sWarpMatrixDllType
    If IsDllStruct($warpMatrix) Then
        $sWarpMatrixDllType = "struct*"
    Else
        $sWarpMatrixDllType = "ptr"
    EndIf

    Local $sCriteriaDllType
    If IsDllStruct($criteria) Then
        $sCriteriaDllType = "struct*"
    Else
        $sCriteriaDllType = "ptr"
    EndIf

    Local $sInputMaskDllType
    If IsDllStruct($inputMask) Then
        $sInputMaskDllType = "struct*"
    Else
        $sInputMaskDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveFindTransformECC", $sTemplateImageDllType, $templateImage, $sInputImageDllType, $inputImage, $sWarpMatrixDllType, $warpMatrix, "int", $motionType, $sCriteriaDllType, $criteria, $sInputMaskDllType, $inputMask), "cveFindTransformECC", @error)
EndFunc   ;==>_cveFindTransformECC

Func _cveFindTransformECCTyped($typeOfTemplateImage, $templateImage, $typeOfInputImage, $inputImage, $typeOfWarpMatrix, $warpMatrix, $motionType, $criteria, $typeOfInputMask, $inputMask)

    Local $iArrTemplateImage, $vectorTemplateImage, $iArrTemplateImageSize
    Local $bTemplateImageIsArray = IsArray($templateImage)
    Local $bTemplateImageCreate = IsDllStruct($templateImage) And $typeOfTemplateImage == "Scalar"

    If $typeOfTemplateImage == Default Then
        $iArrTemplateImage = $templateImage
    ElseIf $bTemplateImageIsArray Then
        $vectorTemplateImage = Call("_VectorOf" & $typeOfTemplateImage & "Create")

        $iArrTemplateImageSize = UBound($templateImage)
        For $i = 0 To $iArrTemplateImageSize - 1
            Call("_VectorOf" & $typeOfTemplateImage & "Push", $vectorTemplateImage, $templateImage[$i])
        Next

        $iArrTemplateImage = Call("_cveInputArrayFromVectorOf" & $typeOfTemplateImage, $vectorTemplateImage)
    Else
        If $bTemplateImageCreate Then
            $templateImage = Call("_cve" & $typeOfTemplateImage & "Create", $templateImage)
        EndIf
        $iArrTemplateImage = Call("_cveInputArrayFrom" & $typeOfTemplateImage, $templateImage)
    EndIf

    Local $iArrInputImage, $vectorInputImage, $iArrInputImageSize
    Local $bInputImageIsArray = IsArray($inputImage)
    Local $bInputImageCreate = IsDllStruct($inputImage) And $typeOfInputImage == "Scalar"

    If $typeOfInputImage == Default Then
        $iArrInputImage = $inputImage
    ElseIf $bInputImageIsArray Then
        $vectorInputImage = Call("_VectorOf" & $typeOfInputImage & "Create")

        $iArrInputImageSize = UBound($inputImage)
        For $i = 0 To $iArrInputImageSize - 1
            Call("_VectorOf" & $typeOfInputImage & "Push", $vectorInputImage, $inputImage[$i])
        Next

        $iArrInputImage = Call("_cveInputArrayFromVectorOf" & $typeOfInputImage, $vectorInputImage)
    Else
        If $bInputImageCreate Then
            $inputImage = Call("_cve" & $typeOfInputImage & "Create", $inputImage)
        EndIf
        $iArrInputImage = Call("_cveInputArrayFrom" & $typeOfInputImage, $inputImage)
    EndIf

    Local $ioArrWarpMatrix, $vectorWarpMatrix, $iArrWarpMatrixSize
    Local $bWarpMatrixIsArray = IsArray($warpMatrix)
    Local $bWarpMatrixCreate = IsDllStruct($warpMatrix) And $typeOfWarpMatrix == "Scalar"

    If $typeOfWarpMatrix == Default Then
        $ioArrWarpMatrix = $warpMatrix
    ElseIf $bWarpMatrixIsArray Then
        $vectorWarpMatrix = Call("_VectorOf" & $typeOfWarpMatrix & "Create")

        $iArrWarpMatrixSize = UBound($warpMatrix)
        For $i = 0 To $iArrWarpMatrixSize - 1
            Call("_VectorOf" & $typeOfWarpMatrix & "Push", $vectorWarpMatrix, $warpMatrix[$i])
        Next

        $ioArrWarpMatrix = Call("_cveInputOutputArrayFromVectorOf" & $typeOfWarpMatrix, $vectorWarpMatrix)
    Else
        If $bWarpMatrixCreate Then
            $warpMatrix = Call("_cve" & $typeOfWarpMatrix & "Create", $warpMatrix)
        EndIf
        $ioArrWarpMatrix = Call("_cveInputOutputArrayFrom" & $typeOfWarpMatrix, $warpMatrix)
    EndIf

    Local $iArrInputMask, $vectorInputMask, $iArrInputMaskSize
    Local $bInputMaskIsArray = IsArray($inputMask)
    Local $bInputMaskCreate = IsDllStruct($inputMask) And $typeOfInputMask == "Scalar"

    If $typeOfInputMask == Default Then
        $iArrInputMask = $inputMask
    ElseIf $bInputMaskIsArray Then
        $vectorInputMask = Call("_VectorOf" & $typeOfInputMask & "Create")

        $iArrInputMaskSize = UBound($inputMask)
        For $i = 0 To $iArrInputMaskSize - 1
            Call("_VectorOf" & $typeOfInputMask & "Push", $vectorInputMask, $inputMask[$i])
        Next

        $iArrInputMask = Call("_cveInputArrayFromVectorOf" & $typeOfInputMask, $vectorInputMask)
    Else
        If $bInputMaskCreate Then
            $inputMask = Call("_cve" & $typeOfInputMask & "Create", $inputMask)
        EndIf
        $iArrInputMask = Call("_cveInputArrayFrom" & $typeOfInputMask, $inputMask)
    EndIf

    Local $retval = _cveFindTransformECC($iArrTemplateImage, $iArrInputImage, $ioArrWarpMatrix, $motionType, $criteria, $iArrInputMask)

    If $bInputMaskIsArray Then
        Call("_VectorOf" & $typeOfInputMask & "Release", $vectorInputMask)
    EndIf

    If $typeOfInputMask <> Default Then
        _cveInputArrayRelease($iArrInputMask)
        If $bInputMaskCreate Then
            Call("_cve" & $typeOfInputMask & "Release", $inputMask)
        EndIf
    EndIf

    If $bWarpMatrixIsArray Then
        Call("_VectorOf" & $typeOfWarpMatrix & "Release", $vectorWarpMatrix)
    EndIf

    If $typeOfWarpMatrix <> Default Then
        _cveInputOutputArrayRelease($ioArrWarpMatrix)
        If $bWarpMatrixCreate Then
            Call("_cve" & $typeOfWarpMatrix & "Release", $warpMatrix)
        EndIf
    EndIf

    If $bInputImageIsArray Then
        Call("_VectorOf" & $typeOfInputImage & "Release", $vectorInputImage)
    EndIf

    If $typeOfInputImage <> Default Then
        _cveInputArrayRelease($iArrInputImage)
        If $bInputImageCreate Then
            Call("_cve" & $typeOfInputImage & "Release", $inputImage)
        EndIf
    EndIf

    If $bTemplateImageIsArray Then
        Call("_VectorOf" & $typeOfTemplateImage & "Release", $vectorTemplateImage)
    EndIf

    If $typeOfTemplateImage <> Default Then
        _cveInputArrayRelease($iArrTemplateImage)
        If $bTemplateImageCreate Then
            Call("_cve" & $typeOfTemplateImage & "Release", $templateImage)
        EndIf
    EndIf

    Return $retval
EndFunc   ;==>_cveFindTransformECCTyped

Func _cveFindTransformECCMat($templateImage, $inputImage, $warpMatrix, $motionType, $criteria, $inputMask)
    ; cveFindTransformECC using cv::Mat instead of _*Array
    Local $retval = _cveFindTransformECCTyped("Mat", $templateImage, "Mat", $inputImage, "Mat", $warpMatrix, $motionType, $criteria, "Mat", $inputMask)

    Return $retval
EndFunc   ;==>_cveFindTransformECCMat

Func _cveKalmanFilterCreate($dynamParams, $measureParams, $controlParams, $type)
    ; CVAPI(cv::KalmanFilter*) cveKalmanFilterCreate(int dynamParams, int measureParams, int controlParams, int type);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveKalmanFilterCreate", "int", $dynamParams, "int", $measureParams, "int", $controlParams, "int", $type), "cveKalmanFilterCreate", @error)
EndFunc   ;==>_cveKalmanFilterCreate

Func _cveKalmanFilterRelease($filter)
    ; CVAPI(void) cveKalmanFilterRelease(cv::KalmanFilter** filter);

    Local $sFilterDllType
    If IsDllStruct($filter) Then
        $sFilterDllType = "struct*"
    ElseIf $filter == Null Then
        $sFilterDllType = "ptr"
    Else
        $sFilterDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveKalmanFilterRelease", $sFilterDllType, $filter), "cveKalmanFilterRelease", @error)
EndFunc   ;==>_cveKalmanFilterRelease

Func _cveKalmanFilterPredict($kalman, $control)
    ; CVAPI(const cv::Mat*) cveKalmanFilterPredict(cv::KalmanFilter* kalman, cv::Mat* control);

    Local $sKalmanDllType
    If IsDllStruct($kalman) Then
        $sKalmanDllType = "struct*"
    Else
        $sKalmanDllType = "ptr"
    EndIf

    Local $sControlDllType
    If IsDllStruct($control) Then
        $sControlDllType = "struct*"
    Else
        $sControlDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveKalmanFilterPredict", $sKalmanDllType, $kalman, $sControlDllType, $control), "cveKalmanFilterPredict", @error)
EndFunc   ;==>_cveKalmanFilterPredict

Func _cveKalmanFilterCorrect($kalman, $measurement)
    ; CVAPI(const cv::Mat*) cveKalmanFilterCorrect(cv::KalmanFilter* kalman, cv::Mat* measurement);

    Local $sKalmanDllType
    If IsDllStruct($kalman) Then
        $sKalmanDllType = "struct*"
    Else
        $sKalmanDllType = "ptr"
    EndIf

    Local $sMeasurementDllType
    If IsDllStruct($measurement) Then
        $sMeasurementDllType = "struct*"
    Else
        $sMeasurementDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveKalmanFilterCorrect", $sKalmanDllType, $kalman, $sMeasurementDllType, $measurement), "cveKalmanFilterCorrect", @error)
EndFunc   ;==>_cveKalmanFilterCorrect

Func _cveDISOpticalFlowCreate($preset, $denseFlow, $algorithm, $sharedPtr)
    ; CVAPI(cv::DISOpticalFlow*) cveDISOpticalFlowCreate(int preset, cv::DenseOpticalFlow** denseFlow, cv::Algorithm** algorithm, cv::Ptr<cv::DISOpticalFlow>** sharedPtr);

    Local $sDenseFlowDllType
    If IsDllStruct($denseFlow) Then
        $sDenseFlowDllType = "struct*"
    ElseIf $denseFlow == Null Then
        $sDenseFlowDllType = "ptr"
    Else
        $sDenseFlowDllType = "ptr*"
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
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveDISOpticalFlowCreate", "int", $preset, $sDenseFlowDllType, $denseFlow, $sAlgorithmDllType, $algorithm, $sSharedPtrDllType, $sharedPtr), "cveDISOpticalFlowCreate", @error)
EndFunc   ;==>_cveDISOpticalFlowCreate

Func _cveDISOpticalFlowRelease($flow, $sharedPtr)
    ; CVAPI(void) cveDISOpticalFlowRelease(cv::DISOpticalFlow** flow, cv::Ptr<cv::DISOpticalFlow>** sharedPtr);

    Local $sFlowDllType
    If IsDllStruct($flow) Then
        $sFlowDllType = "struct*"
    ElseIf $flow == Null Then
        $sFlowDllType = "ptr"
    Else
        $sFlowDllType = "ptr*"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDISOpticalFlowRelease", $sFlowDllType, $flow, $sSharedPtrDllType, $sharedPtr), "cveDISOpticalFlowRelease", @error)
EndFunc   ;==>_cveDISOpticalFlowRelease

Func _cveVariationalRefinementCreate($denseFlow, $algorithm, $sharedPtr)
    ; CVAPI(cv::VariationalRefinement*) cveVariationalRefinementCreate(cv::DenseOpticalFlow** denseFlow, cv::Algorithm** algorithm, cv::Ptr<cv::VariationalRefinement>** sharedPtr);

    Local $sDenseFlowDllType
    If IsDllStruct($denseFlow) Then
        $sDenseFlowDllType = "struct*"
    ElseIf $denseFlow == Null Then
        $sDenseFlowDllType = "ptr"
    Else
        $sDenseFlowDllType = "ptr*"
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
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveVariationalRefinementCreate", $sDenseFlowDllType, $denseFlow, $sAlgorithmDllType, $algorithm, $sSharedPtrDllType, $sharedPtr), "cveVariationalRefinementCreate", @error)
EndFunc   ;==>_cveVariationalRefinementCreate

Func _cveVariationalRefinementRelease($flow, $sharedPtr)
    ; CVAPI(void) cveVariationalRefinementRelease(cv::VariationalRefinement** flow, cv::Ptr<cv::VariationalRefinement>** sharedPtr);

    Local $sFlowDllType
    If IsDllStruct($flow) Then
        $sFlowDllType = "struct*"
    ElseIf $flow == Null Then
        $sFlowDllType = "ptr"
    Else
        $sFlowDllType = "ptr*"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveVariationalRefinementRelease", $sFlowDllType, $flow, $sSharedPtrDllType, $sharedPtr), "cveVariationalRefinementRelease", @error)
EndFunc   ;==>_cveVariationalRefinementRelease

Func _cveTrackerInit($tracker, $image, $boundingBox)
    ; CVAPI(void) cveTrackerInit(cv::Tracker* tracker, cv::Mat* image, CvRect* boundingBox);

    Local $sTrackerDllType
    If IsDllStruct($tracker) Then
        $sTrackerDllType = "struct*"
    Else
        $sTrackerDllType = "ptr"
    EndIf

    Local $sImageDllType
    If IsDllStruct($image) Then
        $sImageDllType = "struct*"
    Else
        $sImageDllType = "ptr"
    EndIf

    Local $sBoundingBoxDllType
    If IsDllStruct($boundingBox) Then
        $sBoundingBoxDllType = "struct*"
    Else
        $sBoundingBoxDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveTrackerInit", $sTrackerDllType, $tracker, $sImageDllType, $image, $sBoundingBoxDllType, $boundingBox), "cveTrackerInit", @error)
EndFunc   ;==>_cveTrackerInit

Func _cveTrackerUpdate($tracker, $image, $boundingBox)
    ; CVAPI(bool) cveTrackerUpdate(cv::Tracker* tracker, cv::Mat* image, CvRect* boundingBox);

    Local $sTrackerDllType
    If IsDllStruct($tracker) Then
        $sTrackerDllType = "struct*"
    Else
        $sTrackerDllType = "ptr"
    EndIf

    Local $sImageDllType
    If IsDllStruct($image) Then
        $sImageDllType = "struct*"
    Else
        $sImageDllType = "ptr"
    EndIf

    Local $sBoundingBoxDllType
    If IsDllStruct($boundingBox) Then
        $sBoundingBoxDllType = "struct*"
    Else
        $sBoundingBoxDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveTrackerUpdate", $sTrackerDllType, $tracker, $sImageDllType, $image, $sBoundingBoxDllType, $boundingBox), "cveTrackerUpdate", @error)
EndFunc   ;==>_cveTrackerUpdate

Func _cveTrackerMILCreate($samplerInitInRadius, $samplerInitMaxNegNum, $samplerSearchWinSize, $samplerTrackInRadius, $samplerTrackMaxPosNum, $samplerTrackMaxNegNum, $featureSetNumFeatures, $tracker, $sharedPtr)
    ; CVAPI(cv::TrackerMIL*) cveTrackerMILCreate(float samplerInitInRadius, int samplerInitMaxNegNum, float samplerSearchWinSize, float samplerTrackInRadius, int samplerTrackMaxPosNum, int samplerTrackMaxNegNum, int featureSetNumFeatures, cv::Tracker** tracker, cv::Ptr<cv::TrackerMIL>** sharedPtr);

    Local $sTrackerDllType
    If IsDllStruct($tracker) Then
        $sTrackerDllType = "struct*"
    ElseIf $tracker == Null Then
        $sTrackerDllType = "ptr"
    Else
        $sTrackerDllType = "ptr*"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveTrackerMILCreate", "float", $samplerInitInRadius, "int", $samplerInitMaxNegNum, "float", $samplerSearchWinSize, "float", $samplerTrackInRadius, "int", $samplerTrackMaxPosNum, "int", $samplerTrackMaxNegNum, "int", $featureSetNumFeatures, $sTrackerDllType, $tracker, $sSharedPtrDllType, $sharedPtr), "cveTrackerMILCreate", @error)
EndFunc   ;==>_cveTrackerMILCreate

Func _cveTrackerMILRelease($tracker, $sharedPtr)
    ; CVAPI(void) cveTrackerMILRelease(cv::TrackerMIL** tracker, cv::Ptr<cv::TrackerMIL>** sharedPtr);

    Local $sTrackerDllType
    If IsDllStruct($tracker) Then
        $sTrackerDllType = "struct*"
    ElseIf $tracker == Null Then
        $sTrackerDllType = "ptr"
    Else
        $sTrackerDllType = "ptr*"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveTrackerMILRelease", $sTrackerDllType, $tracker, $sSharedPtrDllType, $sharedPtr), "cveTrackerMILRelease", @error)
EndFunc   ;==>_cveTrackerMILRelease

Func _cveTrackerGOTURNCreate($tracker, $sharedPtr)
    ; CVAPI(cv::TrackerGOTURN*) cveTrackerGOTURNCreate(cv::Tracker** tracker, cv::Ptr<cv::TrackerGOTURN>** sharedPtr);

    Local $sTrackerDllType
    If IsDllStruct($tracker) Then
        $sTrackerDllType = "struct*"
    ElseIf $tracker == Null Then
        $sTrackerDllType = "ptr"
    Else
        $sTrackerDllType = "ptr*"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveTrackerGOTURNCreate", $sTrackerDllType, $tracker, $sSharedPtrDllType, $sharedPtr), "cveTrackerGOTURNCreate", @error)
EndFunc   ;==>_cveTrackerGOTURNCreate

Func _cveTrackerGOTURNRelease($tracker, $sharedPtr)
    ; CVAPI(void) cveTrackerGOTURNRelease(cv::TrackerGOTURN** tracker, cv::Ptr<cv::TrackerGOTURN>** sharedPtr);

    Local $sTrackerDllType
    If IsDllStruct($tracker) Then
        $sTrackerDllType = "struct*"
    ElseIf $tracker == Null Then
        $sTrackerDllType = "ptr"
    Else
        $sTrackerDllType = "ptr*"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveTrackerGOTURNRelease", $sTrackerDllType, $tracker, $sSharedPtrDllType, $sharedPtr), "cveTrackerGOTURNRelease", @error)
EndFunc   ;==>_cveTrackerGOTURNRelease

Func _cveTrackerDaSiamRPNCreate($model, $kernel_cls1, $kernel_r1, $backend, $target, $tracker, $sharedPtr)
    ; CVAPI(cv::TrackerDaSiamRPN*) cveTrackerDaSiamRPNCreate(cv::String* model, cv::String* kernel_cls1, cv::String* kernel_r1, int backend, int target, cv::Tracker** tracker, cv::Ptr<cv::TrackerDaSiamRPN>** sharedPtr);

    Local $bModelIsString = IsString($model)
    If $bModelIsString Then
        $model = _cveStringCreateFromStr($model)
    EndIf

    Local $sModelDllType
    If IsDllStruct($model) Then
        $sModelDllType = "struct*"
    Else
        $sModelDllType = "ptr"
    EndIf

    Local $bKernel_cls1IsString = IsString($kernel_cls1)
    If $bKernel_cls1IsString Then
        $kernel_cls1 = _cveStringCreateFromStr($kernel_cls1)
    EndIf

    Local $sKernel_cls1DllType
    If IsDllStruct($kernel_cls1) Then
        $sKernel_cls1DllType = "struct*"
    Else
        $sKernel_cls1DllType = "ptr"
    EndIf

    Local $bKernel_r1IsString = IsString($kernel_r1)
    If $bKernel_r1IsString Then
        $kernel_r1 = _cveStringCreateFromStr($kernel_r1)
    EndIf

    Local $sKernel_r1DllType
    If IsDllStruct($kernel_r1) Then
        $sKernel_r1DllType = "struct*"
    Else
        $sKernel_r1DllType = "ptr"
    EndIf

    Local $sTrackerDllType
    If IsDllStruct($tracker) Then
        $sTrackerDllType = "struct*"
    ElseIf $tracker == Null Then
        $sTrackerDllType = "ptr"
    Else
        $sTrackerDllType = "ptr*"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveTrackerDaSiamRPNCreate", $sModelDllType, $model, $sKernel_cls1DllType, $kernel_cls1, $sKernel_r1DllType, $kernel_r1, "int", $backend, "int", $target, $sTrackerDllType, $tracker, $sSharedPtrDllType, $sharedPtr), "cveTrackerDaSiamRPNCreate", @error)

    If $bKernel_r1IsString Then
        _cveStringRelease($kernel_r1)
    EndIf

    If $bKernel_cls1IsString Then
        _cveStringRelease($kernel_cls1)
    EndIf

    If $bModelIsString Then
        _cveStringRelease($model)
    EndIf

    Return $retval
EndFunc   ;==>_cveTrackerDaSiamRPNCreate

Func _cveTrackerDaSiamRPNRelease($tracker, $sharedPtr)
    ; CVAPI(void) cveTrackerDaSiamRPNRelease(cv::TrackerDaSiamRPN** tracker, cv::Ptr<cv::TrackerDaSiamRPN>** sharedPtr);

    Local $sTrackerDllType
    If IsDllStruct($tracker) Then
        $sTrackerDllType = "struct*"
    ElseIf $tracker == Null Then
        $sTrackerDllType = "ptr"
    Else
        $sTrackerDllType = "ptr*"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveTrackerDaSiamRPNRelease", $sTrackerDllType, $tracker, $sSharedPtrDllType, $sharedPtr), "cveTrackerDaSiamRPNRelease", @error)
EndFunc   ;==>_cveTrackerDaSiamRPNRelease