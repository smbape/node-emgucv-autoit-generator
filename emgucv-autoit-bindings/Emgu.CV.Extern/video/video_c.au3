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

Func _cveBackgroundSubtractorUpdateMat($bgSubtractor, $matImage, $matFgmask, $learningRate)
    ; cveBackgroundSubtractorUpdate using cv::Mat instead of _*Array

    Local $iArrImage, $vectorOfMatImage, $iArrImageSize
    Local $bImageIsArray = VarGetType($matImage) == "Array"

    If $bImageIsArray Then
        $vectorOfMatImage = _VectorOfMatCreate()

        $iArrImageSize = UBound($matImage)
        For $i = 0 To $iArrImageSize - 1
            _VectorOfMatPush($vectorOfMatImage, $matImage[$i])
        Next

        $iArrImage = _cveInputArrayFromVectorOfMat($vectorOfMatImage)
    Else
        $iArrImage = _cveInputArrayFromMat($matImage)
    EndIf

    Local $oArrFgmask, $vectorOfMatFgmask, $iArrFgmaskSize
    Local $bFgmaskIsArray = VarGetType($matFgmask) == "Array"

    If $bFgmaskIsArray Then
        $vectorOfMatFgmask = _VectorOfMatCreate()

        $iArrFgmaskSize = UBound($matFgmask)
        For $i = 0 To $iArrFgmaskSize - 1
            _VectorOfMatPush($vectorOfMatFgmask, $matFgmask[$i])
        Next

        $oArrFgmask = _cveOutputArrayFromVectorOfMat($vectorOfMatFgmask)
    Else
        $oArrFgmask = _cveOutputArrayFromMat($matFgmask)
    EndIf

    _cveBackgroundSubtractorUpdate($bgSubtractor, $iArrImage, $oArrFgmask, $learningRate)

    If $bFgmaskIsArray Then
        _VectorOfMatRelease($vectorOfMatFgmask)
    EndIf

    _cveOutputArrayRelease($oArrFgmask)

    If $bImageIsArray Then
        _VectorOfMatRelease($vectorOfMatImage)
    EndIf

    _cveInputArrayRelease($iArrImage)
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

Func _cveBackgroundSubtractorGetBackgroundImageMat($bgSubtractor, $matBackgroundImage)
    ; cveBackgroundSubtractorGetBackgroundImage using cv::Mat instead of _*Array

    Local $oArrBackgroundImage, $vectorOfMatBackgroundImage, $iArrBackgroundImageSize
    Local $bBackgroundImageIsArray = VarGetType($matBackgroundImage) == "Array"

    If $bBackgroundImageIsArray Then
        $vectorOfMatBackgroundImage = _VectorOfMatCreate()

        $iArrBackgroundImageSize = UBound($matBackgroundImage)
        For $i = 0 To $iArrBackgroundImageSize - 1
            _VectorOfMatPush($vectorOfMatBackgroundImage, $matBackgroundImage[$i])
        Next

        $oArrBackgroundImage = _cveOutputArrayFromVectorOfMat($vectorOfMatBackgroundImage)
    Else
        $oArrBackgroundImage = _cveOutputArrayFromMat($matBackgroundImage)
    EndIf

    _cveBackgroundSubtractorGetBackgroundImage($bgSubtractor, $oArrBackgroundImage)

    If $bBackgroundImageIsArray Then
        _VectorOfMatRelease($vectorOfMatBackgroundImage)
    EndIf

    _cveOutputArrayRelease($oArrBackgroundImage)
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

Func _cveDenseOpticalFlowCalcMat($dof, $matI0, $matI1, $matFlow)
    ; cveDenseOpticalFlowCalc using cv::Mat instead of _*Array

    Local $iArrI0, $vectorOfMatI0, $iArrI0Size
    Local $bI0IsArray = VarGetType($matI0) == "Array"

    If $bI0IsArray Then
        $vectorOfMatI0 = _VectorOfMatCreate()

        $iArrI0Size = UBound($matI0)
        For $i = 0 To $iArrI0Size - 1
            _VectorOfMatPush($vectorOfMatI0, $matI0[$i])
        Next

        $iArrI0 = _cveInputArrayFromVectorOfMat($vectorOfMatI0)
    Else
        $iArrI0 = _cveInputArrayFromMat($matI0)
    EndIf

    Local $iArrI1, $vectorOfMatI1, $iArrI1Size
    Local $bI1IsArray = VarGetType($matI1) == "Array"

    If $bI1IsArray Then
        $vectorOfMatI1 = _VectorOfMatCreate()

        $iArrI1Size = UBound($matI1)
        For $i = 0 To $iArrI1Size - 1
            _VectorOfMatPush($vectorOfMatI1, $matI1[$i])
        Next

        $iArrI1 = _cveInputArrayFromVectorOfMat($vectorOfMatI1)
    Else
        $iArrI1 = _cveInputArrayFromMat($matI1)
    EndIf

    Local $ioArrFlow, $vectorOfMatFlow, $iArrFlowSize
    Local $bFlowIsArray = VarGetType($matFlow) == "Array"

    If $bFlowIsArray Then
        $vectorOfMatFlow = _VectorOfMatCreate()

        $iArrFlowSize = UBound($matFlow)
        For $i = 0 To $iArrFlowSize - 1
            _VectorOfMatPush($vectorOfMatFlow, $matFlow[$i])
        Next

        $ioArrFlow = _cveInputOutputArrayFromVectorOfMat($vectorOfMatFlow)
    Else
        $ioArrFlow = _cveInputOutputArrayFromMat($matFlow)
    EndIf

    _cveDenseOpticalFlowCalc($dof, $iArrI0, $iArrI1, $ioArrFlow)

    If $bFlowIsArray Then
        _VectorOfMatRelease($vectorOfMatFlow)
    EndIf

    _cveInputOutputArrayRelease($ioArrFlow)

    If $bI1IsArray Then
        _VectorOfMatRelease($vectorOfMatI1)
    EndIf

    _cveInputArrayRelease($iArrI1)

    If $bI0IsArray Then
        _VectorOfMatRelease($vectorOfMatI0)
    EndIf

    _cveInputArrayRelease($iArrI0)
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

Func _cveSparseOpticalFlowCalcMat($sof, $matPrevImg, $matNextImg, $matPrevPts, $matNextPts, $matStatus, $matErr)
    ; cveSparseOpticalFlowCalc using cv::Mat instead of _*Array

    Local $iArrPrevImg, $vectorOfMatPrevImg, $iArrPrevImgSize
    Local $bPrevImgIsArray = VarGetType($matPrevImg) == "Array"

    If $bPrevImgIsArray Then
        $vectorOfMatPrevImg = _VectorOfMatCreate()

        $iArrPrevImgSize = UBound($matPrevImg)
        For $i = 0 To $iArrPrevImgSize - 1
            _VectorOfMatPush($vectorOfMatPrevImg, $matPrevImg[$i])
        Next

        $iArrPrevImg = _cveInputArrayFromVectorOfMat($vectorOfMatPrevImg)
    Else
        $iArrPrevImg = _cveInputArrayFromMat($matPrevImg)
    EndIf

    Local $iArrNextImg, $vectorOfMatNextImg, $iArrNextImgSize
    Local $bNextImgIsArray = VarGetType($matNextImg) == "Array"

    If $bNextImgIsArray Then
        $vectorOfMatNextImg = _VectorOfMatCreate()

        $iArrNextImgSize = UBound($matNextImg)
        For $i = 0 To $iArrNextImgSize - 1
            _VectorOfMatPush($vectorOfMatNextImg, $matNextImg[$i])
        Next

        $iArrNextImg = _cveInputArrayFromVectorOfMat($vectorOfMatNextImg)
    Else
        $iArrNextImg = _cveInputArrayFromMat($matNextImg)
    EndIf

    Local $iArrPrevPts, $vectorOfMatPrevPts, $iArrPrevPtsSize
    Local $bPrevPtsIsArray = VarGetType($matPrevPts) == "Array"

    If $bPrevPtsIsArray Then
        $vectorOfMatPrevPts = _VectorOfMatCreate()

        $iArrPrevPtsSize = UBound($matPrevPts)
        For $i = 0 To $iArrPrevPtsSize - 1
            _VectorOfMatPush($vectorOfMatPrevPts, $matPrevPts[$i])
        Next

        $iArrPrevPts = _cveInputArrayFromVectorOfMat($vectorOfMatPrevPts)
    Else
        $iArrPrevPts = _cveInputArrayFromMat($matPrevPts)
    EndIf

    Local $ioArrNextPts, $vectorOfMatNextPts, $iArrNextPtsSize
    Local $bNextPtsIsArray = VarGetType($matNextPts) == "Array"

    If $bNextPtsIsArray Then
        $vectorOfMatNextPts = _VectorOfMatCreate()

        $iArrNextPtsSize = UBound($matNextPts)
        For $i = 0 To $iArrNextPtsSize - 1
            _VectorOfMatPush($vectorOfMatNextPts, $matNextPts[$i])
        Next

        $ioArrNextPts = _cveInputOutputArrayFromVectorOfMat($vectorOfMatNextPts)
    Else
        $ioArrNextPts = _cveInputOutputArrayFromMat($matNextPts)
    EndIf

    Local $oArrStatus, $vectorOfMatStatus, $iArrStatusSize
    Local $bStatusIsArray = VarGetType($matStatus) == "Array"

    If $bStatusIsArray Then
        $vectorOfMatStatus = _VectorOfMatCreate()

        $iArrStatusSize = UBound($matStatus)
        For $i = 0 To $iArrStatusSize - 1
            _VectorOfMatPush($vectorOfMatStatus, $matStatus[$i])
        Next

        $oArrStatus = _cveOutputArrayFromVectorOfMat($vectorOfMatStatus)
    Else
        $oArrStatus = _cveOutputArrayFromMat($matStatus)
    EndIf

    Local $oArrErr, $vectorOfMatErr, $iArrErrSize
    Local $bErrIsArray = VarGetType($matErr) == "Array"

    If $bErrIsArray Then
        $vectorOfMatErr = _VectorOfMatCreate()

        $iArrErrSize = UBound($matErr)
        For $i = 0 To $iArrErrSize - 1
            _VectorOfMatPush($vectorOfMatErr, $matErr[$i])
        Next

        $oArrErr = _cveOutputArrayFromVectorOfMat($vectorOfMatErr)
    Else
        $oArrErr = _cveOutputArrayFromMat($matErr)
    EndIf

    _cveSparseOpticalFlowCalc($sof, $iArrPrevImg, $iArrNextImg, $iArrPrevPts, $ioArrNextPts, $oArrStatus, $oArrErr)

    If $bErrIsArray Then
        _VectorOfMatRelease($vectorOfMatErr)
    EndIf

    _cveOutputArrayRelease($oArrErr)

    If $bStatusIsArray Then
        _VectorOfMatRelease($vectorOfMatStatus)
    EndIf

    _cveOutputArrayRelease($oArrStatus)

    If $bNextPtsIsArray Then
        _VectorOfMatRelease($vectorOfMatNextPts)
    EndIf

    _cveInputOutputArrayRelease($ioArrNextPts)

    If $bPrevPtsIsArray Then
        _VectorOfMatRelease($vectorOfMatPrevPts)
    EndIf

    _cveInputArrayRelease($iArrPrevPts)

    If $bNextImgIsArray Then
        _VectorOfMatRelease($vectorOfMatNextImg)
    EndIf

    _cveInputArrayRelease($iArrNextImg)

    If $bPrevImgIsArray Then
        _VectorOfMatRelease($vectorOfMatPrevImg)
    EndIf

    _cveInputArrayRelease($iArrPrevImg)
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

Func _cveCalcOpticalFlowFarnebackMat($matPrev, $matNext, $matFlow, $pyrScale, $levels, $winSize, $iterations, $polyN, $polySigma, $flags)
    ; cveCalcOpticalFlowFarneback using cv::Mat instead of _*Array

    Local $iArrPrev, $vectorOfMatPrev, $iArrPrevSize
    Local $bPrevIsArray = VarGetType($matPrev) == "Array"

    If $bPrevIsArray Then
        $vectorOfMatPrev = _VectorOfMatCreate()

        $iArrPrevSize = UBound($matPrev)
        For $i = 0 To $iArrPrevSize - 1
            _VectorOfMatPush($vectorOfMatPrev, $matPrev[$i])
        Next

        $iArrPrev = _cveInputArrayFromVectorOfMat($vectorOfMatPrev)
    Else
        $iArrPrev = _cveInputArrayFromMat($matPrev)
    EndIf

    Local $iArrNext, $vectorOfMatNext, $iArrNextSize
    Local $bNextIsArray = VarGetType($matNext) == "Array"

    If $bNextIsArray Then
        $vectorOfMatNext = _VectorOfMatCreate()

        $iArrNextSize = UBound($matNext)
        For $i = 0 To $iArrNextSize - 1
            _VectorOfMatPush($vectorOfMatNext, $matNext[$i])
        Next

        $iArrNext = _cveInputArrayFromVectorOfMat($vectorOfMatNext)
    Else
        $iArrNext = _cveInputArrayFromMat($matNext)
    EndIf

    Local $ioArrFlow, $vectorOfMatFlow, $iArrFlowSize
    Local $bFlowIsArray = VarGetType($matFlow) == "Array"

    If $bFlowIsArray Then
        $vectorOfMatFlow = _VectorOfMatCreate()

        $iArrFlowSize = UBound($matFlow)
        For $i = 0 To $iArrFlowSize - 1
            _VectorOfMatPush($vectorOfMatFlow, $matFlow[$i])
        Next

        $ioArrFlow = _cveInputOutputArrayFromVectorOfMat($vectorOfMatFlow)
    Else
        $ioArrFlow = _cveInputOutputArrayFromMat($matFlow)
    EndIf

    _cveCalcOpticalFlowFarneback($iArrPrev, $iArrNext, $ioArrFlow, $pyrScale, $levels, $winSize, $iterations, $polyN, $polySigma, $flags)

    If $bFlowIsArray Then
        _VectorOfMatRelease($vectorOfMatFlow)
    EndIf

    _cveInputOutputArrayRelease($ioArrFlow)

    If $bNextIsArray Then
        _VectorOfMatRelease($vectorOfMatNext)
    EndIf

    _cveInputArrayRelease($iArrNext)

    If $bPrevIsArray Then
        _VectorOfMatRelease($vectorOfMatPrev)
    EndIf

    _cveInputArrayRelease($iArrPrev)
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

Func _cveCalcOpticalFlowPyrLKMat($matPrevImg, $matNextImg, $matPrevPts, $matNextPts, $matStatus, $matErr, $winSize, $maxLevel, $criteria, $flags, $minEigenThreshold)
    ; cveCalcOpticalFlowPyrLK using cv::Mat instead of _*Array

    Local $iArrPrevImg, $vectorOfMatPrevImg, $iArrPrevImgSize
    Local $bPrevImgIsArray = VarGetType($matPrevImg) == "Array"

    If $bPrevImgIsArray Then
        $vectorOfMatPrevImg = _VectorOfMatCreate()

        $iArrPrevImgSize = UBound($matPrevImg)
        For $i = 0 To $iArrPrevImgSize - 1
            _VectorOfMatPush($vectorOfMatPrevImg, $matPrevImg[$i])
        Next

        $iArrPrevImg = _cveInputArrayFromVectorOfMat($vectorOfMatPrevImg)
    Else
        $iArrPrevImg = _cveInputArrayFromMat($matPrevImg)
    EndIf

    Local $iArrNextImg, $vectorOfMatNextImg, $iArrNextImgSize
    Local $bNextImgIsArray = VarGetType($matNextImg) == "Array"

    If $bNextImgIsArray Then
        $vectorOfMatNextImg = _VectorOfMatCreate()

        $iArrNextImgSize = UBound($matNextImg)
        For $i = 0 To $iArrNextImgSize - 1
            _VectorOfMatPush($vectorOfMatNextImg, $matNextImg[$i])
        Next

        $iArrNextImg = _cveInputArrayFromVectorOfMat($vectorOfMatNextImg)
    Else
        $iArrNextImg = _cveInputArrayFromMat($matNextImg)
    EndIf

    Local $iArrPrevPts, $vectorOfMatPrevPts, $iArrPrevPtsSize
    Local $bPrevPtsIsArray = VarGetType($matPrevPts) == "Array"

    If $bPrevPtsIsArray Then
        $vectorOfMatPrevPts = _VectorOfMatCreate()

        $iArrPrevPtsSize = UBound($matPrevPts)
        For $i = 0 To $iArrPrevPtsSize - 1
            _VectorOfMatPush($vectorOfMatPrevPts, $matPrevPts[$i])
        Next

        $iArrPrevPts = _cveInputArrayFromVectorOfMat($vectorOfMatPrevPts)
    Else
        $iArrPrevPts = _cveInputArrayFromMat($matPrevPts)
    EndIf

    Local $ioArrNextPts, $vectorOfMatNextPts, $iArrNextPtsSize
    Local $bNextPtsIsArray = VarGetType($matNextPts) == "Array"

    If $bNextPtsIsArray Then
        $vectorOfMatNextPts = _VectorOfMatCreate()

        $iArrNextPtsSize = UBound($matNextPts)
        For $i = 0 To $iArrNextPtsSize - 1
            _VectorOfMatPush($vectorOfMatNextPts, $matNextPts[$i])
        Next

        $ioArrNextPts = _cveInputOutputArrayFromVectorOfMat($vectorOfMatNextPts)
    Else
        $ioArrNextPts = _cveInputOutputArrayFromMat($matNextPts)
    EndIf

    Local $oArrStatus, $vectorOfMatStatus, $iArrStatusSize
    Local $bStatusIsArray = VarGetType($matStatus) == "Array"

    If $bStatusIsArray Then
        $vectorOfMatStatus = _VectorOfMatCreate()

        $iArrStatusSize = UBound($matStatus)
        For $i = 0 To $iArrStatusSize - 1
            _VectorOfMatPush($vectorOfMatStatus, $matStatus[$i])
        Next

        $oArrStatus = _cveOutputArrayFromVectorOfMat($vectorOfMatStatus)
    Else
        $oArrStatus = _cveOutputArrayFromMat($matStatus)
    EndIf

    Local $oArrErr, $vectorOfMatErr, $iArrErrSize
    Local $bErrIsArray = VarGetType($matErr) == "Array"

    If $bErrIsArray Then
        $vectorOfMatErr = _VectorOfMatCreate()

        $iArrErrSize = UBound($matErr)
        For $i = 0 To $iArrErrSize - 1
            _VectorOfMatPush($vectorOfMatErr, $matErr[$i])
        Next

        $oArrErr = _cveOutputArrayFromVectorOfMat($vectorOfMatErr)
    Else
        $oArrErr = _cveOutputArrayFromMat($matErr)
    EndIf

    _cveCalcOpticalFlowPyrLK($iArrPrevImg, $iArrNextImg, $iArrPrevPts, $ioArrNextPts, $oArrStatus, $oArrErr, $winSize, $maxLevel, $criteria, $flags, $minEigenThreshold)

    If $bErrIsArray Then
        _VectorOfMatRelease($vectorOfMatErr)
    EndIf

    _cveOutputArrayRelease($oArrErr)

    If $bStatusIsArray Then
        _VectorOfMatRelease($vectorOfMatStatus)
    EndIf

    _cveOutputArrayRelease($oArrStatus)

    If $bNextPtsIsArray Then
        _VectorOfMatRelease($vectorOfMatNextPts)
    EndIf

    _cveInputOutputArrayRelease($ioArrNextPts)

    If $bPrevPtsIsArray Then
        _VectorOfMatRelease($vectorOfMatPrevPts)
    EndIf

    _cveInputArrayRelease($iArrPrevPts)

    If $bNextImgIsArray Then
        _VectorOfMatRelease($vectorOfMatNextImg)
    EndIf

    _cveInputArrayRelease($iArrNextImg)

    If $bPrevImgIsArray Then
        _VectorOfMatRelease($vectorOfMatPrevImg)
    EndIf

    _cveInputArrayRelease($iArrPrevImg)
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

Func _cveCamShiftMat($matProbImage, $window, $criteria, $result)
    ; cveCamShift using cv::Mat instead of _*Array

    Local $iArrProbImage, $vectorOfMatProbImage, $iArrProbImageSize
    Local $bProbImageIsArray = VarGetType($matProbImage) == "Array"

    If $bProbImageIsArray Then
        $vectorOfMatProbImage = _VectorOfMatCreate()

        $iArrProbImageSize = UBound($matProbImage)
        For $i = 0 To $iArrProbImageSize - 1
            _VectorOfMatPush($vectorOfMatProbImage, $matProbImage[$i])
        Next

        $iArrProbImage = _cveInputArrayFromVectorOfMat($vectorOfMatProbImage)
    Else
        $iArrProbImage = _cveInputArrayFromMat($matProbImage)
    EndIf

    _cveCamShift($iArrProbImage, $window, $criteria, $result)

    If $bProbImageIsArray Then
        _VectorOfMatRelease($vectorOfMatProbImage)
    EndIf

    _cveInputArrayRelease($iArrProbImage)
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

Func _cveMeanShiftMat($matProbImage, $window, $criteria)
    ; cveMeanShift using cv::Mat instead of _*Array

    Local $iArrProbImage, $vectorOfMatProbImage, $iArrProbImageSize
    Local $bProbImageIsArray = VarGetType($matProbImage) == "Array"

    If $bProbImageIsArray Then
        $vectorOfMatProbImage = _VectorOfMatCreate()

        $iArrProbImageSize = UBound($matProbImage)
        For $i = 0 To $iArrProbImageSize - 1
            _VectorOfMatPush($vectorOfMatProbImage, $matProbImage[$i])
        Next

        $iArrProbImage = _cveInputArrayFromVectorOfMat($vectorOfMatProbImage)
    Else
        $iArrProbImage = _cveInputArrayFromMat($matProbImage)
    EndIf

    Local $retval = _cveMeanShift($iArrProbImage, $window, $criteria)

    If $bProbImageIsArray Then
        _VectorOfMatRelease($vectorOfMatProbImage)
    EndIf

    _cveInputArrayRelease($iArrProbImage)

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

Func _cveBuildOpticalFlowPyramidMat($matImg, $matPyramid, $winSize, $maxLevel, $withDerivatives = true, $pyrBorder = $CV_BORDER_REFLECT_101, $derivBorder = $CV_BORDER_CONSTANT, $tryReuseInputImage = true)
    ; cveBuildOpticalFlowPyramid using cv::Mat instead of _*Array

    Local $iArrImg, $vectorOfMatImg, $iArrImgSize
    Local $bImgIsArray = VarGetType($matImg) == "Array"

    If $bImgIsArray Then
        $vectorOfMatImg = _VectorOfMatCreate()

        $iArrImgSize = UBound($matImg)
        For $i = 0 To $iArrImgSize - 1
            _VectorOfMatPush($vectorOfMatImg, $matImg[$i])
        Next

        $iArrImg = _cveInputArrayFromVectorOfMat($vectorOfMatImg)
    Else
        $iArrImg = _cveInputArrayFromMat($matImg)
    EndIf

    Local $oArrPyramid, $vectorOfMatPyramid, $iArrPyramidSize
    Local $bPyramidIsArray = VarGetType($matPyramid) == "Array"

    If $bPyramidIsArray Then
        $vectorOfMatPyramid = _VectorOfMatCreate()

        $iArrPyramidSize = UBound($matPyramid)
        For $i = 0 To $iArrPyramidSize - 1
            _VectorOfMatPush($vectorOfMatPyramid, $matPyramid[$i])
        Next

        $oArrPyramid = _cveOutputArrayFromVectorOfMat($vectorOfMatPyramid)
    Else
        $oArrPyramid = _cveOutputArrayFromMat($matPyramid)
    EndIf

    Local $retval = _cveBuildOpticalFlowPyramid($iArrImg, $oArrPyramid, $winSize, $maxLevel, $withDerivatives, $pyrBorder, $derivBorder, $tryReuseInputImage)

    If $bPyramidIsArray Then
        _VectorOfMatRelease($vectorOfMatPyramid)
    EndIf

    _cveOutputArrayRelease($oArrPyramid)

    If $bImgIsArray Then
        _VectorOfMatRelease($vectorOfMatImg)
    EndIf

    _cveInputArrayRelease($iArrImg)

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

Func _cveFindTransformECCMat($matTemplateImage, $matInputImage, $matWarpMatrix, $motionType, $criteria, $matInputMask)
    ; cveFindTransformECC using cv::Mat instead of _*Array

    Local $iArrTemplateImage, $vectorOfMatTemplateImage, $iArrTemplateImageSize
    Local $bTemplateImageIsArray = VarGetType($matTemplateImage) == "Array"

    If $bTemplateImageIsArray Then
        $vectorOfMatTemplateImage = _VectorOfMatCreate()

        $iArrTemplateImageSize = UBound($matTemplateImage)
        For $i = 0 To $iArrTemplateImageSize - 1
            _VectorOfMatPush($vectorOfMatTemplateImage, $matTemplateImage[$i])
        Next

        $iArrTemplateImage = _cveInputArrayFromVectorOfMat($vectorOfMatTemplateImage)
    Else
        $iArrTemplateImage = _cveInputArrayFromMat($matTemplateImage)
    EndIf

    Local $iArrInputImage, $vectorOfMatInputImage, $iArrInputImageSize
    Local $bInputImageIsArray = VarGetType($matInputImage) == "Array"

    If $bInputImageIsArray Then
        $vectorOfMatInputImage = _VectorOfMatCreate()

        $iArrInputImageSize = UBound($matInputImage)
        For $i = 0 To $iArrInputImageSize - 1
            _VectorOfMatPush($vectorOfMatInputImage, $matInputImage[$i])
        Next

        $iArrInputImage = _cveInputArrayFromVectorOfMat($vectorOfMatInputImage)
    Else
        $iArrInputImage = _cveInputArrayFromMat($matInputImage)
    EndIf

    Local $ioArrWarpMatrix, $vectorOfMatWarpMatrix, $iArrWarpMatrixSize
    Local $bWarpMatrixIsArray = VarGetType($matWarpMatrix) == "Array"

    If $bWarpMatrixIsArray Then
        $vectorOfMatWarpMatrix = _VectorOfMatCreate()

        $iArrWarpMatrixSize = UBound($matWarpMatrix)
        For $i = 0 To $iArrWarpMatrixSize - 1
            _VectorOfMatPush($vectorOfMatWarpMatrix, $matWarpMatrix[$i])
        Next

        $ioArrWarpMatrix = _cveInputOutputArrayFromVectorOfMat($vectorOfMatWarpMatrix)
    Else
        $ioArrWarpMatrix = _cveInputOutputArrayFromMat($matWarpMatrix)
    EndIf

    Local $iArrInputMask, $vectorOfMatInputMask, $iArrInputMaskSize
    Local $bInputMaskIsArray = VarGetType($matInputMask) == "Array"

    If $bInputMaskIsArray Then
        $vectorOfMatInputMask = _VectorOfMatCreate()

        $iArrInputMaskSize = UBound($matInputMask)
        For $i = 0 To $iArrInputMaskSize - 1
            _VectorOfMatPush($vectorOfMatInputMask, $matInputMask[$i])
        Next

        $iArrInputMask = _cveInputArrayFromVectorOfMat($vectorOfMatInputMask)
    Else
        $iArrInputMask = _cveInputArrayFromMat($matInputMask)
    EndIf

    Local $retval = _cveFindTransformECC($iArrTemplateImage, $iArrInputImage, $ioArrWarpMatrix, $motionType, $criteria, $iArrInputMask)

    If $bInputMaskIsArray Then
        _VectorOfMatRelease($vectorOfMatInputMask)
    EndIf

    _cveInputArrayRelease($iArrInputMask)

    If $bWarpMatrixIsArray Then
        _VectorOfMatRelease($vectorOfMatWarpMatrix)
    EndIf

    _cveInputOutputArrayRelease($ioArrWarpMatrix)

    If $bInputImageIsArray Then
        _VectorOfMatRelease($vectorOfMatInputImage)
    EndIf

    _cveInputArrayRelease($iArrInputImage)

    If $bTemplateImageIsArray Then
        _VectorOfMatRelease($vectorOfMatTemplateImage)
    EndIf

    _cveInputArrayRelease($iArrTemplateImage)

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

    Local $bModelIsString = VarGetType($model) == "String"
    If $bModelIsString Then
        $model = _cveStringCreateFromStr($model)
    EndIf

    Local $sModelDllType
    If IsDllStruct($model) Then
        $sModelDllType = "struct*"
    Else
        $sModelDllType = "ptr"
    EndIf

    Local $bKernel_cls1IsString = VarGetType($kernel_cls1) == "String"
    If $bKernel_cls1IsString Then
        $kernel_cls1 = _cveStringCreateFromStr($kernel_cls1)
    EndIf

    Local $sKernel_cls1DllType
    If IsDllStruct($kernel_cls1) Then
        $sKernel_cls1DllType = "struct*"
    Else
        $sKernel_cls1DllType = "ptr"
    EndIf

    Local $bKernel_r1IsString = VarGetType($kernel_r1) == "String"
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