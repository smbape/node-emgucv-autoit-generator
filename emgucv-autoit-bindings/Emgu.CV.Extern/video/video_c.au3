#include-once
#include <..\..\CVEUtils.au3>

Func _cveBackgroundSubtractorMOG2Create($history, $varThreshold, $bShadowDetection, ByRef $bgSubtractor, ByRef $algorithm, ByRef $sharedPtr)
    ; CVAPI(cv::BackgroundSubtractorMOG2*) cveBackgroundSubtractorMOG2Create(int history, float varThreshold, bool bShadowDetection, cv::BackgroundSubtractor** bgSubtractor, cv::Algorithm** algorithm, cv::Ptr<cv::BackgroundSubtractorMOG2>** sharedPtr);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveBackgroundSubtractorMOG2Create", "int", $history, "float", $varThreshold, "boolean", $bShadowDetection, "ptr*", $bgSubtractor, "ptr*", $algorithm, "ptr*", $sharedPtr), "cveBackgroundSubtractorMOG2Create", @error)
EndFunc   ;==>_cveBackgroundSubtractorMOG2Create

Func _cveBackgroundSubtractorMOG2Release(ByRef $bgSubtractor, ByRef $sharedPtr)
    ; CVAPI(void) cveBackgroundSubtractorMOG2Release(cv::BackgroundSubtractorMOG2** bgSubtractor, cv::Ptr<cv::BackgroundSubtractorMOG2>** sharedPtr);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBackgroundSubtractorMOG2Release", "ptr*", $bgSubtractor, "ptr*", $sharedPtr), "cveBackgroundSubtractorMOG2Release", @error)
EndFunc   ;==>_cveBackgroundSubtractorMOG2Release

Func _cveBackgroundSubtractorUpdate(ByRef $bgSubtractor, ByRef $image, ByRef $fgmask, $learningRate)
    ; CVAPI(void) cveBackgroundSubtractorUpdate(cv::BackgroundSubtractor* bgSubtractor, cv::_InputArray* image, cv::_OutputArray* fgmask, double learningRate);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBackgroundSubtractorUpdate", "ptr", $bgSubtractor, "ptr", $image, "ptr", $fgmask, "double", $learningRate), "cveBackgroundSubtractorUpdate", @error)
EndFunc   ;==>_cveBackgroundSubtractorUpdate

Func _cveBackgroundSubtractorUpdateMat(ByRef $bgSubtractor, ByRef $matImage, ByRef $matFgmask, $learningRate)
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

Func _cveBackgroundSubtractorGetBackgroundImage(ByRef $bgSubtractor, ByRef $backgroundImage)
    ; CVAPI(void) cveBackgroundSubtractorGetBackgroundImage(cv::BackgroundSubtractor* bgSubtractor, cv::_OutputArray* backgroundImage);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBackgroundSubtractorGetBackgroundImage", "ptr", $bgSubtractor, "ptr", $backgroundImage), "cveBackgroundSubtractorGetBackgroundImage", @error)
EndFunc   ;==>_cveBackgroundSubtractorGetBackgroundImage

Func _cveBackgroundSubtractorGetBackgroundImageMat(ByRef $bgSubtractor, ByRef $matBackgroundImage)
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

Func _cveBackgroundSubtractorKNNCreate($history, $dist2Threshold, $detectShadows, ByRef $bgSubtractor, ByRef $algorithm, ByRef $sharedPtr)
    ; CVAPI(cv::BackgroundSubtractorKNN*) cveBackgroundSubtractorKNNCreate(int history, double dist2Threshold, bool detectShadows, cv::BackgroundSubtractor** bgSubtractor, cv::Algorithm** algorithm, cv::Ptr<cv::BackgroundSubtractorKNN>** sharedPtr);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveBackgroundSubtractorKNNCreate", "int", $history, "double", $dist2Threshold, "boolean", $detectShadows, "ptr*", $bgSubtractor, "ptr*", $algorithm, "ptr*", $sharedPtr), "cveBackgroundSubtractorKNNCreate", @error)
EndFunc   ;==>_cveBackgroundSubtractorKNNCreate

Func _cveBackgroundSubtractorKNNRelease(ByRef $bgSubtractor, ByRef $sharedPtr)
    ; CVAPI(void) cveBackgroundSubtractorKNNRelease(cv::BackgroundSubtractorKNN** bgSubtractor, cv::Ptr<cv::BackgroundSubtractorKNN>** sharedPtr);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBackgroundSubtractorKNNRelease", "ptr*", $bgSubtractor, "ptr*", $sharedPtr), "cveBackgroundSubtractorKNNRelease", @error)
EndFunc   ;==>_cveBackgroundSubtractorKNNRelease

Func _cveFarnebackOpticalFlowCreate($numLevels, $pyrScale, $fastPyramids, $winSize, $numIters, $polyN, $polySigma, $flags, ByRef $denseOpticalFlow, ByRef $algorithm, ByRef $sharedPtr)
    ; CVAPI(cv::FarnebackOpticalFlow*) cveFarnebackOpticalFlowCreate(int numLevels, double pyrScale, bool fastPyramids, int winSize, int numIters, int polyN, double polySigma, int flags, cv::DenseOpticalFlow** denseOpticalFlow, cv::Algorithm** algorithm, cv::Ptr<cv::FarnebackOpticalFlow>** sharedPtr);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveFarnebackOpticalFlowCreate", "int", $numLevels, "double", $pyrScale, "boolean", $fastPyramids, "int", $winSize, "int", $numIters, "int", $polyN, "double", $polySigma, "int", $flags, "ptr*", $denseOpticalFlow, "ptr*", $algorithm, "ptr*", $sharedPtr), "cveFarnebackOpticalFlowCreate", @error)
EndFunc   ;==>_cveFarnebackOpticalFlowCreate

Func _cveFarnebackOpticalFlowRelease(ByRef $flow, ByRef $sharedPtr)
    ; CVAPI(void) cveFarnebackOpticalFlowRelease(cv::FarnebackOpticalFlow** flow, cv::Ptr<cv::FarnebackOpticalFlow>** sharedPtr);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFarnebackOpticalFlowRelease", "ptr*", $flow, "ptr*", $sharedPtr), "cveFarnebackOpticalFlowRelease", @error)
EndFunc   ;==>_cveFarnebackOpticalFlowRelease

Func _cveDenseOpticalFlowCalc(ByRef $dof, ByRef $i0, ByRef $i1, ByRef $flow)
    ; CVAPI(void) cveDenseOpticalFlowCalc(cv::DenseOpticalFlow* dof, cv::_InputArray* i0, cv::_InputArray* i1, cv::_InputOutputArray* flow);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDenseOpticalFlowCalc", "ptr", $dof, "ptr", $i0, "ptr", $i1, "ptr", $flow), "cveDenseOpticalFlowCalc", @error)
EndFunc   ;==>_cveDenseOpticalFlowCalc

Func _cveDenseOpticalFlowCalcMat(ByRef $dof, ByRef $matI0, ByRef $matI1, ByRef $matFlow)
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

Func _cveDenseOpticalFlowRelease(ByRef $sharedPtr)
    ; CVAPI(void) cveDenseOpticalFlowRelease(cv::Ptr<cv::DenseOpticalFlow>** sharedPtr);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDenseOpticalFlowRelease", "ptr*", $sharedPtr), "cveDenseOpticalFlowRelease", @error)
EndFunc   ;==>_cveDenseOpticalFlowRelease

Func _cveSparseOpticalFlowCalc(ByRef $sof, ByRef $prevImg, ByRef $nextImg, ByRef $prevPts, ByRef $nextPts, ByRef $status, ByRef $err)
    ; CVAPI(void) cveSparseOpticalFlowCalc(cv::SparseOpticalFlow* sof, cv::_InputArray* prevImg, cv::_InputArray* nextImg, cv::_InputArray* prevPts, cv::_InputOutputArray* nextPts, cv::_OutputArray* status, cv::_OutputArray* err);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSparseOpticalFlowCalc", "ptr", $sof, "ptr", $prevImg, "ptr", $nextImg, "ptr", $prevPts, "ptr", $nextPts, "ptr", $status, "ptr", $err), "cveSparseOpticalFlowCalc", @error)
EndFunc   ;==>_cveSparseOpticalFlowCalc

Func _cveSparseOpticalFlowCalcMat(ByRef $sof, ByRef $matPrevImg, ByRef $matNextImg, ByRef $matPrevPts, ByRef $matNextPts, ByRef $matStatus, ByRef $matErr)
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

Func _cveSparsePyrLKOpticalFlowCreate(ByRef $winSize, $maxLevel, ByRef $crit, $flags, $minEigThreshold, ByRef $sparseOpticalFlow, ByRef $algorithm, ByRef $sharedPtr)
    ; CVAPI(cv::SparsePyrLKOpticalFlow*) cveSparsePyrLKOpticalFlowCreate(CvSize* winSize, int maxLevel, CvTermCriteria* crit, int flags, double minEigThreshold, cv::SparseOpticalFlow** sparseOpticalFlow, cv::Algorithm** algorithm, cv::Ptr<cv::SparsePyrLKOpticalFlow>** sharedPtr);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveSparsePyrLKOpticalFlowCreate", "struct*", $winSize, "int", $maxLevel, "struct*", $crit, "int", $flags, "double", $minEigThreshold, "ptr*", $sparseOpticalFlow, "ptr*", $algorithm, "ptr*", $sharedPtr), "cveSparsePyrLKOpticalFlowCreate", @error)
EndFunc   ;==>_cveSparsePyrLKOpticalFlowCreate

Func _cveSparsePyrLKOpticalFlowRelease(ByRef $flow, ByRef $sharedPtr)
    ; CVAPI(void) cveSparsePyrLKOpticalFlowRelease(cv::SparsePyrLKOpticalFlow** flow, cv::Ptr<cv::SparsePyrLKOpticalFlow>** sharedPtr);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSparsePyrLKOpticalFlowRelease", "ptr*", $flow, "ptr*", $sharedPtr), "cveSparsePyrLKOpticalFlowRelease", @error)
EndFunc   ;==>_cveSparsePyrLKOpticalFlowRelease

Func _cveCalcOpticalFlowFarneback(ByRef $prev, ByRef $next, ByRef $flow, $pyrScale, $levels, $winSize, $iterations, $polyN, $polySigma, $flags)
    ; CVAPI(void) cveCalcOpticalFlowFarneback(cv::_InputArray* prev, cv::_InputArray* next, cv::_InputOutputArray* flow, double pyrScale, int levels, int winSize, int iterations, int polyN, double polySigma, int flags);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCalcOpticalFlowFarneback", "ptr", $prev, "ptr", $next, "ptr", $flow, "double", $pyrScale, "int", $levels, "int", $winSize, "int", $iterations, "int", $polyN, "double", $polySigma, "int", $flags), "cveCalcOpticalFlowFarneback", @error)
EndFunc   ;==>_cveCalcOpticalFlowFarneback

Func _cveCalcOpticalFlowFarnebackMat(ByRef $matPrev, ByRef $matNext, ByRef $matFlow, $pyrScale, $levels, $winSize, $iterations, $polyN, $polySigma, $flags)
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

Func _cveCalcOpticalFlowPyrLK(ByRef $prevImg, ByRef $nextImg, ByRef $prevPts, ByRef $nextPts, ByRef $status, ByRef $err, ByRef $winSize, $maxLevel, ByRef $criteria, $flags, $minEigenThreshold)
    ; CVAPI(void) cveCalcOpticalFlowPyrLK(cv::_InputArray* prevImg, cv::_InputArray* nextImg, cv::_InputArray* prevPts, cv::_InputOutputArray* nextPts, cv::_OutputArray* status, cv::_OutputArray* err, CvSize* winSize, int maxLevel, CvTermCriteria* criteria, int flags, double minEigenThreshold);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCalcOpticalFlowPyrLK", "ptr", $prevImg, "ptr", $nextImg, "ptr", $prevPts, "ptr", $nextPts, "ptr", $status, "ptr", $err, "struct*", $winSize, "int", $maxLevel, "struct*", $criteria, "int", $flags, "double", $minEigenThreshold), "cveCalcOpticalFlowPyrLK", @error)
EndFunc   ;==>_cveCalcOpticalFlowPyrLK

Func _cveCalcOpticalFlowPyrLKMat(ByRef $matPrevImg, ByRef $matNextImg, ByRef $matPrevPts, ByRef $matNextPts, ByRef $matStatus, ByRef $matErr, ByRef $winSize, $maxLevel, ByRef $criteria, $flags, $minEigenThreshold)
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

Func _cveCamShift(ByRef $probImage, ByRef $window, ByRef $criteria, ByRef $result)
    ; CVAPI(void) cveCamShift(cv::_InputArray* probImage, CvRect* window, CvTermCriteria* criteria, CvBox2D* result);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCamShift", "ptr", $probImage, "struct*", $window, "struct*", $criteria, "struct*", $result), "cveCamShift", @error)
EndFunc   ;==>_cveCamShift

Func _cveCamShiftMat(ByRef $matProbImage, ByRef $window, ByRef $criteria, ByRef $result)
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

Func _cveMeanShift(ByRef $probImage, ByRef $window, ByRef $criteria)
    ; CVAPI(int) cveMeanShift(cv::_InputArray* probImage, CvRect* window, CvTermCriteria* criteria);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveMeanShift", "ptr", $probImage, "struct*", $window, "struct*", $criteria), "cveMeanShift", @error)
EndFunc   ;==>_cveMeanShift

Func _cveMeanShiftMat(ByRef $matProbImage, ByRef $window, ByRef $criteria)
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

Func _cveBuildOpticalFlowPyramid(ByRef $img, ByRef $pyramid, ByRef $winSize, $maxLevel, $withDerivatives, $pyrBorder, $derivBorder, $tryReuseInputImage)
    ; CVAPI(int) cveBuildOpticalFlowPyramid(cv::_InputArray* img, cv::_OutputArray* pyramid, CvSize* winSize, int maxLevel, bool withDerivatives, int pyrBorder, int derivBorder, bool tryReuseInputImage);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveBuildOpticalFlowPyramid", "ptr", $img, "ptr", $pyramid, "struct*", $winSize, "int", $maxLevel, "boolean", $withDerivatives, "int", $pyrBorder, "int", $derivBorder, "boolean", $tryReuseInputImage), "cveBuildOpticalFlowPyramid", @error)
EndFunc   ;==>_cveBuildOpticalFlowPyramid

Func _cveBuildOpticalFlowPyramidMat(ByRef $matImg, ByRef $matPyramid, ByRef $winSize, $maxLevel, $withDerivatives, $pyrBorder, $derivBorder, $tryReuseInputImage)
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

Func _cveFindTransformECC(ByRef $templateImage, ByRef $inputImage, ByRef $warpMatrix, $motionType, ByRef $criteria, ByRef $inputMask)
    ; CVAPI(double) cveFindTransformECC(cv::_InputArray* templateImage, cv::_InputArray* inputImage, cv::_InputOutputArray* warpMatrix, int motionType, CvTermCriteria* criteria, cv::_InputArray* inputMask);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveFindTransformECC", "ptr", $templateImage, "ptr", $inputImage, "ptr", $warpMatrix, "int", $motionType, "struct*", $criteria, "ptr", $inputMask), "cveFindTransformECC", @error)
EndFunc   ;==>_cveFindTransformECC

Func _cveFindTransformECCMat(ByRef $matTemplateImage, ByRef $matInputImage, ByRef $matWarpMatrix, $motionType, ByRef $criteria, ByRef $matInputMask)
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

Func _cveKalmanFilterRelease(ByRef $filter)
    ; CVAPI(void) cveKalmanFilterRelease(cv::KalmanFilter** filter);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveKalmanFilterRelease", "ptr*", $filter), "cveKalmanFilterRelease", @error)
EndFunc   ;==>_cveKalmanFilterRelease

Func _cveKalmanFilterPredict(ByRef $kalman, ByRef $control)
    ; CVAPI(const cv::Mat*) cveKalmanFilterPredict(cv::KalmanFilter* kalman, cv::Mat* control);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveKalmanFilterPredict", "ptr", $kalman, "ptr", $control), "cveKalmanFilterPredict", @error)
EndFunc   ;==>_cveKalmanFilterPredict

Func _cveKalmanFilterCorrect(ByRef $kalman, ByRef $measurement)
    ; CVAPI(const cv::Mat*) cveKalmanFilterCorrect(cv::KalmanFilter* kalman, cv::Mat* measurement);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveKalmanFilterCorrect", "ptr", $kalman, "ptr", $measurement), "cveKalmanFilterCorrect", @error)
EndFunc   ;==>_cveKalmanFilterCorrect

Func _cveDISOpticalFlowCreate($preset, ByRef $denseFlow, ByRef $algorithm, ByRef $sharedPtr)
    ; CVAPI(cv::DISOpticalFlow*) cveDISOpticalFlowCreate(int preset, cv::DenseOpticalFlow** denseFlow, cv::Algorithm** algorithm, cv::Ptr<cv::DISOpticalFlow>** sharedPtr);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveDISOpticalFlowCreate", "int", $preset, "ptr*", $denseFlow, "ptr*", $algorithm, "ptr*", $sharedPtr), "cveDISOpticalFlowCreate", @error)
EndFunc   ;==>_cveDISOpticalFlowCreate

Func _cveDISOpticalFlowRelease(ByRef $flow, ByRef $sharedPtr)
    ; CVAPI(void) cveDISOpticalFlowRelease(cv::DISOpticalFlow** flow, cv::Ptr<cv::DISOpticalFlow>** sharedPtr);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDISOpticalFlowRelease", "ptr*", $flow, "ptr*", $sharedPtr), "cveDISOpticalFlowRelease", @error)
EndFunc   ;==>_cveDISOpticalFlowRelease

Func _cveVariationalRefinementCreate(ByRef $denseFlow, ByRef $algorithm, ByRef $sharedPtr)
    ; CVAPI(cv::VariationalRefinement*) cveVariationalRefinementCreate(cv::DenseOpticalFlow** denseFlow, cv::Algorithm** algorithm, cv::Ptr<cv::VariationalRefinement>** sharedPtr);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveVariationalRefinementCreate", "ptr*", $denseFlow, "ptr*", $algorithm, "ptr*", $sharedPtr), "cveVariationalRefinementCreate", @error)
EndFunc   ;==>_cveVariationalRefinementCreate

Func _cveVariationalRefinementRelease(ByRef $flow, ByRef $sharedPtr)
    ; CVAPI(void) cveVariationalRefinementRelease(cv::VariationalRefinement** flow, cv::Ptr<cv::VariationalRefinement>** sharedPtr);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveVariationalRefinementRelease", "ptr*", $flow, "ptr*", $sharedPtr), "cveVariationalRefinementRelease", @error)
EndFunc   ;==>_cveVariationalRefinementRelease

Func _cveTrackerInit(ByRef $tracker, ByRef $image, ByRef $boundingBox)
    ; CVAPI(void) cveTrackerInit(cv::Tracker* tracker, cv::Mat* image, CvRect* boundingBox);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveTrackerInit", "ptr", $tracker, "ptr", $image, "struct*", $boundingBox), "cveTrackerInit", @error)
EndFunc   ;==>_cveTrackerInit

Func _cveTrackerUpdate(ByRef $tracker, ByRef $image, ByRef $boundingBox)
    ; CVAPI(bool) cveTrackerUpdate(cv::Tracker* tracker, cv::Mat* image, CvRect* boundingBox);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveTrackerUpdate", "ptr", $tracker, "ptr", $image, "struct*", $boundingBox), "cveTrackerUpdate", @error)
EndFunc   ;==>_cveTrackerUpdate

Func _cveTrackerMILCreate($samplerInitInRadius, $samplerInitMaxNegNum, $samplerSearchWinSize, $samplerTrackInRadius, $samplerTrackMaxPosNum, $samplerTrackMaxNegNum, $featureSetNumFeatures, ByRef $tracker, ByRef $sharedPtr)
    ; CVAPI(cv::TrackerMIL*) cveTrackerMILCreate(float samplerInitInRadius, int samplerInitMaxNegNum, float samplerSearchWinSize, float samplerTrackInRadius, int samplerTrackMaxPosNum, int samplerTrackMaxNegNum, int featureSetNumFeatures, cv::Tracker** tracker, cv::Ptr<cv::TrackerMIL>** sharedPtr);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveTrackerMILCreate", "float", $samplerInitInRadius, "int", $samplerInitMaxNegNum, "float", $samplerSearchWinSize, "float", $samplerTrackInRadius, "int", $samplerTrackMaxPosNum, "int", $samplerTrackMaxNegNum, "int", $featureSetNumFeatures, "ptr*", $tracker, "ptr*", $sharedPtr), "cveTrackerMILCreate", @error)
EndFunc   ;==>_cveTrackerMILCreate

Func _cveTrackerMILRelease(ByRef $tracker, ByRef $sharedPtr)
    ; CVAPI(void) cveTrackerMILRelease(cv::TrackerMIL** tracker, cv::Ptr<cv::TrackerMIL>** sharedPtr);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveTrackerMILRelease", "ptr*", $tracker, "ptr*", $sharedPtr), "cveTrackerMILRelease", @error)
EndFunc   ;==>_cveTrackerMILRelease

Func _cveTrackerGOTURNCreate(ByRef $tracker, ByRef $sharedPtr)
    ; CVAPI(cv::TrackerGOTURN*) cveTrackerGOTURNCreate(cv::Tracker** tracker, cv::Ptr<cv::TrackerGOTURN>** sharedPtr);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveTrackerGOTURNCreate", "ptr*", $tracker, "ptr*", $sharedPtr), "cveTrackerGOTURNCreate", @error)
EndFunc   ;==>_cveTrackerGOTURNCreate

Func _cveTrackerGOTURNRelease(ByRef $tracker, ByRef $sharedPtr)
    ; CVAPI(void) cveTrackerGOTURNRelease(cv::TrackerGOTURN** tracker, cv::Ptr<cv::TrackerGOTURN>** sharedPtr);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveTrackerGOTURNRelease", "ptr*", $tracker, "ptr*", $sharedPtr), "cveTrackerGOTURNRelease", @error)
EndFunc   ;==>_cveTrackerGOTURNRelease