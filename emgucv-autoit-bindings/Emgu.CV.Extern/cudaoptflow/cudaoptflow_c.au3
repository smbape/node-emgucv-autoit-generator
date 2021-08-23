#include-once
#include "..\..\CVEUtils.au3"

Func _cudaDenseOpticalFlowCalc($opticalFlow, $I0, $I1, $flow, $stream)
    ; CVAPI(void) cudaDenseOpticalFlowCalc(cv::cuda::DenseOpticalFlow* opticalFlow, cv::_InputArray* I0, cv::_InputArray* I1, cv::_InputOutputArray* flow, cv::cuda::Stream* stream);

    Local $sOpticalFlowDllType
    If IsDllStruct($opticalFlow) Then
        $sOpticalFlowDllType = "struct*"
    Else
        $sOpticalFlowDllType = "ptr"
    EndIf

    Local $sI0DllType
    If IsDllStruct($I0) Then
        $sI0DllType = "struct*"
    Else
        $sI0DllType = "ptr"
    EndIf

    Local $sI1DllType
    If IsDllStruct($I1) Then
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

    Local $sStreamDllType
    If IsDllStruct($stream) Then
        $sStreamDllType = "struct*"
    Else
        $sStreamDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaDenseOpticalFlowCalc", $sOpticalFlowDllType, $opticalFlow, $sI0DllType, $I0, $sI1DllType, $I1, $sFlowDllType, $flow, $sStreamDllType, $stream), "cudaDenseOpticalFlowCalc", @error)
EndFunc   ;==>_cudaDenseOpticalFlowCalc

Func _cudaDenseOpticalFlowCalcMat($opticalFlow, $matI0, $matI1, $matFlow, $stream)
    ; cudaDenseOpticalFlowCalc using cv::Mat instead of _*Array

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

    _cudaDenseOpticalFlowCalc($opticalFlow, $iArrI0, $iArrI1, $ioArrFlow, $stream)

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
EndFunc   ;==>_cudaDenseOpticalFlowCalcMat

Func _cudaSparseOpticalFlowCalc($opticalFlow, $prevImg, $nextImg, $prevPts, $nextPts, $status, $err, $stream)
    ; CVAPI(void) cudaSparseOpticalFlowCalc(cv::cuda::SparseOpticalFlow* opticalFlow, cv::_InputArray* prevImg, cv::_InputArray* nextImg, cv::_InputArray* prevPts, cv::_InputOutputArray* nextPts, cv::_OutputArray* status, cv::_OutputArray* err, cv::cuda::Stream* stream);

    Local $sOpticalFlowDllType
    If IsDllStruct($opticalFlow) Then
        $sOpticalFlowDllType = "struct*"
    Else
        $sOpticalFlowDllType = "ptr"
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

    Local $sStreamDllType
    If IsDllStruct($stream) Then
        $sStreamDllType = "struct*"
    Else
        $sStreamDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaSparseOpticalFlowCalc", $sOpticalFlowDllType, $opticalFlow, $sPrevImgDllType, $prevImg, $sNextImgDllType, $nextImg, $sPrevPtsDllType, $prevPts, $sNextPtsDllType, $nextPts, $sStatusDllType, $status, $sErrDllType, $err, $sStreamDllType, $stream), "cudaSparseOpticalFlowCalc", @error)
EndFunc   ;==>_cudaSparseOpticalFlowCalc

Func _cudaSparseOpticalFlowCalcMat($opticalFlow, $matPrevImg, $matNextImg, $matPrevPts, $matNextPts, $matStatus, $matErr, $stream)
    ; cudaSparseOpticalFlowCalc using cv::Mat instead of _*Array

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

    _cudaSparseOpticalFlowCalc($opticalFlow, $iArrPrevImg, $iArrNextImg, $iArrPrevPts, $ioArrNextPts, $oArrStatus, $oArrErr, $stream)

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
EndFunc   ;==>_cudaSparseOpticalFlowCalcMat

Func _cudaBroxOpticalFlowCreate($alpha, $gamma, $scaleFactor, $innerIterations, $outerIterations, $solverIterations, $denseFlow, $algorithm, $sharedPtr)
    ; CVAPI(cv::cuda::BroxOpticalFlow*) cudaBroxOpticalFlowCreate(double alpha, double gamma, double scaleFactor, int innerIterations, int outerIterations, int solverIterations, cv::cuda::DenseOpticalFlow** denseFlow, cv::Algorithm** algorithm, cv::Ptr<cv::cuda::BroxOpticalFlow>** sharedPtr);

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
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cudaBroxOpticalFlowCreate", "double", $alpha, "double", $gamma, "double", $scaleFactor, "int", $innerIterations, "int", $outerIterations, "int", $solverIterations, $sDenseFlowDllType, $denseFlow, $sAlgorithmDllType, $algorithm, $sSharedPtrDllType, $sharedPtr), "cudaBroxOpticalFlowCreate", @error)
EndFunc   ;==>_cudaBroxOpticalFlowCreate

Func _cudaBroxOpticalFlowRelease($flow)
    ; CVAPI(void) cudaBroxOpticalFlowRelease(cv::Ptr<cv::cuda::BroxOpticalFlow>** flow);

    Local $sFlowDllType
    If IsDllStruct($flow) Then
        $sFlowDllType = "struct*"
    ElseIf $flow == Null Then
        $sFlowDllType = "ptr"
    Else
        $sFlowDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaBroxOpticalFlowRelease", $sFlowDllType, $flow), "cudaBroxOpticalFlowRelease", @error)
EndFunc   ;==>_cudaBroxOpticalFlowRelease

Func _cudaDensePyrLKOpticalFlowCreate($winSize, $maxLevel, $iters, $useInitialFlow, $denseFlow, $algorithm, $sharedPtr)
    ; CVAPI(cv::cuda::DensePyrLKOpticalFlow*) cudaDensePyrLKOpticalFlowCreate(CvSize* winSize, int maxLevel, int iters, bool useInitialFlow, cv::cuda::DenseOpticalFlow** denseFlow, cv::Algorithm** algorithm, cv::Ptr<cv::cuda::DensePyrLKOpticalFlow>** sharedPtr);

    Local $sWinSizeDllType
    If IsDllStruct($winSize) Then
        $sWinSizeDllType = "struct*"
    Else
        $sWinSizeDllType = "ptr"
    EndIf

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
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cudaDensePyrLKOpticalFlowCreate", $sWinSizeDllType, $winSize, "int", $maxLevel, "int", $iters, "boolean", $useInitialFlow, $sDenseFlowDllType, $denseFlow, $sAlgorithmDllType, $algorithm, $sSharedPtrDllType, $sharedPtr), "cudaDensePyrLKOpticalFlowCreate", @error)
EndFunc   ;==>_cudaDensePyrLKOpticalFlowCreate

Func _cudaDensePyrLKOpticalFlowRelease($flow)
    ; CVAPI(void) cudaDensePyrLKOpticalFlowRelease(cv::Ptr<cv::cuda::DensePyrLKOpticalFlow>** flow);

    Local $sFlowDllType
    If IsDllStruct($flow) Then
        $sFlowDllType = "struct*"
    ElseIf $flow == Null Then
        $sFlowDllType = "ptr"
    Else
        $sFlowDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaDensePyrLKOpticalFlowRelease", $sFlowDllType, $flow), "cudaDensePyrLKOpticalFlowRelease", @error)
EndFunc   ;==>_cudaDensePyrLKOpticalFlowRelease

Func _cudaSparsePyrLKOpticalFlowCreate($winSize, $maxLevel, $iters, $useInitialFlow, $sparseFlow, $algorithm, $sharedPtr)
    ; CVAPI(cv::cuda::SparsePyrLKOpticalFlow*) cudaSparsePyrLKOpticalFlowCreate(CvSize* winSize, int maxLevel, int iters, bool useInitialFlow, cv::cuda::SparseOpticalFlow** sparseFlow, cv::Algorithm** algorithm, cv::Ptr<cv::cuda::SparsePyrLKOpticalFlow>** sharedPtr);

    Local $sWinSizeDllType
    If IsDllStruct($winSize) Then
        $sWinSizeDllType = "struct*"
    Else
        $sWinSizeDllType = "ptr"
    EndIf

    Local $sSparseFlowDllType
    If IsDllStruct($sparseFlow) Then
        $sSparseFlowDllType = "struct*"
    ElseIf $sparseFlow == Null Then
        $sSparseFlowDllType = "ptr"
    Else
        $sSparseFlowDllType = "ptr*"
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
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cudaSparsePyrLKOpticalFlowCreate", $sWinSizeDllType, $winSize, "int", $maxLevel, "int", $iters, "boolean", $useInitialFlow, $sSparseFlowDllType, $sparseFlow, $sAlgorithmDllType, $algorithm, $sSharedPtrDllType, $sharedPtr), "cudaSparsePyrLKOpticalFlowCreate", @error)
EndFunc   ;==>_cudaSparsePyrLKOpticalFlowCreate

Func _cudaSparsePyrLKOpticalFlowRelease($flow)
    ; CVAPI(void) cudaSparsePyrLKOpticalFlowRelease(cv::Ptr<cv::cuda::SparsePyrLKOpticalFlow>** flow);

    Local $sFlowDllType
    If IsDllStruct($flow) Then
        $sFlowDllType = "struct*"
    ElseIf $flow == Null Then
        $sFlowDllType = "ptr"
    Else
        $sFlowDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaSparsePyrLKOpticalFlowRelease", $sFlowDllType, $flow), "cudaSparsePyrLKOpticalFlowRelease", @error)
EndFunc   ;==>_cudaSparsePyrLKOpticalFlowRelease

Func _cudaFarnebackOpticalFlowCreate($numLevels, $pyrScale, $fastPyramids, $winSize, $numIters, $polyN, $polySigma, $flags, $denseFlow, $algorithm, $sharedPtr)
    ; CVAPI(cv::cuda::FarnebackOpticalFlow*) cudaFarnebackOpticalFlowCreate(int numLevels, double pyrScale, bool fastPyramids, int winSize, int numIters, int polyN, double polySigma, int flags, cv::cuda::DenseOpticalFlow** denseFlow, cv::Algorithm** algorithm, cv::Ptr<cv::cuda::FarnebackOpticalFlow>** sharedPtr);

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
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cudaFarnebackOpticalFlowCreate", "int", $numLevels, "double", $pyrScale, "boolean", $fastPyramids, "int", $winSize, "int", $numIters, "int", $polyN, "double", $polySigma, "int", $flags, $sDenseFlowDllType, $denseFlow, $sAlgorithmDllType, $algorithm, $sSharedPtrDllType, $sharedPtr), "cudaFarnebackOpticalFlowCreate", @error)
EndFunc   ;==>_cudaFarnebackOpticalFlowCreate

Func _cudaFarnebackOpticalFlowRelease($flow)
    ; CVAPI(void) cudaFarnebackOpticalFlowRelease(cv::Ptr<cv::cuda::FarnebackOpticalFlow>** flow);

    Local $sFlowDllType
    If IsDllStruct($flow) Then
        $sFlowDllType = "struct*"
    ElseIf $flow == Null Then
        $sFlowDllType = "ptr"
    Else
        $sFlowDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaFarnebackOpticalFlowRelease", $sFlowDllType, $flow), "cudaFarnebackOpticalFlowRelease", @error)
EndFunc   ;==>_cudaFarnebackOpticalFlowRelease

Func _cudaOpticalFlowDualTvl1Create($tau, $lambda, $theta, $nscales, $warps, $epsilon, $iterations, $scaleStep, $gamma, $useInitialFlow, $denseFlow, $algorithm, $sharedPtr)
    ; CVAPI(cv::cuda::OpticalFlowDual_TVL1*) cudaOpticalFlowDualTvl1Create(double tau, double lambda, double theta, int nscales, int warps, double epsilon, int iterations, double scaleStep, double gamma, bool useInitialFlow, cv::cuda::DenseOpticalFlow** denseFlow, cv::Algorithm** algorithm, cv::Ptr<cv::cuda::OpticalFlowDual_TVL1>** sharedPtr);

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
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cudaOpticalFlowDualTvl1Create", "double", $tau, "double", $lambda, "double", $theta, "int", $nscales, "int", $warps, "double", $epsilon, "int", $iterations, "double", $scaleStep, "double", $gamma, "boolean", $useInitialFlow, $sDenseFlowDllType, $denseFlow, $sAlgorithmDllType, $algorithm, $sSharedPtrDllType, $sharedPtr), "cudaOpticalFlowDualTvl1Create", @error)
EndFunc   ;==>_cudaOpticalFlowDualTvl1Create

Func _cudaOpticalFlowDualTvl1Release($flow)
    ; CVAPI(void) cudaOpticalFlowDualTvl1Release(cv::Ptr<cv::cuda::OpticalFlowDual_TVL1>** flow);

    Local $sFlowDllType
    If IsDllStruct($flow) Then
        $sFlowDllType = "struct*"
    ElseIf $flow == Null Then
        $sFlowDllType = "ptr"
    Else
        $sFlowDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaOpticalFlowDualTvl1Release", $sFlowDllType, $flow), "cudaOpticalFlowDualTvl1Release", @error)
EndFunc   ;==>_cudaOpticalFlowDualTvl1Release

Func _cudaNvidiaOpticalFlow_1_0_Create($imageSize, $perfPreset, $enableTemporalHints, $enableExternalHints, $enableCostBuffer, $gpuId, $inputStream, $outputStream, $nHWOpticalFlow, $algorithm, $sharedPtr)
    ; CVAPI(cv::cuda::NvidiaOpticalFlow_1_0*) cudaNvidiaOpticalFlow_1_0_Create(CvSize* imageSize, int perfPreset, bool enableTemporalHints, bool enableExternalHints, bool enableCostBuffer, int gpuId, cv::cuda::Stream* inputStream, cv::cuda::Stream* outputStream, cv::cuda::NvidiaHWOpticalFlow** nHWOpticalFlow, cv::Algorithm** algorithm, cv::Ptr<cv::cuda::NvidiaOpticalFlow_1_0>** sharedPtr);

    Local $sImageSizeDllType
    If IsDllStruct($imageSize) Then
        $sImageSizeDllType = "struct*"
    Else
        $sImageSizeDllType = "ptr"
    EndIf

    Local $sInputStreamDllType
    If IsDllStruct($inputStream) Then
        $sInputStreamDllType = "struct*"
    Else
        $sInputStreamDllType = "ptr"
    EndIf

    Local $sOutputStreamDllType
    If IsDllStruct($outputStream) Then
        $sOutputStreamDllType = "struct*"
    Else
        $sOutputStreamDllType = "ptr"
    EndIf

    Local $sNHWOpticalFlowDllType
    If IsDllStruct($nHWOpticalFlow) Then
        $sNHWOpticalFlowDllType = "struct*"
    ElseIf $nHWOpticalFlow == Null Then
        $sNHWOpticalFlowDllType = "ptr"
    Else
        $sNHWOpticalFlowDllType = "ptr*"
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
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cudaNvidiaOpticalFlow_1_0_Create", $sImageSizeDllType, $imageSize, "int", $perfPreset, "boolean", $enableTemporalHints, "boolean", $enableExternalHints, "boolean", $enableCostBuffer, "int", $gpuId, $sInputStreamDllType, $inputStream, $sOutputStreamDllType, $outputStream, $sNHWOpticalFlowDllType, $nHWOpticalFlow, $sAlgorithmDllType, $algorithm, $sSharedPtrDllType, $sharedPtr), "cudaNvidiaOpticalFlow_1_0_Create", @error)
EndFunc   ;==>_cudaNvidiaOpticalFlow_1_0_Create

Func _cudaNvidiaOpticalFlow_1_0_UpSampler($nFlow, $flow, $imageSize, $gridSize, $upsampledFlow)
    ; CVAPI(void) cudaNvidiaOpticalFlow_1_0_UpSampler(cv::cuda::NvidiaOpticalFlow_1_0* nFlow, cv::_InputArray* flow, CvSize* imageSize, int gridSize, cv::_InputOutputArray* upsampledFlow);

    Local $sNFlowDllType
    If IsDllStruct($nFlow) Then
        $sNFlowDllType = "struct*"
    Else
        $sNFlowDllType = "ptr"
    EndIf

    Local $sFlowDllType
    If IsDllStruct($flow) Then
        $sFlowDllType = "struct*"
    Else
        $sFlowDllType = "ptr"
    EndIf

    Local $sImageSizeDllType
    If IsDllStruct($imageSize) Then
        $sImageSizeDllType = "struct*"
    Else
        $sImageSizeDllType = "ptr"
    EndIf

    Local $sUpsampledFlowDllType
    If IsDllStruct($upsampledFlow) Then
        $sUpsampledFlowDllType = "struct*"
    Else
        $sUpsampledFlowDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaNvidiaOpticalFlow_1_0_UpSampler", $sNFlowDllType, $nFlow, $sFlowDllType, $flow, $sImageSizeDllType, $imageSize, "int", $gridSize, $sUpsampledFlowDllType, $upsampledFlow), "cudaNvidiaOpticalFlow_1_0_UpSampler", @error)
EndFunc   ;==>_cudaNvidiaOpticalFlow_1_0_UpSampler

Func _cudaNvidiaOpticalFlow_1_0_UpSamplerMat($nFlow, $matFlow, $imageSize, $gridSize, $matUpsampledFlow)
    ; cudaNvidiaOpticalFlow_1_0_UpSampler using cv::Mat instead of _*Array

    Local $iArrFlow, $vectorOfMatFlow, $iArrFlowSize
    Local $bFlowIsArray = VarGetType($matFlow) == "Array"

    If $bFlowIsArray Then
        $vectorOfMatFlow = _VectorOfMatCreate()

        $iArrFlowSize = UBound($matFlow)
        For $i = 0 To $iArrFlowSize - 1
            _VectorOfMatPush($vectorOfMatFlow, $matFlow[$i])
        Next

        $iArrFlow = _cveInputArrayFromVectorOfMat($vectorOfMatFlow)
    Else
        $iArrFlow = _cveInputArrayFromMat($matFlow)
    EndIf

    Local $ioArrUpsampledFlow, $vectorOfMatUpsampledFlow, $iArrUpsampledFlowSize
    Local $bUpsampledFlowIsArray = VarGetType($matUpsampledFlow) == "Array"

    If $bUpsampledFlowIsArray Then
        $vectorOfMatUpsampledFlow = _VectorOfMatCreate()

        $iArrUpsampledFlowSize = UBound($matUpsampledFlow)
        For $i = 0 To $iArrUpsampledFlowSize - 1
            _VectorOfMatPush($vectorOfMatUpsampledFlow, $matUpsampledFlow[$i])
        Next

        $ioArrUpsampledFlow = _cveInputOutputArrayFromVectorOfMat($vectorOfMatUpsampledFlow)
    Else
        $ioArrUpsampledFlow = _cveInputOutputArrayFromMat($matUpsampledFlow)
    EndIf

    _cudaNvidiaOpticalFlow_1_0_UpSampler($nFlow, $iArrFlow, $imageSize, $gridSize, $ioArrUpsampledFlow)

    If $bUpsampledFlowIsArray Then
        _VectorOfMatRelease($vectorOfMatUpsampledFlow)
    EndIf

    _cveInputOutputArrayRelease($ioArrUpsampledFlow)

    If $bFlowIsArray Then
        _VectorOfMatRelease($vectorOfMatFlow)
    EndIf

    _cveInputArrayRelease($iArrFlow)
EndFunc   ;==>_cudaNvidiaOpticalFlow_1_0_UpSamplerMat

Func _cudaNvidiaOpticalFlow_1_0_Release($flow)
    ; CVAPI(void) cudaNvidiaOpticalFlow_1_0_Release(cv::Ptr<cv::cuda::NvidiaOpticalFlow_1_0>** flow);

    Local $sFlowDllType
    If IsDllStruct($flow) Then
        $sFlowDllType = "struct*"
    ElseIf $flow == Null Then
        $sFlowDllType = "ptr"
    Else
        $sFlowDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaNvidiaOpticalFlow_1_0_Release", $sFlowDllType, $flow), "cudaNvidiaOpticalFlow_1_0_Release", @error)
EndFunc   ;==>_cudaNvidiaOpticalFlow_1_0_Release

Func _cudaNvidiaOpticalFlowCalc($nHWOpticalFlow, $inputImage, $referenceImage, $flow, $stream, $hint, $cost)
    ; CVAPI(void) cudaNvidiaOpticalFlowCalc(cv::cuda::NvidiaHWOpticalFlow* nHWOpticalFlow, cv::_InputArray* inputImage, cv::_InputArray* referenceImage, cv::_InputOutputArray* flow, cv::cuda::Stream* stream, cv::_InputArray* hint, cv::_OutputArray* cost);

    Local $sNHWOpticalFlowDllType
    If IsDllStruct($nHWOpticalFlow) Then
        $sNHWOpticalFlowDllType = "struct*"
    Else
        $sNHWOpticalFlowDllType = "ptr"
    EndIf

    Local $sInputImageDllType
    If IsDllStruct($inputImage) Then
        $sInputImageDllType = "struct*"
    Else
        $sInputImageDllType = "ptr"
    EndIf

    Local $sReferenceImageDllType
    If IsDllStruct($referenceImage) Then
        $sReferenceImageDllType = "struct*"
    Else
        $sReferenceImageDllType = "ptr"
    EndIf

    Local $sFlowDllType
    If IsDllStruct($flow) Then
        $sFlowDllType = "struct*"
    Else
        $sFlowDllType = "ptr"
    EndIf

    Local $sStreamDllType
    If IsDllStruct($stream) Then
        $sStreamDllType = "struct*"
    Else
        $sStreamDllType = "ptr"
    EndIf

    Local $sHintDllType
    If IsDllStruct($hint) Then
        $sHintDllType = "struct*"
    Else
        $sHintDllType = "ptr"
    EndIf

    Local $sCostDllType
    If IsDllStruct($cost) Then
        $sCostDllType = "struct*"
    Else
        $sCostDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaNvidiaOpticalFlowCalc", $sNHWOpticalFlowDllType, $nHWOpticalFlow, $sInputImageDllType, $inputImage, $sReferenceImageDllType, $referenceImage, $sFlowDllType, $flow, $sStreamDllType, $stream, $sHintDllType, $hint, $sCostDllType, $cost), "cudaNvidiaOpticalFlowCalc", @error)
EndFunc   ;==>_cudaNvidiaOpticalFlowCalc

Func _cudaNvidiaOpticalFlowCalcMat($nHWOpticalFlow, $matInputImage, $matReferenceImage, $matFlow, $stream, $matHint, $matCost)
    ; cudaNvidiaOpticalFlowCalc using cv::Mat instead of _*Array

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

    Local $iArrReferenceImage, $vectorOfMatReferenceImage, $iArrReferenceImageSize
    Local $bReferenceImageIsArray = VarGetType($matReferenceImage) == "Array"

    If $bReferenceImageIsArray Then
        $vectorOfMatReferenceImage = _VectorOfMatCreate()

        $iArrReferenceImageSize = UBound($matReferenceImage)
        For $i = 0 To $iArrReferenceImageSize - 1
            _VectorOfMatPush($vectorOfMatReferenceImage, $matReferenceImage[$i])
        Next

        $iArrReferenceImage = _cveInputArrayFromVectorOfMat($vectorOfMatReferenceImage)
    Else
        $iArrReferenceImage = _cveInputArrayFromMat($matReferenceImage)
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

    Local $iArrHint, $vectorOfMatHint, $iArrHintSize
    Local $bHintIsArray = VarGetType($matHint) == "Array"

    If $bHintIsArray Then
        $vectorOfMatHint = _VectorOfMatCreate()

        $iArrHintSize = UBound($matHint)
        For $i = 0 To $iArrHintSize - 1
            _VectorOfMatPush($vectorOfMatHint, $matHint[$i])
        Next

        $iArrHint = _cveInputArrayFromVectorOfMat($vectorOfMatHint)
    Else
        $iArrHint = _cveInputArrayFromMat($matHint)
    EndIf

    Local $oArrCost, $vectorOfMatCost, $iArrCostSize
    Local $bCostIsArray = VarGetType($matCost) == "Array"

    If $bCostIsArray Then
        $vectorOfMatCost = _VectorOfMatCreate()

        $iArrCostSize = UBound($matCost)
        For $i = 0 To $iArrCostSize - 1
            _VectorOfMatPush($vectorOfMatCost, $matCost[$i])
        Next

        $oArrCost = _cveOutputArrayFromVectorOfMat($vectorOfMatCost)
    Else
        $oArrCost = _cveOutputArrayFromMat($matCost)
    EndIf

    _cudaNvidiaOpticalFlowCalc($nHWOpticalFlow, $iArrInputImage, $iArrReferenceImage, $ioArrFlow, $stream, $iArrHint, $oArrCost)

    If $bCostIsArray Then
        _VectorOfMatRelease($vectorOfMatCost)
    EndIf

    _cveOutputArrayRelease($oArrCost)

    If $bHintIsArray Then
        _VectorOfMatRelease($vectorOfMatHint)
    EndIf

    _cveInputArrayRelease($iArrHint)

    If $bFlowIsArray Then
        _VectorOfMatRelease($vectorOfMatFlow)
    EndIf

    _cveInputOutputArrayRelease($ioArrFlow)

    If $bReferenceImageIsArray Then
        _VectorOfMatRelease($vectorOfMatReferenceImage)
    EndIf

    _cveInputArrayRelease($iArrReferenceImage)

    If $bInputImageIsArray Then
        _VectorOfMatRelease($vectorOfMatInputImage)
    EndIf

    _cveInputArrayRelease($iArrInputImage)
EndFunc   ;==>_cudaNvidiaOpticalFlowCalcMat

Func _cudaNvidiaOpticalFlowCollectGarbage($nHWOpticalFlow)
    ; CVAPI(void) cudaNvidiaOpticalFlowCollectGarbage(cv::cuda::NvidiaHWOpticalFlow* nHWOpticalFlow);

    Local $sNHWOpticalFlowDllType
    If IsDllStruct($nHWOpticalFlow) Then
        $sNHWOpticalFlowDllType = "struct*"
    Else
        $sNHWOpticalFlowDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaNvidiaOpticalFlowCollectGarbage", $sNHWOpticalFlowDllType, $nHWOpticalFlow), "cudaNvidiaOpticalFlowCollectGarbage", @error)
EndFunc   ;==>_cudaNvidiaOpticalFlowCollectGarbage

Func _cudaNvidiaOpticalFlowGetGridSize($nHWOpticalFlow)
    ; CVAPI(int) cudaNvidiaOpticalFlowGetGridSize(cv::cuda::NvidiaHWOpticalFlow* nHWOpticalFlow);

    Local $sNHWOpticalFlowDllType
    If IsDllStruct($nHWOpticalFlow) Then
        $sNHWOpticalFlowDllType = "struct*"
    Else
        $sNHWOpticalFlowDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cudaNvidiaOpticalFlowGetGridSize", $sNHWOpticalFlowDllType, $nHWOpticalFlow), "cudaNvidiaOpticalFlowGetGridSize", @error)
EndFunc   ;==>_cudaNvidiaOpticalFlowGetGridSize

Func _cudaNvidiaOpticalFlow_2_0_Create($imageSize, $perfPreset, $outputGridSize, $hintGridSize, $enableTemporalHints, $enableExternalHints, $enableCostBuffer, $gpuId, $inputStream, $outputStream, $nHWOpticalFlow, $algorithm, $sharedPtr)
    ; CVAPI(cv::cuda::NvidiaOpticalFlow_2_0*) cudaNvidiaOpticalFlow_2_0_Create(CvSize* imageSize, int perfPreset, int outputGridSize, int hintGridSize, bool enableTemporalHints, bool enableExternalHints, bool enableCostBuffer, int gpuId, cv::cuda::Stream* inputStream, cv::cuda::Stream* outputStream, cv::cuda::NvidiaHWOpticalFlow** nHWOpticalFlow, cv::Algorithm** algorithm, cv::Ptr<cv::cuda::NvidiaOpticalFlow_2_0>** sharedPtr);

    Local $sImageSizeDllType
    If IsDllStruct($imageSize) Then
        $sImageSizeDllType = "struct*"
    Else
        $sImageSizeDllType = "ptr"
    EndIf

    Local $sInputStreamDllType
    If IsDllStruct($inputStream) Then
        $sInputStreamDllType = "struct*"
    Else
        $sInputStreamDllType = "ptr"
    EndIf

    Local $sOutputStreamDllType
    If IsDllStruct($outputStream) Then
        $sOutputStreamDllType = "struct*"
    Else
        $sOutputStreamDllType = "ptr"
    EndIf

    Local $sNHWOpticalFlowDllType
    If IsDllStruct($nHWOpticalFlow) Then
        $sNHWOpticalFlowDllType = "struct*"
    ElseIf $nHWOpticalFlow == Null Then
        $sNHWOpticalFlowDllType = "ptr"
    Else
        $sNHWOpticalFlowDllType = "ptr*"
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
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cudaNvidiaOpticalFlow_2_0_Create", $sImageSizeDllType, $imageSize, "int", $perfPreset, "int", $outputGridSize, "int", $hintGridSize, "boolean", $enableTemporalHints, "boolean", $enableExternalHints, "boolean", $enableCostBuffer, "int", $gpuId, $sInputStreamDllType, $inputStream, $sOutputStreamDllType, $outputStream, $sNHWOpticalFlowDllType, $nHWOpticalFlow, $sAlgorithmDllType, $algorithm, $sSharedPtrDllType, $sharedPtr), "cudaNvidiaOpticalFlow_2_0_Create", @error)
EndFunc   ;==>_cudaNvidiaOpticalFlow_2_0_Create

Func _cudaNvidiaOpticalFlow_2_0_ConvertToFloat($nvof, $flow, $floatFlow)
    ; CVAPI(void) cudaNvidiaOpticalFlow_2_0_ConvertToFloat(cv::cuda::NvidiaOpticalFlow_2_0* nvof, cv::_InputArray* flow, cv::_InputOutputArray* floatFlow);

    Local $sNvofDllType
    If IsDllStruct($nvof) Then
        $sNvofDllType = "struct*"
    Else
        $sNvofDllType = "ptr"
    EndIf

    Local $sFlowDllType
    If IsDllStruct($flow) Then
        $sFlowDllType = "struct*"
    Else
        $sFlowDllType = "ptr"
    EndIf

    Local $sFloatFlowDllType
    If IsDllStruct($floatFlow) Then
        $sFloatFlowDllType = "struct*"
    Else
        $sFloatFlowDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaNvidiaOpticalFlow_2_0_ConvertToFloat", $sNvofDllType, $nvof, $sFlowDllType, $flow, $sFloatFlowDllType, $floatFlow), "cudaNvidiaOpticalFlow_2_0_ConvertToFloat", @error)
EndFunc   ;==>_cudaNvidiaOpticalFlow_2_0_ConvertToFloat

Func _cudaNvidiaOpticalFlow_2_0_ConvertToFloatMat($nvof, $matFlow, $matFloatFlow)
    ; cudaNvidiaOpticalFlow_2_0_ConvertToFloat using cv::Mat instead of _*Array

    Local $iArrFlow, $vectorOfMatFlow, $iArrFlowSize
    Local $bFlowIsArray = VarGetType($matFlow) == "Array"

    If $bFlowIsArray Then
        $vectorOfMatFlow = _VectorOfMatCreate()

        $iArrFlowSize = UBound($matFlow)
        For $i = 0 To $iArrFlowSize - 1
            _VectorOfMatPush($vectorOfMatFlow, $matFlow[$i])
        Next

        $iArrFlow = _cveInputArrayFromVectorOfMat($vectorOfMatFlow)
    Else
        $iArrFlow = _cveInputArrayFromMat($matFlow)
    EndIf

    Local $ioArrFloatFlow, $vectorOfMatFloatFlow, $iArrFloatFlowSize
    Local $bFloatFlowIsArray = VarGetType($matFloatFlow) == "Array"

    If $bFloatFlowIsArray Then
        $vectorOfMatFloatFlow = _VectorOfMatCreate()

        $iArrFloatFlowSize = UBound($matFloatFlow)
        For $i = 0 To $iArrFloatFlowSize - 1
            _VectorOfMatPush($vectorOfMatFloatFlow, $matFloatFlow[$i])
        Next

        $ioArrFloatFlow = _cveInputOutputArrayFromVectorOfMat($vectorOfMatFloatFlow)
    Else
        $ioArrFloatFlow = _cveInputOutputArrayFromMat($matFloatFlow)
    EndIf

    _cudaNvidiaOpticalFlow_2_0_ConvertToFloat($nvof, $iArrFlow, $ioArrFloatFlow)

    If $bFloatFlowIsArray Then
        _VectorOfMatRelease($vectorOfMatFloatFlow)
    EndIf

    _cveInputOutputArrayRelease($ioArrFloatFlow)

    If $bFlowIsArray Then
        _VectorOfMatRelease($vectorOfMatFlow)
    EndIf

    _cveInputArrayRelease($iArrFlow)
EndFunc   ;==>_cudaNvidiaOpticalFlow_2_0_ConvertToFloatMat

Func _cudaNvidiaOpticalFlow_2_0_Release($flow)
    ; CVAPI(void) cudaNvidiaOpticalFlow_2_0_Release(cv::Ptr<cv::cuda::NvidiaOpticalFlow_2_0>** flow);

    Local $sFlowDllType
    If IsDllStruct($flow) Then
        $sFlowDllType = "struct*"
    ElseIf $flow == Null Then
        $sFlowDllType = "ptr"
    Else
        $sFlowDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaNvidiaOpticalFlow_2_0_Release", $sFlowDllType, $flow), "cudaNvidiaOpticalFlow_2_0_Release", @error)
EndFunc   ;==>_cudaNvidiaOpticalFlow_2_0_Release