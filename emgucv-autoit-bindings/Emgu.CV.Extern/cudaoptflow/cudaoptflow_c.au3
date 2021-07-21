#include-once
#include "..\..\CVEUtils.au3"

Func _cudaDenseOpticalFlowCalc($opticalFlow, $I0, $I1, $flow, $stream)
    ; CVAPI(void) cudaDenseOpticalFlowCalc(cv::cuda::DenseOpticalFlow* opticalFlow, cv::_InputArray* I0, cv::_InputArray* I1, cv::_InputOutputArray* flow, cv::cuda::Stream* stream);

    Local $bOpticalFlowDllType
    If VarGetType($opticalFlow) == "DLLStruct" Then
        $bOpticalFlowDllType = "struct*"
    Else
        $bOpticalFlowDllType = "ptr"
    EndIf

    Local $bI0DllType
    If VarGetType($I0) == "DLLStruct" Then
        $bI0DllType = "struct*"
    Else
        $bI0DllType = "ptr"
    EndIf

    Local $bI1DllType
    If VarGetType($I1) == "DLLStruct" Then
        $bI1DllType = "struct*"
    Else
        $bI1DllType = "ptr"
    EndIf

    Local $bFlowDllType
    If VarGetType($flow) == "DLLStruct" Then
        $bFlowDllType = "struct*"
    Else
        $bFlowDllType = "ptr"
    EndIf

    Local $bStreamDllType
    If VarGetType($stream) == "DLLStruct" Then
        $bStreamDllType = "struct*"
    Else
        $bStreamDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaDenseOpticalFlowCalc", $bOpticalFlowDllType, $opticalFlow, $bI0DllType, $I0, $bI1DllType, $I1, $bFlowDllType, $flow, $bStreamDllType, $stream), "cudaDenseOpticalFlowCalc", @error)
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

    Local $bOpticalFlowDllType
    If VarGetType($opticalFlow) == "DLLStruct" Then
        $bOpticalFlowDllType = "struct*"
    Else
        $bOpticalFlowDllType = "ptr"
    EndIf

    Local $bPrevImgDllType
    If VarGetType($prevImg) == "DLLStruct" Then
        $bPrevImgDllType = "struct*"
    Else
        $bPrevImgDllType = "ptr"
    EndIf

    Local $bNextImgDllType
    If VarGetType($nextImg) == "DLLStruct" Then
        $bNextImgDllType = "struct*"
    Else
        $bNextImgDllType = "ptr"
    EndIf

    Local $bPrevPtsDllType
    If VarGetType($prevPts) == "DLLStruct" Then
        $bPrevPtsDllType = "struct*"
    Else
        $bPrevPtsDllType = "ptr"
    EndIf

    Local $bNextPtsDllType
    If VarGetType($nextPts) == "DLLStruct" Then
        $bNextPtsDllType = "struct*"
    Else
        $bNextPtsDllType = "ptr"
    EndIf

    Local $bStatusDllType
    If VarGetType($status) == "DLLStruct" Then
        $bStatusDllType = "struct*"
    Else
        $bStatusDllType = "ptr"
    EndIf

    Local $bErrDllType
    If VarGetType($err) == "DLLStruct" Then
        $bErrDllType = "struct*"
    Else
        $bErrDllType = "ptr"
    EndIf

    Local $bStreamDllType
    If VarGetType($stream) == "DLLStruct" Then
        $bStreamDllType = "struct*"
    Else
        $bStreamDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaSparseOpticalFlowCalc", $bOpticalFlowDllType, $opticalFlow, $bPrevImgDllType, $prevImg, $bNextImgDllType, $nextImg, $bPrevPtsDllType, $prevPts, $bNextPtsDllType, $nextPts, $bStatusDllType, $status, $bErrDllType, $err, $bStreamDllType, $stream), "cudaSparseOpticalFlowCalc", @error)
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

    Local $bDenseFlowDllType
    If VarGetType($denseFlow) == "DLLStruct" Then
        $bDenseFlowDllType = "struct*"
    Else
        $bDenseFlowDllType = "ptr*"
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
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cudaBroxOpticalFlowCreate", "double", $alpha, "double", $gamma, "double", $scaleFactor, "int", $innerIterations, "int", $outerIterations, "int", $solverIterations, $bDenseFlowDllType, $denseFlow, $bAlgorithmDllType, $algorithm, $bSharedPtrDllType, $sharedPtr), "cudaBroxOpticalFlowCreate", @error)
EndFunc   ;==>_cudaBroxOpticalFlowCreate

Func _cudaBroxOpticalFlowRelease($flow)
    ; CVAPI(void) cudaBroxOpticalFlowRelease(cv::Ptr<cv::cuda::BroxOpticalFlow>** flow);

    Local $bFlowDllType
    If VarGetType($flow) == "DLLStruct" Then
        $bFlowDllType = "struct*"
    Else
        $bFlowDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaBroxOpticalFlowRelease", $bFlowDllType, $flow), "cudaBroxOpticalFlowRelease", @error)
EndFunc   ;==>_cudaBroxOpticalFlowRelease

Func _cudaDensePyrLKOpticalFlowCreate($winSize, $maxLevel, $iters, $useInitialFlow, $denseFlow, $algorithm, $sharedPtr)
    ; CVAPI(cv::cuda::DensePyrLKOpticalFlow *) cudaDensePyrLKOpticalFlowCreate(CvSize* winSize, int maxLevel, int iters, bool useInitialFlow, cv::cuda::DenseOpticalFlow** denseFlow, cv::Algorithm** algorithm, cv::Ptr<cv::cuda::DensePyrLKOpticalFlow>** sharedPtr);

    Local $bWinSizeDllType
    If VarGetType($winSize) == "DLLStruct" Then
        $bWinSizeDllType = "struct*"
    Else
        $bWinSizeDllType = "ptr"
    EndIf

    Local $bDenseFlowDllType
    If VarGetType($denseFlow) == "DLLStruct" Then
        $bDenseFlowDllType = "struct*"
    Else
        $bDenseFlowDllType = "ptr*"
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
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cudaDensePyrLKOpticalFlowCreate", $bWinSizeDllType, $winSize, "int", $maxLevel, "int", $iters, "boolean", $useInitialFlow, $bDenseFlowDllType, $denseFlow, $bAlgorithmDllType, $algorithm, $bSharedPtrDllType, $sharedPtr), "cudaDensePyrLKOpticalFlowCreate", @error)
EndFunc   ;==>_cudaDensePyrLKOpticalFlowCreate

Func _cudaDensePyrLKOpticalFlowRelease($flow)
    ; CVAPI(void) cudaDensePyrLKOpticalFlowRelease(cv::Ptr<cv::cuda::DensePyrLKOpticalFlow>** flow);

    Local $bFlowDllType
    If VarGetType($flow) == "DLLStruct" Then
        $bFlowDllType = "struct*"
    Else
        $bFlowDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaDensePyrLKOpticalFlowRelease", $bFlowDllType, $flow), "cudaDensePyrLKOpticalFlowRelease", @error)
EndFunc   ;==>_cudaDensePyrLKOpticalFlowRelease

Func _cudaSparsePyrLKOpticalFlowCreate($winSize, $maxLevel, $iters, $useInitialFlow, $sparseFlow, $algorithm, $sharedPtr)
    ; CVAPI(cv::cuda::SparsePyrLKOpticalFlow *) cudaSparsePyrLKOpticalFlowCreate(CvSize* winSize, int maxLevel, int iters, bool useInitialFlow, cv::cuda::SparseOpticalFlow** sparseFlow, cv::Algorithm** algorithm, cv::Ptr<cv::cuda::SparsePyrLKOpticalFlow>** sharedPtr);

    Local $bWinSizeDllType
    If VarGetType($winSize) == "DLLStruct" Then
        $bWinSizeDllType = "struct*"
    Else
        $bWinSizeDllType = "ptr"
    EndIf

    Local $bSparseFlowDllType
    If VarGetType($sparseFlow) == "DLLStruct" Then
        $bSparseFlowDllType = "struct*"
    Else
        $bSparseFlowDllType = "ptr*"
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
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cudaSparsePyrLKOpticalFlowCreate", $bWinSizeDllType, $winSize, "int", $maxLevel, "int", $iters, "boolean", $useInitialFlow, $bSparseFlowDllType, $sparseFlow, $bAlgorithmDllType, $algorithm, $bSharedPtrDllType, $sharedPtr), "cudaSparsePyrLKOpticalFlowCreate", @error)
EndFunc   ;==>_cudaSparsePyrLKOpticalFlowCreate

Func _cudaSparsePyrLKOpticalFlowRelease($flow)
    ; CVAPI(void) cudaSparsePyrLKOpticalFlowRelease(cv::Ptr<cv::cuda::SparsePyrLKOpticalFlow>** flow);

    Local $bFlowDllType
    If VarGetType($flow) == "DLLStruct" Then
        $bFlowDllType = "struct*"
    Else
        $bFlowDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaSparsePyrLKOpticalFlowRelease", $bFlowDllType, $flow), "cudaSparsePyrLKOpticalFlowRelease", @error)
EndFunc   ;==>_cudaSparsePyrLKOpticalFlowRelease

Func _cudaFarnebackOpticalFlowCreate($numLevels, $pyrScale, $fastPyramids, $winSize, $numIters, $polyN, $polySigma, $flags, $denseFlow, $algorithm, $sharedPtr)
    ; CVAPI(cv::cuda::FarnebackOpticalFlow*) cudaFarnebackOpticalFlowCreate(int numLevels, double pyrScale, bool fastPyramids, int winSize, int numIters, int polyN, double polySigma, int flags, cv::cuda::DenseOpticalFlow** denseFlow, cv::Algorithm** algorithm, cv::Ptr<cv::cuda::FarnebackOpticalFlow>** sharedPtr);

    Local $bDenseFlowDllType
    If VarGetType($denseFlow) == "DLLStruct" Then
        $bDenseFlowDllType = "struct*"
    Else
        $bDenseFlowDllType = "ptr*"
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
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cudaFarnebackOpticalFlowCreate", "int", $numLevels, "double", $pyrScale, "boolean", $fastPyramids, "int", $winSize, "int", $numIters, "int", $polyN, "double", $polySigma, "int", $flags, $bDenseFlowDllType, $denseFlow, $bAlgorithmDllType, $algorithm, $bSharedPtrDllType, $sharedPtr), "cudaFarnebackOpticalFlowCreate", @error)
EndFunc   ;==>_cudaFarnebackOpticalFlowCreate

Func _cudaFarnebackOpticalFlowRelease($flow)
    ; CVAPI(void) cudaFarnebackOpticalFlowRelease(cv::Ptr<cv::cuda::FarnebackOpticalFlow>** flow);

    Local $bFlowDllType
    If VarGetType($flow) == "DLLStruct" Then
        $bFlowDllType = "struct*"
    Else
        $bFlowDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaFarnebackOpticalFlowRelease", $bFlowDllType, $flow), "cudaFarnebackOpticalFlowRelease", @error)
EndFunc   ;==>_cudaFarnebackOpticalFlowRelease

Func _cudaOpticalFlowDualTvl1Create($tau, $lambda, $theta, $nscales, $warps, $epsilon, $iterations, $scaleStep, $gamma, $useInitialFlow, $denseFlow, $algorithm, $sharedPtr)
    ; CVAPI(cv::cuda::OpticalFlowDual_TVL1*) cudaOpticalFlowDualTvl1Create(double tau, double lambda, double theta, int nscales, int warps, double epsilon, int iterations, double scaleStep, double gamma, bool useInitialFlow, cv::cuda::DenseOpticalFlow** denseFlow, cv::Algorithm** algorithm, cv::Ptr<cv::cuda::OpticalFlowDual_TVL1>** sharedPtr);

    Local $bDenseFlowDllType
    If VarGetType($denseFlow) == "DLLStruct" Then
        $bDenseFlowDllType = "struct*"
    Else
        $bDenseFlowDllType = "ptr*"
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
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cudaOpticalFlowDualTvl1Create", "double", $tau, "double", $lambda, "double", $theta, "int", $nscales, "int", $warps, "double", $epsilon, "int", $iterations, "double", $scaleStep, "double", $gamma, "boolean", $useInitialFlow, $bDenseFlowDllType, $denseFlow, $bAlgorithmDllType, $algorithm, $bSharedPtrDllType, $sharedPtr), "cudaOpticalFlowDualTvl1Create", @error)
EndFunc   ;==>_cudaOpticalFlowDualTvl1Create

Func _cudaOpticalFlowDualTvl1Release($flow)
    ; CVAPI(void) cudaOpticalFlowDualTvl1Release(cv::Ptr<cv::cuda::OpticalFlowDual_TVL1>** flow);

    Local $bFlowDllType
    If VarGetType($flow) == "DLLStruct" Then
        $bFlowDllType = "struct*"
    Else
        $bFlowDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaOpticalFlowDualTvl1Release", $bFlowDllType, $flow), "cudaOpticalFlowDualTvl1Release", @error)
EndFunc   ;==>_cudaOpticalFlowDualTvl1Release

Func _cudaNvidiaOpticalFlow_1_0_Create($imageSize, $perfPreset, $enableTemporalHints, $enableExternalHints, $enableCostBuffer, $gpuId, $inputStream, $outputStream, $nHWOpticalFlow, $algorithm, $sharedPtr)
    ; CVAPI(cv::cuda::NvidiaOpticalFlow_1_0*) cudaNvidiaOpticalFlow_1_0_Create(CvSize* imageSize, int perfPreset, bool enableTemporalHints, bool enableExternalHints, bool enableCostBuffer, int gpuId, cv::cuda::Stream* inputStream, cv::cuda::Stream* outputStream, cv::cuda::NvidiaHWOpticalFlow** nHWOpticalFlow, cv::Algorithm** algorithm, cv::Ptr<cv::cuda::NvidiaOpticalFlow_1_0>** sharedPtr);

    Local $bImageSizeDllType
    If VarGetType($imageSize) == "DLLStruct" Then
        $bImageSizeDllType = "struct*"
    Else
        $bImageSizeDllType = "ptr"
    EndIf

    Local $bInputStreamDllType
    If VarGetType($inputStream) == "DLLStruct" Then
        $bInputStreamDllType = "struct*"
    Else
        $bInputStreamDllType = "ptr"
    EndIf

    Local $bOutputStreamDllType
    If VarGetType($outputStream) == "DLLStruct" Then
        $bOutputStreamDllType = "struct*"
    Else
        $bOutputStreamDllType = "ptr"
    EndIf

    Local $bNHWOpticalFlowDllType
    If VarGetType($nHWOpticalFlow) == "DLLStruct" Then
        $bNHWOpticalFlowDllType = "struct*"
    Else
        $bNHWOpticalFlowDllType = "ptr*"
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
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cudaNvidiaOpticalFlow_1_0_Create", $bImageSizeDllType, $imageSize, "int", $perfPreset, "boolean", $enableTemporalHints, "boolean", $enableExternalHints, "boolean", $enableCostBuffer, "int", $gpuId, $bInputStreamDllType, $inputStream, $bOutputStreamDllType, $outputStream, $bNHWOpticalFlowDllType, $nHWOpticalFlow, $bAlgorithmDllType, $algorithm, $bSharedPtrDllType, $sharedPtr), "cudaNvidiaOpticalFlow_1_0_Create", @error)
EndFunc   ;==>_cudaNvidiaOpticalFlow_1_0_Create

Func _cudaNvidiaOpticalFlow_1_0_UpSampler($nFlow, $flow, $imageSize, $gridSize, $upsampledFlow)
    ; CVAPI(void) cudaNvidiaOpticalFlow_1_0_UpSampler(cv::cuda::NvidiaOpticalFlow_1_0* nFlow, cv::_InputArray* flow, CvSize* imageSize, int gridSize, cv::_InputOutputArray* upsampledFlow);

    Local $bNFlowDllType
    If VarGetType($nFlow) == "DLLStruct" Then
        $bNFlowDllType = "struct*"
    Else
        $bNFlowDllType = "ptr"
    EndIf

    Local $bFlowDllType
    If VarGetType($flow) == "DLLStruct" Then
        $bFlowDllType = "struct*"
    Else
        $bFlowDllType = "ptr"
    EndIf

    Local $bImageSizeDllType
    If VarGetType($imageSize) == "DLLStruct" Then
        $bImageSizeDllType = "struct*"
    Else
        $bImageSizeDllType = "ptr"
    EndIf

    Local $bUpsampledFlowDllType
    If VarGetType($upsampledFlow) == "DLLStruct" Then
        $bUpsampledFlowDllType = "struct*"
    Else
        $bUpsampledFlowDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaNvidiaOpticalFlow_1_0_UpSampler", $bNFlowDllType, $nFlow, $bFlowDllType, $flow, $bImageSizeDllType, $imageSize, "int", $gridSize, $bUpsampledFlowDllType, $upsampledFlow), "cudaNvidiaOpticalFlow_1_0_UpSampler", @error)
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

    Local $bFlowDllType
    If VarGetType($flow) == "DLLStruct" Then
        $bFlowDllType = "struct*"
    Else
        $bFlowDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaNvidiaOpticalFlow_1_0_Release", $bFlowDllType, $flow), "cudaNvidiaOpticalFlow_1_0_Release", @error)
EndFunc   ;==>_cudaNvidiaOpticalFlow_1_0_Release

Func _cudaNvidiaOpticalFlowCalc($nHWOpticalFlow, $inputImage, $referenceImage, $flow, $stream, $hint, $cost)
    ; CVAPI(void) cudaNvidiaOpticalFlowCalc(cv::cuda::NvidiaHWOpticalFlow* nHWOpticalFlow, cv::_InputArray* inputImage, cv::_InputArray* referenceImage, cv::_InputOutputArray* flow, cv::cuda::Stream* stream, cv::_InputArray* hint, cv::_OutputArray* cost);

    Local $bNHWOpticalFlowDllType
    If VarGetType($nHWOpticalFlow) == "DLLStruct" Then
        $bNHWOpticalFlowDllType = "struct*"
    Else
        $bNHWOpticalFlowDllType = "ptr"
    EndIf

    Local $bInputImageDllType
    If VarGetType($inputImage) == "DLLStruct" Then
        $bInputImageDllType = "struct*"
    Else
        $bInputImageDllType = "ptr"
    EndIf

    Local $bReferenceImageDllType
    If VarGetType($referenceImage) == "DLLStruct" Then
        $bReferenceImageDllType = "struct*"
    Else
        $bReferenceImageDllType = "ptr"
    EndIf

    Local $bFlowDllType
    If VarGetType($flow) == "DLLStruct" Then
        $bFlowDllType = "struct*"
    Else
        $bFlowDllType = "ptr"
    EndIf

    Local $bStreamDllType
    If VarGetType($stream) == "DLLStruct" Then
        $bStreamDllType = "struct*"
    Else
        $bStreamDllType = "ptr"
    EndIf

    Local $bHintDllType
    If VarGetType($hint) == "DLLStruct" Then
        $bHintDllType = "struct*"
    Else
        $bHintDllType = "ptr"
    EndIf

    Local $bCostDllType
    If VarGetType($cost) == "DLLStruct" Then
        $bCostDllType = "struct*"
    Else
        $bCostDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaNvidiaOpticalFlowCalc", $bNHWOpticalFlowDllType, $nHWOpticalFlow, $bInputImageDllType, $inputImage, $bReferenceImageDllType, $referenceImage, $bFlowDllType, $flow, $bStreamDllType, $stream, $bHintDllType, $hint, $bCostDllType, $cost), "cudaNvidiaOpticalFlowCalc", @error)
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

    Local $bNHWOpticalFlowDllType
    If VarGetType($nHWOpticalFlow) == "DLLStruct" Then
        $bNHWOpticalFlowDllType = "struct*"
    Else
        $bNHWOpticalFlowDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaNvidiaOpticalFlowCollectGarbage", $bNHWOpticalFlowDllType, $nHWOpticalFlow), "cudaNvidiaOpticalFlowCollectGarbage", @error)
EndFunc   ;==>_cudaNvidiaOpticalFlowCollectGarbage

Func _cudaNvidiaOpticalFlowGetGridSize($nHWOpticalFlow)
    ; CVAPI(int) cudaNvidiaOpticalFlowGetGridSize(cv::cuda::NvidiaHWOpticalFlow* nHWOpticalFlow);

    Local $bNHWOpticalFlowDllType
    If VarGetType($nHWOpticalFlow) == "DLLStruct" Then
        $bNHWOpticalFlowDllType = "struct*"
    Else
        $bNHWOpticalFlowDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cudaNvidiaOpticalFlowGetGridSize", $bNHWOpticalFlowDllType, $nHWOpticalFlow), "cudaNvidiaOpticalFlowGetGridSize", @error)
EndFunc   ;==>_cudaNvidiaOpticalFlowGetGridSize

Func _cudaNvidiaOpticalFlow_2_0_Create($imageSize, $perfPreset, $outputGridSize, $hintGridSize, $enableTemporalHints, $enableExternalHints, $enableCostBuffer, $gpuId, $inputStream, $outputStream, $nHWOpticalFlow, $algorithm, $sharedPtr)
    ; CVAPI(cv::cuda::NvidiaOpticalFlow_2_0*) cudaNvidiaOpticalFlow_2_0_Create(CvSize* imageSize, int perfPreset, int outputGridSize, int hintGridSize, bool enableTemporalHints, bool enableExternalHints, bool enableCostBuffer, int gpuId, cv::cuda::Stream* inputStream, cv::cuda::Stream* outputStream, cv::cuda::NvidiaHWOpticalFlow** nHWOpticalFlow, cv::Algorithm** algorithm, cv::Ptr<cv::cuda::NvidiaOpticalFlow_2_0>** sharedPtr);

    Local $bImageSizeDllType
    If VarGetType($imageSize) == "DLLStruct" Then
        $bImageSizeDllType = "struct*"
    Else
        $bImageSizeDllType = "ptr"
    EndIf

    Local $bInputStreamDllType
    If VarGetType($inputStream) == "DLLStruct" Then
        $bInputStreamDllType = "struct*"
    Else
        $bInputStreamDllType = "ptr"
    EndIf

    Local $bOutputStreamDllType
    If VarGetType($outputStream) == "DLLStruct" Then
        $bOutputStreamDllType = "struct*"
    Else
        $bOutputStreamDllType = "ptr"
    EndIf

    Local $bNHWOpticalFlowDllType
    If VarGetType($nHWOpticalFlow) == "DLLStruct" Then
        $bNHWOpticalFlowDllType = "struct*"
    Else
        $bNHWOpticalFlowDllType = "ptr*"
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
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cudaNvidiaOpticalFlow_2_0_Create", $bImageSizeDllType, $imageSize, "int", $perfPreset, "int", $outputGridSize, "int", $hintGridSize, "boolean", $enableTemporalHints, "boolean", $enableExternalHints, "boolean", $enableCostBuffer, "int", $gpuId, $bInputStreamDllType, $inputStream, $bOutputStreamDllType, $outputStream, $bNHWOpticalFlowDllType, $nHWOpticalFlow, $bAlgorithmDllType, $algorithm, $bSharedPtrDllType, $sharedPtr), "cudaNvidiaOpticalFlow_2_0_Create", @error)
EndFunc   ;==>_cudaNvidiaOpticalFlow_2_0_Create

Func _cudaNvidiaOpticalFlow_2_0_ConvertToFloat($nvof, $flow, $floatFlow)
    ; CVAPI(void) cudaNvidiaOpticalFlow_2_0_ConvertToFloat(cv::cuda::NvidiaOpticalFlow_2_0* nvof, cv::_InputArray* flow, cv::_InputOutputArray* floatFlow);

    Local $bNvofDllType
    If VarGetType($nvof) == "DLLStruct" Then
        $bNvofDllType = "struct*"
    Else
        $bNvofDllType = "ptr"
    EndIf

    Local $bFlowDllType
    If VarGetType($flow) == "DLLStruct" Then
        $bFlowDllType = "struct*"
    Else
        $bFlowDllType = "ptr"
    EndIf

    Local $bFloatFlowDllType
    If VarGetType($floatFlow) == "DLLStruct" Then
        $bFloatFlowDllType = "struct*"
    Else
        $bFloatFlowDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaNvidiaOpticalFlow_2_0_ConvertToFloat", $bNvofDllType, $nvof, $bFlowDllType, $flow, $bFloatFlowDllType, $floatFlow), "cudaNvidiaOpticalFlow_2_0_ConvertToFloat", @error)
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

    Local $bFlowDllType
    If VarGetType($flow) == "DLLStruct" Then
        $bFlowDllType = "struct*"
    Else
        $bFlowDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaNvidiaOpticalFlow_2_0_Release", $bFlowDllType, $flow), "cudaNvidiaOpticalFlow_2_0_Release", @error)
EndFunc   ;==>_cudaNvidiaOpticalFlow_2_0_Release