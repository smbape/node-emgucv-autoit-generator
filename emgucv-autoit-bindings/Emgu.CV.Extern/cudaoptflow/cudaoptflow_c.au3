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

Func _cudaDenseOpticalFlowCalcTyped($opticalFlow, $typeOfI0, $I0, $typeOfI1, $I1, $typeOfFlow, $flow, $stream)

    Local $iArrI0, $vectorI0, $iArrI0Size
    Local $bI0IsArray = IsArray($I0)
    Local $bI0Create = IsDllStruct($I0) And $typeOfI0 == "Scalar"

    If $typeOfI0 == Default Then
        $iArrI0 = $I0
    ElseIf $bI0IsArray Then
        $vectorI0 = Call("_VectorOf" & $typeOfI0 & "Create")

        $iArrI0Size = UBound($I0)
        For $i = 0 To $iArrI0Size - 1
            Call("_VectorOf" & $typeOfI0 & "Push", $vectorI0, $I0[$i])
        Next

        $iArrI0 = Call("_cveInputArrayFromVectorOf" & $typeOfI0, $vectorI0)
    Else
        If $bI0Create Then
            $I0 = Call("_cve" & $typeOfI0 & "Create", $I0)
        EndIf
        $iArrI0 = Call("_cveInputArrayFrom" & $typeOfI0, $I0)
    EndIf

    Local $iArrI1, $vectorI1, $iArrI1Size
    Local $bI1IsArray = IsArray($I1)
    Local $bI1Create = IsDllStruct($I1) And $typeOfI1 == "Scalar"

    If $typeOfI1 == Default Then
        $iArrI1 = $I1
    ElseIf $bI1IsArray Then
        $vectorI1 = Call("_VectorOf" & $typeOfI1 & "Create")

        $iArrI1Size = UBound($I1)
        For $i = 0 To $iArrI1Size - 1
            Call("_VectorOf" & $typeOfI1 & "Push", $vectorI1, $I1[$i])
        Next

        $iArrI1 = Call("_cveInputArrayFromVectorOf" & $typeOfI1, $vectorI1)
    Else
        If $bI1Create Then
            $I1 = Call("_cve" & $typeOfI1 & "Create", $I1)
        EndIf
        $iArrI1 = Call("_cveInputArrayFrom" & $typeOfI1, $I1)
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

    _cudaDenseOpticalFlowCalc($opticalFlow, $iArrI0, $iArrI1, $ioArrFlow, $stream)

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
            Call("_cve" & $typeOfI1 & "Release", $I1)
        EndIf
    EndIf

    If $bI0IsArray Then
        Call("_VectorOf" & $typeOfI0 & "Release", $vectorI0)
    EndIf

    If $typeOfI0 <> Default Then
        _cveInputArrayRelease($iArrI0)
        If $bI0Create Then
            Call("_cve" & $typeOfI0 & "Release", $I0)
        EndIf
    EndIf
EndFunc   ;==>_cudaDenseOpticalFlowCalcTyped

Func _cudaDenseOpticalFlowCalcMat($opticalFlow, $I0, $I1, $flow, $stream)
    ; cudaDenseOpticalFlowCalc using cv::Mat instead of _*Array
    _cudaDenseOpticalFlowCalcTyped($opticalFlow, "Mat", $I0, "Mat", $I1, "Mat", $flow, $stream)
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

Func _cudaSparseOpticalFlowCalcTyped($opticalFlow, $typeOfPrevImg, $prevImg, $typeOfNextImg, $nextImg, $typeOfPrevPts, $prevPts, $typeOfNextPts, $nextPts, $typeOfStatus, $status, $typeOfErr, $err, $stream)

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

    _cudaSparseOpticalFlowCalc($opticalFlow, $iArrPrevImg, $iArrNextImg, $iArrPrevPts, $ioArrNextPts, $oArrStatus, $oArrErr, $stream)

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
EndFunc   ;==>_cudaSparseOpticalFlowCalcTyped

Func _cudaSparseOpticalFlowCalcMat($opticalFlow, $prevImg, $nextImg, $prevPts, $nextPts, $status, $err, $stream)
    ; cudaSparseOpticalFlowCalc using cv::Mat instead of _*Array
    _cudaSparseOpticalFlowCalcTyped($opticalFlow, "Mat", $prevImg, "Mat", $nextImg, "Mat", $prevPts, "Mat", $nextPts, "Mat", $status, "Mat", $err, $stream)
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

Func _cudaNvidiaOpticalFlow_1_0_UpSamplerTyped($nFlow, $typeOfFlow, $flow, $imageSize, $gridSize, $typeOfUpsampledFlow, $upsampledFlow)

    Local $iArrFlow, $vectorFlow, $iArrFlowSize
    Local $bFlowIsArray = IsArray($flow)
    Local $bFlowCreate = IsDllStruct($flow) And $typeOfFlow == "Scalar"

    If $typeOfFlow == Default Then
        $iArrFlow = $flow
    ElseIf $bFlowIsArray Then
        $vectorFlow = Call("_VectorOf" & $typeOfFlow & "Create")

        $iArrFlowSize = UBound($flow)
        For $i = 0 To $iArrFlowSize - 1
            Call("_VectorOf" & $typeOfFlow & "Push", $vectorFlow, $flow[$i])
        Next

        $iArrFlow = Call("_cveInputArrayFromVectorOf" & $typeOfFlow, $vectorFlow)
    Else
        If $bFlowCreate Then
            $flow = Call("_cve" & $typeOfFlow & "Create", $flow)
        EndIf
        $iArrFlow = Call("_cveInputArrayFrom" & $typeOfFlow, $flow)
    EndIf

    Local $ioArrUpsampledFlow, $vectorUpsampledFlow, $iArrUpsampledFlowSize
    Local $bUpsampledFlowIsArray = IsArray($upsampledFlow)
    Local $bUpsampledFlowCreate = IsDllStruct($upsampledFlow) And $typeOfUpsampledFlow == "Scalar"

    If $typeOfUpsampledFlow == Default Then
        $ioArrUpsampledFlow = $upsampledFlow
    ElseIf $bUpsampledFlowIsArray Then
        $vectorUpsampledFlow = Call("_VectorOf" & $typeOfUpsampledFlow & "Create")

        $iArrUpsampledFlowSize = UBound($upsampledFlow)
        For $i = 0 To $iArrUpsampledFlowSize - 1
            Call("_VectorOf" & $typeOfUpsampledFlow & "Push", $vectorUpsampledFlow, $upsampledFlow[$i])
        Next

        $ioArrUpsampledFlow = Call("_cveInputOutputArrayFromVectorOf" & $typeOfUpsampledFlow, $vectorUpsampledFlow)
    Else
        If $bUpsampledFlowCreate Then
            $upsampledFlow = Call("_cve" & $typeOfUpsampledFlow & "Create", $upsampledFlow)
        EndIf
        $ioArrUpsampledFlow = Call("_cveInputOutputArrayFrom" & $typeOfUpsampledFlow, $upsampledFlow)
    EndIf

    _cudaNvidiaOpticalFlow_1_0_UpSampler($nFlow, $iArrFlow, $imageSize, $gridSize, $ioArrUpsampledFlow)

    If $bUpsampledFlowIsArray Then
        Call("_VectorOf" & $typeOfUpsampledFlow & "Release", $vectorUpsampledFlow)
    EndIf

    If $typeOfUpsampledFlow <> Default Then
        _cveInputOutputArrayRelease($ioArrUpsampledFlow)
        If $bUpsampledFlowCreate Then
            Call("_cve" & $typeOfUpsampledFlow & "Release", $upsampledFlow)
        EndIf
    EndIf

    If $bFlowIsArray Then
        Call("_VectorOf" & $typeOfFlow & "Release", $vectorFlow)
    EndIf

    If $typeOfFlow <> Default Then
        _cveInputArrayRelease($iArrFlow)
        If $bFlowCreate Then
            Call("_cve" & $typeOfFlow & "Release", $flow)
        EndIf
    EndIf
EndFunc   ;==>_cudaNvidiaOpticalFlow_1_0_UpSamplerTyped

Func _cudaNvidiaOpticalFlow_1_0_UpSamplerMat($nFlow, $flow, $imageSize, $gridSize, $upsampledFlow)
    ; cudaNvidiaOpticalFlow_1_0_UpSampler using cv::Mat instead of _*Array
    _cudaNvidiaOpticalFlow_1_0_UpSamplerTyped($nFlow, "Mat", $flow, $imageSize, $gridSize, "Mat", $upsampledFlow)
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

Func _cudaNvidiaOpticalFlowCalcTyped($nHWOpticalFlow, $typeOfInputImage, $inputImage, $typeOfReferenceImage, $referenceImage, $typeOfFlow, $flow, $stream, $typeOfHint, $hint, $typeOfCost, $cost)

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

    Local $iArrReferenceImage, $vectorReferenceImage, $iArrReferenceImageSize
    Local $bReferenceImageIsArray = IsArray($referenceImage)
    Local $bReferenceImageCreate = IsDllStruct($referenceImage) And $typeOfReferenceImage == "Scalar"

    If $typeOfReferenceImage == Default Then
        $iArrReferenceImage = $referenceImage
    ElseIf $bReferenceImageIsArray Then
        $vectorReferenceImage = Call("_VectorOf" & $typeOfReferenceImage & "Create")

        $iArrReferenceImageSize = UBound($referenceImage)
        For $i = 0 To $iArrReferenceImageSize - 1
            Call("_VectorOf" & $typeOfReferenceImage & "Push", $vectorReferenceImage, $referenceImage[$i])
        Next

        $iArrReferenceImage = Call("_cveInputArrayFromVectorOf" & $typeOfReferenceImage, $vectorReferenceImage)
    Else
        If $bReferenceImageCreate Then
            $referenceImage = Call("_cve" & $typeOfReferenceImage & "Create", $referenceImage)
        EndIf
        $iArrReferenceImage = Call("_cveInputArrayFrom" & $typeOfReferenceImage, $referenceImage)
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

    Local $iArrHint, $vectorHint, $iArrHintSize
    Local $bHintIsArray = IsArray($hint)
    Local $bHintCreate = IsDllStruct($hint) And $typeOfHint == "Scalar"

    If $typeOfHint == Default Then
        $iArrHint = $hint
    ElseIf $bHintIsArray Then
        $vectorHint = Call("_VectorOf" & $typeOfHint & "Create")

        $iArrHintSize = UBound($hint)
        For $i = 0 To $iArrHintSize - 1
            Call("_VectorOf" & $typeOfHint & "Push", $vectorHint, $hint[$i])
        Next

        $iArrHint = Call("_cveInputArrayFromVectorOf" & $typeOfHint, $vectorHint)
    Else
        If $bHintCreate Then
            $hint = Call("_cve" & $typeOfHint & "Create", $hint)
        EndIf
        $iArrHint = Call("_cveInputArrayFrom" & $typeOfHint, $hint)
    EndIf

    Local $oArrCost, $vectorCost, $iArrCostSize
    Local $bCostIsArray = IsArray($cost)
    Local $bCostCreate = IsDllStruct($cost) And $typeOfCost == "Scalar"

    If $typeOfCost == Default Then
        $oArrCost = $cost
    ElseIf $bCostIsArray Then
        $vectorCost = Call("_VectorOf" & $typeOfCost & "Create")

        $iArrCostSize = UBound($cost)
        For $i = 0 To $iArrCostSize - 1
            Call("_VectorOf" & $typeOfCost & "Push", $vectorCost, $cost[$i])
        Next

        $oArrCost = Call("_cveOutputArrayFromVectorOf" & $typeOfCost, $vectorCost)
    Else
        If $bCostCreate Then
            $cost = Call("_cve" & $typeOfCost & "Create", $cost)
        EndIf
        $oArrCost = Call("_cveOutputArrayFrom" & $typeOfCost, $cost)
    EndIf

    _cudaNvidiaOpticalFlowCalc($nHWOpticalFlow, $iArrInputImage, $iArrReferenceImage, $ioArrFlow, $stream, $iArrHint, $oArrCost)

    If $bCostIsArray Then
        Call("_VectorOf" & $typeOfCost & "Release", $vectorCost)
    EndIf

    If $typeOfCost <> Default Then
        _cveOutputArrayRelease($oArrCost)
        If $bCostCreate Then
            Call("_cve" & $typeOfCost & "Release", $cost)
        EndIf
    EndIf

    If $bHintIsArray Then
        Call("_VectorOf" & $typeOfHint & "Release", $vectorHint)
    EndIf

    If $typeOfHint <> Default Then
        _cveInputArrayRelease($iArrHint)
        If $bHintCreate Then
            Call("_cve" & $typeOfHint & "Release", $hint)
        EndIf
    EndIf

    If $bFlowIsArray Then
        Call("_VectorOf" & $typeOfFlow & "Release", $vectorFlow)
    EndIf

    If $typeOfFlow <> Default Then
        _cveInputOutputArrayRelease($ioArrFlow)
        If $bFlowCreate Then
            Call("_cve" & $typeOfFlow & "Release", $flow)
        EndIf
    EndIf

    If $bReferenceImageIsArray Then
        Call("_VectorOf" & $typeOfReferenceImage & "Release", $vectorReferenceImage)
    EndIf

    If $typeOfReferenceImage <> Default Then
        _cveInputArrayRelease($iArrReferenceImage)
        If $bReferenceImageCreate Then
            Call("_cve" & $typeOfReferenceImage & "Release", $referenceImage)
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
EndFunc   ;==>_cudaNvidiaOpticalFlowCalcTyped

Func _cudaNvidiaOpticalFlowCalcMat($nHWOpticalFlow, $inputImage, $referenceImage, $flow, $stream, $hint, $cost)
    ; cudaNvidiaOpticalFlowCalc using cv::Mat instead of _*Array
    _cudaNvidiaOpticalFlowCalcTyped($nHWOpticalFlow, "Mat", $inputImage, "Mat", $referenceImage, "Mat", $flow, $stream, "Mat", $hint, "Mat", $cost)
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

Func _cudaNvidiaOpticalFlow_2_0_ConvertToFloatTyped($nvof, $typeOfFlow, $flow, $typeOfFloatFlow, $floatFlow)

    Local $iArrFlow, $vectorFlow, $iArrFlowSize
    Local $bFlowIsArray = IsArray($flow)
    Local $bFlowCreate = IsDllStruct($flow) And $typeOfFlow == "Scalar"

    If $typeOfFlow == Default Then
        $iArrFlow = $flow
    ElseIf $bFlowIsArray Then
        $vectorFlow = Call("_VectorOf" & $typeOfFlow & "Create")

        $iArrFlowSize = UBound($flow)
        For $i = 0 To $iArrFlowSize - 1
            Call("_VectorOf" & $typeOfFlow & "Push", $vectorFlow, $flow[$i])
        Next

        $iArrFlow = Call("_cveInputArrayFromVectorOf" & $typeOfFlow, $vectorFlow)
    Else
        If $bFlowCreate Then
            $flow = Call("_cve" & $typeOfFlow & "Create", $flow)
        EndIf
        $iArrFlow = Call("_cveInputArrayFrom" & $typeOfFlow, $flow)
    EndIf

    Local $ioArrFloatFlow, $vectorFloatFlow, $iArrFloatFlowSize
    Local $bFloatFlowIsArray = IsArray($floatFlow)
    Local $bFloatFlowCreate = IsDllStruct($floatFlow) And $typeOfFloatFlow == "Scalar"

    If $typeOfFloatFlow == Default Then
        $ioArrFloatFlow = $floatFlow
    ElseIf $bFloatFlowIsArray Then
        $vectorFloatFlow = Call("_VectorOf" & $typeOfFloatFlow & "Create")

        $iArrFloatFlowSize = UBound($floatFlow)
        For $i = 0 To $iArrFloatFlowSize - 1
            Call("_VectorOf" & $typeOfFloatFlow & "Push", $vectorFloatFlow, $floatFlow[$i])
        Next

        $ioArrFloatFlow = Call("_cveInputOutputArrayFromVectorOf" & $typeOfFloatFlow, $vectorFloatFlow)
    Else
        If $bFloatFlowCreate Then
            $floatFlow = Call("_cve" & $typeOfFloatFlow & "Create", $floatFlow)
        EndIf
        $ioArrFloatFlow = Call("_cveInputOutputArrayFrom" & $typeOfFloatFlow, $floatFlow)
    EndIf

    _cudaNvidiaOpticalFlow_2_0_ConvertToFloat($nvof, $iArrFlow, $ioArrFloatFlow)

    If $bFloatFlowIsArray Then
        Call("_VectorOf" & $typeOfFloatFlow & "Release", $vectorFloatFlow)
    EndIf

    If $typeOfFloatFlow <> Default Then
        _cveInputOutputArrayRelease($ioArrFloatFlow)
        If $bFloatFlowCreate Then
            Call("_cve" & $typeOfFloatFlow & "Release", $floatFlow)
        EndIf
    EndIf

    If $bFlowIsArray Then
        Call("_VectorOf" & $typeOfFlow & "Release", $vectorFlow)
    EndIf

    If $typeOfFlow <> Default Then
        _cveInputArrayRelease($iArrFlow)
        If $bFlowCreate Then
            Call("_cve" & $typeOfFlow & "Release", $flow)
        EndIf
    EndIf
EndFunc   ;==>_cudaNvidiaOpticalFlow_2_0_ConvertToFloatTyped

Func _cudaNvidiaOpticalFlow_2_0_ConvertToFloatMat($nvof, $flow, $floatFlow)
    ; cudaNvidiaOpticalFlow_2_0_ConvertToFloat using cv::Mat instead of _*Array
    _cudaNvidiaOpticalFlow_2_0_ConvertToFloatTyped($nvof, "Mat", $flow, "Mat", $floatFlow)
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