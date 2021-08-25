#include-once
#include "..\..\CVEUtils.au3"

Func _cudaStereoBMCreate($numDisparities, $blockSize, $sharedPtr)
    ; CVAPI(cv::cuda::StereoBM*) cudaStereoBMCreate(int numDisparities, int blockSize, cv::Ptr<cv::cuda::StereoBM>** sharedPtr);

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cudaStereoBMCreate", "int", $numDisparities, "int", $blockSize, $sSharedPtrDllType, $sharedPtr), "cudaStereoBMCreate", @error)
EndFunc   ;==>_cudaStereoBMCreate

Func _cudaStereoBMFindStereoCorrespondence($stereo, $left, $right, $disparity, $stream)
    ; CVAPI(void) cudaStereoBMFindStereoCorrespondence(cv::cuda::StereoBM* stereo, cv::_InputArray* left, cv::_InputArray* right, cv::_OutputArray* disparity, cv::cuda::Stream* stream);

    Local $sStereoDllType
    If IsDllStruct($stereo) Then
        $sStereoDllType = "struct*"
    Else
        $sStereoDllType = "ptr"
    EndIf

    Local $sLeftDllType
    If IsDllStruct($left) Then
        $sLeftDllType = "struct*"
    Else
        $sLeftDllType = "ptr"
    EndIf

    Local $sRightDllType
    If IsDllStruct($right) Then
        $sRightDllType = "struct*"
    Else
        $sRightDllType = "ptr"
    EndIf

    Local $sDisparityDllType
    If IsDllStruct($disparity) Then
        $sDisparityDllType = "struct*"
    Else
        $sDisparityDllType = "ptr"
    EndIf

    Local $sStreamDllType
    If IsDllStruct($stream) Then
        $sStreamDllType = "struct*"
    Else
        $sStreamDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaStereoBMFindStereoCorrespondence", $sStereoDllType, $stereo, $sLeftDllType, $left, $sRightDllType, $right, $sDisparityDllType, $disparity, $sStreamDllType, $stream), "cudaStereoBMFindStereoCorrespondence", @error)
EndFunc   ;==>_cudaStereoBMFindStereoCorrespondence

Func _cudaStereoBMFindStereoCorrespondenceTyped($stereo, $typeOfLeft, $left, $typeOfRight, $right, $typeOfDisparity, $disparity, $stream)

    Local $iArrLeft, $vectorLeft, $iArrLeftSize
    Local $bLeftIsArray = IsArray($left)
    Local $bLeftCreate = IsDllStruct($left) And $typeOfLeft == "Scalar"

    If $typeOfLeft == Default Then
        $iArrLeft = $left
    ElseIf $bLeftIsArray Then
        $vectorLeft = Call("_VectorOf" & $typeOfLeft & "Create")

        $iArrLeftSize = UBound($left)
        For $i = 0 To $iArrLeftSize - 1
            Call("_VectorOf" & $typeOfLeft & "Push", $vectorLeft, $left[$i])
        Next

        $iArrLeft = Call("_cveInputArrayFromVectorOf" & $typeOfLeft, $vectorLeft)
    Else
        If $bLeftCreate Then
            $left = Call("_cve" & $typeOfLeft & "Create", $left)
        EndIf
        $iArrLeft = Call("_cveInputArrayFrom" & $typeOfLeft, $left)
    EndIf

    Local $iArrRight, $vectorRight, $iArrRightSize
    Local $bRightIsArray = IsArray($right)
    Local $bRightCreate = IsDllStruct($right) And $typeOfRight == "Scalar"

    If $typeOfRight == Default Then
        $iArrRight = $right
    ElseIf $bRightIsArray Then
        $vectorRight = Call("_VectorOf" & $typeOfRight & "Create")

        $iArrRightSize = UBound($right)
        For $i = 0 To $iArrRightSize - 1
            Call("_VectorOf" & $typeOfRight & "Push", $vectorRight, $right[$i])
        Next

        $iArrRight = Call("_cveInputArrayFromVectorOf" & $typeOfRight, $vectorRight)
    Else
        If $bRightCreate Then
            $right = Call("_cve" & $typeOfRight & "Create", $right)
        EndIf
        $iArrRight = Call("_cveInputArrayFrom" & $typeOfRight, $right)
    EndIf

    Local $oArrDisparity, $vectorDisparity, $iArrDisparitySize
    Local $bDisparityIsArray = IsArray($disparity)
    Local $bDisparityCreate = IsDllStruct($disparity) And $typeOfDisparity == "Scalar"

    If $typeOfDisparity == Default Then
        $oArrDisparity = $disparity
    ElseIf $bDisparityIsArray Then
        $vectorDisparity = Call("_VectorOf" & $typeOfDisparity & "Create")

        $iArrDisparitySize = UBound($disparity)
        For $i = 0 To $iArrDisparitySize - 1
            Call("_VectorOf" & $typeOfDisparity & "Push", $vectorDisparity, $disparity[$i])
        Next

        $oArrDisparity = Call("_cveOutputArrayFromVectorOf" & $typeOfDisparity, $vectorDisparity)
    Else
        If $bDisparityCreate Then
            $disparity = Call("_cve" & $typeOfDisparity & "Create", $disparity)
        EndIf
        $oArrDisparity = Call("_cveOutputArrayFrom" & $typeOfDisparity, $disparity)
    EndIf

    _cudaStereoBMFindStereoCorrespondence($stereo, $iArrLeft, $iArrRight, $oArrDisparity, $stream)

    If $bDisparityIsArray Then
        Call("_VectorOf" & $typeOfDisparity & "Release", $vectorDisparity)
    EndIf

    If $typeOfDisparity <> Default Then
        _cveOutputArrayRelease($oArrDisparity)
        If $bDisparityCreate Then
            Call("_cve" & $typeOfDisparity & "Release", $disparity)
        EndIf
    EndIf

    If $bRightIsArray Then
        Call("_VectorOf" & $typeOfRight & "Release", $vectorRight)
    EndIf

    If $typeOfRight <> Default Then
        _cveInputArrayRelease($iArrRight)
        If $bRightCreate Then
            Call("_cve" & $typeOfRight & "Release", $right)
        EndIf
    EndIf

    If $bLeftIsArray Then
        Call("_VectorOf" & $typeOfLeft & "Release", $vectorLeft)
    EndIf

    If $typeOfLeft <> Default Then
        _cveInputArrayRelease($iArrLeft)
        If $bLeftCreate Then
            Call("_cve" & $typeOfLeft & "Release", $left)
        EndIf
    EndIf
EndFunc   ;==>_cudaStereoBMFindStereoCorrespondenceTyped

Func _cudaStereoBMFindStereoCorrespondenceMat($stereo, $left, $right, $disparity, $stream)
    ; cudaStereoBMFindStereoCorrespondence using cv::Mat instead of _*Array
    _cudaStereoBMFindStereoCorrespondenceTyped($stereo, "Mat", $left, "Mat", $right, "Mat", $disparity, $stream)
EndFunc   ;==>_cudaStereoBMFindStereoCorrespondenceMat

Func _cudaStereoBMRelease($stereoBM)
    ; CVAPI(void) cudaStereoBMRelease(cv::Ptr<cv::cuda::StereoBM>** stereoBM);

    Local $sStereoBMDllType
    If IsDllStruct($stereoBM) Then
        $sStereoBMDllType = "struct*"
    ElseIf $stereoBM == Null Then
        $sStereoBMDllType = "ptr"
    Else
        $sStereoBMDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaStereoBMRelease", $sStereoBMDllType, $stereoBM), "cudaStereoBMRelease", @error)
EndFunc   ;==>_cudaStereoBMRelease

Func _cudaStereoConstantSpaceBPCreate($ndisp, $iters, $levels, $nr_plane, $sharedPtr)
    ; CVAPI(cv::cuda::StereoConstantSpaceBP*) cudaStereoConstantSpaceBPCreate(int ndisp, int iters, int levels, int nr_plane, cv::Ptr<cv::cuda::StereoConstantSpaceBP>** sharedPtr);

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cudaStereoConstantSpaceBPCreate", "int", $ndisp, "int", $iters, "int", $levels, "int", $nr_plane, $sSharedPtrDllType, $sharedPtr), "cudaStereoConstantSpaceBPCreate", @error)
EndFunc   ;==>_cudaStereoConstantSpaceBPCreate

Func _cudaStereoConstantSpaceBPFindStereoCorrespondence($stereo, $left, $right, $disparity, $stream)
    ; CVAPI(void) cudaStereoConstantSpaceBPFindStereoCorrespondence(cv::cuda::StereoConstantSpaceBP* stereo, cv::_InputArray* left, cv::_InputArray* right, cv::_OutputArray* disparity, cv::cuda::Stream* stream);

    Local $sStereoDllType
    If IsDllStruct($stereo) Then
        $sStereoDllType = "struct*"
    Else
        $sStereoDllType = "ptr"
    EndIf

    Local $sLeftDllType
    If IsDllStruct($left) Then
        $sLeftDllType = "struct*"
    Else
        $sLeftDllType = "ptr"
    EndIf

    Local $sRightDllType
    If IsDllStruct($right) Then
        $sRightDllType = "struct*"
    Else
        $sRightDllType = "ptr"
    EndIf

    Local $sDisparityDllType
    If IsDllStruct($disparity) Then
        $sDisparityDllType = "struct*"
    Else
        $sDisparityDllType = "ptr"
    EndIf

    Local $sStreamDllType
    If IsDllStruct($stream) Then
        $sStreamDllType = "struct*"
    Else
        $sStreamDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaStereoConstantSpaceBPFindStereoCorrespondence", $sStereoDllType, $stereo, $sLeftDllType, $left, $sRightDllType, $right, $sDisparityDllType, $disparity, $sStreamDllType, $stream), "cudaStereoConstantSpaceBPFindStereoCorrespondence", @error)
EndFunc   ;==>_cudaStereoConstantSpaceBPFindStereoCorrespondence

Func _cudaStereoConstantSpaceBPFindStereoCorrespondenceTyped($stereo, $typeOfLeft, $left, $typeOfRight, $right, $typeOfDisparity, $disparity, $stream)

    Local $iArrLeft, $vectorLeft, $iArrLeftSize
    Local $bLeftIsArray = IsArray($left)
    Local $bLeftCreate = IsDllStruct($left) And $typeOfLeft == "Scalar"

    If $typeOfLeft == Default Then
        $iArrLeft = $left
    ElseIf $bLeftIsArray Then
        $vectorLeft = Call("_VectorOf" & $typeOfLeft & "Create")

        $iArrLeftSize = UBound($left)
        For $i = 0 To $iArrLeftSize - 1
            Call("_VectorOf" & $typeOfLeft & "Push", $vectorLeft, $left[$i])
        Next

        $iArrLeft = Call("_cveInputArrayFromVectorOf" & $typeOfLeft, $vectorLeft)
    Else
        If $bLeftCreate Then
            $left = Call("_cve" & $typeOfLeft & "Create", $left)
        EndIf
        $iArrLeft = Call("_cveInputArrayFrom" & $typeOfLeft, $left)
    EndIf

    Local $iArrRight, $vectorRight, $iArrRightSize
    Local $bRightIsArray = IsArray($right)
    Local $bRightCreate = IsDllStruct($right) And $typeOfRight == "Scalar"

    If $typeOfRight == Default Then
        $iArrRight = $right
    ElseIf $bRightIsArray Then
        $vectorRight = Call("_VectorOf" & $typeOfRight & "Create")

        $iArrRightSize = UBound($right)
        For $i = 0 To $iArrRightSize - 1
            Call("_VectorOf" & $typeOfRight & "Push", $vectorRight, $right[$i])
        Next

        $iArrRight = Call("_cveInputArrayFromVectorOf" & $typeOfRight, $vectorRight)
    Else
        If $bRightCreate Then
            $right = Call("_cve" & $typeOfRight & "Create", $right)
        EndIf
        $iArrRight = Call("_cveInputArrayFrom" & $typeOfRight, $right)
    EndIf

    Local $oArrDisparity, $vectorDisparity, $iArrDisparitySize
    Local $bDisparityIsArray = IsArray($disparity)
    Local $bDisparityCreate = IsDllStruct($disparity) And $typeOfDisparity == "Scalar"

    If $typeOfDisparity == Default Then
        $oArrDisparity = $disparity
    ElseIf $bDisparityIsArray Then
        $vectorDisparity = Call("_VectorOf" & $typeOfDisparity & "Create")

        $iArrDisparitySize = UBound($disparity)
        For $i = 0 To $iArrDisparitySize - 1
            Call("_VectorOf" & $typeOfDisparity & "Push", $vectorDisparity, $disparity[$i])
        Next

        $oArrDisparity = Call("_cveOutputArrayFromVectorOf" & $typeOfDisparity, $vectorDisparity)
    Else
        If $bDisparityCreate Then
            $disparity = Call("_cve" & $typeOfDisparity & "Create", $disparity)
        EndIf
        $oArrDisparity = Call("_cveOutputArrayFrom" & $typeOfDisparity, $disparity)
    EndIf

    _cudaStereoConstantSpaceBPFindStereoCorrespondence($stereo, $iArrLeft, $iArrRight, $oArrDisparity, $stream)

    If $bDisparityIsArray Then
        Call("_VectorOf" & $typeOfDisparity & "Release", $vectorDisparity)
    EndIf

    If $typeOfDisparity <> Default Then
        _cveOutputArrayRelease($oArrDisparity)
        If $bDisparityCreate Then
            Call("_cve" & $typeOfDisparity & "Release", $disparity)
        EndIf
    EndIf

    If $bRightIsArray Then
        Call("_VectorOf" & $typeOfRight & "Release", $vectorRight)
    EndIf

    If $typeOfRight <> Default Then
        _cveInputArrayRelease($iArrRight)
        If $bRightCreate Then
            Call("_cve" & $typeOfRight & "Release", $right)
        EndIf
    EndIf

    If $bLeftIsArray Then
        Call("_VectorOf" & $typeOfLeft & "Release", $vectorLeft)
    EndIf

    If $typeOfLeft <> Default Then
        _cveInputArrayRelease($iArrLeft)
        If $bLeftCreate Then
            Call("_cve" & $typeOfLeft & "Release", $left)
        EndIf
    EndIf
EndFunc   ;==>_cudaStereoConstantSpaceBPFindStereoCorrespondenceTyped

Func _cudaStereoConstantSpaceBPFindStereoCorrespondenceMat($stereo, $left, $right, $disparity, $stream)
    ; cudaStereoConstantSpaceBPFindStereoCorrespondence using cv::Mat instead of _*Array
    _cudaStereoConstantSpaceBPFindStereoCorrespondenceTyped($stereo, "Mat", $left, "Mat", $right, "Mat", $disparity, $stream)
EndFunc   ;==>_cudaStereoConstantSpaceBPFindStereoCorrespondenceMat

Func _cudaStereoConstantSpaceBPRelease($stereo)
    ; CVAPI(void) cudaStereoConstantSpaceBPRelease(cv::Ptr<cv::cuda::StereoConstantSpaceBP>** stereo);

    Local $sStereoDllType
    If IsDllStruct($stereo) Then
        $sStereoDllType = "struct*"
    ElseIf $stereo == Null Then
        $sStereoDllType = "ptr"
    Else
        $sStereoDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaStereoConstantSpaceBPRelease", $sStereoDllType, $stereo), "cudaStereoConstantSpaceBPRelease", @error)
EndFunc   ;==>_cudaStereoConstantSpaceBPRelease

Func _cudaDisparityBilateralFilterCreate($ndisp, $radius, $iters, $sharedPtr)
    ; CVAPI(cv::cuda::DisparityBilateralFilter*) cudaDisparityBilateralFilterCreate(int ndisp, int radius, int iters, cv::Ptr<cv::cuda::DisparityBilateralFilter>** sharedPtr);

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cudaDisparityBilateralFilterCreate", "int", $ndisp, "int", $radius, "int", $iters, $sSharedPtrDllType, $sharedPtr), "cudaDisparityBilateralFilterCreate", @error)
EndFunc   ;==>_cudaDisparityBilateralFilterCreate

Func _cudaDisparityBilateralFilterApply($filter, $disparity, $image, $dst, $stream)
    ; CVAPI(void) cudaDisparityBilateralFilterApply(cv::cuda::DisparityBilateralFilter* filter, cv::_InputArray* disparity, cv::_InputArray* image, cv::_OutputArray* dst, cv::cuda::Stream* stream);

    Local $sFilterDllType
    If IsDllStruct($filter) Then
        $sFilterDllType = "struct*"
    Else
        $sFilterDllType = "ptr"
    EndIf

    Local $sDisparityDllType
    If IsDllStruct($disparity) Then
        $sDisparityDllType = "struct*"
    Else
        $sDisparityDllType = "ptr"
    EndIf

    Local $sImageDllType
    If IsDllStruct($image) Then
        $sImageDllType = "struct*"
    Else
        $sImageDllType = "ptr"
    EndIf

    Local $sDstDllType
    If IsDllStruct($dst) Then
        $sDstDllType = "struct*"
    Else
        $sDstDllType = "ptr"
    EndIf

    Local $sStreamDllType
    If IsDllStruct($stream) Then
        $sStreamDllType = "struct*"
    Else
        $sStreamDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaDisparityBilateralFilterApply", $sFilterDllType, $filter, $sDisparityDllType, $disparity, $sImageDllType, $image, $sDstDllType, $dst, $sStreamDllType, $stream), "cudaDisparityBilateralFilterApply", @error)
EndFunc   ;==>_cudaDisparityBilateralFilterApply

Func _cudaDisparityBilateralFilterApplyTyped($filter, $typeOfDisparity, $disparity, $typeOfImage, $image, $typeOfDst, $dst, $stream)

    Local $iArrDisparity, $vectorDisparity, $iArrDisparitySize
    Local $bDisparityIsArray = IsArray($disparity)
    Local $bDisparityCreate = IsDllStruct($disparity) And $typeOfDisparity == "Scalar"

    If $typeOfDisparity == Default Then
        $iArrDisparity = $disparity
    ElseIf $bDisparityIsArray Then
        $vectorDisparity = Call("_VectorOf" & $typeOfDisparity & "Create")

        $iArrDisparitySize = UBound($disparity)
        For $i = 0 To $iArrDisparitySize - 1
            Call("_VectorOf" & $typeOfDisparity & "Push", $vectorDisparity, $disparity[$i])
        Next

        $iArrDisparity = Call("_cveInputArrayFromVectorOf" & $typeOfDisparity, $vectorDisparity)
    Else
        If $bDisparityCreate Then
            $disparity = Call("_cve" & $typeOfDisparity & "Create", $disparity)
        EndIf
        $iArrDisparity = Call("_cveInputArrayFrom" & $typeOfDisparity, $disparity)
    EndIf

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

    Local $oArrDst, $vectorDst, $iArrDstSize
    Local $bDstIsArray = IsArray($dst)
    Local $bDstCreate = IsDllStruct($dst) And $typeOfDst == "Scalar"

    If $typeOfDst == Default Then
        $oArrDst = $dst
    ElseIf $bDstIsArray Then
        $vectorDst = Call("_VectorOf" & $typeOfDst & "Create")

        $iArrDstSize = UBound($dst)
        For $i = 0 To $iArrDstSize - 1
            Call("_VectorOf" & $typeOfDst & "Push", $vectorDst, $dst[$i])
        Next

        $oArrDst = Call("_cveOutputArrayFromVectorOf" & $typeOfDst, $vectorDst)
    Else
        If $bDstCreate Then
            $dst = Call("_cve" & $typeOfDst & "Create", $dst)
        EndIf
        $oArrDst = Call("_cveOutputArrayFrom" & $typeOfDst, $dst)
    EndIf

    _cudaDisparityBilateralFilterApply($filter, $iArrDisparity, $iArrImage, $oArrDst, $stream)

    If $bDstIsArray Then
        Call("_VectorOf" & $typeOfDst & "Release", $vectorDst)
    EndIf

    If $typeOfDst <> Default Then
        _cveOutputArrayRelease($oArrDst)
        If $bDstCreate Then
            Call("_cve" & $typeOfDst & "Release", $dst)
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

    If $bDisparityIsArray Then
        Call("_VectorOf" & $typeOfDisparity & "Release", $vectorDisparity)
    EndIf

    If $typeOfDisparity <> Default Then
        _cveInputArrayRelease($iArrDisparity)
        If $bDisparityCreate Then
            Call("_cve" & $typeOfDisparity & "Release", $disparity)
        EndIf
    EndIf
EndFunc   ;==>_cudaDisparityBilateralFilterApplyTyped

Func _cudaDisparityBilateralFilterApplyMat($filter, $disparity, $image, $dst, $stream)
    ; cudaDisparityBilateralFilterApply using cv::Mat instead of _*Array
    _cudaDisparityBilateralFilterApplyTyped($filter, "Mat", $disparity, "Mat", $image, "Mat", $dst, $stream)
EndFunc   ;==>_cudaDisparityBilateralFilterApplyMat

Func _cudaDisparityBilateralFilterRelease($filter)
    ; CVAPI(void) cudaDisparityBilateralFilterRelease(cv::Ptr<cv::cuda::DisparityBilateralFilter>** filter);

    Local $sFilterDllType
    If IsDllStruct($filter) Then
        $sFilterDllType = "struct*"
    ElseIf $filter == Null Then
        $sFilterDllType = "ptr"
    Else
        $sFilterDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaDisparityBilateralFilterRelease", $sFilterDllType, $filter), "cudaDisparityBilateralFilterRelease", @error)
EndFunc   ;==>_cudaDisparityBilateralFilterRelease

Func _cudaDrawColorDisp($srcDisp, $dstDisp, $ndisp, $stream)
    ; CVAPI(void) cudaDrawColorDisp(cv::_InputArray* srcDisp, cv::_OutputArray* dstDisp, int ndisp, cv::cuda::Stream* stream);

    Local $sSrcDispDllType
    If IsDllStruct($srcDisp) Then
        $sSrcDispDllType = "struct*"
    Else
        $sSrcDispDllType = "ptr"
    EndIf

    Local $sDstDispDllType
    If IsDllStruct($dstDisp) Then
        $sDstDispDllType = "struct*"
    Else
        $sDstDispDllType = "ptr"
    EndIf

    Local $sStreamDllType
    If IsDllStruct($stream) Then
        $sStreamDllType = "struct*"
    Else
        $sStreamDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaDrawColorDisp", $sSrcDispDllType, $srcDisp, $sDstDispDllType, $dstDisp, "int", $ndisp, $sStreamDllType, $stream), "cudaDrawColorDisp", @error)
EndFunc   ;==>_cudaDrawColorDisp

Func _cudaDrawColorDispTyped($typeOfSrcDisp, $srcDisp, $typeOfDstDisp, $dstDisp, $ndisp, $stream)

    Local $iArrSrcDisp, $vectorSrcDisp, $iArrSrcDispSize
    Local $bSrcDispIsArray = IsArray($srcDisp)
    Local $bSrcDispCreate = IsDllStruct($srcDisp) And $typeOfSrcDisp == "Scalar"

    If $typeOfSrcDisp == Default Then
        $iArrSrcDisp = $srcDisp
    ElseIf $bSrcDispIsArray Then
        $vectorSrcDisp = Call("_VectorOf" & $typeOfSrcDisp & "Create")

        $iArrSrcDispSize = UBound($srcDisp)
        For $i = 0 To $iArrSrcDispSize - 1
            Call("_VectorOf" & $typeOfSrcDisp & "Push", $vectorSrcDisp, $srcDisp[$i])
        Next

        $iArrSrcDisp = Call("_cveInputArrayFromVectorOf" & $typeOfSrcDisp, $vectorSrcDisp)
    Else
        If $bSrcDispCreate Then
            $srcDisp = Call("_cve" & $typeOfSrcDisp & "Create", $srcDisp)
        EndIf
        $iArrSrcDisp = Call("_cveInputArrayFrom" & $typeOfSrcDisp, $srcDisp)
    EndIf

    Local $oArrDstDisp, $vectorDstDisp, $iArrDstDispSize
    Local $bDstDispIsArray = IsArray($dstDisp)
    Local $bDstDispCreate = IsDllStruct($dstDisp) And $typeOfDstDisp == "Scalar"

    If $typeOfDstDisp == Default Then
        $oArrDstDisp = $dstDisp
    ElseIf $bDstDispIsArray Then
        $vectorDstDisp = Call("_VectorOf" & $typeOfDstDisp & "Create")

        $iArrDstDispSize = UBound($dstDisp)
        For $i = 0 To $iArrDstDispSize - 1
            Call("_VectorOf" & $typeOfDstDisp & "Push", $vectorDstDisp, $dstDisp[$i])
        Next

        $oArrDstDisp = Call("_cveOutputArrayFromVectorOf" & $typeOfDstDisp, $vectorDstDisp)
    Else
        If $bDstDispCreate Then
            $dstDisp = Call("_cve" & $typeOfDstDisp & "Create", $dstDisp)
        EndIf
        $oArrDstDisp = Call("_cveOutputArrayFrom" & $typeOfDstDisp, $dstDisp)
    EndIf

    _cudaDrawColorDisp($iArrSrcDisp, $oArrDstDisp, $ndisp, $stream)

    If $bDstDispIsArray Then
        Call("_VectorOf" & $typeOfDstDisp & "Release", $vectorDstDisp)
    EndIf

    If $typeOfDstDisp <> Default Then
        _cveOutputArrayRelease($oArrDstDisp)
        If $bDstDispCreate Then
            Call("_cve" & $typeOfDstDisp & "Release", $dstDisp)
        EndIf
    EndIf

    If $bSrcDispIsArray Then
        Call("_VectorOf" & $typeOfSrcDisp & "Release", $vectorSrcDisp)
    EndIf

    If $typeOfSrcDisp <> Default Then
        _cveInputArrayRelease($iArrSrcDisp)
        If $bSrcDispCreate Then
            Call("_cve" & $typeOfSrcDisp & "Release", $srcDisp)
        EndIf
    EndIf
EndFunc   ;==>_cudaDrawColorDispTyped

Func _cudaDrawColorDispMat($srcDisp, $dstDisp, $ndisp, $stream)
    ; cudaDrawColorDisp using cv::Mat instead of _*Array
    _cudaDrawColorDispTyped("Mat", $srcDisp, "Mat", $dstDisp, $ndisp, $stream)
EndFunc   ;==>_cudaDrawColorDispMat