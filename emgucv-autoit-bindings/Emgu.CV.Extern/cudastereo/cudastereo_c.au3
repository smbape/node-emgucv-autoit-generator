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

Func _cudaStereoBMFindStereoCorrespondenceMat($stereo, $matLeft, $matRight, $matDisparity, $stream)
    ; cudaStereoBMFindStereoCorrespondence using cv::Mat instead of _*Array

    Local $iArrLeft, $vectorOfMatLeft, $iArrLeftSize
    Local $bLeftIsArray = VarGetType($matLeft) == "Array"

    If $bLeftIsArray Then
        $vectorOfMatLeft = _VectorOfMatCreate()

        $iArrLeftSize = UBound($matLeft)
        For $i = 0 To $iArrLeftSize - 1
            _VectorOfMatPush($vectorOfMatLeft, $matLeft[$i])
        Next

        $iArrLeft = _cveInputArrayFromVectorOfMat($vectorOfMatLeft)
    Else
        $iArrLeft = _cveInputArrayFromMat($matLeft)
    EndIf

    Local $iArrRight, $vectorOfMatRight, $iArrRightSize
    Local $bRightIsArray = VarGetType($matRight) == "Array"

    If $bRightIsArray Then
        $vectorOfMatRight = _VectorOfMatCreate()

        $iArrRightSize = UBound($matRight)
        For $i = 0 To $iArrRightSize - 1
            _VectorOfMatPush($vectorOfMatRight, $matRight[$i])
        Next

        $iArrRight = _cveInputArrayFromVectorOfMat($vectorOfMatRight)
    Else
        $iArrRight = _cveInputArrayFromMat($matRight)
    EndIf

    Local $oArrDisparity, $vectorOfMatDisparity, $iArrDisparitySize
    Local $bDisparityIsArray = VarGetType($matDisparity) == "Array"

    If $bDisparityIsArray Then
        $vectorOfMatDisparity = _VectorOfMatCreate()

        $iArrDisparitySize = UBound($matDisparity)
        For $i = 0 To $iArrDisparitySize - 1
            _VectorOfMatPush($vectorOfMatDisparity, $matDisparity[$i])
        Next

        $oArrDisparity = _cveOutputArrayFromVectorOfMat($vectorOfMatDisparity)
    Else
        $oArrDisparity = _cveOutputArrayFromMat($matDisparity)
    EndIf

    _cudaStereoBMFindStereoCorrespondence($stereo, $iArrLeft, $iArrRight, $oArrDisparity, $stream)

    If $bDisparityIsArray Then
        _VectorOfMatRelease($vectorOfMatDisparity)
    EndIf

    _cveOutputArrayRelease($oArrDisparity)

    If $bRightIsArray Then
        _VectorOfMatRelease($vectorOfMatRight)
    EndIf

    _cveInputArrayRelease($iArrRight)

    If $bLeftIsArray Then
        _VectorOfMatRelease($vectorOfMatLeft)
    EndIf

    _cveInputArrayRelease($iArrLeft)
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

Func _cudaStereoConstantSpaceBPFindStereoCorrespondenceMat($stereo, $matLeft, $matRight, $matDisparity, $stream)
    ; cudaStereoConstantSpaceBPFindStereoCorrespondence using cv::Mat instead of _*Array

    Local $iArrLeft, $vectorOfMatLeft, $iArrLeftSize
    Local $bLeftIsArray = VarGetType($matLeft) == "Array"

    If $bLeftIsArray Then
        $vectorOfMatLeft = _VectorOfMatCreate()

        $iArrLeftSize = UBound($matLeft)
        For $i = 0 To $iArrLeftSize - 1
            _VectorOfMatPush($vectorOfMatLeft, $matLeft[$i])
        Next

        $iArrLeft = _cveInputArrayFromVectorOfMat($vectorOfMatLeft)
    Else
        $iArrLeft = _cveInputArrayFromMat($matLeft)
    EndIf

    Local $iArrRight, $vectorOfMatRight, $iArrRightSize
    Local $bRightIsArray = VarGetType($matRight) == "Array"

    If $bRightIsArray Then
        $vectorOfMatRight = _VectorOfMatCreate()

        $iArrRightSize = UBound($matRight)
        For $i = 0 To $iArrRightSize - 1
            _VectorOfMatPush($vectorOfMatRight, $matRight[$i])
        Next

        $iArrRight = _cveInputArrayFromVectorOfMat($vectorOfMatRight)
    Else
        $iArrRight = _cveInputArrayFromMat($matRight)
    EndIf

    Local $oArrDisparity, $vectorOfMatDisparity, $iArrDisparitySize
    Local $bDisparityIsArray = VarGetType($matDisparity) == "Array"

    If $bDisparityIsArray Then
        $vectorOfMatDisparity = _VectorOfMatCreate()

        $iArrDisparitySize = UBound($matDisparity)
        For $i = 0 To $iArrDisparitySize - 1
            _VectorOfMatPush($vectorOfMatDisparity, $matDisparity[$i])
        Next

        $oArrDisparity = _cveOutputArrayFromVectorOfMat($vectorOfMatDisparity)
    Else
        $oArrDisparity = _cveOutputArrayFromMat($matDisparity)
    EndIf

    _cudaStereoConstantSpaceBPFindStereoCorrespondence($stereo, $iArrLeft, $iArrRight, $oArrDisparity, $stream)

    If $bDisparityIsArray Then
        _VectorOfMatRelease($vectorOfMatDisparity)
    EndIf

    _cveOutputArrayRelease($oArrDisparity)

    If $bRightIsArray Then
        _VectorOfMatRelease($vectorOfMatRight)
    EndIf

    _cveInputArrayRelease($iArrRight)

    If $bLeftIsArray Then
        _VectorOfMatRelease($vectorOfMatLeft)
    EndIf

    _cveInputArrayRelease($iArrLeft)
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

Func _cudaDisparityBilateralFilterApplyMat($filter, $matDisparity, $matImage, $matDst, $stream)
    ; cudaDisparityBilateralFilterApply using cv::Mat instead of _*Array

    Local $iArrDisparity, $vectorOfMatDisparity, $iArrDisparitySize
    Local $bDisparityIsArray = VarGetType($matDisparity) == "Array"

    If $bDisparityIsArray Then
        $vectorOfMatDisparity = _VectorOfMatCreate()

        $iArrDisparitySize = UBound($matDisparity)
        For $i = 0 To $iArrDisparitySize - 1
            _VectorOfMatPush($vectorOfMatDisparity, $matDisparity[$i])
        Next

        $iArrDisparity = _cveInputArrayFromVectorOfMat($vectorOfMatDisparity)
    Else
        $iArrDisparity = _cveInputArrayFromMat($matDisparity)
    EndIf

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

    Local $oArrDst, $vectorOfMatDst, $iArrDstSize
    Local $bDstIsArray = VarGetType($matDst) == "Array"

    If $bDstIsArray Then
        $vectorOfMatDst = _VectorOfMatCreate()

        $iArrDstSize = UBound($matDst)
        For $i = 0 To $iArrDstSize - 1
            _VectorOfMatPush($vectorOfMatDst, $matDst[$i])
        Next

        $oArrDst = _cveOutputArrayFromVectorOfMat($vectorOfMatDst)
    Else
        $oArrDst = _cveOutputArrayFromMat($matDst)
    EndIf

    _cudaDisparityBilateralFilterApply($filter, $iArrDisparity, $iArrImage, $oArrDst, $stream)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveOutputArrayRelease($oArrDst)

    If $bImageIsArray Then
        _VectorOfMatRelease($vectorOfMatImage)
    EndIf

    _cveInputArrayRelease($iArrImage)

    If $bDisparityIsArray Then
        _VectorOfMatRelease($vectorOfMatDisparity)
    EndIf

    _cveInputArrayRelease($iArrDisparity)
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

Func _cudaDrawColorDispMat($matSrcDisp, $matDstDisp, $ndisp, $stream)
    ; cudaDrawColorDisp using cv::Mat instead of _*Array

    Local $iArrSrcDisp, $vectorOfMatSrcDisp, $iArrSrcDispSize
    Local $bSrcDispIsArray = VarGetType($matSrcDisp) == "Array"

    If $bSrcDispIsArray Then
        $vectorOfMatSrcDisp = _VectorOfMatCreate()

        $iArrSrcDispSize = UBound($matSrcDisp)
        For $i = 0 To $iArrSrcDispSize - 1
            _VectorOfMatPush($vectorOfMatSrcDisp, $matSrcDisp[$i])
        Next

        $iArrSrcDisp = _cveInputArrayFromVectorOfMat($vectorOfMatSrcDisp)
    Else
        $iArrSrcDisp = _cveInputArrayFromMat($matSrcDisp)
    EndIf

    Local $oArrDstDisp, $vectorOfMatDstDisp, $iArrDstDispSize
    Local $bDstDispIsArray = VarGetType($matDstDisp) == "Array"

    If $bDstDispIsArray Then
        $vectorOfMatDstDisp = _VectorOfMatCreate()

        $iArrDstDispSize = UBound($matDstDisp)
        For $i = 0 To $iArrDstDispSize - 1
            _VectorOfMatPush($vectorOfMatDstDisp, $matDstDisp[$i])
        Next

        $oArrDstDisp = _cveOutputArrayFromVectorOfMat($vectorOfMatDstDisp)
    Else
        $oArrDstDisp = _cveOutputArrayFromMat($matDstDisp)
    EndIf

    _cudaDrawColorDisp($iArrSrcDisp, $oArrDstDisp, $ndisp, $stream)

    If $bDstDispIsArray Then
        _VectorOfMatRelease($vectorOfMatDstDisp)
    EndIf

    _cveOutputArrayRelease($oArrDstDisp)

    If $bSrcDispIsArray Then
        _VectorOfMatRelease($vectorOfMatSrcDisp)
    EndIf

    _cveInputArrayRelease($iArrSrcDisp)
EndFunc   ;==>_cudaDrawColorDispMat