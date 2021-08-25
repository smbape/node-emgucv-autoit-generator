#include-once
#include "..\..\CVEUtils.au3"

Func _cudaBlendLinear($img1, $img2, $weights1, $weights2, $result, $stream)
    ; CVAPI(void) cudaBlendLinear(cv::_InputArray* img1, cv::_InputArray* img2, cv::_InputArray* weights1, cv::_InputArray* weights2, cv::_OutputArray* result, cv::cuda::Stream* stream);

    Local $sImg1DllType
    If IsDllStruct($img1) Then
        $sImg1DllType = "struct*"
    Else
        $sImg1DllType = "ptr"
    EndIf

    Local $sImg2DllType
    If IsDllStruct($img2) Then
        $sImg2DllType = "struct*"
    Else
        $sImg2DllType = "ptr"
    EndIf

    Local $sWeights1DllType
    If IsDllStruct($weights1) Then
        $sWeights1DllType = "struct*"
    Else
        $sWeights1DllType = "ptr"
    EndIf

    Local $sWeights2DllType
    If IsDllStruct($weights2) Then
        $sWeights2DllType = "struct*"
    Else
        $sWeights2DllType = "ptr"
    EndIf

    Local $sResultDllType
    If IsDllStruct($result) Then
        $sResultDllType = "struct*"
    Else
        $sResultDllType = "ptr"
    EndIf

    Local $sStreamDllType
    If IsDllStruct($stream) Then
        $sStreamDllType = "struct*"
    Else
        $sStreamDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaBlendLinear", $sImg1DllType, $img1, $sImg2DllType, $img2, $sWeights1DllType, $weights1, $sWeights2DllType, $weights2, $sResultDllType, $result, $sStreamDllType, $stream), "cudaBlendLinear", @error)
EndFunc   ;==>_cudaBlendLinear

Func _cudaBlendLinearTyped($typeOfImg1, $img1, $typeOfImg2, $img2, $typeOfWeights1, $weights1, $typeOfWeights2, $weights2, $typeOfResult, $result, $stream)

    Local $iArrImg1, $vectorImg1, $iArrImg1Size
    Local $bImg1IsArray = IsArray($img1)
    Local $bImg1Create = IsDllStruct($img1) And $typeOfImg1 == "Scalar"

    If $typeOfImg1 == Default Then
        $iArrImg1 = $img1
    ElseIf $bImg1IsArray Then
        $vectorImg1 = Call("_VectorOf" & $typeOfImg1 & "Create")

        $iArrImg1Size = UBound($img1)
        For $i = 0 To $iArrImg1Size - 1
            Call("_VectorOf" & $typeOfImg1 & "Push", $vectorImg1, $img1[$i])
        Next

        $iArrImg1 = Call("_cveInputArrayFromVectorOf" & $typeOfImg1, $vectorImg1)
    Else
        If $bImg1Create Then
            $img1 = Call("_cve" & $typeOfImg1 & "Create", $img1)
        EndIf
        $iArrImg1 = Call("_cveInputArrayFrom" & $typeOfImg1, $img1)
    EndIf

    Local $iArrImg2, $vectorImg2, $iArrImg2Size
    Local $bImg2IsArray = IsArray($img2)
    Local $bImg2Create = IsDllStruct($img2) And $typeOfImg2 == "Scalar"

    If $typeOfImg2 == Default Then
        $iArrImg2 = $img2
    ElseIf $bImg2IsArray Then
        $vectorImg2 = Call("_VectorOf" & $typeOfImg2 & "Create")

        $iArrImg2Size = UBound($img2)
        For $i = 0 To $iArrImg2Size - 1
            Call("_VectorOf" & $typeOfImg2 & "Push", $vectorImg2, $img2[$i])
        Next

        $iArrImg2 = Call("_cveInputArrayFromVectorOf" & $typeOfImg2, $vectorImg2)
    Else
        If $bImg2Create Then
            $img2 = Call("_cve" & $typeOfImg2 & "Create", $img2)
        EndIf
        $iArrImg2 = Call("_cveInputArrayFrom" & $typeOfImg2, $img2)
    EndIf

    Local $iArrWeights1, $vectorWeights1, $iArrWeights1Size
    Local $bWeights1IsArray = IsArray($weights1)
    Local $bWeights1Create = IsDllStruct($weights1) And $typeOfWeights1 == "Scalar"

    If $typeOfWeights1 == Default Then
        $iArrWeights1 = $weights1
    ElseIf $bWeights1IsArray Then
        $vectorWeights1 = Call("_VectorOf" & $typeOfWeights1 & "Create")

        $iArrWeights1Size = UBound($weights1)
        For $i = 0 To $iArrWeights1Size - 1
            Call("_VectorOf" & $typeOfWeights1 & "Push", $vectorWeights1, $weights1[$i])
        Next

        $iArrWeights1 = Call("_cveInputArrayFromVectorOf" & $typeOfWeights1, $vectorWeights1)
    Else
        If $bWeights1Create Then
            $weights1 = Call("_cve" & $typeOfWeights1 & "Create", $weights1)
        EndIf
        $iArrWeights1 = Call("_cveInputArrayFrom" & $typeOfWeights1, $weights1)
    EndIf

    Local $iArrWeights2, $vectorWeights2, $iArrWeights2Size
    Local $bWeights2IsArray = IsArray($weights2)
    Local $bWeights2Create = IsDllStruct($weights2) And $typeOfWeights2 == "Scalar"

    If $typeOfWeights2 == Default Then
        $iArrWeights2 = $weights2
    ElseIf $bWeights2IsArray Then
        $vectorWeights2 = Call("_VectorOf" & $typeOfWeights2 & "Create")

        $iArrWeights2Size = UBound($weights2)
        For $i = 0 To $iArrWeights2Size - 1
            Call("_VectorOf" & $typeOfWeights2 & "Push", $vectorWeights2, $weights2[$i])
        Next

        $iArrWeights2 = Call("_cveInputArrayFromVectorOf" & $typeOfWeights2, $vectorWeights2)
    Else
        If $bWeights2Create Then
            $weights2 = Call("_cve" & $typeOfWeights2 & "Create", $weights2)
        EndIf
        $iArrWeights2 = Call("_cveInputArrayFrom" & $typeOfWeights2, $weights2)
    EndIf

    Local $oArrResult, $vectorResult, $iArrResultSize
    Local $bResultIsArray = IsArray($result)
    Local $bResultCreate = IsDllStruct($result) And $typeOfResult == "Scalar"

    If $typeOfResult == Default Then
        $oArrResult = $result
    ElseIf $bResultIsArray Then
        $vectorResult = Call("_VectorOf" & $typeOfResult & "Create")

        $iArrResultSize = UBound($result)
        For $i = 0 To $iArrResultSize - 1
            Call("_VectorOf" & $typeOfResult & "Push", $vectorResult, $result[$i])
        Next

        $oArrResult = Call("_cveOutputArrayFromVectorOf" & $typeOfResult, $vectorResult)
    Else
        If $bResultCreate Then
            $result = Call("_cve" & $typeOfResult & "Create", $result)
        EndIf
        $oArrResult = Call("_cveOutputArrayFrom" & $typeOfResult, $result)
    EndIf

    _cudaBlendLinear($iArrImg1, $iArrImg2, $iArrWeights1, $iArrWeights2, $oArrResult, $stream)

    If $bResultIsArray Then
        Call("_VectorOf" & $typeOfResult & "Release", $vectorResult)
    EndIf

    If $typeOfResult <> Default Then
        _cveOutputArrayRelease($oArrResult)
        If $bResultCreate Then
            Call("_cve" & $typeOfResult & "Release", $result)
        EndIf
    EndIf

    If $bWeights2IsArray Then
        Call("_VectorOf" & $typeOfWeights2 & "Release", $vectorWeights2)
    EndIf

    If $typeOfWeights2 <> Default Then
        _cveInputArrayRelease($iArrWeights2)
        If $bWeights2Create Then
            Call("_cve" & $typeOfWeights2 & "Release", $weights2)
        EndIf
    EndIf

    If $bWeights1IsArray Then
        Call("_VectorOf" & $typeOfWeights1 & "Release", $vectorWeights1)
    EndIf

    If $typeOfWeights1 <> Default Then
        _cveInputArrayRelease($iArrWeights1)
        If $bWeights1Create Then
            Call("_cve" & $typeOfWeights1 & "Release", $weights1)
        EndIf
    EndIf

    If $bImg2IsArray Then
        Call("_VectorOf" & $typeOfImg2 & "Release", $vectorImg2)
    EndIf

    If $typeOfImg2 <> Default Then
        _cveInputArrayRelease($iArrImg2)
        If $bImg2Create Then
            Call("_cve" & $typeOfImg2 & "Release", $img2)
        EndIf
    EndIf

    If $bImg1IsArray Then
        Call("_VectorOf" & $typeOfImg1 & "Release", $vectorImg1)
    EndIf

    If $typeOfImg1 <> Default Then
        _cveInputArrayRelease($iArrImg1)
        If $bImg1Create Then
            Call("_cve" & $typeOfImg1 & "Release", $img1)
        EndIf
    EndIf
EndFunc   ;==>_cudaBlendLinearTyped

Func _cudaBlendLinearMat($img1, $img2, $weights1, $weights2, $result, $stream)
    ; cudaBlendLinear using cv::Mat instead of _*Array
    _cudaBlendLinearTyped("Mat", $img1, "Mat", $img2, "Mat", $weights1, "Mat", $weights2, "Mat", $result, $stream)
EndFunc   ;==>_cudaBlendLinearMat

Func _cudaCvtColor($src, $dst, $code, $dcn, $stream)
    ; CVAPI(void) cudaCvtColor(cv::_InputArray* src, cv::_OutputArray* dst, int code, int dcn, cv::cuda::Stream* stream);

    Local $sSrcDllType
    If IsDllStruct($src) Then
        $sSrcDllType = "struct*"
    Else
        $sSrcDllType = "ptr"
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaCvtColor", $sSrcDllType, $src, $sDstDllType, $dst, "int", $code, "int", $dcn, $sStreamDllType, $stream), "cudaCvtColor", @error)
EndFunc   ;==>_cudaCvtColor

Func _cudaCvtColorTyped($typeOfSrc, $src, $typeOfDst, $dst, $code, $dcn, $stream)

    Local $iArrSrc, $vectorSrc, $iArrSrcSize
    Local $bSrcIsArray = IsArray($src)
    Local $bSrcCreate = IsDllStruct($src) And $typeOfSrc == "Scalar"

    If $typeOfSrc == Default Then
        $iArrSrc = $src
    ElseIf $bSrcIsArray Then
        $vectorSrc = Call("_VectorOf" & $typeOfSrc & "Create")

        $iArrSrcSize = UBound($src)
        For $i = 0 To $iArrSrcSize - 1
            Call("_VectorOf" & $typeOfSrc & "Push", $vectorSrc, $src[$i])
        Next

        $iArrSrc = Call("_cveInputArrayFromVectorOf" & $typeOfSrc, $vectorSrc)
    Else
        If $bSrcCreate Then
            $src = Call("_cve" & $typeOfSrc & "Create", $src)
        EndIf
        $iArrSrc = Call("_cveInputArrayFrom" & $typeOfSrc, $src)
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

    _cudaCvtColor($iArrSrc, $oArrDst, $code, $dcn, $stream)

    If $bDstIsArray Then
        Call("_VectorOf" & $typeOfDst & "Release", $vectorDst)
    EndIf

    If $typeOfDst <> Default Then
        _cveOutputArrayRelease($oArrDst)
        If $bDstCreate Then
            Call("_cve" & $typeOfDst & "Release", $dst)
        EndIf
    EndIf

    If $bSrcIsArray Then
        Call("_VectorOf" & $typeOfSrc & "Release", $vectorSrc)
    EndIf

    If $typeOfSrc <> Default Then
        _cveInputArrayRelease($iArrSrc)
        If $bSrcCreate Then
            Call("_cve" & $typeOfSrc & "Release", $src)
        EndIf
    EndIf
EndFunc   ;==>_cudaCvtColorTyped

Func _cudaCvtColorMat($src, $dst, $code, $dcn, $stream)
    ; cudaCvtColor using cv::Mat instead of _*Array
    _cudaCvtColorTyped("Mat", $src, "Mat", $dst, $code, $dcn, $stream)
EndFunc   ;==>_cudaCvtColorMat

Func _cudaDemosaicing($src, $dst, $code, $dcn, $stream)
    ; CVAPI(void) cudaDemosaicing(cv::_InputArray* src, cv::_OutputArray* dst, int code, int dcn, cv::cuda::Stream* stream);

    Local $sSrcDllType
    If IsDllStruct($src) Then
        $sSrcDllType = "struct*"
    Else
        $sSrcDllType = "ptr"
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaDemosaicing", $sSrcDllType, $src, $sDstDllType, $dst, "int", $code, "int", $dcn, $sStreamDllType, $stream), "cudaDemosaicing", @error)
EndFunc   ;==>_cudaDemosaicing

Func _cudaDemosaicingTyped($typeOfSrc, $src, $typeOfDst, $dst, $code, $dcn, $stream)

    Local $iArrSrc, $vectorSrc, $iArrSrcSize
    Local $bSrcIsArray = IsArray($src)
    Local $bSrcCreate = IsDllStruct($src) And $typeOfSrc == "Scalar"

    If $typeOfSrc == Default Then
        $iArrSrc = $src
    ElseIf $bSrcIsArray Then
        $vectorSrc = Call("_VectorOf" & $typeOfSrc & "Create")

        $iArrSrcSize = UBound($src)
        For $i = 0 To $iArrSrcSize - 1
            Call("_VectorOf" & $typeOfSrc & "Push", $vectorSrc, $src[$i])
        Next

        $iArrSrc = Call("_cveInputArrayFromVectorOf" & $typeOfSrc, $vectorSrc)
    Else
        If $bSrcCreate Then
            $src = Call("_cve" & $typeOfSrc & "Create", $src)
        EndIf
        $iArrSrc = Call("_cveInputArrayFrom" & $typeOfSrc, $src)
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

    _cudaDemosaicing($iArrSrc, $oArrDst, $code, $dcn, $stream)

    If $bDstIsArray Then
        Call("_VectorOf" & $typeOfDst & "Release", $vectorDst)
    EndIf

    If $typeOfDst <> Default Then
        _cveOutputArrayRelease($oArrDst)
        If $bDstCreate Then
            Call("_cve" & $typeOfDst & "Release", $dst)
        EndIf
    EndIf

    If $bSrcIsArray Then
        Call("_VectorOf" & $typeOfSrc & "Release", $vectorSrc)
    EndIf

    If $typeOfSrc <> Default Then
        _cveInputArrayRelease($iArrSrc)
        If $bSrcCreate Then
            Call("_cve" & $typeOfSrc & "Release", $src)
        EndIf
    EndIf
EndFunc   ;==>_cudaDemosaicingTyped

Func _cudaDemosaicingMat($src, $dst, $code, $dcn, $stream)
    ; cudaDemosaicing using cv::Mat instead of _*Array
    _cudaDemosaicingTyped("Mat", $src, "Mat", $dst, $code, $dcn, $stream)
EndFunc   ;==>_cudaDemosaicingMat

Func _cudaSwapChannels($image, $dstOrder, $stream)
    ; CVAPI(void) cudaSwapChannels(cv::_InputOutputArray* image, const int* dstOrder, cv::cuda::Stream* stream);

    Local $sImageDllType
    If IsDllStruct($image) Then
        $sImageDllType = "struct*"
    Else
        $sImageDllType = "ptr"
    EndIf

    Local $sDstOrderDllType
    If IsDllStruct($dstOrder) Then
        $sDstOrderDllType = "struct*"
    Else
        $sDstOrderDllType = "int*"
    EndIf

    Local $sStreamDllType
    If IsDllStruct($stream) Then
        $sStreamDllType = "struct*"
    Else
        $sStreamDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaSwapChannels", $sImageDllType, $image, $sDstOrderDllType, $dstOrder, $sStreamDllType, $stream), "cudaSwapChannels", @error)
EndFunc   ;==>_cudaSwapChannels

Func _cudaSwapChannelsTyped($typeOfImage, $image, $dstOrder, $stream)

    Local $ioArrImage, $vectorImage, $iArrImageSize
    Local $bImageIsArray = IsArray($image)
    Local $bImageCreate = IsDllStruct($image) And $typeOfImage == "Scalar"

    If $typeOfImage == Default Then
        $ioArrImage = $image
    ElseIf $bImageIsArray Then
        $vectorImage = Call("_VectorOf" & $typeOfImage & "Create")

        $iArrImageSize = UBound($image)
        For $i = 0 To $iArrImageSize - 1
            Call("_VectorOf" & $typeOfImage & "Push", $vectorImage, $image[$i])
        Next

        $ioArrImage = Call("_cveInputOutputArrayFromVectorOf" & $typeOfImage, $vectorImage)
    Else
        If $bImageCreate Then
            $image = Call("_cve" & $typeOfImage & "Create", $image)
        EndIf
        $ioArrImage = Call("_cveInputOutputArrayFrom" & $typeOfImage, $image)
    EndIf

    _cudaSwapChannels($ioArrImage, $dstOrder, $stream)

    If $bImageIsArray Then
        Call("_VectorOf" & $typeOfImage & "Release", $vectorImage)
    EndIf

    If $typeOfImage <> Default Then
        _cveInputOutputArrayRelease($ioArrImage)
        If $bImageCreate Then
            Call("_cve" & $typeOfImage & "Release", $image)
        EndIf
    EndIf
EndFunc   ;==>_cudaSwapChannelsTyped

Func _cudaSwapChannelsMat($image, $dstOrder, $stream)
    ; cudaSwapChannels using cv::Mat instead of _*Array
    _cudaSwapChannelsTyped("Mat", $image, $dstOrder, $stream)
EndFunc   ;==>_cudaSwapChannelsMat

Func _cudaAlphaComp($img1, $img2, $dst, $alphaOp, $stream)
    ; CVAPI(void) cudaAlphaComp(cv::_InputArray* img1, cv::_InputArray* img2, cv::_OutputArray* dst, int alphaOp, cv::cuda::Stream* stream);

    Local $sImg1DllType
    If IsDllStruct($img1) Then
        $sImg1DllType = "struct*"
    Else
        $sImg1DllType = "ptr"
    EndIf

    Local $sImg2DllType
    If IsDllStruct($img2) Then
        $sImg2DllType = "struct*"
    Else
        $sImg2DllType = "ptr"
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaAlphaComp", $sImg1DllType, $img1, $sImg2DllType, $img2, $sDstDllType, $dst, "int", $alphaOp, $sStreamDllType, $stream), "cudaAlphaComp", @error)
EndFunc   ;==>_cudaAlphaComp

Func _cudaAlphaCompTyped($typeOfImg1, $img1, $typeOfImg2, $img2, $typeOfDst, $dst, $alphaOp, $stream)

    Local $iArrImg1, $vectorImg1, $iArrImg1Size
    Local $bImg1IsArray = IsArray($img1)
    Local $bImg1Create = IsDllStruct($img1) And $typeOfImg1 == "Scalar"

    If $typeOfImg1 == Default Then
        $iArrImg1 = $img1
    ElseIf $bImg1IsArray Then
        $vectorImg1 = Call("_VectorOf" & $typeOfImg1 & "Create")

        $iArrImg1Size = UBound($img1)
        For $i = 0 To $iArrImg1Size - 1
            Call("_VectorOf" & $typeOfImg1 & "Push", $vectorImg1, $img1[$i])
        Next

        $iArrImg1 = Call("_cveInputArrayFromVectorOf" & $typeOfImg1, $vectorImg1)
    Else
        If $bImg1Create Then
            $img1 = Call("_cve" & $typeOfImg1 & "Create", $img1)
        EndIf
        $iArrImg1 = Call("_cveInputArrayFrom" & $typeOfImg1, $img1)
    EndIf

    Local $iArrImg2, $vectorImg2, $iArrImg2Size
    Local $bImg2IsArray = IsArray($img2)
    Local $bImg2Create = IsDllStruct($img2) And $typeOfImg2 == "Scalar"

    If $typeOfImg2 == Default Then
        $iArrImg2 = $img2
    ElseIf $bImg2IsArray Then
        $vectorImg2 = Call("_VectorOf" & $typeOfImg2 & "Create")

        $iArrImg2Size = UBound($img2)
        For $i = 0 To $iArrImg2Size - 1
            Call("_VectorOf" & $typeOfImg2 & "Push", $vectorImg2, $img2[$i])
        Next

        $iArrImg2 = Call("_cveInputArrayFromVectorOf" & $typeOfImg2, $vectorImg2)
    Else
        If $bImg2Create Then
            $img2 = Call("_cve" & $typeOfImg2 & "Create", $img2)
        EndIf
        $iArrImg2 = Call("_cveInputArrayFrom" & $typeOfImg2, $img2)
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

    _cudaAlphaComp($iArrImg1, $iArrImg2, $oArrDst, $alphaOp, $stream)

    If $bDstIsArray Then
        Call("_VectorOf" & $typeOfDst & "Release", $vectorDst)
    EndIf

    If $typeOfDst <> Default Then
        _cveOutputArrayRelease($oArrDst)
        If $bDstCreate Then
            Call("_cve" & $typeOfDst & "Release", $dst)
        EndIf
    EndIf

    If $bImg2IsArray Then
        Call("_VectorOf" & $typeOfImg2 & "Release", $vectorImg2)
    EndIf

    If $typeOfImg2 <> Default Then
        _cveInputArrayRelease($iArrImg2)
        If $bImg2Create Then
            Call("_cve" & $typeOfImg2 & "Release", $img2)
        EndIf
    EndIf

    If $bImg1IsArray Then
        Call("_VectorOf" & $typeOfImg1 & "Release", $vectorImg1)
    EndIf

    If $typeOfImg1 <> Default Then
        _cveInputArrayRelease($iArrImg1)
        If $bImg1Create Then
            Call("_cve" & $typeOfImg1 & "Release", $img1)
        EndIf
    EndIf
EndFunc   ;==>_cudaAlphaCompTyped

Func _cudaAlphaCompMat($img1, $img2, $dst, $alphaOp, $stream)
    ; cudaAlphaComp using cv::Mat instead of _*Array
    _cudaAlphaCompTyped("Mat", $img1, "Mat", $img2, "Mat", $dst, $alphaOp, $stream)
EndFunc   ;==>_cudaAlphaCompMat

Func _cudaMeanShiftFiltering($src, $dst, $sp, $sr, $criteria, $stream)
    ; CVAPI(void) cudaMeanShiftFiltering(cv::_InputArray* src, cv::_OutputArray* dst, int sp, int sr, CvTermCriteria* criteria, cv::cuda::Stream* stream);

    Local $sSrcDllType
    If IsDllStruct($src) Then
        $sSrcDllType = "struct*"
    Else
        $sSrcDllType = "ptr"
    EndIf

    Local $sDstDllType
    If IsDllStruct($dst) Then
        $sDstDllType = "struct*"
    Else
        $sDstDllType = "ptr"
    EndIf

    Local $sCriteriaDllType
    If IsDllStruct($criteria) Then
        $sCriteriaDllType = "struct*"
    Else
        $sCriteriaDllType = "ptr"
    EndIf

    Local $sStreamDllType
    If IsDllStruct($stream) Then
        $sStreamDllType = "struct*"
    Else
        $sStreamDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaMeanShiftFiltering", $sSrcDllType, $src, $sDstDllType, $dst, "int", $sp, "int", $sr, $sCriteriaDllType, $criteria, $sStreamDllType, $stream), "cudaMeanShiftFiltering", @error)
EndFunc   ;==>_cudaMeanShiftFiltering

Func _cudaMeanShiftFilteringTyped($typeOfSrc, $src, $typeOfDst, $dst, $sp, $sr, $criteria, $stream)

    Local $iArrSrc, $vectorSrc, $iArrSrcSize
    Local $bSrcIsArray = IsArray($src)
    Local $bSrcCreate = IsDllStruct($src) And $typeOfSrc == "Scalar"

    If $typeOfSrc == Default Then
        $iArrSrc = $src
    ElseIf $bSrcIsArray Then
        $vectorSrc = Call("_VectorOf" & $typeOfSrc & "Create")

        $iArrSrcSize = UBound($src)
        For $i = 0 To $iArrSrcSize - 1
            Call("_VectorOf" & $typeOfSrc & "Push", $vectorSrc, $src[$i])
        Next

        $iArrSrc = Call("_cveInputArrayFromVectorOf" & $typeOfSrc, $vectorSrc)
    Else
        If $bSrcCreate Then
            $src = Call("_cve" & $typeOfSrc & "Create", $src)
        EndIf
        $iArrSrc = Call("_cveInputArrayFrom" & $typeOfSrc, $src)
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

    _cudaMeanShiftFiltering($iArrSrc, $oArrDst, $sp, $sr, $criteria, $stream)

    If $bDstIsArray Then
        Call("_VectorOf" & $typeOfDst & "Release", $vectorDst)
    EndIf

    If $typeOfDst <> Default Then
        _cveOutputArrayRelease($oArrDst)
        If $bDstCreate Then
            Call("_cve" & $typeOfDst & "Release", $dst)
        EndIf
    EndIf

    If $bSrcIsArray Then
        Call("_VectorOf" & $typeOfSrc & "Release", $vectorSrc)
    EndIf

    If $typeOfSrc <> Default Then
        _cveInputArrayRelease($iArrSrc)
        If $bSrcCreate Then
            Call("_cve" & $typeOfSrc & "Release", $src)
        EndIf
    EndIf
EndFunc   ;==>_cudaMeanShiftFilteringTyped

Func _cudaMeanShiftFilteringMat($src, $dst, $sp, $sr, $criteria, $stream)
    ; cudaMeanShiftFiltering using cv::Mat instead of _*Array
    _cudaMeanShiftFilteringTyped("Mat", $src, "Mat", $dst, $sp, $sr, $criteria, $stream)
EndFunc   ;==>_cudaMeanShiftFilteringMat

Func _cudaMeanShiftProc($src, $dstr, $dstsp, $sp, $sr, $criteria, $stream)
    ; CVAPI(void) cudaMeanShiftProc(cv::_InputArray* src, cv::_OutputArray* dstr, cv::_OutputArray* dstsp, int sp, int sr, CvTermCriteria* criteria, cv::cuda::Stream* stream);

    Local $sSrcDllType
    If IsDllStruct($src) Then
        $sSrcDllType = "struct*"
    Else
        $sSrcDllType = "ptr"
    EndIf

    Local $sDstrDllType
    If IsDllStruct($dstr) Then
        $sDstrDllType = "struct*"
    Else
        $sDstrDllType = "ptr"
    EndIf

    Local $sDstspDllType
    If IsDllStruct($dstsp) Then
        $sDstspDllType = "struct*"
    Else
        $sDstspDllType = "ptr"
    EndIf

    Local $sCriteriaDllType
    If IsDllStruct($criteria) Then
        $sCriteriaDllType = "struct*"
    Else
        $sCriteriaDllType = "ptr"
    EndIf

    Local $sStreamDllType
    If IsDllStruct($stream) Then
        $sStreamDllType = "struct*"
    Else
        $sStreamDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaMeanShiftProc", $sSrcDllType, $src, $sDstrDllType, $dstr, $sDstspDllType, $dstsp, "int", $sp, "int", $sr, $sCriteriaDllType, $criteria, $sStreamDllType, $stream), "cudaMeanShiftProc", @error)
EndFunc   ;==>_cudaMeanShiftProc

Func _cudaMeanShiftProcTyped($typeOfSrc, $src, $typeOfDstr, $dstr, $typeOfDstsp, $dstsp, $sp, $sr, $criteria, $stream)

    Local $iArrSrc, $vectorSrc, $iArrSrcSize
    Local $bSrcIsArray = IsArray($src)
    Local $bSrcCreate = IsDllStruct($src) And $typeOfSrc == "Scalar"

    If $typeOfSrc == Default Then
        $iArrSrc = $src
    ElseIf $bSrcIsArray Then
        $vectorSrc = Call("_VectorOf" & $typeOfSrc & "Create")

        $iArrSrcSize = UBound($src)
        For $i = 0 To $iArrSrcSize - 1
            Call("_VectorOf" & $typeOfSrc & "Push", $vectorSrc, $src[$i])
        Next

        $iArrSrc = Call("_cveInputArrayFromVectorOf" & $typeOfSrc, $vectorSrc)
    Else
        If $bSrcCreate Then
            $src = Call("_cve" & $typeOfSrc & "Create", $src)
        EndIf
        $iArrSrc = Call("_cveInputArrayFrom" & $typeOfSrc, $src)
    EndIf

    Local $oArrDstr, $vectorDstr, $iArrDstrSize
    Local $bDstrIsArray = IsArray($dstr)
    Local $bDstrCreate = IsDllStruct($dstr) And $typeOfDstr == "Scalar"

    If $typeOfDstr == Default Then
        $oArrDstr = $dstr
    ElseIf $bDstrIsArray Then
        $vectorDstr = Call("_VectorOf" & $typeOfDstr & "Create")

        $iArrDstrSize = UBound($dstr)
        For $i = 0 To $iArrDstrSize - 1
            Call("_VectorOf" & $typeOfDstr & "Push", $vectorDstr, $dstr[$i])
        Next

        $oArrDstr = Call("_cveOutputArrayFromVectorOf" & $typeOfDstr, $vectorDstr)
    Else
        If $bDstrCreate Then
            $dstr = Call("_cve" & $typeOfDstr & "Create", $dstr)
        EndIf
        $oArrDstr = Call("_cveOutputArrayFrom" & $typeOfDstr, $dstr)
    EndIf

    Local $oArrDstsp, $vectorDstsp, $iArrDstspSize
    Local $bDstspIsArray = IsArray($dstsp)
    Local $bDstspCreate = IsDllStruct($dstsp) And $typeOfDstsp == "Scalar"

    If $typeOfDstsp == Default Then
        $oArrDstsp = $dstsp
    ElseIf $bDstspIsArray Then
        $vectorDstsp = Call("_VectorOf" & $typeOfDstsp & "Create")

        $iArrDstspSize = UBound($dstsp)
        For $i = 0 To $iArrDstspSize - 1
            Call("_VectorOf" & $typeOfDstsp & "Push", $vectorDstsp, $dstsp[$i])
        Next

        $oArrDstsp = Call("_cveOutputArrayFromVectorOf" & $typeOfDstsp, $vectorDstsp)
    Else
        If $bDstspCreate Then
            $dstsp = Call("_cve" & $typeOfDstsp & "Create", $dstsp)
        EndIf
        $oArrDstsp = Call("_cveOutputArrayFrom" & $typeOfDstsp, $dstsp)
    EndIf

    _cudaMeanShiftProc($iArrSrc, $oArrDstr, $oArrDstsp, $sp, $sr, $criteria, $stream)

    If $bDstspIsArray Then
        Call("_VectorOf" & $typeOfDstsp & "Release", $vectorDstsp)
    EndIf

    If $typeOfDstsp <> Default Then
        _cveOutputArrayRelease($oArrDstsp)
        If $bDstspCreate Then
            Call("_cve" & $typeOfDstsp & "Release", $dstsp)
        EndIf
    EndIf

    If $bDstrIsArray Then
        Call("_VectorOf" & $typeOfDstr & "Release", $vectorDstr)
    EndIf

    If $typeOfDstr <> Default Then
        _cveOutputArrayRelease($oArrDstr)
        If $bDstrCreate Then
            Call("_cve" & $typeOfDstr & "Release", $dstr)
        EndIf
    EndIf

    If $bSrcIsArray Then
        Call("_VectorOf" & $typeOfSrc & "Release", $vectorSrc)
    EndIf

    If $typeOfSrc <> Default Then
        _cveInputArrayRelease($iArrSrc)
        If $bSrcCreate Then
            Call("_cve" & $typeOfSrc & "Release", $src)
        EndIf
    EndIf
EndFunc   ;==>_cudaMeanShiftProcTyped

Func _cudaMeanShiftProcMat($src, $dstr, $dstsp, $sp, $sr, $criteria, $stream)
    ; cudaMeanShiftProc using cv::Mat instead of _*Array
    _cudaMeanShiftProcTyped("Mat", $src, "Mat", $dstr, "Mat", $dstsp, $sp, $sr, $criteria, $stream)
EndFunc   ;==>_cudaMeanShiftProcMat

Func _cudaMeanShiftSegmentation($src, $dst, $sp, $sr, $minsize, $criteria, $stream)
    ; CVAPI(void) cudaMeanShiftSegmentation(cv::_InputArray* src, cv::_OutputArray* dst, int sp, int sr, int minsize, CvTermCriteria* criteria, cv::cuda::Stream* stream);

    Local $sSrcDllType
    If IsDllStruct($src) Then
        $sSrcDllType = "struct*"
    Else
        $sSrcDllType = "ptr"
    EndIf

    Local $sDstDllType
    If IsDllStruct($dst) Then
        $sDstDllType = "struct*"
    Else
        $sDstDllType = "ptr"
    EndIf

    Local $sCriteriaDllType
    If IsDllStruct($criteria) Then
        $sCriteriaDllType = "struct*"
    Else
        $sCriteriaDllType = "ptr"
    EndIf

    Local $sStreamDllType
    If IsDllStruct($stream) Then
        $sStreamDllType = "struct*"
    Else
        $sStreamDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaMeanShiftSegmentation", $sSrcDllType, $src, $sDstDllType, $dst, "int", $sp, "int", $sr, "int", $minsize, $sCriteriaDllType, $criteria, $sStreamDllType, $stream), "cudaMeanShiftSegmentation", @error)
EndFunc   ;==>_cudaMeanShiftSegmentation

Func _cudaMeanShiftSegmentationTyped($typeOfSrc, $src, $typeOfDst, $dst, $sp, $sr, $minsize, $criteria, $stream)

    Local $iArrSrc, $vectorSrc, $iArrSrcSize
    Local $bSrcIsArray = IsArray($src)
    Local $bSrcCreate = IsDllStruct($src) And $typeOfSrc == "Scalar"

    If $typeOfSrc == Default Then
        $iArrSrc = $src
    ElseIf $bSrcIsArray Then
        $vectorSrc = Call("_VectorOf" & $typeOfSrc & "Create")

        $iArrSrcSize = UBound($src)
        For $i = 0 To $iArrSrcSize - 1
            Call("_VectorOf" & $typeOfSrc & "Push", $vectorSrc, $src[$i])
        Next

        $iArrSrc = Call("_cveInputArrayFromVectorOf" & $typeOfSrc, $vectorSrc)
    Else
        If $bSrcCreate Then
            $src = Call("_cve" & $typeOfSrc & "Create", $src)
        EndIf
        $iArrSrc = Call("_cveInputArrayFrom" & $typeOfSrc, $src)
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

    _cudaMeanShiftSegmentation($iArrSrc, $oArrDst, $sp, $sr, $minsize, $criteria, $stream)

    If $bDstIsArray Then
        Call("_VectorOf" & $typeOfDst & "Release", $vectorDst)
    EndIf

    If $typeOfDst <> Default Then
        _cveOutputArrayRelease($oArrDst)
        If $bDstCreate Then
            Call("_cve" & $typeOfDst & "Release", $dst)
        EndIf
    EndIf

    If $bSrcIsArray Then
        Call("_VectorOf" & $typeOfSrc & "Release", $vectorSrc)
    EndIf

    If $typeOfSrc <> Default Then
        _cveInputArrayRelease($iArrSrc)
        If $bSrcCreate Then
            Call("_cve" & $typeOfSrc & "Release", $src)
        EndIf
    EndIf
EndFunc   ;==>_cudaMeanShiftSegmentationTyped

Func _cudaMeanShiftSegmentationMat($src, $dst, $sp, $sr, $minsize, $criteria, $stream)
    ; cudaMeanShiftSegmentation using cv::Mat instead of _*Array
    _cudaMeanShiftSegmentationTyped("Mat", $src, "Mat", $dst, $sp, $sr, $minsize, $criteria, $stream)
EndFunc   ;==>_cudaMeanShiftSegmentationMat

Func _cudaCalcHist($src, $hist, $stream)
    ; CVAPI(void) cudaCalcHist(cv::_InputArray* src, cv::_OutputArray* hist, cv::cuda::Stream* stream);

    Local $sSrcDllType
    If IsDllStruct($src) Then
        $sSrcDllType = "struct*"
    Else
        $sSrcDllType = "ptr"
    EndIf

    Local $sHistDllType
    If IsDllStruct($hist) Then
        $sHistDllType = "struct*"
    Else
        $sHistDllType = "ptr"
    EndIf

    Local $sStreamDllType
    If IsDllStruct($stream) Then
        $sStreamDllType = "struct*"
    Else
        $sStreamDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaCalcHist", $sSrcDllType, $src, $sHistDllType, $hist, $sStreamDllType, $stream), "cudaCalcHist", @error)
EndFunc   ;==>_cudaCalcHist

Func _cudaCalcHistTyped($typeOfSrc, $src, $typeOfHist, $hist, $stream)

    Local $iArrSrc, $vectorSrc, $iArrSrcSize
    Local $bSrcIsArray = IsArray($src)
    Local $bSrcCreate = IsDllStruct($src) And $typeOfSrc == "Scalar"

    If $typeOfSrc == Default Then
        $iArrSrc = $src
    ElseIf $bSrcIsArray Then
        $vectorSrc = Call("_VectorOf" & $typeOfSrc & "Create")

        $iArrSrcSize = UBound($src)
        For $i = 0 To $iArrSrcSize - 1
            Call("_VectorOf" & $typeOfSrc & "Push", $vectorSrc, $src[$i])
        Next

        $iArrSrc = Call("_cveInputArrayFromVectorOf" & $typeOfSrc, $vectorSrc)
    Else
        If $bSrcCreate Then
            $src = Call("_cve" & $typeOfSrc & "Create", $src)
        EndIf
        $iArrSrc = Call("_cveInputArrayFrom" & $typeOfSrc, $src)
    EndIf

    Local $oArrHist, $vectorHist, $iArrHistSize
    Local $bHistIsArray = IsArray($hist)
    Local $bHistCreate = IsDllStruct($hist) And $typeOfHist == "Scalar"

    If $typeOfHist == Default Then
        $oArrHist = $hist
    ElseIf $bHistIsArray Then
        $vectorHist = Call("_VectorOf" & $typeOfHist & "Create")

        $iArrHistSize = UBound($hist)
        For $i = 0 To $iArrHistSize - 1
            Call("_VectorOf" & $typeOfHist & "Push", $vectorHist, $hist[$i])
        Next

        $oArrHist = Call("_cveOutputArrayFromVectorOf" & $typeOfHist, $vectorHist)
    Else
        If $bHistCreate Then
            $hist = Call("_cve" & $typeOfHist & "Create", $hist)
        EndIf
        $oArrHist = Call("_cveOutputArrayFrom" & $typeOfHist, $hist)
    EndIf

    _cudaCalcHist($iArrSrc, $oArrHist, $stream)

    If $bHistIsArray Then
        Call("_VectorOf" & $typeOfHist & "Release", $vectorHist)
    EndIf

    If $typeOfHist <> Default Then
        _cveOutputArrayRelease($oArrHist)
        If $bHistCreate Then
            Call("_cve" & $typeOfHist & "Release", $hist)
        EndIf
    EndIf

    If $bSrcIsArray Then
        Call("_VectorOf" & $typeOfSrc & "Release", $vectorSrc)
    EndIf

    If $typeOfSrc <> Default Then
        _cveInputArrayRelease($iArrSrc)
        If $bSrcCreate Then
            Call("_cve" & $typeOfSrc & "Release", $src)
        EndIf
    EndIf
EndFunc   ;==>_cudaCalcHistTyped

Func _cudaCalcHistMat($src, $hist, $stream)
    ; cudaCalcHist using cv::Mat instead of _*Array
    _cudaCalcHistTyped("Mat", $src, "Mat", $hist, $stream)
EndFunc   ;==>_cudaCalcHistMat

Func _cudaEqualizeHist($src, $dst, $stream)
    ; CVAPI(void) cudaEqualizeHist(cv::_InputArray* src, cv::_OutputArray* dst, cv::cuda::Stream* stream);

    Local $sSrcDllType
    If IsDllStruct($src) Then
        $sSrcDllType = "struct*"
    Else
        $sSrcDllType = "ptr"
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaEqualizeHist", $sSrcDllType, $src, $sDstDllType, $dst, $sStreamDllType, $stream), "cudaEqualizeHist", @error)
EndFunc   ;==>_cudaEqualizeHist

Func _cudaEqualizeHistTyped($typeOfSrc, $src, $typeOfDst, $dst, $stream)

    Local $iArrSrc, $vectorSrc, $iArrSrcSize
    Local $bSrcIsArray = IsArray($src)
    Local $bSrcCreate = IsDllStruct($src) And $typeOfSrc == "Scalar"

    If $typeOfSrc == Default Then
        $iArrSrc = $src
    ElseIf $bSrcIsArray Then
        $vectorSrc = Call("_VectorOf" & $typeOfSrc & "Create")

        $iArrSrcSize = UBound($src)
        For $i = 0 To $iArrSrcSize - 1
            Call("_VectorOf" & $typeOfSrc & "Push", $vectorSrc, $src[$i])
        Next

        $iArrSrc = Call("_cveInputArrayFromVectorOf" & $typeOfSrc, $vectorSrc)
    Else
        If $bSrcCreate Then
            $src = Call("_cve" & $typeOfSrc & "Create", $src)
        EndIf
        $iArrSrc = Call("_cveInputArrayFrom" & $typeOfSrc, $src)
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

    _cudaEqualizeHist($iArrSrc, $oArrDst, $stream)

    If $bDstIsArray Then
        Call("_VectorOf" & $typeOfDst & "Release", $vectorDst)
    EndIf

    If $typeOfDst <> Default Then
        _cveOutputArrayRelease($oArrDst)
        If $bDstCreate Then
            Call("_cve" & $typeOfDst & "Release", $dst)
        EndIf
    EndIf

    If $bSrcIsArray Then
        Call("_VectorOf" & $typeOfSrc & "Release", $vectorSrc)
    EndIf

    If $typeOfSrc <> Default Then
        _cveInputArrayRelease($iArrSrc)
        If $bSrcCreate Then
            Call("_cve" & $typeOfSrc & "Release", $src)
        EndIf
    EndIf
EndFunc   ;==>_cudaEqualizeHistTyped

Func _cudaEqualizeHistMat($src, $dst, $stream)
    ; cudaEqualizeHist using cv::Mat instead of _*Array
    _cudaEqualizeHistTyped("Mat", $src, "Mat", $dst, $stream)
EndFunc   ;==>_cudaEqualizeHistMat

Func _cudaHistEven($src, $hist, $histSize, $lowerLevel, $upperLevel, $stream)
    ; CVAPI(void) cudaHistEven(cv::_InputArray* src, cv::_OutputArray* hist, int histSize, int lowerLevel, int upperLevel, cv::cuda::Stream* stream);

    Local $sSrcDllType
    If IsDllStruct($src) Then
        $sSrcDllType = "struct*"
    Else
        $sSrcDllType = "ptr"
    EndIf

    Local $sHistDllType
    If IsDllStruct($hist) Then
        $sHistDllType = "struct*"
    Else
        $sHistDllType = "ptr"
    EndIf

    Local $sStreamDllType
    If IsDllStruct($stream) Then
        $sStreamDllType = "struct*"
    Else
        $sStreamDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaHistEven", $sSrcDllType, $src, $sHistDllType, $hist, "int", $histSize, "int", $lowerLevel, "int", $upperLevel, $sStreamDllType, $stream), "cudaHistEven", @error)
EndFunc   ;==>_cudaHistEven

Func _cudaHistEvenTyped($typeOfSrc, $src, $typeOfHist, $hist, $histSize, $lowerLevel, $upperLevel, $stream)

    Local $iArrSrc, $vectorSrc, $iArrSrcSize
    Local $bSrcIsArray = IsArray($src)
    Local $bSrcCreate = IsDllStruct($src) And $typeOfSrc == "Scalar"

    If $typeOfSrc == Default Then
        $iArrSrc = $src
    ElseIf $bSrcIsArray Then
        $vectorSrc = Call("_VectorOf" & $typeOfSrc & "Create")

        $iArrSrcSize = UBound($src)
        For $i = 0 To $iArrSrcSize - 1
            Call("_VectorOf" & $typeOfSrc & "Push", $vectorSrc, $src[$i])
        Next

        $iArrSrc = Call("_cveInputArrayFromVectorOf" & $typeOfSrc, $vectorSrc)
    Else
        If $bSrcCreate Then
            $src = Call("_cve" & $typeOfSrc & "Create", $src)
        EndIf
        $iArrSrc = Call("_cveInputArrayFrom" & $typeOfSrc, $src)
    EndIf

    Local $oArrHist, $vectorHist, $iArrHistSize
    Local $bHistIsArray = IsArray($hist)
    Local $bHistCreate = IsDllStruct($hist) And $typeOfHist == "Scalar"

    If $typeOfHist == Default Then
        $oArrHist = $hist
    ElseIf $bHistIsArray Then
        $vectorHist = Call("_VectorOf" & $typeOfHist & "Create")

        $iArrHistSize = UBound($hist)
        For $i = 0 To $iArrHistSize - 1
            Call("_VectorOf" & $typeOfHist & "Push", $vectorHist, $hist[$i])
        Next

        $oArrHist = Call("_cveOutputArrayFromVectorOf" & $typeOfHist, $vectorHist)
    Else
        If $bHistCreate Then
            $hist = Call("_cve" & $typeOfHist & "Create", $hist)
        EndIf
        $oArrHist = Call("_cveOutputArrayFrom" & $typeOfHist, $hist)
    EndIf

    _cudaHistEven($iArrSrc, $oArrHist, $histSize, $lowerLevel, $upperLevel, $stream)

    If $bHistIsArray Then
        Call("_VectorOf" & $typeOfHist & "Release", $vectorHist)
    EndIf

    If $typeOfHist <> Default Then
        _cveOutputArrayRelease($oArrHist)
        If $bHistCreate Then
            Call("_cve" & $typeOfHist & "Release", $hist)
        EndIf
    EndIf

    If $bSrcIsArray Then
        Call("_VectorOf" & $typeOfSrc & "Release", $vectorSrc)
    EndIf

    If $typeOfSrc <> Default Then
        _cveInputArrayRelease($iArrSrc)
        If $bSrcCreate Then
            Call("_cve" & $typeOfSrc & "Release", $src)
        EndIf
    EndIf
EndFunc   ;==>_cudaHistEvenTyped

Func _cudaHistEvenMat($src, $hist, $histSize, $lowerLevel, $upperLevel, $stream)
    ; cudaHistEven using cv::Mat instead of _*Array
    _cudaHistEvenTyped("Mat", $src, "Mat", $hist, $histSize, $lowerLevel, $upperLevel, $stream)
EndFunc   ;==>_cudaHistEvenMat

Func _cudaHistRange($src, $hist, $levels, $stream)
    ; CVAPI(void) cudaHistRange(cv::_InputArray* src, cv::_OutputArray* hist, cv::_InputArray* levels, cv::cuda::Stream* stream);

    Local $sSrcDllType
    If IsDllStruct($src) Then
        $sSrcDllType = "struct*"
    Else
        $sSrcDllType = "ptr"
    EndIf

    Local $sHistDllType
    If IsDllStruct($hist) Then
        $sHistDllType = "struct*"
    Else
        $sHistDllType = "ptr"
    EndIf

    Local $sLevelsDllType
    If IsDllStruct($levels) Then
        $sLevelsDllType = "struct*"
    Else
        $sLevelsDllType = "ptr"
    EndIf

    Local $sStreamDllType
    If IsDllStruct($stream) Then
        $sStreamDllType = "struct*"
    Else
        $sStreamDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaHistRange", $sSrcDllType, $src, $sHistDllType, $hist, $sLevelsDllType, $levels, $sStreamDllType, $stream), "cudaHistRange", @error)
EndFunc   ;==>_cudaHistRange

Func _cudaHistRangeTyped($typeOfSrc, $src, $typeOfHist, $hist, $typeOfLevels, $levels, $stream)

    Local $iArrSrc, $vectorSrc, $iArrSrcSize
    Local $bSrcIsArray = IsArray($src)
    Local $bSrcCreate = IsDllStruct($src) And $typeOfSrc == "Scalar"

    If $typeOfSrc == Default Then
        $iArrSrc = $src
    ElseIf $bSrcIsArray Then
        $vectorSrc = Call("_VectorOf" & $typeOfSrc & "Create")

        $iArrSrcSize = UBound($src)
        For $i = 0 To $iArrSrcSize - 1
            Call("_VectorOf" & $typeOfSrc & "Push", $vectorSrc, $src[$i])
        Next

        $iArrSrc = Call("_cveInputArrayFromVectorOf" & $typeOfSrc, $vectorSrc)
    Else
        If $bSrcCreate Then
            $src = Call("_cve" & $typeOfSrc & "Create", $src)
        EndIf
        $iArrSrc = Call("_cveInputArrayFrom" & $typeOfSrc, $src)
    EndIf

    Local $oArrHist, $vectorHist, $iArrHistSize
    Local $bHistIsArray = IsArray($hist)
    Local $bHistCreate = IsDllStruct($hist) And $typeOfHist == "Scalar"

    If $typeOfHist == Default Then
        $oArrHist = $hist
    ElseIf $bHistIsArray Then
        $vectorHist = Call("_VectorOf" & $typeOfHist & "Create")

        $iArrHistSize = UBound($hist)
        For $i = 0 To $iArrHistSize - 1
            Call("_VectorOf" & $typeOfHist & "Push", $vectorHist, $hist[$i])
        Next

        $oArrHist = Call("_cveOutputArrayFromVectorOf" & $typeOfHist, $vectorHist)
    Else
        If $bHistCreate Then
            $hist = Call("_cve" & $typeOfHist & "Create", $hist)
        EndIf
        $oArrHist = Call("_cveOutputArrayFrom" & $typeOfHist, $hist)
    EndIf

    Local $iArrLevels, $vectorLevels, $iArrLevelsSize
    Local $bLevelsIsArray = IsArray($levels)
    Local $bLevelsCreate = IsDllStruct($levels) And $typeOfLevels == "Scalar"

    If $typeOfLevels == Default Then
        $iArrLevels = $levels
    ElseIf $bLevelsIsArray Then
        $vectorLevels = Call("_VectorOf" & $typeOfLevels & "Create")

        $iArrLevelsSize = UBound($levels)
        For $i = 0 To $iArrLevelsSize - 1
            Call("_VectorOf" & $typeOfLevels & "Push", $vectorLevels, $levels[$i])
        Next

        $iArrLevels = Call("_cveInputArrayFromVectorOf" & $typeOfLevels, $vectorLevels)
    Else
        If $bLevelsCreate Then
            $levels = Call("_cve" & $typeOfLevels & "Create", $levels)
        EndIf
        $iArrLevels = Call("_cveInputArrayFrom" & $typeOfLevels, $levels)
    EndIf

    _cudaHistRange($iArrSrc, $oArrHist, $iArrLevels, $stream)

    If $bLevelsIsArray Then
        Call("_VectorOf" & $typeOfLevels & "Release", $vectorLevels)
    EndIf

    If $typeOfLevels <> Default Then
        _cveInputArrayRelease($iArrLevels)
        If $bLevelsCreate Then
            Call("_cve" & $typeOfLevels & "Release", $levels)
        EndIf
    EndIf

    If $bHistIsArray Then
        Call("_VectorOf" & $typeOfHist & "Release", $vectorHist)
    EndIf

    If $typeOfHist <> Default Then
        _cveOutputArrayRelease($oArrHist)
        If $bHistCreate Then
            Call("_cve" & $typeOfHist & "Release", $hist)
        EndIf
    EndIf

    If $bSrcIsArray Then
        Call("_VectorOf" & $typeOfSrc & "Release", $vectorSrc)
    EndIf

    If $typeOfSrc <> Default Then
        _cveInputArrayRelease($iArrSrc)
        If $bSrcCreate Then
            Call("_cve" & $typeOfSrc & "Release", $src)
        EndIf
    EndIf
EndFunc   ;==>_cudaHistRangeTyped

Func _cudaHistRangeMat($src, $hist, $levels, $stream)
    ; cudaHistRange using cv::Mat instead of _*Array
    _cudaHistRangeTyped("Mat", $src, "Mat", $hist, "Mat", $levels, $stream)
EndFunc   ;==>_cudaHistRangeMat

Func _cudaBilateralFilter($src, $dst, $kernelSize, $sigmaColor, $sigmaSpatial, $borderMode, $stream)
    ; CVAPI(void) cudaBilateralFilter(cv::_InputArray* src, cv::_OutputArray* dst, int kernelSize, float sigmaColor, float sigmaSpatial, int borderMode, cv::cuda::Stream* stream);

    Local $sSrcDllType
    If IsDllStruct($src) Then
        $sSrcDllType = "struct*"
    Else
        $sSrcDllType = "ptr"
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaBilateralFilter", $sSrcDllType, $src, $sDstDllType, $dst, "int", $kernelSize, "float", $sigmaColor, "float", $sigmaSpatial, "int", $borderMode, $sStreamDllType, $stream), "cudaBilateralFilter", @error)
EndFunc   ;==>_cudaBilateralFilter

Func _cudaBilateralFilterTyped($typeOfSrc, $src, $typeOfDst, $dst, $kernelSize, $sigmaColor, $sigmaSpatial, $borderMode, $stream)

    Local $iArrSrc, $vectorSrc, $iArrSrcSize
    Local $bSrcIsArray = IsArray($src)
    Local $bSrcCreate = IsDllStruct($src) And $typeOfSrc == "Scalar"

    If $typeOfSrc == Default Then
        $iArrSrc = $src
    ElseIf $bSrcIsArray Then
        $vectorSrc = Call("_VectorOf" & $typeOfSrc & "Create")

        $iArrSrcSize = UBound($src)
        For $i = 0 To $iArrSrcSize - 1
            Call("_VectorOf" & $typeOfSrc & "Push", $vectorSrc, $src[$i])
        Next

        $iArrSrc = Call("_cveInputArrayFromVectorOf" & $typeOfSrc, $vectorSrc)
    Else
        If $bSrcCreate Then
            $src = Call("_cve" & $typeOfSrc & "Create", $src)
        EndIf
        $iArrSrc = Call("_cveInputArrayFrom" & $typeOfSrc, $src)
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

    _cudaBilateralFilter($iArrSrc, $oArrDst, $kernelSize, $sigmaColor, $sigmaSpatial, $borderMode, $stream)

    If $bDstIsArray Then
        Call("_VectorOf" & $typeOfDst & "Release", $vectorDst)
    EndIf

    If $typeOfDst <> Default Then
        _cveOutputArrayRelease($oArrDst)
        If $bDstCreate Then
            Call("_cve" & $typeOfDst & "Release", $dst)
        EndIf
    EndIf

    If $bSrcIsArray Then
        Call("_VectorOf" & $typeOfSrc & "Release", $vectorSrc)
    EndIf

    If $typeOfSrc <> Default Then
        _cveInputArrayRelease($iArrSrc)
        If $bSrcCreate Then
            Call("_cve" & $typeOfSrc & "Release", $src)
        EndIf
    EndIf
EndFunc   ;==>_cudaBilateralFilterTyped

Func _cudaBilateralFilterMat($src, $dst, $kernelSize, $sigmaColor, $sigmaSpatial, $borderMode, $stream)
    ; cudaBilateralFilter using cv::Mat instead of _*Array
    _cudaBilateralFilterTyped("Mat", $src, "Mat", $dst, $kernelSize, $sigmaColor, $sigmaSpatial, $borderMode, $stream)
EndFunc   ;==>_cudaBilateralFilterMat

Func _cudaCreateHarrisCorner($srcType, $blockSize, $ksize, $k, $borderType, $sharedPtr)
    ; CVAPI(cv::cuda::CornernessCriteria*) cudaCreateHarrisCorner(int srcType, int blockSize, int ksize, double k, int borderType, cv::Ptr<cv::cuda::CornernessCriteria>** sharedPtr);

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cudaCreateHarrisCorner", "int", $srcType, "int", $blockSize, "int", $ksize, "double", $k, "int", $borderType, $sSharedPtrDllType, $sharedPtr), "cudaCreateHarrisCorner", @error)
EndFunc   ;==>_cudaCreateHarrisCorner

Func _cudaCreateMinEigenValCorner($srcType, $blockSize, $ksize, $borderType, $sharedPtr)
    ; CVAPI(cv::cuda::CornernessCriteria*) cudaCreateMinEigenValCorner(int srcType, int blockSize, int ksize, int borderType, cv::Ptr<cv::cuda::CornernessCriteria>** sharedPtr);

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cudaCreateMinEigenValCorner", "int", $srcType, "int", $blockSize, "int", $ksize, "int", $borderType, $sSharedPtrDllType, $sharedPtr), "cudaCreateMinEigenValCorner", @error)
EndFunc   ;==>_cudaCreateMinEigenValCorner

Func _cudaCornernessCriteriaCompute($detector, $src, $dst, $stream)
    ; CVAPI(void) cudaCornernessCriteriaCompute(cv::Ptr<cv::cuda::CornernessCriteria>* detector, cv::_InputArray* src, cv::_OutputArray* dst, cv::cuda::Stream* stream);

    Local $sDetectorDllType
    If IsDllStruct($detector) Then
        $sDetectorDllType = "struct*"
    Else
        $sDetectorDllType = "ptr"
    EndIf

    Local $sSrcDllType
    If IsDllStruct($src) Then
        $sSrcDllType = "struct*"
    Else
        $sSrcDllType = "ptr"
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaCornernessCriteriaCompute", $sDetectorDllType, $detector, $sSrcDllType, $src, $sDstDllType, $dst, $sStreamDllType, $stream), "cudaCornernessCriteriaCompute", @error)
EndFunc   ;==>_cudaCornernessCriteriaCompute

Func _cudaCornernessCriteriaComputeTyped($detector, $typeOfSrc, $src, $typeOfDst, $dst, $stream)

    Local $iArrSrc, $vectorSrc, $iArrSrcSize
    Local $bSrcIsArray = IsArray($src)
    Local $bSrcCreate = IsDllStruct($src) And $typeOfSrc == "Scalar"

    If $typeOfSrc == Default Then
        $iArrSrc = $src
    ElseIf $bSrcIsArray Then
        $vectorSrc = Call("_VectorOf" & $typeOfSrc & "Create")

        $iArrSrcSize = UBound($src)
        For $i = 0 To $iArrSrcSize - 1
            Call("_VectorOf" & $typeOfSrc & "Push", $vectorSrc, $src[$i])
        Next

        $iArrSrc = Call("_cveInputArrayFromVectorOf" & $typeOfSrc, $vectorSrc)
    Else
        If $bSrcCreate Then
            $src = Call("_cve" & $typeOfSrc & "Create", $src)
        EndIf
        $iArrSrc = Call("_cveInputArrayFrom" & $typeOfSrc, $src)
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

    _cudaCornernessCriteriaCompute($detector, $iArrSrc, $oArrDst, $stream)

    If $bDstIsArray Then
        Call("_VectorOf" & $typeOfDst & "Release", $vectorDst)
    EndIf

    If $typeOfDst <> Default Then
        _cveOutputArrayRelease($oArrDst)
        If $bDstCreate Then
            Call("_cve" & $typeOfDst & "Release", $dst)
        EndIf
    EndIf

    If $bSrcIsArray Then
        Call("_VectorOf" & $typeOfSrc & "Release", $vectorSrc)
    EndIf

    If $typeOfSrc <> Default Then
        _cveInputArrayRelease($iArrSrc)
        If $bSrcCreate Then
            Call("_cve" & $typeOfSrc & "Release", $src)
        EndIf
    EndIf
EndFunc   ;==>_cudaCornernessCriteriaComputeTyped

Func _cudaCornernessCriteriaComputeMat($detector, $src, $dst, $stream)
    ; cudaCornernessCriteriaCompute using cv::Mat instead of _*Array
    _cudaCornernessCriteriaComputeTyped($detector, "Mat", $src, "Mat", $dst, $stream)
EndFunc   ;==>_cudaCornernessCriteriaComputeMat

Func _cudaCornernessCriteriaRelease($detector)
    ; CVAPI(void) cudaCornernessCriteriaRelease(cv::Ptr<cv::cuda::CornernessCriteria>** detector);

    Local $sDetectorDllType
    If IsDllStruct($detector) Then
        $sDetectorDllType = "struct*"
    ElseIf $detector == Null Then
        $sDetectorDllType = "ptr"
    Else
        $sDetectorDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaCornernessCriteriaRelease", $sDetectorDllType, $detector), "cudaCornernessCriteriaRelease", @error)
EndFunc   ;==>_cudaCornernessCriteriaRelease

Func _cudaCLAHECreate($clipLimit, $tileGridSize, $sharedPtr)
    ; CVAPI(cv::cuda::CLAHE*) cudaCLAHECreate(double clipLimit, CvSize* tileGridSize, cv::Ptr<cv::cuda::CLAHE>** sharedPtr);

    Local $sTileGridSizeDllType
    If IsDllStruct($tileGridSize) Then
        $sTileGridSizeDllType = "struct*"
    Else
        $sTileGridSizeDllType = "ptr"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cudaCLAHECreate", "double", $clipLimit, $sTileGridSizeDllType, $tileGridSize, $sSharedPtrDllType, $sharedPtr), "cudaCLAHECreate", @error)
EndFunc   ;==>_cudaCLAHECreate

Func _cudaCLAHEApply($clahe, $src, $dst, $stream)
    ; CVAPI(void) cudaCLAHEApply(cv::cuda::CLAHE* clahe, cv::_InputArray* src, cv::_OutputArray* dst, cv::cuda::Stream* stream);

    Local $sClaheDllType
    If IsDllStruct($clahe) Then
        $sClaheDllType = "struct*"
    Else
        $sClaheDllType = "ptr"
    EndIf

    Local $sSrcDllType
    If IsDllStruct($src) Then
        $sSrcDllType = "struct*"
    Else
        $sSrcDllType = "ptr"
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaCLAHEApply", $sClaheDllType, $clahe, $sSrcDllType, $src, $sDstDllType, $dst, $sStreamDllType, $stream), "cudaCLAHEApply", @error)
EndFunc   ;==>_cudaCLAHEApply

Func _cudaCLAHEApplyTyped($clahe, $typeOfSrc, $src, $typeOfDst, $dst, $stream)

    Local $iArrSrc, $vectorSrc, $iArrSrcSize
    Local $bSrcIsArray = IsArray($src)
    Local $bSrcCreate = IsDllStruct($src) And $typeOfSrc == "Scalar"

    If $typeOfSrc == Default Then
        $iArrSrc = $src
    ElseIf $bSrcIsArray Then
        $vectorSrc = Call("_VectorOf" & $typeOfSrc & "Create")

        $iArrSrcSize = UBound($src)
        For $i = 0 To $iArrSrcSize - 1
            Call("_VectorOf" & $typeOfSrc & "Push", $vectorSrc, $src[$i])
        Next

        $iArrSrc = Call("_cveInputArrayFromVectorOf" & $typeOfSrc, $vectorSrc)
    Else
        If $bSrcCreate Then
            $src = Call("_cve" & $typeOfSrc & "Create", $src)
        EndIf
        $iArrSrc = Call("_cveInputArrayFrom" & $typeOfSrc, $src)
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

    _cudaCLAHEApply($clahe, $iArrSrc, $oArrDst, $stream)

    If $bDstIsArray Then
        Call("_VectorOf" & $typeOfDst & "Release", $vectorDst)
    EndIf

    If $typeOfDst <> Default Then
        _cveOutputArrayRelease($oArrDst)
        If $bDstCreate Then
            Call("_cve" & $typeOfDst & "Release", $dst)
        EndIf
    EndIf

    If $bSrcIsArray Then
        Call("_VectorOf" & $typeOfSrc & "Release", $vectorSrc)
    EndIf

    If $typeOfSrc <> Default Then
        _cveInputArrayRelease($iArrSrc)
        If $bSrcCreate Then
            Call("_cve" & $typeOfSrc & "Release", $src)
        EndIf
    EndIf
EndFunc   ;==>_cudaCLAHEApplyTyped

Func _cudaCLAHEApplyMat($clahe, $src, $dst, $stream)
    ; cudaCLAHEApply using cv::Mat instead of _*Array
    _cudaCLAHEApplyTyped($clahe, "Mat", $src, "Mat", $dst, $stream)
EndFunc   ;==>_cudaCLAHEApplyMat

Func _cudaCLAHERelease($clahe)
    ; CVAPI(void) cudaCLAHERelease(cv::Ptr<cv::cuda::CLAHE>** clahe);

    Local $sClaheDllType
    If IsDllStruct($clahe) Then
        $sClaheDllType = "struct*"
    ElseIf $clahe == Null Then
        $sClaheDllType = "ptr"
    Else
        $sClaheDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaCLAHERelease", $sClaheDllType, $clahe), "cudaCLAHERelease", @error)
EndFunc   ;==>_cudaCLAHERelease

Func _cudaCreateCannyEdgeDetector($lowThreshold, $highThreshold, $apertureSize, $L2gradient, $sharedPtr)
    ; CVAPI(cv::cuda::CannyEdgeDetector*) cudaCreateCannyEdgeDetector(double lowThreshold, double highThreshold, int apertureSize, bool L2gradient, cv::Ptr<cv::cuda::CannyEdgeDetector>** sharedPtr);

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cudaCreateCannyEdgeDetector", "double", $lowThreshold, "double", $highThreshold, "int", $apertureSize, "boolean", $L2gradient, $sSharedPtrDllType, $sharedPtr), "cudaCreateCannyEdgeDetector", @error)
EndFunc   ;==>_cudaCreateCannyEdgeDetector

Func _cudaCannyEdgeDetectorDetect($detector, $src, $edges, $stream)
    ; CVAPI(void) cudaCannyEdgeDetectorDetect(cv::cuda::CannyEdgeDetector* detector, cv::_InputArray* src, cv::_OutputArray* edges, cv::cuda::Stream* stream);

    Local $sDetectorDllType
    If IsDllStruct($detector) Then
        $sDetectorDllType = "struct*"
    Else
        $sDetectorDllType = "ptr"
    EndIf

    Local $sSrcDllType
    If IsDllStruct($src) Then
        $sSrcDllType = "struct*"
    Else
        $sSrcDllType = "ptr"
    EndIf

    Local $sEdgesDllType
    If IsDllStruct($edges) Then
        $sEdgesDllType = "struct*"
    Else
        $sEdgesDllType = "ptr"
    EndIf

    Local $sStreamDllType
    If IsDllStruct($stream) Then
        $sStreamDllType = "struct*"
    Else
        $sStreamDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaCannyEdgeDetectorDetect", $sDetectorDllType, $detector, $sSrcDllType, $src, $sEdgesDllType, $edges, $sStreamDllType, $stream), "cudaCannyEdgeDetectorDetect", @error)
EndFunc   ;==>_cudaCannyEdgeDetectorDetect

Func _cudaCannyEdgeDetectorDetectTyped($detector, $typeOfSrc, $src, $typeOfEdges, $edges, $stream)

    Local $iArrSrc, $vectorSrc, $iArrSrcSize
    Local $bSrcIsArray = IsArray($src)
    Local $bSrcCreate = IsDllStruct($src) And $typeOfSrc == "Scalar"

    If $typeOfSrc == Default Then
        $iArrSrc = $src
    ElseIf $bSrcIsArray Then
        $vectorSrc = Call("_VectorOf" & $typeOfSrc & "Create")

        $iArrSrcSize = UBound($src)
        For $i = 0 To $iArrSrcSize - 1
            Call("_VectorOf" & $typeOfSrc & "Push", $vectorSrc, $src[$i])
        Next

        $iArrSrc = Call("_cveInputArrayFromVectorOf" & $typeOfSrc, $vectorSrc)
    Else
        If $bSrcCreate Then
            $src = Call("_cve" & $typeOfSrc & "Create", $src)
        EndIf
        $iArrSrc = Call("_cveInputArrayFrom" & $typeOfSrc, $src)
    EndIf

    Local $oArrEdges, $vectorEdges, $iArrEdgesSize
    Local $bEdgesIsArray = IsArray($edges)
    Local $bEdgesCreate = IsDllStruct($edges) And $typeOfEdges == "Scalar"

    If $typeOfEdges == Default Then
        $oArrEdges = $edges
    ElseIf $bEdgesIsArray Then
        $vectorEdges = Call("_VectorOf" & $typeOfEdges & "Create")

        $iArrEdgesSize = UBound($edges)
        For $i = 0 To $iArrEdgesSize - 1
            Call("_VectorOf" & $typeOfEdges & "Push", $vectorEdges, $edges[$i])
        Next

        $oArrEdges = Call("_cveOutputArrayFromVectorOf" & $typeOfEdges, $vectorEdges)
    Else
        If $bEdgesCreate Then
            $edges = Call("_cve" & $typeOfEdges & "Create", $edges)
        EndIf
        $oArrEdges = Call("_cveOutputArrayFrom" & $typeOfEdges, $edges)
    EndIf

    _cudaCannyEdgeDetectorDetect($detector, $iArrSrc, $oArrEdges, $stream)

    If $bEdgesIsArray Then
        Call("_VectorOf" & $typeOfEdges & "Release", $vectorEdges)
    EndIf

    If $typeOfEdges <> Default Then
        _cveOutputArrayRelease($oArrEdges)
        If $bEdgesCreate Then
            Call("_cve" & $typeOfEdges & "Release", $edges)
        EndIf
    EndIf

    If $bSrcIsArray Then
        Call("_VectorOf" & $typeOfSrc & "Release", $vectorSrc)
    EndIf

    If $typeOfSrc <> Default Then
        _cveInputArrayRelease($iArrSrc)
        If $bSrcCreate Then
            Call("_cve" & $typeOfSrc & "Release", $src)
        EndIf
    EndIf
EndFunc   ;==>_cudaCannyEdgeDetectorDetectTyped

Func _cudaCannyEdgeDetectorDetectMat($detector, $src, $edges, $stream)
    ; cudaCannyEdgeDetectorDetect using cv::Mat instead of _*Array
    _cudaCannyEdgeDetectorDetectTyped($detector, "Mat", $src, "Mat", $edges, $stream)
EndFunc   ;==>_cudaCannyEdgeDetectorDetectMat

Func _cudaCannyEdgeDetectorRelease($detector)
    ; CVAPI(void) cudaCannyEdgeDetectorRelease(cv::Ptr<cv::cuda::CannyEdgeDetector>** detector);

    Local $sDetectorDllType
    If IsDllStruct($detector) Then
        $sDetectorDllType = "struct*"
    ElseIf $detector == Null Then
        $sDetectorDllType = "ptr"
    Else
        $sDetectorDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaCannyEdgeDetectorRelease", $sDetectorDllType, $detector), "cudaCannyEdgeDetectorRelease", @error)
EndFunc   ;==>_cudaCannyEdgeDetectorRelease

Func _cudaGoodFeaturesToTrackDetectorCreate($srcType, $maxCorners, $qualityLevel, $minDistance, $blockSize, $useHarrisDetector, $harrisK, $sharedPtr)
    ; CVAPI(cv::cuda::CornersDetector*) cudaGoodFeaturesToTrackDetectorCreate(int srcType, int maxCorners, double qualityLevel, double minDistance, int blockSize, bool useHarrisDetector, double harrisK, cv::Ptr<cv::cuda::CornersDetector>** sharedPtr);

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cudaGoodFeaturesToTrackDetectorCreate", "int", $srcType, "int", $maxCorners, "double", $qualityLevel, "double", $minDistance, "int", $blockSize, "boolean", $useHarrisDetector, "double", $harrisK, $sSharedPtrDllType, $sharedPtr), "cudaGoodFeaturesToTrackDetectorCreate", @error)
EndFunc   ;==>_cudaGoodFeaturesToTrackDetectorCreate

Func _cudaCornersDetectorDetect($detector, $image, $corners, $mask, $stream)
    ; CVAPI(void) cudaCornersDetectorDetect(cv::cuda::CornersDetector* detector, cv::_InputArray* image, cv::_OutputArray* corners, cv::_InputArray* mask, cv::cuda::Stream* stream);

    Local $sDetectorDllType
    If IsDllStruct($detector) Then
        $sDetectorDllType = "struct*"
    Else
        $sDetectorDllType = "ptr"
    EndIf

    Local $sImageDllType
    If IsDllStruct($image) Then
        $sImageDllType = "struct*"
    Else
        $sImageDllType = "ptr"
    EndIf

    Local $sCornersDllType
    If IsDllStruct($corners) Then
        $sCornersDllType = "struct*"
    Else
        $sCornersDllType = "ptr"
    EndIf

    Local $sMaskDllType
    If IsDllStruct($mask) Then
        $sMaskDllType = "struct*"
    Else
        $sMaskDllType = "ptr"
    EndIf

    Local $sStreamDllType
    If IsDllStruct($stream) Then
        $sStreamDllType = "struct*"
    Else
        $sStreamDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaCornersDetectorDetect", $sDetectorDllType, $detector, $sImageDllType, $image, $sCornersDllType, $corners, $sMaskDllType, $mask, $sStreamDllType, $stream), "cudaCornersDetectorDetect", @error)
EndFunc   ;==>_cudaCornersDetectorDetect

Func _cudaCornersDetectorDetectTyped($detector, $typeOfImage, $image, $typeOfCorners, $corners, $typeOfMask, $mask, $stream)

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

    Local $oArrCorners, $vectorCorners, $iArrCornersSize
    Local $bCornersIsArray = IsArray($corners)
    Local $bCornersCreate = IsDllStruct($corners) And $typeOfCorners == "Scalar"

    If $typeOfCorners == Default Then
        $oArrCorners = $corners
    ElseIf $bCornersIsArray Then
        $vectorCorners = Call("_VectorOf" & $typeOfCorners & "Create")

        $iArrCornersSize = UBound($corners)
        For $i = 0 To $iArrCornersSize - 1
            Call("_VectorOf" & $typeOfCorners & "Push", $vectorCorners, $corners[$i])
        Next

        $oArrCorners = Call("_cveOutputArrayFromVectorOf" & $typeOfCorners, $vectorCorners)
    Else
        If $bCornersCreate Then
            $corners = Call("_cve" & $typeOfCorners & "Create", $corners)
        EndIf
        $oArrCorners = Call("_cveOutputArrayFrom" & $typeOfCorners, $corners)
    EndIf

    Local $iArrMask, $vectorMask, $iArrMaskSize
    Local $bMaskIsArray = IsArray($mask)
    Local $bMaskCreate = IsDllStruct($mask) And $typeOfMask == "Scalar"

    If $typeOfMask == Default Then
        $iArrMask = $mask
    ElseIf $bMaskIsArray Then
        $vectorMask = Call("_VectorOf" & $typeOfMask & "Create")

        $iArrMaskSize = UBound($mask)
        For $i = 0 To $iArrMaskSize - 1
            Call("_VectorOf" & $typeOfMask & "Push", $vectorMask, $mask[$i])
        Next

        $iArrMask = Call("_cveInputArrayFromVectorOf" & $typeOfMask, $vectorMask)
    Else
        If $bMaskCreate Then
            $mask = Call("_cve" & $typeOfMask & "Create", $mask)
        EndIf
        $iArrMask = Call("_cveInputArrayFrom" & $typeOfMask, $mask)
    EndIf

    _cudaCornersDetectorDetect($detector, $iArrImage, $oArrCorners, $iArrMask, $stream)

    If $bMaskIsArray Then
        Call("_VectorOf" & $typeOfMask & "Release", $vectorMask)
    EndIf

    If $typeOfMask <> Default Then
        _cveInputArrayRelease($iArrMask)
        If $bMaskCreate Then
            Call("_cve" & $typeOfMask & "Release", $mask)
        EndIf
    EndIf

    If $bCornersIsArray Then
        Call("_VectorOf" & $typeOfCorners & "Release", $vectorCorners)
    EndIf

    If $typeOfCorners <> Default Then
        _cveOutputArrayRelease($oArrCorners)
        If $bCornersCreate Then
            Call("_cve" & $typeOfCorners & "Release", $corners)
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
EndFunc   ;==>_cudaCornersDetectorDetectTyped

Func _cudaCornersDetectorDetectMat($detector, $image, $corners, $mask, $stream)
    ; cudaCornersDetectorDetect using cv::Mat instead of _*Array
    _cudaCornersDetectorDetectTyped($detector, "Mat", $image, "Mat", $corners, "Mat", $mask, $stream)
EndFunc   ;==>_cudaCornersDetectorDetectMat

Func _cudaCornersDetectorRelease($detector)
    ; CVAPI(void) cudaCornersDetectorRelease(cv::Ptr<cv::cuda::CornersDetector>** detector);

    Local $sDetectorDllType
    If IsDllStruct($detector) Then
        $sDetectorDllType = "struct*"
    ElseIf $detector == Null Then
        $sDetectorDllType = "ptr"
    Else
        $sDetectorDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaCornersDetectorRelease", $sDetectorDllType, $detector), "cudaCornersDetectorRelease", @error)
EndFunc   ;==>_cudaCornersDetectorRelease

Func _cudaTemplateMatchingCreate($srcType, $method, $blockSize, $sharedPtr)
    ; CVAPI(cv::cuda::TemplateMatching*) cudaTemplateMatchingCreate(int srcType, int method, CvSize* blockSize, cv::Ptr<cv::cuda::TemplateMatching>** sharedPtr);

    Local $sBlockSizeDllType
    If IsDllStruct($blockSize) Then
        $sBlockSizeDllType = "struct*"
    Else
        $sBlockSizeDllType = "ptr"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cudaTemplateMatchingCreate", "int", $srcType, "int", $method, $sBlockSizeDllType, $blockSize, $sSharedPtrDllType, $sharedPtr), "cudaTemplateMatchingCreate", @error)
EndFunc   ;==>_cudaTemplateMatchingCreate

Func _cudaTemplateMatchingRelease($tm)
    ; CVAPI(void) cudaTemplateMatchingRelease(cv::Ptr<cv::cuda::TemplateMatching>** tm);

    Local $sTmDllType
    If IsDllStruct($tm) Then
        $sTmDllType = "struct*"
    ElseIf $tm == Null Then
        $sTmDllType = "ptr"
    Else
        $sTmDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaTemplateMatchingRelease", $sTmDllType, $tm), "cudaTemplateMatchingRelease", @error)
EndFunc   ;==>_cudaTemplateMatchingRelease

Func _cudaTemplateMatchingMatch($tm, $image, $templ, $result, $stream)
    ; CVAPI(void) cudaTemplateMatchingMatch(cv::cuda::TemplateMatching* tm, cv::_InputArray* image, cv::_InputArray* templ, cv::_OutputArray* result, cv::cuda::Stream* stream);

    Local $sTmDllType
    If IsDllStruct($tm) Then
        $sTmDllType = "struct*"
    Else
        $sTmDllType = "ptr"
    EndIf

    Local $sImageDllType
    If IsDllStruct($image) Then
        $sImageDllType = "struct*"
    Else
        $sImageDllType = "ptr"
    EndIf

    Local $sTemplDllType
    If IsDllStruct($templ) Then
        $sTemplDllType = "struct*"
    Else
        $sTemplDllType = "ptr"
    EndIf

    Local $sResultDllType
    If IsDllStruct($result) Then
        $sResultDllType = "struct*"
    Else
        $sResultDllType = "ptr"
    EndIf

    Local $sStreamDllType
    If IsDllStruct($stream) Then
        $sStreamDllType = "struct*"
    Else
        $sStreamDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaTemplateMatchingMatch", $sTmDllType, $tm, $sImageDllType, $image, $sTemplDllType, $templ, $sResultDllType, $result, $sStreamDllType, $stream), "cudaTemplateMatchingMatch", @error)
EndFunc   ;==>_cudaTemplateMatchingMatch

Func _cudaTemplateMatchingMatchTyped($tm, $typeOfImage, $image, $typeOfTempl, $templ, $typeOfResult, $result, $stream)

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

    Local $iArrTempl, $vectorTempl, $iArrTemplSize
    Local $bTemplIsArray = IsArray($templ)
    Local $bTemplCreate = IsDllStruct($templ) And $typeOfTempl == "Scalar"

    If $typeOfTempl == Default Then
        $iArrTempl = $templ
    ElseIf $bTemplIsArray Then
        $vectorTempl = Call("_VectorOf" & $typeOfTempl & "Create")

        $iArrTemplSize = UBound($templ)
        For $i = 0 To $iArrTemplSize - 1
            Call("_VectorOf" & $typeOfTempl & "Push", $vectorTempl, $templ[$i])
        Next

        $iArrTempl = Call("_cveInputArrayFromVectorOf" & $typeOfTempl, $vectorTempl)
    Else
        If $bTemplCreate Then
            $templ = Call("_cve" & $typeOfTempl & "Create", $templ)
        EndIf
        $iArrTempl = Call("_cveInputArrayFrom" & $typeOfTempl, $templ)
    EndIf

    Local $oArrResult, $vectorResult, $iArrResultSize
    Local $bResultIsArray = IsArray($result)
    Local $bResultCreate = IsDllStruct($result) And $typeOfResult == "Scalar"

    If $typeOfResult == Default Then
        $oArrResult = $result
    ElseIf $bResultIsArray Then
        $vectorResult = Call("_VectorOf" & $typeOfResult & "Create")

        $iArrResultSize = UBound($result)
        For $i = 0 To $iArrResultSize - 1
            Call("_VectorOf" & $typeOfResult & "Push", $vectorResult, $result[$i])
        Next

        $oArrResult = Call("_cveOutputArrayFromVectorOf" & $typeOfResult, $vectorResult)
    Else
        If $bResultCreate Then
            $result = Call("_cve" & $typeOfResult & "Create", $result)
        EndIf
        $oArrResult = Call("_cveOutputArrayFrom" & $typeOfResult, $result)
    EndIf

    _cudaTemplateMatchingMatch($tm, $iArrImage, $iArrTempl, $oArrResult, $stream)

    If $bResultIsArray Then
        Call("_VectorOf" & $typeOfResult & "Release", $vectorResult)
    EndIf

    If $typeOfResult <> Default Then
        _cveOutputArrayRelease($oArrResult)
        If $bResultCreate Then
            Call("_cve" & $typeOfResult & "Release", $result)
        EndIf
    EndIf

    If $bTemplIsArray Then
        Call("_VectorOf" & $typeOfTempl & "Release", $vectorTempl)
    EndIf

    If $typeOfTempl <> Default Then
        _cveInputArrayRelease($iArrTempl)
        If $bTemplCreate Then
            Call("_cve" & $typeOfTempl & "Release", $templ)
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
EndFunc   ;==>_cudaTemplateMatchingMatchTyped

Func _cudaTemplateMatchingMatchMat($tm, $image, $templ, $result, $stream)
    ; cudaTemplateMatchingMatch using cv::Mat instead of _*Array
    _cudaTemplateMatchingMatchTyped($tm, "Mat", $image, "Mat", $templ, "Mat", $result, $stream)
EndFunc   ;==>_cudaTemplateMatchingMatchMat

Func _cudaHoughLinesDetectorCreate($rho, $theta, $threshold, $doSort, $maxLines, $sharedPtr)
    ; CVAPI(cv::cuda::HoughLinesDetector*) cudaHoughLinesDetectorCreate(float rho, float theta, int threshold, bool doSort, int maxLines, cv::Ptr<cv::cuda::HoughLinesDetector>** sharedPtr);

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cudaHoughLinesDetectorCreate", "float", $rho, "float", $theta, "int", $threshold, "boolean", $doSort, "int", $maxLines, $sSharedPtrDllType, $sharedPtr), "cudaHoughLinesDetectorCreate", @error)
EndFunc   ;==>_cudaHoughLinesDetectorCreate

Func _cudaHoughLinesDetectorDetect($detector, $src, $lines, $stream)
    ; CVAPI(void) cudaHoughLinesDetectorDetect(cv::cuda::HoughLinesDetector* detector, cv::_InputArray* src, cv::_OutputArray* lines, cv::cuda::Stream* stream);

    Local $sDetectorDllType
    If IsDllStruct($detector) Then
        $sDetectorDllType = "struct*"
    Else
        $sDetectorDllType = "ptr"
    EndIf

    Local $sSrcDllType
    If IsDllStruct($src) Then
        $sSrcDllType = "struct*"
    Else
        $sSrcDllType = "ptr"
    EndIf

    Local $sLinesDllType
    If IsDllStruct($lines) Then
        $sLinesDllType = "struct*"
    Else
        $sLinesDllType = "ptr"
    EndIf

    Local $sStreamDllType
    If IsDllStruct($stream) Then
        $sStreamDllType = "struct*"
    Else
        $sStreamDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaHoughLinesDetectorDetect", $sDetectorDllType, $detector, $sSrcDllType, $src, $sLinesDllType, $lines, $sStreamDllType, $stream), "cudaHoughLinesDetectorDetect", @error)
EndFunc   ;==>_cudaHoughLinesDetectorDetect

Func _cudaHoughLinesDetectorDetectTyped($detector, $typeOfSrc, $src, $typeOfLines, $lines, $stream)

    Local $iArrSrc, $vectorSrc, $iArrSrcSize
    Local $bSrcIsArray = IsArray($src)
    Local $bSrcCreate = IsDllStruct($src) And $typeOfSrc == "Scalar"

    If $typeOfSrc == Default Then
        $iArrSrc = $src
    ElseIf $bSrcIsArray Then
        $vectorSrc = Call("_VectorOf" & $typeOfSrc & "Create")

        $iArrSrcSize = UBound($src)
        For $i = 0 To $iArrSrcSize - 1
            Call("_VectorOf" & $typeOfSrc & "Push", $vectorSrc, $src[$i])
        Next

        $iArrSrc = Call("_cveInputArrayFromVectorOf" & $typeOfSrc, $vectorSrc)
    Else
        If $bSrcCreate Then
            $src = Call("_cve" & $typeOfSrc & "Create", $src)
        EndIf
        $iArrSrc = Call("_cveInputArrayFrom" & $typeOfSrc, $src)
    EndIf

    Local $oArrLines, $vectorLines, $iArrLinesSize
    Local $bLinesIsArray = IsArray($lines)
    Local $bLinesCreate = IsDllStruct($lines) And $typeOfLines == "Scalar"

    If $typeOfLines == Default Then
        $oArrLines = $lines
    ElseIf $bLinesIsArray Then
        $vectorLines = Call("_VectorOf" & $typeOfLines & "Create")

        $iArrLinesSize = UBound($lines)
        For $i = 0 To $iArrLinesSize - 1
            Call("_VectorOf" & $typeOfLines & "Push", $vectorLines, $lines[$i])
        Next

        $oArrLines = Call("_cveOutputArrayFromVectorOf" & $typeOfLines, $vectorLines)
    Else
        If $bLinesCreate Then
            $lines = Call("_cve" & $typeOfLines & "Create", $lines)
        EndIf
        $oArrLines = Call("_cveOutputArrayFrom" & $typeOfLines, $lines)
    EndIf

    _cudaHoughLinesDetectorDetect($detector, $iArrSrc, $oArrLines, $stream)

    If $bLinesIsArray Then
        Call("_VectorOf" & $typeOfLines & "Release", $vectorLines)
    EndIf

    If $typeOfLines <> Default Then
        _cveOutputArrayRelease($oArrLines)
        If $bLinesCreate Then
            Call("_cve" & $typeOfLines & "Release", $lines)
        EndIf
    EndIf

    If $bSrcIsArray Then
        Call("_VectorOf" & $typeOfSrc & "Release", $vectorSrc)
    EndIf

    If $typeOfSrc <> Default Then
        _cveInputArrayRelease($iArrSrc)
        If $bSrcCreate Then
            Call("_cve" & $typeOfSrc & "Release", $src)
        EndIf
    EndIf
EndFunc   ;==>_cudaHoughLinesDetectorDetectTyped

Func _cudaHoughLinesDetectorDetectMat($detector, $src, $lines, $stream)
    ; cudaHoughLinesDetectorDetect using cv::Mat instead of _*Array
    _cudaHoughLinesDetectorDetectTyped($detector, "Mat", $src, "Mat", $lines, $stream)
EndFunc   ;==>_cudaHoughLinesDetectorDetectMat

Func _cudaHoughLinesDetectorRelease($detector)
    ; CVAPI(void) cudaHoughLinesDetectorRelease(cv::Ptr<cv::cuda::HoughLinesDetector>** detector);

    Local $sDetectorDllType
    If IsDllStruct($detector) Then
        $sDetectorDllType = "struct*"
    ElseIf $detector == Null Then
        $sDetectorDllType = "ptr"
    Else
        $sDetectorDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaHoughLinesDetectorRelease", $sDetectorDllType, $detector), "cudaHoughLinesDetectorRelease", @error)
EndFunc   ;==>_cudaHoughLinesDetectorRelease

Func _cudaHoughSegmentDetectorCreate($rho, $theta, $minLineLength, $maxLineGap, $maxLines, $sharedPtr)
    ; CVAPI(cv::cuda::HoughSegmentDetector*) cudaHoughSegmentDetectorCreate(float rho, float theta, int minLineLength, int maxLineGap, int maxLines, cv::Ptr<cv::cuda::HoughSegmentDetector>** sharedPtr);

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cudaHoughSegmentDetectorCreate", "float", $rho, "float", $theta, "int", $minLineLength, "int", $maxLineGap, "int", $maxLines, $sSharedPtrDllType, $sharedPtr), "cudaHoughSegmentDetectorCreate", @error)
EndFunc   ;==>_cudaHoughSegmentDetectorCreate

Func _cudaHoughSegmentDetectorDetect($detector, $src, $lines, $stream)
    ; CVAPI(void) cudaHoughSegmentDetectorDetect(cv::cuda::HoughSegmentDetector* detector, cv::_InputArray* src, cv::_OutputArray* lines, cv::cuda::Stream* stream);

    Local $sDetectorDllType
    If IsDllStruct($detector) Then
        $sDetectorDllType = "struct*"
    Else
        $sDetectorDllType = "ptr"
    EndIf

    Local $sSrcDllType
    If IsDllStruct($src) Then
        $sSrcDllType = "struct*"
    Else
        $sSrcDllType = "ptr"
    EndIf

    Local $sLinesDllType
    If IsDllStruct($lines) Then
        $sLinesDllType = "struct*"
    Else
        $sLinesDllType = "ptr"
    EndIf

    Local $sStreamDllType
    If IsDllStruct($stream) Then
        $sStreamDllType = "struct*"
    Else
        $sStreamDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaHoughSegmentDetectorDetect", $sDetectorDllType, $detector, $sSrcDllType, $src, $sLinesDllType, $lines, $sStreamDllType, $stream), "cudaHoughSegmentDetectorDetect", @error)
EndFunc   ;==>_cudaHoughSegmentDetectorDetect

Func _cudaHoughSegmentDetectorDetectTyped($detector, $typeOfSrc, $src, $typeOfLines, $lines, $stream)

    Local $iArrSrc, $vectorSrc, $iArrSrcSize
    Local $bSrcIsArray = IsArray($src)
    Local $bSrcCreate = IsDllStruct($src) And $typeOfSrc == "Scalar"

    If $typeOfSrc == Default Then
        $iArrSrc = $src
    ElseIf $bSrcIsArray Then
        $vectorSrc = Call("_VectorOf" & $typeOfSrc & "Create")

        $iArrSrcSize = UBound($src)
        For $i = 0 To $iArrSrcSize - 1
            Call("_VectorOf" & $typeOfSrc & "Push", $vectorSrc, $src[$i])
        Next

        $iArrSrc = Call("_cveInputArrayFromVectorOf" & $typeOfSrc, $vectorSrc)
    Else
        If $bSrcCreate Then
            $src = Call("_cve" & $typeOfSrc & "Create", $src)
        EndIf
        $iArrSrc = Call("_cveInputArrayFrom" & $typeOfSrc, $src)
    EndIf

    Local $oArrLines, $vectorLines, $iArrLinesSize
    Local $bLinesIsArray = IsArray($lines)
    Local $bLinesCreate = IsDllStruct($lines) And $typeOfLines == "Scalar"

    If $typeOfLines == Default Then
        $oArrLines = $lines
    ElseIf $bLinesIsArray Then
        $vectorLines = Call("_VectorOf" & $typeOfLines & "Create")

        $iArrLinesSize = UBound($lines)
        For $i = 0 To $iArrLinesSize - 1
            Call("_VectorOf" & $typeOfLines & "Push", $vectorLines, $lines[$i])
        Next

        $oArrLines = Call("_cveOutputArrayFromVectorOf" & $typeOfLines, $vectorLines)
    Else
        If $bLinesCreate Then
            $lines = Call("_cve" & $typeOfLines & "Create", $lines)
        EndIf
        $oArrLines = Call("_cveOutputArrayFrom" & $typeOfLines, $lines)
    EndIf

    _cudaHoughSegmentDetectorDetect($detector, $iArrSrc, $oArrLines, $stream)

    If $bLinesIsArray Then
        Call("_VectorOf" & $typeOfLines & "Release", $vectorLines)
    EndIf

    If $typeOfLines <> Default Then
        _cveOutputArrayRelease($oArrLines)
        If $bLinesCreate Then
            Call("_cve" & $typeOfLines & "Release", $lines)
        EndIf
    EndIf

    If $bSrcIsArray Then
        Call("_VectorOf" & $typeOfSrc & "Release", $vectorSrc)
    EndIf

    If $typeOfSrc <> Default Then
        _cveInputArrayRelease($iArrSrc)
        If $bSrcCreate Then
            Call("_cve" & $typeOfSrc & "Release", $src)
        EndIf
    EndIf
EndFunc   ;==>_cudaHoughSegmentDetectorDetectTyped

Func _cudaHoughSegmentDetectorDetectMat($detector, $src, $lines, $stream)
    ; cudaHoughSegmentDetectorDetect using cv::Mat instead of _*Array
    _cudaHoughSegmentDetectorDetectTyped($detector, "Mat", $src, "Mat", $lines, $stream)
EndFunc   ;==>_cudaHoughSegmentDetectorDetectMat

Func _cudaHoughSegmentDetectorRelease($detector)
    ; CVAPI(void) cudaHoughSegmentDetectorRelease(cv::Ptr<cv::cuda::HoughSegmentDetector>** detector);

    Local $sDetectorDllType
    If IsDllStruct($detector) Then
        $sDetectorDllType = "struct*"
    ElseIf $detector == Null Then
        $sDetectorDllType = "ptr"
    Else
        $sDetectorDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaHoughSegmentDetectorRelease", $sDetectorDllType, $detector), "cudaHoughSegmentDetectorRelease", @error)
EndFunc   ;==>_cudaHoughSegmentDetectorRelease

Func _cudaHoughCirclesDetectorCreate($dp, $minDist, $cannyThreshold, $votesThreshold, $minRadius, $maxRadius, $maxCircles, $sharedPtr)
    ; CVAPI(cv::cuda::HoughCirclesDetector*) cudaHoughCirclesDetectorCreate(float dp, float minDist, int cannyThreshold, int votesThreshold, int minRadius, int maxRadius, int maxCircles, cv::Ptr<cv::cuda::HoughCirclesDetector>** sharedPtr);

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cudaHoughCirclesDetectorCreate", "float", $dp, "float", $minDist, "int", $cannyThreshold, "int", $votesThreshold, "int", $minRadius, "int", $maxRadius, "int", $maxCircles, $sSharedPtrDllType, $sharedPtr), "cudaHoughCirclesDetectorCreate", @error)
EndFunc   ;==>_cudaHoughCirclesDetectorCreate

Func _cudaHoughCirclesDetectorDetect($detector, $src, $circles, $stream)
    ; CVAPI(void) cudaHoughCirclesDetectorDetect(cv::cuda::HoughCirclesDetector* detector, cv::_InputArray* src, cv::_OutputArray* circles, cv::cuda::Stream* stream);

    Local $sDetectorDllType
    If IsDllStruct($detector) Then
        $sDetectorDllType = "struct*"
    Else
        $sDetectorDllType = "ptr"
    EndIf

    Local $sSrcDllType
    If IsDllStruct($src) Then
        $sSrcDllType = "struct*"
    Else
        $sSrcDllType = "ptr"
    EndIf

    Local $sCirclesDllType
    If IsDllStruct($circles) Then
        $sCirclesDllType = "struct*"
    Else
        $sCirclesDllType = "ptr"
    EndIf

    Local $sStreamDllType
    If IsDllStruct($stream) Then
        $sStreamDllType = "struct*"
    Else
        $sStreamDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaHoughCirclesDetectorDetect", $sDetectorDllType, $detector, $sSrcDllType, $src, $sCirclesDllType, $circles, $sStreamDllType, $stream), "cudaHoughCirclesDetectorDetect", @error)
EndFunc   ;==>_cudaHoughCirclesDetectorDetect

Func _cudaHoughCirclesDetectorDetectTyped($detector, $typeOfSrc, $src, $typeOfCircles, $circles, $stream)

    Local $iArrSrc, $vectorSrc, $iArrSrcSize
    Local $bSrcIsArray = IsArray($src)
    Local $bSrcCreate = IsDllStruct($src) And $typeOfSrc == "Scalar"

    If $typeOfSrc == Default Then
        $iArrSrc = $src
    ElseIf $bSrcIsArray Then
        $vectorSrc = Call("_VectorOf" & $typeOfSrc & "Create")

        $iArrSrcSize = UBound($src)
        For $i = 0 To $iArrSrcSize - 1
            Call("_VectorOf" & $typeOfSrc & "Push", $vectorSrc, $src[$i])
        Next

        $iArrSrc = Call("_cveInputArrayFromVectorOf" & $typeOfSrc, $vectorSrc)
    Else
        If $bSrcCreate Then
            $src = Call("_cve" & $typeOfSrc & "Create", $src)
        EndIf
        $iArrSrc = Call("_cveInputArrayFrom" & $typeOfSrc, $src)
    EndIf

    Local $oArrCircles, $vectorCircles, $iArrCirclesSize
    Local $bCirclesIsArray = IsArray($circles)
    Local $bCirclesCreate = IsDllStruct($circles) And $typeOfCircles == "Scalar"

    If $typeOfCircles == Default Then
        $oArrCircles = $circles
    ElseIf $bCirclesIsArray Then
        $vectorCircles = Call("_VectorOf" & $typeOfCircles & "Create")

        $iArrCirclesSize = UBound($circles)
        For $i = 0 To $iArrCirclesSize - 1
            Call("_VectorOf" & $typeOfCircles & "Push", $vectorCircles, $circles[$i])
        Next

        $oArrCircles = Call("_cveOutputArrayFromVectorOf" & $typeOfCircles, $vectorCircles)
    Else
        If $bCirclesCreate Then
            $circles = Call("_cve" & $typeOfCircles & "Create", $circles)
        EndIf
        $oArrCircles = Call("_cveOutputArrayFrom" & $typeOfCircles, $circles)
    EndIf

    _cudaHoughCirclesDetectorDetect($detector, $iArrSrc, $oArrCircles, $stream)

    If $bCirclesIsArray Then
        Call("_VectorOf" & $typeOfCircles & "Release", $vectorCircles)
    EndIf

    If $typeOfCircles <> Default Then
        _cveOutputArrayRelease($oArrCircles)
        If $bCirclesCreate Then
            Call("_cve" & $typeOfCircles & "Release", $circles)
        EndIf
    EndIf

    If $bSrcIsArray Then
        Call("_VectorOf" & $typeOfSrc & "Release", $vectorSrc)
    EndIf

    If $typeOfSrc <> Default Then
        _cveInputArrayRelease($iArrSrc)
        If $bSrcCreate Then
            Call("_cve" & $typeOfSrc & "Release", $src)
        EndIf
    EndIf
EndFunc   ;==>_cudaHoughCirclesDetectorDetectTyped

Func _cudaHoughCirclesDetectorDetectMat($detector, $src, $circles, $stream)
    ; cudaHoughCirclesDetectorDetect using cv::Mat instead of _*Array
    _cudaHoughCirclesDetectorDetectTyped($detector, "Mat", $src, "Mat", $circles, $stream)
EndFunc   ;==>_cudaHoughCirclesDetectorDetectMat

Func _cudaHoughCirclesDetectorRelease($detector)
    ; CVAPI(void) cudaHoughCirclesDetectorRelease(cv::Ptr<cv::cuda::HoughCirclesDetector>** detector);

    Local $sDetectorDllType
    If IsDllStruct($detector) Then
        $sDetectorDllType = "struct*"
    ElseIf $detector == Null Then
        $sDetectorDllType = "ptr"
    Else
        $sDetectorDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaHoughCirclesDetectorRelease", $sDetectorDllType, $detector), "cudaHoughCirclesDetectorRelease", @error)
EndFunc   ;==>_cudaHoughCirclesDetectorRelease

Func _cudaGammaCorrection($src, $dst, $forward, $stream)
    ; CVAPI(void) cudaGammaCorrection(cv::_InputArray* src, cv::_OutputArray* dst, bool forward, cv::cuda::Stream* stream);

    Local $sSrcDllType
    If IsDllStruct($src) Then
        $sSrcDllType = "struct*"
    Else
        $sSrcDllType = "ptr"
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaGammaCorrection", $sSrcDllType, $src, $sDstDllType, $dst, "boolean", $forward, $sStreamDllType, $stream), "cudaGammaCorrection", @error)
EndFunc   ;==>_cudaGammaCorrection

Func _cudaGammaCorrectionTyped($typeOfSrc, $src, $typeOfDst, $dst, $forward, $stream)

    Local $iArrSrc, $vectorSrc, $iArrSrcSize
    Local $bSrcIsArray = IsArray($src)
    Local $bSrcCreate = IsDllStruct($src) And $typeOfSrc == "Scalar"

    If $typeOfSrc == Default Then
        $iArrSrc = $src
    ElseIf $bSrcIsArray Then
        $vectorSrc = Call("_VectorOf" & $typeOfSrc & "Create")

        $iArrSrcSize = UBound($src)
        For $i = 0 To $iArrSrcSize - 1
            Call("_VectorOf" & $typeOfSrc & "Push", $vectorSrc, $src[$i])
        Next

        $iArrSrc = Call("_cveInputArrayFromVectorOf" & $typeOfSrc, $vectorSrc)
    Else
        If $bSrcCreate Then
            $src = Call("_cve" & $typeOfSrc & "Create", $src)
        EndIf
        $iArrSrc = Call("_cveInputArrayFrom" & $typeOfSrc, $src)
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

    _cudaGammaCorrection($iArrSrc, $oArrDst, $forward, $stream)

    If $bDstIsArray Then
        Call("_VectorOf" & $typeOfDst & "Release", $vectorDst)
    EndIf

    If $typeOfDst <> Default Then
        _cveOutputArrayRelease($oArrDst)
        If $bDstCreate Then
            Call("_cve" & $typeOfDst & "Release", $dst)
        EndIf
    EndIf

    If $bSrcIsArray Then
        Call("_VectorOf" & $typeOfSrc & "Release", $vectorSrc)
    EndIf

    If $typeOfSrc <> Default Then
        _cveInputArrayRelease($iArrSrc)
        If $bSrcCreate Then
            Call("_cve" & $typeOfSrc & "Release", $src)
        EndIf
    EndIf
EndFunc   ;==>_cudaGammaCorrectionTyped

Func _cudaGammaCorrectionMat($src, $dst, $forward, $stream)
    ; cudaGammaCorrection using cv::Mat instead of _*Array
    _cudaGammaCorrectionTyped("Mat", $src, "Mat", $dst, $forward, $stream)
EndFunc   ;==>_cudaGammaCorrectionMat