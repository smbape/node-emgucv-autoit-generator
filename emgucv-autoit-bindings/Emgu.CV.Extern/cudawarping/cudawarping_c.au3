#include-once
#include "..\..\CVEUtils.au3"

Func _cudaPyrDown($src, $dst, $stream)
    ; CVAPI(void) cudaPyrDown(cv::_InputArray* src, cv::_OutputArray* dst, cv::cuda::Stream* stream);

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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaPyrDown", $sSrcDllType, $src, $sDstDllType, $dst, $sStreamDllType, $stream), "cudaPyrDown", @error)
EndFunc   ;==>_cudaPyrDown

Func _cudaPyrDownTyped($typeOfSrc, $src, $typeOfDst, $dst, $stream)

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

    _cudaPyrDown($iArrSrc, $oArrDst, $stream)

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
EndFunc   ;==>_cudaPyrDownTyped

Func _cudaPyrDownMat($src, $dst, $stream)
    ; cudaPyrDown using cv::Mat instead of _*Array
    _cudaPyrDownTyped("Mat", $src, "Mat", $dst, $stream)
EndFunc   ;==>_cudaPyrDownMat

Func _cudaPyrUp($src, $dst, $stream)
    ; CVAPI(void) cudaPyrUp(cv::_InputArray* src, cv::_OutputArray* dst, cv::cuda::Stream* stream);

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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaPyrUp", $sSrcDllType, $src, $sDstDllType, $dst, $sStreamDllType, $stream), "cudaPyrUp", @error)
EndFunc   ;==>_cudaPyrUp

Func _cudaPyrUpTyped($typeOfSrc, $src, $typeOfDst, $dst, $stream)

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

    _cudaPyrUp($iArrSrc, $oArrDst, $stream)

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
EndFunc   ;==>_cudaPyrUpTyped

Func _cudaPyrUpMat($src, $dst, $stream)
    ; cudaPyrUp using cv::Mat instead of _*Array
    _cudaPyrUpTyped("Mat", $src, "Mat", $dst, $stream)
EndFunc   ;==>_cudaPyrUpMat

Func _cudaWarpAffine($src, $dst, $M, $dSize, $flags, $borderMode, $borderValue, $stream)
    ; CVAPI(void) cudaWarpAffine(cv::_InputArray* src, cv::_OutputArray* dst, cv::_InputArray* M, CvSize* dSize, int flags, int borderMode, CvScalar* borderValue, cv::cuda::Stream* stream);

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

    Local $sMDllType
    If IsDllStruct($M) Then
        $sMDllType = "struct*"
    Else
        $sMDllType = "ptr"
    EndIf

    Local $sDSizeDllType
    If IsDllStruct($dSize) Then
        $sDSizeDllType = "struct*"
    Else
        $sDSizeDllType = "ptr"
    EndIf

    Local $sBorderValueDllType
    If IsDllStruct($borderValue) Then
        $sBorderValueDllType = "struct*"
    Else
        $sBorderValueDllType = "ptr"
    EndIf

    Local $sStreamDllType
    If IsDllStruct($stream) Then
        $sStreamDllType = "struct*"
    Else
        $sStreamDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaWarpAffine", $sSrcDllType, $src, $sDstDllType, $dst, $sMDllType, $M, $sDSizeDllType, $dSize, "int", $flags, "int", $borderMode, $sBorderValueDllType, $borderValue, $sStreamDllType, $stream), "cudaWarpAffine", @error)
EndFunc   ;==>_cudaWarpAffine

Func _cudaWarpAffineTyped($typeOfSrc, $src, $typeOfDst, $dst, $typeOfM, $M, $dSize, $flags, $borderMode, $borderValue, $stream)

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

    Local $iArrM, $vectorM, $iArrMSize
    Local $bMIsArray = IsArray($M)
    Local $bMCreate = IsDllStruct($M) And $typeOfM == "Scalar"

    If $typeOfM == Default Then
        $iArrM = $M
    ElseIf $bMIsArray Then
        $vectorM = Call("_VectorOf" & $typeOfM & "Create")

        $iArrMSize = UBound($M)
        For $i = 0 To $iArrMSize - 1
            Call("_VectorOf" & $typeOfM & "Push", $vectorM, $M[$i])
        Next

        $iArrM = Call("_cveInputArrayFromVectorOf" & $typeOfM, $vectorM)
    Else
        If $bMCreate Then
            $M = Call("_cve" & $typeOfM & "Create", $M)
        EndIf
        $iArrM = Call("_cveInputArrayFrom" & $typeOfM, $M)
    EndIf

    _cudaWarpAffine($iArrSrc, $oArrDst, $iArrM, $dSize, $flags, $borderMode, $borderValue, $stream)

    If $bMIsArray Then
        Call("_VectorOf" & $typeOfM & "Release", $vectorM)
    EndIf

    If $typeOfM <> Default Then
        _cveInputArrayRelease($iArrM)
        If $bMCreate Then
            Call("_cve" & $typeOfM & "Release", $M)
        EndIf
    EndIf

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
EndFunc   ;==>_cudaWarpAffineTyped

Func _cudaWarpAffineMat($src, $dst, $M, $dSize, $flags, $borderMode, $borderValue, $stream)
    ; cudaWarpAffine using cv::Mat instead of _*Array
    _cudaWarpAffineTyped("Mat", $src, "Mat", $dst, "Mat", $M, $dSize, $flags, $borderMode, $borderValue, $stream)
EndFunc   ;==>_cudaWarpAffineMat

Func _cudaWarpPerspective($src, $dst, $M, $size, $flags, $borderMode, $borderValue, $stream)
    ; CVAPI(void) cudaWarpPerspective(cv::_InputArray* src, cv::_OutputArray* dst, cv::_InputArray* M, CvSize* size, int flags, int borderMode, CvScalar* borderValue, cv::cuda::Stream* stream);

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

    Local $sMDllType
    If IsDllStruct($M) Then
        $sMDllType = "struct*"
    Else
        $sMDllType = "ptr"
    EndIf

    Local $sSizeDllType
    If IsDllStruct($size) Then
        $sSizeDllType = "struct*"
    Else
        $sSizeDllType = "ptr"
    EndIf

    Local $sBorderValueDllType
    If IsDllStruct($borderValue) Then
        $sBorderValueDllType = "struct*"
    Else
        $sBorderValueDllType = "ptr"
    EndIf

    Local $sStreamDllType
    If IsDllStruct($stream) Then
        $sStreamDllType = "struct*"
    Else
        $sStreamDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaWarpPerspective", $sSrcDllType, $src, $sDstDllType, $dst, $sMDllType, $M, $sSizeDllType, $size, "int", $flags, "int", $borderMode, $sBorderValueDllType, $borderValue, $sStreamDllType, $stream), "cudaWarpPerspective", @error)
EndFunc   ;==>_cudaWarpPerspective

Func _cudaWarpPerspectiveTyped($typeOfSrc, $src, $typeOfDst, $dst, $typeOfM, $M, $size, $flags, $borderMode, $borderValue, $stream)

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

    Local $iArrM, $vectorM, $iArrMSize
    Local $bMIsArray = IsArray($M)
    Local $bMCreate = IsDllStruct($M) And $typeOfM == "Scalar"

    If $typeOfM == Default Then
        $iArrM = $M
    ElseIf $bMIsArray Then
        $vectorM = Call("_VectorOf" & $typeOfM & "Create")

        $iArrMSize = UBound($M)
        For $i = 0 To $iArrMSize - 1
            Call("_VectorOf" & $typeOfM & "Push", $vectorM, $M[$i])
        Next

        $iArrM = Call("_cveInputArrayFromVectorOf" & $typeOfM, $vectorM)
    Else
        If $bMCreate Then
            $M = Call("_cve" & $typeOfM & "Create", $M)
        EndIf
        $iArrM = Call("_cveInputArrayFrom" & $typeOfM, $M)
    EndIf

    _cudaWarpPerspective($iArrSrc, $oArrDst, $iArrM, $size, $flags, $borderMode, $borderValue, $stream)

    If $bMIsArray Then
        Call("_VectorOf" & $typeOfM & "Release", $vectorM)
    EndIf

    If $typeOfM <> Default Then
        _cveInputArrayRelease($iArrM)
        If $bMCreate Then
            Call("_cve" & $typeOfM & "Release", $M)
        EndIf
    EndIf

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
EndFunc   ;==>_cudaWarpPerspectiveTyped

Func _cudaWarpPerspectiveMat($src, $dst, $M, $size, $flags, $borderMode, $borderValue, $stream)
    ; cudaWarpPerspective using cv::Mat instead of _*Array
    _cudaWarpPerspectiveTyped("Mat", $src, "Mat", $dst, "Mat", $M, $size, $flags, $borderMode, $borderValue, $stream)
EndFunc   ;==>_cudaWarpPerspectiveMat

Func _cudaRemap($src, $dst, $xmap, $ymap, $interpolation, $borderMode, $borderValue, $stream)
    ; CVAPI(void) cudaRemap(cv::_InputArray* src, cv::_OutputArray* dst, cv::_InputArray* xmap, cv::_InputArray* ymap, int interpolation, int borderMode, CvScalar* borderValue, cv::cuda::Stream* stream);

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

    Local $sXmapDllType
    If IsDllStruct($xmap) Then
        $sXmapDllType = "struct*"
    Else
        $sXmapDllType = "ptr"
    EndIf

    Local $sYmapDllType
    If IsDllStruct($ymap) Then
        $sYmapDllType = "struct*"
    Else
        $sYmapDllType = "ptr"
    EndIf

    Local $sBorderValueDllType
    If IsDllStruct($borderValue) Then
        $sBorderValueDllType = "struct*"
    Else
        $sBorderValueDllType = "ptr"
    EndIf

    Local $sStreamDllType
    If IsDllStruct($stream) Then
        $sStreamDllType = "struct*"
    Else
        $sStreamDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaRemap", $sSrcDllType, $src, $sDstDllType, $dst, $sXmapDllType, $xmap, $sYmapDllType, $ymap, "int", $interpolation, "int", $borderMode, $sBorderValueDllType, $borderValue, $sStreamDllType, $stream), "cudaRemap", @error)
EndFunc   ;==>_cudaRemap

Func _cudaRemapTyped($typeOfSrc, $src, $typeOfDst, $dst, $typeOfXmap, $xmap, $typeOfYmap, $ymap, $interpolation, $borderMode, $borderValue, $stream)

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

    Local $iArrXmap, $vectorXmap, $iArrXmapSize
    Local $bXmapIsArray = IsArray($xmap)
    Local $bXmapCreate = IsDllStruct($xmap) And $typeOfXmap == "Scalar"

    If $typeOfXmap == Default Then
        $iArrXmap = $xmap
    ElseIf $bXmapIsArray Then
        $vectorXmap = Call("_VectorOf" & $typeOfXmap & "Create")

        $iArrXmapSize = UBound($xmap)
        For $i = 0 To $iArrXmapSize - 1
            Call("_VectorOf" & $typeOfXmap & "Push", $vectorXmap, $xmap[$i])
        Next

        $iArrXmap = Call("_cveInputArrayFromVectorOf" & $typeOfXmap, $vectorXmap)
    Else
        If $bXmapCreate Then
            $xmap = Call("_cve" & $typeOfXmap & "Create", $xmap)
        EndIf
        $iArrXmap = Call("_cveInputArrayFrom" & $typeOfXmap, $xmap)
    EndIf

    Local $iArrYmap, $vectorYmap, $iArrYmapSize
    Local $bYmapIsArray = IsArray($ymap)
    Local $bYmapCreate = IsDllStruct($ymap) And $typeOfYmap == "Scalar"

    If $typeOfYmap == Default Then
        $iArrYmap = $ymap
    ElseIf $bYmapIsArray Then
        $vectorYmap = Call("_VectorOf" & $typeOfYmap & "Create")

        $iArrYmapSize = UBound($ymap)
        For $i = 0 To $iArrYmapSize - 1
            Call("_VectorOf" & $typeOfYmap & "Push", $vectorYmap, $ymap[$i])
        Next

        $iArrYmap = Call("_cveInputArrayFromVectorOf" & $typeOfYmap, $vectorYmap)
    Else
        If $bYmapCreate Then
            $ymap = Call("_cve" & $typeOfYmap & "Create", $ymap)
        EndIf
        $iArrYmap = Call("_cveInputArrayFrom" & $typeOfYmap, $ymap)
    EndIf

    _cudaRemap($iArrSrc, $oArrDst, $iArrXmap, $iArrYmap, $interpolation, $borderMode, $borderValue, $stream)

    If $bYmapIsArray Then
        Call("_VectorOf" & $typeOfYmap & "Release", $vectorYmap)
    EndIf

    If $typeOfYmap <> Default Then
        _cveInputArrayRelease($iArrYmap)
        If $bYmapCreate Then
            Call("_cve" & $typeOfYmap & "Release", $ymap)
        EndIf
    EndIf

    If $bXmapIsArray Then
        Call("_VectorOf" & $typeOfXmap & "Release", $vectorXmap)
    EndIf

    If $typeOfXmap <> Default Then
        _cveInputArrayRelease($iArrXmap)
        If $bXmapCreate Then
            Call("_cve" & $typeOfXmap & "Release", $xmap)
        EndIf
    EndIf

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
EndFunc   ;==>_cudaRemapTyped

Func _cudaRemapMat($src, $dst, $xmap, $ymap, $interpolation, $borderMode, $borderValue, $stream)
    ; cudaRemap using cv::Mat instead of _*Array
    _cudaRemapTyped("Mat", $src, "Mat", $dst, "Mat", $xmap, "Mat", $ymap, $interpolation, $borderMode, $borderValue, $stream)
EndFunc   ;==>_cudaRemapMat

Func _cudaResize($src, $dst, $dsize, $fx, $fy, $interpolation, $stream)
    ; CVAPI(void) cudaResize(cv::_InputArray* src, cv::_OutputArray* dst, CvSize* dsize, double fx, double fy, int interpolation, cv::cuda::Stream* stream);

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

    Local $sDsizeDllType
    If IsDllStruct($dsize) Then
        $sDsizeDllType = "struct*"
    Else
        $sDsizeDllType = "ptr"
    EndIf

    Local $sStreamDllType
    If IsDllStruct($stream) Then
        $sStreamDllType = "struct*"
    Else
        $sStreamDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaResize", $sSrcDllType, $src, $sDstDllType, $dst, $sDsizeDllType, $dsize, "double", $fx, "double", $fy, "int", $interpolation, $sStreamDllType, $stream), "cudaResize", @error)
EndFunc   ;==>_cudaResize

Func _cudaResizeTyped($typeOfSrc, $src, $typeOfDst, $dst, $dsize, $fx, $fy, $interpolation, $stream)

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

    _cudaResize($iArrSrc, $oArrDst, $dsize, $fx, $fy, $interpolation, $stream)

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
EndFunc   ;==>_cudaResizeTyped

Func _cudaResizeMat($src, $dst, $dsize, $fx, $fy, $interpolation, $stream)
    ; cudaResize using cv::Mat instead of _*Array
    _cudaResizeTyped("Mat", $src, "Mat", $dst, $dsize, $fx, $fy, $interpolation, $stream)
EndFunc   ;==>_cudaResizeMat

Func _cudaRotate($src, $dst, $dSize, $angle, $xShift, $yShift, $interpolation, $s)
    ; CVAPI(void) cudaRotate(cv::_InputArray* src, cv::_OutputArray* dst, CvSize* dSize, double angle, double xShift, double yShift, int interpolation, cv::cuda::Stream* s);

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

    Local $sDSizeDllType
    If IsDllStruct($dSize) Then
        $sDSizeDllType = "struct*"
    Else
        $sDSizeDllType = "ptr"
    EndIf

    Local $sSDllType
    If IsDllStruct($s) Then
        $sSDllType = "struct*"
    Else
        $sSDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaRotate", $sSrcDllType, $src, $sDstDllType, $dst, $sDSizeDllType, $dSize, "double", $angle, "double", $xShift, "double", $yShift, "int", $interpolation, $sSDllType, $s), "cudaRotate", @error)
EndFunc   ;==>_cudaRotate

Func _cudaRotateTyped($typeOfSrc, $src, $typeOfDst, $dst, $dSize, $angle, $xShift, $yShift, $interpolation, $s)

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

    _cudaRotate($iArrSrc, $oArrDst, $dSize, $angle, $xShift, $yShift, $interpolation, $s)

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
EndFunc   ;==>_cudaRotateTyped

Func _cudaRotateMat($src, $dst, $dSize, $angle, $xShift, $yShift, $interpolation, $s)
    ; cudaRotate using cv::Mat instead of _*Array
    _cudaRotateTyped("Mat", $src, "Mat", $dst, $dSize, $angle, $xShift, $yShift, $interpolation, $s)
EndFunc   ;==>_cudaRotateMat