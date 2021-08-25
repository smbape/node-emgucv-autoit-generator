#include-once
#include "..\..\CVEUtils.au3"

Func _cveInpaint($src, $inpaintMask, $dst, $inpaintRadius, $flags)
    ; CVAPI(void) cveInpaint(cv::_InputArray* src, cv::_InputArray* inpaintMask, cv::_OutputArray* dst, double inpaintRadius, int flags);

    Local $sSrcDllType
    If IsDllStruct($src) Then
        $sSrcDllType = "struct*"
    Else
        $sSrcDllType = "ptr"
    EndIf

    Local $sInpaintMaskDllType
    If IsDllStruct($inpaintMask) Then
        $sInpaintMaskDllType = "struct*"
    Else
        $sInpaintMaskDllType = "ptr"
    EndIf

    Local $sDstDllType
    If IsDllStruct($dst) Then
        $sDstDllType = "struct*"
    Else
        $sDstDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveInpaint", $sSrcDllType, $src, $sInpaintMaskDllType, $inpaintMask, $sDstDllType, $dst, "double", $inpaintRadius, "int", $flags), "cveInpaint", @error)
EndFunc   ;==>_cveInpaint

Func _cveInpaintTyped($typeOfSrc, $src, $typeOfInpaintMask, $inpaintMask, $typeOfDst, $dst, $inpaintRadius, $flags)

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

    Local $iArrInpaintMask, $vectorInpaintMask, $iArrInpaintMaskSize
    Local $bInpaintMaskIsArray = IsArray($inpaintMask)
    Local $bInpaintMaskCreate = IsDllStruct($inpaintMask) And $typeOfInpaintMask == "Scalar"

    If $typeOfInpaintMask == Default Then
        $iArrInpaintMask = $inpaintMask
    ElseIf $bInpaintMaskIsArray Then
        $vectorInpaintMask = Call("_VectorOf" & $typeOfInpaintMask & "Create")

        $iArrInpaintMaskSize = UBound($inpaintMask)
        For $i = 0 To $iArrInpaintMaskSize - 1
            Call("_VectorOf" & $typeOfInpaintMask & "Push", $vectorInpaintMask, $inpaintMask[$i])
        Next

        $iArrInpaintMask = Call("_cveInputArrayFromVectorOf" & $typeOfInpaintMask, $vectorInpaintMask)
    Else
        If $bInpaintMaskCreate Then
            $inpaintMask = Call("_cve" & $typeOfInpaintMask & "Create", $inpaintMask)
        EndIf
        $iArrInpaintMask = Call("_cveInputArrayFrom" & $typeOfInpaintMask, $inpaintMask)
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

    _cveInpaint($iArrSrc, $iArrInpaintMask, $oArrDst, $inpaintRadius, $flags)

    If $bDstIsArray Then
        Call("_VectorOf" & $typeOfDst & "Release", $vectorDst)
    EndIf

    If $typeOfDst <> Default Then
        _cveOutputArrayRelease($oArrDst)
        If $bDstCreate Then
            Call("_cve" & $typeOfDst & "Release", $dst)
        EndIf
    EndIf

    If $bInpaintMaskIsArray Then
        Call("_VectorOf" & $typeOfInpaintMask & "Release", $vectorInpaintMask)
    EndIf

    If $typeOfInpaintMask <> Default Then
        _cveInputArrayRelease($iArrInpaintMask)
        If $bInpaintMaskCreate Then
            Call("_cve" & $typeOfInpaintMask & "Release", $inpaintMask)
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
EndFunc   ;==>_cveInpaintTyped

Func _cveInpaintMat($src, $inpaintMask, $dst, $inpaintRadius, $flags)
    ; cveInpaint using cv::Mat instead of _*Array
    _cveInpaintTyped("Mat", $src, "Mat", $inpaintMask, "Mat", $dst, $inpaintRadius, $flags)
EndFunc   ;==>_cveInpaintMat

Func _cveFastNlMeansDenoising($src, $dst, $h = 3, $templateWindowSize = 7, $searchWindowSize = 21)
    ; CVAPI(void) cveFastNlMeansDenoising(cv::_InputArray* src, cv::_OutputArray* dst, float h, int templateWindowSize, int searchWindowSize);

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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFastNlMeansDenoising", $sSrcDllType, $src, $sDstDllType, $dst, "float", $h, "int", $templateWindowSize, "int", $searchWindowSize), "cveFastNlMeansDenoising", @error)
EndFunc   ;==>_cveFastNlMeansDenoising

Func _cveFastNlMeansDenoisingTyped($typeOfSrc, $src, $typeOfDst, $dst, $h = 3, $templateWindowSize = 7, $searchWindowSize = 21)

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

    _cveFastNlMeansDenoising($iArrSrc, $oArrDst, $h, $templateWindowSize, $searchWindowSize)

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
EndFunc   ;==>_cveFastNlMeansDenoisingTyped

Func _cveFastNlMeansDenoisingMat($src, $dst, $h = 3, $templateWindowSize = 7, $searchWindowSize = 21)
    ; cveFastNlMeansDenoising using cv::Mat instead of _*Array
    _cveFastNlMeansDenoisingTyped("Mat", $src, "Mat", $dst, $h, $templateWindowSize, $searchWindowSize)
EndFunc   ;==>_cveFastNlMeansDenoisingMat

Func _cveFastNlMeansDenoisingColored($src, $dst, $h = 3, $hColor = 3, $templateWindowSize = 7, $searchWindowSize = 21)
    ; CVAPI(void) cveFastNlMeansDenoisingColored(cv::_InputArray* src, cv::_OutputArray* dst, float h, float hColor, int templateWindowSize, int searchWindowSize);

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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFastNlMeansDenoisingColored", $sSrcDllType, $src, $sDstDllType, $dst, "float", $h, "float", $hColor, "int", $templateWindowSize, "int", $searchWindowSize), "cveFastNlMeansDenoisingColored", @error)
EndFunc   ;==>_cveFastNlMeansDenoisingColored

Func _cveFastNlMeansDenoisingColoredTyped($typeOfSrc, $src, $typeOfDst, $dst, $h = 3, $hColor = 3, $templateWindowSize = 7, $searchWindowSize = 21)

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

    _cveFastNlMeansDenoisingColored($iArrSrc, $oArrDst, $h, $hColor, $templateWindowSize, $searchWindowSize)

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
EndFunc   ;==>_cveFastNlMeansDenoisingColoredTyped

Func _cveFastNlMeansDenoisingColoredMat($src, $dst, $h = 3, $hColor = 3, $templateWindowSize = 7, $searchWindowSize = 21)
    ; cveFastNlMeansDenoisingColored using cv::Mat instead of _*Array
    _cveFastNlMeansDenoisingColoredTyped("Mat", $src, "Mat", $dst, $h, $hColor, $templateWindowSize, $searchWindowSize)
EndFunc   ;==>_cveFastNlMeansDenoisingColoredMat

Func _cudaNonLocalMeans($src, $dst, $h, $searchWindow, $blockSize, $borderMode, $stream)
    ; CVAPI(void) cudaNonLocalMeans(const cv::cuda::GpuMat* src, cv::cuda::GpuMat* dst, float h, int searchWindow, int blockSize, int borderMode, cv::cuda::Stream* stream);

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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaNonLocalMeans", $sSrcDllType, $src, $sDstDllType, $dst, "float", $h, "int", $searchWindow, "int", $blockSize, "int", $borderMode, $sStreamDllType, $stream), "cudaNonLocalMeans", @error)
EndFunc   ;==>_cudaNonLocalMeans

Func _cveEdgePreservingFilter($src, $dst, $flags, $sigmaS, $sigmaR)
    ; CVAPI(void) cveEdgePreservingFilter(cv::_InputArray* src, cv::_OutputArray* dst, int flags, float sigmaS, float sigmaR);

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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveEdgePreservingFilter", $sSrcDllType, $src, $sDstDllType, $dst, "int", $flags, "float", $sigmaS, "float", $sigmaR), "cveEdgePreservingFilter", @error)
EndFunc   ;==>_cveEdgePreservingFilter

Func _cveEdgePreservingFilterTyped($typeOfSrc, $src, $typeOfDst, $dst, $flags, $sigmaS, $sigmaR)

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

    _cveEdgePreservingFilter($iArrSrc, $oArrDst, $flags, $sigmaS, $sigmaR)

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
EndFunc   ;==>_cveEdgePreservingFilterTyped

Func _cveEdgePreservingFilterMat($src, $dst, $flags, $sigmaS, $sigmaR)
    ; cveEdgePreservingFilter using cv::Mat instead of _*Array
    _cveEdgePreservingFilterTyped("Mat", $src, "Mat", $dst, $flags, $sigmaS, $sigmaR)
EndFunc   ;==>_cveEdgePreservingFilterMat

Func _cveDetailEnhance($src, $dst, $sigmaS, $sigmaR)
    ; CVAPI(void) cveDetailEnhance(cv::_InputArray* src, cv::_OutputArray* dst, float sigmaS, float sigmaR);

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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDetailEnhance", $sSrcDllType, $src, $sDstDllType, $dst, "float", $sigmaS, "float", $sigmaR), "cveDetailEnhance", @error)
EndFunc   ;==>_cveDetailEnhance

Func _cveDetailEnhanceTyped($typeOfSrc, $src, $typeOfDst, $dst, $sigmaS, $sigmaR)

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

    _cveDetailEnhance($iArrSrc, $oArrDst, $sigmaS, $sigmaR)

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
EndFunc   ;==>_cveDetailEnhanceTyped

Func _cveDetailEnhanceMat($src, $dst, $sigmaS, $sigmaR)
    ; cveDetailEnhance using cv::Mat instead of _*Array
    _cveDetailEnhanceTyped("Mat", $src, "Mat", $dst, $sigmaS, $sigmaR)
EndFunc   ;==>_cveDetailEnhanceMat

Func _cvePencilSketch($src, $dst1, $dst2, $sigmaS, $sigmaR, $shadeFactor)
    ; CVAPI(void) cvePencilSketch(cv::_InputArray* src, cv::_OutputArray* dst1, cv::_OutputArray* dst2, float sigmaS, float sigmaR, float shadeFactor);

    Local $sSrcDllType
    If IsDllStruct($src) Then
        $sSrcDllType = "struct*"
    Else
        $sSrcDllType = "ptr"
    EndIf

    Local $sDst1DllType
    If IsDllStruct($dst1) Then
        $sDst1DllType = "struct*"
    Else
        $sDst1DllType = "ptr"
    EndIf

    Local $sDst2DllType
    If IsDllStruct($dst2) Then
        $sDst2DllType = "struct*"
    Else
        $sDst2DllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cvePencilSketch", $sSrcDllType, $src, $sDst1DllType, $dst1, $sDst2DllType, $dst2, "float", $sigmaS, "float", $sigmaR, "float", $shadeFactor), "cvePencilSketch", @error)
EndFunc   ;==>_cvePencilSketch

Func _cvePencilSketchTyped($typeOfSrc, $src, $typeOfDst1, $dst1, $typeOfDst2, $dst2, $sigmaS, $sigmaR, $shadeFactor)

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

    Local $oArrDst1, $vectorDst1, $iArrDst1Size
    Local $bDst1IsArray = IsArray($dst1)
    Local $bDst1Create = IsDllStruct($dst1) And $typeOfDst1 == "Scalar"

    If $typeOfDst1 == Default Then
        $oArrDst1 = $dst1
    ElseIf $bDst1IsArray Then
        $vectorDst1 = Call("_VectorOf" & $typeOfDst1 & "Create")

        $iArrDst1Size = UBound($dst1)
        For $i = 0 To $iArrDst1Size - 1
            Call("_VectorOf" & $typeOfDst1 & "Push", $vectorDst1, $dst1[$i])
        Next

        $oArrDst1 = Call("_cveOutputArrayFromVectorOf" & $typeOfDst1, $vectorDst1)
    Else
        If $bDst1Create Then
            $dst1 = Call("_cve" & $typeOfDst1 & "Create", $dst1)
        EndIf
        $oArrDst1 = Call("_cveOutputArrayFrom" & $typeOfDst1, $dst1)
    EndIf

    Local $oArrDst2, $vectorDst2, $iArrDst2Size
    Local $bDst2IsArray = IsArray($dst2)
    Local $bDst2Create = IsDllStruct($dst2) And $typeOfDst2 == "Scalar"

    If $typeOfDst2 == Default Then
        $oArrDst2 = $dst2
    ElseIf $bDst2IsArray Then
        $vectorDst2 = Call("_VectorOf" & $typeOfDst2 & "Create")

        $iArrDst2Size = UBound($dst2)
        For $i = 0 To $iArrDst2Size - 1
            Call("_VectorOf" & $typeOfDst2 & "Push", $vectorDst2, $dst2[$i])
        Next

        $oArrDst2 = Call("_cveOutputArrayFromVectorOf" & $typeOfDst2, $vectorDst2)
    Else
        If $bDst2Create Then
            $dst2 = Call("_cve" & $typeOfDst2 & "Create", $dst2)
        EndIf
        $oArrDst2 = Call("_cveOutputArrayFrom" & $typeOfDst2, $dst2)
    EndIf

    _cvePencilSketch($iArrSrc, $oArrDst1, $oArrDst2, $sigmaS, $sigmaR, $shadeFactor)

    If $bDst2IsArray Then
        Call("_VectorOf" & $typeOfDst2 & "Release", $vectorDst2)
    EndIf

    If $typeOfDst2 <> Default Then
        _cveOutputArrayRelease($oArrDst2)
        If $bDst2Create Then
            Call("_cve" & $typeOfDst2 & "Release", $dst2)
        EndIf
    EndIf

    If $bDst1IsArray Then
        Call("_VectorOf" & $typeOfDst1 & "Release", $vectorDst1)
    EndIf

    If $typeOfDst1 <> Default Then
        _cveOutputArrayRelease($oArrDst1)
        If $bDst1Create Then
            Call("_cve" & $typeOfDst1 & "Release", $dst1)
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
EndFunc   ;==>_cvePencilSketchTyped

Func _cvePencilSketchMat($src, $dst1, $dst2, $sigmaS, $sigmaR, $shadeFactor)
    ; cvePencilSketch using cv::Mat instead of _*Array
    _cvePencilSketchTyped("Mat", $src, "Mat", $dst1, "Mat", $dst2, $sigmaS, $sigmaR, $shadeFactor)
EndFunc   ;==>_cvePencilSketchMat

Func _cveStylization($src, $dst, $sigmaS, $sigmaR)
    ; CVAPI(void) cveStylization(cv::_InputArray* src, cv::_OutputArray* dst, float sigmaS, float sigmaR);

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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveStylization", $sSrcDllType, $src, $sDstDllType, $dst, "float", $sigmaS, "float", $sigmaR), "cveStylization", @error)
EndFunc   ;==>_cveStylization

Func _cveStylizationTyped($typeOfSrc, $src, $typeOfDst, $dst, $sigmaS, $sigmaR)

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

    _cveStylization($iArrSrc, $oArrDst, $sigmaS, $sigmaR)

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
EndFunc   ;==>_cveStylizationTyped

Func _cveStylizationMat($src, $dst, $sigmaS, $sigmaR)
    ; cveStylization using cv::Mat instead of _*Array
    _cveStylizationTyped("Mat", $src, "Mat", $dst, $sigmaS, $sigmaR)
EndFunc   ;==>_cveStylizationMat

Func _cveColorChange($src, $mask, $dst, $redMul, $greenMul, $blueMul)
    ; CVAPI(void) cveColorChange(cv::_InputArray* src, cv::_InputArray* mask, cv::_OutputArray* dst, float redMul, float greenMul, float blueMul);

    Local $sSrcDllType
    If IsDllStruct($src) Then
        $sSrcDllType = "struct*"
    Else
        $sSrcDllType = "ptr"
    EndIf

    Local $sMaskDllType
    If IsDllStruct($mask) Then
        $sMaskDllType = "struct*"
    Else
        $sMaskDllType = "ptr"
    EndIf

    Local $sDstDllType
    If IsDllStruct($dst) Then
        $sDstDllType = "struct*"
    Else
        $sDstDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveColorChange", $sSrcDllType, $src, $sMaskDllType, $mask, $sDstDllType, $dst, "float", $redMul, "float", $greenMul, "float", $blueMul), "cveColorChange", @error)
EndFunc   ;==>_cveColorChange

Func _cveColorChangeTyped($typeOfSrc, $src, $typeOfMask, $mask, $typeOfDst, $dst, $redMul, $greenMul, $blueMul)

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

    _cveColorChange($iArrSrc, $iArrMask, $oArrDst, $redMul, $greenMul, $blueMul)

    If $bDstIsArray Then
        Call("_VectorOf" & $typeOfDst & "Release", $vectorDst)
    EndIf

    If $typeOfDst <> Default Then
        _cveOutputArrayRelease($oArrDst)
        If $bDstCreate Then
            Call("_cve" & $typeOfDst & "Release", $dst)
        EndIf
    EndIf

    If $bMaskIsArray Then
        Call("_VectorOf" & $typeOfMask & "Release", $vectorMask)
    EndIf

    If $typeOfMask <> Default Then
        _cveInputArrayRelease($iArrMask)
        If $bMaskCreate Then
            Call("_cve" & $typeOfMask & "Release", $mask)
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
EndFunc   ;==>_cveColorChangeTyped

Func _cveColorChangeMat($src, $mask, $dst, $redMul, $greenMul, $blueMul)
    ; cveColorChange using cv::Mat instead of _*Array
    _cveColorChangeTyped("Mat", $src, "Mat", $mask, "Mat", $dst, $redMul, $greenMul, $blueMul)
EndFunc   ;==>_cveColorChangeMat

Func _cveIlluminationChange($src, $mask, $dst, $alpha = 0.2, $beta = 0.4)
    ; CVAPI(void) cveIlluminationChange(cv::_InputArray* src, cv::_InputArray* mask, cv::_OutputArray* dst, float alpha, float beta);

    Local $sSrcDllType
    If IsDllStruct($src) Then
        $sSrcDllType = "struct*"
    Else
        $sSrcDllType = "ptr"
    EndIf

    Local $sMaskDllType
    If IsDllStruct($mask) Then
        $sMaskDllType = "struct*"
    Else
        $sMaskDllType = "ptr"
    EndIf

    Local $sDstDllType
    If IsDllStruct($dst) Then
        $sDstDllType = "struct*"
    Else
        $sDstDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveIlluminationChange", $sSrcDllType, $src, $sMaskDllType, $mask, $sDstDllType, $dst, "float", $alpha, "float", $beta), "cveIlluminationChange", @error)
EndFunc   ;==>_cveIlluminationChange

Func _cveIlluminationChangeTyped($typeOfSrc, $src, $typeOfMask, $mask, $typeOfDst, $dst, $alpha = 0.2, $beta = 0.4)

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

    _cveIlluminationChange($iArrSrc, $iArrMask, $oArrDst, $alpha, $beta)

    If $bDstIsArray Then
        Call("_VectorOf" & $typeOfDst & "Release", $vectorDst)
    EndIf

    If $typeOfDst <> Default Then
        _cveOutputArrayRelease($oArrDst)
        If $bDstCreate Then
            Call("_cve" & $typeOfDst & "Release", $dst)
        EndIf
    EndIf

    If $bMaskIsArray Then
        Call("_VectorOf" & $typeOfMask & "Release", $vectorMask)
    EndIf

    If $typeOfMask <> Default Then
        _cveInputArrayRelease($iArrMask)
        If $bMaskCreate Then
            Call("_cve" & $typeOfMask & "Release", $mask)
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
EndFunc   ;==>_cveIlluminationChangeTyped

Func _cveIlluminationChangeMat($src, $mask, $dst, $alpha = 0.2, $beta = 0.4)
    ; cveIlluminationChange using cv::Mat instead of _*Array
    _cveIlluminationChangeTyped("Mat", $src, "Mat", $mask, "Mat", $dst, $alpha, $beta)
EndFunc   ;==>_cveIlluminationChangeMat

Func _cveTextureFlattening($src, $mask, $dst, $lowThreshold, $highThreshold, $kernelSize)
    ; CVAPI(void) cveTextureFlattening(cv::_InputArray* src, cv::_InputArray* mask, cv::_OutputArray* dst, float lowThreshold, float highThreshold, int kernelSize);

    Local $sSrcDllType
    If IsDllStruct($src) Then
        $sSrcDllType = "struct*"
    Else
        $sSrcDllType = "ptr"
    EndIf

    Local $sMaskDllType
    If IsDllStruct($mask) Then
        $sMaskDllType = "struct*"
    Else
        $sMaskDllType = "ptr"
    EndIf

    Local $sDstDllType
    If IsDllStruct($dst) Then
        $sDstDllType = "struct*"
    Else
        $sDstDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveTextureFlattening", $sSrcDllType, $src, $sMaskDllType, $mask, $sDstDllType, $dst, "float", $lowThreshold, "float", $highThreshold, "int", $kernelSize), "cveTextureFlattening", @error)
EndFunc   ;==>_cveTextureFlattening

Func _cveTextureFlatteningTyped($typeOfSrc, $src, $typeOfMask, $mask, $typeOfDst, $dst, $lowThreshold, $highThreshold, $kernelSize)

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

    _cveTextureFlattening($iArrSrc, $iArrMask, $oArrDst, $lowThreshold, $highThreshold, $kernelSize)

    If $bDstIsArray Then
        Call("_VectorOf" & $typeOfDst & "Release", $vectorDst)
    EndIf

    If $typeOfDst <> Default Then
        _cveOutputArrayRelease($oArrDst)
        If $bDstCreate Then
            Call("_cve" & $typeOfDst & "Release", $dst)
        EndIf
    EndIf

    If $bMaskIsArray Then
        Call("_VectorOf" & $typeOfMask & "Release", $vectorMask)
    EndIf

    If $typeOfMask <> Default Then
        _cveInputArrayRelease($iArrMask)
        If $bMaskCreate Then
            Call("_cve" & $typeOfMask & "Release", $mask)
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
EndFunc   ;==>_cveTextureFlatteningTyped

Func _cveTextureFlatteningMat($src, $mask, $dst, $lowThreshold, $highThreshold, $kernelSize)
    ; cveTextureFlattening using cv::Mat instead of _*Array
    _cveTextureFlatteningTyped("Mat", $src, "Mat", $mask, "Mat", $dst, $lowThreshold, $highThreshold, $kernelSize)
EndFunc   ;==>_cveTextureFlatteningMat

Func _cveDecolor($src, $grayscale, $colorBoost)
    ; CVAPI(void) cveDecolor(cv::_InputArray* src, cv::_OutputArray* grayscale, cv::_OutputArray* colorBoost);

    Local $sSrcDllType
    If IsDllStruct($src) Then
        $sSrcDllType = "struct*"
    Else
        $sSrcDllType = "ptr"
    EndIf

    Local $sGrayscaleDllType
    If IsDllStruct($grayscale) Then
        $sGrayscaleDllType = "struct*"
    Else
        $sGrayscaleDllType = "ptr"
    EndIf

    Local $sColorBoostDllType
    If IsDllStruct($colorBoost) Then
        $sColorBoostDllType = "struct*"
    Else
        $sColorBoostDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDecolor", $sSrcDllType, $src, $sGrayscaleDllType, $grayscale, $sColorBoostDllType, $colorBoost), "cveDecolor", @error)
EndFunc   ;==>_cveDecolor

Func _cveDecolorTyped($typeOfSrc, $src, $typeOfGrayscale, $grayscale, $typeOfColorBoost, $colorBoost)

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

    Local $oArrGrayscale, $vectorGrayscale, $iArrGrayscaleSize
    Local $bGrayscaleIsArray = IsArray($grayscale)
    Local $bGrayscaleCreate = IsDllStruct($grayscale) And $typeOfGrayscale == "Scalar"

    If $typeOfGrayscale == Default Then
        $oArrGrayscale = $grayscale
    ElseIf $bGrayscaleIsArray Then
        $vectorGrayscale = Call("_VectorOf" & $typeOfGrayscale & "Create")

        $iArrGrayscaleSize = UBound($grayscale)
        For $i = 0 To $iArrGrayscaleSize - 1
            Call("_VectorOf" & $typeOfGrayscale & "Push", $vectorGrayscale, $grayscale[$i])
        Next

        $oArrGrayscale = Call("_cveOutputArrayFromVectorOf" & $typeOfGrayscale, $vectorGrayscale)
    Else
        If $bGrayscaleCreate Then
            $grayscale = Call("_cve" & $typeOfGrayscale & "Create", $grayscale)
        EndIf
        $oArrGrayscale = Call("_cveOutputArrayFrom" & $typeOfGrayscale, $grayscale)
    EndIf

    Local $oArrColorBoost, $vectorColorBoost, $iArrColorBoostSize
    Local $bColorBoostIsArray = IsArray($colorBoost)
    Local $bColorBoostCreate = IsDllStruct($colorBoost) And $typeOfColorBoost == "Scalar"

    If $typeOfColorBoost == Default Then
        $oArrColorBoost = $colorBoost
    ElseIf $bColorBoostIsArray Then
        $vectorColorBoost = Call("_VectorOf" & $typeOfColorBoost & "Create")

        $iArrColorBoostSize = UBound($colorBoost)
        For $i = 0 To $iArrColorBoostSize - 1
            Call("_VectorOf" & $typeOfColorBoost & "Push", $vectorColorBoost, $colorBoost[$i])
        Next

        $oArrColorBoost = Call("_cveOutputArrayFromVectorOf" & $typeOfColorBoost, $vectorColorBoost)
    Else
        If $bColorBoostCreate Then
            $colorBoost = Call("_cve" & $typeOfColorBoost & "Create", $colorBoost)
        EndIf
        $oArrColorBoost = Call("_cveOutputArrayFrom" & $typeOfColorBoost, $colorBoost)
    EndIf

    _cveDecolor($iArrSrc, $oArrGrayscale, $oArrColorBoost)

    If $bColorBoostIsArray Then
        Call("_VectorOf" & $typeOfColorBoost & "Release", $vectorColorBoost)
    EndIf

    If $typeOfColorBoost <> Default Then
        _cveOutputArrayRelease($oArrColorBoost)
        If $bColorBoostCreate Then
            Call("_cve" & $typeOfColorBoost & "Release", $colorBoost)
        EndIf
    EndIf

    If $bGrayscaleIsArray Then
        Call("_VectorOf" & $typeOfGrayscale & "Release", $vectorGrayscale)
    EndIf

    If $typeOfGrayscale <> Default Then
        _cveOutputArrayRelease($oArrGrayscale)
        If $bGrayscaleCreate Then
            Call("_cve" & $typeOfGrayscale & "Release", $grayscale)
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
EndFunc   ;==>_cveDecolorTyped

Func _cveDecolorMat($src, $grayscale, $colorBoost)
    ; cveDecolor using cv::Mat instead of _*Array
    _cveDecolorTyped("Mat", $src, "Mat", $grayscale, "Mat", $colorBoost)
EndFunc   ;==>_cveDecolorMat

Func _cveSeamlessClone($src, $dst, $mask, $p, $blend, $flags)
    ; CVAPI(void) cveSeamlessClone(cv::_InputArray* src, cv::_InputArray* dst, cv::_InputArray* mask, CvPoint* p, cv::_OutputArray* blend, int flags);

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

    Local $sMaskDllType
    If IsDllStruct($mask) Then
        $sMaskDllType = "struct*"
    Else
        $sMaskDllType = "ptr"
    EndIf

    Local $sPDllType
    If IsDllStruct($p) Then
        $sPDllType = "struct*"
    Else
        $sPDllType = "ptr"
    EndIf

    Local $sBlendDllType
    If IsDllStruct($blend) Then
        $sBlendDllType = "struct*"
    Else
        $sBlendDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSeamlessClone", $sSrcDllType, $src, $sDstDllType, $dst, $sMaskDllType, $mask, $sPDllType, $p, $sBlendDllType, $blend, "int", $flags), "cveSeamlessClone", @error)
EndFunc   ;==>_cveSeamlessClone

Func _cveSeamlessCloneTyped($typeOfSrc, $src, $typeOfDst, $dst, $typeOfMask, $mask, $p, $typeOfBlend, $blend, $flags)

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

    Local $iArrDst, $vectorDst, $iArrDstSize
    Local $bDstIsArray = IsArray($dst)
    Local $bDstCreate = IsDllStruct($dst) And $typeOfDst == "Scalar"

    If $typeOfDst == Default Then
        $iArrDst = $dst
    ElseIf $bDstIsArray Then
        $vectorDst = Call("_VectorOf" & $typeOfDst & "Create")

        $iArrDstSize = UBound($dst)
        For $i = 0 To $iArrDstSize - 1
            Call("_VectorOf" & $typeOfDst & "Push", $vectorDst, $dst[$i])
        Next

        $iArrDst = Call("_cveInputArrayFromVectorOf" & $typeOfDst, $vectorDst)
    Else
        If $bDstCreate Then
            $dst = Call("_cve" & $typeOfDst & "Create", $dst)
        EndIf
        $iArrDst = Call("_cveInputArrayFrom" & $typeOfDst, $dst)
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

    Local $oArrBlend, $vectorBlend, $iArrBlendSize
    Local $bBlendIsArray = IsArray($blend)
    Local $bBlendCreate = IsDllStruct($blend) And $typeOfBlend == "Scalar"

    If $typeOfBlend == Default Then
        $oArrBlend = $blend
    ElseIf $bBlendIsArray Then
        $vectorBlend = Call("_VectorOf" & $typeOfBlend & "Create")

        $iArrBlendSize = UBound($blend)
        For $i = 0 To $iArrBlendSize - 1
            Call("_VectorOf" & $typeOfBlend & "Push", $vectorBlend, $blend[$i])
        Next

        $oArrBlend = Call("_cveOutputArrayFromVectorOf" & $typeOfBlend, $vectorBlend)
    Else
        If $bBlendCreate Then
            $blend = Call("_cve" & $typeOfBlend & "Create", $blend)
        EndIf
        $oArrBlend = Call("_cveOutputArrayFrom" & $typeOfBlend, $blend)
    EndIf

    _cveSeamlessClone($iArrSrc, $iArrDst, $iArrMask, $p, $oArrBlend, $flags)

    If $bBlendIsArray Then
        Call("_VectorOf" & $typeOfBlend & "Release", $vectorBlend)
    EndIf

    If $typeOfBlend <> Default Then
        _cveOutputArrayRelease($oArrBlend)
        If $bBlendCreate Then
            Call("_cve" & $typeOfBlend & "Release", $blend)
        EndIf
    EndIf

    If $bMaskIsArray Then
        Call("_VectorOf" & $typeOfMask & "Release", $vectorMask)
    EndIf

    If $typeOfMask <> Default Then
        _cveInputArrayRelease($iArrMask)
        If $bMaskCreate Then
            Call("_cve" & $typeOfMask & "Release", $mask)
        EndIf
    EndIf

    If $bDstIsArray Then
        Call("_VectorOf" & $typeOfDst & "Release", $vectorDst)
    EndIf

    If $typeOfDst <> Default Then
        _cveInputArrayRelease($iArrDst)
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
EndFunc   ;==>_cveSeamlessCloneTyped

Func _cveSeamlessCloneMat($src, $dst, $mask, $p, $blend, $flags)
    ; cveSeamlessClone using cv::Mat instead of _*Array
    _cveSeamlessCloneTyped("Mat", $src, "Mat", $dst, "Mat", $mask, $p, "Mat", $blend, $flags)
EndFunc   ;==>_cveSeamlessCloneMat

Func _cveDenoiseTVL1($observations, $result, $lambda, $niters)
    ; CVAPI(void) cveDenoiseTVL1(const std::vector<cv::Mat>* observations, cv::Mat* result, double lambda, int niters);

    Local $vecObservations, $iArrObservationsSize
    Local $bObservationsIsArray = IsArray($observations)

    If $bObservationsIsArray Then
        $vecObservations = _VectorOfMatCreate()

        $iArrObservationsSize = UBound($observations)
        For $i = 0 To $iArrObservationsSize - 1
            _VectorOfMatPush($vecObservations, $observations[$i])
        Next
    Else
        $vecObservations = $observations
    EndIf

    Local $sObservationsDllType
    If IsDllStruct($observations) Then
        $sObservationsDllType = "struct*"
    Else
        $sObservationsDllType = "ptr"
    EndIf

    Local $sResultDllType
    If IsDllStruct($result) Then
        $sResultDllType = "struct*"
    Else
        $sResultDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDenoiseTVL1", $sObservationsDllType, $vecObservations, $sResultDllType, $result, "double", $lambda, "int", $niters), "cveDenoiseTVL1", @error)

    If $bObservationsIsArray Then
        _VectorOfMatRelease($vecObservations)
    EndIf
EndFunc   ;==>_cveDenoiseTVL1

Func _cveCalibrateCRFProcess($calibrateCRF, $src, $dst, $times)
    ; CVAPI(void) cveCalibrateCRFProcess(cv::CalibrateCRF* calibrateCRF, cv::_InputArray* src, cv::_OutputArray* dst, cv::_InputArray* times);

    Local $sCalibrateCRFDllType
    If IsDllStruct($calibrateCRF) Then
        $sCalibrateCRFDllType = "struct*"
    Else
        $sCalibrateCRFDllType = "ptr"
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

    Local $sTimesDllType
    If IsDllStruct($times) Then
        $sTimesDllType = "struct*"
    Else
        $sTimesDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCalibrateCRFProcess", $sCalibrateCRFDllType, $calibrateCRF, $sSrcDllType, $src, $sDstDllType, $dst, $sTimesDllType, $times), "cveCalibrateCRFProcess", @error)
EndFunc   ;==>_cveCalibrateCRFProcess

Func _cveCalibrateCRFProcessTyped($calibrateCRF, $typeOfSrc, $src, $typeOfDst, $dst, $typeOfTimes, $times)

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

    Local $iArrTimes, $vectorTimes, $iArrTimesSize
    Local $bTimesIsArray = IsArray($times)
    Local $bTimesCreate = IsDllStruct($times) And $typeOfTimes == "Scalar"

    If $typeOfTimes == Default Then
        $iArrTimes = $times
    ElseIf $bTimesIsArray Then
        $vectorTimes = Call("_VectorOf" & $typeOfTimes & "Create")

        $iArrTimesSize = UBound($times)
        For $i = 0 To $iArrTimesSize - 1
            Call("_VectorOf" & $typeOfTimes & "Push", $vectorTimes, $times[$i])
        Next

        $iArrTimes = Call("_cveInputArrayFromVectorOf" & $typeOfTimes, $vectorTimes)
    Else
        If $bTimesCreate Then
            $times = Call("_cve" & $typeOfTimes & "Create", $times)
        EndIf
        $iArrTimes = Call("_cveInputArrayFrom" & $typeOfTimes, $times)
    EndIf

    _cveCalibrateCRFProcess($calibrateCRF, $iArrSrc, $oArrDst, $iArrTimes)

    If $bTimesIsArray Then
        Call("_VectorOf" & $typeOfTimes & "Release", $vectorTimes)
    EndIf

    If $typeOfTimes <> Default Then
        _cveInputArrayRelease($iArrTimes)
        If $bTimesCreate Then
            Call("_cve" & $typeOfTimes & "Release", $times)
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
EndFunc   ;==>_cveCalibrateCRFProcessTyped

Func _cveCalibrateCRFProcessMat($calibrateCRF, $src, $dst, $times)
    ; cveCalibrateCRFProcess using cv::Mat instead of _*Array
    _cveCalibrateCRFProcessTyped($calibrateCRF, "Mat", $src, "Mat", $dst, "Mat", $times)
EndFunc   ;==>_cveCalibrateCRFProcessMat

Func _cveCalibrateDebevecCreate($samples, $lambda, $random, $calibrateCRF, $sharedPtr)
    ; CVAPI(cv::CalibrateDebevec*) cveCalibrateDebevecCreate(int samples, float lambda, bool random, cv::CalibrateCRF** calibrateCRF, cv::Ptr<cv::CalibrateDebevec>** sharedPtr);

    Local $sCalibrateCRFDllType
    If IsDllStruct($calibrateCRF) Then
        $sCalibrateCRFDllType = "struct*"
    ElseIf $calibrateCRF == Null Then
        $sCalibrateCRFDllType = "ptr"
    Else
        $sCalibrateCRFDllType = "ptr*"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveCalibrateDebevecCreate", "int", $samples, "float", $lambda, "boolean", $random, $sCalibrateCRFDllType, $calibrateCRF, $sSharedPtrDllType, $sharedPtr), "cveCalibrateDebevecCreate", @error)
EndFunc   ;==>_cveCalibrateDebevecCreate

Func _cveCalibrateDebevecRelease($calibrateDebevec, $sharedPtr)
    ; CVAPI(void) cveCalibrateDebevecRelease(cv::CalibrateDebevec** calibrateDebevec, cv::Ptr<cv::CalibrateDebevec>** sharedPtr);

    Local $sCalibrateDebevecDllType
    If IsDllStruct($calibrateDebevec) Then
        $sCalibrateDebevecDllType = "struct*"
    ElseIf $calibrateDebevec == Null Then
        $sCalibrateDebevecDllType = "ptr"
    Else
        $sCalibrateDebevecDllType = "ptr*"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCalibrateDebevecRelease", $sCalibrateDebevecDllType, $calibrateDebevec, $sSharedPtrDllType, $sharedPtr), "cveCalibrateDebevecRelease", @error)
EndFunc   ;==>_cveCalibrateDebevecRelease

Func _cveCalibrateRobertsonCreate($maxIter, $threshold, $calibrateCRF, $sharedPtr)
    ; CVAPI(cv::CalibrateRobertson*) cveCalibrateRobertsonCreate(int maxIter, float threshold, cv::CalibrateCRF** calibrateCRF, cv::Ptr<cv::CalibrateRobertson>** sharedPtr);

    Local $sCalibrateCRFDllType
    If IsDllStruct($calibrateCRF) Then
        $sCalibrateCRFDllType = "struct*"
    ElseIf $calibrateCRF == Null Then
        $sCalibrateCRFDllType = "ptr"
    Else
        $sCalibrateCRFDllType = "ptr*"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveCalibrateRobertsonCreate", "int", $maxIter, "float", $threshold, $sCalibrateCRFDllType, $calibrateCRF, $sSharedPtrDllType, $sharedPtr), "cveCalibrateRobertsonCreate", @error)
EndFunc   ;==>_cveCalibrateRobertsonCreate

Func _cveCalibrateRobertsonRelease($calibrateRobertson, $sharedPtr)
    ; CVAPI(void) cveCalibrateRobertsonRelease(cv::CalibrateRobertson** calibrateRobertson, cv::Ptr<cv::CalibrateRobertson>** sharedPtr);

    Local $sCalibrateRobertsonDllType
    If IsDllStruct($calibrateRobertson) Then
        $sCalibrateRobertsonDllType = "struct*"
    ElseIf $calibrateRobertson == Null Then
        $sCalibrateRobertsonDllType = "ptr"
    Else
        $sCalibrateRobertsonDllType = "ptr*"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCalibrateRobertsonRelease", $sCalibrateRobertsonDllType, $calibrateRobertson, $sSharedPtrDllType, $sharedPtr), "cveCalibrateRobertsonRelease", @error)
EndFunc   ;==>_cveCalibrateRobertsonRelease

Func _cveMergeExposuresProcess($mergeExposures, $src, $dst, $times, $response)
    ; CVAPI(void) cveMergeExposuresProcess(cv::MergeExposures* mergeExposures, cv::_InputArray* src, cv::_OutputArray* dst, cv::_InputArray* times, cv::_InputArray* response);

    Local $sMergeExposuresDllType
    If IsDllStruct($mergeExposures) Then
        $sMergeExposuresDllType = "struct*"
    Else
        $sMergeExposuresDllType = "ptr"
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

    Local $sTimesDllType
    If IsDllStruct($times) Then
        $sTimesDllType = "struct*"
    Else
        $sTimesDllType = "ptr"
    EndIf

    Local $sResponseDllType
    If IsDllStruct($response) Then
        $sResponseDllType = "struct*"
    Else
        $sResponseDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMergeExposuresProcess", $sMergeExposuresDllType, $mergeExposures, $sSrcDllType, $src, $sDstDllType, $dst, $sTimesDllType, $times, $sResponseDllType, $response), "cveMergeExposuresProcess", @error)
EndFunc   ;==>_cveMergeExposuresProcess

Func _cveMergeExposuresProcessTyped($mergeExposures, $typeOfSrc, $src, $typeOfDst, $dst, $typeOfTimes, $times, $typeOfResponse, $response)

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

    Local $iArrTimes, $vectorTimes, $iArrTimesSize
    Local $bTimesIsArray = IsArray($times)
    Local $bTimesCreate = IsDllStruct($times) And $typeOfTimes == "Scalar"

    If $typeOfTimes == Default Then
        $iArrTimes = $times
    ElseIf $bTimesIsArray Then
        $vectorTimes = Call("_VectorOf" & $typeOfTimes & "Create")

        $iArrTimesSize = UBound($times)
        For $i = 0 To $iArrTimesSize - 1
            Call("_VectorOf" & $typeOfTimes & "Push", $vectorTimes, $times[$i])
        Next

        $iArrTimes = Call("_cveInputArrayFromVectorOf" & $typeOfTimes, $vectorTimes)
    Else
        If $bTimesCreate Then
            $times = Call("_cve" & $typeOfTimes & "Create", $times)
        EndIf
        $iArrTimes = Call("_cveInputArrayFrom" & $typeOfTimes, $times)
    EndIf

    Local $iArrResponse, $vectorResponse, $iArrResponseSize
    Local $bResponseIsArray = IsArray($response)
    Local $bResponseCreate = IsDllStruct($response) And $typeOfResponse == "Scalar"

    If $typeOfResponse == Default Then
        $iArrResponse = $response
    ElseIf $bResponseIsArray Then
        $vectorResponse = Call("_VectorOf" & $typeOfResponse & "Create")

        $iArrResponseSize = UBound($response)
        For $i = 0 To $iArrResponseSize - 1
            Call("_VectorOf" & $typeOfResponse & "Push", $vectorResponse, $response[$i])
        Next

        $iArrResponse = Call("_cveInputArrayFromVectorOf" & $typeOfResponse, $vectorResponse)
    Else
        If $bResponseCreate Then
            $response = Call("_cve" & $typeOfResponse & "Create", $response)
        EndIf
        $iArrResponse = Call("_cveInputArrayFrom" & $typeOfResponse, $response)
    EndIf

    _cveMergeExposuresProcess($mergeExposures, $iArrSrc, $oArrDst, $iArrTimes, $iArrResponse)

    If $bResponseIsArray Then
        Call("_VectorOf" & $typeOfResponse & "Release", $vectorResponse)
    EndIf

    If $typeOfResponse <> Default Then
        _cveInputArrayRelease($iArrResponse)
        If $bResponseCreate Then
            Call("_cve" & $typeOfResponse & "Release", $response)
        EndIf
    EndIf

    If $bTimesIsArray Then
        Call("_VectorOf" & $typeOfTimes & "Release", $vectorTimes)
    EndIf

    If $typeOfTimes <> Default Then
        _cveInputArrayRelease($iArrTimes)
        If $bTimesCreate Then
            Call("_cve" & $typeOfTimes & "Release", $times)
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
EndFunc   ;==>_cveMergeExposuresProcessTyped

Func _cveMergeExposuresProcessMat($mergeExposures, $src, $dst, $times, $response)
    ; cveMergeExposuresProcess using cv::Mat instead of _*Array
    _cveMergeExposuresProcessTyped($mergeExposures, "Mat", $src, "Mat", $dst, "Mat", $times, "Mat", $response)
EndFunc   ;==>_cveMergeExposuresProcessMat

Func _cveMergeDebevecCreate($merge, $sharedPtr)
    ; CVAPI(cv::MergeDebevec*) cveMergeDebevecCreate(cv::MergeExposures** merge, cv::Ptr<cv::MergeDebevec>** sharedPtr);

    Local $sMergeDllType
    If IsDllStruct($merge) Then
        $sMergeDllType = "struct*"
    ElseIf $merge == Null Then
        $sMergeDllType = "ptr"
    Else
        $sMergeDllType = "ptr*"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveMergeDebevecCreate", $sMergeDllType, $merge, $sSharedPtrDllType, $sharedPtr), "cveMergeDebevecCreate", @error)
EndFunc   ;==>_cveMergeDebevecCreate

Func _cveMergeDebevecRelease($merge, $sharedPtr)
    ; CVAPI(void) cveMergeDebevecRelease(cv::MergeDebevec** merge, cv::Ptr<cv::MergeDebevec>** sharedPtr);

    Local $sMergeDllType
    If IsDllStruct($merge) Then
        $sMergeDllType = "struct*"
    ElseIf $merge == Null Then
        $sMergeDllType = "ptr"
    Else
        $sMergeDllType = "ptr*"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMergeDebevecRelease", $sMergeDllType, $merge, $sSharedPtrDllType, $sharedPtr), "cveMergeDebevecRelease", @error)
EndFunc   ;==>_cveMergeDebevecRelease

Func _cveMergeMertensCreate($contrastWeight, $saturationWeight, $exposureWeight, $merge, $sharedPtr)
    ; CVAPI(cv::MergeMertens*) cveMergeMertensCreate(float contrastWeight, float saturationWeight, float exposureWeight, cv::MergeExposures** merge, cv::Ptr<cv::MergeMertens>** sharedPtr);

    Local $sMergeDllType
    If IsDllStruct($merge) Then
        $sMergeDllType = "struct*"
    ElseIf $merge == Null Then
        $sMergeDllType = "ptr"
    Else
        $sMergeDllType = "ptr*"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveMergeMertensCreate", "float", $contrastWeight, "float", $saturationWeight, "float", $exposureWeight, $sMergeDllType, $merge, $sSharedPtrDllType, $sharedPtr), "cveMergeMertensCreate", @error)
EndFunc   ;==>_cveMergeMertensCreate

Func _cveMergeMertensRelease($merge, $sharedPtr)
    ; CVAPI(void) cveMergeMertensRelease(cv::MergeMertens** merge, cv::Ptr<cv::MergeMertens>** sharedPtr);

    Local $sMergeDllType
    If IsDllStruct($merge) Then
        $sMergeDllType = "struct*"
    ElseIf $merge == Null Then
        $sMergeDllType = "ptr"
    Else
        $sMergeDllType = "ptr*"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMergeMertensRelease", $sMergeDllType, $merge, $sSharedPtrDllType, $sharedPtr), "cveMergeMertensRelease", @error)
EndFunc   ;==>_cveMergeMertensRelease

Func _cveMergeRobertsonCreate($merge, $sharedPtr)
    ; CVAPI(cv::MergeRobertson*) cveMergeRobertsonCreate(cv::MergeExposures** merge, cv::Ptr<cv::MergeRobertson>** sharedPtr);

    Local $sMergeDllType
    If IsDllStruct($merge) Then
        $sMergeDllType = "struct*"
    ElseIf $merge == Null Then
        $sMergeDllType = "ptr"
    Else
        $sMergeDllType = "ptr*"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveMergeRobertsonCreate", $sMergeDllType, $merge, $sSharedPtrDllType, $sharedPtr), "cveMergeRobertsonCreate", @error)
EndFunc   ;==>_cveMergeRobertsonCreate

Func _cveMergeRobertsonRelease($merge, $sharedPtr)
    ; CVAPI(void) cveMergeRobertsonRelease(cv::MergeRobertson** merge, cv::Ptr<cv::MergeRobertson>** sharedPtr);

    Local $sMergeDllType
    If IsDllStruct($merge) Then
        $sMergeDllType = "struct*"
    ElseIf $merge == Null Then
        $sMergeDllType = "ptr"
    Else
        $sMergeDllType = "ptr*"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMergeRobertsonRelease", $sMergeDllType, $merge, $sSharedPtrDllType, $sharedPtr), "cveMergeRobertsonRelease", @error)
EndFunc   ;==>_cveMergeRobertsonRelease

Func _cveTonemapProcess($tonemap, $src, $dst)
    ; CVAPI(void) cveTonemapProcess(cv::Tonemap* tonemap, cv::_InputArray* src, cv::_OutputArray* dst);

    Local $sTonemapDllType
    If IsDllStruct($tonemap) Then
        $sTonemapDllType = "struct*"
    Else
        $sTonemapDllType = "ptr"
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveTonemapProcess", $sTonemapDllType, $tonemap, $sSrcDllType, $src, $sDstDllType, $dst), "cveTonemapProcess", @error)
EndFunc   ;==>_cveTonemapProcess

Func _cveTonemapProcessTyped($tonemap, $typeOfSrc, $src, $typeOfDst, $dst)

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

    _cveTonemapProcess($tonemap, $iArrSrc, $oArrDst)

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
EndFunc   ;==>_cveTonemapProcessTyped

Func _cveTonemapProcessMat($tonemap, $src, $dst)
    ; cveTonemapProcess using cv::Mat instead of _*Array
    _cveTonemapProcessTyped($tonemap, "Mat", $src, "Mat", $dst)
EndFunc   ;==>_cveTonemapProcessMat

Func _cveTonemapCreate($gamma, $algorithm, $sharedPtr)
    ; CVAPI(cv::Tonemap*) cveTonemapCreate(float gamma, cv::Algorithm** algorithm, cv::Ptr<cv::Tonemap>** sharedPtr);

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
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveTonemapCreate", "float", $gamma, $sAlgorithmDllType, $algorithm, $sSharedPtrDllType, $sharedPtr), "cveTonemapCreate", @error)
EndFunc   ;==>_cveTonemapCreate

Func _cveTonemapRelease($tonemap, $sharedPtr)
    ; CVAPI(void) cveTonemapRelease(cv::Tonemap** tonemap, cv::Ptr<cv::Tonemap>** sharedPtr);

    Local $sTonemapDllType
    If IsDllStruct($tonemap) Then
        $sTonemapDllType = "struct*"
    ElseIf $tonemap == Null Then
        $sTonemapDllType = "ptr"
    Else
        $sTonemapDllType = "ptr*"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveTonemapRelease", $sTonemapDllType, $tonemap, $sSharedPtrDllType, $sharedPtr), "cveTonemapRelease", @error)
EndFunc   ;==>_cveTonemapRelease

Func _cveTonemapDragoCreate($gamma, $saturation, $bias, $tonemap, $algorithm, $sharedPtr)
    ; CVAPI(cv::TonemapDrago*) cveTonemapDragoCreate(float gamma, float saturation, float bias, cv::Tonemap** tonemap, cv::Algorithm** algorithm, cv::Ptr<cv::TonemapDrago>** sharedPtr);

    Local $sTonemapDllType
    If IsDllStruct($tonemap) Then
        $sTonemapDllType = "struct*"
    ElseIf $tonemap == Null Then
        $sTonemapDllType = "ptr"
    Else
        $sTonemapDllType = "ptr*"
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
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveTonemapDragoCreate", "float", $gamma, "float", $saturation, "float", $bias, $sTonemapDllType, $tonemap, $sAlgorithmDllType, $algorithm, $sSharedPtrDllType, $sharedPtr), "cveTonemapDragoCreate", @error)
EndFunc   ;==>_cveTonemapDragoCreate

Func _cveTonemapDragoRelease($tonemap, $sharedPtr)
    ; CVAPI(void) cveTonemapDragoRelease(cv::TonemapDrago** tonemap, cv::Ptr<cv::TonemapDrago>** sharedPtr);

    Local $sTonemapDllType
    If IsDllStruct($tonemap) Then
        $sTonemapDllType = "struct*"
    ElseIf $tonemap == Null Then
        $sTonemapDllType = "ptr"
    Else
        $sTonemapDllType = "ptr*"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveTonemapDragoRelease", $sTonemapDllType, $tonemap, $sSharedPtrDllType, $sharedPtr), "cveTonemapDragoRelease", @error)
EndFunc   ;==>_cveTonemapDragoRelease

Func _cveTonemapReinhardCreate($gamma, $intensity, $lightAdapt, $colorAdapt, $tonemap, $algorithm, $sharedPtr)
    ; CVAPI(cv::TonemapReinhard*) cveTonemapReinhardCreate(float gamma, float intensity, float lightAdapt, float colorAdapt, cv::Tonemap** tonemap, cv::Algorithm** algorithm, cv::Ptr<cv::TonemapReinhard>** sharedPtr);

    Local $sTonemapDllType
    If IsDllStruct($tonemap) Then
        $sTonemapDllType = "struct*"
    ElseIf $tonemap == Null Then
        $sTonemapDllType = "ptr"
    Else
        $sTonemapDllType = "ptr*"
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
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveTonemapReinhardCreate", "float", $gamma, "float", $intensity, "float", $lightAdapt, "float", $colorAdapt, $sTonemapDllType, $tonemap, $sAlgorithmDllType, $algorithm, $sSharedPtrDllType, $sharedPtr), "cveTonemapReinhardCreate", @error)
EndFunc   ;==>_cveTonemapReinhardCreate

Func _cveTonemapReinhardRelease($tonemap, $sharedPtr)
    ; CVAPI(void) cveTonemapReinhardRelease(cv::TonemapReinhard** tonemap, cv::Ptr<cv::TonemapReinhard>** sharedPtr);

    Local $sTonemapDllType
    If IsDllStruct($tonemap) Then
        $sTonemapDllType = "struct*"
    ElseIf $tonemap == Null Then
        $sTonemapDllType = "ptr"
    Else
        $sTonemapDllType = "ptr*"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveTonemapReinhardRelease", $sTonemapDllType, $tonemap, $sSharedPtrDllType, $sharedPtr), "cveTonemapReinhardRelease", @error)
EndFunc   ;==>_cveTonemapReinhardRelease

Func _cveTonemapMantiukCreate($gamma, $scale, $saturation, $tonemap, $algorithm, $sharedPtr)
    ; CVAPI(cv::TonemapMantiuk*) cveTonemapMantiukCreate(float gamma, float scale, float saturation, cv::Tonemap** tonemap, cv::Algorithm** algorithm, cv::Ptr<cv::TonemapMantiuk>** sharedPtr);

    Local $sTonemapDllType
    If IsDllStruct($tonemap) Then
        $sTonemapDllType = "struct*"
    ElseIf $tonemap == Null Then
        $sTonemapDllType = "ptr"
    Else
        $sTonemapDllType = "ptr*"
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
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveTonemapMantiukCreate", "float", $gamma, "float", $scale, "float", $saturation, $sTonemapDllType, $tonemap, $sAlgorithmDllType, $algorithm, $sSharedPtrDllType, $sharedPtr), "cveTonemapMantiukCreate", @error)
EndFunc   ;==>_cveTonemapMantiukCreate

Func _cveTonemapMantiukRelease($tonemap, $sharedPtr)
    ; CVAPI(void) cveTonemapMantiukRelease(cv::TonemapMantiuk** tonemap, cv::Ptr<cv::TonemapMantiuk>** sharedPtr);

    Local $sTonemapDllType
    If IsDllStruct($tonemap) Then
        $sTonemapDllType = "struct*"
    ElseIf $tonemap == Null Then
        $sTonemapDllType = "ptr"
    Else
        $sTonemapDllType = "ptr*"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveTonemapMantiukRelease", $sTonemapDllType, $tonemap, $sSharedPtrDllType, $sharedPtr), "cveTonemapMantiukRelease", @error)
EndFunc   ;==>_cveTonemapMantiukRelease

Func _cveAlignExposuresProcess($alignExposures, $src, $dst, $times, $response)
    ; CVAPI(void) cveAlignExposuresProcess(cv::AlignExposures* alignExposures, cv::_InputArray* src, std::vector<cv::Mat>* dst, cv::_InputArray* times, cv::_InputArray* response);

    Local $sAlignExposuresDllType
    If IsDllStruct($alignExposures) Then
        $sAlignExposuresDllType = "struct*"
    Else
        $sAlignExposuresDllType = "ptr"
    EndIf

    Local $sSrcDllType
    If IsDllStruct($src) Then
        $sSrcDllType = "struct*"
    Else
        $sSrcDllType = "ptr"
    EndIf

    Local $vecDst, $iArrDstSize
    Local $bDstIsArray = IsArray($dst)

    If $bDstIsArray Then
        $vecDst = _VectorOfMatCreate()

        $iArrDstSize = UBound($dst)
        For $i = 0 To $iArrDstSize - 1
            _VectorOfMatPush($vecDst, $dst[$i])
        Next
    Else
        $vecDst = $dst
    EndIf

    Local $sDstDllType
    If IsDllStruct($dst) Then
        $sDstDllType = "struct*"
    Else
        $sDstDllType = "ptr"
    EndIf

    Local $sTimesDllType
    If IsDllStruct($times) Then
        $sTimesDllType = "struct*"
    Else
        $sTimesDllType = "ptr"
    EndIf

    Local $sResponseDllType
    If IsDllStruct($response) Then
        $sResponseDllType = "struct*"
    Else
        $sResponseDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveAlignExposuresProcess", $sAlignExposuresDllType, $alignExposures, $sSrcDllType, $src, $sDstDllType, $vecDst, $sTimesDllType, $times, $sResponseDllType, $response), "cveAlignExposuresProcess", @error)

    If $bDstIsArray Then
        _VectorOfMatRelease($vecDst)
    EndIf
EndFunc   ;==>_cveAlignExposuresProcess

Func _cveAlignExposuresProcessTyped($alignExposures, $typeOfSrc, $src, $dst, $typeOfTimes, $times, $typeOfResponse, $response)

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

    Local $iArrTimes, $vectorTimes, $iArrTimesSize
    Local $bTimesIsArray = IsArray($times)
    Local $bTimesCreate = IsDllStruct($times) And $typeOfTimes == "Scalar"

    If $typeOfTimes == Default Then
        $iArrTimes = $times
    ElseIf $bTimesIsArray Then
        $vectorTimes = Call("_VectorOf" & $typeOfTimes & "Create")

        $iArrTimesSize = UBound($times)
        For $i = 0 To $iArrTimesSize - 1
            Call("_VectorOf" & $typeOfTimes & "Push", $vectorTimes, $times[$i])
        Next

        $iArrTimes = Call("_cveInputArrayFromVectorOf" & $typeOfTimes, $vectorTimes)
    Else
        If $bTimesCreate Then
            $times = Call("_cve" & $typeOfTimes & "Create", $times)
        EndIf
        $iArrTimes = Call("_cveInputArrayFrom" & $typeOfTimes, $times)
    EndIf

    Local $iArrResponse, $vectorResponse, $iArrResponseSize
    Local $bResponseIsArray = IsArray($response)
    Local $bResponseCreate = IsDllStruct($response) And $typeOfResponse == "Scalar"

    If $typeOfResponse == Default Then
        $iArrResponse = $response
    ElseIf $bResponseIsArray Then
        $vectorResponse = Call("_VectorOf" & $typeOfResponse & "Create")

        $iArrResponseSize = UBound($response)
        For $i = 0 To $iArrResponseSize - 1
            Call("_VectorOf" & $typeOfResponse & "Push", $vectorResponse, $response[$i])
        Next

        $iArrResponse = Call("_cveInputArrayFromVectorOf" & $typeOfResponse, $vectorResponse)
    Else
        If $bResponseCreate Then
            $response = Call("_cve" & $typeOfResponse & "Create", $response)
        EndIf
        $iArrResponse = Call("_cveInputArrayFrom" & $typeOfResponse, $response)
    EndIf

    _cveAlignExposuresProcess($alignExposures, $iArrSrc, $dst, $iArrTimes, $iArrResponse)

    If $bResponseIsArray Then
        Call("_VectorOf" & $typeOfResponse & "Release", $vectorResponse)
    EndIf

    If $typeOfResponse <> Default Then
        _cveInputArrayRelease($iArrResponse)
        If $bResponseCreate Then
            Call("_cve" & $typeOfResponse & "Release", $response)
        EndIf
    EndIf

    If $bTimesIsArray Then
        Call("_VectorOf" & $typeOfTimes & "Release", $vectorTimes)
    EndIf

    If $typeOfTimes <> Default Then
        _cveInputArrayRelease($iArrTimes)
        If $bTimesCreate Then
            Call("_cve" & $typeOfTimes & "Release", $times)
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
EndFunc   ;==>_cveAlignExposuresProcessTyped

Func _cveAlignExposuresProcessMat($alignExposures, $src, $dst, $times, $response)
    ; cveAlignExposuresProcess using cv::Mat instead of _*Array
    _cveAlignExposuresProcessTyped($alignExposures, "Mat", $src, $dst, "Mat", $times, "Mat", $response)
EndFunc   ;==>_cveAlignExposuresProcessMat

Func _cveAlignMTBCreate($maxBits, $excludeRange, $cut, $alignExposures, $sharedPtr)
    ; CVAPI(cv::AlignMTB*) cveAlignMTBCreate(int maxBits, int excludeRange, bool cut, cv::AlignExposures** alignExposures, cv::Ptr<cv::AlignMTB>** sharedPtr);

    Local $sAlignExposuresDllType
    If IsDllStruct($alignExposures) Then
        $sAlignExposuresDllType = "struct*"
    ElseIf $alignExposures == Null Then
        $sAlignExposuresDllType = "ptr"
    Else
        $sAlignExposuresDllType = "ptr*"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveAlignMTBCreate", "int", $maxBits, "int", $excludeRange, "boolean", $cut, $sAlignExposuresDllType, $alignExposures, $sSharedPtrDllType, $sharedPtr), "cveAlignMTBCreate", @error)
EndFunc   ;==>_cveAlignMTBCreate

Func _cveAlignMTBRelease($alignExposures, $sharedPtr)
    ; CVAPI(void) cveAlignMTBRelease(cv::AlignMTB** alignExposures, cv::Ptr<cv::AlignMTB>** sharedPtr);

    Local $sAlignExposuresDllType
    If IsDllStruct($alignExposures) Then
        $sAlignExposuresDllType = "struct*"
    ElseIf $alignExposures == Null Then
        $sAlignExposuresDllType = "ptr"
    Else
        $sAlignExposuresDllType = "ptr*"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveAlignMTBRelease", $sAlignExposuresDllType, $alignExposures, $sSharedPtrDllType, $sharedPtr), "cveAlignMTBRelease", @error)
EndFunc   ;==>_cveAlignMTBRelease