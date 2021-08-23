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

Func _cveInpaintMat($matSrc, $matInpaintMask, $matDst, $inpaintRadius, $flags)
    ; cveInpaint using cv::Mat instead of _*Array

    Local $iArrSrc, $vectorOfMatSrc, $iArrSrcSize
    Local $bSrcIsArray = VarGetType($matSrc) == "Array"

    If $bSrcIsArray Then
        $vectorOfMatSrc = _VectorOfMatCreate()

        $iArrSrcSize = UBound($matSrc)
        For $i = 0 To $iArrSrcSize - 1
            _VectorOfMatPush($vectorOfMatSrc, $matSrc[$i])
        Next

        $iArrSrc = _cveInputArrayFromVectorOfMat($vectorOfMatSrc)
    Else
        $iArrSrc = _cveInputArrayFromMat($matSrc)
    EndIf

    Local $iArrInpaintMask, $vectorOfMatInpaintMask, $iArrInpaintMaskSize
    Local $bInpaintMaskIsArray = VarGetType($matInpaintMask) == "Array"

    If $bInpaintMaskIsArray Then
        $vectorOfMatInpaintMask = _VectorOfMatCreate()

        $iArrInpaintMaskSize = UBound($matInpaintMask)
        For $i = 0 To $iArrInpaintMaskSize - 1
            _VectorOfMatPush($vectorOfMatInpaintMask, $matInpaintMask[$i])
        Next

        $iArrInpaintMask = _cveInputArrayFromVectorOfMat($vectorOfMatInpaintMask)
    Else
        $iArrInpaintMask = _cveInputArrayFromMat($matInpaintMask)
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

    _cveInpaint($iArrSrc, $iArrInpaintMask, $oArrDst, $inpaintRadius, $flags)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveOutputArrayRelease($oArrDst)

    If $bInpaintMaskIsArray Then
        _VectorOfMatRelease($vectorOfMatInpaintMask)
    EndIf

    _cveInputArrayRelease($iArrInpaintMask)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)
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

Func _cveFastNlMeansDenoisingMat($matSrc, $matDst, $h = 3, $templateWindowSize = 7, $searchWindowSize = 21)
    ; cveFastNlMeansDenoising using cv::Mat instead of _*Array

    Local $iArrSrc, $vectorOfMatSrc, $iArrSrcSize
    Local $bSrcIsArray = VarGetType($matSrc) == "Array"

    If $bSrcIsArray Then
        $vectorOfMatSrc = _VectorOfMatCreate()

        $iArrSrcSize = UBound($matSrc)
        For $i = 0 To $iArrSrcSize - 1
            _VectorOfMatPush($vectorOfMatSrc, $matSrc[$i])
        Next

        $iArrSrc = _cveInputArrayFromVectorOfMat($vectorOfMatSrc)
    Else
        $iArrSrc = _cveInputArrayFromMat($matSrc)
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

    _cveFastNlMeansDenoising($iArrSrc, $oArrDst, $h, $templateWindowSize, $searchWindowSize)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveOutputArrayRelease($oArrDst)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)
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

Func _cveFastNlMeansDenoisingColoredMat($matSrc, $matDst, $h = 3, $hColor = 3, $templateWindowSize = 7, $searchWindowSize = 21)
    ; cveFastNlMeansDenoisingColored using cv::Mat instead of _*Array

    Local $iArrSrc, $vectorOfMatSrc, $iArrSrcSize
    Local $bSrcIsArray = VarGetType($matSrc) == "Array"

    If $bSrcIsArray Then
        $vectorOfMatSrc = _VectorOfMatCreate()

        $iArrSrcSize = UBound($matSrc)
        For $i = 0 To $iArrSrcSize - 1
            _VectorOfMatPush($vectorOfMatSrc, $matSrc[$i])
        Next

        $iArrSrc = _cveInputArrayFromVectorOfMat($vectorOfMatSrc)
    Else
        $iArrSrc = _cveInputArrayFromMat($matSrc)
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

    _cveFastNlMeansDenoisingColored($iArrSrc, $oArrDst, $h, $hColor, $templateWindowSize, $searchWindowSize)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveOutputArrayRelease($oArrDst)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)
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

Func _cveEdgePreservingFilterMat($matSrc, $matDst, $flags, $sigmaS, $sigmaR)
    ; cveEdgePreservingFilter using cv::Mat instead of _*Array

    Local $iArrSrc, $vectorOfMatSrc, $iArrSrcSize
    Local $bSrcIsArray = VarGetType($matSrc) == "Array"

    If $bSrcIsArray Then
        $vectorOfMatSrc = _VectorOfMatCreate()

        $iArrSrcSize = UBound($matSrc)
        For $i = 0 To $iArrSrcSize - 1
            _VectorOfMatPush($vectorOfMatSrc, $matSrc[$i])
        Next

        $iArrSrc = _cveInputArrayFromVectorOfMat($vectorOfMatSrc)
    Else
        $iArrSrc = _cveInputArrayFromMat($matSrc)
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

    _cveEdgePreservingFilter($iArrSrc, $oArrDst, $flags, $sigmaS, $sigmaR)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveOutputArrayRelease($oArrDst)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)
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

Func _cveDetailEnhanceMat($matSrc, $matDst, $sigmaS, $sigmaR)
    ; cveDetailEnhance using cv::Mat instead of _*Array

    Local $iArrSrc, $vectorOfMatSrc, $iArrSrcSize
    Local $bSrcIsArray = VarGetType($matSrc) == "Array"

    If $bSrcIsArray Then
        $vectorOfMatSrc = _VectorOfMatCreate()

        $iArrSrcSize = UBound($matSrc)
        For $i = 0 To $iArrSrcSize - 1
            _VectorOfMatPush($vectorOfMatSrc, $matSrc[$i])
        Next

        $iArrSrc = _cveInputArrayFromVectorOfMat($vectorOfMatSrc)
    Else
        $iArrSrc = _cveInputArrayFromMat($matSrc)
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

    _cveDetailEnhance($iArrSrc, $oArrDst, $sigmaS, $sigmaR)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveOutputArrayRelease($oArrDst)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)
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

Func _cvePencilSketchMat($matSrc, $matDst1, $matDst2, $sigmaS, $sigmaR, $shadeFactor)
    ; cvePencilSketch using cv::Mat instead of _*Array

    Local $iArrSrc, $vectorOfMatSrc, $iArrSrcSize
    Local $bSrcIsArray = VarGetType($matSrc) == "Array"

    If $bSrcIsArray Then
        $vectorOfMatSrc = _VectorOfMatCreate()

        $iArrSrcSize = UBound($matSrc)
        For $i = 0 To $iArrSrcSize - 1
            _VectorOfMatPush($vectorOfMatSrc, $matSrc[$i])
        Next

        $iArrSrc = _cveInputArrayFromVectorOfMat($vectorOfMatSrc)
    Else
        $iArrSrc = _cveInputArrayFromMat($matSrc)
    EndIf

    Local $oArrDst1, $vectorOfMatDst1, $iArrDst1Size
    Local $bDst1IsArray = VarGetType($matDst1) == "Array"

    If $bDst1IsArray Then
        $vectorOfMatDst1 = _VectorOfMatCreate()

        $iArrDst1Size = UBound($matDst1)
        For $i = 0 To $iArrDst1Size - 1
            _VectorOfMatPush($vectorOfMatDst1, $matDst1[$i])
        Next

        $oArrDst1 = _cveOutputArrayFromVectorOfMat($vectorOfMatDst1)
    Else
        $oArrDst1 = _cveOutputArrayFromMat($matDst1)
    EndIf

    Local $oArrDst2, $vectorOfMatDst2, $iArrDst2Size
    Local $bDst2IsArray = VarGetType($matDst2) == "Array"

    If $bDst2IsArray Then
        $vectorOfMatDst2 = _VectorOfMatCreate()

        $iArrDst2Size = UBound($matDst2)
        For $i = 0 To $iArrDst2Size - 1
            _VectorOfMatPush($vectorOfMatDst2, $matDst2[$i])
        Next

        $oArrDst2 = _cveOutputArrayFromVectorOfMat($vectorOfMatDst2)
    Else
        $oArrDst2 = _cveOutputArrayFromMat($matDst2)
    EndIf

    _cvePencilSketch($iArrSrc, $oArrDst1, $oArrDst2, $sigmaS, $sigmaR, $shadeFactor)

    If $bDst2IsArray Then
        _VectorOfMatRelease($vectorOfMatDst2)
    EndIf

    _cveOutputArrayRelease($oArrDst2)

    If $bDst1IsArray Then
        _VectorOfMatRelease($vectorOfMatDst1)
    EndIf

    _cveOutputArrayRelease($oArrDst1)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)
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

Func _cveStylizationMat($matSrc, $matDst, $sigmaS, $sigmaR)
    ; cveStylization using cv::Mat instead of _*Array

    Local $iArrSrc, $vectorOfMatSrc, $iArrSrcSize
    Local $bSrcIsArray = VarGetType($matSrc) == "Array"

    If $bSrcIsArray Then
        $vectorOfMatSrc = _VectorOfMatCreate()

        $iArrSrcSize = UBound($matSrc)
        For $i = 0 To $iArrSrcSize - 1
            _VectorOfMatPush($vectorOfMatSrc, $matSrc[$i])
        Next

        $iArrSrc = _cveInputArrayFromVectorOfMat($vectorOfMatSrc)
    Else
        $iArrSrc = _cveInputArrayFromMat($matSrc)
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

    _cveStylization($iArrSrc, $oArrDst, $sigmaS, $sigmaR)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveOutputArrayRelease($oArrDst)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)
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

Func _cveColorChangeMat($matSrc, $matMask, $matDst, $redMul, $greenMul, $blueMul)
    ; cveColorChange using cv::Mat instead of _*Array

    Local $iArrSrc, $vectorOfMatSrc, $iArrSrcSize
    Local $bSrcIsArray = VarGetType($matSrc) == "Array"

    If $bSrcIsArray Then
        $vectorOfMatSrc = _VectorOfMatCreate()

        $iArrSrcSize = UBound($matSrc)
        For $i = 0 To $iArrSrcSize - 1
            _VectorOfMatPush($vectorOfMatSrc, $matSrc[$i])
        Next

        $iArrSrc = _cveInputArrayFromVectorOfMat($vectorOfMatSrc)
    Else
        $iArrSrc = _cveInputArrayFromMat($matSrc)
    EndIf

    Local $iArrMask, $vectorOfMatMask, $iArrMaskSize
    Local $bMaskIsArray = VarGetType($matMask) == "Array"

    If $bMaskIsArray Then
        $vectorOfMatMask = _VectorOfMatCreate()

        $iArrMaskSize = UBound($matMask)
        For $i = 0 To $iArrMaskSize - 1
            _VectorOfMatPush($vectorOfMatMask, $matMask[$i])
        Next

        $iArrMask = _cveInputArrayFromVectorOfMat($vectorOfMatMask)
    Else
        $iArrMask = _cveInputArrayFromMat($matMask)
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

    _cveColorChange($iArrSrc, $iArrMask, $oArrDst, $redMul, $greenMul, $blueMul)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveOutputArrayRelease($oArrDst)

    If $bMaskIsArray Then
        _VectorOfMatRelease($vectorOfMatMask)
    EndIf

    _cveInputArrayRelease($iArrMask)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)
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

Func _cveIlluminationChangeMat($matSrc, $matMask, $matDst, $alpha = 0.2, $beta = 0.4)
    ; cveIlluminationChange using cv::Mat instead of _*Array

    Local $iArrSrc, $vectorOfMatSrc, $iArrSrcSize
    Local $bSrcIsArray = VarGetType($matSrc) == "Array"

    If $bSrcIsArray Then
        $vectorOfMatSrc = _VectorOfMatCreate()

        $iArrSrcSize = UBound($matSrc)
        For $i = 0 To $iArrSrcSize - 1
            _VectorOfMatPush($vectorOfMatSrc, $matSrc[$i])
        Next

        $iArrSrc = _cveInputArrayFromVectorOfMat($vectorOfMatSrc)
    Else
        $iArrSrc = _cveInputArrayFromMat($matSrc)
    EndIf

    Local $iArrMask, $vectorOfMatMask, $iArrMaskSize
    Local $bMaskIsArray = VarGetType($matMask) == "Array"

    If $bMaskIsArray Then
        $vectorOfMatMask = _VectorOfMatCreate()

        $iArrMaskSize = UBound($matMask)
        For $i = 0 To $iArrMaskSize - 1
            _VectorOfMatPush($vectorOfMatMask, $matMask[$i])
        Next

        $iArrMask = _cveInputArrayFromVectorOfMat($vectorOfMatMask)
    Else
        $iArrMask = _cveInputArrayFromMat($matMask)
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

    _cveIlluminationChange($iArrSrc, $iArrMask, $oArrDst, $alpha, $beta)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveOutputArrayRelease($oArrDst)

    If $bMaskIsArray Then
        _VectorOfMatRelease($vectorOfMatMask)
    EndIf

    _cveInputArrayRelease($iArrMask)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)
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

Func _cveTextureFlatteningMat($matSrc, $matMask, $matDst, $lowThreshold, $highThreshold, $kernelSize)
    ; cveTextureFlattening using cv::Mat instead of _*Array

    Local $iArrSrc, $vectorOfMatSrc, $iArrSrcSize
    Local $bSrcIsArray = VarGetType($matSrc) == "Array"

    If $bSrcIsArray Then
        $vectorOfMatSrc = _VectorOfMatCreate()

        $iArrSrcSize = UBound($matSrc)
        For $i = 0 To $iArrSrcSize - 1
            _VectorOfMatPush($vectorOfMatSrc, $matSrc[$i])
        Next

        $iArrSrc = _cveInputArrayFromVectorOfMat($vectorOfMatSrc)
    Else
        $iArrSrc = _cveInputArrayFromMat($matSrc)
    EndIf

    Local $iArrMask, $vectorOfMatMask, $iArrMaskSize
    Local $bMaskIsArray = VarGetType($matMask) == "Array"

    If $bMaskIsArray Then
        $vectorOfMatMask = _VectorOfMatCreate()

        $iArrMaskSize = UBound($matMask)
        For $i = 0 To $iArrMaskSize - 1
            _VectorOfMatPush($vectorOfMatMask, $matMask[$i])
        Next

        $iArrMask = _cveInputArrayFromVectorOfMat($vectorOfMatMask)
    Else
        $iArrMask = _cveInputArrayFromMat($matMask)
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

    _cveTextureFlattening($iArrSrc, $iArrMask, $oArrDst, $lowThreshold, $highThreshold, $kernelSize)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveOutputArrayRelease($oArrDst)

    If $bMaskIsArray Then
        _VectorOfMatRelease($vectorOfMatMask)
    EndIf

    _cveInputArrayRelease($iArrMask)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)
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

Func _cveDecolorMat($matSrc, $matGrayscale, $matColorBoost)
    ; cveDecolor using cv::Mat instead of _*Array

    Local $iArrSrc, $vectorOfMatSrc, $iArrSrcSize
    Local $bSrcIsArray = VarGetType($matSrc) == "Array"

    If $bSrcIsArray Then
        $vectorOfMatSrc = _VectorOfMatCreate()

        $iArrSrcSize = UBound($matSrc)
        For $i = 0 To $iArrSrcSize - 1
            _VectorOfMatPush($vectorOfMatSrc, $matSrc[$i])
        Next

        $iArrSrc = _cveInputArrayFromVectorOfMat($vectorOfMatSrc)
    Else
        $iArrSrc = _cveInputArrayFromMat($matSrc)
    EndIf

    Local $oArrGrayscale, $vectorOfMatGrayscale, $iArrGrayscaleSize
    Local $bGrayscaleIsArray = VarGetType($matGrayscale) == "Array"

    If $bGrayscaleIsArray Then
        $vectorOfMatGrayscale = _VectorOfMatCreate()

        $iArrGrayscaleSize = UBound($matGrayscale)
        For $i = 0 To $iArrGrayscaleSize - 1
            _VectorOfMatPush($vectorOfMatGrayscale, $matGrayscale[$i])
        Next

        $oArrGrayscale = _cveOutputArrayFromVectorOfMat($vectorOfMatGrayscale)
    Else
        $oArrGrayscale = _cveOutputArrayFromMat($matGrayscale)
    EndIf

    Local $oArrColorBoost, $vectorOfMatColorBoost, $iArrColorBoostSize
    Local $bColorBoostIsArray = VarGetType($matColorBoost) == "Array"

    If $bColorBoostIsArray Then
        $vectorOfMatColorBoost = _VectorOfMatCreate()

        $iArrColorBoostSize = UBound($matColorBoost)
        For $i = 0 To $iArrColorBoostSize - 1
            _VectorOfMatPush($vectorOfMatColorBoost, $matColorBoost[$i])
        Next

        $oArrColorBoost = _cveOutputArrayFromVectorOfMat($vectorOfMatColorBoost)
    Else
        $oArrColorBoost = _cveOutputArrayFromMat($matColorBoost)
    EndIf

    _cveDecolor($iArrSrc, $oArrGrayscale, $oArrColorBoost)

    If $bColorBoostIsArray Then
        _VectorOfMatRelease($vectorOfMatColorBoost)
    EndIf

    _cveOutputArrayRelease($oArrColorBoost)

    If $bGrayscaleIsArray Then
        _VectorOfMatRelease($vectorOfMatGrayscale)
    EndIf

    _cveOutputArrayRelease($oArrGrayscale)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)
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

Func _cveSeamlessCloneMat($matSrc, $matDst, $matMask, $p, $matBlend, $flags)
    ; cveSeamlessClone using cv::Mat instead of _*Array

    Local $iArrSrc, $vectorOfMatSrc, $iArrSrcSize
    Local $bSrcIsArray = VarGetType($matSrc) == "Array"

    If $bSrcIsArray Then
        $vectorOfMatSrc = _VectorOfMatCreate()

        $iArrSrcSize = UBound($matSrc)
        For $i = 0 To $iArrSrcSize - 1
            _VectorOfMatPush($vectorOfMatSrc, $matSrc[$i])
        Next

        $iArrSrc = _cveInputArrayFromVectorOfMat($vectorOfMatSrc)
    Else
        $iArrSrc = _cveInputArrayFromMat($matSrc)
    EndIf

    Local $iArrDst, $vectorOfMatDst, $iArrDstSize
    Local $bDstIsArray = VarGetType($matDst) == "Array"

    If $bDstIsArray Then
        $vectorOfMatDst = _VectorOfMatCreate()

        $iArrDstSize = UBound($matDst)
        For $i = 0 To $iArrDstSize - 1
            _VectorOfMatPush($vectorOfMatDst, $matDst[$i])
        Next

        $iArrDst = _cveInputArrayFromVectorOfMat($vectorOfMatDst)
    Else
        $iArrDst = _cveInputArrayFromMat($matDst)
    EndIf

    Local $iArrMask, $vectorOfMatMask, $iArrMaskSize
    Local $bMaskIsArray = VarGetType($matMask) == "Array"

    If $bMaskIsArray Then
        $vectorOfMatMask = _VectorOfMatCreate()

        $iArrMaskSize = UBound($matMask)
        For $i = 0 To $iArrMaskSize - 1
            _VectorOfMatPush($vectorOfMatMask, $matMask[$i])
        Next

        $iArrMask = _cveInputArrayFromVectorOfMat($vectorOfMatMask)
    Else
        $iArrMask = _cveInputArrayFromMat($matMask)
    EndIf

    Local $oArrBlend, $vectorOfMatBlend, $iArrBlendSize
    Local $bBlendIsArray = VarGetType($matBlend) == "Array"

    If $bBlendIsArray Then
        $vectorOfMatBlend = _VectorOfMatCreate()

        $iArrBlendSize = UBound($matBlend)
        For $i = 0 To $iArrBlendSize - 1
            _VectorOfMatPush($vectorOfMatBlend, $matBlend[$i])
        Next

        $oArrBlend = _cveOutputArrayFromVectorOfMat($vectorOfMatBlend)
    Else
        $oArrBlend = _cveOutputArrayFromMat($matBlend)
    EndIf

    _cveSeamlessClone($iArrSrc, $iArrDst, $iArrMask, $p, $oArrBlend, $flags)

    If $bBlendIsArray Then
        _VectorOfMatRelease($vectorOfMatBlend)
    EndIf

    _cveOutputArrayRelease($oArrBlend)

    If $bMaskIsArray Then
        _VectorOfMatRelease($vectorOfMatMask)
    EndIf

    _cveInputArrayRelease($iArrMask)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveInputArrayRelease($iArrDst)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)
EndFunc   ;==>_cveSeamlessCloneMat

Func _cveDenoiseTVL1($observations, $result, $lambda, $niters)
    ; CVAPI(void) cveDenoiseTVL1(const std::vector<cv::Mat>* observations, cv::Mat* result, double lambda, int niters);

    Local $vecObservations, $iArrObservationsSize
    Local $bObservationsIsArray = VarGetType($observations) == "Array"

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

Func _cveCalibrateCRFProcessMat($calibrateCRF, $matSrc, $matDst, $matTimes)
    ; cveCalibrateCRFProcess using cv::Mat instead of _*Array

    Local $iArrSrc, $vectorOfMatSrc, $iArrSrcSize
    Local $bSrcIsArray = VarGetType($matSrc) == "Array"

    If $bSrcIsArray Then
        $vectorOfMatSrc = _VectorOfMatCreate()

        $iArrSrcSize = UBound($matSrc)
        For $i = 0 To $iArrSrcSize - 1
            _VectorOfMatPush($vectorOfMatSrc, $matSrc[$i])
        Next

        $iArrSrc = _cveInputArrayFromVectorOfMat($vectorOfMatSrc)
    Else
        $iArrSrc = _cveInputArrayFromMat($matSrc)
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

    Local $iArrTimes, $vectorOfMatTimes, $iArrTimesSize
    Local $bTimesIsArray = VarGetType($matTimes) == "Array"

    If $bTimesIsArray Then
        $vectorOfMatTimes = _VectorOfMatCreate()

        $iArrTimesSize = UBound($matTimes)
        For $i = 0 To $iArrTimesSize - 1
            _VectorOfMatPush($vectorOfMatTimes, $matTimes[$i])
        Next

        $iArrTimes = _cveInputArrayFromVectorOfMat($vectorOfMatTimes)
    Else
        $iArrTimes = _cveInputArrayFromMat($matTimes)
    EndIf

    _cveCalibrateCRFProcess($calibrateCRF, $iArrSrc, $oArrDst, $iArrTimes)

    If $bTimesIsArray Then
        _VectorOfMatRelease($vectorOfMatTimes)
    EndIf

    _cveInputArrayRelease($iArrTimes)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveOutputArrayRelease($oArrDst)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)
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

Func _cveMergeExposuresProcessMat($mergeExposures, $matSrc, $matDst, $matTimes, $matResponse)
    ; cveMergeExposuresProcess using cv::Mat instead of _*Array

    Local $iArrSrc, $vectorOfMatSrc, $iArrSrcSize
    Local $bSrcIsArray = VarGetType($matSrc) == "Array"

    If $bSrcIsArray Then
        $vectorOfMatSrc = _VectorOfMatCreate()

        $iArrSrcSize = UBound($matSrc)
        For $i = 0 To $iArrSrcSize - 1
            _VectorOfMatPush($vectorOfMatSrc, $matSrc[$i])
        Next

        $iArrSrc = _cveInputArrayFromVectorOfMat($vectorOfMatSrc)
    Else
        $iArrSrc = _cveInputArrayFromMat($matSrc)
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

    Local $iArrTimes, $vectorOfMatTimes, $iArrTimesSize
    Local $bTimesIsArray = VarGetType($matTimes) == "Array"

    If $bTimesIsArray Then
        $vectorOfMatTimes = _VectorOfMatCreate()

        $iArrTimesSize = UBound($matTimes)
        For $i = 0 To $iArrTimesSize - 1
            _VectorOfMatPush($vectorOfMatTimes, $matTimes[$i])
        Next

        $iArrTimes = _cveInputArrayFromVectorOfMat($vectorOfMatTimes)
    Else
        $iArrTimes = _cveInputArrayFromMat($matTimes)
    EndIf

    Local $iArrResponse, $vectorOfMatResponse, $iArrResponseSize
    Local $bResponseIsArray = VarGetType($matResponse) == "Array"

    If $bResponseIsArray Then
        $vectorOfMatResponse = _VectorOfMatCreate()

        $iArrResponseSize = UBound($matResponse)
        For $i = 0 To $iArrResponseSize - 1
            _VectorOfMatPush($vectorOfMatResponse, $matResponse[$i])
        Next

        $iArrResponse = _cveInputArrayFromVectorOfMat($vectorOfMatResponse)
    Else
        $iArrResponse = _cveInputArrayFromMat($matResponse)
    EndIf

    _cveMergeExposuresProcess($mergeExposures, $iArrSrc, $oArrDst, $iArrTimes, $iArrResponse)

    If $bResponseIsArray Then
        _VectorOfMatRelease($vectorOfMatResponse)
    EndIf

    _cveInputArrayRelease($iArrResponse)

    If $bTimesIsArray Then
        _VectorOfMatRelease($vectorOfMatTimes)
    EndIf

    _cveInputArrayRelease($iArrTimes)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveOutputArrayRelease($oArrDst)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)
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

Func _cveTonemapProcessMat($tonemap, $matSrc, $matDst)
    ; cveTonemapProcess using cv::Mat instead of _*Array

    Local $iArrSrc, $vectorOfMatSrc, $iArrSrcSize
    Local $bSrcIsArray = VarGetType($matSrc) == "Array"

    If $bSrcIsArray Then
        $vectorOfMatSrc = _VectorOfMatCreate()

        $iArrSrcSize = UBound($matSrc)
        For $i = 0 To $iArrSrcSize - 1
            _VectorOfMatPush($vectorOfMatSrc, $matSrc[$i])
        Next

        $iArrSrc = _cveInputArrayFromVectorOfMat($vectorOfMatSrc)
    Else
        $iArrSrc = _cveInputArrayFromMat($matSrc)
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

    _cveTonemapProcess($tonemap, $iArrSrc, $oArrDst)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveOutputArrayRelease($oArrDst)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)
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
    Local $bDstIsArray = VarGetType($dst) == "Array"

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

Func _cveAlignExposuresProcessMat($alignExposures, $matSrc, $dst, $matTimes, $matResponse)
    ; cveAlignExposuresProcess using cv::Mat instead of _*Array

    Local $iArrSrc, $vectorOfMatSrc, $iArrSrcSize
    Local $bSrcIsArray = VarGetType($matSrc) == "Array"

    If $bSrcIsArray Then
        $vectorOfMatSrc = _VectorOfMatCreate()

        $iArrSrcSize = UBound($matSrc)
        For $i = 0 To $iArrSrcSize - 1
            _VectorOfMatPush($vectorOfMatSrc, $matSrc[$i])
        Next

        $iArrSrc = _cveInputArrayFromVectorOfMat($vectorOfMatSrc)
    Else
        $iArrSrc = _cveInputArrayFromMat($matSrc)
    EndIf

    Local $iArrTimes, $vectorOfMatTimes, $iArrTimesSize
    Local $bTimesIsArray = VarGetType($matTimes) == "Array"

    If $bTimesIsArray Then
        $vectorOfMatTimes = _VectorOfMatCreate()

        $iArrTimesSize = UBound($matTimes)
        For $i = 0 To $iArrTimesSize - 1
            _VectorOfMatPush($vectorOfMatTimes, $matTimes[$i])
        Next

        $iArrTimes = _cveInputArrayFromVectorOfMat($vectorOfMatTimes)
    Else
        $iArrTimes = _cveInputArrayFromMat($matTimes)
    EndIf

    Local $iArrResponse, $vectorOfMatResponse, $iArrResponseSize
    Local $bResponseIsArray = VarGetType($matResponse) == "Array"

    If $bResponseIsArray Then
        $vectorOfMatResponse = _VectorOfMatCreate()

        $iArrResponseSize = UBound($matResponse)
        For $i = 0 To $iArrResponseSize - 1
            _VectorOfMatPush($vectorOfMatResponse, $matResponse[$i])
        Next

        $iArrResponse = _cveInputArrayFromVectorOfMat($vectorOfMatResponse)
    Else
        $iArrResponse = _cveInputArrayFromMat($matResponse)
    EndIf

    _cveAlignExposuresProcess($alignExposures, $iArrSrc, $dst, $iArrTimes, $iArrResponse)

    If $bResponseIsArray Then
        _VectorOfMatRelease($vectorOfMatResponse)
    EndIf

    _cveInputArrayRelease($iArrResponse)

    If $bTimesIsArray Then
        _VectorOfMatRelease($vectorOfMatTimes)
    EndIf

    _cveInputArrayRelease($iArrTimes)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)
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