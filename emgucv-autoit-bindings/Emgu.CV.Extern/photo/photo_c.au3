#include-once
#include "..\..\CVEUtils.au3"

Func _cveInpaint(ByRef $src, ByRef $inpaintMask, ByRef $dst, $inpaintRadius, $flags)
    ; CVAPI(void) cveInpaint(cv::_InputArray* src, cv::_InputArray* inpaintMask, cv::_OutputArray* dst, double inpaintRadius, int flags);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveInpaint", "ptr", $src, "ptr", $inpaintMask, "ptr", $dst, "double", $inpaintRadius, "int", $flags), "cveInpaint", @error)
EndFunc   ;==>_cveInpaint

Func _cveInpaintMat(ByRef $matSrc, ByRef $matInpaintMask, ByRef $matDst, $inpaintRadius, $flags)
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

Func _cveFastNlMeansDenoising(ByRef $src, ByRef $dst, $h = 3, $templateWindowSize = 7, $searchWindowSize = 21)
    ; CVAPI(void) cveFastNlMeansDenoising(cv::_InputArray* src, cv::_OutputArray* dst, float h, int templateWindowSize, int searchWindowSize);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFastNlMeansDenoising", "ptr", $src, "ptr", $dst, "float", $h, "int", $templateWindowSize, "int", $searchWindowSize), "cveFastNlMeansDenoising", @error)
EndFunc   ;==>_cveFastNlMeansDenoising

Func _cveFastNlMeansDenoisingMat(ByRef $matSrc, ByRef $matDst, $h = 3, $templateWindowSize = 7, $searchWindowSize = 21)
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

Func _cveFastNlMeansDenoisingColored(ByRef $src, ByRef $dst, $h = 3, $hColor = 3, $templateWindowSize = 7, $searchWindowSize = 21)
    ; CVAPI(void) cveFastNlMeansDenoisingColored(cv::_InputArray* src, cv::_OutputArray* dst, float h, float hColor, int templateWindowSize, int searchWindowSize);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFastNlMeansDenoisingColored", "ptr", $src, "ptr", $dst, "float", $h, "float", $hColor, "int", $templateWindowSize, "int", $searchWindowSize), "cveFastNlMeansDenoisingColored", @error)
EndFunc   ;==>_cveFastNlMeansDenoisingColored

Func _cveFastNlMeansDenoisingColoredMat(ByRef $matSrc, ByRef $matDst, $h = 3, $hColor = 3, $templateWindowSize = 7, $searchWindowSize = 21)
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

Func _cudaNonLocalMeans($src, ByRef $dst, $h, $searchWindow, $blockSize, $borderMode, ByRef $stream)
    ; CVAPI(void) cudaNonLocalMeans(const cv::cuda::GpuMat* src, cv::cuda::GpuMat* dst, float h, int searchWindow, int blockSize, int borderMode, cv::cuda::Stream* stream);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaNonLocalMeans", "ptr", $src, "ptr", $dst, "float", $h, "int", $searchWindow, "int", $blockSize, "int", $borderMode, "ptr", $stream), "cudaNonLocalMeans", @error)
EndFunc   ;==>_cudaNonLocalMeans

Func _cveEdgePreservingFilter(ByRef $src, ByRef $dst, $flags, $sigmaS, $sigmaR)
    ; CVAPI(void) cveEdgePreservingFilter(cv::_InputArray* src, cv::_OutputArray* dst, int flags, float sigmaS, float sigmaR);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveEdgePreservingFilter", "ptr", $src, "ptr", $dst, "int", $flags, "float", $sigmaS, "float", $sigmaR), "cveEdgePreservingFilter", @error)
EndFunc   ;==>_cveEdgePreservingFilter

Func _cveEdgePreservingFilterMat(ByRef $matSrc, ByRef $matDst, $flags, $sigmaS, $sigmaR)
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

Func _cveDetailEnhance(ByRef $src, ByRef $dst, $sigmaS, $sigmaR)
    ; CVAPI(void) cveDetailEnhance(cv::_InputArray* src, cv::_OutputArray* dst, float sigmaS, float sigmaR);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDetailEnhance", "ptr", $src, "ptr", $dst, "float", $sigmaS, "float", $sigmaR), "cveDetailEnhance", @error)
EndFunc   ;==>_cveDetailEnhance

Func _cveDetailEnhanceMat(ByRef $matSrc, ByRef $matDst, $sigmaS, $sigmaR)
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

Func _cvePencilSketch(ByRef $src, ByRef $dst1, ByRef $dst2, $sigmaS, $sigmaR, $shadeFactor)
    ; CVAPI(void) cvePencilSketch(cv::_InputArray* src, cv::_OutputArray* dst1, cv::_OutputArray* dst2, float sigmaS, float sigmaR, float shadeFactor);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cvePencilSketch", "ptr", $src, "ptr", $dst1, "ptr", $dst2, "float", $sigmaS, "float", $sigmaR, "float", $shadeFactor), "cvePencilSketch", @error)
EndFunc   ;==>_cvePencilSketch

Func _cvePencilSketchMat(ByRef $matSrc, ByRef $matDst1, ByRef $matDst2, $sigmaS, $sigmaR, $shadeFactor)
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

Func _cveStylization(ByRef $src, ByRef $dst, $sigmaS, $sigmaR)
    ; CVAPI(void) cveStylization(cv::_InputArray* src, cv::_OutputArray* dst, float sigmaS, float sigmaR);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveStylization", "ptr", $src, "ptr", $dst, "float", $sigmaS, "float", $sigmaR), "cveStylization", @error)
EndFunc   ;==>_cveStylization

Func _cveStylizationMat(ByRef $matSrc, ByRef $matDst, $sigmaS, $sigmaR)
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

Func _cveColorChange(ByRef $src, ByRef $mask, ByRef $dst, $redMul, $greenMul, $blueMul)
    ; CVAPI(void) cveColorChange(cv::_InputArray* src, cv::_InputArray* mask, cv::_OutputArray* dst, float redMul, float greenMul, float blueMul);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveColorChange", "ptr", $src, "ptr", $mask, "ptr", $dst, "float", $redMul, "float", $greenMul, "float", $blueMul), "cveColorChange", @error)
EndFunc   ;==>_cveColorChange

Func _cveColorChangeMat(ByRef $matSrc, ByRef $matMask, ByRef $matDst, $redMul, $greenMul, $blueMul)
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

Func _cveIlluminationChange(ByRef $src, ByRef $mask, ByRef $dst, $alpha = 0.2, $beta = 0.4)
    ; CVAPI(void) cveIlluminationChange(cv::_InputArray* src, cv::_InputArray* mask, cv::_OutputArray* dst, float alpha, float beta);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveIlluminationChange", "ptr", $src, "ptr", $mask, "ptr", $dst, "float", $alpha, "float", $beta), "cveIlluminationChange", @error)
EndFunc   ;==>_cveIlluminationChange

Func _cveIlluminationChangeMat(ByRef $matSrc, ByRef $matMask, ByRef $matDst, $alpha = 0.2, $beta = 0.4)
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

Func _cveTextureFlattening(ByRef $src, ByRef $mask, ByRef $dst, $lowThreshold, $highThreshold, $kernelSize)
    ; CVAPI(void) cveTextureFlattening(cv::_InputArray* src, cv::_InputArray* mask, cv::_OutputArray* dst, float lowThreshold, float highThreshold, int kernelSize);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveTextureFlattening", "ptr", $src, "ptr", $mask, "ptr", $dst, "float", $lowThreshold, "float", $highThreshold, "int", $kernelSize), "cveTextureFlattening", @error)
EndFunc   ;==>_cveTextureFlattening

Func _cveTextureFlatteningMat(ByRef $matSrc, ByRef $matMask, ByRef $matDst, $lowThreshold, $highThreshold, $kernelSize)
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

Func _cveDecolor(ByRef $src, ByRef $grayscale, ByRef $colorBoost)
    ; CVAPI(void) cveDecolor(cv::_InputArray* src, cv::_OutputArray* grayscale, cv::_OutputArray* colorBoost);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDecolor", "ptr", $src, "ptr", $grayscale, "ptr", $colorBoost), "cveDecolor", @error)
EndFunc   ;==>_cveDecolor

Func _cveDecolorMat(ByRef $matSrc, ByRef $matGrayscale, ByRef $matColorBoost)
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

Func _cveSeamlessClone(ByRef $src, ByRef $dst, ByRef $mask, ByRef $p, ByRef $blend, $flags)
    ; CVAPI(void) cveSeamlessClone(cv::_InputArray* src, cv::_InputArray* dst, cv::_InputArray* mask, CvPoint* p, cv::_OutputArray* blend, int flags);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSeamlessClone", "ptr", $src, "ptr", $dst, "ptr", $mask, "struct*", $p, "ptr", $blend, "int", $flags), "cveSeamlessClone", @error)
EndFunc   ;==>_cveSeamlessClone

Func _cveSeamlessCloneMat(ByRef $matSrc, ByRef $matDst, ByRef $matMask, ByRef $p, ByRef $matBlend, $flags)
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

Func _cveDenoiseTVL1($observations, ByRef $result, $lambda, $niters)
    ; CVAPI(void) cveDenoiseTVL1(const std::vector< cv::Mat >* observations, cv::Mat* result, double lambda, int niters);

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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDenoiseTVL1", "ptr", $vecObservations, "ptr", $result, "double", $lambda, "int", $niters), "cveDenoiseTVL1", @error)

    If $bObservationsIsArray Then
        _VectorOfMatRelease($vecObservations)
    EndIf
EndFunc   ;==>_cveDenoiseTVL1

Func _cveCalibrateCRFProcess(ByRef $calibrateCRF, ByRef $src, ByRef $dst, ByRef $times)
    ; CVAPI(void) cveCalibrateCRFProcess(cv::CalibrateCRF* calibrateCRF, cv::_InputArray* src, cv::_OutputArray* dst, cv::_InputArray* times);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCalibrateCRFProcess", "ptr", $calibrateCRF, "ptr", $src, "ptr", $dst, "ptr", $times), "cveCalibrateCRFProcess", @error)
EndFunc   ;==>_cveCalibrateCRFProcess

Func _cveCalibrateCRFProcessMat(ByRef $calibrateCRF, ByRef $matSrc, ByRef $matDst, ByRef $matTimes)
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

Func _cveCalibrateDebevecCreate($samples, $lambda, $random, ByRef $calibrateCRF, ByRef $sharedPtr)
    ; CVAPI(cv::CalibrateDebevec*) cveCalibrateDebevecCreate(int samples, float lambda, bool random, cv::CalibrateCRF** calibrateCRF, cv::Ptr<cv::CalibrateDebevec>** sharedPtr);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveCalibrateDebevecCreate", "int", $samples, "float", $lambda, "boolean", $random, "ptr*", $calibrateCRF, "ptr*", $sharedPtr), "cveCalibrateDebevecCreate", @error)
EndFunc   ;==>_cveCalibrateDebevecCreate

Func _cveCalibrateDebevecRelease(ByRef $calibrateDebevec, ByRef $sharedPtr)
    ; CVAPI(void) cveCalibrateDebevecRelease(cv::CalibrateDebevec** calibrateDebevec, cv::Ptr<cv::CalibrateDebevec>** sharedPtr);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCalibrateDebevecRelease", "ptr*", $calibrateDebevec, "ptr*", $sharedPtr), "cveCalibrateDebevecRelease", @error)
EndFunc   ;==>_cveCalibrateDebevecRelease

Func _cveCalibrateRobertsonCreate($maxIter, $threshold, ByRef $calibrateCRF, ByRef $sharedPtr)
    ; CVAPI(cv::CalibrateRobertson*) cveCalibrateRobertsonCreate(int maxIter, float threshold, cv::CalibrateCRF** calibrateCRF, cv::Ptr<cv::CalibrateRobertson>** sharedPtr);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveCalibrateRobertsonCreate", "int", $maxIter, "float", $threshold, "ptr*", $calibrateCRF, "ptr*", $sharedPtr), "cveCalibrateRobertsonCreate", @error)
EndFunc   ;==>_cveCalibrateRobertsonCreate

Func _cveCalibrateRobertsonRelease(ByRef $calibrateRobertson, ByRef $sharedPtr)
    ; CVAPI(void) cveCalibrateRobertsonRelease(cv::CalibrateRobertson** calibrateRobertson, cv::Ptr<cv::CalibrateRobertson>** sharedPtr);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCalibrateRobertsonRelease", "ptr*", $calibrateRobertson, "ptr*", $sharedPtr), "cveCalibrateRobertsonRelease", @error)
EndFunc   ;==>_cveCalibrateRobertsonRelease

Func _cveMergeExposuresProcess(ByRef $mergeExposures, ByRef $src, ByRef $dst, ByRef $times, ByRef $response)
    ; CVAPI(void) cveMergeExposuresProcess(cv::MergeExposures* mergeExposures, cv::_InputArray* src, cv::_OutputArray* dst, cv::_InputArray* times, cv::_InputArray* response);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMergeExposuresProcess", "ptr", $mergeExposures, "ptr", $src, "ptr", $dst, "ptr", $times, "ptr", $response), "cveMergeExposuresProcess", @error)
EndFunc   ;==>_cveMergeExposuresProcess

Func _cveMergeExposuresProcessMat(ByRef $mergeExposures, ByRef $matSrc, ByRef $matDst, ByRef $matTimes, ByRef $matResponse)
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

Func _cveMergeDebevecCreate(ByRef $merge, ByRef $sharedPtr)
    ; CVAPI(cv::MergeDebevec*) cveMergeDebevecCreate(cv::MergeExposures** merge, cv::Ptr<cv::MergeDebevec>** sharedPtr);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveMergeDebevecCreate", "ptr*", $merge, "ptr*", $sharedPtr), "cveMergeDebevecCreate", @error)
EndFunc   ;==>_cveMergeDebevecCreate

Func _cveMergeDebevecRelease(ByRef $merge, ByRef $sharedPtr)
    ; CVAPI(void) cveMergeDebevecRelease(cv::MergeDebevec** merge, cv::Ptr<cv::MergeDebevec>** sharedPtr);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMergeDebevecRelease", "ptr*", $merge, "ptr*", $sharedPtr), "cveMergeDebevecRelease", @error)
EndFunc   ;==>_cveMergeDebevecRelease

Func _cveMergeMertensCreate($contrastWeight, $saturationWeight, $exposureWeight, ByRef $merge, ByRef $sharedPtr)
    ; CVAPI(cv::MergeMertens*) cveMergeMertensCreate(float contrastWeight, float saturationWeight, float exposureWeight, cv::MergeExposures** merge, cv::Ptr<cv::MergeMertens>** sharedPtr);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveMergeMertensCreate", "float", $contrastWeight, "float", $saturationWeight, "float", $exposureWeight, "ptr*", $merge, "ptr*", $sharedPtr), "cveMergeMertensCreate", @error)
EndFunc   ;==>_cveMergeMertensCreate

Func _cveMergeMertensRelease(ByRef $merge, ByRef $sharedPtr)
    ; CVAPI(void) cveMergeMertensRelease(cv::MergeMertens** merge, cv::Ptr<cv::MergeMertens>** sharedPtr);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMergeMertensRelease", "ptr*", $merge, "ptr*", $sharedPtr), "cveMergeMertensRelease", @error)
EndFunc   ;==>_cveMergeMertensRelease

Func _cveMergeRobertsonCreate(ByRef $merge, ByRef $sharedPtr)
    ; CVAPI(cv::MergeRobertson*) cveMergeRobertsonCreate(cv::MergeExposures** merge, cv::Ptr<cv::MergeRobertson>** sharedPtr);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveMergeRobertsonCreate", "ptr*", $merge, "ptr*", $sharedPtr), "cveMergeRobertsonCreate", @error)
EndFunc   ;==>_cveMergeRobertsonCreate

Func _cveMergeRobertsonRelease(ByRef $merge, ByRef $sharedPtr)
    ; CVAPI(void) cveMergeRobertsonRelease(cv::MergeRobertson** merge, cv::Ptr<cv::MergeRobertson>** sharedPtr);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMergeRobertsonRelease", "ptr*", $merge, "ptr*", $sharedPtr), "cveMergeRobertsonRelease", @error)
EndFunc   ;==>_cveMergeRobertsonRelease

Func _cveTonemapProcess(ByRef $tonemap, ByRef $src, ByRef $dst)
    ; CVAPI(void) cveTonemapProcess(cv::Tonemap* tonemap, cv::_InputArray* src, cv::_OutputArray* dst);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveTonemapProcess", "ptr", $tonemap, "ptr", $src, "ptr", $dst), "cveTonemapProcess", @error)
EndFunc   ;==>_cveTonemapProcess

Func _cveTonemapProcessMat(ByRef $tonemap, ByRef $matSrc, ByRef $matDst)
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

Func _cveTonemapCreate($gamma, ByRef $algorithm, ByRef $sharedPtr)
    ; CVAPI(cv::Tonemap*) cveTonemapCreate(float gamma, cv::Algorithm** algorithm, cv::Ptr<cv::Tonemap>** sharedPtr);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveTonemapCreate", "float", $gamma, "ptr*", $algorithm, "ptr*", $sharedPtr), "cveTonemapCreate", @error)
EndFunc   ;==>_cveTonemapCreate

Func _cveTonemapRelease(ByRef $tonemap, ByRef $sharedPtr)
    ; CVAPI(void) cveTonemapRelease(cv::Tonemap** tonemap, cv::Ptr<cv::Tonemap>** sharedPtr);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveTonemapRelease", "ptr*", $tonemap, "ptr*", $sharedPtr), "cveTonemapRelease", @error)
EndFunc   ;==>_cveTonemapRelease

Func _cveTonemapDragoCreate($gamma, $saturation, $bias, ByRef $tonemap, ByRef $algorithm, ByRef $sharedPtr)
    ; CVAPI(cv::TonemapDrago*) cveTonemapDragoCreate(float gamma, float saturation, float bias, cv::Tonemap** tonemap, cv::Algorithm** algorithm, cv::Ptr<cv::TonemapDrago>** sharedPtr);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveTonemapDragoCreate", "float", $gamma, "float", $saturation, "float", $bias, "ptr*", $tonemap, "ptr*", $algorithm, "ptr*", $sharedPtr), "cveTonemapDragoCreate", @error)
EndFunc   ;==>_cveTonemapDragoCreate

Func _cveTonemapDragoRelease(ByRef $tonemap, ByRef $sharedPtr)
    ; CVAPI(void) cveTonemapDragoRelease(cv::TonemapDrago** tonemap, cv::Ptr<cv::TonemapDrago>** sharedPtr);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveTonemapDragoRelease", "ptr*", $tonemap, "ptr*", $sharedPtr), "cveTonemapDragoRelease", @error)
EndFunc   ;==>_cveTonemapDragoRelease

Func _cveTonemapReinhardCreate($gamma, $intensity, $lightAdapt, $colorAdapt, ByRef $tonemap, ByRef $algorithm, ByRef $sharedPtr)
    ; CVAPI(cv::TonemapReinhard*) cveTonemapReinhardCreate(float gamma, float intensity, float lightAdapt, float colorAdapt, cv::Tonemap** tonemap, cv::Algorithm** algorithm, cv::Ptr<cv::TonemapReinhard>** sharedPtr);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveTonemapReinhardCreate", "float", $gamma, "float", $intensity, "float", $lightAdapt, "float", $colorAdapt, "ptr*", $tonemap, "ptr*", $algorithm, "ptr*", $sharedPtr), "cveTonemapReinhardCreate", @error)
EndFunc   ;==>_cveTonemapReinhardCreate

Func _cveTonemapReinhardRelease(ByRef $tonemap, ByRef $sharedPtr)
    ; CVAPI(void) cveTonemapReinhardRelease(cv::TonemapReinhard** tonemap, cv::Ptr<cv::TonemapReinhard>** sharedPtr);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveTonemapReinhardRelease", "ptr*", $tonemap, "ptr*", $sharedPtr), "cveTonemapReinhardRelease", @error)
EndFunc   ;==>_cveTonemapReinhardRelease

Func _cveTonemapMantiukCreate($gamma, $scale, $saturation, ByRef $tonemap, ByRef $algorithm, ByRef $sharedPtr)
    ; CVAPI(cv::TonemapMantiuk*) cveTonemapMantiukCreate(float gamma, float scale, float saturation, cv::Tonemap** tonemap, cv::Algorithm** algorithm, cv::Ptr<cv::TonemapMantiuk>** sharedPtr);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveTonemapMantiukCreate", "float", $gamma, "float", $scale, "float", $saturation, "ptr*", $tonemap, "ptr*", $algorithm, "ptr*", $sharedPtr), "cveTonemapMantiukCreate", @error)
EndFunc   ;==>_cveTonemapMantiukCreate

Func _cveTonemapMantiukRelease(ByRef $tonemap, ByRef $sharedPtr)
    ; CVAPI(void) cveTonemapMantiukRelease(cv::TonemapMantiuk** tonemap, cv::Ptr<cv::TonemapMantiuk>** sharedPtr);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveTonemapMantiukRelease", "ptr*", $tonemap, "ptr*", $sharedPtr), "cveTonemapMantiukRelease", @error)
EndFunc   ;==>_cveTonemapMantiukRelease

Func _cveAlignExposuresProcess(ByRef $alignExposures, ByRef $src, ByRef $dst, ByRef $times, ByRef $response)
    ; CVAPI(void) cveAlignExposuresProcess(cv::AlignExposures* alignExposures, cv::_InputArray* src, std::vector<cv::Mat>* dst, cv::_InputArray* times, cv::_InputArray* response);

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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveAlignExposuresProcess", "ptr", $alignExposures, "ptr", $src, "ptr", $vecDst, "ptr", $times, "ptr", $response), "cveAlignExposuresProcess", @error)

    If $bDstIsArray Then
        _VectorOfMatRelease($vecDst)
    EndIf
EndFunc   ;==>_cveAlignExposuresProcess

Func _cveAlignExposuresProcessMat(ByRef $alignExposures, ByRef $matSrc, ByRef $dst, ByRef $matTimes, ByRef $matResponse)
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

Func _cveAlignMTBCreate($maxBits, $excludeRange, $cut, ByRef $alignExposures, ByRef $sharedPtr)
    ; CVAPI(cv::AlignMTB*) cveAlignMTBCreate(int maxBits, int excludeRange, bool cut, cv::AlignExposures** alignExposures, cv::Ptr<cv::AlignMTB>** sharedPtr);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveAlignMTBCreate", "int", $maxBits, "int", $excludeRange, "boolean", $cut, "ptr*", $alignExposures, "ptr*", $sharedPtr), "cveAlignMTBCreate", @error)
EndFunc   ;==>_cveAlignMTBCreate

Func _cveAlignMTBRelease(ByRef $alignExposures, ByRef $sharedPtr)
    ; CVAPI(void) cveAlignMTBRelease(cv::AlignMTB** alignExposures, cv::Ptr<cv::AlignMTB>** sharedPtr);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveAlignMTBRelease", "ptr*", $alignExposures, "ptr*", $sharedPtr), "cveAlignMTBRelease", @error)
EndFunc   ;==>_cveAlignMTBRelease