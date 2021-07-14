#include-once
#include <..\..\CVEUtils.au3>

Func _cudaPyrDown(ByRef $src, ByRef $dst, ByRef $stream)
    ; CVAPI(void) cudaPyrDown(cv::_InputArray* src, cv::_OutputArray* dst, cv::cuda::Stream* stream);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaPyrDown", "ptr", $src, "ptr", $dst, "ptr", $stream), "cudaPyrDown", @error)
EndFunc   ;==>_cudaPyrDown

Func _cudaPyrDownMat(ByRef $matSrc, ByRef $matDst, ByRef $stream)
    ; cudaPyrDown using cv::Mat instead of _*Array

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

    _cudaPyrDown($iArrSrc, $oArrDst, $stream)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveOutputArrayRelease($oArrDst)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)
EndFunc   ;==>_cudaPyrDownMat

Func _cudaPyrUp(ByRef $src, ByRef $dst, ByRef $stream)
    ; CVAPI(void) cudaPyrUp(cv::_InputArray* src, cv::_OutputArray* dst, cv::cuda::Stream* stream);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaPyrUp", "ptr", $src, "ptr", $dst, "ptr", $stream), "cudaPyrUp", @error)
EndFunc   ;==>_cudaPyrUp

Func _cudaPyrUpMat(ByRef $matSrc, ByRef $matDst, ByRef $stream)
    ; cudaPyrUp using cv::Mat instead of _*Array

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

    _cudaPyrUp($iArrSrc, $oArrDst, $stream)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveOutputArrayRelease($oArrDst)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)
EndFunc   ;==>_cudaPyrUpMat

Func _cudaWarpAffine(ByRef $src, ByRef $dst, ByRef $M, ByRef $dSize, $flags, $borderMode, ByRef $borderValue, ByRef $stream)
    ; CVAPI(void) cudaWarpAffine(cv::_InputArray* src, cv::_OutputArray* dst, cv::_InputArray* M, CvSize* dSize, int flags, int borderMode, CvScalar* borderValue, cv::cuda::Stream* stream);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaWarpAffine", "ptr", $src, "ptr", $dst, "ptr", $M, "struct*", $dSize, "int", $flags, "int", $borderMode, "struct*", $borderValue, "ptr", $stream), "cudaWarpAffine", @error)
EndFunc   ;==>_cudaWarpAffine

Func _cudaWarpAffineMat(ByRef $matSrc, ByRef $matDst, ByRef $matM, ByRef $dSize, $flags, $borderMode, ByRef $borderValue, ByRef $stream)
    ; cudaWarpAffine using cv::Mat instead of _*Array

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

    Local $iArrM, $vectorOfMatM, $iArrMSize
    Local $bMIsArray = VarGetType($matM) == "Array"

    If $bMIsArray Then
        $vectorOfMatM = _VectorOfMatCreate()

        $iArrMSize = UBound($matM)
        For $i = 0 To $iArrMSize - 1
            _VectorOfMatPush($vectorOfMatM, $matM[$i])
        Next

        $iArrM = _cveInputArrayFromVectorOfMat($vectorOfMatM)
    Else
        $iArrM = _cveInputArrayFromMat($matM)
    EndIf

    _cudaWarpAffine($iArrSrc, $oArrDst, $iArrM, $dSize, $flags, $borderMode, $borderValue, $stream)

    If $bMIsArray Then
        _VectorOfMatRelease($vectorOfMatM)
    EndIf

    _cveInputArrayRelease($iArrM)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveOutputArrayRelease($oArrDst)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)
EndFunc   ;==>_cudaWarpAffineMat

Func _cudaWarpPerspective(ByRef $src, ByRef $dst, ByRef $M, ByRef $size, $flags, $borderMode, ByRef $borderValue, ByRef $stream)
    ; CVAPI(void) cudaWarpPerspective(cv::_InputArray* src, cv::_OutputArray* dst, cv::_InputArray* M, CvSize* size, int flags, int borderMode, CvScalar* borderValue, cv::cuda::Stream* stream);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaWarpPerspective", "ptr", $src, "ptr", $dst, "ptr", $M, "struct*", $size, "int", $flags, "int", $borderMode, "struct*", $borderValue, "ptr", $stream), "cudaWarpPerspective", @error)
EndFunc   ;==>_cudaWarpPerspective

Func _cudaWarpPerspectiveMat(ByRef $matSrc, ByRef $matDst, ByRef $matM, ByRef $size, $flags, $borderMode, ByRef $borderValue, ByRef $stream)
    ; cudaWarpPerspective using cv::Mat instead of _*Array

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

    Local $iArrM, $vectorOfMatM, $iArrMSize
    Local $bMIsArray = VarGetType($matM) == "Array"

    If $bMIsArray Then
        $vectorOfMatM = _VectorOfMatCreate()

        $iArrMSize = UBound($matM)
        For $i = 0 To $iArrMSize - 1
            _VectorOfMatPush($vectorOfMatM, $matM[$i])
        Next

        $iArrM = _cveInputArrayFromVectorOfMat($vectorOfMatM)
    Else
        $iArrM = _cveInputArrayFromMat($matM)
    EndIf

    _cudaWarpPerspective($iArrSrc, $oArrDst, $iArrM, $size, $flags, $borderMode, $borderValue, $stream)

    If $bMIsArray Then
        _VectorOfMatRelease($vectorOfMatM)
    EndIf

    _cveInputArrayRelease($iArrM)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveOutputArrayRelease($oArrDst)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)
EndFunc   ;==>_cudaWarpPerspectiveMat

Func _cudaRemap(ByRef $src, ByRef $dst, ByRef $xmap, ByRef $ymap, $interpolation, $borderMode, ByRef $borderValue, ByRef $stream)
    ; CVAPI(void) cudaRemap(cv::_InputArray* src, cv::_OutputArray* dst, cv::_InputArray* xmap, cv::_InputArray* ymap, int interpolation, int borderMode, CvScalar* borderValue, cv::cuda::Stream* stream);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaRemap", "ptr", $src, "ptr", $dst, "ptr", $xmap, "ptr", $ymap, "int", $interpolation, "int", $borderMode, "struct*", $borderValue, "ptr", $stream), "cudaRemap", @error)
EndFunc   ;==>_cudaRemap

Func _cudaRemapMat(ByRef $matSrc, ByRef $matDst, ByRef $matXmap, ByRef $matYmap, $interpolation, $borderMode, ByRef $borderValue, ByRef $stream)
    ; cudaRemap using cv::Mat instead of _*Array

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

    Local $iArrXmap, $vectorOfMatXmap, $iArrXmapSize
    Local $bXmapIsArray = VarGetType($matXmap) == "Array"

    If $bXmapIsArray Then
        $vectorOfMatXmap = _VectorOfMatCreate()

        $iArrXmapSize = UBound($matXmap)
        For $i = 0 To $iArrXmapSize - 1
            _VectorOfMatPush($vectorOfMatXmap, $matXmap[$i])
        Next

        $iArrXmap = _cveInputArrayFromVectorOfMat($vectorOfMatXmap)
    Else
        $iArrXmap = _cveInputArrayFromMat($matXmap)
    EndIf

    Local $iArrYmap, $vectorOfMatYmap, $iArrYmapSize
    Local $bYmapIsArray = VarGetType($matYmap) == "Array"

    If $bYmapIsArray Then
        $vectorOfMatYmap = _VectorOfMatCreate()

        $iArrYmapSize = UBound($matYmap)
        For $i = 0 To $iArrYmapSize - 1
            _VectorOfMatPush($vectorOfMatYmap, $matYmap[$i])
        Next

        $iArrYmap = _cveInputArrayFromVectorOfMat($vectorOfMatYmap)
    Else
        $iArrYmap = _cveInputArrayFromMat($matYmap)
    EndIf

    _cudaRemap($iArrSrc, $oArrDst, $iArrXmap, $iArrYmap, $interpolation, $borderMode, $borderValue, $stream)

    If $bYmapIsArray Then
        _VectorOfMatRelease($vectorOfMatYmap)
    EndIf

    _cveInputArrayRelease($iArrYmap)

    If $bXmapIsArray Then
        _VectorOfMatRelease($vectorOfMatXmap)
    EndIf

    _cveInputArrayRelease($iArrXmap)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveOutputArrayRelease($oArrDst)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)
EndFunc   ;==>_cudaRemapMat

Func _cudaResize(ByRef $src, ByRef $dst, ByRef $dsize, $fx, $fy, $interpolation, ByRef $stream)
    ; CVAPI(void) cudaResize(cv::_InputArray* src, cv::_OutputArray* dst, CvSize* dsize, double fx, double fy, int interpolation, cv::cuda::Stream* stream);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaResize", "ptr", $src, "ptr", $dst, "struct*", $dsize, "double", $fx, "double", $fy, "int", $interpolation, "ptr", $stream), "cudaResize", @error)
EndFunc   ;==>_cudaResize

Func _cudaResizeMat(ByRef $matSrc, ByRef $matDst, ByRef $dsize, $fx, $fy, $interpolation, ByRef $stream)
    ; cudaResize using cv::Mat instead of _*Array

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

    _cudaResize($iArrSrc, $oArrDst, $dsize, $fx, $fy, $interpolation, $stream)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveOutputArrayRelease($oArrDst)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)
EndFunc   ;==>_cudaResizeMat

Func _cudaRotate(ByRef $src, ByRef $dst, ByRef $dSize, $angle, $xShift, $yShift, $interpolation, ByRef $s)
    ; CVAPI(void) cudaRotate(cv::_InputArray* src, cv::_OutputArray* dst, CvSize* dSize, double angle, double xShift, double yShift, int interpolation, cv::cuda::Stream* s);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaRotate", "ptr", $src, "ptr", $dst, "struct*", $dSize, "double", $angle, "double", $xShift, "double", $yShift, "int", $interpolation, "ptr", $s), "cudaRotate", @error)
EndFunc   ;==>_cudaRotate

Func _cudaRotateMat(ByRef $matSrc, ByRef $matDst, ByRef $dSize, $angle, $xShift, $yShift, $interpolation, ByRef $s)
    ; cudaRotate using cv::Mat instead of _*Array

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

    _cudaRotate($iArrSrc, $oArrDst, $dSize, $angle, $xShift, $yShift, $interpolation, $s)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveOutputArrayRelease($oArrDst)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)
EndFunc   ;==>_cudaRotateMat