#include-once
#include "..\..\CVEUtils.au3"

Func _cvGetImageSubRect(ByRef $image, ByRef $rect)
    ; CVAPI(IplImage*) cvGetImageSubRect(IplImage* image, CvRect* rect);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cvGetImageSubRect", "struct*", $image, "struct*", $rect), "cvGetImageSubRect", @error)
EndFunc   ;==>_cvGetImageSubRect

Func _cveGrabCut(ByRef $img, ByRef $mask, ByRef $rect, ByRef $bgdModel, ByRef $fgdModel, $iterCount, $flag)
    ; CVAPI(void) cveGrabCut(cv::_InputArray* img, cv::_InputOutputArray* mask, cv::Rect* rect, cv::_InputOutputArray* bgdModel, cv::_InputOutputArray* fgdModel, int iterCount, int flag);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveGrabCut", "ptr", $img, "ptr", $mask, "ptr", $rect, "ptr", $bgdModel, "ptr", $fgdModel, "int", $iterCount, "int", $flag), "cveGrabCut", @error)
EndFunc   ;==>_cveGrabCut

Func _cveGrabCutMat(ByRef $matImg, ByRef $matMask, ByRef $rect, ByRef $matBgdModel, ByRef $matFgdModel, $iterCount, $flag)
    ; cveGrabCut using cv::Mat instead of _*Array

    Local $iArrImg, $vectorOfMatImg, $iArrImgSize
    Local $bImgIsArray = VarGetType($matImg) == "Array"

    If $bImgIsArray Then
        $vectorOfMatImg = _VectorOfMatCreate()

        $iArrImgSize = UBound($matImg)
        For $i = 0 To $iArrImgSize - 1
            _VectorOfMatPush($vectorOfMatImg, $matImg[$i])
        Next

        $iArrImg = _cveInputArrayFromVectorOfMat($vectorOfMatImg)
    Else
        $iArrImg = _cveInputArrayFromMat($matImg)
    EndIf

    Local $ioArrMask, $vectorOfMatMask, $iArrMaskSize
    Local $bMaskIsArray = VarGetType($matMask) == "Array"

    If $bMaskIsArray Then
        $vectorOfMatMask = _VectorOfMatCreate()

        $iArrMaskSize = UBound($matMask)
        For $i = 0 To $iArrMaskSize - 1
            _VectorOfMatPush($vectorOfMatMask, $matMask[$i])
        Next

        $ioArrMask = _cveInputOutputArrayFromVectorOfMat($vectorOfMatMask)
    Else
        $ioArrMask = _cveInputOutputArrayFromMat($matMask)
    EndIf

    Local $ioArrBgdModel, $vectorOfMatBgdModel, $iArrBgdModelSize
    Local $bBgdModelIsArray = VarGetType($matBgdModel) == "Array"

    If $bBgdModelIsArray Then
        $vectorOfMatBgdModel = _VectorOfMatCreate()

        $iArrBgdModelSize = UBound($matBgdModel)
        For $i = 0 To $iArrBgdModelSize - 1
            _VectorOfMatPush($vectorOfMatBgdModel, $matBgdModel[$i])
        Next

        $ioArrBgdModel = _cveInputOutputArrayFromVectorOfMat($vectorOfMatBgdModel)
    Else
        $ioArrBgdModel = _cveInputOutputArrayFromMat($matBgdModel)
    EndIf

    Local $ioArrFgdModel, $vectorOfMatFgdModel, $iArrFgdModelSize
    Local $bFgdModelIsArray = VarGetType($matFgdModel) == "Array"

    If $bFgdModelIsArray Then
        $vectorOfMatFgdModel = _VectorOfMatCreate()

        $iArrFgdModelSize = UBound($matFgdModel)
        For $i = 0 To $iArrFgdModelSize - 1
            _VectorOfMatPush($vectorOfMatFgdModel, $matFgdModel[$i])
        Next

        $ioArrFgdModel = _cveInputOutputArrayFromVectorOfMat($vectorOfMatFgdModel)
    Else
        $ioArrFgdModel = _cveInputOutputArrayFromMat($matFgdModel)
    EndIf

    _cveGrabCut($iArrImg, $ioArrMask, $rect, $ioArrBgdModel, $ioArrFgdModel, $iterCount, $flag)

    If $bFgdModelIsArray Then
        _VectorOfMatRelease($vectorOfMatFgdModel)
    EndIf

    _cveInputOutputArrayRelease($ioArrFgdModel)

    If $bBgdModelIsArray Then
        _VectorOfMatRelease($vectorOfMatBgdModel)
    EndIf

    _cveInputOutputArrayRelease($ioArrBgdModel)

    If $bMaskIsArray Then
        _VectorOfMatRelease($vectorOfMatMask)
    EndIf

    _cveInputOutputArrayRelease($ioArrMask)

    If $bImgIsArray Then
        _VectorOfMatRelease($vectorOfMatImg)
    EndIf

    _cveInputArrayRelease($iArrImg)
EndFunc   ;==>_cveGrabCutMat

Func _cveFilter2D(ByRef $src, ByRef $dst, ByRef $kernel, ByRef $anchor, $delta, $borderType)
    ; CVAPI(void) cveFilter2D(cv::_InputArray* src, cv::_OutputArray* dst, cv::_InputArray* kernel, CvPoint* anchor, double delta, int borderType);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFilter2D", "ptr", $src, "ptr", $dst, "ptr", $kernel, "struct*", $anchor, "double", $delta, "int", $borderType), "cveFilter2D", @error)
EndFunc   ;==>_cveFilter2D

Func _cveFilter2DMat(ByRef $matSrc, ByRef $matDst, ByRef $matKernel, ByRef $anchor, $delta, $borderType)
    ; cveFilter2D using cv::Mat instead of _*Array

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

    Local $iArrKernel, $vectorOfMatKernel, $iArrKernelSize
    Local $bKernelIsArray = VarGetType($matKernel) == "Array"

    If $bKernelIsArray Then
        $vectorOfMatKernel = _VectorOfMatCreate()

        $iArrKernelSize = UBound($matKernel)
        For $i = 0 To $iArrKernelSize - 1
            _VectorOfMatPush($vectorOfMatKernel, $matKernel[$i])
        Next

        $iArrKernel = _cveInputArrayFromVectorOfMat($vectorOfMatKernel)
    Else
        $iArrKernel = _cveInputArrayFromMat($matKernel)
    EndIf

    _cveFilter2D($iArrSrc, $oArrDst, $iArrKernel, $anchor, $delta, $borderType)

    If $bKernelIsArray Then
        _VectorOfMatRelease($vectorOfMatKernel)
    EndIf

    _cveInputArrayRelease($iArrKernel)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveOutputArrayRelease($oArrDst)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)
EndFunc   ;==>_cveFilter2DMat

Func _cveSepFilter2D(ByRef $src, ByRef $dst, $ddepth, ByRef $kernelX, ByRef $kernelY, ByRef $anchor, $delta, $borderType)
    ; CVAPI(void) cveSepFilter2D(cv::_InputArray* src, cv::_OutputArray* dst, int ddepth, cv::_InputArray* kernelX, cv::_InputArray* kernelY, CvPoint* anchor, double delta, int borderType);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSepFilter2D", "ptr", $src, "ptr", $dst, "int", $ddepth, "ptr", $kernelX, "ptr", $kernelY, "struct*", $anchor, "double", $delta, "int", $borderType), "cveSepFilter2D", @error)
EndFunc   ;==>_cveSepFilter2D

Func _cveSepFilter2DMat(ByRef $matSrc, ByRef $matDst, $ddepth, ByRef $matKernelX, ByRef $matKernelY, ByRef $anchor, $delta, $borderType)
    ; cveSepFilter2D using cv::Mat instead of _*Array

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

    Local $iArrKernelX, $vectorOfMatKernelX, $iArrKernelXSize
    Local $bKernelXIsArray = VarGetType($matKernelX) == "Array"

    If $bKernelXIsArray Then
        $vectorOfMatKernelX = _VectorOfMatCreate()

        $iArrKernelXSize = UBound($matKernelX)
        For $i = 0 To $iArrKernelXSize - 1
            _VectorOfMatPush($vectorOfMatKernelX, $matKernelX[$i])
        Next

        $iArrKernelX = _cveInputArrayFromVectorOfMat($vectorOfMatKernelX)
    Else
        $iArrKernelX = _cveInputArrayFromMat($matKernelX)
    EndIf

    Local $iArrKernelY, $vectorOfMatKernelY, $iArrKernelYSize
    Local $bKernelYIsArray = VarGetType($matKernelY) == "Array"

    If $bKernelYIsArray Then
        $vectorOfMatKernelY = _VectorOfMatCreate()

        $iArrKernelYSize = UBound($matKernelY)
        For $i = 0 To $iArrKernelYSize - 1
            _VectorOfMatPush($vectorOfMatKernelY, $matKernelY[$i])
        Next

        $iArrKernelY = _cveInputArrayFromVectorOfMat($vectorOfMatKernelY)
    Else
        $iArrKernelY = _cveInputArrayFromMat($matKernelY)
    EndIf

    _cveSepFilter2D($iArrSrc, $oArrDst, $ddepth, $iArrKernelX, $iArrKernelY, $anchor, $delta, $borderType)

    If $bKernelYIsArray Then
        _VectorOfMatRelease($vectorOfMatKernelY)
    EndIf

    _cveInputArrayRelease($iArrKernelY)

    If $bKernelXIsArray Then
        _VectorOfMatRelease($vectorOfMatKernelX)
    EndIf

    _cveInputArrayRelease($iArrKernelX)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveOutputArrayRelease($oArrDst)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)
EndFunc   ;==>_cveSepFilter2DMat

Func _cveBlendLinear(ByRef $src1, ByRef $src2, ByRef $weights1, ByRef $weights2, ByRef $dst)
    ; CVAPI(void) cveBlendLinear(cv::_InputArray* src1, cv::_InputArray* src2, cv::_InputArray* weights1, cv::_InputArray* weights2, cv::_OutputArray* dst);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBlendLinear", "ptr", $src1, "ptr", $src2, "ptr", $weights1, "ptr", $weights2, "ptr", $dst), "cveBlendLinear", @error)
EndFunc   ;==>_cveBlendLinear

Func _cveBlendLinearMat(ByRef $matSrc1, ByRef $matSrc2, ByRef $matWeights1, ByRef $matWeights2, ByRef $matDst)
    ; cveBlendLinear using cv::Mat instead of _*Array

    Local $iArrSrc1, $vectorOfMatSrc1, $iArrSrc1Size
    Local $bSrc1IsArray = VarGetType($matSrc1) == "Array"

    If $bSrc1IsArray Then
        $vectorOfMatSrc1 = _VectorOfMatCreate()

        $iArrSrc1Size = UBound($matSrc1)
        For $i = 0 To $iArrSrc1Size - 1
            _VectorOfMatPush($vectorOfMatSrc1, $matSrc1[$i])
        Next

        $iArrSrc1 = _cveInputArrayFromVectorOfMat($vectorOfMatSrc1)
    Else
        $iArrSrc1 = _cveInputArrayFromMat($matSrc1)
    EndIf

    Local $iArrSrc2, $vectorOfMatSrc2, $iArrSrc2Size
    Local $bSrc2IsArray = VarGetType($matSrc2) == "Array"

    If $bSrc2IsArray Then
        $vectorOfMatSrc2 = _VectorOfMatCreate()

        $iArrSrc2Size = UBound($matSrc2)
        For $i = 0 To $iArrSrc2Size - 1
            _VectorOfMatPush($vectorOfMatSrc2, $matSrc2[$i])
        Next

        $iArrSrc2 = _cveInputArrayFromVectorOfMat($vectorOfMatSrc2)
    Else
        $iArrSrc2 = _cveInputArrayFromMat($matSrc2)
    EndIf

    Local $iArrWeights1, $vectorOfMatWeights1, $iArrWeights1Size
    Local $bWeights1IsArray = VarGetType($matWeights1) == "Array"

    If $bWeights1IsArray Then
        $vectorOfMatWeights1 = _VectorOfMatCreate()

        $iArrWeights1Size = UBound($matWeights1)
        For $i = 0 To $iArrWeights1Size - 1
            _VectorOfMatPush($vectorOfMatWeights1, $matWeights1[$i])
        Next

        $iArrWeights1 = _cveInputArrayFromVectorOfMat($vectorOfMatWeights1)
    Else
        $iArrWeights1 = _cveInputArrayFromMat($matWeights1)
    EndIf

    Local $iArrWeights2, $vectorOfMatWeights2, $iArrWeights2Size
    Local $bWeights2IsArray = VarGetType($matWeights2) == "Array"

    If $bWeights2IsArray Then
        $vectorOfMatWeights2 = _VectorOfMatCreate()

        $iArrWeights2Size = UBound($matWeights2)
        For $i = 0 To $iArrWeights2Size - 1
            _VectorOfMatPush($vectorOfMatWeights2, $matWeights2[$i])
        Next

        $iArrWeights2 = _cveInputArrayFromVectorOfMat($vectorOfMatWeights2)
    Else
        $iArrWeights2 = _cveInputArrayFromMat($matWeights2)
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

    _cveBlendLinear($iArrSrc1, $iArrSrc2, $iArrWeights1, $iArrWeights2, $oArrDst)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveOutputArrayRelease($oArrDst)

    If $bWeights2IsArray Then
        _VectorOfMatRelease($vectorOfMatWeights2)
    EndIf

    _cveInputArrayRelease($iArrWeights2)

    If $bWeights1IsArray Then
        _VectorOfMatRelease($vectorOfMatWeights1)
    EndIf

    _cveInputArrayRelease($iArrWeights1)

    If $bSrc2IsArray Then
        _VectorOfMatRelease($vectorOfMatSrc2)
    EndIf

    _cveInputArrayRelease($iArrSrc2)

    If $bSrc1IsArray Then
        _VectorOfMatRelease($vectorOfMatSrc1)
    EndIf

    _cveInputArrayRelease($iArrSrc1)
EndFunc   ;==>_cveBlendLinearMat

Func _cveCLAHE(ByRef $src, $clipLimit, ByRef $tileGridSize, ByRef $dst)
    ; CVAPI(void) cveCLAHE(cv::_InputArray* src, double clipLimit, CvSize* tileGridSize, cv::_OutputArray* dst);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCLAHE", "ptr", $src, "double", $clipLimit, "struct*", $tileGridSize, "ptr", $dst), "cveCLAHE", @error)
EndFunc   ;==>_cveCLAHE

Func _cveCLAHEMat(ByRef $matSrc, $clipLimit, ByRef $tileGridSize, ByRef $matDst)
    ; cveCLAHE using cv::Mat instead of _*Array

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

    _cveCLAHE($iArrSrc, $clipLimit, $tileGridSize, $oArrDst)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveOutputArrayRelease($oArrDst)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)
EndFunc   ;==>_cveCLAHEMat

Func _cveErode(ByRef $src, ByRef $dst, ByRef $kernel, ByRef $anchor, $iterations, $borderType, ByRef $borderValue)
    ; CVAPI(void) cveErode(cv::_InputArray* src, cv::_OutputArray* dst, cv::_InputArray* kernel, CvPoint* anchor, int iterations, int borderType, CvScalar* borderValue);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveErode", "ptr", $src, "ptr", $dst, "ptr", $kernel, "struct*", $anchor, "int", $iterations, "int", $borderType, "struct*", $borderValue), "cveErode", @error)
EndFunc   ;==>_cveErode

Func _cveErodeMat(ByRef $matSrc, ByRef $matDst, ByRef $matKernel, ByRef $anchor, $iterations, $borderType, ByRef $borderValue)
    ; cveErode using cv::Mat instead of _*Array

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

    Local $iArrKernel, $vectorOfMatKernel, $iArrKernelSize
    Local $bKernelIsArray = VarGetType($matKernel) == "Array"

    If $bKernelIsArray Then
        $vectorOfMatKernel = _VectorOfMatCreate()

        $iArrKernelSize = UBound($matKernel)
        For $i = 0 To $iArrKernelSize - 1
            _VectorOfMatPush($vectorOfMatKernel, $matKernel[$i])
        Next

        $iArrKernel = _cveInputArrayFromVectorOfMat($vectorOfMatKernel)
    Else
        $iArrKernel = _cveInputArrayFromMat($matKernel)
    EndIf

    _cveErode($iArrSrc, $oArrDst, $iArrKernel, $anchor, $iterations, $borderType, $borderValue)

    If $bKernelIsArray Then
        _VectorOfMatRelease($vectorOfMatKernel)
    EndIf

    _cveInputArrayRelease($iArrKernel)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveOutputArrayRelease($oArrDst)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)
EndFunc   ;==>_cveErodeMat

Func _cveDilate(ByRef $src, ByRef $dst, ByRef $kernel, ByRef $anchor, $iterations, $borderType, ByRef $borderValue)
    ; CVAPI(void) cveDilate(cv::_InputArray* src, cv::_OutputArray* dst, cv::_InputArray* kernel, CvPoint* anchor, int iterations, int borderType, CvScalar* borderValue);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDilate", "ptr", $src, "ptr", $dst, "ptr", $kernel, "struct*", $anchor, "int", $iterations, "int", $borderType, "struct*", $borderValue), "cveDilate", @error)
EndFunc   ;==>_cveDilate

Func _cveDilateMat(ByRef $matSrc, ByRef $matDst, ByRef $matKernel, ByRef $anchor, $iterations, $borderType, ByRef $borderValue)
    ; cveDilate using cv::Mat instead of _*Array

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

    Local $iArrKernel, $vectorOfMatKernel, $iArrKernelSize
    Local $bKernelIsArray = VarGetType($matKernel) == "Array"

    If $bKernelIsArray Then
        $vectorOfMatKernel = _VectorOfMatCreate()

        $iArrKernelSize = UBound($matKernel)
        For $i = 0 To $iArrKernelSize - 1
            _VectorOfMatPush($vectorOfMatKernel, $matKernel[$i])
        Next

        $iArrKernel = _cveInputArrayFromVectorOfMat($vectorOfMatKernel)
    Else
        $iArrKernel = _cveInputArrayFromMat($matKernel)
    EndIf

    _cveDilate($iArrSrc, $oArrDst, $iArrKernel, $anchor, $iterations, $borderType, $borderValue)

    If $bKernelIsArray Then
        _VectorOfMatRelease($vectorOfMatKernel)
    EndIf

    _cveInputArrayRelease($iArrKernel)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveOutputArrayRelease($oArrDst)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)
EndFunc   ;==>_cveDilateMat

Func _cveGetStructuringElement(ByRef $mat, $shape, ByRef $ksize, ByRef $anchor)
    ; CVAPI(void) cveGetStructuringElement(cv::Mat* mat, int shape, CvSize* ksize, CvPoint* anchor);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveGetStructuringElement", "ptr", $mat, "int", $shape, "struct*", $ksize, "struct*", $anchor), "cveGetStructuringElement", @error)
EndFunc   ;==>_cveGetStructuringElement

Func _cveMorphologyEx(ByRef $src, ByRef $dst, $op, ByRef $kernel, ByRef $anchor, $iterations, $borderType, ByRef $borderValue)
    ; CVAPI(void) cveMorphologyEx(cv::_InputArray* src, cv::_OutputArray* dst, int op, cv::_InputArray* kernel, CvPoint* anchor, int iterations, int borderType, CvScalar* borderValue);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMorphologyEx", "ptr", $src, "ptr", $dst, "int", $op, "ptr", $kernel, "struct*", $anchor, "int", $iterations, "int", $borderType, "struct*", $borderValue), "cveMorphologyEx", @error)
EndFunc   ;==>_cveMorphologyEx

Func _cveMorphologyExMat(ByRef $matSrc, ByRef $matDst, $op, ByRef $matKernel, ByRef $anchor, $iterations, $borderType, ByRef $borderValue)
    ; cveMorphologyEx using cv::Mat instead of _*Array

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

    Local $iArrKernel, $vectorOfMatKernel, $iArrKernelSize
    Local $bKernelIsArray = VarGetType($matKernel) == "Array"

    If $bKernelIsArray Then
        $vectorOfMatKernel = _VectorOfMatCreate()

        $iArrKernelSize = UBound($matKernel)
        For $i = 0 To $iArrKernelSize - 1
            _VectorOfMatPush($vectorOfMatKernel, $matKernel[$i])
        Next

        $iArrKernel = _cveInputArrayFromVectorOfMat($vectorOfMatKernel)
    Else
        $iArrKernel = _cveInputArrayFromMat($matKernel)
    EndIf

    _cveMorphologyEx($iArrSrc, $oArrDst, $op, $iArrKernel, $anchor, $iterations, $borderType, $borderValue)

    If $bKernelIsArray Then
        _VectorOfMatRelease($vectorOfMatKernel)
    EndIf

    _cveInputArrayRelease($iArrKernel)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveOutputArrayRelease($oArrDst)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)
EndFunc   ;==>_cveMorphologyExMat

Func _cveSobel(ByRef $src, ByRef $dst, $ddepth, $dx, $dy, $ksize, $scale, $delta, $borderType)
    ; CVAPI(void) cveSobel(cv::_InputArray* src, cv::_OutputArray* dst, int ddepth, int dx, int dy, int ksize, double scale, double delta, int borderType);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSobel", "ptr", $src, "ptr", $dst, "int", $ddepth, "int", $dx, "int", $dy, "int", $ksize, "double", $scale, "double", $delta, "int", $borderType), "cveSobel", @error)
EndFunc   ;==>_cveSobel

Func _cveSobelMat(ByRef $matSrc, ByRef $matDst, $ddepth, $dx, $dy, $ksize, $scale, $delta, $borderType)
    ; cveSobel using cv::Mat instead of _*Array

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

    _cveSobel($iArrSrc, $oArrDst, $ddepth, $dx, $dy, $ksize, $scale, $delta, $borderType)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveOutputArrayRelease($oArrDst)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)
EndFunc   ;==>_cveSobelMat

Func _cveSpatialGradient(ByRef $src, ByRef $dx, ByRef $dy, $ksize, $borderType)
    ; CVAPI(void) cveSpatialGradient(cv::_InputArray* src, cv::_OutputArray* dx, cv::_OutputArray* dy, int ksize, int borderType);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSpatialGradient", "ptr", $src, "ptr", $dx, "ptr", $dy, "int", $ksize, "int", $borderType), "cveSpatialGradient", @error)
EndFunc   ;==>_cveSpatialGradient

Func _cveSpatialGradientMat(ByRef $matSrc, ByRef $matDx, ByRef $matDy, $ksize, $borderType)
    ; cveSpatialGradient using cv::Mat instead of _*Array

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

    Local $oArrDx, $vectorOfMatDx, $iArrDxSize
    Local $bDxIsArray = VarGetType($matDx) == "Array"

    If $bDxIsArray Then
        $vectorOfMatDx = _VectorOfMatCreate()

        $iArrDxSize = UBound($matDx)
        For $i = 0 To $iArrDxSize - 1
            _VectorOfMatPush($vectorOfMatDx, $matDx[$i])
        Next

        $oArrDx = _cveOutputArrayFromVectorOfMat($vectorOfMatDx)
    Else
        $oArrDx = _cveOutputArrayFromMat($matDx)
    EndIf

    Local $oArrDy, $vectorOfMatDy, $iArrDySize
    Local $bDyIsArray = VarGetType($matDy) == "Array"

    If $bDyIsArray Then
        $vectorOfMatDy = _VectorOfMatCreate()

        $iArrDySize = UBound($matDy)
        For $i = 0 To $iArrDySize - 1
            _VectorOfMatPush($vectorOfMatDy, $matDy[$i])
        Next

        $oArrDy = _cveOutputArrayFromVectorOfMat($vectorOfMatDy)
    Else
        $oArrDy = _cveOutputArrayFromMat($matDy)
    EndIf

    _cveSpatialGradient($iArrSrc, $oArrDx, $oArrDy, $ksize, $borderType)

    If $bDyIsArray Then
        _VectorOfMatRelease($vectorOfMatDy)
    EndIf

    _cveOutputArrayRelease($oArrDy)

    If $bDxIsArray Then
        _VectorOfMatRelease($vectorOfMatDx)
    EndIf

    _cveOutputArrayRelease($oArrDx)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)
EndFunc   ;==>_cveSpatialGradientMat

Func _cveScharr(ByRef $src, ByRef $dst, $ddepth, $dx, $dy, $scale, $delta, $borderType)
    ; CVAPI(void) cveScharr(cv::_InputArray* src, cv::_OutputArray* dst, int ddepth, int dx, int dy, double scale, double delta, int borderType);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveScharr", "ptr", $src, "ptr", $dst, "int", $ddepth, "int", $dx, "int", $dy, "double", $scale, "double", $delta, "int", $borderType), "cveScharr", @error)
EndFunc   ;==>_cveScharr

Func _cveScharrMat(ByRef $matSrc, ByRef $matDst, $ddepth, $dx, $dy, $scale, $delta, $borderType)
    ; cveScharr using cv::Mat instead of _*Array

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

    _cveScharr($iArrSrc, $oArrDst, $ddepth, $dx, $dy, $scale, $delta, $borderType)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveOutputArrayRelease($oArrDst)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)
EndFunc   ;==>_cveScharrMat

Func _cveLaplacian(ByRef $src, ByRef $dst, $ddepth, $ksize, $scale, $delta, $borderType)
    ; CVAPI(void) cveLaplacian(cv::_InputArray* src, cv::_OutputArray* dst, int ddepth, int ksize, double scale, double delta, int borderType);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveLaplacian", "ptr", $src, "ptr", $dst, "int", $ddepth, "int", $ksize, "double", $scale, "double", $delta, "int", $borderType), "cveLaplacian", @error)
EndFunc   ;==>_cveLaplacian

Func _cveLaplacianMat(ByRef $matSrc, ByRef $matDst, $ddepth, $ksize, $scale, $delta, $borderType)
    ; cveLaplacian using cv::Mat instead of _*Array

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

    _cveLaplacian($iArrSrc, $oArrDst, $ddepth, $ksize, $scale, $delta, $borderType)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveOutputArrayRelease($oArrDst)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)
EndFunc   ;==>_cveLaplacianMat

Func _cvePyrUp(ByRef $src, ByRef $dst, ByRef $size, $borderType)
    ; CVAPI(void) cvePyrUp(cv::_InputArray* src, cv::_OutputArray* dst, CvSize* size, int borderType);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cvePyrUp", "ptr", $src, "ptr", $dst, "struct*", $size, "int", $borderType), "cvePyrUp", @error)
EndFunc   ;==>_cvePyrUp

Func _cvePyrUpMat(ByRef $matSrc, ByRef $matDst, ByRef $size, $borderType)
    ; cvePyrUp using cv::Mat instead of _*Array

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

    _cvePyrUp($iArrSrc, $oArrDst, $size, $borderType)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveOutputArrayRelease($oArrDst)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)
EndFunc   ;==>_cvePyrUpMat

Func _cvePyrDown(ByRef $src, ByRef $dst, ByRef $size, $borderType)
    ; CVAPI(void) cvePyrDown(cv::_InputArray* src, cv::_OutputArray* dst, CvSize* size, int borderType);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cvePyrDown", "ptr", $src, "ptr", $dst, "struct*", $size, "int", $borderType), "cvePyrDown", @error)
EndFunc   ;==>_cvePyrDown

Func _cvePyrDownMat(ByRef $matSrc, ByRef $matDst, ByRef $size, $borderType)
    ; cvePyrDown using cv::Mat instead of _*Array

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

    _cvePyrDown($iArrSrc, $oArrDst, $size, $borderType)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveOutputArrayRelease($oArrDst)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)
EndFunc   ;==>_cvePyrDownMat

Func _cveBuildPyramid(ByRef $src, ByRef $dst, $maxlevel, $borderType)
    ; CVAPI(void) cveBuildPyramid(cv::_InputArray* src, cv::_OutputArray* dst, int maxlevel, int borderType);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBuildPyramid", "ptr", $src, "ptr", $dst, "int", $maxlevel, "int", $borderType), "cveBuildPyramid", @error)
EndFunc   ;==>_cveBuildPyramid

Func _cveBuildPyramidMat(ByRef $matSrc, ByRef $matDst, $maxlevel, $borderType)
    ; cveBuildPyramid using cv::Mat instead of _*Array

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

    _cveBuildPyramid($iArrSrc, $oArrDst, $maxlevel, $borderType)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveOutputArrayRelease($oArrDst)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)
EndFunc   ;==>_cveBuildPyramidMat

Func _cveCanny(ByRef $image, ByRef $edges, $threshold1, $threshold2, $apertureSize = 3, $L2gradient = False)
    ; CVAPI(void) cveCanny(cv::_InputArray* image, cv::_OutputArray* edges, double threshold1, double threshold2, int apertureSize, bool L2gradient);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCanny", "ptr", $image, "ptr", $edges, "double", $threshold1, "double", $threshold2, "int", $apertureSize, "boolean", $L2gradient), "cveCanny", @error)
EndFunc   ;==>_cveCanny

Func _cveCannyMat(ByRef $matImage, ByRef $matEdges, $threshold1, $threshold2, $apertureSize = 3, $L2gradient = False)
    ; cveCanny using cv::Mat instead of _*Array

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

    Local $oArrEdges, $vectorOfMatEdges, $iArrEdgesSize
    Local $bEdgesIsArray = VarGetType($matEdges) == "Array"

    If $bEdgesIsArray Then
        $vectorOfMatEdges = _VectorOfMatCreate()

        $iArrEdgesSize = UBound($matEdges)
        For $i = 0 To $iArrEdgesSize - 1
            _VectorOfMatPush($vectorOfMatEdges, $matEdges[$i])
        Next

        $oArrEdges = _cveOutputArrayFromVectorOfMat($vectorOfMatEdges)
    Else
        $oArrEdges = _cveOutputArrayFromMat($matEdges)
    EndIf

    _cveCanny($iArrImage, $oArrEdges, $threshold1, $threshold2, $apertureSize, $L2gradient)

    If $bEdgesIsArray Then
        _VectorOfMatRelease($vectorOfMatEdges)
    EndIf

    _cveOutputArrayRelease($oArrEdges)

    If $bImageIsArray Then
        _VectorOfMatRelease($vectorOfMatImage)
    EndIf

    _cveInputArrayRelease($iArrImage)
EndFunc   ;==>_cveCannyMat

Func _cveCanny2(ByRef $dx, ByRef $dy, ByRef $edges, $threshold1, $threshold2, $L2gradient)
    ; CVAPI(void) cveCanny2(cv::_InputArray* dx, cv::_InputArray* dy, cv::_OutputArray* edges, double threshold1, double threshold2, bool L2gradient);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCanny2", "ptr", $dx, "ptr", $dy, "ptr", $edges, "double", $threshold1, "double", $threshold2, "boolean", $L2gradient), "cveCanny2", @error)
EndFunc   ;==>_cveCanny2

Func _cveCanny2Mat(ByRef $matDx, ByRef $matDy, ByRef $matEdges, $threshold1, $threshold2, $L2gradient)
    ; cveCanny2 using cv::Mat instead of _*Array

    Local $iArrDx, $vectorOfMatDx, $iArrDxSize
    Local $bDxIsArray = VarGetType($matDx) == "Array"

    If $bDxIsArray Then
        $vectorOfMatDx = _VectorOfMatCreate()

        $iArrDxSize = UBound($matDx)
        For $i = 0 To $iArrDxSize - 1
            _VectorOfMatPush($vectorOfMatDx, $matDx[$i])
        Next

        $iArrDx = _cveInputArrayFromVectorOfMat($vectorOfMatDx)
    Else
        $iArrDx = _cveInputArrayFromMat($matDx)
    EndIf

    Local $iArrDy, $vectorOfMatDy, $iArrDySize
    Local $bDyIsArray = VarGetType($matDy) == "Array"

    If $bDyIsArray Then
        $vectorOfMatDy = _VectorOfMatCreate()

        $iArrDySize = UBound($matDy)
        For $i = 0 To $iArrDySize - 1
            _VectorOfMatPush($vectorOfMatDy, $matDy[$i])
        Next

        $iArrDy = _cveInputArrayFromVectorOfMat($vectorOfMatDy)
    Else
        $iArrDy = _cveInputArrayFromMat($matDy)
    EndIf

    Local $oArrEdges, $vectorOfMatEdges, $iArrEdgesSize
    Local $bEdgesIsArray = VarGetType($matEdges) == "Array"

    If $bEdgesIsArray Then
        $vectorOfMatEdges = _VectorOfMatCreate()

        $iArrEdgesSize = UBound($matEdges)
        For $i = 0 To $iArrEdgesSize - 1
            _VectorOfMatPush($vectorOfMatEdges, $matEdges[$i])
        Next

        $oArrEdges = _cveOutputArrayFromVectorOfMat($vectorOfMatEdges)
    Else
        $oArrEdges = _cveOutputArrayFromMat($matEdges)
    EndIf

    _cveCanny2($iArrDx, $iArrDy, $oArrEdges, $threshold1, $threshold2, $L2gradient)

    If $bEdgesIsArray Then
        _VectorOfMatRelease($vectorOfMatEdges)
    EndIf

    _cveOutputArrayRelease($oArrEdges)

    If $bDyIsArray Then
        _VectorOfMatRelease($vectorOfMatDy)
    EndIf

    _cveInputArrayRelease($iArrDy)

    If $bDxIsArray Then
        _VectorOfMatRelease($vectorOfMatDx)
    EndIf

    _cveInputArrayRelease($iArrDx)
EndFunc   ;==>_cveCanny2Mat

Func _cveCornerHarris(ByRef $src, ByRef $dst, $blockSize, $ksize, $k, $borderType)
    ; CVAPI(void) cveCornerHarris(cv::_InputArray* src, cv::_OutputArray* dst, int blockSize, int ksize, double k, int borderType);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCornerHarris", "ptr", $src, "ptr", $dst, "int", $blockSize, "int", $ksize, "double", $k, "int", $borderType), "cveCornerHarris", @error)
EndFunc   ;==>_cveCornerHarris

Func _cveCornerHarrisMat(ByRef $matSrc, ByRef $matDst, $blockSize, $ksize, $k, $borderType)
    ; cveCornerHarris using cv::Mat instead of _*Array

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

    _cveCornerHarris($iArrSrc, $oArrDst, $blockSize, $ksize, $k, $borderType)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveOutputArrayRelease($oArrDst)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)
EndFunc   ;==>_cveCornerHarrisMat

Func _cveThreshold(ByRef $src, ByRef $dst, $thresh, $maxval, $type)
    ; CVAPI(double) cveThreshold(cv::_InputArray* src, cv::_OutputArray* dst, double thresh, double maxval, int type);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveThreshold", "ptr", $src, "ptr", $dst, "double", $thresh, "double", $maxval, "int", $type), "cveThreshold", @error)
EndFunc   ;==>_cveThreshold

Func _cveThresholdMat(ByRef $matSrc, ByRef $matDst, $thresh, $maxval, $type)
    ; cveThreshold using cv::Mat instead of _*Array

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

    Local $retval = _cveThreshold($iArrSrc, $oArrDst, $thresh, $maxval, $type)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveOutputArrayRelease($oArrDst)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)

    Return $retval
EndFunc   ;==>_cveThresholdMat

Func _cveWatershed(ByRef $image, ByRef $markers)
    ; CVAPI(void) cveWatershed(cv::_InputArray* image, cv::_InputOutputArray* markers);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveWatershed", "ptr", $image, "ptr", $markers), "cveWatershed", @error)
EndFunc   ;==>_cveWatershed

Func _cveWatershedMat(ByRef $matImage, ByRef $matMarkers)
    ; cveWatershed using cv::Mat instead of _*Array

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

    Local $ioArrMarkers, $vectorOfMatMarkers, $iArrMarkersSize
    Local $bMarkersIsArray = VarGetType($matMarkers) == "Array"

    If $bMarkersIsArray Then
        $vectorOfMatMarkers = _VectorOfMatCreate()

        $iArrMarkersSize = UBound($matMarkers)
        For $i = 0 To $iArrMarkersSize - 1
            _VectorOfMatPush($vectorOfMatMarkers, $matMarkers[$i])
        Next

        $ioArrMarkers = _cveInputOutputArrayFromVectorOfMat($vectorOfMatMarkers)
    Else
        $ioArrMarkers = _cveInputOutputArrayFromMat($matMarkers)
    EndIf

    _cveWatershed($iArrImage, $ioArrMarkers)

    If $bMarkersIsArray Then
        _VectorOfMatRelease($vectorOfMatMarkers)
    EndIf

    _cveInputOutputArrayRelease($ioArrMarkers)

    If $bImageIsArray Then
        _VectorOfMatRelease($vectorOfMatImage)
    EndIf

    _cveInputArrayRelease($iArrImage)
EndFunc   ;==>_cveWatershedMat

Func _cveAdaptiveThreshold(ByRef $src, ByRef $dst, $maxValue, $adaptiveMethod, $thresholdType, $blockSize, $c)
    ; CVAPI(void) cveAdaptiveThreshold(cv::_InputArray* src, cv::_OutputArray* dst, double maxValue, int adaptiveMethod, int thresholdType, int blockSize, double c);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveAdaptiveThreshold", "ptr", $src, "ptr", $dst, "double", $maxValue, "int", $adaptiveMethod, "int", $thresholdType, "int", $blockSize, "double", $c), "cveAdaptiveThreshold", @error)
EndFunc   ;==>_cveAdaptiveThreshold

Func _cveAdaptiveThresholdMat(ByRef $matSrc, ByRef $matDst, $maxValue, $adaptiveMethod, $thresholdType, $blockSize, $c)
    ; cveAdaptiveThreshold using cv::Mat instead of _*Array

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

    _cveAdaptiveThreshold($iArrSrc, $oArrDst, $maxValue, $adaptiveMethod, $thresholdType, $blockSize, $c)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveOutputArrayRelease($oArrDst)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)
EndFunc   ;==>_cveAdaptiveThresholdMat

Func _cveCvtColor(ByRef $src, ByRef $dst, $code, $dstCn = 0)
    ; CVAPI(void) cveCvtColor(cv::_InputArray* src, cv::_OutputArray* dst, int code, int dstCn);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCvtColor", "ptr", $src, "ptr", $dst, "int", $code, "int", $dstCn), "cveCvtColor", @error)
EndFunc   ;==>_cveCvtColor

Func _cveCvtColorMat(ByRef $matSrc, ByRef $matDst, $code, $dstCn = 0)
    ; cveCvtColor using cv::Mat instead of _*Array

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

    _cveCvtColor($iArrSrc, $oArrDst, $code, $dstCn)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveOutputArrayRelease($oArrDst)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)
EndFunc   ;==>_cveCvtColorMat

Func _cveCopyMakeBorder(ByRef $src, ByRef $dst, $top, $bottom, $left, $right, $borderType, ByRef $value)
    ; CVAPI(void) cveCopyMakeBorder(cv::_InputArray* src, cv::_OutputArray* dst, int top, int bottom, int left, int right, int borderType, CvScalar* value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCopyMakeBorder", "ptr", $src, "ptr", $dst, "int", $top, "int", $bottom, "int", $left, "int", $right, "int", $borderType, "struct*", $value), "cveCopyMakeBorder", @error)
EndFunc   ;==>_cveCopyMakeBorder

Func _cveCopyMakeBorderMat(ByRef $matSrc, ByRef $matDst, $top, $bottom, $left, $right, $borderType, ByRef $value)
    ; cveCopyMakeBorder using cv::Mat instead of _*Array

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

    _cveCopyMakeBorder($iArrSrc, $oArrDst, $top, $bottom, $left, $right, $borderType, $value)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveOutputArrayRelease($oArrDst)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)
EndFunc   ;==>_cveCopyMakeBorderMat

Func _cveIntegral(ByRef $src, ByRef $sum, ByRef $sqsum, ByRef $tilted, $sdepth, $sqdepth)
    ; CVAPI(void) cveIntegral(cv::_InputArray* src, cv::_OutputArray* sum, cv::_OutputArray* sqsum, cv::_OutputArray* tilted, int sdepth, int sqdepth);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveIntegral", "ptr", $src, "ptr", $sum, "ptr", $sqsum, "ptr", $tilted, "int", $sdepth, "int", $sqdepth), "cveIntegral", @error)
EndFunc   ;==>_cveIntegral

Func _cveIntegralMat(ByRef $matSrc, ByRef $matSum, ByRef $matSqsum, ByRef $matTilted, $sdepth, $sqdepth)
    ; cveIntegral using cv::Mat instead of _*Array

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

    Local $oArrSum, $vectorOfMatSum, $iArrSumSize
    Local $bSumIsArray = VarGetType($matSum) == "Array"

    If $bSumIsArray Then
        $vectorOfMatSum = _VectorOfMatCreate()

        $iArrSumSize = UBound($matSum)
        For $i = 0 To $iArrSumSize - 1
            _VectorOfMatPush($vectorOfMatSum, $matSum[$i])
        Next

        $oArrSum = _cveOutputArrayFromVectorOfMat($vectorOfMatSum)
    Else
        $oArrSum = _cveOutputArrayFromMat($matSum)
    EndIf

    Local $oArrSqsum, $vectorOfMatSqsum, $iArrSqsumSize
    Local $bSqsumIsArray = VarGetType($matSqsum) == "Array"

    If $bSqsumIsArray Then
        $vectorOfMatSqsum = _VectorOfMatCreate()

        $iArrSqsumSize = UBound($matSqsum)
        For $i = 0 To $iArrSqsumSize - 1
            _VectorOfMatPush($vectorOfMatSqsum, $matSqsum[$i])
        Next

        $oArrSqsum = _cveOutputArrayFromVectorOfMat($vectorOfMatSqsum)
    Else
        $oArrSqsum = _cveOutputArrayFromMat($matSqsum)
    EndIf

    Local $oArrTilted, $vectorOfMatTilted, $iArrTiltedSize
    Local $bTiltedIsArray = VarGetType($matTilted) == "Array"

    If $bTiltedIsArray Then
        $vectorOfMatTilted = _VectorOfMatCreate()

        $iArrTiltedSize = UBound($matTilted)
        For $i = 0 To $iArrTiltedSize - 1
            _VectorOfMatPush($vectorOfMatTilted, $matTilted[$i])
        Next

        $oArrTilted = _cveOutputArrayFromVectorOfMat($vectorOfMatTilted)
    Else
        $oArrTilted = _cveOutputArrayFromMat($matTilted)
    EndIf

    _cveIntegral($iArrSrc, $oArrSum, $oArrSqsum, $oArrTilted, $sdepth, $sqdepth)

    If $bTiltedIsArray Then
        _VectorOfMatRelease($vectorOfMatTilted)
    EndIf

    _cveOutputArrayRelease($oArrTilted)

    If $bSqsumIsArray Then
        _VectorOfMatRelease($vectorOfMatSqsum)
    EndIf

    _cveOutputArrayRelease($oArrSqsum)

    If $bSumIsArray Then
        _VectorOfMatRelease($vectorOfMatSum)
    EndIf

    _cveOutputArrayRelease($oArrSum)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)
EndFunc   ;==>_cveIntegralMat

Func _cveFloodFill(ByRef $image, ByRef $mask, ByRef $seedPoint, ByRef $newVal, ByRef $rect, ByRef $loDiff, ByRef $upDiff, $flags)
    ; CVAPI(int) cveFloodFill(cv::_InputOutputArray* image, cv::_InputOutputArray* mask, CvPoint* seedPoint, CvScalar* newVal, CvRect* rect, CvScalar* loDiff, CvScalar* upDiff, int flags);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveFloodFill", "ptr", $image, "ptr", $mask, "struct*", $seedPoint, "struct*", $newVal, "struct*", $rect, "struct*", $loDiff, "struct*", $upDiff, "int", $flags), "cveFloodFill", @error)
EndFunc   ;==>_cveFloodFill

Func _cveFloodFillMat(ByRef $matImage, ByRef $matMask, ByRef $seedPoint, ByRef $newVal, ByRef $rect, ByRef $loDiff, ByRef $upDiff, $flags)
    ; cveFloodFill using cv::Mat instead of _*Array

    Local $ioArrImage, $vectorOfMatImage, $iArrImageSize
    Local $bImageIsArray = VarGetType($matImage) == "Array"

    If $bImageIsArray Then
        $vectorOfMatImage = _VectorOfMatCreate()

        $iArrImageSize = UBound($matImage)
        For $i = 0 To $iArrImageSize - 1
            _VectorOfMatPush($vectorOfMatImage, $matImage[$i])
        Next

        $ioArrImage = _cveInputOutputArrayFromVectorOfMat($vectorOfMatImage)
    Else
        $ioArrImage = _cveInputOutputArrayFromMat($matImage)
    EndIf

    Local $ioArrMask, $vectorOfMatMask, $iArrMaskSize
    Local $bMaskIsArray = VarGetType($matMask) == "Array"

    If $bMaskIsArray Then
        $vectorOfMatMask = _VectorOfMatCreate()

        $iArrMaskSize = UBound($matMask)
        For $i = 0 To $iArrMaskSize - 1
            _VectorOfMatPush($vectorOfMatMask, $matMask[$i])
        Next

        $ioArrMask = _cveInputOutputArrayFromVectorOfMat($vectorOfMatMask)
    Else
        $ioArrMask = _cveInputOutputArrayFromMat($matMask)
    EndIf

    Local $retval = _cveFloodFill($ioArrImage, $ioArrMask, $seedPoint, $newVal, $rect, $loDiff, $upDiff, $flags)

    If $bMaskIsArray Then
        _VectorOfMatRelease($vectorOfMatMask)
    EndIf

    _cveInputOutputArrayRelease($ioArrMask)

    If $bImageIsArray Then
        _VectorOfMatRelease($vectorOfMatImage)
    EndIf

    _cveInputOutputArrayRelease($ioArrImage)

    Return $retval
EndFunc   ;==>_cveFloodFillMat

Func _cvePyrMeanShiftFiltering(ByRef $src, ByRef $dst, $sp, $sr, $maxLevel, ByRef $termCrit)
    ; CVAPI(void) cvePyrMeanShiftFiltering(cv::_InputArray* src, cv::_OutputArray* dst, double sp, double sr, int maxLevel, CvTermCriteria* termCrit);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cvePyrMeanShiftFiltering", "ptr", $src, "ptr", $dst, "double", $sp, "double", $sr, "int", $maxLevel, "struct*", $termCrit), "cvePyrMeanShiftFiltering", @error)
EndFunc   ;==>_cvePyrMeanShiftFiltering

Func _cvePyrMeanShiftFilteringMat(ByRef $matSrc, ByRef $matDst, $sp, $sr, $maxLevel, ByRef $termCrit)
    ; cvePyrMeanShiftFiltering using cv::Mat instead of _*Array

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

    _cvePyrMeanShiftFiltering($iArrSrc, $oArrDst, $sp, $sr, $maxLevel, $termCrit)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveOutputArrayRelease($oArrDst)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)
EndFunc   ;==>_cvePyrMeanShiftFilteringMat

Func _cveMoments(ByRef $arr, $binaryImage, ByRef $moments)
    ; CVAPI(void) cveMoments(cv::_InputArray* arr, bool binaryImage, cv::Moments* moments);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMoments", "ptr", $arr, "boolean", $binaryImage, "ptr", $moments), "cveMoments", @error)
EndFunc   ;==>_cveMoments

Func _cveMomentsMat(ByRef $matArr, $binaryImage, ByRef $moments)
    ; cveMoments using cv::Mat instead of _*Array

    Local $iArrArr, $vectorOfMatArr, $iArrArrSize
    Local $bArrIsArray = VarGetType($matArr) == "Array"

    If $bArrIsArray Then
        $vectorOfMatArr = _VectorOfMatCreate()

        $iArrArrSize = UBound($matArr)
        For $i = 0 To $iArrArrSize - 1
            _VectorOfMatPush($vectorOfMatArr, $matArr[$i])
        Next

        $iArrArr = _cveInputArrayFromVectorOfMat($vectorOfMatArr)
    Else
        $iArrArr = _cveInputArrayFromMat($matArr)
    EndIf

    _cveMoments($iArrArr, $binaryImage, $moments)

    If $bArrIsArray Then
        _VectorOfMatRelease($vectorOfMatArr)
    EndIf

    _cveInputArrayRelease($iArrArr)
EndFunc   ;==>_cveMomentsMat

Func _cveEqualizeHist(ByRef $src, ByRef $dst)
    ; CVAPI(void) cveEqualizeHist(cv::_InputArray* src, cv::_OutputArray* dst);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveEqualizeHist", "ptr", $src, "ptr", $dst), "cveEqualizeHist", @error)
EndFunc   ;==>_cveEqualizeHist

Func _cveEqualizeHistMat(ByRef $matSrc, ByRef $matDst)
    ; cveEqualizeHist using cv::Mat instead of _*Array

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

    _cveEqualizeHist($iArrSrc, $oArrDst)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveOutputArrayRelease($oArrDst)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)
EndFunc   ;==>_cveEqualizeHistMat

Func _cveAccumulate(ByRef $src, ByRef $dst, ByRef $mask)
    ; CVAPI(void) cveAccumulate(cv::_InputArray* src, cv::_InputOutputArray* dst, cv::_InputArray* mask);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveAccumulate", "ptr", $src, "ptr", $dst, "ptr", $mask), "cveAccumulate", @error)
EndFunc   ;==>_cveAccumulate

Func _cveAccumulateMat(ByRef $matSrc, ByRef $matDst, ByRef $matMask)
    ; cveAccumulate using cv::Mat instead of _*Array

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

    Local $ioArrDst, $vectorOfMatDst, $iArrDstSize
    Local $bDstIsArray = VarGetType($matDst) == "Array"

    If $bDstIsArray Then
        $vectorOfMatDst = _VectorOfMatCreate()

        $iArrDstSize = UBound($matDst)
        For $i = 0 To $iArrDstSize - 1
            _VectorOfMatPush($vectorOfMatDst, $matDst[$i])
        Next

        $ioArrDst = _cveInputOutputArrayFromVectorOfMat($vectorOfMatDst)
    Else
        $ioArrDst = _cveInputOutputArrayFromMat($matDst)
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

    _cveAccumulate($iArrSrc, $ioArrDst, $iArrMask)

    If $bMaskIsArray Then
        _VectorOfMatRelease($vectorOfMatMask)
    EndIf

    _cveInputArrayRelease($iArrMask)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveInputOutputArrayRelease($ioArrDst)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)
EndFunc   ;==>_cveAccumulateMat

Func _cveAccumulateSquare(ByRef $src, ByRef $dst, ByRef $mask)
    ; CVAPI(void) cveAccumulateSquare(cv::_InputArray* src, cv::_InputOutputArray* dst, cv::_InputArray* mask);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveAccumulateSquare", "ptr", $src, "ptr", $dst, "ptr", $mask), "cveAccumulateSquare", @error)
EndFunc   ;==>_cveAccumulateSquare

Func _cveAccumulateSquareMat(ByRef $matSrc, ByRef $matDst, ByRef $matMask)
    ; cveAccumulateSquare using cv::Mat instead of _*Array

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

    Local $ioArrDst, $vectorOfMatDst, $iArrDstSize
    Local $bDstIsArray = VarGetType($matDst) == "Array"

    If $bDstIsArray Then
        $vectorOfMatDst = _VectorOfMatCreate()

        $iArrDstSize = UBound($matDst)
        For $i = 0 To $iArrDstSize - 1
            _VectorOfMatPush($vectorOfMatDst, $matDst[$i])
        Next

        $ioArrDst = _cveInputOutputArrayFromVectorOfMat($vectorOfMatDst)
    Else
        $ioArrDst = _cveInputOutputArrayFromMat($matDst)
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

    _cveAccumulateSquare($iArrSrc, $ioArrDst, $iArrMask)

    If $bMaskIsArray Then
        _VectorOfMatRelease($vectorOfMatMask)
    EndIf

    _cveInputArrayRelease($iArrMask)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveInputOutputArrayRelease($ioArrDst)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)
EndFunc   ;==>_cveAccumulateSquareMat

Func _cveAccumulateProduct(ByRef $src1, ByRef $src2, ByRef $dst, ByRef $mask)
    ; CVAPI(void) cveAccumulateProduct(cv::_InputArray* src1, cv::_InputArray* src2, cv::_InputOutputArray* dst, cv::_InputArray* mask);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveAccumulateProduct", "ptr", $src1, "ptr", $src2, "ptr", $dst, "ptr", $mask), "cveAccumulateProduct", @error)
EndFunc   ;==>_cveAccumulateProduct

Func _cveAccumulateProductMat(ByRef $matSrc1, ByRef $matSrc2, ByRef $matDst, ByRef $matMask)
    ; cveAccumulateProduct using cv::Mat instead of _*Array

    Local $iArrSrc1, $vectorOfMatSrc1, $iArrSrc1Size
    Local $bSrc1IsArray = VarGetType($matSrc1) == "Array"

    If $bSrc1IsArray Then
        $vectorOfMatSrc1 = _VectorOfMatCreate()

        $iArrSrc1Size = UBound($matSrc1)
        For $i = 0 To $iArrSrc1Size - 1
            _VectorOfMatPush($vectorOfMatSrc1, $matSrc1[$i])
        Next

        $iArrSrc1 = _cveInputArrayFromVectorOfMat($vectorOfMatSrc1)
    Else
        $iArrSrc1 = _cveInputArrayFromMat($matSrc1)
    EndIf

    Local $iArrSrc2, $vectorOfMatSrc2, $iArrSrc2Size
    Local $bSrc2IsArray = VarGetType($matSrc2) == "Array"

    If $bSrc2IsArray Then
        $vectorOfMatSrc2 = _VectorOfMatCreate()

        $iArrSrc2Size = UBound($matSrc2)
        For $i = 0 To $iArrSrc2Size - 1
            _VectorOfMatPush($vectorOfMatSrc2, $matSrc2[$i])
        Next

        $iArrSrc2 = _cveInputArrayFromVectorOfMat($vectorOfMatSrc2)
    Else
        $iArrSrc2 = _cveInputArrayFromMat($matSrc2)
    EndIf

    Local $ioArrDst, $vectorOfMatDst, $iArrDstSize
    Local $bDstIsArray = VarGetType($matDst) == "Array"

    If $bDstIsArray Then
        $vectorOfMatDst = _VectorOfMatCreate()

        $iArrDstSize = UBound($matDst)
        For $i = 0 To $iArrDstSize - 1
            _VectorOfMatPush($vectorOfMatDst, $matDst[$i])
        Next

        $ioArrDst = _cveInputOutputArrayFromVectorOfMat($vectorOfMatDst)
    Else
        $ioArrDst = _cveInputOutputArrayFromMat($matDst)
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

    _cveAccumulateProduct($iArrSrc1, $iArrSrc2, $ioArrDst, $iArrMask)

    If $bMaskIsArray Then
        _VectorOfMatRelease($vectorOfMatMask)
    EndIf

    _cveInputArrayRelease($iArrMask)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveInputOutputArrayRelease($ioArrDst)

    If $bSrc2IsArray Then
        _VectorOfMatRelease($vectorOfMatSrc2)
    EndIf

    _cveInputArrayRelease($iArrSrc2)

    If $bSrc1IsArray Then
        _VectorOfMatRelease($vectorOfMatSrc1)
    EndIf

    _cveInputArrayRelease($iArrSrc1)
EndFunc   ;==>_cveAccumulateProductMat

Func _cveAccumulateWeighted(ByRef $src, ByRef $dst, $alpha, ByRef $mask)
    ; CVAPI(void) cveAccumulateWeighted(cv::_InputArray* src, cv::_InputOutputArray* dst, double alpha, cv::_InputArray* mask);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveAccumulateWeighted", "ptr", $src, "ptr", $dst, "double", $alpha, "ptr", $mask), "cveAccumulateWeighted", @error)
EndFunc   ;==>_cveAccumulateWeighted

Func _cveAccumulateWeightedMat(ByRef $matSrc, ByRef $matDst, $alpha, ByRef $matMask)
    ; cveAccumulateWeighted using cv::Mat instead of _*Array

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

    Local $ioArrDst, $vectorOfMatDst, $iArrDstSize
    Local $bDstIsArray = VarGetType($matDst) == "Array"

    If $bDstIsArray Then
        $vectorOfMatDst = _VectorOfMatCreate()

        $iArrDstSize = UBound($matDst)
        For $i = 0 To $iArrDstSize - 1
            _VectorOfMatPush($vectorOfMatDst, $matDst[$i])
        Next

        $ioArrDst = _cveInputOutputArrayFromVectorOfMat($vectorOfMatDst)
    Else
        $ioArrDst = _cveInputOutputArrayFromMat($matDst)
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

    _cveAccumulateWeighted($iArrSrc, $ioArrDst, $alpha, $iArrMask)

    If $bMaskIsArray Then
        _VectorOfMatRelease($vectorOfMatMask)
    EndIf

    _cveInputArrayRelease($iArrMask)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveInputOutputArrayRelease($ioArrDst)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)
EndFunc   ;==>_cveAccumulateWeightedMat

Func _cvePhaseCorrelate(ByRef $src1, ByRef $src2, ByRef $window, ByRef $response, ByRef $result)
    ; CVAPI(void) cvePhaseCorrelate(cv::_InputArray* src1, cv::_InputArray* src2, cv::_InputArray* window, double* response, CvPoint2D64f* result);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cvePhaseCorrelate", "ptr", $src1, "ptr", $src2, "ptr", $window, "struct*", $response, "struct*", $result), "cvePhaseCorrelate", @error)
EndFunc   ;==>_cvePhaseCorrelate

Func _cvePhaseCorrelateMat(ByRef $matSrc1, ByRef $matSrc2, ByRef $matWindow, ByRef $response, ByRef $result)
    ; cvePhaseCorrelate using cv::Mat instead of _*Array

    Local $iArrSrc1, $vectorOfMatSrc1, $iArrSrc1Size
    Local $bSrc1IsArray = VarGetType($matSrc1) == "Array"

    If $bSrc1IsArray Then
        $vectorOfMatSrc1 = _VectorOfMatCreate()

        $iArrSrc1Size = UBound($matSrc1)
        For $i = 0 To $iArrSrc1Size - 1
            _VectorOfMatPush($vectorOfMatSrc1, $matSrc1[$i])
        Next

        $iArrSrc1 = _cveInputArrayFromVectorOfMat($vectorOfMatSrc1)
    Else
        $iArrSrc1 = _cveInputArrayFromMat($matSrc1)
    EndIf

    Local $iArrSrc2, $vectorOfMatSrc2, $iArrSrc2Size
    Local $bSrc2IsArray = VarGetType($matSrc2) == "Array"

    If $bSrc2IsArray Then
        $vectorOfMatSrc2 = _VectorOfMatCreate()

        $iArrSrc2Size = UBound($matSrc2)
        For $i = 0 To $iArrSrc2Size - 1
            _VectorOfMatPush($vectorOfMatSrc2, $matSrc2[$i])
        Next

        $iArrSrc2 = _cveInputArrayFromVectorOfMat($vectorOfMatSrc2)
    Else
        $iArrSrc2 = _cveInputArrayFromMat($matSrc2)
    EndIf

    Local $iArrWindow, $vectorOfMatWindow, $iArrWindowSize
    Local $bWindowIsArray = VarGetType($matWindow) == "Array"

    If $bWindowIsArray Then
        $vectorOfMatWindow = _VectorOfMatCreate()

        $iArrWindowSize = UBound($matWindow)
        For $i = 0 To $iArrWindowSize - 1
            _VectorOfMatPush($vectorOfMatWindow, $matWindow[$i])
        Next

        $iArrWindow = _cveInputArrayFromVectorOfMat($vectorOfMatWindow)
    Else
        $iArrWindow = _cveInputArrayFromMat($matWindow)
    EndIf

    _cvePhaseCorrelate($iArrSrc1, $iArrSrc2, $iArrWindow, $response, $result)

    If $bWindowIsArray Then
        _VectorOfMatRelease($vectorOfMatWindow)
    EndIf

    _cveInputArrayRelease($iArrWindow)

    If $bSrc2IsArray Then
        _VectorOfMatRelease($vectorOfMatSrc2)
    EndIf

    _cveInputArrayRelease($iArrSrc2)

    If $bSrc1IsArray Then
        _VectorOfMatRelease($vectorOfMatSrc1)
    EndIf

    _cveInputArrayRelease($iArrSrc1)
EndFunc   ;==>_cvePhaseCorrelateMat

Func _cveCreateHanningWindow(ByRef $dst, ByRef $winSize, $type)
    ; CVAPI(void) cveCreateHanningWindow(cv::_OutputArray* dst, CvSize* winSize, int type);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCreateHanningWindow", "ptr", $dst, "struct*", $winSize, "int", $type), "cveCreateHanningWindow", @error)
EndFunc   ;==>_cveCreateHanningWindow

Func _cveCreateHanningWindowMat(ByRef $matDst, ByRef $winSize, $type)
    ; cveCreateHanningWindow using cv::Mat instead of _*Array

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

    _cveCreateHanningWindow($oArrDst, $winSize, $type)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveOutputArrayRelease($oArrDst)
EndFunc   ;==>_cveCreateHanningWindowMat

Func _cveResize(ByRef $src, ByRef $dst, ByRef $dsize, $fx = 0, $fy = 0, $interpolation = $CV_INTER_LINEAR)
    ; CVAPI(void) cveResize(cv::_InputArray* src, cv::_OutputArray* dst, CvSize* dsize, double fx, double fy, int interpolation);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveResize", "ptr", $src, "ptr", $dst, "struct*", $dsize, "double", $fx, "double", $fy, "int", $interpolation), "cveResize", @error)
EndFunc   ;==>_cveResize

Func _cveResizeMat(ByRef $matSrc, ByRef $matDst, ByRef $dsize, $fx = 0, $fy = 0, $interpolation = $CV_INTER_LINEAR)
    ; cveResize using cv::Mat instead of _*Array

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

    _cveResize($iArrSrc, $oArrDst, $dsize, $fx, $fy, $interpolation)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveOutputArrayRelease($oArrDst)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)
EndFunc   ;==>_cveResizeMat

Func _cveWarpAffine(ByRef $src, ByRef $dst, ByRef $m, ByRef $dsize, $flags, $borderMode, ByRef $borderValue)
    ; CVAPI(void) cveWarpAffine(cv::_InputArray* src, cv::_OutputArray* dst, cv::_InputArray* m, CvSize* dsize, int flags, int borderMode, CvScalar* borderValue);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveWarpAffine", "ptr", $src, "ptr", $dst, "ptr", $m, "struct*", $dsize, "int", $flags, "int", $borderMode, "struct*", $borderValue), "cveWarpAffine", @error)
EndFunc   ;==>_cveWarpAffine

Func _cveWarpAffineMat(ByRef $matSrc, ByRef $matDst, ByRef $matM, ByRef $dsize, $flags, $borderMode, ByRef $borderValue)
    ; cveWarpAffine using cv::Mat instead of _*Array

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

    _cveWarpAffine($iArrSrc, $oArrDst, $iArrM, $dsize, $flags, $borderMode, $borderValue)

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
EndFunc   ;==>_cveWarpAffineMat

Func _cveWarpPerspective(ByRef $src, ByRef $dst, ByRef $m, ByRef $dsize, $flags, $borderMode, ByRef $borderValue)
    ; CVAPI(void) cveWarpPerspective(cv::_InputArray* src, cv::_OutputArray* dst, cv::_InputArray* m, CvSize* dsize, int flags, int borderMode, CvScalar* borderValue);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveWarpPerspective", "ptr", $src, "ptr", $dst, "ptr", $m, "struct*", $dsize, "int", $flags, "int", $borderMode, "struct*", $borderValue), "cveWarpPerspective", @error)
EndFunc   ;==>_cveWarpPerspective

Func _cveWarpPerspectiveMat(ByRef $matSrc, ByRef $matDst, ByRef $matM, ByRef $dsize, $flags, $borderMode, ByRef $borderValue)
    ; cveWarpPerspective using cv::Mat instead of _*Array

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

    _cveWarpPerspective($iArrSrc, $oArrDst, $iArrM, $dsize, $flags, $borderMode, $borderValue)

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
EndFunc   ;==>_cveWarpPerspectiveMat

Func _cveLogPolar(ByRef $src, ByRef $dst, ByRef $center, $M, $flags)
    ; CVAPI(void) cveLogPolar(cv::_InputArray* src, cv::_OutputArray* dst, CvPoint2D32f* center, double M, int flags);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveLogPolar", "ptr", $src, "ptr", $dst, "struct*", $center, "double", $M, "int", $flags), "cveLogPolar", @error)
EndFunc   ;==>_cveLogPolar

Func _cveLogPolarMat(ByRef $matSrc, ByRef $matDst, ByRef $center, $M, $flags)
    ; cveLogPolar using cv::Mat instead of _*Array

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

    _cveLogPolar($iArrSrc, $oArrDst, $center, $M, $flags)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveOutputArrayRelease($oArrDst)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)
EndFunc   ;==>_cveLogPolarMat

Func _cveLinearPolar(ByRef $src, ByRef $dst, ByRef $center, $maxRadius, $flags)
    ; CVAPI(void) cveLinearPolar(cv::_InputArray* src, cv::_OutputArray* dst, CvPoint2D32f* center, double maxRadius, int flags);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveLinearPolar", "ptr", $src, "ptr", $dst, "struct*", $center, "double", $maxRadius, "int", $flags), "cveLinearPolar", @error)
EndFunc   ;==>_cveLinearPolar

Func _cveLinearPolarMat(ByRef $matSrc, ByRef $matDst, ByRef $center, $maxRadius, $flags)
    ; cveLinearPolar using cv::Mat instead of _*Array

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

    _cveLinearPolar($iArrSrc, $oArrDst, $center, $maxRadius, $flags)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveOutputArrayRelease($oArrDst)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)
EndFunc   ;==>_cveLinearPolarMat

Func _cveRemap(ByRef $src, ByRef $dst, ByRef $map1, ByRef $map2, $interpolation, $borderMode, ByRef $borderValue)
    ; CVAPI(void) cveRemap(cv::_InputArray* src, cv::_OutputArray* dst, cv::_InputArray* map1, cv::_InputArray* map2, int interpolation, int borderMode, CvScalar* borderValue);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveRemap", "ptr", $src, "ptr", $dst, "ptr", $map1, "ptr", $map2, "int", $interpolation, "int", $borderMode, "struct*", $borderValue), "cveRemap", @error)
EndFunc   ;==>_cveRemap

Func _cveRemapMat(ByRef $matSrc, ByRef $matDst, ByRef $matMap1, ByRef $matMap2, $interpolation, $borderMode, ByRef $borderValue)
    ; cveRemap using cv::Mat instead of _*Array

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

    Local $iArrMap1, $vectorOfMatMap1, $iArrMap1Size
    Local $bMap1IsArray = VarGetType($matMap1) == "Array"

    If $bMap1IsArray Then
        $vectorOfMatMap1 = _VectorOfMatCreate()

        $iArrMap1Size = UBound($matMap1)
        For $i = 0 To $iArrMap1Size - 1
            _VectorOfMatPush($vectorOfMatMap1, $matMap1[$i])
        Next

        $iArrMap1 = _cveInputArrayFromVectorOfMat($vectorOfMatMap1)
    Else
        $iArrMap1 = _cveInputArrayFromMat($matMap1)
    EndIf

    Local $iArrMap2, $vectorOfMatMap2, $iArrMap2Size
    Local $bMap2IsArray = VarGetType($matMap2) == "Array"

    If $bMap2IsArray Then
        $vectorOfMatMap2 = _VectorOfMatCreate()

        $iArrMap2Size = UBound($matMap2)
        For $i = 0 To $iArrMap2Size - 1
            _VectorOfMatPush($vectorOfMatMap2, $matMap2[$i])
        Next

        $iArrMap2 = _cveInputArrayFromVectorOfMat($vectorOfMatMap2)
    Else
        $iArrMap2 = _cveInputArrayFromMat($matMap2)
    EndIf

    _cveRemap($iArrSrc, $oArrDst, $iArrMap1, $iArrMap2, $interpolation, $borderMode, $borderValue)

    If $bMap2IsArray Then
        _VectorOfMatRelease($vectorOfMatMap2)
    EndIf

    _cveInputArrayRelease($iArrMap2)

    If $bMap1IsArray Then
        _VectorOfMatRelease($vectorOfMatMap1)
    EndIf

    _cveInputArrayRelease($iArrMap1)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveOutputArrayRelease($oArrDst)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)
EndFunc   ;==>_cveRemapMat

Func _cveRepeat(ByRef $src, $ny, $nx, ByRef $dst)
    ; CVAPI(void) cveRepeat(cv::_InputArray* src, int ny, int nx, cv::_OutputArray* dst);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveRepeat", "ptr", $src, "int", $ny, "int", $nx, "ptr", $dst), "cveRepeat", @error)
EndFunc   ;==>_cveRepeat

Func _cveRepeatMat(ByRef $matSrc, $ny, $nx, ByRef $matDst)
    ; cveRepeat using cv::Mat instead of _*Array

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

    _cveRepeat($iArrSrc, $ny, $nx, $oArrDst)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveOutputArrayRelease($oArrDst)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)
EndFunc   ;==>_cveRepeatMat

Func _cveHoughCircles(ByRef $image, ByRef $circles, $method, $dp, $minDist, $param1, $param2, $minRadius, $maxRadius)
    ; CVAPI(void) cveHoughCircles(cv::_InputArray* image, cv::_OutputArray* circles, int method, double dp, double minDist, double param1, double param2, int minRadius, int maxRadius);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveHoughCircles", "ptr", $image, "ptr", $circles, "int", $method, "double", $dp, "double", $minDist, "double", $param1, "double", $param2, "int", $minRadius, "int", $maxRadius), "cveHoughCircles", @error)
EndFunc   ;==>_cveHoughCircles

Func _cveHoughCirclesMat(ByRef $matImage, ByRef $matCircles, $method, $dp, $minDist, $param1, $param2, $minRadius, $maxRadius)
    ; cveHoughCircles using cv::Mat instead of _*Array

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

    Local $oArrCircles, $vectorOfMatCircles, $iArrCirclesSize
    Local $bCirclesIsArray = VarGetType($matCircles) == "Array"

    If $bCirclesIsArray Then
        $vectorOfMatCircles = _VectorOfMatCreate()

        $iArrCirclesSize = UBound($matCircles)
        For $i = 0 To $iArrCirclesSize - 1
            _VectorOfMatPush($vectorOfMatCircles, $matCircles[$i])
        Next

        $oArrCircles = _cveOutputArrayFromVectorOfMat($vectorOfMatCircles)
    Else
        $oArrCircles = _cveOutputArrayFromMat($matCircles)
    EndIf

    _cveHoughCircles($iArrImage, $oArrCircles, $method, $dp, $minDist, $param1, $param2, $minRadius, $maxRadius)

    If $bCirclesIsArray Then
        _VectorOfMatRelease($vectorOfMatCircles)
    EndIf

    _cveOutputArrayRelease($oArrCircles)

    If $bImageIsArray Then
        _VectorOfMatRelease($vectorOfMatImage)
    EndIf

    _cveInputArrayRelease($iArrImage)
EndFunc   ;==>_cveHoughCirclesMat

Func _cveHoughLines(ByRef $image, ByRef $lines, $rho, $theta, $threshold, $srn, $stn)
    ; CVAPI(void) cveHoughLines(cv::_InputArray* image, cv::_OutputArray* lines, double rho, double theta, int threshold, double srn, double stn);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveHoughLines", "ptr", $image, "ptr", $lines, "double", $rho, "double", $theta, "int", $threshold, "double", $srn, "double", $stn), "cveHoughLines", @error)
EndFunc   ;==>_cveHoughLines

Func _cveHoughLinesMat(ByRef $matImage, ByRef $matLines, $rho, $theta, $threshold, $srn, $stn)
    ; cveHoughLines using cv::Mat instead of _*Array

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

    Local $oArrLines, $vectorOfMatLines, $iArrLinesSize
    Local $bLinesIsArray = VarGetType($matLines) == "Array"

    If $bLinesIsArray Then
        $vectorOfMatLines = _VectorOfMatCreate()

        $iArrLinesSize = UBound($matLines)
        For $i = 0 To $iArrLinesSize - 1
            _VectorOfMatPush($vectorOfMatLines, $matLines[$i])
        Next

        $oArrLines = _cveOutputArrayFromVectorOfMat($vectorOfMatLines)
    Else
        $oArrLines = _cveOutputArrayFromMat($matLines)
    EndIf

    _cveHoughLines($iArrImage, $oArrLines, $rho, $theta, $threshold, $srn, $stn)

    If $bLinesIsArray Then
        _VectorOfMatRelease($vectorOfMatLines)
    EndIf

    _cveOutputArrayRelease($oArrLines)

    If $bImageIsArray Then
        _VectorOfMatRelease($vectorOfMatImage)
    EndIf

    _cveInputArrayRelease($iArrImage)
EndFunc   ;==>_cveHoughLinesMat

Func _cveHoughLinesP(ByRef $image, ByRef $lines, $rho, $theta, $threshold, $minLineLength, $maxGap)
    ; CVAPI(void) cveHoughLinesP(cv::_InputArray* image, cv::_OutputArray* lines, double rho, double theta, int threshold, double minLineLength, double maxGap);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveHoughLinesP", "ptr", $image, "ptr", $lines, "double", $rho, "double", $theta, "int", $threshold, "double", $minLineLength, "double", $maxGap), "cveHoughLinesP", @error)
EndFunc   ;==>_cveHoughLinesP

Func _cveHoughLinesPMat(ByRef $matImage, ByRef $matLines, $rho, $theta, $threshold, $minLineLength, $maxGap)
    ; cveHoughLinesP using cv::Mat instead of _*Array

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

    Local $oArrLines, $vectorOfMatLines, $iArrLinesSize
    Local $bLinesIsArray = VarGetType($matLines) == "Array"

    If $bLinesIsArray Then
        $vectorOfMatLines = _VectorOfMatCreate()

        $iArrLinesSize = UBound($matLines)
        For $i = 0 To $iArrLinesSize - 1
            _VectorOfMatPush($vectorOfMatLines, $matLines[$i])
        Next

        $oArrLines = _cveOutputArrayFromVectorOfMat($vectorOfMatLines)
    Else
        $oArrLines = _cveOutputArrayFromMat($matLines)
    EndIf

    _cveHoughLinesP($iArrImage, $oArrLines, $rho, $theta, $threshold, $minLineLength, $maxGap)

    If $bLinesIsArray Then
        _VectorOfMatRelease($vectorOfMatLines)
    EndIf

    _cveOutputArrayRelease($oArrLines)

    If $bImageIsArray Then
        _VectorOfMatRelease($vectorOfMatImage)
    EndIf

    _cveInputArrayRelease($iArrImage)
EndFunc   ;==>_cveHoughLinesPMat

Func _cveMatchTemplate(ByRef $image, ByRef $templ, ByRef $result, $method, ByRef $mask)
    ; CVAPI(void) cveMatchTemplate(cv::_InputArray* image, cv::_InputArray* templ, cv::_OutputArray* result, int method, cv::_InputArray* mask);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMatchTemplate", "ptr", $image, "ptr", $templ, "ptr", $result, "int", $method, "ptr", $mask), "cveMatchTemplate", @error)
EndFunc   ;==>_cveMatchTemplate

Func _cveMatchTemplateMat(ByRef $matImage, ByRef $matTempl, ByRef $matResult, $method, ByRef $matMask)
    ; cveMatchTemplate using cv::Mat instead of _*Array

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

    Local $iArrTempl, $vectorOfMatTempl, $iArrTemplSize
    Local $bTemplIsArray = VarGetType($matTempl) == "Array"

    If $bTemplIsArray Then
        $vectorOfMatTempl = _VectorOfMatCreate()

        $iArrTemplSize = UBound($matTempl)
        For $i = 0 To $iArrTemplSize - 1
            _VectorOfMatPush($vectorOfMatTempl, $matTempl[$i])
        Next

        $iArrTempl = _cveInputArrayFromVectorOfMat($vectorOfMatTempl)
    Else
        $iArrTempl = _cveInputArrayFromMat($matTempl)
    EndIf

    Local $oArrResult, $vectorOfMatResult, $iArrResultSize
    Local $bResultIsArray = VarGetType($matResult) == "Array"

    If $bResultIsArray Then
        $vectorOfMatResult = _VectorOfMatCreate()

        $iArrResultSize = UBound($matResult)
        For $i = 0 To $iArrResultSize - 1
            _VectorOfMatPush($vectorOfMatResult, $matResult[$i])
        Next

        $oArrResult = _cveOutputArrayFromVectorOfMat($vectorOfMatResult)
    Else
        $oArrResult = _cveOutputArrayFromMat($matResult)
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

    _cveMatchTemplate($iArrImage, $iArrTempl, $oArrResult, $method, $iArrMask)

    If $bMaskIsArray Then
        _VectorOfMatRelease($vectorOfMatMask)
    EndIf

    _cveInputArrayRelease($iArrMask)

    If $bResultIsArray Then
        _VectorOfMatRelease($vectorOfMatResult)
    EndIf

    _cveOutputArrayRelease($oArrResult)

    If $bTemplIsArray Then
        _VectorOfMatRelease($vectorOfMatTempl)
    EndIf

    _cveInputArrayRelease($iArrTempl)

    If $bImageIsArray Then
        _VectorOfMatRelease($vectorOfMatImage)
    EndIf

    _cveInputArrayRelease($iArrImage)
EndFunc   ;==>_cveMatchTemplateMat

Func _cveCornerSubPix(ByRef $image, ByRef $corners, ByRef $winSize, ByRef $zeroZone, ByRef $criteria)
    ; CVAPI(void) cveCornerSubPix(cv::_InputArray* image, cv::_InputOutputArray* corners, CvSize* winSize, CvSize* zeroZone, CvTermCriteria* criteria);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCornerSubPix", "ptr", $image, "ptr", $corners, "struct*", $winSize, "struct*", $zeroZone, "struct*", $criteria), "cveCornerSubPix", @error)
EndFunc   ;==>_cveCornerSubPix

Func _cveCornerSubPixMat(ByRef $matImage, ByRef $matCorners, ByRef $winSize, ByRef $zeroZone, ByRef $criteria)
    ; cveCornerSubPix using cv::Mat instead of _*Array

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

    Local $ioArrCorners, $vectorOfMatCorners, $iArrCornersSize
    Local $bCornersIsArray = VarGetType($matCorners) == "Array"

    If $bCornersIsArray Then
        $vectorOfMatCorners = _VectorOfMatCreate()

        $iArrCornersSize = UBound($matCorners)
        For $i = 0 To $iArrCornersSize - 1
            _VectorOfMatPush($vectorOfMatCorners, $matCorners[$i])
        Next

        $ioArrCorners = _cveInputOutputArrayFromVectorOfMat($vectorOfMatCorners)
    Else
        $ioArrCorners = _cveInputOutputArrayFromMat($matCorners)
    EndIf

    _cveCornerSubPix($iArrImage, $ioArrCorners, $winSize, $zeroZone, $criteria)

    If $bCornersIsArray Then
        _VectorOfMatRelease($vectorOfMatCorners)
    EndIf

    _cveInputOutputArrayRelease($ioArrCorners)

    If $bImageIsArray Then
        _VectorOfMatRelease($vectorOfMatImage)
    EndIf

    _cveInputArrayRelease($iArrImage)
EndFunc   ;==>_cveCornerSubPixMat

Func _cveConvertMaps(ByRef $map1, ByRef $map2, ByRef $dstmap1, ByRef $dstmap2, $dstmap1Type, $nninterpolation)
    ; CVAPI(void) cveConvertMaps(cv::_InputArray* map1, cv::_InputArray* map2, cv::_OutputArray* dstmap1, cv::_OutputArray* dstmap2, int dstmap1Type, bool nninterpolation);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveConvertMaps", "ptr", $map1, "ptr", $map2, "ptr", $dstmap1, "ptr", $dstmap2, "int", $dstmap1Type, "boolean", $nninterpolation), "cveConvertMaps", @error)
EndFunc   ;==>_cveConvertMaps

Func _cveConvertMapsMat(ByRef $matMap1, ByRef $matMap2, ByRef $matDstmap1, ByRef $matDstmap2, $dstmap1Type, $nninterpolation)
    ; cveConvertMaps using cv::Mat instead of _*Array

    Local $iArrMap1, $vectorOfMatMap1, $iArrMap1Size
    Local $bMap1IsArray = VarGetType($matMap1) == "Array"

    If $bMap1IsArray Then
        $vectorOfMatMap1 = _VectorOfMatCreate()

        $iArrMap1Size = UBound($matMap1)
        For $i = 0 To $iArrMap1Size - 1
            _VectorOfMatPush($vectorOfMatMap1, $matMap1[$i])
        Next

        $iArrMap1 = _cveInputArrayFromVectorOfMat($vectorOfMatMap1)
    Else
        $iArrMap1 = _cveInputArrayFromMat($matMap1)
    EndIf

    Local $iArrMap2, $vectorOfMatMap2, $iArrMap2Size
    Local $bMap2IsArray = VarGetType($matMap2) == "Array"

    If $bMap2IsArray Then
        $vectorOfMatMap2 = _VectorOfMatCreate()

        $iArrMap2Size = UBound($matMap2)
        For $i = 0 To $iArrMap2Size - 1
            _VectorOfMatPush($vectorOfMatMap2, $matMap2[$i])
        Next

        $iArrMap2 = _cveInputArrayFromVectorOfMat($vectorOfMatMap2)
    Else
        $iArrMap2 = _cveInputArrayFromMat($matMap2)
    EndIf

    Local $oArrDstmap1, $vectorOfMatDstmap1, $iArrDstmap1Size
    Local $bDstmap1IsArray = VarGetType($matDstmap1) == "Array"

    If $bDstmap1IsArray Then
        $vectorOfMatDstmap1 = _VectorOfMatCreate()

        $iArrDstmap1Size = UBound($matDstmap1)
        For $i = 0 To $iArrDstmap1Size - 1
            _VectorOfMatPush($vectorOfMatDstmap1, $matDstmap1[$i])
        Next

        $oArrDstmap1 = _cveOutputArrayFromVectorOfMat($vectorOfMatDstmap1)
    Else
        $oArrDstmap1 = _cveOutputArrayFromMat($matDstmap1)
    EndIf

    Local $oArrDstmap2, $vectorOfMatDstmap2, $iArrDstmap2Size
    Local $bDstmap2IsArray = VarGetType($matDstmap2) == "Array"

    If $bDstmap2IsArray Then
        $vectorOfMatDstmap2 = _VectorOfMatCreate()

        $iArrDstmap2Size = UBound($matDstmap2)
        For $i = 0 To $iArrDstmap2Size - 1
            _VectorOfMatPush($vectorOfMatDstmap2, $matDstmap2[$i])
        Next

        $oArrDstmap2 = _cveOutputArrayFromVectorOfMat($vectorOfMatDstmap2)
    Else
        $oArrDstmap2 = _cveOutputArrayFromMat($matDstmap2)
    EndIf

    _cveConvertMaps($iArrMap1, $iArrMap2, $oArrDstmap1, $oArrDstmap2, $dstmap1Type, $nninterpolation)

    If $bDstmap2IsArray Then
        _VectorOfMatRelease($vectorOfMatDstmap2)
    EndIf

    _cveOutputArrayRelease($oArrDstmap2)

    If $bDstmap1IsArray Then
        _VectorOfMatRelease($vectorOfMatDstmap1)
    EndIf

    _cveOutputArrayRelease($oArrDstmap1)

    If $bMap2IsArray Then
        _VectorOfMatRelease($vectorOfMatMap2)
    EndIf

    _cveInputArrayRelease($iArrMap2)

    If $bMap1IsArray Then
        _VectorOfMatRelease($vectorOfMatMap1)
    EndIf

    _cveInputArrayRelease($iArrMap1)
EndFunc   ;==>_cveConvertMapsMat

Func _cveGetAffineTransform(ByRef $src, ByRef $dst, ByRef $affine)
    ; CVAPI(void) cveGetAffineTransform(cv::_InputArray* src, cv::_InputArray* dst, cv::Mat* affine);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveGetAffineTransform", "ptr", $src, "ptr", $dst, "ptr", $affine), "cveGetAffineTransform", @error)
EndFunc   ;==>_cveGetAffineTransform

Func _cveGetAffineTransformMat(ByRef $matSrc, ByRef $matDst, ByRef $affine)
    ; cveGetAffineTransform using cv::Mat instead of _*Array

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

    _cveGetAffineTransform($iArrSrc, $iArrDst, $affine)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveInputArrayRelease($iArrDst)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)
EndFunc   ;==>_cveGetAffineTransformMat

Func _cveGetPerspectiveTransform(ByRef $src, ByRef $dst, ByRef $perspective)
    ; CVAPI(void) cveGetPerspectiveTransform(cv::_InputArray* src, cv::_InputArray* dst, cv::Mat* perspective);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveGetPerspectiveTransform", "ptr", $src, "ptr", $dst, "ptr", $perspective), "cveGetPerspectiveTransform", @error)
EndFunc   ;==>_cveGetPerspectiveTransform

Func _cveGetPerspectiveTransformMat(ByRef $matSrc, ByRef $matDst, ByRef $perspective)
    ; cveGetPerspectiveTransform using cv::Mat instead of _*Array

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

    _cveGetPerspectiveTransform($iArrSrc, $iArrDst, $perspective)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveInputArrayRelease($iArrDst)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)
EndFunc   ;==>_cveGetPerspectiveTransformMat

Func _cveInvertAffineTransform(ByRef $m, ByRef $im)
    ; CVAPI(void) cveInvertAffineTransform(cv::_InputArray* m, cv::_OutputArray* im);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveInvertAffineTransform", "ptr", $m, "ptr", $im), "cveInvertAffineTransform", @error)
EndFunc   ;==>_cveInvertAffineTransform

Func _cveInvertAffineTransformMat(ByRef $matM, ByRef $matIm)
    ; cveInvertAffineTransform using cv::Mat instead of _*Array

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

    Local $oArrIm, $vectorOfMatIm, $iArrImSize
    Local $bImIsArray = VarGetType($matIm) == "Array"

    If $bImIsArray Then
        $vectorOfMatIm = _VectorOfMatCreate()

        $iArrImSize = UBound($matIm)
        For $i = 0 To $iArrImSize - 1
            _VectorOfMatPush($vectorOfMatIm, $matIm[$i])
        Next

        $oArrIm = _cveOutputArrayFromVectorOfMat($vectorOfMatIm)
    Else
        $oArrIm = _cveOutputArrayFromMat($matIm)
    EndIf

    _cveInvertAffineTransform($iArrM, $oArrIm)

    If $bImIsArray Then
        _VectorOfMatRelease($vectorOfMatIm)
    EndIf

    _cveOutputArrayRelease($oArrIm)

    If $bMIsArray Then
        _VectorOfMatRelease($vectorOfMatM)
    EndIf

    _cveInputArrayRelease($iArrM)
EndFunc   ;==>_cveInvertAffineTransformMat

Func _cveEMD(ByRef $signature1, ByRef $signature2, $distType, ByRef $cost, ByRef $lowerBound, ByRef $flow)
    ; CVAPI(void) cveEMD(cv::_InputArray* signature1, cv::_InputArray* signature2, int distType, cv::_InputArray* cost, float* lowerBound, cv::_OutputArray* flow);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveEMD", "ptr", $signature1, "ptr", $signature2, "int", $distType, "ptr", $cost, "struct*", $lowerBound, "ptr", $flow), "cveEMD", @error)
EndFunc   ;==>_cveEMD

Func _cveEMDMat(ByRef $matSignature1, ByRef $matSignature2, $distType, ByRef $matCost, ByRef $lowerBound, ByRef $matFlow)
    ; cveEMD using cv::Mat instead of _*Array

    Local $iArrSignature1, $vectorOfMatSignature1, $iArrSignature1Size
    Local $bSignature1IsArray = VarGetType($matSignature1) == "Array"

    If $bSignature1IsArray Then
        $vectorOfMatSignature1 = _VectorOfMatCreate()

        $iArrSignature1Size = UBound($matSignature1)
        For $i = 0 To $iArrSignature1Size - 1
            _VectorOfMatPush($vectorOfMatSignature1, $matSignature1[$i])
        Next

        $iArrSignature1 = _cveInputArrayFromVectorOfMat($vectorOfMatSignature1)
    Else
        $iArrSignature1 = _cveInputArrayFromMat($matSignature1)
    EndIf

    Local $iArrSignature2, $vectorOfMatSignature2, $iArrSignature2Size
    Local $bSignature2IsArray = VarGetType($matSignature2) == "Array"

    If $bSignature2IsArray Then
        $vectorOfMatSignature2 = _VectorOfMatCreate()

        $iArrSignature2Size = UBound($matSignature2)
        For $i = 0 To $iArrSignature2Size - 1
            _VectorOfMatPush($vectorOfMatSignature2, $matSignature2[$i])
        Next

        $iArrSignature2 = _cveInputArrayFromVectorOfMat($vectorOfMatSignature2)
    Else
        $iArrSignature2 = _cveInputArrayFromMat($matSignature2)
    EndIf

    Local $iArrCost, $vectorOfMatCost, $iArrCostSize
    Local $bCostIsArray = VarGetType($matCost) == "Array"

    If $bCostIsArray Then
        $vectorOfMatCost = _VectorOfMatCreate()

        $iArrCostSize = UBound($matCost)
        For $i = 0 To $iArrCostSize - 1
            _VectorOfMatPush($vectorOfMatCost, $matCost[$i])
        Next

        $iArrCost = _cveInputArrayFromVectorOfMat($vectorOfMatCost)
    Else
        $iArrCost = _cveInputArrayFromMat($matCost)
    EndIf

    Local $oArrFlow, $vectorOfMatFlow, $iArrFlowSize
    Local $bFlowIsArray = VarGetType($matFlow) == "Array"

    If $bFlowIsArray Then
        $vectorOfMatFlow = _VectorOfMatCreate()

        $iArrFlowSize = UBound($matFlow)
        For $i = 0 To $iArrFlowSize - 1
            _VectorOfMatPush($vectorOfMatFlow, $matFlow[$i])
        Next

        $oArrFlow = _cveOutputArrayFromVectorOfMat($vectorOfMatFlow)
    Else
        $oArrFlow = _cveOutputArrayFromMat($matFlow)
    EndIf

    _cveEMD($iArrSignature1, $iArrSignature2, $distType, $iArrCost, $lowerBound, $oArrFlow)

    If $bFlowIsArray Then
        _VectorOfMatRelease($vectorOfMatFlow)
    EndIf

    _cveOutputArrayRelease($oArrFlow)

    If $bCostIsArray Then
        _VectorOfMatRelease($vectorOfMatCost)
    EndIf

    _cveInputArrayRelease($iArrCost)

    If $bSignature2IsArray Then
        _VectorOfMatRelease($vectorOfMatSignature2)
    EndIf

    _cveInputArrayRelease($iArrSignature2)

    If $bSignature1IsArray Then
        _VectorOfMatRelease($vectorOfMatSignature1)
    EndIf

    _cveInputArrayRelease($iArrSignature1)
EndFunc   ;==>_cveEMDMat

Func _cveCalcHist(ByRef $images, $channels, ByRef $mask, ByRef $hist, ByRef $histSize, ByRef $ranges, $accumulate)
    ; CVAPI(void) cveCalcHist(cv::_InputArray* images, const std::vector<int>* channels, cv::_InputArray* mask, cv::_OutputArray* hist, std::vector<int>* histSize, std::vector<float>* ranges, bool accumulate);

    Local $vecChannels, $iArrChannelsSize
    Local $bChannelsIsArray = VarGetType($channels) == "Array"

    If $bChannelsIsArray Then
        $vecChannels = _VectorOfIntCreate()

        $iArrChannelsSize = UBound($channels)
        For $i = 0 To $iArrChannelsSize - 1
            _VectorOfIntPush($vecChannels, $channels[$i])
        Next
    Else
        $vecChannels = $channels
    EndIf

    Local $vecHistSize, $iArrHistSizeSize
    Local $bHistSizeIsArray = VarGetType($histSize) == "Array"

    If $bHistSizeIsArray Then
        $vecHistSize = _VectorOfIntCreate()

        $iArrHistSizeSize = UBound($histSize)
        For $i = 0 To $iArrHistSizeSize - 1
            _VectorOfIntPush($vecHistSize, $histSize[$i])
        Next
    Else
        $vecHistSize = $histSize
    EndIf

    Local $vecRanges, $iArrRangesSize
    Local $bRangesIsArray = VarGetType($ranges) == "Array"

    If $bRangesIsArray Then
        $vecRanges = _VectorOfFloatCreate()

        $iArrRangesSize = UBound($ranges)
        For $i = 0 To $iArrRangesSize - 1
            _VectorOfFloatPush($vecRanges, $ranges[$i])
        Next
    Else
        $vecRanges = $ranges
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCalcHist", "ptr", $images, "ptr", $vecChannels, "ptr", $mask, "ptr", $hist, "ptr", $vecHistSize, "ptr", $vecRanges, "boolean", $accumulate), "cveCalcHist", @error)

    If $bRangesIsArray Then
        _VectorOfFloatRelease($vecRanges)
    EndIf

    If $bHistSizeIsArray Then
        _VectorOfIntRelease($vecHistSize)
    EndIf

    If $bChannelsIsArray Then
        _VectorOfIntRelease($vecChannels)
    EndIf
EndFunc   ;==>_cveCalcHist

Func _cveCalcHistMat(ByRef $matImages, $channels, ByRef $matMask, ByRef $matHist, ByRef $histSize, ByRef $ranges, $accumulate)
    ; cveCalcHist using cv::Mat instead of _*Array

    Local $iArrImages, $vectorOfMatImages, $iArrImagesSize
    Local $bImagesIsArray = VarGetType($matImages) == "Array"

    If $bImagesIsArray Then
        $vectorOfMatImages = _VectorOfMatCreate()

        $iArrImagesSize = UBound($matImages)
        For $i = 0 To $iArrImagesSize - 1
            _VectorOfMatPush($vectorOfMatImages, $matImages[$i])
        Next

        $iArrImages = _cveInputArrayFromVectorOfMat($vectorOfMatImages)
    Else
        $iArrImages = _cveInputArrayFromMat($matImages)
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

    Local $oArrHist, $vectorOfMatHist, $iArrHistSize
    Local $bHistIsArray = VarGetType($matHist) == "Array"

    If $bHistIsArray Then
        $vectorOfMatHist = _VectorOfMatCreate()

        $iArrHistSize = UBound($matHist)
        For $i = 0 To $iArrHistSize - 1
            _VectorOfMatPush($vectorOfMatHist, $matHist[$i])
        Next

        $oArrHist = _cveOutputArrayFromVectorOfMat($vectorOfMatHist)
    Else
        $oArrHist = _cveOutputArrayFromMat($matHist)
    EndIf

    _cveCalcHist($iArrImages, $channels, $iArrMask, $oArrHist, $histSize, $ranges, $accumulate)

    If $bHistIsArray Then
        _VectorOfMatRelease($vectorOfMatHist)
    EndIf

    _cveOutputArrayRelease($oArrHist)

    If $bMaskIsArray Then
        _VectorOfMatRelease($vectorOfMatMask)
    EndIf

    _cveInputArrayRelease($iArrMask)

    If $bImagesIsArray Then
        _VectorOfMatRelease($vectorOfMatImages)
    EndIf

    _cveInputArrayRelease($iArrImages)
EndFunc   ;==>_cveCalcHistMat

Func _cveCalcBackProject(ByRef $images, $channels, ByRef $hist, ByRef $dst, $ranges, $scale)
    ; CVAPI(void) cveCalcBackProject(cv::_InputArray* images, const std::vector<int>* channels, cv::_InputArray* hist, cv::_OutputArray* dst, const std::vector<float>* ranges, double scale);

    Local $vecChannels, $iArrChannelsSize
    Local $bChannelsIsArray = VarGetType($channels) == "Array"

    If $bChannelsIsArray Then
        $vecChannels = _VectorOfIntCreate()

        $iArrChannelsSize = UBound($channels)
        For $i = 0 To $iArrChannelsSize - 1
            _VectorOfIntPush($vecChannels, $channels[$i])
        Next
    Else
        $vecChannels = $channels
    EndIf

    Local $vecRanges, $iArrRangesSize
    Local $bRangesIsArray = VarGetType($ranges) == "Array"

    If $bRangesIsArray Then
        $vecRanges = _VectorOfFloatCreate()

        $iArrRangesSize = UBound($ranges)
        For $i = 0 To $iArrRangesSize - 1
            _VectorOfFloatPush($vecRanges, $ranges[$i])
        Next
    Else
        $vecRanges = $ranges
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCalcBackProject", "ptr", $images, "ptr", $vecChannels, "ptr", $hist, "ptr", $dst, "ptr", $vecRanges, "double", $scale), "cveCalcBackProject", @error)

    If $bRangesIsArray Then
        _VectorOfFloatRelease($vecRanges)
    EndIf

    If $bChannelsIsArray Then
        _VectorOfIntRelease($vecChannels)
    EndIf
EndFunc   ;==>_cveCalcBackProject

Func _cveCalcBackProjectMat(ByRef $matImages, $channels, ByRef $matHist, ByRef $matDst, $ranges, $scale)
    ; cveCalcBackProject using cv::Mat instead of _*Array

    Local $iArrImages, $vectorOfMatImages, $iArrImagesSize
    Local $bImagesIsArray = VarGetType($matImages) == "Array"

    If $bImagesIsArray Then
        $vectorOfMatImages = _VectorOfMatCreate()

        $iArrImagesSize = UBound($matImages)
        For $i = 0 To $iArrImagesSize - 1
            _VectorOfMatPush($vectorOfMatImages, $matImages[$i])
        Next

        $iArrImages = _cveInputArrayFromVectorOfMat($vectorOfMatImages)
    Else
        $iArrImages = _cveInputArrayFromMat($matImages)
    EndIf

    Local $iArrHist, $vectorOfMatHist, $iArrHistSize
    Local $bHistIsArray = VarGetType($matHist) == "Array"

    If $bHistIsArray Then
        $vectorOfMatHist = _VectorOfMatCreate()

        $iArrHistSize = UBound($matHist)
        For $i = 0 To $iArrHistSize - 1
            _VectorOfMatPush($vectorOfMatHist, $matHist[$i])
        Next

        $iArrHist = _cveInputArrayFromVectorOfMat($vectorOfMatHist)
    Else
        $iArrHist = _cveInputArrayFromMat($matHist)
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

    _cveCalcBackProject($iArrImages, $channels, $iArrHist, $oArrDst, $ranges, $scale)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveOutputArrayRelease($oArrDst)

    If $bHistIsArray Then
        _VectorOfMatRelease($vectorOfMatHist)
    EndIf

    _cveInputArrayRelease($iArrHist)

    If $bImagesIsArray Then
        _VectorOfMatRelease($vectorOfMatImages)
    EndIf

    _cveInputArrayRelease($iArrImages)
EndFunc   ;==>_cveCalcBackProjectMat

Func _cveCompareHist(ByRef $h1, ByRef $h2, $method)
    ; CVAPI(double) cveCompareHist(cv::_InputArray* h1, cv::_InputArray* h2, int method);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveCompareHist", "ptr", $h1, "ptr", $h2, "int", $method), "cveCompareHist", @error)
EndFunc   ;==>_cveCompareHist

Func _cveCompareHistMat(ByRef $matH1, ByRef $matH2, $method)
    ; cveCompareHist using cv::Mat instead of _*Array

    Local $iArrH1, $vectorOfMatH1, $iArrH1Size
    Local $bH1IsArray = VarGetType($matH1) == "Array"

    If $bH1IsArray Then
        $vectorOfMatH1 = _VectorOfMatCreate()

        $iArrH1Size = UBound($matH1)
        For $i = 0 To $iArrH1Size - 1
            _VectorOfMatPush($vectorOfMatH1, $matH1[$i])
        Next

        $iArrH1 = _cveInputArrayFromVectorOfMat($vectorOfMatH1)
    Else
        $iArrH1 = _cveInputArrayFromMat($matH1)
    EndIf

    Local $iArrH2, $vectorOfMatH2, $iArrH2Size
    Local $bH2IsArray = VarGetType($matH2) == "Array"

    If $bH2IsArray Then
        $vectorOfMatH2 = _VectorOfMatCreate()

        $iArrH2Size = UBound($matH2)
        For $i = 0 To $iArrH2Size - 1
            _VectorOfMatPush($vectorOfMatH2, $matH2[$i])
        Next

        $iArrH2 = _cveInputArrayFromVectorOfMat($vectorOfMatH2)
    Else
        $iArrH2 = _cveInputArrayFromMat($matH2)
    EndIf

    Local $retval = _cveCompareHist($iArrH1, $iArrH2, $method)

    If $bH2IsArray Then
        _VectorOfMatRelease($vectorOfMatH2)
    EndIf

    _cveInputArrayRelease($iArrH2)

    If $bH1IsArray Then
        _VectorOfMatRelease($vectorOfMatH1)
    EndIf

    _cveInputArrayRelease($iArrH1)

    Return $retval
EndFunc   ;==>_cveCompareHistMat

Func _cveGetRotationMatrix2D(ByRef $center, $angle, $scale, ByRef $rotationMatrix2D)
    ; CVAPI(void) cveGetRotationMatrix2D(CvPoint2D32f* center, double angle, double scale, cv::_OutputArray* rotationMatrix2D);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveGetRotationMatrix2D", "struct*", $center, "double", $angle, "double", $scale, "ptr", $rotationMatrix2D), "cveGetRotationMatrix2D", @error)
EndFunc   ;==>_cveGetRotationMatrix2D

Func _cveGetRotationMatrix2DMat(ByRef $center, $angle, $scale, ByRef $matRotationMatrix2D)
    ; cveGetRotationMatrix2D using cv::Mat instead of _*Array

    Local $oArrRotationMatrix2D, $vectorOfMatRotationMatrix2D, $iArrRotationMatrix2DSize
    Local $bRotationMatrix2DIsArray = VarGetType($matRotationMatrix2D) == "Array"

    If $bRotationMatrix2DIsArray Then
        $vectorOfMatRotationMatrix2D = _VectorOfMatCreate()

        $iArrRotationMatrix2DSize = UBound($matRotationMatrix2D)
        For $i = 0 To $iArrRotationMatrix2DSize - 1
            _VectorOfMatPush($vectorOfMatRotationMatrix2D, $matRotationMatrix2D[$i])
        Next

        $oArrRotationMatrix2D = _cveOutputArrayFromVectorOfMat($vectorOfMatRotationMatrix2D)
    Else
        $oArrRotationMatrix2D = _cveOutputArrayFromMat($matRotationMatrix2D)
    EndIf

    _cveGetRotationMatrix2D($center, $angle, $scale, $oArrRotationMatrix2D)

    If $bRotationMatrix2DIsArray Then
        _VectorOfMatRelease($vectorOfMatRotationMatrix2D)
    EndIf

    _cveOutputArrayRelease($oArrRotationMatrix2D)
EndFunc   ;==>_cveGetRotationMatrix2DMat

Func _cveFindContours(ByRef $image, ByRef $contours, ByRef $hierarchy, $mode, $method, ByRef $offset)
    ; CVAPI(void) cveFindContours(cv::_InputOutputArray* image, cv::_OutputArray* contours, cv::_OutputArray* hierarchy, int mode, int method, CvPoint* offset);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFindContours", "ptr", $image, "ptr", $contours, "ptr", $hierarchy, "int", $mode, "int", $method, "struct*", $offset), "cveFindContours", @error)
EndFunc   ;==>_cveFindContours

Func _cveFindContoursMat(ByRef $matImage, ByRef $matContours, ByRef $matHierarchy, $mode, $method, ByRef $offset)
    ; cveFindContours using cv::Mat instead of _*Array

    Local $ioArrImage, $vectorOfMatImage, $iArrImageSize
    Local $bImageIsArray = VarGetType($matImage) == "Array"

    If $bImageIsArray Then
        $vectorOfMatImage = _VectorOfMatCreate()

        $iArrImageSize = UBound($matImage)
        For $i = 0 To $iArrImageSize - 1
            _VectorOfMatPush($vectorOfMatImage, $matImage[$i])
        Next

        $ioArrImage = _cveInputOutputArrayFromVectorOfMat($vectorOfMatImage)
    Else
        $ioArrImage = _cveInputOutputArrayFromMat($matImage)
    EndIf

    Local $oArrContours, $vectorOfMatContours, $iArrContoursSize
    Local $bContoursIsArray = VarGetType($matContours) == "Array"

    If $bContoursIsArray Then
        $vectorOfMatContours = _VectorOfMatCreate()

        $iArrContoursSize = UBound($matContours)
        For $i = 0 To $iArrContoursSize - 1
            _VectorOfMatPush($vectorOfMatContours, $matContours[$i])
        Next

        $oArrContours = _cveOutputArrayFromVectorOfMat($vectorOfMatContours)
    Else
        $oArrContours = _cveOutputArrayFromMat($matContours)
    EndIf

    Local $oArrHierarchy, $vectorOfMatHierarchy, $iArrHierarchySize
    Local $bHierarchyIsArray = VarGetType($matHierarchy) == "Array"

    If $bHierarchyIsArray Then
        $vectorOfMatHierarchy = _VectorOfMatCreate()

        $iArrHierarchySize = UBound($matHierarchy)
        For $i = 0 To $iArrHierarchySize - 1
            _VectorOfMatPush($vectorOfMatHierarchy, $matHierarchy[$i])
        Next

        $oArrHierarchy = _cveOutputArrayFromVectorOfMat($vectorOfMatHierarchy)
    Else
        $oArrHierarchy = _cveOutputArrayFromMat($matHierarchy)
    EndIf

    _cveFindContours($ioArrImage, $oArrContours, $oArrHierarchy, $mode, $method, $offset)

    If $bHierarchyIsArray Then
        _VectorOfMatRelease($vectorOfMatHierarchy)
    EndIf

    _cveOutputArrayRelease($oArrHierarchy)

    If $bContoursIsArray Then
        _VectorOfMatRelease($vectorOfMatContours)
    EndIf

    _cveOutputArrayRelease($oArrContours)

    If $bImageIsArray Then
        _VectorOfMatRelease($vectorOfMatImage)
    EndIf

    _cveInputOutputArrayRelease($ioArrImage)
EndFunc   ;==>_cveFindContoursMat

Func _cvePointPolygonTest(ByRef $contour, ByRef $pt, $measureDist)
    ; CVAPI(double) cvePointPolygonTest(cv::_InputArray* contour, CvPoint2D32f* pt, bool measureDist);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cvePointPolygonTest", "ptr", $contour, "struct*", $pt, "boolean", $measureDist), "cvePointPolygonTest", @error)
EndFunc   ;==>_cvePointPolygonTest

Func _cvePointPolygonTestMat(ByRef $matContour, ByRef $pt, $measureDist)
    ; cvePointPolygonTest using cv::Mat instead of _*Array

    Local $iArrContour, $vectorOfMatContour, $iArrContourSize
    Local $bContourIsArray = VarGetType($matContour) == "Array"

    If $bContourIsArray Then
        $vectorOfMatContour = _VectorOfMatCreate()

        $iArrContourSize = UBound($matContour)
        For $i = 0 To $iArrContourSize - 1
            _VectorOfMatPush($vectorOfMatContour, $matContour[$i])
        Next

        $iArrContour = _cveInputArrayFromVectorOfMat($vectorOfMatContour)
    Else
        $iArrContour = _cveInputArrayFromMat($matContour)
    EndIf

    Local $retval = _cvePointPolygonTest($iArrContour, $pt, $measureDist)

    If $bContourIsArray Then
        _VectorOfMatRelease($vectorOfMatContour)
    EndIf

    _cveInputArrayRelease($iArrContour)

    Return $retval
EndFunc   ;==>_cvePointPolygonTestMat

Func _cveContourArea(ByRef $contour, $oriented)
    ; CVAPI(double) cveContourArea(cv::_InputArray* contour, bool oriented);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveContourArea", "ptr", $contour, "boolean", $oriented), "cveContourArea", @error)
EndFunc   ;==>_cveContourArea

Func _cveContourAreaMat(ByRef $matContour, $oriented)
    ; cveContourArea using cv::Mat instead of _*Array

    Local $iArrContour, $vectorOfMatContour, $iArrContourSize
    Local $bContourIsArray = VarGetType($matContour) == "Array"

    If $bContourIsArray Then
        $vectorOfMatContour = _VectorOfMatCreate()

        $iArrContourSize = UBound($matContour)
        For $i = 0 To $iArrContourSize - 1
            _VectorOfMatPush($vectorOfMatContour, $matContour[$i])
        Next

        $iArrContour = _cveInputArrayFromVectorOfMat($vectorOfMatContour)
    Else
        $iArrContour = _cveInputArrayFromMat($matContour)
    EndIf

    Local $retval = _cveContourArea($iArrContour, $oriented)

    If $bContourIsArray Then
        _VectorOfMatRelease($vectorOfMatContour)
    EndIf

    _cveInputArrayRelease($iArrContour)

    Return $retval
EndFunc   ;==>_cveContourAreaMat

Func _cveIsContourConvex(ByRef $contour)
    ; CVAPI(bool) cveIsContourConvex(cv::_InputArray* contour);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveIsContourConvex", "ptr", $contour), "cveIsContourConvex", @error)
EndFunc   ;==>_cveIsContourConvex

Func _cveIsContourConvexMat(ByRef $matContour)
    ; cveIsContourConvex using cv::Mat instead of _*Array

    Local $iArrContour, $vectorOfMatContour, $iArrContourSize
    Local $bContourIsArray = VarGetType($matContour) == "Array"

    If $bContourIsArray Then
        $vectorOfMatContour = _VectorOfMatCreate()

        $iArrContourSize = UBound($matContour)
        For $i = 0 To $iArrContourSize - 1
            _VectorOfMatPush($vectorOfMatContour, $matContour[$i])
        Next

        $iArrContour = _cveInputArrayFromVectorOfMat($vectorOfMatContour)
    Else
        $iArrContour = _cveInputArrayFromMat($matContour)
    EndIf

    Local $retval = _cveIsContourConvex($iArrContour)

    If $bContourIsArray Then
        _VectorOfMatRelease($vectorOfMatContour)
    EndIf

    _cveInputArrayRelease($iArrContour)

    Return $retval
EndFunc   ;==>_cveIsContourConvexMat

Func _cveIntersectConvexConvex(ByRef $p1, ByRef $p2, ByRef $p12, $handleNested)
    ; CVAPI(float) cveIntersectConvexConvex(cv::_InputArray* p1, cv::_InputArray* p2, cv::_OutputArray* p12, bool handleNested);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cveIntersectConvexConvex", "ptr", $p1, "ptr", $p2, "ptr", $p12, "boolean", $handleNested), "cveIntersectConvexConvex", @error)
EndFunc   ;==>_cveIntersectConvexConvex

Func _cveIntersectConvexConvexMat(ByRef $matP1, ByRef $matP2, ByRef $matP12, $handleNested)
    ; cveIntersectConvexConvex using cv::Mat instead of _*Array

    Local $iArrP1, $vectorOfMatP1, $iArrP1Size
    Local $bP1IsArray = VarGetType($matP1) == "Array"

    If $bP1IsArray Then
        $vectorOfMatP1 = _VectorOfMatCreate()

        $iArrP1Size = UBound($matP1)
        For $i = 0 To $iArrP1Size - 1
            _VectorOfMatPush($vectorOfMatP1, $matP1[$i])
        Next

        $iArrP1 = _cveInputArrayFromVectorOfMat($vectorOfMatP1)
    Else
        $iArrP1 = _cveInputArrayFromMat($matP1)
    EndIf

    Local $iArrP2, $vectorOfMatP2, $iArrP2Size
    Local $bP2IsArray = VarGetType($matP2) == "Array"

    If $bP2IsArray Then
        $vectorOfMatP2 = _VectorOfMatCreate()

        $iArrP2Size = UBound($matP2)
        For $i = 0 To $iArrP2Size - 1
            _VectorOfMatPush($vectorOfMatP2, $matP2[$i])
        Next

        $iArrP2 = _cveInputArrayFromVectorOfMat($vectorOfMatP2)
    Else
        $iArrP2 = _cveInputArrayFromMat($matP2)
    EndIf

    Local $oArrP12, $vectorOfMatP12, $iArrP12Size
    Local $bP12IsArray = VarGetType($matP12) == "Array"

    If $bP12IsArray Then
        $vectorOfMatP12 = _VectorOfMatCreate()

        $iArrP12Size = UBound($matP12)
        For $i = 0 To $iArrP12Size - 1
            _VectorOfMatPush($vectorOfMatP12, $matP12[$i])
        Next

        $oArrP12 = _cveOutputArrayFromVectorOfMat($vectorOfMatP12)
    Else
        $oArrP12 = _cveOutputArrayFromMat($matP12)
    EndIf

    Local $retval = _cveIntersectConvexConvex($iArrP1, $iArrP2, $oArrP12, $handleNested)

    If $bP12IsArray Then
        _VectorOfMatRelease($vectorOfMatP12)
    EndIf

    _cveOutputArrayRelease($oArrP12)

    If $bP2IsArray Then
        _VectorOfMatRelease($vectorOfMatP2)
    EndIf

    _cveInputArrayRelease($iArrP2)

    If $bP1IsArray Then
        _VectorOfMatRelease($vectorOfMatP1)
    EndIf

    _cveInputArrayRelease($iArrP1)

    Return $retval
EndFunc   ;==>_cveIntersectConvexConvexMat

Func _cveBoundingRectangle(ByRef $points, ByRef $boundingRect)
    ; CVAPI(void) cveBoundingRectangle(cv::_InputArray* points, CvRect* boundingRect);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBoundingRectangle", "ptr", $points, "struct*", $boundingRect), "cveBoundingRectangle", @error)
EndFunc   ;==>_cveBoundingRectangle

Func _cveBoundingRectangleMat(ByRef $matPoints, ByRef $boundingRect)
    ; cveBoundingRectangle using cv::Mat instead of _*Array

    Local $iArrPoints, $vectorOfMatPoints, $iArrPointsSize
    Local $bPointsIsArray = VarGetType($matPoints) == "Array"

    If $bPointsIsArray Then
        $vectorOfMatPoints = _VectorOfMatCreate()

        $iArrPointsSize = UBound($matPoints)
        For $i = 0 To $iArrPointsSize - 1
            _VectorOfMatPush($vectorOfMatPoints, $matPoints[$i])
        Next

        $iArrPoints = _cveInputArrayFromVectorOfMat($vectorOfMatPoints)
    Else
        $iArrPoints = _cveInputArrayFromMat($matPoints)
    EndIf

    _cveBoundingRectangle($iArrPoints, $boundingRect)

    If $bPointsIsArray Then
        _VectorOfMatRelease($vectorOfMatPoints)
    EndIf

    _cveInputArrayRelease($iArrPoints)
EndFunc   ;==>_cveBoundingRectangleMat

Func _cveArcLength(ByRef $curve, $closed)
    ; CVAPI(double) cveArcLength(cv::_InputArray* curve, bool closed);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveArcLength", "ptr", $curve, "boolean", $closed), "cveArcLength", @error)
EndFunc   ;==>_cveArcLength

Func _cveArcLengthMat(ByRef $matCurve, $closed)
    ; cveArcLength using cv::Mat instead of _*Array

    Local $iArrCurve, $vectorOfMatCurve, $iArrCurveSize
    Local $bCurveIsArray = VarGetType($matCurve) == "Array"

    If $bCurveIsArray Then
        $vectorOfMatCurve = _VectorOfMatCreate()

        $iArrCurveSize = UBound($matCurve)
        For $i = 0 To $iArrCurveSize - 1
            _VectorOfMatPush($vectorOfMatCurve, $matCurve[$i])
        Next

        $iArrCurve = _cveInputArrayFromVectorOfMat($vectorOfMatCurve)
    Else
        $iArrCurve = _cveInputArrayFromMat($matCurve)
    EndIf

    Local $retval = _cveArcLength($iArrCurve, $closed)

    If $bCurveIsArray Then
        _VectorOfMatRelease($vectorOfMatCurve)
    EndIf

    _cveInputArrayRelease($iArrCurve)

    Return $retval
EndFunc   ;==>_cveArcLengthMat

Func _cveMinAreaRect(ByRef $points, ByRef $box)
    ; CVAPI(void) cveMinAreaRect(cv::_InputArray* points, CvBox2D* box);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMinAreaRect", "ptr", $points, "struct*", $box), "cveMinAreaRect", @error)
EndFunc   ;==>_cveMinAreaRect

Func _cveMinAreaRectMat(ByRef $matPoints, ByRef $box)
    ; cveMinAreaRect using cv::Mat instead of _*Array

    Local $iArrPoints, $vectorOfMatPoints, $iArrPointsSize
    Local $bPointsIsArray = VarGetType($matPoints) == "Array"

    If $bPointsIsArray Then
        $vectorOfMatPoints = _VectorOfMatCreate()

        $iArrPointsSize = UBound($matPoints)
        For $i = 0 To $iArrPointsSize - 1
            _VectorOfMatPush($vectorOfMatPoints, $matPoints[$i])
        Next

        $iArrPoints = _cveInputArrayFromVectorOfMat($vectorOfMatPoints)
    Else
        $iArrPoints = _cveInputArrayFromMat($matPoints)
    EndIf

    _cveMinAreaRect($iArrPoints, $box)

    If $bPointsIsArray Then
        _VectorOfMatRelease($vectorOfMatPoints)
    EndIf

    _cveInputArrayRelease($iArrPoints)
EndFunc   ;==>_cveMinAreaRectMat

Func _cveBoxPoints(ByRef $box, ByRef $points)
    ; CVAPI(void) cveBoxPoints(CvBox2D* box, cv::_OutputArray* points);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBoxPoints", "struct*", $box, "ptr", $points), "cveBoxPoints", @error)
EndFunc   ;==>_cveBoxPoints

Func _cveBoxPointsMat(ByRef $box, ByRef $matPoints)
    ; cveBoxPoints using cv::Mat instead of _*Array

    Local $oArrPoints, $vectorOfMatPoints, $iArrPointsSize
    Local $bPointsIsArray = VarGetType($matPoints) == "Array"

    If $bPointsIsArray Then
        $vectorOfMatPoints = _VectorOfMatCreate()

        $iArrPointsSize = UBound($matPoints)
        For $i = 0 To $iArrPointsSize - 1
            _VectorOfMatPush($vectorOfMatPoints, $matPoints[$i])
        Next

        $oArrPoints = _cveOutputArrayFromVectorOfMat($vectorOfMatPoints)
    Else
        $oArrPoints = _cveOutputArrayFromMat($matPoints)
    EndIf

    _cveBoxPoints($box, $oArrPoints)

    If $bPointsIsArray Then
        _VectorOfMatRelease($vectorOfMatPoints)
    EndIf

    _cveOutputArrayRelease($oArrPoints)
EndFunc   ;==>_cveBoxPointsMat

Func _cveMinEnclosingTriangle(ByRef $points, ByRef $triangle)
    ; CVAPI(double) cveMinEnclosingTriangle(cv::_InputArray* points, cv::_OutputArray* triangle);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveMinEnclosingTriangle", "ptr", $points, "ptr", $triangle), "cveMinEnclosingTriangle", @error)
EndFunc   ;==>_cveMinEnclosingTriangle

Func _cveMinEnclosingTriangleMat(ByRef $matPoints, ByRef $matTriangle)
    ; cveMinEnclosingTriangle using cv::Mat instead of _*Array

    Local $iArrPoints, $vectorOfMatPoints, $iArrPointsSize
    Local $bPointsIsArray = VarGetType($matPoints) == "Array"

    If $bPointsIsArray Then
        $vectorOfMatPoints = _VectorOfMatCreate()

        $iArrPointsSize = UBound($matPoints)
        For $i = 0 To $iArrPointsSize - 1
            _VectorOfMatPush($vectorOfMatPoints, $matPoints[$i])
        Next

        $iArrPoints = _cveInputArrayFromVectorOfMat($vectorOfMatPoints)
    Else
        $iArrPoints = _cveInputArrayFromMat($matPoints)
    EndIf

    Local $oArrTriangle, $vectorOfMatTriangle, $iArrTriangleSize
    Local $bTriangleIsArray = VarGetType($matTriangle) == "Array"

    If $bTriangleIsArray Then
        $vectorOfMatTriangle = _VectorOfMatCreate()

        $iArrTriangleSize = UBound($matTriangle)
        For $i = 0 To $iArrTriangleSize - 1
            _VectorOfMatPush($vectorOfMatTriangle, $matTriangle[$i])
        Next

        $oArrTriangle = _cveOutputArrayFromVectorOfMat($vectorOfMatTriangle)
    Else
        $oArrTriangle = _cveOutputArrayFromMat($matTriangle)
    EndIf

    Local $retval = _cveMinEnclosingTriangle($iArrPoints, $oArrTriangle)

    If $bTriangleIsArray Then
        _VectorOfMatRelease($vectorOfMatTriangle)
    EndIf

    _cveOutputArrayRelease($oArrTriangle)

    If $bPointsIsArray Then
        _VectorOfMatRelease($vectorOfMatPoints)
    EndIf

    _cveInputArrayRelease($iArrPoints)

    Return $retval
EndFunc   ;==>_cveMinEnclosingTriangleMat

Func _cveMinEnclosingCircle(ByRef $points, ByRef $center, ByRef $radius)
    ; CVAPI(void) cveMinEnclosingCircle(cv::_InputArray* points, CvPoint2D32f* center, float* radius);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMinEnclosingCircle", "ptr", $points, "struct*", $center, "struct*", $radius), "cveMinEnclosingCircle", @error)
EndFunc   ;==>_cveMinEnclosingCircle

Func _cveMinEnclosingCircleMat(ByRef $matPoints, ByRef $center, ByRef $radius)
    ; cveMinEnclosingCircle using cv::Mat instead of _*Array

    Local $iArrPoints, $vectorOfMatPoints, $iArrPointsSize
    Local $bPointsIsArray = VarGetType($matPoints) == "Array"

    If $bPointsIsArray Then
        $vectorOfMatPoints = _VectorOfMatCreate()

        $iArrPointsSize = UBound($matPoints)
        For $i = 0 To $iArrPointsSize - 1
            _VectorOfMatPush($vectorOfMatPoints, $matPoints[$i])
        Next

        $iArrPoints = _cveInputArrayFromVectorOfMat($vectorOfMatPoints)
    Else
        $iArrPoints = _cveInputArrayFromMat($matPoints)
    EndIf

    _cveMinEnclosingCircle($iArrPoints, $center, $radius)

    If $bPointsIsArray Then
        _VectorOfMatRelease($vectorOfMatPoints)
    EndIf

    _cveInputArrayRelease($iArrPoints)
EndFunc   ;==>_cveMinEnclosingCircleMat

Func _cveMatchShapes(ByRef $contour1, ByRef $contour2, $method, $parameter)
    ; CVAPI(double) cveMatchShapes(cv::_InputArray* contour1, cv::_InputArray* contour2, int method, double parameter);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveMatchShapes", "ptr", $contour1, "ptr", $contour2, "int", $method, "double", $parameter), "cveMatchShapes", @error)
EndFunc   ;==>_cveMatchShapes

Func _cveMatchShapesMat(ByRef $matContour1, ByRef $matContour2, $method, $parameter)
    ; cveMatchShapes using cv::Mat instead of _*Array

    Local $iArrContour1, $vectorOfMatContour1, $iArrContour1Size
    Local $bContour1IsArray = VarGetType($matContour1) == "Array"

    If $bContour1IsArray Then
        $vectorOfMatContour1 = _VectorOfMatCreate()

        $iArrContour1Size = UBound($matContour1)
        For $i = 0 To $iArrContour1Size - 1
            _VectorOfMatPush($vectorOfMatContour1, $matContour1[$i])
        Next

        $iArrContour1 = _cveInputArrayFromVectorOfMat($vectorOfMatContour1)
    Else
        $iArrContour1 = _cveInputArrayFromMat($matContour1)
    EndIf

    Local $iArrContour2, $vectorOfMatContour2, $iArrContour2Size
    Local $bContour2IsArray = VarGetType($matContour2) == "Array"

    If $bContour2IsArray Then
        $vectorOfMatContour2 = _VectorOfMatCreate()

        $iArrContour2Size = UBound($matContour2)
        For $i = 0 To $iArrContour2Size - 1
            _VectorOfMatPush($vectorOfMatContour2, $matContour2[$i])
        Next

        $iArrContour2 = _cveInputArrayFromVectorOfMat($vectorOfMatContour2)
    Else
        $iArrContour2 = _cveInputArrayFromMat($matContour2)
    EndIf

    Local $retval = _cveMatchShapes($iArrContour1, $iArrContour2, $method, $parameter)

    If $bContour2IsArray Then
        _VectorOfMatRelease($vectorOfMatContour2)
    EndIf

    _cveInputArrayRelease($iArrContour2)

    If $bContour1IsArray Then
        _VectorOfMatRelease($vectorOfMatContour1)
    EndIf

    _cveInputArrayRelease($iArrContour1)

    Return $retval
EndFunc   ;==>_cveMatchShapesMat

Func _cveFitEllipse(ByRef $points, ByRef $box)
    ; CVAPI(void) cveFitEllipse(cv::_InputArray* points, CvBox2D* box);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFitEllipse", "ptr", $points, "struct*", $box), "cveFitEllipse", @error)
EndFunc   ;==>_cveFitEllipse

Func _cveFitEllipseMat(ByRef $matPoints, ByRef $box)
    ; cveFitEllipse using cv::Mat instead of _*Array

    Local $iArrPoints, $vectorOfMatPoints, $iArrPointsSize
    Local $bPointsIsArray = VarGetType($matPoints) == "Array"

    If $bPointsIsArray Then
        $vectorOfMatPoints = _VectorOfMatCreate()

        $iArrPointsSize = UBound($matPoints)
        For $i = 0 To $iArrPointsSize - 1
            _VectorOfMatPush($vectorOfMatPoints, $matPoints[$i])
        Next

        $iArrPoints = _cveInputArrayFromVectorOfMat($vectorOfMatPoints)
    Else
        $iArrPoints = _cveInputArrayFromMat($matPoints)
    EndIf

    _cveFitEllipse($iArrPoints, $box)

    If $bPointsIsArray Then
        _VectorOfMatRelease($vectorOfMatPoints)
    EndIf

    _cveInputArrayRelease($iArrPoints)
EndFunc   ;==>_cveFitEllipseMat

Func _cveFitEllipseAMS(ByRef $points, ByRef $box)
    ; CVAPI(void) cveFitEllipseAMS(cv::_InputArray* points, CvBox2D* box);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFitEllipseAMS", "ptr", $points, "struct*", $box), "cveFitEllipseAMS", @error)
EndFunc   ;==>_cveFitEllipseAMS

Func _cveFitEllipseAMSMat(ByRef $matPoints, ByRef $box)
    ; cveFitEllipseAMS using cv::Mat instead of _*Array

    Local $iArrPoints, $vectorOfMatPoints, $iArrPointsSize
    Local $bPointsIsArray = VarGetType($matPoints) == "Array"

    If $bPointsIsArray Then
        $vectorOfMatPoints = _VectorOfMatCreate()

        $iArrPointsSize = UBound($matPoints)
        For $i = 0 To $iArrPointsSize - 1
            _VectorOfMatPush($vectorOfMatPoints, $matPoints[$i])
        Next

        $iArrPoints = _cveInputArrayFromVectorOfMat($vectorOfMatPoints)
    Else
        $iArrPoints = _cveInputArrayFromMat($matPoints)
    EndIf

    _cveFitEllipseAMS($iArrPoints, $box)

    If $bPointsIsArray Then
        _VectorOfMatRelease($vectorOfMatPoints)
    EndIf

    _cveInputArrayRelease($iArrPoints)
EndFunc   ;==>_cveFitEllipseAMSMat

Func _cveFitEllipseDirect(ByRef $points, ByRef $box)
    ; CVAPI(void) cveFitEllipseDirect(cv::_InputArray* points, CvBox2D* box);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFitEllipseDirect", "ptr", $points, "struct*", $box), "cveFitEllipseDirect", @error)
EndFunc   ;==>_cveFitEllipseDirect

Func _cveFitEllipseDirectMat(ByRef $matPoints, ByRef $box)
    ; cveFitEllipseDirect using cv::Mat instead of _*Array

    Local $iArrPoints, $vectorOfMatPoints, $iArrPointsSize
    Local $bPointsIsArray = VarGetType($matPoints) == "Array"

    If $bPointsIsArray Then
        $vectorOfMatPoints = _VectorOfMatCreate()

        $iArrPointsSize = UBound($matPoints)
        For $i = 0 To $iArrPointsSize - 1
            _VectorOfMatPush($vectorOfMatPoints, $matPoints[$i])
        Next

        $iArrPoints = _cveInputArrayFromVectorOfMat($vectorOfMatPoints)
    Else
        $iArrPoints = _cveInputArrayFromMat($matPoints)
    EndIf

    _cveFitEllipseDirect($iArrPoints, $box)

    If $bPointsIsArray Then
        _VectorOfMatRelease($vectorOfMatPoints)
    EndIf

    _cveInputArrayRelease($iArrPoints)
EndFunc   ;==>_cveFitEllipseDirectMat

Func _cveFitLine(ByRef $points, ByRef $line, $distType, $param, $reps, $aeps)
    ; CVAPI(void) cveFitLine(cv::_InputArray* points, cv::_OutputArray* line, int distType, double param, double reps, double aeps);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFitLine", "ptr", $points, "ptr", $line, "int", $distType, "double", $param, "double", $reps, "double", $aeps), "cveFitLine", @error)
EndFunc   ;==>_cveFitLine

Func _cveFitLineMat(ByRef $matPoints, ByRef $matLine, $distType, $param, $reps, $aeps)
    ; cveFitLine using cv::Mat instead of _*Array

    Local $iArrPoints, $vectorOfMatPoints, $iArrPointsSize
    Local $bPointsIsArray = VarGetType($matPoints) == "Array"

    If $bPointsIsArray Then
        $vectorOfMatPoints = _VectorOfMatCreate()

        $iArrPointsSize = UBound($matPoints)
        For $i = 0 To $iArrPointsSize - 1
            _VectorOfMatPush($vectorOfMatPoints, $matPoints[$i])
        Next

        $iArrPoints = _cveInputArrayFromVectorOfMat($vectorOfMatPoints)
    Else
        $iArrPoints = _cveInputArrayFromMat($matPoints)
    EndIf

    Local $oArrLine, $vectorOfMatLine, $iArrLineSize
    Local $bLineIsArray = VarGetType($matLine) == "Array"

    If $bLineIsArray Then
        $vectorOfMatLine = _VectorOfMatCreate()

        $iArrLineSize = UBound($matLine)
        For $i = 0 To $iArrLineSize - 1
            _VectorOfMatPush($vectorOfMatLine, $matLine[$i])
        Next

        $oArrLine = _cveOutputArrayFromVectorOfMat($vectorOfMatLine)
    Else
        $oArrLine = _cveOutputArrayFromMat($matLine)
    EndIf

    _cveFitLine($iArrPoints, $oArrLine, $distType, $param, $reps, $aeps)

    If $bLineIsArray Then
        _VectorOfMatRelease($vectorOfMatLine)
    EndIf

    _cveOutputArrayRelease($oArrLine)

    If $bPointsIsArray Then
        _VectorOfMatRelease($vectorOfMatPoints)
    EndIf

    _cveInputArrayRelease($iArrPoints)
EndFunc   ;==>_cveFitLineMat

Func _cveRotatedRectangleIntersection(ByRef $rect1, ByRef $rect2, ByRef $intersectingRegion)
    ; CVAPI(int) cveRotatedRectangleIntersection(CvBox2D* rect1, CvBox2D* rect2, cv::_OutputArray* intersectingRegion);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveRotatedRectangleIntersection", "struct*", $rect1, "struct*", $rect2, "ptr", $intersectingRegion), "cveRotatedRectangleIntersection", @error)
EndFunc   ;==>_cveRotatedRectangleIntersection

Func _cveRotatedRectangleIntersectionMat(ByRef $rect1, ByRef $rect2, ByRef $matIntersectingRegion)
    ; cveRotatedRectangleIntersection using cv::Mat instead of _*Array

    Local $oArrIntersectingRegion, $vectorOfMatIntersectingRegion, $iArrIntersectingRegionSize
    Local $bIntersectingRegionIsArray = VarGetType($matIntersectingRegion) == "Array"

    If $bIntersectingRegionIsArray Then
        $vectorOfMatIntersectingRegion = _VectorOfMatCreate()

        $iArrIntersectingRegionSize = UBound($matIntersectingRegion)
        For $i = 0 To $iArrIntersectingRegionSize - 1
            _VectorOfMatPush($vectorOfMatIntersectingRegion, $matIntersectingRegion[$i])
        Next

        $oArrIntersectingRegion = _cveOutputArrayFromVectorOfMat($vectorOfMatIntersectingRegion)
    Else
        $oArrIntersectingRegion = _cveOutputArrayFromMat($matIntersectingRegion)
    EndIf

    Local $retval = _cveRotatedRectangleIntersection($rect1, $rect2, $oArrIntersectingRegion)

    If $bIntersectingRegionIsArray Then
        _VectorOfMatRelease($vectorOfMatIntersectingRegion)
    EndIf

    _cveOutputArrayRelease($oArrIntersectingRegion)

    Return $retval
EndFunc   ;==>_cveRotatedRectangleIntersectionMat

Func _cveDrawContours(ByRef $image, ByRef $contours, $contourIdx, ByRef $color, $thickness, $lineType, ByRef $hierarchy, $maxLevel, ByRef $offset)
    ; CVAPI(void) cveDrawContours(cv::_InputOutputArray* image, cv::_InputArray* contours, int contourIdx, CvScalar* color, int thickness, int lineType, cv::_InputArray* hierarchy, int maxLevel, CvPoint* offset);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDrawContours", "ptr", $image, "ptr", $contours, "int", $contourIdx, "struct*", $color, "int", $thickness, "int", $lineType, "ptr", $hierarchy, "int", $maxLevel, "struct*", $offset), "cveDrawContours", @error)
EndFunc   ;==>_cveDrawContours

Func _cveDrawContoursMat(ByRef $matImage, ByRef $matContours, $contourIdx, ByRef $color, $thickness, $lineType, ByRef $matHierarchy, $maxLevel, ByRef $offset)
    ; cveDrawContours using cv::Mat instead of _*Array

    Local $ioArrImage, $vectorOfMatImage, $iArrImageSize
    Local $bImageIsArray = VarGetType($matImage) == "Array"

    If $bImageIsArray Then
        $vectorOfMatImage = _VectorOfMatCreate()

        $iArrImageSize = UBound($matImage)
        For $i = 0 To $iArrImageSize - 1
            _VectorOfMatPush($vectorOfMatImage, $matImage[$i])
        Next

        $ioArrImage = _cveInputOutputArrayFromVectorOfMat($vectorOfMatImage)
    Else
        $ioArrImage = _cveInputOutputArrayFromMat($matImage)
    EndIf

    Local $iArrContours, $vectorOfMatContours, $iArrContoursSize
    Local $bContoursIsArray = VarGetType($matContours) == "Array"

    If $bContoursIsArray Then
        $vectorOfMatContours = _VectorOfMatCreate()

        $iArrContoursSize = UBound($matContours)
        For $i = 0 To $iArrContoursSize - 1
            _VectorOfMatPush($vectorOfMatContours, $matContours[$i])
        Next

        $iArrContours = _cveInputArrayFromVectorOfMat($vectorOfMatContours)
    Else
        $iArrContours = _cveInputArrayFromMat($matContours)
    EndIf

    Local $iArrHierarchy, $vectorOfMatHierarchy, $iArrHierarchySize
    Local $bHierarchyIsArray = VarGetType($matHierarchy) == "Array"

    If $bHierarchyIsArray Then
        $vectorOfMatHierarchy = _VectorOfMatCreate()

        $iArrHierarchySize = UBound($matHierarchy)
        For $i = 0 To $iArrHierarchySize - 1
            _VectorOfMatPush($vectorOfMatHierarchy, $matHierarchy[$i])
        Next

        $iArrHierarchy = _cveInputArrayFromVectorOfMat($vectorOfMatHierarchy)
    Else
        $iArrHierarchy = _cveInputArrayFromMat($matHierarchy)
    EndIf

    _cveDrawContours($ioArrImage, $iArrContours, $contourIdx, $color, $thickness, $lineType, $iArrHierarchy, $maxLevel, $offset)

    If $bHierarchyIsArray Then
        _VectorOfMatRelease($vectorOfMatHierarchy)
    EndIf

    _cveInputArrayRelease($iArrHierarchy)

    If $bContoursIsArray Then
        _VectorOfMatRelease($vectorOfMatContours)
    EndIf

    _cveInputArrayRelease($iArrContours)

    If $bImageIsArray Then
        _VectorOfMatRelease($vectorOfMatImage)
    EndIf

    _cveInputOutputArrayRelease($ioArrImage)
EndFunc   ;==>_cveDrawContoursMat

Func _cveApproxPolyDP(ByRef $curve, ByRef $approxCurve, $epsilon, $closed)
    ; CVAPI(void) cveApproxPolyDP(cv::_InputArray* curve, cv::_OutputArray* approxCurve, double epsilon, bool closed);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveApproxPolyDP", "ptr", $curve, "ptr", $approxCurve, "double", $epsilon, "boolean", $closed), "cveApproxPolyDP", @error)
EndFunc   ;==>_cveApproxPolyDP

Func _cveApproxPolyDPMat(ByRef $matCurve, ByRef $matApproxCurve, $epsilon, $closed)
    ; cveApproxPolyDP using cv::Mat instead of _*Array

    Local $iArrCurve, $vectorOfMatCurve, $iArrCurveSize
    Local $bCurveIsArray = VarGetType($matCurve) == "Array"

    If $bCurveIsArray Then
        $vectorOfMatCurve = _VectorOfMatCreate()

        $iArrCurveSize = UBound($matCurve)
        For $i = 0 To $iArrCurveSize - 1
            _VectorOfMatPush($vectorOfMatCurve, $matCurve[$i])
        Next

        $iArrCurve = _cveInputArrayFromVectorOfMat($vectorOfMatCurve)
    Else
        $iArrCurve = _cveInputArrayFromMat($matCurve)
    EndIf

    Local $oArrApproxCurve, $vectorOfMatApproxCurve, $iArrApproxCurveSize
    Local $bApproxCurveIsArray = VarGetType($matApproxCurve) == "Array"

    If $bApproxCurveIsArray Then
        $vectorOfMatApproxCurve = _VectorOfMatCreate()

        $iArrApproxCurveSize = UBound($matApproxCurve)
        For $i = 0 To $iArrApproxCurveSize - 1
            _VectorOfMatPush($vectorOfMatApproxCurve, $matApproxCurve[$i])
        Next

        $oArrApproxCurve = _cveOutputArrayFromVectorOfMat($vectorOfMatApproxCurve)
    Else
        $oArrApproxCurve = _cveOutputArrayFromMat($matApproxCurve)
    EndIf

    _cveApproxPolyDP($iArrCurve, $oArrApproxCurve, $epsilon, $closed)

    If $bApproxCurveIsArray Then
        _VectorOfMatRelease($vectorOfMatApproxCurve)
    EndIf

    _cveOutputArrayRelease($oArrApproxCurve)

    If $bCurveIsArray Then
        _VectorOfMatRelease($vectorOfMatCurve)
    EndIf

    _cveInputArrayRelease($iArrCurve)
EndFunc   ;==>_cveApproxPolyDPMat

Func _cveConvexHull(ByRef $points, ByRef $hull, $clockwise, $returnPoints)
    ; CVAPI(void) cveConvexHull(cv::_InputArray* points, cv::_OutputArray* hull, bool clockwise, bool returnPoints);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveConvexHull", "ptr", $points, "ptr", $hull, "boolean", $clockwise, "boolean", $returnPoints), "cveConvexHull", @error)
EndFunc   ;==>_cveConvexHull

Func _cveConvexHullMat(ByRef $matPoints, ByRef $matHull, $clockwise, $returnPoints)
    ; cveConvexHull using cv::Mat instead of _*Array

    Local $iArrPoints, $vectorOfMatPoints, $iArrPointsSize
    Local $bPointsIsArray = VarGetType($matPoints) == "Array"

    If $bPointsIsArray Then
        $vectorOfMatPoints = _VectorOfMatCreate()

        $iArrPointsSize = UBound($matPoints)
        For $i = 0 To $iArrPointsSize - 1
            _VectorOfMatPush($vectorOfMatPoints, $matPoints[$i])
        Next

        $iArrPoints = _cveInputArrayFromVectorOfMat($vectorOfMatPoints)
    Else
        $iArrPoints = _cveInputArrayFromMat($matPoints)
    EndIf

    Local $oArrHull, $vectorOfMatHull, $iArrHullSize
    Local $bHullIsArray = VarGetType($matHull) == "Array"

    If $bHullIsArray Then
        $vectorOfMatHull = _VectorOfMatCreate()

        $iArrHullSize = UBound($matHull)
        For $i = 0 To $iArrHullSize - 1
            _VectorOfMatPush($vectorOfMatHull, $matHull[$i])
        Next

        $oArrHull = _cveOutputArrayFromVectorOfMat($vectorOfMatHull)
    Else
        $oArrHull = _cveOutputArrayFromMat($matHull)
    EndIf

    _cveConvexHull($iArrPoints, $oArrHull, $clockwise, $returnPoints)

    If $bHullIsArray Then
        _VectorOfMatRelease($vectorOfMatHull)
    EndIf

    _cveOutputArrayRelease($oArrHull)

    If $bPointsIsArray Then
        _VectorOfMatRelease($vectorOfMatPoints)
    EndIf

    _cveInputArrayRelease($iArrPoints)
EndFunc   ;==>_cveConvexHullMat

Func _cveConvexityDefects(ByRef $contour, ByRef $convexhull, ByRef $convexityDefects)
    ; CVAPI(void) cveConvexityDefects(cv::_InputArray* contour, cv::_InputArray* convexhull, cv::_OutputArray* convexityDefects);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveConvexityDefects", "ptr", $contour, "ptr", $convexhull, "ptr", $convexityDefects), "cveConvexityDefects", @error)
EndFunc   ;==>_cveConvexityDefects

Func _cveConvexityDefectsMat(ByRef $matContour, ByRef $matConvexhull, ByRef $matConvexityDefects)
    ; cveConvexityDefects using cv::Mat instead of _*Array

    Local $iArrContour, $vectorOfMatContour, $iArrContourSize
    Local $bContourIsArray = VarGetType($matContour) == "Array"

    If $bContourIsArray Then
        $vectorOfMatContour = _VectorOfMatCreate()

        $iArrContourSize = UBound($matContour)
        For $i = 0 To $iArrContourSize - 1
            _VectorOfMatPush($vectorOfMatContour, $matContour[$i])
        Next

        $iArrContour = _cveInputArrayFromVectorOfMat($vectorOfMatContour)
    Else
        $iArrContour = _cveInputArrayFromMat($matContour)
    EndIf

    Local $iArrConvexhull, $vectorOfMatConvexhull, $iArrConvexhullSize
    Local $bConvexhullIsArray = VarGetType($matConvexhull) == "Array"

    If $bConvexhullIsArray Then
        $vectorOfMatConvexhull = _VectorOfMatCreate()

        $iArrConvexhullSize = UBound($matConvexhull)
        For $i = 0 To $iArrConvexhullSize - 1
            _VectorOfMatPush($vectorOfMatConvexhull, $matConvexhull[$i])
        Next

        $iArrConvexhull = _cveInputArrayFromVectorOfMat($vectorOfMatConvexhull)
    Else
        $iArrConvexhull = _cveInputArrayFromMat($matConvexhull)
    EndIf

    Local $oArrConvexityDefects, $vectorOfMatConvexityDefects, $iArrConvexityDefectsSize
    Local $bConvexityDefectsIsArray = VarGetType($matConvexityDefects) == "Array"

    If $bConvexityDefectsIsArray Then
        $vectorOfMatConvexityDefects = _VectorOfMatCreate()

        $iArrConvexityDefectsSize = UBound($matConvexityDefects)
        For $i = 0 To $iArrConvexityDefectsSize - 1
            _VectorOfMatPush($vectorOfMatConvexityDefects, $matConvexityDefects[$i])
        Next

        $oArrConvexityDefects = _cveOutputArrayFromVectorOfMat($vectorOfMatConvexityDefects)
    Else
        $oArrConvexityDefects = _cveOutputArrayFromMat($matConvexityDefects)
    EndIf

    _cveConvexityDefects($iArrContour, $iArrConvexhull, $oArrConvexityDefects)

    If $bConvexityDefectsIsArray Then
        _VectorOfMatRelease($vectorOfMatConvexityDefects)
    EndIf

    _cveOutputArrayRelease($oArrConvexityDefects)

    If $bConvexhullIsArray Then
        _VectorOfMatRelease($vectorOfMatConvexhull)
    EndIf

    _cveInputArrayRelease($iArrConvexhull)

    If $bContourIsArray Then
        _VectorOfMatRelease($vectorOfMatContour)
    EndIf

    _cveInputArrayRelease($iArrContour)
EndFunc   ;==>_cveConvexityDefectsMat

Func _cveGaussianBlur(ByRef $src, ByRef $dst, ByRef $ksize, $sigmaX, $sigmaY, $borderType)
    ; CVAPI(void) cveGaussianBlur(cv::_InputArray* src, cv::_OutputArray* dst, CvSize* ksize, double sigmaX, double sigmaY, int borderType);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveGaussianBlur", "ptr", $src, "ptr", $dst, "struct*", $ksize, "double", $sigmaX, "double", $sigmaY, "int", $borderType), "cveGaussianBlur", @error)
EndFunc   ;==>_cveGaussianBlur

Func _cveGaussianBlurMat(ByRef $matSrc, ByRef $matDst, ByRef $ksize, $sigmaX, $sigmaY, $borderType)
    ; cveGaussianBlur using cv::Mat instead of _*Array

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

    _cveGaussianBlur($iArrSrc, $oArrDst, $ksize, $sigmaX, $sigmaY, $borderType)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveOutputArrayRelease($oArrDst)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)
EndFunc   ;==>_cveGaussianBlurMat

Func _cveBlur(ByRef $src, ByRef $dst, ByRef $kSize, ByRef $anchor, $borderType)
    ; CVAPI(void) cveBlur(cv::_InputArray* src, cv::_OutputArray* dst, CvSize* kSize, CvPoint* anchor, int borderType);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBlur", "ptr", $src, "ptr", $dst, "struct*", $kSize, "struct*", $anchor, "int", $borderType), "cveBlur", @error)
EndFunc   ;==>_cveBlur

Func _cveBlurMat(ByRef $matSrc, ByRef $matDst, ByRef $kSize, ByRef $anchor, $borderType)
    ; cveBlur using cv::Mat instead of _*Array

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

    _cveBlur($iArrSrc, $oArrDst, $kSize, $anchor, $borderType)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveOutputArrayRelease($oArrDst)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)
EndFunc   ;==>_cveBlurMat

Func _cveMedianBlur(ByRef $src, ByRef $dst, $ksize)
    ; CVAPI(void) cveMedianBlur(cv::_InputArray* src, cv::_OutputArray* dst, int ksize);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMedianBlur", "ptr", $src, "ptr", $dst, "int", $ksize), "cveMedianBlur", @error)
EndFunc   ;==>_cveMedianBlur

Func _cveMedianBlurMat(ByRef $matSrc, ByRef $matDst, $ksize)
    ; cveMedianBlur using cv::Mat instead of _*Array

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

    _cveMedianBlur($iArrSrc, $oArrDst, $ksize)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveOutputArrayRelease($oArrDst)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)
EndFunc   ;==>_cveMedianBlurMat

Func _cveBoxFilter(ByRef $src, ByRef $dst, $ddepth, ByRef $ksize, ByRef $anchor, $normailize, $borderType)
    ; CVAPI(void) cveBoxFilter(cv::_InputArray* src, cv::_OutputArray* dst, int ddepth, CvSize* ksize, CvPoint* anchor, bool normailize, int borderType);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBoxFilter", "ptr", $src, "ptr", $dst, "int", $ddepth, "struct*", $ksize, "struct*", $anchor, "boolean", $normailize, "int", $borderType), "cveBoxFilter", @error)
EndFunc   ;==>_cveBoxFilter

Func _cveBoxFilterMat(ByRef $matSrc, ByRef $matDst, $ddepth, ByRef $ksize, ByRef $anchor, $normailize, $borderType)
    ; cveBoxFilter using cv::Mat instead of _*Array

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

    _cveBoxFilter($iArrSrc, $oArrDst, $ddepth, $ksize, $anchor, $normailize, $borderType)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveOutputArrayRelease($oArrDst)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)
EndFunc   ;==>_cveBoxFilterMat

Func _cveSqrBoxFilter(ByRef $_src, ByRef $_dst, $ddepth, ByRef $ksize, ByRef $anchor, $normalize, $borderType)
    ; CVAPI(void) cveSqrBoxFilter(cv::_InputArray* _src, cv::_OutputArray* _dst, int ddepth, CvSize* ksize, CvPoint* anchor, bool normalize, int borderType);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSqrBoxFilter", "ptr", $_src, "ptr", $_dst, "int", $ddepth, "struct*", $ksize, "struct*", $anchor, "boolean", $normalize, "int", $borderType), "cveSqrBoxFilter", @error)
EndFunc   ;==>_cveSqrBoxFilter

Func _cveSqrBoxFilterMat(ByRef $mat_src, ByRef $mat_dst, $ddepth, ByRef $ksize, ByRef $anchor, $normalize, $borderType)
    ; cveSqrBoxFilter using cv::Mat instead of _*Array

    Local $iArr_src, $vectorOfMat_src, $iArr_srcSize
    Local $b_srcIsArray = VarGetType($mat_src) == "Array"

    If $b_srcIsArray Then
        $vectorOfMat_src = _VectorOfMatCreate()

        $iArr_srcSize = UBound($mat_src)
        For $i = 0 To $iArr_srcSize - 1
            _VectorOfMatPush($vectorOfMat_src, $mat_src[$i])
        Next

        $iArr_src = _cveInputArrayFromVectorOfMat($vectorOfMat_src)
    Else
        $iArr_src = _cveInputArrayFromMat($mat_src)
    EndIf

    Local $oArr_dst, $vectorOfMat_dst, $iArr_dstSize
    Local $b_dstIsArray = VarGetType($mat_dst) == "Array"

    If $b_dstIsArray Then
        $vectorOfMat_dst = _VectorOfMatCreate()

        $iArr_dstSize = UBound($mat_dst)
        For $i = 0 To $iArr_dstSize - 1
            _VectorOfMatPush($vectorOfMat_dst, $mat_dst[$i])
        Next

        $oArr_dst = _cveOutputArrayFromVectorOfMat($vectorOfMat_dst)
    Else
        $oArr_dst = _cveOutputArrayFromMat($mat_dst)
    EndIf

    _cveSqrBoxFilter($iArr_src, $oArr_dst, $ddepth, $ksize, $anchor, $normalize, $borderType)

    If $b_dstIsArray Then
        _VectorOfMatRelease($vectorOfMat_dst)
    EndIf

    _cveOutputArrayRelease($oArr_dst)

    If $b_srcIsArray Then
        _VectorOfMatRelease($vectorOfMat_src)
    EndIf

    _cveInputArrayRelease($iArr_src)
EndFunc   ;==>_cveSqrBoxFilterMat

Func _cveBilateralFilter(ByRef $src, ByRef $dst, $d, $sigmaColor, $sigmaSpace, $borderType)
    ; CVAPI(void) cveBilateralFilter(cv::_InputArray* src, cv::_OutputArray* dst, int d, double sigmaColor, double sigmaSpace, int borderType);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBilateralFilter", "ptr", $src, "ptr", $dst, "int", $d, "double", $sigmaColor, "double", $sigmaSpace, "int", $borderType), "cveBilateralFilter", @error)
EndFunc   ;==>_cveBilateralFilter

Func _cveBilateralFilterMat(ByRef $matSrc, ByRef $matDst, $d, $sigmaColor, $sigmaSpace, $borderType)
    ; cveBilateralFilter using cv::Mat instead of _*Array

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

    _cveBilateralFilter($iArrSrc, $oArrDst, $d, $sigmaColor, $sigmaSpace, $borderType)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveOutputArrayRelease($oArrDst)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)
EndFunc   ;==>_cveBilateralFilterMat

Func _cveSubdiv2DCreate(ByRef $rect)
    ; CVAPI(cv::Subdiv2D*) cveSubdiv2DCreate(CvRect* rect);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveSubdiv2DCreate", "struct*", $rect), "cveSubdiv2DCreate", @error)
EndFunc   ;==>_cveSubdiv2DCreate

Func _cveSubdiv2DRelease(ByRef $subdiv)
    ; CVAPI(void) cveSubdiv2DRelease(cv::Subdiv2D** subdiv);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSubdiv2DRelease", "ptr*", $subdiv), "cveSubdiv2DRelease", @error)
EndFunc   ;==>_cveSubdiv2DRelease

Func _cveSubdiv2DInsertMulti(ByRef $subdiv, ByRef $points)
    ; CVAPI(void) cveSubdiv2DInsertMulti(cv::Subdiv2D* subdiv, std::vector<cv::Point2f>* points);

    Local $vecPoints, $iArrPointsSize
    Local $bPointsIsArray = VarGetType($points) == "Array"

    If $bPointsIsArray Then
        $vecPoints = _VectorOfPointFCreate()

        $iArrPointsSize = UBound($points)
        For $i = 0 To $iArrPointsSize - 1
            _VectorOfPointFPush($vecPoints, $points[$i])
        Next
    Else
        $vecPoints = $points
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSubdiv2DInsertMulti", "ptr", $subdiv, "ptr", $vecPoints), "cveSubdiv2DInsertMulti", @error)

    If $bPointsIsArray Then
        _VectorOfPointFRelease($vecPoints)
    EndIf
EndFunc   ;==>_cveSubdiv2DInsertMulti

Func _cveSubdiv2DInsertSingle(ByRef $subdiv, ByRef $pt)
    ; CVAPI(int) cveSubdiv2DInsertSingle(cv::Subdiv2D* subdiv, CvPoint2D32f* pt);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveSubdiv2DInsertSingle", "ptr", $subdiv, "struct*", $pt), "cveSubdiv2DInsertSingle", @error)
EndFunc   ;==>_cveSubdiv2DInsertSingle

Func _cveSubdiv2DGetTriangleList(ByRef $subdiv, ByRef $triangleList)
    ; CVAPI(void) cveSubdiv2DGetTriangleList(cv::Subdiv2D* subdiv, std::vector<cv::Vec6f>* triangleList);

    Local $vecTriangleList, $iArrTriangleListSize
    Local $bTriangleListIsArray = VarGetType($triangleList) == "Array"

    If $bTriangleListIsArray Then
        $vecTriangleList = _VectorOfTriangle2DFCreate()

        $iArrTriangleListSize = UBound($triangleList)
        For $i = 0 To $iArrTriangleListSize - 1
            _VectorOfTriangle2DFPush($vecTriangleList, $triangleList[$i])
        Next
    Else
        $vecTriangleList = $triangleList
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSubdiv2DGetTriangleList", "ptr", $subdiv, "ptr", $vecTriangleList), "cveSubdiv2DGetTriangleList", @error)

    If $bTriangleListIsArray Then
        _VectorOfTriangle2DFRelease($vecTriangleList)
    EndIf
EndFunc   ;==>_cveSubdiv2DGetTriangleList

Func _cveSubdiv2DGetVoronoiFacetList(ByRef $subdiv, ByRef $idx, ByRef $facetList, ByRef $facetCenters)
    ; CVAPI(void) cveSubdiv2DGetVoronoiFacetList(cv::Subdiv2D* subdiv, std::vector<int>* idx, std::vector< std::vector< cv::Point2f> >* facetList, std::vector< cv::Point2f >* facetCenters);

    Local $vecIdx, $iArrIdxSize
    Local $bIdxIsArray = VarGetType($idx) == "Array"

    If $bIdxIsArray Then
        $vecIdx = _VectorOfIntCreate()

        $iArrIdxSize = UBound($idx)
        For $i = 0 To $iArrIdxSize - 1
            _VectorOfIntPush($vecIdx, $idx[$i])
        Next
    Else
        $vecIdx = $idx
    EndIf

    Local $vecFacetList, $iArrFacetListSize
    Local $bFacetListIsArray = VarGetType($facetList) == "Array"

    If $bFacetListIsArray Then
        $vecFacetList = _VectorOfVectorOfPointFCreate()

        $iArrFacetListSize = UBound($facetList)
        For $i = 0 To $iArrFacetListSize - 1
            _VectorOfVectorOfPointFPush($vecFacetList, $facetList[$i])
        Next
    Else
        $vecFacetList = $facetList
    EndIf

    Local $vecFacetCenters, $iArrFacetCentersSize
    Local $bFacetCentersIsArray = VarGetType($facetCenters) == "Array"

    If $bFacetCentersIsArray Then
        $vecFacetCenters = _VectorOfPointFCreate()

        $iArrFacetCentersSize = UBound($facetCenters)
        For $i = 0 To $iArrFacetCentersSize - 1
            _VectorOfPointFPush($vecFacetCenters, $facetCenters[$i])
        Next
    Else
        $vecFacetCenters = $facetCenters
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSubdiv2DGetVoronoiFacetList", "ptr", $subdiv, "ptr", $vecIdx, "ptr", $vecFacetList, "ptr", $vecFacetCenters), "cveSubdiv2DGetVoronoiFacetList", @error)

    If $bFacetCentersIsArray Then
        _VectorOfPointFRelease($vecFacetCenters)
    EndIf

    If $bFacetListIsArray Then
        _VectorOfVectorOfPointFRelease($vecFacetList)
    EndIf

    If $bIdxIsArray Then
        _VectorOfIntRelease($vecIdx)
    EndIf
EndFunc   ;==>_cveSubdiv2DGetVoronoiFacetList

Func _cveSubdiv2DFindNearest(ByRef $subdiv, ByRef $pt, ByRef $nearestPt)
    ; CVAPI(int) cveSubdiv2DFindNearest(cv::Subdiv2D* subdiv, CvPoint2D32f* pt, CvPoint2D32f* nearestPt);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveSubdiv2DFindNearest", "ptr", $subdiv, "struct*", $pt, "struct*", $nearestPt), "cveSubdiv2DFindNearest", @error)
EndFunc   ;==>_cveSubdiv2DFindNearest

Func _cveSubdiv2DLocate(ByRef $subdiv, ByRef $pt, ByRef $edge, ByRef $vertex)
    ; CVAPI(int) cveSubdiv2DLocate(cv::Subdiv2D* subdiv, CvPoint2D32f* pt, int* edge, int* vertex);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveSubdiv2DLocate", "ptr", $subdiv, "struct*", $pt, "struct*", $edge, "struct*", $vertex), "cveSubdiv2DLocate", @error)
EndFunc   ;==>_cveSubdiv2DLocate

Func _cveLineIteratorCreate(ByRef $img, ByRef $pt1, ByRef $pt2, $connectivity, $leftToRight)
    ; CVAPI(cv::LineIterator*) cveLineIteratorCreate(cv::Mat* img, CvPoint* pt1, CvPoint* pt2, int connectivity, bool leftToRight);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveLineIteratorCreate", "ptr", $img, "struct*", $pt1, "struct*", $pt2, "int", $connectivity, "boolean", $leftToRight), "cveLineIteratorCreate", @error)
EndFunc   ;==>_cveLineIteratorCreate

Func _cveLineIteratorGetDataPointer(ByRef $iterator)
    ; CVAPI(uchar*) cveLineIteratorGetDataPointer(cv::LineIterator* iterator);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveLineIteratorGetDataPointer", "ptr", $iterator), "cveLineIteratorGetDataPointer", @error)
EndFunc   ;==>_cveLineIteratorGetDataPointer

Func _cveLineIteratorPos(ByRef $iterator, ByRef $pos)
    ; CVAPI(void) cveLineIteratorPos(cv::LineIterator* iterator, CvPoint* pos);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveLineIteratorPos", "ptr", $iterator, "struct*", $pos), "cveLineIteratorPos", @error)
EndFunc   ;==>_cveLineIteratorPos

Func _cveLineIteratorMoveNext(ByRef $iterator)
    ; CVAPI(void) cveLineIteratorMoveNext(cv::LineIterator* iterator);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveLineIteratorMoveNext", "ptr", $iterator), "cveLineIteratorMoveNext", @error)
EndFunc   ;==>_cveLineIteratorMoveNext

Func _cveLineIteratorRelease(ByRef $iterator)
    ; CVAPI(void) cveLineIteratorRelease(cv::LineIterator** iterator);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveLineIteratorRelease", "ptr*", $iterator), "cveLineIteratorRelease", @error)
EndFunc   ;==>_cveLineIteratorRelease

Func _cveLineIteratorSampleLine(ByRef $img, ByRef $pt1, ByRef $pt2, $connectivity, $leftToRight, ByRef $result)
    ; CVAPI(void) cveLineIteratorSampleLine(cv::Mat* img, CvPoint* pt1, CvPoint* pt2, int connectivity, bool leftToRight, cv::Mat* result);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveLineIteratorSampleLine", "ptr", $img, "struct*", $pt1, "struct*", $pt2, "int", $connectivity, "boolean", $leftToRight, "ptr", $result), "cveLineIteratorSampleLine", @error)
EndFunc   ;==>_cveLineIteratorSampleLine

Func _cveLine(ByRef $img, ByRef $p1, ByRef $p2, ByRef $color, $thickness, $lineType, $shift)
    ; CVAPI(void) cveLine(cv::_InputOutputArray* img, CvPoint* p1, CvPoint* p2, CvScalar* color, int thickness, int lineType, int shift);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveLine", "ptr", $img, "struct*", $p1, "struct*", $p2, "struct*", $color, "int", $thickness, "int", $lineType, "int", $shift), "cveLine", @error)
EndFunc   ;==>_cveLine

Func _cveLineMat(ByRef $matImg, ByRef $p1, ByRef $p2, ByRef $color, $thickness, $lineType, $shift)
    ; cveLine using cv::Mat instead of _*Array

    Local $ioArrImg, $vectorOfMatImg, $iArrImgSize
    Local $bImgIsArray = VarGetType($matImg) == "Array"

    If $bImgIsArray Then
        $vectorOfMatImg = _VectorOfMatCreate()

        $iArrImgSize = UBound($matImg)
        For $i = 0 To $iArrImgSize - 1
            _VectorOfMatPush($vectorOfMatImg, $matImg[$i])
        Next

        $ioArrImg = _cveInputOutputArrayFromVectorOfMat($vectorOfMatImg)
    Else
        $ioArrImg = _cveInputOutputArrayFromMat($matImg)
    EndIf

    _cveLine($ioArrImg, $p1, $p2, $color, $thickness, $lineType, $shift)

    If $bImgIsArray Then
        _VectorOfMatRelease($vectorOfMatImg)
    EndIf

    _cveInputOutputArrayRelease($ioArrImg)
EndFunc   ;==>_cveLineMat

Func _cveArrowedLine(ByRef $img, ByRef $pt1, ByRef $pt2, ByRef $color, $thickness, $lineType, $shift, $tipLength)
    ; CVAPI(void) cveArrowedLine(cv::_InputOutputArray* img, CvPoint* pt1, CvPoint* pt2, CvScalar* color, int thickness, int lineType, int shift, double tipLength);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveArrowedLine", "ptr", $img, "struct*", $pt1, "struct*", $pt2, "struct*", $color, "int", $thickness, "int", $lineType, "int", $shift, "double", $tipLength), "cveArrowedLine", @error)
EndFunc   ;==>_cveArrowedLine

Func _cveArrowedLineMat(ByRef $matImg, ByRef $pt1, ByRef $pt2, ByRef $color, $thickness, $lineType, $shift, $tipLength)
    ; cveArrowedLine using cv::Mat instead of _*Array

    Local $ioArrImg, $vectorOfMatImg, $iArrImgSize
    Local $bImgIsArray = VarGetType($matImg) == "Array"

    If $bImgIsArray Then
        $vectorOfMatImg = _VectorOfMatCreate()

        $iArrImgSize = UBound($matImg)
        For $i = 0 To $iArrImgSize - 1
            _VectorOfMatPush($vectorOfMatImg, $matImg[$i])
        Next

        $ioArrImg = _cveInputOutputArrayFromVectorOfMat($vectorOfMatImg)
    Else
        $ioArrImg = _cveInputOutputArrayFromMat($matImg)
    EndIf

    _cveArrowedLine($ioArrImg, $pt1, $pt2, $color, $thickness, $lineType, $shift, $tipLength)

    If $bImgIsArray Then
        _VectorOfMatRelease($vectorOfMatImg)
    EndIf

    _cveInputOutputArrayRelease($ioArrImg)
EndFunc   ;==>_cveArrowedLineMat

Func _cveRectangle(ByRef $img, ByRef $rect, ByRef $color, $thickness, $lineType, $shift)
    ; CVAPI(void) cveRectangle(cv::_InputOutputArray* img, CvRect* rect, CvScalar* color, int thickness, int lineType, int shift);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveRectangle", "ptr", $img, "struct*", $rect, "struct*", $color, "int", $thickness, "int", $lineType, "int", $shift), "cveRectangle", @error)
EndFunc   ;==>_cveRectangle

Func _cveRectangleMat(ByRef $matImg, ByRef $rect, ByRef $color, $thickness, $lineType, $shift)
    ; cveRectangle using cv::Mat instead of _*Array

    Local $ioArrImg, $vectorOfMatImg, $iArrImgSize
    Local $bImgIsArray = VarGetType($matImg) == "Array"

    If $bImgIsArray Then
        $vectorOfMatImg = _VectorOfMatCreate()

        $iArrImgSize = UBound($matImg)
        For $i = 0 To $iArrImgSize - 1
            _VectorOfMatPush($vectorOfMatImg, $matImg[$i])
        Next

        $ioArrImg = _cveInputOutputArrayFromVectorOfMat($vectorOfMatImg)
    Else
        $ioArrImg = _cveInputOutputArrayFromMat($matImg)
    EndIf

    _cveRectangle($ioArrImg, $rect, $color, $thickness, $lineType, $shift)

    If $bImgIsArray Then
        _VectorOfMatRelease($vectorOfMatImg)
    EndIf

    _cveInputOutputArrayRelease($ioArrImg)
EndFunc   ;==>_cveRectangleMat

Func _cveCircle(ByRef $img, ByRef $center, $radius, ByRef $color, $thickness, $lineType, $shift)
    ; CVAPI(void) cveCircle(cv::_InputOutputArray* img, CvPoint* center, int radius, CvScalar* color, int thickness, int lineType, int shift);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCircle", "ptr", $img, "struct*", $center, "int", $radius, "struct*", $color, "int", $thickness, "int", $lineType, "int", $shift), "cveCircle", @error)
EndFunc   ;==>_cveCircle

Func _cveCircleMat(ByRef $matImg, ByRef $center, $radius, ByRef $color, $thickness, $lineType, $shift)
    ; cveCircle using cv::Mat instead of _*Array

    Local $ioArrImg, $vectorOfMatImg, $iArrImgSize
    Local $bImgIsArray = VarGetType($matImg) == "Array"

    If $bImgIsArray Then
        $vectorOfMatImg = _VectorOfMatCreate()

        $iArrImgSize = UBound($matImg)
        For $i = 0 To $iArrImgSize - 1
            _VectorOfMatPush($vectorOfMatImg, $matImg[$i])
        Next

        $ioArrImg = _cveInputOutputArrayFromVectorOfMat($vectorOfMatImg)
    Else
        $ioArrImg = _cveInputOutputArrayFromMat($matImg)
    EndIf

    _cveCircle($ioArrImg, $center, $radius, $color, $thickness, $lineType, $shift)

    If $bImgIsArray Then
        _VectorOfMatRelease($vectorOfMatImg)
    EndIf

    _cveInputOutputArrayRelease($ioArrImg)
EndFunc   ;==>_cveCircleMat

Func _cvePutText(ByRef $img, $text, ByRef $org, $fontFace, $fontScale, ByRef $color, $thickness, $lineType, $bottomLeftOrigin)
    ; CVAPI(void) cvePutText(cv::_InputOutputArray* img, cv::String* text, CvPoint* org, int fontFace, double fontScale, CvScalar* color, int thickness, int lineType, bool bottomLeftOrigin);

    Local $bTextIsString = VarGetType($text) == "String"
    If $bTextIsString Then
        $text = _cveStringCreateFromStr($text)
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cvePutText", "ptr", $img, "ptr", $text, "struct*", $org, "int", $fontFace, "double", $fontScale, "struct*", $color, "int", $thickness, "int", $lineType, "boolean", $bottomLeftOrigin), "cvePutText", @error)

    If $bTextIsString Then
        _cveStringRelease($text)
    EndIf
EndFunc   ;==>_cvePutText

Func _cvePutTextMat(ByRef $matImg, $text, ByRef $org, $fontFace, $fontScale, ByRef $color, $thickness, $lineType, $bottomLeftOrigin)
    ; cvePutText using cv::Mat instead of _*Array

    Local $ioArrImg, $vectorOfMatImg, $iArrImgSize
    Local $bImgIsArray = VarGetType($matImg) == "Array"

    If $bImgIsArray Then
        $vectorOfMatImg = _VectorOfMatCreate()

        $iArrImgSize = UBound($matImg)
        For $i = 0 To $iArrImgSize - 1
            _VectorOfMatPush($vectorOfMatImg, $matImg[$i])
        Next

        $ioArrImg = _cveInputOutputArrayFromVectorOfMat($vectorOfMatImg)
    Else
        $ioArrImg = _cveInputOutputArrayFromMat($matImg)
    EndIf

    _cvePutText($ioArrImg, $text, $org, $fontFace, $fontScale, $color, $thickness, $lineType, $bottomLeftOrigin)

    If $bImgIsArray Then
        _VectorOfMatRelease($vectorOfMatImg)
    EndIf

    _cveInputOutputArrayRelease($ioArrImg)
EndFunc   ;==>_cvePutTextMat

Func _cveGetTextSize($text, $fontFace, $fontScale, $thickness, ByRef $baseLine, ByRef $size)
    ; CVAPI(void) cveGetTextSize(cv::String* text, int fontFace, double fontScale, int thickness, int* baseLine, CvSize* size);

    Local $bTextIsString = VarGetType($text) == "String"
    If $bTextIsString Then
        $text = _cveStringCreateFromStr($text)
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveGetTextSize", "ptr", $text, "int", $fontFace, "double", $fontScale, "int", $thickness, "struct*", $baseLine, "struct*", $size), "cveGetTextSize", @error)

    If $bTextIsString Then
        _cveStringRelease($text)
    EndIf
EndFunc   ;==>_cveGetTextSize

Func _cveFillConvexPoly(ByRef $img, ByRef $points, $color, $lineType, $shift)
    ; CVAPI(void) cveFillConvexPoly(cv::_InputOutputArray* img, cv::_InputArray* points, const CvScalar* color, int lineType, int shift);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFillConvexPoly", "ptr", $img, "ptr", $points, "ptr", $color, "int", $lineType, "int", $shift), "cveFillConvexPoly", @error)
EndFunc   ;==>_cveFillConvexPoly

Func _cveFillConvexPolyMat(ByRef $matImg, ByRef $matPoints, $color, $lineType, $shift)
    ; cveFillConvexPoly using cv::Mat instead of _*Array

    Local $ioArrImg, $vectorOfMatImg, $iArrImgSize
    Local $bImgIsArray = VarGetType($matImg) == "Array"

    If $bImgIsArray Then
        $vectorOfMatImg = _VectorOfMatCreate()

        $iArrImgSize = UBound($matImg)
        For $i = 0 To $iArrImgSize - 1
            _VectorOfMatPush($vectorOfMatImg, $matImg[$i])
        Next

        $ioArrImg = _cveInputOutputArrayFromVectorOfMat($vectorOfMatImg)
    Else
        $ioArrImg = _cveInputOutputArrayFromMat($matImg)
    EndIf

    Local $iArrPoints, $vectorOfMatPoints, $iArrPointsSize
    Local $bPointsIsArray = VarGetType($matPoints) == "Array"

    If $bPointsIsArray Then
        $vectorOfMatPoints = _VectorOfMatCreate()

        $iArrPointsSize = UBound($matPoints)
        For $i = 0 To $iArrPointsSize - 1
            _VectorOfMatPush($vectorOfMatPoints, $matPoints[$i])
        Next

        $iArrPoints = _cveInputArrayFromVectorOfMat($vectorOfMatPoints)
    Else
        $iArrPoints = _cveInputArrayFromMat($matPoints)
    EndIf

    _cveFillConvexPoly($ioArrImg, $iArrPoints, $color, $lineType, $shift)

    If $bPointsIsArray Then
        _VectorOfMatRelease($vectorOfMatPoints)
    EndIf

    _cveInputArrayRelease($iArrPoints)

    If $bImgIsArray Then
        _VectorOfMatRelease($vectorOfMatImg)
    EndIf

    _cveInputOutputArrayRelease($ioArrImg)
EndFunc   ;==>_cveFillConvexPolyMat

Func _cveFillPoly(ByRef $img, ByRef $pts, $color, $lineType, $shift, ByRef $offset)
    ; CVAPI(void) cveFillPoly(cv::_InputOutputArray* img, cv::_InputArray* pts, const CvScalar* color, int lineType, int shift, CvPoint* offset);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFillPoly", "ptr", $img, "ptr", $pts, "ptr", $color, "int", $lineType, "int", $shift, "struct*", $offset), "cveFillPoly", @error)
EndFunc   ;==>_cveFillPoly

Func _cveFillPolyMat(ByRef $matImg, ByRef $matPts, $color, $lineType, $shift, ByRef $offset)
    ; cveFillPoly using cv::Mat instead of _*Array

    Local $ioArrImg, $vectorOfMatImg, $iArrImgSize
    Local $bImgIsArray = VarGetType($matImg) == "Array"

    If $bImgIsArray Then
        $vectorOfMatImg = _VectorOfMatCreate()

        $iArrImgSize = UBound($matImg)
        For $i = 0 To $iArrImgSize - 1
            _VectorOfMatPush($vectorOfMatImg, $matImg[$i])
        Next

        $ioArrImg = _cveInputOutputArrayFromVectorOfMat($vectorOfMatImg)
    Else
        $ioArrImg = _cveInputOutputArrayFromMat($matImg)
    EndIf

    Local $iArrPts, $vectorOfMatPts, $iArrPtsSize
    Local $bPtsIsArray = VarGetType($matPts) == "Array"

    If $bPtsIsArray Then
        $vectorOfMatPts = _VectorOfMatCreate()

        $iArrPtsSize = UBound($matPts)
        For $i = 0 To $iArrPtsSize - 1
            _VectorOfMatPush($vectorOfMatPts, $matPts[$i])
        Next

        $iArrPts = _cveInputArrayFromVectorOfMat($vectorOfMatPts)
    Else
        $iArrPts = _cveInputArrayFromMat($matPts)
    EndIf

    _cveFillPoly($ioArrImg, $iArrPts, $color, $lineType, $shift, $offset)

    If $bPtsIsArray Then
        _VectorOfMatRelease($vectorOfMatPts)
    EndIf

    _cveInputArrayRelease($iArrPts)

    If $bImgIsArray Then
        _VectorOfMatRelease($vectorOfMatImg)
    EndIf

    _cveInputOutputArrayRelease($ioArrImg)
EndFunc   ;==>_cveFillPolyMat

Func _cvePolylines(ByRef $img, ByRef $pts, $isClosed, $color, $thickness, $lineType, $shift)
    ; CVAPI(void) cvePolylines(cv::_InputOutputArray* img, cv::_InputArray* pts, bool isClosed, const CvScalar* color, int thickness, int lineType, int shift);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cvePolylines", "ptr", $img, "ptr", $pts, "boolean", $isClosed, "ptr", $color, "int", $thickness, "int", $lineType, "int", $shift), "cvePolylines", @error)
EndFunc   ;==>_cvePolylines

Func _cvePolylinesMat(ByRef $matImg, ByRef $matPts, $isClosed, $color, $thickness, $lineType, $shift)
    ; cvePolylines using cv::Mat instead of _*Array

    Local $ioArrImg, $vectorOfMatImg, $iArrImgSize
    Local $bImgIsArray = VarGetType($matImg) == "Array"

    If $bImgIsArray Then
        $vectorOfMatImg = _VectorOfMatCreate()

        $iArrImgSize = UBound($matImg)
        For $i = 0 To $iArrImgSize - 1
            _VectorOfMatPush($vectorOfMatImg, $matImg[$i])
        Next

        $ioArrImg = _cveInputOutputArrayFromVectorOfMat($vectorOfMatImg)
    Else
        $ioArrImg = _cveInputOutputArrayFromMat($matImg)
    EndIf

    Local $iArrPts, $vectorOfMatPts, $iArrPtsSize
    Local $bPtsIsArray = VarGetType($matPts) == "Array"

    If $bPtsIsArray Then
        $vectorOfMatPts = _VectorOfMatCreate()

        $iArrPtsSize = UBound($matPts)
        For $i = 0 To $iArrPtsSize - 1
            _VectorOfMatPush($vectorOfMatPts, $matPts[$i])
        Next

        $iArrPts = _cveInputArrayFromVectorOfMat($vectorOfMatPts)
    Else
        $iArrPts = _cveInputArrayFromMat($matPts)
    EndIf

    _cvePolylines($ioArrImg, $iArrPts, $isClosed, $color, $thickness, $lineType, $shift)

    If $bPtsIsArray Then
        _VectorOfMatRelease($vectorOfMatPts)
    EndIf

    _cveInputArrayRelease($iArrPts)

    If $bImgIsArray Then
        _VectorOfMatRelease($vectorOfMatImg)
    EndIf

    _cveInputOutputArrayRelease($ioArrImg)
EndFunc   ;==>_cvePolylinesMat

Func _cveEllipse(ByRef $img, ByRef $center, ByRef $axes, $angle, $startAngle, $endAngle, $color, $thickness, $lineType, $shift)
    ; CVAPI(void) cveEllipse(cv::_InputOutputArray* img, CvPoint* center, CvSize* axes, double angle, double startAngle, double endAngle, const CvScalar* color, int thickness, int lineType, int shift);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveEllipse", "ptr", $img, "struct*", $center, "struct*", $axes, "double", $angle, "double", $startAngle, "double", $endAngle, "ptr", $color, "int", $thickness, "int", $lineType, "int", $shift), "cveEllipse", @error)
EndFunc   ;==>_cveEllipse

Func _cveEllipseMat(ByRef $matImg, ByRef $center, ByRef $axes, $angle, $startAngle, $endAngle, $color, $thickness, $lineType, $shift)
    ; cveEllipse using cv::Mat instead of _*Array

    Local $ioArrImg, $vectorOfMatImg, $iArrImgSize
    Local $bImgIsArray = VarGetType($matImg) == "Array"

    If $bImgIsArray Then
        $vectorOfMatImg = _VectorOfMatCreate()

        $iArrImgSize = UBound($matImg)
        For $i = 0 To $iArrImgSize - 1
            _VectorOfMatPush($vectorOfMatImg, $matImg[$i])
        Next

        $ioArrImg = _cveInputOutputArrayFromVectorOfMat($vectorOfMatImg)
    Else
        $ioArrImg = _cveInputOutputArrayFromMat($matImg)
    EndIf

    _cveEllipse($ioArrImg, $center, $axes, $angle, $startAngle, $endAngle, $color, $thickness, $lineType, $shift)

    If $bImgIsArray Then
        _VectorOfMatRelease($vectorOfMatImg)
    EndIf

    _cveInputOutputArrayRelease($ioArrImg)
EndFunc   ;==>_cveEllipseMat

Func _cveDrawMarker(ByRef $img, ByRef $position, ByRef $color, $markerType, $markerSize, $thickness, $lineType)
    ; CVAPI(void) cveDrawMarker(cv::_InputOutputArray* img, CvPoint* position, CvScalar* color, int markerType, int markerSize, int thickness, int lineType);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDrawMarker", "ptr", $img, "struct*", $position, "struct*", $color, "int", $markerType, "int", $markerSize, "int", $thickness, "int", $lineType), "cveDrawMarker", @error)
EndFunc   ;==>_cveDrawMarker

Func _cveDrawMarkerMat(ByRef $matImg, ByRef $position, ByRef $color, $markerType, $markerSize, $thickness, $lineType)
    ; cveDrawMarker using cv::Mat instead of _*Array

    Local $ioArrImg, $vectorOfMatImg, $iArrImgSize
    Local $bImgIsArray = VarGetType($matImg) == "Array"

    If $bImgIsArray Then
        $vectorOfMatImg = _VectorOfMatCreate()

        $iArrImgSize = UBound($matImg)
        For $i = 0 To $iArrImgSize - 1
            _VectorOfMatPush($vectorOfMatImg, $matImg[$i])
        Next

        $ioArrImg = _cveInputOutputArrayFromVectorOfMat($vectorOfMatImg)
    Else
        $ioArrImg = _cveInputOutputArrayFromMat($matImg)
    EndIf

    _cveDrawMarker($ioArrImg, $position, $color, $markerType, $markerSize, $thickness, $lineType)

    If $bImgIsArray Then
        _VectorOfMatRelease($vectorOfMatImg)
    EndIf

    _cveInputOutputArrayRelease($ioArrImg)
EndFunc   ;==>_cveDrawMarkerMat

Func _cveApplyColorMap1(ByRef $src, ByRef $dst, $colorMap)
    ; CVAPI(void) cveApplyColorMap1(cv::_InputArray* src, cv::_OutputArray* dst, int colorMap);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveApplyColorMap1", "ptr", $src, "ptr", $dst, "int", $colorMap), "cveApplyColorMap1", @error)
EndFunc   ;==>_cveApplyColorMap1

Func _cveApplyColorMap1Mat(ByRef $matSrc, ByRef $matDst, $colorMap)
    ; cveApplyColorMap1 using cv::Mat instead of _*Array

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

    _cveApplyColorMap1($iArrSrc, $oArrDst, $colorMap)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveOutputArrayRelease($oArrDst)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)
EndFunc   ;==>_cveApplyColorMap1Mat

Func _cveApplyColorMap2(ByRef $src, ByRef $dst, $userColorMap)
    ; CVAPI(void) cveApplyColorMap2(cv::_InputArray* src, cv::_OutputArray* dst, cv::_InputArray userColorMap);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveApplyColorMap2", "ptr", $src, "ptr", $dst, "cv::_InputArray", $userColorMap), "cveApplyColorMap2", @error)
EndFunc   ;==>_cveApplyColorMap2

Func _cveApplyColorMap2Mat(ByRef $matSrc, ByRef $matDst, $userColorMap)
    ; cveApplyColorMap2 using cv::Mat instead of _*Array

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

    _cveApplyColorMap2($iArrSrc, $oArrDst, $userColorMap)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveOutputArrayRelease($oArrDst)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)
EndFunc   ;==>_cveApplyColorMap2Mat

Func _cveDistanceTransform(ByRef $src, ByRef $dst, ByRef $labels, $distanceType, $maskSize, $labelType)
    ; CVAPI(void) cveDistanceTransform(cv::_InputArray* src, cv::_OutputArray* dst, cv::_OutputArray* labels, int distanceType, int maskSize, int labelType);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDistanceTransform", "ptr", $src, "ptr", $dst, "ptr", $labels, "int", $distanceType, "int", $maskSize, "int", $labelType), "cveDistanceTransform", @error)
EndFunc   ;==>_cveDistanceTransform

Func _cveDistanceTransformMat(ByRef $matSrc, ByRef $matDst, ByRef $matLabels, $distanceType, $maskSize, $labelType)
    ; cveDistanceTransform using cv::Mat instead of _*Array

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

    Local $oArrLabels, $vectorOfMatLabels, $iArrLabelsSize
    Local $bLabelsIsArray = VarGetType($matLabels) == "Array"

    If $bLabelsIsArray Then
        $vectorOfMatLabels = _VectorOfMatCreate()

        $iArrLabelsSize = UBound($matLabels)
        For $i = 0 To $iArrLabelsSize - 1
            _VectorOfMatPush($vectorOfMatLabels, $matLabels[$i])
        Next

        $oArrLabels = _cveOutputArrayFromVectorOfMat($vectorOfMatLabels)
    Else
        $oArrLabels = _cveOutputArrayFromMat($matLabels)
    EndIf

    _cveDistanceTransform($iArrSrc, $oArrDst, $oArrLabels, $distanceType, $maskSize, $labelType)

    If $bLabelsIsArray Then
        _VectorOfMatRelease($vectorOfMatLabels)
    EndIf

    _cveOutputArrayRelease($oArrLabels)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveOutputArrayRelease($oArrDst)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)
EndFunc   ;==>_cveDistanceTransformMat

Func _cveGetRectSubPix(ByRef $image, ByRef $patchSize, ByRef $center, ByRef $patch, $patchType)
    ; CVAPI(void) cveGetRectSubPix(cv::_InputArray* image, CvSize* patchSize, CvPoint2D32f* center, cv::_OutputArray* patch, int patchType);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveGetRectSubPix", "ptr", $image, "struct*", $patchSize, "struct*", $center, "ptr", $patch, "int", $patchType), "cveGetRectSubPix", @error)
EndFunc   ;==>_cveGetRectSubPix

Func _cveGetRectSubPixMat(ByRef $matImage, ByRef $patchSize, ByRef $center, ByRef $matPatch, $patchType)
    ; cveGetRectSubPix using cv::Mat instead of _*Array

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

    Local $oArrPatch, $vectorOfMatPatch, $iArrPatchSize
    Local $bPatchIsArray = VarGetType($matPatch) == "Array"

    If $bPatchIsArray Then
        $vectorOfMatPatch = _VectorOfMatCreate()

        $iArrPatchSize = UBound($matPatch)
        For $i = 0 To $iArrPatchSize - 1
            _VectorOfMatPush($vectorOfMatPatch, $matPatch[$i])
        Next

        $oArrPatch = _cveOutputArrayFromVectorOfMat($vectorOfMatPatch)
    Else
        $oArrPatch = _cveOutputArrayFromMat($matPatch)
    EndIf

    _cveGetRectSubPix($iArrImage, $patchSize, $center, $oArrPatch, $patchType)

    If $bPatchIsArray Then
        _VectorOfMatRelease($vectorOfMatPatch)
    EndIf

    _cveOutputArrayRelease($oArrPatch)

    If $bImageIsArray Then
        _VectorOfMatRelease($vectorOfMatImage)
    EndIf

    _cveInputArrayRelease($iArrImage)
EndFunc   ;==>_cveGetRectSubPixMat

Func _cveHuMoments(ByRef $moments, ByRef $hu)
    ; CVAPI(void) cveHuMoments(cv::Moments* moments, cv::_OutputArray* hu);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveHuMoments", "ptr", $moments, "ptr", $hu), "cveHuMoments", @error)
EndFunc   ;==>_cveHuMoments

Func _cveHuMomentsMat(ByRef $moments, ByRef $matHu)
    ; cveHuMoments using cv::Mat instead of _*Array

    Local $oArrHu, $vectorOfMatHu, $iArrHuSize
    Local $bHuIsArray = VarGetType($matHu) == "Array"

    If $bHuIsArray Then
        $vectorOfMatHu = _VectorOfMatCreate()

        $iArrHuSize = UBound($matHu)
        For $i = 0 To $iArrHuSize - 1
            _VectorOfMatPush($vectorOfMatHu, $matHu[$i])
        Next

        $oArrHu = _cveOutputArrayFromVectorOfMat($vectorOfMatHu)
    Else
        $oArrHu = _cveOutputArrayFromMat($matHu)
    EndIf

    _cveHuMoments($moments, $oArrHu)

    If $bHuIsArray Then
        _VectorOfMatRelease($vectorOfMatHu)
    EndIf

    _cveOutputArrayRelease($oArrHu)
EndFunc   ;==>_cveHuMomentsMat

Func _cveHuMoments2(ByRef $moments, ByRef $hu)
    ; CVAPI(void) cveHuMoments2(cv::Moments* moments, double* hu);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveHuMoments2", "ptr", $moments, "struct*", $hu), "cveHuMoments2", @error)
EndFunc   ;==>_cveHuMoments2

Func _cveMaxRect(ByRef $rect1, ByRef $rect2, ByRef $result)
    ; CVAPI(void) cveMaxRect(CvRect* rect1, CvRect* rect2, CvRect* result);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMaxRect", "struct*", $rect1, "struct*", $rect2, "struct*", $result), "cveMaxRect", @error)
EndFunc   ;==>_cveMaxRect

Func _cveConnectedComponents(ByRef $image, ByRef $labels, $connectivity, $ltype, $ccltype)
    ; CVAPI(int) cveConnectedComponents(cv::_InputArray* image, cv::_OutputArray* labels, int connectivity, int ltype, int ccltype);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveConnectedComponents", "ptr", $image, "ptr", $labels, "int", $connectivity, "int", $ltype, "int", $ccltype), "cveConnectedComponents", @error)
EndFunc   ;==>_cveConnectedComponents

Func _cveConnectedComponentsMat(ByRef $matImage, ByRef $matLabels, $connectivity, $ltype, $ccltype)
    ; cveConnectedComponents using cv::Mat instead of _*Array

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

    Local $oArrLabels, $vectorOfMatLabels, $iArrLabelsSize
    Local $bLabelsIsArray = VarGetType($matLabels) == "Array"

    If $bLabelsIsArray Then
        $vectorOfMatLabels = _VectorOfMatCreate()

        $iArrLabelsSize = UBound($matLabels)
        For $i = 0 To $iArrLabelsSize - 1
            _VectorOfMatPush($vectorOfMatLabels, $matLabels[$i])
        Next

        $oArrLabels = _cveOutputArrayFromVectorOfMat($vectorOfMatLabels)
    Else
        $oArrLabels = _cveOutputArrayFromMat($matLabels)
    EndIf

    Local $retval = _cveConnectedComponents($iArrImage, $oArrLabels, $connectivity, $ltype, $ccltype)

    If $bLabelsIsArray Then
        _VectorOfMatRelease($vectorOfMatLabels)
    EndIf

    _cveOutputArrayRelease($oArrLabels)

    If $bImageIsArray Then
        _VectorOfMatRelease($vectorOfMatImage)
    EndIf

    _cveInputArrayRelease($iArrImage)

    Return $retval
EndFunc   ;==>_cveConnectedComponentsMat

Func _cveConnectedComponentsWithStats(ByRef $image, ByRef $labels, ByRef $stats, ByRef $centroids, $connectivity, $ltype, $ccltype)
    ; CVAPI(int) cveConnectedComponentsWithStats(cv::_InputArray* image, cv::_OutputArray* labels, cv::_OutputArray* stats, cv::_OutputArray* centroids, int connectivity, int ltype, int ccltype);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveConnectedComponentsWithStats", "ptr", $image, "ptr", $labels, "ptr", $stats, "ptr", $centroids, "int", $connectivity, "int", $ltype, "int", $ccltype), "cveConnectedComponentsWithStats", @error)
EndFunc   ;==>_cveConnectedComponentsWithStats

Func _cveConnectedComponentsWithStatsMat(ByRef $matImage, ByRef $matLabels, ByRef $matStats, ByRef $matCentroids, $connectivity, $ltype, $ccltype)
    ; cveConnectedComponentsWithStats using cv::Mat instead of _*Array

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

    Local $oArrLabels, $vectorOfMatLabels, $iArrLabelsSize
    Local $bLabelsIsArray = VarGetType($matLabels) == "Array"

    If $bLabelsIsArray Then
        $vectorOfMatLabels = _VectorOfMatCreate()

        $iArrLabelsSize = UBound($matLabels)
        For $i = 0 To $iArrLabelsSize - 1
            _VectorOfMatPush($vectorOfMatLabels, $matLabels[$i])
        Next

        $oArrLabels = _cveOutputArrayFromVectorOfMat($vectorOfMatLabels)
    Else
        $oArrLabels = _cveOutputArrayFromMat($matLabels)
    EndIf

    Local $oArrStats, $vectorOfMatStats, $iArrStatsSize
    Local $bStatsIsArray = VarGetType($matStats) == "Array"

    If $bStatsIsArray Then
        $vectorOfMatStats = _VectorOfMatCreate()

        $iArrStatsSize = UBound($matStats)
        For $i = 0 To $iArrStatsSize - 1
            _VectorOfMatPush($vectorOfMatStats, $matStats[$i])
        Next

        $oArrStats = _cveOutputArrayFromVectorOfMat($vectorOfMatStats)
    Else
        $oArrStats = _cveOutputArrayFromMat($matStats)
    EndIf

    Local $oArrCentroids, $vectorOfMatCentroids, $iArrCentroidsSize
    Local $bCentroidsIsArray = VarGetType($matCentroids) == "Array"

    If $bCentroidsIsArray Then
        $vectorOfMatCentroids = _VectorOfMatCreate()

        $iArrCentroidsSize = UBound($matCentroids)
        For $i = 0 To $iArrCentroidsSize - 1
            _VectorOfMatPush($vectorOfMatCentroids, $matCentroids[$i])
        Next

        $oArrCentroids = _cveOutputArrayFromVectorOfMat($vectorOfMatCentroids)
    Else
        $oArrCentroids = _cveOutputArrayFromMat($matCentroids)
    EndIf

    Local $retval = _cveConnectedComponentsWithStats($iArrImage, $oArrLabels, $oArrStats, $oArrCentroids, $connectivity, $ltype, $ccltype)

    If $bCentroidsIsArray Then
        _VectorOfMatRelease($vectorOfMatCentroids)
    EndIf

    _cveOutputArrayRelease($oArrCentroids)

    If $bStatsIsArray Then
        _VectorOfMatRelease($vectorOfMatStats)
    EndIf

    _cveOutputArrayRelease($oArrStats)

    If $bLabelsIsArray Then
        _VectorOfMatRelease($vectorOfMatLabels)
    EndIf

    _cveOutputArrayRelease($oArrLabels)

    If $bImageIsArray Then
        _VectorOfMatRelease($vectorOfMatImage)
    EndIf

    _cveInputArrayRelease($iArrImage)

    Return $retval
EndFunc   ;==>_cveConnectedComponentsWithStatsMat

Func _cveIntelligentScissorsMBCreate()
    ; CVAPI(cv::segmentation::IntelligentScissorsMB*) cveIntelligentScissorsMBCreate();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveIntelligentScissorsMBCreate"), "cveIntelligentScissorsMBCreate", @error)
EndFunc   ;==>_cveIntelligentScissorsMBCreate

Func _cveIntelligentScissorsMBRelease(ByRef $ptr)
    ; CVAPI(void) cveIntelligentScissorsMBRelease(cv::segmentation::IntelligentScissorsMB** ptr);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveIntelligentScissorsMBRelease", "ptr*", $ptr), "cveIntelligentScissorsMBRelease", @error)
EndFunc   ;==>_cveIntelligentScissorsMBRelease

Func _cveIntelligentScissorsMBSetWeights(ByRef $ptr, $weightNonEdge, $weightGradientDirection, $weightGradientMagnitude)
    ; CVAPI(void) cveIntelligentScissorsMBSetWeights(cv::segmentation::IntelligentScissorsMB* ptr, float weightNonEdge, float weightGradientDirection, float weightGradientMagnitude);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveIntelligentScissorsMBSetWeights", "ptr", $ptr, "float", $weightNonEdge, "float", $weightGradientDirection, "float", $weightGradientMagnitude), "cveIntelligentScissorsMBSetWeights", @error)
EndFunc   ;==>_cveIntelligentScissorsMBSetWeights

Func _cveIntelligentScissorsMBSetEdgeFeatureCannyParameters(ByRef $ptr, $threshold1, $threshold2, $apertureSize, $L2gradient)
    ; CVAPI(void) cveIntelligentScissorsMBSetEdgeFeatureCannyParameters(cv::segmentation::IntelligentScissorsMB* ptr, double threshold1, double threshold2, int apertureSize, bool L2gradient);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveIntelligentScissorsMBSetEdgeFeatureCannyParameters", "ptr", $ptr, "double", $threshold1, "double", $threshold2, "int", $apertureSize, "boolean", $L2gradient), "cveIntelligentScissorsMBSetEdgeFeatureCannyParameters", @error)
EndFunc   ;==>_cveIntelligentScissorsMBSetEdgeFeatureCannyParameters

Func _cveIntelligentScissorsMBApplyImage(ByRef $ptr, ByRef $image)
    ; CVAPI(void) cveIntelligentScissorsMBApplyImage(cv::segmentation::IntelligentScissorsMB* ptr, cv::_InputArray* image);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveIntelligentScissorsMBApplyImage", "ptr", $ptr, "ptr", $image), "cveIntelligentScissorsMBApplyImage", @error)
EndFunc   ;==>_cveIntelligentScissorsMBApplyImage

Func _cveIntelligentScissorsMBApplyImageMat(ByRef $ptr, ByRef $matImage)
    ; cveIntelligentScissorsMBApplyImage using cv::Mat instead of _*Array

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

    _cveIntelligentScissorsMBApplyImage($ptr, $iArrImage)

    If $bImageIsArray Then
        _VectorOfMatRelease($vectorOfMatImage)
    EndIf

    _cveInputArrayRelease($iArrImage)
EndFunc   ;==>_cveIntelligentScissorsMBApplyImageMat

Func _cveIntelligentScissorsMBApplyImageFeatures(ByRef $ptr, ByRef $nonEdge, ByRef $gradientDirection, ByRef $gradientMagnitude, ByRef $image)
    ; CVAPI(void) cveIntelligentScissorsMBApplyImageFeatures(cv::segmentation::IntelligentScissorsMB* ptr, cv::_InputArray* nonEdge, cv::_InputArray* gradientDirection, cv::_InputArray* gradientMagnitude, cv::_InputArray* image);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveIntelligentScissorsMBApplyImageFeatures", "ptr", $ptr, "ptr", $nonEdge, "ptr", $gradientDirection, "ptr", $gradientMagnitude, "ptr", $image), "cveIntelligentScissorsMBApplyImageFeatures", @error)
EndFunc   ;==>_cveIntelligentScissorsMBApplyImageFeatures

Func _cveIntelligentScissorsMBApplyImageFeaturesMat(ByRef $ptr, ByRef $matNonEdge, ByRef $matGradientDirection, ByRef $matGradientMagnitude, ByRef $matImage)
    ; cveIntelligentScissorsMBApplyImageFeatures using cv::Mat instead of _*Array

    Local $iArrNonEdge, $vectorOfMatNonEdge, $iArrNonEdgeSize
    Local $bNonEdgeIsArray = VarGetType($matNonEdge) == "Array"

    If $bNonEdgeIsArray Then
        $vectorOfMatNonEdge = _VectorOfMatCreate()

        $iArrNonEdgeSize = UBound($matNonEdge)
        For $i = 0 To $iArrNonEdgeSize - 1
            _VectorOfMatPush($vectorOfMatNonEdge, $matNonEdge[$i])
        Next

        $iArrNonEdge = _cveInputArrayFromVectorOfMat($vectorOfMatNonEdge)
    Else
        $iArrNonEdge = _cveInputArrayFromMat($matNonEdge)
    EndIf

    Local $iArrGradientDirection, $vectorOfMatGradientDirection, $iArrGradientDirectionSize
    Local $bGradientDirectionIsArray = VarGetType($matGradientDirection) == "Array"

    If $bGradientDirectionIsArray Then
        $vectorOfMatGradientDirection = _VectorOfMatCreate()

        $iArrGradientDirectionSize = UBound($matGradientDirection)
        For $i = 0 To $iArrGradientDirectionSize - 1
            _VectorOfMatPush($vectorOfMatGradientDirection, $matGradientDirection[$i])
        Next

        $iArrGradientDirection = _cveInputArrayFromVectorOfMat($vectorOfMatGradientDirection)
    Else
        $iArrGradientDirection = _cveInputArrayFromMat($matGradientDirection)
    EndIf

    Local $iArrGradientMagnitude, $vectorOfMatGradientMagnitude, $iArrGradientMagnitudeSize
    Local $bGradientMagnitudeIsArray = VarGetType($matGradientMagnitude) == "Array"

    If $bGradientMagnitudeIsArray Then
        $vectorOfMatGradientMagnitude = _VectorOfMatCreate()

        $iArrGradientMagnitudeSize = UBound($matGradientMagnitude)
        For $i = 0 To $iArrGradientMagnitudeSize - 1
            _VectorOfMatPush($vectorOfMatGradientMagnitude, $matGradientMagnitude[$i])
        Next

        $iArrGradientMagnitude = _cveInputArrayFromVectorOfMat($vectorOfMatGradientMagnitude)
    Else
        $iArrGradientMagnitude = _cveInputArrayFromMat($matGradientMagnitude)
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

    _cveIntelligentScissorsMBApplyImageFeatures($ptr, $iArrNonEdge, $iArrGradientDirection, $iArrGradientMagnitude, $iArrImage)

    If $bImageIsArray Then
        _VectorOfMatRelease($vectorOfMatImage)
    EndIf

    _cveInputArrayRelease($iArrImage)

    If $bGradientMagnitudeIsArray Then
        _VectorOfMatRelease($vectorOfMatGradientMagnitude)
    EndIf

    _cveInputArrayRelease($iArrGradientMagnitude)

    If $bGradientDirectionIsArray Then
        _VectorOfMatRelease($vectorOfMatGradientDirection)
    EndIf

    _cveInputArrayRelease($iArrGradientDirection)

    If $bNonEdgeIsArray Then
        _VectorOfMatRelease($vectorOfMatNonEdge)
    EndIf

    _cveInputArrayRelease($iArrNonEdge)
EndFunc   ;==>_cveIntelligentScissorsMBApplyImageFeaturesMat

Func _cveIntelligentScissorsMBBuildMap(ByRef $ptr, ByRef $sourcePt)
    ; CVAPI(void) cveIntelligentScissorsMBBuildMap(cv::segmentation::IntelligentScissorsMB* ptr, CvPoint* sourcePt);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveIntelligentScissorsMBBuildMap", "ptr", $ptr, "struct*", $sourcePt), "cveIntelligentScissorsMBBuildMap", @error)
EndFunc   ;==>_cveIntelligentScissorsMBBuildMap

Func _cveIntelligentScissorsMBGetContour(ByRef $ptr, ByRef $targetPt, ByRef $contour, $backward)
    ; CVAPI(void) cveIntelligentScissorsMBGetContour(cv::segmentation::IntelligentScissorsMB* ptr, CvPoint* targetPt, cv::_OutputArray* contour, bool backward);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveIntelligentScissorsMBGetContour", "ptr", $ptr, "struct*", $targetPt, "ptr", $contour, "boolean", $backward), "cveIntelligentScissorsMBGetContour", @error)
EndFunc   ;==>_cveIntelligentScissorsMBGetContour

Func _cveIntelligentScissorsMBGetContourMat(ByRef $ptr, ByRef $targetPt, ByRef $matContour, $backward)
    ; cveIntelligentScissorsMBGetContour using cv::Mat instead of _*Array

    Local $oArrContour, $vectorOfMatContour, $iArrContourSize
    Local $bContourIsArray = VarGetType($matContour) == "Array"

    If $bContourIsArray Then
        $vectorOfMatContour = _VectorOfMatCreate()

        $iArrContourSize = UBound($matContour)
        For $i = 0 To $iArrContourSize - 1
            _VectorOfMatPush($vectorOfMatContour, $matContour[$i])
        Next

        $oArrContour = _cveOutputArrayFromVectorOfMat($vectorOfMatContour)
    Else
        $oArrContour = _cveOutputArrayFromMat($matContour)
    EndIf

    _cveIntelligentScissorsMBGetContour($ptr, $targetPt, $oArrContour, $backward)

    If $bContourIsArray Then
        _VectorOfMatRelease($vectorOfMatContour)
    EndIf

    _cveOutputArrayRelease($oArrContour)
EndFunc   ;==>_cveIntelligentScissorsMBGetContourMat

Func _cveGetGaussianKernel($ksize, $sigma, $ktype, ByRef $result)
    ; CVAPI(void) cveGetGaussianKernel(int ksize, double sigma, int ktype, cv::Mat* result);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveGetGaussianKernel", "int", $ksize, "double", $sigma, "int", $ktype, "ptr", $result), "cveGetGaussianKernel", @error)
EndFunc   ;==>_cveGetGaussianKernel

Func _cveGetDerivKernels(ByRef $kx, ByRef $ky, $dx, $dy, $ksize, $normalize, $ktype)
    ; CVAPI(void) cveGetDerivKernels(cv::_OutputArray* kx, cv::_OutputArray* ky, int dx, int dy, int ksize, bool normalize, int ktype);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveGetDerivKernels", "ptr", $kx, "ptr", $ky, "int", $dx, "int", $dy, "int", $ksize, "boolean", $normalize, "int", $ktype), "cveGetDerivKernels", @error)
EndFunc   ;==>_cveGetDerivKernels

Func _cveGetDerivKernelsMat(ByRef $matKx, ByRef $matKy, $dx, $dy, $ksize, $normalize, $ktype)
    ; cveGetDerivKernels using cv::Mat instead of _*Array

    Local $oArrKx, $vectorOfMatKx, $iArrKxSize
    Local $bKxIsArray = VarGetType($matKx) == "Array"

    If $bKxIsArray Then
        $vectorOfMatKx = _VectorOfMatCreate()

        $iArrKxSize = UBound($matKx)
        For $i = 0 To $iArrKxSize - 1
            _VectorOfMatPush($vectorOfMatKx, $matKx[$i])
        Next

        $oArrKx = _cveOutputArrayFromVectorOfMat($vectorOfMatKx)
    Else
        $oArrKx = _cveOutputArrayFromMat($matKx)
    EndIf

    Local $oArrKy, $vectorOfMatKy, $iArrKySize
    Local $bKyIsArray = VarGetType($matKy) == "Array"

    If $bKyIsArray Then
        $vectorOfMatKy = _VectorOfMatCreate()

        $iArrKySize = UBound($matKy)
        For $i = 0 To $iArrKySize - 1
            _VectorOfMatPush($vectorOfMatKy, $matKy[$i])
        Next

        $oArrKy = _cveOutputArrayFromVectorOfMat($vectorOfMatKy)
    Else
        $oArrKy = _cveOutputArrayFromMat($matKy)
    EndIf

    _cveGetDerivKernels($oArrKx, $oArrKy, $dx, $dy, $ksize, $normalize, $ktype)

    If $bKyIsArray Then
        _VectorOfMatRelease($vectorOfMatKy)
    EndIf

    _cveOutputArrayRelease($oArrKy)

    If $bKxIsArray Then
        _VectorOfMatRelease($vectorOfMatKx)
    EndIf

    _cveOutputArrayRelease($oArrKx)
EndFunc   ;==>_cveGetDerivKernelsMat

Func _cveGetGaborKernel(ByRef $ksize, $sigma, $theta, $lambd, $gamma, $psi, $ktype, ByRef $result)
    ; CVAPI(void) cveGetGaborKernel(CvSize* ksize, double sigma, double theta, double lambd, double gamma, double psi, int ktype, cv::Mat* result);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveGetGaborKernel", "struct*", $ksize, "double", $sigma, "double", $theta, "double", $lambd, "double", $gamma, "double", $psi, "int", $ktype, "ptr", $result), "cveGetGaborKernel", @error)
EndFunc   ;==>_cveGetGaborKernel