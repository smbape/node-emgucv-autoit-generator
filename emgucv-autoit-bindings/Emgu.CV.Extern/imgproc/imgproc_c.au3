#include-once
#include "..\..\CVEUtils.au3"

Func _cvGetImageSubRect($image, $rect)
    ; CVAPI(IplImage*) cvGetImageSubRect(IplImage* image, CvRect* rect);

    Local $bImageDllType
    If VarGetType($image) == "DLLStruct" Then
        $bImageDllType = "struct*"
    Else
        $bImageDllType = "ptr"
    EndIf

    Local $bRectDllType
    If VarGetType($rect) == "DLLStruct" Then
        $bRectDllType = "struct*"
    Else
        $bRectDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cvGetImageSubRect", $bImageDllType, $image, $bRectDllType, $rect), "cvGetImageSubRect", @error)
EndFunc   ;==>_cvGetImageSubRect

Func _cveGrabCut($img, $mask, $rect, $bgdModel, $fgdModel, $iterCount, $flag)
    ; CVAPI(void) cveGrabCut(cv::_InputArray* img, cv::_InputOutputArray* mask, cv::Rect* rect, cv::_InputOutputArray* bgdModel, cv::_InputOutputArray* fgdModel, int iterCount, int flag);

    Local $bImgDllType
    If VarGetType($img) == "DLLStruct" Then
        $bImgDllType = "struct*"
    Else
        $bImgDllType = "ptr"
    EndIf

    Local $bMaskDllType
    If VarGetType($mask) == "DLLStruct" Then
        $bMaskDllType = "struct*"
    Else
        $bMaskDllType = "ptr"
    EndIf

    Local $bRectDllType
    If VarGetType($rect) == "DLLStruct" Then
        $bRectDllType = "struct*"
    Else
        $bRectDllType = "ptr"
    EndIf

    Local $bBgdModelDllType
    If VarGetType($bgdModel) == "DLLStruct" Then
        $bBgdModelDllType = "struct*"
    Else
        $bBgdModelDllType = "ptr"
    EndIf

    Local $bFgdModelDllType
    If VarGetType($fgdModel) == "DLLStruct" Then
        $bFgdModelDllType = "struct*"
    Else
        $bFgdModelDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveGrabCut", $bImgDllType, $img, $bMaskDllType, $mask, $bRectDllType, $rect, $bBgdModelDllType, $bgdModel, $bFgdModelDllType, $fgdModel, "int", $iterCount, "int", $flag), "cveGrabCut", @error)
EndFunc   ;==>_cveGrabCut

Func _cveGrabCutMat($matImg, $matMask, $rect, $matBgdModel, $matFgdModel, $iterCount, $flag)
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

Func _cveFilter2D($src, $dst, $kernel, $anchor = _cvPoint(-1,-1), $delta = 0, $borderType = $CV_BORDER_DEFAULT)
    ; CVAPI(void) cveFilter2D(cv::_InputArray* src, cv::_OutputArray* dst, cv::_InputArray* kernel, CvPoint* anchor, double delta, int borderType);

    Local $bSrcDllType
    If VarGetType($src) == "DLLStruct" Then
        $bSrcDllType = "struct*"
    Else
        $bSrcDllType = "ptr"
    EndIf

    Local $bDstDllType
    If VarGetType($dst) == "DLLStruct" Then
        $bDstDllType = "struct*"
    Else
        $bDstDllType = "ptr"
    EndIf

    Local $bKernelDllType
    If VarGetType($kernel) == "DLLStruct" Then
        $bKernelDllType = "struct*"
    Else
        $bKernelDllType = "ptr"
    EndIf

    Local $bAnchorDllType
    If VarGetType($anchor) == "DLLStruct" Then
        $bAnchorDllType = "struct*"
    Else
        $bAnchorDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFilter2D", $bSrcDllType, $src, $bDstDllType, $dst, $bKernelDllType, $kernel, $bAnchorDllType, $anchor, "double", $delta, "int", $borderType), "cveFilter2D", @error)
EndFunc   ;==>_cveFilter2D

Func _cveFilter2DMat($matSrc, $matDst, $matKernel, $anchor = _cvPoint(-1,-1), $delta = 0, $borderType = $CV_BORDER_DEFAULT)
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

Func _cveSepFilter2D($src, $dst, $ddepth, $kernelX, $kernelY, $anchor = _cvPoint(-1,-1), $delta = 0, $borderType = $CV_BORDER_DEFAULT)
    ; CVAPI(void) cveSepFilter2D(cv::_InputArray* src, cv::_OutputArray* dst, int ddepth, cv::_InputArray* kernelX, cv::_InputArray* kernelY, CvPoint* anchor, double delta, int borderType);

    Local $bSrcDllType
    If VarGetType($src) == "DLLStruct" Then
        $bSrcDllType = "struct*"
    Else
        $bSrcDllType = "ptr"
    EndIf

    Local $bDstDllType
    If VarGetType($dst) == "DLLStruct" Then
        $bDstDllType = "struct*"
    Else
        $bDstDllType = "ptr"
    EndIf

    Local $bKernelXDllType
    If VarGetType($kernelX) == "DLLStruct" Then
        $bKernelXDllType = "struct*"
    Else
        $bKernelXDllType = "ptr"
    EndIf

    Local $bKernelYDllType
    If VarGetType($kernelY) == "DLLStruct" Then
        $bKernelYDllType = "struct*"
    Else
        $bKernelYDllType = "ptr"
    EndIf

    Local $bAnchorDllType
    If VarGetType($anchor) == "DLLStruct" Then
        $bAnchorDllType = "struct*"
    Else
        $bAnchorDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSepFilter2D", $bSrcDllType, $src, $bDstDllType, $dst, "int", $ddepth, $bKernelXDllType, $kernelX, $bKernelYDllType, $kernelY, $bAnchorDllType, $anchor, "double", $delta, "int", $borderType), "cveSepFilter2D", @error)
EndFunc   ;==>_cveSepFilter2D

Func _cveSepFilter2DMat($matSrc, $matDst, $ddepth, $matKernelX, $matKernelY, $anchor = _cvPoint(-1,-1), $delta = 0, $borderType = $CV_BORDER_DEFAULT)
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

Func _cveBlendLinear($src1, $src2, $weights1, $weights2, $dst)
    ; CVAPI(void) cveBlendLinear(cv::_InputArray* src1, cv::_InputArray* src2, cv::_InputArray* weights1, cv::_InputArray* weights2, cv::_OutputArray* dst);

    Local $bSrc1DllType
    If VarGetType($src1) == "DLLStruct" Then
        $bSrc1DllType = "struct*"
    Else
        $bSrc1DllType = "ptr"
    EndIf

    Local $bSrc2DllType
    If VarGetType($src2) == "DLLStruct" Then
        $bSrc2DllType = "struct*"
    Else
        $bSrc2DllType = "ptr"
    EndIf

    Local $bWeights1DllType
    If VarGetType($weights1) == "DLLStruct" Then
        $bWeights1DllType = "struct*"
    Else
        $bWeights1DllType = "ptr"
    EndIf

    Local $bWeights2DllType
    If VarGetType($weights2) == "DLLStruct" Then
        $bWeights2DllType = "struct*"
    Else
        $bWeights2DllType = "ptr"
    EndIf

    Local $bDstDllType
    If VarGetType($dst) == "DLLStruct" Then
        $bDstDllType = "struct*"
    Else
        $bDstDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBlendLinear", $bSrc1DllType, $src1, $bSrc2DllType, $src2, $bWeights1DllType, $weights1, $bWeights2DllType, $weights2, $bDstDllType, $dst), "cveBlendLinear", @error)
EndFunc   ;==>_cveBlendLinear

Func _cveBlendLinearMat($matSrc1, $matSrc2, $matWeights1, $matWeights2, $matDst)
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

Func _cveCLAHE($src, $clipLimit, $tileGridSize, $dst)
    ; CVAPI(void) cveCLAHE(cv::_InputArray* src, double clipLimit, CvSize* tileGridSize, cv::_OutputArray* dst);

    Local $bSrcDllType
    If VarGetType($src) == "DLLStruct" Then
        $bSrcDllType = "struct*"
    Else
        $bSrcDllType = "ptr"
    EndIf

    Local $bTileGridSizeDllType
    If VarGetType($tileGridSize) == "DLLStruct" Then
        $bTileGridSizeDllType = "struct*"
    Else
        $bTileGridSizeDllType = "ptr"
    EndIf

    Local $bDstDllType
    If VarGetType($dst) == "DLLStruct" Then
        $bDstDllType = "struct*"
    Else
        $bDstDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCLAHE", $bSrcDllType, $src, "double", $clipLimit, $bTileGridSizeDllType, $tileGridSize, $bDstDllType, $dst), "cveCLAHE", @error)
EndFunc   ;==>_cveCLAHE

Func _cveCLAHEMat($matSrc, $clipLimit, $tileGridSize, $matDst)
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

Func _cveErode($src, $dst, $kernel, $anchor = _cvPoint(-1,-1), $iterations = 1, $borderType = $CV_BORDER_CONSTANT, $borderValue = _cveMorphologyDefaultBorderValue())
    ; CVAPI(void) cveErode(cv::_InputArray* src, cv::_OutputArray* dst, cv::_InputArray* kernel, CvPoint* anchor, int iterations, int borderType, CvScalar* borderValue);

    Local $bSrcDllType
    If VarGetType($src) == "DLLStruct" Then
        $bSrcDllType = "struct*"
    Else
        $bSrcDllType = "ptr"
    EndIf

    Local $bDstDllType
    If VarGetType($dst) == "DLLStruct" Then
        $bDstDllType = "struct*"
    Else
        $bDstDllType = "ptr"
    EndIf

    Local $bKernelDllType
    If VarGetType($kernel) == "DLLStruct" Then
        $bKernelDllType = "struct*"
    Else
        $bKernelDllType = "ptr"
    EndIf

    Local $bAnchorDllType
    If VarGetType($anchor) == "DLLStruct" Then
        $bAnchorDllType = "struct*"
    Else
        $bAnchorDllType = "ptr"
    EndIf

    Local $bBorderValueDllType
    If VarGetType($borderValue) == "DLLStruct" Then
        $bBorderValueDllType = "struct*"
    Else
        $bBorderValueDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveErode", $bSrcDllType, $src, $bDstDllType, $dst, $bKernelDllType, $kernel, $bAnchorDllType, $anchor, "int", $iterations, "int", $borderType, $bBorderValueDllType, $borderValue), "cveErode", @error)
EndFunc   ;==>_cveErode

Func _cveErodeMat($matSrc, $matDst, $matKernel, $anchor = _cvPoint(-1,-1), $iterations = 1, $borderType = $CV_BORDER_CONSTANT, $borderValue = _cveMorphologyDefaultBorderValue())
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

Func _cveDilate($src, $dst, $kernel, $anchor = _cvPoint(-1,-1), $iterations = 1, $borderType = $CV_BORDER_CONSTANT, $borderValue = _cveMorphologyDefaultBorderValue())
    ; CVAPI(void) cveDilate(cv::_InputArray* src, cv::_OutputArray* dst, cv::_InputArray* kernel, CvPoint* anchor, int iterations, int borderType, CvScalar* borderValue);

    Local $bSrcDllType
    If VarGetType($src) == "DLLStruct" Then
        $bSrcDllType = "struct*"
    Else
        $bSrcDllType = "ptr"
    EndIf

    Local $bDstDllType
    If VarGetType($dst) == "DLLStruct" Then
        $bDstDllType = "struct*"
    Else
        $bDstDllType = "ptr"
    EndIf

    Local $bKernelDllType
    If VarGetType($kernel) == "DLLStruct" Then
        $bKernelDllType = "struct*"
    Else
        $bKernelDllType = "ptr"
    EndIf

    Local $bAnchorDllType
    If VarGetType($anchor) == "DLLStruct" Then
        $bAnchorDllType = "struct*"
    Else
        $bAnchorDllType = "ptr"
    EndIf

    Local $bBorderValueDllType
    If VarGetType($borderValue) == "DLLStruct" Then
        $bBorderValueDllType = "struct*"
    Else
        $bBorderValueDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDilate", $bSrcDllType, $src, $bDstDllType, $dst, $bKernelDllType, $kernel, $bAnchorDllType, $anchor, "int", $iterations, "int", $borderType, $bBorderValueDllType, $borderValue), "cveDilate", @error)
EndFunc   ;==>_cveDilate

Func _cveDilateMat($matSrc, $matDst, $matKernel, $anchor = _cvPoint(-1,-1), $iterations = 1, $borderType = $CV_BORDER_CONSTANT, $borderValue = _cveMorphologyDefaultBorderValue())
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

Func _cveGetStructuringElement($mat, $shape, $ksize, $anchor = _cvPoint(-1,-1))
    ; CVAPI(void) cveGetStructuringElement(cv::Mat* mat, int shape, CvSize* ksize, CvPoint* anchor);

    Local $bMatDllType
    If VarGetType($mat) == "DLLStruct" Then
        $bMatDllType = "struct*"
    Else
        $bMatDllType = "ptr"
    EndIf

    Local $bKsizeDllType
    If VarGetType($ksize) == "DLLStruct" Then
        $bKsizeDllType = "struct*"
    Else
        $bKsizeDllType = "ptr"
    EndIf

    Local $bAnchorDllType
    If VarGetType($anchor) == "DLLStruct" Then
        $bAnchorDllType = "struct*"
    Else
        $bAnchorDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveGetStructuringElement", $bMatDllType, $mat, "int", $shape, $bKsizeDllType, $ksize, $bAnchorDllType, $anchor), "cveGetStructuringElement", @error)
EndFunc   ;==>_cveGetStructuringElement

Func _cveMorphologyEx($src, $dst, $op, $kernel, $anchor = _cvPoint(-1,-1), $iterations = 1, $borderType = $CV_BORDER_CONSTANT, $borderValue = _cveMorphologyDefaultBorderValue())
    ; CVAPI(void) cveMorphologyEx(cv::_InputArray* src, cv::_OutputArray* dst, int op, cv::_InputArray* kernel, CvPoint* anchor, int iterations, int borderType, CvScalar* borderValue);

    Local $bSrcDllType
    If VarGetType($src) == "DLLStruct" Then
        $bSrcDllType = "struct*"
    Else
        $bSrcDllType = "ptr"
    EndIf

    Local $bDstDllType
    If VarGetType($dst) == "DLLStruct" Then
        $bDstDllType = "struct*"
    Else
        $bDstDllType = "ptr"
    EndIf

    Local $bKernelDllType
    If VarGetType($kernel) == "DLLStruct" Then
        $bKernelDllType = "struct*"
    Else
        $bKernelDllType = "ptr"
    EndIf

    Local $bAnchorDllType
    If VarGetType($anchor) == "DLLStruct" Then
        $bAnchorDllType = "struct*"
    Else
        $bAnchorDllType = "ptr"
    EndIf

    Local $bBorderValueDllType
    If VarGetType($borderValue) == "DLLStruct" Then
        $bBorderValueDllType = "struct*"
    Else
        $bBorderValueDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMorphologyEx", $bSrcDllType, $src, $bDstDllType, $dst, "int", $op, $bKernelDllType, $kernel, $bAnchorDllType, $anchor, "int", $iterations, "int", $borderType, $bBorderValueDllType, $borderValue), "cveMorphologyEx", @error)
EndFunc   ;==>_cveMorphologyEx

Func _cveMorphologyExMat($matSrc, $matDst, $op, $matKernel, $anchor = _cvPoint(-1,-1), $iterations = 1, $borderType = $CV_BORDER_CONSTANT, $borderValue = _cveMorphologyDefaultBorderValue())
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

Func _cveSobel($src, $dst, $ddepth, $dx, $dy, $ksize = 3, $scale = 1, $delta = 0, $borderType = $CV_BORDER_DEFAULT)
    ; CVAPI(void) cveSobel(cv::_InputArray* src, cv::_OutputArray* dst, int ddepth, int dx, int dy, int ksize, double scale, double delta, int borderType);

    Local $bSrcDllType
    If VarGetType($src) == "DLLStruct" Then
        $bSrcDllType = "struct*"
    Else
        $bSrcDllType = "ptr"
    EndIf

    Local $bDstDllType
    If VarGetType($dst) == "DLLStruct" Then
        $bDstDllType = "struct*"
    Else
        $bDstDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSobel", $bSrcDllType, $src, $bDstDllType, $dst, "int", $ddepth, "int", $dx, "int", $dy, "int", $ksize, "double", $scale, "double", $delta, "int", $borderType), "cveSobel", @error)
EndFunc   ;==>_cveSobel

Func _cveSobelMat($matSrc, $matDst, $ddepth, $dx, $dy, $ksize = 3, $scale = 1, $delta = 0, $borderType = $CV_BORDER_DEFAULT)
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

Func _cveSpatialGradient($src, $dx, $dy, $ksize = 3, $borderType = $CV_BORDER_DEFAULT)
    ; CVAPI(void) cveSpatialGradient(cv::_InputArray* src, cv::_OutputArray* dx, cv::_OutputArray* dy, int ksize, int borderType);

    Local $bSrcDllType
    If VarGetType($src) == "DLLStruct" Then
        $bSrcDllType = "struct*"
    Else
        $bSrcDllType = "ptr"
    EndIf

    Local $bDxDllType
    If VarGetType($dx) == "DLLStruct" Then
        $bDxDllType = "struct*"
    Else
        $bDxDllType = "ptr"
    EndIf

    Local $bDyDllType
    If VarGetType($dy) == "DLLStruct" Then
        $bDyDllType = "struct*"
    Else
        $bDyDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSpatialGradient", $bSrcDllType, $src, $bDxDllType, $dx, $bDyDllType, $dy, "int", $ksize, "int", $borderType), "cveSpatialGradient", @error)
EndFunc   ;==>_cveSpatialGradient

Func _cveSpatialGradientMat($matSrc, $matDx, $matDy, $ksize = 3, $borderType = $CV_BORDER_DEFAULT)
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

Func _cveScharr($src, $dst, $ddepth, $dx, $dy, $scale = 1, $delta = 0, $borderType = $CV_BORDER_DEFAULT)
    ; CVAPI(void) cveScharr(cv::_InputArray* src, cv::_OutputArray* dst, int ddepth, int dx, int dy, double scale, double delta, int borderType);

    Local $bSrcDllType
    If VarGetType($src) == "DLLStruct" Then
        $bSrcDllType = "struct*"
    Else
        $bSrcDllType = "ptr"
    EndIf

    Local $bDstDllType
    If VarGetType($dst) == "DLLStruct" Then
        $bDstDllType = "struct*"
    Else
        $bDstDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveScharr", $bSrcDllType, $src, $bDstDllType, $dst, "int", $ddepth, "int", $dx, "int", $dy, "double", $scale, "double", $delta, "int", $borderType), "cveScharr", @error)
EndFunc   ;==>_cveScharr

Func _cveScharrMat($matSrc, $matDst, $ddepth, $dx, $dy, $scale = 1, $delta = 0, $borderType = $CV_BORDER_DEFAULT)
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

Func _cveLaplacian($src, $dst, $ddepth, $ksize = 1, $scale = 1, $delta = 0, $borderType = $CV_BORDER_DEFAULT)
    ; CVAPI(void) cveLaplacian(cv::_InputArray* src, cv::_OutputArray* dst, int ddepth, int ksize, double scale, double delta, int borderType);

    Local $bSrcDllType
    If VarGetType($src) == "DLLStruct" Then
        $bSrcDllType = "struct*"
    Else
        $bSrcDllType = "ptr"
    EndIf

    Local $bDstDllType
    If VarGetType($dst) == "DLLStruct" Then
        $bDstDllType = "struct*"
    Else
        $bDstDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveLaplacian", $bSrcDllType, $src, $bDstDllType, $dst, "int", $ddepth, "int", $ksize, "double", $scale, "double", $delta, "int", $borderType), "cveLaplacian", @error)
EndFunc   ;==>_cveLaplacian

Func _cveLaplacianMat($matSrc, $matDst, $ddepth, $ksize = 1, $scale = 1, $delta = 0, $borderType = $CV_BORDER_DEFAULT)
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

Func _cvePyrUp($src, $dst, $size, $borderType = $CV_BORDER_DEFAULT)
    ; CVAPI(void) cvePyrUp(cv::_InputArray* src, cv::_OutputArray* dst, CvSize* size, int borderType);

    Local $bSrcDllType
    If VarGetType($src) == "DLLStruct" Then
        $bSrcDllType = "struct*"
    Else
        $bSrcDllType = "ptr"
    EndIf

    Local $bDstDllType
    If VarGetType($dst) == "DLLStruct" Then
        $bDstDllType = "struct*"
    Else
        $bDstDllType = "ptr"
    EndIf

    Local $bSizeDllType
    If VarGetType($size) == "DLLStruct" Then
        $bSizeDllType = "struct*"
    Else
        $bSizeDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cvePyrUp", $bSrcDllType, $src, $bDstDllType, $dst, $bSizeDllType, $size, "int", $borderType), "cvePyrUp", @error)
EndFunc   ;==>_cvePyrUp

Func _cvePyrUpMat($matSrc, $matDst, $size, $borderType = $CV_BORDER_DEFAULT)
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

Func _cvePyrDown($src, $dst, $size, $borderType = $CV_BORDER_DEFAULT)
    ; CVAPI(void) cvePyrDown(cv::_InputArray* src, cv::_OutputArray* dst, CvSize* size, int borderType);

    Local $bSrcDllType
    If VarGetType($src) == "DLLStruct" Then
        $bSrcDllType = "struct*"
    Else
        $bSrcDllType = "ptr"
    EndIf

    Local $bDstDllType
    If VarGetType($dst) == "DLLStruct" Then
        $bDstDllType = "struct*"
    Else
        $bDstDllType = "ptr"
    EndIf

    Local $bSizeDllType
    If VarGetType($size) == "DLLStruct" Then
        $bSizeDllType = "struct*"
    Else
        $bSizeDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cvePyrDown", $bSrcDllType, $src, $bDstDllType, $dst, $bSizeDllType, $size, "int", $borderType), "cvePyrDown", @error)
EndFunc   ;==>_cvePyrDown

Func _cvePyrDownMat($matSrc, $matDst, $size, $borderType = $CV_BORDER_DEFAULT)
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

Func _cveBuildPyramid($src, $dst, $maxlevel, $borderType)
    ; CVAPI(void) cveBuildPyramid(cv::_InputArray* src, cv::_OutputArray* dst, int maxlevel, int borderType);

    Local $bSrcDllType
    If VarGetType($src) == "DLLStruct" Then
        $bSrcDllType = "struct*"
    Else
        $bSrcDllType = "ptr"
    EndIf

    Local $bDstDllType
    If VarGetType($dst) == "DLLStruct" Then
        $bDstDllType = "struct*"
    Else
        $bDstDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBuildPyramid", $bSrcDllType, $src, $bDstDllType, $dst, "int", $maxlevel, "int", $borderType), "cveBuildPyramid", @error)
EndFunc   ;==>_cveBuildPyramid

Func _cveBuildPyramidMat($matSrc, $matDst, $maxlevel, $borderType)
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

Func _cveCanny($image, $edges, $threshold1, $threshold2, $apertureSize = 3, $L2gradient = false)
    ; CVAPI(void) cveCanny(cv::_InputArray* image, cv::_OutputArray* edges, double threshold1, double threshold2, int apertureSize, bool L2gradient);

    Local $bImageDllType
    If VarGetType($image) == "DLLStruct" Then
        $bImageDllType = "struct*"
    Else
        $bImageDllType = "ptr"
    EndIf

    Local $bEdgesDllType
    If VarGetType($edges) == "DLLStruct" Then
        $bEdgesDllType = "struct*"
    Else
        $bEdgesDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCanny", $bImageDllType, $image, $bEdgesDllType, $edges, "double", $threshold1, "double", $threshold2, "int", $apertureSize, "boolean", $L2gradient), "cveCanny", @error)
EndFunc   ;==>_cveCanny

Func _cveCannyMat($matImage, $matEdges, $threshold1, $threshold2, $apertureSize = 3, $L2gradient = false)
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

Func _cveCanny2($dx, $dy, $edges, $threshold1, $threshold2, $L2gradient)
    ; CVAPI(void) cveCanny2(cv::_InputArray* dx, cv::_InputArray* dy, cv::_OutputArray* edges, double threshold1, double threshold2, bool L2gradient);

    Local $bDxDllType
    If VarGetType($dx) == "DLLStruct" Then
        $bDxDllType = "struct*"
    Else
        $bDxDllType = "ptr"
    EndIf

    Local $bDyDllType
    If VarGetType($dy) == "DLLStruct" Then
        $bDyDllType = "struct*"
    Else
        $bDyDllType = "ptr"
    EndIf

    Local $bEdgesDllType
    If VarGetType($edges) == "DLLStruct" Then
        $bEdgesDllType = "struct*"
    Else
        $bEdgesDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCanny2", $bDxDllType, $dx, $bDyDllType, $dy, $bEdgesDllType, $edges, "double", $threshold1, "double", $threshold2, "boolean", $L2gradient), "cveCanny2", @error)
EndFunc   ;==>_cveCanny2

Func _cveCanny2Mat($matDx, $matDy, $matEdges, $threshold1, $threshold2, $L2gradient)
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

Func _cveCornerHarris($src, $dst, $blockSize, $ksize, $k, $borderType = $CV_BORDER_DEFAULT)
    ; CVAPI(void) cveCornerHarris(cv::_InputArray* src, cv::_OutputArray* dst, int blockSize, int ksize, double k, int borderType);

    Local $bSrcDllType
    If VarGetType($src) == "DLLStruct" Then
        $bSrcDllType = "struct*"
    Else
        $bSrcDllType = "ptr"
    EndIf

    Local $bDstDllType
    If VarGetType($dst) == "DLLStruct" Then
        $bDstDllType = "struct*"
    Else
        $bDstDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCornerHarris", $bSrcDllType, $src, $bDstDllType, $dst, "int", $blockSize, "int", $ksize, "double", $k, "int", $borderType), "cveCornerHarris", @error)
EndFunc   ;==>_cveCornerHarris

Func _cveCornerHarrisMat($matSrc, $matDst, $blockSize, $ksize, $k, $borderType = $CV_BORDER_DEFAULT)
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

Func _cveThreshold($src, $dst, $thresh, $maxval, $type)
    ; CVAPI(double) cveThreshold(cv::_InputArray* src, cv::_OutputArray* dst, double thresh, double maxval, int type);

    Local $bSrcDllType
    If VarGetType($src) == "DLLStruct" Then
        $bSrcDllType = "struct*"
    Else
        $bSrcDllType = "ptr"
    EndIf

    Local $bDstDllType
    If VarGetType($dst) == "DLLStruct" Then
        $bDstDllType = "struct*"
    Else
        $bDstDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveThreshold", $bSrcDllType, $src, $bDstDllType, $dst, "double", $thresh, "double", $maxval, "int", $type), "cveThreshold", @error)
EndFunc   ;==>_cveThreshold

Func _cveThresholdMat($matSrc, $matDst, $thresh, $maxval, $type)
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

Func _cveWatershed($image, $markers)
    ; CVAPI(void) cveWatershed(cv::_InputArray* image, cv::_InputOutputArray* markers);

    Local $bImageDllType
    If VarGetType($image) == "DLLStruct" Then
        $bImageDllType = "struct*"
    Else
        $bImageDllType = "ptr"
    EndIf

    Local $bMarkersDllType
    If VarGetType($markers) == "DLLStruct" Then
        $bMarkersDllType = "struct*"
    Else
        $bMarkersDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveWatershed", $bImageDllType, $image, $bMarkersDllType, $markers), "cveWatershed", @error)
EndFunc   ;==>_cveWatershed

Func _cveWatershedMat($matImage, $matMarkers)
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

Func _cveAdaptiveThreshold($src, $dst, $maxValue, $adaptiveMethod, $thresholdType, $blockSize, $c)
    ; CVAPI(void) cveAdaptiveThreshold(cv::_InputArray* src, cv::_OutputArray* dst, double maxValue, int adaptiveMethod, int thresholdType, int blockSize, double c);

    Local $bSrcDllType
    If VarGetType($src) == "DLLStruct" Then
        $bSrcDllType = "struct*"
    Else
        $bSrcDllType = "ptr"
    EndIf

    Local $bDstDllType
    If VarGetType($dst) == "DLLStruct" Then
        $bDstDllType = "struct*"
    Else
        $bDstDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveAdaptiveThreshold", $bSrcDllType, $src, $bDstDllType, $dst, "double", $maxValue, "int", $adaptiveMethod, "int", $thresholdType, "int", $blockSize, "double", $c), "cveAdaptiveThreshold", @error)
EndFunc   ;==>_cveAdaptiveThreshold

Func _cveAdaptiveThresholdMat($matSrc, $matDst, $maxValue, $adaptiveMethod, $thresholdType, $blockSize, $c)
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

Func _cveCvtColor($src, $dst, $code, $dstCn = 0)
    ; CVAPI(void) cveCvtColor(cv::_InputArray* src, cv::_OutputArray* dst, int code, int dstCn);

    Local $bSrcDllType
    If VarGetType($src) == "DLLStruct" Then
        $bSrcDllType = "struct*"
    Else
        $bSrcDllType = "ptr"
    EndIf

    Local $bDstDllType
    If VarGetType($dst) == "DLLStruct" Then
        $bDstDllType = "struct*"
    Else
        $bDstDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCvtColor", $bSrcDllType, $src, $bDstDllType, $dst, "int", $code, "int", $dstCn), "cveCvtColor", @error)
EndFunc   ;==>_cveCvtColor

Func _cveCvtColorMat($matSrc, $matDst, $code, $dstCn = 0)
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

Func _cveCopyMakeBorder($src, $dst, $top, $bottom, $left, $right, $borderType, $value = _cvScalar())
    ; CVAPI(void) cveCopyMakeBorder(cv::_InputArray* src, cv::_OutputArray* dst, int top, int bottom, int left, int right, int borderType, CvScalar* value);

    Local $bSrcDllType
    If VarGetType($src) == "DLLStruct" Then
        $bSrcDllType = "struct*"
    Else
        $bSrcDllType = "ptr"
    EndIf

    Local $bDstDllType
    If VarGetType($dst) == "DLLStruct" Then
        $bDstDllType = "struct*"
    Else
        $bDstDllType = "ptr"
    EndIf

    Local $bValueDllType
    If VarGetType($value) == "DLLStruct" Then
        $bValueDllType = "struct*"
    Else
        $bValueDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCopyMakeBorder", $bSrcDllType, $src, $bDstDllType, $dst, "int", $top, "int", $bottom, "int", $left, "int", $right, "int", $borderType, $bValueDllType, $value), "cveCopyMakeBorder", @error)
EndFunc   ;==>_cveCopyMakeBorder

Func _cveCopyMakeBorderMat($matSrc, $matDst, $top, $bottom, $left, $right, $borderType, $value = _cvScalar())
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

Func _cveIntegral($src, $sum, $sqsum, $tilted, $sdepth, $sqdepth)
    ; CVAPI(void) cveIntegral(cv::_InputArray* src, cv::_OutputArray* sum, cv::_OutputArray* sqsum, cv::_OutputArray* tilted, int sdepth, int sqdepth);

    Local $bSrcDllType
    If VarGetType($src) == "DLLStruct" Then
        $bSrcDllType = "struct*"
    Else
        $bSrcDllType = "ptr"
    EndIf

    Local $bSumDllType
    If VarGetType($sum) == "DLLStruct" Then
        $bSumDllType = "struct*"
    Else
        $bSumDllType = "ptr"
    EndIf

    Local $bSqsumDllType
    If VarGetType($sqsum) == "DLLStruct" Then
        $bSqsumDllType = "struct*"
    Else
        $bSqsumDllType = "ptr"
    EndIf

    Local $bTiltedDllType
    If VarGetType($tilted) == "DLLStruct" Then
        $bTiltedDllType = "struct*"
    Else
        $bTiltedDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveIntegral", $bSrcDllType, $src, $bSumDllType, $sum, $bSqsumDllType, $sqsum, $bTiltedDllType, $tilted, "int", $sdepth, "int", $sqdepth), "cveIntegral", @error)
EndFunc   ;==>_cveIntegral

Func _cveIntegralMat($matSrc, $matSum, $matSqsum, $matTilted, $sdepth, $sqdepth)
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

Func _cveFloodFill($image, $mask, $seedPoint, $newVal, $rect = 0, $loDiff = _cvScalar(), $upDiff = _cvScalar(), $flags = 4)
    ; CVAPI(int) cveFloodFill(cv::_InputOutputArray* image, cv::_InputOutputArray* mask, CvPoint* seedPoint, CvScalar* newVal, CvRect* rect, CvScalar* loDiff, CvScalar* upDiff, int flags);

    Local $bImageDllType
    If VarGetType($image) == "DLLStruct" Then
        $bImageDllType = "struct*"
    Else
        $bImageDllType = "ptr"
    EndIf

    Local $bMaskDllType
    If VarGetType($mask) == "DLLStruct" Then
        $bMaskDllType = "struct*"
    Else
        $bMaskDllType = "ptr"
    EndIf

    Local $bSeedPointDllType
    If VarGetType($seedPoint) == "DLLStruct" Then
        $bSeedPointDllType = "struct*"
    Else
        $bSeedPointDllType = "ptr"
    EndIf

    Local $bNewValDllType
    If VarGetType($newVal) == "DLLStruct" Then
        $bNewValDllType = "struct*"
    Else
        $bNewValDllType = "ptr"
    EndIf

    Local $bRectDllType
    If VarGetType($rect) == "DLLStruct" Then
        $bRectDllType = "struct*"
    Else
        $bRectDllType = "ptr"
    EndIf

    Local $bLoDiffDllType
    If VarGetType($loDiff) == "DLLStruct" Then
        $bLoDiffDllType = "struct*"
    Else
        $bLoDiffDllType = "ptr"
    EndIf

    Local $bUpDiffDllType
    If VarGetType($upDiff) == "DLLStruct" Then
        $bUpDiffDllType = "struct*"
    Else
        $bUpDiffDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveFloodFill", $bImageDllType, $image, $bMaskDllType, $mask, $bSeedPointDllType, $seedPoint, $bNewValDllType, $newVal, $bRectDllType, $rect, $bLoDiffDllType, $loDiff, $bUpDiffDllType, $upDiff, "int", $flags), "cveFloodFill", @error)
EndFunc   ;==>_cveFloodFill

Func _cveFloodFillMat($matImage, $matMask, $seedPoint, $newVal, $rect = 0, $loDiff = _cvScalar(), $upDiff = _cvScalar(), $flags = 4)
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

Func _cvePyrMeanShiftFiltering($src, $dst, $sp, $sr, $maxLevel, $termCrit)
    ; CVAPI(void) cvePyrMeanShiftFiltering(cv::_InputArray* src, cv::_OutputArray* dst, double sp, double sr, int maxLevel, CvTermCriteria* termCrit);

    Local $bSrcDllType
    If VarGetType($src) == "DLLStruct" Then
        $bSrcDllType = "struct*"
    Else
        $bSrcDllType = "ptr"
    EndIf

    Local $bDstDllType
    If VarGetType($dst) == "DLLStruct" Then
        $bDstDllType = "struct*"
    Else
        $bDstDllType = "ptr"
    EndIf

    Local $bTermCritDllType
    If VarGetType($termCrit) == "DLLStruct" Then
        $bTermCritDllType = "struct*"
    Else
        $bTermCritDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cvePyrMeanShiftFiltering", $bSrcDllType, $src, $bDstDllType, $dst, "double", $sp, "double", $sr, "int", $maxLevel, $bTermCritDllType, $termCrit), "cvePyrMeanShiftFiltering", @error)
EndFunc   ;==>_cvePyrMeanShiftFiltering

Func _cvePyrMeanShiftFilteringMat($matSrc, $matDst, $sp, $sr, $maxLevel, $termCrit)
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

Func _cveMoments($arr, $binaryImage, $moments)
    ; CVAPI(void) cveMoments(cv::_InputArray* arr, bool binaryImage, cv::Moments* moments);

    Local $bArrDllType
    If VarGetType($arr) == "DLLStruct" Then
        $bArrDllType = "struct*"
    Else
        $bArrDllType = "ptr"
    EndIf

    Local $bMomentsDllType
    If VarGetType($moments) == "DLLStruct" Then
        $bMomentsDllType = "struct*"
    Else
        $bMomentsDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMoments", $bArrDllType, $arr, "boolean", $binaryImage, $bMomentsDllType, $moments), "cveMoments", @error)
EndFunc   ;==>_cveMoments

Func _cveMomentsMat($matArr, $binaryImage, $moments)
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

Func _cveEqualizeHist($src, $dst)
    ; CVAPI(void) cveEqualizeHist(cv::_InputArray* src, cv::_OutputArray* dst);

    Local $bSrcDllType
    If VarGetType($src) == "DLLStruct" Then
        $bSrcDllType = "struct*"
    Else
        $bSrcDllType = "ptr"
    EndIf

    Local $bDstDllType
    If VarGetType($dst) == "DLLStruct" Then
        $bDstDllType = "struct*"
    Else
        $bDstDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveEqualizeHist", $bSrcDllType, $src, $bDstDllType, $dst), "cveEqualizeHist", @error)
EndFunc   ;==>_cveEqualizeHist

Func _cveEqualizeHistMat($matSrc, $matDst)
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

Func _cveAccumulate($src, $dst, $mask = _cveNoArray())
    ; CVAPI(void) cveAccumulate(cv::_InputArray* src, cv::_InputOutputArray* dst, cv::_InputArray* mask);

    Local $bSrcDllType
    If VarGetType($src) == "DLLStruct" Then
        $bSrcDllType = "struct*"
    Else
        $bSrcDllType = "ptr"
    EndIf

    Local $bDstDllType
    If VarGetType($dst) == "DLLStruct" Then
        $bDstDllType = "struct*"
    Else
        $bDstDllType = "ptr"
    EndIf

    Local $bMaskDllType
    If VarGetType($mask) == "DLLStruct" Then
        $bMaskDllType = "struct*"
    Else
        $bMaskDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveAccumulate", $bSrcDllType, $src, $bDstDllType, $dst, $bMaskDllType, $mask), "cveAccumulate", @error)
EndFunc   ;==>_cveAccumulate

Func _cveAccumulateMat($matSrc, $matDst, $matMask = _cveNoArrayMat())
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

Func _cveAccumulateSquare($src, $dst, $mask = _cveNoArray())
    ; CVAPI(void) cveAccumulateSquare(cv::_InputArray* src, cv::_InputOutputArray* dst, cv::_InputArray* mask);

    Local $bSrcDllType
    If VarGetType($src) == "DLLStruct" Then
        $bSrcDllType = "struct*"
    Else
        $bSrcDllType = "ptr"
    EndIf

    Local $bDstDllType
    If VarGetType($dst) == "DLLStruct" Then
        $bDstDllType = "struct*"
    Else
        $bDstDllType = "ptr"
    EndIf

    Local $bMaskDllType
    If VarGetType($mask) == "DLLStruct" Then
        $bMaskDllType = "struct*"
    Else
        $bMaskDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveAccumulateSquare", $bSrcDllType, $src, $bDstDllType, $dst, $bMaskDllType, $mask), "cveAccumulateSquare", @error)
EndFunc   ;==>_cveAccumulateSquare

Func _cveAccumulateSquareMat($matSrc, $matDst, $matMask = _cveNoArrayMat())
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

Func _cveAccumulateProduct($src1, $src2, $dst, $mask = _cveNoArray())
    ; CVAPI(void) cveAccumulateProduct(cv::_InputArray* src1, cv::_InputArray* src2, cv::_InputOutputArray* dst, cv::_InputArray* mask);

    Local $bSrc1DllType
    If VarGetType($src1) == "DLLStruct" Then
        $bSrc1DllType = "struct*"
    Else
        $bSrc1DllType = "ptr"
    EndIf

    Local $bSrc2DllType
    If VarGetType($src2) == "DLLStruct" Then
        $bSrc2DllType = "struct*"
    Else
        $bSrc2DllType = "ptr"
    EndIf

    Local $bDstDllType
    If VarGetType($dst) == "DLLStruct" Then
        $bDstDllType = "struct*"
    Else
        $bDstDllType = "ptr"
    EndIf

    Local $bMaskDllType
    If VarGetType($mask) == "DLLStruct" Then
        $bMaskDllType = "struct*"
    Else
        $bMaskDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveAccumulateProduct", $bSrc1DllType, $src1, $bSrc2DllType, $src2, $bDstDllType, $dst, $bMaskDllType, $mask), "cveAccumulateProduct", @error)
EndFunc   ;==>_cveAccumulateProduct

Func _cveAccumulateProductMat($matSrc1, $matSrc2, $matDst, $matMask = _cveNoArrayMat())
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

Func _cveAccumulateWeighted($src, $dst, $alpha, $mask = _cveNoArray())
    ; CVAPI(void) cveAccumulateWeighted(cv::_InputArray* src, cv::_InputOutputArray* dst, double alpha, cv::_InputArray* mask);

    Local $bSrcDllType
    If VarGetType($src) == "DLLStruct" Then
        $bSrcDllType = "struct*"
    Else
        $bSrcDllType = "ptr"
    EndIf

    Local $bDstDllType
    If VarGetType($dst) == "DLLStruct" Then
        $bDstDllType = "struct*"
    Else
        $bDstDllType = "ptr"
    EndIf

    Local $bMaskDllType
    If VarGetType($mask) == "DLLStruct" Then
        $bMaskDllType = "struct*"
    Else
        $bMaskDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveAccumulateWeighted", $bSrcDllType, $src, $bDstDllType, $dst, "double", $alpha, $bMaskDllType, $mask), "cveAccumulateWeighted", @error)
EndFunc   ;==>_cveAccumulateWeighted

Func _cveAccumulateWeightedMat($matSrc, $matDst, $alpha, $matMask = _cveNoArrayMat())
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

Func _cvePhaseCorrelate($src1, $src2, $window, $response, $result)
    ; CVAPI(void) cvePhaseCorrelate(cv::_InputArray* src1, cv::_InputArray* src2, cv::_InputArray* window, double* response, CvPoint2D64f* result);

    Local $bSrc1DllType
    If VarGetType($src1) == "DLLStruct" Then
        $bSrc1DllType = "struct*"
    Else
        $bSrc1DllType = "ptr"
    EndIf

    Local $bSrc2DllType
    If VarGetType($src2) == "DLLStruct" Then
        $bSrc2DllType = "struct*"
    Else
        $bSrc2DllType = "ptr"
    EndIf

    Local $bWindowDllType
    If VarGetType($window) == "DLLStruct" Then
        $bWindowDllType = "struct*"
    Else
        $bWindowDllType = "ptr"
    EndIf

    Local $bResponseDllType
    If VarGetType($response) == "DLLStruct" Then
        $bResponseDllType = "struct*"
    Else
        $bResponseDllType = "double*"
    EndIf

    Local $bResultDllType
    If VarGetType($result) == "DLLStruct" Then
        $bResultDllType = "struct*"
    Else
        $bResultDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cvePhaseCorrelate", $bSrc1DllType, $src1, $bSrc2DllType, $src2, $bWindowDllType, $window, $bResponseDllType, $response, $bResultDllType, $result), "cvePhaseCorrelate", @error)
EndFunc   ;==>_cvePhaseCorrelate

Func _cvePhaseCorrelateMat($matSrc1, $matSrc2, $matWindow, $response, $result)
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

Func _cveCreateHanningWindow($dst, $winSize, $type)
    ; CVAPI(void) cveCreateHanningWindow(cv::_OutputArray* dst, CvSize* winSize, int type);

    Local $bDstDllType
    If VarGetType($dst) == "DLLStruct" Then
        $bDstDllType = "struct*"
    Else
        $bDstDllType = "ptr"
    EndIf

    Local $bWinSizeDllType
    If VarGetType($winSize) == "DLLStruct" Then
        $bWinSizeDllType = "struct*"
    Else
        $bWinSizeDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCreateHanningWindow", $bDstDllType, $dst, $bWinSizeDllType, $winSize, "int", $type), "cveCreateHanningWindow", @error)
EndFunc   ;==>_cveCreateHanningWindow

Func _cveCreateHanningWindowMat($matDst, $winSize, $type)
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

Func _cveResize($src, $dst, $dsize, $fx = 0, $fy = 0, $interpolation = $CV_INTER_LINEAR)
    ; CVAPI(void) cveResize(cv::_InputArray* src, cv::_OutputArray* dst, CvSize* dsize, double fx, double fy, int interpolation);

    Local $bSrcDllType
    If VarGetType($src) == "DLLStruct" Then
        $bSrcDllType = "struct*"
    Else
        $bSrcDllType = "ptr"
    EndIf

    Local $bDstDllType
    If VarGetType($dst) == "DLLStruct" Then
        $bDstDllType = "struct*"
    Else
        $bDstDllType = "ptr"
    EndIf

    Local $bDsizeDllType
    If VarGetType($dsize) == "DLLStruct" Then
        $bDsizeDllType = "struct*"
    Else
        $bDsizeDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveResize", $bSrcDllType, $src, $bDstDllType, $dst, $bDsizeDllType, $dsize, "double", $fx, "double", $fy, "int", $interpolation), "cveResize", @error)
EndFunc   ;==>_cveResize

Func _cveResizeMat($matSrc, $matDst, $dsize, $fx = 0, $fy = 0, $interpolation = $CV_INTER_LINEAR)
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

Func _cveWarpAffine($src, $dst, $m, $dsize, $flags = $CV_INTER_LINEAR, $borderMode = $CV_BORDER_CONSTANT, $borderValue = _cvScalar())
    ; CVAPI(void) cveWarpAffine(cv::_InputArray* src, cv::_OutputArray* dst, cv::_InputArray* m, CvSize* dsize, int flags, int borderMode, CvScalar* borderValue);

    Local $bSrcDllType
    If VarGetType($src) == "DLLStruct" Then
        $bSrcDllType = "struct*"
    Else
        $bSrcDllType = "ptr"
    EndIf

    Local $bDstDllType
    If VarGetType($dst) == "DLLStruct" Then
        $bDstDllType = "struct*"
    Else
        $bDstDllType = "ptr"
    EndIf

    Local $bMDllType
    If VarGetType($m) == "DLLStruct" Then
        $bMDllType = "struct*"
    Else
        $bMDllType = "ptr"
    EndIf

    Local $bDsizeDllType
    If VarGetType($dsize) == "DLLStruct" Then
        $bDsizeDllType = "struct*"
    Else
        $bDsizeDllType = "ptr"
    EndIf

    Local $bBorderValueDllType
    If VarGetType($borderValue) == "DLLStruct" Then
        $bBorderValueDllType = "struct*"
    Else
        $bBorderValueDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveWarpAffine", $bSrcDllType, $src, $bDstDllType, $dst, $bMDllType, $m, $bDsizeDllType, $dsize, "int", $flags, "int", $borderMode, $bBorderValueDllType, $borderValue), "cveWarpAffine", @error)
EndFunc   ;==>_cveWarpAffine

Func _cveWarpAffineMat($matSrc, $matDst, $matM, $dsize, $flags = $CV_INTER_LINEAR, $borderMode = $CV_BORDER_CONSTANT, $borderValue = _cvScalar())
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

Func _cveWarpPerspective($src, $dst, $m, $dsize, $flags = $CV_INTER_LINEAR, $borderMode = $CV_BORDER_CONSTANT, $borderValue = _cvScalar())
    ; CVAPI(void) cveWarpPerspective(cv::_InputArray* src, cv::_OutputArray* dst, cv::_InputArray* m, CvSize* dsize, int flags, int borderMode, CvScalar* borderValue);

    Local $bSrcDllType
    If VarGetType($src) == "DLLStruct" Then
        $bSrcDllType = "struct*"
    Else
        $bSrcDllType = "ptr"
    EndIf

    Local $bDstDllType
    If VarGetType($dst) == "DLLStruct" Then
        $bDstDllType = "struct*"
    Else
        $bDstDllType = "ptr"
    EndIf

    Local $bMDllType
    If VarGetType($m) == "DLLStruct" Then
        $bMDllType = "struct*"
    Else
        $bMDllType = "ptr"
    EndIf

    Local $bDsizeDllType
    If VarGetType($dsize) == "DLLStruct" Then
        $bDsizeDllType = "struct*"
    Else
        $bDsizeDllType = "ptr"
    EndIf

    Local $bBorderValueDllType
    If VarGetType($borderValue) == "DLLStruct" Then
        $bBorderValueDllType = "struct*"
    Else
        $bBorderValueDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveWarpPerspective", $bSrcDllType, $src, $bDstDllType, $dst, $bMDllType, $m, $bDsizeDllType, $dsize, "int", $flags, "int", $borderMode, $bBorderValueDllType, $borderValue), "cveWarpPerspective", @error)
EndFunc   ;==>_cveWarpPerspective

Func _cveWarpPerspectiveMat($matSrc, $matDst, $matM, $dsize, $flags = $CV_INTER_LINEAR, $borderMode = $CV_BORDER_CONSTANT, $borderValue = _cvScalar())
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

Func _cveLogPolar($src, $dst, $center, $M, $flags)
    ; CVAPI(void) cveLogPolar(cv::_InputArray* src, cv::_OutputArray* dst, CvPoint2D32f* center, double M, int flags);

    Local $bSrcDllType
    If VarGetType($src) == "DLLStruct" Then
        $bSrcDllType = "struct*"
    Else
        $bSrcDllType = "ptr"
    EndIf

    Local $bDstDllType
    If VarGetType($dst) == "DLLStruct" Then
        $bDstDllType = "struct*"
    Else
        $bDstDllType = "ptr"
    EndIf

    Local $bCenterDllType
    If VarGetType($center) == "DLLStruct" Then
        $bCenterDllType = "struct*"
    Else
        $bCenterDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveLogPolar", $bSrcDllType, $src, $bDstDllType, $dst, $bCenterDllType, $center, "double", $M, "int", $flags), "cveLogPolar", @error)
EndFunc   ;==>_cveLogPolar

Func _cveLogPolarMat($matSrc, $matDst, $center, $M, $flags)
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

Func _cveLinearPolar($src, $dst, $center, $maxRadius, $flags)
    ; CVAPI(void) cveLinearPolar(cv::_InputArray* src, cv::_OutputArray* dst, CvPoint2D32f* center, double maxRadius, int flags);

    Local $bSrcDllType
    If VarGetType($src) == "DLLStruct" Then
        $bSrcDllType = "struct*"
    Else
        $bSrcDllType = "ptr"
    EndIf

    Local $bDstDllType
    If VarGetType($dst) == "DLLStruct" Then
        $bDstDllType = "struct*"
    Else
        $bDstDllType = "ptr"
    EndIf

    Local $bCenterDllType
    If VarGetType($center) == "DLLStruct" Then
        $bCenterDllType = "struct*"
    Else
        $bCenterDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveLinearPolar", $bSrcDllType, $src, $bDstDllType, $dst, $bCenterDllType, $center, "double", $maxRadius, "int", $flags), "cveLinearPolar", @error)
EndFunc   ;==>_cveLinearPolar

Func _cveLinearPolarMat($matSrc, $matDst, $center, $maxRadius, $flags)
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

Func _cveRemap($src, $dst, $map1, $map2, $interpolation, $borderMode = $CV_BORDER_CONSTANT, $borderValue = _cvScalar())
    ; CVAPI(void) cveRemap(cv::_InputArray* src, cv::_OutputArray* dst, cv::_InputArray* map1, cv::_InputArray* map2, int interpolation, int borderMode, CvScalar* borderValue);

    Local $bSrcDllType
    If VarGetType($src) == "DLLStruct" Then
        $bSrcDllType = "struct*"
    Else
        $bSrcDllType = "ptr"
    EndIf

    Local $bDstDllType
    If VarGetType($dst) == "DLLStruct" Then
        $bDstDllType = "struct*"
    Else
        $bDstDllType = "ptr"
    EndIf

    Local $bMap1DllType
    If VarGetType($map1) == "DLLStruct" Then
        $bMap1DllType = "struct*"
    Else
        $bMap1DllType = "ptr"
    EndIf

    Local $bMap2DllType
    If VarGetType($map2) == "DLLStruct" Then
        $bMap2DllType = "struct*"
    Else
        $bMap2DllType = "ptr"
    EndIf

    Local $bBorderValueDllType
    If VarGetType($borderValue) == "DLLStruct" Then
        $bBorderValueDllType = "struct*"
    Else
        $bBorderValueDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveRemap", $bSrcDllType, $src, $bDstDllType, $dst, $bMap1DllType, $map1, $bMap2DllType, $map2, "int", $interpolation, "int", $borderMode, $bBorderValueDllType, $borderValue), "cveRemap", @error)
EndFunc   ;==>_cveRemap

Func _cveRemapMat($matSrc, $matDst, $matMap1, $matMap2, $interpolation, $borderMode = $CV_BORDER_CONSTANT, $borderValue = _cvScalar())
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

Func _cveRepeat($src, $ny, $nx, $dst)
    ; CVAPI(void) cveRepeat(cv::_InputArray* src, int ny, int nx, cv::_OutputArray* dst);

    Local $bSrcDllType
    If VarGetType($src) == "DLLStruct" Then
        $bSrcDllType = "struct*"
    Else
        $bSrcDllType = "ptr"
    EndIf

    Local $bDstDllType
    If VarGetType($dst) == "DLLStruct" Then
        $bDstDllType = "struct*"
    Else
        $bDstDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveRepeat", $bSrcDllType, $src, "int", $ny, "int", $nx, $bDstDllType, $dst), "cveRepeat", @error)
EndFunc   ;==>_cveRepeat

Func _cveRepeatMat($matSrc, $ny, $nx, $matDst)
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

Func _cveHoughCircles($image, $circles, $method, $dp, $minDist, $param1 = 100, $param2 = 100, $minRadius = 0, $maxRadius = 0)
    ; CVAPI(void) cveHoughCircles(cv::_InputArray* image, cv::_OutputArray* circles, int method, double dp, double minDist, double param1, double param2, int minRadius, int maxRadius);

    Local $bImageDllType
    If VarGetType($image) == "DLLStruct" Then
        $bImageDllType = "struct*"
    Else
        $bImageDllType = "ptr"
    EndIf

    Local $bCirclesDllType
    If VarGetType($circles) == "DLLStruct" Then
        $bCirclesDllType = "struct*"
    Else
        $bCirclesDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveHoughCircles", $bImageDllType, $image, $bCirclesDllType, $circles, "int", $method, "double", $dp, "double", $minDist, "double", $param1, "double", $param2, "int", $minRadius, "int", $maxRadius), "cveHoughCircles", @error)
EndFunc   ;==>_cveHoughCircles

Func _cveHoughCirclesMat($matImage, $matCircles, $method, $dp, $minDist, $param1 = 100, $param2 = 100, $minRadius = 0, $maxRadius = 0)
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

Func _cveHoughLines($image, $lines, $rho, $theta, $threshold, $srn = 0, $stn = 0)
    ; CVAPI(void) cveHoughLines(cv::_InputArray* image, cv::_OutputArray* lines, double rho, double theta, int threshold, double srn, double stn);

    Local $bImageDllType
    If VarGetType($image) == "DLLStruct" Then
        $bImageDllType = "struct*"
    Else
        $bImageDllType = "ptr"
    EndIf

    Local $bLinesDllType
    If VarGetType($lines) == "DLLStruct" Then
        $bLinesDllType = "struct*"
    Else
        $bLinesDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveHoughLines", $bImageDllType, $image, $bLinesDllType, $lines, "double", $rho, "double", $theta, "int", $threshold, "double", $srn, "double", $stn), "cveHoughLines", @error)
EndFunc   ;==>_cveHoughLines

Func _cveHoughLinesMat($matImage, $matLines, $rho, $theta, $threshold, $srn = 0, $stn = 0)
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

Func _cveHoughLinesP($image, $lines, $rho, $theta, $threshold, $minLineLength, $maxGap)
    ; CVAPI(void) cveHoughLinesP(cv::_InputArray* image, cv::_OutputArray* lines, double rho, double theta, int threshold, double minLineLength, double maxGap);

    Local $bImageDllType
    If VarGetType($image) == "DLLStruct" Then
        $bImageDllType = "struct*"
    Else
        $bImageDllType = "ptr"
    EndIf

    Local $bLinesDllType
    If VarGetType($lines) == "DLLStruct" Then
        $bLinesDllType = "struct*"
    Else
        $bLinesDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveHoughLinesP", $bImageDllType, $image, $bLinesDllType, $lines, "double", $rho, "double", $theta, "int", $threshold, "double", $minLineLength, "double", $maxGap), "cveHoughLinesP", @error)
EndFunc   ;==>_cveHoughLinesP

Func _cveHoughLinesPMat($matImage, $matLines, $rho, $theta, $threshold, $minLineLength, $maxGap)
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

Func _cveMatchTemplate($image, $templ, $result, $method, $mask = _cveNoArray())
    ; CVAPI(void) cveMatchTemplate(cv::_InputArray* image, cv::_InputArray* templ, cv::_OutputArray* result, int method, cv::_InputArray* mask);

    Local $bImageDllType
    If VarGetType($image) == "DLLStruct" Then
        $bImageDllType = "struct*"
    Else
        $bImageDllType = "ptr"
    EndIf

    Local $bTemplDllType
    If VarGetType($templ) == "DLLStruct" Then
        $bTemplDllType = "struct*"
    Else
        $bTemplDllType = "ptr"
    EndIf

    Local $bResultDllType
    If VarGetType($result) == "DLLStruct" Then
        $bResultDllType = "struct*"
    Else
        $bResultDllType = "ptr"
    EndIf

    Local $bMaskDllType
    If VarGetType($mask) == "DLLStruct" Then
        $bMaskDllType = "struct*"
    Else
        $bMaskDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMatchTemplate", $bImageDllType, $image, $bTemplDllType, $templ, $bResultDllType, $result, "int", $method, $bMaskDllType, $mask), "cveMatchTemplate", @error)
EndFunc   ;==>_cveMatchTemplate

Func _cveMatchTemplateMat($matImage, $matTempl, $matResult, $method, $matMask = _cveNoArrayMat())
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

Func _cveCornerSubPix($image, $corners, $winSize, $zeroZone, $criteria)
    ; CVAPI(void) cveCornerSubPix(cv::_InputArray* image, cv::_InputOutputArray* corners, CvSize* winSize, CvSize* zeroZone, CvTermCriteria* criteria);

    Local $bImageDllType
    If VarGetType($image) == "DLLStruct" Then
        $bImageDllType = "struct*"
    Else
        $bImageDllType = "ptr"
    EndIf

    Local $bCornersDllType
    If VarGetType($corners) == "DLLStruct" Then
        $bCornersDllType = "struct*"
    Else
        $bCornersDllType = "ptr"
    EndIf

    Local $bWinSizeDllType
    If VarGetType($winSize) == "DLLStruct" Then
        $bWinSizeDllType = "struct*"
    Else
        $bWinSizeDllType = "ptr"
    EndIf

    Local $bZeroZoneDllType
    If VarGetType($zeroZone) == "DLLStruct" Then
        $bZeroZoneDllType = "struct*"
    Else
        $bZeroZoneDllType = "ptr"
    EndIf

    Local $bCriteriaDllType
    If VarGetType($criteria) == "DLLStruct" Then
        $bCriteriaDllType = "struct*"
    Else
        $bCriteriaDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCornerSubPix", $bImageDllType, $image, $bCornersDllType, $corners, $bWinSizeDllType, $winSize, $bZeroZoneDllType, $zeroZone, $bCriteriaDllType, $criteria), "cveCornerSubPix", @error)
EndFunc   ;==>_cveCornerSubPix

Func _cveCornerSubPixMat($matImage, $matCorners, $winSize, $zeroZone, $criteria)
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

Func _cveConvertMaps($map1, $map2, $dstmap1, $dstmap2, $dstmap1Type, $nninterpolation = false)
    ; CVAPI(void) cveConvertMaps(cv::_InputArray* map1, cv::_InputArray* map2, cv::_OutputArray* dstmap1, cv::_OutputArray* dstmap2, int dstmap1Type, bool nninterpolation);

    Local $bMap1DllType
    If VarGetType($map1) == "DLLStruct" Then
        $bMap1DllType = "struct*"
    Else
        $bMap1DllType = "ptr"
    EndIf

    Local $bMap2DllType
    If VarGetType($map2) == "DLLStruct" Then
        $bMap2DllType = "struct*"
    Else
        $bMap2DllType = "ptr"
    EndIf

    Local $bDstmap1DllType
    If VarGetType($dstmap1) == "DLLStruct" Then
        $bDstmap1DllType = "struct*"
    Else
        $bDstmap1DllType = "ptr"
    EndIf

    Local $bDstmap2DllType
    If VarGetType($dstmap2) == "DLLStruct" Then
        $bDstmap2DllType = "struct*"
    Else
        $bDstmap2DllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveConvertMaps", $bMap1DllType, $map1, $bMap2DllType, $map2, $bDstmap1DllType, $dstmap1, $bDstmap2DllType, $dstmap2, "int", $dstmap1Type, "boolean", $nninterpolation), "cveConvertMaps", @error)
EndFunc   ;==>_cveConvertMaps

Func _cveConvertMapsMat($matMap1, $matMap2, $matDstmap1, $matDstmap2, $dstmap1Type, $nninterpolation = false)
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

Func _cveGetAffineTransform($src, $dst, $affine)
    ; CVAPI(void) cveGetAffineTransform(cv::_InputArray* src, cv::_InputArray* dst, cv::Mat* affine);

    Local $bSrcDllType
    If VarGetType($src) == "DLLStruct" Then
        $bSrcDllType = "struct*"
    Else
        $bSrcDllType = "ptr"
    EndIf

    Local $bDstDllType
    If VarGetType($dst) == "DLLStruct" Then
        $bDstDllType = "struct*"
    Else
        $bDstDllType = "ptr"
    EndIf

    Local $bAffineDllType
    If VarGetType($affine) == "DLLStruct" Then
        $bAffineDllType = "struct*"
    Else
        $bAffineDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveGetAffineTransform", $bSrcDllType, $src, $bDstDllType, $dst, $bAffineDllType, $affine), "cveGetAffineTransform", @error)
EndFunc   ;==>_cveGetAffineTransform

Func _cveGetAffineTransformMat($matSrc, $matDst, $affine)
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

Func _cveGetPerspectiveTransform($src, $dst, $perspective)
    ; CVAPI(void) cveGetPerspectiveTransform(cv::_InputArray* src, cv::_InputArray* dst, cv::Mat* perspective);

    Local $bSrcDllType
    If VarGetType($src) == "DLLStruct" Then
        $bSrcDllType = "struct*"
    Else
        $bSrcDllType = "ptr"
    EndIf

    Local $bDstDllType
    If VarGetType($dst) == "DLLStruct" Then
        $bDstDllType = "struct*"
    Else
        $bDstDllType = "ptr"
    EndIf

    Local $bPerspectiveDllType
    If VarGetType($perspective) == "DLLStruct" Then
        $bPerspectiveDllType = "struct*"
    Else
        $bPerspectiveDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveGetPerspectiveTransform", $bSrcDllType, $src, $bDstDllType, $dst, $bPerspectiveDllType, $perspective), "cveGetPerspectiveTransform", @error)
EndFunc   ;==>_cveGetPerspectiveTransform

Func _cveGetPerspectiveTransformMat($matSrc, $matDst, $perspective)
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

Func _cveInvertAffineTransform($m, $im)
    ; CVAPI(void) cveInvertAffineTransform(cv::_InputArray* m, cv::_OutputArray* im);

    Local $bMDllType
    If VarGetType($m) == "DLLStruct" Then
        $bMDllType = "struct*"
    Else
        $bMDllType = "ptr"
    EndIf

    Local $bImDllType
    If VarGetType($im) == "DLLStruct" Then
        $bImDllType = "struct*"
    Else
        $bImDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveInvertAffineTransform", $bMDllType, $m, $bImDllType, $im), "cveInvertAffineTransform", @error)
EndFunc   ;==>_cveInvertAffineTransform

Func _cveInvertAffineTransformMat($matM, $matIm)
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

Func _cveEMD($signature1, $signature2, $distType, $cost, $lowerBound, $flow)
    ; CVAPI(void) cveEMD(cv::_InputArray* signature1, cv::_InputArray* signature2, int distType, cv::_InputArray* cost, float* lowerBound, cv::_OutputArray* flow);

    Local $bSignature1DllType
    If VarGetType($signature1) == "DLLStruct" Then
        $bSignature1DllType = "struct*"
    Else
        $bSignature1DllType = "ptr"
    EndIf

    Local $bSignature2DllType
    If VarGetType($signature2) == "DLLStruct" Then
        $bSignature2DllType = "struct*"
    Else
        $bSignature2DllType = "ptr"
    EndIf

    Local $bCostDllType
    If VarGetType($cost) == "DLLStruct" Then
        $bCostDllType = "struct*"
    Else
        $bCostDllType = "ptr"
    EndIf

    Local $bLowerBoundDllType
    If VarGetType($lowerBound) == "DLLStruct" Then
        $bLowerBoundDllType = "struct*"
    Else
        $bLowerBoundDllType = "float*"
    EndIf

    Local $bFlowDllType
    If VarGetType($flow) == "DLLStruct" Then
        $bFlowDllType = "struct*"
    Else
        $bFlowDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveEMD", $bSignature1DllType, $signature1, $bSignature2DllType, $signature2, "int", $distType, $bCostDllType, $cost, $bLowerBoundDllType, $lowerBound, $bFlowDllType, $flow), "cveEMD", @error)
EndFunc   ;==>_cveEMD

Func _cveEMDMat($matSignature1, $matSignature2, $distType, $matCost, $lowerBound, $matFlow)
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

Func _cveCalcHist($images, $channels, $mask, $hist, $histSize, $ranges, $accumulate = false)
    ; CVAPI(void) cveCalcHist(cv::_InputArray* images, const std::vector<int>* channels, cv::_InputArray* mask, cv::_OutputArray* hist, std::vector<int>* histSize, std::vector<float>* ranges, bool accumulate);

    Local $bImagesDllType
    If VarGetType($images) == "DLLStruct" Then
        $bImagesDllType = "struct*"
    Else
        $bImagesDllType = "ptr"
    EndIf

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

    Local $bChannelsDllType
    If VarGetType($channels) == "DLLStruct" Then
        $bChannelsDllType = "struct*"
    Else
        $bChannelsDllType = "ptr"
    EndIf

    Local $bMaskDllType
    If VarGetType($mask) == "DLLStruct" Then
        $bMaskDllType = "struct*"
    Else
        $bMaskDllType = "ptr"
    EndIf

    Local $bHistDllType
    If VarGetType($hist) == "DLLStruct" Then
        $bHistDllType = "struct*"
    Else
        $bHistDllType = "ptr"
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

    Local $bHistSizeDllType
    If VarGetType($histSize) == "DLLStruct" Then
        $bHistSizeDllType = "struct*"
    Else
        $bHistSizeDllType = "ptr"
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

    Local $bRangesDllType
    If VarGetType($ranges) == "DLLStruct" Then
        $bRangesDllType = "struct*"
    Else
        $bRangesDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCalcHist", $bImagesDllType, $images, $bChannelsDllType, $vecChannels, $bMaskDllType, $mask, $bHistDllType, $hist, $bHistSizeDllType, $vecHistSize, $bRangesDllType, $vecRanges, "boolean", $accumulate), "cveCalcHist", @error)

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

Func _cveCalcHistMat($matImages, $channels, $matMask, $matHist, $histSize, $ranges, $accumulate = false)
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

Func _cveCalcBackProject($images, $channels, $hist, $dst, $ranges, $scale)
    ; CVAPI(void) cveCalcBackProject(cv::_InputArray* images, const std::vector<int>* channels, cv::_InputArray* hist, cv::_OutputArray* dst, const std::vector<float>* ranges, double scale);

    Local $bImagesDllType
    If VarGetType($images) == "DLLStruct" Then
        $bImagesDllType = "struct*"
    Else
        $bImagesDllType = "ptr"
    EndIf

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

    Local $bChannelsDllType
    If VarGetType($channels) == "DLLStruct" Then
        $bChannelsDllType = "struct*"
    Else
        $bChannelsDllType = "ptr"
    EndIf

    Local $bHistDllType
    If VarGetType($hist) == "DLLStruct" Then
        $bHistDllType = "struct*"
    Else
        $bHistDllType = "ptr"
    EndIf

    Local $bDstDllType
    If VarGetType($dst) == "DLLStruct" Then
        $bDstDllType = "struct*"
    Else
        $bDstDllType = "ptr"
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

    Local $bRangesDllType
    If VarGetType($ranges) == "DLLStruct" Then
        $bRangesDllType = "struct*"
    Else
        $bRangesDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCalcBackProject", $bImagesDllType, $images, $bChannelsDllType, $vecChannels, $bHistDllType, $hist, $bDstDllType, $dst, $bRangesDllType, $vecRanges, "double", $scale), "cveCalcBackProject", @error)

    If $bRangesIsArray Then
        _VectorOfFloatRelease($vecRanges)
    EndIf

    If $bChannelsIsArray Then
        _VectorOfIntRelease($vecChannels)
    EndIf
EndFunc   ;==>_cveCalcBackProject

Func _cveCalcBackProjectMat($matImages, $channels, $matHist, $matDst, $ranges, $scale)
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

Func _cveCompareHist($h1, $h2, $method)
    ; CVAPI(double) cveCompareHist(cv::_InputArray* h1, cv::_InputArray* h2, int method);

    Local $bH1DllType
    If VarGetType($h1) == "DLLStruct" Then
        $bH1DllType = "struct*"
    Else
        $bH1DllType = "ptr"
    EndIf

    Local $bH2DllType
    If VarGetType($h2) == "DLLStruct" Then
        $bH2DllType = "struct*"
    Else
        $bH2DllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveCompareHist", $bH1DllType, $h1, $bH2DllType, $h2, "int", $method), "cveCompareHist", @error)
EndFunc   ;==>_cveCompareHist

Func _cveCompareHistMat($matH1, $matH2, $method)
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

Func _cveGetRotationMatrix2D($center, $angle, $scale, $rotationMatrix2D)
    ; CVAPI(void) cveGetRotationMatrix2D(CvPoint2D32f* center, double angle, double scale, cv::_OutputArray* rotationMatrix2D);

    Local $bCenterDllType
    If VarGetType($center) == "DLLStruct" Then
        $bCenterDllType = "struct*"
    Else
        $bCenterDllType = "ptr"
    EndIf

    Local $bRotationMatrix2DDllType
    If VarGetType($rotationMatrix2D) == "DLLStruct" Then
        $bRotationMatrix2DDllType = "struct*"
    Else
        $bRotationMatrix2DDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveGetRotationMatrix2D", $bCenterDllType, $center, "double", $angle, "double", $scale, $bRotationMatrix2DDllType, $rotationMatrix2D), "cveGetRotationMatrix2D", @error)
EndFunc   ;==>_cveGetRotationMatrix2D

Func _cveGetRotationMatrix2DMat($center, $angle, $scale, $matRotationMatrix2D)
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

Func _cveFindContours($image, $contours, $hierarchy, $mode, $method, $offset = _cvPoint())
    ; CVAPI(void) cveFindContours(cv::_InputOutputArray* image, cv::_OutputArray* contours, cv::_OutputArray* hierarchy, int mode, int method, CvPoint* offset);

    Local $bImageDllType
    If VarGetType($image) == "DLLStruct" Then
        $bImageDllType = "struct*"
    Else
        $bImageDllType = "ptr"
    EndIf

    Local $bContoursDllType
    If VarGetType($contours) == "DLLStruct" Then
        $bContoursDllType = "struct*"
    Else
        $bContoursDllType = "ptr"
    EndIf

    Local $bHierarchyDllType
    If VarGetType($hierarchy) == "DLLStruct" Then
        $bHierarchyDllType = "struct*"
    Else
        $bHierarchyDllType = "ptr"
    EndIf

    Local $bOffsetDllType
    If VarGetType($offset) == "DLLStruct" Then
        $bOffsetDllType = "struct*"
    Else
        $bOffsetDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFindContours", $bImageDllType, $image, $bContoursDllType, $contours, $bHierarchyDllType, $hierarchy, "int", $mode, "int", $method, $bOffsetDllType, $offset), "cveFindContours", @error)
EndFunc   ;==>_cveFindContours

Func _cveFindContoursMat($matImage, $matContours, $matHierarchy, $mode, $method, $offset = _cvPoint())
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

Func _cvePointPolygonTest($contour, $pt, $measureDist)
    ; CVAPI(double) cvePointPolygonTest(cv::_InputArray* contour, CvPoint2D32f* pt, bool measureDist);

    Local $bContourDllType
    If VarGetType($contour) == "DLLStruct" Then
        $bContourDllType = "struct*"
    Else
        $bContourDllType = "ptr"
    EndIf

    Local $bPtDllType
    If VarGetType($pt) == "DLLStruct" Then
        $bPtDllType = "struct*"
    Else
        $bPtDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cvePointPolygonTest", $bContourDllType, $contour, $bPtDllType, $pt, "boolean", $measureDist), "cvePointPolygonTest", @error)
EndFunc   ;==>_cvePointPolygonTest

Func _cvePointPolygonTestMat($matContour, $pt, $measureDist)
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

Func _cveContourArea($contour, $oriented = false)
    ; CVAPI(double) cveContourArea(cv::_InputArray* contour, bool oriented);

    Local $bContourDllType
    If VarGetType($contour) == "DLLStruct" Then
        $bContourDllType = "struct*"
    Else
        $bContourDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveContourArea", $bContourDllType, $contour, "boolean", $oriented), "cveContourArea", @error)
EndFunc   ;==>_cveContourArea

Func _cveContourAreaMat($matContour, $oriented = false)
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

Func _cveIsContourConvex($contour)
    ; CVAPI(bool) cveIsContourConvex(cv::_InputArray* contour);

    Local $bContourDllType
    If VarGetType($contour) == "DLLStruct" Then
        $bContourDllType = "struct*"
    Else
        $bContourDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveIsContourConvex", $bContourDllType, $contour), "cveIsContourConvex", @error)
EndFunc   ;==>_cveIsContourConvex

Func _cveIsContourConvexMat($matContour)
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

Func _cveIntersectConvexConvex($p1, $p2, $p12, $handleNested = true)
    ; CVAPI(float) cveIntersectConvexConvex(cv::_InputArray* p1, cv::_InputArray* p2, cv::_OutputArray* p12, bool handleNested);

    Local $bP1DllType
    If VarGetType($p1) == "DLLStruct" Then
        $bP1DllType = "struct*"
    Else
        $bP1DllType = "ptr"
    EndIf

    Local $bP2DllType
    If VarGetType($p2) == "DLLStruct" Then
        $bP2DllType = "struct*"
    Else
        $bP2DllType = "ptr"
    EndIf

    Local $bP12DllType
    If VarGetType($p12) == "DLLStruct" Then
        $bP12DllType = "struct*"
    Else
        $bP12DllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cveIntersectConvexConvex", $bP1DllType, $p1, $bP2DllType, $p2, $bP12DllType, $p12, "boolean", $handleNested), "cveIntersectConvexConvex", @error)
EndFunc   ;==>_cveIntersectConvexConvex

Func _cveIntersectConvexConvexMat($matP1, $matP2, $matP12, $handleNested = true)
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

Func _cveBoundingRectangle($points, $boundingRect)
    ; CVAPI(void) cveBoundingRectangle(cv::_InputArray* points, CvRect* boundingRect);

    Local $bPointsDllType
    If VarGetType($points) == "DLLStruct" Then
        $bPointsDllType = "struct*"
    Else
        $bPointsDllType = "ptr"
    EndIf

    Local $bBoundingRectDllType
    If VarGetType($boundingRect) == "DLLStruct" Then
        $bBoundingRectDllType = "struct*"
    Else
        $bBoundingRectDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBoundingRectangle", $bPointsDllType, $points, $bBoundingRectDllType, $boundingRect), "cveBoundingRectangle", @error)
EndFunc   ;==>_cveBoundingRectangle

Func _cveBoundingRectangleMat($matPoints, $boundingRect)
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

Func _cveArcLength($curve, $closed)
    ; CVAPI(double) cveArcLength(cv::_InputArray* curve, bool closed);

    Local $bCurveDllType
    If VarGetType($curve) == "DLLStruct" Then
        $bCurveDllType = "struct*"
    Else
        $bCurveDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveArcLength", $bCurveDllType, $curve, "boolean", $closed), "cveArcLength", @error)
EndFunc   ;==>_cveArcLength

Func _cveArcLengthMat($matCurve, $closed)
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

Func _cveMinAreaRect($points, $box)
    ; CVAPI(void) cveMinAreaRect(cv::_InputArray* points, CvBox2D* box);

    Local $bPointsDllType
    If VarGetType($points) == "DLLStruct" Then
        $bPointsDllType = "struct*"
    Else
        $bPointsDllType = "ptr"
    EndIf

    Local $bBoxDllType
    If VarGetType($box) == "DLLStruct" Then
        $bBoxDllType = "struct*"
    Else
        $bBoxDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMinAreaRect", $bPointsDllType, $points, $bBoxDllType, $box), "cveMinAreaRect", @error)
EndFunc   ;==>_cveMinAreaRect

Func _cveMinAreaRectMat($matPoints, $box)
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

Func _cveBoxPoints($box, $points)
    ; CVAPI(void) cveBoxPoints(CvBox2D* box, cv::_OutputArray* points);

    Local $bBoxDllType
    If VarGetType($box) == "DLLStruct" Then
        $bBoxDllType = "struct*"
    Else
        $bBoxDllType = "ptr"
    EndIf

    Local $bPointsDllType
    If VarGetType($points) == "DLLStruct" Then
        $bPointsDllType = "struct*"
    Else
        $bPointsDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBoxPoints", $bBoxDllType, $box, $bPointsDllType, $points), "cveBoxPoints", @error)
EndFunc   ;==>_cveBoxPoints

Func _cveBoxPointsMat($box, $matPoints)
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

Func _cveMinEnclosingTriangle($points, $triangle)
    ; CVAPI(double) cveMinEnclosingTriangle(cv::_InputArray* points, cv::_OutputArray* triangle);

    Local $bPointsDllType
    If VarGetType($points) == "DLLStruct" Then
        $bPointsDllType = "struct*"
    Else
        $bPointsDllType = "ptr"
    EndIf

    Local $bTriangleDllType
    If VarGetType($triangle) == "DLLStruct" Then
        $bTriangleDllType = "struct*"
    Else
        $bTriangleDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveMinEnclosingTriangle", $bPointsDllType, $points, $bTriangleDllType, $triangle), "cveMinEnclosingTriangle", @error)
EndFunc   ;==>_cveMinEnclosingTriangle

Func _cveMinEnclosingTriangleMat($matPoints, $matTriangle)
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

Func _cveMinEnclosingCircle($points, $center, $radius)
    ; CVAPI(void) cveMinEnclosingCircle(cv::_InputArray* points, CvPoint2D32f* center, float* radius);

    Local $bPointsDllType
    If VarGetType($points) == "DLLStruct" Then
        $bPointsDllType = "struct*"
    Else
        $bPointsDllType = "ptr"
    EndIf

    Local $bCenterDllType
    If VarGetType($center) == "DLLStruct" Then
        $bCenterDllType = "struct*"
    Else
        $bCenterDllType = "ptr"
    EndIf

    Local $bRadiusDllType
    If VarGetType($radius) == "DLLStruct" Then
        $bRadiusDllType = "struct*"
    Else
        $bRadiusDllType = "float*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMinEnclosingCircle", $bPointsDllType, $points, $bCenterDllType, $center, $bRadiusDllType, $radius), "cveMinEnclosingCircle", @error)
EndFunc   ;==>_cveMinEnclosingCircle

Func _cveMinEnclosingCircleMat($matPoints, $center, $radius)
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

Func _cveMatchShapes($contour1, $contour2, $method, $parameter)
    ; CVAPI(double) cveMatchShapes(cv::_InputArray* contour1, cv::_InputArray* contour2, int method, double parameter);

    Local $bContour1DllType
    If VarGetType($contour1) == "DLLStruct" Then
        $bContour1DllType = "struct*"
    Else
        $bContour1DllType = "ptr"
    EndIf

    Local $bContour2DllType
    If VarGetType($contour2) == "DLLStruct" Then
        $bContour2DllType = "struct*"
    Else
        $bContour2DllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveMatchShapes", $bContour1DllType, $contour1, $bContour2DllType, $contour2, "int", $method, "double", $parameter), "cveMatchShapes", @error)
EndFunc   ;==>_cveMatchShapes

Func _cveMatchShapesMat($matContour1, $matContour2, $method, $parameter)
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

Func _cveFitEllipse($points, $box)
    ; CVAPI(void) cveFitEllipse(cv::_InputArray* points, CvBox2D* box);

    Local $bPointsDllType
    If VarGetType($points) == "DLLStruct" Then
        $bPointsDllType = "struct*"
    Else
        $bPointsDllType = "ptr"
    EndIf

    Local $bBoxDllType
    If VarGetType($box) == "DLLStruct" Then
        $bBoxDllType = "struct*"
    Else
        $bBoxDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFitEllipse", $bPointsDllType, $points, $bBoxDllType, $box), "cveFitEllipse", @error)
EndFunc   ;==>_cveFitEllipse

Func _cveFitEllipseMat($matPoints, $box)
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

Func _cveFitEllipseAMS($points, $box)
    ; CVAPI(void) cveFitEllipseAMS(cv::_InputArray* points, CvBox2D* box);

    Local $bPointsDllType
    If VarGetType($points) == "DLLStruct" Then
        $bPointsDllType = "struct*"
    Else
        $bPointsDllType = "ptr"
    EndIf

    Local $bBoxDllType
    If VarGetType($box) == "DLLStruct" Then
        $bBoxDllType = "struct*"
    Else
        $bBoxDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFitEllipseAMS", $bPointsDllType, $points, $bBoxDllType, $box), "cveFitEllipseAMS", @error)
EndFunc   ;==>_cveFitEllipseAMS

Func _cveFitEllipseAMSMat($matPoints, $box)
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

Func _cveFitEllipseDirect($points, $box)
    ; CVAPI(void) cveFitEllipseDirect(cv::_InputArray* points, CvBox2D* box);

    Local $bPointsDllType
    If VarGetType($points) == "DLLStruct" Then
        $bPointsDllType = "struct*"
    Else
        $bPointsDllType = "ptr"
    EndIf

    Local $bBoxDllType
    If VarGetType($box) == "DLLStruct" Then
        $bBoxDllType = "struct*"
    Else
        $bBoxDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFitEllipseDirect", $bPointsDllType, $points, $bBoxDllType, $box), "cveFitEllipseDirect", @error)
EndFunc   ;==>_cveFitEllipseDirect

Func _cveFitEllipseDirectMat($matPoints, $box)
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

Func _cveFitLine($points, $line, $distType, $param, $reps, $aeps)
    ; CVAPI(void) cveFitLine(cv::_InputArray* points, cv::_OutputArray* line, int distType, double param, double reps, double aeps);

    Local $bPointsDllType
    If VarGetType($points) == "DLLStruct" Then
        $bPointsDllType = "struct*"
    Else
        $bPointsDllType = "ptr"
    EndIf

    Local $bLineDllType
    If VarGetType($line) == "DLLStruct" Then
        $bLineDllType = "struct*"
    Else
        $bLineDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFitLine", $bPointsDllType, $points, $bLineDllType, $line, "int", $distType, "double", $param, "double", $reps, "double", $aeps), "cveFitLine", @error)
EndFunc   ;==>_cveFitLine

Func _cveFitLineMat($matPoints, $matLine, $distType, $param, $reps, $aeps)
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

Func _cveRotatedRectangleIntersection($rect1, $rect2, $intersectingRegion)
    ; CVAPI(int) cveRotatedRectangleIntersection(CvBox2D* rect1, CvBox2D* rect2, cv::_OutputArray* intersectingRegion);

    Local $bRect1DllType
    If VarGetType($rect1) == "DLLStruct" Then
        $bRect1DllType = "struct*"
    Else
        $bRect1DllType = "ptr"
    EndIf

    Local $bRect2DllType
    If VarGetType($rect2) == "DLLStruct" Then
        $bRect2DllType = "struct*"
    Else
        $bRect2DllType = "ptr"
    EndIf

    Local $bIntersectingRegionDllType
    If VarGetType($intersectingRegion) == "DLLStruct" Then
        $bIntersectingRegionDllType = "struct*"
    Else
        $bIntersectingRegionDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveRotatedRectangleIntersection", $bRect1DllType, $rect1, $bRect2DllType, $rect2, $bIntersectingRegionDllType, $intersectingRegion), "cveRotatedRectangleIntersection", @error)
EndFunc   ;==>_cveRotatedRectangleIntersection

Func _cveRotatedRectangleIntersectionMat($rect1, $rect2, $matIntersectingRegion)
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

Func _cveDrawContours($image, $contours, $contourIdx, $color, $thickness = 1, $lineType = $CV_LINE_8, $hierarchy = _cveNoArray(), $maxLevel = $CV_INT_MAX, $offset = _cvPoint())
    ; CVAPI(void) cveDrawContours(cv::_InputOutputArray* image, cv::_InputArray* contours, int contourIdx, CvScalar* color, int thickness, int lineType, cv::_InputArray* hierarchy, int maxLevel, CvPoint* offset);

    Local $bImageDllType
    If VarGetType($image) == "DLLStruct" Then
        $bImageDllType = "struct*"
    Else
        $bImageDllType = "ptr"
    EndIf

    Local $bContoursDllType
    If VarGetType($contours) == "DLLStruct" Then
        $bContoursDllType = "struct*"
    Else
        $bContoursDllType = "ptr"
    EndIf

    Local $bColorDllType
    If VarGetType($color) == "DLLStruct" Then
        $bColorDllType = "struct*"
    Else
        $bColorDllType = "ptr"
    EndIf

    Local $bHierarchyDllType
    If VarGetType($hierarchy) == "DLLStruct" Then
        $bHierarchyDllType = "struct*"
    Else
        $bHierarchyDllType = "ptr"
    EndIf

    Local $bOffsetDllType
    If VarGetType($offset) == "DLLStruct" Then
        $bOffsetDllType = "struct*"
    Else
        $bOffsetDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDrawContours", $bImageDllType, $image, $bContoursDllType, $contours, "int", $contourIdx, $bColorDllType, $color, "int", $thickness, "int", $lineType, $bHierarchyDllType, $hierarchy, "int", $maxLevel, $bOffsetDllType, $offset), "cveDrawContours", @error)
EndFunc   ;==>_cveDrawContours

Func _cveDrawContoursMat($matImage, $matContours, $contourIdx, $color, $thickness = 1, $lineType = $CV_LINE_8, $matHierarchy = _cveNoArrayMat(), $maxLevel = $CV_INT_MAX, $offset = _cvPoint())
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

Func _cveApproxPolyDP($curve, $approxCurve, $epsilon, $closed)
    ; CVAPI(void) cveApproxPolyDP(cv::_InputArray* curve, cv::_OutputArray* approxCurve, double epsilon, bool closed);

    Local $bCurveDllType
    If VarGetType($curve) == "DLLStruct" Then
        $bCurveDllType = "struct*"
    Else
        $bCurveDllType = "ptr"
    EndIf

    Local $bApproxCurveDllType
    If VarGetType($approxCurve) == "DLLStruct" Then
        $bApproxCurveDllType = "struct*"
    Else
        $bApproxCurveDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveApproxPolyDP", $bCurveDllType, $curve, $bApproxCurveDllType, $approxCurve, "double", $epsilon, "boolean", $closed), "cveApproxPolyDP", @error)
EndFunc   ;==>_cveApproxPolyDP

Func _cveApproxPolyDPMat($matCurve, $matApproxCurve, $epsilon, $closed)
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

Func _cveConvexHull($points, $hull, $clockwise = false, $returnPoints = true)
    ; CVAPI(void) cveConvexHull(cv::_InputArray* points, cv::_OutputArray* hull, bool clockwise, bool returnPoints);

    Local $bPointsDllType
    If VarGetType($points) == "DLLStruct" Then
        $bPointsDllType = "struct*"
    Else
        $bPointsDllType = "ptr"
    EndIf

    Local $bHullDllType
    If VarGetType($hull) == "DLLStruct" Then
        $bHullDllType = "struct*"
    Else
        $bHullDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveConvexHull", $bPointsDllType, $points, $bHullDllType, $hull, "boolean", $clockwise, "boolean", $returnPoints), "cveConvexHull", @error)
EndFunc   ;==>_cveConvexHull

Func _cveConvexHullMat($matPoints, $matHull, $clockwise = false, $returnPoints = true)
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

Func _cveConvexityDefects($contour, $convexhull, $convexityDefects)
    ; CVAPI(void) cveConvexityDefects(cv::_InputArray* contour, cv::_InputArray* convexhull, cv::_OutputArray* convexityDefects);

    Local $bContourDllType
    If VarGetType($contour) == "DLLStruct" Then
        $bContourDllType = "struct*"
    Else
        $bContourDllType = "ptr"
    EndIf

    Local $bConvexhullDllType
    If VarGetType($convexhull) == "DLLStruct" Then
        $bConvexhullDllType = "struct*"
    Else
        $bConvexhullDllType = "ptr"
    EndIf

    Local $bConvexityDefectsDllType
    If VarGetType($convexityDefects) == "DLLStruct" Then
        $bConvexityDefectsDllType = "struct*"
    Else
        $bConvexityDefectsDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveConvexityDefects", $bContourDllType, $contour, $bConvexhullDllType, $convexhull, $bConvexityDefectsDllType, $convexityDefects), "cveConvexityDefects", @error)
EndFunc   ;==>_cveConvexityDefects

Func _cveConvexityDefectsMat($matContour, $matConvexhull, $matConvexityDefects)
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

Func _cveGaussianBlur($src, $dst, $ksize, $sigmaX, $sigmaY = 0, $borderType = $CV_BORDER_DEFAULT)
    ; CVAPI(void) cveGaussianBlur(cv::_InputArray* src, cv::_OutputArray* dst, CvSize* ksize, double sigmaX, double sigmaY, int borderType);

    Local $bSrcDllType
    If VarGetType($src) == "DLLStruct" Then
        $bSrcDllType = "struct*"
    Else
        $bSrcDllType = "ptr"
    EndIf

    Local $bDstDllType
    If VarGetType($dst) == "DLLStruct" Then
        $bDstDllType = "struct*"
    Else
        $bDstDllType = "ptr"
    EndIf

    Local $bKsizeDllType
    If VarGetType($ksize) == "DLLStruct" Then
        $bKsizeDllType = "struct*"
    Else
        $bKsizeDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveGaussianBlur", $bSrcDllType, $src, $bDstDllType, $dst, $bKsizeDllType, $ksize, "double", $sigmaX, "double", $sigmaY, "int", $borderType), "cveGaussianBlur", @error)
EndFunc   ;==>_cveGaussianBlur

Func _cveGaussianBlurMat($matSrc, $matDst, $ksize, $sigmaX, $sigmaY = 0, $borderType = $CV_BORDER_DEFAULT)
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

Func _cveBlur($src, $dst, $kSize, $anchor = _cvPoint(-1,-1), $borderType = $CV_BORDER_DEFAULT)
    ; CVAPI(void) cveBlur(cv::_InputArray* src, cv::_OutputArray* dst, CvSize* kSize, CvPoint* anchor, int borderType);

    Local $bSrcDllType
    If VarGetType($src) == "DLLStruct" Then
        $bSrcDllType = "struct*"
    Else
        $bSrcDllType = "ptr"
    EndIf

    Local $bDstDllType
    If VarGetType($dst) == "DLLStruct" Then
        $bDstDllType = "struct*"
    Else
        $bDstDllType = "ptr"
    EndIf

    Local $bKSizeDllType
    If VarGetType($kSize) == "DLLStruct" Then
        $bKSizeDllType = "struct*"
    Else
        $bKSizeDllType = "ptr"
    EndIf

    Local $bAnchorDllType
    If VarGetType($anchor) == "DLLStruct" Then
        $bAnchorDllType = "struct*"
    Else
        $bAnchorDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBlur", $bSrcDllType, $src, $bDstDllType, $dst, $bKSizeDllType, $kSize, $bAnchorDllType, $anchor, "int", $borderType), "cveBlur", @error)
EndFunc   ;==>_cveBlur

Func _cveBlurMat($matSrc, $matDst, $kSize, $anchor = _cvPoint(-1,-1), $borderType = $CV_BORDER_DEFAULT)
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

Func _cveMedianBlur($src, $dst, $ksize)
    ; CVAPI(void) cveMedianBlur(cv::_InputArray* src, cv::_OutputArray* dst, int ksize);

    Local $bSrcDllType
    If VarGetType($src) == "DLLStruct" Then
        $bSrcDllType = "struct*"
    Else
        $bSrcDllType = "ptr"
    EndIf

    Local $bDstDllType
    If VarGetType($dst) == "DLLStruct" Then
        $bDstDllType = "struct*"
    Else
        $bDstDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMedianBlur", $bSrcDllType, $src, $bDstDllType, $dst, "int", $ksize), "cveMedianBlur", @error)
EndFunc   ;==>_cveMedianBlur

Func _cveMedianBlurMat($matSrc, $matDst, $ksize)
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

Func _cveBoxFilter($src, $dst, $ddepth, $ksize, $anchor, $normailize, $borderType = $CV_BORDER_DEFAULT)
    ; CVAPI(void) cveBoxFilter(cv::_InputArray* src, cv::_OutputArray* dst, int ddepth, CvSize* ksize, CvPoint* anchor, bool normailize, int borderType);

    Local $bSrcDllType
    If VarGetType($src) == "DLLStruct" Then
        $bSrcDllType = "struct*"
    Else
        $bSrcDllType = "ptr"
    EndIf

    Local $bDstDllType
    If VarGetType($dst) == "DLLStruct" Then
        $bDstDllType = "struct*"
    Else
        $bDstDllType = "ptr"
    EndIf

    Local $bKsizeDllType
    If VarGetType($ksize) == "DLLStruct" Then
        $bKsizeDllType = "struct*"
    Else
        $bKsizeDllType = "ptr"
    EndIf

    Local $bAnchorDllType
    If VarGetType($anchor) == "DLLStruct" Then
        $bAnchorDllType = "struct*"
    Else
        $bAnchorDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBoxFilter", $bSrcDllType, $src, $bDstDllType, $dst, "int", $ddepth, $bKsizeDllType, $ksize, $bAnchorDllType, $anchor, "boolean", $normailize, "int", $borderType), "cveBoxFilter", @error)
EndFunc   ;==>_cveBoxFilter

Func _cveBoxFilterMat($matSrc, $matDst, $ddepth, $ksize, $anchor, $normailize, $borderType = $CV_BORDER_DEFAULT)
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

Func _cveSqrBoxFilter($_src, $_dst, $ddepth, $ksize, $anchor = _cvPoint(-1, -1), $normalize = true, $borderType = $CV_BORDER_DEFAULT)
    ; CVAPI(void) cveSqrBoxFilter(cv::_InputArray* _src, cv::_OutputArray* _dst, int ddepth, CvSize* ksize, CvPoint* anchor, bool normalize, int borderType);

    Local $b_srcDllType
    If VarGetType($_src) == "DLLStruct" Then
        $b_srcDllType = "struct*"
    Else
        $b_srcDllType = "ptr"
    EndIf

    Local $b_dstDllType
    If VarGetType($_dst) == "DLLStruct" Then
        $b_dstDllType = "struct*"
    Else
        $b_dstDllType = "ptr"
    EndIf

    Local $bKsizeDllType
    If VarGetType($ksize) == "DLLStruct" Then
        $bKsizeDllType = "struct*"
    Else
        $bKsizeDllType = "ptr"
    EndIf

    Local $bAnchorDllType
    If VarGetType($anchor) == "DLLStruct" Then
        $bAnchorDllType = "struct*"
    Else
        $bAnchorDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSqrBoxFilter", $b_srcDllType, $_src, $b_dstDllType, $_dst, "int", $ddepth, $bKsizeDllType, $ksize, $bAnchorDllType, $anchor, "boolean", $normalize, "int", $borderType), "cveSqrBoxFilter", @error)
EndFunc   ;==>_cveSqrBoxFilter

Func _cveSqrBoxFilterMat($mat_src, $mat_dst, $ddepth, $ksize, $anchor = _cvPoint(-1, -1), $normalize = true, $borderType = $CV_BORDER_DEFAULT)
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

Func _cveBilateralFilter($src, $dst, $d, $sigmaColor, $sigmaSpace, $borderType = $CV_BORDER_DEFAULT)
    ; CVAPI(void) cveBilateralFilter(cv::_InputArray* src, cv::_OutputArray* dst, int d, double sigmaColor, double sigmaSpace, int borderType);

    Local $bSrcDllType
    If VarGetType($src) == "DLLStruct" Then
        $bSrcDllType = "struct*"
    Else
        $bSrcDllType = "ptr"
    EndIf

    Local $bDstDllType
    If VarGetType($dst) == "DLLStruct" Then
        $bDstDllType = "struct*"
    Else
        $bDstDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBilateralFilter", $bSrcDllType, $src, $bDstDllType, $dst, "int", $d, "double", $sigmaColor, "double", $sigmaSpace, "int", $borderType), "cveBilateralFilter", @error)
EndFunc   ;==>_cveBilateralFilter

Func _cveBilateralFilterMat($matSrc, $matDst, $d, $sigmaColor, $sigmaSpace, $borderType = $CV_BORDER_DEFAULT)
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

Func _cveSubdiv2DCreate($rect)
    ; CVAPI(cv::Subdiv2D*) cveSubdiv2DCreate(CvRect* rect);

    Local $bRectDllType
    If VarGetType($rect) == "DLLStruct" Then
        $bRectDllType = "struct*"
    Else
        $bRectDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveSubdiv2DCreate", $bRectDllType, $rect), "cveSubdiv2DCreate", @error)
EndFunc   ;==>_cveSubdiv2DCreate

Func _cveSubdiv2DRelease($subdiv)
    ; CVAPI(void) cveSubdiv2DRelease(cv::Subdiv2D** subdiv);

    Local $bSubdivDllType
    If VarGetType($subdiv) == "DLLStruct" Then
        $bSubdivDllType = "struct*"
    Else
        $bSubdivDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSubdiv2DRelease", $bSubdivDllType, $subdiv), "cveSubdiv2DRelease", @error)
EndFunc   ;==>_cveSubdiv2DRelease

Func _cveSubdiv2DInsertMulti($subdiv, $points)
    ; CVAPI(void) cveSubdiv2DInsertMulti(cv::Subdiv2D* subdiv, std::vector<cv::Point2f>* points);

    Local $bSubdivDllType
    If VarGetType($subdiv) == "DLLStruct" Then
        $bSubdivDllType = "struct*"
    Else
        $bSubdivDllType = "ptr"
    EndIf

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

    Local $bPointsDllType
    If VarGetType($points) == "DLLStruct" Then
        $bPointsDllType = "struct*"
    Else
        $bPointsDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSubdiv2DInsertMulti", $bSubdivDllType, $subdiv, $bPointsDllType, $vecPoints), "cveSubdiv2DInsertMulti", @error)

    If $bPointsIsArray Then
        _VectorOfPointFRelease($vecPoints)
    EndIf
EndFunc   ;==>_cveSubdiv2DInsertMulti

Func _cveSubdiv2DInsertSingle($subdiv, $pt)
    ; CVAPI(int) cveSubdiv2DInsertSingle(cv::Subdiv2D* subdiv, CvPoint2D32f* pt);

    Local $bSubdivDllType
    If VarGetType($subdiv) == "DLLStruct" Then
        $bSubdivDllType = "struct*"
    Else
        $bSubdivDllType = "ptr"
    EndIf

    Local $bPtDllType
    If VarGetType($pt) == "DLLStruct" Then
        $bPtDllType = "struct*"
    Else
        $bPtDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveSubdiv2DInsertSingle", $bSubdivDllType, $subdiv, $bPtDllType, $pt), "cveSubdiv2DInsertSingle", @error)
EndFunc   ;==>_cveSubdiv2DInsertSingle

Func _cveSubdiv2DGetTriangleList($subdiv, $triangleList)
    ; CVAPI(void) cveSubdiv2DGetTriangleList(cv::Subdiv2D* subdiv, std::vector<cv::Vec6f>* triangleList);

    Local $bSubdivDllType
    If VarGetType($subdiv) == "DLLStruct" Then
        $bSubdivDllType = "struct*"
    Else
        $bSubdivDllType = "ptr"
    EndIf

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

    Local $bTriangleListDllType
    If VarGetType($triangleList) == "DLLStruct" Then
        $bTriangleListDllType = "struct*"
    Else
        $bTriangleListDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSubdiv2DGetTriangleList", $bSubdivDllType, $subdiv, $bTriangleListDllType, $vecTriangleList), "cveSubdiv2DGetTriangleList", @error)

    If $bTriangleListIsArray Then
        _VectorOfTriangle2DFRelease($vecTriangleList)
    EndIf
EndFunc   ;==>_cveSubdiv2DGetTriangleList

Func _cveSubdiv2DGetVoronoiFacetList($subdiv, $idx, $facetList, $facetCenters)
    ; CVAPI(void) cveSubdiv2DGetVoronoiFacetList(cv::Subdiv2D* subdiv, std::vector<int>* idx, std::vector< std::vector< cv::Point2f> >* facetList, std::vector< cv::Point2f >* facetCenters);

    Local $bSubdivDllType
    If VarGetType($subdiv) == "DLLStruct" Then
        $bSubdivDllType = "struct*"
    Else
        $bSubdivDllType = "ptr"
    EndIf

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

    Local $bIdxDllType
    If VarGetType($idx) == "DLLStruct" Then
        $bIdxDllType = "struct*"
    Else
        $bIdxDllType = "ptr"
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

    Local $bFacetListDllType
    If VarGetType($facetList) == "DLLStruct" Then
        $bFacetListDllType = "struct*"
    Else
        $bFacetListDllType = "ptr"
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

    Local $bFacetCentersDllType
    If VarGetType($facetCenters) == "DLLStruct" Then
        $bFacetCentersDllType = "struct*"
    Else
        $bFacetCentersDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSubdiv2DGetVoronoiFacetList", $bSubdivDllType, $subdiv, $bIdxDllType, $vecIdx, $bFacetListDllType, $vecFacetList, $bFacetCentersDllType, $vecFacetCenters), "cveSubdiv2DGetVoronoiFacetList", @error)

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

Func _cveSubdiv2DFindNearest($subdiv, $pt, $nearestPt)
    ; CVAPI(int) cveSubdiv2DFindNearest(cv::Subdiv2D* subdiv, CvPoint2D32f* pt, CvPoint2D32f* nearestPt);

    Local $bSubdivDllType
    If VarGetType($subdiv) == "DLLStruct" Then
        $bSubdivDllType = "struct*"
    Else
        $bSubdivDllType = "ptr"
    EndIf

    Local $bPtDllType
    If VarGetType($pt) == "DLLStruct" Then
        $bPtDllType = "struct*"
    Else
        $bPtDllType = "ptr"
    EndIf

    Local $bNearestPtDllType
    If VarGetType($nearestPt) == "DLLStruct" Then
        $bNearestPtDllType = "struct*"
    Else
        $bNearestPtDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveSubdiv2DFindNearest", $bSubdivDllType, $subdiv, $bPtDllType, $pt, $bNearestPtDllType, $nearestPt), "cveSubdiv2DFindNearest", @error)
EndFunc   ;==>_cveSubdiv2DFindNearest

Func _cveSubdiv2DLocate($subdiv, $pt, $edge, $vertex)
    ; CVAPI(int) cveSubdiv2DLocate(cv::Subdiv2D* subdiv, CvPoint2D32f* pt, int* edge, int* vertex);

    Local $bSubdivDllType
    If VarGetType($subdiv) == "DLLStruct" Then
        $bSubdivDllType = "struct*"
    Else
        $bSubdivDllType = "ptr"
    EndIf

    Local $bPtDllType
    If VarGetType($pt) == "DLLStruct" Then
        $bPtDllType = "struct*"
    Else
        $bPtDllType = "ptr"
    EndIf

    Local $bEdgeDllType
    If VarGetType($edge) == "DLLStruct" Then
        $bEdgeDllType = "struct*"
    Else
        $bEdgeDllType = "int*"
    EndIf

    Local $bVertexDllType
    If VarGetType($vertex) == "DLLStruct" Then
        $bVertexDllType = "struct*"
    Else
        $bVertexDllType = "int*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveSubdiv2DLocate", $bSubdivDllType, $subdiv, $bPtDllType, $pt, $bEdgeDllType, $edge, $bVertexDllType, $vertex), "cveSubdiv2DLocate", @error)
EndFunc   ;==>_cveSubdiv2DLocate

Func _cveLineIteratorCreate($img, $pt1, $pt2, $connectivity, $leftToRight)
    ; CVAPI(cv::LineIterator*) cveLineIteratorCreate(cv::Mat* img, CvPoint* pt1, CvPoint* pt2, int connectivity, bool leftToRight);

    Local $bImgDllType
    If VarGetType($img) == "DLLStruct" Then
        $bImgDllType = "struct*"
    Else
        $bImgDllType = "ptr"
    EndIf

    Local $bPt1DllType
    If VarGetType($pt1) == "DLLStruct" Then
        $bPt1DllType = "struct*"
    Else
        $bPt1DllType = "ptr"
    EndIf

    Local $bPt2DllType
    If VarGetType($pt2) == "DLLStruct" Then
        $bPt2DllType = "struct*"
    Else
        $bPt2DllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveLineIteratorCreate", $bImgDllType, $img, $bPt1DllType, $pt1, $bPt2DllType, $pt2, "int", $connectivity, "boolean", $leftToRight), "cveLineIteratorCreate", @error)
EndFunc   ;==>_cveLineIteratorCreate

Func _cveLineIteratorGetDataPointer($iterator)
    ; CVAPI(uchar*) cveLineIteratorGetDataPointer(cv::LineIterator* iterator);

    Local $bIteratorDllType
    If VarGetType($iterator) == "DLLStruct" Then
        $bIteratorDllType = "struct*"
    Else
        $bIteratorDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveLineIteratorGetDataPointer", $bIteratorDllType, $iterator), "cveLineIteratorGetDataPointer", @error)
EndFunc   ;==>_cveLineIteratorGetDataPointer

Func _cveLineIteratorPos($iterator, $pos)
    ; CVAPI(void) cveLineIteratorPos(cv::LineIterator* iterator, CvPoint* pos);

    Local $bIteratorDllType
    If VarGetType($iterator) == "DLLStruct" Then
        $bIteratorDllType = "struct*"
    Else
        $bIteratorDllType = "ptr"
    EndIf

    Local $bPosDllType
    If VarGetType($pos) == "DLLStruct" Then
        $bPosDllType = "struct*"
    Else
        $bPosDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveLineIteratorPos", $bIteratorDllType, $iterator, $bPosDllType, $pos), "cveLineIteratorPos", @error)
EndFunc   ;==>_cveLineIteratorPos

Func _cveLineIteratorMoveNext($iterator)
    ; CVAPI(void) cveLineIteratorMoveNext(cv::LineIterator* iterator);

    Local $bIteratorDllType
    If VarGetType($iterator) == "DLLStruct" Then
        $bIteratorDllType = "struct*"
    Else
        $bIteratorDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveLineIteratorMoveNext", $bIteratorDllType, $iterator), "cveLineIteratorMoveNext", @error)
EndFunc   ;==>_cveLineIteratorMoveNext

Func _cveLineIteratorRelease($iterator)
    ; CVAPI(void) cveLineIteratorRelease(cv::LineIterator** iterator);

    Local $bIteratorDllType
    If VarGetType($iterator) == "DLLStruct" Then
        $bIteratorDllType = "struct*"
    Else
        $bIteratorDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveLineIteratorRelease", $bIteratorDllType, $iterator), "cveLineIteratorRelease", @error)
EndFunc   ;==>_cveLineIteratorRelease

Func _cveLineIteratorSampleLine($img, $pt1, $pt2, $connectivity, $leftToRight, $result)
    ; CVAPI(void) cveLineIteratorSampleLine(cv::Mat* img, CvPoint* pt1, CvPoint* pt2, int connectivity, bool leftToRight, cv::Mat* result);

    Local $bImgDllType
    If VarGetType($img) == "DLLStruct" Then
        $bImgDllType = "struct*"
    Else
        $bImgDllType = "ptr"
    EndIf

    Local $bPt1DllType
    If VarGetType($pt1) == "DLLStruct" Then
        $bPt1DllType = "struct*"
    Else
        $bPt1DllType = "ptr"
    EndIf

    Local $bPt2DllType
    If VarGetType($pt2) == "DLLStruct" Then
        $bPt2DllType = "struct*"
    Else
        $bPt2DllType = "ptr"
    EndIf

    Local $bResultDllType
    If VarGetType($result) == "DLLStruct" Then
        $bResultDllType = "struct*"
    Else
        $bResultDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveLineIteratorSampleLine", $bImgDllType, $img, $bPt1DllType, $pt1, $bPt2DllType, $pt2, "int", $connectivity, "boolean", $leftToRight, $bResultDllType, $result), "cveLineIteratorSampleLine", @error)
EndFunc   ;==>_cveLineIteratorSampleLine

Func _cveLine($img, $p1, $p2, $color, $thickness = 1, $lineType = $CV_LINE_8, $shift = 0)
    ; CVAPI(void) cveLine(cv::_InputOutputArray* img, CvPoint* p1, CvPoint* p2, CvScalar* color, int thickness, int lineType, int shift);

    Local $bImgDllType
    If VarGetType($img) == "DLLStruct" Then
        $bImgDllType = "struct*"
    Else
        $bImgDllType = "ptr"
    EndIf

    Local $bP1DllType
    If VarGetType($p1) == "DLLStruct" Then
        $bP1DllType = "struct*"
    Else
        $bP1DllType = "ptr"
    EndIf

    Local $bP2DllType
    If VarGetType($p2) == "DLLStruct" Then
        $bP2DllType = "struct*"
    Else
        $bP2DllType = "ptr"
    EndIf

    Local $bColorDllType
    If VarGetType($color) == "DLLStruct" Then
        $bColorDllType = "struct*"
    Else
        $bColorDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveLine", $bImgDllType, $img, $bP1DllType, $p1, $bP2DllType, $p2, $bColorDllType, $color, "int", $thickness, "int", $lineType, "int", $shift), "cveLine", @error)
EndFunc   ;==>_cveLine

Func _cveLineMat($matImg, $p1, $p2, $color, $thickness = 1, $lineType = $CV_LINE_8, $shift = 0)
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

Func _cveArrowedLine($img, $pt1, $pt2, $color, $thickness, $lineType, $shift = 0, $tipLength = 0.1)
    ; CVAPI(void) cveArrowedLine(cv::_InputOutputArray* img, CvPoint* pt1, CvPoint* pt2, CvScalar* color, int thickness, int lineType, int shift, double tipLength);

    Local $bImgDllType
    If VarGetType($img) == "DLLStruct" Then
        $bImgDllType = "struct*"
    Else
        $bImgDllType = "ptr"
    EndIf

    Local $bPt1DllType
    If VarGetType($pt1) == "DLLStruct" Then
        $bPt1DllType = "struct*"
    Else
        $bPt1DllType = "ptr"
    EndIf

    Local $bPt2DllType
    If VarGetType($pt2) == "DLLStruct" Then
        $bPt2DllType = "struct*"
    Else
        $bPt2DllType = "ptr"
    EndIf

    Local $bColorDllType
    If VarGetType($color) == "DLLStruct" Then
        $bColorDllType = "struct*"
    Else
        $bColorDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveArrowedLine", $bImgDllType, $img, $bPt1DllType, $pt1, $bPt2DllType, $pt2, $bColorDllType, $color, "int", $thickness, "int", $lineType, "int", $shift, "double", $tipLength), "cveArrowedLine", @error)
EndFunc   ;==>_cveArrowedLine

Func _cveArrowedLineMat($matImg, $pt1, $pt2, $color, $thickness, $lineType, $shift = 0, $tipLength = 0.1)
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

Func _cveRectangle($img, $rect, $color, $thickness = 1, $lineType = $CV_LINE_8, $shift = 0)
    ; CVAPI(void) cveRectangle(cv::_InputOutputArray* img, CvRect* rect, CvScalar* color, int thickness, int lineType, int shift);

    Local $bImgDllType
    If VarGetType($img) == "DLLStruct" Then
        $bImgDllType = "struct*"
    Else
        $bImgDllType = "ptr"
    EndIf

    Local $bRectDllType
    If VarGetType($rect) == "DLLStruct" Then
        $bRectDllType = "struct*"
    Else
        $bRectDllType = "ptr"
    EndIf

    Local $bColorDllType
    If VarGetType($color) == "DLLStruct" Then
        $bColorDllType = "struct*"
    Else
        $bColorDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveRectangle", $bImgDllType, $img, $bRectDllType, $rect, $bColorDllType, $color, "int", $thickness, "int", $lineType, "int", $shift), "cveRectangle", @error)
EndFunc   ;==>_cveRectangle

Func _cveRectangleMat($matImg, $rect, $color, $thickness = 1, $lineType = $CV_LINE_8, $shift = 0)
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

Func _cveCircle($img, $center, $radius, $color, $thickness = 1, $lineType = $CV_LINE_8, $shift = 0)
    ; CVAPI(void) cveCircle(cv::_InputOutputArray* img, CvPoint* center, int radius, CvScalar* color, int thickness, int lineType, int shift);

    Local $bImgDllType
    If VarGetType($img) == "DLLStruct" Then
        $bImgDllType = "struct*"
    Else
        $bImgDllType = "ptr"
    EndIf

    Local $bCenterDllType
    If VarGetType($center) == "DLLStruct" Then
        $bCenterDllType = "struct*"
    Else
        $bCenterDllType = "ptr"
    EndIf

    Local $bColorDllType
    If VarGetType($color) == "DLLStruct" Then
        $bColorDllType = "struct*"
    Else
        $bColorDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCircle", $bImgDllType, $img, $bCenterDllType, $center, "int", $radius, $bColorDllType, $color, "int", $thickness, "int", $lineType, "int", $shift), "cveCircle", @error)
EndFunc   ;==>_cveCircle

Func _cveCircleMat($matImg, $center, $radius, $color, $thickness = 1, $lineType = $CV_LINE_8, $shift = 0)
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

Func _cvePutText($img, $text, $org, $fontFace, $fontScale, $color, $thickness = 1, $lineType = $CV_LINE_8, $bottomLeftOrigin = false)
    ; CVAPI(void) cvePutText(cv::_InputOutputArray* img, cv::String* text, CvPoint* org, int fontFace, double fontScale, CvScalar* color, int thickness, int lineType, bool bottomLeftOrigin);

    Local $bImgDllType
    If VarGetType($img) == "DLLStruct" Then
        $bImgDllType = "struct*"
    Else
        $bImgDllType = "ptr"
    EndIf

    Local $bTextIsString = VarGetType($text) == "String"
    If $bTextIsString Then
        $text = _cveStringCreateFromStr($text)
    EndIf

    Local $bTextDllType
    If VarGetType($text) == "DLLStruct" Then
        $bTextDllType = "struct*"
    Else
        $bTextDllType = "ptr"
    EndIf

    Local $bOrgDllType
    If VarGetType($org) == "DLLStruct" Then
        $bOrgDllType = "struct*"
    Else
        $bOrgDllType = "ptr"
    EndIf

    Local $bColorDllType
    If VarGetType($color) == "DLLStruct" Then
        $bColorDllType = "struct*"
    Else
        $bColorDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cvePutText", $bImgDllType, $img, $bTextDllType, $text, $bOrgDllType, $org, "int", $fontFace, "double", $fontScale, $bColorDllType, $color, "int", $thickness, "int", $lineType, "boolean", $bottomLeftOrigin), "cvePutText", @error)

    If $bTextIsString Then
        _cveStringRelease($text)
    EndIf
EndFunc   ;==>_cvePutText

Func _cvePutTextMat($matImg, $text, $org, $fontFace, $fontScale, $color, $thickness = 1, $lineType = $CV_LINE_8, $bottomLeftOrigin = false)
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

Func _cveGetTextSize($text, $fontFace, $fontScale, $thickness, $baseLine, $size)
    ; CVAPI(void) cveGetTextSize(cv::String* text, int fontFace, double fontScale, int thickness, int* baseLine, CvSize* size);

    Local $bTextIsString = VarGetType($text) == "String"
    If $bTextIsString Then
        $text = _cveStringCreateFromStr($text)
    EndIf

    Local $bTextDllType
    If VarGetType($text) == "DLLStruct" Then
        $bTextDllType = "struct*"
    Else
        $bTextDllType = "ptr"
    EndIf

    Local $bBaseLineDllType
    If VarGetType($baseLine) == "DLLStruct" Then
        $bBaseLineDllType = "struct*"
    Else
        $bBaseLineDllType = "int*"
    EndIf

    Local $bSizeDllType
    If VarGetType($size) == "DLLStruct" Then
        $bSizeDllType = "struct*"
    Else
        $bSizeDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveGetTextSize", $bTextDllType, $text, "int", $fontFace, "double", $fontScale, "int", $thickness, $bBaseLineDllType, $baseLine, $bSizeDllType, $size), "cveGetTextSize", @error)

    If $bTextIsString Then
        _cveStringRelease($text)
    EndIf
EndFunc   ;==>_cveGetTextSize

Func _cveFillConvexPoly($img, $points, $color, $lineType = $CV_LINE_8, $shift = 0)
    ; CVAPI(void) cveFillConvexPoly(cv::_InputOutputArray* img, cv::_InputArray* points, const CvScalar* color, int lineType, int shift);

    Local $bImgDllType
    If VarGetType($img) == "DLLStruct" Then
        $bImgDllType = "struct*"
    Else
        $bImgDllType = "ptr"
    EndIf

    Local $bPointsDllType
    If VarGetType($points) == "DLLStruct" Then
        $bPointsDllType = "struct*"
    Else
        $bPointsDllType = "ptr"
    EndIf

    Local $bColorDllType
    If VarGetType($color) == "DLLStruct" Then
        $bColorDllType = "struct*"
    Else
        $bColorDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFillConvexPoly", $bImgDllType, $img, $bPointsDllType, $points, $bColorDllType, $color, "int", $lineType, "int", $shift), "cveFillConvexPoly", @error)
EndFunc   ;==>_cveFillConvexPoly

Func _cveFillConvexPolyMat($matImg, $matPoints, $color, $lineType = $CV_LINE_8, $shift = 0)
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

Func _cveFillPoly($img, $pts, $color, $lineType = $CV_LINE_8, $shift = 0, $offset = _cvPoint())
    ; CVAPI(void) cveFillPoly(cv::_InputOutputArray* img, cv::_InputArray* pts, const CvScalar* color, int lineType, int shift, CvPoint* offset);

    Local $bImgDllType
    If VarGetType($img) == "DLLStruct" Then
        $bImgDllType = "struct*"
    Else
        $bImgDllType = "ptr"
    EndIf

    Local $bPtsDllType
    If VarGetType($pts) == "DLLStruct" Then
        $bPtsDllType = "struct*"
    Else
        $bPtsDllType = "ptr"
    EndIf

    Local $bColorDllType
    If VarGetType($color) == "DLLStruct" Then
        $bColorDllType = "struct*"
    Else
        $bColorDllType = "ptr"
    EndIf

    Local $bOffsetDllType
    If VarGetType($offset) == "DLLStruct" Then
        $bOffsetDllType = "struct*"
    Else
        $bOffsetDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFillPoly", $bImgDllType, $img, $bPtsDllType, $pts, $bColorDllType, $color, "int", $lineType, "int", $shift, $bOffsetDllType, $offset), "cveFillPoly", @error)
EndFunc   ;==>_cveFillPoly

Func _cveFillPolyMat($matImg, $matPts, $color, $lineType = $CV_LINE_8, $shift = 0, $offset = _cvPoint())
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

Func _cvePolylines($img, $pts, $isClosed, $color, $thickness = 1, $lineType = $CV_LINE_8, $shift = 0)
    ; CVAPI(void) cvePolylines(cv::_InputOutputArray* img, cv::_InputArray* pts, bool isClosed, const CvScalar* color, int thickness, int lineType, int shift);

    Local $bImgDllType
    If VarGetType($img) == "DLLStruct" Then
        $bImgDllType = "struct*"
    Else
        $bImgDllType = "ptr"
    EndIf

    Local $bPtsDllType
    If VarGetType($pts) == "DLLStruct" Then
        $bPtsDllType = "struct*"
    Else
        $bPtsDllType = "ptr"
    EndIf

    Local $bColorDllType
    If VarGetType($color) == "DLLStruct" Then
        $bColorDllType = "struct*"
    Else
        $bColorDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cvePolylines", $bImgDllType, $img, $bPtsDllType, $pts, "boolean", $isClosed, $bColorDllType, $color, "int", $thickness, "int", $lineType, "int", $shift), "cvePolylines", @error)
EndFunc   ;==>_cvePolylines

Func _cvePolylinesMat($matImg, $matPts, $isClosed, $color, $thickness = 1, $lineType = $CV_LINE_8, $shift = 0)
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

Func _cveEllipse($img, $center, $axes, $angle, $startAngle, $endAngle, $color, $thickness = 1, $lineType = $CV_LINE_8, $shift = 0)
    ; CVAPI(void) cveEllipse(cv::_InputOutputArray* img, CvPoint* center, CvSize* axes, double angle, double startAngle, double endAngle, const CvScalar* color, int thickness, int lineType, int shift);

    Local $bImgDllType
    If VarGetType($img) == "DLLStruct" Then
        $bImgDllType = "struct*"
    Else
        $bImgDllType = "ptr"
    EndIf

    Local $bCenterDllType
    If VarGetType($center) == "DLLStruct" Then
        $bCenterDllType = "struct*"
    Else
        $bCenterDllType = "ptr"
    EndIf

    Local $bAxesDllType
    If VarGetType($axes) == "DLLStruct" Then
        $bAxesDllType = "struct*"
    Else
        $bAxesDllType = "ptr"
    EndIf

    Local $bColorDllType
    If VarGetType($color) == "DLLStruct" Then
        $bColorDllType = "struct*"
    Else
        $bColorDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveEllipse", $bImgDllType, $img, $bCenterDllType, $center, $bAxesDllType, $axes, "double", $angle, "double", $startAngle, "double", $endAngle, $bColorDllType, $color, "int", $thickness, "int", $lineType, "int", $shift), "cveEllipse", @error)
EndFunc   ;==>_cveEllipse

Func _cveEllipseMat($matImg, $center, $axes, $angle, $startAngle, $endAngle, $color, $thickness = 1, $lineType = $CV_LINE_8, $shift = 0)
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

Func _cveDrawMarker($img, $position, $color, $markerType, $markerSize, $thickness, $lineType)
    ; CVAPI(void) cveDrawMarker(cv::_InputOutputArray* img, CvPoint* position, CvScalar* color, int markerType, int markerSize, int thickness, int lineType);

    Local $bImgDllType
    If VarGetType($img) == "DLLStruct" Then
        $bImgDllType = "struct*"
    Else
        $bImgDllType = "ptr"
    EndIf

    Local $bPositionDllType
    If VarGetType($position) == "DLLStruct" Then
        $bPositionDllType = "struct*"
    Else
        $bPositionDllType = "ptr"
    EndIf

    Local $bColorDllType
    If VarGetType($color) == "DLLStruct" Then
        $bColorDllType = "struct*"
    Else
        $bColorDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDrawMarker", $bImgDllType, $img, $bPositionDllType, $position, $bColorDllType, $color, "int", $markerType, "int", $markerSize, "int", $thickness, "int", $lineType), "cveDrawMarker", @error)
EndFunc   ;==>_cveDrawMarker

Func _cveDrawMarkerMat($matImg, $position, $color, $markerType, $markerSize, $thickness, $lineType)
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

Func _cveApplyColorMap1($src, $dst, $colorMap)
    ; CVAPI(void) cveApplyColorMap1(cv::_InputArray* src, cv::_OutputArray* dst, int colorMap);

    Local $bSrcDllType
    If VarGetType($src) == "DLLStruct" Then
        $bSrcDllType = "struct*"
    Else
        $bSrcDllType = "ptr"
    EndIf

    Local $bDstDllType
    If VarGetType($dst) == "DLLStruct" Then
        $bDstDllType = "struct*"
    Else
        $bDstDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveApplyColorMap1", $bSrcDllType, $src, $bDstDllType, $dst, "int", $colorMap), "cveApplyColorMap1", @error)
EndFunc   ;==>_cveApplyColorMap1

Func _cveApplyColorMap1Mat($matSrc, $matDst, $colorMap)
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

Func _cveApplyColorMap2($src, $dst, $userColorMap)
    ; CVAPI(void) cveApplyColorMap2(cv::_InputArray* src, cv::_OutputArray* dst, cv::_InputArray userColorMap);

    Local $bSrcDllType
    If VarGetType($src) == "DLLStruct" Then
        $bSrcDllType = "struct*"
    Else
        $bSrcDllType = "ptr"
    EndIf

    Local $bDstDllType
    If VarGetType($dst) == "DLLStruct" Then
        $bDstDllType = "struct*"
    Else
        $bDstDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveApplyColorMap2", $bSrcDllType, $src, $bDstDllType, $dst, "cv::_InputArray", $userColorMap), "cveApplyColorMap2", @error)
EndFunc   ;==>_cveApplyColorMap2

Func _cveApplyColorMap2Mat($matSrc, $matDst, $userColorMap)
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

Func _cveDistanceTransform($src, $dst, $labels, $distanceType, $maskSize, $labelType)
    ; CVAPI(void) cveDistanceTransform(cv::_InputArray* src, cv::_OutputArray* dst, cv::_OutputArray* labels, int distanceType, int maskSize, int labelType);

    Local $bSrcDllType
    If VarGetType($src) == "DLLStruct" Then
        $bSrcDllType = "struct*"
    Else
        $bSrcDllType = "ptr"
    EndIf

    Local $bDstDllType
    If VarGetType($dst) == "DLLStruct" Then
        $bDstDllType = "struct*"
    Else
        $bDstDllType = "ptr"
    EndIf

    Local $bLabelsDllType
    If VarGetType($labels) == "DLLStruct" Then
        $bLabelsDllType = "struct*"
    Else
        $bLabelsDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDistanceTransform", $bSrcDllType, $src, $bDstDllType, $dst, $bLabelsDllType, $labels, "int", $distanceType, "int", $maskSize, "int", $labelType), "cveDistanceTransform", @error)
EndFunc   ;==>_cveDistanceTransform

Func _cveDistanceTransformMat($matSrc, $matDst, $matLabels, $distanceType, $maskSize, $labelType)
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

Func _cveGetRectSubPix($image, $patchSize, $center, $patch, $patchType = -1)
    ; CVAPI(void) cveGetRectSubPix(cv::_InputArray* image, CvSize* patchSize, CvPoint2D32f* center, cv::_OutputArray* patch, int patchType);

    Local $bImageDllType
    If VarGetType($image) == "DLLStruct" Then
        $bImageDllType = "struct*"
    Else
        $bImageDllType = "ptr"
    EndIf

    Local $bPatchSizeDllType
    If VarGetType($patchSize) == "DLLStruct" Then
        $bPatchSizeDllType = "struct*"
    Else
        $bPatchSizeDllType = "ptr"
    EndIf

    Local $bCenterDllType
    If VarGetType($center) == "DLLStruct" Then
        $bCenterDllType = "struct*"
    Else
        $bCenterDllType = "ptr"
    EndIf

    Local $bPatchDllType
    If VarGetType($patch) == "DLLStruct" Then
        $bPatchDllType = "struct*"
    Else
        $bPatchDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveGetRectSubPix", $bImageDllType, $image, $bPatchSizeDllType, $patchSize, $bCenterDllType, $center, $bPatchDllType, $patch, "int", $patchType), "cveGetRectSubPix", @error)
EndFunc   ;==>_cveGetRectSubPix

Func _cveGetRectSubPixMat($matImage, $patchSize, $center, $matPatch, $patchType = -1)
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

Func _cveHuMoments($moments, $hu)
    ; CVAPI(void) cveHuMoments(cv::Moments* moments, cv::_OutputArray* hu);

    Local $bMomentsDllType
    If VarGetType($moments) == "DLLStruct" Then
        $bMomentsDllType = "struct*"
    Else
        $bMomentsDllType = "ptr"
    EndIf

    Local $bHuDllType
    If VarGetType($hu) == "DLLStruct" Then
        $bHuDllType = "struct*"
    Else
        $bHuDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveHuMoments", $bMomentsDllType, $moments, $bHuDllType, $hu), "cveHuMoments", @error)
EndFunc   ;==>_cveHuMoments

Func _cveHuMomentsMat($moments, $matHu)
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

Func _cveHuMoments2($moments, $hu)
    ; CVAPI(void) cveHuMoments2(cv::Moments* moments, double* hu);

    Local $bMomentsDllType
    If VarGetType($moments) == "DLLStruct" Then
        $bMomentsDllType = "struct*"
    Else
        $bMomentsDllType = "ptr"
    EndIf

    Local $bHuDllType
    If VarGetType($hu) == "DLLStruct" Then
        $bHuDllType = "struct*"
    Else
        $bHuDllType = "double*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveHuMoments2", $bMomentsDllType, $moments, $bHuDllType, $hu), "cveHuMoments2", @error)
EndFunc   ;==>_cveHuMoments2

Func _cveMaxRect($rect1, $rect2, $result)
    ; CVAPI(void) cveMaxRect(CvRect* rect1, CvRect* rect2, CvRect* result);

    Local $bRect1DllType
    If VarGetType($rect1) == "DLLStruct" Then
        $bRect1DllType = "struct*"
    Else
        $bRect1DllType = "ptr"
    EndIf

    Local $bRect2DllType
    If VarGetType($rect2) == "DLLStruct" Then
        $bRect2DllType = "struct*"
    Else
        $bRect2DllType = "ptr"
    EndIf

    Local $bResultDllType
    If VarGetType($result) == "DLLStruct" Then
        $bResultDllType = "struct*"
    Else
        $bResultDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMaxRect", $bRect1DllType, $rect1, $bRect2DllType, $rect2, $bResultDllType, $result), "cveMaxRect", @error)
EndFunc   ;==>_cveMaxRect

Func _cveConnectedComponents($image, $labels, $connectivity, $ltype, $ccltype)
    ; CVAPI(int) cveConnectedComponents(cv::_InputArray* image, cv::_OutputArray* labels, int connectivity, int ltype, int ccltype);

    Local $bImageDllType
    If VarGetType($image) == "DLLStruct" Then
        $bImageDllType = "struct*"
    Else
        $bImageDllType = "ptr"
    EndIf

    Local $bLabelsDllType
    If VarGetType($labels) == "DLLStruct" Then
        $bLabelsDllType = "struct*"
    Else
        $bLabelsDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveConnectedComponents", $bImageDllType, $image, $bLabelsDllType, $labels, "int", $connectivity, "int", $ltype, "int", $ccltype), "cveConnectedComponents", @error)
EndFunc   ;==>_cveConnectedComponents

Func _cveConnectedComponentsMat($matImage, $matLabels, $connectivity, $ltype, $ccltype)
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

Func _cveConnectedComponentsWithStats($image, $labels, $stats, $centroids, $connectivity, $ltype, $ccltype)
    ; CVAPI(int) cveConnectedComponentsWithStats(cv::_InputArray* image, cv::_OutputArray* labels, cv::_OutputArray* stats, cv::_OutputArray* centroids, int connectivity, int ltype, int ccltype);

    Local $bImageDllType
    If VarGetType($image) == "DLLStruct" Then
        $bImageDllType = "struct*"
    Else
        $bImageDllType = "ptr"
    EndIf

    Local $bLabelsDllType
    If VarGetType($labels) == "DLLStruct" Then
        $bLabelsDllType = "struct*"
    Else
        $bLabelsDllType = "ptr"
    EndIf

    Local $bStatsDllType
    If VarGetType($stats) == "DLLStruct" Then
        $bStatsDllType = "struct*"
    Else
        $bStatsDllType = "ptr"
    EndIf

    Local $bCentroidsDllType
    If VarGetType($centroids) == "DLLStruct" Then
        $bCentroidsDllType = "struct*"
    Else
        $bCentroidsDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveConnectedComponentsWithStats", $bImageDllType, $image, $bLabelsDllType, $labels, $bStatsDllType, $stats, $bCentroidsDllType, $centroids, "int", $connectivity, "int", $ltype, "int", $ccltype), "cveConnectedComponentsWithStats", @error)
EndFunc   ;==>_cveConnectedComponentsWithStats

Func _cveConnectedComponentsWithStatsMat($matImage, $matLabels, $matStats, $matCentroids, $connectivity, $ltype, $ccltype)
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

Func _cveIntelligentScissorsMBRelease($ptr)
    ; CVAPI(void) cveIntelligentScissorsMBRelease(cv::segmentation::IntelligentScissorsMB** ptr);

    Local $bPtrDllType
    If VarGetType($ptr) == "DLLStruct" Then
        $bPtrDllType = "struct*"
    Else
        $bPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveIntelligentScissorsMBRelease", $bPtrDllType, $ptr), "cveIntelligentScissorsMBRelease", @error)
EndFunc   ;==>_cveIntelligentScissorsMBRelease

Func _cveIntelligentScissorsMBSetWeights($ptr, $weightNonEdge, $weightGradientDirection, $weightGradientMagnitude)
    ; CVAPI(void) cveIntelligentScissorsMBSetWeights(cv::segmentation::IntelligentScissorsMB* ptr, float weightNonEdge, float weightGradientDirection, float weightGradientMagnitude);

    Local $bPtrDllType
    If VarGetType($ptr) == "DLLStruct" Then
        $bPtrDllType = "struct*"
    Else
        $bPtrDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveIntelligentScissorsMBSetWeights", $bPtrDllType, $ptr, "float", $weightNonEdge, "float", $weightGradientDirection, "float", $weightGradientMagnitude), "cveIntelligentScissorsMBSetWeights", @error)
EndFunc   ;==>_cveIntelligentScissorsMBSetWeights

Func _cveIntelligentScissorsMBSetEdgeFeatureCannyParameters($ptr, $threshold1, $threshold2, $apertureSize, $L2gradient)
    ; CVAPI(void) cveIntelligentScissorsMBSetEdgeFeatureCannyParameters(cv::segmentation::IntelligentScissorsMB* ptr, double threshold1, double threshold2, int apertureSize, bool L2gradient);

    Local $bPtrDllType
    If VarGetType($ptr) == "DLLStruct" Then
        $bPtrDllType = "struct*"
    Else
        $bPtrDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveIntelligentScissorsMBSetEdgeFeatureCannyParameters", $bPtrDllType, $ptr, "double", $threshold1, "double", $threshold2, "int", $apertureSize, "boolean", $L2gradient), "cveIntelligentScissorsMBSetEdgeFeatureCannyParameters", @error)
EndFunc   ;==>_cveIntelligentScissorsMBSetEdgeFeatureCannyParameters

Func _cveIntelligentScissorsMBApplyImage($ptr, $image)
    ; CVAPI(void) cveIntelligentScissorsMBApplyImage(cv::segmentation::IntelligentScissorsMB* ptr, cv::_InputArray* image);

    Local $bPtrDllType
    If VarGetType($ptr) == "DLLStruct" Then
        $bPtrDllType = "struct*"
    Else
        $bPtrDllType = "ptr"
    EndIf

    Local $bImageDllType
    If VarGetType($image) == "DLLStruct" Then
        $bImageDllType = "struct*"
    Else
        $bImageDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveIntelligentScissorsMBApplyImage", $bPtrDllType, $ptr, $bImageDllType, $image), "cveIntelligentScissorsMBApplyImage", @error)
EndFunc   ;==>_cveIntelligentScissorsMBApplyImage

Func _cveIntelligentScissorsMBApplyImageMat($ptr, $matImage)
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

Func _cveIntelligentScissorsMBApplyImageFeatures($ptr, $nonEdge, $gradientDirection, $gradientMagnitude, $image)
    ; CVAPI(void) cveIntelligentScissorsMBApplyImageFeatures(cv::segmentation::IntelligentScissorsMB* ptr, cv::_InputArray* nonEdge, cv::_InputArray* gradientDirection, cv::_InputArray* gradientMagnitude, cv::_InputArray* image);

    Local $bPtrDllType
    If VarGetType($ptr) == "DLLStruct" Then
        $bPtrDllType = "struct*"
    Else
        $bPtrDllType = "ptr"
    EndIf

    Local $bNonEdgeDllType
    If VarGetType($nonEdge) == "DLLStruct" Then
        $bNonEdgeDllType = "struct*"
    Else
        $bNonEdgeDllType = "ptr"
    EndIf

    Local $bGradientDirectionDllType
    If VarGetType($gradientDirection) == "DLLStruct" Then
        $bGradientDirectionDllType = "struct*"
    Else
        $bGradientDirectionDllType = "ptr"
    EndIf

    Local $bGradientMagnitudeDllType
    If VarGetType($gradientMagnitude) == "DLLStruct" Then
        $bGradientMagnitudeDllType = "struct*"
    Else
        $bGradientMagnitudeDllType = "ptr"
    EndIf

    Local $bImageDllType
    If VarGetType($image) == "DLLStruct" Then
        $bImageDllType = "struct*"
    Else
        $bImageDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveIntelligentScissorsMBApplyImageFeatures", $bPtrDllType, $ptr, $bNonEdgeDllType, $nonEdge, $bGradientDirectionDllType, $gradientDirection, $bGradientMagnitudeDllType, $gradientMagnitude, $bImageDllType, $image), "cveIntelligentScissorsMBApplyImageFeatures", @error)
EndFunc   ;==>_cveIntelligentScissorsMBApplyImageFeatures

Func _cveIntelligentScissorsMBApplyImageFeaturesMat($ptr, $matNonEdge, $matGradientDirection, $matGradientMagnitude, $matImage)
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

Func _cveIntelligentScissorsMBBuildMap($ptr, $sourcePt)
    ; CVAPI(void) cveIntelligentScissorsMBBuildMap(cv::segmentation::IntelligentScissorsMB* ptr, CvPoint* sourcePt);

    Local $bPtrDllType
    If VarGetType($ptr) == "DLLStruct" Then
        $bPtrDllType = "struct*"
    Else
        $bPtrDllType = "ptr"
    EndIf

    Local $bSourcePtDllType
    If VarGetType($sourcePt) == "DLLStruct" Then
        $bSourcePtDllType = "struct*"
    Else
        $bSourcePtDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveIntelligentScissorsMBBuildMap", $bPtrDllType, $ptr, $bSourcePtDllType, $sourcePt), "cveIntelligentScissorsMBBuildMap", @error)
EndFunc   ;==>_cveIntelligentScissorsMBBuildMap

Func _cveIntelligentScissorsMBGetContour($ptr, $targetPt, $contour, $backward)
    ; CVAPI(void) cveIntelligentScissorsMBGetContour(cv::segmentation::IntelligentScissorsMB* ptr, CvPoint* targetPt, cv::_OutputArray* contour, bool backward);

    Local $bPtrDllType
    If VarGetType($ptr) == "DLLStruct" Then
        $bPtrDllType = "struct*"
    Else
        $bPtrDllType = "ptr"
    EndIf

    Local $bTargetPtDllType
    If VarGetType($targetPt) == "DLLStruct" Then
        $bTargetPtDllType = "struct*"
    Else
        $bTargetPtDllType = "ptr"
    EndIf

    Local $bContourDllType
    If VarGetType($contour) == "DLLStruct" Then
        $bContourDllType = "struct*"
    Else
        $bContourDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveIntelligentScissorsMBGetContour", $bPtrDllType, $ptr, $bTargetPtDllType, $targetPt, $bContourDllType, $contour, "boolean", $backward), "cveIntelligentScissorsMBGetContour", @error)
EndFunc   ;==>_cveIntelligentScissorsMBGetContour

Func _cveIntelligentScissorsMBGetContourMat($ptr, $targetPt, $matContour, $backward)
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

Func _cveGetGaussianKernel($ksize, $sigma, $ktype, $result)
    ; CVAPI(void) cveGetGaussianKernel(int ksize, double sigma, int ktype, cv::Mat* result);

    Local $bResultDllType
    If VarGetType($result) == "DLLStruct" Then
        $bResultDllType = "struct*"
    Else
        $bResultDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveGetGaussianKernel", "int", $ksize, "double", $sigma, "int", $ktype, $bResultDllType, $result), "cveGetGaussianKernel", @error)
EndFunc   ;==>_cveGetGaussianKernel

Func _cveGetDerivKernels($kx, $ky, $dx, $dy, $ksize, $normalize = false, $ktype = $CV_32F)
    ; CVAPI(void) cveGetDerivKernels(cv::_OutputArray* kx, cv::_OutputArray* ky, int dx, int dy, int ksize, bool normalize, int ktype);

    Local $bKxDllType
    If VarGetType($kx) == "DLLStruct" Then
        $bKxDllType = "struct*"
    Else
        $bKxDllType = "ptr"
    EndIf

    Local $bKyDllType
    If VarGetType($ky) == "DLLStruct" Then
        $bKyDllType = "struct*"
    Else
        $bKyDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveGetDerivKernels", $bKxDllType, $kx, $bKyDllType, $ky, "int", $dx, "int", $dy, "int", $ksize, "boolean", $normalize, "int", $ktype), "cveGetDerivKernels", @error)
EndFunc   ;==>_cveGetDerivKernels

Func _cveGetDerivKernelsMat($matKx, $matKy, $dx, $dy, $ksize, $normalize = false, $ktype = $CV_32F)
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

Func _cveGetGaborKernel($ksize, $sigma, $theta, $lambd, $gamma, $psi, $ktype, $result)
    ; CVAPI(void) cveGetGaborKernel(CvSize* ksize, double sigma, double theta, double lambd, double gamma, double psi, int ktype, cv::Mat* result);

    Local $bKsizeDllType
    If VarGetType($ksize) == "DLLStruct" Then
        $bKsizeDllType = "struct*"
    Else
        $bKsizeDllType = "ptr"
    EndIf

    Local $bResultDllType
    If VarGetType($result) == "DLLStruct" Then
        $bResultDllType = "struct*"
    Else
        $bResultDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveGetGaborKernel", $bKsizeDllType, $ksize, "double", $sigma, "double", $theta, "double", $lambd, "double", $gamma, "double", $psi, "int", $ktype, $bResultDllType, $result), "cveGetGaborKernel", @error)
EndFunc   ;==>_cveGetGaborKernel