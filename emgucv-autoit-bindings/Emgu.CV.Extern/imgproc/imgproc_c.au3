#include-once
#include "..\..\CVEUtils.au3"

Func _cvGetImageSubRect($image, $rect)
    ; CVAPI(IplImage*) cvGetImageSubRect(IplImage* image, CvRect* rect);

    Local $sImageDllType
    If IsDllStruct($image) Then
        $sImageDllType = "struct*"
    Else
        $sImageDllType = "ptr"
    EndIf

    Local $sRectDllType
    If IsDllStruct($rect) Then
        $sRectDllType = "struct*"
    Else
        $sRectDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cvGetImageSubRect", $sImageDllType, $image, $sRectDllType, $rect), "cvGetImageSubRect", @error)
EndFunc   ;==>_cvGetImageSubRect

Func _cveGrabCut($img, $mask, $rect, $bgdModel, $fgdModel, $iterCount, $flag)
    ; CVAPI(void) cveGrabCut(cv::_InputArray* img, cv::_InputOutputArray* mask, cv::Rect* rect, cv::_InputOutputArray* bgdModel, cv::_InputOutputArray* fgdModel, int iterCount, int flag);

    Local $sImgDllType
    If IsDllStruct($img) Then
        $sImgDllType = "struct*"
    Else
        $sImgDllType = "ptr"
    EndIf

    Local $sMaskDllType
    If IsDllStruct($mask) Then
        $sMaskDllType = "struct*"
    Else
        $sMaskDllType = "ptr"
    EndIf

    Local $sRectDllType
    If IsDllStruct($rect) Then
        $sRectDllType = "struct*"
    Else
        $sRectDllType = "ptr"
    EndIf

    Local $sBgdModelDllType
    If IsDllStruct($bgdModel) Then
        $sBgdModelDllType = "struct*"
    Else
        $sBgdModelDllType = "ptr"
    EndIf

    Local $sFgdModelDllType
    If IsDllStruct($fgdModel) Then
        $sFgdModelDllType = "struct*"
    Else
        $sFgdModelDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveGrabCut", $sImgDllType, $img, $sMaskDllType, $mask, $sRectDllType, $rect, $sBgdModelDllType, $bgdModel, $sFgdModelDllType, $fgdModel, "int", $iterCount, "int", $flag), "cveGrabCut", @error)
EndFunc   ;==>_cveGrabCut

Func _cveGrabCutTyped($typeOfImg, $img, $typeOfMask, $mask, $rect, $typeOfBgdModel, $bgdModel, $typeOfFgdModel, $fgdModel, $iterCount, $flag)

    Local $iArrImg, $vectorImg, $iArrImgSize
    Local $bImgIsArray = IsArray($img)
    Local $bImgCreate = IsDllStruct($img) And $typeOfImg == "Scalar"

    If $typeOfImg == Default Then
        $iArrImg = $img
    ElseIf $bImgIsArray Then
        $vectorImg = Call("_VectorOf" & $typeOfImg & "Create")

        $iArrImgSize = UBound($img)
        For $i = 0 To $iArrImgSize - 1
            Call("_VectorOf" & $typeOfImg & "Push", $vectorImg, $img[$i])
        Next

        $iArrImg = Call("_cveInputArrayFromVectorOf" & $typeOfImg, $vectorImg)
    Else
        If $bImgCreate Then
            $img = Call("_cve" & $typeOfImg & "Create", $img)
        EndIf
        $iArrImg = Call("_cveInputArrayFrom" & $typeOfImg, $img)
    EndIf

    Local $ioArrMask, $vectorMask, $iArrMaskSize
    Local $bMaskIsArray = IsArray($mask)
    Local $bMaskCreate = IsDllStruct($mask) And $typeOfMask == "Scalar"

    If $typeOfMask == Default Then
        $ioArrMask = $mask
    ElseIf $bMaskIsArray Then
        $vectorMask = Call("_VectorOf" & $typeOfMask & "Create")

        $iArrMaskSize = UBound($mask)
        For $i = 0 To $iArrMaskSize - 1
            Call("_VectorOf" & $typeOfMask & "Push", $vectorMask, $mask[$i])
        Next

        $ioArrMask = Call("_cveInputOutputArrayFromVectorOf" & $typeOfMask, $vectorMask)
    Else
        If $bMaskCreate Then
            $mask = Call("_cve" & $typeOfMask & "Create", $mask)
        EndIf
        $ioArrMask = Call("_cveInputOutputArrayFrom" & $typeOfMask, $mask)
    EndIf

    Local $ioArrBgdModel, $vectorBgdModel, $iArrBgdModelSize
    Local $bBgdModelIsArray = IsArray($bgdModel)
    Local $bBgdModelCreate = IsDllStruct($bgdModel) And $typeOfBgdModel == "Scalar"

    If $typeOfBgdModel == Default Then
        $ioArrBgdModel = $bgdModel
    ElseIf $bBgdModelIsArray Then
        $vectorBgdModel = Call("_VectorOf" & $typeOfBgdModel & "Create")

        $iArrBgdModelSize = UBound($bgdModel)
        For $i = 0 To $iArrBgdModelSize - 1
            Call("_VectorOf" & $typeOfBgdModel & "Push", $vectorBgdModel, $bgdModel[$i])
        Next

        $ioArrBgdModel = Call("_cveInputOutputArrayFromVectorOf" & $typeOfBgdModel, $vectorBgdModel)
    Else
        If $bBgdModelCreate Then
            $bgdModel = Call("_cve" & $typeOfBgdModel & "Create", $bgdModel)
        EndIf
        $ioArrBgdModel = Call("_cveInputOutputArrayFrom" & $typeOfBgdModel, $bgdModel)
    EndIf

    Local $ioArrFgdModel, $vectorFgdModel, $iArrFgdModelSize
    Local $bFgdModelIsArray = IsArray($fgdModel)
    Local $bFgdModelCreate = IsDllStruct($fgdModel) And $typeOfFgdModel == "Scalar"

    If $typeOfFgdModel == Default Then
        $ioArrFgdModel = $fgdModel
    ElseIf $bFgdModelIsArray Then
        $vectorFgdModel = Call("_VectorOf" & $typeOfFgdModel & "Create")

        $iArrFgdModelSize = UBound($fgdModel)
        For $i = 0 To $iArrFgdModelSize - 1
            Call("_VectorOf" & $typeOfFgdModel & "Push", $vectorFgdModel, $fgdModel[$i])
        Next

        $ioArrFgdModel = Call("_cveInputOutputArrayFromVectorOf" & $typeOfFgdModel, $vectorFgdModel)
    Else
        If $bFgdModelCreate Then
            $fgdModel = Call("_cve" & $typeOfFgdModel & "Create", $fgdModel)
        EndIf
        $ioArrFgdModel = Call("_cveInputOutputArrayFrom" & $typeOfFgdModel, $fgdModel)
    EndIf

    _cveGrabCut($iArrImg, $ioArrMask, $rect, $ioArrBgdModel, $ioArrFgdModel, $iterCount, $flag)

    If $bFgdModelIsArray Then
        Call("_VectorOf" & $typeOfFgdModel & "Release", $vectorFgdModel)
    EndIf

    If $typeOfFgdModel <> Default Then
        _cveInputOutputArrayRelease($ioArrFgdModel)
        If $bFgdModelCreate Then
            Call("_cve" & $typeOfFgdModel & "Release", $fgdModel)
        EndIf
    EndIf

    If $bBgdModelIsArray Then
        Call("_VectorOf" & $typeOfBgdModel & "Release", $vectorBgdModel)
    EndIf

    If $typeOfBgdModel <> Default Then
        _cveInputOutputArrayRelease($ioArrBgdModel)
        If $bBgdModelCreate Then
            Call("_cve" & $typeOfBgdModel & "Release", $bgdModel)
        EndIf
    EndIf

    If $bMaskIsArray Then
        Call("_VectorOf" & $typeOfMask & "Release", $vectorMask)
    EndIf

    If $typeOfMask <> Default Then
        _cveInputOutputArrayRelease($ioArrMask)
        If $bMaskCreate Then
            Call("_cve" & $typeOfMask & "Release", $mask)
        EndIf
    EndIf

    If $bImgIsArray Then
        Call("_VectorOf" & $typeOfImg & "Release", $vectorImg)
    EndIf

    If $typeOfImg <> Default Then
        _cveInputArrayRelease($iArrImg)
        If $bImgCreate Then
            Call("_cve" & $typeOfImg & "Release", $img)
        EndIf
    EndIf
EndFunc   ;==>_cveGrabCutTyped

Func _cveGrabCutMat($img, $mask, $rect, $bgdModel, $fgdModel, $iterCount, $flag)
    ; cveGrabCut using cv::Mat instead of _*Array
    _cveGrabCutTyped("Mat", $img, "Mat", $mask, $rect, "Mat", $bgdModel, "Mat", $fgdModel, $iterCount, $flag)
EndFunc   ;==>_cveGrabCutMat

Func _cveFilter2D($src, $dst, $kernel, $anchor = _cvPoint(-1,-1), $delta = 0, $borderType = $CV_BORDER_DEFAULT)
    ; CVAPI(void) cveFilter2D(cv::_InputArray* src, cv::_OutputArray* dst, cv::_InputArray* kernel, CvPoint* anchor, double delta, int borderType);

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

    Local $sKernelDllType
    If IsDllStruct($kernel) Then
        $sKernelDllType = "struct*"
    Else
        $sKernelDllType = "ptr"
    EndIf

    Local $sAnchorDllType
    If IsDllStruct($anchor) Then
        $sAnchorDllType = "struct*"
    Else
        $sAnchorDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFilter2D", $sSrcDllType, $src, $sDstDllType, $dst, $sKernelDllType, $kernel, $sAnchorDllType, $anchor, "double", $delta, "int", $borderType), "cveFilter2D", @error)
EndFunc   ;==>_cveFilter2D

Func _cveFilter2DTyped($typeOfSrc, $src, $typeOfDst, $dst, $typeOfKernel, $kernel, $anchor = _cvPoint(-1,-1), $delta = 0, $borderType = $CV_BORDER_DEFAULT)

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

    Local $iArrKernel, $vectorKernel, $iArrKernelSize
    Local $bKernelIsArray = IsArray($kernel)
    Local $bKernelCreate = IsDllStruct($kernel) And $typeOfKernel == "Scalar"

    If $typeOfKernel == Default Then
        $iArrKernel = $kernel
    ElseIf $bKernelIsArray Then
        $vectorKernel = Call("_VectorOf" & $typeOfKernel & "Create")

        $iArrKernelSize = UBound($kernel)
        For $i = 0 To $iArrKernelSize - 1
            Call("_VectorOf" & $typeOfKernel & "Push", $vectorKernel, $kernel[$i])
        Next

        $iArrKernel = Call("_cveInputArrayFromVectorOf" & $typeOfKernel, $vectorKernel)
    Else
        If $bKernelCreate Then
            $kernel = Call("_cve" & $typeOfKernel & "Create", $kernel)
        EndIf
        $iArrKernel = Call("_cveInputArrayFrom" & $typeOfKernel, $kernel)
    EndIf

    _cveFilter2D($iArrSrc, $oArrDst, $iArrKernel, $anchor, $delta, $borderType)

    If $bKernelIsArray Then
        Call("_VectorOf" & $typeOfKernel & "Release", $vectorKernel)
    EndIf

    If $typeOfKernel <> Default Then
        _cveInputArrayRelease($iArrKernel)
        If $bKernelCreate Then
            Call("_cve" & $typeOfKernel & "Release", $kernel)
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
EndFunc   ;==>_cveFilter2DTyped

Func _cveFilter2DMat($src, $dst, $kernel, $anchor = _cvPoint(-1,-1), $delta = 0, $borderType = $CV_BORDER_DEFAULT)
    ; cveFilter2D using cv::Mat instead of _*Array
    _cveFilter2DTyped("Mat", $src, "Mat", $dst, "Mat", $kernel, $anchor, $delta, $borderType)
EndFunc   ;==>_cveFilter2DMat

Func _cveSepFilter2D($src, $dst, $ddepth, $kernelX, $kernelY, $anchor = _cvPoint(-1,-1), $delta = 0, $borderType = $CV_BORDER_DEFAULT)
    ; CVAPI(void) cveSepFilter2D(cv::_InputArray* src, cv::_OutputArray* dst, int ddepth, cv::_InputArray* kernelX, cv::_InputArray* kernelY, CvPoint* anchor, double delta, int borderType);

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

    Local $sKernelXDllType
    If IsDllStruct($kernelX) Then
        $sKernelXDllType = "struct*"
    Else
        $sKernelXDllType = "ptr"
    EndIf

    Local $sKernelYDllType
    If IsDllStruct($kernelY) Then
        $sKernelYDllType = "struct*"
    Else
        $sKernelYDllType = "ptr"
    EndIf

    Local $sAnchorDllType
    If IsDllStruct($anchor) Then
        $sAnchorDllType = "struct*"
    Else
        $sAnchorDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSepFilter2D", $sSrcDllType, $src, $sDstDllType, $dst, "int", $ddepth, $sKernelXDllType, $kernelX, $sKernelYDllType, $kernelY, $sAnchorDllType, $anchor, "double", $delta, "int", $borderType), "cveSepFilter2D", @error)
EndFunc   ;==>_cveSepFilter2D

Func _cveSepFilter2DTyped($typeOfSrc, $src, $typeOfDst, $dst, $ddepth, $typeOfKernelX, $kernelX, $typeOfKernelY, $kernelY, $anchor = _cvPoint(-1,-1), $delta = 0, $borderType = $CV_BORDER_DEFAULT)

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

    Local $iArrKernelX, $vectorKernelX, $iArrKernelXSize
    Local $bKernelXIsArray = IsArray($kernelX)
    Local $bKernelXCreate = IsDllStruct($kernelX) And $typeOfKernelX == "Scalar"

    If $typeOfKernelX == Default Then
        $iArrKernelX = $kernelX
    ElseIf $bKernelXIsArray Then
        $vectorKernelX = Call("_VectorOf" & $typeOfKernelX & "Create")

        $iArrKernelXSize = UBound($kernelX)
        For $i = 0 To $iArrKernelXSize - 1
            Call("_VectorOf" & $typeOfKernelX & "Push", $vectorKernelX, $kernelX[$i])
        Next

        $iArrKernelX = Call("_cveInputArrayFromVectorOf" & $typeOfKernelX, $vectorKernelX)
    Else
        If $bKernelXCreate Then
            $kernelX = Call("_cve" & $typeOfKernelX & "Create", $kernelX)
        EndIf
        $iArrKernelX = Call("_cveInputArrayFrom" & $typeOfKernelX, $kernelX)
    EndIf

    Local $iArrKernelY, $vectorKernelY, $iArrKernelYSize
    Local $bKernelYIsArray = IsArray($kernelY)
    Local $bKernelYCreate = IsDllStruct($kernelY) And $typeOfKernelY == "Scalar"

    If $typeOfKernelY == Default Then
        $iArrKernelY = $kernelY
    ElseIf $bKernelYIsArray Then
        $vectorKernelY = Call("_VectorOf" & $typeOfKernelY & "Create")

        $iArrKernelYSize = UBound($kernelY)
        For $i = 0 To $iArrKernelYSize - 1
            Call("_VectorOf" & $typeOfKernelY & "Push", $vectorKernelY, $kernelY[$i])
        Next

        $iArrKernelY = Call("_cveInputArrayFromVectorOf" & $typeOfKernelY, $vectorKernelY)
    Else
        If $bKernelYCreate Then
            $kernelY = Call("_cve" & $typeOfKernelY & "Create", $kernelY)
        EndIf
        $iArrKernelY = Call("_cveInputArrayFrom" & $typeOfKernelY, $kernelY)
    EndIf

    _cveSepFilter2D($iArrSrc, $oArrDst, $ddepth, $iArrKernelX, $iArrKernelY, $anchor, $delta, $borderType)

    If $bKernelYIsArray Then
        Call("_VectorOf" & $typeOfKernelY & "Release", $vectorKernelY)
    EndIf

    If $typeOfKernelY <> Default Then
        _cveInputArrayRelease($iArrKernelY)
        If $bKernelYCreate Then
            Call("_cve" & $typeOfKernelY & "Release", $kernelY)
        EndIf
    EndIf

    If $bKernelXIsArray Then
        Call("_VectorOf" & $typeOfKernelX & "Release", $vectorKernelX)
    EndIf

    If $typeOfKernelX <> Default Then
        _cveInputArrayRelease($iArrKernelX)
        If $bKernelXCreate Then
            Call("_cve" & $typeOfKernelX & "Release", $kernelX)
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
EndFunc   ;==>_cveSepFilter2DTyped

Func _cveSepFilter2DMat($src, $dst, $ddepth, $kernelX, $kernelY, $anchor = _cvPoint(-1,-1), $delta = 0, $borderType = $CV_BORDER_DEFAULT)
    ; cveSepFilter2D using cv::Mat instead of _*Array
    _cveSepFilter2DTyped("Mat", $src, "Mat", $dst, $ddepth, "Mat", $kernelX, "Mat", $kernelY, $anchor, $delta, $borderType)
EndFunc   ;==>_cveSepFilter2DMat

Func _cveBlendLinear($src1, $src2, $weights1, $weights2, $dst)
    ; CVAPI(void) cveBlendLinear(cv::_InputArray* src1, cv::_InputArray* src2, cv::_InputArray* weights1, cv::_InputArray* weights2, cv::_OutputArray* dst);

    Local $sSrc1DllType
    If IsDllStruct($src1) Then
        $sSrc1DllType = "struct*"
    Else
        $sSrc1DllType = "ptr"
    EndIf

    Local $sSrc2DllType
    If IsDllStruct($src2) Then
        $sSrc2DllType = "struct*"
    Else
        $sSrc2DllType = "ptr"
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

    Local $sDstDllType
    If IsDllStruct($dst) Then
        $sDstDllType = "struct*"
    Else
        $sDstDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBlendLinear", $sSrc1DllType, $src1, $sSrc2DllType, $src2, $sWeights1DllType, $weights1, $sWeights2DllType, $weights2, $sDstDllType, $dst), "cveBlendLinear", @error)
EndFunc   ;==>_cveBlendLinear

Func _cveBlendLinearTyped($typeOfSrc1, $src1, $typeOfSrc2, $src2, $typeOfWeights1, $weights1, $typeOfWeights2, $weights2, $typeOfDst, $dst)

    Local $iArrSrc1, $vectorSrc1, $iArrSrc1Size
    Local $bSrc1IsArray = IsArray($src1)
    Local $bSrc1Create = IsDllStruct($src1) And $typeOfSrc1 == "Scalar"

    If $typeOfSrc1 == Default Then
        $iArrSrc1 = $src1
    ElseIf $bSrc1IsArray Then
        $vectorSrc1 = Call("_VectorOf" & $typeOfSrc1 & "Create")

        $iArrSrc1Size = UBound($src1)
        For $i = 0 To $iArrSrc1Size - 1
            Call("_VectorOf" & $typeOfSrc1 & "Push", $vectorSrc1, $src1[$i])
        Next

        $iArrSrc1 = Call("_cveInputArrayFromVectorOf" & $typeOfSrc1, $vectorSrc1)
    Else
        If $bSrc1Create Then
            $src1 = Call("_cve" & $typeOfSrc1 & "Create", $src1)
        EndIf
        $iArrSrc1 = Call("_cveInputArrayFrom" & $typeOfSrc1, $src1)
    EndIf

    Local $iArrSrc2, $vectorSrc2, $iArrSrc2Size
    Local $bSrc2IsArray = IsArray($src2)
    Local $bSrc2Create = IsDllStruct($src2) And $typeOfSrc2 == "Scalar"

    If $typeOfSrc2 == Default Then
        $iArrSrc2 = $src2
    ElseIf $bSrc2IsArray Then
        $vectorSrc2 = Call("_VectorOf" & $typeOfSrc2 & "Create")

        $iArrSrc2Size = UBound($src2)
        For $i = 0 To $iArrSrc2Size - 1
            Call("_VectorOf" & $typeOfSrc2 & "Push", $vectorSrc2, $src2[$i])
        Next

        $iArrSrc2 = Call("_cveInputArrayFromVectorOf" & $typeOfSrc2, $vectorSrc2)
    Else
        If $bSrc2Create Then
            $src2 = Call("_cve" & $typeOfSrc2 & "Create", $src2)
        EndIf
        $iArrSrc2 = Call("_cveInputArrayFrom" & $typeOfSrc2, $src2)
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

    _cveBlendLinear($iArrSrc1, $iArrSrc2, $iArrWeights1, $iArrWeights2, $oArrDst)

    If $bDstIsArray Then
        Call("_VectorOf" & $typeOfDst & "Release", $vectorDst)
    EndIf

    If $typeOfDst <> Default Then
        _cveOutputArrayRelease($oArrDst)
        If $bDstCreate Then
            Call("_cve" & $typeOfDst & "Release", $dst)
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

    If $bSrc2IsArray Then
        Call("_VectorOf" & $typeOfSrc2 & "Release", $vectorSrc2)
    EndIf

    If $typeOfSrc2 <> Default Then
        _cveInputArrayRelease($iArrSrc2)
        If $bSrc2Create Then
            Call("_cve" & $typeOfSrc2 & "Release", $src2)
        EndIf
    EndIf

    If $bSrc1IsArray Then
        Call("_VectorOf" & $typeOfSrc1 & "Release", $vectorSrc1)
    EndIf

    If $typeOfSrc1 <> Default Then
        _cveInputArrayRelease($iArrSrc1)
        If $bSrc1Create Then
            Call("_cve" & $typeOfSrc1 & "Release", $src1)
        EndIf
    EndIf
EndFunc   ;==>_cveBlendLinearTyped

Func _cveBlendLinearMat($src1, $src2, $weights1, $weights2, $dst)
    ; cveBlendLinear using cv::Mat instead of _*Array
    _cveBlendLinearTyped("Mat", $src1, "Mat", $src2, "Mat", $weights1, "Mat", $weights2, "Mat", $dst)
EndFunc   ;==>_cveBlendLinearMat

Func _cveCLAHE($src, $clipLimit, $tileGridSize, $dst)
    ; CVAPI(void) cveCLAHE(cv::_InputArray* src, double clipLimit, CvSize* tileGridSize, cv::_OutputArray* dst);

    Local $sSrcDllType
    If IsDllStruct($src) Then
        $sSrcDllType = "struct*"
    Else
        $sSrcDllType = "ptr"
    EndIf

    Local $sTileGridSizeDllType
    If IsDllStruct($tileGridSize) Then
        $sTileGridSizeDllType = "struct*"
    Else
        $sTileGridSizeDllType = "ptr"
    EndIf

    Local $sDstDllType
    If IsDllStruct($dst) Then
        $sDstDllType = "struct*"
    Else
        $sDstDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCLAHE", $sSrcDllType, $src, "double", $clipLimit, $sTileGridSizeDllType, $tileGridSize, $sDstDllType, $dst), "cveCLAHE", @error)
EndFunc   ;==>_cveCLAHE

Func _cveCLAHETyped($typeOfSrc, $src, $clipLimit, $tileGridSize, $typeOfDst, $dst)

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

    _cveCLAHE($iArrSrc, $clipLimit, $tileGridSize, $oArrDst)

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
EndFunc   ;==>_cveCLAHETyped

Func _cveCLAHEMat($src, $clipLimit, $tileGridSize, $dst)
    ; cveCLAHE using cv::Mat instead of _*Array
    _cveCLAHETyped("Mat", $src, $clipLimit, $tileGridSize, "Mat", $dst)
EndFunc   ;==>_cveCLAHEMat

Func _cveErode($src, $dst, $kernel, $anchor = _cvPoint(-1,-1), $iterations = 1, $borderType = $CV_BORDER_CONSTANT, $borderValue = _cveMorphologyDefaultBorderValue())
    ; CVAPI(void) cveErode(cv::_InputArray* src, cv::_OutputArray* dst, cv::_InputArray* kernel, CvPoint* anchor, int iterations, int borderType, CvScalar* borderValue);

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

    Local $sKernelDllType
    If IsDllStruct($kernel) Then
        $sKernelDllType = "struct*"
    Else
        $sKernelDllType = "ptr"
    EndIf

    Local $sAnchorDllType
    If IsDllStruct($anchor) Then
        $sAnchorDllType = "struct*"
    Else
        $sAnchorDllType = "ptr"
    EndIf

    Local $sBorderValueDllType
    If IsDllStruct($borderValue) Then
        $sBorderValueDllType = "struct*"
    Else
        $sBorderValueDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveErode", $sSrcDllType, $src, $sDstDllType, $dst, $sKernelDllType, $kernel, $sAnchorDllType, $anchor, "int", $iterations, "int", $borderType, $sBorderValueDllType, $borderValue), "cveErode", @error)
EndFunc   ;==>_cveErode

Func _cveErodeTyped($typeOfSrc, $src, $typeOfDst, $dst, $typeOfKernel, $kernel, $anchor = _cvPoint(-1,-1), $iterations = 1, $borderType = $CV_BORDER_CONSTANT, $borderValue = _cveMorphologyDefaultBorderValue())

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

    Local $iArrKernel, $vectorKernel, $iArrKernelSize
    Local $bKernelIsArray = IsArray($kernel)
    Local $bKernelCreate = IsDllStruct($kernel) And $typeOfKernel == "Scalar"

    If $typeOfKernel == Default Then
        $iArrKernel = $kernel
    ElseIf $bKernelIsArray Then
        $vectorKernel = Call("_VectorOf" & $typeOfKernel & "Create")

        $iArrKernelSize = UBound($kernel)
        For $i = 0 To $iArrKernelSize - 1
            Call("_VectorOf" & $typeOfKernel & "Push", $vectorKernel, $kernel[$i])
        Next

        $iArrKernel = Call("_cveInputArrayFromVectorOf" & $typeOfKernel, $vectorKernel)
    Else
        If $bKernelCreate Then
            $kernel = Call("_cve" & $typeOfKernel & "Create", $kernel)
        EndIf
        $iArrKernel = Call("_cveInputArrayFrom" & $typeOfKernel, $kernel)
    EndIf

    _cveErode($iArrSrc, $oArrDst, $iArrKernel, $anchor, $iterations, $borderType, $borderValue)

    If $bKernelIsArray Then
        Call("_VectorOf" & $typeOfKernel & "Release", $vectorKernel)
    EndIf

    If $typeOfKernel <> Default Then
        _cveInputArrayRelease($iArrKernel)
        If $bKernelCreate Then
            Call("_cve" & $typeOfKernel & "Release", $kernel)
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
EndFunc   ;==>_cveErodeTyped

Func _cveErodeMat($src, $dst, $kernel, $anchor = _cvPoint(-1,-1), $iterations = 1, $borderType = $CV_BORDER_CONSTANT, $borderValue = _cveMorphologyDefaultBorderValue())
    ; cveErode using cv::Mat instead of _*Array
    _cveErodeTyped("Mat", $src, "Mat", $dst, "Mat", $kernel, $anchor, $iterations, $borderType, $borderValue)
EndFunc   ;==>_cveErodeMat

Func _cveDilate($src, $dst, $kernel, $anchor = _cvPoint(-1,-1), $iterations = 1, $borderType = $CV_BORDER_CONSTANT, $borderValue = _cveMorphologyDefaultBorderValue())
    ; CVAPI(void) cveDilate(cv::_InputArray* src, cv::_OutputArray* dst, cv::_InputArray* kernel, CvPoint* anchor, int iterations, int borderType, CvScalar* borderValue);

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

    Local $sKernelDllType
    If IsDllStruct($kernel) Then
        $sKernelDllType = "struct*"
    Else
        $sKernelDllType = "ptr"
    EndIf

    Local $sAnchorDllType
    If IsDllStruct($anchor) Then
        $sAnchorDllType = "struct*"
    Else
        $sAnchorDllType = "ptr"
    EndIf

    Local $sBorderValueDllType
    If IsDllStruct($borderValue) Then
        $sBorderValueDllType = "struct*"
    Else
        $sBorderValueDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDilate", $sSrcDllType, $src, $sDstDllType, $dst, $sKernelDllType, $kernel, $sAnchorDllType, $anchor, "int", $iterations, "int", $borderType, $sBorderValueDllType, $borderValue), "cveDilate", @error)
EndFunc   ;==>_cveDilate

Func _cveDilateTyped($typeOfSrc, $src, $typeOfDst, $dst, $typeOfKernel, $kernel, $anchor = _cvPoint(-1,-1), $iterations = 1, $borderType = $CV_BORDER_CONSTANT, $borderValue = _cveMorphologyDefaultBorderValue())

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

    Local $iArrKernel, $vectorKernel, $iArrKernelSize
    Local $bKernelIsArray = IsArray($kernel)
    Local $bKernelCreate = IsDllStruct($kernel) And $typeOfKernel == "Scalar"

    If $typeOfKernel == Default Then
        $iArrKernel = $kernel
    ElseIf $bKernelIsArray Then
        $vectorKernel = Call("_VectorOf" & $typeOfKernel & "Create")

        $iArrKernelSize = UBound($kernel)
        For $i = 0 To $iArrKernelSize - 1
            Call("_VectorOf" & $typeOfKernel & "Push", $vectorKernel, $kernel[$i])
        Next

        $iArrKernel = Call("_cveInputArrayFromVectorOf" & $typeOfKernel, $vectorKernel)
    Else
        If $bKernelCreate Then
            $kernel = Call("_cve" & $typeOfKernel & "Create", $kernel)
        EndIf
        $iArrKernel = Call("_cveInputArrayFrom" & $typeOfKernel, $kernel)
    EndIf

    _cveDilate($iArrSrc, $oArrDst, $iArrKernel, $anchor, $iterations, $borderType, $borderValue)

    If $bKernelIsArray Then
        Call("_VectorOf" & $typeOfKernel & "Release", $vectorKernel)
    EndIf

    If $typeOfKernel <> Default Then
        _cveInputArrayRelease($iArrKernel)
        If $bKernelCreate Then
            Call("_cve" & $typeOfKernel & "Release", $kernel)
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
EndFunc   ;==>_cveDilateTyped

Func _cveDilateMat($src, $dst, $kernel, $anchor = _cvPoint(-1,-1), $iterations = 1, $borderType = $CV_BORDER_CONSTANT, $borderValue = _cveMorphologyDefaultBorderValue())
    ; cveDilate using cv::Mat instead of _*Array
    _cveDilateTyped("Mat", $src, "Mat", $dst, "Mat", $kernel, $anchor, $iterations, $borderType, $borderValue)
EndFunc   ;==>_cveDilateMat

Func _cveGetStructuringElement($mat, $shape, $ksize, $anchor = _cvPoint(-1,-1))
    ; CVAPI(void) cveGetStructuringElement(cv::Mat* mat, int shape, CvSize* ksize, CvPoint* anchor);

    Local $sMatDllType
    If IsDllStruct($mat) Then
        $sMatDllType = "struct*"
    Else
        $sMatDllType = "ptr"
    EndIf

    Local $sKsizeDllType
    If IsDllStruct($ksize) Then
        $sKsizeDllType = "struct*"
    Else
        $sKsizeDllType = "ptr"
    EndIf

    Local $sAnchorDllType
    If IsDllStruct($anchor) Then
        $sAnchorDllType = "struct*"
    Else
        $sAnchorDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveGetStructuringElement", $sMatDllType, $mat, "int", $shape, $sKsizeDllType, $ksize, $sAnchorDllType, $anchor), "cveGetStructuringElement", @error)
EndFunc   ;==>_cveGetStructuringElement

Func _cveMorphologyEx($src, $dst, $op, $kernel, $anchor = _cvPoint(-1,-1), $iterations = 1, $borderType = $CV_BORDER_CONSTANT, $borderValue = _cveMorphologyDefaultBorderValue())
    ; CVAPI(void) cveMorphologyEx(cv::_InputArray* src, cv::_OutputArray* dst, int op, cv::_InputArray* kernel, CvPoint* anchor, int iterations, int borderType, CvScalar* borderValue);

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

    Local $sKernelDllType
    If IsDllStruct($kernel) Then
        $sKernelDllType = "struct*"
    Else
        $sKernelDllType = "ptr"
    EndIf

    Local $sAnchorDllType
    If IsDllStruct($anchor) Then
        $sAnchorDllType = "struct*"
    Else
        $sAnchorDllType = "ptr"
    EndIf

    Local $sBorderValueDllType
    If IsDllStruct($borderValue) Then
        $sBorderValueDllType = "struct*"
    Else
        $sBorderValueDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMorphologyEx", $sSrcDllType, $src, $sDstDllType, $dst, "int", $op, $sKernelDllType, $kernel, $sAnchorDllType, $anchor, "int", $iterations, "int", $borderType, $sBorderValueDllType, $borderValue), "cveMorphologyEx", @error)
EndFunc   ;==>_cveMorphologyEx

Func _cveMorphologyExTyped($typeOfSrc, $src, $typeOfDst, $dst, $op, $typeOfKernel, $kernel, $anchor = _cvPoint(-1,-1), $iterations = 1, $borderType = $CV_BORDER_CONSTANT, $borderValue = _cveMorphologyDefaultBorderValue())

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

    Local $iArrKernel, $vectorKernel, $iArrKernelSize
    Local $bKernelIsArray = IsArray($kernel)
    Local $bKernelCreate = IsDllStruct($kernel) And $typeOfKernel == "Scalar"

    If $typeOfKernel == Default Then
        $iArrKernel = $kernel
    ElseIf $bKernelIsArray Then
        $vectorKernel = Call("_VectorOf" & $typeOfKernel & "Create")

        $iArrKernelSize = UBound($kernel)
        For $i = 0 To $iArrKernelSize - 1
            Call("_VectorOf" & $typeOfKernel & "Push", $vectorKernel, $kernel[$i])
        Next

        $iArrKernel = Call("_cveInputArrayFromVectorOf" & $typeOfKernel, $vectorKernel)
    Else
        If $bKernelCreate Then
            $kernel = Call("_cve" & $typeOfKernel & "Create", $kernel)
        EndIf
        $iArrKernel = Call("_cveInputArrayFrom" & $typeOfKernel, $kernel)
    EndIf

    _cveMorphologyEx($iArrSrc, $oArrDst, $op, $iArrKernel, $anchor, $iterations, $borderType, $borderValue)

    If $bKernelIsArray Then
        Call("_VectorOf" & $typeOfKernel & "Release", $vectorKernel)
    EndIf

    If $typeOfKernel <> Default Then
        _cveInputArrayRelease($iArrKernel)
        If $bKernelCreate Then
            Call("_cve" & $typeOfKernel & "Release", $kernel)
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
EndFunc   ;==>_cveMorphologyExTyped

Func _cveMorphologyExMat($src, $dst, $op, $kernel, $anchor = _cvPoint(-1,-1), $iterations = 1, $borderType = $CV_BORDER_CONSTANT, $borderValue = _cveMorphologyDefaultBorderValue())
    ; cveMorphologyEx using cv::Mat instead of _*Array
    _cveMorphologyExTyped("Mat", $src, "Mat", $dst, $op, "Mat", $kernel, $anchor, $iterations, $borderType, $borderValue)
EndFunc   ;==>_cveMorphologyExMat

Func _cveSobel($src, $dst, $ddepth, $dx, $dy, $ksize = 3, $scale = 1, $delta = 0, $borderType = $CV_BORDER_DEFAULT)
    ; CVAPI(void) cveSobel(cv::_InputArray* src, cv::_OutputArray* dst, int ddepth, int dx, int dy, int ksize, double scale, double delta, int borderType);

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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSobel", $sSrcDllType, $src, $sDstDllType, $dst, "int", $ddepth, "int", $dx, "int", $dy, "int", $ksize, "double", $scale, "double", $delta, "int", $borderType), "cveSobel", @error)
EndFunc   ;==>_cveSobel

Func _cveSobelTyped($typeOfSrc, $src, $typeOfDst, $dst, $ddepth, $dx, $dy, $ksize = 3, $scale = 1, $delta = 0, $borderType = $CV_BORDER_DEFAULT)

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

    _cveSobel($iArrSrc, $oArrDst, $ddepth, $dx, $dy, $ksize, $scale, $delta, $borderType)

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
EndFunc   ;==>_cveSobelTyped

Func _cveSobelMat($src, $dst, $ddepth, $dx, $dy, $ksize = 3, $scale = 1, $delta = 0, $borderType = $CV_BORDER_DEFAULT)
    ; cveSobel using cv::Mat instead of _*Array
    _cveSobelTyped("Mat", $src, "Mat", $dst, $ddepth, $dx, $dy, $ksize, $scale, $delta, $borderType)
EndFunc   ;==>_cveSobelMat

Func _cveSpatialGradient($src, $dx, $dy, $ksize = 3, $borderType = $CV_BORDER_DEFAULT)
    ; CVAPI(void) cveSpatialGradient(cv::_InputArray* src, cv::_OutputArray* dx, cv::_OutputArray* dy, int ksize, int borderType);

    Local $sSrcDllType
    If IsDllStruct($src) Then
        $sSrcDllType = "struct*"
    Else
        $sSrcDllType = "ptr"
    EndIf

    Local $sDxDllType
    If IsDllStruct($dx) Then
        $sDxDllType = "struct*"
    Else
        $sDxDllType = "ptr"
    EndIf

    Local $sDyDllType
    If IsDllStruct($dy) Then
        $sDyDllType = "struct*"
    Else
        $sDyDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSpatialGradient", $sSrcDllType, $src, $sDxDllType, $dx, $sDyDllType, $dy, "int", $ksize, "int", $borderType), "cveSpatialGradient", @error)
EndFunc   ;==>_cveSpatialGradient

Func _cveSpatialGradientTyped($typeOfSrc, $src, $typeOfDx, $dx, $typeOfDy, $dy, $ksize = 3, $borderType = $CV_BORDER_DEFAULT)

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

    Local $oArrDx, $vectorDx, $iArrDxSize
    Local $bDxIsArray = IsArray($dx)
    Local $bDxCreate = IsDllStruct($dx) And $typeOfDx == "Scalar"

    If $typeOfDx == Default Then
        $oArrDx = $dx
    ElseIf $bDxIsArray Then
        $vectorDx = Call("_VectorOf" & $typeOfDx & "Create")

        $iArrDxSize = UBound($dx)
        For $i = 0 To $iArrDxSize - 1
            Call("_VectorOf" & $typeOfDx & "Push", $vectorDx, $dx[$i])
        Next

        $oArrDx = Call("_cveOutputArrayFromVectorOf" & $typeOfDx, $vectorDx)
    Else
        If $bDxCreate Then
            $dx = Call("_cve" & $typeOfDx & "Create", $dx)
        EndIf
        $oArrDx = Call("_cveOutputArrayFrom" & $typeOfDx, $dx)
    EndIf

    Local $oArrDy, $vectorDy, $iArrDySize
    Local $bDyIsArray = IsArray($dy)
    Local $bDyCreate = IsDllStruct($dy) And $typeOfDy == "Scalar"

    If $typeOfDy == Default Then
        $oArrDy = $dy
    ElseIf $bDyIsArray Then
        $vectorDy = Call("_VectorOf" & $typeOfDy & "Create")

        $iArrDySize = UBound($dy)
        For $i = 0 To $iArrDySize - 1
            Call("_VectorOf" & $typeOfDy & "Push", $vectorDy, $dy[$i])
        Next

        $oArrDy = Call("_cveOutputArrayFromVectorOf" & $typeOfDy, $vectorDy)
    Else
        If $bDyCreate Then
            $dy = Call("_cve" & $typeOfDy & "Create", $dy)
        EndIf
        $oArrDy = Call("_cveOutputArrayFrom" & $typeOfDy, $dy)
    EndIf

    _cveSpatialGradient($iArrSrc, $oArrDx, $oArrDy, $ksize, $borderType)

    If $bDyIsArray Then
        Call("_VectorOf" & $typeOfDy & "Release", $vectorDy)
    EndIf

    If $typeOfDy <> Default Then
        _cveOutputArrayRelease($oArrDy)
        If $bDyCreate Then
            Call("_cve" & $typeOfDy & "Release", $dy)
        EndIf
    EndIf

    If $bDxIsArray Then
        Call("_VectorOf" & $typeOfDx & "Release", $vectorDx)
    EndIf

    If $typeOfDx <> Default Then
        _cveOutputArrayRelease($oArrDx)
        If $bDxCreate Then
            Call("_cve" & $typeOfDx & "Release", $dx)
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
EndFunc   ;==>_cveSpatialGradientTyped

Func _cveSpatialGradientMat($src, $dx, $dy, $ksize = 3, $borderType = $CV_BORDER_DEFAULT)
    ; cveSpatialGradient using cv::Mat instead of _*Array
    _cveSpatialGradientTyped("Mat", $src, "Mat", $dx, "Mat", $dy, $ksize, $borderType)
EndFunc   ;==>_cveSpatialGradientMat

Func _cveScharr($src, $dst, $ddepth, $dx, $dy, $scale = 1, $delta = 0, $borderType = $CV_BORDER_DEFAULT)
    ; CVAPI(void) cveScharr(cv::_InputArray* src, cv::_OutputArray* dst, int ddepth, int dx, int dy, double scale, double delta, int borderType);

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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveScharr", $sSrcDllType, $src, $sDstDllType, $dst, "int", $ddepth, "int", $dx, "int", $dy, "double", $scale, "double", $delta, "int", $borderType), "cveScharr", @error)
EndFunc   ;==>_cveScharr

Func _cveScharrTyped($typeOfSrc, $src, $typeOfDst, $dst, $ddepth, $dx, $dy, $scale = 1, $delta = 0, $borderType = $CV_BORDER_DEFAULT)

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

    _cveScharr($iArrSrc, $oArrDst, $ddepth, $dx, $dy, $scale, $delta, $borderType)

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
EndFunc   ;==>_cveScharrTyped

Func _cveScharrMat($src, $dst, $ddepth, $dx, $dy, $scale = 1, $delta = 0, $borderType = $CV_BORDER_DEFAULT)
    ; cveScharr using cv::Mat instead of _*Array
    _cveScharrTyped("Mat", $src, "Mat", $dst, $ddepth, $dx, $dy, $scale, $delta, $borderType)
EndFunc   ;==>_cveScharrMat

Func _cveLaplacian($src, $dst, $ddepth, $ksize = 1, $scale = 1, $delta = 0, $borderType = $CV_BORDER_DEFAULT)
    ; CVAPI(void) cveLaplacian(cv::_InputArray* src, cv::_OutputArray* dst, int ddepth, int ksize, double scale, double delta, int borderType);

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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveLaplacian", $sSrcDllType, $src, $sDstDllType, $dst, "int", $ddepth, "int", $ksize, "double", $scale, "double", $delta, "int", $borderType), "cveLaplacian", @error)
EndFunc   ;==>_cveLaplacian

Func _cveLaplacianTyped($typeOfSrc, $src, $typeOfDst, $dst, $ddepth, $ksize = 1, $scale = 1, $delta = 0, $borderType = $CV_BORDER_DEFAULT)

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

    _cveLaplacian($iArrSrc, $oArrDst, $ddepth, $ksize, $scale, $delta, $borderType)

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
EndFunc   ;==>_cveLaplacianTyped

Func _cveLaplacianMat($src, $dst, $ddepth, $ksize = 1, $scale = 1, $delta = 0, $borderType = $CV_BORDER_DEFAULT)
    ; cveLaplacian using cv::Mat instead of _*Array
    _cveLaplacianTyped("Mat", $src, "Mat", $dst, $ddepth, $ksize, $scale, $delta, $borderType)
EndFunc   ;==>_cveLaplacianMat

Func _cvePyrUp($src, $dst, $size, $borderType = $CV_BORDER_DEFAULT)
    ; CVAPI(void) cvePyrUp(cv::_InputArray* src, cv::_OutputArray* dst, CvSize* size, int borderType);

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

    Local $sSizeDllType
    If IsDllStruct($size) Then
        $sSizeDllType = "struct*"
    Else
        $sSizeDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cvePyrUp", $sSrcDllType, $src, $sDstDllType, $dst, $sSizeDllType, $size, "int", $borderType), "cvePyrUp", @error)
EndFunc   ;==>_cvePyrUp

Func _cvePyrUpTyped($typeOfSrc, $src, $typeOfDst, $dst, $size, $borderType = $CV_BORDER_DEFAULT)

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

    _cvePyrUp($iArrSrc, $oArrDst, $size, $borderType)

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
EndFunc   ;==>_cvePyrUpTyped

Func _cvePyrUpMat($src, $dst, $size, $borderType = $CV_BORDER_DEFAULT)
    ; cvePyrUp using cv::Mat instead of _*Array
    _cvePyrUpTyped("Mat", $src, "Mat", $dst, $size, $borderType)
EndFunc   ;==>_cvePyrUpMat

Func _cvePyrDown($src, $dst, $size, $borderType = $CV_BORDER_DEFAULT)
    ; CVAPI(void) cvePyrDown(cv::_InputArray* src, cv::_OutputArray* dst, CvSize* size, int borderType);

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

    Local $sSizeDllType
    If IsDllStruct($size) Then
        $sSizeDllType = "struct*"
    Else
        $sSizeDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cvePyrDown", $sSrcDllType, $src, $sDstDllType, $dst, $sSizeDllType, $size, "int", $borderType), "cvePyrDown", @error)
EndFunc   ;==>_cvePyrDown

Func _cvePyrDownTyped($typeOfSrc, $src, $typeOfDst, $dst, $size, $borderType = $CV_BORDER_DEFAULT)

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

    _cvePyrDown($iArrSrc, $oArrDst, $size, $borderType)

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
EndFunc   ;==>_cvePyrDownTyped

Func _cvePyrDownMat($src, $dst, $size, $borderType = $CV_BORDER_DEFAULT)
    ; cvePyrDown using cv::Mat instead of _*Array
    _cvePyrDownTyped("Mat", $src, "Mat", $dst, $size, $borderType)
EndFunc   ;==>_cvePyrDownMat

Func _cveBuildPyramid($src, $dst, $maxlevel, $borderType)
    ; CVAPI(void) cveBuildPyramid(cv::_InputArray* src, cv::_OutputArray* dst, int maxlevel, int borderType);

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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBuildPyramid", $sSrcDllType, $src, $sDstDllType, $dst, "int", $maxlevel, "int", $borderType), "cveBuildPyramid", @error)
EndFunc   ;==>_cveBuildPyramid

Func _cveBuildPyramidTyped($typeOfSrc, $src, $typeOfDst, $dst, $maxlevel, $borderType)

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

    _cveBuildPyramid($iArrSrc, $oArrDst, $maxlevel, $borderType)

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
EndFunc   ;==>_cveBuildPyramidTyped

Func _cveBuildPyramidMat($src, $dst, $maxlevel, $borderType)
    ; cveBuildPyramid using cv::Mat instead of _*Array
    _cveBuildPyramidTyped("Mat", $src, "Mat", $dst, $maxlevel, $borderType)
EndFunc   ;==>_cveBuildPyramidMat

Func _cveCanny($image, $edges, $threshold1, $threshold2, $apertureSize = 3, $L2gradient = false)
    ; CVAPI(void) cveCanny(cv::_InputArray* image, cv::_OutputArray* edges, double threshold1, double threshold2, int apertureSize, bool L2gradient);

    Local $sImageDllType
    If IsDllStruct($image) Then
        $sImageDllType = "struct*"
    Else
        $sImageDllType = "ptr"
    EndIf

    Local $sEdgesDllType
    If IsDllStruct($edges) Then
        $sEdgesDllType = "struct*"
    Else
        $sEdgesDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCanny", $sImageDllType, $image, $sEdgesDllType, $edges, "double", $threshold1, "double", $threshold2, "int", $apertureSize, "boolean", $L2gradient), "cveCanny", @error)
EndFunc   ;==>_cveCanny

Func _cveCannyTyped($typeOfImage, $image, $typeOfEdges, $edges, $threshold1, $threshold2, $apertureSize = 3, $L2gradient = false)

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

    _cveCanny($iArrImage, $oArrEdges, $threshold1, $threshold2, $apertureSize, $L2gradient)

    If $bEdgesIsArray Then
        Call("_VectorOf" & $typeOfEdges & "Release", $vectorEdges)
    EndIf

    If $typeOfEdges <> Default Then
        _cveOutputArrayRelease($oArrEdges)
        If $bEdgesCreate Then
            Call("_cve" & $typeOfEdges & "Release", $edges)
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
EndFunc   ;==>_cveCannyTyped

Func _cveCannyMat($image, $edges, $threshold1, $threshold2, $apertureSize = 3, $L2gradient = false)
    ; cveCanny using cv::Mat instead of _*Array
    _cveCannyTyped("Mat", $image, "Mat", $edges, $threshold1, $threshold2, $apertureSize, $L2gradient)
EndFunc   ;==>_cveCannyMat

Func _cveCanny2($dx, $dy, $edges, $threshold1, $threshold2, $L2gradient)
    ; CVAPI(void) cveCanny2(cv::_InputArray* dx, cv::_InputArray* dy, cv::_OutputArray* edges, double threshold1, double threshold2, bool L2gradient);

    Local $sDxDllType
    If IsDllStruct($dx) Then
        $sDxDllType = "struct*"
    Else
        $sDxDllType = "ptr"
    EndIf

    Local $sDyDllType
    If IsDllStruct($dy) Then
        $sDyDllType = "struct*"
    Else
        $sDyDllType = "ptr"
    EndIf

    Local $sEdgesDllType
    If IsDllStruct($edges) Then
        $sEdgesDllType = "struct*"
    Else
        $sEdgesDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCanny2", $sDxDllType, $dx, $sDyDllType, $dy, $sEdgesDllType, $edges, "double", $threshold1, "double", $threshold2, "boolean", $L2gradient), "cveCanny2", @error)
EndFunc   ;==>_cveCanny2

Func _cveCanny2Typed($typeOfDx, $dx, $typeOfDy, $dy, $typeOfEdges, $edges, $threshold1, $threshold2, $L2gradient)

    Local $iArrDx, $vectorDx, $iArrDxSize
    Local $bDxIsArray = IsArray($dx)
    Local $bDxCreate = IsDllStruct($dx) And $typeOfDx == "Scalar"

    If $typeOfDx == Default Then
        $iArrDx = $dx
    ElseIf $bDxIsArray Then
        $vectorDx = Call("_VectorOf" & $typeOfDx & "Create")

        $iArrDxSize = UBound($dx)
        For $i = 0 To $iArrDxSize - 1
            Call("_VectorOf" & $typeOfDx & "Push", $vectorDx, $dx[$i])
        Next

        $iArrDx = Call("_cveInputArrayFromVectorOf" & $typeOfDx, $vectorDx)
    Else
        If $bDxCreate Then
            $dx = Call("_cve" & $typeOfDx & "Create", $dx)
        EndIf
        $iArrDx = Call("_cveInputArrayFrom" & $typeOfDx, $dx)
    EndIf

    Local $iArrDy, $vectorDy, $iArrDySize
    Local $bDyIsArray = IsArray($dy)
    Local $bDyCreate = IsDllStruct($dy) And $typeOfDy == "Scalar"

    If $typeOfDy == Default Then
        $iArrDy = $dy
    ElseIf $bDyIsArray Then
        $vectorDy = Call("_VectorOf" & $typeOfDy & "Create")

        $iArrDySize = UBound($dy)
        For $i = 0 To $iArrDySize - 1
            Call("_VectorOf" & $typeOfDy & "Push", $vectorDy, $dy[$i])
        Next

        $iArrDy = Call("_cveInputArrayFromVectorOf" & $typeOfDy, $vectorDy)
    Else
        If $bDyCreate Then
            $dy = Call("_cve" & $typeOfDy & "Create", $dy)
        EndIf
        $iArrDy = Call("_cveInputArrayFrom" & $typeOfDy, $dy)
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

    _cveCanny2($iArrDx, $iArrDy, $oArrEdges, $threshold1, $threshold2, $L2gradient)

    If $bEdgesIsArray Then
        Call("_VectorOf" & $typeOfEdges & "Release", $vectorEdges)
    EndIf

    If $typeOfEdges <> Default Then
        _cveOutputArrayRelease($oArrEdges)
        If $bEdgesCreate Then
            Call("_cve" & $typeOfEdges & "Release", $edges)
        EndIf
    EndIf

    If $bDyIsArray Then
        Call("_VectorOf" & $typeOfDy & "Release", $vectorDy)
    EndIf

    If $typeOfDy <> Default Then
        _cveInputArrayRelease($iArrDy)
        If $bDyCreate Then
            Call("_cve" & $typeOfDy & "Release", $dy)
        EndIf
    EndIf

    If $bDxIsArray Then
        Call("_VectorOf" & $typeOfDx & "Release", $vectorDx)
    EndIf

    If $typeOfDx <> Default Then
        _cveInputArrayRelease($iArrDx)
        If $bDxCreate Then
            Call("_cve" & $typeOfDx & "Release", $dx)
        EndIf
    EndIf
EndFunc   ;==>_cveCanny2Typed

Func _cveCanny2Mat($dx, $dy, $edges, $threshold1, $threshold2, $L2gradient)
    ; cveCanny2 using cv::Mat instead of _*Array
    _cveCanny2Typed("Mat", $dx, "Mat", $dy, "Mat", $edges, $threshold1, $threshold2, $L2gradient)
EndFunc   ;==>_cveCanny2Mat

Func _cveCornerHarris($src, $dst, $blockSize, $ksize, $k, $borderType = $CV_BORDER_DEFAULT)
    ; CVAPI(void) cveCornerHarris(cv::_InputArray* src, cv::_OutputArray* dst, int blockSize, int ksize, double k, int borderType);

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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCornerHarris", $sSrcDllType, $src, $sDstDllType, $dst, "int", $blockSize, "int", $ksize, "double", $k, "int", $borderType), "cveCornerHarris", @error)
EndFunc   ;==>_cveCornerHarris

Func _cveCornerHarrisTyped($typeOfSrc, $src, $typeOfDst, $dst, $blockSize, $ksize, $k, $borderType = $CV_BORDER_DEFAULT)

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

    _cveCornerHarris($iArrSrc, $oArrDst, $blockSize, $ksize, $k, $borderType)

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
EndFunc   ;==>_cveCornerHarrisTyped

Func _cveCornerHarrisMat($src, $dst, $blockSize, $ksize, $k, $borderType = $CV_BORDER_DEFAULT)
    ; cveCornerHarris using cv::Mat instead of _*Array
    _cveCornerHarrisTyped("Mat", $src, "Mat", $dst, $blockSize, $ksize, $k, $borderType)
EndFunc   ;==>_cveCornerHarrisMat

Func _cveThreshold($src, $dst, $thresh, $maxval, $type)
    ; CVAPI(double) cveThreshold(cv::_InputArray* src, cv::_OutputArray* dst, double thresh, double maxval, int type);

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
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveThreshold", $sSrcDllType, $src, $sDstDllType, $dst, "double", $thresh, "double", $maxval, "int", $type), "cveThreshold", @error)
EndFunc   ;==>_cveThreshold

Func _cveThresholdTyped($typeOfSrc, $src, $typeOfDst, $dst, $thresh, $maxval, $type)

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

    Local $retval = _cveThreshold($iArrSrc, $oArrDst, $thresh, $maxval, $type)

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

    Return $retval
EndFunc   ;==>_cveThresholdTyped

Func _cveThresholdMat($src, $dst, $thresh, $maxval, $type)
    ; cveThreshold using cv::Mat instead of _*Array
    Local $retval = _cveThresholdTyped("Mat", $src, "Mat", $dst, $thresh, $maxval, $type)

    Return $retval
EndFunc   ;==>_cveThresholdMat

Func _cveWatershed($image, $markers)
    ; CVAPI(void) cveWatershed(cv::_InputArray* image, cv::_InputOutputArray* markers);

    Local $sImageDllType
    If IsDllStruct($image) Then
        $sImageDllType = "struct*"
    Else
        $sImageDllType = "ptr"
    EndIf

    Local $sMarkersDllType
    If IsDllStruct($markers) Then
        $sMarkersDllType = "struct*"
    Else
        $sMarkersDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveWatershed", $sImageDllType, $image, $sMarkersDllType, $markers), "cveWatershed", @error)
EndFunc   ;==>_cveWatershed

Func _cveWatershedTyped($typeOfImage, $image, $typeOfMarkers, $markers)

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

    Local $ioArrMarkers, $vectorMarkers, $iArrMarkersSize
    Local $bMarkersIsArray = IsArray($markers)
    Local $bMarkersCreate = IsDllStruct($markers) And $typeOfMarkers == "Scalar"

    If $typeOfMarkers == Default Then
        $ioArrMarkers = $markers
    ElseIf $bMarkersIsArray Then
        $vectorMarkers = Call("_VectorOf" & $typeOfMarkers & "Create")

        $iArrMarkersSize = UBound($markers)
        For $i = 0 To $iArrMarkersSize - 1
            Call("_VectorOf" & $typeOfMarkers & "Push", $vectorMarkers, $markers[$i])
        Next

        $ioArrMarkers = Call("_cveInputOutputArrayFromVectorOf" & $typeOfMarkers, $vectorMarkers)
    Else
        If $bMarkersCreate Then
            $markers = Call("_cve" & $typeOfMarkers & "Create", $markers)
        EndIf
        $ioArrMarkers = Call("_cveInputOutputArrayFrom" & $typeOfMarkers, $markers)
    EndIf

    _cveWatershed($iArrImage, $ioArrMarkers)

    If $bMarkersIsArray Then
        Call("_VectorOf" & $typeOfMarkers & "Release", $vectorMarkers)
    EndIf

    If $typeOfMarkers <> Default Then
        _cveInputOutputArrayRelease($ioArrMarkers)
        If $bMarkersCreate Then
            Call("_cve" & $typeOfMarkers & "Release", $markers)
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
EndFunc   ;==>_cveWatershedTyped

Func _cveWatershedMat($image, $markers)
    ; cveWatershed using cv::Mat instead of _*Array
    _cveWatershedTyped("Mat", $image, "Mat", $markers)
EndFunc   ;==>_cveWatershedMat

Func _cveAdaptiveThreshold($src, $dst, $maxValue, $adaptiveMethod, $thresholdType, $blockSize, $c)
    ; CVAPI(void) cveAdaptiveThreshold(cv::_InputArray* src, cv::_OutputArray* dst, double maxValue, int adaptiveMethod, int thresholdType, int blockSize, double c);

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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveAdaptiveThreshold", $sSrcDllType, $src, $sDstDllType, $dst, "double", $maxValue, "int", $adaptiveMethod, "int", $thresholdType, "int", $blockSize, "double", $c), "cveAdaptiveThreshold", @error)
EndFunc   ;==>_cveAdaptiveThreshold

Func _cveAdaptiveThresholdTyped($typeOfSrc, $src, $typeOfDst, $dst, $maxValue, $adaptiveMethod, $thresholdType, $blockSize, $c)

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

    _cveAdaptiveThreshold($iArrSrc, $oArrDst, $maxValue, $adaptiveMethod, $thresholdType, $blockSize, $c)

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
EndFunc   ;==>_cveAdaptiveThresholdTyped

Func _cveAdaptiveThresholdMat($src, $dst, $maxValue, $adaptiveMethod, $thresholdType, $blockSize, $c)
    ; cveAdaptiveThreshold using cv::Mat instead of _*Array
    _cveAdaptiveThresholdTyped("Mat", $src, "Mat", $dst, $maxValue, $adaptiveMethod, $thresholdType, $blockSize, $c)
EndFunc   ;==>_cveAdaptiveThresholdMat

Func _cveCvtColor($src, $dst, $code, $dstCn = 0)
    ; CVAPI(void) cveCvtColor(cv::_InputArray* src, cv::_OutputArray* dst, int code, int dstCn);

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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCvtColor", $sSrcDllType, $src, $sDstDllType, $dst, "int", $code, "int", $dstCn), "cveCvtColor", @error)
EndFunc   ;==>_cveCvtColor

Func _cveCvtColorTyped($typeOfSrc, $src, $typeOfDst, $dst, $code, $dstCn = 0)

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

    _cveCvtColor($iArrSrc, $oArrDst, $code, $dstCn)

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
EndFunc   ;==>_cveCvtColorTyped

Func _cveCvtColorMat($src, $dst, $code, $dstCn = 0)
    ; cveCvtColor using cv::Mat instead of _*Array
    _cveCvtColorTyped("Mat", $src, "Mat", $dst, $code, $dstCn)
EndFunc   ;==>_cveCvtColorMat

Func _cveCopyMakeBorder($src, $dst, $top, $bottom, $left, $right, $borderType, $value = _cvScalar())
    ; CVAPI(void) cveCopyMakeBorder(cv::_InputArray* src, cv::_OutputArray* dst, int top, int bottom, int left, int right, int borderType, CvScalar* value);

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

    Local $sValueDllType
    If IsDllStruct($value) Then
        $sValueDllType = "struct*"
    Else
        $sValueDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCopyMakeBorder", $sSrcDllType, $src, $sDstDllType, $dst, "int", $top, "int", $bottom, "int", $left, "int", $right, "int", $borderType, $sValueDllType, $value), "cveCopyMakeBorder", @error)
EndFunc   ;==>_cveCopyMakeBorder

Func _cveCopyMakeBorderTyped($typeOfSrc, $src, $typeOfDst, $dst, $top, $bottom, $left, $right, $borderType, $value = _cvScalar())

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

    _cveCopyMakeBorder($iArrSrc, $oArrDst, $top, $bottom, $left, $right, $borderType, $value)

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
EndFunc   ;==>_cveCopyMakeBorderTyped

Func _cveCopyMakeBorderMat($src, $dst, $top, $bottom, $left, $right, $borderType, $value = _cvScalar())
    ; cveCopyMakeBorder using cv::Mat instead of _*Array
    _cveCopyMakeBorderTyped("Mat", $src, "Mat", $dst, $top, $bottom, $left, $right, $borderType, $value)
EndFunc   ;==>_cveCopyMakeBorderMat

Func _cveIntegral($src, $sum, $sqsum, $tilted, $sdepth, $sqdepth)
    ; CVAPI(void) cveIntegral(cv::_InputArray* src, cv::_OutputArray* sum, cv::_OutputArray* sqsum, cv::_OutputArray* tilted, int sdepth, int sqdepth);

    Local $sSrcDllType
    If IsDllStruct($src) Then
        $sSrcDllType = "struct*"
    Else
        $sSrcDllType = "ptr"
    EndIf

    Local $sSumDllType
    If IsDllStruct($sum) Then
        $sSumDllType = "struct*"
    Else
        $sSumDllType = "ptr"
    EndIf

    Local $sSqsumDllType
    If IsDllStruct($sqsum) Then
        $sSqsumDllType = "struct*"
    Else
        $sSqsumDllType = "ptr"
    EndIf

    Local $sTiltedDllType
    If IsDllStruct($tilted) Then
        $sTiltedDllType = "struct*"
    Else
        $sTiltedDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveIntegral", $sSrcDllType, $src, $sSumDllType, $sum, $sSqsumDllType, $sqsum, $sTiltedDllType, $tilted, "int", $sdepth, "int", $sqdepth), "cveIntegral", @error)
EndFunc   ;==>_cveIntegral

Func _cveIntegralTyped($typeOfSrc, $src, $typeOfSum, $sum, $typeOfSqsum, $sqsum, $typeOfTilted, $tilted, $sdepth, $sqdepth)

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

    Local $oArrSum, $vectorSum, $iArrSumSize
    Local $bSumIsArray = IsArray($sum)
    Local $bSumCreate = IsDllStruct($sum) And $typeOfSum == "Scalar"

    If $typeOfSum == Default Then
        $oArrSum = $sum
    ElseIf $bSumIsArray Then
        $vectorSum = Call("_VectorOf" & $typeOfSum & "Create")

        $iArrSumSize = UBound($sum)
        For $i = 0 To $iArrSumSize - 1
            Call("_VectorOf" & $typeOfSum & "Push", $vectorSum, $sum[$i])
        Next

        $oArrSum = Call("_cveOutputArrayFromVectorOf" & $typeOfSum, $vectorSum)
    Else
        If $bSumCreate Then
            $sum = Call("_cve" & $typeOfSum & "Create", $sum)
        EndIf
        $oArrSum = Call("_cveOutputArrayFrom" & $typeOfSum, $sum)
    EndIf

    Local $oArrSqsum, $vectorSqsum, $iArrSqsumSize
    Local $bSqsumIsArray = IsArray($sqsum)
    Local $bSqsumCreate = IsDllStruct($sqsum) And $typeOfSqsum == "Scalar"

    If $typeOfSqsum == Default Then
        $oArrSqsum = $sqsum
    ElseIf $bSqsumIsArray Then
        $vectorSqsum = Call("_VectorOf" & $typeOfSqsum & "Create")

        $iArrSqsumSize = UBound($sqsum)
        For $i = 0 To $iArrSqsumSize - 1
            Call("_VectorOf" & $typeOfSqsum & "Push", $vectorSqsum, $sqsum[$i])
        Next

        $oArrSqsum = Call("_cveOutputArrayFromVectorOf" & $typeOfSqsum, $vectorSqsum)
    Else
        If $bSqsumCreate Then
            $sqsum = Call("_cve" & $typeOfSqsum & "Create", $sqsum)
        EndIf
        $oArrSqsum = Call("_cveOutputArrayFrom" & $typeOfSqsum, $sqsum)
    EndIf

    Local $oArrTilted, $vectorTilted, $iArrTiltedSize
    Local $bTiltedIsArray = IsArray($tilted)
    Local $bTiltedCreate = IsDllStruct($tilted) And $typeOfTilted == "Scalar"

    If $typeOfTilted == Default Then
        $oArrTilted = $tilted
    ElseIf $bTiltedIsArray Then
        $vectorTilted = Call("_VectorOf" & $typeOfTilted & "Create")

        $iArrTiltedSize = UBound($tilted)
        For $i = 0 To $iArrTiltedSize - 1
            Call("_VectorOf" & $typeOfTilted & "Push", $vectorTilted, $tilted[$i])
        Next

        $oArrTilted = Call("_cveOutputArrayFromVectorOf" & $typeOfTilted, $vectorTilted)
    Else
        If $bTiltedCreate Then
            $tilted = Call("_cve" & $typeOfTilted & "Create", $tilted)
        EndIf
        $oArrTilted = Call("_cveOutputArrayFrom" & $typeOfTilted, $tilted)
    EndIf

    _cveIntegral($iArrSrc, $oArrSum, $oArrSqsum, $oArrTilted, $sdepth, $sqdepth)

    If $bTiltedIsArray Then
        Call("_VectorOf" & $typeOfTilted & "Release", $vectorTilted)
    EndIf

    If $typeOfTilted <> Default Then
        _cveOutputArrayRelease($oArrTilted)
        If $bTiltedCreate Then
            Call("_cve" & $typeOfTilted & "Release", $tilted)
        EndIf
    EndIf

    If $bSqsumIsArray Then
        Call("_VectorOf" & $typeOfSqsum & "Release", $vectorSqsum)
    EndIf

    If $typeOfSqsum <> Default Then
        _cveOutputArrayRelease($oArrSqsum)
        If $bSqsumCreate Then
            Call("_cve" & $typeOfSqsum & "Release", $sqsum)
        EndIf
    EndIf

    If $bSumIsArray Then
        Call("_VectorOf" & $typeOfSum & "Release", $vectorSum)
    EndIf

    If $typeOfSum <> Default Then
        _cveOutputArrayRelease($oArrSum)
        If $bSumCreate Then
            Call("_cve" & $typeOfSum & "Release", $sum)
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
EndFunc   ;==>_cveIntegralTyped

Func _cveIntegralMat($src, $sum, $sqsum, $tilted, $sdepth, $sqdepth)
    ; cveIntegral using cv::Mat instead of _*Array
    _cveIntegralTyped("Mat", $src, "Mat", $sum, "Mat", $sqsum, "Mat", $tilted, $sdepth, $sqdepth)
EndFunc   ;==>_cveIntegralMat

Func _cveFloodFill($image, $mask, $seedPoint, $newVal, $rect = 0, $loDiff = _cvScalar(), $upDiff = _cvScalar(), $flags = 4)
    ; CVAPI(int) cveFloodFill(cv::_InputOutputArray* image, cv::_InputOutputArray* mask, CvPoint* seedPoint, CvScalar* newVal, CvRect* rect, CvScalar* loDiff, CvScalar* upDiff, int flags);

    Local $sImageDllType
    If IsDllStruct($image) Then
        $sImageDllType = "struct*"
    Else
        $sImageDllType = "ptr"
    EndIf

    Local $sMaskDllType
    If IsDllStruct($mask) Then
        $sMaskDllType = "struct*"
    Else
        $sMaskDllType = "ptr"
    EndIf

    Local $sSeedPointDllType
    If IsDllStruct($seedPoint) Then
        $sSeedPointDllType = "struct*"
    Else
        $sSeedPointDllType = "ptr"
    EndIf

    Local $sNewValDllType
    If IsDllStruct($newVal) Then
        $sNewValDllType = "struct*"
    Else
        $sNewValDllType = "ptr"
    EndIf

    Local $sRectDllType
    If IsDllStruct($rect) Then
        $sRectDllType = "struct*"
    Else
        $sRectDllType = "ptr"
    EndIf

    Local $sLoDiffDllType
    If IsDllStruct($loDiff) Then
        $sLoDiffDllType = "struct*"
    Else
        $sLoDiffDllType = "ptr"
    EndIf

    Local $sUpDiffDllType
    If IsDllStruct($upDiff) Then
        $sUpDiffDllType = "struct*"
    Else
        $sUpDiffDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveFloodFill", $sImageDllType, $image, $sMaskDllType, $mask, $sSeedPointDllType, $seedPoint, $sNewValDllType, $newVal, $sRectDllType, $rect, $sLoDiffDllType, $loDiff, $sUpDiffDllType, $upDiff, "int", $flags), "cveFloodFill", @error)
EndFunc   ;==>_cveFloodFill

Func _cveFloodFillTyped($typeOfImage, $image, $typeOfMask, $mask, $seedPoint, $newVal, $rect = 0, $loDiff = _cvScalar(), $upDiff = _cvScalar(), $flags = 4)

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

    Local $ioArrMask, $vectorMask, $iArrMaskSize
    Local $bMaskIsArray = IsArray($mask)
    Local $bMaskCreate = IsDllStruct($mask) And $typeOfMask == "Scalar"

    If $typeOfMask == Default Then
        $ioArrMask = $mask
    ElseIf $bMaskIsArray Then
        $vectorMask = Call("_VectorOf" & $typeOfMask & "Create")

        $iArrMaskSize = UBound($mask)
        For $i = 0 To $iArrMaskSize - 1
            Call("_VectorOf" & $typeOfMask & "Push", $vectorMask, $mask[$i])
        Next

        $ioArrMask = Call("_cveInputOutputArrayFromVectorOf" & $typeOfMask, $vectorMask)
    Else
        If $bMaskCreate Then
            $mask = Call("_cve" & $typeOfMask & "Create", $mask)
        EndIf
        $ioArrMask = Call("_cveInputOutputArrayFrom" & $typeOfMask, $mask)
    EndIf

    Local $retval = _cveFloodFill($ioArrImage, $ioArrMask, $seedPoint, $newVal, $rect, $loDiff, $upDiff, $flags)

    If $bMaskIsArray Then
        Call("_VectorOf" & $typeOfMask & "Release", $vectorMask)
    EndIf

    If $typeOfMask <> Default Then
        _cveInputOutputArrayRelease($ioArrMask)
        If $bMaskCreate Then
            Call("_cve" & $typeOfMask & "Release", $mask)
        EndIf
    EndIf

    If $bImageIsArray Then
        Call("_VectorOf" & $typeOfImage & "Release", $vectorImage)
    EndIf

    If $typeOfImage <> Default Then
        _cveInputOutputArrayRelease($ioArrImage)
        If $bImageCreate Then
            Call("_cve" & $typeOfImage & "Release", $image)
        EndIf
    EndIf

    Return $retval
EndFunc   ;==>_cveFloodFillTyped

Func _cveFloodFillMat($image, $mask, $seedPoint, $newVal, $rect = 0, $loDiff = _cvScalar(), $upDiff = _cvScalar(), $flags = 4)
    ; cveFloodFill using cv::Mat instead of _*Array
    Local $retval = _cveFloodFillTyped("Mat", $image, "Mat", $mask, $seedPoint, $newVal, $rect, $loDiff, $upDiff, $flags)

    Return $retval
EndFunc   ;==>_cveFloodFillMat

Func _cvePyrMeanShiftFiltering($src, $dst, $sp, $sr, $maxLevel = 1, $termCrit = _cvTermCriteria($CV_TERM_CRITERIA_MAX_ITER+$CV_TERM_CRITERIA_EPS,5,1))
    ; CVAPI(void) cvePyrMeanShiftFiltering(cv::_InputArray* src, cv::_OutputArray* dst, double sp, double sr, int maxLevel, CvTermCriteria* termCrit);

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

    Local $sTermCritDllType
    If IsDllStruct($termCrit) Then
        $sTermCritDllType = "struct*"
    Else
        $sTermCritDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cvePyrMeanShiftFiltering", $sSrcDllType, $src, $sDstDllType, $dst, "double", $sp, "double", $sr, "int", $maxLevel, $sTermCritDllType, $termCrit), "cvePyrMeanShiftFiltering", @error)
EndFunc   ;==>_cvePyrMeanShiftFiltering

Func _cvePyrMeanShiftFilteringTyped($typeOfSrc, $src, $typeOfDst, $dst, $sp, $sr, $maxLevel = 1, $termCrit = _cvTermCriteria($CV_TERM_CRITERIA_MAX_ITER+$CV_TERM_CRITERIA_EPS,5,1))

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

    _cvePyrMeanShiftFiltering($iArrSrc, $oArrDst, $sp, $sr, $maxLevel, $termCrit)

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
EndFunc   ;==>_cvePyrMeanShiftFilteringTyped

Func _cvePyrMeanShiftFilteringMat($src, $dst, $sp, $sr, $maxLevel = 1, $termCrit = _cvTermCriteria($CV_TERM_CRITERIA_MAX_ITER+$CV_TERM_CRITERIA_EPS,5,1))
    ; cvePyrMeanShiftFiltering using cv::Mat instead of _*Array
    _cvePyrMeanShiftFilteringTyped("Mat", $src, "Mat", $dst, $sp, $sr, $maxLevel, $termCrit)
EndFunc   ;==>_cvePyrMeanShiftFilteringMat

Func _cveMoments($arr, $binaryImage, $moments)
    ; CVAPI(void) cveMoments(cv::_InputArray* arr, bool binaryImage, cv::Moments* moments);

    Local $sArrDllType
    If IsDllStruct($arr) Then
        $sArrDllType = "struct*"
    Else
        $sArrDllType = "ptr"
    EndIf

    Local $sMomentsDllType
    If IsDllStruct($moments) Then
        $sMomentsDllType = "struct*"
    Else
        $sMomentsDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMoments", $sArrDllType, $arr, "boolean", $binaryImage, $sMomentsDllType, $moments), "cveMoments", @error)
EndFunc   ;==>_cveMoments

Func _cveMomentsTyped($typeOfArr, $arr, $binaryImage, $moments)

    Local $iArrArr, $vectorArr, $iArrArrSize
    Local $bArrIsArray = IsArray($arr)
    Local $bArrCreate = IsDllStruct($arr) And $typeOfArr == "Scalar"

    If $typeOfArr == Default Then
        $iArrArr = $arr
    ElseIf $bArrIsArray Then
        $vectorArr = Call("_VectorOf" & $typeOfArr & "Create")

        $iArrArrSize = UBound($arr)
        For $i = 0 To $iArrArrSize - 1
            Call("_VectorOf" & $typeOfArr & "Push", $vectorArr, $arr[$i])
        Next

        $iArrArr = Call("_cveInputArrayFromVectorOf" & $typeOfArr, $vectorArr)
    Else
        If $bArrCreate Then
            $arr = Call("_cve" & $typeOfArr & "Create", $arr)
        EndIf
        $iArrArr = Call("_cveInputArrayFrom" & $typeOfArr, $arr)
    EndIf

    _cveMoments($iArrArr, $binaryImage, $moments)

    If $bArrIsArray Then
        Call("_VectorOf" & $typeOfArr & "Release", $vectorArr)
    EndIf

    If $typeOfArr <> Default Then
        _cveInputArrayRelease($iArrArr)
        If $bArrCreate Then
            Call("_cve" & $typeOfArr & "Release", $arr)
        EndIf
    EndIf
EndFunc   ;==>_cveMomentsTyped

Func _cveMomentsMat($arr, $binaryImage, $moments)
    ; cveMoments using cv::Mat instead of _*Array
    _cveMomentsTyped("Mat", $arr, $binaryImage, $moments)
EndFunc   ;==>_cveMomentsMat

Func _cveEqualizeHist($src, $dst)
    ; CVAPI(void) cveEqualizeHist(cv::_InputArray* src, cv::_OutputArray* dst);

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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveEqualizeHist", $sSrcDllType, $src, $sDstDllType, $dst), "cveEqualizeHist", @error)
EndFunc   ;==>_cveEqualizeHist

Func _cveEqualizeHistTyped($typeOfSrc, $src, $typeOfDst, $dst)

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

    _cveEqualizeHist($iArrSrc, $oArrDst)

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
EndFunc   ;==>_cveEqualizeHistTyped

Func _cveEqualizeHistMat($src, $dst)
    ; cveEqualizeHist using cv::Mat instead of _*Array
    _cveEqualizeHistTyped("Mat", $src, "Mat", $dst)
EndFunc   ;==>_cveEqualizeHistMat

Func _cveAccumulate($src, $dst, $mask = _cveNoArray())
    ; CVAPI(void) cveAccumulate(cv::_InputArray* src, cv::_InputOutputArray* dst, cv::_InputArray* mask);

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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveAccumulate", $sSrcDllType, $src, $sDstDllType, $dst, $sMaskDllType, $mask), "cveAccumulate", @error)
EndFunc   ;==>_cveAccumulate

Func _cveAccumulateTyped($typeOfSrc, $src, $typeOfDst, $dst, $typeOfMask = Default, $mask = _cveNoArray())

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

    Local $ioArrDst, $vectorDst, $iArrDstSize
    Local $bDstIsArray = IsArray($dst)
    Local $bDstCreate = IsDllStruct($dst) And $typeOfDst == "Scalar"

    If $typeOfDst == Default Then
        $ioArrDst = $dst
    ElseIf $bDstIsArray Then
        $vectorDst = Call("_VectorOf" & $typeOfDst & "Create")

        $iArrDstSize = UBound($dst)
        For $i = 0 To $iArrDstSize - 1
            Call("_VectorOf" & $typeOfDst & "Push", $vectorDst, $dst[$i])
        Next

        $ioArrDst = Call("_cveInputOutputArrayFromVectorOf" & $typeOfDst, $vectorDst)
    Else
        If $bDstCreate Then
            $dst = Call("_cve" & $typeOfDst & "Create", $dst)
        EndIf
        $ioArrDst = Call("_cveInputOutputArrayFrom" & $typeOfDst, $dst)
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

    _cveAccumulate($iArrSrc, $ioArrDst, $iArrMask)

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
        _cveInputOutputArrayRelease($ioArrDst)
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
EndFunc   ;==>_cveAccumulateTyped

Func _cveAccumulateMat($src, $dst, $mask = _cveNoArrayMat())
    ; cveAccumulate using cv::Mat instead of _*Array
    _cveAccumulateTyped("Mat", $src, "Mat", $dst, "Mat", $mask)
EndFunc   ;==>_cveAccumulateMat

Func _cveAccumulateSquare($src, $dst, $mask = _cveNoArray())
    ; CVAPI(void) cveAccumulateSquare(cv::_InputArray* src, cv::_InputOutputArray* dst, cv::_InputArray* mask);

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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveAccumulateSquare", $sSrcDllType, $src, $sDstDllType, $dst, $sMaskDllType, $mask), "cveAccumulateSquare", @error)
EndFunc   ;==>_cveAccumulateSquare

Func _cveAccumulateSquareTyped($typeOfSrc, $src, $typeOfDst, $dst, $typeOfMask = Default, $mask = _cveNoArray())

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

    Local $ioArrDst, $vectorDst, $iArrDstSize
    Local $bDstIsArray = IsArray($dst)
    Local $bDstCreate = IsDllStruct($dst) And $typeOfDst == "Scalar"

    If $typeOfDst == Default Then
        $ioArrDst = $dst
    ElseIf $bDstIsArray Then
        $vectorDst = Call("_VectorOf" & $typeOfDst & "Create")

        $iArrDstSize = UBound($dst)
        For $i = 0 To $iArrDstSize - 1
            Call("_VectorOf" & $typeOfDst & "Push", $vectorDst, $dst[$i])
        Next

        $ioArrDst = Call("_cveInputOutputArrayFromVectorOf" & $typeOfDst, $vectorDst)
    Else
        If $bDstCreate Then
            $dst = Call("_cve" & $typeOfDst & "Create", $dst)
        EndIf
        $ioArrDst = Call("_cveInputOutputArrayFrom" & $typeOfDst, $dst)
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

    _cveAccumulateSquare($iArrSrc, $ioArrDst, $iArrMask)

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
        _cveInputOutputArrayRelease($ioArrDst)
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
EndFunc   ;==>_cveAccumulateSquareTyped

Func _cveAccumulateSquareMat($src, $dst, $mask = _cveNoArrayMat())
    ; cveAccumulateSquare using cv::Mat instead of _*Array
    _cveAccumulateSquareTyped("Mat", $src, "Mat", $dst, "Mat", $mask)
EndFunc   ;==>_cveAccumulateSquareMat

Func _cveAccumulateProduct($src1, $src2, $dst, $mask = _cveNoArray())
    ; CVAPI(void) cveAccumulateProduct(cv::_InputArray* src1, cv::_InputArray* src2, cv::_InputOutputArray* dst, cv::_InputArray* mask);

    Local $sSrc1DllType
    If IsDllStruct($src1) Then
        $sSrc1DllType = "struct*"
    Else
        $sSrc1DllType = "ptr"
    EndIf

    Local $sSrc2DllType
    If IsDllStruct($src2) Then
        $sSrc2DllType = "struct*"
    Else
        $sSrc2DllType = "ptr"
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveAccumulateProduct", $sSrc1DllType, $src1, $sSrc2DllType, $src2, $sDstDllType, $dst, $sMaskDllType, $mask), "cveAccumulateProduct", @error)
EndFunc   ;==>_cveAccumulateProduct

Func _cveAccumulateProductTyped($typeOfSrc1, $src1, $typeOfSrc2, $src2, $typeOfDst, $dst, $typeOfMask = Default, $mask = _cveNoArray())

    Local $iArrSrc1, $vectorSrc1, $iArrSrc1Size
    Local $bSrc1IsArray = IsArray($src1)
    Local $bSrc1Create = IsDllStruct($src1) And $typeOfSrc1 == "Scalar"

    If $typeOfSrc1 == Default Then
        $iArrSrc1 = $src1
    ElseIf $bSrc1IsArray Then
        $vectorSrc1 = Call("_VectorOf" & $typeOfSrc1 & "Create")

        $iArrSrc1Size = UBound($src1)
        For $i = 0 To $iArrSrc1Size - 1
            Call("_VectorOf" & $typeOfSrc1 & "Push", $vectorSrc1, $src1[$i])
        Next

        $iArrSrc1 = Call("_cveInputArrayFromVectorOf" & $typeOfSrc1, $vectorSrc1)
    Else
        If $bSrc1Create Then
            $src1 = Call("_cve" & $typeOfSrc1 & "Create", $src1)
        EndIf
        $iArrSrc1 = Call("_cveInputArrayFrom" & $typeOfSrc1, $src1)
    EndIf

    Local $iArrSrc2, $vectorSrc2, $iArrSrc2Size
    Local $bSrc2IsArray = IsArray($src2)
    Local $bSrc2Create = IsDllStruct($src2) And $typeOfSrc2 == "Scalar"

    If $typeOfSrc2 == Default Then
        $iArrSrc2 = $src2
    ElseIf $bSrc2IsArray Then
        $vectorSrc2 = Call("_VectorOf" & $typeOfSrc2 & "Create")

        $iArrSrc2Size = UBound($src2)
        For $i = 0 To $iArrSrc2Size - 1
            Call("_VectorOf" & $typeOfSrc2 & "Push", $vectorSrc2, $src2[$i])
        Next

        $iArrSrc2 = Call("_cveInputArrayFromVectorOf" & $typeOfSrc2, $vectorSrc2)
    Else
        If $bSrc2Create Then
            $src2 = Call("_cve" & $typeOfSrc2 & "Create", $src2)
        EndIf
        $iArrSrc2 = Call("_cveInputArrayFrom" & $typeOfSrc2, $src2)
    EndIf

    Local $ioArrDst, $vectorDst, $iArrDstSize
    Local $bDstIsArray = IsArray($dst)
    Local $bDstCreate = IsDllStruct($dst) And $typeOfDst == "Scalar"

    If $typeOfDst == Default Then
        $ioArrDst = $dst
    ElseIf $bDstIsArray Then
        $vectorDst = Call("_VectorOf" & $typeOfDst & "Create")

        $iArrDstSize = UBound($dst)
        For $i = 0 To $iArrDstSize - 1
            Call("_VectorOf" & $typeOfDst & "Push", $vectorDst, $dst[$i])
        Next

        $ioArrDst = Call("_cveInputOutputArrayFromVectorOf" & $typeOfDst, $vectorDst)
    Else
        If $bDstCreate Then
            $dst = Call("_cve" & $typeOfDst & "Create", $dst)
        EndIf
        $ioArrDst = Call("_cveInputOutputArrayFrom" & $typeOfDst, $dst)
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

    _cveAccumulateProduct($iArrSrc1, $iArrSrc2, $ioArrDst, $iArrMask)

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
        _cveInputOutputArrayRelease($ioArrDst)
        If $bDstCreate Then
            Call("_cve" & $typeOfDst & "Release", $dst)
        EndIf
    EndIf

    If $bSrc2IsArray Then
        Call("_VectorOf" & $typeOfSrc2 & "Release", $vectorSrc2)
    EndIf

    If $typeOfSrc2 <> Default Then
        _cveInputArrayRelease($iArrSrc2)
        If $bSrc2Create Then
            Call("_cve" & $typeOfSrc2 & "Release", $src2)
        EndIf
    EndIf

    If $bSrc1IsArray Then
        Call("_VectorOf" & $typeOfSrc1 & "Release", $vectorSrc1)
    EndIf

    If $typeOfSrc1 <> Default Then
        _cveInputArrayRelease($iArrSrc1)
        If $bSrc1Create Then
            Call("_cve" & $typeOfSrc1 & "Release", $src1)
        EndIf
    EndIf
EndFunc   ;==>_cveAccumulateProductTyped

Func _cveAccumulateProductMat($src1, $src2, $dst, $mask = _cveNoArrayMat())
    ; cveAccumulateProduct using cv::Mat instead of _*Array
    _cveAccumulateProductTyped("Mat", $src1, "Mat", $src2, "Mat", $dst, "Mat", $mask)
EndFunc   ;==>_cveAccumulateProductMat

Func _cveAccumulateWeighted($src, $dst, $alpha, $mask = _cveNoArray())
    ; CVAPI(void) cveAccumulateWeighted(cv::_InputArray* src, cv::_InputOutputArray* dst, double alpha, cv::_InputArray* mask);

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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveAccumulateWeighted", $sSrcDllType, $src, $sDstDllType, $dst, "double", $alpha, $sMaskDllType, $mask), "cveAccumulateWeighted", @error)
EndFunc   ;==>_cveAccumulateWeighted

Func _cveAccumulateWeightedTyped($typeOfSrc, $src, $typeOfDst, $dst, $alpha, $typeOfMask = Default, $mask = _cveNoArray())

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

    Local $ioArrDst, $vectorDst, $iArrDstSize
    Local $bDstIsArray = IsArray($dst)
    Local $bDstCreate = IsDllStruct($dst) And $typeOfDst == "Scalar"

    If $typeOfDst == Default Then
        $ioArrDst = $dst
    ElseIf $bDstIsArray Then
        $vectorDst = Call("_VectorOf" & $typeOfDst & "Create")

        $iArrDstSize = UBound($dst)
        For $i = 0 To $iArrDstSize - 1
            Call("_VectorOf" & $typeOfDst & "Push", $vectorDst, $dst[$i])
        Next

        $ioArrDst = Call("_cveInputOutputArrayFromVectorOf" & $typeOfDst, $vectorDst)
    Else
        If $bDstCreate Then
            $dst = Call("_cve" & $typeOfDst & "Create", $dst)
        EndIf
        $ioArrDst = Call("_cveInputOutputArrayFrom" & $typeOfDst, $dst)
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

    _cveAccumulateWeighted($iArrSrc, $ioArrDst, $alpha, $iArrMask)

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
        _cveInputOutputArrayRelease($ioArrDst)
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
EndFunc   ;==>_cveAccumulateWeightedTyped

Func _cveAccumulateWeightedMat($src, $dst, $alpha, $mask = _cveNoArrayMat())
    ; cveAccumulateWeighted using cv::Mat instead of _*Array
    _cveAccumulateWeightedTyped("Mat", $src, "Mat", $dst, $alpha, "Mat", $mask)
EndFunc   ;==>_cveAccumulateWeightedMat

Func _cvePhaseCorrelate($src1, $src2, $window, $response, $result)
    ; CVAPI(void) cvePhaseCorrelate(cv::_InputArray* src1, cv::_InputArray* src2, cv::_InputArray* window, double* response, CvPoint2D64f* result);

    Local $sSrc1DllType
    If IsDllStruct($src1) Then
        $sSrc1DllType = "struct*"
    Else
        $sSrc1DllType = "ptr"
    EndIf

    Local $sSrc2DllType
    If IsDllStruct($src2) Then
        $sSrc2DllType = "struct*"
    Else
        $sSrc2DllType = "ptr"
    EndIf

    Local $sWindowDllType
    If IsDllStruct($window) Then
        $sWindowDllType = "struct*"
    Else
        $sWindowDllType = "ptr"
    EndIf

    Local $sResponseDllType
    If IsDllStruct($response) Then
        $sResponseDllType = "struct*"
    Else
        $sResponseDllType = "double*"
    EndIf

    Local $sResultDllType
    If IsDllStruct($result) Then
        $sResultDllType = "struct*"
    Else
        $sResultDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cvePhaseCorrelate", $sSrc1DllType, $src1, $sSrc2DllType, $src2, $sWindowDllType, $window, $sResponseDllType, $response, $sResultDllType, $result), "cvePhaseCorrelate", @error)
EndFunc   ;==>_cvePhaseCorrelate

Func _cvePhaseCorrelateTyped($typeOfSrc1, $src1, $typeOfSrc2, $src2, $typeOfWindow, $window, $response, $result)

    Local $iArrSrc1, $vectorSrc1, $iArrSrc1Size
    Local $bSrc1IsArray = IsArray($src1)
    Local $bSrc1Create = IsDllStruct($src1) And $typeOfSrc1 == "Scalar"

    If $typeOfSrc1 == Default Then
        $iArrSrc1 = $src1
    ElseIf $bSrc1IsArray Then
        $vectorSrc1 = Call("_VectorOf" & $typeOfSrc1 & "Create")

        $iArrSrc1Size = UBound($src1)
        For $i = 0 To $iArrSrc1Size - 1
            Call("_VectorOf" & $typeOfSrc1 & "Push", $vectorSrc1, $src1[$i])
        Next

        $iArrSrc1 = Call("_cveInputArrayFromVectorOf" & $typeOfSrc1, $vectorSrc1)
    Else
        If $bSrc1Create Then
            $src1 = Call("_cve" & $typeOfSrc1 & "Create", $src1)
        EndIf
        $iArrSrc1 = Call("_cveInputArrayFrom" & $typeOfSrc1, $src1)
    EndIf

    Local $iArrSrc2, $vectorSrc2, $iArrSrc2Size
    Local $bSrc2IsArray = IsArray($src2)
    Local $bSrc2Create = IsDllStruct($src2) And $typeOfSrc2 == "Scalar"

    If $typeOfSrc2 == Default Then
        $iArrSrc2 = $src2
    ElseIf $bSrc2IsArray Then
        $vectorSrc2 = Call("_VectorOf" & $typeOfSrc2 & "Create")

        $iArrSrc2Size = UBound($src2)
        For $i = 0 To $iArrSrc2Size - 1
            Call("_VectorOf" & $typeOfSrc2 & "Push", $vectorSrc2, $src2[$i])
        Next

        $iArrSrc2 = Call("_cveInputArrayFromVectorOf" & $typeOfSrc2, $vectorSrc2)
    Else
        If $bSrc2Create Then
            $src2 = Call("_cve" & $typeOfSrc2 & "Create", $src2)
        EndIf
        $iArrSrc2 = Call("_cveInputArrayFrom" & $typeOfSrc2, $src2)
    EndIf

    Local $iArrWindow, $vectorWindow, $iArrWindowSize
    Local $bWindowIsArray = IsArray($window)
    Local $bWindowCreate = IsDllStruct($window) And $typeOfWindow == "Scalar"

    If $typeOfWindow == Default Then
        $iArrWindow = $window
    ElseIf $bWindowIsArray Then
        $vectorWindow = Call("_VectorOf" & $typeOfWindow & "Create")

        $iArrWindowSize = UBound($window)
        For $i = 0 To $iArrWindowSize - 1
            Call("_VectorOf" & $typeOfWindow & "Push", $vectorWindow, $window[$i])
        Next

        $iArrWindow = Call("_cveInputArrayFromVectorOf" & $typeOfWindow, $vectorWindow)
    Else
        If $bWindowCreate Then
            $window = Call("_cve" & $typeOfWindow & "Create", $window)
        EndIf
        $iArrWindow = Call("_cveInputArrayFrom" & $typeOfWindow, $window)
    EndIf

    _cvePhaseCorrelate($iArrSrc1, $iArrSrc2, $iArrWindow, $response, $result)

    If $bWindowIsArray Then
        Call("_VectorOf" & $typeOfWindow & "Release", $vectorWindow)
    EndIf

    If $typeOfWindow <> Default Then
        _cveInputArrayRelease($iArrWindow)
        If $bWindowCreate Then
            Call("_cve" & $typeOfWindow & "Release", $window)
        EndIf
    EndIf

    If $bSrc2IsArray Then
        Call("_VectorOf" & $typeOfSrc2 & "Release", $vectorSrc2)
    EndIf

    If $typeOfSrc2 <> Default Then
        _cveInputArrayRelease($iArrSrc2)
        If $bSrc2Create Then
            Call("_cve" & $typeOfSrc2 & "Release", $src2)
        EndIf
    EndIf

    If $bSrc1IsArray Then
        Call("_VectorOf" & $typeOfSrc1 & "Release", $vectorSrc1)
    EndIf

    If $typeOfSrc1 <> Default Then
        _cveInputArrayRelease($iArrSrc1)
        If $bSrc1Create Then
            Call("_cve" & $typeOfSrc1 & "Release", $src1)
        EndIf
    EndIf
EndFunc   ;==>_cvePhaseCorrelateTyped

Func _cvePhaseCorrelateMat($src1, $src2, $window, $response, $result)
    ; cvePhaseCorrelate using cv::Mat instead of _*Array
    _cvePhaseCorrelateTyped("Mat", $src1, "Mat", $src2, "Mat", $window, $response, $result)
EndFunc   ;==>_cvePhaseCorrelateMat

Func _cveCreateHanningWindow($dst, $winSize, $type)
    ; CVAPI(void) cveCreateHanningWindow(cv::_OutputArray* dst, CvSize* winSize, int type);

    Local $sDstDllType
    If IsDllStruct($dst) Then
        $sDstDllType = "struct*"
    Else
        $sDstDllType = "ptr"
    EndIf

    Local $sWinSizeDllType
    If IsDllStruct($winSize) Then
        $sWinSizeDllType = "struct*"
    Else
        $sWinSizeDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCreateHanningWindow", $sDstDllType, $dst, $sWinSizeDllType, $winSize, "int", $type), "cveCreateHanningWindow", @error)
EndFunc   ;==>_cveCreateHanningWindow

Func _cveCreateHanningWindowTyped($typeOfDst, $dst, $winSize, $type)

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

    _cveCreateHanningWindow($oArrDst, $winSize, $type)

    If $bDstIsArray Then
        Call("_VectorOf" & $typeOfDst & "Release", $vectorDst)
    EndIf

    If $typeOfDst <> Default Then
        _cveOutputArrayRelease($oArrDst)
        If $bDstCreate Then
            Call("_cve" & $typeOfDst & "Release", $dst)
        EndIf
    EndIf
EndFunc   ;==>_cveCreateHanningWindowTyped

Func _cveCreateHanningWindowMat($dst, $winSize, $type)
    ; cveCreateHanningWindow using cv::Mat instead of _*Array
    _cveCreateHanningWindowTyped("Mat", $dst, $winSize, $type)
EndFunc   ;==>_cveCreateHanningWindowMat

Func _cveResize($src, $dst, $dsize, $fx = 0, $fy = 0, $interpolation = $CV_INTER_LINEAR)
    ; CVAPI(void) cveResize(cv::_InputArray* src, cv::_OutputArray* dst, CvSize* dsize, double fx, double fy, int interpolation);

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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveResize", $sSrcDllType, $src, $sDstDllType, $dst, $sDsizeDllType, $dsize, "double", $fx, "double", $fy, "int", $interpolation), "cveResize", @error)
EndFunc   ;==>_cveResize

Func _cveResizeTyped($typeOfSrc, $src, $typeOfDst, $dst, $dsize, $fx = 0, $fy = 0, $interpolation = $CV_INTER_LINEAR)

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

    _cveResize($iArrSrc, $oArrDst, $dsize, $fx, $fy, $interpolation)

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
EndFunc   ;==>_cveResizeTyped

Func _cveResizeMat($src, $dst, $dsize, $fx = 0, $fy = 0, $interpolation = $CV_INTER_LINEAR)
    ; cveResize using cv::Mat instead of _*Array
    _cveResizeTyped("Mat", $src, "Mat", $dst, $dsize, $fx, $fy, $interpolation)
EndFunc   ;==>_cveResizeMat

Func _cveWarpAffine($src, $dst, $m, $dsize, $flags = $CV_INTER_LINEAR, $borderMode = $CV_BORDER_CONSTANT, $borderValue = _cvScalar())
    ; CVAPI(void) cveWarpAffine(cv::_InputArray* src, cv::_OutputArray* dst, cv::_InputArray* m, CvSize* dsize, int flags, int borderMode, CvScalar* borderValue);

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
    If IsDllStruct($m) Then
        $sMDllType = "struct*"
    Else
        $sMDllType = "ptr"
    EndIf

    Local $sDsizeDllType
    If IsDllStruct($dsize) Then
        $sDsizeDllType = "struct*"
    Else
        $sDsizeDllType = "ptr"
    EndIf

    Local $sBorderValueDllType
    If IsDllStruct($borderValue) Then
        $sBorderValueDllType = "struct*"
    Else
        $sBorderValueDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveWarpAffine", $sSrcDllType, $src, $sDstDllType, $dst, $sMDllType, $m, $sDsizeDllType, $dsize, "int", $flags, "int", $borderMode, $sBorderValueDllType, $borderValue), "cveWarpAffine", @error)
EndFunc   ;==>_cveWarpAffine

Func _cveWarpAffineTyped($typeOfSrc, $src, $typeOfDst, $dst, $typeOfM, $m, $dsize, $flags = $CV_INTER_LINEAR, $borderMode = $CV_BORDER_CONSTANT, $borderValue = _cvScalar())

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
    Local $bMIsArray = IsArray($m)
    Local $bMCreate = IsDllStruct($m) And $typeOfM == "Scalar"

    If $typeOfM == Default Then
        $iArrM = $m
    ElseIf $bMIsArray Then
        $vectorM = Call("_VectorOf" & $typeOfM & "Create")

        $iArrMSize = UBound($m)
        For $i = 0 To $iArrMSize - 1
            Call("_VectorOf" & $typeOfM & "Push", $vectorM, $m[$i])
        Next

        $iArrM = Call("_cveInputArrayFromVectorOf" & $typeOfM, $vectorM)
    Else
        If $bMCreate Then
            $m = Call("_cve" & $typeOfM & "Create", $m)
        EndIf
        $iArrM = Call("_cveInputArrayFrom" & $typeOfM, $m)
    EndIf

    _cveWarpAffine($iArrSrc, $oArrDst, $iArrM, $dsize, $flags, $borderMode, $borderValue)

    If $bMIsArray Then
        Call("_VectorOf" & $typeOfM & "Release", $vectorM)
    EndIf

    If $typeOfM <> Default Then
        _cveInputArrayRelease($iArrM)
        If $bMCreate Then
            Call("_cve" & $typeOfM & "Release", $m)
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
EndFunc   ;==>_cveWarpAffineTyped

Func _cveWarpAffineMat($src, $dst, $m, $dsize, $flags = $CV_INTER_LINEAR, $borderMode = $CV_BORDER_CONSTANT, $borderValue = _cvScalar())
    ; cveWarpAffine using cv::Mat instead of _*Array
    _cveWarpAffineTyped("Mat", $src, "Mat", $dst, "Mat", $m, $dsize, $flags, $borderMode, $borderValue)
EndFunc   ;==>_cveWarpAffineMat

Func _cveWarpPerspective($src, $dst, $m, $dsize, $flags = $CV_INTER_LINEAR, $borderMode = $CV_BORDER_CONSTANT, $borderValue = _cvScalar())
    ; CVAPI(void) cveWarpPerspective(cv::_InputArray* src, cv::_OutputArray* dst, cv::_InputArray* m, CvSize* dsize, int flags, int borderMode, CvScalar* borderValue);

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
    If IsDllStruct($m) Then
        $sMDllType = "struct*"
    Else
        $sMDllType = "ptr"
    EndIf

    Local $sDsizeDllType
    If IsDllStruct($dsize) Then
        $sDsizeDllType = "struct*"
    Else
        $sDsizeDllType = "ptr"
    EndIf

    Local $sBorderValueDllType
    If IsDllStruct($borderValue) Then
        $sBorderValueDllType = "struct*"
    Else
        $sBorderValueDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveWarpPerspective", $sSrcDllType, $src, $sDstDllType, $dst, $sMDllType, $m, $sDsizeDllType, $dsize, "int", $flags, "int", $borderMode, $sBorderValueDllType, $borderValue), "cveWarpPerspective", @error)
EndFunc   ;==>_cveWarpPerspective

Func _cveWarpPerspectiveTyped($typeOfSrc, $src, $typeOfDst, $dst, $typeOfM, $m, $dsize, $flags = $CV_INTER_LINEAR, $borderMode = $CV_BORDER_CONSTANT, $borderValue = _cvScalar())

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
    Local $bMIsArray = IsArray($m)
    Local $bMCreate = IsDllStruct($m) And $typeOfM == "Scalar"

    If $typeOfM == Default Then
        $iArrM = $m
    ElseIf $bMIsArray Then
        $vectorM = Call("_VectorOf" & $typeOfM & "Create")

        $iArrMSize = UBound($m)
        For $i = 0 To $iArrMSize - 1
            Call("_VectorOf" & $typeOfM & "Push", $vectorM, $m[$i])
        Next

        $iArrM = Call("_cveInputArrayFromVectorOf" & $typeOfM, $vectorM)
    Else
        If $bMCreate Then
            $m = Call("_cve" & $typeOfM & "Create", $m)
        EndIf
        $iArrM = Call("_cveInputArrayFrom" & $typeOfM, $m)
    EndIf

    _cveWarpPerspective($iArrSrc, $oArrDst, $iArrM, $dsize, $flags, $borderMode, $borderValue)

    If $bMIsArray Then
        Call("_VectorOf" & $typeOfM & "Release", $vectorM)
    EndIf

    If $typeOfM <> Default Then
        _cveInputArrayRelease($iArrM)
        If $bMCreate Then
            Call("_cve" & $typeOfM & "Release", $m)
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
EndFunc   ;==>_cveWarpPerspectiveTyped

Func _cveWarpPerspectiveMat($src, $dst, $m, $dsize, $flags = $CV_INTER_LINEAR, $borderMode = $CV_BORDER_CONSTANT, $borderValue = _cvScalar())
    ; cveWarpPerspective using cv::Mat instead of _*Array
    _cveWarpPerspectiveTyped("Mat", $src, "Mat", $dst, "Mat", $m, $dsize, $flags, $borderMode, $borderValue)
EndFunc   ;==>_cveWarpPerspectiveMat

Func _cveLogPolar($src, $dst, $center, $M, $flags)
    ; CVAPI(void) cveLogPolar(cv::_InputArray* src, cv::_OutputArray* dst, CvPoint2D32f* center, double M, int flags);

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

    Local $sCenterDllType
    If IsDllStruct($center) Then
        $sCenterDllType = "struct*"
    Else
        $sCenterDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveLogPolar", $sSrcDllType, $src, $sDstDllType, $dst, $sCenterDllType, $center, "double", $M, "int", $flags), "cveLogPolar", @error)
EndFunc   ;==>_cveLogPolar

Func _cveLogPolarTyped($typeOfSrc, $src, $typeOfDst, $dst, $center, $M, $flags)

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

    _cveLogPolar($iArrSrc, $oArrDst, $center, $M, $flags)

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
EndFunc   ;==>_cveLogPolarTyped

Func _cveLogPolarMat($src, $dst, $center, $M, $flags)
    ; cveLogPolar using cv::Mat instead of _*Array
    _cveLogPolarTyped("Mat", $src, "Mat", $dst, $center, $M, $flags)
EndFunc   ;==>_cveLogPolarMat

Func _cveLinearPolar($src, $dst, $center, $maxRadius, $flags)
    ; CVAPI(void) cveLinearPolar(cv::_InputArray* src, cv::_OutputArray* dst, CvPoint2D32f* center, double maxRadius, int flags);

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

    Local $sCenterDllType
    If IsDllStruct($center) Then
        $sCenterDllType = "struct*"
    Else
        $sCenterDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveLinearPolar", $sSrcDllType, $src, $sDstDllType, $dst, $sCenterDllType, $center, "double", $maxRadius, "int", $flags), "cveLinearPolar", @error)
EndFunc   ;==>_cveLinearPolar

Func _cveLinearPolarTyped($typeOfSrc, $src, $typeOfDst, $dst, $center, $maxRadius, $flags)

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

    _cveLinearPolar($iArrSrc, $oArrDst, $center, $maxRadius, $flags)

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
EndFunc   ;==>_cveLinearPolarTyped

Func _cveLinearPolarMat($src, $dst, $center, $maxRadius, $flags)
    ; cveLinearPolar using cv::Mat instead of _*Array
    _cveLinearPolarTyped("Mat", $src, "Mat", $dst, $center, $maxRadius, $flags)
EndFunc   ;==>_cveLinearPolarMat

Func _cveRemap($src, $dst, $map1, $map2, $interpolation, $borderMode = $CV_BORDER_CONSTANT, $borderValue = _cvScalar())
    ; CVAPI(void) cveRemap(cv::_InputArray* src, cv::_OutputArray* dst, cv::_InputArray* map1, cv::_InputArray* map2, int interpolation, int borderMode, CvScalar* borderValue);

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

    Local $sMap1DllType
    If IsDllStruct($map1) Then
        $sMap1DllType = "struct*"
    Else
        $sMap1DllType = "ptr"
    EndIf

    Local $sMap2DllType
    If IsDllStruct($map2) Then
        $sMap2DllType = "struct*"
    Else
        $sMap2DllType = "ptr"
    EndIf

    Local $sBorderValueDllType
    If IsDllStruct($borderValue) Then
        $sBorderValueDllType = "struct*"
    Else
        $sBorderValueDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveRemap", $sSrcDllType, $src, $sDstDllType, $dst, $sMap1DllType, $map1, $sMap2DllType, $map2, "int", $interpolation, "int", $borderMode, $sBorderValueDllType, $borderValue), "cveRemap", @error)
EndFunc   ;==>_cveRemap

Func _cveRemapTyped($typeOfSrc, $src, $typeOfDst, $dst, $typeOfMap1, $map1, $typeOfMap2, $map2, $interpolation, $borderMode = $CV_BORDER_CONSTANT, $borderValue = _cvScalar())

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

    Local $iArrMap1, $vectorMap1, $iArrMap1Size
    Local $bMap1IsArray = IsArray($map1)
    Local $bMap1Create = IsDllStruct($map1) And $typeOfMap1 == "Scalar"

    If $typeOfMap1 == Default Then
        $iArrMap1 = $map1
    ElseIf $bMap1IsArray Then
        $vectorMap1 = Call("_VectorOf" & $typeOfMap1 & "Create")

        $iArrMap1Size = UBound($map1)
        For $i = 0 To $iArrMap1Size - 1
            Call("_VectorOf" & $typeOfMap1 & "Push", $vectorMap1, $map1[$i])
        Next

        $iArrMap1 = Call("_cveInputArrayFromVectorOf" & $typeOfMap1, $vectorMap1)
    Else
        If $bMap1Create Then
            $map1 = Call("_cve" & $typeOfMap1 & "Create", $map1)
        EndIf
        $iArrMap1 = Call("_cveInputArrayFrom" & $typeOfMap1, $map1)
    EndIf

    Local $iArrMap2, $vectorMap2, $iArrMap2Size
    Local $bMap2IsArray = IsArray($map2)
    Local $bMap2Create = IsDllStruct($map2) And $typeOfMap2 == "Scalar"

    If $typeOfMap2 == Default Then
        $iArrMap2 = $map2
    ElseIf $bMap2IsArray Then
        $vectorMap2 = Call("_VectorOf" & $typeOfMap2 & "Create")

        $iArrMap2Size = UBound($map2)
        For $i = 0 To $iArrMap2Size - 1
            Call("_VectorOf" & $typeOfMap2 & "Push", $vectorMap2, $map2[$i])
        Next

        $iArrMap2 = Call("_cveInputArrayFromVectorOf" & $typeOfMap2, $vectorMap2)
    Else
        If $bMap2Create Then
            $map2 = Call("_cve" & $typeOfMap2 & "Create", $map2)
        EndIf
        $iArrMap2 = Call("_cveInputArrayFrom" & $typeOfMap2, $map2)
    EndIf

    _cveRemap($iArrSrc, $oArrDst, $iArrMap1, $iArrMap2, $interpolation, $borderMode, $borderValue)

    If $bMap2IsArray Then
        Call("_VectorOf" & $typeOfMap2 & "Release", $vectorMap2)
    EndIf

    If $typeOfMap2 <> Default Then
        _cveInputArrayRelease($iArrMap2)
        If $bMap2Create Then
            Call("_cve" & $typeOfMap2 & "Release", $map2)
        EndIf
    EndIf

    If $bMap1IsArray Then
        Call("_VectorOf" & $typeOfMap1 & "Release", $vectorMap1)
    EndIf

    If $typeOfMap1 <> Default Then
        _cveInputArrayRelease($iArrMap1)
        If $bMap1Create Then
            Call("_cve" & $typeOfMap1 & "Release", $map1)
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
EndFunc   ;==>_cveRemapTyped

Func _cveRemapMat($src, $dst, $map1, $map2, $interpolation, $borderMode = $CV_BORDER_CONSTANT, $borderValue = _cvScalar())
    ; cveRemap using cv::Mat instead of _*Array
    _cveRemapTyped("Mat", $src, "Mat", $dst, "Mat", $map1, "Mat", $map2, $interpolation, $borderMode, $borderValue)
EndFunc   ;==>_cveRemapMat

Func _cveRepeat($src, $ny, $nx, $dst)
    ; CVAPI(void) cveRepeat(cv::_InputArray* src, int ny, int nx, cv::_OutputArray* dst);

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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveRepeat", $sSrcDllType, $src, "int", $ny, "int", $nx, $sDstDllType, $dst), "cveRepeat", @error)
EndFunc   ;==>_cveRepeat

Func _cveRepeatTyped($typeOfSrc, $src, $ny, $nx, $typeOfDst, $dst)

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

    _cveRepeat($iArrSrc, $ny, $nx, $oArrDst)

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
EndFunc   ;==>_cveRepeatTyped

Func _cveRepeatMat($src, $ny, $nx, $dst)
    ; cveRepeat using cv::Mat instead of _*Array
    _cveRepeatTyped("Mat", $src, $ny, $nx, "Mat", $dst)
EndFunc   ;==>_cveRepeatMat

Func _cveHoughCircles($image, $circles, $method, $dp, $minDist, $param1 = 100, $param2 = 100, $minRadius = 0, $maxRadius = 0)
    ; CVAPI(void) cveHoughCircles(cv::_InputArray* image, cv::_OutputArray* circles, int method, double dp, double minDist, double param1, double param2, int minRadius, int maxRadius);

    Local $sImageDllType
    If IsDllStruct($image) Then
        $sImageDllType = "struct*"
    Else
        $sImageDllType = "ptr"
    EndIf

    Local $sCirclesDllType
    If IsDllStruct($circles) Then
        $sCirclesDllType = "struct*"
    Else
        $sCirclesDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveHoughCircles", $sImageDllType, $image, $sCirclesDllType, $circles, "int", $method, "double", $dp, "double", $minDist, "double", $param1, "double", $param2, "int", $minRadius, "int", $maxRadius), "cveHoughCircles", @error)
EndFunc   ;==>_cveHoughCircles

Func _cveHoughCirclesTyped($typeOfImage, $image, $typeOfCircles, $circles, $method, $dp, $minDist, $param1 = 100, $param2 = 100, $minRadius = 0, $maxRadius = 0)

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

    _cveHoughCircles($iArrImage, $oArrCircles, $method, $dp, $minDist, $param1, $param2, $minRadius, $maxRadius)

    If $bCirclesIsArray Then
        Call("_VectorOf" & $typeOfCircles & "Release", $vectorCircles)
    EndIf

    If $typeOfCircles <> Default Then
        _cveOutputArrayRelease($oArrCircles)
        If $bCirclesCreate Then
            Call("_cve" & $typeOfCircles & "Release", $circles)
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
EndFunc   ;==>_cveHoughCirclesTyped

Func _cveHoughCirclesMat($image, $circles, $method, $dp, $minDist, $param1 = 100, $param2 = 100, $minRadius = 0, $maxRadius = 0)
    ; cveHoughCircles using cv::Mat instead of _*Array
    _cveHoughCirclesTyped("Mat", $image, "Mat", $circles, $method, $dp, $minDist, $param1, $param2, $minRadius, $maxRadius)
EndFunc   ;==>_cveHoughCirclesMat

Func _cveHoughLines($image, $lines, $rho, $theta, $threshold, $srn = 0, $stn = 0)
    ; CVAPI(void) cveHoughLines(cv::_InputArray* image, cv::_OutputArray* lines, double rho, double theta, int threshold, double srn, double stn);

    Local $sImageDllType
    If IsDllStruct($image) Then
        $sImageDllType = "struct*"
    Else
        $sImageDllType = "ptr"
    EndIf

    Local $sLinesDllType
    If IsDllStruct($lines) Then
        $sLinesDllType = "struct*"
    Else
        $sLinesDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveHoughLines", $sImageDllType, $image, $sLinesDllType, $lines, "double", $rho, "double", $theta, "int", $threshold, "double", $srn, "double", $stn), "cveHoughLines", @error)
EndFunc   ;==>_cveHoughLines

Func _cveHoughLinesTyped($typeOfImage, $image, $typeOfLines, $lines, $rho, $theta, $threshold, $srn = 0, $stn = 0)

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

    _cveHoughLines($iArrImage, $oArrLines, $rho, $theta, $threshold, $srn, $stn)

    If $bLinesIsArray Then
        Call("_VectorOf" & $typeOfLines & "Release", $vectorLines)
    EndIf

    If $typeOfLines <> Default Then
        _cveOutputArrayRelease($oArrLines)
        If $bLinesCreate Then
            Call("_cve" & $typeOfLines & "Release", $lines)
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
EndFunc   ;==>_cveHoughLinesTyped

Func _cveHoughLinesMat($image, $lines, $rho, $theta, $threshold, $srn = 0, $stn = 0)
    ; cveHoughLines using cv::Mat instead of _*Array
    _cveHoughLinesTyped("Mat", $image, "Mat", $lines, $rho, $theta, $threshold, $srn, $stn)
EndFunc   ;==>_cveHoughLinesMat

Func _cveHoughLinesP($image, $lines, $rho, $theta, $threshold, $minLineLength, $maxGap)
    ; CVAPI(void) cveHoughLinesP(cv::_InputArray* image, cv::_OutputArray* lines, double rho, double theta, int threshold, double minLineLength, double maxGap);

    Local $sImageDllType
    If IsDllStruct($image) Then
        $sImageDllType = "struct*"
    Else
        $sImageDllType = "ptr"
    EndIf

    Local $sLinesDllType
    If IsDllStruct($lines) Then
        $sLinesDllType = "struct*"
    Else
        $sLinesDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveHoughLinesP", $sImageDllType, $image, $sLinesDllType, $lines, "double", $rho, "double", $theta, "int", $threshold, "double", $minLineLength, "double", $maxGap), "cveHoughLinesP", @error)
EndFunc   ;==>_cveHoughLinesP

Func _cveHoughLinesPTyped($typeOfImage, $image, $typeOfLines, $lines, $rho, $theta, $threshold, $minLineLength, $maxGap)

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

    _cveHoughLinesP($iArrImage, $oArrLines, $rho, $theta, $threshold, $minLineLength, $maxGap)

    If $bLinesIsArray Then
        Call("_VectorOf" & $typeOfLines & "Release", $vectorLines)
    EndIf

    If $typeOfLines <> Default Then
        _cveOutputArrayRelease($oArrLines)
        If $bLinesCreate Then
            Call("_cve" & $typeOfLines & "Release", $lines)
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
EndFunc   ;==>_cveHoughLinesPTyped

Func _cveHoughLinesPMat($image, $lines, $rho, $theta, $threshold, $minLineLength, $maxGap)
    ; cveHoughLinesP using cv::Mat instead of _*Array
    _cveHoughLinesPTyped("Mat", $image, "Mat", $lines, $rho, $theta, $threshold, $minLineLength, $maxGap)
EndFunc   ;==>_cveHoughLinesPMat

Func _cveMatchTemplate($image, $templ, $result, $method, $mask = _cveNoArray())
    ; CVAPI(void) cveMatchTemplate(cv::_InputArray* image, cv::_InputArray* templ, cv::_OutputArray* result, int method, cv::_InputArray* mask);

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

    Local $sMaskDllType
    If IsDllStruct($mask) Then
        $sMaskDllType = "struct*"
    Else
        $sMaskDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMatchTemplate", $sImageDllType, $image, $sTemplDllType, $templ, $sResultDllType, $result, "int", $method, $sMaskDllType, $mask), "cveMatchTemplate", @error)
EndFunc   ;==>_cveMatchTemplate

Func _cveMatchTemplateTyped($typeOfImage, $image, $typeOfTempl, $templ, $typeOfResult, $result, $method, $typeOfMask = Default, $mask = _cveNoArray())

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

    _cveMatchTemplate($iArrImage, $iArrTempl, $oArrResult, $method, $iArrMask)

    If $bMaskIsArray Then
        Call("_VectorOf" & $typeOfMask & "Release", $vectorMask)
    EndIf

    If $typeOfMask <> Default Then
        _cveInputArrayRelease($iArrMask)
        If $bMaskCreate Then
            Call("_cve" & $typeOfMask & "Release", $mask)
        EndIf
    EndIf

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
EndFunc   ;==>_cveMatchTemplateTyped

Func _cveMatchTemplateMat($image, $templ, $result, $method, $mask = _cveNoArrayMat())
    ; cveMatchTemplate using cv::Mat instead of _*Array
    _cveMatchTemplateTyped("Mat", $image, "Mat", $templ, "Mat", $result, $method, "Mat", $mask)
EndFunc   ;==>_cveMatchTemplateMat

Func _cveCornerSubPix($image, $corners, $winSize, $zeroZone, $criteria)
    ; CVAPI(void) cveCornerSubPix(cv::_InputArray* image, cv::_InputOutputArray* corners, CvSize* winSize, CvSize* zeroZone, CvTermCriteria* criteria);

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

    Local $sWinSizeDllType
    If IsDllStruct($winSize) Then
        $sWinSizeDllType = "struct*"
    Else
        $sWinSizeDllType = "ptr"
    EndIf

    Local $sZeroZoneDllType
    If IsDllStruct($zeroZone) Then
        $sZeroZoneDllType = "struct*"
    Else
        $sZeroZoneDllType = "ptr"
    EndIf

    Local $sCriteriaDllType
    If IsDllStruct($criteria) Then
        $sCriteriaDllType = "struct*"
    Else
        $sCriteriaDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCornerSubPix", $sImageDllType, $image, $sCornersDllType, $corners, $sWinSizeDllType, $winSize, $sZeroZoneDllType, $zeroZone, $sCriteriaDllType, $criteria), "cveCornerSubPix", @error)
EndFunc   ;==>_cveCornerSubPix

Func _cveCornerSubPixTyped($typeOfImage, $image, $typeOfCorners, $corners, $winSize, $zeroZone, $criteria)

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

    Local $ioArrCorners, $vectorCorners, $iArrCornersSize
    Local $bCornersIsArray = IsArray($corners)
    Local $bCornersCreate = IsDllStruct($corners) And $typeOfCorners == "Scalar"

    If $typeOfCorners == Default Then
        $ioArrCorners = $corners
    ElseIf $bCornersIsArray Then
        $vectorCorners = Call("_VectorOf" & $typeOfCorners & "Create")

        $iArrCornersSize = UBound($corners)
        For $i = 0 To $iArrCornersSize - 1
            Call("_VectorOf" & $typeOfCorners & "Push", $vectorCorners, $corners[$i])
        Next

        $ioArrCorners = Call("_cveInputOutputArrayFromVectorOf" & $typeOfCorners, $vectorCorners)
    Else
        If $bCornersCreate Then
            $corners = Call("_cve" & $typeOfCorners & "Create", $corners)
        EndIf
        $ioArrCorners = Call("_cveInputOutputArrayFrom" & $typeOfCorners, $corners)
    EndIf

    _cveCornerSubPix($iArrImage, $ioArrCorners, $winSize, $zeroZone, $criteria)

    If $bCornersIsArray Then
        Call("_VectorOf" & $typeOfCorners & "Release", $vectorCorners)
    EndIf

    If $typeOfCorners <> Default Then
        _cveInputOutputArrayRelease($ioArrCorners)
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
EndFunc   ;==>_cveCornerSubPixTyped

Func _cveCornerSubPixMat($image, $corners, $winSize, $zeroZone, $criteria)
    ; cveCornerSubPix using cv::Mat instead of _*Array
    _cveCornerSubPixTyped("Mat", $image, "Mat", $corners, $winSize, $zeroZone, $criteria)
EndFunc   ;==>_cveCornerSubPixMat

Func _cveConvertMaps($map1, $map2, $dstmap1, $dstmap2, $dstmap1Type, $nninterpolation = false)
    ; CVAPI(void) cveConvertMaps(cv::_InputArray* map1, cv::_InputArray* map2, cv::_OutputArray* dstmap1, cv::_OutputArray* dstmap2, int dstmap1Type, bool nninterpolation);

    Local $sMap1DllType
    If IsDllStruct($map1) Then
        $sMap1DllType = "struct*"
    Else
        $sMap1DllType = "ptr"
    EndIf

    Local $sMap2DllType
    If IsDllStruct($map2) Then
        $sMap2DllType = "struct*"
    Else
        $sMap2DllType = "ptr"
    EndIf

    Local $sDstmap1DllType
    If IsDllStruct($dstmap1) Then
        $sDstmap1DllType = "struct*"
    Else
        $sDstmap1DllType = "ptr"
    EndIf

    Local $sDstmap2DllType
    If IsDllStruct($dstmap2) Then
        $sDstmap2DllType = "struct*"
    Else
        $sDstmap2DllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveConvertMaps", $sMap1DllType, $map1, $sMap2DllType, $map2, $sDstmap1DllType, $dstmap1, $sDstmap2DllType, $dstmap2, "int", $dstmap1Type, "boolean", $nninterpolation), "cveConvertMaps", @error)
EndFunc   ;==>_cveConvertMaps

Func _cveConvertMapsTyped($typeOfMap1, $map1, $typeOfMap2, $map2, $typeOfDstmap1, $dstmap1, $typeOfDstmap2, $dstmap2, $dstmap1Type, $nninterpolation = false)

    Local $iArrMap1, $vectorMap1, $iArrMap1Size
    Local $bMap1IsArray = IsArray($map1)
    Local $bMap1Create = IsDllStruct($map1) And $typeOfMap1 == "Scalar"

    If $typeOfMap1 == Default Then
        $iArrMap1 = $map1
    ElseIf $bMap1IsArray Then
        $vectorMap1 = Call("_VectorOf" & $typeOfMap1 & "Create")

        $iArrMap1Size = UBound($map1)
        For $i = 0 To $iArrMap1Size - 1
            Call("_VectorOf" & $typeOfMap1 & "Push", $vectorMap1, $map1[$i])
        Next

        $iArrMap1 = Call("_cveInputArrayFromVectorOf" & $typeOfMap1, $vectorMap1)
    Else
        If $bMap1Create Then
            $map1 = Call("_cve" & $typeOfMap1 & "Create", $map1)
        EndIf
        $iArrMap1 = Call("_cveInputArrayFrom" & $typeOfMap1, $map1)
    EndIf

    Local $iArrMap2, $vectorMap2, $iArrMap2Size
    Local $bMap2IsArray = IsArray($map2)
    Local $bMap2Create = IsDllStruct($map2) And $typeOfMap2 == "Scalar"

    If $typeOfMap2 == Default Then
        $iArrMap2 = $map2
    ElseIf $bMap2IsArray Then
        $vectorMap2 = Call("_VectorOf" & $typeOfMap2 & "Create")

        $iArrMap2Size = UBound($map2)
        For $i = 0 To $iArrMap2Size - 1
            Call("_VectorOf" & $typeOfMap2 & "Push", $vectorMap2, $map2[$i])
        Next

        $iArrMap2 = Call("_cveInputArrayFromVectorOf" & $typeOfMap2, $vectorMap2)
    Else
        If $bMap2Create Then
            $map2 = Call("_cve" & $typeOfMap2 & "Create", $map2)
        EndIf
        $iArrMap2 = Call("_cveInputArrayFrom" & $typeOfMap2, $map2)
    EndIf

    Local $oArrDstmap1, $vectorDstmap1, $iArrDstmap1Size
    Local $bDstmap1IsArray = IsArray($dstmap1)
    Local $bDstmap1Create = IsDllStruct($dstmap1) And $typeOfDstmap1 == "Scalar"

    If $typeOfDstmap1 == Default Then
        $oArrDstmap1 = $dstmap1
    ElseIf $bDstmap1IsArray Then
        $vectorDstmap1 = Call("_VectorOf" & $typeOfDstmap1 & "Create")

        $iArrDstmap1Size = UBound($dstmap1)
        For $i = 0 To $iArrDstmap1Size - 1
            Call("_VectorOf" & $typeOfDstmap1 & "Push", $vectorDstmap1, $dstmap1[$i])
        Next

        $oArrDstmap1 = Call("_cveOutputArrayFromVectorOf" & $typeOfDstmap1, $vectorDstmap1)
    Else
        If $bDstmap1Create Then
            $dstmap1 = Call("_cve" & $typeOfDstmap1 & "Create", $dstmap1)
        EndIf
        $oArrDstmap1 = Call("_cveOutputArrayFrom" & $typeOfDstmap1, $dstmap1)
    EndIf

    Local $oArrDstmap2, $vectorDstmap2, $iArrDstmap2Size
    Local $bDstmap2IsArray = IsArray($dstmap2)
    Local $bDstmap2Create = IsDllStruct($dstmap2) And $typeOfDstmap2 == "Scalar"

    If $typeOfDstmap2 == Default Then
        $oArrDstmap2 = $dstmap2
    ElseIf $bDstmap2IsArray Then
        $vectorDstmap2 = Call("_VectorOf" & $typeOfDstmap2 & "Create")

        $iArrDstmap2Size = UBound($dstmap2)
        For $i = 0 To $iArrDstmap2Size - 1
            Call("_VectorOf" & $typeOfDstmap2 & "Push", $vectorDstmap2, $dstmap2[$i])
        Next

        $oArrDstmap2 = Call("_cveOutputArrayFromVectorOf" & $typeOfDstmap2, $vectorDstmap2)
    Else
        If $bDstmap2Create Then
            $dstmap2 = Call("_cve" & $typeOfDstmap2 & "Create", $dstmap2)
        EndIf
        $oArrDstmap2 = Call("_cveOutputArrayFrom" & $typeOfDstmap2, $dstmap2)
    EndIf

    _cveConvertMaps($iArrMap1, $iArrMap2, $oArrDstmap1, $oArrDstmap2, $dstmap1Type, $nninterpolation)

    If $bDstmap2IsArray Then
        Call("_VectorOf" & $typeOfDstmap2 & "Release", $vectorDstmap2)
    EndIf

    If $typeOfDstmap2 <> Default Then
        _cveOutputArrayRelease($oArrDstmap2)
        If $bDstmap2Create Then
            Call("_cve" & $typeOfDstmap2 & "Release", $dstmap2)
        EndIf
    EndIf

    If $bDstmap1IsArray Then
        Call("_VectorOf" & $typeOfDstmap1 & "Release", $vectorDstmap1)
    EndIf

    If $typeOfDstmap1 <> Default Then
        _cveOutputArrayRelease($oArrDstmap1)
        If $bDstmap1Create Then
            Call("_cve" & $typeOfDstmap1 & "Release", $dstmap1)
        EndIf
    EndIf

    If $bMap2IsArray Then
        Call("_VectorOf" & $typeOfMap2 & "Release", $vectorMap2)
    EndIf

    If $typeOfMap2 <> Default Then
        _cveInputArrayRelease($iArrMap2)
        If $bMap2Create Then
            Call("_cve" & $typeOfMap2 & "Release", $map2)
        EndIf
    EndIf

    If $bMap1IsArray Then
        Call("_VectorOf" & $typeOfMap1 & "Release", $vectorMap1)
    EndIf

    If $typeOfMap1 <> Default Then
        _cveInputArrayRelease($iArrMap1)
        If $bMap1Create Then
            Call("_cve" & $typeOfMap1 & "Release", $map1)
        EndIf
    EndIf
EndFunc   ;==>_cveConvertMapsTyped

Func _cveConvertMapsMat($map1, $map2, $dstmap1, $dstmap2, $dstmap1Type, $nninterpolation = false)
    ; cveConvertMaps using cv::Mat instead of _*Array
    _cveConvertMapsTyped("Mat", $map1, "Mat", $map2, "Mat", $dstmap1, "Mat", $dstmap2, $dstmap1Type, $nninterpolation)
EndFunc   ;==>_cveConvertMapsMat

Func _cveGetAffineTransform($src, $dst, $affine)
    ; CVAPI(void) cveGetAffineTransform(cv::_InputArray* src, cv::_InputArray* dst, cv::Mat* affine);

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

    Local $sAffineDllType
    If IsDllStruct($affine) Then
        $sAffineDllType = "struct*"
    Else
        $sAffineDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveGetAffineTransform", $sSrcDllType, $src, $sDstDllType, $dst, $sAffineDllType, $affine), "cveGetAffineTransform", @error)
EndFunc   ;==>_cveGetAffineTransform

Func _cveGetAffineTransformTyped($typeOfSrc, $src, $typeOfDst, $dst, $affine)

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

    _cveGetAffineTransform($iArrSrc, $iArrDst, $affine)

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
EndFunc   ;==>_cveGetAffineTransformTyped

Func _cveGetAffineTransformMat($src, $dst, $affine)
    ; cveGetAffineTransform using cv::Mat instead of _*Array
    _cveGetAffineTransformTyped("Mat", $src, "Mat", $dst, $affine)
EndFunc   ;==>_cveGetAffineTransformMat

Func _cveGetPerspectiveTransform($src, $dst, $perspective)
    ; CVAPI(void) cveGetPerspectiveTransform(cv::_InputArray* src, cv::_InputArray* dst, cv::Mat* perspective);

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

    Local $sPerspectiveDllType
    If IsDllStruct($perspective) Then
        $sPerspectiveDllType = "struct*"
    Else
        $sPerspectiveDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveGetPerspectiveTransform", $sSrcDllType, $src, $sDstDllType, $dst, $sPerspectiveDllType, $perspective), "cveGetPerspectiveTransform", @error)
EndFunc   ;==>_cveGetPerspectiveTransform

Func _cveGetPerspectiveTransformTyped($typeOfSrc, $src, $typeOfDst, $dst, $perspective)

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

    _cveGetPerspectiveTransform($iArrSrc, $iArrDst, $perspective)

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
EndFunc   ;==>_cveGetPerspectiveTransformTyped

Func _cveGetPerspectiveTransformMat($src, $dst, $perspective)
    ; cveGetPerspectiveTransform using cv::Mat instead of _*Array
    _cveGetPerspectiveTransformTyped("Mat", $src, "Mat", $dst, $perspective)
EndFunc   ;==>_cveGetPerspectiveTransformMat

Func _cveInvertAffineTransform($m, $im)
    ; CVAPI(void) cveInvertAffineTransform(cv::_InputArray* m, cv::_OutputArray* im);

    Local $sMDllType
    If IsDllStruct($m) Then
        $sMDllType = "struct*"
    Else
        $sMDllType = "ptr"
    EndIf

    Local $sImDllType
    If IsDllStruct($im) Then
        $sImDllType = "struct*"
    Else
        $sImDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveInvertAffineTransform", $sMDllType, $m, $sImDllType, $im), "cveInvertAffineTransform", @error)
EndFunc   ;==>_cveInvertAffineTransform

Func _cveInvertAffineTransformTyped($typeOfM, $m, $typeOfIm, $im)

    Local $iArrM, $vectorM, $iArrMSize
    Local $bMIsArray = IsArray($m)
    Local $bMCreate = IsDllStruct($m) And $typeOfM == "Scalar"

    If $typeOfM == Default Then
        $iArrM = $m
    ElseIf $bMIsArray Then
        $vectorM = Call("_VectorOf" & $typeOfM & "Create")

        $iArrMSize = UBound($m)
        For $i = 0 To $iArrMSize - 1
            Call("_VectorOf" & $typeOfM & "Push", $vectorM, $m[$i])
        Next

        $iArrM = Call("_cveInputArrayFromVectorOf" & $typeOfM, $vectorM)
    Else
        If $bMCreate Then
            $m = Call("_cve" & $typeOfM & "Create", $m)
        EndIf
        $iArrM = Call("_cveInputArrayFrom" & $typeOfM, $m)
    EndIf

    Local $oArrIm, $vectorIm, $iArrImSize
    Local $bImIsArray = IsArray($im)
    Local $bImCreate = IsDllStruct($im) And $typeOfIm == "Scalar"

    If $typeOfIm == Default Then
        $oArrIm = $im
    ElseIf $bImIsArray Then
        $vectorIm = Call("_VectorOf" & $typeOfIm & "Create")

        $iArrImSize = UBound($im)
        For $i = 0 To $iArrImSize - 1
            Call("_VectorOf" & $typeOfIm & "Push", $vectorIm, $im[$i])
        Next

        $oArrIm = Call("_cveOutputArrayFromVectorOf" & $typeOfIm, $vectorIm)
    Else
        If $bImCreate Then
            $im = Call("_cve" & $typeOfIm & "Create", $im)
        EndIf
        $oArrIm = Call("_cveOutputArrayFrom" & $typeOfIm, $im)
    EndIf

    _cveInvertAffineTransform($iArrM, $oArrIm)

    If $bImIsArray Then
        Call("_VectorOf" & $typeOfIm & "Release", $vectorIm)
    EndIf

    If $typeOfIm <> Default Then
        _cveOutputArrayRelease($oArrIm)
        If $bImCreate Then
            Call("_cve" & $typeOfIm & "Release", $im)
        EndIf
    EndIf

    If $bMIsArray Then
        Call("_VectorOf" & $typeOfM & "Release", $vectorM)
    EndIf

    If $typeOfM <> Default Then
        _cveInputArrayRelease($iArrM)
        If $bMCreate Then
            Call("_cve" & $typeOfM & "Release", $m)
        EndIf
    EndIf
EndFunc   ;==>_cveInvertAffineTransformTyped

Func _cveInvertAffineTransformMat($m, $im)
    ; cveInvertAffineTransform using cv::Mat instead of _*Array
    _cveInvertAffineTransformTyped("Mat", $m, "Mat", $im)
EndFunc   ;==>_cveInvertAffineTransformMat

Func _cveEMD($signature1, $signature2, $distType, $cost, $lowerBound, $flow)
    ; CVAPI(void) cveEMD(cv::_InputArray* signature1, cv::_InputArray* signature2, int distType, cv::_InputArray* cost, float* lowerBound, cv::_OutputArray* flow);

    Local $sSignature1DllType
    If IsDllStruct($signature1) Then
        $sSignature1DllType = "struct*"
    Else
        $sSignature1DllType = "ptr"
    EndIf

    Local $sSignature2DllType
    If IsDllStruct($signature2) Then
        $sSignature2DllType = "struct*"
    Else
        $sSignature2DllType = "ptr"
    EndIf

    Local $sCostDllType
    If IsDllStruct($cost) Then
        $sCostDllType = "struct*"
    Else
        $sCostDllType = "ptr"
    EndIf

    Local $sLowerBoundDllType
    If IsDllStruct($lowerBound) Then
        $sLowerBoundDllType = "struct*"
    Else
        $sLowerBoundDllType = "float*"
    EndIf

    Local $sFlowDllType
    If IsDllStruct($flow) Then
        $sFlowDllType = "struct*"
    Else
        $sFlowDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveEMD", $sSignature1DllType, $signature1, $sSignature2DllType, $signature2, "int", $distType, $sCostDllType, $cost, $sLowerBoundDllType, $lowerBound, $sFlowDllType, $flow), "cveEMD", @error)
EndFunc   ;==>_cveEMD

Func _cveEMDTyped($typeOfSignature1, $signature1, $typeOfSignature2, $signature2, $distType, $typeOfCost, $cost, $lowerBound, $typeOfFlow, $flow)

    Local $iArrSignature1, $vectorSignature1, $iArrSignature1Size
    Local $bSignature1IsArray = IsArray($signature1)
    Local $bSignature1Create = IsDllStruct($signature1) And $typeOfSignature1 == "Scalar"

    If $typeOfSignature1 == Default Then
        $iArrSignature1 = $signature1
    ElseIf $bSignature1IsArray Then
        $vectorSignature1 = Call("_VectorOf" & $typeOfSignature1 & "Create")

        $iArrSignature1Size = UBound($signature1)
        For $i = 0 To $iArrSignature1Size - 1
            Call("_VectorOf" & $typeOfSignature1 & "Push", $vectorSignature1, $signature1[$i])
        Next

        $iArrSignature1 = Call("_cveInputArrayFromVectorOf" & $typeOfSignature1, $vectorSignature1)
    Else
        If $bSignature1Create Then
            $signature1 = Call("_cve" & $typeOfSignature1 & "Create", $signature1)
        EndIf
        $iArrSignature1 = Call("_cveInputArrayFrom" & $typeOfSignature1, $signature1)
    EndIf

    Local $iArrSignature2, $vectorSignature2, $iArrSignature2Size
    Local $bSignature2IsArray = IsArray($signature2)
    Local $bSignature2Create = IsDllStruct($signature2) And $typeOfSignature2 == "Scalar"

    If $typeOfSignature2 == Default Then
        $iArrSignature2 = $signature2
    ElseIf $bSignature2IsArray Then
        $vectorSignature2 = Call("_VectorOf" & $typeOfSignature2 & "Create")

        $iArrSignature2Size = UBound($signature2)
        For $i = 0 To $iArrSignature2Size - 1
            Call("_VectorOf" & $typeOfSignature2 & "Push", $vectorSignature2, $signature2[$i])
        Next

        $iArrSignature2 = Call("_cveInputArrayFromVectorOf" & $typeOfSignature2, $vectorSignature2)
    Else
        If $bSignature2Create Then
            $signature2 = Call("_cve" & $typeOfSignature2 & "Create", $signature2)
        EndIf
        $iArrSignature2 = Call("_cveInputArrayFrom" & $typeOfSignature2, $signature2)
    EndIf

    Local $iArrCost, $vectorCost, $iArrCostSize
    Local $bCostIsArray = IsArray($cost)
    Local $bCostCreate = IsDllStruct($cost) And $typeOfCost == "Scalar"

    If $typeOfCost == Default Then
        $iArrCost = $cost
    ElseIf $bCostIsArray Then
        $vectorCost = Call("_VectorOf" & $typeOfCost & "Create")

        $iArrCostSize = UBound($cost)
        For $i = 0 To $iArrCostSize - 1
            Call("_VectorOf" & $typeOfCost & "Push", $vectorCost, $cost[$i])
        Next

        $iArrCost = Call("_cveInputArrayFromVectorOf" & $typeOfCost, $vectorCost)
    Else
        If $bCostCreate Then
            $cost = Call("_cve" & $typeOfCost & "Create", $cost)
        EndIf
        $iArrCost = Call("_cveInputArrayFrom" & $typeOfCost, $cost)
    EndIf

    Local $oArrFlow, $vectorFlow, $iArrFlowSize
    Local $bFlowIsArray = IsArray($flow)
    Local $bFlowCreate = IsDllStruct($flow) And $typeOfFlow == "Scalar"

    If $typeOfFlow == Default Then
        $oArrFlow = $flow
    ElseIf $bFlowIsArray Then
        $vectorFlow = Call("_VectorOf" & $typeOfFlow & "Create")

        $iArrFlowSize = UBound($flow)
        For $i = 0 To $iArrFlowSize - 1
            Call("_VectorOf" & $typeOfFlow & "Push", $vectorFlow, $flow[$i])
        Next

        $oArrFlow = Call("_cveOutputArrayFromVectorOf" & $typeOfFlow, $vectorFlow)
    Else
        If $bFlowCreate Then
            $flow = Call("_cve" & $typeOfFlow & "Create", $flow)
        EndIf
        $oArrFlow = Call("_cveOutputArrayFrom" & $typeOfFlow, $flow)
    EndIf

    _cveEMD($iArrSignature1, $iArrSignature2, $distType, $iArrCost, $lowerBound, $oArrFlow)

    If $bFlowIsArray Then
        Call("_VectorOf" & $typeOfFlow & "Release", $vectorFlow)
    EndIf

    If $typeOfFlow <> Default Then
        _cveOutputArrayRelease($oArrFlow)
        If $bFlowCreate Then
            Call("_cve" & $typeOfFlow & "Release", $flow)
        EndIf
    EndIf

    If $bCostIsArray Then
        Call("_VectorOf" & $typeOfCost & "Release", $vectorCost)
    EndIf

    If $typeOfCost <> Default Then
        _cveInputArrayRelease($iArrCost)
        If $bCostCreate Then
            Call("_cve" & $typeOfCost & "Release", $cost)
        EndIf
    EndIf

    If $bSignature2IsArray Then
        Call("_VectorOf" & $typeOfSignature2 & "Release", $vectorSignature2)
    EndIf

    If $typeOfSignature2 <> Default Then
        _cveInputArrayRelease($iArrSignature2)
        If $bSignature2Create Then
            Call("_cve" & $typeOfSignature2 & "Release", $signature2)
        EndIf
    EndIf

    If $bSignature1IsArray Then
        Call("_VectorOf" & $typeOfSignature1 & "Release", $vectorSignature1)
    EndIf

    If $typeOfSignature1 <> Default Then
        _cveInputArrayRelease($iArrSignature1)
        If $bSignature1Create Then
            Call("_cve" & $typeOfSignature1 & "Release", $signature1)
        EndIf
    EndIf
EndFunc   ;==>_cveEMDTyped

Func _cveEMDMat($signature1, $signature2, $distType, $cost, $lowerBound, $flow)
    ; cveEMD using cv::Mat instead of _*Array
    _cveEMDTyped("Mat", $signature1, "Mat", $signature2, $distType, "Mat", $cost, $lowerBound, "Mat", $flow)
EndFunc   ;==>_cveEMDMat

Func _cveCalcHist($images, $channels, $mask, $hist, $histSize, $ranges, $accumulate = false)
    ; CVAPI(void) cveCalcHist(cv::_InputArray* images, const std::vector<int>* channels, cv::_InputArray* mask, cv::_OutputArray* hist, std::vector<int>* histSize, std::vector<float>* ranges, bool accumulate);

    Local $sImagesDllType
    If IsDllStruct($images) Then
        $sImagesDllType = "struct*"
    Else
        $sImagesDllType = "ptr"
    EndIf

    Local $vecChannels, $iArrChannelsSize
    Local $bChannelsIsArray = IsArray($channels)

    If $bChannelsIsArray Then
        $vecChannels = _VectorOfIntCreate()

        $iArrChannelsSize = UBound($channels)
        For $i = 0 To $iArrChannelsSize - 1
            _VectorOfIntPush($vecChannels, $channels[$i])
        Next
    Else
        $vecChannels = $channels
    EndIf

    Local $sChannelsDllType
    If IsDllStruct($channels) Then
        $sChannelsDllType = "struct*"
    Else
        $sChannelsDllType = "ptr"
    EndIf

    Local $sMaskDllType
    If IsDllStruct($mask) Then
        $sMaskDllType = "struct*"
    Else
        $sMaskDllType = "ptr"
    EndIf

    Local $sHistDllType
    If IsDllStruct($hist) Then
        $sHistDllType = "struct*"
    Else
        $sHistDllType = "ptr"
    EndIf

    Local $vecHistSize, $iArrHistSizeSize
    Local $bHistSizeIsArray = IsArray($histSize)

    If $bHistSizeIsArray Then
        $vecHistSize = _VectorOfIntCreate()

        $iArrHistSizeSize = UBound($histSize)
        For $i = 0 To $iArrHistSizeSize - 1
            _VectorOfIntPush($vecHistSize, $histSize[$i])
        Next
    Else
        $vecHistSize = $histSize
    EndIf

    Local $sHistSizeDllType
    If IsDllStruct($histSize) Then
        $sHistSizeDllType = "struct*"
    Else
        $sHistSizeDllType = "ptr"
    EndIf

    Local $vecRanges, $iArrRangesSize
    Local $bRangesIsArray = IsArray($ranges)

    If $bRangesIsArray Then
        $vecRanges = _VectorOfFloatCreate()

        $iArrRangesSize = UBound($ranges)
        For $i = 0 To $iArrRangesSize - 1
            _VectorOfFloatPush($vecRanges, $ranges[$i])
        Next
    Else
        $vecRanges = $ranges
    EndIf

    Local $sRangesDllType
    If IsDllStruct($ranges) Then
        $sRangesDllType = "struct*"
    Else
        $sRangesDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCalcHist", $sImagesDllType, $images, $sChannelsDllType, $vecChannels, $sMaskDllType, $mask, $sHistDllType, $hist, $sHistSizeDllType, $vecHistSize, $sRangesDllType, $vecRanges, "boolean", $accumulate), "cveCalcHist", @error)

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

Func _cveCalcHistTyped($typeOfImages, $images, $channels, $typeOfMask, $mask, $typeOfHist, $hist, $histSize, $ranges, $accumulate = false)

    Local $iArrImages, $vectorImages, $iArrImagesSize
    Local $bImagesIsArray = IsArray($images)
    Local $bImagesCreate = IsDllStruct($images) And $typeOfImages == "Scalar"

    If $typeOfImages == Default Then
        $iArrImages = $images
    ElseIf $bImagesIsArray Then
        $vectorImages = Call("_VectorOf" & $typeOfImages & "Create")

        $iArrImagesSize = UBound($images)
        For $i = 0 To $iArrImagesSize - 1
            Call("_VectorOf" & $typeOfImages & "Push", $vectorImages, $images[$i])
        Next

        $iArrImages = Call("_cveInputArrayFromVectorOf" & $typeOfImages, $vectorImages)
    Else
        If $bImagesCreate Then
            $images = Call("_cve" & $typeOfImages & "Create", $images)
        EndIf
        $iArrImages = Call("_cveInputArrayFrom" & $typeOfImages, $images)
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

    _cveCalcHist($iArrImages, $channels, $iArrMask, $oArrHist, $histSize, $ranges, $accumulate)

    If $bHistIsArray Then
        Call("_VectorOf" & $typeOfHist & "Release", $vectorHist)
    EndIf

    If $typeOfHist <> Default Then
        _cveOutputArrayRelease($oArrHist)
        If $bHistCreate Then
            Call("_cve" & $typeOfHist & "Release", $hist)
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

    If $bImagesIsArray Then
        Call("_VectorOf" & $typeOfImages & "Release", $vectorImages)
    EndIf

    If $typeOfImages <> Default Then
        _cveInputArrayRelease($iArrImages)
        If $bImagesCreate Then
            Call("_cve" & $typeOfImages & "Release", $images)
        EndIf
    EndIf
EndFunc   ;==>_cveCalcHistTyped

Func _cveCalcHistMat($images, $channels, $mask, $hist, $histSize, $ranges, $accumulate = false)
    ; cveCalcHist using cv::Mat instead of _*Array
    _cveCalcHistTyped("Mat", $images, $channels, "Mat", $mask, "Mat", $hist, $histSize, $ranges, $accumulate)
EndFunc   ;==>_cveCalcHistMat

Func _cveCalcBackProject($images, $channels, $hist, $dst, $ranges, $scale)
    ; CVAPI(void) cveCalcBackProject(cv::_InputArray* images, const std::vector<int>* channels, cv::_InputArray* hist, cv::_OutputArray* dst, const std::vector<float>* ranges, double scale);

    Local $sImagesDllType
    If IsDllStruct($images) Then
        $sImagesDllType = "struct*"
    Else
        $sImagesDllType = "ptr"
    EndIf

    Local $vecChannels, $iArrChannelsSize
    Local $bChannelsIsArray = IsArray($channels)

    If $bChannelsIsArray Then
        $vecChannels = _VectorOfIntCreate()

        $iArrChannelsSize = UBound($channels)
        For $i = 0 To $iArrChannelsSize - 1
            _VectorOfIntPush($vecChannels, $channels[$i])
        Next
    Else
        $vecChannels = $channels
    EndIf

    Local $sChannelsDllType
    If IsDllStruct($channels) Then
        $sChannelsDllType = "struct*"
    Else
        $sChannelsDllType = "ptr"
    EndIf

    Local $sHistDllType
    If IsDllStruct($hist) Then
        $sHistDllType = "struct*"
    Else
        $sHistDllType = "ptr"
    EndIf

    Local $sDstDllType
    If IsDllStruct($dst) Then
        $sDstDllType = "struct*"
    Else
        $sDstDllType = "ptr"
    EndIf

    Local $vecRanges, $iArrRangesSize
    Local $bRangesIsArray = IsArray($ranges)

    If $bRangesIsArray Then
        $vecRanges = _VectorOfFloatCreate()

        $iArrRangesSize = UBound($ranges)
        For $i = 0 To $iArrRangesSize - 1
            _VectorOfFloatPush($vecRanges, $ranges[$i])
        Next
    Else
        $vecRanges = $ranges
    EndIf

    Local $sRangesDllType
    If IsDllStruct($ranges) Then
        $sRangesDllType = "struct*"
    Else
        $sRangesDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCalcBackProject", $sImagesDllType, $images, $sChannelsDllType, $vecChannels, $sHistDllType, $hist, $sDstDllType, $dst, $sRangesDllType, $vecRanges, "double", $scale), "cveCalcBackProject", @error)

    If $bRangesIsArray Then
        _VectorOfFloatRelease($vecRanges)
    EndIf

    If $bChannelsIsArray Then
        _VectorOfIntRelease($vecChannels)
    EndIf
EndFunc   ;==>_cveCalcBackProject

Func _cveCalcBackProjectTyped($typeOfImages, $images, $channels, $typeOfHist, $hist, $typeOfDst, $dst, $ranges, $scale)

    Local $iArrImages, $vectorImages, $iArrImagesSize
    Local $bImagesIsArray = IsArray($images)
    Local $bImagesCreate = IsDllStruct($images) And $typeOfImages == "Scalar"

    If $typeOfImages == Default Then
        $iArrImages = $images
    ElseIf $bImagesIsArray Then
        $vectorImages = Call("_VectorOf" & $typeOfImages & "Create")

        $iArrImagesSize = UBound($images)
        For $i = 0 To $iArrImagesSize - 1
            Call("_VectorOf" & $typeOfImages & "Push", $vectorImages, $images[$i])
        Next

        $iArrImages = Call("_cveInputArrayFromVectorOf" & $typeOfImages, $vectorImages)
    Else
        If $bImagesCreate Then
            $images = Call("_cve" & $typeOfImages & "Create", $images)
        EndIf
        $iArrImages = Call("_cveInputArrayFrom" & $typeOfImages, $images)
    EndIf

    Local $iArrHist, $vectorHist, $iArrHistSize
    Local $bHistIsArray = IsArray($hist)
    Local $bHistCreate = IsDllStruct($hist) And $typeOfHist == "Scalar"

    If $typeOfHist == Default Then
        $iArrHist = $hist
    ElseIf $bHistIsArray Then
        $vectorHist = Call("_VectorOf" & $typeOfHist & "Create")

        $iArrHistSize = UBound($hist)
        For $i = 0 To $iArrHistSize - 1
            Call("_VectorOf" & $typeOfHist & "Push", $vectorHist, $hist[$i])
        Next

        $iArrHist = Call("_cveInputArrayFromVectorOf" & $typeOfHist, $vectorHist)
    Else
        If $bHistCreate Then
            $hist = Call("_cve" & $typeOfHist & "Create", $hist)
        EndIf
        $iArrHist = Call("_cveInputArrayFrom" & $typeOfHist, $hist)
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

    _cveCalcBackProject($iArrImages, $channels, $iArrHist, $oArrDst, $ranges, $scale)

    If $bDstIsArray Then
        Call("_VectorOf" & $typeOfDst & "Release", $vectorDst)
    EndIf

    If $typeOfDst <> Default Then
        _cveOutputArrayRelease($oArrDst)
        If $bDstCreate Then
            Call("_cve" & $typeOfDst & "Release", $dst)
        EndIf
    EndIf

    If $bHistIsArray Then
        Call("_VectorOf" & $typeOfHist & "Release", $vectorHist)
    EndIf

    If $typeOfHist <> Default Then
        _cveInputArrayRelease($iArrHist)
        If $bHistCreate Then
            Call("_cve" & $typeOfHist & "Release", $hist)
        EndIf
    EndIf

    If $bImagesIsArray Then
        Call("_VectorOf" & $typeOfImages & "Release", $vectorImages)
    EndIf

    If $typeOfImages <> Default Then
        _cveInputArrayRelease($iArrImages)
        If $bImagesCreate Then
            Call("_cve" & $typeOfImages & "Release", $images)
        EndIf
    EndIf
EndFunc   ;==>_cveCalcBackProjectTyped

Func _cveCalcBackProjectMat($images, $channels, $hist, $dst, $ranges, $scale)
    ; cveCalcBackProject using cv::Mat instead of _*Array
    _cveCalcBackProjectTyped("Mat", $images, $channels, "Mat", $hist, "Mat", $dst, $ranges, $scale)
EndFunc   ;==>_cveCalcBackProjectMat

Func _cveCompareHist($h1, $h2, $method)
    ; CVAPI(double) cveCompareHist(cv::_InputArray* h1, cv::_InputArray* h2, int method);

    Local $sH1DllType
    If IsDllStruct($h1) Then
        $sH1DllType = "struct*"
    Else
        $sH1DllType = "ptr"
    EndIf

    Local $sH2DllType
    If IsDllStruct($h2) Then
        $sH2DllType = "struct*"
    Else
        $sH2DllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveCompareHist", $sH1DllType, $h1, $sH2DllType, $h2, "int", $method), "cveCompareHist", @error)
EndFunc   ;==>_cveCompareHist

Func _cveCompareHistTyped($typeOfH1, $h1, $typeOfH2, $h2, $method)

    Local $iArrH1, $vectorH1, $iArrH1Size
    Local $bH1IsArray = IsArray($h1)
    Local $bH1Create = IsDllStruct($h1) And $typeOfH1 == "Scalar"

    If $typeOfH1 == Default Then
        $iArrH1 = $h1
    ElseIf $bH1IsArray Then
        $vectorH1 = Call("_VectorOf" & $typeOfH1 & "Create")

        $iArrH1Size = UBound($h1)
        For $i = 0 To $iArrH1Size - 1
            Call("_VectorOf" & $typeOfH1 & "Push", $vectorH1, $h1[$i])
        Next

        $iArrH1 = Call("_cveInputArrayFromVectorOf" & $typeOfH1, $vectorH1)
    Else
        If $bH1Create Then
            $h1 = Call("_cve" & $typeOfH1 & "Create", $h1)
        EndIf
        $iArrH1 = Call("_cveInputArrayFrom" & $typeOfH1, $h1)
    EndIf

    Local $iArrH2, $vectorH2, $iArrH2Size
    Local $bH2IsArray = IsArray($h2)
    Local $bH2Create = IsDllStruct($h2) And $typeOfH2 == "Scalar"

    If $typeOfH2 == Default Then
        $iArrH2 = $h2
    ElseIf $bH2IsArray Then
        $vectorH2 = Call("_VectorOf" & $typeOfH2 & "Create")

        $iArrH2Size = UBound($h2)
        For $i = 0 To $iArrH2Size - 1
            Call("_VectorOf" & $typeOfH2 & "Push", $vectorH2, $h2[$i])
        Next

        $iArrH2 = Call("_cveInputArrayFromVectorOf" & $typeOfH2, $vectorH2)
    Else
        If $bH2Create Then
            $h2 = Call("_cve" & $typeOfH2 & "Create", $h2)
        EndIf
        $iArrH2 = Call("_cveInputArrayFrom" & $typeOfH2, $h2)
    EndIf

    Local $retval = _cveCompareHist($iArrH1, $iArrH2, $method)

    If $bH2IsArray Then
        Call("_VectorOf" & $typeOfH2 & "Release", $vectorH2)
    EndIf

    If $typeOfH2 <> Default Then
        _cveInputArrayRelease($iArrH2)
        If $bH2Create Then
            Call("_cve" & $typeOfH2 & "Release", $h2)
        EndIf
    EndIf

    If $bH1IsArray Then
        Call("_VectorOf" & $typeOfH1 & "Release", $vectorH1)
    EndIf

    If $typeOfH1 <> Default Then
        _cveInputArrayRelease($iArrH1)
        If $bH1Create Then
            Call("_cve" & $typeOfH1 & "Release", $h1)
        EndIf
    EndIf

    Return $retval
EndFunc   ;==>_cveCompareHistTyped

Func _cveCompareHistMat($h1, $h2, $method)
    ; cveCompareHist using cv::Mat instead of _*Array
    Local $retval = _cveCompareHistTyped("Mat", $h1, "Mat", $h2, $method)

    Return $retval
EndFunc   ;==>_cveCompareHistMat

Func _cveGetRotationMatrix2D($center, $angle, $scale, $rotationMatrix2D)
    ; CVAPI(void) cveGetRotationMatrix2D(CvPoint2D32f* center, double angle, double scale, cv::_OutputArray* rotationMatrix2D);

    Local $sCenterDllType
    If IsDllStruct($center) Then
        $sCenterDllType = "struct*"
    Else
        $sCenterDllType = "ptr"
    EndIf

    Local $sRotationMatrix2DDllType
    If IsDllStruct($rotationMatrix2D) Then
        $sRotationMatrix2DDllType = "struct*"
    Else
        $sRotationMatrix2DDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveGetRotationMatrix2D", $sCenterDllType, $center, "double", $angle, "double", $scale, $sRotationMatrix2DDllType, $rotationMatrix2D), "cveGetRotationMatrix2D", @error)
EndFunc   ;==>_cveGetRotationMatrix2D

Func _cveGetRotationMatrix2DTyped($center, $angle, $scale, $typeOfRotationMatrix2D, $rotationMatrix2D)

    Local $oArrRotationMatrix2D, $vectorRotationMatrix2D, $iArrRotationMatrix2DSize
    Local $bRotationMatrix2DIsArray = IsArray($rotationMatrix2D)
    Local $bRotationMatrix2DCreate = IsDllStruct($rotationMatrix2D) And $typeOfRotationMatrix2D == "Scalar"

    If $typeOfRotationMatrix2D == Default Then
        $oArrRotationMatrix2D = $rotationMatrix2D
    ElseIf $bRotationMatrix2DIsArray Then
        $vectorRotationMatrix2D = Call("_VectorOf" & $typeOfRotationMatrix2D & "Create")

        $iArrRotationMatrix2DSize = UBound($rotationMatrix2D)
        For $i = 0 To $iArrRotationMatrix2DSize - 1
            Call("_VectorOf" & $typeOfRotationMatrix2D & "Push", $vectorRotationMatrix2D, $rotationMatrix2D[$i])
        Next

        $oArrRotationMatrix2D = Call("_cveOutputArrayFromVectorOf" & $typeOfRotationMatrix2D, $vectorRotationMatrix2D)
    Else
        If $bRotationMatrix2DCreate Then
            $rotationMatrix2D = Call("_cve" & $typeOfRotationMatrix2D & "Create", $rotationMatrix2D)
        EndIf
        $oArrRotationMatrix2D = Call("_cveOutputArrayFrom" & $typeOfRotationMatrix2D, $rotationMatrix2D)
    EndIf

    _cveGetRotationMatrix2D($center, $angle, $scale, $oArrRotationMatrix2D)

    If $bRotationMatrix2DIsArray Then
        Call("_VectorOf" & $typeOfRotationMatrix2D & "Release", $vectorRotationMatrix2D)
    EndIf

    If $typeOfRotationMatrix2D <> Default Then
        _cveOutputArrayRelease($oArrRotationMatrix2D)
        If $bRotationMatrix2DCreate Then
            Call("_cve" & $typeOfRotationMatrix2D & "Release", $rotationMatrix2D)
        EndIf
    EndIf
EndFunc   ;==>_cveGetRotationMatrix2DTyped

Func _cveGetRotationMatrix2DMat($center, $angle, $scale, $rotationMatrix2D)
    ; cveGetRotationMatrix2D using cv::Mat instead of _*Array
    _cveGetRotationMatrix2DTyped($center, $angle, $scale, "Mat", $rotationMatrix2D)
EndFunc   ;==>_cveGetRotationMatrix2DMat

Func _cveFindContours($image, $contours, $hierarchy, $mode, $method, $offset = _cvPoint())
    ; CVAPI(void) cveFindContours(cv::_InputOutputArray* image, cv::_OutputArray* contours, cv::_OutputArray* hierarchy, int mode, int method, CvPoint* offset);

    Local $sImageDllType
    If IsDllStruct($image) Then
        $sImageDllType = "struct*"
    Else
        $sImageDllType = "ptr"
    EndIf

    Local $sContoursDllType
    If IsDllStruct($contours) Then
        $sContoursDllType = "struct*"
    Else
        $sContoursDllType = "ptr"
    EndIf

    Local $sHierarchyDllType
    If IsDllStruct($hierarchy) Then
        $sHierarchyDllType = "struct*"
    Else
        $sHierarchyDllType = "ptr"
    EndIf

    Local $sOffsetDllType
    If IsDllStruct($offset) Then
        $sOffsetDllType = "struct*"
    Else
        $sOffsetDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFindContours", $sImageDllType, $image, $sContoursDllType, $contours, $sHierarchyDllType, $hierarchy, "int", $mode, "int", $method, $sOffsetDllType, $offset), "cveFindContours", @error)
EndFunc   ;==>_cveFindContours

Func _cveFindContoursTyped($typeOfImage, $image, $typeOfContours, $contours, $typeOfHierarchy, $hierarchy, $mode, $method, $offset = _cvPoint())

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

    Local $oArrContours, $vectorContours, $iArrContoursSize
    Local $bContoursIsArray = IsArray($contours)
    Local $bContoursCreate = IsDllStruct($contours) And $typeOfContours == "Scalar"

    If $typeOfContours == Default Then
        $oArrContours = $contours
    ElseIf $bContoursIsArray Then
        $vectorContours = Call("_VectorOf" & $typeOfContours & "Create")

        $iArrContoursSize = UBound($contours)
        For $i = 0 To $iArrContoursSize - 1
            Call("_VectorOf" & $typeOfContours & "Push", $vectorContours, $contours[$i])
        Next

        $oArrContours = Call("_cveOutputArrayFromVectorOf" & $typeOfContours, $vectorContours)
    Else
        If $bContoursCreate Then
            $contours = Call("_cve" & $typeOfContours & "Create", $contours)
        EndIf
        $oArrContours = Call("_cveOutputArrayFrom" & $typeOfContours, $contours)
    EndIf

    Local $oArrHierarchy, $vectorHierarchy, $iArrHierarchySize
    Local $bHierarchyIsArray = IsArray($hierarchy)
    Local $bHierarchyCreate = IsDllStruct($hierarchy) And $typeOfHierarchy == "Scalar"

    If $typeOfHierarchy == Default Then
        $oArrHierarchy = $hierarchy
    ElseIf $bHierarchyIsArray Then
        $vectorHierarchy = Call("_VectorOf" & $typeOfHierarchy & "Create")

        $iArrHierarchySize = UBound($hierarchy)
        For $i = 0 To $iArrHierarchySize - 1
            Call("_VectorOf" & $typeOfHierarchy & "Push", $vectorHierarchy, $hierarchy[$i])
        Next

        $oArrHierarchy = Call("_cveOutputArrayFromVectorOf" & $typeOfHierarchy, $vectorHierarchy)
    Else
        If $bHierarchyCreate Then
            $hierarchy = Call("_cve" & $typeOfHierarchy & "Create", $hierarchy)
        EndIf
        $oArrHierarchy = Call("_cveOutputArrayFrom" & $typeOfHierarchy, $hierarchy)
    EndIf

    _cveFindContours($ioArrImage, $oArrContours, $oArrHierarchy, $mode, $method, $offset)

    If $bHierarchyIsArray Then
        Call("_VectorOf" & $typeOfHierarchy & "Release", $vectorHierarchy)
    EndIf

    If $typeOfHierarchy <> Default Then
        _cveOutputArrayRelease($oArrHierarchy)
        If $bHierarchyCreate Then
            Call("_cve" & $typeOfHierarchy & "Release", $hierarchy)
        EndIf
    EndIf

    If $bContoursIsArray Then
        Call("_VectorOf" & $typeOfContours & "Release", $vectorContours)
    EndIf

    If $typeOfContours <> Default Then
        _cveOutputArrayRelease($oArrContours)
        If $bContoursCreate Then
            Call("_cve" & $typeOfContours & "Release", $contours)
        EndIf
    EndIf

    If $bImageIsArray Then
        Call("_VectorOf" & $typeOfImage & "Release", $vectorImage)
    EndIf

    If $typeOfImage <> Default Then
        _cveInputOutputArrayRelease($ioArrImage)
        If $bImageCreate Then
            Call("_cve" & $typeOfImage & "Release", $image)
        EndIf
    EndIf
EndFunc   ;==>_cveFindContoursTyped

Func _cveFindContoursMat($image, $contours, $hierarchy, $mode, $method, $offset = _cvPoint())
    ; cveFindContours using cv::Mat instead of _*Array
    _cveFindContoursTyped("Mat", $image, "Mat", $contours, "Mat", $hierarchy, $mode, $method, $offset)
EndFunc   ;==>_cveFindContoursMat

Func _cvePointPolygonTest($contour, $pt, $measureDist)
    ; CVAPI(double) cvePointPolygonTest(cv::_InputArray* contour, CvPoint2D32f* pt, bool measureDist);

    Local $sContourDllType
    If IsDllStruct($contour) Then
        $sContourDllType = "struct*"
    Else
        $sContourDllType = "ptr"
    EndIf

    Local $sPtDllType
    If IsDllStruct($pt) Then
        $sPtDllType = "struct*"
    Else
        $sPtDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cvePointPolygonTest", $sContourDllType, $contour, $sPtDllType, $pt, "boolean", $measureDist), "cvePointPolygonTest", @error)
EndFunc   ;==>_cvePointPolygonTest

Func _cvePointPolygonTestTyped($typeOfContour, $contour, $pt, $measureDist)

    Local $iArrContour, $vectorContour, $iArrContourSize
    Local $bContourIsArray = IsArray($contour)
    Local $bContourCreate = IsDllStruct($contour) And $typeOfContour == "Scalar"

    If $typeOfContour == Default Then
        $iArrContour = $contour
    ElseIf $bContourIsArray Then
        $vectorContour = Call("_VectorOf" & $typeOfContour & "Create")

        $iArrContourSize = UBound($contour)
        For $i = 0 To $iArrContourSize - 1
            Call("_VectorOf" & $typeOfContour & "Push", $vectorContour, $contour[$i])
        Next

        $iArrContour = Call("_cveInputArrayFromVectorOf" & $typeOfContour, $vectorContour)
    Else
        If $bContourCreate Then
            $contour = Call("_cve" & $typeOfContour & "Create", $contour)
        EndIf
        $iArrContour = Call("_cveInputArrayFrom" & $typeOfContour, $contour)
    EndIf

    Local $retval = _cvePointPolygonTest($iArrContour, $pt, $measureDist)

    If $bContourIsArray Then
        Call("_VectorOf" & $typeOfContour & "Release", $vectorContour)
    EndIf

    If $typeOfContour <> Default Then
        _cveInputArrayRelease($iArrContour)
        If $bContourCreate Then
            Call("_cve" & $typeOfContour & "Release", $contour)
        EndIf
    EndIf

    Return $retval
EndFunc   ;==>_cvePointPolygonTestTyped

Func _cvePointPolygonTestMat($contour, $pt, $measureDist)
    ; cvePointPolygonTest using cv::Mat instead of _*Array
    Local $retval = _cvePointPolygonTestTyped("Mat", $contour, $pt, $measureDist)

    Return $retval
EndFunc   ;==>_cvePointPolygonTestMat

Func _cveContourArea($contour, $oriented = false)
    ; CVAPI(double) cveContourArea(cv::_InputArray* contour, bool oriented);

    Local $sContourDllType
    If IsDllStruct($contour) Then
        $sContourDllType = "struct*"
    Else
        $sContourDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveContourArea", $sContourDllType, $contour, "boolean", $oriented), "cveContourArea", @error)
EndFunc   ;==>_cveContourArea

Func _cveContourAreaTyped($typeOfContour, $contour, $oriented = false)

    Local $iArrContour, $vectorContour, $iArrContourSize
    Local $bContourIsArray = IsArray($contour)
    Local $bContourCreate = IsDllStruct($contour) And $typeOfContour == "Scalar"

    If $typeOfContour == Default Then
        $iArrContour = $contour
    ElseIf $bContourIsArray Then
        $vectorContour = Call("_VectorOf" & $typeOfContour & "Create")

        $iArrContourSize = UBound($contour)
        For $i = 0 To $iArrContourSize - 1
            Call("_VectorOf" & $typeOfContour & "Push", $vectorContour, $contour[$i])
        Next

        $iArrContour = Call("_cveInputArrayFromVectorOf" & $typeOfContour, $vectorContour)
    Else
        If $bContourCreate Then
            $contour = Call("_cve" & $typeOfContour & "Create", $contour)
        EndIf
        $iArrContour = Call("_cveInputArrayFrom" & $typeOfContour, $contour)
    EndIf

    Local $retval = _cveContourArea($iArrContour, $oriented)

    If $bContourIsArray Then
        Call("_VectorOf" & $typeOfContour & "Release", $vectorContour)
    EndIf

    If $typeOfContour <> Default Then
        _cveInputArrayRelease($iArrContour)
        If $bContourCreate Then
            Call("_cve" & $typeOfContour & "Release", $contour)
        EndIf
    EndIf

    Return $retval
EndFunc   ;==>_cveContourAreaTyped

Func _cveContourAreaMat($contour, $oriented = false)
    ; cveContourArea using cv::Mat instead of _*Array
    Local $retval = _cveContourAreaTyped("Mat", $contour, $oriented)

    Return $retval
EndFunc   ;==>_cveContourAreaMat

Func _cveIsContourConvex($contour)
    ; CVAPI(bool) cveIsContourConvex(cv::_InputArray* contour);

    Local $sContourDllType
    If IsDllStruct($contour) Then
        $sContourDllType = "struct*"
    Else
        $sContourDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveIsContourConvex", $sContourDllType, $contour), "cveIsContourConvex", @error)
EndFunc   ;==>_cveIsContourConvex

Func _cveIsContourConvexTyped($typeOfContour, $contour)

    Local $iArrContour, $vectorContour, $iArrContourSize
    Local $bContourIsArray = IsArray($contour)
    Local $bContourCreate = IsDllStruct($contour) And $typeOfContour == "Scalar"

    If $typeOfContour == Default Then
        $iArrContour = $contour
    ElseIf $bContourIsArray Then
        $vectorContour = Call("_VectorOf" & $typeOfContour & "Create")

        $iArrContourSize = UBound($contour)
        For $i = 0 To $iArrContourSize - 1
            Call("_VectorOf" & $typeOfContour & "Push", $vectorContour, $contour[$i])
        Next

        $iArrContour = Call("_cveInputArrayFromVectorOf" & $typeOfContour, $vectorContour)
    Else
        If $bContourCreate Then
            $contour = Call("_cve" & $typeOfContour & "Create", $contour)
        EndIf
        $iArrContour = Call("_cveInputArrayFrom" & $typeOfContour, $contour)
    EndIf

    Local $retval = _cveIsContourConvex($iArrContour)

    If $bContourIsArray Then
        Call("_VectorOf" & $typeOfContour & "Release", $vectorContour)
    EndIf

    If $typeOfContour <> Default Then
        _cveInputArrayRelease($iArrContour)
        If $bContourCreate Then
            Call("_cve" & $typeOfContour & "Release", $contour)
        EndIf
    EndIf

    Return $retval
EndFunc   ;==>_cveIsContourConvexTyped

Func _cveIsContourConvexMat($contour)
    ; cveIsContourConvex using cv::Mat instead of _*Array
    Local $retval = _cveIsContourConvexTyped("Mat", $contour)

    Return $retval
EndFunc   ;==>_cveIsContourConvexMat

Func _cveIntersectConvexConvex($p1, $p2, $p12, $handleNested = true)
    ; CVAPI(float) cveIntersectConvexConvex(cv::_InputArray* p1, cv::_InputArray* p2, cv::_OutputArray* p12, bool handleNested);

    Local $sP1DllType
    If IsDllStruct($p1) Then
        $sP1DllType = "struct*"
    Else
        $sP1DllType = "ptr"
    EndIf

    Local $sP2DllType
    If IsDllStruct($p2) Then
        $sP2DllType = "struct*"
    Else
        $sP2DllType = "ptr"
    EndIf

    Local $sP12DllType
    If IsDllStruct($p12) Then
        $sP12DllType = "struct*"
    Else
        $sP12DllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cveIntersectConvexConvex", $sP1DllType, $p1, $sP2DllType, $p2, $sP12DllType, $p12, "boolean", $handleNested), "cveIntersectConvexConvex", @error)
EndFunc   ;==>_cveIntersectConvexConvex

Func _cveIntersectConvexConvexTyped($typeOfP1, $p1, $typeOfP2, $p2, $typeOfP12, $p12, $handleNested = true)

    Local $iArrP1, $vectorP1, $iArrP1Size
    Local $bP1IsArray = IsArray($p1)
    Local $bP1Create = IsDllStruct($p1) And $typeOfP1 == "Scalar"

    If $typeOfP1 == Default Then
        $iArrP1 = $p1
    ElseIf $bP1IsArray Then
        $vectorP1 = Call("_VectorOf" & $typeOfP1 & "Create")

        $iArrP1Size = UBound($p1)
        For $i = 0 To $iArrP1Size - 1
            Call("_VectorOf" & $typeOfP1 & "Push", $vectorP1, $p1[$i])
        Next

        $iArrP1 = Call("_cveInputArrayFromVectorOf" & $typeOfP1, $vectorP1)
    Else
        If $bP1Create Then
            $p1 = Call("_cve" & $typeOfP1 & "Create", $p1)
        EndIf
        $iArrP1 = Call("_cveInputArrayFrom" & $typeOfP1, $p1)
    EndIf

    Local $iArrP2, $vectorP2, $iArrP2Size
    Local $bP2IsArray = IsArray($p2)
    Local $bP2Create = IsDllStruct($p2) And $typeOfP2 == "Scalar"

    If $typeOfP2 == Default Then
        $iArrP2 = $p2
    ElseIf $bP2IsArray Then
        $vectorP2 = Call("_VectorOf" & $typeOfP2 & "Create")

        $iArrP2Size = UBound($p2)
        For $i = 0 To $iArrP2Size - 1
            Call("_VectorOf" & $typeOfP2 & "Push", $vectorP2, $p2[$i])
        Next

        $iArrP2 = Call("_cveInputArrayFromVectorOf" & $typeOfP2, $vectorP2)
    Else
        If $bP2Create Then
            $p2 = Call("_cve" & $typeOfP2 & "Create", $p2)
        EndIf
        $iArrP2 = Call("_cveInputArrayFrom" & $typeOfP2, $p2)
    EndIf

    Local $oArrP12, $vectorP12, $iArrP12Size
    Local $bP12IsArray = IsArray($p12)
    Local $bP12Create = IsDllStruct($p12) And $typeOfP12 == "Scalar"

    If $typeOfP12 == Default Then
        $oArrP12 = $p12
    ElseIf $bP12IsArray Then
        $vectorP12 = Call("_VectorOf" & $typeOfP12 & "Create")

        $iArrP12Size = UBound($p12)
        For $i = 0 To $iArrP12Size - 1
            Call("_VectorOf" & $typeOfP12 & "Push", $vectorP12, $p12[$i])
        Next

        $oArrP12 = Call("_cveOutputArrayFromVectorOf" & $typeOfP12, $vectorP12)
    Else
        If $bP12Create Then
            $p12 = Call("_cve" & $typeOfP12 & "Create", $p12)
        EndIf
        $oArrP12 = Call("_cveOutputArrayFrom" & $typeOfP12, $p12)
    EndIf

    Local $retval = _cveIntersectConvexConvex($iArrP1, $iArrP2, $oArrP12, $handleNested)

    If $bP12IsArray Then
        Call("_VectorOf" & $typeOfP12 & "Release", $vectorP12)
    EndIf

    If $typeOfP12 <> Default Then
        _cveOutputArrayRelease($oArrP12)
        If $bP12Create Then
            Call("_cve" & $typeOfP12 & "Release", $p12)
        EndIf
    EndIf

    If $bP2IsArray Then
        Call("_VectorOf" & $typeOfP2 & "Release", $vectorP2)
    EndIf

    If $typeOfP2 <> Default Then
        _cveInputArrayRelease($iArrP2)
        If $bP2Create Then
            Call("_cve" & $typeOfP2 & "Release", $p2)
        EndIf
    EndIf

    If $bP1IsArray Then
        Call("_VectorOf" & $typeOfP1 & "Release", $vectorP1)
    EndIf

    If $typeOfP1 <> Default Then
        _cveInputArrayRelease($iArrP1)
        If $bP1Create Then
            Call("_cve" & $typeOfP1 & "Release", $p1)
        EndIf
    EndIf

    Return $retval
EndFunc   ;==>_cveIntersectConvexConvexTyped

Func _cveIntersectConvexConvexMat($p1, $p2, $p12, $handleNested = true)
    ; cveIntersectConvexConvex using cv::Mat instead of _*Array
    Local $retval = _cveIntersectConvexConvexTyped("Mat", $p1, "Mat", $p2, "Mat", $p12, $handleNested)

    Return $retval
EndFunc   ;==>_cveIntersectConvexConvexMat

Func _cveBoundingRectangle($points, $boundingRect)
    ; CVAPI(void) cveBoundingRectangle(cv::_InputArray* points, CvRect* boundingRect);

    Local $sPointsDllType
    If IsDllStruct($points) Then
        $sPointsDllType = "struct*"
    Else
        $sPointsDllType = "ptr"
    EndIf

    Local $sBoundingRectDllType
    If IsDllStruct($boundingRect) Then
        $sBoundingRectDllType = "struct*"
    Else
        $sBoundingRectDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBoundingRectangle", $sPointsDllType, $points, $sBoundingRectDllType, $boundingRect), "cveBoundingRectangle", @error)
EndFunc   ;==>_cveBoundingRectangle

Func _cveBoundingRectangleTyped($typeOfPoints, $points, $boundingRect)

    Local $iArrPoints, $vectorPoints, $iArrPointsSize
    Local $bPointsIsArray = IsArray($points)
    Local $bPointsCreate = IsDllStruct($points) And $typeOfPoints == "Scalar"

    If $typeOfPoints == Default Then
        $iArrPoints = $points
    ElseIf $bPointsIsArray Then
        $vectorPoints = Call("_VectorOf" & $typeOfPoints & "Create")

        $iArrPointsSize = UBound($points)
        For $i = 0 To $iArrPointsSize - 1
            Call("_VectorOf" & $typeOfPoints & "Push", $vectorPoints, $points[$i])
        Next

        $iArrPoints = Call("_cveInputArrayFromVectorOf" & $typeOfPoints, $vectorPoints)
    Else
        If $bPointsCreate Then
            $points = Call("_cve" & $typeOfPoints & "Create", $points)
        EndIf
        $iArrPoints = Call("_cveInputArrayFrom" & $typeOfPoints, $points)
    EndIf

    _cveBoundingRectangle($iArrPoints, $boundingRect)

    If $bPointsIsArray Then
        Call("_VectorOf" & $typeOfPoints & "Release", $vectorPoints)
    EndIf

    If $typeOfPoints <> Default Then
        _cveInputArrayRelease($iArrPoints)
        If $bPointsCreate Then
            Call("_cve" & $typeOfPoints & "Release", $points)
        EndIf
    EndIf
EndFunc   ;==>_cveBoundingRectangleTyped

Func _cveBoundingRectangleMat($points, $boundingRect)
    ; cveBoundingRectangle using cv::Mat instead of _*Array
    _cveBoundingRectangleTyped("Mat", $points, $boundingRect)
EndFunc   ;==>_cveBoundingRectangleMat

Func _cveArcLength($curve, $closed)
    ; CVAPI(double) cveArcLength(cv::_InputArray* curve, bool closed);

    Local $sCurveDllType
    If IsDllStruct($curve) Then
        $sCurveDllType = "struct*"
    Else
        $sCurveDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveArcLength", $sCurveDllType, $curve, "boolean", $closed), "cveArcLength", @error)
EndFunc   ;==>_cveArcLength

Func _cveArcLengthTyped($typeOfCurve, $curve, $closed)

    Local $iArrCurve, $vectorCurve, $iArrCurveSize
    Local $bCurveIsArray = IsArray($curve)
    Local $bCurveCreate = IsDllStruct($curve) And $typeOfCurve == "Scalar"

    If $typeOfCurve == Default Then
        $iArrCurve = $curve
    ElseIf $bCurveIsArray Then
        $vectorCurve = Call("_VectorOf" & $typeOfCurve & "Create")

        $iArrCurveSize = UBound($curve)
        For $i = 0 To $iArrCurveSize - 1
            Call("_VectorOf" & $typeOfCurve & "Push", $vectorCurve, $curve[$i])
        Next

        $iArrCurve = Call("_cveInputArrayFromVectorOf" & $typeOfCurve, $vectorCurve)
    Else
        If $bCurveCreate Then
            $curve = Call("_cve" & $typeOfCurve & "Create", $curve)
        EndIf
        $iArrCurve = Call("_cveInputArrayFrom" & $typeOfCurve, $curve)
    EndIf

    Local $retval = _cveArcLength($iArrCurve, $closed)

    If $bCurveIsArray Then
        Call("_VectorOf" & $typeOfCurve & "Release", $vectorCurve)
    EndIf

    If $typeOfCurve <> Default Then
        _cveInputArrayRelease($iArrCurve)
        If $bCurveCreate Then
            Call("_cve" & $typeOfCurve & "Release", $curve)
        EndIf
    EndIf

    Return $retval
EndFunc   ;==>_cveArcLengthTyped

Func _cveArcLengthMat($curve, $closed)
    ; cveArcLength using cv::Mat instead of _*Array
    Local $retval = _cveArcLengthTyped("Mat", $curve, $closed)

    Return $retval
EndFunc   ;==>_cveArcLengthMat

Func _cveMinAreaRect($points, $box)
    ; CVAPI(void) cveMinAreaRect(cv::_InputArray* points, CvBox2D* box);

    Local $sPointsDllType
    If IsDllStruct($points) Then
        $sPointsDllType = "struct*"
    Else
        $sPointsDllType = "ptr"
    EndIf

    Local $sBoxDllType
    If IsDllStruct($box) Then
        $sBoxDllType = "struct*"
    Else
        $sBoxDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMinAreaRect", $sPointsDllType, $points, $sBoxDllType, $box), "cveMinAreaRect", @error)
EndFunc   ;==>_cveMinAreaRect

Func _cveMinAreaRectTyped($typeOfPoints, $points, $box)

    Local $iArrPoints, $vectorPoints, $iArrPointsSize
    Local $bPointsIsArray = IsArray($points)
    Local $bPointsCreate = IsDllStruct($points) And $typeOfPoints == "Scalar"

    If $typeOfPoints == Default Then
        $iArrPoints = $points
    ElseIf $bPointsIsArray Then
        $vectorPoints = Call("_VectorOf" & $typeOfPoints & "Create")

        $iArrPointsSize = UBound($points)
        For $i = 0 To $iArrPointsSize - 1
            Call("_VectorOf" & $typeOfPoints & "Push", $vectorPoints, $points[$i])
        Next

        $iArrPoints = Call("_cveInputArrayFromVectorOf" & $typeOfPoints, $vectorPoints)
    Else
        If $bPointsCreate Then
            $points = Call("_cve" & $typeOfPoints & "Create", $points)
        EndIf
        $iArrPoints = Call("_cveInputArrayFrom" & $typeOfPoints, $points)
    EndIf

    _cveMinAreaRect($iArrPoints, $box)

    If $bPointsIsArray Then
        Call("_VectorOf" & $typeOfPoints & "Release", $vectorPoints)
    EndIf

    If $typeOfPoints <> Default Then
        _cveInputArrayRelease($iArrPoints)
        If $bPointsCreate Then
            Call("_cve" & $typeOfPoints & "Release", $points)
        EndIf
    EndIf
EndFunc   ;==>_cveMinAreaRectTyped

Func _cveMinAreaRectMat($points, $box)
    ; cveMinAreaRect using cv::Mat instead of _*Array
    _cveMinAreaRectTyped("Mat", $points, $box)
EndFunc   ;==>_cveMinAreaRectMat

Func _cveBoxPoints($box, $points)
    ; CVAPI(void) cveBoxPoints(CvBox2D* box, cv::_OutputArray* points);

    Local $sBoxDllType
    If IsDllStruct($box) Then
        $sBoxDllType = "struct*"
    Else
        $sBoxDllType = "ptr"
    EndIf

    Local $sPointsDllType
    If IsDllStruct($points) Then
        $sPointsDllType = "struct*"
    Else
        $sPointsDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBoxPoints", $sBoxDllType, $box, $sPointsDllType, $points), "cveBoxPoints", @error)
EndFunc   ;==>_cveBoxPoints

Func _cveBoxPointsTyped($box, $typeOfPoints, $points)

    Local $oArrPoints, $vectorPoints, $iArrPointsSize
    Local $bPointsIsArray = IsArray($points)
    Local $bPointsCreate = IsDllStruct($points) And $typeOfPoints == "Scalar"

    If $typeOfPoints == Default Then
        $oArrPoints = $points
    ElseIf $bPointsIsArray Then
        $vectorPoints = Call("_VectorOf" & $typeOfPoints & "Create")

        $iArrPointsSize = UBound($points)
        For $i = 0 To $iArrPointsSize - 1
            Call("_VectorOf" & $typeOfPoints & "Push", $vectorPoints, $points[$i])
        Next

        $oArrPoints = Call("_cveOutputArrayFromVectorOf" & $typeOfPoints, $vectorPoints)
    Else
        If $bPointsCreate Then
            $points = Call("_cve" & $typeOfPoints & "Create", $points)
        EndIf
        $oArrPoints = Call("_cveOutputArrayFrom" & $typeOfPoints, $points)
    EndIf

    _cveBoxPoints($box, $oArrPoints)

    If $bPointsIsArray Then
        Call("_VectorOf" & $typeOfPoints & "Release", $vectorPoints)
    EndIf

    If $typeOfPoints <> Default Then
        _cveOutputArrayRelease($oArrPoints)
        If $bPointsCreate Then
            Call("_cve" & $typeOfPoints & "Release", $points)
        EndIf
    EndIf
EndFunc   ;==>_cveBoxPointsTyped

Func _cveBoxPointsMat($box, $points)
    ; cveBoxPoints using cv::Mat instead of _*Array
    _cveBoxPointsTyped($box, "Mat", $points)
EndFunc   ;==>_cveBoxPointsMat

Func _cveMinEnclosingTriangle($points, $triangle)
    ; CVAPI(double) cveMinEnclosingTriangle(cv::_InputArray* points, cv::_OutputArray* triangle);

    Local $sPointsDllType
    If IsDllStruct($points) Then
        $sPointsDllType = "struct*"
    Else
        $sPointsDllType = "ptr"
    EndIf

    Local $sTriangleDllType
    If IsDllStruct($triangle) Then
        $sTriangleDllType = "struct*"
    Else
        $sTriangleDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveMinEnclosingTriangle", $sPointsDllType, $points, $sTriangleDllType, $triangle), "cveMinEnclosingTriangle", @error)
EndFunc   ;==>_cveMinEnclosingTriangle

Func _cveMinEnclosingTriangleTyped($typeOfPoints, $points, $typeOfTriangle, $triangle)

    Local $iArrPoints, $vectorPoints, $iArrPointsSize
    Local $bPointsIsArray = IsArray($points)
    Local $bPointsCreate = IsDllStruct($points) And $typeOfPoints == "Scalar"

    If $typeOfPoints == Default Then
        $iArrPoints = $points
    ElseIf $bPointsIsArray Then
        $vectorPoints = Call("_VectorOf" & $typeOfPoints & "Create")

        $iArrPointsSize = UBound($points)
        For $i = 0 To $iArrPointsSize - 1
            Call("_VectorOf" & $typeOfPoints & "Push", $vectorPoints, $points[$i])
        Next

        $iArrPoints = Call("_cveInputArrayFromVectorOf" & $typeOfPoints, $vectorPoints)
    Else
        If $bPointsCreate Then
            $points = Call("_cve" & $typeOfPoints & "Create", $points)
        EndIf
        $iArrPoints = Call("_cveInputArrayFrom" & $typeOfPoints, $points)
    EndIf

    Local $oArrTriangle, $vectorTriangle, $iArrTriangleSize
    Local $bTriangleIsArray = IsArray($triangle)
    Local $bTriangleCreate = IsDllStruct($triangle) And $typeOfTriangle == "Scalar"

    If $typeOfTriangle == Default Then
        $oArrTriangle = $triangle
    ElseIf $bTriangleIsArray Then
        $vectorTriangle = Call("_VectorOf" & $typeOfTriangle & "Create")

        $iArrTriangleSize = UBound($triangle)
        For $i = 0 To $iArrTriangleSize - 1
            Call("_VectorOf" & $typeOfTriangle & "Push", $vectorTriangle, $triangle[$i])
        Next

        $oArrTriangle = Call("_cveOutputArrayFromVectorOf" & $typeOfTriangle, $vectorTriangle)
    Else
        If $bTriangleCreate Then
            $triangle = Call("_cve" & $typeOfTriangle & "Create", $triangle)
        EndIf
        $oArrTriangle = Call("_cveOutputArrayFrom" & $typeOfTriangle, $triangle)
    EndIf

    Local $retval = _cveMinEnclosingTriangle($iArrPoints, $oArrTriangle)

    If $bTriangleIsArray Then
        Call("_VectorOf" & $typeOfTriangle & "Release", $vectorTriangle)
    EndIf

    If $typeOfTriangle <> Default Then
        _cveOutputArrayRelease($oArrTriangle)
        If $bTriangleCreate Then
            Call("_cve" & $typeOfTriangle & "Release", $triangle)
        EndIf
    EndIf

    If $bPointsIsArray Then
        Call("_VectorOf" & $typeOfPoints & "Release", $vectorPoints)
    EndIf

    If $typeOfPoints <> Default Then
        _cveInputArrayRelease($iArrPoints)
        If $bPointsCreate Then
            Call("_cve" & $typeOfPoints & "Release", $points)
        EndIf
    EndIf

    Return $retval
EndFunc   ;==>_cveMinEnclosingTriangleTyped

Func _cveMinEnclosingTriangleMat($points, $triangle)
    ; cveMinEnclosingTriangle using cv::Mat instead of _*Array
    Local $retval = _cveMinEnclosingTriangleTyped("Mat", $points, "Mat", $triangle)

    Return $retval
EndFunc   ;==>_cveMinEnclosingTriangleMat

Func _cveMinEnclosingCircle($points, $center, $radius)
    ; CVAPI(void) cveMinEnclosingCircle(cv::_InputArray* points, CvPoint2D32f* center, float* radius);

    Local $sPointsDllType
    If IsDllStruct($points) Then
        $sPointsDllType = "struct*"
    Else
        $sPointsDllType = "ptr"
    EndIf

    Local $sCenterDllType
    If IsDllStruct($center) Then
        $sCenterDllType = "struct*"
    Else
        $sCenterDllType = "ptr"
    EndIf

    Local $sRadiusDllType
    If IsDllStruct($radius) Then
        $sRadiusDllType = "struct*"
    Else
        $sRadiusDllType = "float*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMinEnclosingCircle", $sPointsDllType, $points, $sCenterDllType, $center, $sRadiusDllType, $radius), "cveMinEnclosingCircle", @error)
EndFunc   ;==>_cveMinEnclosingCircle

Func _cveMinEnclosingCircleTyped($typeOfPoints, $points, $center, $radius)

    Local $iArrPoints, $vectorPoints, $iArrPointsSize
    Local $bPointsIsArray = IsArray($points)
    Local $bPointsCreate = IsDllStruct($points) And $typeOfPoints == "Scalar"

    If $typeOfPoints == Default Then
        $iArrPoints = $points
    ElseIf $bPointsIsArray Then
        $vectorPoints = Call("_VectorOf" & $typeOfPoints & "Create")

        $iArrPointsSize = UBound($points)
        For $i = 0 To $iArrPointsSize - 1
            Call("_VectorOf" & $typeOfPoints & "Push", $vectorPoints, $points[$i])
        Next

        $iArrPoints = Call("_cveInputArrayFromVectorOf" & $typeOfPoints, $vectorPoints)
    Else
        If $bPointsCreate Then
            $points = Call("_cve" & $typeOfPoints & "Create", $points)
        EndIf
        $iArrPoints = Call("_cveInputArrayFrom" & $typeOfPoints, $points)
    EndIf

    _cveMinEnclosingCircle($iArrPoints, $center, $radius)

    If $bPointsIsArray Then
        Call("_VectorOf" & $typeOfPoints & "Release", $vectorPoints)
    EndIf

    If $typeOfPoints <> Default Then
        _cveInputArrayRelease($iArrPoints)
        If $bPointsCreate Then
            Call("_cve" & $typeOfPoints & "Release", $points)
        EndIf
    EndIf
EndFunc   ;==>_cveMinEnclosingCircleTyped

Func _cveMinEnclosingCircleMat($points, $center, $radius)
    ; cveMinEnclosingCircle using cv::Mat instead of _*Array
    _cveMinEnclosingCircleTyped("Mat", $points, $center, $radius)
EndFunc   ;==>_cveMinEnclosingCircleMat

Func _cveMatchShapes($contour1, $contour2, $method, $parameter)
    ; CVAPI(double) cveMatchShapes(cv::_InputArray* contour1, cv::_InputArray* contour2, int method, double parameter);

    Local $sContour1DllType
    If IsDllStruct($contour1) Then
        $sContour1DllType = "struct*"
    Else
        $sContour1DllType = "ptr"
    EndIf

    Local $sContour2DllType
    If IsDllStruct($contour2) Then
        $sContour2DllType = "struct*"
    Else
        $sContour2DllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveMatchShapes", $sContour1DllType, $contour1, $sContour2DllType, $contour2, "int", $method, "double", $parameter), "cveMatchShapes", @error)
EndFunc   ;==>_cveMatchShapes

Func _cveMatchShapesTyped($typeOfContour1, $contour1, $typeOfContour2, $contour2, $method, $parameter)

    Local $iArrContour1, $vectorContour1, $iArrContour1Size
    Local $bContour1IsArray = IsArray($contour1)
    Local $bContour1Create = IsDllStruct($contour1) And $typeOfContour1 == "Scalar"

    If $typeOfContour1 == Default Then
        $iArrContour1 = $contour1
    ElseIf $bContour1IsArray Then
        $vectorContour1 = Call("_VectorOf" & $typeOfContour1 & "Create")

        $iArrContour1Size = UBound($contour1)
        For $i = 0 To $iArrContour1Size - 1
            Call("_VectorOf" & $typeOfContour1 & "Push", $vectorContour1, $contour1[$i])
        Next

        $iArrContour1 = Call("_cveInputArrayFromVectorOf" & $typeOfContour1, $vectorContour1)
    Else
        If $bContour1Create Then
            $contour1 = Call("_cve" & $typeOfContour1 & "Create", $contour1)
        EndIf
        $iArrContour1 = Call("_cveInputArrayFrom" & $typeOfContour1, $contour1)
    EndIf

    Local $iArrContour2, $vectorContour2, $iArrContour2Size
    Local $bContour2IsArray = IsArray($contour2)
    Local $bContour2Create = IsDllStruct($contour2) And $typeOfContour2 == "Scalar"

    If $typeOfContour2 == Default Then
        $iArrContour2 = $contour2
    ElseIf $bContour2IsArray Then
        $vectorContour2 = Call("_VectorOf" & $typeOfContour2 & "Create")

        $iArrContour2Size = UBound($contour2)
        For $i = 0 To $iArrContour2Size - 1
            Call("_VectorOf" & $typeOfContour2 & "Push", $vectorContour2, $contour2[$i])
        Next

        $iArrContour2 = Call("_cveInputArrayFromVectorOf" & $typeOfContour2, $vectorContour2)
    Else
        If $bContour2Create Then
            $contour2 = Call("_cve" & $typeOfContour2 & "Create", $contour2)
        EndIf
        $iArrContour2 = Call("_cveInputArrayFrom" & $typeOfContour2, $contour2)
    EndIf

    Local $retval = _cveMatchShapes($iArrContour1, $iArrContour2, $method, $parameter)

    If $bContour2IsArray Then
        Call("_VectorOf" & $typeOfContour2 & "Release", $vectorContour2)
    EndIf

    If $typeOfContour2 <> Default Then
        _cveInputArrayRelease($iArrContour2)
        If $bContour2Create Then
            Call("_cve" & $typeOfContour2 & "Release", $contour2)
        EndIf
    EndIf

    If $bContour1IsArray Then
        Call("_VectorOf" & $typeOfContour1 & "Release", $vectorContour1)
    EndIf

    If $typeOfContour1 <> Default Then
        _cveInputArrayRelease($iArrContour1)
        If $bContour1Create Then
            Call("_cve" & $typeOfContour1 & "Release", $contour1)
        EndIf
    EndIf

    Return $retval
EndFunc   ;==>_cveMatchShapesTyped

Func _cveMatchShapesMat($contour1, $contour2, $method, $parameter)
    ; cveMatchShapes using cv::Mat instead of _*Array
    Local $retval = _cveMatchShapesTyped("Mat", $contour1, "Mat", $contour2, $method, $parameter)

    Return $retval
EndFunc   ;==>_cveMatchShapesMat

Func _cveFitEllipse($points, $box)
    ; CVAPI(void) cveFitEllipse(cv::_InputArray* points, CvBox2D* box);

    Local $sPointsDllType
    If IsDllStruct($points) Then
        $sPointsDllType = "struct*"
    Else
        $sPointsDllType = "ptr"
    EndIf

    Local $sBoxDllType
    If IsDllStruct($box) Then
        $sBoxDllType = "struct*"
    Else
        $sBoxDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFitEllipse", $sPointsDllType, $points, $sBoxDllType, $box), "cveFitEllipse", @error)
EndFunc   ;==>_cveFitEllipse

Func _cveFitEllipseTyped($typeOfPoints, $points, $box)

    Local $iArrPoints, $vectorPoints, $iArrPointsSize
    Local $bPointsIsArray = IsArray($points)
    Local $bPointsCreate = IsDllStruct($points) And $typeOfPoints == "Scalar"

    If $typeOfPoints == Default Then
        $iArrPoints = $points
    ElseIf $bPointsIsArray Then
        $vectorPoints = Call("_VectorOf" & $typeOfPoints & "Create")

        $iArrPointsSize = UBound($points)
        For $i = 0 To $iArrPointsSize - 1
            Call("_VectorOf" & $typeOfPoints & "Push", $vectorPoints, $points[$i])
        Next

        $iArrPoints = Call("_cveInputArrayFromVectorOf" & $typeOfPoints, $vectorPoints)
    Else
        If $bPointsCreate Then
            $points = Call("_cve" & $typeOfPoints & "Create", $points)
        EndIf
        $iArrPoints = Call("_cveInputArrayFrom" & $typeOfPoints, $points)
    EndIf

    _cveFitEllipse($iArrPoints, $box)

    If $bPointsIsArray Then
        Call("_VectorOf" & $typeOfPoints & "Release", $vectorPoints)
    EndIf

    If $typeOfPoints <> Default Then
        _cveInputArrayRelease($iArrPoints)
        If $bPointsCreate Then
            Call("_cve" & $typeOfPoints & "Release", $points)
        EndIf
    EndIf
EndFunc   ;==>_cveFitEllipseTyped

Func _cveFitEllipseMat($points, $box)
    ; cveFitEllipse using cv::Mat instead of _*Array
    _cveFitEllipseTyped("Mat", $points, $box)
EndFunc   ;==>_cveFitEllipseMat

Func _cveFitEllipseAMS($points, $box)
    ; CVAPI(void) cveFitEllipseAMS(cv::_InputArray* points, CvBox2D* box);

    Local $sPointsDllType
    If IsDllStruct($points) Then
        $sPointsDllType = "struct*"
    Else
        $sPointsDllType = "ptr"
    EndIf

    Local $sBoxDllType
    If IsDllStruct($box) Then
        $sBoxDllType = "struct*"
    Else
        $sBoxDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFitEllipseAMS", $sPointsDllType, $points, $sBoxDllType, $box), "cveFitEllipseAMS", @error)
EndFunc   ;==>_cveFitEllipseAMS

Func _cveFitEllipseAMSTyped($typeOfPoints, $points, $box)

    Local $iArrPoints, $vectorPoints, $iArrPointsSize
    Local $bPointsIsArray = IsArray($points)
    Local $bPointsCreate = IsDllStruct($points) And $typeOfPoints == "Scalar"

    If $typeOfPoints == Default Then
        $iArrPoints = $points
    ElseIf $bPointsIsArray Then
        $vectorPoints = Call("_VectorOf" & $typeOfPoints & "Create")

        $iArrPointsSize = UBound($points)
        For $i = 0 To $iArrPointsSize - 1
            Call("_VectorOf" & $typeOfPoints & "Push", $vectorPoints, $points[$i])
        Next

        $iArrPoints = Call("_cveInputArrayFromVectorOf" & $typeOfPoints, $vectorPoints)
    Else
        If $bPointsCreate Then
            $points = Call("_cve" & $typeOfPoints & "Create", $points)
        EndIf
        $iArrPoints = Call("_cveInputArrayFrom" & $typeOfPoints, $points)
    EndIf

    _cveFitEllipseAMS($iArrPoints, $box)

    If $bPointsIsArray Then
        Call("_VectorOf" & $typeOfPoints & "Release", $vectorPoints)
    EndIf

    If $typeOfPoints <> Default Then
        _cveInputArrayRelease($iArrPoints)
        If $bPointsCreate Then
            Call("_cve" & $typeOfPoints & "Release", $points)
        EndIf
    EndIf
EndFunc   ;==>_cveFitEllipseAMSTyped

Func _cveFitEllipseAMSMat($points, $box)
    ; cveFitEllipseAMS using cv::Mat instead of _*Array
    _cveFitEllipseAMSTyped("Mat", $points, $box)
EndFunc   ;==>_cveFitEllipseAMSMat

Func _cveFitEllipseDirect($points, $box)
    ; CVAPI(void) cveFitEllipseDirect(cv::_InputArray* points, CvBox2D* box);

    Local $sPointsDllType
    If IsDllStruct($points) Then
        $sPointsDllType = "struct*"
    Else
        $sPointsDllType = "ptr"
    EndIf

    Local $sBoxDllType
    If IsDllStruct($box) Then
        $sBoxDllType = "struct*"
    Else
        $sBoxDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFitEllipseDirect", $sPointsDllType, $points, $sBoxDllType, $box), "cveFitEllipseDirect", @error)
EndFunc   ;==>_cveFitEllipseDirect

Func _cveFitEllipseDirectTyped($typeOfPoints, $points, $box)

    Local $iArrPoints, $vectorPoints, $iArrPointsSize
    Local $bPointsIsArray = IsArray($points)
    Local $bPointsCreate = IsDllStruct($points) And $typeOfPoints == "Scalar"

    If $typeOfPoints == Default Then
        $iArrPoints = $points
    ElseIf $bPointsIsArray Then
        $vectorPoints = Call("_VectorOf" & $typeOfPoints & "Create")

        $iArrPointsSize = UBound($points)
        For $i = 0 To $iArrPointsSize - 1
            Call("_VectorOf" & $typeOfPoints & "Push", $vectorPoints, $points[$i])
        Next

        $iArrPoints = Call("_cveInputArrayFromVectorOf" & $typeOfPoints, $vectorPoints)
    Else
        If $bPointsCreate Then
            $points = Call("_cve" & $typeOfPoints & "Create", $points)
        EndIf
        $iArrPoints = Call("_cveInputArrayFrom" & $typeOfPoints, $points)
    EndIf

    _cveFitEllipseDirect($iArrPoints, $box)

    If $bPointsIsArray Then
        Call("_VectorOf" & $typeOfPoints & "Release", $vectorPoints)
    EndIf

    If $typeOfPoints <> Default Then
        _cveInputArrayRelease($iArrPoints)
        If $bPointsCreate Then
            Call("_cve" & $typeOfPoints & "Release", $points)
        EndIf
    EndIf
EndFunc   ;==>_cveFitEllipseDirectTyped

Func _cveFitEllipseDirectMat($points, $box)
    ; cveFitEllipseDirect using cv::Mat instead of _*Array
    _cveFitEllipseDirectTyped("Mat", $points, $box)
EndFunc   ;==>_cveFitEllipseDirectMat

Func _cveFitLine($points, $line, $distType, $param, $reps, $aeps)
    ; CVAPI(void) cveFitLine(cv::_InputArray* points, cv::_OutputArray* line, int distType, double param, double reps, double aeps);

    Local $sPointsDllType
    If IsDllStruct($points) Then
        $sPointsDllType = "struct*"
    Else
        $sPointsDllType = "ptr"
    EndIf

    Local $sLineDllType
    If IsDllStruct($line) Then
        $sLineDllType = "struct*"
    Else
        $sLineDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFitLine", $sPointsDllType, $points, $sLineDllType, $line, "int", $distType, "double", $param, "double", $reps, "double", $aeps), "cveFitLine", @error)
EndFunc   ;==>_cveFitLine

Func _cveFitLineTyped($typeOfPoints, $points, $typeOfLine, $line, $distType, $param, $reps, $aeps)

    Local $iArrPoints, $vectorPoints, $iArrPointsSize
    Local $bPointsIsArray = IsArray($points)
    Local $bPointsCreate = IsDllStruct($points) And $typeOfPoints == "Scalar"

    If $typeOfPoints == Default Then
        $iArrPoints = $points
    ElseIf $bPointsIsArray Then
        $vectorPoints = Call("_VectorOf" & $typeOfPoints & "Create")

        $iArrPointsSize = UBound($points)
        For $i = 0 To $iArrPointsSize - 1
            Call("_VectorOf" & $typeOfPoints & "Push", $vectorPoints, $points[$i])
        Next

        $iArrPoints = Call("_cveInputArrayFromVectorOf" & $typeOfPoints, $vectorPoints)
    Else
        If $bPointsCreate Then
            $points = Call("_cve" & $typeOfPoints & "Create", $points)
        EndIf
        $iArrPoints = Call("_cveInputArrayFrom" & $typeOfPoints, $points)
    EndIf

    Local $oArrLine, $vectorLine, $iArrLineSize
    Local $bLineIsArray = IsArray($line)
    Local $bLineCreate = IsDllStruct($line) And $typeOfLine == "Scalar"

    If $typeOfLine == Default Then
        $oArrLine = $line
    ElseIf $bLineIsArray Then
        $vectorLine = Call("_VectorOf" & $typeOfLine & "Create")

        $iArrLineSize = UBound($line)
        For $i = 0 To $iArrLineSize - 1
            Call("_VectorOf" & $typeOfLine & "Push", $vectorLine, $line[$i])
        Next

        $oArrLine = Call("_cveOutputArrayFromVectorOf" & $typeOfLine, $vectorLine)
    Else
        If $bLineCreate Then
            $line = Call("_cve" & $typeOfLine & "Create", $line)
        EndIf
        $oArrLine = Call("_cveOutputArrayFrom" & $typeOfLine, $line)
    EndIf

    _cveFitLine($iArrPoints, $oArrLine, $distType, $param, $reps, $aeps)

    If $bLineIsArray Then
        Call("_VectorOf" & $typeOfLine & "Release", $vectorLine)
    EndIf

    If $typeOfLine <> Default Then
        _cveOutputArrayRelease($oArrLine)
        If $bLineCreate Then
            Call("_cve" & $typeOfLine & "Release", $line)
        EndIf
    EndIf

    If $bPointsIsArray Then
        Call("_VectorOf" & $typeOfPoints & "Release", $vectorPoints)
    EndIf

    If $typeOfPoints <> Default Then
        _cveInputArrayRelease($iArrPoints)
        If $bPointsCreate Then
            Call("_cve" & $typeOfPoints & "Release", $points)
        EndIf
    EndIf
EndFunc   ;==>_cveFitLineTyped

Func _cveFitLineMat($points, $line, $distType, $param, $reps, $aeps)
    ; cveFitLine using cv::Mat instead of _*Array
    _cveFitLineTyped("Mat", $points, "Mat", $line, $distType, $param, $reps, $aeps)
EndFunc   ;==>_cveFitLineMat

Func _cveRotatedRectangleIntersection($rect1, $rect2, $intersectingRegion)
    ; CVAPI(int) cveRotatedRectangleIntersection(CvBox2D* rect1, CvBox2D* rect2, cv::_OutputArray* intersectingRegion);

    Local $sRect1DllType
    If IsDllStruct($rect1) Then
        $sRect1DllType = "struct*"
    Else
        $sRect1DllType = "ptr"
    EndIf

    Local $sRect2DllType
    If IsDllStruct($rect2) Then
        $sRect2DllType = "struct*"
    Else
        $sRect2DllType = "ptr"
    EndIf

    Local $sIntersectingRegionDllType
    If IsDllStruct($intersectingRegion) Then
        $sIntersectingRegionDllType = "struct*"
    Else
        $sIntersectingRegionDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveRotatedRectangleIntersection", $sRect1DllType, $rect1, $sRect2DllType, $rect2, $sIntersectingRegionDllType, $intersectingRegion), "cveRotatedRectangleIntersection", @error)
EndFunc   ;==>_cveRotatedRectangleIntersection

Func _cveRotatedRectangleIntersectionTyped($rect1, $rect2, $typeOfIntersectingRegion, $intersectingRegion)

    Local $oArrIntersectingRegion, $vectorIntersectingRegion, $iArrIntersectingRegionSize
    Local $bIntersectingRegionIsArray = IsArray($intersectingRegion)
    Local $bIntersectingRegionCreate = IsDllStruct($intersectingRegion) And $typeOfIntersectingRegion == "Scalar"

    If $typeOfIntersectingRegion == Default Then
        $oArrIntersectingRegion = $intersectingRegion
    ElseIf $bIntersectingRegionIsArray Then
        $vectorIntersectingRegion = Call("_VectorOf" & $typeOfIntersectingRegion & "Create")

        $iArrIntersectingRegionSize = UBound($intersectingRegion)
        For $i = 0 To $iArrIntersectingRegionSize - 1
            Call("_VectorOf" & $typeOfIntersectingRegion & "Push", $vectorIntersectingRegion, $intersectingRegion[$i])
        Next

        $oArrIntersectingRegion = Call("_cveOutputArrayFromVectorOf" & $typeOfIntersectingRegion, $vectorIntersectingRegion)
    Else
        If $bIntersectingRegionCreate Then
            $intersectingRegion = Call("_cve" & $typeOfIntersectingRegion & "Create", $intersectingRegion)
        EndIf
        $oArrIntersectingRegion = Call("_cveOutputArrayFrom" & $typeOfIntersectingRegion, $intersectingRegion)
    EndIf

    Local $retval = _cveRotatedRectangleIntersection($rect1, $rect2, $oArrIntersectingRegion)

    If $bIntersectingRegionIsArray Then
        Call("_VectorOf" & $typeOfIntersectingRegion & "Release", $vectorIntersectingRegion)
    EndIf

    If $typeOfIntersectingRegion <> Default Then
        _cveOutputArrayRelease($oArrIntersectingRegion)
        If $bIntersectingRegionCreate Then
            Call("_cve" & $typeOfIntersectingRegion & "Release", $intersectingRegion)
        EndIf
    EndIf

    Return $retval
EndFunc   ;==>_cveRotatedRectangleIntersectionTyped

Func _cveRotatedRectangleIntersectionMat($rect1, $rect2, $intersectingRegion)
    ; cveRotatedRectangleIntersection using cv::Mat instead of _*Array
    Local $retval = _cveRotatedRectangleIntersectionTyped($rect1, $rect2, "Mat", $intersectingRegion)

    Return $retval
EndFunc   ;==>_cveRotatedRectangleIntersectionMat

Func _cveDrawContours($image, $contours, $contourIdx, $color, $thickness = 1, $lineType = $CV_LINE_8, $hierarchy = _cveNoArray(), $maxLevel = $CV_INT_MAX, $offset = _cvPoint())
    ; CVAPI(void) cveDrawContours(cv::_InputOutputArray* image, cv::_InputArray* contours, int contourIdx, CvScalar* color, int thickness, int lineType, cv::_InputArray* hierarchy, int maxLevel, CvPoint* offset);

    Local $sImageDllType
    If IsDllStruct($image) Then
        $sImageDllType = "struct*"
    Else
        $sImageDllType = "ptr"
    EndIf

    Local $sContoursDllType
    If IsDllStruct($contours) Then
        $sContoursDllType = "struct*"
    Else
        $sContoursDllType = "ptr"
    EndIf

    Local $sColorDllType
    If IsDllStruct($color) Then
        $sColorDllType = "struct*"
    Else
        $sColorDllType = "ptr"
    EndIf

    Local $sHierarchyDllType
    If IsDllStruct($hierarchy) Then
        $sHierarchyDllType = "struct*"
    Else
        $sHierarchyDllType = "ptr"
    EndIf

    Local $sOffsetDllType
    If IsDllStruct($offset) Then
        $sOffsetDllType = "struct*"
    Else
        $sOffsetDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDrawContours", $sImageDllType, $image, $sContoursDllType, $contours, "int", $contourIdx, $sColorDllType, $color, "int", $thickness, "int", $lineType, $sHierarchyDllType, $hierarchy, "int", $maxLevel, $sOffsetDllType, $offset), "cveDrawContours", @error)
EndFunc   ;==>_cveDrawContours

Func _cveDrawContoursTyped($typeOfImage, $image, $typeOfContours, $contours, $contourIdx, $color, $thickness = 1, $lineType = $CV_LINE_8, $typeOfHierarchy = Default, $hierarchy = _cveNoArray(), $maxLevel = $CV_INT_MAX, $offset = _cvPoint())

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

    Local $iArrContours, $vectorContours, $iArrContoursSize
    Local $bContoursIsArray = IsArray($contours)
    Local $bContoursCreate = IsDllStruct($contours) And $typeOfContours == "Scalar"

    If $typeOfContours == Default Then
        $iArrContours = $contours
    ElseIf $bContoursIsArray Then
        $vectorContours = Call("_VectorOf" & $typeOfContours & "Create")

        $iArrContoursSize = UBound($contours)
        For $i = 0 To $iArrContoursSize - 1
            Call("_VectorOf" & $typeOfContours & "Push", $vectorContours, $contours[$i])
        Next

        $iArrContours = Call("_cveInputArrayFromVectorOf" & $typeOfContours, $vectorContours)
    Else
        If $bContoursCreate Then
            $contours = Call("_cve" & $typeOfContours & "Create", $contours)
        EndIf
        $iArrContours = Call("_cveInputArrayFrom" & $typeOfContours, $contours)
    EndIf

    Local $iArrHierarchy, $vectorHierarchy, $iArrHierarchySize
    Local $bHierarchyIsArray = IsArray($hierarchy)
    Local $bHierarchyCreate = IsDllStruct($hierarchy) And $typeOfHierarchy == "Scalar"

    If $typeOfHierarchy == Default Then
        $iArrHierarchy = $hierarchy
    ElseIf $bHierarchyIsArray Then
        $vectorHierarchy = Call("_VectorOf" & $typeOfHierarchy & "Create")

        $iArrHierarchySize = UBound($hierarchy)
        For $i = 0 To $iArrHierarchySize - 1
            Call("_VectorOf" & $typeOfHierarchy & "Push", $vectorHierarchy, $hierarchy[$i])
        Next

        $iArrHierarchy = Call("_cveInputArrayFromVectorOf" & $typeOfHierarchy, $vectorHierarchy)
    Else
        If $bHierarchyCreate Then
            $hierarchy = Call("_cve" & $typeOfHierarchy & "Create", $hierarchy)
        EndIf
        $iArrHierarchy = Call("_cveInputArrayFrom" & $typeOfHierarchy, $hierarchy)
    EndIf

    _cveDrawContours($ioArrImage, $iArrContours, $contourIdx, $color, $thickness, $lineType, $iArrHierarchy, $maxLevel, $offset)

    If $bHierarchyIsArray Then
        Call("_VectorOf" & $typeOfHierarchy & "Release", $vectorHierarchy)
    EndIf

    If $typeOfHierarchy <> Default Then
        _cveInputArrayRelease($iArrHierarchy)
        If $bHierarchyCreate Then
            Call("_cve" & $typeOfHierarchy & "Release", $hierarchy)
        EndIf
    EndIf

    If $bContoursIsArray Then
        Call("_VectorOf" & $typeOfContours & "Release", $vectorContours)
    EndIf

    If $typeOfContours <> Default Then
        _cveInputArrayRelease($iArrContours)
        If $bContoursCreate Then
            Call("_cve" & $typeOfContours & "Release", $contours)
        EndIf
    EndIf

    If $bImageIsArray Then
        Call("_VectorOf" & $typeOfImage & "Release", $vectorImage)
    EndIf

    If $typeOfImage <> Default Then
        _cveInputOutputArrayRelease($ioArrImage)
        If $bImageCreate Then
            Call("_cve" & $typeOfImage & "Release", $image)
        EndIf
    EndIf
EndFunc   ;==>_cveDrawContoursTyped

Func _cveDrawContoursMat($image, $contours, $contourIdx, $color, $thickness = 1, $lineType = $CV_LINE_8, $hierarchy = _cveNoArrayMat(), $maxLevel = $CV_INT_MAX, $offset = _cvPoint())
    ; cveDrawContours using cv::Mat instead of _*Array
    _cveDrawContoursTyped("Mat", $image, "Mat", $contours, $contourIdx, $color, $thickness, $lineType, "Mat", $hierarchy, $maxLevel, $offset)
EndFunc   ;==>_cveDrawContoursMat

Func _cveApproxPolyDP($curve, $approxCurve, $epsilon, $closed)
    ; CVAPI(void) cveApproxPolyDP(cv::_InputArray* curve, cv::_OutputArray* approxCurve, double epsilon, bool closed);

    Local $sCurveDllType
    If IsDllStruct($curve) Then
        $sCurveDllType = "struct*"
    Else
        $sCurveDllType = "ptr"
    EndIf

    Local $sApproxCurveDllType
    If IsDllStruct($approxCurve) Then
        $sApproxCurveDllType = "struct*"
    Else
        $sApproxCurveDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveApproxPolyDP", $sCurveDllType, $curve, $sApproxCurveDllType, $approxCurve, "double", $epsilon, "boolean", $closed), "cveApproxPolyDP", @error)
EndFunc   ;==>_cveApproxPolyDP

Func _cveApproxPolyDPTyped($typeOfCurve, $curve, $typeOfApproxCurve, $approxCurve, $epsilon, $closed)

    Local $iArrCurve, $vectorCurve, $iArrCurveSize
    Local $bCurveIsArray = IsArray($curve)
    Local $bCurveCreate = IsDllStruct($curve) And $typeOfCurve == "Scalar"

    If $typeOfCurve == Default Then
        $iArrCurve = $curve
    ElseIf $bCurveIsArray Then
        $vectorCurve = Call("_VectorOf" & $typeOfCurve & "Create")

        $iArrCurveSize = UBound($curve)
        For $i = 0 To $iArrCurveSize - 1
            Call("_VectorOf" & $typeOfCurve & "Push", $vectorCurve, $curve[$i])
        Next

        $iArrCurve = Call("_cveInputArrayFromVectorOf" & $typeOfCurve, $vectorCurve)
    Else
        If $bCurveCreate Then
            $curve = Call("_cve" & $typeOfCurve & "Create", $curve)
        EndIf
        $iArrCurve = Call("_cveInputArrayFrom" & $typeOfCurve, $curve)
    EndIf

    Local $oArrApproxCurve, $vectorApproxCurve, $iArrApproxCurveSize
    Local $bApproxCurveIsArray = IsArray($approxCurve)
    Local $bApproxCurveCreate = IsDllStruct($approxCurve) And $typeOfApproxCurve == "Scalar"

    If $typeOfApproxCurve == Default Then
        $oArrApproxCurve = $approxCurve
    ElseIf $bApproxCurveIsArray Then
        $vectorApproxCurve = Call("_VectorOf" & $typeOfApproxCurve & "Create")

        $iArrApproxCurveSize = UBound($approxCurve)
        For $i = 0 To $iArrApproxCurveSize - 1
            Call("_VectorOf" & $typeOfApproxCurve & "Push", $vectorApproxCurve, $approxCurve[$i])
        Next

        $oArrApproxCurve = Call("_cveOutputArrayFromVectorOf" & $typeOfApproxCurve, $vectorApproxCurve)
    Else
        If $bApproxCurveCreate Then
            $approxCurve = Call("_cve" & $typeOfApproxCurve & "Create", $approxCurve)
        EndIf
        $oArrApproxCurve = Call("_cveOutputArrayFrom" & $typeOfApproxCurve, $approxCurve)
    EndIf

    _cveApproxPolyDP($iArrCurve, $oArrApproxCurve, $epsilon, $closed)

    If $bApproxCurveIsArray Then
        Call("_VectorOf" & $typeOfApproxCurve & "Release", $vectorApproxCurve)
    EndIf

    If $typeOfApproxCurve <> Default Then
        _cveOutputArrayRelease($oArrApproxCurve)
        If $bApproxCurveCreate Then
            Call("_cve" & $typeOfApproxCurve & "Release", $approxCurve)
        EndIf
    EndIf

    If $bCurveIsArray Then
        Call("_VectorOf" & $typeOfCurve & "Release", $vectorCurve)
    EndIf

    If $typeOfCurve <> Default Then
        _cveInputArrayRelease($iArrCurve)
        If $bCurveCreate Then
            Call("_cve" & $typeOfCurve & "Release", $curve)
        EndIf
    EndIf
EndFunc   ;==>_cveApproxPolyDPTyped

Func _cveApproxPolyDPMat($curve, $approxCurve, $epsilon, $closed)
    ; cveApproxPolyDP using cv::Mat instead of _*Array
    _cveApproxPolyDPTyped("Mat", $curve, "Mat", $approxCurve, $epsilon, $closed)
EndFunc   ;==>_cveApproxPolyDPMat

Func _cveConvexHull($points, $hull, $clockwise = false, $returnPoints = true)
    ; CVAPI(void) cveConvexHull(cv::_InputArray* points, cv::_OutputArray* hull, bool clockwise, bool returnPoints);

    Local $sPointsDllType
    If IsDllStruct($points) Then
        $sPointsDllType = "struct*"
    Else
        $sPointsDllType = "ptr"
    EndIf

    Local $sHullDllType
    If IsDllStruct($hull) Then
        $sHullDllType = "struct*"
    Else
        $sHullDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveConvexHull", $sPointsDllType, $points, $sHullDllType, $hull, "boolean", $clockwise, "boolean", $returnPoints), "cveConvexHull", @error)
EndFunc   ;==>_cveConvexHull

Func _cveConvexHullTyped($typeOfPoints, $points, $typeOfHull, $hull, $clockwise = false, $returnPoints = true)

    Local $iArrPoints, $vectorPoints, $iArrPointsSize
    Local $bPointsIsArray = IsArray($points)
    Local $bPointsCreate = IsDllStruct($points) And $typeOfPoints == "Scalar"

    If $typeOfPoints == Default Then
        $iArrPoints = $points
    ElseIf $bPointsIsArray Then
        $vectorPoints = Call("_VectorOf" & $typeOfPoints & "Create")

        $iArrPointsSize = UBound($points)
        For $i = 0 To $iArrPointsSize - 1
            Call("_VectorOf" & $typeOfPoints & "Push", $vectorPoints, $points[$i])
        Next

        $iArrPoints = Call("_cveInputArrayFromVectorOf" & $typeOfPoints, $vectorPoints)
    Else
        If $bPointsCreate Then
            $points = Call("_cve" & $typeOfPoints & "Create", $points)
        EndIf
        $iArrPoints = Call("_cveInputArrayFrom" & $typeOfPoints, $points)
    EndIf

    Local $oArrHull, $vectorHull, $iArrHullSize
    Local $bHullIsArray = IsArray($hull)
    Local $bHullCreate = IsDllStruct($hull) And $typeOfHull == "Scalar"

    If $typeOfHull == Default Then
        $oArrHull = $hull
    ElseIf $bHullIsArray Then
        $vectorHull = Call("_VectorOf" & $typeOfHull & "Create")

        $iArrHullSize = UBound($hull)
        For $i = 0 To $iArrHullSize - 1
            Call("_VectorOf" & $typeOfHull & "Push", $vectorHull, $hull[$i])
        Next

        $oArrHull = Call("_cveOutputArrayFromVectorOf" & $typeOfHull, $vectorHull)
    Else
        If $bHullCreate Then
            $hull = Call("_cve" & $typeOfHull & "Create", $hull)
        EndIf
        $oArrHull = Call("_cveOutputArrayFrom" & $typeOfHull, $hull)
    EndIf

    _cveConvexHull($iArrPoints, $oArrHull, $clockwise, $returnPoints)

    If $bHullIsArray Then
        Call("_VectorOf" & $typeOfHull & "Release", $vectorHull)
    EndIf

    If $typeOfHull <> Default Then
        _cveOutputArrayRelease($oArrHull)
        If $bHullCreate Then
            Call("_cve" & $typeOfHull & "Release", $hull)
        EndIf
    EndIf

    If $bPointsIsArray Then
        Call("_VectorOf" & $typeOfPoints & "Release", $vectorPoints)
    EndIf

    If $typeOfPoints <> Default Then
        _cveInputArrayRelease($iArrPoints)
        If $bPointsCreate Then
            Call("_cve" & $typeOfPoints & "Release", $points)
        EndIf
    EndIf
EndFunc   ;==>_cveConvexHullTyped

Func _cveConvexHullMat($points, $hull, $clockwise = false, $returnPoints = true)
    ; cveConvexHull using cv::Mat instead of _*Array
    _cveConvexHullTyped("Mat", $points, "Mat", $hull, $clockwise, $returnPoints)
EndFunc   ;==>_cveConvexHullMat

Func _cveConvexityDefects($contour, $convexhull, $convexityDefects)
    ; CVAPI(void) cveConvexityDefects(cv::_InputArray* contour, cv::_InputArray* convexhull, cv::_OutputArray* convexityDefects);

    Local $sContourDllType
    If IsDllStruct($contour) Then
        $sContourDllType = "struct*"
    Else
        $sContourDllType = "ptr"
    EndIf

    Local $sConvexhullDllType
    If IsDllStruct($convexhull) Then
        $sConvexhullDllType = "struct*"
    Else
        $sConvexhullDllType = "ptr"
    EndIf

    Local $sConvexityDefectsDllType
    If IsDllStruct($convexityDefects) Then
        $sConvexityDefectsDllType = "struct*"
    Else
        $sConvexityDefectsDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveConvexityDefects", $sContourDllType, $contour, $sConvexhullDllType, $convexhull, $sConvexityDefectsDllType, $convexityDefects), "cveConvexityDefects", @error)
EndFunc   ;==>_cveConvexityDefects

Func _cveConvexityDefectsTyped($typeOfContour, $contour, $typeOfConvexhull, $convexhull, $typeOfConvexityDefects, $convexityDefects)

    Local $iArrContour, $vectorContour, $iArrContourSize
    Local $bContourIsArray = IsArray($contour)
    Local $bContourCreate = IsDllStruct($contour) And $typeOfContour == "Scalar"

    If $typeOfContour == Default Then
        $iArrContour = $contour
    ElseIf $bContourIsArray Then
        $vectorContour = Call("_VectorOf" & $typeOfContour & "Create")

        $iArrContourSize = UBound($contour)
        For $i = 0 To $iArrContourSize - 1
            Call("_VectorOf" & $typeOfContour & "Push", $vectorContour, $contour[$i])
        Next

        $iArrContour = Call("_cveInputArrayFromVectorOf" & $typeOfContour, $vectorContour)
    Else
        If $bContourCreate Then
            $contour = Call("_cve" & $typeOfContour & "Create", $contour)
        EndIf
        $iArrContour = Call("_cveInputArrayFrom" & $typeOfContour, $contour)
    EndIf

    Local $iArrConvexhull, $vectorConvexhull, $iArrConvexhullSize
    Local $bConvexhullIsArray = IsArray($convexhull)
    Local $bConvexhullCreate = IsDllStruct($convexhull) And $typeOfConvexhull == "Scalar"

    If $typeOfConvexhull == Default Then
        $iArrConvexhull = $convexhull
    ElseIf $bConvexhullIsArray Then
        $vectorConvexhull = Call("_VectorOf" & $typeOfConvexhull & "Create")

        $iArrConvexhullSize = UBound($convexhull)
        For $i = 0 To $iArrConvexhullSize - 1
            Call("_VectorOf" & $typeOfConvexhull & "Push", $vectorConvexhull, $convexhull[$i])
        Next

        $iArrConvexhull = Call("_cveInputArrayFromVectorOf" & $typeOfConvexhull, $vectorConvexhull)
    Else
        If $bConvexhullCreate Then
            $convexhull = Call("_cve" & $typeOfConvexhull & "Create", $convexhull)
        EndIf
        $iArrConvexhull = Call("_cveInputArrayFrom" & $typeOfConvexhull, $convexhull)
    EndIf

    Local $oArrConvexityDefects, $vectorConvexityDefects, $iArrConvexityDefectsSize
    Local $bConvexityDefectsIsArray = IsArray($convexityDefects)
    Local $bConvexityDefectsCreate = IsDllStruct($convexityDefects) And $typeOfConvexityDefects == "Scalar"

    If $typeOfConvexityDefects == Default Then
        $oArrConvexityDefects = $convexityDefects
    ElseIf $bConvexityDefectsIsArray Then
        $vectorConvexityDefects = Call("_VectorOf" & $typeOfConvexityDefects & "Create")

        $iArrConvexityDefectsSize = UBound($convexityDefects)
        For $i = 0 To $iArrConvexityDefectsSize - 1
            Call("_VectorOf" & $typeOfConvexityDefects & "Push", $vectorConvexityDefects, $convexityDefects[$i])
        Next

        $oArrConvexityDefects = Call("_cveOutputArrayFromVectorOf" & $typeOfConvexityDefects, $vectorConvexityDefects)
    Else
        If $bConvexityDefectsCreate Then
            $convexityDefects = Call("_cve" & $typeOfConvexityDefects & "Create", $convexityDefects)
        EndIf
        $oArrConvexityDefects = Call("_cveOutputArrayFrom" & $typeOfConvexityDefects, $convexityDefects)
    EndIf

    _cveConvexityDefects($iArrContour, $iArrConvexhull, $oArrConvexityDefects)

    If $bConvexityDefectsIsArray Then
        Call("_VectorOf" & $typeOfConvexityDefects & "Release", $vectorConvexityDefects)
    EndIf

    If $typeOfConvexityDefects <> Default Then
        _cveOutputArrayRelease($oArrConvexityDefects)
        If $bConvexityDefectsCreate Then
            Call("_cve" & $typeOfConvexityDefects & "Release", $convexityDefects)
        EndIf
    EndIf

    If $bConvexhullIsArray Then
        Call("_VectorOf" & $typeOfConvexhull & "Release", $vectorConvexhull)
    EndIf

    If $typeOfConvexhull <> Default Then
        _cveInputArrayRelease($iArrConvexhull)
        If $bConvexhullCreate Then
            Call("_cve" & $typeOfConvexhull & "Release", $convexhull)
        EndIf
    EndIf

    If $bContourIsArray Then
        Call("_VectorOf" & $typeOfContour & "Release", $vectorContour)
    EndIf

    If $typeOfContour <> Default Then
        _cveInputArrayRelease($iArrContour)
        If $bContourCreate Then
            Call("_cve" & $typeOfContour & "Release", $contour)
        EndIf
    EndIf
EndFunc   ;==>_cveConvexityDefectsTyped

Func _cveConvexityDefectsMat($contour, $convexhull, $convexityDefects)
    ; cveConvexityDefects using cv::Mat instead of _*Array
    _cveConvexityDefectsTyped("Mat", $contour, "Mat", $convexhull, "Mat", $convexityDefects)
EndFunc   ;==>_cveConvexityDefectsMat

Func _cveGaussianBlur($src, $dst, $ksize, $sigmaX, $sigmaY = 0, $borderType = $CV_BORDER_DEFAULT)
    ; CVAPI(void) cveGaussianBlur(cv::_InputArray* src, cv::_OutputArray* dst, CvSize* ksize, double sigmaX, double sigmaY, int borderType);

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

    Local $sKsizeDllType
    If IsDllStruct($ksize) Then
        $sKsizeDllType = "struct*"
    Else
        $sKsizeDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveGaussianBlur", $sSrcDllType, $src, $sDstDllType, $dst, $sKsizeDllType, $ksize, "double", $sigmaX, "double", $sigmaY, "int", $borderType), "cveGaussianBlur", @error)
EndFunc   ;==>_cveGaussianBlur

Func _cveGaussianBlurTyped($typeOfSrc, $src, $typeOfDst, $dst, $ksize, $sigmaX, $sigmaY = 0, $borderType = $CV_BORDER_DEFAULT)

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

    _cveGaussianBlur($iArrSrc, $oArrDst, $ksize, $sigmaX, $sigmaY, $borderType)

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
EndFunc   ;==>_cveGaussianBlurTyped

Func _cveGaussianBlurMat($src, $dst, $ksize, $sigmaX, $sigmaY = 0, $borderType = $CV_BORDER_DEFAULT)
    ; cveGaussianBlur using cv::Mat instead of _*Array
    _cveGaussianBlurTyped("Mat", $src, "Mat", $dst, $ksize, $sigmaX, $sigmaY, $borderType)
EndFunc   ;==>_cveGaussianBlurMat

Func _cveBlur($src, $dst, $kSize, $anchor = _cvPoint(-1,-1), $borderType = $CV_BORDER_DEFAULT)
    ; CVAPI(void) cveBlur(cv::_InputArray* src, cv::_OutputArray* dst, CvSize* kSize, CvPoint* anchor, int borderType);

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

    Local $sKSizeDllType
    If IsDllStruct($kSize) Then
        $sKSizeDllType = "struct*"
    Else
        $sKSizeDllType = "ptr"
    EndIf

    Local $sAnchorDllType
    If IsDllStruct($anchor) Then
        $sAnchorDllType = "struct*"
    Else
        $sAnchorDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBlur", $sSrcDllType, $src, $sDstDllType, $dst, $sKSizeDllType, $kSize, $sAnchorDllType, $anchor, "int", $borderType), "cveBlur", @error)
EndFunc   ;==>_cveBlur

Func _cveBlurTyped($typeOfSrc, $src, $typeOfDst, $dst, $kSize, $anchor = _cvPoint(-1,-1), $borderType = $CV_BORDER_DEFAULT)

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

    _cveBlur($iArrSrc, $oArrDst, $kSize, $anchor, $borderType)

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
EndFunc   ;==>_cveBlurTyped

Func _cveBlurMat($src, $dst, $kSize, $anchor = _cvPoint(-1,-1), $borderType = $CV_BORDER_DEFAULT)
    ; cveBlur using cv::Mat instead of _*Array
    _cveBlurTyped("Mat", $src, "Mat", $dst, $kSize, $anchor, $borderType)
EndFunc   ;==>_cveBlurMat

Func _cveMedianBlur($src, $dst, $ksize)
    ; CVAPI(void) cveMedianBlur(cv::_InputArray* src, cv::_OutputArray* dst, int ksize);

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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMedianBlur", $sSrcDllType, $src, $sDstDllType, $dst, "int", $ksize), "cveMedianBlur", @error)
EndFunc   ;==>_cveMedianBlur

Func _cveMedianBlurTyped($typeOfSrc, $src, $typeOfDst, $dst, $ksize)

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

    _cveMedianBlur($iArrSrc, $oArrDst, $ksize)

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
EndFunc   ;==>_cveMedianBlurTyped

Func _cveMedianBlurMat($src, $dst, $ksize)
    ; cveMedianBlur using cv::Mat instead of _*Array
    _cveMedianBlurTyped("Mat", $src, "Mat", $dst, $ksize)
EndFunc   ;==>_cveMedianBlurMat

Func _cveBoxFilter($src, $dst, $ddepth, $ksize, $anchor, $normailize, $borderType = $CV_BORDER_DEFAULT)
    ; CVAPI(void) cveBoxFilter(cv::_InputArray* src, cv::_OutputArray* dst, int ddepth, CvSize* ksize, CvPoint* anchor, bool normailize, int borderType);

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

    Local $sKsizeDllType
    If IsDllStruct($ksize) Then
        $sKsizeDllType = "struct*"
    Else
        $sKsizeDllType = "ptr"
    EndIf

    Local $sAnchorDllType
    If IsDllStruct($anchor) Then
        $sAnchorDllType = "struct*"
    Else
        $sAnchorDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBoxFilter", $sSrcDllType, $src, $sDstDllType, $dst, "int", $ddepth, $sKsizeDllType, $ksize, $sAnchorDllType, $anchor, "boolean", $normailize, "int", $borderType), "cveBoxFilter", @error)
EndFunc   ;==>_cveBoxFilter

Func _cveBoxFilterTyped($typeOfSrc, $src, $typeOfDst, $dst, $ddepth, $ksize, $anchor, $normailize, $borderType = $CV_BORDER_DEFAULT)

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

    _cveBoxFilter($iArrSrc, $oArrDst, $ddepth, $ksize, $anchor, $normailize, $borderType)

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
EndFunc   ;==>_cveBoxFilterTyped

Func _cveBoxFilterMat($src, $dst, $ddepth, $ksize, $anchor, $normailize, $borderType = $CV_BORDER_DEFAULT)
    ; cveBoxFilter using cv::Mat instead of _*Array
    _cveBoxFilterTyped("Mat", $src, "Mat", $dst, $ddepth, $ksize, $anchor, $normailize, $borderType)
EndFunc   ;==>_cveBoxFilterMat

Func _cveSqrBoxFilter($_src, $_dst, $ddepth, $ksize, $anchor = _cvPoint(-1, -1), $normalize = true, $borderType = $CV_BORDER_DEFAULT)
    ; CVAPI(void) cveSqrBoxFilter(cv::_InputArray* _src, cv::_OutputArray* _dst, int ddepth, CvSize* ksize, CvPoint* anchor, bool normalize, int borderType);

    Local $s_srcDllType
    If IsDllStruct($_src) Then
        $s_srcDllType = "struct*"
    Else
        $s_srcDllType = "ptr"
    EndIf

    Local $s_dstDllType
    If IsDllStruct($_dst) Then
        $s_dstDllType = "struct*"
    Else
        $s_dstDllType = "ptr"
    EndIf

    Local $sKsizeDllType
    If IsDllStruct($ksize) Then
        $sKsizeDllType = "struct*"
    Else
        $sKsizeDllType = "ptr"
    EndIf

    Local $sAnchorDllType
    If IsDllStruct($anchor) Then
        $sAnchorDllType = "struct*"
    Else
        $sAnchorDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSqrBoxFilter", $s_srcDllType, $_src, $s_dstDllType, $_dst, "int", $ddepth, $sKsizeDllType, $ksize, $sAnchorDllType, $anchor, "boolean", $normalize, "int", $borderType), "cveSqrBoxFilter", @error)
EndFunc   ;==>_cveSqrBoxFilter

Func _cveSqrBoxFilterTyped($typeOf_src, $_src, $typeOf_dst, $_dst, $ddepth, $ksize, $anchor = _cvPoint(-1, -1), $normalize = true, $borderType = $CV_BORDER_DEFAULT)

    Local $iArr_src, $vector_src, $iArr_srcSize
    Local $b_srcIsArray = IsArray($_src)
    Local $b_srcCreate = IsDllStruct($_src) And $typeOf_src == "Scalar"

    If $typeOf_src == Default Then
        $iArr_src = $_src
    ElseIf $b_srcIsArray Then
        $vector_src = Call("_VectorOf" & $typeOf_src & "Create")

        $iArr_srcSize = UBound($_src)
        For $i = 0 To $iArr_srcSize - 1
            Call("_VectorOf" & $typeOf_src & "Push", $vector_src, $_src[$i])
        Next

        $iArr_src = Call("_cveInputArrayFromVectorOf" & $typeOf_src, $vector_src)
    Else
        If $b_srcCreate Then
            $_src = Call("_cve" & $typeOf_src & "Create", $_src)
        EndIf
        $iArr_src = Call("_cveInputArrayFrom" & $typeOf_src, $_src)
    EndIf

    Local $oArr_dst, $vector_dst, $iArr_dstSize
    Local $b_dstIsArray = IsArray($_dst)
    Local $b_dstCreate = IsDllStruct($_dst) And $typeOf_dst == "Scalar"

    If $typeOf_dst == Default Then
        $oArr_dst = $_dst
    ElseIf $b_dstIsArray Then
        $vector_dst = Call("_VectorOf" & $typeOf_dst & "Create")

        $iArr_dstSize = UBound($_dst)
        For $i = 0 To $iArr_dstSize - 1
            Call("_VectorOf" & $typeOf_dst & "Push", $vector_dst, $_dst[$i])
        Next

        $oArr_dst = Call("_cveOutputArrayFromVectorOf" & $typeOf_dst, $vector_dst)
    Else
        If $b_dstCreate Then
            $_dst = Call("_cve" & $typeOf_dst & "Create", $_dst)
        EndIf
        $oArr_dst = Call("_cveOutputArrayFrom" & $typeOf_dst, $_dst)
    EndIf

    _cveSqrBoxFilter($iArr_src, $oArr_dst, $ddepth, $ksize, $anchor, $normalize, $borderType)

    If $b_dstIsArray Then
        Call("_VectorOf" & $typeOf_dst & "Release", $vector_dst)
    EndIf

    If $typeOf_dst <> Default Then
        _cveOutputArrayRelease($oArr_dst)
        If $b_dstCreate Then
            Call("_cve" & $typeOf_dst & "Release", $_dst)
        EndIf
    EndIf

    If $b_srcIsArray Then
        Call("_VectorOf" & $typeOf_src & "Release", $vector_src)
    EndIf

    If $typeOf_src <> Default Then
        _cveInputArrayRelease($iArr_src)
        If $b_srcCreate Then
            Call("_cve" & $typeOf_src & "Release", $_src)
        EndIf
    EndIf
EndFunc   ;==>_cveSqrBoxFilterTyped

Func _cveSqrBoxFilterMat($_src, $_dst, $ddepth, $ksize, $anchor = _cvPoint(-1, -1), $normalize = true, $borderType = $CV_BORDER_DEFAULT)
    ; cveSqrBoxFilter using cv::Mat instead of _*Array
    _cveSqrBoxFilterTyped("Mat", $_src, "Mat", $_dst, $ddepth, $ksize, $anchor, $normalize, $borderType)
EndFunc   ;==>_cveSqrBoxFilterMat

Func _cveBilateralFilter($src, $dst, $d, $sigmaColor, $sigmaSpace, $borderType = $CV_BORDER_DEFAULT)
    ; CVAPI(void) cveBilateralFilter(cv::_InputArray* src, cv::_OutputArray* dst, int d, double sigmaColor, double sigmaSpace, int borderType);

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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBilateralFilter", $sSrcDllType, $src, $sDstDllType, $dst, "int", $d, "double", $sigmaColor, "double", $sigmaSpace, "int", $borderType), "cveBilateralFilter", @error)
EndFunc   ;==>_cveBilateralFilter

Func _cveBilateralFilterTyped($typeOfSrc, $src, $typeOfDst, $dst, $d, $sigmaColor, $sigmaSpace, $borderType = $CV_BORDER_DEFAULT)

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

    _cveBilateralFilter($iArrSrc, $oArrDst, $d, $sigmaColor, $sigmaSpace, $borderType)

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
EndFunc   ;==>_cveBilateralFilterTyped

Func _cveBilateralFilterMat($src, $dst, $d, $sigmaColor, $sigmaSpace, $borderType = $CV_BORDER_DEFAULT)
    ; cveBilateralFilter using cv::Mat instead of _*Array
    _cveBilateralFilterTyped("Mat", $src, "Mat", $dst, $d, $sigmaColor, $sigmaSpace, $borderType)
EndFunc   ;==>_cveBilateralFilterMat

Func _cveSubdiv2DCreate($rect)
    ; CVAPI(cv::Subdiv2D*) cveSubdiv2DCreate(CvRect* rect);

    Local $sRectDllType
    If IsDllStruct($rect) Then
        $sRectDllType = "struct*"
    Else
        $sRectDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveSubdiv2DCreate", $sRectDllType, $rect), "cveSubdiv2DCreate", @error)
EndFunc   ;==>_cveSubdiv2DCreate

Func _cveSubdiv2DRelease($subdiv)
    ; CVAPI(void) cveSubdiv2DRelease(cv::Subdiv2D** subdiv);

    Local $sSubdivDllType
    If IsDllStruct($subdiv) Then
        $sSubdivDllType = "struct*"
    ElseIf $subdiv == Null Then
        $sSubdivDllType = "ptr"
    Else
        $sSubdivDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSubdiv2DRelease", $sSubdivDllType, $subdiv), "cveSubdiv2DRelease", @error)
EndFunc   ;==>_cveSubdiv2DRelease

Func _cveSubdiv2DInsertMulti($subdiv, $points)
    ; CVAPI(void) cveSubdiv2DInsertMulti(cv::Subdiv2D* subdiv, std::vector<cv::Point2f>* points);

    Local $sSubdivDllType
    If IsDllStruct($subdiv) Then
        $sSubdivDllType = "struct*"
    Else
        $sSubdivDllType = "ptr"
    EndIf

    Local $vecPoints, $iArrPointsSize
    Local $bPointsIsArray = IsArray($points)

    If $bPointsIsArray Then
        $vecPoints = _VectorOfPointFCreate()

        $iArrPointsSize = UBound($points)
        For $i = 0 To $iArrPointsSize - 1
            _VectorOfPointFPush($vecPoints, $points[$i])
        Next
    Else
        $vecPoints = $points
    EndIf

    Local $sPointsDllType
    If IsDllStruct($points) Then
        $sPointsDllType = "struct*"
    Else
        $sPointsDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSubdiv2DInsertMulti", $sSubdivDllType, $subdiv, $sPointsDllType, $vecPoints), "cveSubdiv2DInsertMulti", @error)

    If $bPointsIsArray Then
        _VectorOfPointFRelease($vecPoints)
    EndIf
EndFunc   ;==>_cveSubdiv2DInsertMulti

Func _cveSubdiv2DInsertSingle($subdiv, $pt)
    ; CVAPI(int) cveSubdiv2DInsertSingle(cv::Subdiv2D* subdiv, CvPoint2D32f* pt);

    Local $sSubdivDllType
    If IsDllStruct($subdiv) Then
        $sSubdivDllType = "struct*"
    Else
        $sSubdivDllType = "ptr"
    EndIf

    Local $sPtDllType
    If IsDllStruct($pt) Then
        $sPtDllType = "struct*"
    Else
        $sPtDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveSubdiv2DInsertSingle", $sSubdivDllType, $subdiv, $sPtDllType, $pt), "cveSubdiv2DInsertSingle", @error)
EndFunc   ;==>_cveSubdiv2DInsertSingle

Func _cveSubdiv2DGetTriangleList($subdiv, $triangleList)
    ; CVAPI(void) cveSubdiv2DGetTriangleList(cv::Subdiv2D* subdiv, std::vector<cv::Vec6f>* triangleList);

    Local $sSubdivDllType
    If IsDllStruct($subdiv) Then
        $sSubdivDllType = "struct*"
    Else
        $sSubdivDllType = "ptr"
    EndIf

    Local $vecTriangleList, $iArrTriangleListSize
    Local $bTriangleListIsArray = IsArray($triangleList)

    If $bTriangleListIsArray Then
        $vecTriangleList = _VectorOfTriangle2DFCreate()

        $iArrTriangleListSize = UBound($triangleList)
        For $i = 0 To $iArrTriangleListSize - 1
            _VectorOfTriangle2DFPush($vecTriangleList, $triangleList[$i])
        Next
    Else
        $vecTriangleList = $triangleList
    EndIf

    Local $sTriangleListDllType
    If IsDllStruct($triangleList) Then
        $sTriangleListDllType = "struct*"
    Else
        $sTriangleListDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSubdiv2DGetTriangleList", $sSubdivDllType, $subdiv, $sTriangleListDllType, $vecTriangleList), "cveSubdiv2DGetTriangleList", @error)

    If $bTriangleListIsArray Then
        _VectorOfTriangle2DFRelease($vecTriangleList)
    EndIf
EndFunc   ;==>_cveSubdiv2DGetTriangleList

Func _cveSubdiv2DGetVoronoiFacetList($subdiv, $idx, $facetList, $facetCenters)
    ; CVAPI(void) cveSubdiv2DGetVoronoiFacetList(cv::Subdiv2D* subdiv, std::vector<int>* idx, std::vector<std::vector<cv::Point2f>>* facetList, std::vector<cv::Point2f>* facetCenters);

    Local $sSubdivDllType
    If IsDllStruct($subdiv) Then
        $sSubdivDllType = "struct*"
    Else
        $sSubdivDllType = "ptr"
    EndIf

    Local $vecIdx, $iArrIdxSize
    Local $bIdxIsArray = IsArray($idx)

    If $bIdxIsArray Then
        $vecIdx = _VectorOfIntCreate()

        $iArrIdxSize = UBound($idx)
        For $i = 0 To $iArrIdxSize - 1
            _VectorOfIntPush($vecIdx, $idx[$i])
        Next
    Else
        $vecIdx = $idx
    EndIf

    Local $sIdxDllType
    If IsDllStruct($idx) Then
        $sIdxDllType = "struct*"
    Else
        $sIdxDllType = "ptr"
    EndIf

    Local $vecFacetList, $iArrFacetListSize
    Local $bFacetListIsArray = IsArray($facetList)

    If $bFacetListIsArray Then
        $vecFacetList = _VectorOfVectorOfPointFCreate()

        $iArrFacetListSize = UBound($facetList)
        For $i = 0 To $iArrFacetListSize - 1
            _VectorOfVectorOfPointFPush($vecFacetList, $facetList[$i])
        Next
    Else
        $vecFacetList = $facetList
    EndIf

    Local $sFacetListDllType
    If IsDllStruct($facetList) Then
        $sFacetListDllType = "struct*"
    Else
        $sFacetListDllType = "ptr"
    EndIf

    Local $vecFacetCenters, $iArrFacetCentersSize
    Local $bFacetCentersIsArray = IsArray($facetCenters)

    If $bFacetCentersIsArray Then
        $vecFacetCenters = _VectorOfPointFCreate()

        $iArrFacetCentersSize = UBound($facetCenters)
        For $i = 0 To $iArrFacetCentersSize - 1
            _VectorOfPointFPush($vecFacetCenters, $facetCenters[$i])
        Next
    Else
        $vecFacetCenters = $facetCenters
    EndIf

    Local $sFacetCentersDllType
    If IsDllStruct($facetCenters) Then
        $sFacetCentersDllType = "struct*"
    Else
        $sFacetCentersDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSubdiv2DGetVoronoiFacetList", $sSubdivDllType, $subdiv, $sIdxDllType, $vecIdx, $sFacetListDllType, $vecFacetList, $sFacetCentersDllType, $vecFacetCenters), "cveSubdiv2DGetVoronoiFacetList", @error)

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

    Local $sSubdivDllType
    If IsDllStruct($subdiv) Then
        $sSubdivDllType = "struct*"
    Else
        $sSubdivDllType = "ptr"
    EndIf

    Local $sPtDllType
    If IsDllStruct($pt) Then
        $sPtDllType = "struct*"
    Else
        $sPtDllType = "ptr"
    EndIf

    Local $sNearestPtDllType
    If IsDllStruct($nearestPt) Then
        $sNearestPtDllType = "struct*"
    Else
        $sNearestPtDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveSubdiv2DFindNearest", $sSubdivDllType, $subdiv, $sPtDllType, $pt, $sNearestPtDllType, $nearestPt), "cveSubdiv2DFindNearest", @error)
EndFunc   ;==>_cveSubdiv2DFindNearest

Func _cveSubdiv2DLocate($subdiv, $pt, $edge, $vertex)
    ; CVAPI(int) cveSubdiv2DLocate(cv::Subdiv2D* subdiv, CvPoint2D32f* pt, int* edge, int* vertex);

    Local $sSubdivDllType
    If IsDllStruct($subdiv) Then
        $sSubdivDllType = "struct*"
    Else
        $sSubdivDllType = "ptr"
    EndIf

    Local $sPtDllType
    If IsDllStruct($pt) Then
        $sPtDllType = "struct*"
    Else
        $sPtDllType = "ptr"
    EndIf

    Local $sEdgeDllType
    If IsDllStruct($edge) Then
        $sEdgeDllType = "struct*"
    Else
        $sEdgeDllType = "int*"
    EndIf

    Local $sVertexDllType
    If IsDllStruct($vertex) Then
        $sVertexDllType = "struct*"
    Else
        $sVertexDllType = "int*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveSubdiv2DLocate", $sSubdivDllType, $subdiv, $sPtDllType, $pt, $sEdgeDllType, $edge, $sVertexDllType, $vertex), "cveSubdiv2DLocate", @error)
EndFunc   ;==>_cveSubdiv2DLocate

Func _cveLineIteratorCreate($img, $pt1, $pt2, $connectivity, $leftToRight)
    ; CVAPI(cv::LineIterator*) cveLineIteratorCreate(cv::Mat* img, CvPoint* pt1, CvPoint* pt2, int connectivity, bool leftToRight);

    Local $sImgDllType
    If IsDllStruct($img) Then
        $sImgDllType = "struct*"
    Else
        $sImgDllType = "ptr"
    EndIf

    Local $sPt1DllType
    If IsDllStruct($pt1) Then
        $sPt1DllType = "struct*"
    Else
        $sPt1DllType = "ptr"
    EndIf

    Local $sPt2DllType
    If IsDllStruct($pt2) Then
        $sPt2DllType = "struct*"
    Else
        $sPt2DllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveLineIteratorCreate", $sImgDllType, $img, $sPt1DllType, $pt1, $sPt2DllType, $pt2, "int", $connectivity, "boolean", $leftToRight), "cveLineIteratorCreate", @error)
EndFunc   ;==>_cveLineIteratorCreate

Func _cveLineIteratorGetDataPointer($iterator)
    ; CVAPI(uchar*) cveLineIteratorGetDataPointer(cv::LineIterator* iterator);

    Local $sIteratorDllType
    If IsDllStruct($iterator) Then
        $sIteratorDllType = "struct*"
    Else
        $sIteratorDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveLineIteratorGetDataPointer", $sIteratorDllType, $iterator), "cveLineIteratorGetDataPointer", @error)
EndFunc   ;==>_cveLineIteratorGetDataPointer

Func _cveLineIteratorPos($iterator, $pos)
    ; CVAPI(void) cveLineIteratorPos(cv::LineIterator* iterator, CvPoint* pos);

    Local $sIteratorDllType
    If IsDllStruct($iterator) Then
        $sIteratorDllType = "struct*"
    Else
        $sIteratorDllType = "ptr"
    EndIf

    Local $sPosDllType
    If IsDllStruct($pos) Then
        $sPosDllType = "struct*"
    Else
        $sPosDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveLineIteratorPos", $sIteratorDllType, $iterator, $sPosDllType, $pos), "cveLineIteratorPos", @error)
EndFunc   ;==>_cveLineIteratorPos

Func _cveLineIteratorMoveNext($iterator)
    ; CVAPI(void) cveLineIteratorMoveNext(cv::LineIterator* iterator);

    Local $sIteratorDllType
    If IsDllStruct($iterator) Then
        $sIteratorDllType = "struct*"
    Else
        $sIteratorDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveLineIteratorMoveNext", $sIteratorDllType, $iterator), "cveLineIteratorMoveNext", @error)
EndFunc   ;==>_cveLineIteratorMoveNext

Func _cveLineIteratorRelease($iterator)
    ; CVAPI(void) cveLineIteratorRelease(cv::LineIterator** iterator);

    Local $sIteratorDllType
    If IsDllStruct($iterator) Then
        $sIteratorDllType = "struct*"
    ElseIf $iterator == Null Then
        $sIteratorDllType = "ptr"
    Else
        $sIteratorDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveLineIteratorRelease", $sIteratorDllType, $iterator), "cveLineIteratorRelease", @error)
EndFunc   ;==>_cveLineIteratorRelease

Func _cveLineIteratorSampleLine($img, $pt1, $pt2, $connectivity, $leftToRight, $result)
    ; CVAPI(void) cveLineIteratorSampleLine(cv::Mat* img, CvPoint* pt1, CvPoint* pt2, int connectivity, bool leftToRight, cv::Mat* result);

    Local $sImgDllType
    If IsDllStruct($img) Then
        $sImgDllType = "struct*"
    Else
        $sImgDllType = "ptr"
    EndIf

    Local $sPt1DllType
    If IsDllStruct($pt1) Then
        $sPt1DllType = "struct*"
    Else
        $sPt1DllType = "ptr"
    EndIf

    Local $sPt2DllType
    If IsDllStruct($pt2) Then
        $sPt2DllType = "struct*"
    Else
        $sPt2DllType = "ptr"
    EndIf

    Local $sResultDllType
    If IsDllStruct($result) Then
        $sResultDllType = "struct*"
    Else
        $sResultDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveLineIteratorSampleLine", $sImgDllType, $img, $sPt1DllType, $pt1, $sPt2DllType, $pt2, "int", $connectivity, "boolean", $leftToRight, $sResultDllType, $result), "cveLineIteratorSampleLine", @error)
EndFunc   ;==>_cveLineIteratorSampleLine

Func _cveLine($img, $p1, $p2, $color, $thickness = 1, $lineType = $CV_LINE_8, $shift = 0)
    ; CVAPI(void) cveLine(cv::_InputOutputArray* img, CvPoint* p1, CvPoint* p2, CvScalar* color, int thickness, int lineType, int shift);

    Local $sImgDllType
    If IsDllStruct($img) Then
        $sImgDllType = "struct*"
    Else
        $sImgDllType = "ptr"
    EndIf

    Local $sP1DllType
    If IsDllStruct($p1) Then
        $sP1DllType = "struct*"
    Else
        $sP1DllType = "ptr"
    EndIf

    Local $sP2DllType
    If IsDllStruct($p2) Then
        $sP2DllType = "struct*"
    Else
        $sP2DllType = "ptr"
    EndIf

    Local $sColorDllType
    If IsDllStruct($color) Then
        $sColorDllType = "struct*"
    Else
        $sColorDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveLine", $sImgDllType, $img, $sP1DllType, $p1, $sP2DllType, $p2, $sColorDllType, $color, "int", $thickness, "int", $lineType, "int", $shift), "cveLine", @error)
EndFunc   ;==>_cveLine

Func _cveLineTyped($typeOfImg, $img, $p1, $p2, $color, $thickness = 1, $lineType = $CV_LINE_8, $shift = 0)

    Local $ioArrImg, $vectorImg, $iArrImgSize
    Local $bImgIsArray = IsArray($img)
    Local $bImgCreate = IsDllStruct($img) And $typeOfImg == "Scalar"

    If $typeOfImg == Default Then
        $ioArrImg = $img
    ElseIf $bImgIsArray Then
        $vectorImg = Call("_VectorOf" & $typeOfImg & "Create")

        $iArrImgSize = UBound($img)
        For $i = 0 To $iArrImgSize - 1
            Call("_VectorOf" & $typeOfImg & "Push", $vectorImg, $img[$i])
        Next

        $ioArrImg = Call("_cveInputOutputArrayFromVectorOf" & $typeOfImg, $vectorImg)
    Else
        If $bImgCreate Then
            $img = Call("_cve" & $typeOfImg & "Create", $img)
        EndIf
        $ioArrImg = Call("_cveInputOutputArrayFrom" & $typeOfImg, $img)
    EndIf

    _cveLine($ioArrImg, $p1, $p2, $color, $thickness, $lineType, $shift)

    If $bImgIsArray Then
        Call("_VectorOf" & $typeOfImg & "Release", $vectorImg)
    EndIf

    If $typeOfImg <> Default Then
        _cveInputOutputArrayRelease($ioArrImg)
        If $bImgCreate Then
            Call("_cve" & $typeOfImg & "Release", $img)
        EndIf
    EndIf
EndFunc   ;==>_cveLineTyped

Func _cveLineMat($img, $p1, $p2, $color, $thickness = 1, $lineType = $CV_LINE_8, $shift = 0)
    ; cveLine using cv::Mat instead of _*Array
    _cveLineTyped("Mat", $img, $p1, $p2, $color, $thickness, $lineType, $shift)
EndFunc   ;==>_cveLineMat

Func _cveArrowedLine($img, $pt1, $pt2, $color, $thickness, $lineType, $shift = 0, $tipLength = 0.1)
    ; CVAPI(void) cveArrowedLine(cv::_InputOutputArray* img, CvPoint* pt1, CvPoint* pt2, CvScalar* color, int thickness, int lineType, int shift, double tipLength);

    Local $sImgDllType
    If IsDllStruct($img) Then
        $sImgDllType = "struct*"
    Else
        $sImgDllType = "ptr"
    EndIf

    Local $sPt1DllType
    If IsDllStruct($pt1) Then
        $sPt1DllType = "struct*"
    Else
        $sPt1DllType = "ptr"
    EndIf

    Local $sPt2DllType
    If IsDllStruct($pt2) Then
        $sPt2DllType = "struct*"
    Else
        $sPt2DllType = "ptr"
    EndIf

    Local $sColorDllType
    If IsDllStruct($color) Then
        $sColorDllType = "struct*"
    Else
        $sColorDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveArrowedLine", $sImgDllType, $img, $sPt1DllType, $pt1, $sPt2DllType, $pt2, $sColorDllType, $color, "int", $thickness, "int", $lineType, "int", $shift, "double", $tipLength), "cveArrowedLine", @error)
EndFunc   ;==>_cveArrowedLine

Func _cveArrowedLineTyped($typeOfImg, $img, $pt1, $pt2, $color, $thickness, $lineType, $shift = 0, $tipLength = 0.1)

    Local $ioArrImg, $vectorImg, $iArrImgSize
    Local $bImgIsArray = IsArray($img)
    Local $bImgCreate = IsDllStruct($img) And $typeOfImg == "Scalar"

    If $typeOfImg == Default Then
        $ioArrImg = $img
    ElseIf $bImgIsArray Then
        $vectorImg = Call("_VectorOf" & $typeOfImg & "Create")

        $iArrImgSize = UBound($img)
        For $i = 0 To $iArrImgSize - 1
            Call("_VectorOf" & $typeOfImg & "Push", $vectorImg, $img[$i])
        Next

        $ioArrImg = Call("_cveInputOutputArrayFromVectorOf" & $typeOfImg, $vectorImg)
    Else
        If $bImgCreate Then
            $img = Call("_cve" & $typeOfImg & "Create", $img)
        EndIf
        $ioArrImg = Call("_cveInputOutputArrayFrom" & $typeOfImg, $img)
    EndIf

    _cveArrowedLine($ioArrImg, $pt1, $pt2, $color, $thickness, $lineType, $shift, $tipLength)

    If $bImgIsArray Then
        Call("_VectorOf" & $typeOfImg & "Release", $vectorImg)
    EndIf

    If $typeOfImg <> Default Then
        _cveInputOutputArrayRelease($ioArrImg)
        If $bImgCreate Then
            Call("_cve" & $typeOfImg & "Release", $img)
        EndIf
    EndIf
EndFunc   ;==>_cveArrowedLineTyped

Func _cveArrowedLineMat($img, $pt1, $pt2, $color, $thickness, $lineType, $shift = 0, $tipLength = 0.1)
    ; cveArrowedLine using cv::Mat instead of _*Array
    _cveArrowedLineTyped("Mat", $img, $pt1, $pt2, $color, $thickness, $lineType, $shift, $tipLength)
EndFunc   ;==>_cveArrowedLineMat

Func _cveRectangle($img, $rect, $color, $thickness = 1, $lineType = $CV_LINE_8, $shift = 0)
    ; CVAPI(void) cveRectangle(cv::_InputOutputArray* img, CvRect* rect, CvScalar* color, int thickness, int lineType, int shift);

    Local $sImgDllType
    If IsDllStruct($img) Then
        $sImgDllType = "struct*"
    Else
        $sImgDllType = "ptr"
    EndIf

    Local $sRectDllType
    If IsDllStruct($rect) Then
        $sRectDllType = "struct*"
    Else
        $sRectDllType = "ptr"
    EndIf

    Local $sColorDllType
    If IsDllStruct($color) Then
        $sColorDllType = "struct*"
    Else
        $sColorDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveRectangle", $sImgDllType, $img, $sRectDllType, $rect, $sColorDllType, $color, "int", $thickness, "int", $lineType, "int", $shift), "cveRectangle", @error)
EndFunc   ;==>_cveRectangle

Func _cveRectangleTyped($typeOfImg, $img, $rect, $color, $thickness = 1, $lineType = $CV_LINE_8, $shift = 0)

    Local $ioArrImg, $vectorImg, $iArrImgSize
    Local $bImgIsArray = IsArray($img)
    Local $bImgCreate = IsDllStruct($img) And $typeOfImg == "Scalar"

    If $typeOfImg == Default Then
        $ioArrImg = $img
    ElseIf $bImgIsArray Then
        $vectorImg = Call("_VectorOf" & $typeOfImg & "Create")

        $iArrImgSize = UBound($img)
        For $i = 0 To $iArrImgSize - 1
            Call("_VectorOf" & $typeOfImg & "Push", $vectorImg, $img[$i])
        Next

        $ioArrImg = Call("_cveInputOutputArrayFromVectorOf" & $typeOfImg, $vectorImg)
    Else
        If $bImgCreate Then
            $img = Call("_cve" & $typeOfImg & "Create", $img)
        EndIf
        $ioArrImg = Call("_cveInputOutputArrayFrom" & $typeOfImg, $img)
    EndIf

    _cveRectangle($ioArrImg, $rect, $color, $thickness, $lineType, $shift)

    If $bImgIsArray Then
        Call("_VectorOf" & $typeOfImg & "Release", $vectorImg)
    EndIf

    If $typeOfImg <> Default Then
        _cveInputOutputArrayRelease($ioArrImg)
        If $bImgCreate Then
            Call("_cve" & $typeOfImg & "Release", $img)
        EndIf
    EndIf
EndFunc   ;==>_cveRectangleTyped

Func _cveRectangleMat($img, $rect, $color, $thickness = 1, $lineType = $CV_LINE_8, $shift = 0)
    ; cveRectangle using cv::Mat instead of _*Array
    _cveRectangleTyped("Mat", $img, $rect, $color, $thickness, $lineType, $shift)
EndFunc   ;==>_cveRectangleMat

Func _cveCircle($img, $center, $radius, $color, $thickness = 1, $lineType = $CV_LINE_8, $shift = 0)
    ; CVAPI(void) cveCircle(cv::_InputOutputArray* img, CvPoint* center, int radius, CvScalar* color, int thickness, int lineType, int shift);

    Local $sImgDllType
    If IsDllStruct($img) Then
        $sImgDllType = "struct*"
    Else
        $sImgDllType = "ptr"
    EndIf

    Local $sCenterDllType
    If IsDllStruct($center) Then
        $sCenterDllType = "struct*"
    Else
        $sCenterDllType = "ptr"
    EndIf

    Local $sColorDllType
    If IsDllStruct($color) Then
        $sColorDllType = "struct*"
    Else
        $sColorDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCircle", $sImgDllType, $img, $sCenterDllType, $center, "int", $radius, $sColorDllType, $color, "int", $thickness, "int", $lineType, "int", $shift), "cveCircle", @error)
EndFunc   ;==>_cveCircle

Func _cveCircleTyped($typeOfImg, $img, $center, $radius, $color, $thickness = 1, $lineType = $CV_LINE_8, $shift = 0)

    Local $ioArrImg, $vectorImg, $iArrImgSize
    Local $bImgIsArray = IsArray($img)
    Local $bImgCreate = IsDllStruct($img) And $typeOfImg == "Scalar"

    If $typeOfImg == Default Then
        $ioArrImg = $img
    ElseIf $bImgIsArray Then
        $vectorImg = Call("_VectorOf" & $typeOfImg & "Create")

        $iArrImgSize = UBound($img)
        For $i = 0 To $iArrImgSize - 1
            Call("_VectorOf" & $typeOfImg & "Push", $vectorImg, $img[$i])
        Next

        $ioArrImg = Call("_cveInputOutputArrayFromVectorOf" & $typeOfImg, $vectorImg)
    Else
        If $bImgCreate Then
            $img = Call("_cve" & $typeOfImg & "Create", $img)
        EndIf
        $ioArrImg = Call("_cveInputOutputArrayFrom" & $typeOfImg, $img)
    EndIf

    _cveCircle($ioArrImg, $center, $radius, $color, $thickness, $lineType, $shift)

    If $bImgIsArray Then
        Call("_VectorOf" & $typeOfImg & "Release", $vectorImg)
    EndIf

    If $typeOfImg <> Default Then
        _cveInputOutputArrayRelease($ioArrImg)
        If $bImgCreate Then
            Call("_cve" & $typeOfImg & "Release", $img)
        EndIf
    EndIf
EndFunc   ;==>_cveCircleTyped

Func _cveCircleMat($img, $center, $radius, $color, $thickness = 1, $lineType = $CV_LINE_8, $shift = 0)
    ; cveCircle using cv::Mat instead of _*Array
    _cveCircleTyped("Mat", $img, $center, $radius, $color, $thickness, $lineType, $shift)
EndFunc   ;==>_cveCircleMat

Func _cvePutText($img, $text, $org, $fontFace, $fontScale, $color, $thickness = 1, $lineType = $CV_LINE_8, $bottomLeftOrigin = false)
    ; CVAPI(void) cvePutText(cv::_InputOutputArray* img, cv::String* text, CvPoint* org, int fontFace, double fontScale, CvScalar* color, int thickness, int lineType, bool bottomLeftOrigin);

    Local $sImgDllType
    If IsDllStruct($img) Then
        $sImgDllType = "struct*"
    Else
        $sImgDllType = "ptr"
    EndIf

    Local $bTextIsString = IsString($text)
    If $bTextIsString Then
        $text = _cveStringCreateFromStr($text)
    EndIf

    Local $sTextDllType
    If IsDllStruct($text) Then
        $sTextDllType = "struct*"
    Else
        $sTextDllType = "ptr"
    EndIf

    Local $sOrgDllType
    If IsDllStruct($org) Then
        $sOrgDllType = "struct*"
    Else
        $sOrgDllType = "ptr"
    EndIf

    Local $sColorDllType
    If IsDllStruct($color) Then
        $sColorDllType = "struct*"
    Else
        $sColorDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cvePutText", $sImgDllType, $img, $sTextDllType, $text, $sOrgDllType, $org, "int", $fontFace, "double", $fontScale, $sColorDllType, $color, "int", $thickness, "int", $lineType, "boolean", $bottomLeftOrigin), "cvePutText", @error)

    If $bTextIsString Then
        _cveStringRelease($text)
    EndIf
EndFunc   ;==>_cvePutText

Func _cvePutTextTyped($typeOfImg, $img, $text, $org, $fontFace, $fontScale, $color, $thickness = 1, $lineType = $CV_LINE_8, $bottomLeftOrigin = false)

    Local $ioArrImg, $vectorImg, $iArrImgSize
    Local $bImgIsArray = IsArray($img)
    Local $bImgCreate = IsDllStruct($img) And $typeOfImg == "Scalar"

    If $typeOfImg == Default Then
        $ioArrImg = $img
    ElseIf $bImgIsArray Then
        $vectorImg = Call("_VectorOf" & $typeOfImg & "Create")

        $iArrImgSize = UBound($img)
        For $i = 0 To $iArrImgSize - 1
            Call("_VectorOf" & $typeOfImg & "Push", $vectorImg, $img[$i])
        Next

        $ioArrImg = Call("_cveInputOutputArrayFromVectorOf" & $typeOfImg, $vectorImg)
    Else
        If $bImgCreate Then
            $img = Call("_cve" & $typeOfImg & "Create", $img)
        EndIf
        $ioArrImg = Call("_cveInputOutputArrayFrom" & $typeOfImg, $img)
    EndIf

    _cvePutText($ioArrImg, $text, $org, $fontFace, $fontScale, $color, $thickness, $lineType, $bottomLeftOrigin)

    If $bImgIsArray Then
        Call("_VectorOf" & $typeOfImg & "Release", $vectorImg)
    EndIf

    If $typeOfImg <> Default Then
        _cveInputOutputArrayRelease($ioArrImg)
        If $bImgCreate Then
            Call("_cve" & $typeOfImg & "Release", $img)
        EndIf
    EndIf
EndFunc   ;==>_cvePutTextTyped

Func _cvePutTextMat($img, $text, $org, $fontFace, $fontScale, $color, $thickness = 1, $lineType = $CV_LINE_8, $bottomLeftOrigin = false)
    ; cvePutText using cv::Mat instead of _*Array
    _cvePutTextTyped("Mat", $img, $text, $org, $fontFace, $fontScale, $color, $thickness, $lineType, $bottomLeftOrigin)
EndFunc   ;==>_cvePutTextMat

Func _cveGetTextSize($text, $fontFace, $fontScale, $thickness, $baseLine, $size)
    ; CVAPI(void) cveGetTextSize(cv::String* text, int fontFace, double fontScale, int thickness, int* baseLine, CvSize* size);

    Local $bTextIsString = IsString($text)
    If $bTextIsString Then
        $text = _cveStringCreateFromStr($text)
    EndIf

    Local $sTextDllType
    If IsDllStruct($text) Then
        $sTextDllType = "struct*"
    Else
        $sTextDllType = "ptr"
    EndIf

    Local $sBaseLineDllType
    If IsDllStruct($baseLine) Then
        $sBaseLineDllType = "struct*"
    Else
        $sBaseLineDllType = "int*"
    EndIf

    Local $sSizeDllType
    If IsDllStruct($size) Then
        $sSizeDllType = "struct*"
    Else
        $sSizeDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveGetTextSize", $sTextDllType, $text, "int", $fontFace, "double", $fontScale, "int", $thickness, $sBaseLineDllType, $baseLine, $sSizeDllType, $size), "cveGetTextSize", @error)

    If $bTextIsString Then
        _cveStringRelease($text)
    EndIf
EndFunc   ;==>_cveGetTextSize

Func _cveFillConvexPoly($img, $points, $color, $lineType = $CV_LINE_8, $shift = 0)
    ; CVAPI(void) cveFillConvexPoly(cv::_InputOutputArray* img, cv::_InputArray* points, const CvScalar* color, int lineType, int shift);

    Local $sImgDllType
    If IsDllStruct($img) Then
        $sImgDllType = "struct*"
    Else
        $sImgDllType = "ptr"
    EndIf

    Local $sPointsDllType
    If IsDllStruct($points) Then
        $sPointsDllType = "struct*"
    Else
        $sPointsDllType = "ptr"
    EndIf

    Local $sColorDllType
    If IsDllStruct($color) Then
        $sColorDllType = "struct*"
    Else
        $sColorDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFillConvexPoly", $sImgDllType, $img, $sPointsDllType, $points, $sColorDllType, $color, "int", $lineType, "int", $shift), "cveFillConvexPoly", @error)
EndFunc   ;==>_cveFillConvexPoly

Func _cveFillConvexPolyTyped($typeOfImg, $img, $typeOfPoints, $points, $color, $lineType = $CV_LINE_8, $shift = 0)

    Local $ioArrImg, $vectorImg, $iArrImgSize
    Local $bImgIsArray = IsArray($img)
    Local $bImgCreate = IsDllStruct($img) And $typeOfImg == "Scalar"

    If $typeOfImg == Default Then
        $ioArrImg = $img
    ElseIf $bImgIsArray Then
        $vectorImg = Call("_VectorOf" & $typeOfImg & "Create")

        $iArrImgSize = UBound($img)
        For $i = 0 To $iArrImgSize - 1
            Call("_VectorOf" & $typeOfImg & "Push", $vectorImg, $img[$i])
        Next

        $ioArrImg = Call("_cveInputOutputArrayFromVectorOf" & $typeOfImg, $vectorImg)
    Else
        If $bImgCreate Then
            $img = Call("_cve" & $typeOfImg & "Create", $img)
        EndIf
        $ioArrImg = Call("_cveInputOutputArrayFrom" & $typeOfImg, $img)
    EndIf

    Local $iArrPoints, $vectorPoints, $iArrPointsSize
    Local $bPointsIsArray = IsArray($points)
    Local $bPointsCreate = IsDllStruct($points) And $typeOfPoints == "Scalar"

    If $typeOfPoints == Default Then
        $iArrPoints = $points
    ElseIf $bPointsIsArray Then
        $vectorPoints = Call("_VectorOf" & $typeOfPoints & "Create")

        $iArrPointsSize = UBound($points)
        For $i = 0 To $iArrPointsSize - 1
            Call("_VectorOf" & $typeOfPoints & "Push", $vectorPoints, $points[$i])
        Next

        $iArrPoints = Call("_cveInputArrayFromVectorOf" & $typeOfPoints, $vectorPoints)
    Else
        If $bPointsCreate Then
            $points = Call("_cve" & $typeOfPoints & "Create", $points)
        EndIf
        $iArrPoints = Call("_cveInputArrayFrom" & $typeOfPoints, $points)
    EndIf

    _cveFillConvexPoly($ioArrImg, $iArrPoints, $color, $lineType, $shift)

    If $bPointsIsArray Then
        Call("_VectorOf" & $typeOfPoints & "Release", $vectorPoints)
    EndIf

    If $typeOfPoints <> Default Then
        _cveInputArrayRelease($iArrPoints)
        If $bPointsCreate Then
            Call("_cve" & $typeOfPoints & "Release", $points)
        EndIf
    EndIf

    If $bImgIsArray Then
        Call("_VectorOf" & $typeOfImg & "Release", $vectorImg)
    EndIf

    If $typeOfImg <> Default Then
        _cveInputOutputArrayRelease($ioArrImg)
        If $bImgCreate Then
            Call("_cve" & $typeOfImg & "Release", $img)
        EndIf
    EndIf
EndFunc   ;==>_cveFillConvexPolyTyped

Func _cveFillConvexPolyMat($img, $points, $color, $lineType = $CV_LINE_8, $shift = 0)
    ; cveFillConvexPoly using cv::Mat instead of _*Array
    _cveFillConvexPolyTyped("Mat", $img, "Mat", $points, $color, $lineType, $shift)
EndFunc   ;==>_cveFillConvexPolyMat

Func _cveFillPoly($img, $pts, $color, $lineType = $CV_LINE_8, $shift = 0, $offset = _cvPoint())
    ; CVAPI(void) cveFillPoly(cv::_InputOutputArray* img, cv::_InputArray* pts, const CvScalar* color, int lineType, int shift, CvPoint* offset);

    Local $sImgDllType
    If IsDllStruct($img) Then
        $sImgDllType = "struct*"
    Else
        $sImgDllType = "ptr"
    EndIf

    Local $sPtsDllType
    If IsDllStruct($pts) Then
        $sPtsDllType = "struct*"
    Else
        $sPtsDllType = "ptr"
    EndIf

    Local $sColorDllType
    If IsDllStruct($color) Then
        $sColorDllType = "struct*"
    Else
        $sColorDllType = "ptr"
    EndIf

    Local $sOffsetDllType
    If IsDllStruct($offset) Then
        $sOffsetDllType = "struct*"
    Else
        $sOffsetDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFillPoly", $sImgDllType, $img, $sPtsDllType, $pts, $sColorDllType, $color, "int", $lineType, "int", $shift, $sOffsetDllType, $offset), "cveFillPoly", @error)
EndFunc   ;==>_cveFillPoly

Func _cveFillPolyTyped($typeOfImg, $img, $typeOfPts, $pts, $color, $lineType = $CV_LINE_8, $shift = 0, $offset = _cvPoint())

    Local $ioArrImg, $vectorImg, $iArrImgSize
    Local $bImgIsArray = IsArray($img)
    Local $bImgCreate = IsDllStruct($img) And $typeOfImg == "Scalar"

    If $typeOfImg == Default Then
        $ioArrImg = $img
    ElseIf $bImgIsArray Then
        $vectorImg = Call("_VectorOf" & $typeOfImg & "Create")

        $iArrImgSize = UBound($img)
        For $i = 0 To $iArrImgSize - 1
            Call("_VectorOf" & $typeOfImg & "Push", $vectorImg, $img[$i])
        Next

        $ioArrImg = Call("_cveInputOutputArrayFromVectorOf" & $typeOfImg, $vectorImg)
    Else
        If $bImgCreate Then
            $img = Call("_cve" & $typeOfImg & "Create", $img)
        EndIf
        $ioArrImg = Call("_cveInputOutputArrayFrom" & $typeOfImg, $img)
    EndIf

    Local $iArrPts, $vectorPts, $iArrPtsSize
    Local $bPtsIsArray = IsArray($pts)
    Local $bPtsCreate = IsDllStruct($pts) And $typeOfPts == "Scalar"

    If $typeOfPts == Default Then
        $iArrPts = $pts
    ElseIf $bPtsIsArray Then
        $vectorPts = Call("_VectorOf" & $typeOfPts & "Create")

        $iArrPtsSize = UBound($pts)
        For $i = 0 To $iArrPtsSize - 1
            Call("_VectorOf" & $typeOfPts & "Push", $vectorPts, $pts[$i])
        Next

        $iArrPts = Call("_cveInputArrayFromVectorOf" & $typeOfPts, $vectorPts)
    Else
        If $bPtsCreate Then
            $pts = Call("_cve" & $typeOfPts & "Create", $pts)
        EndIf
        $iArrPts = Call("_cveInputArrayFrom" & $typeOfPts, $pts)
    EndIf

    _cveFillPoly($ioArrImg, $iArrPts, $color, $lineType, $shift, $offset)

    If $bPtsIsArray Then
        Call("_VectorOf" & $typeOfPts & "Release", $vectorPts)
    EndIf

    If $typeOfPts <> Default Then
        _cveInputArrayRelease($iArrPts)
        If $bPtsCreate Then
            Call("_cve" & $typeOfPts & "Release", $pts)
        EndIf
    EndIf

    If $bImgIsArray Then
        Call("_VectorOf" & $typeOfImg & "Release", $vectorImg)
    EndIf

    If $typeOfImg <> Default Then
        _cveInputOutputArrayRelease($ioArrImg)
        If $bImgCreate Then
            Call("_cve" & $typeOfImg & "Release", $img)
        EndIf
    EndIf
EndFunc   ;==>_cveFillPolyTyped

Func _cveFillPolyMat($img, $pts, $color, $lineType = $CV_LINE_8, $shift = 0, $offset = _cvPoint())
    ; cveFillPoly using cv::Mat instead of _*Array
    _cveFillPolyTyped("Mat", $img, "Mat", $pts, $color, $lineType, $shift, $offset)
EndFunc   ;==>_cveFillPolyMat

Func _cvePolylines($img, $pts, $isClosed, $color, $thickness = 1, $lineType = $CV_LINE_8, $shift = 0)
    ; CVAPI(void) cvePolylines(cv::_InputOutputArray* img, cv::_InputArray* pts, bool isClosed, const CvScalar* color, int thickness, int lineType, int shift);

    Local $sImgDllType
    If IsDllStruct($img) Then
        $sImgDllType = "struct*"
    Else
        $sImgDllType = "ptr"
    EndIf

    Local $sPtsDllType
    If IsDllStruct($pts) Then
        $sPtsDllType = "struct*"
    Else
        $sPtsDllType = "ptr"
    EndIf

    Local $sColorDllType
    If IsDllStruct($color) Then
        $sColorDllType = "struct*"
    Else
        $sColorDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cvePolylines", $sImgDllType, $img, $sPtsDllType, $pts, "boolean", $isClosed, $sColorDllType, $color, "int", $thickness, "int", $lineType, "int", $shift), "cvePolylines", @error)
EndFunc   ;==>_cvePolylines

Func _cvePolylinesTyped($typeOfImg, $img, $typeOfPts, $pts, $isClosed, $color, $thickness = 1, $lineType = $CV_LINE_8, $shift = 0)

    Local $ioArrImg, $vectorImg, $iArrImgSize
    Local $bImgIsArray = IsArray($img)
    Local $bImgCreate = IsDllStruct($img) And $typeOfImg == "Scalar"

    If $typeOfImg == Default Then
        $ioArrImg = $img
    ElseIf $bImgIsArray Then
        $vectorImg = Call("_VectorOf" & $typeOfImg & "Create")

        $iArrImgSize = UBound($img)
        For $i = 0 To $iArrImgSize - 1
            Call("_VectorOf" & $typeOfImg & "Push", $vectorImg, $img[$i])
        Next

        $ioArrImg = Call("_cveInputOutputArrayFromVectorOf" & $typeOfImg, $vectorImg)
    Else
        If $bImgCreate Then
            $img = Call("_cve" & $typeOfImg & "Create", $img)
        EndIf
        $ioArrImg = Call("_cveInputOutputArrayFrom" & $typeOfImg, $img)
    EndIf

    Local $iArrPts, $vectorPts, $iArrPtsSize
    Local $bPtsIsArray = IsArray($pts)
    Local $bPtsCreate = IsDllStruct($pts) And $typeOfPts == "Scalar"

    If $typeOfPts == Default Then
        $iArrPts = $pts
    ElseIf $bPtsIsArray Then
        $vectorPts = Call("_VectorOf" & $typeOfPts & "Create")

        $iArrPtsSize = UBound($pts)
        For $i = 0 To $iArrPtsSize - 1
            Call("_VectorOf" & $typeOfPts & "Push", $vectorPts, $pts[$i])
        Next

        $iArrPts = Call("_cveInputArrayFromVectorOf" & $typeOfPts, $vectorPts)
    Else
        If $bPtsCreate Then
            $pts = Call("_cve" & $typeOfPts & "Create", $pts)
        EndIf
        $iArrPts = Call("_cveInputArrayFrom" & $typeOfPts, $pts)
    EndIf

    _cvePolylines($ioArrImg, $iArrPts, $isClosed, $color, $thickness, $lineType, $shift)

    If $bPtsIsArray Then
        Call("_VectorOf" & $typeOfPts & "Release", $vectorPts)
    EndIf

    If $typeOfPts <> Default Then
        _cveInputArrayRelease($iArrPts)
        If $bPtsCreate Then
            Call("_cve" & $typeOfPts & "Release", $pts)
        EndIf
    EndIf

    If $bImgIsArray Then
        Call("_VectorOf" & $typeOfImg & "Release", $vectorImg)
    EndIf

    If $typeOfImg <> Default Then
        _cveInputOutputArrayRelease($ioArrImg)
        If $bImgCreate Then
            Call("_cve" & $typeOfImg & "Release", $img)
        EndIf
    EndIf
EndFunc   ;==>_cvePolylinesTyped

Func _cvePolylinesMat($img, $pts, $isClosed, $color, $thickness = 1, $lineType = $CV_LINE_8, $shift = 0)
    ; cvePolylines using cv::Mat instead of _*Array
    _cvePolylinesTyped("Mat", $img, "Mat", $pts, $isClosed, $color, $thickness, $lineType, $shift)
EndFunc   ;==>_cvePolylinesMat

Func _cveEllipse($img, $center, $axes, $angle, $startAngle, $endAngle, $color, $thickness = 1, $lineType = $CV_LINE_8, $shift = 0)
    ; CVAPI(void) cveEllipse(cv::_InputOutputArray* img, CvPoint* center, CvSize* axes, double angle, double startAngle, double endAngle, const CvScalar* color, int thickness, int lineType, int shift);

    Local $sImgDllType
    If IsDllStruct($img) Then
        $sImgDllType = "struct*"
    Else
        $sImgDllType = "ptr"
    EndIf

    Local $sCenterDllType
    If IsDllStruct($center) Then
        $sCenterDllType = "struct*"
    Else
        $sCenterDllType = "ptr"
    EndIf

    Local $sAxesDllType
    If IsDllStruct($axes) Then
        $sAxesDllType = "struct*"
    Else
        $sAxesDllType = "ptr"
    EndIf

    Local $sColorDllType
    If IsDllStruct($color) Then
        $sColorDllType = "struct*"
    Else
        $sColorDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveEllipse", $sImgDllType, $img, $sCenterDllType, $center, $sAxesDllType, $axes, "double", $angle, "double", $startAngle, "double", $endAngle, $sColorDllType, $color, "int", $thickness, "int", $lineType, "int", $shift), "cveEllipse", @error)
EndFunc   ;==>_cveEllipse

Func _cveEllipseTyped($typeOfImg, $img, $center, $axes, $angle, $startAngle, $endAngle, $color, $thickness = 1, $lineType = $CV_LINE_8, $shift = 0)

    Local $ioArrImg, $vectorImg, $iArrImgSize
    Local $bImgIsArray = IsArray($img)
    Local $bImgCreate = IsDllStruct($img) And $typeOfImg == "Scalar"

    If $typeOfImg == Default Then
        $ioArrImg = $img
    ElseIf $bImgIsArray Then
        $vectorImg = Call("_VectorOf" & $typeOfImg & "Create")

        $iArrImgSize = UBound($img)
        For $i = 0 To $iArrImgSize - 1
            Call("_VectorOf" & $typeOfImg & "Push", $vectorImg, $img[$i])
        Next

        $ioArrImg = Call("_cveInputOutputArrayFromVectorOf" & $typeOfImg, $vectorImg)
    Else
        If $bImgCreate Then
            $img = Call("_cve" & $typeOfImg & "Create", $img)
        EndIf
        $ioArrImg = Call("_cveInputOutputArrayFrom" & $typeOfImg, $img)
    EndIf

    _cveEllipse($ioArrImg, $center, $axes, $angle, $startAngle, $endAngle, $color, $thickness, $lineType, $shift)

    If $bImgIsArray Then
        Call("_VectorOf" & $typeOfImg & "Release", $vectorImg)
    EndIf

    If $typeOfImg <> Default Then
        _cveInputOutputArrayRelease($ioArrImg)
        If $bImgCreate Then
            Call("_cve" & $typeOfImg & "Release", $img)
        EndIf
    EndIf
EndFunc   ;==>_cveEllipseTyped

Func _cveEllipseMat($img, $center, $axes, $angle, $startAngle, $endAngle, $color, $thickness = 1, $lineType = $CV_LINE_8, $shift = 0)
    ; cveEllipse using cv::Mat instead of _*Array
    _cveEllipseTyped("Mat", $img, $center, $axes, $angle, $startAngle, $endAngle, $color, $thickness, $lineType, $shift)
EndFunc   ;==>_cveEllipseMat

Func _cveDrawMarker($img, $position, $color, $markerType, $markerSize, $thickness, $lineType)
    ; CVAPI(void) cveDrawMarker(cv::_InputOutputArray* img, CvPoint* position, CvScalar* color, int markerType, int markerSize, int thickness, int lineType);

    Local $sImgDllType
    If IsDllStruct($img) Then
        $sImgDllType = "struct*"
    Else
        $sImgDllType = "ptr"
    EndIf

    Local $sPositionDllType
    If IsDllStruct($position) Then
        $sPositionDllType = "struct*"
    Else
        $sPositionDllType = "ptr"
    EndIf

    Local $sColorDllType
    If IsDllStruct($color) Then
        $sColorDllType = "struct*"
    Else
        $sColorDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDrawMarker", $sImgDllType, $img, $sPositionDllType, $position, $sColorDllType, $color, "int", $markerType, "int", $markerSize, "int", $thickness, "int", $lineType), "cveDrawMarker", @error)
EndFunc   ;==>_cveDrawMarker

Func _cveDrawMarkerTyped($typeOfImg, $img, $position, $color, $markerType, $markerSize, $thickness, $lineType)

    Local $ioArrImg, $vectorImg, $iArrImgSize
    Local $bImgIsArray = IsArray($img)
    Local $bImgCreate = IsDllStruct($img) And $typeOfImg == "Scalar"

    If $typeOfImg == Default Then
        $ioArrImg = $img
    ElseIf $bImgIsArray Then
        $vectorImg = Call("_VectorOf" & $typeOfImg & "Create")

        $iArrImgSize = UBound($img)
        For $i = 0 To $iArrImgSize - 1
            Call("_VectorOf" & $typeOfImg & "Push", $vectorImg, $img[$i])
        Next

        $ioArrImg = Call("_cveInputOutputArrayFromVectorOf" & $typeOfImg, $vectorImg)
    Else
        If $bImgCreate Then
            $img = Call("_cve" & $typeOfImg & "Create", $img)
        EndIf
        $ioArrImg = Call("_cveInputOutputArrayFrom" & $typeOfImg, $img)
    EndIf

    _cveDrawMarker($ioArrImg, $position, $color, $markerType, $markerSize, $thickness, $lineType)

    If $bImgIsArray Then
        Call("_VectorOf" & $typeOfImg & "Release", $vectorImg)
    EndIf

    If $typeOfImg <> Default Then
        _cveInputOutputArrayRelease($ioArrImg)
        If $bImgCreate Then
            Call("_cve" & $typeOfImg & "Release", $img)
        EndIf
    EndIf
EndFunc   ;==>_cveDrawMarkerTyped

Func _cveDrawMarkerMat($img, $position, $color, $markerType, $markerSize, $thickness, $lineType)
    ; cveDrawMarker using cv::Mat instead of _*Array
    _cveDrawMarkerTyped("Mat", $img, $position, $color, $markerType, $markerSize, $thickness, $lineType)
EndFunc   ;==>_cveDrawMarkerMat

Func _cveApplyColorMap1($src, $dst, $colorMap)
    ; CVAPI(void) cveApplyColorMap1(cv::_InputArray* src, cv::_OutputArray* dst, int colorMap);

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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveApplyColorMap1", $sSrcDllType, $src, $sDstDllType, $dst, "int", $colorMap), "cveApplyColorMap1", @error)
EndFunc   ;==>_cveApplyColorMap1

Func _cveApplyColorMap1Typed($typeOfSrc, $src, $typeOfDst, $dst, $colorMap)

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

    _cveApplyColorMap1($iArrSrc, $oArrDst, $colorMap)

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
EndFunc   ;==>_cveApplyColorMap1Typed

Func _cveApplyColorMap1Mat($src, $dst, $colorMap)
    ; cveApplyColorMap1 using cv::Mat instead of _*Array
    _cveApplyColorMap1Typed("Mat", $src, "Mat", $dst, $colorMap)
EndFunc   ;==>_cveApplyColorMap1Mat

Func _cveApplyColorMap2($src, $dst, $userColorMap)
    ; CVAPI(void) cveApplyColorMap2(cv::_InputArray* src, cv::_OutputArray* dst, cv::_InputArray userColorMap);

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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveApplyColorMap2", $sSrcDllType, $src, $sDstDllType, $dst, "ptr", $userColorMap), "cveApplyColorMap2", @error)
EndFunc   ;==>_cveApplyColorMap2

Func _cveApplyColorMap2Typed($typeOfSrc, $src, $typeOfDst, $dst, $userColorMap)

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

    _cveApplyColorMap2($iArrSrc, $oArrDst, $userColorMap)

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
EndFunc   ;==>_cveApplyColorMap2Typed

Func _cveApplyColorMap2Mat($src, $dst, $userColorMap)
    ; cveApplyColorMap2 using cv::Mat instead of _*Array
    _cveApplyColorMap2Typed("Mat", $src, "Mat", $dst, $userColorMap)
EndFunc   ;==>_cveApplyColorMap2Mat

Func _cveDistanceTransform($src, $dst, $labels, $distanceType, $maskSize, $labelType)
    ; CVAPI(void) cveDistanceTransform(cv::_InputArray* src, cv::_OutputArray* dst, cv::_OutputArray* labels, int distanceType, int maskSize, int labelType);

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

    Local $sLabelsDllType
    If IsDllStruct($labels) Then
        $sLabelsDllType = "struct*"
    Else
        $sLabelsDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDistanceTransform", $sSrcDllType, $src, $sDstDllType, $dst, $sLabelsDllType, $labels, "int", $distanceType, "int", $maskSize, "int", $labelType), "cveDistanceTransform", @error)
EndFunc   ;==>_cveDistanceTransform

Func _cveDistanceTransformTyped($typeOfSrc, $src, $typeOfDst, $dst, $typeOfLabels, $labels, $distanceType, $maskSize, $labelType)

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

    Local $oArrLabels, $vectorLabels, $iArrLabelsSize
    Local $bLabelsIsArray = IsArray($labels)
    Local $bLabelsCreate = IsDllStruct($labels) And $typeOfLabels == "Scalar"

    If $typeOfLabels == Default Then
        $oArrLabels = $labels
    ElseIf $bLabelsIsArray Then
        $vectorLabels = Call("_VectorOf" & $typeOfLabels & "Create")

        $iArrLabelsSize = UBound($labels)
        For $i = 0 To $iArrLabelsSize - 1
            Call("_VectorOf" & $typeOfLabels & "Push", $vectorLabels, $labels[$i])
        Next

        $oArrLabels = Call("_cveOutputArrayFromVectorOf" & $typeOfLabels, $vectorLabels)
    Else
        If $bLabelsCreate Then
            $labels = Call("_cve" & $typeOfLabels & "Create", $labels)
        EndIf
        $oArrLabels = Call("_cveOutputArrayFrom" & $typeOfLabels, $labels)
    EndIf

    _cveDistanceTransform($iArrSrc, $oArrDst, $oArrLabels, $distanceType, $maskSize, $labelType)

    If $bLabelsIsArray Then
        Call("_VectorOf" & $typeOfLabels & "Release", $vectorLabels)
    EndIf

    If $typeOfLabels <> Default Then
        _cveOutputArrayRelease($oArrLabels)
        If $bLabelsCreate Then
            Call("_cve" & $typeOfLabels & "Release", $labels)
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
EndFunc   ;==>_cveDistanceTransformTyped

Func _cveDistanceTransformMat($src, $dst, $labels, $distanceType, $maskSize, $labelType)
    ; cveDistanceTransform using cv::Mat instead of _*Array
    _cveDistanceTransformTyped("Mat", $src, "Mat", $dst, "Mat", $labels, $distanceType, $maskSize, $labelType)
EndFunc   ;==>_cveDistanceTransformMat

Func _cveGetRectSubPix($image, $patchSize, $center, $patch, $patchType = -1)
    ; CVAPI(void) cveGetRectSubPix(cv::_InputArray* image, CvSize* patchSize, CvPoint2D32f* center, cv::_OutputArray* patch, int patchType);

    Local $sImageDllType
    If IsDllStruct($image) Then
        $sImageDllType = "struct*"
    Else
        $sImageDllType = "ptr"
    EndIf

    Local $sPatchSizeDllType
    If IsDllStruct($patchSize) Then
        $sPatchSizeDllType = "struct*"
    Else
        $sPatchSizeDllType = "ptr"
    EndIf

    Local $sCenterDllType
    If IsDllStruct($center) Then
        $sCenterDllType = "struct*"
    Else
        $sCenterDllType = "ptr"
    EndIf

    Local $sPatchDllType
    If IsDllStruct($patch) Then
        $sPatchDllType = "struct*"
    Else
        $sPatchDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveGetRectSubPix", $sImageDllType, $image, $sPatchSizeDllType, $patchSize, $sCenterDllType, $center, $sPatchDllType, $patch, "int", $patchType), "cveGetRectSubPix", @error)
EndFunc   ;==>_cveGetRectSubPix

Func _cveGetRectSubPixTyped($typeOfImage, $image, $patchSize, $center, $typeOfPatch, $patch, $patchType = -1)

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

    Local $oArrPatch, $vectorPatch, $iArrPatchSize
    Local $bPatchIsArray = IsArray($patch)
    Local $bPatchCreate = IsDllStruct($patch) And $typeOfPatch == "Scalar"

    If $typeOfPatch == Default Then
        $oArrPatch = $patch
    ElseIf $bPatchIsArray Then
        $vectorPatch = Call("_VectorOf" & $typeOfPatch & "Create")

        $iArrPatchSize = UBound($patch)
        For $i = 0 To $iArrPatchSize - 1
            Call("_VectorOf" & $typeOfPatch & "Push", $vectorPatch, $patch[$i])
        Next

        $oArrPatch = Call("_cveOutputArrayFromVectorOf" & $typeOfPatch, $vectorPatch)
    Else
        If $bPatchCreate Then
            $patch = Call("_cve" & $typeOfPatch & "Create", $patch)
        EndIf
        $oArrPatch = Call("_cveOutputArrayFrom" & $typeOfPatch, $patch)
    EndIf

    _cveGetRectSubPix($iArrImage, $patchSize, $center, $oArrPatch, $patchType)

    If $bPatchIsArray Then
        Call("_VectorOf" & $typeOfPatch & "Release", $vectorPatch)
    EndIf

    If $typeOfPatch <> Default Then
        _cveOutputArrayRelease($oArrPatch)
        If $bPatchCreate Then
            Call("_cve" & $typeOfPatch & "Release", $patch)
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
EndFunc   ;==>_cveGetRectSubPixTyped

Func _cveGetRectSubPixMat($image, $patchSize, $center, $patch, $patchType = -1)
    ; cveGetRectSubPix using cv::Mat instead of _*Array
    _cveGetRectSubPixTyped("Mat", $image, $patchSize, $center, "Mat", $patch, $patchType)
EndFunc   ;==>_cveGetRectSubPixMat

Func _cveHuMoments($moments, $hu)
    ; CVAPI(void) cveHuMoments(cv::Moments* moments, cv::_OutputArray* hu);

    Local $sMomentsDllType
    If IsDllStruct($moments) Then
        $sMomentsDllType = "struct*"
    Else
        $sMomentsDllType = "ptr"
    EndIf

    Local $sHuDllType
    If IsDllStruct($hu) Then
        $sHuDllType = "struct*"
    Else
        $sHuDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveHuMoments", $sMomentsDllType, $moments, $sHuDllType, $hu), "cveHuMoments", @error)
EndFunc   ;==>_cveHuMoments

Func _cveHuMomentsTyped($moments, $typeOfHu, $hu)

    Local $oArrHu, $vectorHu, $iArrHuSize
    Local $bHuIsArray = IsArray($hu)
    Local $bHuCreate = IsDllStruct($hu) And $typeOfHu == "Scalar"

    If $typeOfHu == Default Then
        $oArrHu = $hu
    ElseIf $bHuIsArray Then
        $vectorHu = Call("_VectorOf" & $typeOfHu & "Create")

        $iArrHuSize = UBound($hu)
        For $i = 0 To $iArrHuSize - 1
            Call("_VectorOf" & $typeOfHu & "Push", $vectorHu, $hu[$i])
        Next

        $oArrHu = Call("_cveOutputArrayFromVectorOf" & $typeOfHu, $vectorHu)
    Else
        If $bHuCreate Then
            $hu = Call("_cve" & $typeOfHu & "Create", $hu)
        EndIf
        $oArrHu = Call("_cveOutputArrayFrom" & $typeOfHu, $hu)
    EndIf

    _cveHuMoments($moments, $oArrHu)

    If $bHuIsArray Then
        Call("_VectorOf" & $typeOfHu & "Release", $vectorHu)
    EndIf

    If $typeOfHu <> Default Then
        _cveOutputArrayRelease($oArrHu)
        If $bHuCreate Then
            Call("_cve" & $typeOfHu & "Release", $hu)
        EndIf
    EndIf
EndFunc   ;==>_cveHuMomentsTyped

Func _cveHuMomentsMat($moments, $hu)
    ; cveHuMoments using cv::Mat instead of _*Array
    _cveHuMomentsTyped($moments, "Mat", $hu)
EndFunc   ;==>_cveHuMomentsMat

Func _cveHuMoments2($moments, $hu)
    ; CVAPI(void) cveHuMoments2(cv::Moments* moments, double* hu);

    Local $sMomentsDllType
    If IsDllStruct($moments) Then
        $sMomentsDllType = "struct*"
    Else
        $sMomentsDllType = "ptr"
    EndIf

    Local $sHuDllType
    If IsDllStruct($hu) Then
        $sHuDllType = "struct*"
    Else
        $sHuDllType = "double*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveHuMoments2", $sMomentsDllType, $moments, $sHuDllType, $hu), "cveHuMoments2", @error)
EndFunc   ;==>_cveHuMoments2

Func _cveMaxRect($rect1, $rect2, $result)
    ; CVAPI(void) cveMaxRect(CvRect* rect1, CvRect* rect2, CvRect* result);

    Local $sRect1DllType
    If IsDllStruct($rect1) Then
        $sRect1DllType = "struct*"
    Else
        $sRect1DllType = "ptr"
    EndIf

    Local $sRect2DllType
    If IsDllStruct($rect2) Then
        $sRect2DllType = "struct*"
    Else
        $sRect2DllType = "ptr"
    EndIf

    Local $sResultDllType
    If IsDllStruct($result) Then
        $sResultDllType = "struct*"
    Else
        $sResultDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMaxRect", $sRect1DllType, $rect1, $sRect2DllType, $rect2, $sResultDllType, $result), "cveMaxRect", @error)
EndFunc   ;==>_cveMaxRect

Func _cveConnectedComponents($image, $labels, $connectivity, $ltype, $ccltype)
    ; CVAPI(int) cveConnectedComponents(cv::_InputArray* image, cv::_OutputArray* labels, int connectivity, int ltype, int ccltype);

    Local $sImageDllType
    If IsDllStruct($image) Then
        $sImageDllType = "struct*"
    Else
        $sImageDllType = "ptr"
    EndIf

    Local $sLabelsDllType
    If IsDllStruct($labels) Then
        $sLabelsDllType = "struct*"
    Else
        $sLabelsDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveConnectedComponents", $sImageDllType, $image, $sLabelsDllType, $labels, "int", $connectivity, "int", $ltype, "int", $ccltype), "cveConnectedComponents", @error)
EndFunc   ;==>_cveConnectedComponents

Func _cveConnectedComponentsTyped($typeOfImage, $image, $typeOfLabels, $labels, $connectivity, $ltype, $ccltype)

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

    Local $oArrLabels, $vectorLabels, $iArrLabelsSize
    Local $bLabelsIsArray = IsArray($labels)
    Local $bLabelsCreate = IsDllStruct($labels) And $typeOfLabels == "Scalar"

    If $typeOfLabels == Default Then
        $oArrLabels = $labels
    ElseIf $bLabelsIsArray Then
        $vectorLabels = Call("_VectorOf" & $typeOfLabels & "Create")

        $iArrLabelsSize = UBound($labels)
        For $i = 0 To $iArrLabelsSize - 1
            Call("_VectorOf" & $typeOfLabels & "Push", $vectorLabels, $labels[$i])
        Next

        $oArrLabels = Call("_cveOutputArrayFromVectorOf" & $typeOfLabels, $vectorLabels)
    Else
        If $bLabelsCreate Then
            $labels = Call("_cve" & $typeOfLabels & "Create", $labels)
        EndIf
        $oArrLabels = Call("_cveOutputArrayFrom" & $typeOfLabels, $labels)
    EndIf

    Local $retval = _cveConnectedComponents($iArrImage, $oArrLabels, $connectivity, $ltype, $ccltype)

    If $bLabelsIsArray Then
        Call("_VectorOf" & $typeOfLabels & "Release", $vectorLabels)
    EndIf

    If $typeOfLabels <> Default Then
        _cveOutputArrayRelease($oArrLabels)
        If $bLabelsCreate Then
            Call("_cve" & $typeOfLabels & "Release", $labels)
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

    Return $retval
EndFunc   ;==>_cveConnectedComponentsTyped

Func _cveConnectedComponentsMat($image, $labels, $connectivity, $ltype, $ccltype)
    ; cveConnectedComponents using cv::Mat instead of _*Array
    Local $retval = _cveConnectedComponentsTyped("Mat", $image, "Mat", $labels, $connectivity, $ltype, $ccltype)

    Return $retval
EndFunc   ;==>_cveConnectedComponentsMat

Func _cveConnectedComponentsWithStats($image, $labels, $stats, $centroids, $connectivity, $ltype, $ccltype)
    ; CVAPI(int) cveConnectedComponentsWithStats(cv::_InputArray* image, cv::_OutputArray* labels, cv::_OutputArray* stats, cv::_OutputArray* centroids, int connectivity, int ltype, int ccltype);

    Local $sImageDllType
    If IsDllStruct($image) Then
        $sImageDllType = "struct*"
    Else
        $sImageDllType = "ptr"
    EndIf

    Local $sLabelsDllType
    If IsDllStruct($labels) Then
        $sLabelsDllType = "struct*"
    Else
        $sLabelsDllType = "ptr"
    EndIf

    Local $sStatsDllType
    If IsDllStruct($stats) Then
        $sStatsDllType = "struct*"
    Else
        $sStatsDllType = "ptr"
    EndIf

    Local $sCentroidsDllType
    If IsDllStruct($centroids) Then
        $sCentroidsDllType = "struct*"
    Else
        $sCentroidsDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveConnectedComponentsWithStats", $sImageDllType, $image, $sLabelsDllType, $labels, $sStatsDllType, $stats, $sCentroidsDllType, $centroids, "int", $connectivity, "int", $ltype, "int", $ccltype), "cveConnectedComponentsWithStats", @error)
EndFunc   ;==>_cveConnectedComponentsWithStats

Func _cveConnectedComponentsWithStatsTyped($typeOfImage, $image, $typeOfLabels, $labels, $typeOfStats, $stats, $typeOfCentroids, $centroids, $connectivity, $ltype, $ccltype)

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

    Local $oArrLabels, $vectorLabels, $iArrLabelsSize
    Local $bLabelsIsArray = IsArray($labels)
    Local $bLabelsCreate = IsDllStruct($labels) And $typeOfLabels == "Scalar"

    If $typeOfLabels == Default Then
        $oArrLabels = $labels
    ElseIf $bLabelsIsArray Then
        $vectorLabels = Call("_VectorOf" & $typeOfLabels & "Create")

        $iArrLabelsSize = UBound($labels)
        For $i = 0 To $iArrLabelsSize - 1
            Call("_VectorOf" & $typeOfLabels & "Push", $vectorLabels, $labels[$i])
        Next

        $oArrLabels = Call("_cveOutputArrayFromVectorOf" & $typeOfLabels, $vectorLabels)
    Else
        If $bLabelsCreate Then
            $labels = Call("_cve" & $typeOfLabels & "Create", $labels)
        EndIf
        $oArrLabels = Call("_cveOutputArrayFrom" & $typeOfLabels, $labels)
    EndIf

    Local $oArrStats, $vectorStats, $iArrStatsSize
    Local $bStatsIsArray = IsArray($stats)
    Local $bStatsCreate = IsDllStruct($stats) And $typeOfStats == "Scalar"

    If $typeOfStats == Default Then
        $oArrStats = $stats
    ElseIf $bStatsIsArray Then
        $vectorStats = Call("_VectorOf" & $typeOfStats & "Create")

        $iArrStatsSize = UBound($stats)
        For $i = 0 To $iArrStatsSize - 1
            Call("_VectorOf" & $typeOfStats & "Push", $vectorStats, $stats[$i])
        Next

        $oArrStats = Call("_cveOutputArrayFromVectorOf" & $typeOfStats, $vectorStats)
    Else
        If $bStatsCreate Then
            $stats = Call("_cve" & $typeOfStats & "Create", $stats)
        EndIf
        $oArrStats = Call("_cveOutputArrayFrom" & $typeOfStats, $stats)
    EndIf

    Local $oArrCentroids, $vectorCentroids, $iArrCentroidsSize
    Local $bCentroidsIsArray = IsArray($centroids)
    Local $bCentroidsCreate = IsDllStruct($centroids) And $typeOfCentroids == "Scalar"

    If $typeOfCentroids == Default Then
        $oArrCentroids = $centroids
    ElseIf $bCentroidsIsArray Then
        $vectorCentroids = Call("_VectorOf" & $typeOfCentroids & "Create")

        $iArrCentroidsSize = UBound($centroids)
        For $i = 0 To $iArrCentroidsSize - 1
            Call("_VectorOf" & $typeOfCentroids & "Push", $vectorCentroids, $centroids[$i])
        Next

        $oArrCentroids = Call("_cveOutputArrayFromVectorOf" & $typeOfCentroids, $vectorCentroids)
    Else
        If $bCentroidsCreate Then
            $centroids = Call("_cve" & $typeOfCentroids & "Create", $centroids)
        EndIf
        $oArrCentroids = Call("_cveOutputArrayFrom" & $typeOfCentroids, $centroids)
    EndIf

    Local $retval = _cveConnectedComponentsWithStats($iArrImage, $oArrLabels, $oArrStats, $oArrCentroids, $connectivity, $ltype, $ccltype)

    If $bCentroidsIsArray Then
        Call("_VectorOf" & $typeOfCentroids & "Release", $vectorCentroids)
    EndIf

    If $typeOfCentroids <> Default Then
        _cveOutputArrayRelease($oArrCentroids)
        If $bCentroidsCreate Then
            Call("_cve" & $typeOfCentroids & "Release", $centroids)
        EndIf
    EndIf

    If $bStatsIsArray Then
        Call("_VectorOf" & $typeOfStats & "Release", $vectorStats)
    EndIf

    If $typeOfStats <> Default Then
        _cveOutputArrayRelease($oArrStats)
        If $bStatsCreate Then
            Call("_cve" & $typeOfStats & "Release", $stats)
        EndIf
    EndIf

    If $bLabelsIsArray Then
        Call("_VectorOf" & $typeOfLabels & "Release", $vectorLabels)
    EndIf

    If $typeOfLabels <> Default Then
        _cveOutputArrayRelease($oArrLabels)
        If $bLabelsCreate Then
            Call("_cve" & $typeOfLabels & "Release", $labels)
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

    Return $retval
EndFunc   ;==>_cveConnectedComponentsWithStatsTyped

Func _cveConnectedComponentsWithStatsMat($image, $labels, $stats, $centroids, $connectivity, $ltype, $ccltype)
    ; cveConnectedComponentsWithStats using cv::Mat instead of _*Array
    Local $retval = _cveConnectedComponentsWithStatsTyped("Mat", $image, "Mat", $labels, "Mat", $stats, "Mat", $centroids, $connectivity, $ltype, $ccltype)

    Return $retval
EndFunc   ;==>_cveConnectedComponentsWithStatsMat

Func _cveIntelligentScissorsMBCreate()
    ; CVAPI(cv::segmentation::IntelligentScissorsMB*) cveIntelligentScissorsMBCreate();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveIntelligentScissorsMBCreate"), "cveIntelligentScissorsMBCreate", @error)
EndFunc   ;==>_cveIntelligentScissorsMBCreate

Func _cveIntelligentScissorsMBRelease($ptr)
    ; CVAPI(void) cveIntelligentScissorsMBRelease(cv::segmentation::IntelligentScissorsMB** ptr);

    Local $sPtrDllType
    If IsDllStruct($ptr) Then
        $sPtrDllType = "struct*"
    ElseIf $ptr == Null Then
        $sPtrDllType = "ptr"
    Else
        $sPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveIntelligentScissorsMBRelease", $sPtrDllType, $ptr), "cveIntelligentScissorsMBRelease", @error)
EndFunc   ;==>_cveIntelligentScissorsMBRelease

Func _cveIntelligentScissorsMBSetWeights($ptr, $weightNonEdge, $weightGradientDirection, $weightGradientMagnitude)
    ; CVAPI(void) cveIntelligentScissorsMBSetWeights(cv::segmentation::IntelligentScissorsMB* ptr, float weightNonEdge, float weightGradientDirection, float weightGradientMagnitude);

    Local $sPtrDllType
    If IsDllStruct($ptr) Then
        $sPtrDllType = "struct*"
    Else
        $sPtrDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveIntelligentScissorsMBSetWeights", $sPtrDllType, $ptr, "float", $weightNonEdge, "float", $weightGradientDirection, "float", $weightGradientMagnitude), "cveIntelligentScissorsMBSetWeights", @error)
EndFunc   ;==>_cveIntelligentScissorsMBSetWeights

Func _cveIntelligentScissorsMBSetEdgeFeatureCannyParameters($ptr, $threshold1, $threshold2, $apertureSize, $L2gradient)
    ; CVAPI(void) cveIntelligentScissorsMBSetEdgeFeatureCannyParameters(cv::segmentation::IntelligentScissorsMB* ptr, double threshold1, double threshold2, int apertureSize, bool L2gradient);

    Local $sPtrDllType
    If IsDllStruct($ptr) Then
        $sPtrDllType = "struct*"
    Else
        $sPtrDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveIntelligentScissorsMBSetEdgeFeatureCannyParameters", $sPtrDllType, $ptr, "double", $threshold1, "double", $threshold2, "int", $apertureSize, "boolean", $L2gradient), "cveIntelligentScissorsMBSetEdgeFeatureCannyParameters", @error)
EndFunc   ;==>_cveIntelligentScissorsMBSetEdgeFeatureCannyParameters

Func _cveIntelligentScissorsMBApplyImage($ptr, $image)
    ; CVAPI(void) cveIntelligentScissorsMBApplyImage(cv::segmentation::IntelligentScissorsMB* ptr, cv::_InputArray* image);

    Local $sPtrDllType
    If IsDllStruct($ptr) Then
        $sPtrDllType = "struct*"
    Else
        $sPtrDllType = "ptr"
    EndIf

    Local $sImageDllType
    If IsDllStruct($image) Then
        $sImageDllType = "struct*"
    Else
        $sImageDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveIntelligentScissorsMBApplyImage", $sPtrDllType, $ptr, $sImageDllType, $image), "cveIntelligentScissorsMBApplyImage", @error)
EndFunc   ;==>_cveIntelligentScissorsMBApplyImage

Func _cveIntelligentScissorsMBApplyImageTyped($ptr, $typeOfImage, $image)

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

    _cveIntelligentScissorsMBApplyImage($ptr, $iArrImage)

    If $bImageIsArray Then
        Call("_VectorOf" & $typeOfImage & "Release", $vectorImage)
    EndIf

    If $typeOfImage <> Default Then
        _cveInputArrayRelease($iArrImage)
        If $bImageCreate Then
            Call("_cve" & $typeOfImage & "Release", $image)
        EndIf
    EndIf
EndFunc   ;==>_cveIntelligentScissorsMBApplyImageTyped

Func _cveIntelligentScissorsMBApplyImageMat($ptr, $image)
    ; cveIntelligentScissorsMBApplyImage using cv::Mat instead of _*Array
    _cveIntelligentScissorsMBApplyImageTyped($ptr, "Mat", $image)
EndFunc   ;==>_cveIntelligentScissorsMBApplyImageMat

Func _cveIntelligentScissorsMBApplyImageFeatures($ptr, $nonEdge, $gradientDirection, $gradientMagnitude, $image)
    ; CVAPI(void) cveIntelligentScissorsMBApplyImageFeatures(cv::segmentation::IntelligentScissorsMB* ptr, cv::_InputArray* nonEdge, cv::_InputArray* gradientDirection, cv::_InputArray* gradientMagnitude, cv::_InputArray* image);

    Local $sPtrDllType
    If IsDllStruct($ptr) Then
        $sPtrDllType = "struct*"
    Else
        $sPtrDllType = "ptr"
    EndIf

    Local $sNonEdgeDllType
    If IsDllStruct($nonEdge) Then
        $sNonEdgeDllType = "struct*"
    Else
        $sNonEdgeDllType = "ptr"
    EndIf

    Local $sGradientDirectionDllType
    If IsDllStruct($gradientDirection) Then
        $sGradientDirectionDllType = "struct*"
    Else
        $sGradientDirectionDllType = "ptr"
    EndIf

    Local $sGradientMagnitudeDllType
    If IsDllStruct($gradientMagnitude) Then
        $sGradientMagnitudeDllType = "struct*"
    Else
        $sGradientMagnitudeDllType = "ptr"
    EndIf

    Local $sImageDllType
    If IsDllStruct($image) Then
        $sImageDllType = "struct*"
    Else
        $sImageDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveIntelligentScissorsMBApplyImageFeatures", $sPtrDllType, $ptr, $sNonEdgeDllType, $nonEdge, $sGradientDirectionDllType, $gradientDirection, $sGradientMagnitudeDllType, $gradientMagnitude, $sImageDllType, $image), "cveIntelligentScissorsMBApplyImageFeatures", @error)
EndFunc   ;==>_cveIntelligentScissorsMBApplyImageFeatures

Func _cveIntelligentScissorsMBApplyImageFeaturesTyped($ptr, $typeOfNonEdge, $nonEdge, $typeOfGradientDirection, $gradientDirection, $typeOfGradientMagnitude, $gradientMagnitude, $typeOfImage, $image)

    Local $iArrNonEdge, $vectorNonEdge, $iArrNonEdgeSize
    Local $bNonEdgeIsArray = IsArray($nonEdge)
    Local $bNonEdgeCreate = IsDllStruct($nonEdge) And $typeOfNonEdge == "Scalar"

    If $typeOfNonEdge == Default Then
        $iArrNonEdge = $nonEdge
    ElseIf $bNonEdgeIsArray Then
        $vectorNonEdge = Call("_VectorOf" & $typeOfNonEdge & "Create")

        $iArrNonEdgeSize = UBound($nonEdge)
        For $i = 0 To $iArrNonEdgeSize - 1
            Call("_VectorOf" & $typeOfNonEdge & "Push", $vectorNonEdge, $nonEdge[$i])
        Next

        $iArrNonEdge = Call("_cveInputArrayFromVectorOf" & $typeOfNonEdge, $vectorNonEdge)
    Else
        If $bNonEdgeCreate Then
            $nonEdge = Call("_cve" & $typeOfNonEdge & "Create", $nonEdge)
        EndIf
        $iArrNonEdge = Call("_cveInputArrayFrom" & $typeOfNonEdge, $nonEdge)
    EndIf

    Local $iArrGradientDirection, $vectorGradientDirection, $iArrGradientDirectionSize
    Local $bGradientDirectionIsArray = IsArray($gradientDirection)
    Local $bGradientDirectionCreate = IsDllStruct($gradientDirection) And $typeOfGradientDirection == "Scalar"

    If $typeOfGradientDirection == Default Then
        $iArrGradientDirection = $gradientDirection
    ElseIf $bGradientDirectionIsArray Then
        $vectorGradientDirection = Call("_VectorOf" & $typeOfGradientDirection & "Create")

        $iArrGradientDirectionSize = UBound($gradientDirection)
        For $i = 0 To $iArrGradientDirectionSize - 1
            Call("_VectorOf" & $typeOfGradientDirection & "Push", $vectorGradientDirection, $gradientDirection[$i])
        Next

        $iArrGradientDirection = Call("_cveInputArrayFromVectorOf" & $typeOfGradientDirection, $vectorGradientDirection)
    Else
        If $bGradientDirectionCreate Then
            $gradientDirection = Call("_cve" & $typeOfGradientDirection & "Create", $gradientDirection)
        EndIf
        $iArrGradientDirection = Call("_cveInputArrayFrom" & $typeOfGradientDirection, $gradientDirection)
    EndIf

    Local $iArrGradientMagnitude, $vectorGradientMagnitude, $iArrGradientMagnitudeSize
    Local $bGradientMagnitudeIsArray = IsArray($gradientMagnitude)
    Local $bGradientMagnitudeCreate = IsDllStruct($gradientMagnitude) And $typeOfGradientMagnitude == "Scalar"

    If $typeOfGradientMagnitude == Default Then
        $iArrGradientMagnitude = $gradientMagnitude
    ElseIf $bGradientMagnitudeIsArray Then
        $vectorGradientMagnitude = Call("_VectorOf" & $typeOfGradientMagnitude & "Create")

        $iArrGradientMagnitudeSize = UBound($gradientMagnitude)
        For $i = 0 To $iArrGradientMagnitudeSize - 1
            Call("_VectorOf" & $typeOfGradientMagnitude & "Push", $vectorGradientMagnitude, $gradientMagnitude[$i])
        Next

        $iArrGradientMagnitude = Call("_cveInputArrayFromVectorOf" & $typeOfGradientMagnitude, $vectorGradientMagnitude)
    Else
        If $bGradientMagnitudeCreate Then
            $gradientMagnitude = Call("_cve" & $typeOfGradientMagnitude & "Create", $gradientMagnitude)
        EndIf
        $iArrGradientMagnitude = Call("_cveInputArrayFrom" & $typeOfGradientMagnitude, $gradientMagnitude)
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

    _cveIntelligentScissorsMBApplyImageFeatures($ptr, $iArrNonEdge, $iArrGradientDirection, $iArrGradientMagnitude, $iArrImage)

    If $bImageIsArray Then
        Call("_VectorOf" & $typeOfImage & "Release", $vectorImage)
    EndIf

    If $typeOfImage <> Default Then
        _cveInputArrayRelease($iArrImage)
        If $bImageCreate Then
            Call("_cve" & $typeOfImage & "Release", $image)
        EndIf
    EndIf

    If $bGradientMagnitudeIsArray Then
        Call("_VectorOf" & $typeOfGradientMagnitude & "Release", $vectorGradientMagnitude)
    EndIf

    If $typeOfGradientMagnitude <> Default Then
        _cveInputArrayRelease($iArrGradientMagnitude)
        If $bGradientMagnitudeCreate Then
            Call("_cve" & $typeOfGradientMagnitude & "Release", $gradientMagnitude)
        EndIf
    EndIf

    If $bGradientDirectionIsArray Then
        Call("_VectorOf" & $typeOfGradientDirection & "Release", $vectorGradientDirection)
    EndIf

    If $typeOfGradientDirection <> Default Then
        _cveInputArrayRelease($iArrGradientDirection)
        If $bGradientDirectionCreate Then
            Call("_cve" & $typeOfGradientDirection & "Release", $gradientDirection)
        EndIf
    EndIf

    If $bNonEdgeIsArray Then
        Call("_VectorOf" & $typeOfNonEdge & "Release", $vectorNonEdge)
    EndIf

    If $typeOfNonEdge <> Default Then
        _cveInputArrayRelease($iArrNonEdge)
        If $bNonEdgeCreate Then
            Call("_cve" & $typeOfNonEdge & "Release", $nonEdge)
        EndIf
    EndIf
EndFunc   ;==>_cveIntelligentScissorsMBApplyImageFeaturesTyped

Func _cveIntelligentScissorsMBApplyImageFeaturesMat($ptr, $nonEdge, $gradientDirection, $gradientMagnitude, $image)
    ; cveIntelligentScissorsMBApplyImageFeatures using cv::Mat instead of _*Array
    _cveIntelligentScissorsMBApplyImageFeaturesTyped($ptr, "Mat", $nonEdge, "Mat", $gradientDirection, "Mat", $gradientMagnitude, "Mat", $image)
EndFunc   ;==>_cveIntelligentScissorsMBApplyImageFeaturesMat

Func _cveIntelligentScissorsMBBuildMap($ptr, $sourcePt)
    ; CVAPI(void) cveIntelligentScissorsMBBuildMap(cv::segmentation::IntelligentScissorsMB* ptr, CvPoint* sourcePt);

    Local $sPtrDllType
    If IsDllStruct($ptr) Then
        $sPtrDllType = "struct*"
    Else
        $sPtrDllType = "ptr"
    EndIf

    Local $sSourcePtDllType
    If IsDllStruct($sourcePt) Then
        $sSourcePtDllType = "struct*"
    Else
        $sSourcePtDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveIntelligentScissorsMBBuildMap", $sPtrDllType, $ptr, $sSourcePtDllType, $sourcePt), "cveIntelligentScissorsMBBuildMap", @error)
EndFunc   ;==>_cveIntelligentScissorsMBBuildMap

Func _cveIntelligentScissorsMBGetContour($ptr, $targetPt, $contour, $backward)
    ; CVAPI(void) cveIntelligentScissorsMBGetContour(cv::segmentation::IntelligentScissorsMB* ptr, CvPoint* targetPt, cv::_OutputArray* contour, bool backward);

    Local $sPtrDllType
    If IsDllStruct($ptr) Then
        $sPtrDllType = "struct*"
    Else
        $sPtrDllType = "ptr"
    EndIf

    Local $sTargetPtDllType
    If IsDllStruct($targetPt) Then
        $sTargetPtDllType = "struct*"
    Else
        $sTargetPtDllType = "ptr"
    EndIf

    Local $sContourDllType
    If IsDllStruct($contour) Then
        $sContourDllType = "struct*"
    Else
        $sContourDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveIntelligentScissorsMBGetContour", $sPtrDllType, $ptr, $sTargetPtDllType, $targetPt, $sContourDllType, $contour, "boolean", $backward), "cveIntelligentScissorsMBGetContour", @error)
EndFunc   ;==>_cveIntelligentScissorsMBGetContour

Func _cveIntelligentScissorsMBGetContourTyped($ptr, $targetPt, $typeOfContour, $contour, $backward)

    Local $oArrContour, $vectorContour, $iArrContourSize
    Local $bContourIsArray = IsArray($contour)
    Local $bContourCreate = IsDllStruct($contour) And $typeOfContour == "Scalar"

    If $typeOfContour == Default Then
        $oArrContour = $contour
    ElseIf $bContourIsArray Then
        $vectorContour = Call("_VectorOf" & $typeOfContour & "Create")

        $iArrContourSize = UBound($contour)
        For $i = 0 To $iArrContourSize - 1
            Call("_VectorOf" & $typeOfContour & "Push", $vectorContour, $contour[$i])
        Next

        $oArrContour = Call("_cveOutputArrayFromVectorOf" & $typeOfContour, $vectorContour)
    Else
        If $bContourCreate Then
            $contour = Call("_cve" & $typeOfContour & "Create", $contour)
        EndIf
        $oArrContour = Call("_cveOutputArrayFrom" & $typeOfContour, $contour)
    EndIf

    _cveIntelligentScissorsMBGetContour($ptr, $targetPt, $oArrContour, $backward)

    If $bContourIsArray Then
        Call("_VectorOf" & $typeOfContour & "Release", $vectorContour)
    EndIf

    If $typeOfContour <> Default Then
        _cveOutputArrayRelease($oArrContour)
        If $bContourCreate Then
            Call("_cve" & $typeOfContour & "Release", $contour)
        EndIf
    EndIf
EndFunc   ;==>_cveIntelligentScissorsMBGetContourTyped

Func _cveIntelligentScissorsMBGetContourMat($ptr, $targetPt, $contour, $backward)
    ; cveIntelligentScissorsMBGetContour using cv::Mat instead of _*Array
    _cveIntelligentScissorsMBGetContourTyped($ptr, $targetPt, "Mat", $contour, $backward)
EndFunc   ;==>_cveIntelligentScissorsMBGetContourMat

Func _cveGetGaussianKernel($ksize, $sigma, $ktype, $result)
    ; CVAPI(void) cveGetGaussianKernel(int ksize, double sigma, int ktype, cv::Mat* result);

    Local $sResultDllType
    If IsDllStruct($result) Then
        $sResultDllType = "struct*"
    Else
        $sResultDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveGetGaussianKernel", "int", $ksize, "double", $sigma, "int", $ktype, $sResultDllType, $result), "cveGetGaussianKernel", @error)
EndFunc   ;==>_cveGetGaussianKernel

Func _cveGetDerivKernels($kx, $ky, $dx, $dy, $ksize, $normalize = false, $ktype = $CV_32F)
    ; CVAPI(void) cveGetDerivKernels(cv::_OutputArray* kx, cv::_OutputArray* ky, int dx, int dy, int ksize, bool normalize, int ktype);

    Local $sKxDllType
    If IsDllStruct($kx) Then
        $sKxDllType = "struct*"
    Else
        $sKxDllType = "ptr"
    EndIf

    Local $sKyDllType
    If IsDllStruct($ky) Then
        $sKyDllType = "struct*"
    Else
        $sKyDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveGetDerivKernels", $sKxDllType, $kx, $sKyDllType, $ky, "int", $dx, "int", $dy, "int", $ksize, "boolean", $normalize, "int", $ktype), "cveGetDerivKernels", @error)
EndFunc   ;==>_cveGetDerivKernels

Func _cveGetDerivKernelsTyped($typeOfKx, $kx, $typeOfKy, $ky, $dx, $dy, $ksize, $normalize = false, $ktype = $CV_32F)

    Local $oArrKx, $vectorKx, $iArrKxSize
    Local $bKxIsArray = IsArray($kx)
    Local $bKxCreate = IsDllStruct($kx) And $typeOfKx == "Scalar"

    If $typeOfKx == Default Then
        $oArrKx = $kx
    ElseIf $bKxIsArray Then
        $vectorKx = Call("_VectorOf" & $typeOfKx & "Create")

        $iArrKxSize = UBound($kx)
        For $i = 0 To $iArrKxSize - 1
            Call("_VectorOf" & $typeOfKx & "Push", $vectorKx, $kx[$i])
        Next

        $oArrKx = Call("_cveOutputArrayFromVectorOf" & $typeOfKx, $vectorKx)
    Else
        If $bKxCreate Then
            $kx = Call("_cve" & $typeOfKx & "Create", $kx)
        EndIf
        $oArrKx = Call("_cveOutputArrayFrom" & $typeOfKx, $kx)
    EndIf

    Local $oArrKy, $vectorKy, $iArrKySize
    Local $bKyIsArray = IsArray($ky)
    Local $bKyCreate = IsDllStruct($ky) And $typeOfKy == "Scalar"

    If $typeOfKy == Default Then
        $oArrKy = $ky
    ElseIf $bKyIsArray Then
        $vectorKy = Call("_VectorOf" & $typeOfKy & "Create")

        $iArrKySize = UBound($ky)
        For $i = 0 To $iArrKySize - 1
            Call("_VectorOf" & $typeOfKy & "Push", $vectorKy, $ky[$i])
        Next

        $oArrKy = Call("_cveOutputArrayFromVectorOf" & $typeOfKy, $vectorKy)
    Else
        If $bKyCreate Then
            $ky = Call("_cve" & $typeOfKy & "Create", $ky)
        EndIf
        $oArrKy = Call("_cveOutputArrayFrom" & $typeOfKy, $ky)
    EndIf

    _cveGetDerivKernels($oArrKx, $oArrKy, $dx, $dy, $ksize, $normalize, $ktype)

    If $bKyIsArray Then
        Call("_VectorOf" & $typeOfKy & "Release", $vectorKy)
    EndIf

    If $typeOfKy <> Default Then
        _cveOutputArrayRelease($oArrKy)
        If $bKyCreate Then
            Call("_cve" & $typeOfKy & "Release", $ky)
        EndIf
    EndIf

    If $bKxIsArray Then
        Call("_VectorOf" & $typeOfKx & "Release", $vectorKx)
    EndIf

    If $typeOfKx <> Default Then
        _cveOutputArrayRelease($oArrKx)
        If $bKxCreate Then
            Call("_cve" & $typeOfKx & "Release", $kx)
        EndIf
    EndIf
EndFunc   ;==>_cveGetDerivKernelsTyped

Func _cveGetDerivKernelsMat($kx, $ky, $dx, $dy, $ksize, $normalize = false, $ktype = $CV_32F)
    ; cveGetDerivKernels using cv::Mat instead of _*Array
    _cveGetDerivKernelsTyped("Mat", $kx, "Mat", $ky, $dx, $dy, $ksize, $normalize, $ktype)
EndFunc   ;==>_cveGetDerivKernelsMat

Func _cveGetGaborKernel($ksize, $sigma, $theta, $lambd, $gamma, $psi, $ktype, $result)
    ; CVAPI(void) cveGetGaborKernel(CvSize* ksize, double sigma, double theta, double lambd, double gamma, double psi, int ktype, cv::Mat* result);

    Local $sKsizeDllType
    If IsDllStruct($ksize) Then
        $sKsizeDllType = "struct*"
    Else
        $sKsizeDllType = "ptr"
    EndIf

    Local $sResultDllType
    If IsDllStruct($result) Then
        $sResultDllType = "struct*"
    Else
        $sResultDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveGetGaborKernel", $sKsizeDllType, $ksize, "double", $sigma, "double", $theta, "double", $lambd, "double", $gamma, "double", $psi, "int", $ktype, $sResultDllType, $result), "cveGetGaborKernel", @error)
EndFunc   ;==>_cveGetGaborKernel