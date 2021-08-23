#include-once
#include "..\..\CVEUtils.au3"

Func _cudaCreateSobelFilter($srcType, $dstType, $dx, $dy, $ksize, $scale, $rowBorderType, $columnBorderType, $sharedPtr)
    ; CVAPI(cv::cuda::Filter*) cudaCreateSobelFilter(int srcType, int dstType, int dx, int dy, int ksize, double scale, int rowBorderType, int columnBorderType, cv::Ptr<cv::cuda::Filter>** sharedPtr);

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cudaCreateSobelFilter", "int", $srcType, "int", $dstType, "int", $dx, "int", $dy, "int", $ksize, "double", $scale, "int", $rowBorderType, "int", $columnBorderType, $sSharedPtrDllType, $sharedPtr), "cudaCreateSobelFilter", @error)
EndFunc   ;==>_cudaCreateSobelFilter

Func _cudaCreateGaussianFilter($srcType, $dstType, $ksize, $sigma1, $sigma2, $rowBorderType, $columnBorderType, $sharedPtr)
    ; CVAPI(cv::cuda::Filter*) cudaCreateGaussianFilter(int srcType, int dstType, CvSize* ksize, double sigma1, double sigma2, int rowBorderType, int columnBorderType, cv::Ptr<cv::cuda::Filter>** sharedPtr);

    Local $sKsizeDllType
    If IsDllStruct($ksize) Then
        $sKsizeDllType = "struct*"
    Else
        $sKsizeDllType = "ptr"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cudaCreateGaussianFilter", "int", $srcType, "int", $dstType, $sKsizeDllType, $ksize, "double", $sigma1, "double", $sigma2, "int", $rowBorderType, "int", $columnBorderType, $sSharedPtrDllType, $sharedPtr), "cudaCreateGaussianFilter", @error)
EndFunc   ;==>_cudaCreateGaussianFilter

Func _cudaCreateLaplacianFilter($srcType, $dstType, $ksize, $scale, $borderMode, $borderValue, $sharedPtr)
    ; CVAPI(cv::cuda::Filter*) cudaCreateLaplacianFilter(int srcType, int dstType, int ksize, double scale, int borderMode, CvScalar* borderValue, cv::Ptr<cv::cuda::Filter>** sharedPtr);

    Local $sBorderValueDllType
    If IsDllStruct($borderValue) Then
        $sBorderValueDllType = "struct*"
    Else
        $sBorderValueDllType = "ptr"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cudaCreateLaplacianFilter", "int", $srcType, "int", $dstType, "int", $ksize, "double", $scale, "int", $borderMode, $sBorderValueDllType, $borderValue, $sSharedPtrDllType, $sharedPtr), "cudaCreateLaplacianFilter", @error)
EndFunc   ;==>_cudaCreateLaplacianFilter

Func _cudaCreateLinearFilter($srcType, $dstType, $kernel, $anchor, $borderMode, $borderValue, $sharedPtr)
    ; CVAPI(cv::cuda::Filter*) cudaCreateLinearFilter(int srcType, int dstType, cv::_InputArray* kernel, CvPoint* anchor, int borderMode, CvScalar* borderValue, cv::Ptr<cv::cuda::Filter>** sharedPtr);

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

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cudaCreateLinearFilter", "int", $srcType, "int", $dstType, $sKernelDllType, $kernel, $sAnchorDllType, $anchor, "int", $borderMode, $sBorderValueDllType, $borderValue, $sSharedPtrDllType, $sharedPtr), "cudaCreateLinearFilter", @error)
EndFunc   ;==>_cudaCreateLinearFilter

Func _cudaCreateLinearFilterMat($srcType, $dstType, $matKernel, $anchor, $borderMode, $borderValue, $sharedPtr)
    ; cudaCreateLinearFilter using cv::Mat instead of _*Array

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

    Local $retval = _cudaCreateLinearFilter($srcType, $dstType, $iArrKernel, $anchor, $borderMode, $borderValue, $sharedPtr)

    If $bKernelIsArray Then
        _VectorOfMatRelease($vectorOfMatKernel)
    EndIf

    _cveInputArrayRelease($iArrKernel)

    Return $retval
EndFunc   ;==>_cudaCreateLinearFilterMat

Func _cudaCreateBoxFilter($srcType, $dstType, $ksize, $anchor, $borderMode, $borderValue, $sharedPtr)
    ; CVAPI(cv::cuda::Filter*) cudaCreateBoxFilter(int srcType, int dstType, CvSize* ksize, CvPoint* anchor, int borderMode, CvScalar* borderValue, cv::Ptr<cv::cuda::Filter>** sharedPtr);

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

    Local $sBorderValueDllType
    If IsDllStruct($borderValue) Then
        $sBorderValueDllType = "struct*"
    Else
        $sBorderValueDllType = "ptr"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cudaCreateBoxFilter", "int", $srcType, "int", $dstType, $sKsizeDllType, $ksize, $sAnchorDllType, $anchor, "int", $borderMode, $sBorderValueDllType, $borderValue, $sSharedPtrDllType, $sharedPtr), "cudaCreateBoxFilter", @error)
EndFunc   ;==>_cudaCreateBoxFilter

Func _cudaCreateBoxMaxFilter($srcType, $ksize, $anchor, $borderMode, $borderValue, $sharedPtr)
    ; CVAPI(cv::cuda::Filter*) cudaCreateBoxMaxFilter(int srcType, CvSize* ksize, CvPoint* anchor, int borderMode, CvScalar* borderValue, cv::Ptr<cv::cuda::Filter>** sharedPtr);

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

    Local $sBorderValueDllType
    If IsDllStruct($borderValue) Then
        $sBorderValueDllType = "struct*"
    Else
        $sBorderValueDllType = "ptr"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cudaCreateBoxMaxFilter", "int", $srcType, $sKsizeDllType, $ksize, $sAnchorDllType, $anchor, "int", $borderMode, $sBorderValueDllType, $borderValue, $sSharedPtrDllType, $sharedPtr), "cudaCreateBoxMaxFilter", @error)
EndFunc   ;==>_cudaCreateBoxMaxFilter

Func _cudaCreateBoxMinFilter($srcType, $ksize, $anchor, $borderMode, $borderValue, $sharedPtr)
    ; CVAPI(cv::cuda::Filter*) cudaCreateBoxMinFilter(int srcType, CvSize* ksize, CvPoint* anchor, int borderMode, CvScalar* borderValue, cv::Ptr<cv::cuda::Filter>** sharedPtr);

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

    Local $sBorderValueDllType
    If IsDllStruct($borderValue) Then
        $sBorderValueDllType = "struct*"
    Else
        $sBorderValueDllType = "ptr"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cudaCreateBoxMinFilter", "int", $srcType, $sKsizeDllType, $ksize, $sAnchorDllType, $anchor, "int", $borderMode, $sBorderValueDllType, $borderValue, $sSharedPtrDllType, $sharedPtr), "cudaCreateBoxMinFilter", @error)
EndFunc   ;==>_cudaCreateBoxMinFilter

Func _cudaCreateMorphologyFilter($op, $srcType, $kernel, $anchor, $iterations, $sharedPtr)
    ; CVAPI(cv::cuda::Filter*) cudaCreateMorphologyFilter(int op, int srcType, cv::_InputArray* kernel, CvPoint* anchor, int iterations, cv::Ptr<cv::cuda::Filter>** sharedPtr);

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

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cudaCreateMorphologyFilter", "int", $op, "int", $srcType, $sKernelDllType, $kernel, $sAnchorDllType, $anchor, "int", $iterations, $sSharedPtrDllType, $sharedPtr), "cudaCreateMorphologyFilter", @error)
EndFunc   ;==>_cudaCreateMorphologyFilter

Func _cudaCreateMorphologyFilterMat($op, $srcType, $matKernel, $anchor, $iterations, $sharedPtr)
    ; cudaCreateMorphologyFilter using cv::Mat instead of _*Array

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

    Local $retval = _cudaCreateMorphologyFilter($op, $srcType, $iArrKernel, $anchor, $iterations, $sharedPtr)

    If $bKernelIsArray Then
        _VectorOfMatRelease($vectorOfMatKernel)
    EndIf

    _cveInputArrayRelease($iArrKernel)

    Return $retval
EndFunc   ;==>_cudaCreateMorphologyFilterMat

Func _cudaCreateSeparableLinearFilter($srcType, $dstType, $rowKernel, $columnKernel, $anchor, $rowBorderMode, $columnBorderMode, $sharedPtr)
    ; CVAPI(cv::cuda::Filter*) cudaCreateSeparableLinearFilter(int srcType, int dstType, cv::_InputArray* rowKernel, cv::_InputArray* columnKernel, CvPoint* anchor, int rowBorderMode, int columnBorderMode, cv::Ptr<cv::cuda::Filter>** sharedPtr);

    Local $sRowKernelDllType
    If IsDllStruct($rowKernel) Then
        $sRowKernelDllType = "struct*"
    Else
        $sRowKernelDllType = "ptr"
    EndIf

    Local $sColumnKernelDllType
    If IsDllStruct($columnKernel) Then
        $sColumnKernelDllType = "struct*"
    Else
        $sColumnKernelDllType = "ptr"
    EndIf

    Local $sAnchorDllType
    If IsDllStruct($anchor) Then
        $sAnchorDllType = "struct*"
    Else
        $sAnchorDllType = "ptr"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cudaCreateSeparableLinearFilter", "int", $srcType, "int", $dstType, $sRowKernelDllType, $rowKernel, $sColumnKernelDllType, $columnKernel, $sAnchorDllType, $anchor, "int", $rowBorderMode, "int", $columnBorderMode, $sSharedPtrDllType, $sharedPtr), "cudaCreateSeparableLinearFilter", @error)
EndFunc   ;==>_cudaCreateSeparableLinearFilter

Func _cudaCreateSeparableLinearFilterMat($srcType, $dstType, $matRowKernel, $matColumnKernel, $anchor, $rowBorderMode, $columnBorderMode, $sharedPtr)
    ; cudaCreateSeparableLinearFilter using cv::Mat instead of _*Array

    Local $iArrRowKernel, $vectorOfMatRowKernel, $iArrRowKernelSize
    Local $bRowKernelIsArray = VarGetType($matRowKernel) == "Array"

    If $bRowKernelIsArray Then
        $vectorOfMatRowKernel = _VectorOfMatCreate()

        $iArrRowKernelSize = UBound($matRowKernel)
        For $i = 0 To $iArrRowKernelSize - 1
            _VectorOfMatPush($vectorOfMatRowKernel, $matRowKernel[$i])
        Next

        $iArrRowKernel = _cveInputArrayFromVectorOfMat($vectorOfMatRowKernel)
    Else
        $iArrRowKernel = _cveInputArrayFromMat($matRowKernel)
    EndIf

    Local $iArrColumnKernel, $vectorOfMatColumnKernel, $iArrColumnKernelSize
    Local $bColumnKernelIsArray = VarGetType($matColumnKernel) == "Array"

    If $bColumnKernelIsArray Then
        $vectorOfMatColumnKernel = _VectorOfMatCreate()

        $iArrColumnKernelSize = UBound($matColumnKernel)
        For $i = 0 To $iArrColumnKernelSize - 1
            _VectorOfMatPush($vectorOfMatColumnKernel, $matColumnKernel[$i])
        Next

        $iArrColumnKernel = _cveInputArrayFromVectorOfMat($vectorOfMatColumnKernel)
    Else
        $iArrColumnKernel = _cveInputArrayFromMat($matColumnKernel)
    EndIf

    Local $retval = _cudaCreateSeparableLinearFilter($srcType, $dstType, $iArrRowKernel, $iArrColumnKernel, $anchor, $rowBorderMode, $columnBorderMode, $sharedPtr)

    If $bColumnKernelIsArray Then
        _VectorOfMatRelease($vectorOfMatColumnKernel)
    EndIf

    _cveInputArrayRelease($iArrColumnKernel)

    If $bRowKernelIsArray Then
        _VectorOfMatRelease($vectorOfMatRowKernel)
    EndIf

    _cveInputArrayRelease($iArrRowKernel)

    Return $retval
EndFunc   ;==>_cudaCreateSeparableLinearFilterMat

Func _cudaCreateDerivFilter($srcType, $dstType, $dx, $dy, $ksize, $normalize, $scale, $rowBorderMode, $columnBorderMode, $sharedPtr)
    ; CVAPI(cv::cuda::Filter*) cudaCreateDerivFilter(int srcType, int dstType, int dx, int dy, int ksize, bool normalize, double scale, int rowBorderMode, int columnBorderMode, cv::Ptr<cv::cuda::Filter>** sharedPtr);

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cudaCreateDerivFilter", "int", $srcType, "int", $dstType, "int", $dx, "int", $dy, "int", $ksize, "boolean", $normalize, "double", $scale, "int", $rowBorderMode, "int", $columnBorderMode, $sSharedPtrDllType, $sharedPtr), "cudaCreateDerivFilter", @error)
EndFunc   ;==>_cudaCreateDerivFilter

Func _cudaCreateScharrFilter($srcType, $dstType, $dx, $dy, $scale, $rowBorderMode, $columnBorderMode, $sharedPtr)
    ; CVAPI(cv::cuda::Filter*) cudaCreateScharrFilter(int srcType, int dstType, int dx, int dy, double scale, int rowBorderMode, int columnBorderMode, cv::Ptr<cv::cuda::Filter>** sharedPtr);

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cudaCreateScharrFilter", "int", $srcType, "int", $dstType, "int", $dx, "int", $dy, "double", $scale, "int", $rowBorderMode, "int", $columnBorderMode, $sSharedPtrDllType, $sharedPtr), "cudaCreateScharrFilter", @error)
EndFunc   ;==>_cudaCreateScharrFilter

Func _cudaCreateRowSumFilter($srcType, $dstType, $ksize, $anchor, $borderMode, $borderVal, $sharedPtr)
    ; CVAPI(cv::cuda::Filter*) cudaCreateRowSumFilter(int srcType, int dstType, int ksize, int anchor, int borderMode, CvScalar* borderVal, cv::Ptr<cv::cuda::Filter>** sharedPtr);

    Local $sBorderValDllType
    If IsDllStruct($borderVal) Then
        $sBorderValDllType = "struct*"
    Else
        $sBorderValDllType = "ptr"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cudaCreateRowSumFilter", "int", $srcType, "int", $dstType, "int", $ksize, "int", $anchor, "int", $borderMode, $sBorderValDllType, $borderVal, $sSharedPtrDllType, $sharedPtr), "cudaCreateRowSumFilter", @error)
EndFunc   ;==>_cudaCreateRowSumFilter

Func _cudaCreateColumnSumFilter($srcType, $dstType, $ksize, $anchor, $borderMode, $borderVal, $sharedPtr)
    ; CVAPI(cv::cuda::Filter*) cudaCreateColumnSumFilter(int srcType, int dstType, int ksize, int anchor, int borderMode, CvScalar* borderVal, cv::Ptr<cv::cuda::Filter>** sharedPtr);

    Local $sBorderValDllType
    If IsDllStruct($borderVal) Then
        $sBorderValDllType = "struct*"
    Else
        $sBorderValDllType = "ptr"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cudaCreateColumnSumFilter", "int", $srcType, "int", $dstType, "int", $ksize, "int", $anchor, "int", $borderMode, $sBorderValDllType, $borderVal, $sSharedPtrDllType, $sharedPtr), "cudaCreateColumnSumFilter", @error)
EndFunc   ;==>_cudaCreateColumnSumFilter

Func _cudaCreateMedianFilter($srcType, $windowSize, $partition, $sharedPtr)
    ; CVAPI(cv::cuda::Filter*) cudaCreateMedianFilter(int srcType, int windowSize, int partition, cv::Ptr<cv::cuda::Filter>** sharedPtr);

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cudaCreateMedianFilter", "int", $srcType, "int", $windowSize, "int", $partition, $sSharedPtrDllType, $sharedPtr), "cudaCreateMedianFilter", @error)
EndFunc   ;==>_cudaCreateMedianFilter

Func _cudaFilterApply($filter, $image, $dst, $stream)
    ; CVAPI(void) cudaFilterApply(cv::cuda::Filter* filter, cv::_InputArray* image, cv::_OutputArray* dst, cv::cuda::Stream* stream);

    Local $sFilterDllType
    If IsDllStruct($filter) Then
        $sFilterDllType = "struct*"
    Else
        $sFilterDllType = "ptr"
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaFilterApply", $sFilterDllType, $filter, $sImageDllType, $image, $sDstDllType, $dst, $sStreamDllType, $stream), "cudaFilterApply", @error)
EndFunc   ;==>_cudaFilterApply

Func _cudaFilterApplyMat($filter, $matImage, $matDst, $stream)
    ; cudaFilterApply using cv::Mat instead of _*Array

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

    _cudaFilterApply($filter, $iArrImage, $oArrDst, $stream)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveOutputArrayRelease($oArrDst)

    If $bImageIsArray Then
        _VectorOfMatRelease($vectorOfMatImage)
    EndIf

    _cveInputArrayRelease($iArrImage)
EndFunc   ;==>_cudaFilterApplyMat

Func _cudaFilterRelease($filter)
    ; CVAPI(void) cudaFilterRelease(cv::Ptr<cv::cuda::Filter>** filter);

    Local $sFilterDllType
    If IsDllStruct($filter) Then
        $sFilterDllType = "struct*"
    ElseIf $filter == Null Then
        $sFilterDllType = "ptr"
    Else
        $sFilterDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaFilterRelease", $sFilterDllType, $filter), "cudaFilterRelease", @error)
EndFunc   ;==>_cudaFilterRelease