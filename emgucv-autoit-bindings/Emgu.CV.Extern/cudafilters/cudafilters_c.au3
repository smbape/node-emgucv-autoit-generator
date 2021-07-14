#include-once
#include <..\..\CVEUtils.au3>

Func _cudaCreateSobelFilter($srcType, $dstType, $dx, $dy, $ksize, $scale, $rowBorderType, $columnBorderType, ByRef $sharedPtr)
    ; CVAPI(cv::cuda::Filter*) cudaCreateSobelFilter(int srcType, int dstType, int dx, int dy, int ksize, double scale, int rowBorderType, int columnBorderType, cv::Ptr<cv::cuda::Filter>** sharedPtr);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cudaCreateSobelFilter", "int", $srcType, "int", $dstType, "int", $dx, "int", $dy, "int", $ksize, "double", $scale, "int", $rowBorderType, "int", $columnBorderType, "ptr*", $sharedPtr), "cudaCreateSobelFilter", @error)
EndFunc   ;==>_cudaCreateSobelFilter

Func _cudaCreateGaussianFilter($srcType, $dstType, ByRef $ksize, $sigma1, $sigma2, $rowBorderType, $columnBorderType, ByRef $sharedPtr)
    ; CVAPI(cv::cuda::Filter*) cudaCreateGaussianFilter(int srcType, int dstType, CvSize* ksize, double sigma1, double sigma2, int rowBorderType, int columnBorderType, cv::Ptr<cv::cuda::Filter>** sharedPtr);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cudaCreateGaussianFilter", "int", $srcType, "int", $dstType, "struct*", $ksize, "double", $sigma1, "double", $sigma2, "int", $rowBorderType, "int", $columnBorderType, "ptr*", $sharedPtr), "cudaCreateGaussianFilter", @error)
EndFunc   ;==>_cudaCreateGaussianFilter

Func _cudaCreateLaplacianFilter($srcType, $dstType, $ksize, $scale, $borderMode, ByRef $borderValue, ByRef $sharedPtr)
    ; CVAPI(cv::cuda::Filter*) cudaCreateLaplacianFilter(int srcType, int dstType, int ksize, double scale, int borderMode, CvScalar* borderValue, cv::Ptr<cv::cuda::Filter>** sharedPtr);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cudaCreateLaplacianFilter", "int", $srcType, "int", $dstType, "int", $ksize, "double", $scale, "int", $borderMode, "struct*", $borderValue, "ptr*", $sharedPtr), "cudaCreateLaplacianFilter", @error)
EndFunc   ;==>_cudaCreateLaplacianFilter

Func _cudaCreateLinearFilter($srcType, $dstType, ByRef $kernel, ByRef $anchor, $borderMode, ByRef $borderValue, ByRef $sharedPtr)
    ; CVAPI(cv::cuda::Filter*) cudaCreateLinearFilter(int srcType, int dstType, cv::_InputArray* kernel, CvPoint* anchor, int borderMode, CvScalar* borderValue, cv::Ptr<cv::cuda::Filter>** sharedPtr);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cudaCreateLinearFilter", "int", $srcType, "int", $dstType, "ptr", $kernel, "struct*", $anchor, "int", $borderMode, "struct*", $borderValue, "ptr*", $sharedPtr), "cudaCreateLinearFilter", @error)
EndFunc   ;==>_cudaCreateLinearFilter

Func _cudaCreateLinearFilterMat($srcType, $dstType, ByRef $matKernel, ByRef $anchor, $borderMode, ByRef $borderValue, ByRef $sharedPtr)
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

Func _cudaCreateBoxFilter($srcType, $dstType, ByRef $ksize, ByRef $anchor, $borderMode, ByRef $borderValue, ByRef $sharedPtr)
    ; CVAPI(cv::cuda::Filter*) cudaCreateBoxFilter(int srcType, int dstType, CvSize* ksize, CvPoint* anchor, int borderMode, CvScalar* borderValue, cv::Ptr<cv::cuda::Filter>** sharedPtr);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cudaCreateBoxFilter", "int", $srcType, "int", $dstType, "struct*", $ksize, "struct*", $anchor, "int", $borderMode, "struct*", $borderValue, "ptr*", $sharedPtr), "cudaCreateBoxFilter", @error)
EndFunc   ;==>_cudaCreateBoxFilter

Func _cudaCreateBoxMaxFilter($srcType, ByRef $ksize, ByRef $anchor, $borderMode, ByRef $borderValue, ByRef $sharedPtr)
    ; CVAPI(cv::cuda::Filter*) cudaCreateBoxMaxFilter(int srcType, CvSize* ksize, CvPoint* anchor, int borderMode, CvScalar* borderValue, cv::Ptr<cv::cuda::Filter>** sharedPtr);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cudaCreateBoxMaxFilter", "int", $srcType, "struct*", $ksize, "struct*", $anchor, "int", $borderMode, "struct*", $borderValue, "ptr*", $sharedPtr), "cudaCreateBoxMaxFilter", @error)
EndFunc   ;==>_cudaCreateBoxMaxFilter

Func _cudaCreateBoxMinFilter($srcType, ByRef $ksize, ByRef $anchor, $borderMode, ByRef $borderValue, ByRef $sharedPtr)
    ; CVAPI(cv::cuda::Filter*) cudaCreateBoxMinFilter(int srcType, CvSize* ksize, CvPoint* anchor, int borderMode, CvScalar* borderValue, cv::Ptr<cv::cuda::Filter>** sharedPtr);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cudaCreateBoxMinFilter", "int", $srcType, "struct*", $ksize, "struct*", $anchor, "int", $borderMode, "struct*", $borderValue, "ptr*", $sharedPtr), "cudaCreateBoxMinFilter", @error)
EndFunc   ;==>_cudaCreateBoxMinFilter

Func _cudaCreateMorphologyFilter($op, $srcType, ByRef $kernel, ByRef $anchor, $iterations, ByRef $sharedPtr)
    ; CVAPI(cv::cuda::Filter*) cudaCreateMorphologyFilter(int op, int srcType, cv::_InputArray* kernel, CvPoint* anchor, int iterations, cv::Ptr<cv::cuda::Filter>** sharedPtr);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cudaCreateMorphologyFilter", "int", $op, "int", $srcType, "ptr", $kernel, "struct*", $anchor, "int", $iterations, "ptr*", $sharedPtr), "cudaCreateMorphologyFilter", @error)
EndFunc   ;==>_cudaCreateMorphologyFilter

Func _cudaCreateMorphologyFilterMat($op, $srcType, ByRef $matKernel, ByRef $anchor, $iterations, ByRef $sharedPtr)
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

Func _cudaCreateSeparableLinearFilter($srcType, $dstType, ByRef $rowKernel, ByRef $columnKernel, ByRef $anchor, $rowBorderMode, $columnBorderMode, ByRef $sharedPtr)
    ; CVAPI(cv::cuda::Filter*) cudaCreateSeparableLinearFilter(int srcType, int dstType, cv::_InputArray* rowKernel, cv::_InputArray* columnKernel, CvPoint* anchor, int rowBorderMode, int columnBorderMode, cv::Ptr<cv::cuda::Filter>** sharedPtr);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cudaCreateSeparableLinearFilter", "int", $srcType, "int", $dstType, "ptr", $rowKernel, "ptr", $columnKernel, "struct*", $anchor, "int", $rowBorderMode, "int", $columnBorderMode, "ptr*", $sharedPtr), "cudaCreateSeparableLinearFilter", @error)
EndFunc   ;==>_cudaCreateSeparableLinearFilter

Func _cudaCreateSeparableLinearFilterMat($srcType, $dstType, ByRef $matRowKernel, ByRef $matColumnKernel, ByRef $anchor, $rowBorderMode, $columnBorderMode, ByRef $sharedPtr)
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

Func _cudaCreateDerivFilter($srcType, $dstType, $dx, $dy, $ksize, $normalize, $scale, $rowBorderMode, $columnBorderMode, ByRef $sharedPtr)
    ; CVAPI(cv::cuda::Filter*) cudaCreateDerivFilter(int srcType, int dstType, int dx, int dy, int ksize, bool normalize, double scale, int rowBorderMode, int columnBorderMode, cv::Ptr<cv::cuda::Filter>** sharedPtr);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cudaCreateDerivFilter", "int", $srcType, "int", $dstType, "int", $dx, "int", $dy, "int", $ksize, "boolean", $normalize, "double", $scale, "int", $rowBorderMode, "int", $columnBorderMode, "ptr*", $sharedPtr), "cudaCreateDerivFilter", @error)
EndFunc   ;==>_cudaCreateDerivFilter

Func _cudaCreateScharrFilter($srcType, $dstType, $dx, $dy, $scale, $rowBorderMode, $columnBorderMode, ByRef $sharedPtr)
    ; CVAPI(cv::cuda::Filter*) cudaCreateScharrFilter(int srcType, int dstType, int dx, int dy, double scale, int rowBorderMode, int columnBorderMode, cv::Ptr<cv::cuda::Filter>** sharedPtr);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cudaCreateScharrFilter", "int", $srcType, "int", $dstType, "int", $dx, "int", $dy, "double", $scale, "int", $rowBorderMode, "int", $columnBorderMode, "ptr*", $sharedPtr), "cudaCreateScharrFilter", @error)
EndFunc   ;==>_cudaCreateScharrFilter

Func _cudaCreateRowSumFilter($srcType, $dstType, $ksize, $anchor, $borderMode, ByRef $borderVal, ByRef $sharedPtr)
    ; CVAPI(cv::cuda::Filter*) cudaCreateRowSumFilter(int srcType, int dstType, int ksize, int anchor, int borderMode, CvScalar* borderVal, cv::Ptr<cv::cuda::Filter>** sharedPtr);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cudaCreateRowSumFilter", "int", $srcType, "int", $dstType, "int", $ksize, "int", $anchor, "int", $borderMode, "struct*", $borderVal, "ptr*", $sharedPtr), "cudaCreateRowSumFilter", @error)
EndFunc   ;==>_cudaCreateRowSumFilter

Func _cudaCreateColumnSumFilter($srcType, $dstType, $ksize, $anchor, $borderMode, ByRef $borderVal, ByRef $sharedPtr)
    ; CVAPI(cv::cuda::Filter*) cudaCreateColumnSumFilter(int srcType, int dstType, int ksize, int anchor, int borderMode, CvScalar* borderVal, cv::Ptr<cv::cuda::Filter>** sharedPtr);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cudaCreateColumnSumFilter", "int", $srcType, "int", $dstType, "int", $ksize, "int", $anchor, "int", $borderMode, "struct*", $borderVal, "ptr*", $sharedPtr), "cudaCreateColumnSumFilter", @error)
EndFunc   ;==>_cudaCreateColumnSumFilter

Func _cudaCreateMedianFilter($srcType, $windowSize, $partition, ByRef $sharedPtr)
    ; CVAPI(cv::cuda::Filter*) cudaCreateMedianFilter(int srcType, int windowSize, int partition, cv::Ptr<cv::cuda::Filter>** sharedPtr);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cudaCreateMedianFilter", "int", $srcType, "int", $windowSize, "int", $partition, "ptr*", $sharedPtr), "cudaCreateMedianFilter", @error)
EndFunc   ;==>_cudaCreateMedianFilter

Func _cudaFilterApply(ByRef $filter, ByRef $image, ByRef $dst, ByRef $stream)
    ; CVAPI(void) cudaFilterApply(cv::cuda::Filter* filter, cv::_InputArray* image, cv::_OutputArray* dst, cv::cuda::Stream* stream);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaFilterApply", "ptr", $filter, "ptr", $image, "ptr", $dst, "ptr", $stream), "cudaFilterApply", @error)
EndFunc   ;==>_cudaFilterApply

Func _cudaFilterApplyMat(ByRef $filter, ByRef $matImage, ByRef $matDst, ByRef $stream)
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

Func _cudaFilterRelease(ByRef $filter)
    ; CVAPI(void) cudaFilterRelease(cv::Ptr<cv::cuda::Filter>** filter);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaFilterRelease", "ptr*", $filter), "cudaFilterRelease", @error)
EndFunc   ;==>_cudaFilterRelease