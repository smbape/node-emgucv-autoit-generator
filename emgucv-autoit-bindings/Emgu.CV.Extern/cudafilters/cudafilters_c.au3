#include-once
#include "..\..\CVEUtils.au3"

Func _cudaCreateSobelFilter($srcType, $dstType, $dx, $dy, $ksize, $scale, $rowBorderType, $columnBorderType, $sharedPtr)
    ; CVAPI(cv::cuda::Filter*) cudaCreateSobelFilter(int srcType, int dstType, int dx, int dy, int ksize, double scale, int rowBorderType, int columnBorderType, cv::Ptr<cv::cuda::Filter>** sharedPtr);

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cudaCreateSobelFilter", "int", $srcType, "int", $dstType, "int", $dx, "int", $dy, "int", $ksize, "double", $scale, "int", $rowBorderType, "int", $columnBorderType, $bSharedPtrDllType, $sharedPtr), "cudaCreateSobelFilter", @error)
EndFunc   ;==>_cudaCreateSobelFilter

Func _cudaCreateGaussianFilter($srcType, $dstType, $ksize, $sigma1, $sigma2, $rowBorderType, $columnBorderType, $sharedPtr)
    ; CVAPI(cv::cuda::Filter*) cudaCreateGaussianFilter(int srcType, int dstType, CvSize* ksize, double sigma1, double sigma2, int rowBorderType, int columnBorderType, cv::Ptr<cv::cuda::Filter>** sharedPtr);

    Local $bKsizeDllType
    If VarGetType($ksize) == "DLLStruct" Then
        $bKsizeDllType = "struct*"
    Else
        $bKsizeDllType = "ptr"
    EndIf

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cudaCreateGaussianFilter", "int", $srcType, "int", $dstType, $bKsizeDllType, $ksize, "double", $sigma1, "double", $sigma2, "int", $rowBorderType, "int", $columnBorderType, $bSharedPtrDllType, $sharedPtr), "cudaCreateGaussianFilter", @error)
EndFunc   ;==>_cudaCreateGaussianFilter

Func _cudaCreateLaplacianFilter($srcType, $dstType, $ksize, $scale, $borderMode, $borderValue, $sharedPtr)
    ; CVAPI(cv::cuda::Filter*) cudaCreateLaplacianFilter(int srcType, int dstType, int ksize, double scale, int borderMode, CvScalar* borderValue, cv::Ptr<cv::cuda::Filter>** sharedPtr);

    Local $bBorderValueDllType
    If VarGetType($borderValue) == "DLLStruct" Then
        $bBorderValueDllType = "struct*"
    Else
        $bBorderValueDllType = "ptr"
    EndIf

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cudaCreateLaplacianFilter", "int", $srcType, "int", $dstType, "int", $ksize, "double", $scale, "int", $borderMode, $bBorderValueDllType, $borderValue, $bSharedPtrDllType, $sharedPtr), "cudaCreateLaplacianFilter", @error)
EndFunc   ;==>_cudaCreateLaplacianFilter

Func _cudaCreateLinearFilter($srcType, $dstType, $kernel, $anchor, $borderMode, $borderValue, $sharedPtr)
    ; CVAPI(cv::cuda::Filter*) cudaCreateLinearFilter(int srcType, int dstType, cv::_InputArray* kernel, CvPoint* anchor, int borderMode, CvScalar* borderValue, cv::Ptr<cv::cuda::Filter>** sharedPtr);

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

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cudaCreateLinearFilter", "int", $srcType, "int", $dstType, $bKernelDllType, $kernel, $bAnchorDllType, $anchor, "int", $borderMode, $bBorderValueDllType, $borderValue, $bSharedPtrDllType, $sharedPtr), "cudaCreateLinearFilter", @error)
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

    Local $bBorderValueDllType
    If VarGetType($borderValue) == "DLLStruct" Then
        $bBorderValueDllType = "struct*"
    Else
        $bBorderValueDllType = "ptr"
    EndIf

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cudaCreateBoxFilter", "int", $srcType, "int", $dstType, $bKsizeDllType, $ksize, $bAnchorDllType, $anchor, "int", $borderMode, $bBorderValueDllType, $borderValue, $bSharedPtrDllType, $sharedPtr), "cudaCreateBoxFilter", @error)
EndFunc   ;==>_cudaCreateBoxFilter

Func _cudaCreateBoxMaxFilter($srcType, $ksize, $anchor, $borderMode, $borderValue, $sharedPtr)
    ; CVAPI(cv::cuda::Filter*) cudaCreateBoxMaxFilter(int srcType, CvSize* ksize, CvPoint* anchor, int borderMode, CvScalar* borderValue, cv::Ptr<cv::cuda::Filter>** sharedPtr);

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

    Local $bBorderValueDllType
    If VarGetType($borderValue) == "DLLStruct" Then
        $bBorderValueDllType = "struct*"
    Else
        $bBorderValueDllType = "ptr"
    EndIf

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cudaCreateBoxMaxFilter", "int", $srcType, $bKsizeDllType, $ksize, $bAnchorDllType, $anchor, "int", $borderMode, $bBorderValueDllType, $borderValue, $bSharedPtrDllType, $sharedPtr), "cudaCreateBoxMaxFilter", @error)
EndFunc   ;==>_cudaCreateBoxMaxFilter

Func _cudaCreateBoxMinFilter($srcType, $ksize, $anchor, $borderMode, $borderValue, $sharedPtr)
    ; CVAPI(cv::cuda::Filter*) cudaCreateBoxMinFilter(int srcType, CvSize* ksize, CvPoint* anchor, int borderMode, CvScalar* borderValue, cv::Ptr<cv::cuda::Filter>** sharedPtr);

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

    Local $bBorderValueDllType
    If VarGetType($borderValue) == "DLLStruct" Then
        $bBorderValueDllType = "struct*"
    Else
        $bBorderValueDllType = "ptr"
    EndIf

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cudaCreateBoxMinFilter", "int", $srcType, $bKsizeDllType, $ksize, $bAnchorDllType, $anchor, "int", $borderMode, $bBorderValueDllType, $borderValue, $bSharedPtrDllType, $sharedPtr), "cudaCreateBoxMinFilter", @error)
EndFunc   ;==>_cudaCreateBoxMinFilter

Func _cudaCreateMorphologyFilter($op, $srcType, $kernel, $anchor, $iterations, $sharedPtr)
    ; CVAPI(cv::cuda::Filter*) cudaCreateMorphologyFilter(int op, int srcType, cv::_InputArray* kernel, CvPoint* anchor, int iterations, cv::Ptr<cv::cuda::Filter>** sharedPtr);

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

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cudaCreateMorphologyFilter", "int", $op, "int", $srcType, $bKernelDllType, $kernel, $bAnchorDllType, $anchor, "int", $iterations, $bSharedPtrDllType, $sharedPtr), "cudaCreateMorphologyFilter", @error)
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

    Local $bRowKernelDllType
    If VarGetType($rowKernel) == "DLLStruct" Then
        $bRowKernelDllType = "struct*"
    Else
        $bRowKernelDllType = "ptr"
    EndIf

    Local $bColumnKernelDllType
    If VarGetType($columnKernel) == "DLLStruct" Then
        $bColumnKernelDllType = "struct*"
    Else
        $bColumnKernelDllType = "ptr"
    EndIf

    Local $bAnchorDllType
    If VarGetType($anchor) == "DLLStruct" Then
        $bAnchorDllType = "struct*"
    Else
        $bAnchorDllType = "ptr"
    EndIf

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cudaCreateSeparableLinearFilter", "int", $srcType, "int", $dstType, $bRowKernelDllType, $rowKernel, $bColumnKernelDllType, $columnKernel, $bAnchorDllType, $anchor, "int", $rowBorderMode, "int", $columnBorderMode, $bSharedPtrDllType, $sharedPtr), "cudaCreateSeparableLinearFilter", @error)
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

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cudaCreateDerivFilter", "int", $srcType, "int", $dstType, "int", $dx, "int", $dy, "int", $ksize, "boolean", $normalize, "double", $scale, "int", $rowBorderMode, "int", $columnBorderMode, $bSharedPtrDllType, $sharedPtr), "cudaCreateDerivFilter", @error)
EndFunc   ;==>_cudaCreateDerivFilter

Func _cudaCreateScharrFilter($srcType, $dstType, $dx, $dy, $scale, $rowBorderMode, $columnBorderMode, $sharedPtr)
    ; CVAPI(cv::cuda::Filter*) cudaCreateScharrFilter(int srcType, int dstType, int dx, int dy, double scale, int rowBorderMode, int columnBorderMode, cv::Ptr<cv::cuda::Filter>** sharedPtr);

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cudaCreateScharrFilter", "int", $srcType, "int", $dstType, "int", $dx, "int", $dy, "double", $scale, "int", $rowBorderMode, "int", $columnBorderMode, $bSharedPtrDllType, $sharedPtr), "cudaCreateScharrFilter", @error)
EndFunc   ;==>_cudaCreateScharrFilter

Func _cudaCreateRowSumFilter($srcType, $dstType, $ksize, $anchor, $borderMode, $borderVal, $sharedPtr)
    ; CVAPI(cv::cuda::Filter*) cudaCreateRowSumFilter(int srcType, int dstType, int ksize, int anchor, int borderMode, CvScalar* borderVal, cv::Ptr<cv::cuda::Filter>** sharedPtr);

    Local $bBorderValDllType
    If VarGetType($borderVal) == "DLLStruct" Then
        $bBorderValDllType = "struct*"
    Else
        $bBorderValDllType = "ptr"
    EndIf

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cudaCreateRowSumFilter", "int", $srcType, "int", $dstType, "int", $ksize, "int", $anchor, "int", $borderMode, $bBorderValDllType, $borderVal, $bSharedPtrDllType, $sharedPtr), "cudaCreateRowSumFilter", @error)
EndFunc   ;==>_cudaCreateRowSumFilter

Func _cudaCreateColumnSumFilter($srcType, $dstType, $ksize, $anchor, $borderMode, $borderVal, $sharedPtr)
    ; CVAPI(cv::cuda::Filter*) cudaCreateColumnSumFilter(int srcType, int dstType, int ksize, int anchor, int borderMode, CvScalar* borderVal, cv::Ptr<cv::cuda::Filter>** sharedPtr);

    Local $bBorderValDllType
    If VarGetType($borderVal) == "DLLStruct" Then
        $bBorderValDllType = "struct*"
    Else
        $bBorderValDllType = "ptr"
    EndIf

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cudaCreateColumnSumFilter", "int", $srcType, "int", $dstType, "int", $ksize, "int", $anchor, "int", $borderMode, $bBorderValDllType, $borderVal, $bSharedPtrDllType, $sharedPtr), "cudaCreateColumnSumFilter", @error)
EndFunc   ;==>_cudaCreateColumnSumFilter

Func _cudaCreateMedianFilter($srcType, $windowSize, $partition, $sharedPtr)
    ; CVAPI(cv::cuda::Filter*) cudaCreateMedianFilter(int srcType, int windowSize, int partition, cv::Ptr<cv::cuda::Filter>** sharedPtr);

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cudaCreateMedianFilter", "int", $srcType, "int", $windowSize, "int", $partition, $bSharedPtrDllType, $sharedPtr), "cudaCreateMedianFilter", @error)
EndFunc   ;==>_cudaCreateMedianFilter

Func _cudaFilterApply($filter, $image, $dst, $stream)
    ; CVAPI(void) cudaFilterApply(cv::cuda::Filter* filter, cv::_InputArray* image, cv::_OutputArray* dst, cv::cuda::Stream* stream);

    Local $bFilterDllType
    If VarGetType($filter) == "DLLStruct" Then
        $bFilterDllType = "struct*"
    Else
        $bFilterDllType = "ptr"
    EndIf

    Local $bImageDllType
    If VarGetType($image) == "DLLStruct" Then
        $bImageDllType = "struct*"
    Else
        $bImageDllType = "ptr"
    EndIf

    Local $bDstDllType
    If VarGetType($dst) == "DLLStruct" Then
        $bDstDllType = "struct*"
    Else
        $bDstDllType = "ptr"
    EndIf

    Local $bStreamDllType
    If VarGetType($stream) == "DLLStruct" Then
        $bStreamDllType = "struct*"
    Else
        $bStreamDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaFilterApply", $bFilterDllType, $filter, $bImageDllType, $image, $bDstDllType, $dst, $bStreamDllType, $stream), "cudaFilterApply", @error)
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

    Local $bFilterDllType
    If VarGetType($filter) == "DLLStruct" Then
        $bFilterDllType = "struct*"
    Else
        $bFilterDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaFilterRelease", $bFilterDllType, $filter), "cudaFilterRelease", @error)
EndFunc   ;==>_cudaFilterRelease