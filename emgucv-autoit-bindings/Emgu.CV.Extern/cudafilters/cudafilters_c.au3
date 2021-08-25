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

Func _cudaCreateLinearFilterTyped($srcType, $dstType, $typeOfKernel, $kernel, $anchor, $borderMode, $borderValue, $sharedPtr)

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

    Local $retval = _cudaCreateLinearFilter($srcType, $dstType, $iArrKernel, $anchor, $borderMode, $borderValue, $sharedPtr)

    If $bKernelIsArray Then
        Call("_VectorOf" & $typeOfKernel & "Release", $vectorKernel)
    EndIf

    If $typeOfKernel <> Default Then
        _cveInputArrayRelease($iArrKernel)
        If $bKernelCreate Then
            Call("_cve" & $typeOfKernel & "Release", $kernel)
        EndIf
    EndIf

    Return $retval
EndFunc   ;==>_cudaCreateLinearFilterTyped

Func _cudaCreateLinearFilterMat($srcType, $dstType, $kernel, $anchor, $borderMode, $borderValue, $sharedPtr)
    ; cudaCreateLinearFilter using cv::Mat instead of _*Array
    Local $retval = _cudaCreateLinearFilterTyped($srcType, $dstType, "Mat", $kernel, $anchor, $borderMode, $borderValue, $sharedPtr)

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

Func _cudaCreateMorphologyFilterTyped($op, $srcType, $typeOfKernel, $kernel, $anchor, $iterations, $sharedPtr)

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

    Local $retval = _cudaCreateMorphologyFilter($op, $srcType, $iArrKernel, $anchor, $iterations, $sharedPtr)

    If $bKernelIsArray Then
        Call("_VectorOf" & $typeOfKernel & "Release", $vectorKernel)
    EndIf

    If $typeOfKernel <> Default Then
        _cveInputArrayRelease($iArrKernel)
        If $bKernelCreate Then
            Call("_cve" & $typeOfKernel & "Release", $kernel)
        EndIf
    EndIf

    Return $retval
EndFunc   ;==>_cudaCreateMorphologyFilterTyped

Func _cudaCreateMorphologyFilterMat($op, $srcType, $kernel, $anchor, $iterations, $sharedPtr)
    ; cudaCreateMorphologyFilter using cv::Mat instead of _*Array
    Local $retval = _cudaCreateMorphologyFilterTyped($op, $srcType, "Mat", $kernel, $anchor, $iterations, $sharedPtr)

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

Func _cudaCreateSeparableLinearFilterTyped($srcType, $dstType, $typeOfRowKernel, $rowKernel, $typeOfColumnKernel, $columnKernel, $anchor, $rowBorderMode, $columnBorderMode, $sharedPtr)

    Local $iArrRowKernel, $vectorRowKernel, $iArrRowKernelSize
    Local $bRowKernelIsArray = IsArray($rowKernel)
    Local $bRowKernelCreate = IsDllStruct($rowKernel) And $typeOfRowKernel == "Scalar"

    If $typeOfRowKernel == Default Then
        $iArrRowKernel = $rowKernel
    ElseIf $bRowKernelIsArray Then
        $vectorRowKernel = Call("_VectorOf" & $typeOfRowKernel & "Create")

        $iArrRowKernelSize = UBound($rowKernel)
        For $i = 0 To $iArrRowKernelSize - 1
            Call("_VectorOf" & $typeOfRowKernel & "Push", $vectorRowKernel, $rowKernel[$i])
        Next

        $iArrRowKernel = Call("_cveInputArrayFromVectorOf" & $typeOfRowKernel, $vectorRowKernel)
    Else
        If $bRowKernelCreate Then
            $rowKernel = Call("_cve" & $typeOfRowKernel & "Create", $rowKernel)
        EndIf
        $iArrRowKernel = Call("_cveInputArrayFrom" & $typeOfRowKernel, $rowKernel)
    EndIf

    Local $iArrColumnKernel, $vectorColumnKernel, $iArrColumnKernelSize
    Local $bColumnKernelIsArray = IsArray($columnKernel)
    Local $bColumnKernelCreate = IsDllStruct($columnKernel) And $typeOfColumnKernel == "Scalar"

    If $typeOfColumnKernel == Default Then
        $iArrColumnKernel = $columnKernel
    ElseIf $bColumnKernelIsArray Then
        $vectorColumnKernel = Call("_VectorOf" & $typeOfColumnKernel & "Create")

        $iArrColumnKernelSize = UBound($columnKernel)
        For $i = 0 To $iArrColumnKernelSize - 1
            Call("_VectorOf" & $typeOfColumnKernel & "Push", $vectorColumnKernel, $columnKernel[$i])
        Next

        $iArrColumnKernel = Call("_cveInputArrayFromVectorOf" & $typeOfColumnKernel, $vectorColumnKernel)
    Else
        If $bColumnKernelCreate Then
            $columnKernel = Call("_cve" & $typeOfColumnKernel & "Create", $columnKernel)
        EndIf
        $iArrColumnKernel = Call("_cveInputArrayFrom" & $typeOfColumnKernel, $columnKernel)
    EndIf

    Local $retval = _cudaCreateSeparableLinearFilter($srcType, $dstType, $iArrRowKernel, $iArrColumnKernel, $anchor, $rowBorderMode, $columnBorderMode, $sharedPtr)

    If $bColumnKernelIsArray Then
        Call("_VectorOf" & $typeOfColumnKernel & "Release", $vectorColumnKernel)
    EndIf

    If $typeOfColumnKernel <> Default Then
        _cveInputArrayRelease($iArrColumnKernel)
        If $bColumnKernelCreate Then
            Call("_cve" & $typeOfColumnKernel & "Release", $columnKernel)
        EndIf
    EndIf

    If $bRowKernelIsArray Then
        Call("_VectorOf" & $typeOfRowKernel & "Release", $vectorRowKernel)
    EndIf

    If $typeOfRowKernel <> Default Then
        _cveInputArrayRelease($iArrRowKernel)
        If $bRowKernelCreate Then
            Call("_cve" & $typeOfRowKernel & "Release", $rowKernel)
        EndIf
    EndIf

    Return $retval
EndFunc   ;==>_cudaCreateSeparableLinearFilterTyped

Func _cudaCreateSeparableLinearFilterMat($srcType, $dstType, $rowKernel, $columnKernel, $anchor, $rowBorderMode, $columnBorderMode, $sharedPtr)
    ; cudaCreateSeparableLinearFilter using cv::Mat instead of _*Array
    Local $retval = _cudaCreateSeparableLinearFilterTyped($srcType, $dstType, "Mat", $rowKernel, "Mat", $columnKernel, $anchor, $rowBorderMode, $columnBorderMode, $sharedPtr)

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

Func _cudaFilterApplyTyped($filter, $typeOfImage, $image, $typeOfDst, $dst, $stream)

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

    _cudaFilterApply($filter, $iArrImage, $oArrDst, $stream)

    If $bDstIsArray Then
        Call("_VectorOf" & $typeOfDst & "Release", $vectorDst)
    EndIf

    If $typeOfDst <> Default Then
        _cveOutputArrayRelease($oArrDst)
        If $bDstCreate Then
            Call("_cve" & $typeOfDst & "Release", $dst)
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
EndFunc   ;==>_cudaFilterApplyTyped

Func _cudaFilterApplyMat($filter, $image, $dst, $stream)
    ; cudaFilterApply using cv::Mat instead of _*Array
    _cudaFilterApplyTyped($filter, "Mat", $image, "Mat", $dst, $stream)
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