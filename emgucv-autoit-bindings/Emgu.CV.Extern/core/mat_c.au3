#include-once
#include "..\..\CVEUtils.au3"

Func _cveMatCreate()
    ; CVAPI(cv::Mat*) cveMatCreate();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveMatCreate"), "cveMatCreate", @error)
EndFunc   ;==>_cveMatCreate

Func _cveMatCreateData($mat, $row, $cols, $type)
    ; CVAPI(void) cveMatCreateData(cv::Mat* mat, int row, int cols, int type);

    Local $sMatDllType
    If IsDllStruct($mat) Then
        $sMatDllType = "struct*"
    Else
        $sMatDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMatCreateData", $sMatDllType, $mat, "int", $row, "int", $cols, "int", $type), "cveMatCreateData", @error)
EndFunc   ;==>_cveMatCreateData

Func _cveMatCreateWithData($rows, $cols, $type, $data, $step)
    ; CVAPI(cv::Mat*) cveMatCreateWithData(int rows, int cols, int type, void* data, size_t step);

    Local $sDataDllType
    If IsDllStruct($data) Then
        $sDataDllType = "struct*"
    Else
        $sDataDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveMatCreateWithData", "int", $rows, "int", $cols, "int", $type, $sDataDllType, $data, "ulong_ptr", $step), "cveMatCreateWithData", @error)
EndFunc   ;==>_cveMatCreateWithData

Func _cveMatCreateMultiDimWithData($ndims, $sizes, $type, $data, $steps)
    ; CVAPI(cv::Mat*) cveMatCreateMultiDimWithData(int ndims, const int* sizes, int type, void* data, size_t* steps);

    Local $sSizesDllType
    If IsDllStruct($sizes) Then
        $sSizesDllType = "struct*"
    Else
        $sSizesDllType = "int*"
    EndIf

    Local $sDataDllType
    If IsDllStruct($data) Then
        $sDataDllType = "struct*"
    Else
        $sDataDllType = "ptr"
    EndIf

    Local $sStepsDllType
    If IsDllStruct($steps) Then
        $sStepsDllType = "struct*"
    Else
        $sStepsDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveMatCreateMultiDimWithData", "int", $ndims, $sSizesDllType, $sizes, "int", $type, $sDataDllType, $data, $sStepsDllType, $steps), "cveMatCreateMultiDimWithData", @error)
EndFunc   ;==>_cveMatCreateMultiDimWithData

Func _cveMatCreateFromRect($mat, $roi)
    ; CVAPI(cv::Mat*) cveMatCreateFromRect(cv::Mat* mat, CvRect* roi);

    Local $sMatDllType
    If IsDllStruct($mat) Then
        $sMatDllType = "struct*"
    Else
        $sMatDllType = "ptr"
    EndIf

    Local $sRoiDllType
    If IsDllStruct($roi) Then
        $sRoiDllType = "struct*"
    Else
        $sRoiDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveMatCreateFromRect", $sMatDllType, $mat, $sRoiDllType, $roi), "cveMatCreateFromRect", @error)
EndFunc   ;==>_cveMatCreateFromRect

Func _cveMatCreateFromRange($mat, $rowRange, $colRange)
    ; CVAPI(cv::Mat*) cveMatCreateFromRange(cv::Mat* mat, cv::Range* rowRange, cv::Range* colRange);

    Local $sMatDllType
    If IsDllStruct($mat) Then
        $sMatDllType = "struct*"
    Else
        $sMatDllType = "ptr"
    EndIf

    Local $sRowRangeDllType
    If IsDllStruct($rowRange) Then
        $sRowRangeDllType = "struct*"
    Else
        $sRowRangeDllType = "ptr"
    EndIf

    Local $sColRangeDllType
    If IsDllStruct($colRange) Then
        $sColRangeDllType = "struct*"
    Else
        $sColRangeDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveMatCreateFromRange", $sMatDllType, $mat, $sRowRangeDllType, $rowRange, $sColRangeDllType, $colRange), "cveMatCreateFromRange", @error)
EndFunc   ;==>_cveMatCreateFromRange

Func _cveMatRelease($mat)
    ; CVAPI(void) cveMatRelease(cv::Mat** mat);

    Local $sMatDllType
    If IsDllStruct($mat) Then
        $sMatDllType = "struct*"
    ElseIf $mat == Null Then
        $sMatDllType = "ptr"
    Else
        $sMatDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMatRelease", $sMatDllType, $mat), "cveMatRelease", @error)
EndFunc   ;==>_cveMatRelease

Func _cveMatGetSize($mat, $size)
    ; CVAPI(void) cveMatGetSize(cv::Mat* mat, CvSize* size);

    Local $sMatDllType
    If IsDllStruct($mat) Then
        $sMatDllType = "struct*"
    Else
        $sMatDllType = "ptr"
    EndIf

    Local $sSizeDllType
    If IsDllStruct($size) Then
        $sSizeDllType = "struct*"
    Else
        $sSizeDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMatGetSize", $sMatDllType, $mat, $sSizeDllType, $size), "cveMatGetSize", @error)
EndFunc   ;==>_cveMatGetSize

Func _cveMatCopyTo($mat, $m, $mask)
    ; CVAPI(void) cveMatCopyTo(cv::Mat* mat, cv::_OutputArray* m, cv::_InputArray* mask);

    Local $sMatDllType
    If IsDllStruct($mat) Then
        $sMatDllType = "struct*"
    Else
        $sMatDllType = "ptr"
    EndIf

    Local $sMDllType
    If IsDllStruct($m) Then
        $sMDllType = "struct*"
    Else
        $sMDllType = "ptr"
    EndIf

    Local $sMaskDllType
    If IsDllStruct($mask) Then
        $sMaskDllType = "struct*"
    Else
        $sMaskDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMatCopyTo", $sMatDllType, $mat, $sMDllType, $m, $sMaskDllType, $mask), "cveMatCopyTo", @error)
EndFunc   ;==>_cveMatCopyTo

Func _cveMatCopyToTyped($mat, $typeOfM, $m, $typeOfMask, $mask)

    Local $oArrM, $vectorM, $iArrMSize
    Local $bMIsArray = IsArray($m)
    Local $bMCreate = IsDllStruct($m) And $typeOfM == "Scalar"

    If $typeOfM == Default Then
        $oArrM = $m
    ElseIf $bMIsArray Then
        $vectorM = Call("_VectorOf" & $typeOfM & "Create")

        $iArrMSize = UBound($m)
        For $i = 0 To $iArrMSize - 1
            Call("_VectorOf" & $typeOfM & "Push", $vectorM, $m[$i])
        Next

        $oArrM = Call("_cveOutputArrayFromVectorOf" & $typeOfM, $vectorM)
    Else
        If $bMCreate Then
            $m = Call("_cve" & $typeOfM & "Create", $m)
        EndIf
        $oArrM = Call("_cveOutputArrayFrom" & $typeOfM, $m)
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

    _cveMatCopyTo($mat, $oArrM, $iArrMask)

    If $bMaskIsArray Then
        Call("_VectorOf" & $typeOfMask & "Release", $vectorMask)
    EndIf

    If $typeOfMask <> Default Then
        _cveInputArrayRelease($iArrMask)
        If $bMaskCreate Then
            Call("_cve" & $typeOfMask & "Release", $mask)
        EndIf
    EndIf

    If $bMIsArray Then
        Call("_VectorOf" & $typeOfM & "Release", $vectorM)
    EndIf

    If $typeOfM <> Default Then
        _cveOutputArrayRelease($oArrM)
        If $bMCreate Then
            Call("_cve" & $typeOfM & "Release", $m)
        EndIf
    EndIf
EndFunc   ;==>_cveMatCopyToTyped

Func _cveMatCopyToMat($mat, $m, $mask)
    ; cveMatCopyTo using cv::Mat instead of _*Array
    _cveMatCopyToTyped($mat, "Mat", $m, "Mat", $mask)
EndFunc   ;==>_cveMatCopyToMat

Func _cveArrToMat($cvArray, $copyData, $allowND, $coiMode)
    ; CVAPI(cv::Mat*) cveArrToMat(CvArr* cvArray, bool copyData, bool allowND, int coiMode);

    Local $sCvArrayDllType
    If IsDllStruct($cvArray) Then
        $sCvArrayDllType = "struct*"
    Else
        $sCvArrayDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveArrToMat", $sCvArrayDllType, $cvArray, "boolean", $copyData, "boolean", $allowND, "int", $coiMode), "cveArrToMat", @error)
EndFunc   ;==>_cveArrToMat

Func _cveMatToIplImage($mat)
    ; CVAPI(IplImage*) cveMatToIplImage(cv::Mat* mat);

    Local $sMatDllType
    If IsDllStruct($mat) Then
        $sMatDllType = "struct*"
    Else
        $sMatDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveMatToIplImage", $sMatDllType, $mat), "cveMatToIplImage", @error)
EndFunc   ;==>_cveMatToIplImage

Func _cveMatGetElementSize($mat)
    ; CVAPI(int) cveMatGetElementSize(cv::Mat* mat);

    Local $sMatDllType
    If IsDllStruct($mat) Then
        $sMatDllType = "struct*"
    Else
        $sMatDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveMatGetElementSize", $sMatDllType, $mat), "cveMatGetElementSize", @error)
EndFunc   ;==>_cveMatGetElementSize

Func _cveMatGetDataPointer($mat)
    ; CVAPI(uchar*) cveMatGetDataPointer(cv::Mat* mat);

    Local $sMatDllType
    If IsDllStruct($mat) Then
        $sMatDllType = "struct*"
    Else
        $sMatDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveMatGetDataPointer", $sMatDllType, $mat), "cveMatGetDataPointer", @error)
EndFunc   ;==>_cveMatGetDataPointer

Func _cveMatGetDataPointer2($mat, $indices)
    ; CVAPI(uchar*) cveMatGetDataPointer2(cv::Mat* mat, int* indices);

    Local $sMatDllType
    If IsDllStruct($mat) Then
        $sMatDllType = "struct*"
    Else
        $sMatDllType = "ptr"
    EndIf

    Local $sIndicesDllType
    If IsDllStruct($indices) Then
        $sIndicesDllType = "struct*"
    Else
        $sIndicesDllType = "int*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveMatGetDataPointer2", $sMatDllType, $mat, $sIndicesDllType, $indices), "cveMatGetDataPointer2", @error)
EndFunc   ;==>_cveMatGetDataPointer2

Func _cveMatGetStep($mat)
    ; CVAPI(size_t) cveMatGetStep(cv::Mat* mat);

    Local $sMatDllType
    If IsDllStruct($mat) Then
        $sMatDllType = "struct*"
    Else
        $sMatDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ulong_ptr:cdecl", "cveMatGetStep", $sMatDllType, $mat), "cveMatGetStep", @error)
EndFunc   ;==>_cveMatGetStep

Func _cveMatSetTo($mat, $value, $mask)
    ; CVAPI(void) cveMatSetTo(cv::Mat* mat, cv::_InputArray* value, cv::_InputArray* mask);

    Local $sMatDllType
    If IsDllStruct($mat) Then
        $sMatDllType = "struct*"
    Else
        $sMatDllType = "ptr"
    EndIf

    Local $sValueDllType
    If IsDllStruct($value) Then
        $sValueDllType = "struct*"
    Else
        $sValueDllType = "ptr"
    EndIf

    Local $sMaskDllType
    If IsDllStruct($mask) Then
        $sMaskDllType = "struct*"
    Else
        $sMaskDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMatSetTo", $sMatDllType, $mat, $sValueDllType, $value, $sMaskDllType, $mask), "cveMatSetTo", @error)
EndFunc   ;==>_cveMatSetTo

Func _cveMatSetToTyped($mat, $typeOfValue, $value, $typeOfMask, $mask)

    Local $iArrValue, $vectorValue, $iArrValueSize
    Local $bValueIsArray = IsArray($value)
    Local $bValueCreate = IsDllStruct($value) And $typeOfValue == "Scalar"

    If $typeOfValue == Default Then
        $iArrValue = $value
    ElseIf $bValueIsArray Then
        $vectorValue = Call("_VectorOf" & $typeOfValue & "Create")

        $iArrValueSize = UBound($value)
        For $i = 0 To $iArrValueSize - 1
            Call("_VectorOf" & $typeOfValue & "Push", $vectorValue, $value[$i])
        Next

        $iArrValue = Call("_cveInputArrayFromVectorOf" & $typeOfValue, $vectorValue)
    Else
        If $bValueCreate Then
            $value = Call("_cve" & $typeOfValue & "Create", $value)
        EndIf
        $iArrValue = Call("_cveInputArrayFrom" & $typeOfValue, $value)
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

    _cveMatSetTo($mat, $iArrValue, $iArrMask)

    If $bMaskIsArray Then
        Call("_VectorOf" & $typeOfMask & "Release", $vectorMask)
    EndIf

    If $typeOfMask <> Default Then
        _cveInputArrayRelease($iArrMask)
        If $bMaskCreate Then
            Call("_cve" & $typeOfMask & "Release", $mask)
        EndIf
    EndIf

    If $bValueIsArray Then
        Call("_VectorOf" & $typeOfValue & "Release", $vectorValue)
    EndIf

    If $typeOfValue <> Default Then
        _cveInputArrayRelease($iArrValue)
        If $bValueCreate Then
            Call("_cve" & $typeOfValue & "Release", $value)
        EndIf
    EndIf
EndFunc   ;==>_cveMatSetToTyped

Func _cveMatSetToMat($mat, $value, $mask)
    ; cveMatSetTo using cv::Mat instead of _*Array
    _cveMatSetToTyped($mat, "Mat", $value, "Mat", $mask)
EndFunc   ;==>_cveMatSetToMat

Func _cveMatGetUMat($mat, $access, $usageFlags)
    ; CVAPI(cv::UMat*) cveMatGetUMat(cv::Mat* mat, int access, cv::UMatUsageFlags usageFlags);

    Local $sMatDllType
    If IsDllStruct($mat) Then
        $sMatDllType = "struct*"
    Else
        $sMatDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveMatGetUMat", $sMatDllType, $mat, "int", $access, "int", $usageFlags), "cveMatGetUMat", @error)
EndFunc   ;==>_cveMatGetUMat

Func _cveMatConvertTo($mat, $out, $rtype, $alpha, $beta)
    ; CVAPI(void) cveMatConvertTo(cv::Mat* mat, cv::_OutputArray* out, int rtype, double alpha, double beta);

    Local $sMatDllType
    If IsDllStruct($mat) Then
        $sMatDllType = "struct*"
    Else
        $sMatDllType = "ptr"
    EndIf

    Local $sOutDllType
    If IsDllStruct($out) Then
        $sOutDllType = "struct*"
    Else
        $sOutDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMatConvertTo", $sMatDllType, $mat, $sOutDllType, $out, "int", $rtype, "double", $alpha, "double", $beta), "cveMatConvertTo", @error)
EndFunc   ;==>_cveMatConvertTo

Func _cveMatConvertToTyped($mat, $typeOfOut, $out, $rtype, $alpha, $beta)

    Local $oArrOut, $vectorOut, $iArrOutSize
    Local $bOutIsArray = IsArray($out)
    Local $bOutCreate = IsDllStruct($out) And $typeOfOut == "Scalar"

    If $typeOfOut == Default Then
        $oArrOut = $out
    ElseIf $bOutIsArray Then
        $vectorOut = Call("_VectorOf" & $typeOfOut & "Create")

        $iArrOutSize = UBound($out)
        For $i = 0 To $iArrOutSize - 1
            Call("_VectorOf" & $typeOfOut & "Push", $vectorOut, $out[$i])
        Next

        $oArrOut = Call("_cveOutputArrayFromVectorOf" & $typeOfOut, $vectorOut)
    Else
        If $bOutCreate Then
            $out = Call("_cve" & $typeOfOut & "Create", $out)
        EndIf
        $oArrOut = Call("_cveOutputArrayFrom" & $typeOfOut, $out)
    EndIf

    _cveMatConvertTo($mat, $oArrOut, $rtype, $alpha, $beta)

    If $bOutIsArray Then
        Call("_VectorOf" & $typeOfOut & "Release", $vectorOut)
    EndIf

    If $typeOfOut <> Default Then
        _cveOutputArrayRelease($oArrOut)
        If $bOutCreate Then
            Call("_cve" & $typeOfOut & "Release", $out)
        EndIf
    EndIf
EndFunc   ;==>_cveMatConvertToTyped

Func _cveMatConvertToMat($mat, $out, $rtype, $alpha, $beta)
    ; cveMatConvertTo using cv::Mat instead of _*Array
    _cveMatConvertToTyped($mat, "Mat", $out, $rtype, $alpha, $beta)
EndFunc   ;==>_cveMatConvertToMat

Func _cveMatReshape($mat, $cn, $rows)
    ; CVAPI(cv::Mat*) cveMatReshape(cv::Mat* mat, int cn, int rows);

    Local $sMatDllType
    If IsDllStruct($mat) Then
        $sMatDllType = "struct*"
    Else
        $sMatDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveMatReshape", $sMatDllType, $mat, "int", $cn, "int", $rows), "cveMatReshape", @error)
EndFunc   ;==>_cveMatReshape

Func _cveMatDot($mat, $m)
    ; CVAPI(double) cveMatDot(cv::Mat* mat, cv::_InputArray* m);

    Local $sMatDllType
    If IsDllStruct($mat) Then
        $sMatDllType = "struct*"
    Else
        $sMatDllType = "ptr"
    EndIf

    Local $sMDllType
    If IsDllStruct($m) Then
        $sMDllType = "struct*"
    Else
        $sMDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveMatDot", $sMatDllType, $mat, $sMDllType, $m), "cveMatDot", @error)
EndFunc   ;==>_cveMatDot

Func _cveMatDotTyped($mat, $typeOfM, $m)

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

    Local $retval = _cveMatDot($mat, $iArrM)

    If $bMIsArray Then
        Call("_VectorOf" & $typeOfM & "Release", $vectorM)
    EndIf

    If $typeOfM <> Default Then
        _cveInputArrayRelease($iArrM)
        If $bMCreate Then
            Call("_cve" & $typeOfM & "Release", $m)
        EndIf
    EndIf

    Return $retval
EndFunc   ;==>_cveMatDotTyped

Func _cveMatDotMat($mat, $m)
    ; cveMatDot using cv::Mat instead of _*Array
    Local $retval = _cveMatDotTyped($mat, "Mat", $m)

    Return $retval
EndFunc   ;==>_cveMatDotMat

Func _cveMatCross($mat, $m, $result)
    ; CVAPI(void) cveMatCross(cv::Mat* mat, cv::_InputArray* m, cv::Mat* result);

    Local $sMatDllType
    If IsDllStruct($mat) Then
        $sMatDllType = "struct*"
    Else
        $sMatDllType = "ptr"
    EndIf

    Local $sMDllType
    If IsDllStruct($m) Then
        $sMDllType = "struct*"
    Else
        $sMDllType = "ptr"
    EndIf

    Local $sResultDllType
    If IsDllStruct($result) Then
        $sResultDllType = "struct*"
    Else
        $sResultDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMatCross", $sMatDllType, $mat, $sMDllType, $m, $sResultDllType, $result), "cveMatCross", @error)
EndFunc   ;==>_cveMatCross

Func _cveMatCrossTyped($mat, $typeOfM, $m, $result)

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

    _cveMatCross($mat, $iArrM, $result)

    If $bMIsArray Then
        Call("_VectorOf" & $typeOfM & "Release", $vectorM)
    EndIf

    If $typeOfM <> Default Then
        _cveInputArrayRelease($iArrM)
        If $bMCreate Then
            Call("_cve" & $typeOfM & "Release", $m)
        EndIf
    EndIf
EndFunc   ;==>_cveMatCrossTyped

Func _cveMatCrossMat($mat, $m, $result)
    ; cveMatCross using cv::Mat instead of _*Array
    _cveMatCrossTyped($mat, "Mat", $m, $result)
EndFunc   ;==>_cveMatCrossMat

Func _cveMatCopyDataTo($mat, $dest)
    ; CVAPI(void) cveMatCopyDataTo(cv::Mat* mat, unsigned char* dest);

    Local $sMatDllType
    If IsDllStruct($mat) Then
        $sMatDllType = "struct*"
    Else
        $sMatDllType = "ptr"
    EndIf

    Local $sDestDllType
    If IsDllStruct($dest) Then
        $sDestDllType = "struct*"
    Else
        $sDestDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMatCopyDataTo", $sMatDllType, $mat, $sDestDllType, $dest), "cveMatCopyDataTo", @error)
EndFunc   ;==>_cveMatCopyDataTo

Func _cveMatCopyDataFrom($mat, $source)
    ; CVAPI(void) cveMatCopyDataFrom(cv::Mat* mat, unsigned char* source);

    Local $sMatDllType
    If IsDllStruct($mat) Then
        $sMatDllType = "struct*"
    Else
        $sMatDllType = "ptr"
    EndIf

    Local $sSourceDllType
    If IsDllStruct($source) Then
        $sSourceDllType = "struct*"
    Else
        $sSourceDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMatCopyDataFrom", $sMatDllType, $mat, $sSourceDllType, $source), "cveMatCopyDataFrom", @error)
EndFunc   ;==>_cveMatCopyDataFrom

Func _cveMatGetSizeOfDimension($mat, $sizes)
    ; CVAPI(void) cveMatGetSizeOfDimension(cv::Mat* mat, int* sizes);

    Local $sMatDllType
    If IsDllStruct($mat) Then
        $sMatDllType = "struct*"
    Else
        $sMatDllType = "ptr"
    EndIf

    Local $sSizesDllType
    If IsDllStruct($sizes) Then
        $sSizesDllType = "struct*"
    Else
        $sSizesDllType = "int*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMatGetSizeOfDimension", $sMatDllType, $mat, $sSizesDllType, $sizes), "cveMatGetSizeOfDimension", @error)
EndFunc   ;==>_cveMatGetSizeOfDimension

Func _cveSwapMat($mat1, $mat2)
    ; CVAPI(void) cveSwapMat(cv::Mat* mat1, cv::Mat* mat2);

    Local $sMat1DllType
    If IsDllStruct($mat1) Then
        $sMat1DllType = "struct*"
    Else
        $sMat1DllType = "ptr"
    EndIf

    Local $sMat2DllType
    If IsDllStruct($mat2) Then
        $sMat2DllType = "struct*"
    Else
        $sMat2DllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSwapMat", $sMat1DllType, $mat1, $sMat2DllType, $mat2), "cveSwapMat", @error)
EndFunc   ;==>_cveSwapMat

Func _cveMatEye($rows, $cols, $type, $m)
    ; CVAPI(void) cveMatEye(int rows, int cols, int type, cv::Mat* m);

    Local $sMDllType
    If IsDllStruct($m) Then
        $sMDllType = "struct*"
    Else
        $sMDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMatEye", "int", $rows, "int", $cols, "int", $type, $sMDllType, $m), "cveMatEye", @error)
EndFunc   ;==>_cveMatEye

Func _cveMatDiag($src, $d, $dst)
    ; CVAPI(void) cveMatDiag(cv::Mat* src, int d, cv::Mat* dst);

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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMatDiag", $sSrcDllType, $src, "int", $d, $sDstDllType, $dst), "cveMatDiag", @error)
EndFunc   ;==>_cveMatDiag

Func _cveMatT($src, $dst)
    ; CVAPI(void) cveMatT(cv::Mat* src, cv::Mat* dst);

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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMatT", $sSrcDllType, $src, $sDstDllType, $dst), "cveMatT", @error)
EndFunc   ;==>_cveMatT

Func _cveMatZeros($rows, $cols, $type, $dst)
    ; CVAPI(void) cveMatZeros(int rows, int cols, int type, cv::Mat* dst);

    Local $sDstDllType
    If IsDllStruct($dst) Then
        $sDstDllType = "struct*"
    Else
        $sDstDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMatZeros", "int", $rows, "int", $cols, "int", $type, $sDstDllType, $dst), "cveMatZeros", @error)
EndFunc   ;==>_cveMatZeros

Func _cveMatOnes($rows, $cols, $type, $dst)
    ; CVAPI(void) cveMatOnes(int rows, int cols, int type, cv::Mat* dst);

    Local $sDstDllType
    If IsDllStruct($dst) Then
        $sDstDllType = "struct*"
    Else
        $sDstDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMatOnes", "int", $rows, "int", $cols, "int", $type, $sDstDllType, $dst), "cveMatOnes", @error)
EndFunc   ;==>_cveMatOnes