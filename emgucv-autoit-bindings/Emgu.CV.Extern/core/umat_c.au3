#include-once
#include "..\..\CVEUtils.au3"

Func _cveUMatCreate($flags)
    ; CVAPI(cv::UMat*) cveUMatCreate(cv::UMatUsageFlags flags);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveUMatCreate", "int", $flags), "cveUMatCreate", @error)
EndFunc   ;==>_cveUMatCreate

Func _cveUMatCreateData($mat, $row, $cols, $type, $flags)
    ; CVAPI(void) cveUMatCreateData(cv::UMat* mat, int row, int cols, int type, cv::UMatUsageFlags flags);

    Local $sMatDllType
    If IsDllStruct($mat) Then
        $sMatDllType = "struct*"
    Else
        $sMatDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveUMatCreateData", $sMatDllType, $mat, "int", $row, "int", $cols, "int", $type, "int", $flags), "cveUMatCreateData", @error)
EndFunc   ;==>_cveUMatCreateData

Func _cveUMatCreateFromRect($mat, $roi)
    ; CVAPI(cv::UMat*) cveUMatCreateFromRect(cv::UMat* mat, CvRect* roi);

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
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveUMatCreateFromRect", $sMatDllType, $mat, $sRoiDllType, $roi), "cveUMatCreateFromRect", @error)
EndFunc   ;==>_cveUMatCreateFromRect

Func _cveUMatCreateFromRange($mat, $rowRange, $colRange)
    ; CVAPI(cv::UMat*) cveUMatCreateFromRange(cv::UMat* mat, cv::Range* rowRange, cv::Range* colRange);

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
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveUMatCreateFromRange", $sMatDllType, $mat, $sRowRangeDllType, $rowRange, $sColRangeDllType, $colRange), "cveUMatCreateFromRange", @error)
EndFunc   ;==>_cveUMatCreateFromRange

Func _cveUMatRelease($mat)
    ; CVAPI(void) cveUMatRelease(cv::UMat** mat);

    Local $sMatDllType
    If IsDllStruct($mat) Then
        $sMatDllType = "struct*"
    ElseIf $mat == Null Then
        $sMatDllType = "ptr"
    Else
        $sMatDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveUMatRelease", $sMatDllType, $mat), "cveUMatRelease", @error)
EndFunc   ;==>_cveUMatRelease

Func _cveUMatGetSize($mat, $size)
    ; CVAPI(void) cveUMatGetSize(cv::UMat* mat, CvSize* size);

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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveUMatGetSize", $sMatDllType, $mat, $sSizeDllType, $size), "cveUMatGetSize", @error)
EndFunc   ;==>_cveUMatGetSize

Func _cveUMatCopyTo($mat, $m, $mask)
    ; CVAPI(void) cveUMatCopyTo(cv::UMat* mat, cv::_OutputArray* m, cv::_InputArray* mask);

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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveUMatCopyTo", $sMatDllType, $mat, $sMDllType, $m, $sMaskDllType, $mask), "cveUMatCopyTo", @error)
EndFunc   ;==>_cveUMatCopyTo

Func _cveUMatCopyToTyped($mat, $typeOfM, $m, $typeOfMask, $mask)

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

    _cveUMatCopyTo($mat, $oArrM, $iArrMask)

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
EndFunc   ;==>_cveUMatCopyToTyped

Func _cveUMatCopyToMat($mat, $m, $mask)
    ; cveUMatCopyTo using cv::Mat instead of _*Array
    _cveUMatCopyToTyped($mat, "Mat", $m, "Mat", $mask)
EndFunc   ;==>_cveUMatCopyToMat

Func _cveUMatGetElementSize($mat)
    ; CVAPI(int) cveUMatGetElementSize(cv::UMat* mat);

    Local $sMatDllType
    If IsDllStruct($mat) Then
        $sMatDllType = "struct*"
    Else
        $sMatDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveUMatGetElementSize", $sMatDllType, $mat), "cveUMatGetElementSize", @error)
EndFunc   ;==>_cveUMatGetElementSize

Func _cveUMatSetTo($mat, $value, $mask)
    ; CVAPI(void) cveUMatSetTo(cv::UMat* mat, cv::_InputArray* value, cv::_InputArray* mask);

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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveUMatSetTo", $sMatDllType, $mat, $sValueDllType, $value, $sMaskDllType, $mask), "cveUMatSetTo", @error)
EndFunc   ;==>_cveUMatSetTo

Func _cveUMatSetToTyped($mat, $typeOfValue, $value, $typeOfMask, $mask)

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

    _cveUMatSetTo($mat, $iArrValue, $iArrMask)

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
EndFunc   ;==>_cveUMatSetToTyped

Func _cveUMatSetToMat($mat, $value, $mask)
    ; cveUMatSetTo using cv::Mat instead of _*Array
    _cveUMatSetToTyped($mat, "Mat", $value, "Mat", $mask)
EndFunc   ;==>_cveUMatSetToMat

Func _cveUMatGetMat($mat, $access)
    ; CVAPI(cv::Mat*) cveUMatGetMat(cv::UMat* mat, int access);

    Local $sMatDllType
    If IsDllStruct($mat) Then
        $sMatDllType = "struct*"
    Else
        $sMatDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveUMatGetMat", $sMatDllType, $mat, "int", $access), "cveUMatGetMat", @error)
EndFunc   ;==>_cveUMatGetMat

Func _cveUMatConvertTo($mat, $out, $rtype, $alpha, $beta)
    ; CVAPI(void) cveUMatConvertTo(cv::UMat* mat, cv::_OutputArray* out, int rtype, double alpha, double beta);

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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveUMatConvertTo", $sMatDllType, $mat, $sOutDllType, $out, "int", $rtype, "double", $alpha, "double", $beta), "cveUMatConvertTo", @error)
EndFunc   ;==>_cveUMatConvertTo

Func _cveUMatConvertToTyped($mat, $typeOfOut, $out, $rtype, $alpha, $beta)

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

    _cveUMatConvertTo($mat, $oArrOut, $rtype, $alpha, $beta)

    If $bOutIsArray Then
        Call("_VectorOf" & $typeOfOut & "Release", $vectorOut)
    EndIf

    If $typeOfOut <> Default Then
        _cveOutputArrayRelease($oArrOut)
        If $bOutCreate Then
            Call("_cve" & $typeOfOut & "Release", $out)
        EndIf
    EndIf
EndFunc   ;==>_cveUMatConvertToTyped

Func _cveUMatConvertToMat($mat, $out, $rtype, $alpha, $beta)
    ; cveUMatConvertTo using cv::Mat instead of _*Array
    _cveUMatConvertToTyped($mat, "Mat", $out, $rtype, $alpha, $beta)
EndFunc   ;==>_cveUMatConvertToMat

Func _cveUMatReshape($mat, $cn, $rows)
    ; CVAPI(cv::UMat*) cveUMatReshape(cv::UMat* mat, int cn, int rows);

    Local $sMatDllType
    If IsDllStruct($mat) Then
        $sMatDllType = "struct*"
    Else
        $sMatDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveUMatReshape", $sMatDllType, $mat, "int", $cn, "int", $rows), "cveUMatReshape", @error)
EndFunc   ;==>_cveUMatReshape

Func _cveUMatCopyDataTo($mat, $dest)
    ; CVAPI(void) cveUMatCopyDataTo(cv::UMat* mat, unsigned char* dest);

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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveUMatCopyDataTo", $sMatDllType, $mat, $sDestDllType, $dest), "cveUMatCopyDataTo", @error)
EndFunc   ;==>_cveUMatCopyDataTo

Func _cveUMatCopyDataFrom($mat, $source)
    ; CVAPI(void) cveUMatCopyDataFrom(cv::UMat* mat, unsigned char* source);

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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveUMatCopyDataFrom", $sMatDllType, $mat, $sSourceDllType, $source), "cveUMatCopyDataFrom", @error)
EndFunc   ;==>_cveUMatCopyDataFrom

Func _cveUMatDot($mat, $m)
    ; CVAPI(double) cveUMatDot(cv::UMat* mat, cv::_InputArray* m);

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
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveUMatDot", $sMatDllType, $mat, $sMDllType, $m), "cveUMatDot", @error)
EndFunc   ;==>_cveUMatDot

Func _cveUMatDotTyped($mat, $typeOfM, $m)

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

    Local $retval = _cveUMatDot($mat, $iArrM)

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
EndFunc   ;==>_cveUMatDotTyped

Func _cveUMatDotMat($mat, $m)
    ; cveUMatDot using cv::Mat instead of _*Array
    Local $retval = _cveUMatDotTyped($mat, "Mat", $m)

    Return $retval
EndFunc   ;==>_cveUMatDotMat

Func _cveSwapUMat($mat1, $mat2)
    ; CVAPI(void) cveSwapUMat(cv::UMat* mat1, cv::UMat* mat2);

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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSwapUMat", $sMat1DllType, $mat1, $sMat2DllType, $mat2), "cveSwapUMat", @error)
EndFunc   ;==>_cveSwapUMat