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

Func _cveUMatCopyToMat($mat, $matM, $matMask)
    ; cveUMatCopyTo using cv::Mat instead of _*Array

    Local $oArrM, $vectorOfMatM, $iArrMSize
    Local $bMIsArray = VarGetType($matM) == "Array"

    If $bMIsArray Then
        $vectorOfMatM = _VectorOfMatCreate()

        $iArrMSize = UBound($matM)
        For $i = 0 To $iArrMSize - 1
            _VectorOfMatPush($vectorOfMatM, $matM[$i])
        Next

        $oArrM = _cveOutputArrayFromVectorOfMat($vectorOfMatM)
    Else
        $oArrM = _cveOutputArrayFromMat($matM)
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

    _cveUMatCopyTo($mat, $oArrM, $iArrMask)

    If $bMaskIsArray Then
        _VectorOfMatRelease($vectorOfMatMask)
    EndIf

    _cveInputArrayRelease($iArrMask)

    If $bMIsArray Then
        _VectorOfMatRelease($vectorOfMatM)
    EndIf

    _cveOutputArrayRelease($oArrM)
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

Func _cveUMatSetToMat($mat, $matValue, $matMask)
    ; cveUMatSetTo using cv::Mat instead of _*Array

    Local $iArrValue, $vectorOfMatValue, $iArrValueSize
    Local $bValueIsArray = VarGetType($matValue) == "Array"

    If $bValueIsArray Then
        $vectorOfMatValue = _VectorOfMatCreate()

        $iArrValueSize = UBound($matValue)
        For $i = 0 To $iArrValueSize - 1
            _VectorOfMatPush($vectorOfMatValue, $matValue[$i])
        Next

        $iArrValue = _cveInputArrayFromVectorOfMat($vectorOfMatValue)
    Else
        $iArrValue = _cveInputArrayFromMat($matValue)
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

    _cveUMatSetTo($mat, $iArrValue, $iArrMask)

    If $bMaskIsArray Then
        _VectorOfMatRelease($vectorOfMatMask)
    EndIf

    _cveInputArrayRelease($iArrMask)

    If $bValueIsArray Then
        _VectorOfMatRelease($vectorOfMatValue)
    EndIf

    _cveInputArrayRelease($iArrValue)
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

Func _cveUMatConvertToMat($mat, $matOut, $rtype, $alpha, $beta)
    ; cveUMatConvertTo using cv::Mat instead of _*Array

    Local $oArrOut, $vectorOfMatOut, $iArrOutSize
    Local $bOutIsArray = VarGetType($matOut) == "Array"

    If $bOutIsArray Then
        $vectorOfMatOut = _VectorOfMatCreate()

        $iArrOutSize = UBound($matOut)
        For $i = 0 To $iArrOutSize - 1
            _VectorOfMatPush($vectorOfMatOut, $matOut[$i])
        Next

        $oArrOut = _cveOutputArrayFromVectorOfMat($vectorOfMatOut)
    Else
        $oArrOut = _cveOutputArrayFromMat($matOut)
    EndIf

    _cveUMatConvertTo($mat, $oArrOut, $rtype, $alpha, $beta)

    If $bOutIsArray Then
        _VectorOfMatRelease($vectorOfMatOut)
    EndIf

    _cveOutputArrayRelease($oArrOut)
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

Func _cveUMatDotMat($mat, $matM)
    ; cveUMatDot using cv::Mat instead of _*Array

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

    Local $retval = _cveUMatDot($mat, $iArrM)

    If $bMIsArray Then
        _VectorOfMatRelease($vectorOfMatM)
    EndIf

    _cveInputArrayRelease($iArrM)

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