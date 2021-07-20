#include-once
#include "..\..\CVEUtils.au3"

Func _cveUMatCreate($flags)
    ; CVAPI(cv::UMat*) cveUMatCreate(cv::UMatUsageFlags flags);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveUMatCreate", "cv::UMatUsageFlags", $flags), "cveUMatCreate", @error)
EndFunc   ;==>_cveUMatCreate

Func _cveUMatCreateData($mat, $row, $cols, $type, $flags)
    ; CVAPI(void) cveUMatCreateData(cv::UMat* mat, int row, int cols, int type, cv::UMatUsageFlags flags);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveUMatCreateData", "ptr", $mat, "int", $row, "int", $cols, "int", $type, "cv::UMatUsageFlags", $flags), "cveUMatCreateData", @error)
EndFunc   ;==>_cveUMatCreateData

Func _cveUMatCreateFromRect($mat, $roi)
    ; CVAPI(cv::UMat*) cveUMatCreateFromRect(cv::UMat* mat, CvRect* roi);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveUMatCreateFromRect", "ptr", $mat, "struct*", $roi), "cveUMatCreateFromRect", @error)
EndFunc   ;==>_cveUMatCreateFromRect

Func _cveUMatCreateFromRange($mat, $rowRange, $colRange)
    ; CVAPI(cv::UMat*) cveUMatCreateFromRange(cv::UMat* mat, cv::Range* rowRange, cv::Range* colRange);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveUMatCreateFromRange", "ptr", $mat, "ptr", $rowRange, "ptr", $colRange), "cveUMatCreateFromRange", @error)
EndFunc   ;==>_cveUMatCreateFromRange

Func _cveUMatRelease($mat)
    ; CVAPI(void) cveUMatRelease(cv::UMat** mat);

    Local $bMatDllType
    If VarGetType($mat) == "DLLStruct" Then
        $bMatDllType = "struct*"
    Else
        $bMatDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveUMatRelease", $bMatDllType, $mat), "cveUMatRelease", @error)
EndFunc   ;==>_cveUMatRelease

Func _cveUMatGetSize($mat, $size)
    ; CVAPI(void) cveUMatGetSize(cv::UMat* mat, CvSize* size);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveUMatGetSize", "ptr", $mat, "struct*", $size), "cveUMatGetSize", @error)
EndFunc   ;==>_cveUMatGetSize

Func _cveUMatCopyTo($mat, $m, $mask)
    ; CVAPI(void) cveUMatCopyTo(cv::UMat* mat, cv::_OutputArray* m, cv::_InputArray* mask);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveUMatCopyTo", "ptr", $mat, "ptr", $m, "ptr", $mask), "cveUMatCopyTo", @error)
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
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveUMatGetElementSize", "ptr", $mat), "cveUMatGetElementSize", @error)
EndFunc   ;==>_cveUMatGetElementSize

Func _cveUMatSetTo($mat, $value, $mask)
    ; CVAPI(void) cveUMatSetTo(cv::UMat* mat, cv::_InputArray* value, cv::_InputArray* mask);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveUMatSetTo", "ptr", $mat, "ptr", $value, "ptr", $mask), "cveUMatSetTo", @error)
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
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveUMatGetMat", "ptr", $mat, "int", $access), "cveUMatGetMat", @error)
EndFunc   ;==>_cveUMatGetMat

Func _cveUMatConvertTo($mat, $out, $rtype, $alpha, $beta)
    ; CVAPI(void) cveUMatConvertTo(cv::UMat* mat, cv::_OutputArray* out, int rtype, double alpha, double beta);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveUMatConvertTo", "ptr", $mat, "ptr", $out, "int", $rtype, "double", $alpha, "double", $beta), "cveUMatConvertTo", @error)
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
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveUMatReshape", "ptr", $mat, "int", $cn, "int", $rows), "cveUMatReshape", @error)
EndFunc   ;==>_cveUMatReshape

Func _cveUMatCopyDataTo($mat, $dest)
    ; CVAPI(void) cveUMatCopyDataTo(cv::UMat* mat, unsigned char* dest);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveUMatCopyDataTo", "ptr", $mat, "ptr", $dest), "cveUMatCopyDataTo", @error)
EndFunc   ;==>_cveUMatCopyDataTo

Func _cveUMatCopyDataFrom($mat, $source)
    ; CVAPI(void) cveUMatCopyDataFrom(cv::UMat* mat, unsigned char* source);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveUMatCopyDataFrom", "ptr", $mat, "ptr", $source), "cveUMatCopyDataFrom", @error)
EndFunc   ;==>_cveUMatCopyDataFrom

Func _cveUMatDot($mat, $m)
    ; CVAPI(double) cveUMatDot(cv::UMat* mat, cv::_InputArray* m);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveUMatDot", "ptr", $mat, "ptr", $m), "cveUMatDot", @error)
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
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSwapUMat", "ptr", $mat1, "ptr", $mat2), "cveSwapUMat", @error)
EndFunc   ;==>_cveSwapUMat