#include-once
#include <..\..\CVEUtils.au3>

Func _cveUMatCreate($flags)
    ; CVAPI(cv::UMat*) cveUMatCreate(cv::UMatUsageFlags flags);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveUMatCreate", "cv::UMatUsageFlags", $flags), "cveUMatCreate", @error)
EndFunc   ;==>_cveUMatCreate

Func _cveUMatCreateData(ByRef $mat, $row, $cols, $type, $flags)
    ; CVAPI(void) cveUMatCreateData(cv::UMat* mat, int row, int cols, int type, cv::UMatUsageFlags flags);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveUMatCreateData", "ptr", $mat, "int", $row, "int", $cols, "int", $type, "cv::UMatUsageFlags", $flags), "cveUMatCreateData", @error)
EndFunc   ;==>_cveUMatCreateData

Func _cveUMatCreateFromRect(ByRef $mat, ByRef $roi)
    ; CVAPI(cv::UMat*) cveUMatCreateFromRect(cv::UMat* mat, CvRect* roi);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveUMatCreateFromRect", "ptr", $mat, "struct*", $roi), "cveUMatCreateFromRect", @error)
EndFunc   ;==>_cveUMatCreateFromRect

Func _cveUMatCreateFromRange(ByRef $mat, ByRef $rowRange, ByRef $colRange)
    ; CVAPI(cv::UMat*) cveUMatCreateFromRange(cv::UMat* mat, cv::Range* rowRange, cv::Range* colRange);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveUMatCreateFromRange", "ptr", $mat, "ptr", $rowRange, "ptr", $colRange), "cveUMatCreateFromRange", @error)
EndFunc   ;==>_cveUMatCreateFromRange

Func _cveUMatRelease(ByRef $mat)
    ; CVAPI(void) cveUMatRelease(cv::UMat** mat);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveUMatRelease", "ptr*", $mat), "cveUMatRelease", @error)
EndFunc   ;==>_cveUMatRelease

Func _cveUMatGetSize(ByRef $mat, ByRef $size)
    ; CVAPI(void) cveUMatGetSize(cv::UMat* mat, CvSize* size);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveUMatGetSize", "ptr", $mat, "struct*", $size), "cveUMatGetSize", @error)
EndFunc   ;==>_cveUMatGetSize

Func _cveUMatCopyTo(ByRef $mat, ByRef $m, ByRef $mask)
    ; CVAPI(void) cveUMatCopyTo(cv::UMat* mat, cv::_OutputArray* m, cv::_InputArray* mask);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveUMatCopyTo", "ptr", $mat, "ptr", $m, "ptr", $mask), "cveUMatCopyTo", @error)
EndFunc   ;==>_cveUMatCopyTo

Func _cveUMatCopyToMat(ByRef $mat, ByRef $matM, ByRef $matMask)
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

Func _cveUMatGetElementSize(ByRef $mat)
    ; CVAPI(int) cveUMatGetElementSize(cv::UMat* mat);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveUMatGetElementSize", "ptr", $mat), "cveUMatGetElementSize", @error)
EndFunc   ;==>_cveUMatGetElementSize

Func _cveUMatSetTo(ByRef $mat, ByRef $value, ByRef $mask)
    ; CVAPI(void) cveUMatSetTo(cv::UMat* mat, cv::_InputArray* value, cv::_InputArray* mask);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveUMatSetTo", "ptr", $mat, "ptr", $value, "ptr", $mask), "cveUMatSetTo", @error)
EndFunc   ;==>_cveUMatSetTo

Func _cveUMatSetToMat(ByRef $mat, ByRef $matValue, ByRef $matMask)
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

Func _cveUMatGetMat(ByRef $mat, $access)
    ; CVAPI(cv::Mat*) cveUMatGetMat(cv::UMat* mat, int access);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveUMatGetMat", "ptr", $mat, "int", $access), "cveUMatGetMat", @error)
EndFunc   ;==>_cveUMatGetMat

Func _cveUMatConvertTo(ByRef $mat, ByRef $out, $rtype, $alpha, $beta)
    ; CVAPI(void) cveUMatConvertTo(cv::UMat* mat, cv::_OutputArray* out, int rtype, double alpha, double beta);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveUMatConvertTo", "ptr", $mat, "ptr", $out, "int", $rtype, "double", $alpha, "double", $beta), "cveUMatConvertTo", @error)
EndFunc   ;==>_cveUMatConvertTo

Func _cveUMatConvertToMat(ByRef $mat, ByRef $matOut, $rtype, $alpha, $beta)
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

Func _cveUMatReshape(ByRef $mat, $cn, $rows)
    ; CVAPI(cv::UMat*) cveUMatReshape(cv::UMat* mat, int cn, int rows);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveUMatReshape", "ptr", $mat, "int", $cn, "int", $rows), "cveUMatReshape", @error)
EndFunc   ;==>_cveUMatReshape

Func _cveUMatCopyDataTo(ByRef $mat, ByRef $dest)
    ; CVAPI(void) cveUMatCopyDataTo(cv::UMat* mat, unsigned char* dest);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveUMatCopyDataTo", "ptr", $mat, "ptr", $dest), "cveUMatCopyDataTo", @error)
EndFunc   ;==>_cveUMatCopyDataTo

Func _cveUMatCopyDataFrom(ByRef $mat, ByRef $source)
    ; CVAPI(void) cveUMatCopyDataFrom(cv::UMat* mat, unsigned char* source);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveUMatCopyDataFrom", "ptr", $mat, "ptr", $source), "cveUMatCopyDataFrom", @error)
EndFunc   ;==>_cveUMatCopyDataFrom

Func _cveUMatDot(ByRef $mat, ByRef $m)
    ; CVAPI(double) cveUMatDot(cv::UMat* mat, cv::_InputArray* m);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveUMatDot", "ptr", $mat, "ptr", $m), "cveUMatDot", @error)
EndFunc   ;==>_cveUMatDot

Func _cveUMatDotMat(ByRef $mat, ByRef $matM)
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

Func _cveSwapUMat(ByRef $mat1, ByRef $mat2)
    ; CVAPI(void) cveSwapUMat(cv::UMat* mat1, cv::UMat* mat2);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSwapUMat", "ptr", $mat1, "ptr", $mat2), "cveSwapUMat", @error)
EndFunc   ;==>_cveSwapUMat