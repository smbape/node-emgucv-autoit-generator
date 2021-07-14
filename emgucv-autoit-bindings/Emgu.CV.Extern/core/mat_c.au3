#include-once
#include <..\..\CVEUtils.au3>

Func _cveMatCreate()
    ; CVAPI(cv::Mat*) cveMatCreate();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveMatCreate"), "cveMatCreate", @error)
EndFunc   ;==>_cveMatCreate

Func _cveMatCreateData(ByRef $mat, $row, $cols, $type)
    ; CVAPI(void) cveMatCreateData(cv::Mat* mat, int row, int cols, int type);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMatCreateData", "ptr", $mat, "int", $row, "int", $cols, "int", $type), "cveMatCreateData", @error)
EndFunc   ;==>_cveMatCreateData

Func _cveMatCreateWithData($rows, $cols, $type, ByRef $data, $step)
    ; CVAPI(cv::Mat*) cveMatCreateWithData(int rows, int cols, int type, void* data, size_t step);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveMatCreateWithData", "int", $rows, "int", $cols, "int", $type, "struct*", $data, "ulong_ptr", $step), "cveMatCreateWithData", @error)
EndFunc   ;==>_cveMatCreateWithData

Func _cveMatCreateMultiDimWithData($ndims, $sizes, $type, ByRef $data, ByRef $steps)
    ; CVAPI(cv::Mat*) cveMatCreateMultiDimWithData(int ndims, const int* sizes, int type, void* data, size_t* steps);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveMatCreateMultiDimWithData", "int", $ndims, "const int*", $sizes, "int", $type, "struct*", $data, "struct*", $steps), "cveMatCreateMultiDimWithData", @error)
EndFunc   ;==>_cveMatCreateMultiDimWithData

Func _cveMatCreateFromRect(ByRef $mat, ByRef $roi)
    ; CVAPI(cv::Mat*) cveMatCreateFromRect(cv::Mat* mat, CvRect* roi);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveMatCreateFromRect", "ptr", $mat, "struct*", $roi), "cveMatCreateFromRect", @error)
EndFunc   ;==>_cveMatCreateFromRect

Func _cveMatCreateFromRange(ByRef $mat, ByRef $rowRange, ByRef $colRange)
    ; CVAPI(cv::Mat*) cveMatCreateFromRange(cv::Mat* mat, cv::Range* rowRange, cv::Range* colRange);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveMatCreateFromRange", "ptr", $mat, "ptr", $rowRange, "ptr", $colRange), "cveMatCreateFromRange", @error)
EndFunc   ;==>_cveMatCreateFromRange

Func _cveMatRelease(ByRef $mat)
    ; CVAPI(void) cveMatRelease(cv::Mat** mat);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMatRelease", "ptr*", $mat), "cveMatRelease", @error)
EndFunc   ;==>_cveMatRelease

Func _cveMatGetSize(ByRef $mat, ByRef $size)
    ; CVAPI(void) cveMatGetSize(cv::Mat* mat, CvSize* size);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMatGetSize", "ptr", $mat, "struct*", $size), "cveMatGetSize", @error)
EndFunc   ;==>_cveMatGetSize

Func _cveMatCopyTo(ByRef $mat, ByRef $m, ByRef $mask)
    ; CVAPI(void) cveMatCopyTo(cv::Mat* mat, cv::_OutputArray* m, cv::_InputArray* mask);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMatCopyTo", "ptr", $mat, "ptr", $m, "ptr", $mask), "cveMatCopyTo", @error)
EndFunc   ;==>_cveMatCopyTo

Func _cveMatCopyToMat(ByRef $mat, ByRef $matM, ByRef $matMask)
    ; cveMatCopyTo using cv::Mat instead of _*Array

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

    _cveMatCopyTo($mat, $oArrM, $iArrMask)

    If $bMaskIsArray Then
        _VectorOfMatRelease($vectorOfMatMask)
    EndIf

    _cveInputArrayRelease($iArrMask)

    If $bMIsArray Then
        _VectorOfMatRelease($vectorOfMatM)
    EndIf

    _cveOutputArrayRelease($oArrM)
EndFunc   ;==>_cveMatCopyToMat

Func _cveArrToMat(ByRef $cvArray, $copyData, $allowND, $coiMode)
    ; CVAPI(cv::Mat*) cveArrToMat(CvArr* cvArray, bool copyData, bool allowND, int coiMode);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveArrToMat", "struct*", $cvArray, "boolean", $copyData, "boolean", $allowND, "int", $coiMode), "cveArrToMat", @error)
EndFunc   ;==>_cveArrToMat

Func _cveMatToIplImage(ByRef $mat)
    ; CVAPI(IplImage*) cveMatToIplImage(cv::Mat* mat);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveMatToIplImage", "ptr", $mat), "cveMatToIplImage", @error)
EndFunc   ;==>_cveMatToIplImage

Func _cveMatGetElementSize(ByRef $mat)
    ; CVAPI(int) cveMatGetElementSize(cv::Mat* mat);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveMatGetElementSize", "ptr", $mat), "cveMatGetElementSize", @error)
EndFunc   ;==>_cveMatGetElementSize

Func _cveMatGetDataPointer(ByRef $mat)
    ; CVAPI(uchar*) cveMatGetDataPointer(cv::Mat* mat);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveMatGetDataPointer", "ptr", $mat), "cveMatGetDataPointer", @error)
EndFunc   ;==>_cveMatGetDataPointer

Func _cveMatGetDataPointer2(ByRef $mat, ByRef $indices)
    ; CVAPI(uchar*) cveMatGetDataPointer2(cv::Mat* mat, int* indices);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveMatGetDataPointer2", "ptr", $mat, "struct*", $indices), "cveMatGetDataPointer2", @error)
EndFunc   ;==>_cveMatGetDataPointer2

Func _cveMatGetStep(ByRef $mat)
    ; CVAPI(size_t) cveMatGetStep(cv::Mat* mat);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ulong_ptr:cdecl", "cveMatGetStep", "ptr", $mat), "cveMatGetStep", @error)
EndFunc   ;==>_cveMatGetStep

Func _cveMatSetTo(ByRef $mat, ByRef $value, ByRef $mask)
    ; CVAPI(void) cveMatSetTo(cv::Mat* mat, cv::_InputArray* value, cv::_InputArray* mask);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMatSetTo", "ptr", $mat, "ptr", $value, "ptr", $mask), "cveMatSetTo", @error)
EndFunc   ;==>_cveMatSetTo

Func _cveMatSetToMat(ByRef $mat, ByRef $matValue, ByRef $matMask)
    ; cveMatSetTo using cv::Mat instead of _*Array

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

    _cveMatSetTo($mat, $iArrValue, $iArrMask)

    If $bMaskIsArray Then
        _VectorOfMatRelease($vectorOfMatMask)
    EndIf

    _cveInputArrayRelease($iArrMask)

    If $bValueIsArray Then
        _VectorOfMatRelease($vectorOfMatValue)
    EndIf

    _cveInputArrayRelease($iArrValue)
EndFunc   ;==>_cveMatSetToMat

Func _cveMatGetUMat(ByRef $mat, $access, $usageFlags)
    ; CVAPI(cv::UMat*) cveMatGetUMat(cv::Mat* mat, int access, cv::UMatUsageFlags usageFlags);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveMatGetUMat", "ptr", $mat, "int", $access, "cv::UMatUsageFlags", $usageFlags), "cveMatGetUMat", @error)
EndFunc   ;==>_cveMatGetUMat

Func _cveMatConvertTo(ByRef $mat, ByRef $out, $rtype, $alpha, $beta)
    ; CVAPI(void) cveMatConvertTo(cv::Mat* mat, cv::_OutputArray* out, int rtype, double alpha, double beta);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMatConvertTo", "ptr", $mat, "ptr", $out, "int", $rtype, "double", $alpha, "double", $beta), "cveMatConvertTo", @error)
EndFunc   ;==>_cveMatConvertTo

Func _cveMatConvertToMat(ByRef $mat, ByRef $matOut, $rtype, $alpha, $beta)
    ; cveMatConvertTo using cv::Mat instead of _*Array

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

    _cveMatConvertTo($mat, $oArrOut, $rtype, $alpha, $beta)

    If $bOutIsArray Then
        _VectorOfMatRelease($vectorOfMatOut)
    EndIf

    _cveOutputArrayRelease($oArrOut)
EndFunc   ;==>_cveMatConvertToMat

Func _cveMatReshape(ByRef $mat, $cn, $rows)
    ; CVAPI(cv::Mat*) cveMatReshape(cv::Mat* mat, int cn, int rows);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveMatReshape", "ptr", $mat, "int", $cn, "int", $rows), "cveMatReshape", @error)
EndFunc   ;==>_cveMatReshape

Func _cveMatDot(ByRef $mat, ByRef $m)
    ; CVAPI(double) cveMatDot(cv::Mat* mat, cv::_InputArray* m);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveMatDot", "ptr", $mat, "ptr", $m), "cveMatDot", @error)
EndFunc   ;==>_cveMatDot

Func _cveMatDotMat(ByRef $mat, ByRef $matM)
    ; cveMatDot using cv::Mat instead of _*Array

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

    Local $retval = _cveMatDot($mat, $iArrM)

    If $bMIsArray Then
        _VectorOfMatRelease($vectorOfMatM)
    EndIf

    _cveInputArrayRelease($iArrM)

    Return $retval
EndFunc   ;==>_cveMatDotMat

Func _cveMatCross(ByRef $mat, ByRef $m, ByRef $result)
    ; CVAPI(void) cveMatCross(cv::Mat* mat, cv::_InputArray* m, cv::Mat* result);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMatCross", "ptr", $mat, "ptr", $m, "ptr", $result), "cveMatCross", @error)
EndFunc   ;==>_cveMatCross

Func _cveMatCrossMat(ByRef $mat, ByRef $matM, ByRef $result)
    ; cveMatCross using cv::Mat instead of _*Array

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

    _cveMatCross($mat, $iArrM, $result)

    If $bMIsArray Then
        _VectorOfMatRelease($vectorOfMatM)
    EndIf

    _cveInputArrayRelease($iArrM)
EndFunc   ;==>_cveMatCrossMat

Func _cveMatCopyDataTo(ByRef $mat, ByRef $dest)
    ; CVAPI(void) cveMatCopyDataTo(cv::Mat* mat, unsigned char* dest);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMatCopyDataTo", "ptr", $mat, "ptr", $dest), "cveMatCopyDataTo", @error)
EndFunc   ;==>_cveMatCopyDataTo

Func _cveMatCopyDataFrom(ByRef $mat, ByRef $source)
    ; CVAPI(void) cveMatCopyDataFrom(cv::Mat* mat, unsigned char* source);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMatCopyDataFrom", "ptr", $mat, "ptr", $source), "cveMatCopyDataFrom", @error)
EndFunc   ;==>_cveMatCopyDataFrom

Func _cveMatGetSizeOfDimension(ByRef $mat, ByRef $sizes)
    ; CVAPI(void) cveMatGetSizeOfDimension(cv::Mat* mat, int* sizes);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMatGetSizeOfDimension", "ptr", $mat, "struct*", $sizes), "cveMatGetSizeOfDimension", @error)
EndFunc   ;==>_cveMatGetSizeOfDimension

Func _cveSwapMat(ByRef $mat1, ByRef $mat2)
    ; CVAPI(void) cveSwapMat(cv::Mat* mat1, cv::Mat* mat2);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSwapMat", "ptr", $mat1, "ptr", $mat2), "cveSwapMat", @error)
EndFunc   ;==>_cveSwapMat

Func _cveMatEye($rows, $cols, $type, ByRef $m)
    ; CVAPI(void) cveMatEye(int rows, int cols, int type, cv::Mat* m);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMatEye", "int", $rows, "int", $cols, "int", $type, "ptr", $m), "cveMatEye", @error)
EndFunc   ;==>_cveMatEye

Func _cveMatDiag(ByRef $src, $d, ByRef $dst)
    ; CVAPI(void) cveMatDiag(cv::Mat* src, int d, cv::Mat* dst);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMatDiag", "ptr", $src, "int", $d, "ptr", $dst), "cveMatDiag", @error)
EndFunc   ;==>_cveMatDiag

Func _cveMatT(ByRef $src, ByRef $dst)
    ; CVAPI(void) cveMatT(cv::Mat* src, cv::Mat* dst);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMatT", "ptr", $src, "ptr", $dst), "cveMatT", @error)
EndFunc   ;==>_cveMatT

Func _cveMatZeros($rows, $cols, $type, ByRef $dst)
    ; CVAPI(void) cveMatZeros(int rows, int cols, int type, cv::Mat* dst);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMatZeros", "int", $rows, "int", $cols, "int", $type, "ptr", $dst), "cveMatZeros", @error)
EndFunc   ;==>_cveMatZeros

Func _cveMatOnes($rows, $cols, $type, ByRef $dst)
    ; CVAPI(void) cveMatOnes(int rows, int cols, int type, cv::Mat* dst);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMatOnes", "int", $rows, "int", $cols, "int", $type, "ptr", $dst), "cveMatOnes", @error)
EndFunc   ;==>_cveMatOnes