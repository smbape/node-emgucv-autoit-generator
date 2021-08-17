#include-once
#include "..\..\CVEUtils.au3"

Func _cveMatCreate()
    ; CVAPI(cv::Mat*) cveMatCreate();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveMatCreate"), "cveMatCreate", @error)
EndFunc   ;==>_cveMatCreate

Func _cveMatCreateData($mat, $row, $cols, $type)
    ; CVAPI(void) cveMatCreateData(cv::Mat* mat, int row, int cols, int type);

    Local $bMatDllType
    If VarGetType($mat) == "DLLStruct" Then
        $bMatDllType = "struct*"
    Else
        $bMatDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMatCreateData", $bMatDllType, $mat, "int", $row, "int", $cols, "int", $type), "cveMatCreateData", @error)
EndFunc   ;==>_cveMatCreateData

Func _cveMatCreateWithData($rows, $cols, $type, $data, $step)
    ; CVAPI(cv::Mat*) cveMatCreateWithData(int rows, int cols, int type, void* data, size_t step);

    Local $bDataDllType
    If VarGetType($data) == "DLLStruct" Then
        $bDataDllType = "struct*"
    Else
        $bDataDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveMatCreateWithData", "int", $rows, "int", $cols, "int", $type, $bDataDllType, $data, "ulong_ptr", $step), "cveMatCreateWithData", @error)
EndFunc   ;==>_cveMatCreateWithData

Func _cveMatCreateMultiDimWithData($ndims, $sizes, $type, $data, $steps)
    ; CVAPI(cv::Mat*) cveMatCreateMultiDimWithData(int ndims, const int* sizes, int type, void* data, size_t* steps);

    Local $bSizesDllType
    If VarGetType($sizes) == "DLLStruct" Then
        $bSizesDllType = "struct*"
    Else
        $bSizesDllType = "int*"
    EndIf

    Local $bDataDllType
    If VarGetType($data) == "DLLStruct" Then
        $bDataDllType = "struct*"
    Else
        $bDataDllType = "ptr"
    EndIf

    Local $bStepsDllType
    If VarGetType($steps) == "DLLStruct" Then
        $bStepsDllType = "struct*"
    Else
        $bStepsDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveMatCreateMultiDimWithData", "int", $ndims, $bSizesDllType, $sizes, "int", $type, $bDataDllType, $data, $bStepsDllType, $steps), "cveMatCreateMultiDimWithData", @error)
EndFunc   ;==>_cveMatCreateMultiDimWithData

Func _cveMatCreateFromRect($mat, $roi)
    ; CVAPI(cv::Mat*) cveMatCreateFromRect(cv::Mat* mat, CvRect* roi);

    Local $bMatDllType
    If VarGetType($mat) == "DLLStruct" Then
        $bMatDllType = "struct*"
    Else
        $bMatDllType = "ptr"
    EndIf

    Local $bRoiDllType
    If VarGetType($roi) == "DLLStruct" Then
        $bRoiDllType = "struct*"
    Else
        $bRoiDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveMatCreateFromRect", $bMatDllType, $mat, $bRoiDllType, $roi), "cveMatCreateFromRect", @error)
EndFunc   ;==>_cveMatCreateFromRect

Func _cveMatCreateFromRange($mat, $rowRange, $colRange)
    ; CVAPI(cv::Mat*) cveMatCreateFromRange(cv::Mat* mat, cv::Range* rowRange, cv::Range* colRange);

    Local $bMatDllType
    If VarGetType($mat) == "DLLStruct" Then
        $bMatDllType = "struct*"
    Else
        $bMatDllType = "ptr"
    EndIf

    Local $bRowRangeDllType
    If VarGetType($rowRange) == "DLLStruct" Then
        $bRowRangeDllType = "struct*"
    Else
        $bRowRangeDllType = "ptr"
    EndIf

    Local $bColRangeDllType
    If VarGetType($colRange) == "DLLStruct" Then
        $bColRangeDllType = "struct*"
    Else
        $bColRangeDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveMatCreateFromRange", $bMatDllType, $mat, $bRowRangeDllType, $rowRange, $bColRangeDllType, $colRange), "cveMatCreateFromRange", @error)
EndFunc   ;==>_cveMatCreateFromRange

Func _cveMatRelease($mat)
    ; CVAPI(void) cveMatRelease(cv::Mat** mat);

    Local $bMatDllType
    If VarGetType($mat) == "DLLStruct" Then
        $bMatDllType = "struct*"
    Else
        $bMatDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMatRelease", $bMatDllType, $mat), "cveMatRelease", @error)
EndFunc   ;==>_cveMatRelease

Func _cveMatGetSize($mat, $size)
    ; CVAPI(void) cveMatGetSize(cv::Mat* mat, CvSize* size);

    Local $bMatDllType
    If VarGetType($mat) == "DLLStruct" Then
        $bMatDllType = "struct*"
    Else
        $bMatDllType = "ptr"
    EndIf

    Local $bSizeDllType
    If VarGetType($size) == "DLLStruct" Then
        $bSizeDllType = "struct*"
    Else
        $bSizeDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMatGetSize", $bMatDllType, $mat, $bSizeDllType, $size), "cveMatGetSize", @error)
EndFunc   ;==>_cveMatGetSize

Func _cveMatCopyTo($mat, $m, $mask)
    ; CVAPI(void) cveMatCopyTo(cv::Mat* mat, cv::_OutputArray* m, cv::_InputArray* mask);

    Local $bMatDllType
    If VarGetType($mat) == "DLLStruct" Then
        $bMatDllType = "struct*"
    Else
        $bMatDllType = "ptr"
    EndIf

    Local $bMDllType
    If VarGetType($m) == "DLLStruct" Then
        $bMDllType = "struct*"
    Else
        $bMDllType = "ptr"
    EndIf

    Local $bMaskDllType
    If VarGetType($mask) == "DLLStruct" Then
        $bMaskDllType = "struct*"
    Else
        $bMaskDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMatCopyTo", $bMatDllType, $mat, $bMDllType, $m, $bMaskDllType, $mask), "cveMatCopyTo", @error)
EndFunc   ;==>_cveMatCopyTo

Func _cveMatCopyToMat($mat, $matM, $matMask)
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

Func _cveArrToMat($cvArray, $copyData, $allowND, $coiMode)
    ; CVAPI(cv::Mat*) cveArrToMat(CvArr* cvArray, bool copyData, bool allowND, int coiMode);

    Local $bCvArrayDllType
    If VarGetType($cvArray) == "DLLStruct" Then
        $bCvArrayDllType = "struct*"
    Else
        $bCvArrayDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveArrToMat", $bCvArrayDllType, $cvArray, "boolean", $copyData, "boolean", $allowND, "int", $coiMode), "cveArrToMat", @error)
EndFunc   ;==>_cveArrToMat

Func _cveMatToIplImage($mat)
    ; CVAPI(IplImage*) cveMatToIplImage(cv::Mat* mat);

    Local $bMatDllType
    If VarGetType($mat) == "DLLStruct" Then
        $bMatDllType = "struct*"
    Else
        $bMatDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveMatToIplImage", $bMatDllType, $mat), "cveMatToIplImage", @error)
EndFunc   ;==>_cveMatToIplImage

Func _cveMatGetElementSize($mat)
    ; CVAPI(int) cveMatGetElementSize(cv::Mat* mat);

    Local $bMatDllType
    If VarGetType($mat) == "DLLStruct" Then
        $bMatDllType = "struct*"
    Else
        $bMatDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveMatGetElementSize", $bMatDllType, $mat), "cveMatGetElementSize", @error)
EndFunc   ;==>_cveMatGetElementSize

Func _cveMatGetDataPointer($mat)
    ; CVAPI(uchar*) cveMatGetDataPointer(cv::Mat* mat);

    Local $bMatDllType
    If VarGetType($mat) == "DLLStruct" Then
        $bMatDllType = "struct*"
    Else
        $bMatDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveMatGetDataPointer", $bMatDllType, $mat), "cveMatGetDataPointer", @error)
EndFunc   ;==>_cveMatGetDataPointer

Func _cveMatGetDataPointer2($mat, $indices)
    ; CVAPI(uchar*) cveMatGetDataPointer2(cv::Mat* mat, int* indices);

    Local $bMatDllType
    If VarGetType($mat) == "DLLStruct" Then
        $bMatDllType = "struct*"
    Else
        $bMatDllType = "ptr"
    EndIf

    Local $bIndicesDllType
    If VarGetType($indices) == "DLLStruct" Then
        $bIndicesDllType = "struct*"
    Else
        $bIndicesDllType = "int*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveMatGetDataPointer2", $bMatDllType, $mat, $bIndicesDllType, $indices), "cveMatGetDataPointer2", @error)
EndFunc   ;==>_cveMatGetDataPointer2

Func _cveMatGetStep($mat)
    ; CVAPI(size_t) cveMatGetStep(cv::Mat* mat);

    Local $bMatDllType
    If VarGetType($mat) == "DLLStruct" Then
        $bMatDllType = "struct*"
    Else
        $bMatDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ulong_ptr:cdecl", "cveMatGetStep", $bMatDllType, $mat), "cveMatGetStep", @error)
EndFunc   ;==>_cveMatGetStep

Func _cveMatSetTo($mat, $value, $mask)
    ; CVAPI(void) cveMatSetTo(cv::Mat* mat, cv::_InputArray* value, cv::_InputArray* mask);

    Local $bMatDllType
    If VarGetType($mat) == "DLLStruct" Then
        $bMatDllType = "struct*"
    Else
        $bMatDllType = "ptr"
    EndIf

    Local $bValueDllType
    If VarGetType($value) == "DLLStruct" Then
        $bValueDllType = "struct*"
    Else
        $bValueDllType = "ptr"
    EndIf

    Local $bMaskDllType
    If VarGetType($mask) == "DLLStruct" Then
        $bMaskDllType = "struct*"
    Else
        $bMaskDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMatSetTo", $bMatDllType, $mat, $bValueDllType, $value, $bMaskDllType, $mask), "cveMatSetTo", @error)
EndFunc   ;==>_cveMatSetTo

Func _cveMatSetToMat($mat, $matValue, $matMask)
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

Func _cveMatGetUMat($mat, $access, $usageFlags)
    ; CVAPI(cv::UMat*) cveMatGetUMat(cv::Mat* mat, int access, cv::UMatUsageFlags usageFlags);

    Local $bMatDllType
    If VarGetType($mat) == "DLLStruct" Then
        $bMatDllType = "struct*"
    Else
        $bMatDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveMatGetUMat", $bMatDllType, $mat, "int", $access, "int", $usageFlags), "cveMatGetUMat", @error)
EndFunc   ;==>_cveMatGetUMat

Func _cveMatConvertTo($mat, $out, $rtype, $alpha, $beta)
    ; CVAPI(void) cveMatConvertTo(cv::Mat* mat, cv::_OutputArray* out, int rtype, double alpha, double beta);

    Local $bMatDllType
    If VarGetType($mat) == "DLLStruct" Then
        $bMatDllType = "struct*"
    Else
        $bMatDllType = "ptr"
    EndIf

    Local $bOutDllType
    If VarGetType($out) == "DLLStruct" Then
        $bOutDllType = "struct*"
    Else
        $bOutDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMatConvertTo", $bMatDllType, $mat, $bOutDllType, $out, "int", $rtype, "double", $alpha, "double", $beta), "cveMatConvertTo", @error)
EndFunc   ;==>_cveMatConvertTo

Func _cveMatConvertToMat($mat, $matOut, $rtype, $alpha, $beta)
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

Func _cveMatReshape($mat, $cn, $rows)
    ; CVAPI(cv::Mat*) cveMatReshape(cv::Mat* mat, int cn, int rows);

    Local $bMatDllType
    If VarGetType($mat) == "DLLStruct" Then
        $bMatDllType = "struct*"
    Else
        $bMatDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveMatReshape", $bMatDllType, $mat, "int", $cn, "int", $rows), "cveMatReshape", @error)
EndFunc   ;==>_cveMatReshape

Func _cveMatDot($mat, $m)
    ; CVAPI(double) cveMatDot(cv::Mat* mat, cv::_InputArray* m);

    Local $bMatDllType
    If VarGetType($mat) == "DLLStruct" Then
        $bMatDllType = "struct*"
    Else
        $bMatDllType = "ptr"
    EndIf

    Local $bMDllType
    If VarGetType($m) == "DLLStruct" Then
        $bMDllType = "struct*"
    Else
        $bMDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveMatDot", $bMatDllType, $mat, $bMDllType, $m), "cveMatDot", @error)
EndFunc   ;==>_cveMatDot

Func _cveMatDotMat($mat, $matM)
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

Func _cveMatCross($mat, $m, $result)
    ; CVAPI(void) cveMatCross(cv::Mat* mat, cv::_InputArray* m, cv::Mat* result);

    Local $bMatDllType
    If VarGetType($mat) == "DLLStruct" Then
        $bMatDllType = "struct*"
    Else
        $bMatDllType = "ptr"
    EndIf

    Local $bMDllType
    If VarGetType($m) == "DLLStruct" Then
        $bMDllType = "struct*"
    Else
        $bMDllType = "ptr"
    EndIf

    Local $bResultDllType
    If VarGetType($result) == "DLLStruct" Then
        $bResultDllType = "struct*"
    Else
        $bResultDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMatCross", $bMatDllType, $mat, $bMDllType, $m, $bResultDllType, $result), "cveMatCross", @error)
EndFunc   ;==>_cveMatCross

Func _cveMatCrossMat($mat, $matM, $result)
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

Func _cveMatCopyDataTo($mat, $dest)
    ; CVAPI(void) cveMatCopyDataTo(cv::Mat* mat, unsigned char* dest);

    Local $bMatDllType
    If VarGetType($mat) == "DLLStruct" Then
        $bMatDllType = "struct*"
    Else
        $bMatDllType = "ptr"
    EndIf

    Local $bDestDllType
    If VarGetType($dest) == "DLLStruct" Then
        $bDestDllType = "struct*"
    Else
        $bDestDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMatCopyDataTo", $bMatDllType, $mat, $bDestDllType, $dest), "cveMatCopyDataTo", @error)
EndFunc   ;==>_cveMatCopyDataTo

Func _cveMatCopyDataFrom($mat, $source)
    ; CVAPI(void) cveMatCopyDataFrom(cv::Mat* mat, unsigned char* source);

    Local $bMatDllType
    If VarGetType($mat) == "DLLStruct" Then
        $bMatDllType = "struct*"
    Else
        $bMatDllType = "ptr"
    EndIf

    Local $bSourceDllType
    If VarGetType($source) == "DLLStruct" Then
        $bSourceDllType = "struct*"
    Else
        $bSourceDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMatCopyDataFrom", $bMatDllType, $mat, $bSourceDllType, $source), "cveMatCopyDataFrom", @error)
EndFunc   ;==>_cveMatCopyDataFrom

Func _cveMatGetSizeOfDimension($mat, $sizes)
    ; CVAPI(void) cveMatGetSizeOfDimension(cv::Mat* mat, int* sizes);

    Local $bMatDllType
    If VarGetType($mat) == "DLLStruct" Then
        $bMatDllType = "struct*"
    Else
        $bMatDllType = "ptr"
    EndIf

    Local $bSizesDllType
    If VarGetType($sizes) == "DLLStruct" Then
        $bSizesDllType = "struct*"
    Else
        $bSizesDllType = "int*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMatGetSizeOfDimension", $bMatDllType, $mat, $bSizesDllType, $sizes), "cveMatGetSizeOfDimension", @error)
EndFunc   ;==>_cveMatGetSizeOfDimension

Func _cveSwapMat($mat1, $mat2)
    ; CVAPI(void) cveSwapMat(cv::Mat* mat1, cv::Mat* mat2);

    Local $bMat1DllType
    If VarGetType($mat1) == "DLLStruct" Then
        $bMat1DllType = "struct*"
    Else
        $bMat1DllType = "ptr"
    EndIf

    Local $bMat2DllType
    If VarGetType($mat2) == "DLLStruct" Then
        $bMat2DllType = "struct*"
    Else
        $bMat2DllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSwapMat", $bMat1DllType, $mat1, $bMat2DllType, $mat2), "cveSwapMat", @error)
EndFunc   ;==>_cveSwapMat

Func _cveMatEye($rows, $cols, $type, $m)
    ; CVAPI(void) cveMatEye(int rows, int cols, int type, cv::Mat* m);

    Local $bMDllType
    If VarGetType($m) == "DLLStruct" Then
        $bMDllType = "struct*"
    Else
        $bMDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMatEye", "int", $rows, "int", $cols, "int", $type, $bMDllType, $m), "cveMatEye", @error)
EndFunc   ;==>_cveMatEye

Func _cveMatDiag($src, $d, $dst)
    ; CVAPI(void) cveMatDiag(cv::Mat* src, int d, cv::Mat* dst);

    Local $bSrcDllType
    If VarGetType($src) == "DLLStruct" Then
        $bSrcDllType = "struct*"
    Else
        $bSrcDllType = "ptr"
    EndIf

    Local $bDstDllType
    If VarGetType($dst) == "DLLStruct" Then
        $bDstDllType = "struct*"
    Else
        $bDstDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMatDiag", $bSrcDllType, $src, "int", $d, $bDstDllType, $dst), "cveMatDiag", @error)
EndFunc   ;==>_cveMatDiag

Func _cveMatT($src, $dst)
    ; CVAPI(void) cveMatT(cv::Mat* src, cv::Mat* dst);

    Local $bSrcDllType
    If VarGetType($src) == "DLLStruct" Then
        $bSrcDllType = "struct*"
    Else
        $bSrcDllType = "ptr"
    EndIf

    Local $bDstDllType
    If VarGetType($dst) == "DLLStruct" Then
        $bDstDllType = "struct*"
    Else
        $bDstDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMatT", $bSrcDllType, $src, $bDstDllType, $dst), "cveMatT", @error)
EndFunc   ;==>_cveMatT

Func _cveMatZeros($rows, $cols, $type, $dst)
    ; CVAPI(void) cveMatZeros(int rows, int cols, int type, cv::Mat* dst);

    Local $bDstDllType
    If VarGetType($dst) == "DLLStruct" Then
        $bDstDllType = "struct*"
    Else
        $bDstDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMatZeros", "int", $rows, "int", $cols, "int", $type, $bDstDllType, $dst), "cveMatZeros", @error)
EndFunc   ;==>_cveMatZeros

Func _cveMatOnes($rows, $cols, $type, $dst)
    ; CVAPI(void) cveMatOnes(int rows, int cols, int type, cv::Mat* dst);

    Local $bDstDllType
    If VarGetType($dst) == "DLLStruct" Then
        $bDstDllType = "struct*"
    Else
        $bDstDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMatOnes", "int", $rows, "int", $cols, "int", $type, $bDstDllType, $dst), "cveMatOnes", @error)
EndFunc   ;==>_cveMatOnes