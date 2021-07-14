#include-once
#include "..\CVEUtils.au3"

Func _VectorOfDoubleCreate()
    ; CVAPI(std::vector< double >*) VectorOfDoubleCreate();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfDoubleCreate"), "VectorOfDoubleCreate", @error)
EndFunc   ;==>_VectorOfDoubleCreate

Func _VectorOfDoubleCreateSize($size)
    ; CVAPI(std::vector< double >*) VectorOfDoubleCreateSize(int size);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfDoubleCreateSize", "int", $size), "VectorOfDoubleCreateSize", @error)
EndFunc   ;==>_VectorOfDoubleCreateSize

Func _VectorOfDoubleGetSize(ByRef $v)
    ; CVAPI(int) VectorOfDoubleGetSize(std::vector< double >* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfDoubleCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfDoublePush($vecV, $v[$i])
        Next
    Else
        $vecV = $v
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "VectorOfDoubleGetSize", "ptr", $vecV), "VectorOfDoubleGetSize", @error)

    If $bVIsArray Then
        _VectorOfDoubleRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfDoubleGetSize

Func _VectorOfDoublePush(ByRef $v, ByRef $value)
    ; CVAPI(void) VectorOfDoublePush(std::vector< double >* v, double* value);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfDoubleCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfDoublePush($vecV, $v[$i])
        Next
    Else
        $vecV = $v
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfDoublePush", "ptr", $vecV, "double*", $value), "VectorOfDoublePush", @error)

    If $bVIsArray Then
        _VectorOfDoubleRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfDoublePush

Func _VectorOfDoublePushMulti(ByRef $v, ByRef $values, $count)
    ; CVAPI(void) VectorOfDoublePushMulti(std::vector< double >* v, double* values, int count);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfDoubleCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfDoublePush($vecV, $v[$i])
        Next
    Else
        $vecV = $v
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfDoublePushMulti", "ptr", $vecV, "struct*", $values, "int", $count), "VectorOfDoublePushMulti", @error)

    If $bVIsArray Then
        _VectorOfDoubleRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfDoublePushMulti

Func _VectorOfDoublePushVector(ByRef $v, ByRef $other)
    ; CVAPI(void) VectorOfDoublePushVector(std::vector< double >* v, std::vector< double >* other);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfDoubleCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfDoublePush($vecV, $v[$i])
        Next
    Else
        $vecV = $v
    EndIf

    Local $vecOther, $iArrOtherSize
    Local $bOtherIsArray = VarGetType($other) == "Array"

    If $bOtherIsArray Then
        $vecOther = _VectorOfDoubleCreate()

        $iArrOtherSize = UBound($other)
        For $i = 0 To $iArrOtherSize - 1
            _VectorOfDoublePush($vecOther, $other[$i])
        Next
    Else
        $vecOther = $other
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfDoublePushVector", "ptr", $vecV, "ptr", $vecOther), "VectorOfDoublePushVector", @error)

    If $bOtherIsArray Then
        _VectorOfDoubleRelease($vecOther)
    EndIf

    If $bVIsArray Then
        _VectorOfDoubleRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfDoublePushVector

Func _VectorOfDoubleClear(ByRef $v)
    ; CVAPI(void) VectorOfDoubleClear(std::vector< double >* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfDoubleCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfDoublePush($vecV, $v[$i])
        Next
    Else
        $vecV = $v
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfDoubleClear", "ptr", $vecV), "VectorOfDoubleClear", @error)

    If $bVIsArray Then
        _VectorOfDoubleRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfDoubleClear

Func _VectorOfDoubleRelease(ByRef $v)
    ; CVAPI(void) VectorOfDoubleRelease(std::vector< double >** v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfDoubleCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfDoublePush($vecV, $v[$i])
        Next
    Else
        $vecV = $v
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfDoubleRelease", "ptr*", $vecV), "VectorOfDoubleRelease", @error)

    If $bVIsArray Then
        _VectorOfDoubleRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfDoubleRelease

Func _VectorOfDoubleCopyData(ByRef $v, ByRef $data)
    ; CVAPI(void) VectorOfDoubleCopyData(std::vector< double >* v, double* data);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfDoubleCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfDoublePush($vecV, $v[$i])
        Next
    Else
        $vecV = $v
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfDoubleCopyData", "ptr", $vecV, "struct*", $data), "VectorOfDoubleCopyData", @error)

    If $bVIsArray Then
        _VectorOfDoubleRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfDoubleCopyData

Func _VectorOfDoubleGetStartAddress(ByRef $v)
    ; CVAPI(double*) VectorOfDoubleGetStartAddress(std::vector< double >* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfDoubleCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfDoublePush($vecV, $v[$i])
        Next
    Else
        $vecV = $v
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfDoubleGetStartAddress", "ptr", $vecV), "VectorOfDoubleGetStartAddress", @error)

    If $bVIsArray Then
        _VectorOfDoubleRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfDoubleGetStartAddress

Func _VectorOfDoubleGetEndAddress(ByRef $v)
    ; CVAPI(void*) VectorOfDoubleGetEndAddress(std::vector< double >* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfDoubleCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfDoublePush($vecV, $v[$i])
        Next
    Else
        $vecV = $v
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfDoubleGetEndAddress", "ptr", $vecV), "VectorOfDoubleGetEndAddress", @error)

    If $bVIsArray Then
        _VectorOfDoubleRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfDoubleGetEndAddress

Func _VectorOfDoubleGetItem(ByRef $vec, $index, ByRef $element)
    ; CVAPI(void) VectorOfDoubleGetItem(std::vector<  double >* vec, int index, double* element);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfDoubleCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfDoublePush($vecVec, $vec[$i])
        Next
    Else
        $vecVec = $vec
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfDoubleGetItem", "ptr", $vecVec, "int", $index, "struct*", $element), "VectorOfDoubleGetItem", @error)

    If $bVecIsArray Then
        _VectorOfDoubleRelease($vecVec)
    EndIf
EndFunc   ;==>_VectorOfDoubleGetItem

Func _VectorOfDoubleGetItemPtr(ByRef $vec, $index, ByRef $element)
    ; CVAPI(void) VectorOfDoubleGetItemPtr(std::vector<  double >* vec, int index, double** element);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfDoubleCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfDoublePush($vecVec, $vec[$i])
        Next
    Else
        $vecVec = $vec
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfDoubleGetItemPtr", "ptr", $vecVec, "int", $index, "ptr*", $element), "VectorOfDoubleGetItemPtr", @error)

    If $bVecIsArray Then
        _VectorOfDoubleRelease($vecVec)
    EndIf
EndFunc   ;==>_VectorOfDoubleGetItemPtr

Func _cveInputArrayFromVectorOfDouble(ByRef $vec)
    ; CVAPI(cv::_InputArray*) cveInputArrayFromVectorOfDouble(std::vector< double >* vec);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfDoubleCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfDoublePush($vecVec, $vec[$i])
        Next
    Else
        $vecVec = $vec
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveInputArrayFromVectorOfDouble", "ptr", $vecVec), "cveInputArrayFromVectorOfDouble", @error)

    If $bVecIsArray Then
        _VectorOfDoubleRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveInputArrayFromVectorOfDouble

Func _cveOutputArrayFromVectorOfDouble(ByRef $vec)
    ; CVAPI(cv::_OutputArray*) cveOutputArrayFromVectorOfDouble(std::vector< double >* vec);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfDoubleCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfDoublePush($vecVec, $vec[$i])
        Next
    Else
        $vecVec = $vec
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveOutputArrayFromVectorOfDouble", "ptr", $vecVec), "cveOutputArrayFromVectorOfDouble", @error)

    If $bVecIsArray Then
        _VectorOfDoubleRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveOutputArrayFromVectorOfDouble

Func _cveInputOutputArrayFromVectorOfDouble(ByRef $vec)
    ; CVAPI(cv::_InputOutputArray*) cveInputOutputArrayFromVectorOfDouble(std::vector< double >* vec);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfDoubleCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfDoublePush($vecVec, $vec[$i])
        Next
    Else
        $vecVec = $vec
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveInputOutputArrayFromVectorOfDouble", "ptr", $vecVec), "cveInputOutputArrayFromVectorOfDouble", @error)

    If $bVecIsArray Then
        _VectorOfDoubleRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveInputOutputArrayFromVectorOfDouble

Func _VectorOfDoubleSizeOfItemInBytes()
    ; CVAPI(int) VectorOfDoubleSizeOfItemInBytes();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "VectorOfDoubleSizeOfItemInBytes"), "VectorOfDoubleSizeOfItemInBytes", @error)
EndFunc   ;==>_VectorOfDoubleSizeOfItemInBytes