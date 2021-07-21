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

Func _VectorOfDoubleGetSize($v)
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

    Local $bVDllType
    If VarGetType($v) == "DLLStruct" Then
        $bVDllType = "struct*"
    Else
        $bVDllType = "ptr"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "VectorOfDoubleGetSize", $bVDllType, $vecV), "VectorOfDoubleGetSize", @error)

    If $bVIsArray Then
        _VectorOfDoubleRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfDoubleGetSize

Func _VectorOfDoublePush($v, $value)
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

    Local $bVDllType
    If VarGetType($v) == "DLLStruct" Then
        $bVDllType = "struct*"
    Else
        $bVDllType = "ptr"
    EndIf

    Local $bValueDllType
    If VarGetType($value) == "DLLStruct" Then
        $bValueDllType = "struct*"
    Else
        $bValueDllType = "double*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfDoublePush", $bVDllType, $vecV, "double*", $value), "VectorOfDoublePush", @error)

    If $bVIsArray Then
        _VectorOfDoubleRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfDoublePush

Func _VectorOfDoublePushMulti($v, $values, $count)
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

    Local $bVDllType
    If VarGetType($v) == "DLLStruct" Then
        $bVDllType = "struct*"
    Else
        $bVDllType = "ptr"
    EndIf

    Local $bValuesDllType
    If VarGetType($values) == "DLLStruct" Then
        $bValuesDllType = "struct*"
    Else
        $bValuesDllType = "double*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfDoublePushMulti", $bVDllType, $vecV, $bValuesDllType, $values, "int", $count), "VectorOfDoublePushMulti", @error)

    If $bVIsArray Then
        _VectorOfDoubleRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfDoublePushMulti

Func _VectorOfDoublePushVector($v, $other)
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

    Local $bVDllType
    If VarGetType($v) == "DLLStruct" Then
        $bVDllType = "struct*"
    Else
        $bVDllType = "ptr"
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

    Local $bOtherDllType
    If VarGetType($other) == "DLLStruct" Then
        $bOtherDllType = "struct*"
    Else
        $bOtherDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfDoublePushVector", $bVDllType, $vecV, $bOtherDllType, $vecOther), "VectorOfDoublePushVector", @error)

    If $bOtherIsArray Then
        _VectorOfDoubleRelease($vecOther)
    EndIf

    If $bVIsArray Then
        _VectorOfDoubleRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfDoublePushVector

Func _VectorOfDoubleClear($v)
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

    Local $bVDllType
    If VarGetType($v) == "DLLStruct" Then
        $bVDllType = "struct*"
    Else
        $bVDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfDoubleClear", $bVDllType, $vecV), "VectorOfDoubleClear", @error)

    If $bVIsArray Then
        _VectorOfDoubleRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfDoubleClear

Func _VectorOfDoubleRelease($v)
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

    Local $bVDllType
    If VarGetType($v) == "DLLStruct" Then
        $bVDllType = "struct*"
    Else
        $bVDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfDoubleRelease", $bVDllType, $vecV), "VectorOfDoubleRelease", @error)

    If $bVIsArray Then
        _VectorOfDoubleRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfDoubleRelease

Func _VectorOfDoubleCopyData($v, $data)
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

    Local $bVDllType
    If VarGetType($v) == "DLLStruct" Then
        $bVDllType = "struct*"
    Else
        $bVDllType = "ptr"
    EndIf

    Local $bDataDllType
    If VarGetType($data) == "DLLStruct" Then
        $bDataDllType = "struct*"
    Else
        $bDataDllType = "double*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfDoubleCopyData", $bVDllType, $vecV, $bDataDllType, $data), "VectorOfDoubleCopyData", @error)

    If $bVIsArray Then
        _VectorOfDoubleRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfDoubleCopyData

Func _VectorOfDoubleGetStartAddress($v)
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

    Local $bVDllType
    If VarGetType($v) == "DLLStruct" Then
        $bVDllType = "struct*"
    Else
        $bVDllType = "ptr"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfDoubleGetStartAddress", $bVDllType, $vecV), "VectorOfDoubleGetStartAddress", @error)

    If $bVIsArray Then
        _VectorOfDoubleRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfDoubleGetStartAddress

Func _VectorOfDoubleGetEndAddress($v)
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

    Local $bVDllType
    If VarGetType($v) == "DLLStruct" Then
        $bVDllType = "struct*"
    Else
        $bVDllType = "ptr"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfDoubleGetEndAddress", $bVDllType, $vecV), "VectorOfDoubleGetEndAddress", @error)

    If $bVIsArray Then
        _VectorOfDoubleRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfDoubleGetEndAddress

Func _VectorOfDoubleGetItem($vec, $index, $element)
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

    Local $bVecDllType
    If VarGetType($vec) == "DLLStruct" Then
        $bVecDllType = "struct*"
    Else
        $bVecDllType = "ptr"
    EndIf

    Local $bElementDllType
    If VarGetType($element) == "DLLStruct" Then
        $bElementDllType = "struct*"
    Else
        $bElementDllType = "double*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfDoubleGetItem", $bVecDllType, $vecVec, "int", $index, $bElementDllType, $element), "VectorOfDoubleGetItem", @error)

    If $bVecIsArray Then
        _VectorOfDoubleRelease($vecVec)
    EndIf
EndFunc   ;==>_VectorOfDoubleGetItem

Func _VectorOfDoubleGetItemPtr($vec, $index, $element)
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

    Local $bVecDllType
    If VarGetType($vec) == "DLLStruct" Then
        $bVecDllType = "struct*"
    Else
        $bVecDllType = "ptr"
    EndIf

    Local $bElementDllType
    If VarGetType($element) == "DLLStruct" Then
        $bElementDllType = "struct*"
    Else
        $bElementDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfDoubleGetItemPtr", $bVecDllType, $vecVec, "int", $index, $bElementDllType, $element), "VectorOfDoubleGetItemPtr", @error)

    If $bVecIsArray Then
        _VectorOfDoubleRelease($vecVec)
    EndIf
EndFunc   ;==>_VectorOfDoubleGetItemPtr

Func _cveInputArrayFromVectorOfDouble($vec)
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

    Local $bVecDllType
    If VarGetType($vec) == "DLLStruct" Then
        $bVecDllType = "struct*"
    Else
        $bVecDllType = "ptr"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveInputArrayFromVectorOfDouble", $bVecDllType, $vecVec), "cveInputArrayFromVectorOfDouble", @error)

    If $bVecIsArray Then
        _VectorOfDoubleRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveInputArrayFromVectorOfDouble

Func _cveOutputArrayFromVectorOfDouble($vec)
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

    Local $bVecDllType
    If VarGetType($vec) == "DLLStruct" Then
        $bVecDllType = "struct*"
    Else
        $bVecDllType = "ptr"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveOutputArrayFromVectorOfDouble", $bVecDllType, $vecVec), "cveOutputArrayFromVectorOfDouble", @error)

    If $bVecIsArray Then
        _VectorOfDoubleRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveOutputArrayFromVectorOfDouble

Func _cveInputOutputArrayFromVectorOfDouble($vec)
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

    Local $bVecDllType
    If VarGetType($vec) == "DLLStruct" Then
        $bVecDllType = "struct*"
    Else
        $bVecDllType = "ptr"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveInputOutputArrayFromVectorOfDouble", $bVecDllType, $vecVec), "cveInputOutputArrayFromVectorOfDouble", @error)

    If $bVecIsArray Then
        _VectorOfDoubleRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveInputOutputArrayFromVectorOfDouble

Func _VectorOfDoubleSizeOfItemInBytes()
    ; CVAPI(int) VectorOfDoubleSizeOfItemInBytes();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "VectorOfDoubleSizeOfItemInBytes"), "VectorOfDoubleSizeOfItemInBytes", @error)
EndFunc   ;==>_VectorOfDoubleSizeOfItemInBytes