#include-once
#include "..\CVEUtils.au3"

Func _VectorOfDoubleCreate()
    ; CVAPI(std::vector<double>*) VectorOfDoubleCreate();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfDoubleCreate"), "VectorOfDoubleCreate", @error)
EndFunc   ;==>_VectorOfDoubleCreate

Func _VectorOfDoubleCreateSize($size)
    ; CVAPI(std::vector<double>*) VectorOfDoubleCreateSize(int size);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfDoubleCreateSize", "int", $size), "VectorOfDoubleCreateSize", @error)
EndFunc   ;==>_VectorOfDoubleCreateSize

Func _VectorOfDoubleGetSize($v)
    ; CVAPI(int) VectorOfDoubleGetSize(std::vector<double>* v);

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

    Local $sVDllType
    If IsDllStruct($v) Then
        $sVDllType = "struct*"
    Else
        $sVDllType = "ptr"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "VectorOfDoubleGetSize", $sVDllType, $vecV), "VectorOfDoubleGetSize", @error)

    If $bVIsArray Then
        _VectorOfDoubleRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfDoubleGetSize

Func _VectorOfDoublePush($v, $value)
    ; CVAPI(void) VectorOfDoublePush(std::vector<double>* v, double* value);

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

    Local $sVDllType
    If IsDllStruct($v) Then
        $sVDllType = "struct*"
    Else
        $sVDllType = "ptr"
    EndIf

    Local $sValueDllType
    If IsDllStruct($value) Then
        $sValueDllType = "struct*"
    Else
        $sValueDllType = "double*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfDoublePush", $sVDllType, $vecV, "double*", $value), "VectorOfDoublePush", @error)

    If $bVIsArray Then
        _VectorOfDoubleRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfDoublePush

Func _VectorOfDoublePushMulti($v, $values, $count)
    ; CVAPI(void) VectorOfDoublePushMulti(std::vector<double>* v, double* values, int count);

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

    Local $sVDllType
    If IsDllStruct($v) Then
        $sVDllType = "struct*"
    Else
        $sVDllType = "ptr"
    EndIf

    Local $sValuesDllType
    If IsDllStruct($values) Then
        $sValuesDllType = "struct*"
    Else
        $sValuesDllType = "double*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfDoublePushMulti", $sVDllType, $vecV, $sValuesDllType, $values, "int", $count), "VectorOfDoublePushMulti", @error)

    If $bVIsArray Then
        _VectorOfDoubleRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfDoublePushMulti

Func _VectorOfDoublePushVector($v, $other)
    ; CVAPI(void) VectorOfDoublePushVector(std::vector<double>* v, std::vector<double>* other);

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

    Local $sVDllType
    If IsDllStruct($v) Then
        $sVDllType = "struct*"
    Else
        $sVDllType = "ptr"
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

    Local $sOtherDllType
    If IsDllStruct($other) Then
        $sOtherDllType = "struct*"
    Else
        $sOtherDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfDoublePushVector", $sVDllType, $vecV, $sOtherDllType, $vecOther), "VectorOfDoublePushVector", @error)

    If $bOtherIsArray Then
        _VectorOfDoubleRelease($vecOther)
    EndIf

    If $bVIsArray Then
        _VectorOfDoubleRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfDoublePushVector

Func _VectorOfDoubleClear($v)
    ; CVAPI(void) VectorOfDoubleClear(std::vector<double>* v);

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

    Local $sVDllType
    If IsDllStruct($v) Then
        $sVDllType = "struct*"
    Else
        $sVDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfDoubleClear", $sVDllType, $vecV), "VectorOfDoubleClear", @error)

    If $bVIsArray Then
        _VectorOfDoubleRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfDoubleClear

Func _VectorOfDoubleRelease($v)
    ; CVAPI(void) VectorOfDoubleRelease(std::vector<double>** v);

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

    Local $sVDllType
    If IsDllStruct($v) Then
        $sVDllType = "struct*"
    ElseIf $v == Null Then
        $sVDllType = "ptr"
    Else
        $sVDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfDoubleRelease", $sVDllType, $vecV), "VectorOfDoubleRelease", @error)

    If $bVIsArray Then
        _VectorOfDoubleRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfDoubleRelease

Func _VectorOfDoubleCopyData($v, $data)
    ; CVAPI(void) VectorOfDoubleCopyData(std::vector<double>* v, double* data);

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

    Local $sVDllType
    If IsDllStruct($v) Then
        $sVDllType = "struct*"
    Else
        $sVDllType = "ptr"
    EndIf

    Local $sDataDllType
    If IsDllStruct($data) Then
        $sDataDllType = "struct*"
    Else
        $sDataDllType = "double*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfDoubleCopyData", $sVDllType, $vecV, $sDataDllType, $data), "VectorOfDoubleCopyData", @error)

    If $bVIsArray Then
        _VectorOfDoubleRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfDoubleCopyData

Func _VectorOfDoubleGetStartAddress($v)
    ; CVAPI(double*) VectorOfDoubleGetStartAddress(std::vector<double>* v);

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

    Local $sVDllType
    If IsDllStruct($v) Then
        $sVDllType = "struct*"
    Else
        $sVDllType = "ptr"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfDoubleGetStartAddress", $sVDllType, $vecV), "VectorOfDoubleGetStartAddress", @error)

    If $bVIsArray Then
        _VectorOfDoubleRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfDoubleGetStartAddress

Func _VectorOfDoubleGetEndAddress($v)
    ; CVAPI(void*) VectorOfDoubleGetEndAddress(std::vector<double>* v);

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

    Local $sVDllType
    If IsDllStruct($v) Then
        $sVDllType = "struct*"
    Else
        $sVDllType = "ptr"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfDoubleGetEndAddress", $sVDllType, $vecV), "VectorOfDoubleGetEndAddress", @error)

    If $bVIsArray Then
        _VectorOfDoubleRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfDoubleGetEndAddress

Func _VectorOfDoubleGetItem($vec, $index, $element)
    ; CVAPI(void) VectorOfDoubleGetItem(std::vector<double>* vec, int index, double* element);

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

    Local $sVecDllType
    If IsDllStruct($vec) Then
        $sVecDllType = "struct*"
    Else
        $sVecDllType = "ptr"
    EndIf

    Local $sElementDllType
    If IsDllStruct($element) Then
        $sElementDllType = "struct*"
    Else
        $sElementDllType = "double*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfDoubleGetItem", $sVecDllType, $vecVec, "int", $index, $sElementDllType, $element), "VectorOfDoubleGetItem", @error)

    If $bVecIsArray Then
        _VectorOfDoubleRelease($vecVec)
    EndIf
EndFunc   ;==>_VectorOfDoubleGetItem

Func _VectorOfDoubleGetItemPtr($vec, $index, $element)
    ; CVAPI(void) VectorOfDoubleGetItemPtr(std::vector<double>* vec, int index, double** element);

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

    Local $sVecDllType
    If IsDllStruct($vec) Then
        $sVecDllType = "struct*"
    Else
        $sVecDllType = "ptr"
    EndIf

    Local $sElementDllType
    If IsDllStruct($element) Then
        $sElementDllType = "struct*"
    ElseIf $element == Null Then
        $sElementDllType = "ptr"
    Else
        $sElementDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfDoubleGetItemPtr", $sVecDllType, $vecVec, "int", $index, $sElementDllType, $element), "VectorOfDoubleGetItemPtr", @error)

    If $bVecIsArray Then
        _VectorOfDoubleRelease($vecVec)
    EndIf
EndFunc   ;==>_VectorOfDoubleGetItemPtr

Func _cveInputArrayFromVectorOfDouble($vec)
    ; CVAPI(cv::_InputArray*) cveInputArrayFromVectorOfDouble(std::vector<double>* vec);

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

    Local $sVecDllType
    If IsDllStruct($vec) Then
        $sVecDllType = "struct*"
    Else
        $sVecDllType = "ptr"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveInputArrayFromVectorOfDouble", $sVecDllType, $vecVec), "cveInputArrayFromVectorOfDouble", @error)

    If $bVecIsArray Then
        _VectorOfDoubleRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveInputArrayFromVectorOfDouble

Func _cveOutputArrayFromVectorOfDouble($vec)
    ; CVAPI(cv::_OutputArray*) cveOutputArrayFromVectorOfDouble(std::vector<double>* vec);

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

    Local $sVecDllType
    If IsDllStruct($vec) Then
        $sVecDllType = "struct*"
    Else
        $sVecDllType = "ptr"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveOutputArrayFromVectorOfDouble", $sVecDllType, $vecVec), "cveOutputArrayFromVectorOfDouble", @error)

    If $bVecIsArray Then
        _VectorOfDoubleRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveOutputArrayFromVectorOfDouble

Func _cveInputOutputArrayFromVectorOfDouble($vec)
    ; CVAPI(cv::_InputOutputArray*) cveInputOutputArrayFromVectorOfDouble(std::vector<double>* vec);

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

    Local $sVecDllType
    If IsDllStruct($vec) Then
        $sVecDllType = "struct*"
    Else
        $sVecDllType = "ptr"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveInputOutputArrayFromVectorOfDouble", $sVecDllType, $vecVec), "cveInputOutputArrayFromVectorOfDouble", @error)

    If $bVecIsArray Then
        _VectorOfDoubleRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveInputOutputArrayFromVectorOfDouble

Func _VectorOfDoubleSizeOfItemInBytes()
    ; CVAPI(int) VectorOfDoubleSizeOfItemInBytes();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "VectorOfDoubleSizeOfItemInBytes"), "VectorOfDoubleSizeOfItemInBytes", @error)
EndFunc   ;==>_VectorOfDoubleSizeOfItemInBytes