#include-once
#include "..\CVEUtils.au3"

Func _VectorOfTesseractResultCreate()
    ; CVAPI(std::vector<TesseractResult>*) VectorOfTesseractResultCreate();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfTesseractResultCreate"), "VectorOfTesseractResultCreate", @error)
EndFunc   ;==>_VectorOfTesseractResultCreate

Func _VectorOfTesseractResultCreateSize($size)
    ; CVAPI(std::vector<TesseractResult>*) VectorOfTesseractResultCreateSize(int size);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfTesseractResultCreateSize", "int", $size), "VectorOfTesseractResultCreateSize", @error)
EndFunc   ;==>_VectorOfTesseractResultCreateSize

Func _VectorOfTesseractResultGetSize($v)
    ; CVAPI(int) VectorOfTesseractResultGetSize(std::vector<TesseractResult>* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfTesseractResultCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfTesseractResultPush($vecV, $v[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "VectorOfTesseractResultGetSize", $sVDllType, $vecV), "VectorOfTesseractResultGetSize", @error)

    If $bVIsArray Then
        _VectorOfTesseractResultRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfTesseractResultGetSize

Func _VectorOfTesseractResultPush($v, $value)
    ; CVAPI(void) VectorOfTesseractResultPush(std::vector<TesseractResult>* v, TesseractResult* value);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfTesseractResultCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfTesseractResultPush($vecV, $v[$i])
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
        $sValueDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfTesseractResultPush", $sVDllType, $vecV, $sValueDllType, $value), "VectorOfTesseractResultPush", @error)

    If $bVIsArray Then
        _VectorOfTesseractResultRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfTesseractResultPush

Func _VectorOfTesseractResultPushMulti($v, $values, $count)
    ; CVAPI(void) VectorOfTesseractResultPushMulti(std::vector<TesseractResult>* v, TesseractResult* values, int count);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfTesseractResultCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfTesseractResultPush($vecV, $v[$i])
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
        $sValuesDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfTesseractResultPushMulti", $sVDllType, $vecV, $sValuesDllType, $values, "int", $count), "VectorOfTesseractResultPushMulti", @error)

    If $bVIsArray Then
        _VectorOfTesseractResultRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfTesseractResultPushMulti

Func _VectorOfTesseractResultPushVector($v, $other)
    ; CVAPI(void) VectorOfTesseractResultPushVector(std::vector<TesseractResult>* v, std::vector<TesseractResult>* other);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfTesseractResultCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfTesseractResultPush($vecV, $v[$i])
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
        $vecOther = _VectorOfTesseractResultCreate()

        $iArrOtherSize = UBound($other)
        For $i = 0 To $iArrOtherSize - 1
            _VectorOfTesseractResultPush($vecOther, $other[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfTesseractResultPushVector", $sVDllType, $vecV, $sOtherDllType, $vecOther), "VectorOfTesseractResultPushVector", @error)

    If $bOtherIsArray Then
        _VectorOfTesseractResultRelease($vecOther)
    EndIf

    If $bVIsArray Then
        _VectorOfTesseractResultRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfTesseractResultPushVector

Func _VectorOfTesseractResultClear($v)
    ; CVAPI(void) VectorOfTesseractResultClear(std::vector<TesseractResult>* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfTesseractResultCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfTesseractResultPush($vecV, $v[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfTesseractResultClear", $sVDllType, $vecV), "VectorOfTesseractResultClear", @error)

    If $bVIsArray Then
        _VectorOfTesseractResultRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfTesseractResultClear

Func _VectorOfTesseractResultRelease($v)
    ; CVAPI(void) VectorOfTesseractResultRelease(std::vector<TesseractResult>** v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfTesseractResultCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfTesseractResultPush($vecV, $v[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfTesseractResultRelease", $sVDllType, $vecV), "VectorOfTesseractResultRelease", @error)

    If $bVIsArray Then
        _VectorOfTesseractResultRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfTesseractResultRelease

Func _VectorOfTesseractResultCopyData($v, $data)
    ; CVAPI(void) VectorOfTesseractResultCopyData(std::vector<TesseractResult>* v, TesseractResult* data);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfTesseractResultCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfTesseractResultPush($vecV, $v[$i])
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
        $sDataDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfTesseractResultCopyData", $sVDllType, $vecV, $sDataDllType, $data), "VectorOfTesseractResultCopyData", @error)

    If $bVIsArray Then
        _VectorOfTesseractResultRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfTesseractResultCopyData

Func _VectorOfTesseractResultGetStartAddress($v)
    ; CVAPI(TesseractResult*) VectorOfTesseractResultGetStartAddress(std::vector<TesseractResult>* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfTesseractResultCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfTesseractResultPush($vecV, $v[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfTesseractResultGetStartAddress", $sVDllType, $vecV), "VectorOfTesseractResultGetStartAddress", @error)

    If $bVIsArray Then
        _VectorOfTesseractResultRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfTesseractResultGetStartAddress

Func _VectorOfTesseractResultGetEndAddress($v)
    ; CVAPI(void*) VectorOfTesseractResultGetEndAddress(std::vector<TesseractResult>* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfTesseractResultCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfTesseractResultPush($vecV, $v[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfTesseractResultGetEndAddress", $sVDllType, $vecV), "VectorOfTesseractResultGetEndAddress", @error)

    If $bVIsArray Then
        _VectorOfTesseractResultRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfTesseractResultGetEndAddress

Func _VectorOfTesseractResultGetItem($vec, $index, $element)
    ; CVAPI(void) VectorOfTesseractResultGetItem(std::vector<TesseractResult>* vec, int index, TesseractResult* element);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfTesseractResultCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfTesseractResultPush($vecVec, $vec[$i])
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
        $sElementDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfTesseractResultGetItem", $sVecDllType, $vecVec, "int", $index, $sElementDllType, $element), "VectorOfTesseractResultGetItem", @error)

    If $bVecIsArray Then
        _VectorOfTesseractResultRelease($vecVec)
    EndIf
EndFunc   ;==>_VectorOfTesseractResultGetItem

Func _VectorOfTesseractResultGetItemPtr($vec, $index, $element)
    ; CVAPI(void) VectorOfTesseractResultGetItemPtr(std::vector<TesseractResult>* vec, int index, TesseractResult** element);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfTesseractResultCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfTesseractResultPush($vecVec, $vec[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfTesseractResultGetItemPtr", $sVecDllType, $vecVec, "int", $index, $sElementDllType, $element), "VectorOfTesseractResultGetItemPtr", @error)

    If $bVecIsArray Then
        _VectorOfTesseractResultRelease($vecVec)
    EndIf
EndFunc   ;==>_VectorOfTesseractResultGetItemPtr

Func _cveInputArrayFromVectorOfTesseractResult($vec)
    ; CVAPI(cv::_InputArray*) cveInputArrayFromVectorOfTesseractResult(std::vector<TesseractResult>* vec);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfTesseractResultCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfTesseractResultPush($vecVec, $vec[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveInputArrayFromVectorOfTesseractResult", $sVecDllType, $vecVec), "cveInputArrayFromVectorOfTesseractResult", @error)

    If $bVecIsArray Then
        _VectorOfTesseractResultRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveInputArrayFromVectorOfTesseractResult

Func _cveOutputArrayFromVectorOfTesseractResult($vec)
    ; CVAPI(cv::_OutputArray*) cveOutputArrayFromVectorOfTesseractResult(std::vector<TesseractResult>* vec);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfTesseractResultCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfTesseractResultPush($vecVec, $vec[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveOutputArrayFromVectorOfTesseractResult", $sVecDllType, $vecVec), "cveOutputArrayFromVectorOfTesseractResult", @error)

    If $bVecIsArray Then
        _VectorOfTesseractResultRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveOutputArrayFromVectorOfTesseractResult

Func _cveInputOutputArrayFromVectorOfTesseractResult($vec)
    ; CVAPI(cv::_InputOutputArray*) cveInputOutputArrayFromVectorOfTesseractResult(std::vector<TesseractResult>* vec);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfTesseractResultCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfTesseractResultPush($vecVec, $vec[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveInputOutputArrayFromVectorOfTesseractResult", $sVecDllType, $vecVec), "cveInputOutputArrayFromVectorOfTesseractResult", @error)

    If $bVecIsArray Then
        _VectorOfTesseractResultRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveInputOutputArrayFromVectorOfTesseractResult

Func _VectorOfTesseractResultSizeOfItemInBytes()
    ; CVAPI(int) VectorOfTesseractResultSizeOfItemInBytes();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "VectorOfTesseractResultSizeOfItemInBytes"), "VectorOfTesseractResultSizeOfItemInBytes", @error)
EndFunc   ;==>_VectorOfTesseractResultSizeOfItemInBytes