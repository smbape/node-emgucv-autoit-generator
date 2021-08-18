#include-once
#include "..\CVEUtils.au3"

Func _VectorOfIntCreate()
    ; CVAPI(std::vector<int>*) VectorOfIntCreate();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfIntCreate"), "VectorOfIntCreate", @error)
EndFunc   ;==>_VectorOfIntCreate

Func _VectorOfIntCreateSize($size)
    ; CVAPI(std::vector<int>*) VectorOfIntCreateSize(int size);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfIntCreateSize", "int", $size), "VectorOfIntCreateSize", @error)
EndFunc   ;==>_VectorOfIntCreateSize

Func _VectorOfIntGetSize($v)
    ; CVAPI(int) VectorOfIntGetSize(std::vector<int>* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfIntCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfIntPush($vecV, $v[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "VectorOfIntGetSize", $bVDllType, $vecV), "VectorOfIntGetSize", @error)

    If $bVIsArray Then
        _VectorOfIntRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfIntGetSize

Func _VectorOfIntPush($v, $value)
    ; CVAPI(void) VectorOfIntPush(std::vector<int>* v, int* value);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfIntCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfIntPush($vecV, $v[$i])
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
        $bValueDllType = "int*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfIntPush", $bVDllType, $vecV, "int*", $value), "VectorOfIntPush", @error)

    If $bVIsArray Then
        _VectorOfIntRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfIntPush

Func _VectorOfIntPushMulti($v, $values, $count)
    ; CVAPI(void) VectorOfIntPushMulti(std::vector<int>* v, int* values, int count);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfIntCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfIntPush($vecV, $v[$i])
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
        $bValuesDllType = "int*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfIntPushMulti", $bVDllType, $vecV, $bValuesDllType, $values, "int", $count), "VectorOfIntPushMulti", @error)

    If $bVIsArray Then
        _VectorOfIntRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfIntPushMulti

Func _VectorOfIntPushVector($v, $other)
    ; CVAPI(void) VectorOfIntPushVector(std::vector<int>* v, std::vector<int>* other);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfIntCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfIntPush($vecV, $v[$i])
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
        $vecOther = _VectorOfIntCreate()

        $iArrOtherSize = UBound($other)
        For $i = 0 To $iArrOtherSize - 1
            _VectorOfIntPush($vecOther, $other[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfIntPushVector", $bVDllType, $vecV, $bOtherDllType, $vecOther), "VectorOfIntPushVector", @error)

    If $bOtherIsArray Then
        _VectorOfIntRelease($vecOther)
    EndIf

    If $bVIsArray Then
        _VectorOfIntRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfIntPushVector

Func _VectorOfIntClear($v)
    ; CVAPI(void) VectorOfIntClear(std::vector<int>* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfIntCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfIntPush($vecV, $v[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfIntClear", $bVDllType, $vecV), "VectorOfIntClear", @error)

    If $bVIsArray Then
        _VectorOfIntRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfIntClear

Func _VectorOfIntRelease($v)
    ; CVAPI(void) VectorOfIntRelease(std::vector<int>** v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfIntCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfIntPush($vecV, $v[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfIntRelease", $bVDllType, $vecV), "VectorOfIntRelease", @error)

    If $bVIsArray Then
        _VectorOfIntRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfIntRelease

Func _VectorOfIntCopyData($v, $data)
    ; CVAPI(void) VectorOfIntCopyData(std::vector<int>* v, int* data);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfIntCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfIntPush($vecV, $v[$i])
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
        $bDataDllType = "int*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfIntCopyData", $bVDllType, $vecV, $bDataDllType, $data), "VectorOfIntCopyData", @error)

    If $bVIsArray Then
        _VectorOfIntRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfIntCopyData

Func _VectorOfIntGetStartAddress($v)
    ; CVAPI(int*) VectorOfIntGetStartAddress(std::vector<int>* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfIntCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfIntPush($vecV, $v[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfIntGetStartAddress", $bVDllType, $vecV), "VectorOfIntGetStartAddress", @error)

    If $bVIsArray Then
        _VectorOfIntRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfIntGetStartAddress

Func _VectorOfIntGetEndAddress($v)
    ; CVAPI(void*) VectorOfIntGetEndAddress(std::vector<int>* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfIntCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfIntPush($vecV, $v[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfIntGetEndAddress", $bVDllType, $vecV), "VectorOfIntGetEndAddress", @error)

    If $bVIsArray Then
        _VectorOfIntRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfIntGetEndAddress

Func _VectorOfIntGetItem($vec, $index, $element)
    ; CVAPI(void) VectorOfIntGetItem(std::vector<int>* vec, int index, int* element);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfIntCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfIntPush($vecVec, $vec[$i])
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
        $bElementDllType = "int*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfIntGetItem", $bVecDllType, $vecVec, "int", $index, $bElementDllType, $element), "VectorOfIntGetItem", @error)

    If $bVecIsArray Then
        _VectorOfIntRelease($vecVec)
    EndIf
EndFunc   ;==>_VectorOfIntGetItem

Func _VectorOfIntGetItemPtr($vec, $index, $element)
    ; CVAPI(void) VectorOfIntGetItemPtr(std::vector<int>* vec, int index, int** element);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfIntCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfIntPush($vecVec, $vec[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfIntGetItemPtr", $bVecDllType, $vecVec, "int", $index, $bElementDllType, $element), "VectorOfIntGetItemPtr", @error)

    If $bVecIsArray Then
        _VectorOfIntRelease($vecVec)
    EndIf
EndFunc   ;==>_VectorOfIntGetItemPtr

Func _cveInputArrayFromVectorOfInt($vec)
    ; CVAPI(cv::_InputArray*) cveInputArrayFromVectorOfInt(std::vector<int>* vec);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfIntCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfIntPush($vecVec, $vec[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveInputArrayFromVectorOfInt", $bVecDllType, $vecVec), "cveInputArrayFromVectorOfInt", @error)

    If $bVecIsArray Then
        _VectorOfIntRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveInputArrayFromVectorOfInt

Func _cveOutputArrayFromVectorOfInt($vec)
    ; CVAPI(cv::_OutputArray*) cveOutputArrayFromVectorOfInt(std::vector<int>* vec);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfIntCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfIntPush($vecVec, $vec[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveOutputArrayFromVectorOfInt", $bVecDllType, $vecVec), "cveOutputArrayFromVectorOfInt", @error)

    If $bVecIsArray Then
        _VectorOfIntRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveOutputArrayFromVectorOfInt

Func _cveInputOutputArrayFromVectorOfInt($vec)
    ; CVAPI(cv::_InputOutputArray*) cveInputOutputArrayFromVectorOfInt(std::vector<int>* vec);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfIntCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfIntPush($vecVec, $vec[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveInputOutputArrayFromVectorOfInt", $bVecDllType, $vecVec), "cveInputOutputArrayFromVectorOfInt", @error)

    If $bVecIsArray Then
        _VectorOfIntRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveInputOutputArrayFromVectorOfInt

Func _VectorOfIntSizeOfItemInBytes()
    ; CVAPI(int) VectorOfIntSizeOfItemInBytes();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "VectorOfIntSizeOfItemInBytes"), "VectorOfIntSizeOfItemInBytes", @error)
EndFunc   ;==>_VectorOfIntSizeOfItemInBytes