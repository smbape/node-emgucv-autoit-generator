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
    Local $bVIsArray = IsArray($v)

    If $bVIsArray Then
        $vecV = _VectorOfIntCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfIntPush($vecV, $v[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "VectorOfIntGetSize", $sVDllType, $vecV), "VectorOfIntGetSize", @error)

    If $bVIsArray Then
        _VectorOfIntRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfIntGetSize

Func _VectorOfIntPush($v, $value)
    ; CVAPI(void) VectorOfIntPush(std::vector<int>* v, int* value);

    Local $vecV, $iArrVSize
    Local $bVIsArray = IsArray($v)

    If $bVIsArray Then
        $vecV = _VectorOfIntCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfIntPush($vecV, $v[$i])
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
        $sValueDllType = "int*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfIntPush", $sVDllType, $vecV, "int*", $value), "VectorOfIntPush", @error)

    If $bVIsArray Then
        _VectorOfIntRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfIntPush

Func _VectorOfIntPushMulti($v, $values, $count)
    ; CVAPI(void) VectorOfIntPushMulti(std::vector<int>* v, int* values, int count);

    Local $vecV, $iArrVSize
    Local $bVIsArray = IsArray($v)

    If $bVIsArray Then
        $vecV = _VectorOfIntCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfIntPush($vecV, $v[$i])
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
        $sValuesDllType = "int*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfIntPushMulti", $sVDllType, $vecV, $sValuesDllType, $values, "int", $count), "VectorOfIntPushMulti", @error)

    If $bVIsArray Then
        _VectorOfIntRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfIntPushMulti

Func _VectorOfIntPushVector($v, $other)
    ; CVAPI(void) VectorOfIntPushVector(std::vector<int>* v, std::vector<int>* other);

    Local $vecV, $iArrVSize
    Local $bVIsArray = IsArray($v)

    If $bVIsArray Then
        $vecV = _VectorOfIntCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfIntPush($vecV, $v[$i])
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
    Local $bOtherIsArray = IsArray($other)

    If $bOtherIsArray Then
        $vecOther = _VectorOfIntCreate()

        $iArrOtherSize = UBound($other)
        For $i = 0 To $iArrOtherSize - 1
            _VectorOfIntPush($vecOther, $other[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfIntPushVector", $sVDllType, $vecV, $sOtherDllType, $vecOther), "VectorOfIntPushVector", @error)

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
    Local $bVIsArray = IsArray($v)

    If $bVIsArray Then
        $vecV = _VectorOfIntCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfIntPush($vecV, $v[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfIntClear", $sVDllType, $vecV), "VectorOfIntClear", @error)

    If $bVIsArray Then
        _VectorOfIntRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfIntClear

Func _VectorOfIntRelease($v)
    ; CVAPI(void) VectorOfIntRelease(std::vector<int>** v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = IsArray($v)

    If $bVIsArray Then
        $vecV = _VectorOfIntCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfIntPush($vecV, $v[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfIntRelease", $sVDllType, $vecV), "VectorOfIntRelease", @error)

    If $bVIsArray Then
        _VectorOfIntRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfIntRelease

Func _VectorOfIntCopyData($v, $data)
    ; CVAPI(void) VectorOfIntCopyData(std::vector<int>* v, int* data);

    Local $vecV, $iArrVSize
    Local $bVIsArray = IsArray($v)

    If $bVIsArray Then
        $vecV = _VectorOfIntCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfIntPush($vecV, $v[$i])
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
        $sDataDllType = "int*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfIntCopyData", $sVDllType, $vecV, $sDataDllType, $data), "VectorOfIntCopyData", @error)

    If $bVIsArray Then
        _VectorOfIntRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfIntCopyData

Func _VectorOfIntGetStartAddress($v)
    ; CVAPI(int*) VectorOfIntGetStartAddress(std::vector<int>* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = IsArray($v)

    If $bVIsArray Then
        $vecV = _VectorOfIntCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfIntPush($vecV, $v[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfIntGetStartAddress", $sVDllType, $vecV), "VectorOfIntGetStartAddress", @error)

    If $bVIsArray Then
        _VectorOfIntRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfIntGetStartAddress

Func _VectorOfIntGetEndAddress($v)
    ; CVAPI(void*) VectorOfIntGetEndAddress(std::vector<int>* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = IsArray($v)

    If $bVIsArray Then
        $vecV = _VectorOfIntCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfIntPush($vecV, $v[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfIntGetEndAddress", $sVDllType, $vecV), "VectorOfIntGetEndAddress", @error)

    If $bVIsArray Then
        _VectorOfIntRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfIntGetEndAddress

Func _VectorOfIntGetItem($vec, $index, $element)
    ; CVAPI(void) VectorOfIntGetItem(std::vector<int>* vec, int index, int* element);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = IsArray($vec)

    If $bVecIsArray Then
        $vecVec = _VectorOfIntCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfIntPush($vecVec, $vec[$i])
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
        $sElementDllType = "int*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfIntGetItem", $sVecDllType, $vecVec, "int", $index, $sElementDllType, $element), "VectorOfIntGetItem", @error)

    If $bVecIsArray Then
        _VectorOfIntRelease($vecVec)
    EndIf
EndFunc   ;==>_VectorOfIntGetItem

Func _VectorOfIntGetItemPtr($vec, $index, $element)
    ; CVAPI(void) VectorOfIntGetItemPtr(std::vector<int>* vec, int index, int** element);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = IsArray($vec)

    If $bVecIsArray Then
        $vecVec = _VectorOfIntCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfIntPush($vecVec, $vec[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfIntGetItemPtr", $sVecDllType, $vecVec, "int", $index, $sElementDllType, $element), "VectorOfIntGetItemPtr", @error)

    If $bVecIsArray Then
        _VectorOfIntRelease($vecVec)
    EndIf
EndFunc   ;==>_VectorOfIntGetItemPtr

Func _cveInputArrayFromVectorOfInt($vec)
    ; CVAPI(cv::_InputArray*) cveInputArrayFromVectorOfInt(std::vector<int>* vec);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = IsArray($vec)

    If $bVecIsArray Then
        $vecVec = _VectorOfIntCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfIntPush($vecVec, $vec[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveInputArrayFromVectorOfInt", $sVecDllType, $vecVec), "cveInputArrayFromVectorOfInt", @error)

    If $bVecIsArray Then
        _VectorOfIntRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveInputArrayFromVectorOfInt

Func _cveOutputArrayFromVectorOfInt($vec)
    ; CVAPI(cv::_OutputArray*) cveOutputArrayFromVectorOfInt(std::vector<int>* vec);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = IsArray($vec)

    If $bVecIsArray Then
        $vecVec = _VectorOfIntCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfIntPush($vecVec, $vec[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveOutputArrayFromVectorOfInt", $sVecDllType, $vecVec), "cveOutputArrayFromVectorOfInt", @error)

    If $bVecIsArray Then
        _VectorOfIntRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveOutputArrayFromVectorOfInt

Func _cveInputOutputArrayFromVectorOfInt($vec)
    ; CVAPI(cv::_InputOutputArray*) cveInputOutputArrayFromVectorOfInt(std::vector<int>* vec);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = IsArray($vec)

    If $bVecIsArray Then
        $vecVec = _VectorOfIntCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfIntPush($vecVec, $vec[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveInputOutputArrayFromVectorOfInt", $sVecDllType, $vecVec), "cveInputOutputArrayFromVectorOfInt", @error)

    If $bVecIsArray Then
        _VectorOfIntRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveInputOutputArrayFromVectorOfInt

Func _VectorOfIntSizeOfItemInBytes()
    ; CVAPI(int) VectorOfIntSizeOfItemInBytes();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "VectorOfIntSizeOfItemInBytes"), "VectorOfIntSizeOfItemInBytes", @error)
EndFunc   ;==>_VectorOfIntSizeOfItemInBytes