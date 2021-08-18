#include-once
#include "..\CVEUtils.au3"

Func _VectorOfVectorOfIntCreate()
    ; CVAPI(std::vector<std::vector<int>>*) VectorOfVectorOfIntCreate();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfVectorOfIntCreate"), "VectorOfVectorOfIntCreate", @error)
EndFunc   ;==>_VectorOfVectorOfIntCreate

Func _VectorOfVectorOfIntCreateSize($size)
    ; CVAPI(std::vector<std::vector<int>>*) VectorOfVectorOfIntCreateSize(int size);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfVectorOfIntCreateSize", "int", $size), "VectorOfVectorOfIntCreateSize", @error)
EndFunc   ;==>_VectorOfVectorOfIntCreateSize

Func _VectorOfVectorOfIntGetSize($v)
    ; CVAPI(int) VectorOfVectorOfIntGetSize(std::vector<std::vector<int>>* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfVectorOfIntCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfVectorOfIntPush($vecV, $v[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "VectorOfVectorOfIntGetSize", $bVDllType, $vecV), "VectorOfVectorOfIntGetSize", @error)

    If $bVIsArray Then
        _VectorOfVectorOfIntRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfVectorOfIntGetSize

Func _VectorOfVectorOfIntPush($v, $value)
    ; CVAPI(void) VectorOfVectorOfIntPush(std::vector<std::vector<int>>* v, std::vector<int>* value);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfVectorOfIntCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfVectorOfIntPush($vecV, $v[$i])
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

    Local $vecValue, $iArrValueSize
    Local $bValueIsArray = VarGetType($value) == "Array"

    If $bValueIsArray Then
        $vecValue = _VectorOfIntCreate()

        $iArrValueSize = UBound($value)
        For $i = 0 To $iArrValueSize - 1
            _VectorOfIntPush($vecValue, $value[$i])
        Next
    Else
        $vecValue = $value
    EndIf

    Local $bValueDllType
    If VarGetType($value) == "DLLStruct" Then
        $bValueDllType = "struct*"
    Else
        $bValueDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfVectorOfIntPush", $bVDllType, $vecV, $bValueDllType, $vecValue), "VectorOfVectorOfIntPush", @error)

    If $bValueIsArray Then
        _VectorOfIntRelease($vecValue)
    EndIf

    If $bVIsArray Then
        _VectorOfVectorOfIntRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfVectorOfIntPush

Func _VectorOfVectorOfIntPushVector($v, $other)
    ; CVAPI(void) VectorOfVectorOfIntPushVector(std::vector<std::vector<int>>* v, std::vector<std::vector<int>>* other);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfVectorOfIntCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfVectorOfIntPush($vecV, $v[$i])
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
        $vecOther = _VectorOfVectorOfIntCreate()

        $iArrOtherSize = UBound($other)
        For $i = 0 To $iArrOtherSize - 1
            _VectorOfVectorOfIntPush($vecOther, $other[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfVectorOfIntPushVector", $bVDllType, $vecV, $bOtherDllType, $vecOther), "VectorOfVectorOfIntPushVector", @error)

    If $bOtherIsArray Then
        _VectorOfVectorOfIntRelease($vecOther)
    EndIf

    If $bVIsArray Then
        _VectorOfVectorOfIntRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfVectorOfIntPushVector

Func _VectorOfVectorOfIntGetStartAddress($v)
    ; CVAPI(std::vector<int>*) VectorOfVectorOfIntGetStartAddress(std::vector<std::vector<int>>* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfVectorOfIntCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfVectorOfIntPush($vecV, $v[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfVectorOfIntGetStartAddress", $bVDllType, $vecV), "VectorOfVectorOfIntGetStartAddress", @error)

    If $bVIsArray Then
        _VectorOfVectorOfIntRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfVectorOfIntGetStartAddress

Func _VectorOfVectorOfIntGetEndAddress($v)
    ; CVAPI(void*) VectorOfVectorOfIntGetEndAddress(std::vector<std::vector<int>>* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfVectorOfIntCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfVectorOfIntPush($vecV, $v[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfVectorOfIntGetEndAddress", $bVDllType, $vecV), "VectorOfVectorOfIntGetEndAddress", @error)

    If $bVIsArray Then
        _VectorOfVectorOfIntRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfVectorOfIntGetEndAddress

Func _VectorOfVectorOfIntClear($v)
    ; CVAPI(void) VectorOfVectorOfIntClear(std::vector<std::vector<int>>* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfVectorOfIntCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfVectorOfIntPush($vecV, $v[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfVectorOfIntClear", $bVDllType, $vecV), "VectorOfVectorOfIntClear", @error)

    If $bVIsArray Then
        _VectorOfVectorOfIntRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfVectorOfIntClear

Func _VectorOfVectorOfIntRelease($v)
    ; CVAPI(void) VectorOfVectorOfIntRelease(std::vector<std::vector<int>>** v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfVectorOfIntCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfVectorOfIntPush($vecV, $v[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfVectorOfIntRelease", $bVDllType, $vecV), "VectorOfVectorOfIntRelease", @error)

    If $bVIsArray Then
        _VectorOfVectorOfIntRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfVectorOfIntRelease

Func _VectorOfVectorOfIntCopyData($v, $data)
    ; CVAPI(void) VectorOfVectorOfIntCopyData(std::vector<std::vector<int>>* v, std::vector<int>* data);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfVectorOfIntCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfVectorOfIntPush($vecV, $v[$i])
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

    Local $vecData, $iArrDataSize
    Local $bDataIsArray = VarGetType($data) == "Array"

    If $bDataIsArray Then
        $vecData = _VectorOfIntCreate()

        $iArrDataSize = UBound($data)
        For $i = 0 To $iArrDataSize - 1
            _VectorOfIntPush($vecData, $data[$i])
        Next
    Else
        $vecData = $data
    EndIf

    Local $bDataDllType
    If VarGetType($data) == "DLLStruct" Then
        $bDataDllType = "struct*"
    Else
        $bDataDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfVectorOfIntCopyData", $bVDllType, $vecV, $bDataDllType, $vecData), "VectorOfVectorOfIntCopyData", @error)

    If $bDataIsArray Then
        _VectorOfIntRelease($vecData)
    EndIf

    If $bVIsArray Then
        _VectorOfVectorOfIntRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfVectorOfIntCopyData

Func _VectorOfVectorOfIntGetItemPtr($vec, $index, $element)
    ; CVAPI(void) VectorOfVectorOfIntGetItemPtr(std::vector<std::vector<int>>* vec, int index, std::vector<int>** element);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfVectorOfIntCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfVectorOfIntPush($vecVec, $vec[$i])
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

    Local $vecElement, $iArrElementSize
    Local $bElementIsArray = VarGetType($element) == "Array"

    If $bElementIsArray Then
        $vecElement = _VectorOfIntCreate()

        $iArrElementSize = UBound($element)
        For $i = 0 To $iArrElementSize - 1
            _VectorOfIntPush($vecElement, $element[$i])
        Next
    Else
        $vecElement = $element
    EndIf

    Local $bElementDllType
    If VarGetType($element) == "DLLStruct" Then
        $bElementDllType = "struct*"
    Else
        $bElementDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfVectorOfIntGetItemPtr", $bVecDllType, $vecVec, "int", $index, $bElementDllType, $vecElement), "VectorOfVectorOfIntGetItemPtr", @error)

    If $bElementIsArray Then
        _VectorOfIntRelease($vecElement)
    EndIf

    If $bVecIsArray Then
        _VectorOfVectorOfIntRelease($vecVec)
    EndIf
EndFunc   ;==>_VectorOfVectorOfIntGetItemPtr

Func _cveInputArrayFromVectorOfVectorOfInt($vec)
    ; CVAPI(cv::_InputArray*) cveInputArrayFromVectorOfVectorOfInt(std::vector<std::vector<int>>* vec);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfVectorOfIntCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfVectorOfIntPush($vecVec, $vec[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveInputArrayFromVectorOfVectorOfInt", $bVecDllType, $vecVec), "cveInputArrayFromVectorOfVectorOfInt", @error)

    If $bVecIsArray Then
        _VectorOfVectorOfIntRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveInputArrayFromVectorOfVectorOfInt

Func _cveOutputArrayFromVectorOfVectorOfInt($vec)
    ; CVAPI(cv::_OutputArray*) cveOutputArrayFromVectorOfVectorOfInt(std::vector<std::vector<int>>* vec);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfVectorOfIntCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfVectorOfIntPush($vecVec, $vec[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveOutputArrayFromVectorOfVectorOfInt", $bVecDllType, $vecVec), "cveOutputArrayFromVectorOfVectorOfInt", @error)

    If $bVecIsArray Then
        _VectorOfVectorOfIntRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveOutputArrayFromVectorOfVectorOfInt

Func _cveInputOutputArrayFromVectorOfVectorOfInt($vec)
    ; CVAPI(cv::_InputOutputArray*) cveInputOutputArrayFromVectorOfVectorOfInt(std::vector<std::vector<int>>* vec);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfVectorOfIntCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfVectorOfIntPush($vecVec, $vec[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveInputOutputArrayFromVectorOfVectorOfInt", $bVecDllType, $vecVec), "cveInputOutputArrayFromVectorOfVectorOfInt", @error)

    If $bVecIsArray Then
        _VectorOfVectorOfIntRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveInputOutputArrayFromVectorOfVectorOfInt

Func _VectorOfVectorOfIntSizeOfItemInBytes()
    ; CVAPI(int) VectorOfVectorOfIntSizeOfItemInBytes();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "VectorOfVectorOfIntSizeOfItemInBytes"), "VectorOfVectorOfIntSizeOfItemInBytes", @error)
EndFunc   ;==>_VectorOfVectorOfIntSizeOfItemInBytes