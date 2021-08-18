#include-once
#include "..\CVEUtils.au3"

Func _VectorOfVectorOfByteCreate()
    ; CVAPI(std::vector<std::vector<unsigned char>>*) VectorOfVectorOfByteCreate();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfVectorOfByteCreate"), "VectorOfVectorOfByteCreate", @error)
EndFunc   ;==>_VectorOfVectorOfByteCreate

Func _VectorOfVectorOfByteCreateSize($size)
    ; CVAPI(std::vector<std::vector<unsigned char>>*) VectorOfVectorOfByteCreateSize(int size);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfVectorOfByteCreateSize", "int", $size), "VectorOfVectorOfByteCreateSize", @error)
EndFunc   ;==>_VectorOfVectorOfByteCreateSize

Func _VectorOfVectorOfByteGetSize($v)
    ; CVAPI(int) VectorOfVectorOfByteGetSize(std::vector<std::vector<unsigned char>>* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfVectorOfByteCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfVectorOfBytePush($vecV, $v[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "VectorOfVectorOfByteGetSize", $bVDllType, $vecV), "VectorOfVectorOfByteGetSize", @error)

    If $bVIsArray Then
        _VectorOfVectorOfByteRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfVectorOfByteGetSize

Func _VectorOfVectorOfBytePush($v, $value)
    ; CVAPI(void) VectorOfVectorOfBytePush(std::vector<std::vector<unsigned char>>* v, std::vector<unsigned char>* value);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfVectorOfByteCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfVectorOfBytePush($vecV, $v[$i])
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
        $vecValue = _VectorOfByteCreate()

        $iArrValueSize = UBound($value)
        For $i = 0 To $iArrValueSize - 1
            _VectorOfBytePush($vecValue, $value[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfVectorOfBytePush", $bVDllType, $vecV, $bValueDllType, $vecValue), "VectorOfVectorOfBytePush", @error)

    If $bValueIsArray Then
        _VectorOfByteRelease($vecValue)
    EndIf

    If $bVIsArray Then
        _VectorOfVectorOfByteRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfVectorOfBytePush

Func _VectorOfVectorOfBytePushVector($v, $other)
    ; CVAPI(void) VectorOfVectorOfBytePushVector(std::vector<std::vector<unsigned char>>* v, std::vector<std::vector<unsigned char>>* other);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfVectorOfByteCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfVectorOfBytePush($vecV, $v[$i])
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
        $vecOther = _VectorOfVectorOfByteCreate()

        $iArrOtherSize = UBound($other)
        For $i = 0 To $iArrOtherSize - 1
            _VectorOfVectorOfBytePush($vecOther, $other[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfVectorOfBytePushVector", $bVDllType, $vecV, $bOtherDllType, $vecOther), "VectorOfVectorOfBytePushVector", @error)

    If $bOtherIsArray Then
        _VectorOfVectorOfByteRelease($vecOther)
    EndIf

    If $bVIsArray Then
        _VectorOfVectorOfByteRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfVectorOfBytePushVector

Func _VectorOfVectorOfByteGetStartAddress($v)
    ; CVAPI(std::vector<unsigned char>*) VectorOfVectorOfByteGetStartAddress(std::vector<std::vector<unsigned char>>* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfVectorOfByteCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfVectorOfBytePush($vecV, $v[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfVectorOfByteGetStartAddress", $bVDllType, $vecV), "VectorOfVectorOfByteGetStartAddress", @error)

    If $bVIsArray Then
        _VectorOfVectorOfByteRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfVectorOfByteGetStartAddress

Func _VectorOfVectorOfByteGetEndAddress($v)
    ; CVAPI(void*) VectorOfVectorOfByteGetEndAddress(std::vector<std::vector<unsigned char>>* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfVectorOfByteCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfVectorOfBytePush($vecV, $v[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfVectorOfByteGetEndAddress", $bVDllType, $vecV), "VectorOfVectorOfByteGetEndAddress", @error)

    If $bVIsArray Then
        _VectorOfVectorOfByteRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfVectorOfByteGetEndAddress

Func _VectorOfVectorOfByteClear($v)
    ; CVAPI(void) VectorOfVectorOfByteClear(std::vector<std::vector<unsigned char>>* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfVectorOfByteCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfVectorOfBytePush($vecV, $v[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfVectorOfByteClear", $bVDllType, $vecV), "VectorOfVectorOfByteClear", @error)

    If $bVIsArray Then
        _VectorOfVectorOfByteRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfVectorOfByteClear

Func _VectorOfVectorOfByteRelease($v)
    ; CVAPI(void) VectorOfVectorOfByteRelease(std::vector<std::vector<unsigned char>>** v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfVectorOfByteCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfVectorOfBytePush($vecV, $v[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfVectorOfByteRelease", $bVDllType, $vecV), "VectorOfVectorOfByteRelease", @error)

    If $bVIsArray Then
        _VectorOfVectorOfByteRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfVectorOfByteRelease

Func _VectorOfVectorOfByteCopyData($v, $data)
    ; CVAPI(void) VectorOfVectorOfByteCopyData(std::vector<std::vector<unsigned char>>* v, std::vector<unsigned char>* data);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfVectorOfByteCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfVectorOfBytePush($vecV, $v[$i])
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
        $vecData = _VectorOfByteCreate()

        $iArrDataSize = UBound($data)
        For $i = 0 To $iArrDataSize - 1
            _VectorOfBytePush($vecData, $data[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfVectorOfByteCopyData", $bVDllType, $vecV, $bDataDllType, $vecData), "VectorOfVectorOfByteCopyData", @error)

    If $bDataIsArray Then
        _VectorOfByteRelease($vecData)
    EndIf

    If $bVIsArray Then
        _VectorOfVectorOfByteRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfVectorOfByteCopyData

Func _VectorOfVectorOfByteGetItemPtr($vec, $index, $element)
    ; CVAPI(void) VectorOfVectorOfByteGetItemPtr(std::vector<std::vector<unsigned char>>* vec, int index, std::vector<unsigned char>** element);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfVectorOfByteCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfVectorOfBytePush($vecVec, $vec[$i])
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
        $vecElement = _VectorOfByteCreate()

        $iArrElementSize = UBound($element)
        For $i = 0 To $iArrElementSize - 1
            _VectorOfBytePush($vecElement, $element[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfVectorOfByteGetItemPtr", $bVecDllType, $vecVec, "int", $index, $bElementDllType, $vecElement), "VectorOfVectorOfByteGetItemPtr", @error)

    If $bElementIsArray Then
        _VectorOfByteRelease($vecElement)
    EndIf

    If $bVecIsArray Then
        _VectorOfVectorOfByteRelease($vecVec)
    EndIf
EndFunc   ;==>_VectorOfVectorOfByteGetItemPtr

Func _cveInputArrayFromVectorOfVectorOfByte($vec)
    ; CVAPI(cv::_InputArray*) cveInputArrayFromVectorOfVectorOfByte(std::vector<std::vector<unsigned char>>* vec);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfVectorOfByteCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfVectorOfBytePush($vecVec, $vec[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveInputArrayFromVectorOfVectorOfByte", $bVecDllType, $vecVec), "cveInputArrayFromVectorOfVectorOfByte", @error)

    If $bVecIsArray Then
        _VectorOfVectorOfByteRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveInputArrayFromVectorOfVectorOfByte

Func _cveOutputArrayFromVectorOfVectorOfByte($vec)
    ; CVAPI(cv::_OutputArray*) cveOutputArrayFromVectorOfVectorOfByte(std::vector<std::vector<unsigned char>>* vec);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfVectorOfByteCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfVectorOfBytePush($vecVec, $vec[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveOutputArrayFromVectorOfVectorOfByte", $bVecDllType, $vecVec), "cveOutputArrayFromVectorOfVectorOfByte", @error)

    If $bVecIsArray Then
        _VectorOfVectorOfByteRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveOutputArrayFromVectorOfVectorOfByte

Func _cveInputOutputArrayFromVectorOfVectorOfByte($vec)
    ; CVAPI(cv::_InputOutputArray*) cveInputOutputArrayFromVectorOfVectorOfByte(std::vector<std::vector<unsigned char>>* vec);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfVectorOfByteCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfVectorOfBytePush($vecVec, $vec[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveInputOutputArrayFromVectorOfVectorOfByte", $bVecDllType, $vecVec), "cveInputOutputArrayFromVectorOfVectorOfByte", @error)

    If $bVecIsArray Then
        _VectorOfVectorOfByteRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveInputOutputArrayFromVectorOfVectorOfByte

Func _VectorOfVectorOfByteSizeOfItemInBytes()
    ; CVAPI(int) VectorOfVectorOfByteSizeOfItemInBytes();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "VectorOfVectorOfByteSizeOfItemInBytes"), "VectorOfVectorOfByteSizeOfItemInBytes", @error)
EndFunc   ;==>_VectorOfVectorOfByteSizeOfItemInBytes