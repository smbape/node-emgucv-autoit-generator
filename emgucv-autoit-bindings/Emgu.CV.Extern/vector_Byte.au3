#include-once
#include "..\CVEUtils.au3"

Func _VectorOfByteCreate()
    ; CVAPI(std::vector< unsigned char >*) VectorOfByteCreate();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfByteCreate"), "VectorOfByteCreate", @error)
EndFunc   ;==>_VectorOfByteCreate

Func _VectorOfByteCreateSize($size)
    ; CVAPI(std::vector< unsigned char >*) VectorOfByteCreateSize(int size);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfByteCreateSize", "int", $size), "VectorOfByteCreateSize", @error)
EndFunc   ;==>_VectorOfByteCreateSize

Func _VectorOfByteGetSize($v)
    ; CVAPI(int) VectorOfByteGetSize(std::vector< unsigned char >* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfByteCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfBytePush($vecV, $v[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "VectorOfByteGetSize", $bVDllType, $vecV), "VectorOfByteGetSize", @error)

    If $bVIsArray Then
        _VectorOfByteRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfByteGetSize

Func _VectorOfBytePush($v, $value)
    ; CVAPI(void) VectorOfBytePush(std::vector< unsigned char >* v, unsigned char* value);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfByteCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfBytePush($vecV, $v[$i])
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
        $bValueDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfBytePush", $bVDllType, $vecV, $bValueDllType, $value), "VectorOfBytePush", @error)

    If $bVIsArray Then
        _VectorOfByteRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfBytePush

Func _VectorOfBytePushMulti($v, $values, $count)
    ; CVAPI(void) VectorOfBytePushMulti(std::vector< unsigned char >* v, unsigned char* values, int count);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfByteCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfBytePush($vecV, $v[$i])
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
        $bValuesDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfBytePushMulti", $bVDllType, $vecV, $bValuesDllType, $values, "int", $count), "VectorOfBytePushMulti", @error)

    If $bVIsArray Then
        _VectorOfByteRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfBytePushMulti

Func _VectorOfBytePushVector($v, $other)
    ; CVAPI(void) VectorOfBytePushVector(std::vector< unsigned char >* v, std::vector< unsigned char >* other);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfByteCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfBytePush($vecV, $v[$i])
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
        $vecOther = _VectorOfByteCreate()

        $iArrOtherSize = UBound($other)
        For $i = 0 To $iArrOtherSize - 1
            _VectorOfBytePush($vecOther, $other[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfBytePushVector", $bVDllType, $vecV, $bOtherDllType, $vecOther), "VectorOfBytePushVector", @error)

    If $bOtherIsArray Then
        _VectorOfByteRelease($vecOther)
    EndIf

    If $bVIsArray Then
        _VectorOfByteRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfBytePushVector

Func _VectorOfByteClear($v)
    ; CVAPI(void) VectorOfByteClear(std::vector< unsigned char >* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfByteCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfBytePush($vecV, $v[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfByteClear", $bVDllType, $vecV), "VectorOfByteClear", @error)

    If $bVIsArray Then
        _VectorOfByteRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfByteClear

Func _VectorOfByteRelease($v)
    ; CVAPI(void) VectorOfByteRelease(std::vector< unsigned char >** v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfByteCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfBytePush($vecV, $v[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfByteRelease", $bVDllType, $vecV), "VectorOfByteRelease", @error)

    If $bVIsArray Then
        _VectorOfByteRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfByteRelease

Func _VectorOfByteCopyData($v, $data)
    ; CVAPI(void) VectorOfByteCopyData(std::vector< unsigned char >* v, unsigned char* data);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfByteCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfBytePush($vecV, $v[$i])
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
        $bDataDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfByteCopyData", $bVDllType, $vecV, $bDataDllType, $data), "VectorOfByteCopyData", @error)

    If $bVIsArray Then
        _VectorOfByteRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfByteCopyData

Func _VectorOfByteGetStartAddress($v)
    ; CVAPI(unsigned char*) VectorOfByteGetStartAddress(std::vector< unsigned char >* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfByteCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfBytePush($vecV, $v[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfByteGetStartAddress", $bVDllType, $vecV), "VectorOfByteGetStartAddress", @error)

    If $bVIsArray Then
        _VectorOfByteRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfByteGetStartAddress

Func _VectorOfByteGetEndAddress($v)
    ; CVAPI(void*) VectorOfByteGetEndAddress(std::vector< unsigned char >* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfByteCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfBytePush($vecV, $v[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfByteGetEndAddress", $bVDllType, $vecV), "VectorOfByteGetEndAddress", @error)

    If $bVIsArray Then
        _VectorOfByteRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfByteGetEndAddress

Func _VectorOfByteGetItem($vec, $index, $element)
    ; CVAPI(void) VectorOfByteGetItem(std::vector<  unsigned char >* vec, int index, unsigned char* element);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfByteCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfBytePush($vecVec, $vec[$i])
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
        $bElementDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfByteGetItem", $bVecDllType, $vecVec, "int", $index, $bElementDllType, $element), "VectorOfByteGetItem", @error)

    If $bVecIsArray Then
        _VectorOfByteRelease($vecVec)
    EndIf
EndFunc   ;==>_VectorOfByteGetItem

Func _VectorOfByteGetItemPtr($vec, $index, $element)
    ; CVAPI(void) VectorOfByteGetItemPtr(std::vector<  unsigned char >* vec, int index, unsigned char** element);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfByteCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfBytePush($vecVec, $vec[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfByteGetItemPtr", $bVecDllType, $vecVec, "int", $index, $bElementDllType, $element), "VectorOfByteGetItemPtr", @error)

    If $bVecIsArray Then
        _VectorOfByteRelease($vecVec)
    EndIf
EndFunc   ;==>_VectorOfByteGetItemPtr

Func _cveInputArrayFromVectorOfByte($vec)
    ; CVAPI(cv::_InputArray*) cveInputArrayFromVectorOfByte(std::vector< unsigned char >* vec);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfByteCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfBytePush($vecVec, $vec[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveInputArrayFromVectorOfByte", $bVecDllType, $vecVec), "cveInputArrayFromVectorOfByte", @error)

    If $bVecIsArray Then
        _VectorOfByteRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveInputArrayFromVectorOfByte

Func _cveOutputArrayFromVectorOfByte($vec)
    ; CVAPI(cv::_OutputArray*) cveOutputArrayFromVectorOfByte(std::vector< unsigned char >* vec);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfByteCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfBytePush($vecVec, $vec[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveOutputArrayFromVectorOfByte", $bVecDllType, $vecVec), "cveOutputArrayFromVectorOfByte", @error)

    If $bVecIsArray Then
        _VectorOfByteRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveOutputArrayFromVectorOfByte

Func _cveInputOutputArrayFromVectorOfByte($vec)
    ; CVAPI(cv::_InputOutputArray*) cveInputOutputArrayFromVectorOfByte(std::vector< unsigned char >* vec);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfByteCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfBytePush($vecVec, $vec[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveInputOutputArrayFromVectorOfByte", $bVecDllType, $vecVec), "cveInputOutputArrayFromVectorOfByte", @error)

    If $bVecIsArray Then
        _VectorOfByteRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveInputOutputArrayFromVectorOfByte

Func _VectorOfByteSizeOfItemInBytes()
    ; CVAPI(int) VectorOfByteSizeOfItemInBytes();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "VectorOfByteSizeOfItemInBytes"), "VectorOfByteSizeOfItemInBytes", @error)
EndFunc   ;==>_VectorOfByteSizeOfItemInBytes