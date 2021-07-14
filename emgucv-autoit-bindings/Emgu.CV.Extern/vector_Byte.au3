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

Func _VectorOfByteGetSize(ByRef $v)
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "VectorOfByteGetSize", "ptr", $vecV), "VectorOfByteGetSize", @error)

    If $bVIsArray Then
        _VectorOfByteRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfByteGetSize

Func _VectorOfBytePush(ByRef $v, ByRef $value)
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfBytePush", "ptr", $vecV, "ptr", $value), "VectorOfBytePush", @error)

    If $bVIsArray Then
        _VectorOfByteRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfBytePush

Func _VectorOfBytePushMulti(ByRef $v, ByRef $values, $count)
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfBytePushMulti", "ptr", $vecV, "ptr", $values, "int", $count), "VectorOfBytePushMulti", @error)

    If $bVIsArray Then
        _VectorOfByteRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfBytePushMulti

Func _VectorOfBytePushVector(ByRef $v, ByRef $other)
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfBytePushVector", "ptr", $vecV, "ptr", $vecOther), "VectorOfBytePushVector", @error)

    If $bOtherIsArray Then
        _VectorOfByteRelease($vecOther)
    EndIf

    If $bVIsArray Then
        _VectorOfByteRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfBytePushVector

Func _VectorOfByteClear(ByRef $v)
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfByteClear", "ptr", $vecV), "VectorOfByteClear", @error)

    If $bVIsArray Then
        _VectorOfByteRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfByteClear

Func _VectorOfByteRelease(ByRef $v)
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfByteRelease", "ptr*", $vecV), "VectorOfByteRelease", @error)

    If $bVIsArray Then
        _VectorOfByteRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfByteRelease

Func _VectorOfByteCopyData(ByRef $v, ByRef $data)
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfByteCopyData", "ptr", $vecV, "ptr", $data), "VectorOfByteCopyData", @error)

    If $bVIsArray Then
        _VectorOfByteRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfByteCopyData

Func _VectorOfByteGetStartAddress(ByRef $v)
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfByteGetStartAddress", "ptr", $vecV), "VectorOfByteGetStartAddress", @error)

    If $bVIsArray Then
        _VectorOfByteRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfByteGetStartAddress

Func _VectorOfByteGetEndAddress(ByRef $v)
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfByteGetEndAddress", "ptr", $vecV), "VectorOfByteGetEndAddress", @error)

    If $bVIsArray Then
        _VectorOfByteRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfByteGetEndAddress

Func _VectorOfByteGetItem(ByRef $vec, $index, ByRef $element)
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfByteGetItem", "ptr", $vecVec, "int", $index, "ptr", $element), "VectorOfByteGetItem", @error)

    If $bVecIsArray Then
        _VectorOfByteRelease($vecVec)
    EndIf
EndFunc   ;==>_VectorOfByteGetItem

Func _VectorOfByteGetItemPtr(ByRef $vec, $index, ByRef $element)
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfByteGetItemPtr", "ptr", $vecVec, "int", $index, "ptr*", $element), "VectorOfByteGetItemPtr", @error)

    If $bVecIsArray Then
        _VectorOfByteRelease($vecVec)
    EndIf
EndFunc   ;==>_VectorOfByteGetItemPtr

Func _cveInputArrayFromVectorOfByte(ByRef $vec)
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveInputArrayFromVectorOfByte", "ptr", $vecVec), "cveInputArrayFromVectorOfByte", @error)

    If $bVecIsArray Then
        _VectorOfByteRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveInputArrayFromVectorOfByte

Func _cveOutputArrayFromVectorOfByte(ByRef $vec)
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveOutputArrayFromVectorOfByte", "ptr", $vecVec), "cveOutputArrayFromVectorOfByte", @error)

    If $bVecIsArray Then
        _VectorOfByteRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveOutputArrayFromVectorOfByte

Func _cveInputOutputArrayFromVectorOfByte(ByRef $vec)
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveInputOutputArrayFromVectorOfByte", "ptr", $vecVec), "cveInputOutputArrayFromVectorOfByte", @error)

    If $bVecIsArray Then
        _VectorOfByteRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveInputOutputArrayFromVectorOfByte

Func _VectorOfByteSizeOfItemInBytes()
    ; CVAPI(int) VectorOfByteSizeOfItemInBytes();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "VectorOfByteSizeOfItemInBytes"), "VectorOfByteSizeOfItemInBytes", @error)
EndFunc   ;==>_VectorOfByteSizeOfItemInBytes