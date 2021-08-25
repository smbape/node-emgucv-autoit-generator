#include-once
#include "..\CVEUtils.au3"

Func _VectorOfByteCreate()
    ; CVAPI(std::vector<unsigned char>*) VectorOfByteCreate();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfByteCreate"), "VectorOfByteCreate", @error)
EndFunc   ;==>_VectorOfByteCreate

Func _VectorOfByteCreateSize($size)
    ; CVAPI(std::vector<unsigned char>*) VectorOfByteCreateSize(int size);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfByteCreateSize", "int", $size), "VectorOfByteCreateSize", @error)
EndFunc   ;==>_VectorOfByteCreateSize

Func _VectorOfByteGetSize($v)
    ; CVAPI(int) VectorOfByteGetSize(std::vector<unsigned char>* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = IsArray($v)

    If $bVIsArray Then
        $vecV = _VectorOfByteCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfBytePush($vecV, $v[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "VectorOfByteGetSize", $sVDllType, $vecV), "VectorOfByteGetSize", @error)

    If $bVIsArray Then
        _VectorOfByteRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfByteGetSize

Func _VectorOfBytePush($v, $value)
    ; CVAPI(void) VectorOfBytePush(std::vector<unsigned char>* v, unsigned char* value);

    Local $vecV, $iArrVSize
    Local $bVIsArray = IsArray($v)

    If $bVIsArray Then
        $vecV = _VectorOfByteCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfBytePush($vecV, $v[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfBytePush", $sVDllType, $vecV, $sValueDllType, $value), "VectorOfBytePush", @error)

    If $bVIsArray Then
        _VectorOfByteRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfBytePush

Func _VectorOfBytePushMulti($v, $values, $count)
    ; CVAPI(void) VectorOfBytePushMulti(std::vector<unsigned char>* v, unsigned char* values, int count);

    Local $vecV, $iArrVSize
    Local $bVIsArray = IsArray($v)

    If $bVIsArray Then
        $vecV = _VectorOfByteCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfBytePush($vecV, $v[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfBytePushMulti", $sVDllType, $vecV, $sValuesDllType, $values, "int", $count), "VectorOfBytePushMulti", @error)

    If $bVIsArray Then
        _VectorOfByteRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfBytePushMulti

Func _VectorOfBytePushVector($v, $other)
    ; CVAPI(void) VectorOfBytePushVector(std::vector<unsigned char>* v, std::vector<unsigned char>* other);

    Local $vecV, $iArrVSize
    Local $bVIsArray = IsArray($v)

    If $bVIsArray Then
        $vecV = _VectorOfByteCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfBytePush($vecV, $v[$i])
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
        $vecOther = _VectorOfByteCreate()

        $iArrOtherSize = UBound($other)
        For $i = 0 To $iArrOtherSize - 1
            _VectorOfBytePush($vecOther, $other[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfBytePushVector", $sVDllType, $vecV, $sOtherDllType, $vecOther), "VectorOfBytePushVector", @error)

    If $bOtherIsArray Then
        _VectorOfByteRelease($vecOther)
    EndIf

    If $bVIsArray Then
        _VectorOfByteRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfBytePushVector

Func _VectorOfByteClear($v)
    ; CVAPI(void) VectorOfByteClear(std::vector<unsigned char>* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = IsArray($v)

    If $bVIsArray Then
        $vecV = _VectorOfByteCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfBytePush($vecV, $v[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfByteClear", $sVDllType, $vecV), "VectorOfByteClear", @error)

    If $bVIsArray Then
        _VectorOfByteRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfByteClear

Func _VectorOfByteRelease($v)
    ; CVAPI(void) VectorOfByteRelease(std::vector<unsigned char>** v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = IsArray($v)

    If $bVIsArray Then
        $vecV = _VectorOfByteCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfBytePush($vecV, $v[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfByteRelease", $sVDllType, $vecV), "VectorOfByteRelease", @error)

    If $bVIsArray Then
        _VectorOfByteRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfByteRelease

Func _VectorOfByteCopyData($v, $data)
    ; CVAPI(void) VectorOfByteCopyData(std::vector<unsigned char>* v, unsigned char* data);

    Local $vecV, $iArrVSize
    Local $bVIsArray = IsArray($v)

    If $bVIsArray Then
        $vecV = _VectorOfByteCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfBytePush($vecV, $v[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfByteCopyData", $sVDllType, $vecV, $sDataDllType, $data), "VectorOfByteCopyData", @error)

    If $bVIsArray Then
        _VectorOfByteRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfByteCopyData

Func _VectorOfByteGetStartAddress($v)
    ; CVAPI(unsigned char*) VectorOfByteGetStartAddress(std::vector<unsigned char>* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = IsArray($v)

    If $bVIsArray Then
        $vecV = _VectorOfByteCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfBytePush($vecV, $v[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfByteGetStartAddress", $sVDllType, $vecV), "VectorOfByteGetStartAddress", @error)

    If $bVIsArray Then
        _VectorOfByteRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfByteGetStartAddress

Func _VectorOfByteGetEndAddress($v)
    ; CVAPI(void*) VectorOfByteGetEndAddress(std::vector<unsigned char>* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = IsArray($v)

    If $bVIsArray Then
        $vecV = _VectorOfByteCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfBytePush($vecV, $v[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfByteGetEndAddress", $sVDllType, $vecV), "VectorOfByteGetEndAddress", @error)

    If $bVIsArray Then
        _VectorOfByteRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfByteGetEndAddress

Func _VectorOfByteGetItem($vec, $index, $element)
    ; CVAPI(void) VectorOfByteGetItem(std::vector<unsigned char>* vec, int index, unsigned char* element);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = IsArray($vec)

    If $bVecIsArray Then
        $vecVec = _VectorOfByteCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfBytePush($vecVec, $vec[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfByteGetItem", $sVecDllType, $vecVec, "int", $index, $sElementDllType, $element), "VectorOfByteGetItem", @error)

    If $bVecIsArray Then
        _VectorOfByteRelease($vecVec)
    EndIf
EndFunc   ;==>_VectorOfByteGetItem

Func _VectorOfByteGetItemPtr($vec, $index, $element)
    ; CVAPI(void) VectorOfByteGetItemPtr(std::vector<unsigned char>* vec, int index, unsigned char** element);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = IsArray($vec)

    If $bVecIsArray Then
        $vecVec = _VectorOfByteCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfBytePush($vecVec, $vec[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfByteGetItemPtr", $sVecDllType, $vecVec, "int", $index, $sElementDllType, $element), "VectorOfByteGetItemPtr", @error)

    If $bVecIsArray Then
        _VectorOfByteRelease($vecVec)
    EndIf
EndFunc   ;==>_VectorOfByteGetItemPtr

Func _cveInputArrayFromVectorOfByte($vec)
    ; CVAPI(cv::_InputArray*) cveInputArrayFromVectorOfByte(std::vector<unsigned char>* vec);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = IsArray($vec)

    If $bVecIsArray Then
        $vecVec = _VectorOfByteCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfBytePush($vecVec, $vec[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveInputArrayFromVectorOfByte", $sVecDllType, $vecVec), "cveInputArrayFromVectorOfByte", @error)

    If $bVecIsArray Then
        _VectorOfByteRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveInputArrayFromVectorOfByte

Func _cveOutputArrayFromVectorOfByte($vec)
    ; CVAPI(cv::_OutputArray*) cveOutputArrayFromVectorOfByte(std::vector<unsigned char>* vec);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = IsArray($vec)

    If $bVecIsArray Then
        $vecVec = _VectorOfByteCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfBytePush($vecVec, $vec[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveOutputArrayFromVectorOfByte", $sVecDllType, $vecVec), "cveOutputArrayFromVectorOfByte", @error)

    If $bVecIsArray Then
        _VectorOfByteRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveOutputArrayFromVectorOfByte

Func _cveInputOutputArrayFromVectorOfByte($vec)
    ; CVAPI(cv::_InputOutputArray*) cveInputOutputArrayFromVectorOfByte(std::vector<unsigned char>* vec);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = IsArray($vec)

    If $bVecIsArray Then
        $vecVec = _VectorOfByteCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfBytePush($vecVec, $vec[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveInputOutputArrayFromVectorOfByte", $sVecDllType, $vecVec), "cveInputOutputArrayFromVectorOfByte", @error)

    If $bVecIsArray Then
        _VectorOfByteRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveInputOutputArrayFromVectorOfByte

Func _VectorOfByteSizeOfItemInBytes()
    ; CVAPI(int) VectorOfByteSizeOfItemInBytes();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "VectorOfByteSizeOfItemInBytes"), "VectorOfByteSizeOfItemInBytes", @error)
EndFunc   ;==>_VectorOfByteSizeOfItemInBytes