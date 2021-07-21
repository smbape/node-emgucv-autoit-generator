#include-once
#include "..\CVEUtils.au3"

Func _VectorOfCvStringCreate()
    ; CVAPI(std::vector< cv::String >*) VectorOfCvStringCreate();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfCvStringCreate"), "VectorOfCvStringCreate", @error)
EndFunc   ;==>_VectorOfCvStringCreate

Func _VectorOfCvStringCreateSize($size)
    ; CVAPI(std::vector< cv::String >*) VectorOfCvStringCreateSize(int size);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfCvStringCreateSize", "int", $size), "VectorOfCvStringCreateSize", @error)
EndFunc   ;==>_VectorOfCvStringCreateSize

Func _VectorOfCvStringGetSize($v)
    ; CVAPI(int) VectorOfCvStringGetSize(std::vector< cv::String >* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfCvStringCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfCvStringPush($vecV, $v[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "VectorOfCvStringGetSize", $bVDllType, $vecV), "VectorOfCvStringGetSize", @error)

    If $bVIsArray Then
        _VectorOfCvStringRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfCvStringGetSize

Func _VectorOfCvStringPush($v, $value)
    ; CVAPI(void) VectorOfCvStringPush(std::vector< cv::String >* v, cv::String* value);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfCvStringCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfCvStringPush($vecV, $v[$i])
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

    Local $bValueIsString = VarGetType($value) == "String"
    If $bValueIsString Then
        $value = _cveStringCreateFromStr($value)
    EndIf

    Local $bValueDllType
    If VarGetType($value) == "DLLStruct" Then
        $bValueDllType = "struct*"
    Else
        $bValueDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfCvStringPush", $bVDllType, $vecV, $bValueDllType, $value), "VectorOfCvStringPush", @error)

    If $bValueIsString Then
        _cveStringRelease($value)
    EndIf

    If $bVIsArray Then
        _VectorOfCvStringRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfCvStringPush

Func _VectorOfCvStringPushVector($v, $other)
    ; CVAPI(void) VectorOfCvStringPushVector(std::vector< cv::String >* v, std::vector< cv::String >* other);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfCvStringCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfCvStringPush($vecV, $v[$i])
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
        $vecOther = _VectorOfCvStringCreate()

        $iArrOtherSize = UBound($other)
        For $i = 0 To $iArrOtherSize - 1
            _VectorOfCvStringPush($vecOther, $other[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfCvStringPushVector", $bVDllType, $vecV, $bOtherDllType, $vecOther), "VectorOfCvStringPushVector", @error)

    If $bOtherIsArray Then
        _VectorOfCvStringRelease($vecOther)
    EndIf

    If $bVIsArray Then
        _VectorOfCvStringRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfCvStringPushVector

Func _VectorOfCvStringGetStartAddress($v)
    ; CVAPI(cv::String*) VectorOfCvStringGetStartAddress(std::vector< cv::String >* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfCvStringCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfCvStringPush($vecV, $v[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfCvStringGetStartAddress", $bVDllType, $vecV), "VectorOfCvStringGetStartAddress", @error)

    If $bVIsArray Then
        _VectorOfCvStringRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfCvStringGetStartAddress

Func _VectorOfCvStringGetEndAddress($v)
    ; CVAPI(void*) VectorOfCvStringGetEndAddress(std::vector< cv::String >* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfCvStringCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfCvStringPush($vecV, $v[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfCvStringGetEndAddress", $bVDllType, $vecV), "VectorOfCvStringGetEndAddress", @error)

    If $bVIsArray Then
        _VectorOfCvStringRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfCvStringGetEndAddress

Func _VectorOfCvStringClear($v)
    ; CVAPI(void) VectorOfCvStringClear(std::vector< cv::String >* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfCvStringCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfCvStringPush($vecV, $v[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfCvStringClear", $bVDllType, $vecV), "VectorOfCvStringClear", @error)

    If $bVIsArray Then
        _VectorOfCvStringRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfCvStringClear

Func _VectorOfCvStringRelease($v)
    ; CVAPI(void) VectorOfCvStringRelease(std::vector< cv::String >** v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfCvStringCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfCvStringPush($vecV, $v[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfCvStringRelease", $bVDllType, $vecV), "VectorOfCvStringRelease", @error)

    If $bVIsArray Then
        _VectorOfCvStringRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfCvStringRelease

Func _VectorOfCvStringCopyData($v, $data)
    ; CVAPI(void) VectorOfCvStringCopyData(std::vector< cv::String >* v, cv::String* data);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfCvStringCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfCvStringPush($vecV, $v[$i])
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

    Local $bDataIsString = VarGetType($data) == "String"
    If $bDataIsString Then
        $data = _cveStringCreateFromStr($data)
    EndIf

    Local $bDataDllType
    If VarGetType($data) == "DLLStruct" Then
        $bDataDllType = "struct*"
    Else
        $bDataDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfCvStringCopyData", $bVDllType, $vecV, $bDataDllType, $data), "VectorOfCvStringCopyData", @error)

    If $bDataIsString Then
        _cveStringRelease($data)
    EndIf

    If $bVIsArray Then
        _VectorOfCvStringRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfCvStringCopyData

Func _VectorOfCvStringGetItemPtr($vec, $index, $element)
    ; CVAPI(void) VectorOfCvStringGetItemPtr(std::vector<  cv::String >* vec, int index, cv::String** element);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfCvStringCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfCvStringPush($vecVec, $vec[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfCvStringGetItemPtr", $bVecDllType, $vecVec, "int", $index, $bElementDllType, $element), "VectorOfCvStringGetItemPtr", @error)

    If $bVecIsArray Then
        _VectorOfCvStringRelease($vecVec)
    EndIf
EndFunc   ;==>_VectorOfCvStringGetItemPtr

Func _cveInputArrayFromVectorOfCvString($vec)
    ; CVAPI(cv::_InputArray*) cveInputArrayFromVectorOfCvString(std::vector< cv::String >* vec);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfCvStringCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfCvStringPush($vecVec, $vec[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveInputArrayFromVectorOfCvString", $bVecDllType, $vecVec), "cveInputArrayFromVectorOfCvString", @error)

    If $bVecIsArray Then
        _VectorOfCvStringRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveInputArrayFromVectorOfCvString

Func _cveOutputArrayFromVectorOfCvString($vec)
    ; CVAPI(cv::_OutputArray*) cveOutputArrayFromVectorOfCvString(std::vector< cv::String >* vec);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfCvStringCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfCvStringPush($vecVec, $vec[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveOutputArrayFromVectorOfCvString", $bVecDllType, $vecVec), "cveOutputArrayFromVectorOfCvString", @error)

    If $bVecIsArray Then
        _VectorOfCvStringRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveOutputArrayFromVectorOfCvString

Func _cveInputOutputArrayFromVectorOfCvString($vec)
    ; CVAPI(cv::_InputOutputArray*) cveInputOutputArrayFromVectorOfCvString(std::vector< cv::String >* vec);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfCvStringCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfCvStringPush($vecVec, $vec[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveInputOutputArrayFromVectorOfCvString", $bVecDllType, $vecVec), "cveInputOutputArrayFromVectorOfCvString", @error)

    If $bVecIsArray Then
        _VectorOfCvStringRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveInputOutputArrayFromVectorOfCvString

Func _VectorOfCvStringSizeOfItemInBytes()
    ; CVAPI(int) VectorOfCvStringSizeOfItemInBytes();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "VectorOfCvStringSizeOfItemInBytes"), "VectorOfCvStringSizeOfItemInBytes", @error)
EndFunc   ;==>_VectorOfCvStringSizeOfItemInBytes