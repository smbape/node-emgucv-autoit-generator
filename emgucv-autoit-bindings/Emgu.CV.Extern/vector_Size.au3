#include-once
#include "..\CVEUtils.au3"

Func _VectorOfSizeCreate()
    ; CVAPI(std::vector< cv::Size >*) VectorOfSizeCreate();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfSizeCreate"), "VectorOfSizeCreate", @error)
EndFunc   ;==>_VectorOfSizeCreate

Func _VectorOfSizeCreateSize($size)
    ; CVAPI(std::vector< cv::Size >*) VectorOfSizeCreateSize(int size);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfSizeCreateSize", "int", $size), "VectorOfSizeCreateSize", @error)
EndFunc   ;==>_VectorOfSizeCreateSize

Func _VectorOfSizeGetSize($v)
    ; CVAPI(int) VectorOfSizeGetSize(std::vector< cv::Size >* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfSizeCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfSizePush($vecV, $v[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "VectorOfSizeGetSize", $bVDllType, $vecV), "VectorOfSizeGetSize", @error)

    If $bVIsArray Then
        _VectorOfSizeRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfSizeGetSize

Func _VectorOfSizePush($v, $value)
    ; CVAPI(void) VectorOfSizePush(std::vector< cv::Size >* v, cv::Size* value);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfSizeCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfSizePush($vecV, $v[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfSizePush", $bVDllType, $vecV, $bValueDllType, $value), "VectorOfSizePush", @error)

    If $bVIsArray Then
        _VectorOfSizeRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfSizePush

Func _VectorOfSizePushMulti($v, $values, $count)
    ; CVAPI(void) VectorOfSizePushMulti(std::vector< cv::Size >* v, cv::Size* values, int count);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfSizeCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfSizePush($vecV, $v[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfSizePushMulti", $bVDllType, $vecV, $bValuesDllType, $values, "int", $count), "VectorOfSizePushMulti", @error)

    If $bVIsArray Then
        _VectorOfSizeRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfSizePushMulti

Func _VectorOfSizePushVector($v, $other)
    ; CVAPI(void) VectorOfSizePushVector(std::vector< cv::Size >* v, std::vector< cv::Size >* other);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfSizeCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfSizePush($vecV, $v[$i])
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
        $vecOther = _VectorOfSizeCreate()

        $iArrOtherSize = UBound($other)
        For $i = 0 To $iArrOtherSize - 1
            _VectorOfSizePush($vecOther, $other[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfSizePushVector", $bVDllType, $vecV, $bOtherDllType, $vecOther), "VectorOfSizePushVector", @error)

    If $bOtherIsArray Then
        _VectorOfSizeRelease($vecOther)
    EndIf

    If $bVIsArray Then
        _VectorOfSizeRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfSizePushVector

Func _VectorOfSizeClear($v)
    ; CVAPI(void) VectorOfSizeClear(std::vector< cv::Size >* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfSizeCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfSizePush($vecV, $v[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfSizeClear", $bVDllType, $vecV), "VectorOfSizeClear", @error)

    If $bVIsArray Then
        _VectorOfSizeRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfSizeClear

Func _VectorOfSizeRelease($v)
    ; CVAPI(void) VectorOfSizeRelease(std::vector< cv::Size >** v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfSizeCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfSizePush($vecV, $v[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfSizeRelease", $bVDllType, $vecV), "VectorOfSizeRelease", @error)

    If $bVIsArray Then
        _VectorOfSizeRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfSizeRelease

Func _VectorOfSizeCopyData($v, $data)
    ; CVAPI(void) VectorOfSizeCopyData(std::vector< cv::Size >* v, cv::Size* data);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfSizeCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfSizePush($vecV, $v[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfSizeCopyData", $bVDllType, $vecV, $bDataDllType, $data), "VectorOfSizeCopyData", @error)

    If $bVIsArray Then
        _VectorOfSizeRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfSizeCopyData

Func _VectorOfSizeGetStartAddress($v)
    ; CVAPI(cv::Size*) VectorOfSizeGetStartAddress(std::vector< cv::Size >* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfSizeCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfSizePush($vecV, $v[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfSizeGetStartAddress", $bVDllType, $vecV), "VectorOfSizeGetStartAddress", @error)

    If $bVIsArray Then
        _VectorOfSizeRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfSizeGetStartAddress

Func _VectorOfSizeGetEndAddress($v)
    ; CVAPI(void*) VectorOfSizeGetEndAddress(std::vector< cv::Size >* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfSizeCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfSizePush($vecV, $v[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfSizeGetEndAddress", $bVDllType, $vecV), "VectorOfSizeGetEndAddress", @error)

    If $bVIsArray Then
        _VectorOfSizeRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfSizeGetEndAddress

Func _VectorOfSizeGetItem($vec, $index, $element)
    ; CVAPI(void) VectorOfSizeGetItem(std::vector<  cv::Size >* vec, int index, cv::Size* element);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfSizeCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfSizePush($vecVec, $vec[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfSizeGetItem", $bVecDllType, $vecVec, "int", $index, $bElementDllType, $element), "VectorOfSizeGetItem", @error)

    If $bVecIsArray Then
        _VectorOfSizeRelease($vecVec)
    EndIf
EndFunc   ;==>_VectorOfSizeGetItem

Func _VectorOfSizeGetItemPtr($vec, $index, $element)
    ; CVAPI(void) VectorOfSizeGetItemPtr(std::vector<  cv::Size >* vec, int index, cv::Size** element);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfSizeCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfSizePush($vecVec, $vec[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfSizeGetItemPtr", $bVecDllType, $vecVec, "int", $index, $bElementDllType, $element), "VectorOfSizeGetItemPtr", @error)

    If $bVecIsArray Then
        _VectorOfSizeRelease($vecVec)
    EndIf
EndFunc   ;==>_VectorOfSizeGetItemPtr

Func _cveInputArrayFromVectorOfSize($vec)
    ; CVAPI(cv::_InputArray*) cveInputArrayFromVectorOfSize(std::vector< cv::Size >* vec);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfSizeCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfSizePush($vecVec, $vec[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveInputArrayFromVectorOfSize", $bVecDllType, $vecVec), "cveInputArrayFromVectorOfSize", @error)

    If $bVecIsArray Then
        _VectorOfSizeRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveInputArrayFromVectorOfSize

Func _cveOutputArrayFromVectorOfSize($vec)
    ; CVAPI(cv::_OutputArray*) cveOutputArrayFromVectorOfSize(std::vector< cv::Size >* vec);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfSizeCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfSizePush($vecVec, $vec[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveOutputArrayFromVectorOfSize", $bVecDllType, $vecVec), "cveOutputArrayFromVectorOfSize", @error)

    If $bVecIsArray Then
        _VectorOfSizeRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveOutputArrayFromVectorOfSize

Func _cveInputOutputArrayFromVectorOfSize($vec)
    ; CVAPI(cv::_InputOutputArray*) cveInputOutputArrayFromVectorOfSize(std::vector< cv::Size >* vec);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfSizeCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfSizePush($vecVec, $vec[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveInputOutputArrayFromVectorOfSize", $bVecDllType, $vecVec), "cveInputOutputArrayFromVectorOfSize", @error)

    If $bVecIsArray Then
        _VectorOfSizeRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveInputOutputArrayFromVectorOfSize

Func _VectorOfSizeSizeOfItemInBytes()
    ; CVAPI(int) VectorOfSizeSizeOfItemInBytes();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "VectorOfSizeSizeOfItemInBytes"), "VectorOfSizeSizeOfItemInBytes", @error)
EndFunc   ;==>_VectorOfSizeSizeOfItemInBytes