#include-once
#include "..\CVEUtils.au3"

Func _VectorOfERStatCreate()
    ; CVAPI(std::vector< cv::text::ERStat >*) VectorOfERStatCreate();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfERStatCreate"), "VectorOfERStatCreate", @error)
EndFunc   ;==>_VectorOfERStatCreate

Func _VectorOfERStatCreateSize($size)
    ; CVAPI(std::vector< cv::text::ERStat >*) VectorOfERStatCreateSize(int size);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfERStatCreateSize", "int", $size), "VectorOfERStatCreateSize", @error)
EndFunc   ;==>_VectorOfERStatCreateSize

Func _VectorOfERStatGetSize($v)
    ; CVAPI(int) VectorOfERStatGetSize(std::vector< cv::text::ERStat >* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfERStatCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfERStatPush($vecV, $v[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "VectorOfERStatGetSize", $bVDllType, $vecV), "VectorOfERStatGetSize", @error)

    If $bVIsArray Then
        _VectorOfERStatRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfERStatGetSize

Func _VectorOfERStatPush($v, $value)
    ; CVAPI(void) VectorOfERStatPush(std::vector< cv::text::ERStat >* v, cv::text::ERStat* value);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfERStatCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfERStatPush($vecV, $v[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfERStatPush", $bVDllType, $vecV, $bValueDllType, $value), "VectorOfERStatPush", @error)

    If $bVIsArray Then
        _VectorOfERStatRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfERStatPush

Func _VectorOfERStatPushMulti($v, $values, $count)
    ; CVAPI(void) VectorOfERStatPushMulti(std::vector< cv::text::ERStat >* v, cv::text::ERStat* values, int count);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfERStatCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfERStatPush($vecV, $v[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfERStatPushMulti", $bVDllType, $vecV, $bValuesDllType, $values, "int", $count), "VectorOfERStatPushMulti", @error)

    If $bVIsArray Then
        _VectorOfERStatRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfERStatPushMulti

Func _VectorOfERStatPushVector($v, $other)
    ; CVAPI(void) VectorOfERStatPushVector(std::vector< cv::text::ERStat >* v, std::vector< cv::text::ERStat >* other);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfERStatCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfERStatPush($vecV, $v[$i])
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
        $vecOther = _VectorOfERStatCreate()

        $iArrOtherSize = UBound($other)
        For $i = 0 To $iArrOtherSize - 1
            _VectorOfERStatPush($vecOther, $other[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfERStatPushVector", $bVDllType, $vecV, $bOtherDllType, $vecOther), "VectorOfERStatPushVector", @error)

    If $bOtherIsArray Then
        _VectorOfERStatRelease($vecOther)
    EndIf

    If $bVIsArray Then
        _VectorOfERStatRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfERStatPushVector

Func _VectorOfERStatClear($v)
    ; CVAPI(void) VectorOfERStatClear(std::vector< cv::text::ERStat >* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfERStatCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfERStatPush($vecV, $v[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfERStatClear", $bVDllType, $vecV), "VectorOfERStatClear", @error)

    If $bVIsArray Then
        _VectorOfERStatRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfERStatClear

Func _VectorOfERStatRelease($v)
    ; CVAPI(void) VectorOfERStatRelease(std::vector< cv::text::ERStat >** v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfERStatCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfERStatPush($vecV, $v[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfERStatRelease", $bVDllType, $vecV), "VectorOfERStatRelease", @error)

    If $bVIsArray Then
        _VectorOfERStatRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfERStatRelease

Func _VectorOfERStatCopyData($v, $data)
    ; CVAPI(void) VectorOfERStatCopyData(std::vector< cv::text::ERStat >* v, cv::text::ERStat* data);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfERStatCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfERStatPush($vecV, $v[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfERStatCopyData", $bVDllType, $vecV, $bDataDllType, $data), "VectorOfERStatCopyData", @error)

    If $bVIsArray Then
        _VectorOfERStatRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfERStatCopyData

Func _VectorOfERStatGetStartAddress($v)
    ; CVAPI(cv::text::ERStat*) VectorOfERStatGetStartAddress(std::vector< cv::text::ERStat >* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfERStatCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfERStatPush($vecV, $v[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfERStatGetStartAddress", $bVDllType, $vecV), "VectorOfERStatGetStartAddress", @error)

    If $bVIsArray Then
        _VectorOfERStatRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfERStatGetStartAddress

Func _VectorOfERStatGetEndAddress($v)
    ; CVAPI(void*) VectorOfERStatGetEndAddress(std::vector< cv::text::ERStat >* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfERStatCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfERStatPush($vecV, $v[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfERStatGetEndAddress", $bVDllType, $vecV), "VectorOfERStatGetEndAddress", @error)

    If $bVIsArray Then
        _VectorOfERStatRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfERStatGetEndAddress

Func _VectorOfERStatGetItem($vec, $index, $element)
    ; CVAPI(void) VectorOfERStatGetItem(std::vector<  cv::text::ERStat >* vec, int index, cv::text::ERStat* element);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfERStatCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfERStatPush($vecVec, $vec[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfERStatGetItem", $bVecDllType, $vecVec, "int", $index, $bElementDllType, $element), "VectorOfERStatGetItem", @error)

    If $bVecIsArray Then
        _VectorOfERStatRelease($vecVec)
    EndIf
EndFunc   ;==>_VectorOfERStatGetItem

Func _VectorOfERStatGetItemPtr($vec, $index, $element)
    ; CVAPI(void) VectorOfERStatGetItemPtr(std::vector<  cv::text::ERStat >* vec, int index, cv::text::ERStat** element);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfERStatCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfERStatPush($vecVec, $vec[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfERStatGetItemPtr", $bVecDllType, $vecVec, "int", $index, $bElementDllType, $element), "VectorOfERStatGetItemPtr", @error)

    If $bVecIsArray Then
        _VectorOfERStatRelease($vecVec)
    EndIf
EndFunc   ;==>_VectorOfERStatGetItemPtr

Func _cveInputArrayFromVectorOfERStat($vec)
    ; CVAPI(cv::_InputArray*) cveInputArrayFromVectorOfERStat(std::vector< cv::text::ERStat >* vec);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfERStatCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfERStatPush($vecVec, $vec[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveInputArrayFromVectorOfERStat", $bVecDllType, $vecVec), "cveInputArrayFromVectorOfERStat", @error)

    If $bVecIsArray Then
        _VectorOfERStatRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveInputArrayFromVectorOfERStat

Func _cveOutputArrayFromVectorOfERStat($vec)
    ; CVAPI(cv::_OutputArray*) cveOutputArrayFromVectorOfERStat(std::vector< cv::text::ERStat >* vec);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfERStatCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfERStatPush($vecVec, $vec[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveOutputArrayFromVectorOfERStat", $bVecDllType, $vecVec), "cveOutputArrayFromVectorOfERStat", @error)

    If $bVecIsArray Then
        _VectorOfERStatRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveOutputArrayFromVectorOfERStat

Func _cveInputOutputArrayFromVectorOfERStat($vec)
    ; CVAPI(cv::_InputOutputArray*) cveInputOutputArrayFromVectorOfERStat(std::vector< cv::text::ERStat >* vec);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfERStatCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfERStatPush($vecVec, $vec[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveInputOutputArrayFromVectorOfERStat", $bVecDllType, $vecVec), "cveInputOutputArrayFromVectorOfERStat", @error)

    If $bVecIsArray Then
        _VectorOfERStatRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveInputOutputArrayFromVectorOfERStat

Func _VectorOfERStatSizeOfItemInBytes()
    ; CVAPI(int) VectorOfERStatSizeOfItemInBytes();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "VectorOfERStatSizeOfItemInBytes"), "VectorOfERStatSizeOfItemInBytes", @error)
EndFunc   ;==>_VectorOfERStatSizeOfItemInBytes