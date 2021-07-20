#include-once
#include "..\CVEUtils.au3"

Func _VectorOfDMatchCreate()
    ; CVAPI(std::vector< cv::DMatch >*) VectorOfDMatchCreate();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfDMatchCreate"), "VectorOfDMatchCreate", @error)
EndFunc   ;==>_VectorOfDMatchCreate

Func _VectorOfDMatchCreateSize($size)
    ; CVAPI(std::vector< cv::DMatch >*) VectorOfDMatchCreateSize(int size);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfDMatchCreateSize", "int", $size), "VectorOfDMatchCreateSize", @error)
EndFunc   ;==>_VectorOfDMatchCreateSize

Func _VectorOfDMatchGetSize($v)
    ; CVAPI(int) VectorOfDMatchGetSize(std::vector< cv::DMatch >* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfDMatchCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfDMatchPush($vecV, $v[$i])
        Next
    Else
        $vecV = $v
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "VectorOfDMatchGetSize", "ptr", $vecV), "VectorOfDMatchGetSize", @error)

    If $bVIsArray Then
        _VectorOfDMatchRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfDMatchGetSize

Func _VectorOfDMatchPush($v, $value)
    ; CVAPI(void) VectorOfDMatchPush(std::vector< cv::DMatch >* v, cv::DMatch* value);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfDMatchCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfDMatchPush($vecV, $v[$i])
        Next
    Else
        $vecV = $v
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfDMatchPush", "ptr", $vecV, "ptr", $value), "VectorOfDMatchPush", @error)

    If $bVIsArray Then
        _VectorOfDMatchRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfDMatchPush

Func _VectorOfDMatchPushMulti($v, $values, $count)
    ; CVAPI(void) VectorOfDMatchPushMulti(std::vector< cv::DMatch >* v, cv::DMatch* values, int count);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfDMatchCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfDMatchPush($vecV, $v[$i])
        Next
    Else
        $vecV = $v
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfDMatchPushMulti", "ptr", $vecV, "ptr", $values, "int", $count), "VectorOfDMatchPushMulti", @error)

    If $bVIsArray Then
        _VectorOfDMatchRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfDMatchPushMulti

Func _VectorOfDMatchPushVector($v, $other)
    ; CVAPI(void) VectorOfDMatchPushVector(std::vector< cv::DMatch >* v, std::vector< cv::DMatch >* other);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfDMatchCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfDMatchPush($vecV, $v[$i])
        Next
    Else
        $vecV = $v
    EndIf

    Local $vecOther, $iArrOtherSize
    Local $bOtherIsArray = VarGetType($other) == "Array"

    If $bOtherIsArray Then
        $vecOther = _VectorOfDMatchCreate()

        $iArrOtherSize = UBound($other)
        For $i = 0 To $iArrOtherSize - 1
            _VectorOfDMatchPush($vecOther, $other[$i])
        Next
    Else
        $vecOther = $other
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfDMatchPushVector", "ptr", $vecV, "ptr", $vecOther), "VectorOfDMatchPushVector", @error)

    If $bOtherIsArray Then
        _VectorOfDMatchRelease($vecOther)
    EndIf

    If $bVIsArray Then
        _VectorOfDMatchRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfDMatchPushVector

Func _VectorOfDMatchClear($v)
    ; CVAPI(void) VectorOfDMatchClear(std::vector< cv::DMatch >* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfDMatchCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfDMatchPush($vecV, $v[$i])
        Next
    Else
        $vecV = $v
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfDMatchClear", "ptr", $vecV), "VectorOfDMatchClear", @error)

    If $bVIsArray Then
        _VectorOfDMatchRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfDMatchClear

Func _VectorOfDMatchRelease($v)
    ; CVAPI(void) VectorOfDMatchRelease(std::vector< cv::DMatch >** v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfDMatchCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfDMatchPush($vecV, $v[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfDMatchRelease", $bVDllType, $vecV), "VectorOfDMatchRelease", @error)

    If $bVIsArray Then
        _VectorOfDMatchRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfDMatchRelease

Func _VectorOfDMatchCopyData($v, $data)
    ; CVAPI(void) VectorOfDMatchCopyData(std::vector< cv::DMatch >* v, cv::DMatch* data);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfDMatchCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfDMatchPush($vecV, $v[$i])
        Next
    Else
        $vecV = $v
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfDMatchCopyData", "ptr", $vecV, "ptr", $data), "VectorOfDMatchCopyData", @error)

    If $bVIsArray Then
        _VectorOfDMatchRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfDMatchCopyData

Func _VectorOfDMatchGetStartAddress($v)
    ; CVAPI(cv::DMatch*) VectorOfDMatchGetStartAddress(std::vector< cv::DMatch >* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfDMatchCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfDMatchPush($vecV, $v[$i])
        Next
    Else
        $vecV = $v
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfDMatchGetStartAddress", "ptr", $vecV), "VectorOfDMatchGetStartAddress", @error)

    If $bVIsArray Then
        _VectorOfDMatchRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfDMatchGetStartAddress

Func _VectorOfDMatchGetEndAddress($v)
    ; CVAPI(void*) VectorOfDMatchGetEndAddress(std::vector< cv::DMatch >* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfDMatchCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfDMatchPush($vecV, $v[$i])
        Next
    Else
        $vecV = $v
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfDMatchGetEndAddress", "ptr", $vecV), "VectorOfDMatchGetEndAddress", @error)

    If $bVIsArray Then
        _VectorOfDMatchRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfDMatchGetEndAddress

Func _VectorOfDMatchGetItem($vec, $index, $element)
    ; CVAPI(void) VectorOfDMatchGetItem(std::vector<  cv::DMatch >* vec, int index, cv::DMatch* element);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfDMatchCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfDMatchPush($vecVec, $vec[$i])
        Next
    Else
        $vecVec = $vec
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfDMatchGetItem", "ptr", $vecVec, "int", $index, "ptr", $element), "VectorOfDMatchGetItem", @error)

    If $bVecIsArray Then
        _VectorOfDMatchRelease($vecVec)
    EndIf
EndFunc   ;==>_VectorOfDMatchGetItem

Func _VectorOfDMatchGetItemPtr($vec, $index, $element)
    ; CVAPI(void) VectorOfDMatchGetItemPtr(std::vector<  cv::DMatch >* vec, int index, cv::DMatch** element);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfDMatchCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfDMatchPush($vecVec, $vec[$i])
        Next
    Else
        $vecVec = $vec
    EndIf

    Local $bElementDllType
    If VarGetType($element) == "DLLStruct" Then
        $bElementDllType = "struct*"
    Else
        $bElementDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfDMatchGetItemPtr", "ptr", $vecVec, "int", $index, $bElementDllType, $element), "VectorOfDMatchGetItemPtr", @error)

    If $bVecIsArray Then
        _VectorOfDMatchRelease($vecVec)
    EndIf
EndFunc   ;==>_VectorOfDMatchGetItemPtr

Func _cveInputArrayFromVectorOfDMatch($vec)
    ; CVAPI(cv::_InputArray*) cveInputArrayFromVectorOfDMatch(std::vector< cv::DMatch >* vec);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfDMatchCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfDMatchPush($vecVec, $vec[$i])
        Next
    Else
        $vecVec = $vec
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveInputArrayFromVectorOfDMatch", "ptr", $vecVec), "cveInputArrayFromVectorOfDMatch", @error)

    If $bVecIsArray Then
        _VectorOfDMatchRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveInputArrayFromVectorOfDMatch

Func _cveOutputArrayFromVectorOfDMatch($vec)
    ; CVAPI(cv::_OutputArray*) cveOutputArrayFromVectorOfDMatch(std::vector< cv::DMatch >* vec);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfDMatchCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfDMatchPush($vecVec, $vec[$i])
        Next
    Else
        $vecVec = $vec
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveOutputArrayFromVectorOfDMatch", "ptr", $vecVec), "cveOutputArrayFromVectorOfDMatch", @error)

    If $bVecIsArray Then
        _VectorOfDMatchRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveOutputArrayFromVectorOfDMatch

Func _cveInputOutputArrayFromVectorOfDMatch($vec)
    ; CVAPI(cv::_InputOutputArray*) cveInputOutputArrayFromVectorOfDMatch(std::vector< cv::DMatch >* vec);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfDMatchCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfDMatchPush($vecVec, $vec[$i])
        Next
    Else
        $vecVec = $vec
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveInputOutputArrayFromVectorOfDMatch", "ptr", $vecVec), "cveInputOutputArrayFromVectorOfDMatch", @error)

    If $bVecIsArray Then
        _VectorOfDMatchRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveInputOutputArrayFromVectorOfDMatch

Func _VectorOfDMatchSizeOfItemInBytes()
    ; CVAPI(int) VectorOfDMatchSizeOfItemInBytes();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "VectorOfDMatchSizeOfItemInBytes"), "VectorOfDMatchSizeOfItemInBytes", @error)
EndFunc   ;==>_VectorOfDMatchSizeOfItemInBytes