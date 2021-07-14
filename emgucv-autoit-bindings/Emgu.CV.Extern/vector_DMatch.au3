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

Func _VectorOfDMatchGetSize(ByRef $v)
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

Func _VectorOfDMatchPush(ByRef $v, ByRef $value)
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

Func _VectorOfDMatchPushMulti(ByRef $v, ByRef $values, $count)
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

Func _VectorOfDMatchPushVector(ByRef $v, ByRef $other)
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

Func _VectorOfDMatchClear(ByRef $v)
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

Func _VectorOfDMatchRelease(ByRef $v)
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfDMatchRelease", "ptr*", $vecV), "VectorOfDMatchRelease", @error)

    If $bVIsArray Then
        _VectorOfDMatchRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfDMatchRelease

Func _VectorOfDMatchCopyData(ByRef $v, ByRef $data)
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

Func _VectorOfDMatchGetStartAddress(ByRef $v)
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

Func _VectorOfDMatchGetEndAddress(ByRef $v)
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

Func _VectorOfDMatchGetItem(ByRef $vec, $index, ByRef $element)
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

Func _VectorOfDMatchGetItemPtr(ByRef $vec, $index, ByRef $element)
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfDMatchGetItemPtr", "ptr", $vecVec, "int", $index, "ptr*", $element), "VectorOfDMatchGetItemPtr", @error)

    If $bVecIsArray Then
        _VectorOfDMatchRelease($vecVec)
    EndIf
EndFunc   ;==>_VectorOfDMatchGetItemPtr

Func _cveInputArrayFromVectorOfDMatch(ByRef $vec)
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

Func _cveOutputArrayFromVectorOfDMatch(ByRef $vec)
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

Func _cveInputOutputArrayFromVectorOfDMatch(ByRef $vec)
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