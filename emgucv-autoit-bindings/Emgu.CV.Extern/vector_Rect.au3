#include-once
#include "..\CVEUtils.au3"

Func _VectorOfRectCreate()
    ; CVAPI(std::vector< cv::Rect >*) VectorOfRectCreate();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfRectCreate"), "VectorOfRectCreate", @error)
EndFunc   ;==>_VectorOfRectCreate

Func _VectorOfRectCreateSize($size)
    ; CVAPI(std::vector< cv::Rect >*) VectorOfRectCreateSize(int size);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfRectCreateSize", "int", $size), "VectorOfRectCreateSize", @error)
EndFunc   ;==>_VectorOfRectCreateSize

Func _VectorOfRectGetSize(ByRef $v)
    ; CVAPI(int) VectorOfRectGetSize(std::vector< cv::Rect >* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfRectCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfRectPush($vecV, $v[$i])
        Next
    Else
        $vecV = $v
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "VectorOfRectGetSize", "ptr", $vecV), "VectorOfRectGetSize", @error)

    If $bVIsArray Then
        _VectorOfRectRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfRectGetSize

Func _VectorOfRectPush(ByRef $v, ByRef $value)
    ; CVAPI(void) VectorOfRectPush(std::vector< cv::Rect >* v, cv::Rect* value);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfRectCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfRectPush($vecV, $v[$i])
        Next
    Else
        $vecV = $v
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfRectPush", "ptr", $vecV, "ptr", $value), "VectorOfRectPush", @error)

    If $bVIsArray Then
        _VectorOfRectRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfRectPush

Func _VectorOfRectPushMulti(ByRef $v, ByRef $values, $count)
    ; CVAPI(void) VectorOfRectPushMulti(std::vector< cv::Rect >* v, cv::Rect* values, int count);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfRectCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfRectPush($vecV, $v[$i])
        Next
    Else
        $vecV = $v
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfRectPushMulti", "ptr", $vecV, "ptr", $values, "int", $count), "VectorOfRectPushMulti", @error)

    If $bVIsArray Then
        _VectorOfRectRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfRectPushMulti

Func _VectorOfRectPushVector(ByRef $v, ByRef $other)
    ; CVAPI(void) VectorOfRectPushVector(std::vector< cv::Rect >* v, std::vector< cv::Rect >* other);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfRectCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfRectPush($vecV, $v[$i])
        Next
    Else
        $vecV = $v
    EndIf

    Local $vecOther, $iArrOtherSize
    Local $bOtherIsArray = VarGetType($other) == "Array"

    If $bOtherIsArray Then
        $vecOther = _VectorOfRectCreate()

        $iArrOtherSize = UBound($other)
        For $i = 0 To $iArrOtherSize - 1
            _VectorOfRectPush($vecOther, $other[$i])
        Next
    Else
        $vecOther = $other
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfRectPushVector", "ptr", $vecV, "ptr", $vecOther), "VectorOfRectPushVector", @error)

    If $bOtherIsArray Then
        _VectorOfRectRelease($vecOther)
    EndIf

    If $bVIsArray Then
        _VectorOfRectRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfRectPushVector

Func _VectorOfRectClear(ByRef $v)
    ; CVAPI(void) VectorOfRectClear(std::vector< cv::Rect >* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfRectCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfRectPush($vecV, $v[$i])
        Next
    Else
        $vecV = $v
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfRectClear", "ptr", $vecV), "VectorOfRectClear", @error)

    If $bVIsArray Then
        _VectorOfRectRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfRectClear

Func _VectorOfRectRelease(ByRef $v)
    ; CVAPI(void) VectorOfRectRelease(std::vector< cv::Rect >** v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfRectCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfRectPush($vecV, $v[$i])
        Next
    Else
        $vecV = $v
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfRectRelease", "ptr*", $vecV), "VectorOfRectRelease", @error)

    If $bVIsArray Then
        _VectorOfRectRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfRectRelease

Func _VectorOfRectCopyData(ByRef $v, ByRef $data)
    ; CVAPI(void) VectorOfRectCopyData(std::vector< cv::Rect >* v, cv::Rect* data);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfRectCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfRectPush($vecV, $v[$i])
        Next
    Else
        $vecV = $v
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfRectCopyData", "ptr", $vecV, "ptr", $data), "VectorOfRectCopyData", @error)

    If $bVIsArray Then
        _VectorOfRectRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfRectCopyData

Func _VectorOfRectGetStartAddress(ByRef $v)
    ; CVAPI(cv::Rect*) VectorOfRectGetStartAddress(std::vector< cv::Rect >* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfRectCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfRectPush($vecV, $v[$i])
        Next
    Else
        $vecV = $v
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfRectGetStartAddress", "ptr", $vecV), "VectorOfRectGetStartAddress", @error)

    If $bVIsArray Then
        _VectorOfRectRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfRectGetStartAddress

Func _VectorOfRectGetEndAddress(ByRef $v)
    ; CVAPI(void*) VectorOfRectGetEndAddress(std::vector< cv::Rect >* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfRectCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfRectPush($vecV, $v[$i])
        Next
    Else
        $vecV = $v
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfRectGetEndAddress", "ptr", $vecV), "VectorOfRectGetEndAddress", @error)

    If $bVIsArray Then
        _VectorOfRectRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfRectGetEndAddress

Func _VectorOfRectGetItem(ByRef $vec, $index, ByRef $element)
    ; CVAPI(void) VectorOfRectGetItem(std::vector<  cv::Rect >* vec, int index, cv::Rect* element);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfRectCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfRectPush($vecVec, $vec[$i])
        Next
    Else
        $vecVec = $vec
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfRectGetItem", "ptr", $vecVec, "int", $index, "ptr", $element), "VectorOfRectGetItem", @error)

    If $bVecIsArray Then
        _VectorOfRectRelease($vecVec)
    EndIf
EndFunc   ;==>_VectorOfRectGetItem

Func _VectorOfRectGetItemPtr(ByRef $vec, $index, ByRef $element)
    ; CVAPI(void) VectorOfRectGetItemPtr(std::vector<  cv::Rect >* vec, int index, cv::Rect** element);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfRectCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfRectPush($vecVec, $vec[$i])
        Next
    Else
        $vecVec = $vec
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfRectGetItemPtr", "ptr", $vecVec, "int", $index, "ptr*", $element), "VectorOfRectGetItemPtr", @error)

    If $bVecIsArray Then
        _VectorOfRectRelease($vecVec)
    EndIf
EndFunc   ;==>_VectorOfRectGetItemPtr

Func _cveInputArrayFromVectorOfRect(ByRef $vec)
    ; CVAPI(cv::_InputArray*) cveInputArrayFromVectorOfRect(std::vector< cv::Rect >* vec);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfRectCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfRectPush($vecVec, $vec[$i])
        Next
    Else
        $vecVec = $vec
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveInputArrayFromVectorOfRect", "ptr", $vecVec), "cveInputArrayFromVectorOfRect", @error)

    If $bVecIsArray Then
        _VectorOfRectRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveInputArrayFromVectorOfRect

Func _cveOutputArrayFromVectorOfRect(ByRef $vec)
    ; CVAPI(cv::_OutputArray*) cveOutputArrayFromVectorOfRect(std::vector< cv::Rect >* vec);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfRectCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfRectPush($vecVec, $vec[$i])
        Next
    Else
        $vecVec = $vec
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveOutputArrayFromVectorOfRect", "ptr", $vecVec), "cveOutputArrayFromVectorOfRect", @error)

    If $bVecIsArray Then
        _VectorOfRectRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveOutputArrayFromVectorOfRect

Func _cveInputOutputArrayFromVectorOfRect(ByRef $vec)
    ; CVAPI(cv::_InputOutputArray*) cveInputOutputArrayFromVectorOfRect(std::vector< cv::Rect >* vec);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfRectCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfRectPush($vecVec, $vec[$i])
        Next
    Else
        $vecVec = $vec
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveInputOutputArrayFromVectorOfRect", "ptr", $vecVec), "cveInputOutputArrayFromVectorOfRect", @error)

    If $bVecIsArray Then
        _VectorOfRectRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveInputOutputArrayFromVectorOfRect

Func _VectorOfRectSizeOfItemInBytes()
    ; CVAPI(int) VectorOfRectSizeOfItemInBytes();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "VectorOfRectSizeOfItemInBytes"), "VectorOfRectSizeOfItemInBytes", @error)
EndFunc   ;==>_VectorOfRectSizeOfItemInBytes