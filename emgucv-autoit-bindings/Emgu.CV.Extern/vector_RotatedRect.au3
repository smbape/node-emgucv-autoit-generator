#include-once
#include <..\CVEUtils.au3>

Func _VectorOfRotatedRectCreate()
    ; CVAPI(std::vector< cv::RotatedRect >*) VectorOfRotatedRectCreate();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfRotatedRectCreate"), "VectorOfRotatedRectCreate", @error)
EndFunc   ;==>_VectorOfRotatedRectCreate

Func _VectorOfRotatedRectCreateSize($size)
    ; CVAPI(std::vector< cv::RotatedRect >*) VectorOfRotatedRectCreateSize(int size);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfRotatedRectCreateSize", "int", $size), "VectorOfRotatedRectCreateSize", @error)
EndFunc   ;==>_VectorOfRotatedRectCreateSize

Func _VectorOfRotatedRectGetSize(ByRef $v)
    ; CVAPI(int) VectorOfRotatedRectGetSize(std::vector< cv::RotatedRect >* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfRotatedRectCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfRotatedRectPush($vecV, $v[$i])
        Next
    Else
        $vecV = $v
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "VectorOfRotatedRectGetSize", "ptr", $vecV), "VectorOfRotatedRectGetSize", @error)

    If $bVIsArray Then
        _VectorOfRotatedRectRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfRotatedRectGetSize

Func _VectorOfRotatedRectPush(ByRef $v, ByRef $value)
    ; CVAPI(void) VectorOfRotatedRectPush(std::vector< cv::RotatedRect >* v, cv::RotatedRect* value);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfRotatedRectCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfRotatedRectPush($vecV, $v[$i])
        Next
    Else
        $vecV = $v
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfRotatedRectPush", "ptr", $vecV, "ptr", $value), "VectorOfRotatedRectPush", @error)

    If $bVIsArray Then
        _VectorOfRotatedRectRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfRotatedRectPush

Func _VectorOfRotatedRectPushMulti(ByRef $v, ByRef $values, $count)
    ; CVAPI(void) VectorOfRotatedRectPushMulti(std::vector< cv::RotatedRect >* v, cv::RotatedRect* values, int count);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfRotatedRectCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfRotatedRectPush($vecV, $v[$i])
        Next
    Else
        $vecV = $v
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfRotatedRectPushMulti", "ptr", $vecV, "ptr", $values, "int", $count), "VectorOfRotatedRectPushMulti", @error)

    If $bVIsArray Then
        _VectorOfRotatedRectRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfRotatedRectPushMulti

Func _VectorOfRotatedRectPushVector(ByRef $v, ByRef $other)
    ; CVAPI(void) VectorOfRotatedRectPushVector(std::vector< cv::RotatedRect >* v, std::vector< cv::RotatedRect >* other);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfRotatedRectCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfRotatedRectPush($vecV, $v[$i])
        Next
    Else
        $vecV = $v
    EndIf

    Local $vecOther, $iArrOtherSize
    Local $bOtherIsArray = VarGetType($other) == "Array"

    If $bOtherIsArray Then
        $vecOther = _VectorOfRotatedRectCreate()

        $iArrOtherSize = UBound($other)
        For $i = 0 To $iArrOtherSize - 1
            _VectorOfRotatedRectPush($vecOther, $other[$i])
        Next
    Else
        $vecOther = $other
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfRotatedRectPushVector", "ptr", $vecV, "ptr", $vecOther), "VectorOfRotatedRectPushVector", @error)

    If $bOtherIsArray Then
        _VectorOfRotatedRectRelease($vecOther)
    EndIf

    If $bVIsArray Then
        _VectorOfRotatedRectRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfRotatedRectPushVector

Func _VectorOfRotatedRectClear(ByRef $v)
    ; CVAPI(void) VectorOfRotatedRectClear(std::vector< cv::RotatedRect >* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfRotatedRectCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfRotatedRectPush($vecV, $v[$i])
        Next
    Else
        $vecV = $v
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfRotatedRectClear", "ptr", $vecV), "VectorOfRotatedRectClear", @error)

    If $bVIsArray Then
        _VectorOfRotatedRectRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfRotatedRectClear

Func _VectorOfRotatedRectRelease(ByRef $v)
    ; CVAPI(void) VectorOfRotatedRectRelease(std::vector< cv::RotatedRect >** v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfRotatedRectCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfRotatedRectPush($vecV, $v[$i])
        Next
    Else
        $vecV = $v
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfRotatedRectRelease", "ptr*", $vecV), "VectorOfRotatedRectRelease", @error)

    If $bVIsArray Then
        _VectorOfRotatedRectRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfRotatedRectRelease

Func _VectorOfRotatedRectCopyData(ByRef $v, ByRef $data)
    ; CVAPI(void) VectorOfRotatedRectCopyData(std::vector< cv::RotatedRect >* v, cv::RotatedRect* data);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfRotatedRectCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfRotatedRectPush($vecV, $v[$i])
        Next
    Else
        $vecV = $v
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfRotatedRectCopyData", "ptr", $vecV, "ptr", $data), "VectorOfRotatedRectCopyData", @error)

    If $bVIsArray Then
        _VectorOfRotatedRectRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfRotatedRectCopyData

Func _VectorOfRotatedRectGetStartAddress(ByRef $v)
    ; CVAPI(cv::RotatedRect*) VectorOfRotatedRectGetStartAddress(std::vector< cv::RotatedRect >* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfRotatedRectCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfRotatedRectPush($vecV, $v[$i])
        Next
    Else
        $vecV = $v
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfRotatedRectGetStartAddress", "ptr", $vecV), "VectorOfRotatedRectGetStartAddress", @error)

    If $bVIsArray Then
        _VectorOfRotatedRectRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfRotatedRectGetStartAddress

Func _VectorOfRotatedRectGetEndAddress(ByRef $v)
    ; CVAPI(void*) VectorOfRotatedRectGetEndAddress(std::vector< cv::RotatedRect >* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfRotatedRectCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfRotatedRectPush($vecV, $v[$i])
        Next
    Else
        $vecV = $v
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfRotatedRectGetEndAddress", "ptr", $vecV), "VectorOfRotatedRectGetEndAddress", @error)

    If $bVIsArray Then
        _VectorOfRotatedRectRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfRotatedRectGetEndAddress

Func _VectorOfRotatedRectGetItem(ByRef $vec, $index, ByRef $element)
    ; CVAPI(void) VectorOfRotatedRectGetItem(std::vector<  cv::RotatedRect >* vec, int index, cv::RotatedRect* element);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfRotatedRectCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfRotatedRectPush($vecVec, $vec[$i])
        Next
    Else
        $vecVec = $vec
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfRotatedRectGetItem", "ptr", $vecVec, "int", $index, "ptr", $element), "VectorOfRotatedRectGetItem", @error)

    If $bVecIsArray Then
        _VectorOfRotatedRectRelease($vecVec)
    EndIf
EndFunc   ;==>_VectorOfRotatedRectGetItem

Func _VectorOfRotatedRectGetItemPtr(ByRef $vec, $index, ByRef $element)
    ; CVAPI(void) VectorOfRotatedRectGetItemPtr(std::vector<  cv::RotatedRect >* vec, int index, cv::RotatedRect** element);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfRotatedRectCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfRotatedRectPush($vecVec, $vec[$i])
        Next
    Else
        $vecVec = $vec
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfRotatedRectGetItemPtr", "ptr", $vecVec, "int", $index, "ptr*", $element), "VectorOfRotatedRectGetItemPtr", @error)

    If $bVecIsArray Then
        _VectorOfRotatedRectRelease($vecVec)
    EndIf
EndFunc   ;==>_VectorOfRotatedRectGetItemPtr

Func _cveInputArrayFromVectorOfRotatedRect(ByRef $vec)
    ; CVAPI(cv::_InputArray*) cveInputArrayFromVectorOfRotatedRect(std::vector< cv::RotatedRect >* vec);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfRotatedRectCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfRotatedRectPush($vecVec, $vec[$i])
        Next
    Else
        $vecVec = $vec
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveInputArrayFromVectorOfRotatedRect", "ptr", $vecVec), "cveInputArrayFromVectorOfRotatedRect", @error)

    If $bVecIsArray Then
        _VectorOfRotatedRectRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveInputArrayFromVectorOfRotatedRect

Func _cveOutputArrayFromVectorOfRotatedRect(ByRef $vec)
    ; CVAPI(cv::_OutputArray*) cveOutputArrayFromVectorOfRotatedRect(std::vector< cv::RotatedRect >* vec);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfRotatedRectCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfRotatedRectPush($vecVec, $vec[$i])
        Next
    Else
        $vecVec = $vec
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveOutputArrayFromVectorOfRotatedRect", "ptr", $vecVec), "cveOutputArrayFromVectorOfRotatedRect", @error)

    If $bVecIsArray Then
        _VectorOfRotatedRectRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveOutputArrayFromVectorOfRotatedRect

Func _cveInputOutputArrayFromVectorOfRotatedRect(ByRef $vec)
    ; CVAPI(cv::_InputOutputArray*) cveInputOutputArrayFromVectorOfRotatedRect(std::vector< cv::RotatedRect >* vec);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfRotatedRectCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfRotatedRectPush($vecVec, $vec[$i])
        Next
    Else
        $vecVec = $vec
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveInputOutputArrayFromVectorOfRotatedRect", "ptr", $vecVec), "cveInputOutputArrayFromVectorOfRotatedRect", @error)

    If $bVecIsArray Then
        _VectorOfRotatedRectRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveInputOutputArrayFromVectorOfRotatedRect

Func _VectorOfRotatedRectSizeOfItemInBytes()
    ; CVAPI(int) VectorOfRotatedRectSizeOfItemInBytes();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "VectorOfRotatedRectSizeOfItemInBytes"), "VectorOfRotatedRectSizeOfItemInBytes", @error)
EndFunc   ;==>_VectorOfRotatedRectSizeOfItemInBytes