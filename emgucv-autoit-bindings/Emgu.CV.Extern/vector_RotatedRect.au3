#include-once
#include "..\CVEUtils.au3"

Func _VectorOfRotatedRectCreate()
    ; CVAPI(std::vector<cv::RotatedRect>*) VectorOfRotatedRectCreate();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfRotatedRectCreate"), "VectorOfRotatedRectCreate", @error)
EndFunc   ;==>_VectorOfRotatedRectCreate

Func _VectorOfRotatedRectCreateSize($size)
    ; CVAPI(std::vector<cv::RotatedRect>*) VectorOfRotatedRectCreateSize(int size);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfRotatedRectCreateSize", "int", $size), "VectorOfRotatedRectCreateSize", @error)
EndFunc   ;==>_VectorOfRotatedRectCreateSize

Func _VectorOfRotatedRectGetSize($v)
    ; CVAPI(int) VectorOfRotatedRectGetSize(std::vector<cv::RotatedRect>* v);

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

    Local $sVDllType
    If IsDllStruct($v) Then
        $sVDllType = "struct*"
    Else
        $sVDllType = "ptr"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "VectorOfRotatedRectGetSize", $sVDllType, $vecV), "VectorOfRotatedRectGetSize", @error)

    If $bVIsArray Then
        _VectorOfRotatedRectRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfRotatedRectGetSize

Func _VectorOfRotatedRectPush($v, $value)
    ; CVAPI(void) VectorOfRotatedRectPush(std::vector<cv::RotatedRect>* v, cv::RotatedRect* value);

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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfRotatedRectPush", $sVDllType, $vecV, $sValueDllType, $value), "VectorOfRotatedRectPush", @error)

    If $bVIsArray Then
        _VectorOfRotatedRectRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfRotatedRectPush

Func _VectorOfRotatedRectPushMulti($v, $values, $count)
    ; CVAPI(void) VectorOfRotatedRectPushMulti(std::vector<cv::RotatedRect>* v, cv::RotatedRect* values, int count);

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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfRotatedRectPushMulti", $sVDllType, $vecV, $sValuesDllType, $values, "int", $count), "VectorOfRotatedRectPushMulti", @error)

    If $bVIsArray Then
        _VectorOfRotatedRectRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfRotatedRectPushMulti

Func _VectorOfRotatedRectPushVector($v, $other)
    ; CVAPI(void) VectorOfRotatedRectPushVector(std::vector<cv::RotatedRect>* v, std::vector<cv::RotatedRect>* other);

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

    Local $sVDllType
    If IsDllStruct($v) Then
        $sVDllType = "struct*"
    Else
        $sVDllType = "ptr"
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

    Local $sOtherDllType
    If IsDllStruct($other) Then
        $sOtherDllType = "struct*"
    Else
        $sOtherDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfRotatedRectPushVector", $sVDllType, $vecV, $sOtherDllType, $vecOther), "VectorOfRotatedRectPushVector", @error)

    If $bOtherIsArray Then
        _VectorOfRotatedRectRelease($vecOther)
    EndIf

    If $bVIsArray Then
        _VectorOfRotatedRectRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfRotatedRectPushVector

Func _VectorOfRotatedRectClear($v)
    ; CVAPI(void) VectorOfRotatedRectClear(std::vector<cv::RotatedRect>* v);

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

    Local $sVDllType
    If IsDllStruct($v) Then
        $sVDllType = "struct*"
    Else
        $sVDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfRotatedRectClear", $sVDllType, $vecV), "VectorOfRotatedRectClear", @error)

    If $bVIsArray Then
        _VectorOfRotatedRectRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfRotatedRectClear

Func _VectorOfRotatedRectRelease($v)
    ; CVAPI(void) VectorOfRotatedRectRelease(std::vector<cv::RotatedRect>** v);

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

    Local $sVDllType
    If IsDllStruct($v) Then
        $sVDllType = "struct*"
    ElseIf $v == Null Then
        $sVDllType = "ptr"
    Else
        $sVDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfRotatedRectRelease", $sVDllType, $vecV), "VectorOfRotatedRectRelease", @error)

    If $bVIsArray Then
        _VectorOfRotatedRectRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfRotatedRectRelease

Func _VectorOfRotatedRectCopyData($v, $data)
    ; CVAPI(void) VectorOfRotatedRectCopyData(std::vector<cv::RotatedRect>* v, cv::RotatedRect* data);

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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfRotatedRectCopyData", $sVDllType, $vecV, $sDataDllType, $data), "VectorOfRotatedRectCopyData", @error)

    If $bVIsArray Then
        _VectorOfRotatedRectRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfRotatedRectCopyData

Func _VectorOfRotatedRectGetStartAddress($v)
    ; CVAPI(cv::RotatedRect*) VectorOfRotatedRectGetStartAddress(std::vector<cv::RotatedRect>* v);

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

    Local $sVDllType
    If IsDllStruct($v) Then
        $sVDllType = "struct*"
    Else
        $sVDllType = "ptr"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfRotatedRectGetStartAddress", $sVDllType, $vecV), "VectorOfRotatedRectGetStartAddress", @error)

    If $bVIsArray Then
        _VectorOfRotatedRectRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfRotatedRectGetStartAddress

Func _VectorOfRotatedRectGetEndAddress($v)
    ; CVAPI(void*) VectorOfRotatedRectGetEndAddress(std::vector<cv::RotatedRect>* v);

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

    Local $sVDllType
    If IsDllStruct($v) Then
        $sVDllType = "struct*"
    Else
        $sVDllType = "ptr"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfRotatedRectGetEndAddress", $sVDllType, $vecV), "VectorOfRotatedRectGetEndAddress", @error)

    If $bVIsArray Then
        _VectorOfRotatedRectRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfRotatedRectGetEndAddress

Func _VectorOfRotatedRectGetItem($vec, $index, $element)
    ; CVAPI(void) VectorOfRotatedRectGetItem(std::vector<cv::RotatedRect>* vec, int index, cv::RotatedRect* element);

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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfRotatedRectGetItem", $sVecDllType, $vecVec, "int", $index, $sElementDllType, $element), "VectorOfRotatedRectGetItem", @error)

    If $bVecIsArray Then
        _VectorOfRotatedRectRelease($vecVec)
    EndIf
EndFunc   ;==>_VectorOfRotatedRectGetItem

Func _VectorOfRotatedRectGetItemPtr($vec, $index, $element)
    ; CVAPI(void) VectorOfRotatedRectGetItemPtr(std::vector<cv::RotatedRect>* vec, int index, cv::RotatedRect** element);

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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfRotatedRectGetItemPtr", $sVecDllType, $vecVec, "int", $index, $sElementDllType, $element), "VectorOfRotatedRectGetItemPtr", @error)

    If $bVecIsArray Then
        _VectorOfRotatedRectRelease($vecVec)
    EndIf
EndFunc   ;==>_VectorOfRotatedRectGetItemPtr

Func _cveInputArrayFromVectorOfRotatedRect($vec)
    ; CVAPI(cv::_InputArray*) cveInputArrayFromVectorOfRotatedRect(std::vector<cv::RotatedRect>* vec);

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

    Local $sVecDllType
    If IsDllStruct($vec) Then
        $sVecDllType = "struct*"
    Else
        $sVecDllType = "ptr"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveInputArrayFromVectorOfRotatedRect", $sVecDllType, $vecVec), "cveInputArrayFromVectorOfRotatedRect", @error)

    If $bVecIsArray Then
        _VectorOfRotatedRectRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveInputArrayFromVectorOfRotatedRect

Func _cveOutputArrayFromVectorOfRotatedRect($vec)
    ; CVAPI(cv::_OutputArray*) cveOutputArrayFromVectorOfRotatedRect(std::vector<cv::RotatedRect>* vec);

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

    Local $sVecDllType
    If IsDllStruct($vec) Then
        $sVecDllType = "struct*"
    Else
        $sVecDllType = "ptr"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveOutputArrayFromVectorOfRotatedRect", $sVecDllType, $vecVec), "cveOutputArrayFromVectorOfRotatedRect", @error)

    If $bVecIsArray Then
        _VectorOfRotatedRectRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveOutputArrayFromVectorOfRotatedRect

Func _cveInputOutputArrayFromVectorOfRotatedRect($vec)
    ; CVAPI(cv::_InputOutputArray*) cveInputOutputArrayFromVectorOfRotatedRect(std::vector<cv::RotatedRect>* vec);

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

    Local $sVecDllType
    If IsDllStruct($vec) Then
        $sVecDllType = "struct*"
    Else
        $sVecDllType = "ptr"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveInputOutputArrayFromVectorOfRotatedRect", $sVecDllType, $vecVec), "cveInputOutputArrayFromVectorOfRotatedRect", @error)

    If $bVecIsArray Then
        _VectorOfRotatedRectRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveInputOutputArrayFromVectorOfRotatedRect

Func _VectorOfRotatedRectSizeOfItemInBytes()
    ; CVAPI(int) VectorOfRotatedRectSizeOfItemInBytes();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "VectorOfRotatedRectSizeOfItemInBytes"), "VectorOfRotatedRectSizeOfItemInBytes", @error)
EndFunc   ;==>_VectorOfRotatedRectSizeOfItemInBytes