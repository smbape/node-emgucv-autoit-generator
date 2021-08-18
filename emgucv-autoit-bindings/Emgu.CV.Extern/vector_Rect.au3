#include-once
#include "..\CVEUtils.au3"

Func _VectorOfRectCreate()
    ; CVAPI(std::vector<cv::Rect>*) VectorOfRectCreate();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfRectCreate"), "VectorOfRectCreate", @error)
EndFunc   ;==>_VectorOfRectCreate

Func _VectorOfRectCreateSize($size)
    ; CVAPI(std::vector<cv::Rect>*) VectorOfRectCreateSize(int size);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfRectCreateSize", "int", $size), "VectorOfRectCreateSize", @error)
EndFunc   ;==>_VectorOfRectCreateSize

Func _VectorOfRectGetSize($v)
    ; CVAPI(int) VectorOfRectGetSize(std::vector<cv::Rect>* v);

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

    Local $bVDllType
    If VarGetType($v) == "DLLStruct" Then
        $bVDllType = "struct*"
    Else
        $bVDllType = "ptr"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "VectorOfRectGetSize", $bVDllType, $vecV), "VectorOfRectGetSize", @error)

    If $bVIsArray Then
        _VectorOfRectRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfRectGetSize

Func _VectorOfRectPush($v, $value)
    ; CVAPI(void) VectorOfRectPush(std::vector<cv::Rect>* v, cv::Rect* value);

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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfRectPush", $bVDllType, $vecV, $bValueDllType, $value), "VectorOfRectPush", @error)

    If $bVIsArray Then
        _VectorOfRectRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfRectPush

Func _VectorOfRectPushMulti($v, $values, $count)
    ; CVAPI(void) VectorOfRectPushMulti(std::vector<cv::Rect>* v, cv::Rect* values, int count);

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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfRectPushMulti", $bVDllType, $vecV, $bValuesDllType, $values, "int", $count), "VectorOfRectPushMulti", @error)

    If $bVIsArray Then
        _VectorOfRectRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfRectPushMulti

Func _VectorOfRectPushVector($v, $other)
    ; CVAPI(void) VectorOfRectPushVector(std::vector<cv::Rect>* v, std::vector<cv::Rect>* other);

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

    Local $bVDllType
    If VarGetType($v) == "DLLStruct" Then
        $bVDllType = "struct*"
    Else
        $bVDllType = "ptr"
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

    Local $bOtherDllType
    If VarGetType($other) == "DLLStruct" Then
        $bOtherDllType = "struct*"
    Else
        $bOtherDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfRectPushVector", $bVDllType, $vecV, $bOtherDllType, $vecOther), "VectorOfRectPushVector", @error)

    If $bOtherIsArray Then
        _VectorOfRectRelease($vecOther)
    EndIf

    If $bVIsArray Then
        _VectorOfRectRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfRectPushVector

Func _VectorOfRectClear($v)
    ; CVAPI(void) VectorOfRectClear(std::vector<cv::Rect>* v);

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

    Local $bVDllType
    If VarGetType($v) == "DLLStruct" Then
        $bVDllType = "struct*"
    Else
        $bVDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfRectClear", $bVDllType, $vecV), "VectorOfRectClear", @error)

    If $bVIsArray Then
        _VectorOfRectRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfRectClear

Func _VectorOfRectRelease($v)
    ; CVAPI(void) VectorOfRectRelease(std::vector<cv::Rect>** v);

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

    Local $bVDllType
    If VarGetType($v) == "DLLStruct" Then
        $bVDllType = "struct*"
    Else
        $bVDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfRectRelease", $bVDllType, $vecV), "VectorOfRectRelease", @error)

    If $bVIsArray Then
        _VectorOfRectRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfRectRelease

Func _VectorOfRectCopyData($v, $data)
    ; CVAPI(void) VectorOfRectCopyData(std::vector<cv::Rect>* v, cv::Rect* data);

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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfRectCopyData", $bVDllType, $vecV, $bDataDllType, $data), "VectorOfRectCopyData", @error)

    If $bVIsArray Then
        _VectorOfRectRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfRectCopyData

Func _VectorOfRectGetStartAddress($v)
    ; CVAPI(cv::Rect*) VectorOfRectGetStartAddress(std::vector<cv::Rect>* v);

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

    Local $bVDllType
    If VarGetType($v) == "DLLStruct" Then
        $bVDllType = "struct*"
    Else
        $bVDllType = "ptr"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfRectGetStartAddress", $bVDllType, $vecV), "VectorOfRectGetStartAddress", @error)

    If $bVIsArray Then
        _VectorOfRectRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfRectGetStartAddress

Func _VectorOfRectGetEndAddress($v)
    ; CVAPI(void*) VectorOfRectGetEndAddress(std::vector<cv::Rect>* v);

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

    Local $bVDllType
    If VarGetType($v) == "DLLStruct" Then
        $bVDllType = "struct*"
    Else
        $bVDllType = "ptr"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfRectGetEndAddress", $bVDllType, $vecV), "VectorOfRectGetEndAddress", @error)

    If $bVIsArray Then
        _VectorOfRectRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfRectGetEndAddress

Func _VectorOfRectGetItem($vec, $index, $element)
    ; CVAPI(void) VectorOfRectGetItem(std::vector<cv::Rect>* vec, int index, cv::Rect* element);

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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfRectGetItem", $bVecDllType, $vecVec, "int", $index, $bElementDllType, $element), "VectorOfRectGetItem", @error)

    If $bVecIsArray Then
        _VectorOfRectRelease($vecVec)
    EndIf
EndFunc   ;==>_VectorOfRectGetItem

Func _VectorOfRectGetItemPtr($vec, $index, $element)
    ; CVAPI(void) VectorOfRectGetItemPtr(std::vector<cv::Rect>* vec, int index, cv::Rect** element);

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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfRectGetItemPtr", $bVecDllType, $vecVec, "int", $index, $bElementDllType, $element), "VectorOfRectGetItemPtr", @error)

    If $bVecIsArray Then
        _VectorOfRectRelease($vecVec)
    EndIf
EndFunc   ;==>_VectorOfRectGetItemPtr

Func _cveInputArrayFromVectorOfRect($vec)
    ; CVAPI(cv::_InputArray*) cveInputArrayFromVectorOfRect(std::vector<cv::Rect>* vec);

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

    Local $bVecDllType
    If VarGetType($vec) == "DLLStruct" Then
        $bVecDllType = "struct*"
    Else
        $bVecDllType = "ptr"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveInputArrayFromVectorOfRect", $bVecDllType, $vecVec), "cveInputArrayFromVectorOfRect", @error)

    If $bVecIsArray Then
        _VectorOfRectRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveInputArrayFromVectorOfRect

Func _cveOutputArrayFromVectorOfRect($vec)
    ; CVAPI(cv::_OutputArray*) cveOutputArrayFromVectorOfRect(std::vector<cv::Rect>* vec);

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

    Local $bVecDllType
    If VarGetType($vec) == "DLLStruct" Then
        $bVecDllType = "struct*"
    Else
        $bVecDllType = "ptr"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveOutputArrayFromVectorOfRect", $bVecDllType, $vecVec), "cveOutputArrayFromVectorOfRect", @error)

    If $bVecIsArray Then
        _VectorOfRectRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveOutputArrayFromVectorOfRect

Func _cveInputOutputArrayFromVectorOfRect($vec)
    ; CVAPI(cv::_InputOutputArray*) cveInputOutputArrayFromVectorOfRect(std::vector<cv::Rect>* vec);

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

    Local $bVecDllType
    If VarGetType($vec) == "DLLStruct" Then
        $bVecDllType = "struct*"
    Else
        $bVecDllType = "ptr"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveInputOutputArrayFromVectorOfRect", $bVecDllType, $vecVec), "cveInputOutputArrayFromVectorOfRect", @error)

    If $bVecIsArray Then
        _VectorOfRectRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveInputOutputArrayFromVectorOfRect

Func _VectorOfRectSizeOfItemInBytes()
    ; CVAPI(int) VectorOfRectSizeOfItemInBytes();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "VectorOfRectSizeOfItemInBytes"), "VectorOfRectSizeOfItemInBytes", @error)
EndFunc   ;==>_VectorOfRectSizeOfItemInBytes