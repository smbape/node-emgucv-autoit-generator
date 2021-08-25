#include-once
#include "..\CVEUtils.au3"

Func _VectorOfVectorOfRectCreate()
    ; CVAPI(std::vector<std::vector<cv::Rect>>*) VectorOfVectorOfRectCreate();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfVectorOfRectCreate"), "VectorOfVectorOfRectCreate", @error)
EndFunc   ;==>_VectorOfVectorOfRectCreate

Func _VectorOfVectorOfRectCreateSize($size)
    ; CVAPI(std::vector<std::vector<cv::Rect>>*) VectorOfVectorOfRectCreateSize(int size);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfVectorOfRectCreateSize", "int", $size), "VectorOfVectorOfRectCreateSize", @error)
EndFunc   ;==>_VectorOfVectorOfRectCreateSize

Func _VectorOfVectorOfRectGetSize($v)
    ; CVAPI(int) VectorOfVectorOfRectGetSize(std::vector<std::vector<cv::Rect>>* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = IsArray($v)

    If $bVIsArray Then
        $vecV = _VectorOfVectorOfRectCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfVectorOfRectPush($vecV, $v[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "VectorOfVectorOfRectGetSize", $sVDllType, $vecV), "VectorOfVectorOfRectGetSize", @error)

    If $bVIsArray Then
        _VectorOfVectorOfRectRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfVectorOfRectGetSize

Func _VectorOfVectorOfRectPush($v, $value)
    ; CVAPI(void) VectorOfVectorOfRectPush(std::vector<std::vector<cv::Rect>>* v, std::vector<cv::Rect>* value);

    Local $vecV, $iArrVSize
    Local $bVIsArray = IsArray($v)

    If $bVIsArray Then
        $vecV = _VectorOfVectorOfRectCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfVectorOfRectPush($vecV, $v[$i])
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

    Local $vecValue, $iArrValueSize
    Local $bValueIsArray = IsArray($value)

    If $bValueIsArray Then
        $vecValue = _VectorOfRectCreate()

        $iArrValueSize = UBound($value)
        For $i = 0 To $iArrValueSize - 1
            _VectorOfRectPush($vecValue, $value[$i])
        Next
    Else
        $vecValue = $value
    EndIf

    Local $sValueDllType
    If IsDllStruct($value) Then
        $sValueDllType = "struct*"
    Else
        $sValueDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfVectorOfRectPush", $sVDllType, $vecV, $sValueDllType, $vecValue), "VectorOfVectorOfRectPush", @error)

    If $bValueIsArray Then
        _VectorOfRectRelease($vecValue)
    EndIf

    If $bVIsArray Then
        _VectorOfVectorOfRectRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfVectorOfRectPush

Func _VectorOfVectorOfRectPushVector($v, $other)
    ; CVAPI(void) VectorOfVectorOfRectPushVector(std::vector<std::vector<cv::Rect>>* v, std::vector<std::vector<cv::Rect>>* other);

    Local $vecV, $iArrVSize
    Local $bVIsArray = IsArray($v)

    If $bVIsArray Then
        $vecV = _VectorOfVectorOfRectCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfVectorOfRectPush($vecV, $v[$i])
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
        $vecOther = _VectorOfVectorOfRectCreate()

        $iArrOtherSize = UBound($other)
        For $i = 0 To $iArrOtherSize - 1
            _VectorOfVectorOfRectPush($vecOther, $other[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfVectorOfRectPushVector", $sVDllType, $vecV, $sOtherDllType, $vecOther), "VectorOfVectorOfRectPushVector", @error)

    If $bOtherIsArray Then
        _VectorOfVectorOfRectRelease($vecOther)
    EndIf

    If $bVIsArray Then
        _VectorOfVectorOfRectRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfVectorOfRectPushVector

Func _VectorOfVectorOfRectGetStartAddress($v)
    ; CVAPI(std::vector<cv::Rect>*) VectorOfVectorOfRectGetStartAddress(std::vector<std::vector<cv::Rect>>* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = IsArray($v)

    If $bVIsArray Then
        $vecV = _VectorOfVectorOfRectCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfVectorOfRectPush($vecV, $v[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfVectorOfRectGetStartAddress", $sVDllType, $vecV), "VectorOfVectorOfRectGetStartAddress", @error)

    If $bVIsArray Then
        _VectorOfVectorOfRectRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfVectorOfRectGetStartAddress

Func _VectorOfVectorOfRectGetEndAddress($v)
    ; CVAPI(void*) VectorOfVectorOfRectGetEndAddress(std::vector<std::vector<cv::Rect>>* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = IsArray($v)

    If $bVIsArray Then
        $vecV = _VectorOfVectorOfRectCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfVectorOfRectPush($vecV, $v[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfVectorOfRectGetEndAddress", $sVDllType, $vecV), "VectorOfVectorOfRectGetEndAddress", @error)

    If $bVIsArray Then
        _VectorOfVectorOfRectRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfVectorOfRectGetEndAddress

Func _VectorOfVectorOfRectClear($v)
    ; CVAPI(void) VectorOfVectorOfRectClear(std::vector<std::vector<cv::Rect>>* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = IsArray($v)

    If $bVIsArray Then
        $vecV = _VectorOfVectorOfRectCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfVectorOfRectPush($vecV, $v[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfVectorOfRectClear", $sVDllType, $vecV), "VectorOfVectorOfRectClear", @error)

    If $bVIsArray Then
        _VectorOfVectorOfRectRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfVectorOfRectClear

Func _VectorOfVectorOfRectRelease($v)
    ; CVAPI(void) VectorOfVectorOfRectRelease(std::vector<std::vector<cv::Rect>>** v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = IsArray($v)

    If $bVIsArray Then
        $vecV = _VectorOfVectorOfRectCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfVectorOfRectPush($vecV, $v[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfVectorOfRectRelease", $sVDllType, $vecV), "VectorOfVectorOfRectRelease", @error)

    If $bVIsArray Then
        _VectorOfVectorOfRectRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfVectorOfRectRelease

Func _VectorOfVectorOfRectCopyData($v, $data)
    ; CVAPI(void) VectorOfVectorOfRectCopyData(std::vector<std::vector<cv::Rect>>* v, std::vector<cv::Rect>* data);

    Local $vecV, $iArrVSize
    Local $bVIsArray = IsArray($v)

    If $bVIsArray Then
        $vecV = _VectorOfVectorOfRectCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfVectorOfRectPush($vecV, $v[$i])
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

    Local $vecData, $iArrDataSize
    Local $bDataIsArray = IsArray($data)

    If $bDataIsArray Then
        $vecData = _VectorOfRectCreate()

        $iArrDataSize = UBound($data)
        For $i = 0 To $iArrDataSize - 1
            _VectorOfRectPush($vecData, $data[$i])
        Next
    Else
        $vecData = $data
    EndIf

    Local $sDataDllType
    If IsDllStruct($data) Then
        $sDataDllType = "struct*"
    Else
        $sDataDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfVectorOfRectCopyData", $sVDllType, $vecV, $sDataDllType, $vecData), "VectorOfVectorOfRectCopyData", @error)

    If $bDataIsArray Then
        _VectorOfRectRelease($vecData)
    EndIf

    If $bVIsArray Then
        _VectorOfVectorOfRectRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfVectorOfRectCopyData

Func _VectorOfVectorOfRectGetItemPtr($vec, $index, $element)
    ; CVAPI(void) VectorOfVectorOfRectGetItemPtr(std::vector<std::vector<cv::Rect>>* vec, int index, std::vector<cv::Rect>** element);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = IsArray($vec)

    If $bVecIsArray Then
        $vecVec = _VectorOfVectorOfRectCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfVectorOfRectPush($vecVec, $vec[$i])
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

    Local $vecElement, $iArrElementSize
    Local $bElementIsArray = IsArray($element)

    If $bElementIsArray Then
        $vecElement = _VectorOfRectCreate()

        $iArrElementSize = UBound($element)
        For $i = 0 To $iArrElementSize - 1
            _VectorOfRectPush($vecElement, $element[$i])
        Next
    Else
        $vecElement = $element
    EndIf

    Local $sElementDllType
    If IsDllStruct($element) Then
        $sElementDllType = "struct*"
    ElseIf $element == Null Then
        $sElementDllType = "ptr"
    Else
        $sElementDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfVectorOfRectGetItemPtr", $sVecDllType, $vecVec, "int", $index, $sElementDllType, $vecElement), "VectorOfVectorOfRectGetItemPtr", @error)

    If $bElementIsArray Then
        _VectorOfRectRelease($vecElement)
    EndIf

    If $bVecIsArray Then
        _VectorOfVectorOfRectRelease($vecVec)
    EndIf
EndFunc   ;==>_VectorOfVectorOfRectGetItemPtr

Func _cveInputArrayFromVectorOfVectorOfRect($vec)
    ; CVAPI(cv::_InputArray*) cveInputArrayFromVectorOfVectorOfRect(std::vector<std::vector<cv::Rect>>* vec);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = IsArray($vec)

    If $bVecIsArray Then
        $vecVec = _VectorOfVectorOfRectCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfVectorOfRectPush($vecVec, $vec[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveInputArrayFromVectorOfVectorOfRect", $sVecDllType, $vecVec), "cveInputArrayFromVectorOfVectorOfRect", @error)

    If $bVecIsArray Then
        _VectorOfVectorOfRectRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveInputArrayFromVectorOfVectorOfRect

Func _cveOutputArrayFromVectorOfVectorOfRect($vec)
    ; CVAPI(cv::_OutputArray*) cveOutputArrayFromVectorOfVectorOfRect(std::vector<std::vector<cv::Rect>>* vec);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = IsArray($vec)

    If $bVecIsArray Then
        $vecVec = _VectorOfVectorOfRectCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfVectorOfRectPush($vecVec, $vec[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveOutputArrayFromVectorOfVectorOfRect", $sVecDllType, $vecVec), "cveOutputArrayFromVectorOfVectorOfRect", @error)

    If $bVecIsArray Then
        _VectorOfVectorOfRectRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveOutputArrayFromVectorOfVectorOfRect

Func _cveInputOutputArrayFromVectorOfVectorOfRect($vec)
    ; CVAPI(cv::_InputOutputArray*) cveInputOutputArrayFromVectorOfVectorOfRect(std::vector<std::vector<cv::Rect>>* vec);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = IsArray($vec)

    If $bVecIsArray Then
        $vecVec = _VectorOfVectorOfRectCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfVectorOfRectPush($vecVec, $vec[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveInputOutputArrayFromVectorOfVectorOfRect", $sVecDllType, $vecVec), "cveInputOutputArrayFromVectorOfVectorOfRect", @error)

    If $bVecIsArray Then
        _VectorOfVectorOfRectRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveInputOutputArrayFromVectorOfVectorOfRect

Func _VectorOfVectorOfRectSizeOfItemInBytes()
    ; CVAPI(int) VectorOfVectorOfRectSizeOfItemInBytes();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "VectorOfVectorOfRectSizeOfItemInBytes"), "VectorOfVectorOfRectSizeOfItemInBytes", @error)
EndFunc   ;==>_VectorOfVectorOfRectSizeOfItemInBytes