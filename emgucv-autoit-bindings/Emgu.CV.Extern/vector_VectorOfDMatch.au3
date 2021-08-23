#include-once
#include "..\CVEUtils.au3"

Func _VectorOfVectorOfDMatchCreate()
    ; CVAPI(std::vector<std::vector<cv::DMatch>>*) VectorOfVectorOfDMatchCreate();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfVectorOfDMatchCreate"), "VectorOfVectorOfDMatchCreate", @error)
EndFunc   ;==>_VectorOfVectorOfDMatchCreate

Func _VectorOfVectorOfDMatchCreateSize($size)
    ; CVAPI(std::vector<std::vector<cv::DMatch>>*) VectorOfVectorOfDMatchCreateSize(int size);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfVectorOfDMatchCreateSize", "int", $size), "VectorOfVectorOfDMatchCreateSize", @error)
EndFunc   ;==>_VectorOfVectorOfDMatchCreateSize

Func _VectorOfVectorOfDMatchGetSize($v)
    ; CVAPI(int) VectorOfVectorOfDMatchGetSize(std::vector<std::vector<cv::DMatch>>* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfVectorOfDMatchCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfVectorOfDMatchPush($vecV, $v[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "VectorOfVectorOfDMatchGetSize", $sVDllType, $vecV), "VectorOfVectorOfDMatchGetSize", @error)

    If $bVIsArray Then
        _VectorOfVectorOfDMatchRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfVectorOfDMatchGetSize

Func _VectorOfVectorOfDMatchPush($v, $value)
    ; CVAPI(void) VectorOfVectorOfDMatchPush(std::vector<std::vector<cv::DMatch>>* v, std::vector<cv::DMatch>* value);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfVectorOfDMatchCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfVectorOfDMatchPush($vecV, $v[$i])
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
    Local $bValueIsArray = VarGetType($value) == "Array"

    If $bValueIsArray Then
        $vecValue = _VectorOfDMatchCreate()

        $iArrValueSize = UBound($value)
        For $i = 0 To $iArrValueSize - 1
            _VectorOfDMatchPush($vecValue, $value[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfVectorOfDMatchPush", $sVDllType, $vecV, $sValueDllType, $vecValue), "VectorOfVectorOfDMatchPush", @error)

    If $bValueIsArray Then
        _VectorOfDMatchRelease($vecValue)
    EndIf

    If $bVIsArray Then
        _VectorOfVectorOfDMatchRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfVectorOfDMatchPush

Func _VectorOfVectorOfDMatchPushVector($v, $other)
    ; CVAPI(void) VectorOfVectorOfDMatchPushVector(std::vector<std::vector<cv::DMatch>>* v, std::vector<std::vector<cv::DMatch>>* other);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfVectorOfDMatchCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfVectorOfDMatchPush($vecV, $v[$i])
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
        $vecOther = _VectorOfVectorOfDMatchCreate()

        $iArrOtherSize = UBound($other)
        For $i = 0 To $iArrOtherSize - 1
            _VectorOfVectorOfDMatchPush($vecOther, $other[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfVectorOfDMatchPushVector", $sVDllType, $vecV, $sOtherDllType, $vecOther), "VectorOfVectorOfDMatchPushVector", @error)

    If $bOtherIsArray Then
        _VectorOfVectorOfDMatchRelease($vecOther)
    EndIf

    If $bVIsArray Then
        _VectorOfVectorOfDMatchRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfVectorOfDMatchPushVector

Func _VectorOfVectorOfDMatchGetStartAddress($v)
    ; CVAPI(std::vector<cv::DMatch>*) VectorOfVectorOfDMatchGetStartAddress(std::vector<std::vector<cv::DMatch>>* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfVectorOfDMatchCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfVectorOfDMatchPush($vecV, $v[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfVectorOfDMatchGetStartAddress", $sVDllType, $vecV), "VectorOfVectorOfDMatchGetStartAddress", @error)

    If $bVIsArray Then
        _VectorOfVectorOfDMatchRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfVectorOfDMatchGetStartAddress

Func _VectorOfVectorOfDMatchGetEndAddress($v)
    ; CVAPI(void*) VectorOfVectorOfDMatchGetEndAddress(std::vector<std::vector<cv::DMatch>>* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfVectorOfDMatchCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfVectorOfDMatchPush($vecV, $v[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfVectorOfDMatchGetEndAddress", $sVDllType, $vecV), "VectorOfVectorOfDMatchGetEndAddress", @error)

    If $bVIsArray Then
        _VectorOfVectorOfDMatchRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfVectorOfDMatchGetEndAddress

Func _VectorOfVectorOfDMatchClear($v)
    ; CVAPI(void) VectorOfVectorOfDMatchClear(std::vector<std::vector<cv::DMatch>>* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfVectorOfDMatchCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfVectorOfDMatchPush($vecV, $v[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfVectorOfDMatchClear", $sVDllType, $vecV), "VectorOfVectorOfDMatchClear", @error)

    If $bVIsArray Then
        _VectorOfVectorOfDMatchRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfVectorOfDMatchClear

Func _VectorOfVectorOfDMatchRelease($v)
    ; CVAPI(void) VectorOfVectorOfDMatchRelease(std::vector<std::vector<cv::DMatch>>** v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfVectorOfDMatchCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfVectorOfDMatchPush($vecV, $v[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfVectorOfDMatchRelease", $sVDllType, $vecV), "VectorOfVectorOfDMatchRelease", @error)

    If $bVIsArray Then
        _VectorOfVectorOfDMatchRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfVectorOfDMatchRelease

Func _VectorOfVectorOfDMatchCopyData($v, $data)
    ; CVAPI(void) VectorOfVectorOfDMatchCopyData(std::vector<std::vector<cv::DMatch>>* v, std::vector<cv::DMatch>* data);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfVectorOfDMatchCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfVectorOfDMatchPush($vecV, $v[$i])
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
    Local $bDataIsArray = VarGetType($data) == "Array"

    If $bDataIsArray Then
        $vecData = _VectorOfDMatchCreate()

        $iArrDataSize = UBound($data)
        For $i = 0 To $iArrDataSize - 1
            _VectorOfDMatchPush($vecData, $data[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfVectorOfDMatchCopyData", $sVDllType, $vecV, $sDataDllType, $vecData), "VectorOfVectorOfDMatchCopyData", @error)

    If $bDataIsArray Then
        _VectorOfDMatchRelease($vecData)
    EndIf

    If $bVIsArray Then
        _VectorOfVectorOfDMatchRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfVectorOfDMatchCopyData

Func _VectorOfVectorOfDMatchGetItemPtr($vec, $index, $element)
    ; CVAPI(void) VectorOfVectorOfDMatchGetItemPtr(std::vector<std::vector<cv::DMatch>>* vec, int index, std::vector<cv::DMatch>** element);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfVectorOfDMatchCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfVectorOfDMatchPush($vecVec, $vec[$i])
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
    Local $bElementIsArray = VarGetType($element) == "Array"

    If $bElementIsArray Then
        $vecElement = _VectorOfDMatchCreate()

        $iArrElementSize = UBound($element)
        For $i = 0 To $iArrElementSize - 1
            _VectorOfDMatchPush($vecElement, $element[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfVectorOfDMatchGetItemPtr", $sVecDllType, $vecVec, "int", $index, $sElementDllType, $vecElement), "VectorOfVectorOfDMatchGetItemPtr", @error)

    If $bElementIsArray Then
        _VectorOfDMatchRelease($vecElement)
    EndIf

    If $bVecIsArray Then
        _VectorOfVectorOfDMatchRelease($vecVec)
    EndIf
EndFunc   ;==>_VectorOfVectorOfDMatchGetItemPtr

Func _cveInputArrayFromVectorOfVectorOfDMatch($vec)
    ; CVAPI(cv::_InputArray*) cveInputArrayFromVectorOfVectorOfDMatch(std::vector<std::vector<cv::DMatch>>* vec);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfVectorOfDMatchCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfVectorOfDMatchPush($vecVec, $vec[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveInputArrayFromVectorOfVectorOfDMatch", $sVecDllType, $vecVec), "cveInputArrayFromVectorOfVectorOfDMatch", @error)

    If $bVecIsArray Then
        _VectorOfVectorOfDMatchRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveInputArrayFromVectorOfVectorOfDMatch

Func _cveOutputArrayFromVectorOfVectorOfDMatch($vec)
    ; CVAPI(cv::_OutputArray*) cveOutputArrayFromVectorOfVectorOfDMatch(std::vector<std::vector<cv::DMatch>>* vec);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfVectorOfDMatchCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfVectorOfDMatchPush($vecVec, $vec[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveOutputArrayFromVectorOfVectorOfDMatch", $sVecDllType, $vecVec), "cveOutputArrayFromVectorOfVectorOfDMatch", @error)

    If $bVecIsArray Then
        _VectorOfVectorOfDMatchRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveOutputArrayFromVectorOfVectorOfDMatch

Func _cveInputOutputArrayFromVectorOfVectorOfDMatch($vec)
    ; CVAPI(cv::_InputOutputArray*) cveInputOutputArrayFromVectorOfVectorOfDMatch(std::vector<std::vector<cv::DMatch>>* vec);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfVectorOfDMatchCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfVectorOfDMatchPush($vecVec, $vec[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveInputOutputArrayFromVectorOfVectorOfDMatch", $sVecDllType, $vecVec), "cveInputOutputArrayFromVectorOfVectorOfDMatch", @error)

    If $bVecIsArray Then
        _VectorOfVectorOfDMatchRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveInputOutputArrayFromVectorOfVectorOfDMatch

Func _VectorOfVectorOfDMatchSizeOfItemInBytes()
    ; CVAPI(int) VectorOfVectorOfDMatchSizeOfItemInBytes();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "VectorOfVectorOfDMatchSizeOfItemInBytes"), "VectorOfVectorOfDMatchSizeOfItemInBytes", @error)
EndFunc   ;==>_VectorOfVectorOfDMatchSizeOfItemInBytes