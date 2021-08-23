#include-once
#include "..\CVEUtils.au3"

Func _VectorOfVectorOfERStatCreate()
    ; CVAPI(std::vector<std::vector<cv::text::ERStat>>*) VectorOfVectorOfERStatCreate();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfVectorOfERStatCreate"), "VectorOfVectorOfERStatCreate", @error)
EndFunc   ;==>_VectorOfVectorOfERStatCreate

Func _VectorOfVectorOfERStatCreateSize($size)
    ; CVAPI(std::vector<std::vector<cv::text::ERStat>>*) VectorOfVectorOfERStatCreateSize(int size);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfVectorOfERStatCreateSize", "int", $size), "VectorOfVectorOfERStatCreateSize", @error)
EndFunc   ;==>_VectorOfVectorOfERStatCreateSize

Func _VectorOfVectorOfERStatGetSize($v)
    ; CVAPI(int) VectorOfVectorOfERStatGetSize(std::vector<std::vector<cv::text::ERStat>>* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfVectorOfERStatCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfVectorOfERStatPush($vecV, $v[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "VectorOfVectorOfERStatGetSize", $sVDllType, $vecV), "VectorOfVectorOfERStatGetSize", @error)

    If $bVIsArray Then
        _VectorOfVectorOfERStatRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfVectorOfERStatGetSize

Func _VectorOfVectorOfERStatPush($v, $value)
    ; CVAPI(void) VectorOfVectorOfERStatPush(std::vector<std::vector<cv::text::ERStat>>* v, std::vector<cv::text::ERStat>* value);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfVectorOfERStatCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfVectorOfERStatPush($vecV, $v[$i])
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
        $vecValue = _VectorOfERStatCreate()

        $iArrValueSize = UBound($value)
        For $i = 0 To $iArrValueSize - 1
            _VectorOfERStatPush($vecValue, $value[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfVectorOfERStatPush", $sVDllType, $vecV, $sValueDllType, $vecValue), "VectorOfVectorOfERStatPush", @error)

    If $bValueIsArray Then
        _VectorOfERStatRelease($vecValue)
    EndIf

    If $bVIsArray Then
        _VectorOfVectorOfERStatRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfVectorOfERStatPush

Func _VectorOfVectorOfERStatPushVector($v, $other)
    ; CVAPI(void) VectorOfVectorOfERStatPushVector(std::vector<std::vector<cv::text::ERStat>>* v, std::vector<std::vector<cv::text::ERStat>>* other);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfVectorOfERStatCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfVectorOfERStatPush($vecV, $v[$i])
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
        $vecOther = _VectorOfVectorOfERStatCreate()

        $iArrOtherSize = UBound($other)
        For $i = 0 To $iArrOtherSize - 1
            _VectorOfVectorOfERStatPush($vecOther, $other[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfVectorOfERStatPushVector", $sVDllType, $vecV, $sOtherDllType, $vecOther), "VectorOfVectorOfERStatPushVector", @error)

    If $bOtherIsArray Then
        _VectorOfVectorOfERStatRelease($vecOther)
    EndIf

    If $bVIsArray Then
        _VectorOfVectorOfERStatRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfVectorOfERStatPushVector

Func _VectorOfVectorOfERStatGetStartAddress($v)
    ; CVAPI(std::vector<cv::text::ERStat>*) VectorOfVectorOfERStatGetStartAddress(std::vector<std::vector<cv::text::ERStat>>* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfVectorOfERStatCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfVectorOfERStatPush($vecV, $v[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfVectorOfERStatGetStartAddress", $sVDllType, $vecV), "VectorOfVectorOfERStatGetStartAddress", @error)

    If $bVIsArray Then
        _VectorOfVectorOfERStatRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfVectorOfERStatGetStartAddress

Func _VectorOfVectorOfERStatGetEndAddress($v)
    ; CVAPI(void*) VectorOfVectorOfERStatGetEndAddress(std::vector<std::vector<cv::text::ERStat>>* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfVectorOfERStatCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfVectorOfERStatPush($vecV, $v[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfVectorOfERStatGetEndAddress", $sVDllType, $vecV), "VectorOfVectorOfERStatGetEndAddress", @error)

    If $bVIsArray Then
        _VectorOfVectorOfERStatRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfVectorOfERStatGetEndAddress

Func _VectorOfVectorOfERStatClear($v)
    ; CVAPI(void) VectorOfVectorOfERStatClear(std::vector<std::vector<cv::text::ERStat>>* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfVectorOfERStatCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfVectorOfERStatPush($vecV, $v[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfVectorOfERStatClear", $sVDllType, $vecV), "VectorOfVectorOfERStatClear", @error)

    If $bVIsArray Then
        _VectorOfVectorOfERStatRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfVectorOfERStatClear

Func _VectorOfVectorOfERStatRelease($v)
    ; CVAPI(void) VectorOfVectorOfERStatRelease(std::vector<std::vector<cv::text::ERStat>>** v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfVectorOfERStatCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfVectorOfERStatPush($vecV, $v[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfVectorOfERStatRelease", $sVDllType, $vecV), "VectorOfVectorOfERStatRelease", @error)

    If $bVIsArray Then
        _VectorOfVectorOfERStatRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfVectorOfERStatRelease

Func _VectorOfVectorOfERStatCopyData($v, $data)
    ; CVAPI(void) VectorOfVectorOfERStatCopyData(std::vector<std::vector<cv::text::ERStat>>* v, std::vector<cv::text::ERStat>* data);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfVectorOfERStatCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfVectorOfERStatPush($vecV, $v[$i])
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
        $vecData = _VectorOfERStatCreate()

        $iArrDataSize = UBound($data)
        For $i = 0 To $iArrDataSize - 1
            _VectorOfERStatPush($vecData, $data[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfVectorOfERStatCopyData", $sVDllType, $vecV, $sDataDllType, $vecData), "VectorOfVectorOfERStatCopyData", @error)

    If $bDataIsArray Then
        _VectorOfERStatRelease($vecData)
    EndIf

    If $bVIsArray Then
        _VectorOfVectorOfERStatRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfVectorOfERStatCopyData

Func _VectorOfVectorOfERStatGetItemPtr($vec, $index, $element)
    ; CVAPI(void) VectorOfVectorOfERStatGetItemPtr(std::vector<std::vector<cv::text::ERStat>>* vec, int index, std::vector<cv::text::ERStat>** element);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfVectorOfERStatCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfVectorOfERStatPush($vecVec, $vec[$i])
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
        $vecElement = _VectorOfERStatCreate()

        $iArrElementSize = UBound($element)
        For $i = 0 To $iArrElementSize - 1
            _VectorOfERStatPush($vecElement, $element[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfVectorOfERStatGetItemPtr", $sVecDllType, $vecVec, "int", $index, $sElementDllType, $vecElement), "VectorOfVectorOfERStatGetItemPtr", @error)

    If $bElementIsArray Then
        _VectorOfERStatRelease($vecElement)
    EndIf

    If $bVecIsArray Then
        _VectorOfVectorOfERStatRelease($vecVec)
    EndIf
EndFunc   ;==>_VectorOfVectorOfERStatGetItemPtr

Func _cveInputArrayFromVectorOfVectorOfERStat($vec)
    ; CVAPI(cv::_InputArray*) cveInputArrayFromVectorOfVectorOfERStat(std::vector<std::vector<cv::text::ERStat>>* vec);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfVectorOfERStatCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfVectorOfERStatPush($vecVec, $vec[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveInputArrayFromVectorOfVectorOfERStat", $sVecDllType, $vecVec), "cveInputArrayFromVectorOfVectorOfERStat", @error)

    If $bVecIsArray Then
        _VectorOfVectorOfERStatRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveInputArrayFromVectorOfVectorOfERStat

Func _cveOutputArrayFromVectorOfVectorOfERStat($vec)
    ; CVAPI(cv::_OutputArray*) cveOutputArrayFromVectorOfVectorOfERStat(std::vector<std::vector<cv::text::ERStat>>* vec);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfVectorOfERStatCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfVectorOfERStatPush($vecVec, $vec[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveOutputArrayFromVectorOfVectorOfERStat", $sVecDllType, $vecVec), "cveOutputArrayFromVectorOfVectorOfERStat", @error)

    If $bVecIsArray Then
        _VectorOfVectorOfERStatRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveOutputArrayFromVectorOfVectorOfERStat

Func _cveInputOutputArrayFromVectorOfVectorOfERStat($vec)
    ; CVAPI(cv::_InputOutputArray*) cveInputOutputArrayFromVectorOfVectorOfERStat(std::vector<std::vector<cv::text::ERStat>>* vec);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfVectorOfERStatCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfVectorOfERStatPush($vecVec, $vec[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveInputOutputArrayFromVectorOfVectorOfERStat", $sVecDllType, $vecVec), "cveInputOutputArrayFromVectorOfVectorOfERStat", @error)

    If $bVecIsArray Then
        _VectorOfVectorOfERStatRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveInputOutputArrayFromVectorOfVectorOfERStat

Func _VectorOfVectorOfERStatSizeOfItemInBytes()
    ; CVAPI(int) VectorOfVectorOfERStatSizeOfItemInBytes();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "VectorOfVectorOfERStatSizeOfItemInBytes"), "VectorOfVectorOfERStatSizeOfItemInBytes", @error)
EndFunc   ;==>_VectorOfVectorOfERStatSizeOfItemInBytes