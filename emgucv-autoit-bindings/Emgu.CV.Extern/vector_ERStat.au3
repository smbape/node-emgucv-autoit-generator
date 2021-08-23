#include-once
#include "..\CVEUtils.au3"

Func _VectorOfERStatCreate()
    ; CVAPI(std::vector<cv::text::ERStat>*) VectorOfERStatCreate();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfERStatCreate"), "VectorOfERStatCreate", @error)
EndFunc   ;==>_VectorOfERStatCreate

Func _VectorOfERStatCreateSize($size)
    ; CVAPI(std::vector<cv::text::ERStat>*) VectorOfERStatCreateSize(int size);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfERStatCreateSize", "int", $size), "VectorOfERStatCreateSize", @error)
EndFunc   ;==>_VectorOfERStatCreateSize

Func _VectorOfERStatGetSize($v)
    ; CVAPI(int) VectorOfERStatGetSize(std::vector<cv::text::ERStat>* v);

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

    Local $sVDllType
    If IsDllStruct($v) Then
        $sVDllType = "struct*"
    Else
        $sVDllType = "ptr"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "VectorOfERStatGetSize", $sVDllType, $vecV), "VectorOfERStatGetSize", @error)

    If $bVIsArray Then
        _VectorOfERStatRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfERStatGetSize

Func _VectorOfERStatPush($v, $value)
    ; CVAPI(void) VectorOfERStatPush(std::vector<cv::text::ERStat>* v, cv::text::ERStat* value);

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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfERStatPush", $sVDllType, $vecV, $sValueDllType, $value), "VectorOfERStatPush", @error)

    If $bVIsArray Then
        _VectorOfERStatRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfERStatPush

Func _VectorOfERStatPushMulti($v, $values, $count)
    ; CVAPI(void) VectorOfERStatPushMulti(std::vector<cv::text::ERStat>* v, cv::text::ERStat* values, int count);

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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfERStatPushMulti", $sVDllType, $vecV, $sValuesDllType, $values, "int", $count), "VectorOfERStatPushMulti", @error)

    If $bVIsArray Then
        _VectorOfERStatRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfERStatPushMulti

Func _VectorOfERStatPushVector($v, $other)
    ; CVAPI(void) VectorOfERStatPushVector(std::vector<cv::text::ERStat>* v, std::vector<cv::text::ERStat>* other);

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

    Local $sVDllType
    If IsDllStruct($v) Then
        $sVDllType = "struct*"
    Else
        $sVDllType = "ptr"
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

    Local $sOtherDllType
    If IsDllStruct($other) Then
        $sOtherDllType = "struct*"
    Else
        $sOtherDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfERStatPushVector", $sVDllType, $vecV, $sOtherDllType, $vecOther), "VectorOfERStatPushVector", @error)

    If $bOtherIsArray Then
        _VectorOfERStatRelease($vecOther)
    EndIf

    If $bVIsArray Then
        _VectorOfERStatRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfERStatPushVector

Func _VectorOfERStatClear($v)
    ; CVAPI(void) VectorOfERStatClear(std::vector<cv::text::ERStat>* v);

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

    Local $sVDllType
    If IsDllStruct($v) Then
        $sVDllType = "struct*"
    Else
        $sVDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfERStatClear", $sVDllType, $vecV), "VectorOfERStatClear", @error)

    If $bVIsArray Then
        _VectorOfERStatRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfERStatClear

Func _VectorOfERStatRelease($v)
    ; CVAPI(void) VectorOfERStatRelease(std::vector<cv::text::ERStat>** v);

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

    Local $sVDllType
    If IsDllStruct($v) Then
        $sVDllType = "struct*"
    ElseIf $v == Null Then
        $sVDllType = "ptr"
    Else
        $sVDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfERStatRelease", $sVDllType, $vecV), "VectorOfERStatRelease", @error)

    If $bVIsArray Then
        _VectorOfERStatRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfERStatRelease

Func _VectorOfERStatCopyData($v, $data)
    ; CVAPI(void) VectorOfERStatCopyData(std::vector<cv::text::ERStat>* v, cv::text::ERStat* data);

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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfERStatCopyData", $sVDllType, $vecV, $sDataDllType, $data), "VectorOfERStatCopyData", @error)

    If $bVIsArray Then
        _VectorOfERStatRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfERStatCopyData

Func _VectorOfERStatGetStartAddress($v)
    ; CVAPI(cv::text::ERStat*) VectorOfERStatGetStartAddress(std::vector<cv::text::ERStat>* v);

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

    Local $sVDllType
    If IsDllStruct($v) Then
        $sVDllType = "struct*"
    Else
        $sVDllType = "ptr"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfERStatGetStartAddress", $sVDllType, $vecV), "VectorOfERStatGetStartAddress", @error)

    If $bVIsArray Then
        _VectorOfERStatRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfERStatGetStartAddress

Func _VectorOfERStatGetEndAddress($v)
    ; CVAPI(void*) VectorOfERStatGetEndAddress(std::vector<cv::text::ERStat>* v);

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

    Local $sVDllType
    If IsDllStruct($v) Then
        $sVDllType = "struct*"
    Else
        $sVDllType = "ptr"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfERStatGetEndAddress", $sVDllType, $vecV), "VectorOfERStatGetEndAddress", @error)

    If $bVIsArray Then
        _VectorOfERStatRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfERStatGetEndAddress

Func _VectorOfERStatGetItem($vec, $index, $element)
    ; CVAPI(void) VectorOfERStatGetItem(std::vector<cv::text::ERStat>* vec, int index, cv::text::ERStat* element);

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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfERStatGetItem", $sVecDllType, $vecVec, "int", $index, $sElementDllType, $element), "VectorOfERStatGetItem", @error)

    If $bVecIsArray Then
        _VectorOfERStatRelease($vecVec)
    EndIf
EndFunc   ;==>_VectorOfERStatGetItem

Func _VectorOfERStatGetItemPtr($vec, $index, $element)
    ; CVAPI(void) VectorOfERStatGetItemPtr(std::vector<cv::text::ERStat>* vec, int index, cv::text::ERStat** element);

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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfERStatGetItemPtr", $sVecDllType, $vecVec, "int", $index, $sElementDllType, $element), "VectorOfERStatGetItemPtr", @error)

    If $bVecIsArray Then
        _VectorOfERStatRelease($vecVec)
    EndIf
EndFunc   ;==>_VectorOfERStatGetItemPtr

Func _cveInputArrayFromVectorOfERStat($vec)
    ; CVAPI(cv::_InputArray*) cveInputArrayFromVectorOfERStat(std::vector<cv::text::ERStat>* vec);

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

    Local $sVecDllType
    If IsDllStruct($vec) Then
        $sVecDllType = "struct*"
    Else
        $sVecDllType = "ptr"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveInputArrayFromVectorOfERStat", $sVecDllType, $vecVec), "cveInputArrayFromVectorOfERStat", @error)

    If $bVecIsArray Then
        _VectorOfERStatRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveInputArrayFromVectorOfERStat

Func _cveOutputArrayFromVectorOfERStat($vec)
    ; CVAPI(cv::_OutputArray*) cveOutputArrayFromVectorOfERStat(std::vector<cv::text::ERStat>* vec);

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

    Local $sVecDllType
    If IsDllStruct($vec) Then
        $sVecDllType = "struct*"
    Else
        $sVecDllType = "ptr"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveOutputArrayFromVectorOfERStat", $sVecDllType, $vecVec), "cveOutputArrayFromVectorOfERStat", @error)

    If $bVecIsArray Then
        _VectorOfERStatRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveOutputArrayFromVectorOfERStat

Func _cveInputOutputArrayFromVectorOfERStat($vec)
    ; CVAPI(cv::_InputOutputArray*) cveInputOutputArrayFromVectorOfERStat(std::vector<cv::text::ERStat>* vec);

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

    Local $sVecDllType
    If IsDllStruct($vec) Then
        $sVecDllType = "struct*"
    Else
        $sVecDllType = "ptr"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveInputOutputArrayFromVectorOfERStat", $sVecDllType, $vecVec), "cveInputOutputArrayFromVectorOfERStat", @error)

    If $bVecIsArray Then
        _VectorOfERStatRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveInputOutputArrayFromVectorOfERStat

Func _VectorOfERStatSizeOfItemInBytes()
    ; CVAPI(int) VectorOfERStatSizeOfItemInBytes();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "VectorOfERStatSizeOfItemInBytes"), "VectorOfERStatSizeOfItemInBytes", @error)
EndFunc   ;==>_VectorOfERStatSizeOfItemInBytes