#include-once
#include "..\CVEUtils.au3"

Func _VectorOfColorPointCreate()
    ; CVAPI(std::vector<ColorPoint>*) VectorOfColorPointCreate();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfColorPointCreate"), "VectorOfColorPointCreate", @error)
EndFunc   ;==>_VectorOfColorPointCreate

Func _VectorOfColorPointCreateSize($size)
    ; CVAPI(std::vector<ColorPoint>*) VectorOfColorPointCreateSize(int size);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfColorPointCreateSize", "int", $size), "VectorOfColorPointCreateSize", @error)
EndFunc   ;==>_VectorOfColorPointCreateSize

Func _VectorOfColorPointGetSize($v)
    ; CVAPI(int) VectorOfColorPointGetSize(std::vector<ColorPoint>* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfColorPointCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfColorPointPush($vecV, $v[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "VectorOfColorPointGetSize", $sVDllType, $vecV), "VectorOfColorPointGetSize", @error)

    If $bVIsArray Then
        _VectorOfColorPointRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfColorPointGetSize

Func _VectorOfColorPointPush($v, $value)
    ; CVAPI(void) VectorOfColorPointPush(std::vector<ColorPoint>* v, ColorPoint* value);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfColorPointCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfColorPointPush($vecV, $v[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfColorPointPush", $sVDllType, $vecV, $sValueDllType, $value), "VectorOfColorPointPush", @error)

    If $bVIsArray Then
        _VectorOfColorPointRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfColorPointPush

Func _VectorOfColorPointPushMulti($v, $values, $count)
    ; CVAPI(void) VectorOfColorPointPushMulti(std::vector<ColorPoint>* v, ColorPoint* values, int count);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfColorPointCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfColorPointPush($vecV, $v[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfColorPointPushMulti", $sVDllType, $vecV, $sValuesDllType, $values, "int", $count), "VectorOfColorPointPushMulti", @error)

    If $bVIsArray Then
        _VectorOfColorPointRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfColorPointPushMulti

Func _VectorOfColorPointPushVector($v, $other)
    ; CVAPI(void) VectorOfColorPointPushVector(std::vector<ColorPoint>* v, std::vector<ColorPoint>* other);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfColorPointCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfColorPointPush($vecV, $v[$i])
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
        $vecOther = _VectorOfColorPointCreate()

        $iArrOtherSize = UBound($other)
        For $i = 0 To $iArrOtherSize - 1
            _VectorOfColorPointPush($vecOther, $other[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfColorPointPushVector", $sVDllType, $vecV, $sOtherDllType, $vecOther), "VectorOfColorPointPushVector", @error)

    If $bOtherIsArray Then
        _VectorOfColorPointRelease($vecOther)
    EndIf

    If $bVIsArray Then
        _VectorOfColorPointRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfColorPointPushVector

Func _VectorOfColorPointClear($v)
    ; CVAPI(void) VectorOfColorPointClear(std::vector<ColorPoint>* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfColorPointCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfColorPointPush($vecV, $v[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfColorPointClear", $sVDllType, $vecV), "VectorOfColorPointClear", @error)

    If $bVIsArray Then
        _VectorOfColorPointRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfColorPointClear

Func _VectorOfColorPointRelease($v)
    ; CVAPI(void) VectorOfColorPointRelease(std::vector<ColorPoint>** v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfColorPointCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfColorPointPush($vecV, $v[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfColorPointRelease", $sVDllType, $vecV), "VectorOfColorPointRelease", @error)

    If $bVIsArray Then
        _VectorOfColorPointRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfColorPointRelease

Func _VectorOfColorPointCopyData($v, $data)
    ; CVAPI(void) VectorOfColorPointCopyData(std::vector<ColorPoint>* v, ColorPoint* data);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfColorPointCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfColorPointPush($vecV, $v[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfColorPointCopyData", $sVDllType, $vecV, $sDataDllType, $data), "VectorOfColorPointCopyData", @error)

    If $bVIsArray Then
        _VectorOfColorPointRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfColorPointCopyData

Func _VectorOfColorPointGetStartAddress($v)
    ; CVAPI(ColorPoint*) VectorOfColorPointGetStartAddress(std::vector<ColorPoint>* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfColorPointCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfColorPointPush($vecV, $v[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfColorPointGetStartAddress", $sVDllType, $vecV), "VectorOfColorPointGetStartAddress", @error)

    If $bVIsArray Then
        _VectorOfColorPointRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfColorPointGetStartAddress

Func _VectorOfColorPointGetEndAddress($v)
    ; CVAPI(void*) VectorOfColorPointGetEndAddress(std::vector<ColorPoint>* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfColorPointCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfColorPointPush($vecV, $v[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfColorPointGetEndAddress", $sVDllType, $vecV), "VectorOfColorPointGetEndAddress", @error)

    If $bVIsArray Then
        _VectorOfColorPointRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfColorPointGetEndAddress

Func _VectorOfColorPointGetItem($vec, $index, $element)
    ; CVAPI(void) VectorOfColorPointGetItem(std::vector<ColorPoint>* vec, int index, ColorPoint* element);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfColorPointCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfColorPointPush($vecVec, $vec[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfColorPointGetItem", $sVecDllType, $vecVec, "int", $index, $sElementDllType, $element), "VectorOfColorPointGetItem", @error)

    If $bVecIsArray Then
        _VectorOfColorPointRelease($vecVec)
    EndIf
EndFunc   ;==>_VectorOfColorPointGetItem

Func _VectorOfColorPointGetItemPtr($vec, $index, $element)
    ; CVAPI(void) VectorOfColorPointGetItemPtr(std::vector<ColorPoint>* vec, int index, ColorPoint** element);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfColorPointCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfColorPointPush($vecVec, $vec[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfColorPointGetItemPtr", $sVecDllType, $vecVec, "int", $index, $sElementDllType, $element), "VectorOfColorPointGetItemPtr", @error)

    If $bVecIsArray Then
        _VectorOfColorPointRelease($vecVec)
    EndIf
EndFunc   ;==>_VectorOfColorPointGetItemPtr

Func _cveInputArrayFromVectorOfColorPoint($vec)
    ; CVAPI(cv::_InputArray*) cveInputArrayFromVectorOfColorPoint(std::vector<ColorPoint>* vec);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfColorPointCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfColorPointPush($vecVec, $vec[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveInputArrayFromVectorOfColorPoint", $sVecDllType, $vecVec), "cveInputArrayFromVectorOfColorPoint", @error)

    If $bVecIsArray Then
        _VectorOfColorPointRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveInputArrayFromVectorOfColorPoint

Func _cveOutputArrayFromVectorOfColorPoint($vec)
    ; CVAPI(cv::_OutputArray*) cveOutputArrayFromVectorOfColorPoint(std::vector<ColorPoint>* vec);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfColorPointCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfColorPointPush($vecVec, $vec[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveOutputArrayFromVectorOfColorPoint", $sVecDllType, $vecVec), "cveOutputArrayFromVectorOfColorPoint", @error)

    If $bVecIsArray Then
        _VectorOfColorPointRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveOutputArrayFromVectorOfColorPoint

Func _cveInputOutputArrayFromVectorOfColorPoint($vec)
    ; CVAPI(cv::_InputOutputArray*) cveInputOutputArrayFromVectorOfColorPoint(std::vector<ColorPoint>* vec);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfColorPointCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfColorPointPush($vecVec, $vec[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveInputOutputArrayFromVectorOfColorPoint", $sVecDllType, $vecVec), "cveInputOutputArrayFromVectorOfColorPoint", @error)

    If $bVecIsArray Then
        _VectorOfColorPointRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveInputOutputArrayFromVectorOfColorPoint

Func _VectorOfColorPointSizeOfItemInBytes()
    ; CVAPI(int) VectorOfColorPointSizeOfItemInBytes();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "VectorOfColorPointSizeOfItemInBytes"), "VectorOfColorPointSizeOfItemInBytes", @error)
EndFunc   ;==>_VectorOfColorPointSizeOfItemInBytes