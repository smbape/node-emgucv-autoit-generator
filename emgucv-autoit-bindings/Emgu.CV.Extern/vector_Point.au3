#include-once
#include "..\CVEUtils.au3"

Func _VectorOfPointCreate()
    ; CVAPI(std::vector<cv::Point>*) VectorOfPointCreate();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfPointCreate"), "VectorOfPointCreate", @error)
EndFunc   ;==>_VectorOfPointCreate

Func _VectorOfPointCreateSize($size)
    ; CVAPI(std::vector<cv::Point>*) VectorOfPointCreateSize(int size);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfPointCreateSize", "int", $size), "VectorOfPointCreateSize", @error)
EndFunc   ;==>_VectorOfPointCreateSize

Func _VectorOfPointGetSize($v)
    ; CVAPI(int) VectorOfPointGetSize(std::vector<cv::Point>* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfPointCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfPointPush($vecV, $v[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "VectorOfPointGetSize", $sVDllType, $vecV), "VectorOfPointGetSize", @error)

    If $bVIsArray Then
        _VectorOfPointRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfPointGetSize

Func _VectorOfPointPush($v, $value)
    ; CVAPI(void) VectorOfPointPush(std::vector<cv::Point>* v, cv::Point* value);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfPointCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfPointPush($vecV, $v[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfPointPush", $sVDllType, $vecV, $sValueDllType, $value), "VectorOfPointPush", @error)

    If $bVIsArray Then
        _VectorOfPointRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfPointPush

Func _VectorOfPointPushMulti($v, $values, $count)
    ; CVAPI(void) VectorOfPointPushMulti(std::vector<cv::Point>* v, cv::Point* values, int count);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfPointCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfPointPush($vecV, $v[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfPointPushMulti", $sVDllType, $vecV, $sValuesDllType, $values, "int", $count), "VectorOfPointPushMulti", @error)

    If $bVIsArray Then
        _VectorOfPointRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfPointPushMulti

Func _VectorOfPointPushVector($v, $other)
    ; CVAPI(void) VectorOfPointPushVector(std::vector<cv::Point>* v, std::vector<cv::Point>* other);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfPointCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfPointPush($vecV, $v[$i])
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
        $vecOther = _VectorOfPointCreate()

        $iArrOtherSize = UBound($other)
        For $i = 0 To $iArrOtherSize - 1
            _VectorOfPointPush($vecOther, $other[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfPointPushVector", $sVDllType, $vecV, $sOtherDllType, $vecOther), "VectorOfPointPushVector", @error)

    If $bOtherIsArray Then
        _VectorOfPointRelease($vecOther)
    EndIf

    If $bVIsArray Then
        _VectorOfPointRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfPointPushVector

Func _VectorOfPointClear($v)
    ; CVAPI(void) VectorOfPointClear(std::vector<cv::Point>* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfPointCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfPointPush($vecV, $v[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfPointClear", $sVDllType, $vecV), "VectorOfPointClear", @error)

    If $bVIsArray Then
        _VectorOfPointRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfPointClear

Func _VectorOfPointRelease($v)
    ; CVAPI(void) VectorOfPointRelease(std::vector<cv::Point>** v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfPointCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfPointPush($vecV, $v[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfPointRelease", $sVDllType, $vecV), "VectorOfPointRelease", @error)

    If $bVIsArray Then
        _VectorOfPointRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfPointRelease

Func _VectorOfPointCopyData($v, $data)
    ; CVAPI(void) VectorOfPointCopyData(std::vector<cv::Point>* v, cv::Point* data);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfPointCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfPointPush($vecV, $v[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfPointCopyData", $sVDllType, $vecV, $sDataDllType, $data), "VectorOfPointCopyData", @error)

    If $bVIsArray Then
        _VectorOfPointRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfPointCopyData

Func _VectorOfPointGetStartAddress($v)
    ; CVAPI(cv::Point*) VectorOfPointGetStartAddress(std::vector<cv::Point>* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfPointCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfPointPush($vecV, $v[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfPointGetStartAddress", $sVDllType, $vecV), "VectorOfPointGetStartAddress", @error)

    If $bVIsArray Then
        _VectorOfPointRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfPointGetStartAddress

Func _VectorOfPointGetEndAddress($v)
    ; CVAPI(void*) VectorOfPointGetEndAddress(std::vector<cv::Point>* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfPointCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfPointPush($vecV, $v[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfPointGetEndAddress", $sVDllType, $vecV), "VectorOfPointGetEndAddress", @error)

    If $bVIsArray Then
        _VectorOfPointRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfPointGetEndAddress

Func _VectorOfPointGetItem($vec, $index, $element)
    ; CVAPI(void) VectorOfPointGetItem(std::vector<cv::Point>* vec, int index, cv::Point* element);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfPointCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfPointPush($vecVec, $vec[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfPointGetItem", $sVecDllType, $vecVec, "int", $index, $sElementDllType, $element), "VectorOfPointGetItem", @error)

    If $bVecIsArray Then
        _VectorOfPointRelease($vecVec)
    EndIf
EndFunc   ;==>_VectorOfPointGetItem

Func _VectorOfPointGetItemPtr($vec, $index, $element)
    ; CVAPI(void) VectorOfPointGetItemPtr(std::vector<cv::Point>* vec, int index, cv::Point** element);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfPointCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfPointPush($vecVec, $vec[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfPointGetItemPtr", $sVecDllType, $vecVec, "int", $index, $sElementDllType, $element), "VectorOfPointGetItemPtr", @error)

    If $bVecIsArray Then
        _VectorOfPointRelease($vecVec)
    EndIf
EndFunc   ;==>_VectorOfPointGetItemPtr

Func _cveInputArrayFromVectorOfPoint($vec)
    ; CVAPI(cv::_InputArray*) cveInputArrayFromVectorOfPoint(std::vector<cv::Point>* vec);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfPointCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfPointPush($vecVec, $vec[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveInputArrayFromVectorOfPoint", $sVecDllType, $vecVec), "cveInputArrayFromVectorOfPoint", @error)

    If $bVecIsArray Then
        _VectorOfPointRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveInputArrayFromVectorOfPoint

Func _cveOutputArrayFromVectorOfPoint($vec)
    ; CVAPI(cv::_OutputArray*) cveOutputArrayFromVectorOfPoint(std::vector<cv::Point>* vec);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfPointCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfPointPush($vecVec, $vec[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveOutputArrayFromVectorOfPoint", $sVecDllType, $vecVec), "cveOutputArrayFromVectorOfPoint", @error)

    If $bVecIsArray Then
        _VectorOfPointRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveOutputArrayFromVectorOfPoint

Func _cveInputOutputArrayFromVectorOfPoint($vec)
    ; CVAPI(cv::_InputOutputArray*) cveInputOutputArrayFromVectorOfPoint(std::vector<cv::Point>* vec);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfPointCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfPointPush($vecVec, $vec[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveInputOutputArrayFromVectorOfPoint", $sVecDllType, $vecVec), "cveInputOutputArrayFromVectorOfPoint", @error)

    If $bVecIsArray Then
        _VectorOfPointRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveInputOutputArrayFromVectorOfPoint

Func _VectorOfPointSizeOfItemInBytes()
    ; CVAPI(int) VectorOfPointSizeOfItemInBytes();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "VectorOfPointSizeOfItemInBytes"), "VectorOfPointSizeOfItemInBytes", @error)
EndFunc   ;==>_VectorOfPointSizeOfItemInBytes