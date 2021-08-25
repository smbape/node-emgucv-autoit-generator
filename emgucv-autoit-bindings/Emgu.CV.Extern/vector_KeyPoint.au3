#include-once
#include "..\CVEUtils.au3"

Func _VectorOfKeyPointCreate()
    ; CVAPI(std::vector<cv::KeyPoint>*) VectorOfKeyPointCreate();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfKeyPointCreate"), "VectorOfKeyPointCreate", @error)
EndFunc   ;==>_VectorOfKeyPointCreate

Func _VectorOfKeyPointCreateSize($size)
    ; CVAPI(std::vector<cv::KeyPoint>*) VectorOfKeyPointCreateSize(int size);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfKeyPointCreateSize", "int", $size), "VectorOfKeyPointCreateSize", @error)
EndFunc   ;==>_VectorOfKeyPointCreateSize

Func _VectorOfKeyPointGetSize($v)
    ; CVAPI(int) VectorOfKeyPointGetSize(std::vector<cv::KeyPoint>* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = IsArray($v)

    If $bVIsArray Then
        $vecV = _VectorOfKeyPointCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfKeyPointPush($vecV, $v[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "VectorOfKeyPointGetSize", $sVDllType, $vecV), "VectorOfKeyPointGetSize", @error)

    If $bVIsArray Then
        _VectorOfKeyPointRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfKeyPointGetSize

Func _VectorOfKeyPointPush($v, $value)
    ; CVAPI(void) VectorOfKeyPointPush(std::vector<cv::KeyPoint>* v, cv::KeyPoint* value);

    Local $vecV, $iArrVSize
    Local $bVIsArray = IsArray($v)

    If $bVIsArray Then
        $vecV = _VectorOfKeyPointCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfKeyPointPush($vecV, $v[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfKeyPointPush", $sVDllType, $vecV, $sValueDllType, $value), "VectorOfKeyPointPush", @error)

    If $bVIsArray Then
        _VectorOfKeyPointRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfKeyPointPush

Func _VectorOfKeyPointPushMulti($v, $values, $count)
    ; CVAPI(void) VectorOfKeyPointPushMulti(std::vector<cv::KeyPoint>* v, cv::KeyPoint* values, int count);

    Local $vecV, $iArrVSize
    Local $bVIsArray = IsArray($v)

    If $bVIsArray Then
        $vecV = _VectorOfKeyPointCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfKeyPointPush($vecV, $v[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfKeyPointPushMulti", $sVDllType, $vecV, $sValuesDllType, $values, "int", $count), "VectorOfKeyPointPushMulti", @error)

    If $bVIsArray Then
        _VectorOfKeyPointRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfKeyPointPushMulti

Func _VectorOfKeyPointPushVector($v, $other)
    ; CVAPI(void) VectorOfKeyPointPushVector(std::vector<cv::KeyPoint>* v, std::vector<cv::KeyPoint>* other);

    Local $vecV, $iArrVSize
    Local $bVIsArray = IsArray($v)

    If $bVIsArray Then
        $vecV = _VectorOfKeyPointCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfKeyPointPush($vecV, $v[$i])
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
        $vecOther = _VectorOfKeyPointCreate()

        $iArrOtherSize = UBound($other)
        For $i = 0 To $iArrOtherSize - 1
            _VectorOfKeyPointPush($vecOther, $other[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfKeyPointPushVector", $sVDllType, $vecV, $sOtherDllType, $vecOther), "VectorOfKeyPointPushVector", @error)

    If $bOtherIsArray Then
        _VectorOfKeyPointRelease($vecOther)
    EndIf

    If $bVIsArray Then
        _VectorOfKeyPointRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfKeyPointPushVector

Func _VectorOfKeyPointClear($v)
    ; CVAPI(void) VectorOfKeyPointClear(std::vector<cv::KeyPoint>* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = IsArray($v)

    If $bVIsArray Then
        $vecV = _VectorOfKeyPointCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfKeyPointPush($vecV, $v[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfKeyPointClear", $sVDllType, $vecV), "VectorOfKeyPointClear", @error)

    If $bVIsArray Then
        _VectorOfKeyPointRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfKeyPointClear

Func _VectorOfKeyPointRelease($v)
    ; CVAPI(void) VectorOfKeyPointRelease(std::vector<cv::KeyPoint>** v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = IsArray($v)

    If $bVIsArray Then
        $vecV = _VectorOfKeyPointCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfKeyPointPush($vecV, $v[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfKeyPointRelease", $sVDllType, $vecV), "VectorOfKeyPointRelease", @error)

    If $bVIsArray Then
        _VectorOfKeyPointRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfKeyPointRelease

Func _VectorOfKeyPointCopyData($v, $data)
    ; CVAPI(void) VectorOfKeyPointCopyData(std::vector<cv::KeyPoint>* v, cv::KeyPoint* data);

    Local $vecV, $iArrVSize
    Local $bVIsArray = IsArray($v)

    If $bVIsArray Then
        $vecV = _VectorOfKeyPointCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfKeyPointPush($vecV, $v[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfKeyPointCopyData", $sVDllType, $vecV, $sDataDllType, $data), "VectorOfKeyPointCopyData", @error)

    If $bVIsArray Then
        _VectorOfKeyPointRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfKeyPointCopyData

Func _VectorOfKeyPointGetStartAddress($v)
    ; CVAPI(cv::KeyPoint*) VectorOfKeyPointGetStartAddress(std::vector<cv::KeyPoint>* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = IsArray($v)

    If $bVIsArray Then
        $vecV = _VectorOfKeyPointCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfKeyPointPush($vecV, $v[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfKeyPointGetStartAddress", $sVDllType, $vecV), "VectorOfKeyPointGetStartAddress", @error)

    If $bVIsArray Then
        _VectorOfKeyPointRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfKeyPointGetStartAddress

Func _VectorOfKeyPointGetEndAddress($v)
    ; CVAPI(void*) VectorOfKeyPointGetEndAddress(std::vector<cv::KeyPoint>* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = IsArray($v)

    If $bVIsArray Then
        $vecV = _VectorOfKeyPointCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfKeyPointPush($vecV, $v[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfKeyPointGetEndAddress", $sVDllType, $vecV), "VectorOfKeyPointGetEndAddress", @error)

    If $bVIsArray Then
        _VectorOfKeyPointRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfKeyPointGetEndAddress

Func _VectorOfKeyPointGetItem($vec, $index, $element)
    ; CVAPI(void) VectorOfKeyPointGetItem(std::vector<cv::KeyPoint>* vec, int index, cv::KeyPoint* element);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = IsArray($vec)

    If $bVecIsArray Then
        $vecVec = _VectorOfKeyPointCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfKeyPointPush($vecVec, $vec[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfKeyPointGetItem", $sVecDllType, $vecVec, "int", $index, $sElementDllType, $element), "VectorOfKeyPointGetItem", @error)

    If $bVecIsArray Then
        _VectorOfKeyPointRelease($vecVec)
    EndIf
EndFunc   ;==>_VectorOfKeyPointGetItem

Func _VectorOfKeyPointGetItemPtr($vec, $index, $element)
    ; CVAPI(void) VectorOfKeyPointGetItemPtr(std::vector<cv::KeyPoint>* vec, int index, cv::KeyPoint** element);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = IsArray($vec)

    If $bVecIsArray Then
        $vecVec = _VectorOfKeyPointCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfKeyPointPush($vecVec, $vec[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfKeyPointGetItemPtr", $sVecDllType, $vecVec, "int", $index, $sElementDllType, $element), "VectorOfKeyPointGetItemPtr", @error)

    If $bVecIsArray Then
        _VectorOfKeyPointRelease($vecVec)
    EndIf
EndFunc   ;==>_VectorOfKeyPointGetItemPtr

Func _cveInputArrayFromVectorOfKeyPoint($vec)
    ; CVAPI(cv::_InputArray*) cveInputArrayFromVectorOfKeyPoint(std::vector<cv::KeyPoint>* vec);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = IsArray($vec)

    If $bVecIsArray Then
        $vecVec = _VectorOfKeyPointCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfKeyPointPush($vecVec, $vec[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveInputArrayFromVectorOfKeyPoint", $sVecDllType, $vecVec), "cveInputArrayFromVectorOfKeyPoint", @error)

    If $bVecIsArray Then
        _VectorOfKeyPointRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveInputArrayFromVectorOfKeyPoint

Func _cveOutputArrayFromVectorOfKeyPoint($vec)
    ; CVAPI(cv::_OutputArray*) cveOutputArrayFromVectorOfKeyPoint(std::vector<cv::KeyPoint>* vec);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = IsArray($vec)

    If $bVecIsArray Then
        $vecVec = _VectorOfKeyPointCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfKeyPointPush($vecVec, $vec[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveOutputArrayFromVectorOfKeyPoint", $sVecDllType, $vecVec), "cveOutputArrayFromVectorOfKeyPoint", @error)

    If $bVecIsArray Then
        _VectorOfKeyPointRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveOutputArrayFromVectorOfKeyPoint

Func _cveInputOutputArrayFromVectorOfKeyPoint($vec)
    ; CVAPI(cv::_InputOutputArray*) cveInputOutputArrayFromVectorOfKeyPoint(std::vector<cv::KeyPoint>* vec);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = IsArray($vec)

    If $bVecIsArray Then
        $vecVec = _VectorOfKeyPointCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfKeyPointPush($vecVec, $vec[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveInputOutputArrayFromVectorOfKeyPoint", $sVecDllType, $vecVec), "cveInputOutputArrayFromVectorOfKeyPoint", @error)

    If $bVecIsArray Then
        _VectorOfKeyPointRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveInputOutputArrayFromVectorOfKeyPoint

Func _VectorOfKeyPointSizeOfItemInBytes()
    ; CVAPI(int) VectorOfKeyPointSizeOfItemInBytes();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "VectorOfKeyPointSizeOfItemInBytes"), "VectorOfKeyPointSizeOfItemInBytes", @error)
EndFunc   ;==>_VectorOfKeyPointSizeOfItemInBytes