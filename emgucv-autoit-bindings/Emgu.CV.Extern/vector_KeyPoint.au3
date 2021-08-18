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
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfKeyPointCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfKeyPointPush($vecV, $v[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "VectorOfKeyPointGetSize", $bVDllType, $vecV), "VectorOfKeyPointGetSize", @error)

    If $bVIsArray Then
        _VectorOfKeyPointRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfKeyPointGetSize

Func _VectorOfKeyPointPush($v, $value)
    ; CVAPI(void) VectorOfKeyPointPush(std::vector<cv::KeyPoint>* v, cv::KeyPoint* value);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfKeyPointCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfKeyPointPush($vecV, $v[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfKeyPointPush", $bVDllType, $vecV, $bValueDllType, $value), "VectorOfKeyPointPush", @error)

    If $bVIsArray Then
        _VectorOfKeyPointRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfKeyPointPush

Func _VectorOfKeyPointPushMulti($v, $values, $count)
    ; CVAPI(void) VectorOfKeyPointPushMulti(std::vector<cv::KeyPoint>* v, cv::KeyPoint* values, int count);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfKeyPointCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfKeyPointPush($vecV, $v[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfKeyPointPushMulti", $bVDllType, $vecV, $bValuesDllType, $values, "int", $count), "VectorOfKeyPointPushMulti", @error)

    If $bVIsArray Then
        _VectorOfKeyPointRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfKeyPointPushMulti

Func _VectorOfKeyPointPushVector($v, $other)
    ; CVAPI(void) VectorOfKeyPointPushVector(std::vector<cv::KeyPoint>* v, std::vector<cv::KeyPoint>* other);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfKeyPointCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfKeyPointPush($vecV, $v[$i])
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
        $vecOther = _VectorOfKeyPointCreate()

        $iArrOtherSize = UBound($other)
        For $i = 0 To $iArrOtherSize - 1
            _VectorOfKeyPointPush($vecOther, $other[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfKeyPointPushVector", $bVDllType, $vecV, $bOtherDllType, $vecOther), "VectorOfKeyPointPushVector", @error)

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
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfKeyPointCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfKeyPointPush($vecV, $v[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfKeyPointClear", $bVDllType, $vecV), "VectorOfKeyPointClear", @error)

    If $bVIsArray Then
        _VectorOfKeyPointRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfKeyPointClear

Func _VectorOfKeyPointRelease($v)
    ; CVAPI(void) VectorOfKeyPointRelease(std::vector<cv::KeyPoint>** v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfKeyPointCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfKeyPointPush($vecV, $v[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfKeyPointRelease", $bVDllType, $vecV), "VectorOfKeyPointRelease", @error)

    If $bVIsArray Then
        _VectorOfKeyPointRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfKeyPointRelease

Func _VectorOfKeyPointCopyData($v, $data)
    ; CVAPI(void) VectorOfKeyPointCopyData(std::vector<cv::KeyPoint>* v, cv::KeyPoint* data);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfKeyPointCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfKeyPointPush($vecV, $v[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfKeyPointCopyData", $bVDllType, $vecV, $bDataDllType, $data), "VectorOfKeyPointCopyData", @error)

    If $bVIsArray Then
        _VectorOfKeyPointRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfKeyPointCopyData

Func _VectorOfKeyPointGetStartAddress($v)
    ; CVAPI(cv::KeyPoint*) VectorOfKeyPointGetStartAddress(std::vector<cv::KeyPoint>* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfKeyPointCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfKeyPointPush($vecV, $v[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfKeyPointGetStartAddress", $bVDllType, $vecV), "VectorOfKeyPointGetStartAddress", @error)

    If $bVIsArray Then
        _VectorOfKeyPointRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfKeyPointGetStartAddress

Func _VectorOfKeyPointGetEndAddress($v)
    ; CVAPI(void*) VectorOfKeyPointGetEndAddress(std::vector<cv::KeyPoint>* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfKeyPointCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfKeyPointPush($vecV, $v[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfKeyPointGetEndAddress", $bVDllType, $vecV), "VectorOfKeyPointGetEndAddress", @error)

    If $bVIsArray Then
        _VectorOfKeyPointRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfKeyPointGetEndAddress

Func _VectorOfKeyPointGetItem($vec, $index, $element)
    ; CVAPI(void) VectorOfKeyPointGetItem(std::vector<cv::KeyPoint>* vec, int index, cv::KeyPoint* element);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfKeyPointCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfKeyPointPush($vecVec, $vec[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfKeyPointGetItem", $bVecDllType, $vecVec, "int", $index, $bElementDllType, $element), "VectorOfKeyPointGetItem", @error)

    If $bVecIsArray Then
        _VectorOfKeyPointRelease($vecVec)
    EndIf
EndFunc   ;==>_VectorOfKeyPointGetItem

Func _VectorOfKeyPointGetItemPtr($vec, $index, $element)
    ; CVAPI(void) VectorOfKeyPointGetItemPtr(std::vector<cv::KeyPoint>* vec, int index, cv::KeyPoint** element);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfKeyPointCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfKeyPointPush($vecVec, $vec[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfKeyPointGetItemPtr", $bVecDllType, $vecVec, "int", $index, $bElementDllType, $element), "VectorOfKeyPointGetItemPtr", @error)

    If $bVecIsArray Then
        _VectorOfKeyPointRelease($vecVec)
    EndIf
EndFunc   ;==>_VectorOfKeyPointGetItemPtr

Func _cveInputArrayFromVectorOfKeyPoint($vec)
    ; CVAPI(cv::_InputArray*) cveInputArrayFromVectorOfKeyPoint(std::vector<cv::KeyPoint>* vec);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfKeyPointCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfKeyPointPush($vecVec, $vec[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveInputArrayFromVectorOfKeyPoint", $bVecDllType, $vecVec), "cveInputArrayFromVectorOfKeyPoint", @error)

    If $bVecIsArray Then
        _VectorOfKeyPointRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveInputArrayFromVectorOfKeyPoint

Func _cveOutputArrayFromVectorOfKeyPoint($vec)
    ; CVAPI(cv::_OutputArray*) cveOutputArrayFromVectorOfKeyPoint(std::vector<cv::KeyPoint>* vec);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfKeyPointCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfKeyPointPush($vecVec, $vec[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveOutputArrayFromVectorOfKeyPoint", $bVecDllType, $vecVec), "cveOutputArrayFromVectorOfKeyPoint", @error)

    If $bVecIsArray Then
        _VectorOfKeyPointRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveOutputArrayFromVectorOfKeyPoint

Func _cveInputOutputArrayFromVectorOfKeyPoint($vec)
    ; CVAPI(cv::_InputOutputArray*) cveInputOutputArrayFromVectorOfKeyPoint(std::vector<cv::KeyPoint>* vec);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfKeyPointCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfKeyPointPush($vecVec, $vec[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveInputOutputArrayFromVectorOfKeyPoint", $bVecDllType, $vecVec), "cveInputOutputArrayFromVectorOfKeyPoint", @error)

    If $bVecIsArray Then
        _VectorOfKeyPointRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveInputOutputArrayFromVectorOfKeyPoint

Func _VectorOfKeyPointSizeOfItemInBytes()
    ; CVAPI(int) VectorOfKeyPointSizeOfItemInBytes();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "VectorOfKeyPointSizeOfItemInBytes"), "VectorOfKeyPointSizeOfItemInBytes", @error)
EndFunc   ;==>_VectorOfKeyPointSizeOfItemInBytes