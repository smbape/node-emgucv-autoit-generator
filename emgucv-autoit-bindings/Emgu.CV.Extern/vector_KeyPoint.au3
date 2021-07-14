#include-once
#include "..\CVEUtils.au3"

Func _VectorOfKeyPointCreate()
    ; CVAPI(std::vector< cv::KeyPoint >*) VectorOfKeyPointCreate();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfKeyPointCreate"), "VectorOfKeyPointCreate", @error)
EndFunc   ;==>_VectorOfKeyPointCreate

Func _VectorOfKeyPointCreateSize($size)
    ; CVAPI(std::vector< cv::KeyPoint >*) VectorOfKeyPointCreateSize(int size);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfKeyPointCreateSize", "int", $size), "VectorOfKeyPointCreateSize", @error)
EndFunc   ;==>_VectorOfKeyPointCreateSize

Func _VectorOfKeyPointGetSize(ByRef $v)
    ; CVAPI(int) VectorOfKeyPointGetSize(std::vector< cv::KeyPoint >* v);

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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "VectorOfKeyPointGetSize", "ptr", $vecV), "VectorOfKeyPointGetSize", @error)

    If $bVIsArray Then
        _VectorOfKeyPointRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfKeyPointGetSize

Func _VectorOfKeyPointPush(ByRef $v, ByRef $value)
    ; CVAPI(void) VectorOfKeyPointPush(std::vector< cv::KeyPoint >* v, cv::KeyPoint* value);

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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfKeyPointPush", "ptr", $vecV, "ptr", $value), "VectorOfKeyPointPush", @error)

    If $bVIsArray Then
        _VectorOfKeyPointRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfKeyPointPush

Func _VectorOfKeyPointPushMulti(ByRef $v, ByRef $values, $count)
    ; CVAPI(void) VectorOfKeyPointPushMulti(std::vector< cv::KeyPoint >* v, cv::KeyPoint* values, int count);

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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfKeyPointPushMulti", "ptr", $vecV, "ptr", $values, "int", $count), "VectorOfKeyPointPushMulti", @error)

    If $bVIsArray Then
        _VectorOfKeyPointRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfKeyPointPushMulti

Func _VectorOfKeyPointPushVector(ByRef $v, ByRef $other)
    ; CVAPI(void) VectorOfKeyPointPushVector(std::vector< cv::KeyPoint >* v, std::vector< cv::KeyPoint >* other);

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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfKeyPointPushVector", "ptr", $vecV, "ptr", $vecOther), "VectorOfKeyPointPushVector", @error)

    If $bOtherIsArray Then
        _VectorOfKeyPointRelease($vecOther)
    EndIf

    If $bVIsArray Then
        _VectorOfKeyPointRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfKeyPointPushVector

Func _VectorOfKeyPointClear(ByRef $v)
    ; CVAPI(void) VectorOfKeyPointClear(std::vector< cv::KeyPoint >* v);

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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfKeyPointClear", "ptr", $vecV), "VectorOfKeyPointClear", @error)

    If $bVIsArray Then
        _VectorOfKeyPointRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfKeyPointClear

Func _VectorOfKeyPointRelease(ByRef $v)
    ; CVAPI(void) VectorOfKeyPointRelease(std::vector< cv::KeyPoint >** v);

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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfKeyPointRelease", "ptr*", $vecV), "VectorOfKeyPointRelease", @error)

    If $bVIsArray Then
        _VectorOfKeyPointRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfKeyPointRelease

Func _VectorOfKeyPointCopyData(ByRef $v, ByRef $data)
    ; CVAPI(void) VectorOfKeyPointCopyData(std::vector< cv::KeyPoint >* v, cv::KeyPoint* data);

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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfKeyPointCopyData", "ptr", $vecV, "ptr", $data), "VectorOfKeyPointCopyData", @error)

    If $bVIsArray Then
        _VectorOfKeyPointRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfKeyPointCopyData

Func _VectorOfKeyPointGetStartAddress(ByRef $v)
    ; CVAPI(cv::KeyPoint*) VectorOfKeyPointGetStartAddress(std::vector< cv::KeyPoint >* v);

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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfKeyPointGetStartAddress", "ptr", $vecV), "VectorOfKeyPointGetStartAddress", @error)

    If $bVIsArray Then
        _VectorOfKeyPointRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfKeyPointGetStartAddress

Func _VectorOfKeyPointGetEndAddress(ByRef $v)
    ; CVAPI(void*) VectorOfKeyPointGetEndAddress(std::vector< cv::KeyPoint >* v);

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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfKeyPointGetEndAddress", "ptr", $vecV), "VectorOfKeyPointGetEndAddress", @error)

    If $bVIsArray Then
        _VectorOfKeyPointRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfKeyPointGetEndAddress

Func _VectorOfKeyPointGetItem(ByRef $vec, $index, ByRef $element)
    ; CVAPI(void) VectorOfKeyPointGetItem(std::vector<  cv::KeyPoint >* vec, int index, cv::KeyPoint* element);

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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfKeyPointGetItem", "ptr", $vecVec, "int", $index, "ptr", $element), "VectorOfKeyPointGetItem", @error)

    If $bVecIsArray Then
        _VectorOfKeyPointRelease($vecVec)
    EndIf
EndFunc   ;==>_VectorOfKeyPointGetItem

Func _VectorOfKeyPointGetItemPtr(ByRef $vec, $index, ByRef $element)
    ; CVAPI(void) VectorOfKeyPointGetItemPtr(std::vector<  cv::KeyPoint >* vec, int index, cv::KeyPoint** element);

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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfKeyPointGetItemPtr", "ptr", $vecVec, "int", $index, "ptr*", $element), "VectorOfKeyPointGetItemPtr", @error)

    If $bVecIsArray Then
        _VectorOfKeyPointRelease($vecVec)
    EndIf
EndFunc   ;==>_VectorOfKeyPointGetItemPtr

Func _cveInputArrayFromVectorOfKeyPoint(ByRef $vec)
    ; CVAPI(cv::_InputArray*) cveInputArrayFromVectorOfKeyPoint(std::vector< cv::KeyPoint >* vec);

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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveInputArrayFromVectorOfKeyPoint", "ptr", $vecVec), "cveInputArrayFromVectorOfKeyPoint", @error)

    If $bVecIsArray Then
        _VectorOfKeyPointRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveInputArrayFromVectorOfKeyPoint

Func _cveOutputArrayFromVectorOfKeyPoint(ByRef $vec)
    ; CVAPI(cv::_OutputArray*) cveOutputArrayFromVectorOfKeyPoint(std::vector< cv::KeyPoint >* vec);

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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveOutputArrayFromVectorOfKeyPoint", "ptr", $vecVec), "cveOutputArrayFromVectorOfKeyPoint", @error)

    If $bVecIsArray Then
        _VectorOfKeyPointRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveOutputArrayFromVectorOfKeyPoint

Func _cveInputOutputArrayFromVectorOfKeyPoint(ByRef $vec)
    ; CVAPI(cv::_InputOutputArray*) cveInputOutputArrayFromVectorOfKeyPoint(std::vector< cv::KeyPoint >* vec);

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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveInputOutputArrayFromVectorOfKeyPoint", "ptr", $vecVec), "cveInputOutputArrayFromVectorOfKeyPoint", @error)

    If $bVecIsArray Then
        _VectorOfKeyPointRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveInputOutputArrayFromVectorOfKeyPoint

Func _VectorOfKeyPointSizeOfItemInBytes()
    ; CVAPI(int) VectorOfKeyPointSizeOfItemInBytes();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "VectorOfKeyPointSizeOfItemInBytes"), "VectorOfKeyPointSizeOfItemInBytes", @error)
EndFunc   ;==>_VectorOfKeyPointSizeOfItemInBytes