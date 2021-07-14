#include-once
#include <..\CVEUtils.au3>

Func _VectorOfPointCreate()
    ; CVAPI(std::vector< cv::Point >*) VectorOfPointCreate();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfPointCreate"), "VectorOfPointCreate", @error)
EndFunc   ;==>_VectorOfPointCreate

Func _VectorOfPointCreateSize($size)
    ; CVAPI(std::vector< cv::Point >*) VectorOfPointCreateSize(int size);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfPointCreateSize", "int", $size), "VectorOfPointCreateSize", @error)
EndFunc   ;==>_VectorOfPointCreateSize

Func _VectorOfPointGetSize(ByRef $v)
    ; CVAPI(int) VectorOfPointGetSize(std::vector< cv::Point >* v);

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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "VectorOfPointGetSize", "ptr", $vecV), "VectorOfPointGetSize", @error)

    If $bVIsArray Then
        _VectorOfPointRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfPointGetSize

Func _VectorOfPointPush(ByRef $v, ByRef $value)
    ; CVAPI(void) VectorOfPointPush(std::vector< cv::Point >* v, cv::Point* value);

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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfPointPush", "ptr", $vecV, "ptr", $value), "VectorOfPointPush", @error)

    If $bVIsArray Then
        _VectorOfPointRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfPointPush

Func _VectorOfPointPushMulti(ByRef $v, ByRef $values, $count)
    ; CVAPI(void) VectorOfPointPushMulti(std::vector< cv::Point >* v, cv::Point* values, int count);

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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfPointPushMulti", "ptr", $vecV, "ptr", $values, "int", $count), "VectorOfPointPushMulti", @error)

    If $bVIsArray Then
        _VectorOfPointRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfPointPushMulti

Func _VectorOfPointPushVector(ByRef $v, ByRef $other)
    ; CVAPI(void) VectorOfPointPushVector(std::vector< cv::Point >* v, std::vector< cv::Point >* other);

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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfPointPushVector", "ptr", $vecV, "ptr", $vecOther), "VectorOfPointPushVector", @error)

    If $bOtherIsArray Then
        _VectorOfPointRelease($vecOther)
    EndIf

    If $bVIsArray Then
        _VectorOfPointRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfPointPushVector

Func _VectorOfPointClear(ByRef $v)
    ; CVAPI(void) VectorOfPointClear(std::vector< cv::Point >* v);

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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfPointClear", "ptr", $vecV), "VectorOfPointClear", @error)

    If $bVIsArray Then
        _VectorOfPointRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfPointClear

Func _VectorOfPointRelease(ByRef $v)
    ; CVAPI(void) VectorOfPointRelease(std::vector< cv::Point >** v);

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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfPointRelease", "ptr*", $vecV), "VectorOfPointRelease", @error)

    If $bVIsArray Then
        _VectorOfPointRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfPointRelease

Func _VectorOfPointCopyData(ByRef $v, ByRef $data)
    ; CVAPI(void) VectorOfPointCopyData(std::vector< cv::Point >* v, cv::Point* data);

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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfPointCopyData", "ptr", $vecV, "ptr", $data), "VectorOfPointCopyData", @error)

    If $bVIsArray Then
        _VectorOfPointRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfPointCopyData

Func _VectorOfPointGetStartAddress(ByRef $v)
    ; CVAPI(cv::Point*) VectorOfPointGetStartAddress(std::vector< cv::Point >* v);

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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfPointGetStartAddress", "ptr", $vecV), "VectorOfPointGetStartAddress", @error)

    If $bVIsArray Then
        _VectorOfPointRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfPointGetStartAddress

Func _VectorOfPointGetEndAddress(ByRef $v)
    ; CVAPI(void*) VectorOfPointGetEndAddress(std::vector< cv::Point >* v);

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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfPointGetEndAddress", "ptr", $vecV), "VectorOfPointGetEndAddress", @error)

    If $bVIsArray Then
        _VectorOfPointRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfPointGetEndAddress

Func _VectorOfPointGetItem(ByRef $vec, $index, ByRef $element)
    ; CVAPI(void) VectorOfPointGetItem(std::vector<  cv::Point >* vec, int index, cv::Point* element);

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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfPointGetItem", "ptr", $vecVec, "int", $index, "ptr", $element), "VectorOfPointGetItem", @error)

    If $bVecIsArray Then
        _VectorOfPointRelease($vecVec)
    EndIf
EndFunc   ;==>_VectorOfPointGetItem

Func _VectorOfPointGetItemPtr(ByRef $vec, $index, ByRef $element)
    ; CVAPI(void) VectorOfPointGetItemPtr(std::vector<  cv::Point >* vec, int index, cv::Point** element);

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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfPointGetItemPtr", "ptr", $vecVec, "int", $index, "ptr*", $element), "VectorOfPointGetItemPtr", @error)

    If $bVecIsArray Then
        _VectorOfPointRelease($vecVec)
    EndIf
EndFunc   ;==>_VectorOfPointGetItemPtr

Func _cveInputArrayFromVectorOfPoint(ByRef $vec)
    ; CVAPI(cv::_InputArray*) cveInputArrayFromVectorOfPoint(std::vector< cv::Point >* vec);

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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveInputArrayFromVectorOfPoint", "ptr", $vecVec), "cveInputArrayFromVectorOfPoint", @error)

    If $bVecIsArray Then
        _VectorOfPointRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveInputArrayFromVectorOfPoint

Func _cveOutputArrayFromVectorOfPoint(ByRef $vec)
    ; CVAPI(cv::_OutputArray*) cveOutputArrayFromVectorOfPoint(std::vector< cv::Point >* vec);

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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveOutputArrayFromVectorOfPoint", "ptr", $vecVec), "cveOutputArrayFromVectorOfPoint", @error)

    If $bVecIsArray Then
        _VectorOfPointRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveOutputArrayFromVectorOfPoint

Func _cveInputOutputArrayFromVectorOfPoint(ByRef $vec)
    ; CVAPI(cv::_InputOutputArray*) cveInputOutputArrayFromVectorOfPoint(std::vector< cv::Point >* vec);

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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveInputOutputArrayFromVectorOfPoint", "ptr", $vecVec), "cveInputOutputArrayFromVectorOfPoint", @error)

    If $bVecIsArray Then
        _VectorOfPointRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveInputOutputArrayFromVectorOfPoint

Func _VectorOfPointSizeOfItemInBytes()
    ; CVAPI(int) VectorOfPointSizeOfItemInBytes();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "VectorOfPointSizeOfItemInBytes"), "VectorOfPointSizeOfItemInBytes", @error)
EndFunc   ;==>_VectorOfPointSizeOfItemInBytes