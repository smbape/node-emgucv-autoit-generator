#include-once
#include <..\CVEUtils.au3>

Func _VectorOfColorPointCreate()
    ; CVAPI(std::vector< ColorPoint >*) VectorOfColorPointCreate();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfColorPointCreate"), "VectorOfColorPointCreate", @error)
EndFunc   ;==>_VectorOfColorPointCreate

Func _VectorOfColorPointCreateSize($size)
    ; CVAPI(std::vector< ColorPoint >*) VectorOfColorPointCreateSize(int size);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfColorPointCreateSize", "int", $size), "VectorOfColorPointCreateSize", @error)
EndFunc   ;==>_VectorOfColorPointCreateSize

Func _VectorOfColorPointGetSize(ByRef $v)
    ; CVAPI(int) VectorOfColorPointGetSize(std::vector< ColorPoint >* v);

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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "VectorOfColorPointGetSize", "ptr", $vecV), "VectorOfColorPointGetSize", @error)

    If $bVIsArray Then
        _VectorOfColorPointRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfColorPointGetSize

Func _VectorOfColorPointPush(ByRef $v, ByRef $value)
    ; CVAPI(void) VectorOfColorPointPush(std::vector< ColorPoint >* v, ColorPoint* value);

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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfColorPointPush", "ptr", $vecV, "struct*", $value), "VectorOfColorPointPush", @error)

    If $bVIsArray Then
        _VectorOfColorPointRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfColorPointPush

Func _VectorOfColorPointPushMulti(ByRef $v, ByRef $values, $count)
    ; CVAPI(void) VectorOfColorPointPushMulti(std::vector< ColorPoint >* v, ColorPoint* values, int count);

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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfColorPointPushMulti", "ptr", $vecV, "struct*", $values, "int", $count), "VectorOfColorPointPushMulti", @error)

    If $bVIsArray Then
        _VectorOfColorPointRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfColorPointPushMulti

Func _VectorOfColorPointPushVector(ByRef $v, ByRef $other)
    ; CVAPI(void) VectorOfColorPointPushVector(std::vector< ColorPoint >* v, std::vector< ColorPoint >* other);

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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfColorPointPushVector", "ptr", $vecV, "ptr", $vecOther), "VectorOfColorPointPushVector", @error)

    If $bOtherIsArray Then
        _VectorOfColorPointRelease($vecOther)
    EndIf

    If $bVIsArray Then
        _VectorOfColorPointRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfColorPointPushVector

Func _VectorOfColorPointClear(ByRef $v)
    ; CVAPI(void) VectorOfColorPointClear(std::vector< ColorPoint >* v);

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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfColorPointClear", "ptr", $vecV), "VectorOfColorPointClear", @error)

    If $bVIsArray Then
        _VectorOfColorPointRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfColorPointClear

Func _VectorOfColorPointRelease(ByRef $v)
    ; CVAPI(void) VectorOfColorPointRelease(std::vector< ColorPoint >** v);

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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfColorPointRelease", "ptr*", $vecV), "VectorOfColorPointRelease", @error)

    If $bVIsArray Then
        _VectorOfColorPointRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfColorPointRelease

Func _VectorOfColorPointCopyData(ByRef $v, ByRef $data)
    ; CVAPI(void) VectorOfColorPointCopyData(std::vector< ColorPoint >* v, ColorPoint* data);

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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfColorPointCopyData", "ptr", $vecV, "struct*", $data), "VectorOfColorPointCopyData", @error)

    If $bVIsArray Then
        _VectorOfColorPointRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfColorPointCopyData

Func _VectorOfColorPointGetStartAddress(ByRef $v)
    ; CVAPI(ColorPoint*) VectorOfColorPointGetStartAddress(std::vector< ColorPoint >* v);

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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfColorPointGetStartAddress", "ptr", $vecV), "VectorOfColorPointGetStartAddress", @error)

    If $bVIsArray Then
        _VectorOfColorPointRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfColorPointGetStartAddress

Func _VectorOfColorPointGetEndAddress(ByRef $v)
    ; CVAPI(void*) VectorOfColorPointGetEndAddress(std::vector< ColorPoint >* v);

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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfColorPointGetEndAddress", "ptr", $vecV), "VectorOfColorPointGetEndAddress", @error)

    If $bVIsArray Then
        _VectorOfColorPointRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfColorPointGetEndAddress

Func _VectorOfColorPointGetItem(ByRef $vec, $index, ByRef $element)
    ; CVAPI(void) VectorOfColorPointGetItem(std::vector<  ColorPoint >* vec, int index, ColorPoint* element);

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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfColorPointGetItem", "ptr", $vecVec, "int", $index, "struct*", $element), "VectorOfColorPointGetItem", @error)

    If $bVecIsArray Then
        _VectorOfColorPointRelease($vecVec)
    EndIf
EndFunc   ;==>_VectorOfColorPointGetItem

Func _VectorOfColorPointGetItemPtr(ByRef $vec, $index, ByRef $element)
    ; CVAPI(void) VectorOfColorPointGetItemPtr(std::vector<  ColorPoint >* vec, int index, ColorPoint** element);

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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfColorPointGetItemPtr", "ptr", $vecVec, "int", $index, "ptr*", $element), "VectorOfColorPointGetItemPtr", @error)

    If $bVecIsArray Then
        _VectorOfColorPointRelease($vecVec)
    EndIf
EndFunc   ;==>_VectorOfColorPointGetItemPtr

Func _cveInputArrayFromVectorOfColorPoint(ByRef $vec)
    ; CVAPI(cv::_InputArray*) cveInputArrayFromVectorOfColorPoint(std::vector< ColorPoint >* vec);

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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveInputArrayFromVectorOfColorPoint", "ptr", $vecVec), "cveInputArrayFromVectorOfColorPoint", @error)

    If $bVecIsArray Then
        _VectorOfColorPointRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveInputArrayFromVectorOfColorPoint

Func _cveOutputArrayFromVectorOfColorPoint(ByRef $vec)
    ; CVAPI(cv::_OutputArray*) cveOutputArrayFromVectorOfColorPoint(std::vector< ColorPoint >* vec);

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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveOutputArrayFromVectorOfColorPoint", "ptr", $vecVec), "cveOutputArrayFromVectorOfColorPoint", @error)

    If $bVecIsArray Then
        _VectorOfColorPointRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveOutputArrayFromVectorOfColorPoint

Func _cveInputOutputArrayFromVectorOfColorPoint(ByRef $vec)
    ; CVAPI(cv::_InputOutputArray*) cveInputOutputArrayFromVectorOfColorPoint(std::vector< ColorPoint >* vec);

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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveInputOutputArrayFromVectorOfColorPoint", "ptr", $vecVec), "cveInputOutputArrayFromVectorOfColorPoint", @error)

    If $bVecIsArray Then
        _VectorOfColorPointRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveInputOutputArrayFromVectorOfColorPoint

Func _VectorOfColorPointSizeOfItemInBytes()
    ; CVAPI(int) VectorOfColorPointSizeOfItemInBytes();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "VectorOfColorPointSizeOfItemInBytes"), "VectorOfColorPointSizeOfItemInBytes", @error)
EndFunc   ;==>_VectorOfColorPointSizeOfItemInBytes