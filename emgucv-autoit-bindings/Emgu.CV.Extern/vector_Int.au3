#include-once
#include <..\CVEUtils.au3>

Func _VectorOfIntCreate()
    ; CVAPI(std::vector< int >*) VectorOfIntCreate();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfIntCreate"), "VectorOfIntCreate", @error)
EndFunc   ;==>_VectorOfIntCreate

Func _VectorOfIntCreateSize($size)
    ; CVAPI(std::vector< int >*) VectorOfIntCreateSize(int size);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfIntCreateSize", "int", $size), "VectorOfIntCreateSize", @error)
EndFunc   ;==>_VectorOfIntCreateSize

Func _VectorOfIntGetSize(ByRef $v)
    ; CVAPI(int) VectorOfIntGetSize(std::vector< int >* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfIntCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfIntPush($vecV, $v[$i])
        Next
    Else
        $vecV = $v
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "VectorOfIntGetSize", "ptr", $vecV), "VectorOfIntGetSize", @error)

    If $bVIsArray Then
        _VectorOfIntRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfIntGetSize

Func _VectorOfIntPush(ByRef $v, ByRef $value)
    ; CVAPI(void) VectorOfIntPush(std::vector< int >* v, int* value);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfIntCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfIntPush($vecV, $v[$i])
        Next
    Else
        $vecV = $v
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfIntPush", "ptr", $vecV, "int*", $value), "VectorOfIntPush", @error)

    If $bVIsArray Then
        _VectorOfIntRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfIntPush

Func _VectorOfIntPushMulti(ByRef $v, ByRef $values, $count)
    ; CVAPI(void) VectorOfIntPushMulti(std::vector< int >* v, int* values, int count);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfIntCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfIntPush($vecV, $v[$i])
        Next
    Else
        $vecV = $v
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfIntPushMulti", "ptr", $vecV, "struct*", $values, "int", $count), "VectorOfIntPushMulti", @error)

    If $bVIsArray Then
        _VectorOfIntRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfIntPushMulti

Func _VectorOfIntPushVector(ByRef $v, ByRef $other)
    ; CVAPI(void) VectorOfIntPushVector(std::vector< int >* v, std::vector< int >* other);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfIntCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfIntPush($vecV, $v[$i])
        Next
    Else
        $vecV = $v
    EndIf

    Local $vecOther, $iArrOtherSize
    Local $bOtherIsArray = VarGetType($other) == "Array"

    If $bOtherIsArray Then
        $vecOther = _VectorOfIntCreate()

        $iArrOtherSize = UBound($other)
        For $i = 0 To $iArrOtherSize - 1
            _VectorOfIntPush($vecOther, $other[$i])
        Next
    Else
        $vecOther = $other
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfIntPushVector", "ptr", $vecV, "ptr", $vecOther), "VectorOfIntPushVector", @error)

    If $bOtherIsArray Then
        _VectorOfIntRelease($vecOther)
    EndIf

    If $bVIsArray Then
        _VectorOfIntRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfIntPushVector

Func _VectorOfIntClear(ByRef $v)
    ; CVAPI(void) VectorOfIntClear(std::vector< int >* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfIntCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfIntPush($vecV, $v[$i])
        Next
    Else
        $vecV = $v
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfIntClear", "ptr", $vecV), "VectorOfIntClear", @error)

    If $bVIsArray Then
        _VectorOfIntRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfIntClear

Func _VectorOfIntRelease(ByRef $v)
    ; CVAPI(void) VectorOfIntRelease(std::vector< int >** v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfIntCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfIntPush($vecV, $v[$i])
        Next
    Else
        $vecV = $v
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfIntRelease", "ptr*", $vecV), "VectorOfIntRelease", @error)

    If $bVIsArray Then
        _VectorOfIntRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfIntRelease

Func _VectorOfIntCopyData(ByRef $v, ByRef $data)
    ; CVAPI(void) VectorOfIntCopyData(std::vector< int >* v, int* data);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfIntCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfIntPush($vecV, $v[$i])
        Next
    Else
        $vecV = $v
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfIntCopyData", "ptr", $vecV, "struct*", $data), "VectorOfIntCopyData", @error)

    If $bVIsArray Then
        _VectorOfIntRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfIntCopyData

Func _VectorOfIntGetStartAddress(ByRef $v)
    ; CVAPI(int*) VectorOfIntGetStartAddress(std::vector< int >* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfIntCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfIntPush($vecV, $v[$i])
        Next
    Else
        $vecV = $v
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfIntGetStartAddress", "ptr", $vecV), "VectorOfIntGetStartAddress", @error)

    If $bVIsArray Then
        _VectorOfIntRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfIntGetStartAddress

Func _VectorOfIntGetEndAddress(ByRef $v)
    ; CVAPI(void*) VectorOfIntGetEndAddress(std::vector< int >* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfIntCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfIntPush($vecV, $v[$i])
        Next
    Else
        $vecV = $v
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfIntGetEndAddress", "ptr", $vecV), "VectorOfIntGetEndAddress", @error)

    If $bVIsArray Then
        _VectorOfIntRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfIntGetEndAddress

Func _VectorOfIntGetItem(ByRef $vec, $index, ByRef $element)
    ; CVAPI(void) VectorOfIntGetItem(std::vector<  int >* vec, int index, int* element);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfIntCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfIntPush($vecVec, $vec[$i])
        Next
    Else
        $vecVec = $vec
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfIntGetItem", "ptr", $vecVec, "int", $index, "struct*", $element), "VectorOfIntGetItem", @error)

    If $bVecIsArray Then
        _VectorOfIntRelease($vecVec)
    EndIf
EndFunc   ;==>_VectorOfIntGetItem

Func _VectorOfIntGetItemPtr(ByRef $vec, $index, ByRef $element)
    ; CVAPI(void) VectorOfIntGetItemPtr(std::vector<  int >* vec, int index, int** element);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfIntCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfIntPush($vecVec, $vec[$i])
        Next
    Else
        $vecVec = $vec
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfIntGetItemPtr", "ptr", $vecVec, "int", $index, "ptr*", $element), "VectorOfIntGetItemPtr", @error)

    If $bVecIsArray Then
        _VectorOfIntRelease($vecVec)
    EndIf
EndFunc   ;==>_VectorOfIntGetItemPtr

Func _cveInputArrayFromVectorOfInt(ByRef $vec)
    ; CVAPI(cv::_InputArray*) cveInputArrayFromVectorOfInt(std::vector< int >* vec);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfIntCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfIntPush($vecVec, $vec[$i])
        Next
    Else
        $vecVec = $vec
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveInputArrayFromVectorOfInt", "ptr", $vecVec), "cveInputArrayFromVectorOfInt", @error)

    If $bVecIsArray Then
        _VectorOfIntRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveInputArrayFromVectorOfInt

Func _cveOutputArrayFromVectorOfInt(ByRef $vec)
    ; CVAPI(cv::_OutputArray*) cveOutputArrayFromVectorOfInt(std::vector< int >* vec);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfIntCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfIntPush($vecVec, $vec[$i])
        Next
    Else
        $vecVec = $vec
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveOutputArrayFromVectorOfInt", "ptr", $vecVec), "cveOutputArrayFromVectorOfInt", @error)

    If $bVecIsArray Then
        _VectorOfIntRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveOutputArrayFromVectorOfInt

Func _cveInputOutputArrayFromVectorOfInt(ByRef $vec)
    ; CVAPI(cv::_InputOutputArray*) cveInputOutputArrayFromVectorOfInt(std::vector< int >* vec);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfIntCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfIntPush($vecVec, $vec[$i])
        Next
    Else
        $vecVec = $vec
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveInputOutputArrayFromVectorOfInt", "ptr", $vecVec), "cveInputOutputArrayFromVectorOfInt", @error)

    If $bVecIsArray Then
        _VectorOfIntRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveInputOutputArrayFromVectorOfInt

Func _VectorOfIntSizeOfItemInBytes()
    ; CVAPI(int) VectorOfIntSizeOfItemInBytes();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "VectorOfIntSizeOfItemInBytes"), "VectorOfIntSizeOfItemInBytes", @error)
EndFunc   ;==>_VectorOfIntSizeOfItemInBytes