#include-once
#include "..\CVEUtils.au3"

Func _VectorOfVectorOfIntCreate()
    ; CVAPI(std::vector< std::vector< int > >*) VectorOfVectorOfIntCreate();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfVectorOfIntCreate"), "VectorOfVectorOfIntCreate", @error)
EndFunc   ;==>_VectorOfVectorOfIntCreate

Func _VectorOfVectorOfIntCreateSize($size)
    ; CVAPI(std::vector< std::vector< int > >*) VectorOfVectorOfIntCreateSize(int size);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfVectorOfIntCreateSize", "int", $size), "VectorOfVectorOfIntCreateSize", @error)
EndFunc   ;==>_VectorOfVectorOfIntCreateSize

Func _VectorOfVectorOfIntGetSize(ByRef $v)
    ; CVAPI(int) VectorOfVectorOfIntGetSize(std::vector< std::vector< int > >* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfVectorOfIntCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfVectorOfIntPush($vecV, $v[$i])
        Next
    Else
        $vecV = $v
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "VectorOfVectorOfIntGetSize", "ptr", $vecV), "VectorOfVectorOfIntGetSize", @error)

    If $bVIsArray Then
        _VectorOfVectorOfIntRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfVectorOfIntGetSize

Func _VectorOfVectorOfIntPush(ByRef $v, ByRef $value)
    ; CVAPI(void) VectorOfVectorOfIntPush(std::vector< std::vector< int > >* v, std::vector< int >* value);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfVectorOfIntCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfVectorOfIntPush($vecV, $v[$i])
        Next
    Else
        $vecV = $v
    EndIf

    Local $vecValue, $iArrValueSize
    Local $bValueIsArray = VarGetType($value) == "Array"

    If $bValueIsArray Then
        $vecValue = _VectorOfIntCreate()

        $iArrValueSize = UBound($value)
        For $i = 0 To $iArrValueSize - 1
            _VectorOfIntPush($vecValue, $value[$i])
        Next
    Else
        $vecValue = $value
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfVectorOfIntPush", "ptr", $vecV, "ptr", $vecValue), "VectorOfVectorOfIntPush", @error)

    If $bValueIsArray Then
        _VectorOfIntRelease($vecValue)
    EndIf

    If $bVIsArray Then
        _VectorOfVectorOfIntRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfVectorOfIntPush

Func _VectorOfVectorOfIntPushVector(ByRef $v, ByRef $other)
    ; CVAPI(void) VectorOfVectorOfIntPushVector(std::vector< std::vector< int > >* v, std::vector< std::vector< int > >* other);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfVectorOfIntCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfVectorOfIntPush($vecV, $v[$i])
        Next
    Else
        $vecV = $v
    EndIf

    Local $vecOther, $iArrOtherSize
    Local $bOtherIsArray = VarGetType($other) == "Array"

    If $bOtherIsArray Then
        $vecOther = _VectorOfVectorOfIntCreate()

        $iArrOtherSize = UBound($other)
        For $i = 0 To $iArrOtherSize - 1
            _VectorOfVectorOfIntPush($vecOther, $other[$i])
        Next
    Else
        $vecOther = $other
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfVectorOfIntPushVector", "ptr", $vecV, "ptr", $vecOther), "VectorOfVectorOfIntPushVector", @error)

    If $bOtherIsArray Then
        _VectorOfVectorOfIntRelease($vecOther)
    EndIf

    If $bVIsArray Then
        _VectorOfVectorOfIntRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfVectorOfIntPushVector

Func _VectorOfVectorOfIntGetStartAddress(ByRef $v)
    ; CVAPI(std::vector< int >*) VectorOfVectorOfIntGetStartAddress(std::vector< std::vector< int > >* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfVectorOfIntCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfVectorOfIntPush($vecV, $v[$i])
        Next
    Else
        $vecV = $v
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfVectorOfIntGetStartAddress", "ptr", $vecV), "VectorOfVectorOfIntGetStartAddress", @error)

    If $bVIsArray Then
        _VectorOfVectorOfIntRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfVectorOfIntGetStartAddress

Func _VectorOfVectorOfIntGetEndAddress(ByRef $v)
    ; CVAPI(void*) VectorOfVectorOfIntGetEndAddress(std::vector< std::vector< int > >* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfVectorOfIntCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfVectorOfIntPush($vecV, $v[$i])
        Next
    Else
        $vecV = $v
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfVectorOfIntGetEndAddress", "ptr", $vecV), "VectorOfVectorOfIntGetEndAddress", @error)

    If $bVIsArray Then
        _VectorOfVectorOfIntRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfVectorOfIntGetEndAddress

Func _VectorOfVectorOfIntClear(ByRef $v)
    ; CVAPI(void) VectorOfVectorOfIntClear(std::vector< std::vector< int > >* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfVectorOfIntCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfVectorOfIntPush($vecV, $v[$i])
        Next
    Else
        $vecV = $v
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfVectorOfIntClear", "ptr", $vecV), "VectorOfVectorOfIntClear", @error)

    If $bVIsArray Then
        _VectorOfVectorOfIntRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfVectorOfIntClear

Func _VectorOfVectorOfIntRelease(ByRef $v)
    ; CVAPI(void) VectorOfVectorOfIntRelease(std::vector< std::vector< int > >** v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfVectorOfIntCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfVectorOfIntPush($vecV, $v[$i])
        Next
    Else
        $vecV = $v
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfVectorOfIntRelease", "ptr*", $vecV), "VectorOfVectorOfIntRelease", @error)

    If $bVIsArray Then
        _VectorOfVectorOfIntRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfVectorOfIntRelease

Func _VectorOfVectorOfIntCopyData(ByRef $v, ByRef $data)
    ; CVAPI(void) VectorOfVectorOfIntCopyData(std::vector< std::vector< int > >* v, std::vector< int >* data);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfVectorOfIntCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfVectorOfIntPush($vecV, $v[$i])
        Next
    Else
        $vecV = $v
    EndIf

    Local $vecData, $iArrDataSize
    Local $bDataIsArray = VarGetType($data) == "Array"

    If $bDataIsArray Then
        $vecData = _VectorOfIntCreate()

        $iArrDataSize = UBound($data)
        For $i = 0 To $iArrDataSize - 1
            _VectorOfIntPush($vecData, $data[$i])
        Next
    Else
        $vecData = $data
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfVectorOfIntCopyData", "ptr", $vecV, "ptr", $vecData), "VectorOfVectorOfIntCopyData", @error)

    If $bDataIsArray Then
        _VectorOfIntRelease($vecData)
    EndIf

    If $bVIsArray Then
        _VectorOfVectorOfIntRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfVectorOfIntCopyData

Func _VectorOfVectorOfIntGetItemPtr(ByRef $vec, $index, ByRef $element)
    ; CVAPI(void) VectorOfVectorOfIntGetItemPtr(std::vector<  std::vector< int > >* vec, int index, std::vector< int >** element);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfVectorOfIntCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfVectorOfIntPush($vecVec, $vec[$i])
        Next
    Else
        $vecVec = $vec
    EndIf

    Local $vecElement, $iArrElementSize
    Local $bElementIsArray = VarGetType($element) == "Array"

    If $bElementIsArray Then
        $vecElement = _VectorOfIntCreate()

        $iArrElementSize = UBound($element)
        For $i = 0 To $iArrElementSize - 1
            _VectorOfIntPush($vecElement, $element[$i])
        Next
    Else
        $vecElement = $element
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfVectorOfIntGetItemPtr", "ptr", $vecVec, "int", $index, "ptr*", $vecElement), "VectorOfVectorOfIntGetItemPtr", @error)

    If $bElementIsArray Then
        _VectorOfIntRelease($vecElement)
    EndIf

    If $bVecIsArray Then
        _VectorOfVectorOfIntRelease($vecVec)
    EndIf
EndFunc   ;==>_VectorOfVectorOfIntGetItemPtr

Func _cveInputArrayFromVectorOfVectorOfInt(ByRef $vec)
    ; CVAPI(cv::_InputArray*) cveInputArrayFromVectorOfVectorOfInt(std::vector< std::vector< int > >* vec);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfVectorOfIntCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfVectorOfIntPush($vecVec, $vec[$i])
        Next
    Else
        $vecVec = $vec
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveInputArrayFromVectorOfVectorOfInt", "ptr", $vecVec), "cveInputArrayFromVectorOfVectorOfInt", @error)

    If $bVecIsArray Then
        _VectorOfVectorOfIntRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveInputArrayFromVectorOfVectorOfInt

Func _cveOutputArrayFromVectorOfVectorOfInt(ByRef $vec)
    ; CVAPI(cv::_OutputArray*) cveOutputArrayFromVectorOfVectorOfInt(std::vector< std::vector< int > >* vec);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfVectorOfIntCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfVectorOfIntPush($vecVec, $vec[$i])
        Next
    Else
        $vecVec = $vec
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveOutputArrayFromVectorOfVectorOfInt", "ptr", $vecVec), "cveOutputArrayFromVectorOfVectorOfInt", @error)

    If $bVecIsArray Then
        _VectorOfVectorOfIntRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveOutputArrayFromVectorOfVectorOfInt

Func _cveInputOutputArrayFromVectorOfVectorOfInt(ByRef $vec)
    ; CVAPI(cv::_InputOutputArray*) cveInputOutputArrayFromVectorOfVectorOfInt(std::vector< std::vector< int > >* vec);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfVectorOfIntCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfVectorOfIntPush($vecVec, $vec[$i])
        Next
    Else
        $vecVec = $vec
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveInputOutputArrayFromVectorOfVectorOfInt", "ptr", $vecVec), "cveInputOutputArrayFromVectorOfVectorOfInt", @error)

    If $bVecIsArray Then
        _VectorOfVectorOfIntRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveInputOutputArrayFromVectorOfVectorOfInt

Func _VectorOfVectorOfIntSizeOfItemInBytes()
    ; CVAPI(int) VectorOfVectorOfIntSizeOfItemInBytes();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "VectorOfVectorOfIntSizeOfItemInBytes"), "VectorOfVectorOfIntSizeOfItemInBytes", @error)
EndFunc   ;==>_VectorOfVectorOfIntSizeOfItemInBytes