#include-once
#include "..\CVEUtils.au3"

Func _VectorOfSizeCreate()
    ; CVAPI(std::vector< cv::Size >*) VectorOfSizeCreate();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfSizeCreate"), "VectorOfSizeCreate", @error)
EndFunc   ;==>_VectorOfSizeCreate

Func _VectorOfSizeCreateSize($size)
    ; CVAPI(std::vector< cv::Size >*) VectorOfSizeCreateSize(int size);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfSizeCreateSize", "int", $size), "VectorOfSizeCreateSize", @error)
EndFunc   ;==>_VectorOfSizeCreateSize

Func _VectorOfSizeGetSize(ByRef $v)
    ; CVAPI(int) VectorOfSizeGetSize(std::vector< cv::Size >* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfSizeCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfSizePush($vecV, $v[$i])
        Next
    Else
        $vecV = $v
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "VectorOfSizeGetSize", "ptr", $vecV), "VectorOfSizeGetSize", @error)

    If $bVIsArray Then
        _VectorOfSizeRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfSizeGetSize

Func _VectorOfSizePush(ByRef $v, ByRef $value)
    ; CVAPI(void) VectorOfSizePush(std::vector< cv::Size >* v, cv::Size* value);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfSizeCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfSizePush($vecV, $v[$i])
        Next
    Else
        $vecV = $v
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfSizePush", "ptr", $vecV, "ptr", $value), "VectorOfSizePush", @error)

    If $bVIsArray Then
        _VectorOfSizeRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfSizePush

Func _VectorOfSizePushMulti(ByRef $v, ByRef $values, $count)
    ; CVAPI(void) VectorOfSizePushMulti(std::vector< cv::Size >* v, cv::Size* values, int count);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfSizeCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfSizePush($vecV, $v[$i])
        Next
    Else
        $vecV = $v
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfSizePushMulti", "ptr", $vecV, "ptr", $values, "int", $count), "VectorOfSizePushMulti", @error)

    If $bVIsArray Then
        _VectorOfSizeRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfSizePushMulti

Func _VectorOfSizePushVector(ByRef $v, ByRef $other)
    ; CVAPI(void) VectorOfSizePushVector(std::vector< cv::Size >* v, std::vector< cv::Size >* other);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfSizeCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfSizePush($vecV, $v[$i])
        Next
    Else
        $vecV = $v
    EndIf

    Local $vecOther, $iArrOtherSize
    Local $bOtherIsArray = VarGetType($other) == "Array"

    If $bOtherIsArray Then
        $vecOther = _VectorOfSizeCreate()

        $iArrOtherSize = UBound($other)
        For $i = 0 To $iArrOtherSize - 1
            _VectorOfSizePush($vecOther, $other[$i])
        Next
    Else
        $vecOther = $other
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfSizePushVector", "ptr", $vecV, "ptr", $vecOther), "VectorOfSizePushVector", @error)

    If $bOtherIsArray Then
        _VectorOfSizeRelease($vecOther)
    EndIf

    If $bVIsArray Then
        _VectorOfSizeRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfSizePushVector

Func _VectorOfSizeClear(ByRef $v)
    ; CVAPI(void) VectorOfSizeClear(std::vector< cv::Size >* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfSizeCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfSizePush($vecV, $v[$i])
        Next
    Else
        $vecV = $v
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfSizeClear", "ptr", $vecV), "VectorOfSizeClear", @error)

    If $bVIsArray Then
        _VectorOfSizeRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfSizeClear

Func _VectorOfSizeRelease(ByRef $v)
    ; CVAPI(void) VectorOfSizeRelease(std::vector< cv::Size >** v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfSizeCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfSizePush($vecV, $v[$i])
        Next
    Else
        $vecV = $v
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfSizeRelease", "ptr*", $vecV), "VectorOfSizeRelease", @error)

    If $bVIsArray Then
        _VectorOfSizeRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfSizeRelease

Func _VectorOfSizeCopyData(ByRef $v, ByRef $data)
    ; CVAPI(void) VectorOfSizeCopyData(std::vector< cv::Size >* v, cv::Size* data);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfSizeCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfSizePush($vecV, $v[$i])
        Next
    Else
        $vecV = $v
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfSizeCopyData", "ptr", $vecV, "ptr", $data), "VectorOfSizeCopyData", @error)

    If $bVIsArray Then
        _VectorOfSizeRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfSizeCopyData

Func _VectorOfSizeGetStartAddress(ByRef $v)
    ; CVAPI(cv::Size*) VectorOfSizeGetStartAddress(std::vector< cv::Size >* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfSizeCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfSizePush($vecV, $v[$i])
        Next
    Else
        $vecV = $v
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfSizeGetStartAddress", "ptr", $vecV), "VectorOfSizeGetStartAddress", @error)

    If $bVIsArray Then
        _VectorOfSizeRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfSizeGetStartAddress

Func _VectorOfSizeGetEndAddress(ByRef $v)
    ; CVAPI(void*) VectorOfSizeGetEndAddress(std::vector< cv::Size >* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfSizeCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfSizePush($vecV, $v[$i])
        Next
    Else
        $vecV = $v
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfSizeGetEndAddress", "ptr", $vecV), "VectorOfSizeGetEndAddress", @error)

    If $bVIsArray Then
        _VectorOfSizeRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfSizeGetEndAddress

Func _VectorOfSizeGetItem(ByRef $vec, $index, ByRef $element)
    ; CVAPI(void) VectorOfSizeGetItem(std::vector<  cv::Size >* vec, int index, cv::Size* element);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfSizeCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfSizePush($vecVec, $vec[$i])
        Next
    Else
        $vecVec = $vec
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfSizeGetItem", "ptr", $vecVec, "int", $index, "ptr", $element), "VectorOfSizeGetItem", @error)

    If $bVecIsArray Then
        _VectorOfSizeRelease($vecVec)
    EndIf
EndFunc   ;==>_VectorOfSizeGetItem

Func _VectorOfSizeGetItemPtr(ByRef $vec, $index, ByRef $element)
    ; CVAPI(void) VectorOfSizeGetItemPtr(std::vector<  cv::Size >* vec, int index, cv::Size** element);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfSizeCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfSizePush($vecVec, $vec[$i])
        Next
    Else
        $vecVec = $vec
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfSizeGetItemPtr", "ptr", $vecVec, "int", $index, "ptr*", $element), "VectorOfSizeGetItemPtr", @error)

    If $bVecIsArray Then
        _VectorOfSizeRelease($vecVec)
    EndIf
EndFunc   ;==>_VectorOfSizeGetItemPtr

Func _cveInputArrayFromVectorOfSize(ByRef $vec)
    ; CVAPI(cv::_InputArray*) cveInputArrayFromVectorOfSize(std::vector< cv::Size >* vec);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfSizeCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfSizePush($vecVec, $vec[$i])
        Next
    Else
        $vecVec = $vec
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveInputArrayFromVectorOfSize", "ptr", $vecVec), "cveInputArrayFromVectorOfSize", @error)

    If $bVecIsArray Then
        _VectorOfSizeRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveInputArrayFromVectorOfSize

Func _cveOutputArrayFromVectorOfSize(ByRef $vec)
    ; CVAPI(cv::_OutputArray*) cveOutputArrayFromVectorOfSize(std::vector< cv::Size >* vec);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfSizeCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfSizePush($vecVec, $vec[$i])
        Next
    Else
        $vecVec = $vec
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveOutputArrayFromVectorOfSize", "ptr", $vecVec), "cveOutputArrayFromVectorOfSize", @error)

    If $bVecIsArray Then
        _VectorOfSizeRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveOutputArrayFromVectorOfSize

Func _cveInputOutputArrayFromVectorOfSize(ByRef $vec)
    ; CVAPI(cv::_InputOutputArray*) cveInputOutputArrayFromVectorOfSize(std::vector< cv::Size >* vec);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfSizeCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfSizePush($vecVec, $vec[$i])
        Next
    Else
        $vecVec = $vec
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveInputOutputArrayFromVectorOfSize", "ptr", $vecVec), "cveInputOutputArrayFromVectorOfSize", @error)

    If $bVecIsArray Then
        _VectorOfSizeRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveInputOutputArrayFromVectorOfSize

Func _VectorOfSizeSizeOfItemInBytes()
    ; CVAPI(int) VectorOfSizeSizeOfItemInBytes();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "VectorOfSizeSizeOfItemInBytes"), "VectorOfSizeSizeOfItemInBytes", @error)
EndFunc   ;==>_VectorOfSizeSizeOfItemInBytes