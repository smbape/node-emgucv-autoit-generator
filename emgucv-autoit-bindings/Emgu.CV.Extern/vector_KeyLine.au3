#include-once
#include "..\CVEUtils.au3"

Func _VectorOfKeyLineCreate()
    ; CVAPI(std::vector< cv::line_descriptor::KeyLine >*) VectorOfKeyLineCreate();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfKeyLineCreate"), "VectorOfKeyLineCreate", @error)
EndFunc   ;==>_VectorOfKeyLineCreate

Func _VectorOfKeyLineCreateSize($size)
    ; CVAPI(std::vector< cv::line_descriptor::KeyLine >*) VectorOfKeyLineCreateSize(int size);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfKeyLineCreateSize", "int", $size), "VectorOfKeyLineCreateSize", @error)
EndFunc   ;==>_VectorOfKeyLineCreateSize

Func _VectorOfKeyLineGetSize($v)
    ; CVAPI(int) VectorOfKeyLineGetSize(std::vector< cv::line_descriptor::KeyLine >* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfKeyLineCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfKeyLinePush($vecV, $v[$i])
        Next
    Else
        $vecV = $v
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "VectorOfKeyLineGetSize", "ptr", $vecV), "VectorOfKeyLineGetSize", @error)

    If $bVIsArray Then
        _VectorOfKeyLineRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfKeyLineGetSize

Func _VectorOfKeyLinePush($v, $value)
    ; CVAPI(void) VectorOfKeyLinePush(std::vector< cv::line_descriptor::KeyLine >* v, cv::line_descriptor::KeyLine* value);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfKeyLineCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfKeyLinePush($vecV, $v[$i])
        Next
    Else
        $vecV = $v
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfKeyLinePush", "ptr", $vecV, "ptr", $value), "VectorOfKeyLinePush", @error)

    If $bVIsArray Then
        _VectorOfKeyLineRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfKeyLinePush

Func _VectorOfKeyLinePushMulti($v, $values, $count)
    ; CVAPI(void) VectorOfKeyLinePushMulti(std::vector< cv::line_descriptor::KeyLine >* v, cv::line_descriptor::KeyLine* values, int count);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfKeyLineCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfKeyLinePush($vecV, $v[$i])
        Next
    Else
        $vecV = $v
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfKeyLinePushMulti", "ptr", $vecV, "ptr", $values, "int", $count), "VectorOfKeyLinePushMulti", @error)

    If $bVIsArray Then
        _VectorOfKeyLineRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfKeyLinePushMulti

Func _VectorOfKeyLinePushVector($v, $other)
    ; CVAPI(void) VectorOfKeyLinePushVector(std::vector< cv::line_descriptor::KeyLine >* v, std::vector< cv::line_descriptor::KeyLine >* other);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfKeyLineCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfKeyLinePush($vecV, $v[$i])
        Next
    Else
        $vecV = $v
    EndIf

    Local $vecOther, $iArrOtherSize
    Local $bOtherIsArray = VarGetType($other) == "Array"

    If $bOtherIsArray Then
        $vecOther = _VectorOfKeyLineCreate()

        $iArrOtherSize = UBound($other)
        For $i = 0 To $iArrOtherSize - 1
            _VectorOfKeyLinePush($vecOther, $other[$i])
        Next
    Else
        $vecOther = $other
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfKeyLinePushVector", "ptr", $vecV, "ptr", $vecOther), "VectorOfKeyLinePushVector", @error)

    If $bOtherIsArray Then
        _VectorOfKeyLineRelease($vecOther)
    EndIf

    If $bVIsArray Then
        _VectorOfKeyLineRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfKeyLinePushVector

Func _VectorOfKeyLineClear($v)
    ; CVAPI(void) VectorOfKeyLineClear(std::vector< cv::line_descriptor::KeyLine >* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfKeyLineCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfKeyLinePush($vecV, $v[$i])
        Next
    Else
        $vecV = $v
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfKeyLineClear", "ptr", $vecV), "VectorOfKeyLineClear", @error)

    If $bVIsArray Then
        _VectorOfKeyLineRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfKeyLineClear

Func _VectorOfKeyLineRelease($v)
    ; CVAPI(void) VectorOfKeyLineRelease(std::vector< cv::line_descriptor::KeyLine >** v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfKeyLineCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfKeyLinePush($vecV, $v[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfKeyLineRelease", $bVDllType, $vecV), "VectorOfKeyLineRelease", @error)

    If $bVIsArray Then
        _VectorOfKeyLineRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfKeyLineRelease

Func _VectorOfKeyLineCopyData($v, $data)
    ; CVAPI(void) VectorOfKeyLineCopyData(std::vector< cv::line_descriptor::KeyLine >* v, cv::line_descriptor::KeyLine* data);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfKeyLineCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfKeyLinePush($vecV, $v[$i])
        Next
    Else
        $vecV = $v
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfKeyLineCopyData", "ptr", $vecV, "ptr", $data), "VectorOfKeyLineCopyData", @error)

    If $bVIsArray Then
        _VectorOfKeyLineRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfKeyLineCopyData

Func _VectorOfKeyLineGetStartAddress($v)
    ; CVAPI(cv::line_descriptor::KeyLine*) VectorOfKeyLineGetStartAddress(std::vector< cv::line_descriptor::KeyLine >* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfKeyLineCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfKeyLinePush($vecV, $v[$i])
        Next
    Else
        $vecV = $v
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfKeyLineGetStartAddress", "ptr", $vecV), "VectorOfKeyLineGetStartAddress", @error)

    If $bVIsArray Then
        _VectorOfKeyLineRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfKeyLineGetStartAddress

Func _VectorOfKeyLineGetEndAddress($v)
    ; CVAPI(void*) VectorOfKeyLineGetEndAddress(std::vector< cv::line_descriptor::KeyLine >* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfKeyLineCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfKeyLinePush($vecV, $v[$i])
        Next
    Else
        $vecV = $v
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfKeyLineGetEndAddress", "ptr", $vecV), "VectorOfKeyLineGetEndAddress", @error)

    If $bVIsArray Then
        _VectorOfKeyLineRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfKeyLineGetEndAddress

Func _VectorOfKeyLineGetItem($vec, $index, $element)
    ; CVAPI(void) VectorOfKeyLineGetItem(std::vector<  cv::line_descriptor::KeyLine >* vec, int index, cv::line_descriptor::KeyLine* element);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfKeyLineCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfKeyLinePush($vecVec, $vec[$i])
        Next
    Else
        $vecVec = $vec
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfKeyLineGetItem", "ptr", $vecVec, "int", $index, "ptr", $element), "VectorOfKeyLineGetItem", @error)

    If $bVecIsArray Then
        _VectorOfKeyLineRelease($vecVec)
    EndIf
EndFunc   ;==>_VectorOfKeyLineGetItem

Func _VectorOfKeyLineGetItemPtr($vec, $index, $element)
    ; CVAPI(void) VectorOfKeyLineGetItemPtr(std::vector<  cv::line_descriptor::KeyLine >* vec, int index, cv::line_descriptor::KeyLine** element);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfKeyLineCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfKeyLinePush($vecVec, $vec[$i])
        Next
    Else
        $vecVec = $vec
    EndIf

    Local $bElementDllType
    If VarGetType($element) == "DLLStruct" Then
        $bElementDllType = "struct*"
    Else
        $bElementDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfKeyLineGetItemPtr", "ptr", $vecVec, "int", $index, $bElementDllType, $element), "VectorOfKeyLineGetItemPtr", @error)

    If $bVecIsArray Then
        _VectorOfKeyLineRelease($vecVec)
    EndIf
EndFunc   ;==>_VectorOfKeyLineGetItemPtr

Func _cveInputArrayFromVectorOfKeyLine($vec)
    ; CVAPI(cv::_InputArray*) cveInputArrayFromVectorOfKeyLine(std::vector< cv::line_descriptor::KeyLine >* vec);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfKeyLineCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfKeyLinePush($vecVec, $vec[$i])
        Next
    Else
        $vecVec = $vec
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveInputArrayFromVectorOfKeyLine", "ptr", $vecVec), "cveInputArrayFromVectorOfKeyLine", @error)

    If $bVecIsArray Then
        _VectorOfKeyLineRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveInputArrayFromVectorOfKeyLine

Func _cveOutputArrayFromVectorOfKeyLine($vec)
    ; CVAPI(cv::_OutputArray*) cveOutputArrayFromVectorOfKeyLine(std::vector< cv::line_descriptor::KeyLine >* vec);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfKeyLineCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfKeyLinePush($vecVec, $vec[$i])
        Next
    Else
        $vecVec = $vec
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveOutputArrayFromVectorOfKeyLine", "ptr", $vecVec), "cveOutputArrayFromVectorOfKeyLine", @error)

    If $bVecIsArray Then
        _VectorOfKeyLineRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveOutputArrayFromVectorOfKeyLine

Func _cveInputOutputArrayFromVectorOfKeyLine($vec)
    ; CVAPI(cv::_InputOutputArray*) cveInputOutputArrayFromVectorOfKeyLine(std::vector< cv::line_descriptor::KeyLine >* vec);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfKeyLineCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfKeyLinePush($vecVec, $vec[$i])
        Next
    Else
        $vecVec = $vec
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveInputOutputArrayFromVectorOfKeyLine", "ptr", $vecVec), "cveInputOutputArrayFromVectorOfKeyLine", @error)

    If $bVecIsArray Then
        _VectorOfKeyLineRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveInputOutputArrayFromVectorOfKeyLine

Func _VectorOfKeyLineSizeOfItemInBytes()
    ; CVAPI(int) VectorOfKeyLineSizeOfItemInBytes();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "VectorOfKeyLineSizeOfItemInBytes"), "VectorOfKeyLineSizeOfItemInBytes", @error)
EndFunc   ;==>_VectorOfKeyLineSizeOfItemInBytes