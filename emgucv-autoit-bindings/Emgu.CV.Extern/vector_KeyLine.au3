#include-once
#include "..\CVEUtils.au3"

Func _VectorOfKeyLineCreate()
    ; CVAPI(std::vector<cv::line_descriptor::KeyLine>*) VectorOfKeyLineCreate();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfKeyLineCreate"), "VectorOfKeyLineCreate", @error)
EndFunc   ;==>_VectorOfKeyLineCreate

Func _VectorOfKeyLineCreateSize($size)
    ; CVAPI(std::vector<cv::line_descriptor::KeyLine>*) VectorOfKeyLineCreateSize(int size);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfKeyLineCreateSize", "int", $size), "VectorOfKeyLineCreateSize", @error)
EndFunc   ;==>_VectorOfKeyLineCreateSize

Func _VectorOfKeyLineGetSize($v)
    ; CVAPI(int) VectorOfKeyLineGetSize(std::vector<cv::line_descriptor::KeyLine>* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = IsArray($v)

    If $bVIsArray Then
        $vecV = _VectorOfKeyLineCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfKeyLinePush($vecV, $v[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "VectorOfKeyLineGetSize", $sVDllType, $vecV), "VectorOfKeyLineGetSize", @error)

    If $bVIsArray Then
        _VectorOfKeyLineRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfKeyLineGetSize

Func _VectorOfKeyLinePush($v, $value)
    ; CVAPI(void) VectorOfKeyLinePush(std::vector<cv::line_descriptor::KeyLine>* v, cv::line_descriptor::KeyLine* value);

    Local $vecV, $iArrVSize
    Local $bVIsArray = IsArray($v)

    If $bVIsArray Then
        $vecV = _VectorOfKeyLineCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfKeyLinePush($vecV, $v[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfKeyLinePush", $sVDllType, $vecV, $sValueDllType, $value), "VectorOfKeyLinePush", @error)

    If $bVIsArray Then
        _VectorOfKeyLineRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfKeyLinePush

Func _VectorOfKeyLinePushMulti($v, $values, $count)
    ; CVAPI(void) VectorOfKeyLinePushMulti(std::vector<cv::line_descriptor::KeyLine>* v, cv::line_descriptor::KeyLine* values, int count);

    Local $vecV, $iArrVSize
    Local $bVIsArray = IsArray($v)

    If $bVIsArray Then
        $vecV = _VectorOfKeyLineCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfKeyLinePush($vecV, $v[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfKeyLinePushMulti", $sVDllType, $vecV, $sValuesDllType, $values, "int", $count), "VectorOfKeyLinePushMulti", @error)

    If $bVIsArray Then
        _VectorOfKeyLineRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfKeyLinePushMulti

Func _VectorOfKeyLinePushVector($v, $other)
    ; CVAPI(void) VectorOfKeyLinePushVector(std::vector<cv::line_descriptor::KeyLine>* v, std::vector<cv::line_descriptor::KeyLine>* other);

    Local $vecV, $iArrVSize
    Local $bVIsArray = IsArray($v)

    If $bVIsArray Then
        $vecV = _VectorOfKeyLineCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfKeyLinePush($vecV, $v[$i])
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
        $vecOther = _VectorOfKeyLineCreate()

        $iArrOtherSize = UBound($other)
        For $i = 0 To $iArrOtherSize - 1
            _VectorOfKeyLinePush($vecOther, $other[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfKeyLinePushVector", $sVDllType, $vecV, $sOtherDllType, $vecOther), "VectorOfKeyLinePushVector", @error)

    If $bOtherIsArray Then
        _VectorOfKeyLineRelease($vecOther)
    EndIf

    If $bVIsArray Then
        _VectorOfKeyLineRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfKeyLinePushVector

Func _VectorOfKeyLineClear($v)
    ; CVAPI(void) VectorOfKeyLineClear(std::vector<cv::line_descriptor::KeyLine>* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = IsArray($v)

    If $bVIsArray Then
        $vecV = _VectorOfKeyLineCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfKeyLinePush($vecV, $v[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfKeyLineClear", $sVDllType, $vecV), "VectorOfKeyLineClear", @error)

    If $bVIsArray Then
        _VectorOfKeyLineRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfKeyLineClear

Func _VectorOfKeyLineRelease($v)
    ; CVAPI(void) VectorOfKeyLineRelease(std::vector<cv::line_descriptor::KeyLine>** v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = IsArray($v)

    If $bVIsArray Then
        $vecV = _VectorOfKeyLineCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfKeyLinePush($vecV, $v[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfKeyLineRelease", $sVDllType, $vecV), "VectorOfKeyLineRelease", @error)

    If $bVIsArray Then
        _VectorOfKeyLineRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfKeyLineRelease

Func _VectorOfKeyLineCopyData($v, $data)
    ; CVAPI(void) VectorOfKeyLineCopyData(std::vector<cv::line_descriptor::KeyLine>* v, cv::line_descriptor::KeyLine* data);

    Local $vecV, $iArrVSize
    Local $bVIsArray = IsArray($v)

    If $bVIsArray Then
        $vecV = _VectorOfKeyLineCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfKeyLinePush($vecV, $v[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfKeyLineCopyData", $sVDllType, $vecV, $sDataDllType, $data), "VectorOfKeyLineCopyData", @error)

    If $bVIsArray Then
        _VectorOfKeyLineRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfKeyLineCopyData

Func _VectorOfKeyLineGetStartAddress($v)
    ; CVAPI(cv::line_descriptor::KeyLine*) VectorOfKeyLineGetStartAddress(std::vector<cv::line_descriptor::KeyLine>* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = IsArray($v)

    If $bVIsArray Then
        $vecV = _VectorOfKeyLineCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfKeyLinePush($vecV, $v[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfKeyLineGetStartAddress", $sVDllType, $vecV), "VectorOfKeyLineGetStartAddress", @error)

    If $bVIsArray Then
        _VectorOfKeyLineRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfKeyLineGetStartAddress

Func _VectorOfKeyLineGetEndAddress($v)
    ; CVAPI(void*) VectorOfKeyLineGetEndAddress(std::vector<cv::line_descriptor::KeyLine>* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = IsArray($v)

    If $bVIsArray Then
        $vecV = _VectorOfKeyLineCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfKeyLinePush($vecV, $v[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfKeyLineGetEndAddress", $sVDllType, $vecV), "VectorOfKeyLineGetEndAddress", @error)

    If $bVIsArray Then
        _VectorOfKeyLineRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfKeyLineGetEndAddress

Func _VectorOfKeyLineGetItem($vec, $index, $element)
    ; CVAPI(void) VectorOfKeyLineGetItem(std::vector<cv::line_descriptor::KeyLine>* vec, int index, cv::line_descriptor::KeyLine* element);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = IsArray($vec)

    If $bVecIsArray Then
        $vecVec = _VectorOfKeyLineCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfKeyLinePush($vecVec, $vec[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfKeyLineGetItem", $sVecDllType, $vecVec, "int", $index, $sElementDllType, $element), "VectorOfKeyLineGetItem", @error)

    If $bVecIsArray Then
        _VectorOfKeyLineRelease($vecVec)
    EndIf
EndFunc   ;==>_VectorOfKeyLineGetItem

Func _VectorOfKeyLineGetItemPtr($vec, $index, $element)
    ; CVAPI(void) VectorOfKeyLineGetItemPtr(std::vector<cv::line_descriptor::KeyLine>* vec, int index, cv::line_descriptor::KeyLine** element);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = IsArray($vec)

    If $bVecIsArray Then
        $vecVec = _VectorOfKeyLineCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfKeyLinePush($vecVec, $vec[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfKeyLineGetItemPtr", $sVecDllType, $vecVec, "int", $index, $sElementDllType, $element), "VectorOfKeyLineGetItemPtr", @error)

    If $bVecIsArray Then
        _VectorOfKeyLineRelease($vecVec)
    EndIf
EndFunc   ;==>_VectorOfKeyLineGetItemPtr

Func _cveInputArrayFromVectorOfKeyLine($vec)
    ; CVAPI(cv::_InputArray*) cveInputArrayFromVectorOfKeyLine(std::vector<cv::line_descriptor::KeyLine>* vec);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = IsArray($vec)

    If $bVecIsArray Then
        $vecVec = _VectorOfKeyLineCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfKeyLinePush($vecVec, $vec[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveInputArrayFromVectorOfKeyLine", $sVecDllType, $vecVec), "cveInputArrayFromVectorOfKeyLine", @error)

    If $bVecIsArray Then
        _VectorOfKeyLineRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveInputArrayFromVectorOfKeyLine

Func _cveOutputArrayFromVectorOfKeyLine($vec)
    ; CVAPI(cv::_OutputArray*) cveOutputArrayFromVectorOfKeyLine(std::vector<cv::line_descriptor::KeyLine>* vec);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = IsArray($vec)

    If $bVecIsArray Then
        $vecVec = _VectorOfKeyLineCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfKeyLinePush($vecVec, $vec[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveOutputArrayFromVectorOfKeyLine", $sVecDllType, $vecVec), "cveOutputArrayFromVectorOfKeyLine", @error)

    If $bVecIsArray Then
        _VectorOfKeyLineRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveOutputArrayFromVectorOfKeyLine

Func _cveInputOutputArrayFromVectorOfKeyLine($vec)
    ; CVAPI(cv::_InputOutputArray*) cveInputOutputArrayFromVectorOfKeyLine(std::vector<cv::line_descriptor::KeyLine>* vec);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = IsArray($vec)

    If $bVecIsArray Then
        $vecVec = _VectorOfKeyLineCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfKeyLinePush($vecVec, $vec[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveInputOutputArrayFromVectorOfKeyLine", $sVecDllType, $vecVec), "cveInputOutputArrayFromVectorOfKeyLine", @error)

    If $bVecIsArray Then
        _VectorOfKeyLineRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveInputOutputArrayFromVectorOfKeyLine

Func _VectorOfKeyLineSizeOfItemInBytes()
    ; CVAPI(int) VectorOfKeyLineSizeOfItemInBytes();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "VectorOfKeyLineSizeOfItemInBytes"), "VectorOfKeyLineSizeOfItemInBytes", @error)
EndFunc   ;==>_VectorOfKeyLineSizeOfItemInBytes