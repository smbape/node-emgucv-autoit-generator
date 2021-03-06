#include-once
#include "..\CVEUtils.au3"

Func _VectorOfFloatCreate()
    ; CVAPI(std::vector<float>*) VectorOfFloatCreate();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfFloatCreate"), "VectorOfFloatCreate", @error)
EndFunc   ;==>_VectorOfFloatCreate

Func _VectorOfFloatCreateSize($size)
    ; CVAPI(std::vector<float>*) VectorOfFloatCreateSize(int size);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfFloatCreateSize", "int", $size), "VectorOfFloatCreateSize", @error)
EndFunc   ;==>_VectorOfFloatCreateSize

Func _VectorOfFloatGetSize($v)
    ; CVAPI(int) VectorOfFloatGetSize(std::vector<float>* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = IsArray($v)

    If $bVIsArray Then
        $vecV = _VectorOfFloatCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfFloatPush($vecV, $v[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "VectorOfFloatGetSize", $sVDllType, $vecV), "VectorOfFloatGetSize", @error)

    If $bVIsArray Then
        _VectorOfFloatRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfFloatGetSize

Func _VectorOfFloatPush($v, $value)
    ; CVAPI(void) VectorOfFloatPush(std::vector<float>* v, float* value);

    Local $vecV, $iArrVSize
    Local $bVIsArray = IsArray($v)

    If $bVIsArray Then
        $vecV = _VectorOfFloatCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfFloatPush($vecV, $v[$i])
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
        $sValueDllType = "float*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfFloatPush", $sVDllType, $vecV, "float*", $value), "VectorOfFloatPush", @error)

    If $bVIsArray Then
        _VectorOfFloatRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfFloatPush

Func _VectorOfFloatPushMulti($v, $values, $count)
    ; CVAPI(void) VectorOfFloatPushMulti(std::vector<float>* v, float* values, int count);

    Local $vecV, $iArrVSize
    Local $bVIsArray = IsArray($v)

    If $bVIsArray Then
        $vecV = _VectorOfFloatCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfFloatPush($vecV, $v[$i])
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
        $sValuesDllType = "float*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfFloatPushMulti", $sVDllType, $vecV, $sValuesDllType, $values, "int", $count), "VectorOfFloatPushMulti", @error)

    If $bVIsArray Then
        _VectorOfFloatRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfFloatPushMulti

Func _VectorOfFloatPushVector($v, $other)
    ; CVAPI(void) VectorOfFloatPushVector(std::vector<float>* v, std::vector<float>* other);

    Local $vecV, $iArrVSize
    Local $bVIsArray = IsArray($v)

    If $bVIsArray Then
        $vecV = _VectorOfFloatCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfFloatPush($vecV, $v[$i])
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
        $vecOther = _VectorOfFloatCreate()

        $iArrOtherSize = UBound($other)
        For $i = 0 To $iArrOtherSize - 1
            _VectorOfFloatPush($vecOther, $other[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfFloatPushVector", $sVDllType, $vecV, $sOtherDllType, $vecOther), "VectorOfFloatPushVector", @error)

    If $bOtherIsArray Then
        _VectorOfFloatRelease($vecOther)
    EndIf

    If $bVIsArray Then
        _VectorOfFloatRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfFloatPushVector

Func _VectorOfFloatClear($v)
    ; CVAPI(void) VectorOfFloatClear(std::vector<float>* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = IsArray($v)

    If $bVIsArray Then
        $vecV = _VectorOfFloatCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfFloatPush($vecV, $v[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfFloatClear", $sVDllType, $vecV), "VectorOfFloatClear", @error)

    If $bVIsArray Then
        _VectorOfFloatRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfFloatClear

Func _VectorOfFloatRelease($v)
    ; CVAPI(void) VectorOfFloatRelease(std::vector<float>** v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = IsArray($v)

    If $bVIsArray Then
        $vecV = _VectorOfFloatCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfFloatPush($vecV, $v[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfFloatRelease", $sVDllType, $vecV), "VectorOfFloatRelease", @error)

    If $bVIsArray Then
        _VectorOfFloatRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfFloatRelease

Func _VectorOfFloatCopyData($v, $data)
    ; CVAPI(void) VectorOfFloatCopyData(std::vector<float>* v, float* data);

    Local $vecV, $iArrVSize
    Local $bVIsArray = IsArray($v)

    If $bVIsArray Then
        $vecV = _VectorOfFloatCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfFloatPush($vecV, $v[$i])
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
        $sDataDllType = "float*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfFloatCopyData", $sVDllType, $vecV, $sDataDllType, $data), "VectorOfFloatCopyData", @error)

    If $bVIsArray Then
        _VectorOfFloatRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfFloatCopyData

Func _VectorOfFloatGetStartAddress($v)
    ; CVAPI(float*) VectorOfFloatGetStartAddress(std::vector<float>* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = IsArray($v)

    If $bVIsArray Then
        $vecV = _VectorOfFloatCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfFloatPush($vecV, $v[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfFloatGetStartAddress", $sVDllType, $vecV), "VectorOfFloatGetStartAddress", @error)

    If $bVIsArray Then
        _VectorOfFloatRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfFloatGetStartAddress

Func _VectorOfFloatGetEndAddress($v)
    ; CVAPI(void*) VectorOfFloatGetEndAddress(std::vector<float>* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = IsArray($v)

    If $bVIsArray Then
        $vecV = _VectorOfFloatCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfFloatPush($vecV, $v[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfFloatGetEndAddress", $sVDllType, $vecV), "VectorOfFloatGetEndAddress", @error)

    If $bVIsArray Then
        _VectorOfFloatRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfFloatGetEndAddress

Func _VectorOfFloatGetItem($vec, $index, $element)
    ; CVAPI(void) VectorOfFloatGetItem(std::vector<float>* vec, int index, float* element);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = IsArray($vec)

    If $bVecIsArray Then
        $vecVec = _VectorOfFloatCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfFloatPush($vecVec, $vec[$i])
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
        $sElementDllType = "float*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfFloatGetItem", $sVecDllType, $vecVec, "int", $index, $sElementDllType, $element), "VectorOfFloatGetItem", @error)

    If $bVecIsArray Then
        _VectorOfFloatRelease($vecVec)
    EndIf
EndFunc   ;==>_VectorOfFloatGetItem

Func _VectorOfFloatGetItemPtr($vec, $index, $element)
    ; CVAPI(void) VectorOfFloatGetItemPtr(std::vector<float>* vec, int index, float** element);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = IsArray($vec)

    If $bVecIsArray Then
        $vecVec = _VectorOfFloatCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfFloatPush($vecVec, $vec[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfFloatGetItemPtr", $sVecDllType, $vecVec, "int", $index, $sElementDllType, $element), "VectorOfFloatGetItemPtr", @error)

    If $bVecIsArray Then
        _VectorOfFloatRelease($vecVec)
    EndIf
EndFunc   ;==>_VectorOfFloatGetItemPtr

Func _cveInputArrayFromVectorOfFloat($vec)
    ; CVAPI(cv::_InputArray*) cveInputArrayFromVectorOfFloat(std::vector<float>* vec);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = IsArray($vec)

    If $bVecIsArray Then
        $vecVec = _VectorOfFloatCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfFloatPush($vecVec, $vec[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveInputArrayFromVectorOfFloat", $sVecDllType, $vecVec), "cveInputArrayFromVectorOfFloat", @error)

    If $bVecIsArray Then
        _VectorOfFloatRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveInputArrayFromVectorOfFloat

Func _cveOutputArrayFromVectorOfFloat($vec)
    ; CVAPI(cv::_OutputArray*) cveOutputArrayFromVectorOfFloat(std::vector<float>* vec);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = IsArray($vec)

    If $bVecIsArray Then
        $vecVec = _VectorOfFloatCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfFloatPush($vecVec, $vec[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveOutputArrayFromVectorOfFloat", $sVecDllType, $vecVec), "cveOutputArrayFromVectorOfFloat", @error)

    If $bVecIsArray Then
        _VectorOfFloatRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveOutputArrayFromVectorOfFloat

Func _cveInputOutputArrayFromVectorOfFloat($vec)
    ; CVAPI(cv::_InputOutputArray*) cveInputOutputArrayFromVectorOfFloat(std::vector<float>* vec);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = IsArray($vec)

    If $bVecIsArray Then
        $vecVec = _VectorOfFloatCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfFloatPush($vecVec, $vec[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveInputOutputArrayFromVectorOfFloat", $sVecDllType, $vecVec), "cveInputOutputArrayFromVectorOfFloat", @error)

    If $bVecIsArray Then
        _VectorOfFloatRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveInputOutputArrayFromVectorOfFloat

Func _VectorOfFloatSizeOfItemInBytes()
    ; CVAPI(int) VectorOfFloatSizeOfItemInBytes();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "VectorOfFloatSizeOfItemInBytes"), "VectorOfFloatSizeOfItemInBytes", @error)
EndFunc   ;==>_VectorOfFloatSizeOfItemInBytes