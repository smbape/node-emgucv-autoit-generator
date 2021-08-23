#include-once
#include "..\CVEUtils.au3"

Func _VectorOfPoint3D32FCreate()
    ; CVAPI(std::vector<cv::Point3f>*) VectorOfPoint3D32FCreate();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfPoint3D32FCreate"), "VectorOfPoint3D32FCreate", @error)
EndFunc   ;==>_VectorOfPoint3D32FCreate

Func _VectorOfPoint3D32FCreateSize($size)
    ; CVAPI(std::vector<cv::Point3f>*) VectorOfPoint3D32FCreateSize(int size);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfPoint3D32FCreateSize", "int", $size), "VectorOfPoint3D32FCreateSize", @error)
EndFunc   ;==>_VectorOfPoint3D32FCreateSize

Func _VectorOfPoint3D32FGetSize($v)
    ; CVAPI(int) VectorOfPoint3D32FGetSize(std::vector<cv::Point3f>* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfPoint3D32FCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfPoint3D32FPush($vecV, $v[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "VectorOfPoint3D32FGetSize", $sVDllType, $vecV), "VectorOfPoint3D32FGetSize", @error)

    If $bVIsArray Then
        _VectorOfPoint3D32FRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfPoint3D32FGetSize

Func _VectorOfPoint3D32FPush($v, $value)
    ; CVAPI(void) VectorOfPoint3D32FPush(std::vector<cv::Point3f>* v, cv::Point3f* value);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfPoint3D32FCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfPoint3D32FPush($vecV, $v[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfPoint3D32FPush", $sVDllType, $vecV, $sValueDllType, $value), "VectorOfPoint3D32FPush", @error)

    If $bVIsArray Then
        _VectorOfPoint3D32FRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfPoint3D32FPush

Func _VectorOfPoint3D32FPushMulti($v, $values, $count)
    ; CVAPI(void) VectorOfPoint3D32FPushMulti(std::vector<cv::Point3f>* v, cv::Point3f* values, int count);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfPoint3D32FCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfPoint3D32FPush($vecV, $v[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfPoint3D32FPushMulti", $sVDllType, $vecV, $sValuesDllType, $values, "int", $count), "VectorOfPoint3D32FPushMulti", @error)

    If $bVIsArray Then
        _VectorOfPoint3D32FRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfPoint3D32FPushMulti

Func _VectorOfPoint3D32FPushVector($v, $other)
    ; CVAPI(void) VectorOfPoint3D32FPushVector(std::vector<cv::Point3f>* v, std::vector<cv::Point3f>* other);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfPoint3D32FCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfPoint3D32FPush($vecV, $v[$i])
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
    Local $bOtherIsArray = VarGetType($other) == "Array"

    If $bOtherIsArray Then
        $vecOther = _VectorOfPoint3D32FCreate()

        $iArrOtherSize = UBound($other)
        For $i = 0 To $iArrOtherSize - 1
            _VectorOfPoint3D32FPush($vecOther, $other[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfPoint3D32FPushVector", $sVDllType, $vecV, $sOtherDllType, $vecOther), "VectorOfPoint3D32FPushVector", @error)

    If $bOtherIsArray Then
        _VectorOfPoint3D32FRelease($vecOther)
    EndIf

    If $bVIsArray Then
        _VectorOfPoint3D32FRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfPoint3D32FPushVector

Func _VectorOfPoint3D32FClear($v)
    ; CVAPI(void) VectorOfPoint3D32FClear(std::vector<cv::Point3f>* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfPoint3D32FCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfPoint3D32FPush($vecV, $v[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfPoint3D32FClear", $sVDllType, $vecV), "VectorOfPoint3D32FClear", @error)

    If $bVIsArray Then
        _VectorOfPoint3D32FRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfPoint3D32FClear

Func _VectorOfPoint3D32FRelease($v)
    ; CVAPI(void) VectorOfPoint3D32FRelease(std::vector<cv::Point3f>** v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfPoint3D32FCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfPoint3D32FPush($vecV, $v[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfPoint3D32FRelease", $sVDllType, $vecV), "VectorOfPoint3D32FRelease", @error)

    If $bVIsArray Then
        _VectorOfPoint3D32FRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfPoint3D32FRelease

Func _VectorOfPoint3D32FCopyData($v, $data)
    ; CVAPI(void) VectorOfPoint3D32FCopyData(std::vector<cv::Point3f>* v, cv::Point3f* data);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfPoint3D32FCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfPoint3D32FPush($vecV, $v[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfPoint3D32FCopyData", $sVDllType, $vecV, $sDataDllType, $data), "VectorOfPoint3D32FCopyData", @error)

    If $bVIsArray Then
        _VectorOfPoint3D32FRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfPoint3D32FCopyData

Func _VectorOfPoint3D32FGetStartAddress($v)
    ; CVAPI(cv::Point3f*) VectorOfPoint3D32FGetStartAddress(std::vector<cv::Point3f>* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfPoint3D32FCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfPoint3D32FPush($vecV, $v[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfPoint3D32FGetStartAddress", $sVDllType, $vecV), "VectorOfPoint3D32FGetStartAddress", @error)

    If $bVIsArray Then
        _VectorOfPoint3D32FRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfPoint3D32FGetStartAddress

Func _VectorOfPoint3D32FGetEndAddress($v)
    ; CVAPI(void*) VectorOfPoint3D32FGetEndAddress(std::vector<cv::Point3f>* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfPoint3D32FCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfPoint3D32FPush($vecV, $v[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfPoint3D32FGetEndAddress", $sVDllType, $vecV), "VectorOfPoint3D32FGetEndAddress", @error)

    If $bVIsArray Then
        _VectorOfPoint3D32FRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfPoint3D32FGetEndAddress

Func _VectorOfPoint3D32FGetItem($vec, $index, $element)
    ; CVAPI(void) VectorOfPoint3D32FGetItem(std::vector<cv::Point3f>* vec, int index, cv::Point3f* element);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfPoint3D32FCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfPoint3D32FPush($vecVec, $vec[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfPoint3D32FGetItem", $sVecDllType, $vecVec, "int", $index, $sElementDllType, $element), "VectorOfPoint3D32FGetItem", @error)

    If $bVecIsArray Then
        _VectorOfPoint3D32FRelease($vecVec)
    EndIf
EndFunc   ;==>_VectorOfPoint3D32FGetItem

Func _VectorOfPoint3D32FGetItemPtr($vec, $index, $element)
    ; CVAPI(void) VectorOfPoint3D32FGetItemPtr(std::vector<cv::Point3f>* vec, int index, cv::Point3f** element);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfPoint3D32FCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfPoint3D32FPush($vecVec, $vec[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfPoint3D32FGetItemPtr", $sVecDllType, $vecVec, "int", $index, $sElementDllType, $element), "VectorOfPoint3D32FGetItemPtr", @error)

    If $bVecIsArray Then
        _VectorOfPoint3D32FRelease($vecVec)
    EndIf
EndFunc   ;==>_VectorOfPoint3D32FGetItemPtr

Func _cveInputArrayFromVectorOfPoint3D32F($vec)
    ; CVAPI(cv::_InputArray*) cveInputArrayFromVectorOfPoint3D32F(std::vector<cv::Point3f>* vec);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfPoint3D32FCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfPoint3D32FPush($vecVec, $vec[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveInputArrayFromVectorOfPoint3D32F", $sVecDllType, $vecVec), "cveInputArrayFromVectorOfPoint3D32F", @error)

    If $bVecIsArray Then
        _VectorOfPoint3D32FRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveInputArrayFromVectorOfPoint3D32F

Func _cveOutputArrayFromVectorOfPoint3D32F($vec)
    ; CVAPI(cv::_OutputArray*) cveOutputArrayFromVectorOfPoint3D32F(std::vector<cv::Point3f>* vec);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfPoint3D32FCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfPoint3D32FPush($vecVec, $vec[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveOutputArrayFromVectorOfPoint3D32F", $sVecDllType, $vecVec), "cveOutputArrayFromVectorOfPoint3D32F", @error)

    If $bVecIsArray Then
        _VectorOfPoint3D32FRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveOutputArrayFromVectorOfPoint3D32F

Func _cveInputOutputArrayFromVectorOfPoint3D32F($vec)
    ; CVAPI(cv::_InputOutputArray*) cveInputOutputArrayFromVectorOfPoint3D32F(std::vector<cv::Point3f>* vec);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfPoint3D32FCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfPoint3D32FPush($vecVec, $vec[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveInputOutputArrayFromVectorOfPoint3D32F", $sVecDllType, $vecVec), "cveInputOutputArrayFromVectorOfPoint3D32F", @error)

    If $bVecIsArray Then
        _VectorOfPoint3D32FRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveInputOutputArrayFromVectorOfPoint3D32F

Func _VectorOfPoint3D32FSizeOfItemInBytes()
    ; CVAPI(int) VectorOfPoint3D32FSizeOfItemInBytes();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "VectorOfPoint3D32FSizeOfItemInBytes"), "VectorOfPoint3D32FSizeOfItemInBytes", @error)
EndFunc   ;==>_VectorOfPoint3D32FSizeOfItemInBytes