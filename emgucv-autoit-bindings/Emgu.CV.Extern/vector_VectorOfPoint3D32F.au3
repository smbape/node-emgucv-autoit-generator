#include-once
#include "..\CVEUtils.au3"

Func _VectorOfVectorOfPoint3D32FCreate()
    ; CVAPI(std::vector<std::vector<cv::Point3f>>*) VectorOfVectorOfPoint3D32FCreate();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfVectorOfPoint3D32FCreate"), "VectorOfVectorOfPoint3D32FCreate", @error)
EndFunc   ;==>_VectorOfVectorOfPoint3D32FCreate

Func _VectorOfVectorOfPoint3D32FCreateSize($size)
    ; CVAPI(std::vector<std::vector<cv::Point3f>>*) VectorOfVectorOfPoint3D32FCreateSize(int size);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfVectorOfPoint3D32FCreateSize", "int", $size), "VectorOfVectorOfPoint3D32FCreateSize", @error)
EndFunc   ;==>_VectorOfVectorOfPoint3D32FCreateSize

Func _VectorOfVectorOfPoint3D32FGetSize($v)
    ; CVAPI(int) VectorOfVectorOfPoint3D32FGetSize(std::vector<std::vector<cv::Point3f>>* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = IsArray($v)

    If $bVIsArray Then
        $vecV = _VectorOfVectorOfPoint3D32FCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfVectorOfPoint3D32FPush($vecV, $v[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "VectorOfVectorOfPoint3D32FGetSize", $sVDllType, $vecV), "VectorOfVectorOfPoint3D32FGetSize", @error)

    If $bVIsArray Then
        _VectorOfVectorOfPoint3D32FRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfVectorOfPoint3D32FGetSize

Func _VectorOfVectorOfPoint3D32FPush($v, $value)
    ; CVAPI(void) VectorOfVectorOfPoint3D32FPush(std::vector<std::vector<cv::Point3f>>* v, std::vector<cv::Point3f>* value);

    Local $vecV, $iArrVSize
    Local $bVIsArray = IsArray($v)

    If $bVIsArray Then
        $vecV = _VectorOfVectorOfPoint3D32FCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfVectorOfPoint3D32FPush($vecV, $v[$i])
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

    Local $vecValue, $iArrValueSize
    Local $bValueIsArray = IsArray($value)

    If $bValueIsArray Then
        $vecValue = _VectorOfPoint3D32FCreate()

        $iArrValueSize = UBound($value)
        For $i = 0 To $iArrValueSize - 1
            _VectorOfPoint3D32FPush($vecValue, $value[$i])
        Next
    Else
        $vecValue = $value
    EndIf

    Local $sValueDllType
    If IsDllStruct($value) Then
        $sValueDllType = "struct*"
    Else
        $sValueDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfVectorOfPoint3D32FPush", $sVDllType, $vecV, $sValueDllType, $vecValue), "VectorOfVectorOfPoint3D32FPush", @error)

    If $bValueIsArray Then
        _VectorOfPoint3D32FRelease($vecValue)
    EndIf

    If $bVIsArray Then
        _VectorOfVectorOfPoint3D32FRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfVectorOfPoint3D32FPush

Func _VectorOfVectorOfPoint3D32FPushVector($v, $other)
    ; CVAPI(void) VectorOfVectorOfPoint3D32FPushVector(std::vector<std::vector<cv::Point3f>>* v, std::vector<std::vector<cv::Point3f>>* other);

    Local $vecV, $iArrVSize
    Local $bVIsArray = IsArray($v)

    If $bVIsArray Then
        $vecV = _VectorOfVectorOfPoint3D32FCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfVectorOfPoint3D32FPush($vecV, $v[$i])
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
        $vecOther = _VectorOfVectorOfPoint3D32FCreate()

        $iArrOtherSize = UBound($other)
        For $i = 0 To $iArrOtherSize - 1
            _VectorOfVectorOfPoint3D32FPush($vecOther, $other[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfVectorOfPoint3D32FPushVector", $sVDllType, $vecV, $sOtherDllType, $vecOther), "VectorOfVectorOfPoint3D32FPushVector", @error)

    If $bOtherIsArray Then
        _VectorOfVectorOfPoint3D32FRelease($vecOther)
    EndIf

    If $bVIsArray Then
        _VectorOfVectorOfPoint3D32FRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfVectorOfPoint3D32FPushVector

Func _VectorOfVectorOfPoint3D32FGetStartAddress($v)
    ; CVAPI(std::vector<cv::Point3f>*) VectorOfVectorOfPoint3D32FGetStartAddress(std::vector<std::vector<cv::Point3f>>* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = IsArray($v)

    If $bVIsArray Then
        $vecV = _VectorOfVectorOfPoint3D32FCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfVectorOfPoint3D32FPush($vecV, $v[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfVectorOfPoint3D32FGetStartAddress", $sVDllType, $vecV), "VectorOfVectorOfPoint3D32FGetStartAddress", @error)

    If $bVIsArray Then
        _VectorOfVectorOfPoint3D32FRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfVectorOfPoint3D32FGetStartAddress

Func _VectorOfVectorOfPoint3D32FGetEndAddress($v)
    ; CVAPI(void*) VectorOfVectorOfPoint3D32FGetEndAddress(std::vector<std::vector<cv::Point3f>>* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = IsArray($v)

    If $bVIsArray Then
        $vecV = _VectorOfVectorOfPoint3D32FCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfVectorOfPoint3D32FPush($vecV, $v[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfVectorOfPoint3D32FGetEndAddress", $sVDllType, $vecV), "VectorOfVectorOfPoint3D32FGetEndAddress", @error)

    If $bVIsArray Then
        _VectorOfVectorOfPoint3D32FRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfVectorOfPoint3D32FGetEndAddress

Func _VectorOfVectorOfPoint3D32FClear($v)
    ; CVAPI(void) VectorOfVectorOfPoint3D32FClear(std::vector<std::vector<cv::Point3f>>* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = IsArray($v)

    If $bVIsArray Then
        $vecV = _VectorOfVectorOfPoint3D32FCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfVectorOfPoint3D32FPush($vecV, $v[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfVectorOfPoint3D32FClear", $sVDllType, $vecV), "VectorOfVectorOfPoint3D32FClear", @error)

    If $bVIsArray Then
        _VectorOfVectorOfPoint3D32FRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfVectorOfPoint3D32FClear

Func _VectorOfVectorOfPoint3D32FRelease($v)
    ; CVAPI(void) VectorOfVectorOfPoint3D32FRelease(std::vector<std::vector<cv::Point3f>>** v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = IsArray($v)

    If $bVIsArray Then
        $vecV = _VectorOfVectorOfPoint3D32FCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfVectorOfPoint3D32FPush($vecV, $v[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfVectorOfPoint3D32FRelease", $sVDllType, $vecV), "VectorOfVectorOfPoint3D32FRelease", @error)

    If $bVIsArray Then
        _VectorOfVectorOfPoint3D32FRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfVectorOfPoint3D32FRelease

Func _VectorOfVectorOfPoint3D32FCopyData($v, $data)
    ; CVAPI(void) VectorOfVectorOfPoint3D32FCopyData(std::vector<std::vector<cv::Point3f>>* v, std::vector<cv::Point3f>* data);

    Local $vecV, $iArrVSize
    Local $bVIsArray = IsArray($v)

    If $bVIsArray Then
        $vecV = _VectorOfVectorOfPoint3D32FCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfVectorOfPoint3D32FPush($vecV, $v[$i])
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

    Local $vecData, $iArrDataSize
    Local $bDataIsArray = IsArray($data)

    If $bDataIsArray Then
        $vecData = _VectorOfPoint3D32FCreate()

        $iArrDataSize = UBound($data)
        For $i = 0 To $iArrDataSize - 1
            _VectorOfPoint3D32FPush($vecData, $data[$i])
        Next
    Else
        $vecData = $data
    EndIf

    Local $sDataDllType
    If IsDllStruct($data) Then
        $sDataDllType = "struct*"
    Else
        $sDataDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfVectorOfPoint3D32FCopyData", $sVDllType, $vecV, $sDataDllType, $vecData), "VectorOfVectorOfPoint3D32FCopyData", @error)

    If $bDataIsArray Then
        _VectorOfPoint3D32FRelease($vecData)
    EndIf

    If $bVIsArray Then
        _VectorOfVectorOfPoint3D32FRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfVectorOfPoint3D32FCopyData

Func _VectorOfVectorOfPoint3D32FGetItemPtr($vec, $index, $element)
    ; CVAPI(void) VectorOfVectorOfPoint3D32FGetItemPtr(std::vector<std::vector<cv::Point3f>>* vec, int index, std::vector<cv::Point3f>** element);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = IsArray($vec)

    If $bVecIsArray Then
        $vecVec = _VectorOfVectorOfPoint3D32FCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfVectorOfPoint3D32FPush($vecVec, $vec[$i])
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

    Local $vecElement, $iArrElementSize
    Local $bElementIsArray = IsArray($element)

    If $bElementIsArray Then
        $vecElement = _VectorOfPoint3D32FCreate()

        $iArrElementSize = UBound($element)
        For $i = 0 To $iArrElementSize - 1
            _VectorOfPoint3D32FPush($vecElement, $element[$i])
        Next
    Else
        $vecElement = $element
    EndIf

    Local $sElementDllType
    If IsDllStruct($element) Then
        $sElementDllType = "struct*"
    ElseIf $element == Null Then
        $sElementDllType = "ptr"
    Else
        $sElementDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfVectorOfPoint3D32FGetItemPtr", $sVecDllType, $vecVec, "int", $index, $sElementDllType, $vecElement), "VectorOfVectorOfPoint3D32FGetItemPtr", @error)

    If $bElementIsArray Then
        _VectorOfPoint3D32FRelease($vecElement)
    EndIf

    If $bVecIsArray Then
        _VectorOfVectorOfPoint3D32FRelease($vecVec)
    EndIf
EndFunc   ;==>_VectorOfVectorOfPoint3D32FGetItemPtr

Func _cveInputArrayFromVectorOfVectorOfPoint3D32F($vec)
    ; CVAPI(cv::_InputArray*) cveInputArrayFromVectorOfVectorOfPoint3D32F(std::vector<std::vector<cv::Point3f>>* vec);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = IsArray($vec)

    If $bVecIsArray Then
        $vecVec = _VectorOfVectorOfPoint3D32FCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfVectorOfPoint3D32FPush($vecVec, $vec[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveInputArrayFromVectorOfVectorOfPoint3D32F", $sVecDllType, $vecVec), "cveInputArrayFromVectorOfVectorOfPoint3D32F", @error)

    If $bVecIsArray Then
        _VectorOfVectorOfPoint3D32FRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveInputArrayFromVectorOfVectorOfPoint3D32F

Func _cveOutputArrayFromVectorOfVectorOfPoint3D32F($vec)
    ; CVAPI(cv::_OutputArray*) cveOutputArrayFromVectorOfVectorOfPoint3D32F(std::vector<std::vector<cv::Point3f>>* vec);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = IsArray($vec)

    If $bVecIsArray Then
        $vecVec = _VectorOfVectorOfPoint3D32FCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfVectorOfPoint3D32FPush($vecVec, $vec[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveOutputArrayFromVectorOfVectorOfPoint3D32F", $sVecDllType, $vecVec), "cveOutputArrayFromVectorOfVectorOfPoint3D32F", @error)

    If $bVecIsArray Then
        _VectorOfVectorOfPoint3D32FRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveOutputArrayFromVectorOfVectorOfPoint3D32F

Func _cveInputOutputArrayFromVectorOfVectorOfPoint3D32F($vec)
    ; CVAPI(cv::_InputOutputArray*) cveInputOutputArrayFromVectorOfVectorOfPoint3D32F(std::vector<std::vector<cv::Point3f>>* vec);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = IsArray($vec)

    If $bVecIsArray Then
        $vecVec = _VectorOfVectorOfPoint3D32FCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfVectorOfPoint3D32FPush($vecVec, $vec[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveInputOutputArrayFromVectorOfVectorOfPoint3D32F", $sVecDllType, $vecVec), "cveInputOutputArrayFromVectorOfVectorOfPoint3D32F", @error)

    If $bVecIsArray Then
        _VectorOfVectorOfPoint3D32FRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveInputOutputArrayFromVectorOfVectorOfPoint3D32F

Func _VectorOfVectorOfPoint3D32FSizeOfItemInBytes()
    ; CVAPI(int) VectorOfVectorOfPoint3D32FSizeOfItemInBytes();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "VectorOfVectorOfPoint3D32FSizeOfItemInBytes"), "VectorOfVectorOfPoint3D32FSizeOfItemInBytes", @error)
EndFunc   ;==>_VectorOfVectorOfPoint3D32FSizeOfItemInBytes