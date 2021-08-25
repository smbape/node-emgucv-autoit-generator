#include-once
#include "..\CVEUtils.au3"

Func _VectorOfVectorOfPointFCreate()
    ; CVAPI(std::vector<std::vector<cv::Point2f>>*) VectorOfVectorOfPointFCreate();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfVectorOfPointFCreate"), "VectorOfVectorOfPointFCreate", @error)
EndFunc   ;==>_VectorOfVectorOfPointFCreate

Func _VectorOfVectorOfPointFCreateSize($size)
    ; CVAPI(std::vector<std::vector<cv::Point2f>>*) VectorOfVectorOfPointFCreateSize(int size);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfVectorOfPointFCreateSize", "int", $size), "VectorOfVectorOfPointFCreateSize", @error)
EndFunc   ;==>_VectorOfVectorOfPointFCreateSize

Func _VectorOfVectorOfPointFGetSize($v)
    ; CVAPI(int) VectorOfVectorOfPointFGetSize(std::vector<std::vector<cv::Point2f>>* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = IsArray($v)

    If $bVIsArray Then
        $vecV = _VectorOfVectorOfPointFCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfVectorOfPointFPush($vecV, $v[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "VectorOfVectorOfPointFGetSize", $sVDllType, $vecV), "VectorOfVectorOfPointFGetSize", @error)

    If $bVIsArray Then
        _VectorOfVectorOfPointFRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfVectorOfPointFGetSize

Func _VectorOfVectorOfPointFPush($v, $value)
    ; CVAPI(void) VectorOfVectorOfPointFPush(std::vector<std::vector<cv::Point2f>>* v, std::vector<cv::Point2f>* value);

    Local $vecV, $iArrVSize
    Local $bVIsArray = IsArray($v)

    If $bVIsArray Then
        $vecV = _VectorOfVectorOfPointFCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfVectorOfPointFPush($vecV, $v[$i])
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
        $vecValue = _VectorOfPointFCreate()

        $iArrValueSize = UBound($value)
        For $i = 0 To $iArrValueSize - 1
            _VectorOfPointFPush($vecValue, $value[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfVectorOfPointFPush", $sVDllType, $vecV, $sValueDllType, $vecValue), "VectorOfVectorOfPointFPush", @error)

    If $bValueIsArray Then
        _VectorOfPointFRelease($vecValue)
    EndIf

    If $bVIsArray Then
        _VectorOfVectorOfPointFRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfVectorOfPointFPush

Func _VectorOfVectorOfPointFPushVector($v, $other)
    ; CVAPI(void) VectorOfVectorOfPointFPushVector(std::vector<std::vector<cv::Point2f>>* v, std::vector<std::vector<cv::Point2f>>* other);

    Local $vecV, $iArrVSize
    Local $bVIsArray = IsArray($v)

    If $bVIsArray Then
        $vecV = _VectorOfVectorOfPointFCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfVectorOfPointFPush($vecV, $v[$i])
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
        $vecOther = _VectorOfVectorOfPointFCreate()

        $iArrOtherSize = UBound($other)
        For $i = 0 To $iArrOtherSize - 1
            _VectorOfVectorOfPointFPush($vecOther, $other[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfVectorOfPointFPushVector", $sVDllType, $vecV, $sOtherDllType, $vecOther), "VectorOfVectorOfPointFPushVector", @error)

    If $bOtherIsArray Then
        _VectorOfVectorOfPointFRelease($vecOther)
    EndIf

    If $bVIsArray Then
        _VectorOfVectorOfPointFRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfVectorOfPointFPushVector

Func _VectorOfVectorOfPointFGetStartAddress($v)
    ; CVAPI(std::vector<cv::Point2f>*) VectorOfVectorOfPointFGetStartAddress(std::vector<std::vector<cv::Point2f>>* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = IsArray($v)

    If $bVIsArray Then
        $vecV = _VectorOfVectorOfPointFCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfVectorOfPointFPush($vecV, $v[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfVectorOfPointFGetStartAddress", $sVDllType, $vecV), "VectorOfVectorOfPointFGetStartAddress", @error)

    If $bVIsArray Then
        _VectorOfVectorOfPointFRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfVectorOfPointFGetStartAddress

Func _VectorOfVectorOfPointFGetEndAddress($v)
    ; CVAPI(void*) VectorOfVectorOfPointFGetEndAddress(std::vector<std::vector<cv::Point2f>>* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = IsArray($v)

    If $bVIsArray Then
        $vecV = _VectorOfVectorOfPointFCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfVectorOfPointFPush($vecV, $v[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfVectorOfPointFGetEndAddress", $sVDllType, $vecV), "VectorOfVectorOfPointFGetEndAddress", @error)

    If $bVIsArray Then
        _VectorOfVectorOfPointFRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfVectorOfPointFGetEndAddress

Func _VectorOfVectorOfPointFClear($v)
    ; CVAPI(void) VectorOfVectorOfPointFClear(std::vector<std::vector<cv::Point2f>>* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = IsArray($v)

    If $bVIsArray Then
        $vecV = _VectorOfVectorOfPointFCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfVectorOfPointFPush($vecV, $v[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfVectorOfPointFClear", $sVDllType, $vecV), "VectorOfVectorOfPointFClear", @error)

    If $bVIsArray Then
        _VectorOfVectorOfPointFRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfVectorOfPointFClear

Func _VectorOfVectorOfPointFRelease($v)
    ; CVAPI(void) VectorOfVectorOfPointFRelease(std::vector<std::vector<cv::Point2f>>** v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = IsArray($v)

    If $bVIsArray Then
        $vecV = _VectorOfVectorOfPointFCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfVectorOfPointFPush($vecV, $v[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfVectorOfPointFRelease", $sVDllType, $vecV), "VectorOfVectorOfPointFRelease", @error)

    If $bVIsArray Then
        _VectorOfVectorOfPointFRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfVectorOfPointFRelease

Func _VectorOfVectorOfPointFCopyData($v, $data)
    ; CVAPI(void) VectorOfVectorOfPointFCopyData(std::vector<std::vector<cv::Point2f>>* v, std::vector<cv::Point2f>* data);

    Local $vecV, $iArrVSize
    Local $bVIsArray = IsArray($v)

    If $bVIsArray Then
        $vecV = _VectorOfVectorOfPointFCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfVectorOfPointFPush($vecV, $v[$i])
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
        $vecData = _VectorOfPointFCreate()

        $iArrDataSize = UBound($data)
        For $i = 0 To $iArrDataSize - 1
            _VectorOfPointFPush($vecData, $data[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfVectorOfPointFCopyData", $sVDllType, $vecV, $sDataDllType, $vecData), "VectorOfVectorOfPointFCopyData", @error)

    If $bDataIsArray Then
        _VectorOfPointFRelease($vecData)
    EndIf

    If $bVIsArray Then
        _VectorOfVectorOfPointFRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfVectorOfPointFCopyData

Func _VectorOfVectorOfPointFGetItemPtr($vec, $index, $element)
    ; CVAPI(void) VectorOfVectorOfPointFGetItemPtr(std::vector<std::vector<cv::Point2f>>* vec, int index, std::vector<cv::Point2f>** element);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = IsArray($vec)

    If $bVecIsArray Then
        $vecVec = _VectorOfVectorOfPointFCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfVectorOfPointFPush($vecVec, $vec[$i])
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
        $vecElement = _VectorOfPointFCreate()

        $iArrElementSize = UBound($element)
        For $i = 0 To $iArrElementSize - 1
            _VectorOfPointFPush($vecElement, $element[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfVectorOfPointFGetItemPtr", $sVecDllType, $vecVec, "int", $index, $sElementDllType, $vecElement), "VectorOfVectorOfPointFGetItemPtr", @error)

    If $bElementIsArray Then
        _VectorOfPointFRelease($vecElement)
    EndIf

    If $bVecIsArray Then
        _VectorOfVectorOfPointFRelease($vecVec)
    EndIf
EndFunc   ;==>_VectorOfVectorOfPointFGetItemPtr

Func _cveInputArrayFromVectorOfVectorOfPointF($vec)
    ; CVAPI(cv::_InputArray*) cveInputArrayFromVectorOfVectorOfPointF(std::vector<std::vector<cv::Point2f>>* vec);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = IsArray($vec)

    If $bVecIsArray Then
        $vecVec = _VectorOfVectorOfPointFCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfVectorOfPointFPush($vecVec, $vec[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveInputArrayFromVectorOfVectorOfPointF", $sVecDllType, $vecVec), "cveInputArrayFromVectorOfVectorOfPointF", @error)

    If $bVecIsArray Then
        _VectorOfVectorOfPointFRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveInputArrayFromVectorOfVectorOfPointF

Func _cveOutputArrayFromVectorOfVectorOfPointF($vec)
    ; CVAPI(cv::_OutputArray*) cveOutputArrayFromVectorOfVectorOfPointF(std::vector<std::vector<cv::Point2f>>* vec);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = IsArray($vec)

    If $bVecIsArray Then
        $vecVec = _VectorOfVectorOfPointFCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfVectorOfPointFPush($vecVec, $vec[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveOutputArrayFromVectorOfVectorOfPointF", $sVecDllType, $vecVec), "cveOutputArrayFromVectorOfVectorOfPointF", @error)

    If $bVecIsArray Then
        _VectorOfVectorOfPointFRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveOutputArrayFromVectorOfVectorOfPointF

Func _cveInputOutputArrayFromVectorOfVectorOfPointF($vec)
    ; CVAPI(cv::_InputOutputArray*) cveInputOutputArrayFromVectorOfVectorOfPointF(std::vector<std::vector<cv::Point2f>>* vec);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = IsArray($vec)

    If $bVecIsArray Then
        $vecVec = _VectorOfVectorOfPointFCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfVectorOfPointFPush($vecVec, $vec[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveInputOutputArrayFromVectorOfVectorOfPointF", $sVecDllType, $vecVec), "cveInputOutputArrayFromVectorOfVectorOfPointF", @error)

    If $bVecIsArray Then
        _VectorOfVectorOfPointFRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveInputOutputArrayFromVectorOfVectorOfPointF

Func _VectorOfVectorOfPointFSizeOfItemInBytes()
    ; CVAPI(int) VectorOfVectorOfPointFSizeOfItemInBytes();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "VectorOfVectorOfPointFSizeOfItemInBytes"), "VectorOfVectorOfPointFSizeOfItemInBytes", @error)
EndFunc   ;==>_VectorOfVectorOfPointFSizeOfItemInBytes