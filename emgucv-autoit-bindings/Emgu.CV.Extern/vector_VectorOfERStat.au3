#include-once
#include "..\CVEUtils.au3"

Func _VectorOfVectorOfERStatCreate()
    ; CVAPI(std::vector<std::vector<cv::text::ERStat>>*) VectorOfVectorOfERStatCreate();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfVectorOfERStatCreate"), "VectorOfVectorOfERStatCreate", @error)
EndFunc   ;==>_VectorOfVectorOfERStatCreate

Func _VectorOfVectorOfERStatCreateSize($size)
    ; CVAPI(std::vector<std::vector<cv::text::ERStat>>*) VectorOfVectorOfERStatCreateSize(int size);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfVectorOfERStatCreateSize", "int", $size), "VectorOfVectorOfERStatCreateSize", @error)
EndFunc   ;==>_VectorOfVectorOfERStatCreateSize

Func _VectorOfVectorOfERStatGetSize($v)
    ; CVAPI(int) VectorOfVectorOfERStatGetSize(std::vector<std::vector<cv::text::ERStat>>* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfVectorOfERStatCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfVectorOfERStatPush($vecV, $v[$i])
        Next
    Else
        $vecV = $v
    EndIf

    Local $bVDllType
    If VarGetType($v) == "DLLStruct" Then
        $bVDllType = "struct*"
    Else
        $bVDllType = "ptr"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "VectorOfVectorOfERStatGetSize", $bVDllType, $vecV), "VectorOfVectorOfERStatGetSize", @error)

    If $bVIsArray Then
        _VectorOfVectorOfERStatRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfVectorOfERStatGetSize

Func _VectorOfVectorOfERStatPush($v, $value)
    ; CVAPI(void) VectorOfVectorOfERStatPush(std::vector<std::vector<cv::text::ERStat>>* v, std::vector<cv::text::ERStat>* value);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfVectorOfERStatCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfVectorOfERStatPush($vecV, $v[$i])
        Next
    Else
        $vecV = $v
    EndIf

    Local $bVDllType
    If VarGetType($v) == "DLLStruct" Then
        $bVDllType = "struct*"
    Else
        $bVDllType = "ptr"
    EndIf

    Local $vecValue, $iArrValueSize
    Local $bValueIsArray = VarGetType($value) == "Array"

    If $bValueIsArray Then
        $vecValue = _VectorOfERStatCreate()

        $iArrValueSize = UBound($value)
        For $i = 0 To $iArrValueSize - 1
            _VectorOfERStatPush($vecValue, $value[$i])
        Next
    Else
        $vecValue = $value
    EndIf

    Local $bValueDllType
    If VarGetType($value) == "DLLStruct" Then
        $bValueDllType = "struct*"
    Else
        $bValueDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfVectorOfERStatPush", $bVDllType, $vecV, $bValueDllType, $vecValue), "VectorOfVectorOfERStatPush", @error)

    If $bValueIsArray Then
        _VectorOfERStatRelease($vecValue)
    EndIf

    If $bVIsArray Then
        _VectorOfVectorOfERStatRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfVectorOfERStatPush

Func _VectorOfVectorOfERStatPushVector($v, $other)
    ; CVAPI(void) VectorOfVectorOfERStatPushVector(std::vector<std::vector<cv::text::ERStat>>* v, std::vector<std::vector<cv::text::ERStat>>* other);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfVectorOfERStatCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfVectorOfERStatPush($vecV, $v[$i])
        Next
    Else
        $vecV = $v
    EndIf

    Local $bVDllType
    If VarGetType($v) == "DLLStruct" Then
        $bVDllType = "struct*"
    Else
        $bVDllType = "ptr"
    EndIf

    Local $vecOther, $iArrOtherSize
    Local $bOtherIsArray = VarGetType($other) == "Array"

    If $bOtherIsArray Then
        $vecOther = _VectorOfVectorOfERStatCreate()

        $iArrOtherSize = UBound($other)
        For $i = 0 To $iArrOtherSize - 1
            _VectorOfVectorOfERStatPush($vecOther, $other[$i])
        Next
    Else
        $vecOther = $other
    EndIf

    Local $bOtherDllType
    If VarGetType($other) == "DLLStruct" Then
        $bOtherDllType = "struct*"
    Else
        $bOtherDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfVectorOfERStatPushVector", $bVDllType, $vecV, $bOtherDllType, $vecOther), "VectorOfVectorOfERStatPushVector", @error)

    If $bOtherIsArray Then
        _VectorOfVectorOfERStatRelease($vecOther)
    EndIf

    If $bVIsArray Then
        _VectorOfVectorOfERStatRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfVectorOfERStatPushVector

Func _VectorOfVectorOfERStatGetStartAddress($v)
    ; CVAPI(std::vector<cv::text::ERStat>*) VectorOfVectorOfERStatGetStartAddress(std::vector<std::vector<cv::text::ERStat>>* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfVectorOfERStatCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfVectorOfERStatPush($vecV, $v[$i])
        Next
    Else
        $vecV = $v
    EndIf

    Local $bVDllType
    If VarGetType($v) == "DLLStruct" Then
        $bVDllType = "struct*"
    Else
        $bVDllType = "ptr"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfVectorOfERStatGetStartAddress", $bVDllType, $vecV), "VectorOfVectorOfERStatGetStartAddress", @error)

    If $bVIsArray Then
        _VectorOfVectorOfERStatRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfVectorOfERStatGetStartAddress

Func _VectorOfVectorOfERStatGetEndAddress($v)
    ; CVAPI(void*) VectorOfVectorOfERStatGetEndAddress(std::vector<std::vector<cv::text::ERStat>>* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfVectorOfERStatCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfVectorOfERStatPush($vecV, $v[$i])
        Next
    Else
        $vecV = $v
    EndIf

    Local $bVDllType
    If VarGetType($v) == "DLLStruct" Then
        $bVDllType = "struct*"
    Else
        $bVDllType = "ptr"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfVectorOfERStatGetEndAddress", $bVDllType, $vecV), "VectorOfVectorOfERStatGetEndAddress", @error)

    If $bVIsArray Then
        _VectorOfVectorOfERStatRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfVectorOfERStatGetEndAddress

Func _VectorOfVectorOfERStatClear($v)
    ; CVAPI(void) VectorOfVectorOfERStatClear(std::vector<std::vector<cv::text::ERStat>>* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfVectorOfERStatCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfVectorOfERStatPush($vecV, $v[$i])
        Next
    Else
        $vecV = $v
    EndIf

    Local $bVDllType
    If VarGetType($v) == "DLLStruct" Then
        $bVDllType = "struct*"
    Else
        $bVDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfVectorOfERStatClear", $bVDllType, $vecV), "VectorOfVectorOfERStatClear", @error)

    If $bVIsArray Then
        _VectorOfVectorOfERStatRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfVectorOfERStatClear

Func _VectorOfVectorOfERStatRelease($v)
    ; CVAPI(void) VectorOfVectorOfERStatRelease(std::vector<std::vector<cv::text::ERStat>>** v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfVectorOfERStatCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfVectorOfERStatPush($vecV, $v[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfVectorOfERStatRelease", $bVDllType, $vecV), "VectorOfVectorOfERStatRelease", @error)

    If $bVIsArray Then
        _VectorOfVectorOfERStatRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfVectorOfERStatRelease

Func _VectorOfVectorOfERStatCopyData($v, $data)
    ; CVAPI(void) VectorOfVectorOfERStatCopyData(std::vector<std::vector<cv::text::ERStat>>* v, std::vector<cv::text::ERStat>* data);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfVectorOfERStatCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfVectorOfERStatPush($vecV, $v[$i])
        Next
    Else
        $vecV = $v
    EndIf

    Local $bVDllType
    If VarGetType($v) == "DLLStruct" Then
        $bVDllType = "struct*"
    Else
        $bVDllType = "ptr"
    EndIf

    Local $vecData, $iArrDataSize
    Local $bDataIsArray = VarGetType($data) == "Array"

    If $bDataIsArray Then
        $vecData = _VectorOfERStatCreate()

        $iArrDataSize = UBound($data)
        For $i = 0 To $iArrDataSize - 1
            _VectorOfERStatPush($vecData, $data[$i])
        Next
    Else
        $vecData = $data
    EndIf

    Local $bDataDllType
    If VarGetType($data) == "DLLStruct" Then
        $bDataDllType = "struct*"
    Else
        $bDataDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfVectorOfERStatCopyData", $bVDllType, $vecV, $bDataDllType, $vecData), "VectorOfVectorOfERStatCopyData", @error)

    If $bDataIsArray Then
        _VectorOfERStatRelease($vecData)
    EndIf

    If $bVIsArray Then
        _VectorOfVectorOfERStatRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfVectorOfERStatCopyData

Func _VectorOfVectorOfERStatGetItemPtr($vec, $index, $element)
    ; CVAPI(void) VectorOfVectorOfERStatGetItemPtr(std::vector<std::vector<cv::text::ERStat>>* vec, int index, std::vector<cv::text::ERStat>** element);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfVectorOfERStatCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfVectorOfERStatPush($vecVec, $vec[$i])
        Next
    Else
        $vecVec = $vec
    EndIf

    Local $bVecDllType
    If VarGetType($vec) == "DLLStruct" Then
        $bVecDllType = "struct*"
    Else
        $bVecDllType = "ptr"
    EndIf

    Local $vecElement, $iArrElementSize
    Local $bElementIsArray = VarGetType($element) == "Array"

    If $bElementIsArray Then
        $vecElement = _VectorOfERStatCreate()

        $iArrElementSize = UBound($element)
        For $i = 0 To $iArrElementSize - 1
            _VectorOfERStatPush($vecElement, $element[$i])
        Next
    Else
        $vecElement = $element
    EndIf

    Local $bElementDllType
    If VarGetType($element) == "DLLStruct" Then
        $bElementDllType = "struct*"
    Else
        $bElementDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfVectorOfERStatGetItemPtr", $bVecDllType, $vecVec, "int", $index, $bElementDllType, $vecElement), "VectorOfVectorOfERStatGetItemPtr", @error)

    If $bElementIsArray Then
        _VectorOfERStatRelease($vecElement)
    EndIf

    If $bVecIsArray Then
        _VectorOfVectorOfERStatRelease($vecVec)
    EndIf
EndFunc   ;==>_VectorOfVectorOfERStatGetItemPtr

Func _cveInputArrayFromVectorOfVectorOfERStat($vec)
    ; CVAPI(cv::_InputArray*) cveInputArrayFromVectorOfVectorOfERStat(std::vector<std::vector<cv::text::ERStat>>* vec);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfVectorOfERStatCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfVectorOfERStatPush($vecVec, $vec[$i])
        Next
    Else
        $vecVec = $vec
    EndIf

    Local $bVecDllType
    If VarGetType($vec) == "DLLStruct" Then
        $bVecDllType = "struct*"
    Else
        $bVecDllType = "ptr"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveInputArrayFromVectorOfVectorOfERStat", $bVecDllType, $vecVec), "cveInputArrayFromVectorOfVectorOfERStat", @error)

    If $bVecIsArray Then
        _VectorOfVectorOfERStatRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveInputArrayFromVectorOfVectorOfERStat

Func _cveOutputArrayFromVectorOfVectorOfERStat($vec)
    ; CVAPI(cv::_OutputArray*) cveOutputArrayFromVectorOfVectorOfERStat(std::vector<std::vector<cv::text::ERStat>>* vec);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfVectorOfERStatCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfVectorOfERStatPush($vecVec, $vec[$i])
        Next
    Else
        $vecVec = $vec
    EndIf

    Local $bVecDllType
    If VarGetType($vec) == "DLLStruct" Then
        $bVecDllType = "struct*"
    Else
        $bVecDllType = "ptr"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveOutputArrayFromVectorOfVectorOfERStat", $bVecDllType, $vecVec), "cveOutputArrayFromVectorOfVectorOfERStat", @error)

    If $bVecIsArray Then
        _VectorOfVectorOfERStatRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveOutputArrayFromVectorOfVectorOfERStat

Func _cveInputOutputArrayFromVectorOfVectorOfERStat($vec)
    ; CVAPI(cv::_InputOutputArray*) cveInputOutputArrayFromVectorOfVectorOfERStat(std::vector<std::vector<cv::text::ERStat>>* vec);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfVectorOfERStatCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfVectorOfERStatPush($vecVec, $vec[$i])
        Next
    Else
        $vecVec = $vec
    EndIf

    Local $bVecDllType
    If VarGetType($vec) == "DLLStruct" Then
        $bVecDllType = "struct*"
    Else
        $bVecDllType = "ptr"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveInputOutputArrayFromVectorOfVectorOfERStat", $bVecDllType, $vecVec), "cveInputOutputArrayFromVectorOfVectorOfERStat", @error)

    If $bVecIsArray Then
        _VectorOfVectorOfERStatRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveInputOutputArrayFromVectorOfVectorOfERStat

Func _VectorOfVectorOfERStatSizeOfItemInBytes()
    ; CVAPI(int) VectorOfVectorOfERStatSizeOfItemInBytes();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "VectorOfVectorOfERStatSizeOfItemInBytes"), "VectorOfVectorOfERStatSizeOfItemInBytes", @error)
EndFunc   ;==>_VectorOfVectorOfERStatSizeOfItemInBytes