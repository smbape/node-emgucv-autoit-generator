#include-once
#include "..\CVEUtils.au3"

Func _VectorOfVectorOfPointCreate()
    ; CVAPI(std::vector< std::vector< cv::Point > >*) VectorOfVectorOfPointCreate();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfVectorOfPointCreate"), "VectorOfVectorOfPointCreate", @error)
EndFunc   ;==>_VectorOfVectorOfPointCreate

Func _VectorOfVectorOfPointCreateSize($size)
    ; CVAPI(std::vector< std::vector< cv::Point > >*) VectorOfVectorOfPointCreateSize(int size);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfVectorOfPointCreateSize", "int", $size), "VectorOfVectorOfPointCreateSize", @error)
EndFunc   ;==>_VectorOfVectorOfPointCreateSize

Func _VectorOfVectorOfPointGetSize($v)
    ; CVAPI(int) VectorOfVectorOfPointGetSize(std::vector< std::vector< cv::Point > >* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfVectorOfPointCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfVectorOfPointPush($vecV, $v[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "VectorOfVectorOfPointGetSize", $bVDllType, $vecV), "VectorOfVectorOfPointGetSize", @error)

    If $bVIsArray Then
        _VectorOfVectorOfPointRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfVectorOfPointGetSize

Func _VectorOfVectorOfPointPush($v, $value)
    ; CVAPI(void) VectorOfVectorOfPointPush(std::vector< std::vector< cv::Point > >* v, std::vector< cv::Point >* value);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfVectorOfPointCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfVectorOfPointPush($vecV, $v[$i])
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
        $vecValue = _VectorOfPointCreate()

        $iArrValueSize = UBound($value)
        For $i = 0 To $iArrValueSize - 1
            _VectorOfPointPush($vecValue, $value[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfVectorOfPointPush", $bVDllType, $vecV, $bValueDllType, $vecValue), "VectorOfVectorOfPointPush", @error)

    If $bValueIsArray Then
        _VectorOfPointRelease($vecValue)
    EndIf

    If $bVIsArray Then
        _VectorOfVectorOfPointRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfVectorOfPointPush

Func _VectorOfVectorOfPointPushVector($v, $other)
    ; CVAPI(void) VectorOfVectorOfPointPushVector(std::vector< std::vector< cv::Point > >* v, std::vector< std::vector< cv::Point > >* other);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfVectorOfPointCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfVectorOfPointPush($vecV, $v[$i])
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
        $vecOther = _VectorOfVectorOfPointCreate()

        $iArrOtherSize = UBound($other)
        For $i = 0 To $iArrOtherSize - 1
            _VectorOfVectorOfPointPush($vecOther, $other[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfVectorOfPointPushVector", $bVDllType, $vecV, $bOtherDllType, $vecOther), "VectorOfVectorOfPointPushVector", @error)

    If $bOtherIsArray Then
        _VectorOfVectorOfPointRelease($vecOther)
    EndIf

    If $bVIsArray Then
        _VectorOfVectorOfPointRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfVectorOfPointPushVector

Func _VectorOfVectorOfPointGetStartAddress($v)
    ; CVAPI(std::vector< cv::Point >*) VectorOfVectorOfPointGetStartAddress(std::vector< std::vector< cv::Point > >* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfVectorOfPointCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfVectorOfPointPush($vecV, $v[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfVectorOfPointGetStartAddress", $bVDllType, $vecV), "VectorOfVectorOfPointGetStartAddress", @error)

    If $bVIsArray Then
        _VectorOfVectorOfPointRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfVectorOfPointGetStartAddress

Func _VectorOfVectorOfPointGetEndAddress($v)
    ; CVAPI(void*) VectorOfVectorOfPointGetEndAddress(std::vector< std::vector< cv::Point > >* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfVectorOfPointCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfVectorOfPointPush($vecV, $v[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfVectorOfPointGetEndAddress", $bVDllType, $vecV), "VectorOfVectorOfPointGetEndAddress", @error)

    If $bVIsArray Then
        _VectorOfVectorOfPointRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfVectorOfPointGetEndAddress

Func _VectorOfVectorOfPointClear($v)
    ; CVAPI(void) VectorOfVectorOfPointClear(std::vector< std::vector< cv::Point > >* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfVectorOfPointCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfVectorOfPointPush($vecV, $v[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfVectorOfPointClear", $bVDllType, $vecV), "VectorOfVectorOfPointClear", @error)

    If $bVIsArray Then
        _VectorOfVectorOfPointRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfVectorOfPointClear

Func _VectorOfVectorOfPointRelease($v)
    ; CVAPI(void) VectorOfVectorOfPointRelease(std::vector< std::vector< cv::Point > >** v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfVectorOfPointCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfVectorOfPointPush($vecV, $v[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfVectorOfPointRelease", $bVDllType, $vecV), "VectorOfVectorOfPointRelease", @error)

    If $bVIsArray Then
        _VectorOfVectorOfPointRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfVectorOfPointRelease

Func _VectorOfVectorOfPointCopyData($v, $data)
    ; CVAPI(void) VectorOfVectorOfPointCopyData(std::vector< std::vector< cv::Point > >* v, std::vector< cv::Point >* data);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfVectorOfPointCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfVectorOfPointPush($vecV, $v[$i])
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
        $vecData = _VectorOfPointCreate()

        $iArrDataSize = UBound($data)
        For $i = 0 To $iArrDataSize - 1
            _VectorOfPointPush($vecData, $data[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfVectorOfPointCopyData", $bVDllType, $vecV, $bDataDllType, $vecData), "VectorOfVectorOfPointCopyData", @error)

    If $bDataIsArray Then
        _VectorOfPointRelease($vecData)
    EndIf

    If $bVIsArray Then
        _VectorOfVectorOfPointRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfVectorOfPointCopyData

Func _VectorOfVectorOfPointGetItemPtr($vec, $index, $element)
    ; CVAPI(void) VectorOfVectorOfPointGetItemPtr(std::vector<  std::vector< cv::Point > >* vec, int index, std::vector< cv::Point >** element);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfVectorOfPointCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfVectorOfPointPush($vecVec, $vec[$i])
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
        $vecElement = _VectorOfPointCreate()

        $iArrElementSize = UBound($element)
        For $i = 0 To $iArrElementSize - 1
            _VectorOfPointPush($vecElement, $element[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfVectorOfPointGetItemPtr", $bVecDllType, $vecVec, "int", $index, $bElementDllType, $vecElement), "VectorOfVectorOfPointGetItemPtr", @error)

    If $bElementIsArray Then
        _VectorOfPointRelease($vecElement)
    EndIf

    If $bVecIsArray Then
        _VectorOfVectorOfPointRelease($vecVec)
    EndIf
EndFunc   ;==>_VectorOfVectorOfPointGetItemPtr

Func _cveInputArrayFromVectorOfVectorOfPoint($vec)
    ; CVAPI(cv::_InputArray*) cveInputArrayFromVectorOfVectorOfPoint(std::vector< std::vector< cv::Point > >* vec);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfVectorOfPointCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfVectorOfPointPush($vecVec, $vec[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveInputArrayFromVectorOfVectorOfPoint", $bVecDllType, $vecVec), "cveInputArrayFromVectorOfVectorOfPoint", @error)

    If $bVecIsArray Then
        _VectorOfVectorOfPointRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveInputArrayFromVectorOfVectorOfPoint

Func _cveOutputArrayFromVectorOfVectorOfPoint($vec)
    ; CVAPI(cv::_OutputArray*) cveOutputArrayFromVectorOfVectorOfPoint(std::vector< std::vector< cv::Point > >* vec);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfVectorOfPointCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfVectorOfPointPush($vecVec, $vec[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveOutputArrayFromVectorOfVectorOfPoint", $bVecDllType, $vecVec), "cveOutputArrayFromVectorOfVectorOfPoint", @error)

    If $bVecIsArray Then
        _VectorOfVectorOfPointRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveOutputArrayFromVectorOfVectorOfPoint

Func _cveInputOutputArrayFromVectorOfVectorOfPoint($vec)
    ; CVAPI(cv::_InputOutputArray*) cveInputOutputArrayFromVectorOfVectorOfPoint(std::vector< std::vector< cv::Point > >* vec);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfVectorOfPointCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfVectorOfPointPush($vecVec, $vec[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveInputOutputArrayFromVectorOfVectorOfPoint", $bVecDllType, $vecVec), "cveInputOutputArrayFromVectorOfVectorOfPoint", @error)

    If $bVecIsArray Then
        _VectorOfVectorOfPointRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveInputOutputArrayFromVectorOfVectorOfPoint

Func _VectorOfVectorOfPointSizeOfItemInBytes()
    ; CVAPI(int) VectorOfVectorOfPointSizeOfItemInBytes();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "VectorOfVectorOfPointSizeOfItemInBytes"), "VectorOfVectorOfPointSizeOfItemInBytes", @error)
EndFunc   ;==>_VectorOfVectorOfPointSizeOfItemInBytes