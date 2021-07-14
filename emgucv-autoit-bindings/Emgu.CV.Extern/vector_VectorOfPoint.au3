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

Func _VectorOfVectorOfPointGetSize(ByRef $v)
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "VectorOfVectorOfPointGetSize", "ptr", $vecV), "VectorOfVectorOfPointGetSize", @error)

    If $bVIsArray Then
        _VectorOfVectorOfPointRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfVectorOfPointGetSize

Func _VectorOfVectorOfPointPush(ByRef $v, ByRef $value)
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfVectorOfPointPush", "ptr", $vecV, "ptr", $vecValue), "VectorOfVectorOfPointPush", @error)

    If $bValueIsArray Then
        _VectorOfPointRelease($vecValue)
    EndIf

    If $bVIsArray Then
        _VectorOfVectorOfPointRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfVectorOfPointPush

Func _VectorOfVectorOfPointPushVector(ByRef $v, ByRef $other)
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfVectorOfPointPushVector", "ptr", $vecV, "ptr", $vecOther), "VectorOfVectorOfPointPushVector", @error)

    If $bOtherIsArray Then
        _VectorOfVectorOfPointRelease($vecOther)
    EndIf

    If $bVIsArray Then
        _VectorOfVectorOfPointRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfVectorOfPointPushVector

Func _VectorOfVectorOfPointGetStartAddress(ByRef $v)
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfVectorOfPointGetStartAddress", "ptr", $vecV), "VectorOfVectorOfPointGetStartAddress", @error)

    If $bVIsArray Then
        _VectorOfVectorOfPointRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfVectorOfPointGetStartAddress

Func _VectorOfVectorOfPointGetEndAddress(ByRef $v)
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfVectorOfPointGetEndAddress", "ptr", $vecV), "VectorOfVectorOfPointGetEndAddress", @error)

    If $bVIsArray Then
        _VectorOfVectorOfPointRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfVectorOfPointGetEndAddress

Func _VectorOfVectorOfPointClear(ByRef $v)
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfVectorOfPointClear", "ptr", $vecV), "VectorOfVectorOfPointClear", @error)

    If $bVIsArray Then
        _VectorOfVectorOfPointRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfVectorOfPointClear

Func _VectorOfVectorOfPointRelease(ByRef $v)
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfVectorOfPointRelease", "ptr*", $vecV), "VectorOfVectorOfPointRelease", @error)

    If $bVIsArray Then
        _VectorOfVectorOfPointRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfVectorOfPointRelease

Func _VectorOfVectorOfPointCopyData(ByRef $v, ByRef $data)
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfVectorOfPointCopyData", "ptr", $vecV, "ptr", $vecData), "VectorOfVectorOfPointCopyData", @error)

    If $bDataIsArray Then
        _VectorOfPointRelease($vecData)
    EndIf

    If $bVIsArray Then
        _VectorOfVectorOfPointRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfVectorOfPointCopyData

Func _VectorOfVectorOfPointGetItemPtr(ByRef $vec, $index, ByRef $element)
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfVectorOfPointGetItemPtr", "ptr", $vecVec, "int", $index, "ptr*", $vecElement), "VectorOfVectorOfPointGetItemPtr", @error)

    If $bElementIsArray Then
        _VectorOfPointRelease($vecElement)
    EndIf

    If $bVecIsArray Then
        _VectorOfVectorOfPointRelease($vecVec)
    EndIf
EndFunc   ;==>_VectorOfVectorOfPointGetItemPtr

Func _cveInputArrayFromVectorOfVectorOfPoint(ByRef $vec)
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveInputArrayFromVectorOfVectorOfPoint", "ptr", $vecVec), "cveInputArrayFromVectorOfVectorOfPoint", @error)

    If $bVecIsArray Then
        _VectorOfVectorOfPointRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveInputArrayFromVectorOfVectorOfPoint

Func _cveOutputArrayFromVectorOfVectorOfPoint(ByRef $vec)
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveOutputArrayFromVectorOfVectorOfPoint", "ptr", $vecVec), "cveOutputArrayFromVectorOfVectorOfPoint", @error)

    If $bVecIsArray Then
        _VectorOfVectorOfPointRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveOutputArrayFromVectorOfVectorOfPoint

Func _cveInputOutputArrayFromVectorOfVectorOfPoint(ByRef $vec)
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveInputOutputArrayFromVectorOfVectorOfPoint", "ptr", $vecVec), "cveInputOutputArrayFromVectorOfVectorOfPoint", @error)

    If $bVecIsArray Then
        _VectorOfVectorOfPointRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveInputOutputArrayFromVectorOfVectorOfPoint

Func _VectorOfVectorOfPointSizeOfItemInBytes()
    ; CVAPI(int) VectorOfVectorOfPointSizeOfItemInBytes();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "VectorOfVectorOfPointSizeOfItemInBytes"), "VectorOfVectorOfPointSizeOfItemInBytes", @error)
EndFunc   ;==>_VectorOfVectorOfPointSizeOfItemInBytes