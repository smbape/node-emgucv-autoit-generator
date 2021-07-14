#include-once
#include <..\CVEUtils.au3>

Func _VectorOfVectorOfDMatchCreate()
    ; CVAPI(std::vector< std::vector< cv::DMatch > >*) VectorOfVectorOfDMatchCreate();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfVectorOfDMatchCreate"), "VectorOfVectorOfDMatchCreate", @error)
EndFunc   ;==>_VectorOfVectorOfDMatchCreate

Func _VectorOfVectorOfDMatchCreateSize($size)
    ; CVAPI(std::vector< std::vector< cv::DMatch > >*) VectorOfVectorOfDMatchCreateSize(int size);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfVectorOfDMatchCreateSize", "int", $size), "VectorOfVectorOfDMatchCreateSize", @error)
EndFunc   ;==>_VectorOfVectorOfDMatchCreateSize

Func _VectorOfVectorOfDMatchGetSize(ByRef $v)
    ; CVAPI(int) VectorOfVectorOfDMatchGetSize(std::vector< std::vector< cv::DMatch > >* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfVectorOfDMatchCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfVectorOfDMatchPush($vecV, $v[$i])
        Next
    Else
        $vecV = $v
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "VectorOfVectorOfDMatchGetSize", "ptr", $vecV), "VectorOfVectorOfDMatchGetSize", @error)

    If $bVIsArray Then
        _VectorOfVectorOfDMatchRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfVectorOfDMatchGetSize

Func _VectorOfVectorOfDMatchPush(ByRef $v, ByRef $value)
    ; CVAPI(void) VectorOfVectorOfDMatchPush(std::vector< std::vector< cv::DMatch > >* v, std::vector< cv::DMatch >* value);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfVectorOfDMatchCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfVectorOfDMatchPush($vecV, $v[$i])
        Next
    Else
        $vecV = $v
    EndIf

    Local $vecValue, $iArrValueSize
    Local $bValueIsArray = VarGetType($value) == "Array"

    If $bValueIsArray Then
        $vecValue = _VectorOfDMatchCreate()

        $iArrValueSize = UBound($value)
        For $i = 0 To $iArrValueSize - 1
            _VectorOfDMatchPush($vecValue, $value[$i])
        Next
    Else
        $vecValue = $value
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfVectorOfDMatchPush", "ptr", $vecV, "ptr", $vecValue), "VectorOfVectorOfDMatchPush", @error)

    If $bValueIsArray Then
        _VectorOfDMatchRelease($vecValue)
    EndIf

    If $bVIsArray Then
        _VectorOfVectorOfDMatchRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfVectorOfDMatchPush

Func _VectorOfVectorOfDMatchPushVector(ByRef $v, ByRef $other)
    ; CVAPI(void) VectorOfVectorOfDMatchPushVector(std::vector< std::vector< cv::DMatch > >* v, std::vector< std::vector< cv::DMatch > >* other);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfVectorOfDMatchCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfVectorOfDMatchPush($vecV, $v[$i])
        Next
    Else
        $vecV = $v
    EndIf

    Local $vecOther, $iArrOtherSize
    Local $bOtherIsArray = VarGetType($other) == "Array"

    If $bOtherIsArray Then
        $vecOther = _VectorOfVectorOfDMatchCreate()

        $iArrOtherSize = UBound($other)
        For $i = 0 To $iArrOtherSize - 1
            _VectorOfVectorOfDMatchPush($vecOther, $other[$i])
        Next
    Else
        $vecOther = $other
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfVectorOfDMatchPushVector", "ptr", $vecV, "ptr", $vecOther), "VectorOfVectorOfDMatchPushVector", @error)

    If $bOtherIsArray Then
        _VectorOfVectorOfDMatchRelease($vecOther)
    EndIf

    If $bVIsArray Then
        _VectorOfVectorOfDMatchRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfVectorOfDMatchPushVector

Func _VectorOfVectorOfDMatchGetStartAddress(ByRef $v)
    ; CVAPI(std::vector< cv::DMatch >*) VectorOfVectorOfDMatchGetStartAddress(std::vector< std::vector< cv::DMatch > >* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfVectorOfDMatchCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfVectorOfDMatchPush($vecV, $v[$i])
        Next
    Else
        $vecV = $v
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfVectorOfDMatchGetStartAddress", "ptr", $vecV), "VectorOfVectorOfDMatchGetStartAddress", @error)

    If $bVIsArray Then
        _VectorOfVectorOfDMatchRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfVectorOfDMatchGetStartAddress

Func _VectorOfVectorOfDMatchGetEndAddress(ByRef $v)
    ; CVAPI(void*) VectorOfVectorOfDMatchGetEndAddress(std::vector< std::vector< cv::DMatch > >* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfVectorOfDMatchCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfVectorOfDMatchPush($vecV, $v[$i])
        Next
    Else
        $vecV = $v
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfVectorOfDMatchGetEndAddress", "ptr", $vecV), "VectorOfVectorOfDMatchGetEndAddress", @error)

    If $bVIsArray Then
        _VectorOfVectorOfDMatchRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfVectorOfDMatchGetEndAddress

Func _VectorOfVectorOfDMatchClear(ByRef $v)
    ; CVAPI(void) VectorOfVectorOfDMatchClear(std::vector< std::vector< cv::DMatch > >* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfVectorOfDMatchCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfVectorOfDMatchPush($vecV, $v[$i])
        Next
    Else
        $vecV = $v
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfVectorOfDMatchClear", "ptr", $vecV), "VectorOfVectorOfDMatchClear", @error)

    If $bVIsArray Then
        _VectorOfVectorOfDMatchRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfVectorOfDMatchClear

Func _VectorOfVectorOfDMatchRelease(ByRef $v)
    ; CVAPI(void) VectorOfVectorOfDMatchRelease(std::vector< std::vector< cv::DMatch > >** v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfVectorOfDMatchCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfVectorOfDMatchPush($vecV, $v[$i])
        Next
    Else
        $vecV = $v
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfVectorOfDMatchRelease", "ptr*", $vecV), "VectorOfVectorOfDMatchRelease", @error)

    If $bVIsArray Then
        _VectorOfVectorOfDMatchRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfVectorOfDMatchRelease

Func _VectorOfVectorOfDMatchCopyData(ByRef $v, ByRef $data)
    ; CVAPI(void) VectorOfVectorOfDMatchCopyData(std::vector< std::vector< cv::DMatch > >* v, std::vector< cv::DMatch >* data);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfVectorOfDMatchCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfVectorOfDMatchPush($vecV, $v[$i])
        Next
    Else
        $vecV = $v
    EndIf

    Local $vecData, $iArrDataSize
    Local $bDataIsArray = VarGetType($data) == "Array"

    If $bDataIsArray Then
        $vecData = _VectorOfDMatchCreate()

        $iArrDataSize = UBound($data)
        For $i = 0 To $iArrDataSize - 1
            _VectorOfDMatchPush($vecData, $data[$i])
        Next
    Else
        $vecData = $data
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfVectorOfDMatchCopyData", "ptr", $vecV, "ptr", $vecData), "VectorOfVectorOfDMatchCopyData", @error)

    If $bDataIsArray Then
        _VectorOfDMatchRelease($vecData)
    EndIf

    If $bVIsArray Then
        _VectorOfVectorOfDMatchRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfVectorOfDMatchCopyData

Func _VectorOfVectorOfDMatchGetItemPtr(ByRef $vec, $index, ByRef $element)
    ; CVAPI(void) VectorOfVectorOfDMatchGetItemPtr(std::vector<  std::vector< cv::DMatch > >* vec, int index, std::vector< cv::DMatch >** element);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfVectorOfDMatchCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfVectorOfDMatchPush($vecVec, $vec[$i])
        Next
    Else
        $vecVec = $vec
    EndIf

    Local $vecElement, $iArrElementSize
    Local $bElementIsArray = VarGetType($element) == "Array"

    If $bElementIsArray Then
        $vecElement = _VectorOfDMatchCreate()

        $iArrElementSize = UBound($element)
        For $i = 0 To $iArrElementSize - 1
            _VectorOfDMatchPush($vecElement, $element[$i])
        Next
    Else
        $vecElement = $element
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfVectorOfDMatchGetItemPtr", "ptr", $vecVec, "int", $index, "ptr*", $vecElement), "VectorOfVectorOfDMatchGetItemPtr", @error)

    If $bElementIsArray Then
        _VectorOfDMatchRelease($vecElement)
    EndIf

    If $bVecIsArray Then
        _VectorOfVectorOfDMatchRelease($vecVec)
    EndIf
EndFunc   ;==>_VectorOfVectorOfDMatchGetItemPtr

Func _cveInputArrayFromVectorOfVectorOfDMatch(ByRef $vec)
    ; CVAPI(cv::_InputArray*) cveInputArrayFromVectorOfVectorOfDMatch(std::vector< std::vector< cv::DMatch > >* vec);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfVectorOfDMatchCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfVectorOfDMatchPush($vecVec, $vec[$i])
        Next
    Else
        $vecVec = $vec
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveInputArrayFromVectorOfVectorOfDMatch", "ptr", $vecVec), "cveInputArrayFromVectorOfVectorOfDMatch", @error)

    If $bVecIsArray Then
        _VectorOfVectorOfDMatchRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveInputArrayFromVectorOfVectorOfDMatch

Func _cveOutputArrayFromVectorOfVectorOfDMatch(ByRef $vec)
    ; CVAPI(cv::_OutputArray*) cveOutputArrayFromVectorOfVectorOfDMatch(std::vector< std::vector< cv::DMatch > >* vec);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfVectorOfDMatchCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfVectorOfDMatchPush($vecVec, $vec[$i])
        Next
    Else
        $vecVec = $vec
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveOutputArrayFromVectorOfVectorOfDMatch", "ptr", $vecVec), "cveOutputArrayFromVectorOfVectorOfDMatch", @error)

    If $bVecIsArray Then
        _VectorOfVectorOfDMatchRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveOutputArrayFromVectorOfVectorOfDMatch

Func _cveInputOutputArrayFromVectorOfVectorOfDMatch(ByRef $vec)
    ; CVAPI(cv::_InputOutputArray*) cveInputOutputArrayFromVectorOfVectorOfDMatch(std::vector< std::vector< cv::DMatch > >* vec);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfVectorOfDMatchCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfVectorOfDMatchPush($vecVec, $vec[$i])
        Next
    Else
        $vecVec = $vec
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveInputOutputArrayFromVectorOfVectorOfDMatch", "ptr", $vecVec), "cveInputOutputArrayFromVectorOfVectorOfDMatch", @error)

    If $bVecIsArray Then
        _VectorOfVectorOfDMatchRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveInputOutputArrayFromVectorOfVectorOfDMatch

Func _VectorOfVectorOfDMatchSizeOfItemInBytes()
    ; CVAPI(int) VectorOfVectorOfDMatchSizeOfItemInBytes();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "VectorOfVectorOfDMatchSizeOfItemInBytes"), "VectorOfVectorOfDMatchSizeOfItemInBytes", @error)
EndFunc   ;==>_VectorOfVectorOfDMatchSizeOfItemInBytes