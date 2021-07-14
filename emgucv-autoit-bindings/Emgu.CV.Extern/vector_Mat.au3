#include-once
#include "..\CVEUtils.au3"

Func _VectorOfMatCreate()
    ; CVAPI(std::vector< cv::Mat >*) VectorOfMatCreate();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfMatCreate"), "VectorOfMatCreate", @error)
EndFunc   ;==>_VectorOfMatCreate

Func _VectorOfMatCreateSize($size)
    ; CVAPI(std::vector< cv::Mat >*) VectorOfMatCreateSize(int size);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfMatCreateSize", "int", $size), "VectorOfMatCreateSize", @error)
EndFunc   ;==>_VectorOfMatCreateSize

Func _VectorOfMatGetSize(ByRef $v)
    ; CVAPI(int) VectorOfMatGetSize(std::vector< cv::Mat >* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfMatCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfMatPush($vecV, $v[$i])
        Next
    Else
        $vecV = $v
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "VectorOfMatGetSize", "ptr", $vecV), "VectorOfMatGetSize", @error)

    If $bVIsArray Then
        _VectorOfMatRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfMatGetSize

Func _VectorOfMatPush(ByRef $v, ByRef $value)
    ; CVAPI(void) VectorOfMatPush(std::vector< cv::Mat >* v, cv::Mat* value);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfMatCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfMatPush($vecV, $v[$i])
        Next
    Else
        $vecV = $v
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfMatPush", "ptr", $vecV, "ptr", $value), "VectorOfMatPush", @error)

    If $bVIsArray Then
        _VectorOfMatRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfMatPush

Func _VectorOfMatPushVector(ByRef $v, ByRef $other)
    ; CVAPI(void) VectorOfMatPushVector(std::vector< cv::Mat >* v, std::vector< cv::Mat >* other);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfMatCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfMatPush($vecV, $v[$i])
        Next
    Else
        $vecV = $v
    EndIf

    Local $vecOther, $iArrOtherSize
    Local $bOtherIsArray = VarGetType($other) == "Array"

    If $bOtherIsArray Then
        $vecOther = _VectorOfMatCreate()

        $iArrOtherSize = UBound($other)
        For $i = 0 To $iArrOtherSize - 1
            _VectorOfMatPush($vecOther, $other[$i])
        Next
    Else
        $vecOther = $other
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfMatPushVector", "ptr", $vecV, "ptr", $vecOther), "VectorOfMatPushVector", @error)

    If $bOtherIsArray Then
        _VectorOfMatRelease($vecOther)
    EndIf

    If $bVIsArray Then
        _VectorOfMatRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfMatPushVector

Func _VectorOfMatGetStartAddress(ByRef $v)
    ; CVAPI(cv::Mat*) VectorOfMatGetStartAddress(std::vector< cv::Mat >* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfMatCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfMatPush($vecV, $v[$i])
        Next
    Else
        $vecV = $v
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfMatGetStartAddress", "ptr", $vecV), "VectorOfMatGetStartAddress", @error)

    If $bVIsArray Then
        _VectorOfMatRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfMatGetStartAddress

Func _VectorOfMatGetEndAddress(ByRef $v)
    ; CVAPI(void*) VectorOfMatGetEndAddress(std::vector< cv::Mat >* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfMatCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfMatPush($vecV, $v[$i])
        Next
    Else
        $vecV = $v
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfMatGetEndAddress", "ptr", $vecV), "VectorOfMatGetEndAddress", @error)

    If $bVIsArray Then
        _VectorOfMatRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfMatGetEndAddress

Func _VectorOfMatClear(ByRef $v)
    ; CVAPI(void) VectorOfMatClear(std::vector< cv::Mat >* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfMatCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfMatPush($vecV, $v[$i])
        Next
    Else
        $vecV = $v
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfMatClear", "ptr", $vecV), "VectorOfMatClear", @error)

    If $bVIsArray Then
        _VectorOfMatRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfMatClear

Func _VectorOfMatRelease(ByRef $v)
    ; CVAPI(void) VectorOfMatRelease(std::vector< cv::Mat >** v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfMatCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfMatPush($vecV, $v[$i])
        Next
    Else
        $vecV = $v
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfMatRelease", "ptr*", $vecV), "VectorOfMatRelease", @error)

    If $bVIsArray Then
        _VectorOfMatRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfMatRelease

Func _VectorOfMatCopyData(ByRef $v, ByRef $data)
    ; CVAPI(void) VectorOfMatCopyData(std::vector< cv::Mat >* v, cv::Mat* data);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfMatCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfMatPush($vecV, $v[$i])
        Next
    Else
        $vecV = $v
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfMatCopyData", "ptr", $vecV, "ptr", $data), "VectorOfMatCopyData", @error)

    If $bVIsArray Then
        _VectorOfMatRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfMatCopyData

Func _VectorOfMatGetItemPtr(ByRef $vec, $index, ByRef $element)
    ; CVAPI(void) VectorOfMatGetItemPtr(std::vector<  cv::Mat >* vec, int index, cv::Mat** element);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfMatCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfMatPush($vecVec, $vec[$i])
        Next
    Else
        $vecVec = $vec
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfMatGetItemPtr", "ptr", $vecVec, "int", $index, "ptr*", $element), "VectorOfMatGetItemPtr", @error)

    If $bVecIsArray Then
        _VectorOfMatRelease($vecVec)
    EndIf
EndFunc   ;==>_VectorOfMatGetItemPtr

Func _cveInputArrayFromVectorOfMat(ByRef $vec)
    ; CVAPI(cv::_InputArray*) cveInputArrayFromVectorOfMat(std::vector< cv::Mat >* vec);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfMatCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfMatPush($vecVec, $vec[$i])
        Next
    Else
        $vecVec = $vec
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveInputArrayFromVectorOfMat", "ptr", $vecVec), "cveInputArrayFromVectorOfMat", @error)

    If $bVecIsArray Then
        _VectorOfMatRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveInputArrayFromVectorOfMat

Func _cveOutputArrayFromVectorOfMat(ByRef $vec)
    ; CVAPI(cv::_OutputArray*) cveOutputArrayFromVectorOfMat(std::vector< cv::Mat >* vec);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfMatCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfMatPush($vecVec, $vec[$i])
        Next
    Else
        $vecVec = $vec
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveOutputArrayFromVectorOfMat", "ptr", $vecVec), "cveOutputArrayFromVectorOfMat", @error)

    If $bVecIsArray Then
        _VectorOfMatRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveOutputArrayFromVectorOfMat

Func _cveInputOutputArrayFromVectorOfMat(ByRef $vec)
    ; CVAPI(cv::_InputOutputArray*) cveInputOutputArrayFromVectorOfMat(std::vector< cv::Mat >* vec);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfMatCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfMatPush($vecVec, $vec[$i])
        Next
    Else
        $vecVec = $vec
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveInputOutputArrayFromVectorOfMat", "ptr", $vecVec), "cveInputOutputArrayFromVectorOfMat", @error)

    If $bVecIsArray Then
        _VectorOfMatRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveInputOutputArrayFromVectorOfMat

Func _VectorOfMatSizeOfItemInBytes()
    ; CVAPI(int) VectorOfMatSizeOfItemInBytes();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "VectorOfMatSizeOfItemInBytes"), "VectorOfMatSizeOfItemInBytes", @error)
EndFunc   ;==>_VectorOfMatSizeOfItemInBytes