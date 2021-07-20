#include-once
#include "..\CVEUtils.au3"

Func _VectorOfGMatCreate()
    ; CVAPI(std::vector< cv::GMat >*) VectorOfGMatCreate();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfGMatCreate"), "VectorOfGMatCreate", @error)
EndFunc   ;==>_VectorOfGMatCreate

Func _VectorOfGMatCreateSize($size)
    ; CVAPI(std::vector< cv::GMat >*) VectorOfGMatCreateSize(int size);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfGMatCreateSize", "int", $size), "VectorOfGMatCreateSize", @error)
EndFunc   ;==>_VectorOfGMatCreateSize

Func _VectorOfGMatGetSize($v)
    ; CVAPI(int) VectorOfGMatGetSize(std::vector< cv::GMat >* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfGMatCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfGMatPush($vecV, $v[$i])
        Next
    Else
        $vecV = $v
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "VectorOfGMatGetSize", "ptr", $vecV), "VectorOfGMatGetSize", @error)

    If $bVIsArray Then
        _VectorOfGMatRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfGMatGetSize

Func _VectorOfGMatPush($v, $value)
    ; CVAPI(void) VectorOfGMatPush(std::vector< cv::GMat >* v, cv::GMat* value);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfGMatCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfGMatPush($vecV, $v[$i])
        Next
    Else
        $vecV = $v
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfGMatPush", "ptr", $vecV, "ptr", $value), "VectorOfGMatPush", @error)

    If $bVIsArray Then
        _VectorOfGMatRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfGMatPush

Func _VectorOfGMatPushVector($v, $other)
    ; CVAPI(void) VectorOfGMatPushVector(std::vector< cv::GMat >* v, std::vector< cv::GMat >* other);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfGMatCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfGMatPush($vecV, $v[$i])
        Next
    Else
        $vecV = $v
    EndIf

    Local $vecOther, $iArrOtherSize
    Local $bOtherIsArray = VarGetType($other) == "Array"

    If $bOtherIsArray Then
        $vecOther = _VectorOfGMatCreate()

        $iArrOtherSize = UBound($other)
        For $i = 0 To $iArrOtherSize - 1
            _VectorOfGMatPush($vecOther, $other[$i])
        Next
    Else
        $vecOther = $other
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfGMatPushVector", "ptr", $vecV, "ptr", $vecOther), "VectorOfGMatPushVector", @error)

    If $bOtherIsArray Then
        _VectorOfGMatRelease($vecOther)
    EndIf

    If $bVIsArray Then
        _VectorOfGMatRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfGMatPushVector

Func _VectorOfGMatGetStartAddress($v)
    ; CVAPI(cv::GMat*) VectorOfGMatGetStartAddress(std::vector< cv::GMat >* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfGMatCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfGMatPush($vecV, $v[$i])
        Next
    Else
        $vecV = $v
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfGMatGetStartAddress", "ptr", $vecV), "VectorOfGMatGetStartAddress", @error)

    If $bVIsArray Then
        _VectorOfGMatRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfGMatGetStartAddress

Func _VectorOfGMatGetEndAddress($v)
    ; CVAPI(void*) VectorOfGMatGetEndAddress(std::vector< cv::GMat >* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfGMatCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfGMatPush($vecV, $v[$i])
        Next
    Else
        $vecV = $v
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfGMatGetEndAddress", "ptr", $vecV), "VectorOfGMatGetEndAddress", @error)

    If $bVIsArray Then
        _VectorOfGMatRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfGMatGetEndAddress

Func _VectorOfGMatClear($v)
    ; CVAPI(void) VectorOfGMatClear(std::vector< cv::GMat >* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfGMatCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfGMatPush($vecV, $v[$i])
        Next
    Else
        $vecV = $v
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfGMatClear", "ptr", $vecV), "VectorOfGMatClear", @error)

    If $bVIsArray Then
        _VectorOfGMatRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfGMatClear

Func _VectorOfGMatRelease($v)
    ; CVAPI(void) VectorOfGMatRelease(std::vector< cv::GMat >** v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfGMatCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfGMatPush($vecV, $v[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfGMatRelease", $bVDllType, $vecV), "VectorOfGMatRelease", @error)

    If $bVIsArray Then
        _VectorOfGMatRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfGMatRelease

Func _VectorOfGMatCopyData($v, $data)
    ; CVAPI(void) VectorOfGMatCopyData(std::vector< cv::GMat >* v, cv::GMat* data);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfGMatCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfGMatPush($vecV, $v[$i])
        Next
    Else
        $vecV = $v
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfGMatCopyData", "ptr", $vecV, "ptr", $data), "VectorOfGMatCopyData", @error)

    If $bVIsArray Then
        _VectorOfGMatRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfGMatCopyData

Func _VectorOfGMatGetItemPtr($vec, $index, $element)
    ; CVAPI(void) VectorOfGMatGetItemPtr(std::vector<  cv::GMat >* vec, int index, cv::GMat** element);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfGMatCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfGMatPush($vecVec, $vec[$i])
        Next
    Else
        $vecVec = $vec
    EndIf

    Local $bElementDllType
    If VarGetType($element) == "DLLStruct" Then
        $bElementDllType = "struct*"
    Else
        $bElementDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfGMatGetItemPtr", "ptr", $vecVec, "int", $index, $bElementDllType, $element), "VectorOfGMatGetItemPtr", @error)

    If $bVecIsArray Then
        _VectorOfGMatRelease($vecVec)
    EndIf
EndFunc   ;==>_VectorOfGMatGetItemPtr

Func _cveInputArrayFromVectorOfGMat($vec)
    ; CVAPI(cv::_InputArray*) cveInputArrayFromVectorOfGMat(std::vector< cv::GMat >* vec);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfGMatCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfGMatPush($vecVec, $vec[$i])
        Next
    Else
        $vecVec = $vec
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveInputArrayFromVectorOfGMat", "ptr", $vecVec), "cveInputArrayFromVectorOfGMat", @error)

    If $bVecIsArray Then
        _VectorOfGMatRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveInputArrayFromVectorOfGMat

Func _cveOutputArrayFromVectorOfGMat($vec)
    ; CVAPI(cv::_OutputArray*) cveOutputArrayFromVectorOfGMat(std::vector< cv::GMat >* vec);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfGMatCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfGMatPush($vecVec, $vec[$i])
        Next
    Else
        $vecVec = $vec
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveOutputArrayFromVectorOfGMat", "ptr", $vecVec), "cveOutputArrayFromVectorOfGMat", @error)

    If $bVecIsArray Then
        _VectorOfGMatRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveOutputArrayFromVectorOfGMat

Func _cveInputOutputArrayFromVectorOfGMat($vec)
    ; CVAPI(cv::_InputOutputArray*) cveInputOutputArrayFromVectorOfGMat(std::vector< cv::GMat >* vec);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfGMatCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfGMatPush($vecVec, $vec[$i])
        Next
    Else
        $vecVec = $vec
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveInputOutputArrayFromVectorOfGMat", "ptr", $vecVec), "cveInputOutputArrayFromVectorOfGMat", @error)

    If $bVecIsArray Then
        _VectorOfGMatRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveInputOutputArrayFromVectorOfGMat

Func _VectorOfGMatSizeOfItemInBytes()
    ; CVAPI(int) VectorOfGMatSizeOfItemInBytes();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "VectorOfGMatSizeOfItemInBytes"), "VectorOfGMatSizeOfItemInBytes", @error)
EndFunc   ;==>_VectorOfGMatSizeOfItemInBytes