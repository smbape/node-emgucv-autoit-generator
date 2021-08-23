#include-once
#include "..\CVEUtils.au3"

Func _VectorOfUMatCreate()
    ; CVAPI(std::vector<cv::UMat>*) VectorOfUMatCreate();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfUMatCreate"), "VectorOfUMatCreate", @error)
EndFunc   ;==>_VectorOfUMatCreate

Func _VectorOfUMatCreateSize($size)
    ; CVAPI(std::vector<cv::UMat>*) VectorOfUMatCreateSize(int size);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfUMatCreateSize", "int", $size), "VectorOfUMatCreateSize", @error)
EndFunc   ;==>_VectorOfUMatCreateSize

Func _VectorOfUMatGetSize($v)
    ; CVAPI(int) VectorOfUMatGetSize(std::vector<cv::UMat>* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfUMatCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfUMatPush($vecV, $v[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "VectorOfUMatGetSize", $sVDllType, $vecV), "VectorOfUMatGetSize", @error)

    If $bVIsArray Then
        _VectorOfUMatRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfUMatGetSize

Func _VectorOfUMatPush($v, $value)
    ; CVAPI(void) VectorOfUMatPush(std::vector<cv::UMat>* v, cv::UMat* value);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfUMatCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfUMatPush($vecV, $v[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfUMatPush", $sVDllType, $vecV, $sValueDllType, $value), "VectorOfUMatPush", @error)

    If $bVIsArray Then
        _VectorOfUMatRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfUMatPush

Func _VectorOfUMatPushVector($v, $other)
    ; CVAPI(void) VectorOfUMatPushVector(std::vector<cv::UMat>* v, std::vector<cv::UMat>* other);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfUMatCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfUMatPush($vecV, $v[$i])
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
        $vecOther = _VectorOfUMatCreate()

        $iArrOtherSize = UBound($other)
        For $i = 0 To $iArrOtherSize - 1
            _VectorOfUMatPush($vecOther, $other[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfUMatPushVector", $sVDllType, $vecV, $sOtherDllType, $vecOther), "VectorOfUMatPushVector", @error)

    If $bOtherIsArray Then
        _VectorOfUMatRelease($vecOther)
    EndIf

    If $bVIsArray Then
        _VectorOfUMatRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfUMatPushVector

Func _VectorOfUMatGetStartAddress($v)
    ; CVAPI(cv::UMat*) VectorOfUMatGetStartAddress(std::vector<cv::UMat>* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfUMatCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfUMatPush($vecV, $v[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfUMatGetStartAddress", $sVDllType, $vecV), "VectorOfUMatGetStartAddress", @error)

    If $bVIsArray Then
        _VectorOfUMatRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfUMatGetStartAddress

Func _VectorOfUMatGetEndAddress($v)
    ; CVAPI(void*) VectorOfUMatGetEndAddress(std::vector<cv::UMat>* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfUMatCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfUMatPush($vecV, $v[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfUMatGetEndAddress", $sVDllType, $vecV), "VectorOfUMatGetEndAddress", @error)

    If $bVIsArray Then
        _VectorOfUMatRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfUMatGetEndAddress

Func _VectorOfUMatClear($v)
    ; CVAPI(void) VectorOfUMatClear(std::vector<cv::UMat>* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfUMatCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfUMatPush($vecV, $v[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfUMatClear", $sVDllType, $vecV), "VectorOfUMatClear", @error)

    If $bVIsArray Then
        _VectorOfUMatRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfUMatClear

Func _VectorOfUMatRelease($v)
    ; CVAPI(void) VectorOfUMatRelease(std::vector<cv::UMat>** v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfUMatCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfUMatPush($vecV, $v[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfUMatRelease", $sVDllType, $vecV), "VectorOfUMatRelease", @error)

    If $bVIsArray Then
        _VectorOfUMatRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfUMatRelease

Func _VectorOfUMatCopyData($v, $data)
    ; CVAPI(void) VectorOfUMatCopyData(std::vector<cv::UMat>* v, cv::UMat* data);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfUMatCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfUMatPush($vecV, $v[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfUMatCopyData", $sVDllType, $vecV, $sDataDllType, $data), "VectorOfUMatCopyData", @error)

    If $bVIsArray Then
        _VectorOfUMatRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfUMatCopyData

Func _VectorOfUMatGetItemPtr($vec, $index, $element)
    ; CVAPI(void) VectorOfUMatGetItemPtr(std::vector<cv::UMat>* vec, int index, cv::UMat** element);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfUMatCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfUMatPush($vecVec, $vec[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfUMatGetItemPtr", $sVecDllType, $vecVec, "int", $index, $sElementDllType, $element), "VectorOfUMatGetItemPtr", @error)

    If $bVecIsArray Then
        _VectorOfUMatRelease($vecVec)
    EndIf
EndFunc   ;==>_VectorOfUMatGetItemPtr

Func _cveInputArrayFromVectorOfUMat($vec)
    ; CVAPI(cv::_InputArray*) cveInputArrayFromVectorOfUMat(std::vector<cv::UMat>* vec);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfUMatCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfUMatPush($vecVec, $vec[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveInputArrayFromVectorOfUMat", $sVecDllType, $vecVec), "cveInputArrayFromVectorOfUMat", @error)

    If $bVecIsArray Then
        _VectorOfUMatRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveInputArrayFromVectorOfUMat

Func _cveOutputArrayFromVectorOfUMat($vec)
    ; CVAPI(cv::_OutputArray*) cveOutputArrayFromVectorOfUMat(std::vector<cv::UMat>* vec);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfUMatCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfUMatPush($vecVec, $vec[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveOutputArrayFromVectorOfUMat", $sVecDllType, $vecVec), "cveOutputArrayFromVectorOfUMat", @error)

    If $bVecIsArray Then
        _VectorOfUMatRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveOutputArrayFromVectorOfUMat

Func _cveInputOutputArrayFromVectorOfUMat($vec)
    ; CVAPI(cv::_InputOutputArray*) cveInputOutputArrayFromVectorOfUMat(std::vector<cv::UMat>* vec);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfUMatCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfUMatPush($vecVec, $vec[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveInputOutputArrayFromVectorOfUMat", $sVecDllType, $vecVec), "cveInputOutputArrayFromVectorOfUMat", @error)

    If $bVecIsArray Then
        _VectorOfUMatRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveInputOutputArrayFromVectorOfUMat

Func _VectorOfUMatSizeOfItemInBytes()
    ; CVAPI(int) VectorOfUMatSizeOfItemInBytes();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "VectorOfUMatSizeOfItemInBytes"), "VectorOfUMatSizeOfItemInBytes", @error)
EndFunc   ;==>_VectorOfUMatSizeOfItemInBytes