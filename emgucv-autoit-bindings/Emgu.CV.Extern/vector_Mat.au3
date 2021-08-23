#include-once
#include "..\CVEUtils.au3"

Func _VectorOfMatCreate()
    ; CVAPI(std::vector<cv::Mat>*) VectorOfMatCreate();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfMatCreate"), "VectorOfMatCreate", @error)
EndFunc   ;==>_VectorOfMatCreate

Func _VectorOfMatCreateSize($size)
    ; CVAPI(std::vector<cv::Mat>*) VectorOfMatCreateSize(int size);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfMatCreateSize", "int", $size), "VectorOfMatCreateSize", @error)
EndFunc   ;==>_VectorOfMatCreateSize

Func _VectorOfMatGetSize($v)
    ; CVAPI(int) VectorOfMatGetSize(std::vector<cv::Mat>* v);

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

    Local $sVDllType
    If IsDllStruct($v) Then
        $sVDllType = "struct*"
    Else
        $sVDllType = "ptr"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "VectorOfMatGetSize", $sVDllType, $vecV), "VectorOfMatGetSize", @error)

    If $bVIsArray Then
        _VectorOfMatRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfMatGetSize

Func _VectorOfMatPush($v, $value)
    ; CVAPI(void) VectorOfMatPush(std::vector<cv::Mat>* v, cv::Mat* value);

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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfMatPush", $sVDllType, $vecV, $sValueDllType, $value), "VectorOfMatPush", @error)

    If $bVIsArray Then
        _VectorOfMatRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfMatPush

Func _VectorOfMatPushVector($v, $other)
    ; CVAPI(void) VectorOfMatPushVector(std::vector<cv::Mat>* v, std::vector<cv::Mat>* other);

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

    Local $sVDllType
    If IsDllStruct($v) Then
        $sVDllType = "struct*"
    Else
        $sVDllType = "ptr"
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

    Local $sOtherDllType
    If IsDllStruct($other) Then
        $sOtherDllType = "struct*"
    Else
        $sOtherDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfMatPushVector", $sVDllType, $vecV, $sOtherDllType, $vecOther), "VectorOfMatPushVector", @error)

    If $bOtherIsArray Then
        _VectorOfMatRelease($vecOther)
    EndIf

    If $bVIsArray Then
        _VectorOfMatRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfMatPushVector

Func _VectorOfMatGetStartAddress($v)
    ; CVAPI(cv::Mat*) VectorOfMatGetStartAddress(std::vector<cv::Mat>* v);

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

    Local $sVDllType
    If IsDllStruct($v) Then
        $sVDllType = "struct*"
    Else
        $sVDllType = "ptr"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfMatGetStartAddress", $sVDllType, $vecV), "VectorOfMatGetStartAddress", @error)

    If $bVIsArray Then
        _VectorOfMatRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfMatGetStartAddress

Func _VectorOfMatGetEndAddress($v)
    ; CVAPI(void*) VectorOfMatGetEndAddress(std::vector<cv::Mat>* v);

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

    Local $sVDllType
    If IsDllStruct($v) Then
        $sVDllType = "struct*"
    Else
        $sVDllType = "ptr"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfMatGetEndAddress", $sVDllType, $vecV), "VectorOfMatGetEndAddress", @error)

    If $bVIsArray Then
        _VectorOfMatRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfMatGetEndAddress

Func _VectorOfMatClear($v)
    ; CVAPI(void) VectorOfMatClear(std::vector<cv::Mat>* v);

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

    Local $sVDllType
    If IsDllStruct($v) Then
        $sVDllType = "struct*"
    Else
        $sVDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfMatClear", $sVDllType, $vecV), "VectorOfMatClear", @error)

    If $bVIsArray Then
        _VectorOfMatRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfMatClear

Func _VectorOfMatRelease($v)
    ; CVAPI(void) VectorOfMatRelease(std::vector<cv::Mat>** v);

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

    Local $sVDllType
    If IsDllStruct($v) Then
        $sVDllType = "struct*"
    ElseIf $v == Null Then
        $sVDllType = "ptr"
    Else
        $sVDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfMatRelease", $sVDllType, $vecV), "VectorOfMatRelease", @error)

    If $bVIsArray Then
        _VectorOfMatRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfMatRelease

Func _VectorOfMatCopyData($v, $data)
    ; CVAPI(void) VectorOfMatCopyData(std::vector<cv::Mat>* v, cv::Mat* data);

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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfMatCopyData", $sVDllType, $vecV, $sDataDllType, $data), "VectorOfMatCopyData", @error)

    If $bVIsArray Then
        _VectorOfMatRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfMatCopyData

Func _VectorOfMatGetItemPtr($vec, $index, $element)
    ; CVAPI(void) VectorOfMatGetItemPtr(std::vector<cv::Mat>* vec, int index, cv::Mat** element);

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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfMatGetItemPtr", $sVecDllType, $vecVec, "int", $index, $sElementDllType, $element), "VectorOfMatGetItemPtr", @error)

    If $bVecIsArray Then
        _VectorOfMatRelease($vecVec)
    EndIf
EndFunc   ;==>_VectorOfMatGetItemPtr

Func _cveInputArrayFromVectorOfMat($vec)
    ; CVAPI(cv::_InputArray*) cveInputArrayFromVectorOfMat(std::vector<cv::Mat>* vec);

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

    Local $sVecDllType
    If IsDllStruct($vec) Then
        $sVecDllType = "struct*"
    Else
        $sVecDllType = "ptr"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveInputArrayFromVectorOfMat", $sVecDllType, $vecVec), "cveInputArrayFromVectorOfMat", @error)

    If $bVecIsArray Then
        _VectorOfMatRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveInputArrayFromVectorOfMat

Func _cveOutputArrayFromVectorOfMat($vec)
    ; CVAPI(cv::_OutputArray*) cveOutputArrayFromVectorOfMat(std::vector<cv::Mat>* vec);

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

    Local $sVecDllType
    If IsDllStruct($vec) Then
        $sVecDllType = "struct*"
    Else
        $sVecDllType = "ptr"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveOutputArrayFromVectorOfMat", $sVecDllType, $vecVec), "cveOutputArrayFromVectorOfMat", @error)

    If $bVecIsArray Then
        _VectorOfMatRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveOutputArrayFromVectorOfMat

Func _cveInputOutputArrayFromVectorOfMat($vec)
    ; CVAPI(cv::_InputOutputArray*) cveInputOutputArrayFromVectorOfMat(std::vector<cv::Mat>* vec);

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

    Local $sVecDllType
    If IsDllStruct($vec) Then
        $sVecDllType = "struct*"
    Else
        $sVecDllType = "ptr"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveInputOutputArrayFromVectorOfMat", $sVecDllType, $vecVec), "cveInputOutputArrayFromVectorOfMat", @error)

    If $bVecIsArray Then
        _VectorOfMatRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveInputOutputArrayFromVectorOfMat

Func _VectorOfMatSizeOfItemInBytes()
    ; CVAPI(int) VectorOfMatSizeOfItemInBytes();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "VectorOfMatSizeOfItemInBytes"), "VectorOfMatSizeOfItemInBytes", @error)
EndFunc   ;==>_VectorOfMatSizeOfItemInBytes