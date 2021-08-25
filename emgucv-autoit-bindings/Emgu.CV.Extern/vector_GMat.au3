#include-once
#include "..\CVEUtils.au3"

Func _VectorOfGMatCreate()
    ; CVAPI(std::vector<cv::GMat>*) VectorOfGMatCreate();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfGMatCreate"), "VectorOfGMatCreate", @error)
EndFunc   ;==>_VectorOfGMatCreate

Func _VectorOfGMatCreateSize($size)
    ; CVAPI(std::vector<cv::GMat>*) VectorOfGMatCreateSize(int size);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfGMatCreateSize", "int", $size), "VectorOfGMatCreateSize", @error)
EndFunc   ;==>_VectorOfGMatCreateSize

Func _VectorOfGMatGetSize($v)
    ; CVAPI(int) VectorOfGMatGetSize(std::vector<cv::GMat>* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = IsArray($v)

    If $bVIsArray Then
        $vecV = _VectorOfGMatCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfGMatPush($vecV, $v[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "VectorOfGMatGetSize", $sVDllType, $vecV), "VectorOfGMatGetSize", @error)

    If $bVIsArray Then
        _VectorOfGMatRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfGMatGetSize

Func _VectorOfGMatPush($v, $value)
    ; CVAPI(void) VectorOfGMatPush(std::vector<cv::GMat>* v, cv::GMat* value);

    Local $vecV, $iArrVSize
    Local $bVIsArray = IsArray($v)

    If $bVIsArray Then
        $vecV = _VectorOfGMatCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfGMatPush($vecV, $v[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfGMatPush", $sVDllType, $vecV, $sValueDllType, $value), "VectorOfGMatPush", @error)

    If $bVIsArray Then
        _VectorOfGMatRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfGMatPush

Func _VectorOfGMatPushVector($v, $other)
    ; CVAPI(void) VectorOfGMatPushVector(std::vector<cv::GMat>* v, std::vector<cv::GMat>* other);

    Local $vecV, $iArrVSize
    Local $bVIsArray = IsArray($v)

    If $bVIsArray Then
        $vecV = _VectorOfGMatCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfGMatPush($vecV, $v[$i])
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
        $vecOther = _VectorOfGMatCreate()

        $iArrOtherSize = UBound($other)
        For $i = 0 To $iArrOtherSize - 1
            _VectorOfGMatPush($vecOther, $other[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfGMatPushVector", $sVDllType, $vecV, $sOtherDllType, $vecOther), "VectorOfGMatPushVector", @error)

    If $bOtherIsArray Then
        _VectorOfGMatRelease($vecOther)
    EndIf

    If $bVIsArray Then
        _VectorOfGMatRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfGMatPushVector

Func _VectorOfGMatGetStartAddress($v)
    ; CVAPI(cv::GMat*) VectorOfGMatGetStartAddress(std::vector<cv::GMat>* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = IsArray($v)

    If $bVIsArray Then
        $vecV = _VectorOfGMatCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfGMatPush($vecV, $v[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfGMatGetStartAddress", $sVDllType, $vecV), "VectorOfGMatGetStartAddress", @error)

    If $bVIsArray Then
        _VectorOfGMatRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfGMatGetStartAddress

Func _VectorOfGMatGetEndAddress($v)
    ; CVAPI(void*) VectorOfGMatGetEndAddress(std::vector<cv::GMat>* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = IsArray($v)

    If $bVIsArray Then
        $vecV = _VectorOfGMatCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfGMatPush($vecV, $v[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfGMatGetEndAddress", $sVDllType, $vecV), "VectorOfGMatGetEndAddress", @error)

    If $bVIsArray Then
        _VectorOfGMatRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfGMatGetEndAddress

Func _VectorOfGMatClear($v)
    ; CVAPI(void) VectorOfGMatClear(std::vector<cv::GMat>* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = IsArray($v)

    If $bVIsArray Then
        $vecV = _VectorOfGMatCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfGMatPush($vecV, $v[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfGMatClear", $sVDllType, $vecV), "VectorOfGMatClear", @error)

    If $bVIsArray Then
        _VectorOfGMatRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfGMatClear

Func _VectorOfGMatRelease($v)
    ; CVAPI(void) VectorOfGMatRelease(std::vector<cv::GMat>** v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = IsArray($v)

    If $bVIsArray Then
        $vecV = _VectorOfGMatCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfGMatPush($vecV, $v[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfGMatRelease", $sVDllType, $vecV), "VectorOfGMatRelease", @error)

    If $bVIsArray Then
        _VectorOfGMatRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfGMatRelease

Func _VectorOfGMatCopyData($v, $data)
    ; CVAPI(void) VectorOfGMatCopyData(std::vector<cv::GMat>* v, cv::GMat* data);

    Local $vecV, $iArrVSize
    Local $bVIsArray = IsArray($v)

    If $bVIsArray Then
        $vecV = _VectorOfGMatCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfGMatPush($vecV, $v[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfGMatCopyData", $sVDllType, $vecV, $sDataDllType, $data), "VectorOfGMatCopyData", @error)

    If $bVIsArray Then
        _VectorOfGMatRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfGMatCopyData

Func _VectorOfGMatGetItemPtr($vec, $index, $element)
    ; CVAPI(void) VectorOfGMatGetItemPtr(std::vector<cv::GMat>* vec, int index, cv::GMat** element);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = IsArray($vec)

    If $bVecIsArray Then
        $vecVec = _VectorOfGMatCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfGMatPush($vecVec, $vec[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfGMatGetItemPtr", $sVecDllType, $vecVec, "int", $index, $sElementDllType, $element), "VectorOfGMatGetItemPtr", @error)

    If $bVecIsArray Then
        _VectorOfGMatRelease($vecVec)
    EndIf
EndFunc   ;==>_VectorOfGMatGetItemPtr

Func _cveInputArrayFromVectorOfGMat($vec)
    ; CVAPI(cv::_InputArray*) cveInputArrayFromVectorOfGMat(std::vector<cv::GMat>* vec);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = IsArray($vec)

    If $bVecIsArray Then
        $vecVec = _VectorOfGMatCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfGMatPush($vecVec, $vec[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveInputArrayFromVectorOfGMat", $sVecDllType, $vecVec), "cveInputArrayFromVectorOfGMat", @error)

    If $bVecIsArray Then
        _VectorOfGMatRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveInputArrayFromVectorOfGMat

Func _cveOutputArrayFromVectorOfGMat($vec)
    ; CVAPI(cv::_OutputArray*) cveOutputArrayFromVectorOfGMat(std::vector<cv::GMat>* vec);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = IsArray($vec)

    If $bVecIsArray Then
        $vecVec = _VectorOfGMatCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfGMatPush($vecVec, $vec[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveOutputArrayFromVectorOfGMat", $sVecDllType, $vecVec), "cveOutputArrayFromVectorOfGMat", @error)

    If $bVecIsArray Then
        _VectorOfGMatRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveOutputArrayFromVectorOfGMat

Func _cveInputOutputArrayFromVectorOfGMat($vec)
    ; CVAPI(cv::_InputOutputArray*) cveInputOutputArrayFromVectorOfGMat(std::vector<cv::GMat>* vec);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = IsArray($vec)

    If $bVecIsArray Then
        $vecVec = _VectorOfGMatCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfGMatPush($vecVec, $vec[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveInputOutputArrayFromVectorOfGMat", $sVecDllType, $vecVec), "cveInputOutputArrayFromVectorOfGMat", @error)

    If $bVecIsArray Then
        _VectorOfGMatRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveInputOutputArrayFromVectorOfGMat

Func _VectorOfGMatSizeOfItemInBytes()
    ; CVAPI(int) VectorOfGMatSizeOfItemInBytes();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "VectorOfGMatSizeOfItemInBytes"), "VectorOfGMatSizeOfItemInBytes", @error)
EndFunc   ;==>_VectorOfGMatSizeOfItemInBytes