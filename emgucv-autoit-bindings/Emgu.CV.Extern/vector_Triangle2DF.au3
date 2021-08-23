#include-once
#include "..\CVEUtils.au3"

Func _VectorOfTriangle2DFCreate()
    ; CVAPI(std::vector<cv::Vec6f>*) VectorOfTriangle2DFCreate();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfTriangle2DFCreate"), "VectorOfTriangle2DFCreate", @error)
EndFunc   ;==>_VectorOfTriangle2DFCreate

Func _VectorOfTriangle2DFCreateSize($size)
    ; CVAPI(std::vector<cv::Vec6f>*) VectorOfTriangle2DFCreateSize(int size);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfTriangle2DFCreateSize", "int", $size), "VectorOfTriangle2DFCreateSize", @error)
EndFunc   ;==>_VectorOfTriangle2DFCreateSize

Func _VectorOfTriangle2DFGetSize($v)
    ; CVAPI(int) VectorOfTriangle2DFGetSize(std::vector<cv::Vec6f>* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfTriangle2DFCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfTriangle2DFPush($vecV, $v[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "VectorOfTriangle2DFGetSize", $sVDllType, $vecV), "VectorOfTriangle2DFGetSize", @error)

    If $bVIsArray Then
        _VectorOfTriangle2DFRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfTriangle2DFGetSize

Func _VectorOfTriangle2DFPush($v, $value)
    ; CVAPI(void) VectorOfTriangle2DFPush(std::vector<cv::Vec6f>* v, cv::Vec6f* value);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfTriangle2DFCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfTriangle2DFPush($vecV, $v[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfTriangle2DFPush", $sVDllType, $vecV, $sValueDllType, $value), "VectorOfTriangle2DFPush", @error)

    If $bVIsArray Then
        _VectorOfTriangle2DFRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfTriangle2DFPush

Func _VectorOfTriangle2DFPushMulti($v, $values, $count)
    ; CVAPI(void) VectorOfTriangle2DFPushMulti(std::vector<cv::Vec6f>* v, cv::Vec6f* values, int count);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfTriangle2DFCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfTriangle2DFPush($vecV, $v[$i])
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

    Local $sValuesDllType
    If IsDllStruct($values) Then
        $sValuesDllType = "struct*"
    Else
        $sValuesDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfTriangle2DFPushMulti", $sVDllType, $vecV, $sValuesDllType, $values, "int", $count), "VectorOfTriangle2DFPushMulti", @error)

    If $bVIsArray Then
        _VectorOfTriangle2DFRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfTriangle2DFPushMulti

Func _VectorOfTriangle2DFPushVector($v, $other)
    ; CVAPI(void) VectorOfTriangle2DFPushVector(std::vector<cv::Vec6f>* v, std::vector<cv::Vec6f>* other);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfTriangle2DFCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfTriangle2DFPush($vecV, $v[$i])
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
        $vecOther = _VectorOfTriangle2DFCreate()

        $iArrOtherSize = UBound($other)
        For $i = 0 To $iArrOtherSize - 1
            _VectorOfTriangle2DFPush($vecOther, $other[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfTriangle2DFPushVector", $sVDllType, $vecV, $sOtherDllType, $vecOther), "VectorOfTriangle2DFPushVector", @error)

    If $bOtherIsArray Then
        _VectorOfTriangle2DFRelease($vecOther)
    EndIf

    If $bVIsArray Then
        _VectorOfTriangle2DFRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfTriangle2DFPushVector

Func _VectorOfTriangle2DFClear($v)
    ; CVAPI(void) VectorOfTriangle2DFClear(std::vector<cv::Vec6f>* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfTriangle2DFCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfTriangle2DFPush($vecV, $v[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfTriangle2DFClear", $sVDllType, $vecV), "VectorOfTriangle2DFClear", @error)

    If $bVIsArray Then
        _VectorOfTriangle2DFRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfTriangle2DFClear

Func _VectorOfTriangle2DFRelease($v)
    ; CVAPI(void) VectorOfTriangle2DFRelease(std::vector<cv::Vec6f>** v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfTriangle2DFCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfTriangle2DFPush($vecV, $v[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfTriangle2DFRelease", $sVDllType, $vecV), "VectorOfTriangle2DFRelease", @error)

    If $bVIsArray Then
        _VectorOfTriangle2DFRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfTriangle2DFRelease

Func _VectorOfTriangle2DFCopyData($v, $data)
    ; CVAPI(void) VectorOfTriangle2DFCopyData(std::vector<cv::Vec6f>* v, cv::Vec6f* data);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfTriangle2DFCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfTriangle2DFPush($vecV, $v[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfTriangle2DFCopyData", $sVDllType, $vecV, $sDataDllType, $data), "VectorOfTriangle2DFCopyData", @error)

    If $bVIsArray Then
        _VectorOfTriangle2DFRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfTriangle2DFCopyData

Func _VectorOfTriangle2DFGetStartAddress($v)
    ; CVAPI(cv::Vec6f*) VectorOfTriangle2DFGetStartAddress(std::vector<cv::Vec6f>* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfTriangle2DFCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfTriangle2DFPush($vecV, $v[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfTriangle2DFGetStartAddress", $sVDllType, $vecV), "VectorOfTriangle2DFGetStartAddress", @error)

    If $bVIsArray Then
        _VectorOfTriangle2DFRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfTriangle2DFGetStartAddress

Func _VectorOfTriangle2DFGetEndAddress($v)
    ; CVAPI(void*) VectorOfTriangle2DFGetEndAddress(std::vector<cv::Vec6f>* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfTriangle2DFCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfTriangle2DFPush($vecV, $v[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfTriangle2DFGetEndAddress", $sVDllType, $vecV), "VectorOfTriangle2DFGetEndAddress", @error)

    If $bVIsArray Then
        _VectorOfTriangle2DFRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfTriangle2DFGetEndAddress

Func _VectorOfTriangle2DFGetItem($vec, $index, $element)
    ; CVAPI(void) VectorOfTriangle2DFGetItem(std::vector<cv::Vec6f>* vec, int index, cv::Vec6f* element);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfTriangle2DFCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfTriangle2DFPush($vecVec, $vec[$i])
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
    Else
        $sElementDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfTriangle2DFGetItem", $sVecDllType, $vecVec, "int", $index, $sElementDllType, $element), "VectorOfTriangle2DFGetItem", @error)

    If $bVecIsArray Then
        _VectorOfTriangle2DFRelease($vecVec)
    EndIf
EndFunc   ;==>_VectorOfTriangle2DFGetItem

Func _VectorOfTriangle2DFGetItemPtr($vec, $index, $element)
    ; CVAPI(void) VectorOfTriangle2DFGetItemPtr(std::vector<cv::Vec6f>* vec, int index, cv::Vec6f** element);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfTriangle2DFCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfTriangle2DFPush($vecVec, $vec[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfTriangle2DFGetItemPtr", $sVecDllType, $vecVec, "int", $index, $sElementDllType, $element), "VectorOfTriangle2DFGetItemPtr", @error)

    If $bVecIsArray Then
        _VectorOfTriangle2DFRelease($vecVec)
    EndIf
EndFunc   ;==>_VectorOfTriangle2DFGetItemPtr

Func _cveInputArrayFromVectorOfTriangle2DF($vec)
    ; CVAPI(cv::_InputArray*) cveInputArrayFromVectorOfTriangle2DF(std::vector<cv::Vec6f>* vec);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfTriangle2DFCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfTriangle2DFPush($vecVec, $vec[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveInputArrayFromVectorOfTriangle2DF", $sVecDllType, $vecVec), "cveInputArrayFromVectorOfTriangle2DF", @error)

    If $bVecIsArray Then
        _VectorOfTriangle2DFRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveInputArrayFromVectorOfTriangle2DF

Func _cveOutputArrayFromVectorOfTriangle2DF($vec)
    ; CVAPI(cv::_OutputArray*) cveOutputArrayFromVectorOfTriangle2DF(std::vector<cv::Vec6f>* vec);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfTriangle2DFCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfTriangle2DFPush($vecVec, $vec[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveOutputArrayFromVectorOfTriangle2DF", $sVecDllType, $vecVec), "cveOutputArrayFromVectorOfTriangle2DF", @error)

    If $bVecIsArray Then
        _VectorOfTriangle2DFRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveOutputArrayFromVectorOfTriangle2DF

Func _cveInputOutputArrayFromVectorOfTriangle2DF($vec)
    ; CVAPI(cv::_InputOutputArray*) cveInputOutputArrayFromVectorOfTriangle2DF(std::vector<cv::Vec6f>* vec);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfTriangle2DFCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfTriangle2DFPush($vecVec, $vec[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveInputOutputArrayFromVectorOfTriangle2DF", $sVecDllType, $vecVec), "cveInputOutputArrayFromVectorOfTriangle2DF", @error)

    If $bVecIsArray Then
        _VectorOfTriangle2DFRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveInputOutputArrayFromVectorOfTriangle2DF

Func _VectorOfTriangle2DFSizeOfItemInBytes()
    ; CVAPI(int) VectorOfTriangle2DFSizeOfItemInBytes();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "VectorOfTriangle2DFSizeOfItemInBytes"), "VectorOfTriangle2DFSizeOfItemInBytes", @error)
EndFunc   ;==>_VectorOfTriangle2DFSizeOfItemInBytes