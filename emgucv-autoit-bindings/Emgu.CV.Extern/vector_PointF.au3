#include-once
#include "..\CVEUtils.au3"

Func _VectorOfPointFCreate()
    ; CVAPI(std::vector<cv::Point2f>*) VectorOfPointFCreate();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfPointFCreate"), "VectorOfPointFCreate", @error)
EndFunc   ;==>_VectorOfPointFCreate

Func _VectorOfPointFCreateSize($size)
    ; CVAPI(std::vector<cv::Point2f>*) VectorOfPointFCreateSize(int size);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfPointFCreateSize", "int", $size), "VectorOfPointFCreateSize", @error)
EndFunc   ;==>_VectorOfPointFCreateSize

Func _VectorOfPointFGetSize($v)
    ; CVAPI(int) VectorOfPointFGetSize(std::vector<cv::Point2f>* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfPointFCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfPointFPush($vecV, $v[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "VectorOfPointFGetSize", $bVDllType, $vecV), "VectorOfPointFGetSize", @error)

    If $bVIsArray Then
        _VectorOfPointFRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfPointFGetSize

Func _VectorOfPointFPush($v, $value)
    ; CVAPI(void) VectorOfPointFPush(std::vector<cv::Point2f>* v, cv::Point2f* value);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfPointFCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfPointFPush($vecV, $v[$i])
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

    Local $bValueDllType
    If VarGetType($value) == "DLLStruct" Then
        $bValueDllType = "struct*"
    Else
        $bValueDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfPointFPush", $bVDllType, $vecV, $bValueDllType, $value), "VectorOfPointFPush", @error)

    If $bVIsArray Then
        _VectorOfPointFRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfPointFPush

Func _VectorOfPointFPushMulti($v, $values, $count)
    ; CVAPI(void) VectorOfPointFPushMulti(std::vector<cv::Point2f>* v, cv::Point2f* values, int count);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfPointFCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfPointFPush($vecV, $v[$i])
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

    Local $bValuesDllType
    If VarGetType($values) == "DLLStruct" Then
        $bValuesDllType = "struct*"
    Else
        $bValuesDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfPointFPushMulti", $bVDllType, $vecV, $bValuesDllType, $values, "int", $count), "VectorOfPointFPushMulti", @error)

    If $bVIsArray Then
        _VectorOfPointFRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfPointFPushMulti

Func _VectorOfPointFPushVector($v, $other)
    ; CVAPI(void) VectorOfPointFPushVector(std::vector<cv::Point2f>* v, std::vector<cv::Point2f>* other);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfPointFCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfPointFPush($vecV, $v[$i])
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
        $vecOther = _VectorOfPointFCreate()

        $iArrOtherSize = UBound($other)
        For $i = 0 To $iArrOtherSize - 1
            _VectorOfPointFPush($vecOther, $other[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfPointFPushVector", $bVDllType, $vecV, $bOtherDllType, $vecOther), "VectorOfPointFPushVector", @error)

    If $bOtherIsArray Then
        _VectorOfPointFRelease($vecOther)
    EndIf

    If $bVIsArray Then
        _VectorOfPointFRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfPointFPushVector

Func _VectorOfPointFClear($v)
    ; CVAPI(void) VectorOfPointFClear(std::vector<cv::Point2f>* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfPointFCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfPointFPush($vecV, $v[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfPointFClear", $bVDllType, $vecV), "VectorOfPointFClear", @error)

    If $bVIsArray Then
        _VectorOfPointFRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfPointFClear

Func _VectorOfPointFRelease($v)
    ; CVAPI(void) VectorOfPointFRelease(std::vector<cv::Point2f>** v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfPointFCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfPointFPush($vecV, $v[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfPointFRelease", $bVDllType, $vecV), "VectorOfPointFRelease", @error)

    If $bVIsArray Then
        _VectorOfPointFRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfPointFRelease

Func _VectorOfPointFCopyData($v, $data)
    ; CVAPI(void) VectorOfPointFCopyData(std::vector<cv::Point2f>* v, cv::Point2f* data);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfPointFCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfPointFPush($vecV, $v[$i])
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

    Local $bDataDllType
    If VarGetType($data) == "DLLStruct" Then
        $bDataDllType = "struct*"
    Else
        $bDataDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfPointFCopyData", $bVDllType, $vecV, $bDataDllType, $data), "VectorOfPointFCopyData", @error)

    If $bVIsArray Then
        _VectorOfPointFRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfPointFCopyData

Func _VectorOfPointFGetStartAddress($v)
    ; CVAPI(cv::Point2f*) VectorOfPointFGetStartAddress(std::vector<cv::Point2f>* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfPointFCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfPointFPush($vecV, $v[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfPointFGetStartAddress", $bVDllType, $vecV), "VectorOfPointFGetStartAddress", @error)

    If $bVIsArray Then
        _VectorOfPointFRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfPointFGetStartAddress

Func _VectorOfPointFGetEndAddress($v)
    ; CVAPI(void*) VectorOfPointFGetEndAddress(std::vector<cv::Point2f>* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfPointFCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfPointFPush($vecV, $v[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfPointFGetEndAddress", $bVDllType, $vecV), "VectorOfPointFGetEndAddress", @error)

    If $bVIsArray Then
        _VectorOfPointFRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfPointFGetEndAddress

Func _VectorOfPointFGetItem($vec, $index, $element)
    ; CVAPI(void) VectorOfPointFGetItem(std::vector<cv::Point2f>* vec, int index, cv::Point2f* element);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfPointFCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfPointFPush($vecVec, $vec[$i])
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

    Local $bElementDllType
    If VarGetType($element) == "DLLStruct" Then
        $bElementDllType = "struct*"
    Else
        $bElementDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfPointFGetItem", $bVecDllType, $vecVec, "int", $index, $bElementDllType, $element), "VectorOfPointFGetItem", @error)

    If $bVecIsArray Then
        _VectorOfPointFRelease($vecVec)
    EndIf
EndFunc   ;==>_VectorOfPointFGetItem

Func _VectorOfPointFGetItemPtr($vec, $index, $element)
    ; CVAPI(void) VectorOfPointFGetItemPtr(std::vector<cv::Point2f>* vec, int index, cv::Point2f** element);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfPointFCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfPointFPush($vecVec, $vec[$i])
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

    Local $bElementDllType
    If VarGetType($element) == "DLLStruct" Then
        $bElementDllType = "struct*"
    Else
        $bElementDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfPointFGetItemPtr", $bVecDllType, $vecVec, "int", $index, $bElementDllType, $element), "VectorOfPointFGetItemPtr", @error)

    If $bVecIsArray Then
        _VectorOfPointFRelease($vecVec)
    EndIf
EndFunc   ;==>_VectorOfPointFGetItemPtr

Func _cveInputArrayFromVectorOfPointF($vec)
    ; CVAPI(cv::_InputArray*) cveInputArrayFromVectorOfPointF(std::vector<cv::Point2f>* vec);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfPointFCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfPointFPush($vecVec, $vec[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveInputArrayFromVectorOfPointF", $bVecDllType, $vecVec), "cveInputArrayFromVectorOfPointF", @error)

    If $bVecIsArray Then
        _VectorOfPointFRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveInputArrayFromVectorOfPointF

Func _cveOutputArrayFromVectorOfPointF($vec)
    ; CVAPI(cv::_OutputArray*) cveOutputArrayFromVectorOfPointF(std::vector<cv::Point2f>* vec);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfPointFCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfPointFPush($vecVec, $vec[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveOutputArrayFromVectorOfPointF", $bVecDllType, $vecVec), "cveOutputArrayFromVectorOfPointF", @error)

    If $bVecIsArray Then
        _VectorOfPointFRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveOutputArrayFromVectorOfPointF

Func _cveInputOutputArrayFromVectorOfPointF($vec)
    ; CVAPI(cv::_InputOutputArray*) cveInputOutputArrayFromVectorOfPointF(std::vector<cv::Point2f>* vec);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfPointFCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfPointFPush($vecVec, $vec[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveInputOutputArrayFromVectorOfPointF", $bVecDllType, $vecVec), "cveInputOutputArrayFromVectorOfPointF", @error)

    If $bVecIsArray Then
        _VectorOfPointFRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveInputOutputArrayFromVectorOfPointF

Func _VectorOfPointFSizeOfItemInBytes()
    ; CVAPI(int) VectorOfPointFSizeOfItemInBytes();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "VectorOfPointFSizeOfItemInBytes"), "VectorOfPointFSizeOfItemInBytes", @error)
EndFunc   ;==>_VectorOfPointFSizeOfItemInBytes