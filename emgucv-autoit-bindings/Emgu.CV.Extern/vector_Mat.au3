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

    Local $bVDllType
    If VarGetType($v) == "DLLStruct" Then
        $bVDllType = "struct*"
    Else
        $bVDllType = "ptr"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "VectorOfMatGetSize", $bVDllType, $vecV), "VectorOfMatGetSize", @error)

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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfMatPush", $bVDllType, $vecV, $bValueDllType, $value), "VectorOfMatPush", @error)

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

    Local $bVDllType
    If VarGetType($v) == "DLLStruct" Then
        $bVDllType = "struct*"
    Else
        $bVDllType = "ptr"
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

    Local $bOtherDllType
    If VarGetType($other) == "DLLStruct" Then
        $bOtherDllType = "struct*"
    Else
        $bOtherDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfMatPushVector", $bVDllType, $vecV, $bOtherDllType, $vecOther), "VectorOfMatPushVector", @error)

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

    Local $bVDllType
    If VarGetType($v) == "DLLStruct" Then
        $bVDllType = "struct*"
    Else
        $bVDllType = "ptr"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfMatGetStartAddress", $bVDllType, $vecV), "VectorOfMatGetStartAddress", @error)

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

    Local $bVDllType
    If VarGetType($v) == "DLLStruct" Then
        $bVDllType = "struct*"
    Else
        $bVDllType = "ptr"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfMatGetEndAddress", $bVDllType, $vecV), "VectorOfMatGetEndAddress", @error)

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

    Local $bVDllType
    If VarGetType($v) == "DLLStruct" Then
        $bVDllType = "struct*"
    Else
        $bVDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfMatClear", $bVDllType, $vecV), "VectorOfMatClear", @error)

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

    Local $bVDllType
    If VarGetType($v) == "DLLStruct" Then
        $bVDllType = "struct*"
    Else
        $bVDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfMatRelease", $bVDllType, $vecV), "VectorOfMatRelease", @error)

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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfMatCopyData", $bVDllType, $vecV, $bDataDllType, $data), "VectorOfMatCopyData", @error)

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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfMatGetItemPtr", $bVecDllType, $vecVec, "int", $index, $bElementDllType, $element), "VectorOfMatGetItemPtr", @error)

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

    Local $bVecDllType
    If VarGetType($vec) == "DLLStruct" Then
        $bVecDllType = "struct*"
    Else
        $bVecDllType = "ptr"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveInputArrayFromVectorOfMat", $bVecDllType, $vecVec), "cveInputArrayFromVectorOfMat", @error)

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

    Local $bVecDllType
    If VarGetType($vec) == "DLLStruct" Then
        $bVecDllType = "struct*"
    Else
        $bVecDllType = "ptr"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveOutputArrayFromVectorOfMat", $bVecDllType, $vecVec), "cveOutputArrayFromVectorOfMat", @error)

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

    Local $bVecDllType
    If VarGetType($vec) == "DLLStruct" Then
        $bVecDllType = "struct*"
    Else
        $bVecDllType = "ptr"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveInputOutputArrayFromVectorOfMat", $bVecDllType, $vecVec), "cveInputOutputArrayFromVectorOfMat", @error)

    If $bVecIsArray Then
        _VectorOfMatRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveInputOutputArrayFromVectorOfMat

Func _VectorOfMatSizeOfItemInBytes()
    ; CVAPI(int) VectorOfMatSizeOfItemInBytes();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "VectorOfMatSizeOfItemInBytes"), "VectorOfMatSizeOfItemInBytes", @error)
EndFunc   ;==>_VectorOfMatSizeOfItemInBytes