#include-once
#include "..\CVEUtils.au3"

Func _VectorOfGpuMatCreate()
    ; CVAPI(std::vector<cv::cuda::GpuMat>*) VectorOfGpuMatCreate();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfGpuMatCreate"), "VectorOfGpuMatCreate", @error)
EndFunc   ;==>_VectorOfGpuMatCreate

Func _VectorOfGpuMatCreateSize($size)
    ; CVAPI(std::vector<cv::cuda::GpuMat>*) VectorOfGpuMatCreateSize(int size);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfGpuMatCreateSize", "int", $size), "VectorOfGpuMatCreateSize", @error)
EndFunc   ;==>_VectorOfGpuMatCreateSize

Func _VectorOfGpuMatGetSize($v)
    ; CVAPI(int) VectorOfGpuMatGetSize(std::vector<cv::cuda::GpuMat>* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfGpuMatCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfGpuMatPush($vecV, $v[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "VectorOfGpuMatGetSize", $bVDllType, $vecV), "VectorOfGpuMatGetSize", @error)

    If $bVIsArray Then
        _VectorOfGpuMatRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfGpuMatGetSize

Func _VectorOfGpuMatPush($v, $value)
    ; CVAPI(void) VectorOfGpuMatPush(std::vector<cv::cuda::GpuMat>* v, cv::cuda::GpuMat* value);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfGpuMatCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfGpuMatPush($vecV, $v[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfGpuMatPush", $bVDllType, $vecV, $bValueDllType, $value), "VectorOfGpuMatPush", @error)

    If $bVIsArray Then
        _VectorOfGpuMatRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfGpuMatPush

Func _VectorOfGpuMatPushVector($v, $other)
    ; CVAPI(void) VectorOfGpuMatPushVector(std::vector<cv::cuda::GpuMat>* v, std::vector<cv::cuda::GpuMat>* other);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfGpuMatCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfGpuMatPush($vecV, $v[$i])
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
        $vecOther = _VectorOfGpuMatCreate()

        $iArrOtherSize = UBound($other)
        For $i = 0 To $iArrOtherSize - 1
            _VectorOfGpuMatPush($vecOther, $other[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfGpuMatPushVector", $bVDllType, $vecV, $bOtherDllType, $vecOther), "VectorOfGpuMatPushVector", @error)

    If $bOtherIsArray Then
        _VectorOfGpuMatRelease($vecOther)
    EndIf

    If $bVIsArray Then
        _VectorOfGpuMatRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfGpuMatPushVector

Func _VectorOfGpuMatGetStartAddress($v)
    ; CVAPI(cv::cuda::GpuMat*) VectorOfGpuMatGetStartAddress(std::vector<cv::cuda::GpuMat>* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfGpuMatCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfGpuMatPush($vecV, $v[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfGpuMatGetStartAddress", $bVDllType, $vecV), "VectorOfGpuMatGetStartAddress", @error)

    If $bVIsArray Then
        _VectorOfGpuMatRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfGpuMatGetStartAddress

Func _VectorOfGpuMatGetEndAddress($v)
    ; CVAPI(void*) VectorOfGpuMatGetEndAddress(std::vector<cv::cuda::GpuMat>* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfGpuMatCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfGpuMatPush($vecV, $v[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfGpuMatGetEndAddress", $bVDllType, $vecV), "VectorOfGpuMatGetEndAddress", @error)

    If $bVIsArray Then
        _VectorOfGpuMatRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfGpuMatGetEndAddress

Func _VectorOfGpuMatClear($v)
    ; CVAPI(void) VectorOfGpuMatClear(std::vector<cv::cuda::GpuMat>* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfGpuMatCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfGpuMatPush($vecV, $v[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfGpuMatClear", $bVDllType, $vecV), "VectorOfGpuMatClear", @error)

    If $bVIsArray Then
        _VectorOfGpuMatRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfGpuMatClear

Func _VectorOfGpuMatRelease($v)
    ; CVAPI(void) VectorOfGpuMatRelease(std::vector<cv::cuda::GpuMat>** v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfGpuMatCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfGpuMatPush($vecV, $v[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfGpuMatRelease", $bVDllType, $vecV), "VectorOfGpuMatRelease", @error)

    If $bVIsArray Then
        _VectorOfGpuMatRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfGpuMatRelease

Func _VectorOfGpuMatCopyData($v, $data)
    ; CVAPI(void) VectorOfGpuMatCopyData(std::vector<cv::cuda::GpuMat>* v, cv::cuda::GpuMat* data);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfGpuMatCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfGpuMatPush($vecV, $v[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfGpuMatCopyData", $bVDllType, $vecV, $bDataDllType, $data), "VectorOfGpuMatCopyData", @error)

    If $bVIsArray Then
        _VectorOfGpuMatRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfGpuMatCopyData

Func _VectorOfGpuMatGetItemPtr($vec, $index, $element)
    ; CVAPI(void) VectorOfGpuMatGetItemPtr(std::vector<cv::cuda::GpuMat>* vec, int index, cv::cuda::GpuMat** element);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfGpuMatCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfGpuMatPush($vecVec, $vec[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfGpuMatGetItemPtr", $bVecDllType, $vecVec, "int", $index, $bElementDllType, $element), "VectorOfGpuMatGetItemPtr", @error)

    If $bVecIsArray Then
        _VectorOfGpuMatRelease($vecVec)
    EndIf
EndFunc   ;==>_VectorOfGpuMatGetItemPtr

Func _cveInputArrayFromVectorOfGpuMat($vec)
    ; CVAPI(cv::_InputArray*) cveInputArrayFromVectorOfGpuMat(std::vector<cv::cuda::GpuMat>* vec);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfGpuMatCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfGpuMatPush($vecVec, $vec[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveInputArrayFromVectorOfGpuMat", $bVecDllType, $vecVec), "cveInputArrayFromVectorOfGpuMat", @error)

    If $bVecIsArray Then
        _VectorOfGpuMatRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveInputArrayFromVectorOfGpuMat

Func _cveOutputArrayFromVectorOfGpuMat($vec)
    ; CVAPI(cv::_OutputArray*) cveOutputArrayFromVectorOfGpuMat(std::vector<cv::cuda::GpuMat>* vec);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfGpuMatCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfGpuMatPush($vecVec, $vec[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveOutputArrayFromVectorOfGpuMat", $bVecDllType, $vecVec), "cveOutputArrayFromVectorOfGpuMat", @error)

    If $bVecIsArray Then
        _VectorOfGpuMatRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveOutputArrayFromVectorOfGpuMat

Func _cveInputOutputArrayFromVectorOfGpuMat($vec)
    ; CVAPI(cv::_InputOutputArray*) cveInputOutputArrayFromVectorOfGpuMat(std::vector<cv::cuda::GpuMat>* vec);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfGpuMatCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfGpuMatPush($vecVec, $vec[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveInputOutputArrayFromVectorOfGpuMat", $bVecDllType, $vecVec), "cveInputOutputArrayFromVectorOfGpuMat", @error)

    If $bVecIsArray Then
        _VectorOfGpuMatRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveInputOutputArrayFromVectorOfGpuMat

Func _VectorOfGpuMatSizeOfItemInBytes()
    ; CVAPI(int) VectorOfGpuMatSizeOfItemInBytes();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "VectorOfGpuMatSizeOfItemInBytes"), "VectorOfGpuMatSizeOfItemInBytes", @error)
EndFunc   ;==>_VectorOfGpuMatSizeOfItemInBytes