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
    Local $bVIsArray = IsArray($v)

    If $bVIsArray Then
        $vecV = _VectorOfGpuMatCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfGpuMatPush($vecV, $v[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "VectorOfGpuMatGetSize", $sVDllType, $vecV), "VectorOfGpuMatGetSize", @error)

    If $bVIsArray Then
        _VectorOfGpuMatRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfGpuMatGetSize

Func _VectorOfGpuMatPush($v, $value)
    ; CVAPI(void) VectorOfGpuMatPush(std::vector<cv::cuda::GpuMat>* v, cv::cuda::GpuMat* value);

    Local $vecV, $iArrVSize
    Local $bVIsArray = IsArray($v)

    If $bVIsArray Then
        $vecV = _VectorOfGpuMatCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfGpuMatPush($vecV, $v[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfGpuMatPush", $sVDllType, $vecV, $sValueDllType, $value), "VectorOfGpuMatPush", @error)

    If $bVIsArray Then
        _VectorOfGpuMatRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfGpuMatPush

Func _VectorOfGpuMatPushVector($v, $other)
    ; CVAPI(void) VectorOfGpuMatPushVector(std::vector<cv::cuda::GpuMat>* v, std::vector<cv::cuda::GpuMat>* other);

    Local $vecV, $iArrVSize
    Local $bVIsArray = IsArray($v)

    If $bVIsArray Then
        $vecV = _VectorOfGpuMatCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfGpuMatPush($vecV, $v[$i])
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
        $vecOther = _VectorOfGpuMatCreate()

        $iArrOtherSize = UBound($other)
        For $i = 0 To $iArrOtherSize - 1
            _VectorOfGpuMatPush($vecOther, $other[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfGpuMatPushVector", $sVDllType, $vecV, $sOtherDllType, $vecOther), "VectorOfGpuMatPushVector", @error)

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
    Local $bVIsArray = IsArray($v)

    If $bVIsArray Then
        $vecV = _VectorOfGpuMatCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfGpuMatPush($vecV, $v[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfGpuMatGetStartAddress", $sVDllType, $vecV), "VectorOfGpuMatGetStartAddress", @error)

    If $bVIsArray Then
        _VectorOfGpuMatRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfGpuMatGetStartAddress

Func _VectorOfGpuMatGetEndAddress($v)
    ; CVAPI(void*) VectorOfGpuMatGetEndAddress(std::vector<cv::cuda::GpuMat>* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = IsArray($v)

    If $bVIsArray Then
        $vecV = _VectorOfGpuMatCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfGpuMatPush($vecV, $v[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfGpuMatGetEndAddress", $sVDllType, $vecV), "VectorOfGpuMatGetEndAddress", @error)

    If $bVIsArray Then
        _VectorOfGpuMatRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfGpuMatGetEndAddress

Func _VectorOfGpuMatClear($v)
    ; CVAPI(void) VectorOfGpuMatClear(std::vector<cv::cuda::GpuMat>* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = IsArray($v)

    If $bVIsArray Then
        $vecV = _VectorOfGpuMatCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfGpuMatPush($vecV, $v[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfGpuMatClear", $sVDllType, $vecV), "VectorOfGpuMatClear", @error)

    If $bVIsArray Then
        _VectorOfGpuMatRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfGpuMatClear

Func _VectorOfGpuMatRelease($v)
    ; CVAPI(void) VectorOfGpuMatRelease(std::vector<cv::cuda::GpuMat>** v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = IsArray($v)

    If $bVIsArray Then
        $vecV = _VectorOfGpuMatCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfGpuMatPush($vecV, $v[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfGpuMatRelease", $sVDllType, $vecV), "VectorOfGpuMatRelease", @error)

    If $bVIsArray Then
        _VectorOfGpuMatRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfGpuMatRelease

Func _VectorOfGpuMatCopyData($v, $data)
    ; CVAPI(void) VectorOfGpuMatCopyData(std::vector<cv::cuda::GpuMat>* v, cv::cuda::GpuMat* data);

    Local $vecV, $iArrVSize
    Local $bVIsArray = IsArray($v)

    If $bVIsArray Then
        $vecV = _VectorOfGpuMatCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfGpuMatPush($vecV, $v[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfGpuMatCopyData", $sVDllType, $vecV, $sDataDllType, $data), "VectorOfGpuMatCopyData", @error)

    If $bVIsArray Then
        _VectorOfGpuMatRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfGpuMatCopyData

Func _VectorOfGpuMatGetItemPtr($vec, $index, $element)
    ; CVAPI(void) VectorOfGpuMatGetItemPtr(std::vector<cv::cuda::GpuMat>* vec, int index, cv::cuda::GpuMat** element);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = IsArray($vec)

    If $bVecIsArray Then
        $vecVec = _VectorOfGpuMatCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfGpuMatPush($vecVec, $vec[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfGpuMatGetItemPtr", $sVecDllType, $vecVec, "int", $index, $sElementDllType, $element), "VectorOfGpuMatGetItemPtr", @error)

    If $bVecIsArray Then
        _VectorOfGpuMatRelease($vecVec)
    EndIf
EndFunc   ;==>_VectorOfGpuMatGetItemPtr

Func _cveInputArrayFromVectorOfGpuMat($vec)
    ; CVAPI(cv::_InputArray*) cveInputArrayFromVectorOfGpuMat(std::vector<cv::cuda::GpuMat>* vec);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = IsArray($vec)

    If $bVecIsArray Then
        $vecVec = _VectorOfGpuMatCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfGpuMatPush($vecVec, $vec[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveInputArrayFromVectorOfGpuMat", $sVecDllType, $vecVec), "cveInputArrayFromVectorOfGpuMat", @error)

    If $bVecIsArray Then
        _VectorOfGpuMatRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveInputArrayFromVectorOfGpuMat

Func _cveOutputArrayFromVectorOfGpuMat($vec)
    ; CVAPI(cv::_OutputArray*) cveOutputArrayFromVectorOfGpuMat(std::vector<cv::cuda::GpuMat>* vec);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = IsArray($vec)

    If $bVecIsArray Then
        $vecVec = _VectorOfGpuMatCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfGpuMatPush($vecVec, $vec[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveOutputArrayFromVectorOfGpuMat", $sVecDllType, $vecVec), "cveOutputArrayFromVectorOfGpuMat", @error)

    If $bVecIsArray Then
        _VectorOfGpuMatRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveOutputArrayFromVectorOfGpuMat

Func _cveInputOutputArrayFromVectorOfGpuMat($vec)
    ; CVAPI(cv::_InputOutputArray*) cveInputOutputArrayFromVectorOfGpuMat(std::vector<cv::cuda::GpuMat>* vec);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = IsArray($vec)

    If $bVecIsArray Then
        $vecVec = _VectorOfGpuMatCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfGpuMatPush($vecVec, $vec[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveInputOutputArrayFromVectorOfGpuMat", $sVecDllType, $vecVec), "cveInputOutputArrayFromVectorOfGpuMat", @error)

    If $bVecIsArray Then
        _VectorOfGpuMatRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveInputOutputArrayFromVectorOfGpuMat

Func _VectorOfGpuMatSizeOfItemInBytes()
    ; CVAPI(int) VectorOfGpuMatSizeOfItemInBytes();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "VectorOfGpuMatSizeOfItemInBytes"), "VectorOfGpuMatSizeOfItemInBytes", @error)
EndFunc   ;==>_VectorOfGpuMatSizeOfItemInBytes