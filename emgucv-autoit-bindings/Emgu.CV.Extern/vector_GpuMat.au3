#include-once
#include <..\CVEUtils.au3>

Func _VectorOfGpuMatCreate()
    ; CVAPI(std::vector< cv::cuda::GpuMat >*) VectorOfGpuMatCreate();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfGpuMatCreate"), "VectorOfGpuMatCreate", @error)
EndFunc   ;==>_VectorOfGpuMatCreate

Func _VectorOfGpuMatCreateSize($size)
    ; CVAPI(std::vector< cv::cuda::GpuMat >*) VectorOfGpuMatCreateSize(int size);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfGpuMatCreateSize", "int", $size), "VectorOfGpuMatCreateSize", @error)
EndFunc   ;==>_VectorOfGpuMatCreateSize

Func _VectorOfGpuMatGetSize(ByRef $v)
    ; CVAPI(int) VectorOfGpuMatGetSize(std::vector< cv::cuda::GpuMat >* v);

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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "VectorOfGpuMatGetSize", "ptr", $vecV), "VectorOfGpuMatGetSize", @error)

    If $bVIsArray Then
        _VectorOfGpuMatRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfGpuMatGetSize

Func _VectorOfGpuMatPush(ByRef $v, ByRef $value)
    ; CVAPI(void) VectorOfGpuMatPush(std::vector< cv::cuda::GpuMat >* v, cv::cuda::GpuMat* value);

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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfGpuMatPush", "ptr", $vecV, "ptr", $value), "VectorOfGpuMatPush", @error)

    If $bVIsArray Then
        _VectorOfGpuMatRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfGpuMatPush

Func _VectorOfGpuMatPushVector(ByRef $v, ByRef $other)
    ; CVAPI(void) VectorOfGpuMatPushVector(std::vector< cv::cuda::GpuMat >* v, std::vector< cv::cuda::GpuMat >* other);

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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfGpuMatPushVector", "ptr", $vecV, "ptr", $vecOther), "VectorOfGpuMatPushVector", @error)

    If $bOtherIsArray Then
        _VectorOfGpuMatRelease($vecOther)
    EndIf

    If $bVIsArray Then
        _VectorOfGpuMatRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfGpuMatPushVector

Func _VectorOfGpuMatGetStartAddress(ByRef $v)
    ; CVAPI(cv::cuda::GpuMat*) VectorOfGpuMatGetStartAddress(std::vector< cv::cuda::GpuMat >* v);

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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfGpuMatGetStartAddress", "ptr", $vecV), "VectorOfGpuMatGetStartAddress", @error)

    If $bVIsArray Then
        _VectorOfGpuMatRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfGpuMatGetStartAddress

Func _VectorOfGpuMatGetEndAddress(ByRef $v)
    ; CVAPI(void*) VectorOfGpuMatGetEndAddress(std::vector< cv::cuda::GpuMat >* v);

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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfGpuMatGetEndAddress", "ptr", $vecV), "VectorOfGpuMatGetEndAddress", @error)

    If $bVIsArray Then
        _VectorOfGpuMatRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfGpuMatGetEndAddress

Func _VectorOfGpuMatClear(ByRef $v)
    ; CVAPI(void) VectorOfGpuMatClear(std::vector< cv::cuda::GpuMat >* v);

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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfGpuMatClear", "ptr", $vecV), "VectorOfGpuMatClear", @error)

    If $bVIsArray Then
        _VectorOfGpuMatRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfGpuMatClear

Func _VectorOfGpuMatRelease(ByRef $v)
    ; CVAPI(void) VectorOfGpuMatRelease(std::vector< cv::cuda::GpuMat >** v);

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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfGpuMatRelease", "ptr*", $vecV), "VectorOfGpuMatRelease", @error)

    If $bVIsArray Then
        _VectorOfGpuMatRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfGpuMatRelease

Func _VectorOfGpuMatCopyData(ByRef $v, ByRef $data)
    ; CVAPI(void) VectorOfGpuMatCopyData(std::vector< cv::cuda::GpuMat >* v, cv::cuda::GpuMat* data);

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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfGpuMatCopyData", "ptr", $vecV, "ptr", $data), "VectorOfGpuMatCopyData", @error)

    If $bVIsArray Then
        _VectorOfGpuMatRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfGpuMatCopyData

Func _VectorOfGpuMatGetItemPtr(ByRef $vec, $index, ByRef $element)
    ; CVAPI(void) VectorOfGpuMatGetItemPtr(std::vector<  cv::cuda::GpuMat >* vec, int index, cv::cuda::GpuMat** element);

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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfGpuMatGetItemPtr", "ptr", $vecVec, "int", $index, "ptr*", $element), "VectorOfGpuMatGetItemPtr", @error)

    If $bVecIsArray Then
        _VectorOfGpuMatRelease($vecVec)
    EndIf
EndFunc   ;==>_VectorOfGpuMatGetItemPtr

Func _cveInputArrayFromVectorOfGpuMat(ByRef $vec)
    ; CVAPI(cv::_InputArray*) cveInputArrayFromVectorOfGpuMat(std::vector< cv::cuda::GpuMat >* vec);

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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveInputArrayFromVectorOfGpuMat", "ptr", $vecVec), "cveInputArrayFromVectorOfGpuMat", @error)

    If $bVecIsArray Then
        _VectorOfGpuMatRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveInputArrayFromVectorOfGpuMat

Func _cveOutputArrayFromVectorOfGpuMat(ByRef $vec)
    ; CVAPI(cv::_OutputArray*) cveOutputArrayFromVectorOfGpuMat(std::vector< cv::cuda::GpuMat >* vec);

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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveOutputArrayFromVectorOfGpuMat", "ptr", $vecVec), "cveOutputArrayFromVectorOfGpuMat", @error)

    If $bVecIsArray Then
        _VectorOfGpuMatRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveOutputArrayFromVectorOfGpuMat

Func _cveInputOutputArrayFromVectorOfGpuMat(ByRef $vec)
    ; CVAPI(cv::_InputOutputArray*) cveInputOutputArrayFromVectorOfGpuMat(std::vector< cv::cuda::GpuMat >* vec);

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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveInputOutputArrayFromVectorOfGpuMat", "ptr", $vecVec), "cveInputOutputArrayFromVectorOfGpuMat", @error)

    If $bVecIsArray Then
        _VectorOfGpuMatRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveInputOutputArrayFromVectorOfGpuMat

Func _VectorOfGpuMatSizeOfItemInBytes()
    ; CVAPI(int) VectorOfGpuMatSizeOfItemInBytes();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "VectorOfGpuMatSizeOfItemInBytes"), "VectorOfGpuMatSizeOfItemInBytes", @error)
EndFunc   ;==>_VectorOfGpuMatSizeOfItemInBytes