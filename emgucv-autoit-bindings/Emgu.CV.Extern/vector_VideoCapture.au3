#include-once
#include "..\CVEUtils.au3"

Func _VectorOfVideoCaptureCreate()
    ; CVAPI(std::vector< cv::VideoCapture >*) VectorOfVideoCaptureCreate();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfVideoCaptureCreate"), "VectorOfVideoCaptureCreate", @error)
EndFunc   ;==>_VectorOfVideoCaptureCreate

Func _VectorOfVideoCaptureCreateSize($size)
    ; CVAPI(std::vector< cv::VideoCapture >*) VectorOfVideoCaptureCreateSize(int size);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfVideoCaptureCreateSize", "int", $size), "VectorOfVideoCaptureCreateSize", @error)
EndFunc   ;==>_VectorOfVideoCaptureCreateSize

Func _VectorOfVideoCaptureGetSize(ByRef $v)
    ; CVAPI(int) VectorOfVideoCaptureGetSize(std::vector< cv::VideoCapture >* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfVideoCaptureCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfVideoCapturePush($vecV, $v[$i])
        Next
    Else
        $vecV = $v
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "VectorOfVideoCaptureGetSize", "ptr", $vecV), "VectorOfVideoCaptureGetSize", @error)

    If $bVIsArray Then
        _VectorOfVideoCaptureRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfVideoCaptureGetSize

Func _VectorOfVideoCapturePush(ByRef $v, ByRef $value)
    ; CVAPI(void) VectorOfVideoCapturePush(std::vector< cv::VideoCapture >* v, cv::VideoCapture* value);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfVideoCaptureCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfVideoCapturePush($vecV, $v[$i])
        Next
    Else
        $vecV = $v
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfVideoCapturePush", "ptr", $vecV, "ptr", $value), "VectorOfVideoCapturePush", @error)

    If $bVIsArray Then
        _VectorOfVideoCaptureRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfVideoCapturePush

Func _VectorOfVideoCapturePushVector(ByRef $v, ByRef $other)
    ; CVAPI(void) VectorOfVideoCapturePushVector(std::vector< cv::VideoCapture >* v, std::vector< cv::VideoCapture >* other);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfVideoCaptureCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfVideoCapturePush($vecV, $v[$i])
        Next
    Else
        $vecV = $v
    EndIf

    Local $vecOther, $iArrOtherSize
    Local $bOtherIsArray = VarGetType($other) == "Array"

    If $bOtherIsArray Then
        $vecOther = _VectorOfVideoCaptureCreate()

        $iArrOtherSize = UBound($other)
        For $i = 0 To $iArrOtherSize - 1
            _VectorOfVideoCapturePush($vecOther, $other[$i])
        Next
    Else
        $vecOther = $other
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfVideoCapturePushVector", "ptr", $vecV, "ptr", $vecOther), "VectorOfVideoCapturePushVector", @error)

    If $bOtherIsArray Then
        _VectorOfVideoCaptureRelease($vecOther)
    EndIf

    If $bVIsArray Then
        _VectorOfVideoCaptureRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfVideoCapturePushVector

Func _VectorOfVideoCaptureGetStartAddress(ByRef $v)
    ; CVAPI(cv::VideoCapture*) VectorOfVideoCaptureGetStartAddress(std::vector< cv::VideoCapture >* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfVideoCaptureCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfVideoCapturePush($vecV, $v[$i])
        Next
    Else
        $vecV = $v
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfVideoCaptureGetStartAddress", "ptr", $vecV), "VectorOfVideoCaptureGetStartAddress", @error)

    If $bVIsArray Then
        _VectorOfVideoCaptureRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfVideoCaptureGetStartAddress

Func _VectorOfVideoCaptureGetEndAddress(ByRef $v)
    ; CVAPI(void*) VectorOfVideoCaptureGetEndAddress(std::vector< cv::VideoCapture >* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfVideoCaptureCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfVideoCapturePush($vecV, $v[$i])
        Next
    Else
        $vecV = $v
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfVideoCaptureGetEndAddress", "ptr", $vecV), "VectorOfVideoCaptureGetEndAddress", @error)

    If $bVIsArray Then
        _VectorOfVideoCaptureRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfVideoCaptureGetEndAddress

Func _VectorOfVideoCaptureClear(ByRef $v)
    ; CVAPI(void) VectorOfVideoCaptureClear(std::vector< cv::VideoCapture >* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfVideoCaptureCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfVideoCapturePush($vecV, $v[$i])
        Next
    Else
        $vecV = $v
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfVideoCaptureClear", "ptr", $vecV), "VectorOfVideoCaptureClear", @error)

    If $bVIsArray Then
        _VectorOfVideoCaptureRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfVideoCaptureClear

Func _VectorOfVideoCaptureRelease(ByRef $v)
    ; CVAPI(void) VectorOfVideoCaptureRelease(std::vector< cv::VideoCapture >** v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfVideoCaptureCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfVideoCapturePush($vecV, $v[$i])
        Next
    Else
        $vecV = $v
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfVideoCaptureRelease", "ptr*", $vecV), "VectorOfVideoCaptureRelease", @error)

    If $bVIsArray Then
        _VectorOfVideoCaptureRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfVideoCaptureRelease

Func _VectorOfVideoCaptureCopyData(ByRef $v, ByRef $data)
    ; CVAPI(void) VectorOfVideoCaptureCopyData(std::vector< cv::VideoCapture >* v, cv::VideoCapture* data);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfVideoCaptureCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfVideoCapturePush($vecV, $v[$i])
        Next
    Else
        $vecV = $v
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfVideoCaptureCopyData", "ptr", $vecV, "ptr", $data), "VectorOfVideoCaptureCopyData", @error)

    If $bVIsArray Then
        _VectorOfVideoCaptureRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfVideoCaptureCopyData

Func _VectorOfVideoCaptureGetItemPtr(ByRef $vec, $index, ByRef $element)
    ; CVAPI(void) VectorOfVideoCaptureGetItemPtr(std::vector<  cv::VideoCapture >* vec, int index, cv::VideoCapture** element);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfVideoCaptureCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfVideoCapturePush($vecVec, $vec[$i])
        Next
    Else
        $vecVec = $vec
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfVideoCaptureGetItemPtr", "ptr", $vecVec, "int", $index, "ptr*", $element), "VectorOfVideoCaptureGetItemPtr", @error)

    If $bVecIsArray Then
        _VectorOfVideoCaptureRelease($vecVec)
    EndIf
EndFunc   ;==>_VectorOfVideoCaptureGetItemPtr

Func _cveInputArrayFromVectorOfVideoCapture(ByRef $vec)
    ; CVAPI(cv::_InputArray*) cveInputArrayFromVectorOfVideoCapture(std::vector< cv::VideoCapture >* vec);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfVideoCaptureCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfVideoCapturePush($vecVec, $vec[$i])
        Next
    Else
        $vecVec = $vec
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveInputArrayFromVectorOfVideoCapture", "ptr", $vecVec), "cveInputArrayFromVectorOfVideoCapture", @error)

    If $bVecIsArray Then
        _VectorOfVideoCaptureRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveInputArrayFromVectorOfVideoCapture

Func _cveOutputArrayFromVectorOfVideoCapture(ByRef $vec)
    ; CVAPI(cv::_OutputArray*) cveOutputArrayFromVectorOfVideoCapture(std::vector< cv::VideoCapture >* vec);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfVideoCaptureCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfVideoCapturePush($vecVec, $vec[$i])
        Next
    Else
        $vecVec = $vec
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveOutputArrayFromVectorOfVideoCapture", "ptr", $vecVec), "cveOutputArrayFromVectorOfVideoCapture", @error)

    If $bVecIsArray Then
        _VectorOfVideoCaptureRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveOutputArrayFromVectorOfVideoCapture

Func _cveInputOutputArrayFromVectorOfVideoCapture(ByRef $vec)
    ; CVAPI(cv::_InputOutputArray*) cveInputOutputArrayFromVectorOfVideoCapture(std::vector< cv::VideoCapture >* vec);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfVideoCaptureCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfVideoCapturePush($vecVec, $vec[$i])
        Next
    Else
        $vecVec = $vec
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveInputOutputArrayFromVectorOfVideoCapture", "ptr", $vecVec), "cveInputOutputArrayFromVectorOfVideoCapture", @error)

    If $bVecIsArray Then
        _VectorOfVideoCaptureRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveInputOutputArrayFromVectorOfVideoCapture

Func _VectorOfVideoCaptureSizeOfItemInBytes()
    ; CVAPI(int) VectorOfVideoCaptureSizeOfItemInBytes();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "VectorOfVideoCaptureSizeOfItemInBytes"), "VectorOfVideoCaptureSizeOfItemInBytes", @error)
EndFunc   ;==>_VectorOfVideoCaptureSizeOfItemInBytes