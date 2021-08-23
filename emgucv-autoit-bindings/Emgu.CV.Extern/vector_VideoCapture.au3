#include-once
#include "..\CVEUtils.au3"

Func _VectorOfVideoCaptureCreate()
    ; CVAPI(std::vector<cv::VideoCapture>*) VectorOfVideoCaptureCreate();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfVideoCaptureCreate"), "VectorOfVideoCaptureCreate", @error)
EndFunc   ;==>_VectorOfVideoCaptureCreate

Func _VectorOfVideoCaptureCreateSize($size)
    ; CVAPI(std::vector<cv::VideoCapture>*) VectorOfVideoCaptureCreateSize(int size);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfVideoCaptureCreateSize", "int", $size), "VectorOfVideoCaptureCreateSize", @error)
EndFunc   ;==>_VectorOfVideoCaptureCreateSize

Func _VectorOfVideoCaptureGetSize($v)
    ; CVAPI(int) VectorOfVideoCaptureGetSize(std::vector<cv::VideoCapture>* v);

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

    Local $sVDllType
    If IsDllStruct($v) Then
        $sVDllType = "struct*"
    Else
        $sVDllType = "ptr"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "VectorOfVideoCaptureGetSize", $sVDllType, $vecV), "VectorOfVideoCaptureGetSize", @error)

    If $bVIsArray Then
        _VectorOfVideoCaptureRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfVideoCaptureGetSize

Func _VectorOfVideoCapturePush($v, $value)
    ; CVAPI(void) VectorOfVideoCapturePush(std::vector<cv::VideoCapture>* v, cv::VideoCapture* value);

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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfVideoCapturePush", $sVDllType, $vecV, $sValueDllType, $value), "VectorOfVideoCapturePush", @error)

    If $bVIsArray Then
        _VectorOfVideoCaptureRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfVideoCapturePush

Func _VectorOfVideoCapturePushVector($v, $other)
    ; CVAPI(void) VectorOfVideoCapturePushVector(std::vector<cv::VideoCapture>* v, std::vector<cv::VideoCapture>* other);

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

    Local $sVDllType
    If IsDllStruct($v) Then
        $sVDllType = "struct*"
    Else
        $sVDllType = "ptr"
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

    Local $sOtherDllType
    If IsDllStruct($other) Then
        $sOtherDllType = "struct*"
    Else
        $sOtherDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfVideoCapturePushVector", $sVDllType, $vecV, $sOtherDllType, $vecOther), "VectorOfVideoCapturePushVector", @error)

    If $bOtherIsArray Then
        _VectorOfVideoCaptureRelease($vecOther)
    EndIf

    If $bVIsArray Then
        _VectorOfVideoCaptureRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfVideoCapturePushVector

Func _VectorOfVideoCaptureGetStartAddress($v)
    ; CVAPI(cv::VideoCapture*) VectorOfVideoCaptureGetStartAddress(std::vector<cv::VideoCapture>* v);

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

    Local $sVDllType
    If IsDllStruct($v) Then
        $sVDllType = "struct*"
    Else
        $sVDllType = "ptr"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfVideoCaptureGetStartAddress", $sVDllType, $vecV), "VectorOfVideoCaptureGetStartAddress", @error)

    If $bVIsArray Then
        _VectorOfVideoCaptureRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfVideoCaptureGetStartAddress

Func _VectorOfVideoCaptureGetEndAddress($v)
    ; CVAPI(void*) VectorOfVideoCaptureGetEndAddress(std::vector<cv::VideoCapture>* v);

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

    Local $sVDllType
    If IsDllStruct($v) Then
        $sVDllType = "struct*"
    Else
        $sVDllType = "ptr"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfVideoCaptureGetEndAddress", $sVDllType, $vecV), "VectorOfVideoCaptureGetEndAddress", @error)

    If $bVIsArray Then
        _VectorOfVideoCaptureRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfVideoCaptureGetEndAddress

Func _VectorOfVideoCaptureClear($v)
    ; CVAPI(void) VectorOfVideoCaptureClear(std::vector<cv::VideoCapture>* v);

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

    Local $sVDllType
    If IsDllStruct($v) Then
        $sVDllType = "struct*"
    Else
        $sVDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfVideoCaptureClear", $sVDllType, $vecV), "VectorOfVideoCaptureClear", @error)

    If $bVIsArray Then
        _VectorOfVideoCaptureRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfVideoCaptureClear

Func _VectorOfVideoCaptureRelease($v)
    ; CVAPI(void) VectorOfVideoCaptureRelease(std::vector<cv::VideoCapture>** v);

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

    Local $sVDllType
    If IsDllStruct($v) Then
        $sVDllType = "struct*"
    ElseIf $v == Null Then
        $sVDllType = "ptr"
    Else
        $sVDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfVideoCaptureRelease", $sVDllType, $vecV), "VectorOfVideoCaptureRelease", @error)

    If $bVIsArray Then
        _VectorOfVideoCaptureRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfVideoCaptureRelease

Func _VectorOfVideoCaptureCopyData($v, $data)
    ; CVAPI(void) VectorOfVideoCaptureCopyData(std::vector<cv::VideoCapture>* v, cv::VideoCapture* data);

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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfVideoCaptureCopyData", $sVDllType, $vecV, $sDataDllType, $data), "VectorOfVideoCaptureCopyData", @error)

    If $bVIsArray Then
        _VectorOfVideoCaptureRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfVideoCaptureCopyData

Func _VectorOfVideoCaptureGetItemPtr($vec, $index, $element)
    ; CVAPI(void) VectorOfVideoCaptureGetItemPtr(std::vector<cv::VideoCapture>* vec, int index, cv::VideoCapture** element);

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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfVideoCaptureGetItemPtr", $sVecDllType, $vecVec, "int", $index, $sElementDllType, $element), "VectorOfVideoCaptureGetItemPtr", @error)

    If $bVecIsArray Then
        _VectorOfVideoCaptureRelease($vecVec)
    EndIf
EndFunc   ;==>_VectorOfVideoCaptureGetItemPtr

Func _cveInputArrayFromVectorOfVideoCapture($vec)
    ; CVAPI(cv::_InputArray*) cveInputArrayFromVectorOfVideoCapture(std::vector<cv::VideoCapture>* vec);

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

    Local $sVecDllType
    If IsDllStruct($vec) Then
        $sVecDllType = "struct*"
    Else
        $sVecDllType = "ptr"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveInputArrayFromVectorOfVideoCapture", $sVecDllType, $vecVec), "cveInputArrayFromVectorOfVideoCapture", @error)

    If $bVecIsArray Then
        _VectorOfVideoCaptureRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveInputArrayFromVectorOfVideoCapture

Func _cveOutputArrayFromVectorOfVideoCapture($vec)
    ; CVAPI(cv::_OutputArray*) cveOutputArrayFromVectorOfVideoCapture(std::vector<cv::VideoCapture>* vec);

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

    Local $sVecDllType
    If IsDllStruct($vec) Then
        $sVecDllType = "struct*"
    Else
        $sVecDllType = "ptr"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveOutputArrayFromVectorOfVideoCapture", $sVecDllType, $vecVec), "cveOutputArrayFromVectorOfVideoCapture", @error)

    If $bVecIsArray Then
        _VectorOfVideoCaptureRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveOutputArrayFromVectorOfVideoCapture

Func _cveInputOutputArrayFromVectorOfVideoCapture($vec)
    ; CVAPI(cv::_InputOutputArray*) cveInputOutputArrayFromVectorOfVideoCapture(std::vector<cv::VideoCapture>* vec);

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

    Local $sVecDllType
    If IsDllStruct($vec) Then
        $sVecDllType = "struct*"
    Else
        $sVecDllType = "ptr"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveInputOutputArrayFromVectorOfVideoCapture", $sVecDllType, $vecVec), "cveInputOutputArrayFromVectorOfVideoCapture", @error)

    If $bVecIsArray Then
        _VectorOfVideoCaptureRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveInputOutputArrayFromVectorOfVideoCapture

Func _VectorOfVideoCaptureSizeOfItemInBytes()
    ; CVAPI(int) VectorOfVideoCaptureSizeOfItemInBytes();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "VectorOfVideoCaptureSizeOfItemInBytes"), "VectorOfVideoCaptureSizeOfItemInBytes", @error)
EndFunc   ;==>_VectorOfVideoCaptureSizeOfItemInBytes