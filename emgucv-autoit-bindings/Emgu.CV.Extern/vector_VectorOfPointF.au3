#include-once
#include <..\CVEUtils.au3>

Func _VectorOfVectorOfPointFCreate()
    ; CVAPI(std::vector< std::vector< cv::Point2f > >*) VectorOfVectorOfPointFCreate();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfVectorOfPointFCreate"), "VectorOfVectorOfPointFCreate", @error)
EndFunc   ;==>_VectorOfVectorOfPointFCreate

Func _VectorOfVectorOfPointFCreateSize($size)
    ; CVAPI(std::vector< std::vector< cv::Point2f > >*) VectorOfVectorOfPointFCreateSize(int size);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfVectorOfPointFCreateSize", "int", $size), "VectorOfVectorOfPointFCreateSize", @error)
EndFunc   ;==>_VectorOfVectorOfPointFCreateSize

Func _VectorOfVectorOfPointFGetSize(ByRef $v)
    ; CVAPI(int) VectorOfVectorOfPointFGetSize(std::vector< std::vector< cv::Point2f > >* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfVectorOfPointFCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfVectorOfPointFPush($vecV, $v[$i])
        Next
    Else
        $vecV = $v
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "VectorOfVectorOfPointFGetSize", "ptr", $vecV), "VectorOfVectorOfPointFGetSize", @error)

    If $bVIsArray Then
        _VectorOfVectorOfPointFRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfVectorOfPointFGetSize

Func _VectorOfVectorOfPointFPush(ByRef $v, ByRef $value)
    ; CVAPI(void) VectorOfVectorOfPointFPush(std::vector< std::vector< cv::Point2f > >* v, std::vector< cv::Point2f >* value);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfVectorOfPointFCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfVectorOfPointFPush($vecV, $v[$i])
        Next
    Else
        $vecV = $v
    EndIf

    Local $vecValue, $iArrValueSize
    Local $bValueIsArray = VarGetType($value) == "Array"

    If $bValueIsArray Then
        $vecValue = _VectorOfPointFCreate()

        $iArrValueSize = UBound($value)
        For $i = 0 To $iArrValueSize - 1
            _VectorOfPointFPush($vecValue, $value[$i])
        Next
    Else
        $vecValue = $value
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfVectorOfPointFPush", "ptr", $vecV, "ptr", $vecValue), "VectorOfVectorOfPointFPush", @error)

    If $bValueIsArray Then
        _VectorOfPointFRelease($vecValue)
    EndIf

    If $bVIsArray Then
        _VectorOfVectorOfPointFRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfVectorOfPointFPush

Func _VectorOfVectorOfPointFPushVector(ByRef $v, ByRef $other)
    ; CVAPI(void) VectorOfVectorOfPointFPushVector(std::vector< std::vector< cv::Point2f > >* v, std::vector< std::vector< cv::Point2f > >* other);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfVectorOfPointFCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfVectorOfPointFPush($vecV, $v[$i])
        Next
    Else
        $vecV = $v
    EndIf

    Local $vecOther, $iArrOtherSize
    Local $bOtherIsArray = VarGetType($other) == "Array"

    If $bOtherIsArray Then
        $vecOther = _VectorOfVectorOfPointFCreate()

        $iArrOtherSize = UBound($other)
        For $i = 0 To $iArrOtherSize - 1
            _VectorOfVectorOfPointFPush($vecOther, $other[$i])
        Next
    Else
        $vecOther = $other
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfVectorOfPointFPushVector", "ptr", $vecV, "ptr", $vecOther), "VectorOfVectorOfPointFPushVector", @error)

    If $bOtherIsArray Then
        _VectorOfVectorOfPointFRelease($vecOther)
    EndIf

    If $bVIsArray Then
        _VectorOfVectorOfPointFRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfVectorOfPointFPushVector

Func _VectorOfVectorOfPointFGetStartAddress(ByRef $v)
    ; CVAPI(std::vector< cv::Point2f >*) VectorOfVectorOfPointFGetStartAddress(std::vector< std::vector< cv::Point2f > >* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfVectorOfPointFCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfVectorOfPointFPush($vecV, $v[$i])
        Next
    Else
        $vecV = $v
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfVectorOfPointFGetStartAddress", "ptr", $vecV), "VectorOfVectorOfPointFGetStartAddress", @error)

    If $bVIsArray Then
        _VectorOfVectorOfPointFRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfVectorOfPointFGetStartAddress

Func _VectorOfVectorOfPointFGetEndAddress(ByRef $v)
    ; CVAPI(void*) VectorOfVectorOfPointFGetEndAddress(std::vector< std::vector< cv::Point2f > >* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfVectorOfPointFCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfVectorOfPointFPush($vecV, $v[$i])
        Next
    Else
        $vecV = $v
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfVectorOfPointFGetEndAddress", "ptr", $vecV), "VectorOfVectorOfPointFGetEndAddress", @error)

    If $bVIsArray Then
        _VectorOfVectorOfPointFRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfVectorOfPointFGetEndAddress

Func _VectorOfVectorOfPointFClear(ByRef $v)
    ; CVAPI(void) VectorOfVectorOfPointFClear(std::vector< std::vector< cv::Point2f > >* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfVectorOfPointFCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfVectorOfPointFPush($vecV, $v[$i])
        Next
    Else
        $vecV = $v
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfVectorOfPointFClear", "ptr", $vecV), "VectorOfVectorOfPointFClear", @error)

    If $bVIsArray Then
        _VectorOfVectorOfPointFRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfVectorOfPointFClear

Func _VectorOfVectorOfPointFRelease(ByRef $v)
    ; CVAPI(void) VectorOfVectorOfPointFRelease(std::vector< std::vector< cv::Point2f > >** v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfVectorOfPointFCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfVectorOfPointFPush($vecV, $v[$i])
        Next
    Else
        $vecV = $v
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfVectorOfPointFRelease", "ptr*", $vecV), "VectorOfVectorOfPointFRelease", @error)

    If $bVIsArray Then
        _VectorOfVectorOfPointFRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfVectorOfPointFRelease

Func _VectorOfVectorOfPointFCopyData(ByRef $v, ByRef $data)
    ; CVAPI(void) VectorOfVectorOfPointFCopyData(std::vector< std::vector< cv::Point2f > >* v, std::vector< cv::Point2f >* data);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfVectorOfPointFCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfVectorOfPointFPush($vecV, $v[$i])
        Next
    Else
        $vecV = $v
    EndIf

    Local $vecData, $iArrDataSize
    Local $bDataIsArray = VarGetType($data) == "Array"

    If $bDataIsArray Then
        $vecData = _VectorOfPointFCreate()

        $iArrDataSize = UBound($data)
        For $i = 0 To $iArrDataSize - 1
            _VectorOfPointFPush($vecData, $data[$i])
        Next
    Else
        $vecData = $data
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfVectorOfPointFCopyData", "ptr", $vecV, "ptr", $vecData), "VectorOfVectorOfPointFCopyData", @error)

    If $bDataIsArray Then
        _VectorOfPointFRelease($vecData)
    EndIf

    If $bVIsArray Then
        _VectorOfVectorOfPointFRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfVectorOfPointFCopyData

Func _VectorOfVectorOfPointFGetItemPtr(ByRef $vec, $index, ByRef $element)
    ; CVAPI(void) VectorOfVectorOfPointFGetItemPtr(std::vector<  std::vector< cv::Point2f > >* vec, int index, std::vector< cv::Point2f >** element);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfVectorOfPointFCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfVectorOfPointFPush($vecVec, $vec[$i])
        Next
    Else
        $vecVec = $vec
    EndIf

    Local $vecElement, $iArrElementSize
    Local $bElementIsArray = VarGetType($element) == "Array"

    If $bElementIsArray Then
        $vecElement = _VectorOfPointFCreate()

        $iArrElementSize = UBound($element)
        For $i = 0 To $iArrElementSize - 1
            _VectorOfPointFPush($vecElement, $element[$i])
        Next
    Else
        $vecElement = $element
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfVectorOfPointFGetItemPtr", "ptr", $vecVec, "int", $index, "ptr*", $vecElement), "VectorOfVectorOfPointFGetItemPtr", @error)

    If $bElementIsArray Then
        _VectorOfPointFRelease($vecElement)
    EndIf

    If $bVecIsArray Then
        _VectorOfVectorOfPointFRelease($vecVec)
    EndIf
EndFunc   ;==>_VectorOfVectorOfPointFGetItemPtr

Func _cveInputArrayFromVectorOfVectorOfPointF(ByRef $vec)
    ; CVAPI(cv::_InputArray*) cveInputArrayFromVectorOfVectorOfPointF(std::vector< std::vector< cv::Point2f > >* vec);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfVectorOfPointFCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfVectorOfPointFPush($vecVec, $vec[$i])
        Next
    Else
        $vecVec = $vec
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveInputArrayFromVectorOfVectorOfPointF", "ptr", $vecVec), "cveInputArrayFromVectorOfVectorOfPointF", @error)

    If $bVecIsArray Then
        _VectorOfVectorOfPointFRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveInputArrayFromVectorOfVectorOfPointF

Func _cveOutputArrayFromVectorOfVectorOfPointF(ByRef $vec)
    ; CVAPI(cv::_OutputArray*) cveOutputArrayFromVectorOfVectorOfPointF(std::vector< std::vector< cv::Point2f > >* vec);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfVectorOfPointFCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfVectorOfPointFPush($vecVec, $vec[$i])
        Next
    Else
        $vecVec = $vec
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveOutputArrayFromVectorOfVectorOfPointF", "ptr", $vecVec), "cveOutputArrayFromVectorOfVectorOfPointF", @error)

    If $bVecIsArray Then
        _VectorOfVectorOfPointFRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveOutputArrayFromVectorOfVectorOfPointF

Func _cveInputOutputArrayFromVectorOfVectorOfPointF(ByRef $vec)
    ; CVAPI(cv::_InputOutputArray*) cveInputOutputArrayFromVectorOfVectorOfPointF(std::vector< std::vector< cv::Point2f > >* vec);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfVectorOfPointFCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfVectorOfPointFPush($vecVec, $vec[$i])
        Next
    Else
        $vecVec = $vec
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveInputOutputArrayFromVectorOfVectorOfPointF", "ptr", $vecVec), "cveInputOutputArrayFromVectorOfVectorOfPointF", @error)

    If $bVecIsArray Then
        _VectorOfVectorOfPointFRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveInputOutputArrayFromVectorOfVectorOfPointF

Func _VectorOfVectorOfPointFSizeOfItemInBytes()
    ; CVAPI(int) VectorOfVectorOfPointFSizeOfItemInBytes();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "VectorOfVectorOfPointFSizeOfItemInBytes"), "VectorOfVectorOfPointFSizeOfItemInBytes", @error)
EndFunc   ;==>_VectorOfVectorOfPointFSizeOfItemInBytes