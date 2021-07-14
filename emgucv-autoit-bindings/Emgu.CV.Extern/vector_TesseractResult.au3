#include-once
#include "..\CVEUtils.au3"

Func _VectorOfTesseractResultCreate()
    ; CVAPI(std::vector< TesseractResult >*) VectorOfTesseractResultCreate();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfTesseractResultCreate"), "VectorOfTesseractResultCreate", @error)
EndFunc   ;==>_VectorOfTesseractResultCreate

Func _VectorOfTesseractResultCreateSize($size)
    ; CVAPI(std::vector< TesseractResult >*) VectorOfTesseractResultCreateSize(int size);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfTesseractResultCreateSize", "int", $size), "VectorOfTesseractResultCreateSize", @error)
EndFunc   ;==>_VectorOfTesseractResultCreateSize

Func _VectorOfTesseractResultGetSize(ByRef $v)
    ; CVAPI(int) VectorOfTesseractResultGetSize(std::vector< TesseractResult >* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfTesseractResultCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfTesseractResultPush($vecV, $v[$i])
        Next
    Else
        $vecV = $v
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "VectorOfTesseractResultGetSize", "ptr", $vecV), "VectorOfTesseractResultGetSize", @error)

    If $bVIsArray Then
        _VectorOfTesseractResultRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfTesseractResultGetSize

Func _VectorOfTesseractResultPush(ByRef $v, ByRef $value)
    ; CVAPI(void) VectorOfTesseractResultPush(std::vector< TesseractResult >* v, TesseractResult* value);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfTesseractResultCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfTesseractResultPush($vecV, $v[$i])
        Next
    Else
        $vecV = $v
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfTesseractResultPush", "ptr", $vecV, "struct*", $value), "VectorOfTesseractResultPush", @error)

    If $bVIsArray Then
        _VectorOfTesseractResultRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfTesseractResultPush

Func _VectorOfTesseractResultPushMulti(ByRef $v, ByRef $values, $count)
    ; CVAPI(void) VectorOfTesseractResultPushMulti(std::vector< TesseractResult >* v, TesseractResult* values, int count);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfTesseractResultCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfTesseractResultPush($vecV, $v[$i])
        Next
    Else
        $vecV = $v
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfTesseractResultPushMulti", "ptr", $vecV, "struct*", $values, "int", $count), "VectorOfTesseractResultPushMulti", @error)

    If $bVIsArray Then
        _VectorOfTesseractResultRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfTesseractResultPushMulti

Func _VectorOfTesseractResultPushVector(ByRef $v, ByRef $other)
    ; CVAPI(void) VectorOfTesseractResultPushVector(std::vector< TesseractResult >* v, std::vector< TesseractResult >* other);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfTesseractResultCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfTesseractResultPush($vecV, $v[$i])
        Next
    Else
        $vecV = $v
    EndIf

    Local $vecOther, $iArrOtherSize
    Local $bOtherIsArray = VarGetType($other) == "Array"

    If $bOtherIsArray Then
        $vecOther = _VectorOfTesseractResultCreate()

        $iArrOtherSize = UBound($other)
        For $i = 0 To $iArrOtherSize - 1
            _VectorOfTesseractResultPush($vecOther, $other[$i])
        Next
    Else
        $vecOther = $other
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfTesseractResultPushVector", "ptr", $vecV, "ptr", $vecOther), "VectorOfTesseractResultPushVector", @error)

    If $bOtherIsArray Then
        _VectorOfTesseractResultRelease($vecOther)
    EndIf

    If $bVIsArray Then
        _VectorOfTesseractResultRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfTesseractResultPushVector

Func _VectorOfTesseractResultClear(ByRef $v)
    ; CVAPI(void) VectorOfTesseractResultClear(std::vector< TesseractResult >* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfTesseractResultCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfTesseractResultPush($vecV, $v[$i])
        Next
    Else
        $vecV = $v
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfTesseractResultClear", "ptr", $vecV), "VectorOfTesseractResultClear", @error)

    If $bVIsArray Then
        _VectorOfTesseractResultRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfTesseractResultClear

Func _VectorOfTesseractResultRelease(ByRef $v)
    ; CVAPI(void) VectorOfTesseractResultRelease(std::vector< TesseractResult >** v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfTesseractResultCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfTesseractResultPush($vecV, $v[$i])
        Next
    Else
        $vecV = $v
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfTesseractResultRelease", "ptr*", $vecV), "VectorOfTesseractResultRelease", @error)

    If $bVIsArray Then
        _VectorOfTesseractResultRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfTesseractResultRelease

Func _VectorOfTesseractResultCopyData(ByRef $v, ByRef $data)
    ; CVAPI(void) VectorOfTesseractResultCopyData(std::vector< TesseractResult >* v, TesseractResult* data);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfTesseractResultCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfTesseractResultPush($vecV, $v[$i])
        Next
    Else
        $vecV = $v
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfTesseractResultCopyData", "ptr", $vecV, "struct*", $data), "VectorOfTesseractResultCopyData", @error)

    If $bVIsArray Then
        _VectorOfTesseractResultRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfTesseractResultCopyData

Func _VectorOfTesseractResultGetStartAddress(ByRef $v)
    ; CVAPI(TesseractResult*) VectorOfTesseractResultGetStartAddress(std::vector< TesseractResult >* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfTesseractResultCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfTesseractResultPush($vecV, $v[$i])
        Next
    Else
        $vecV = $v
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfTesseractResultGetStartAddress", "ptr", $vecV), "VectorOfTesseractResultGetStartAddress", @error)

    If $bVIsArray Then
        _VectorOfTesseractResultRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfTesseractResultGetStartAddress

Func _VectorOfTesseractResultGetEndAddress(ByRef $v)
    ; CVAPI(void*) VectorOfTesseractResultGetEndAddress(std::vector< TesseractResult >* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfTesseractResultCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfTesseractResultPush($vecV, $v[$i])
        Next
    Else
        $vecV = $v
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfTesseractResultGetEndAddress", "ptr", $vecV), "VectorOfTesseractResultGetEndAddress", @error)

    If $bVIsArray Then
        _VectorOfTesseractResultRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfTesseractResultGetEndAddress

Func _VectorOfTesseractResultGetItem(ByRef $vec, $index, ByRef $element)
    ; CVAPI(void) VectorOfTesseractResultGetItem(std::vector<  TesseractResult >* vec, int index, TesseractResult* element);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfTesseractResultCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfTesseractResultPush($vecVec, $vec[$i])
        Next
    Else
        $vecVec = $vec
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfTesseractResultGetItem", "ptr", $vecVec, "int", $index, "struct*", $element), "VectorOfTesseractResultGetItem", @error)

    If $bVecIsArray Then
        _VectorOfTesseractResultRelease($vecVec)
    EndIf
EndFunc   ;==>_VectorOfTesseractResultGetItem

Func _VectorOfTesseractResultGetItemPtr(ByRef $vec, $index, ByRef $element)
    ; CVAPI(void) VectorOfTesseractResultGetItemPtr(std::vector<  TesseractResult >* vec, int index, TesseractResult** element);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfTesseractResultCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfTesseractResultPush($vecVec, $vec[$i])
        Next
    Else
        $vecVec = $vec
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfTesseractResultGetItemPtr", "ptr", $vecVec, "int", $index, "ptr*", $element), "VectorOfTesseractResultGetItemPtr", @error)

    If $bVecIsArray Then
        _VectorOfTesseractResultRelease($vecVec)
    EndIf
EndFunc   ;==>_VectorOfTesseractResultGetItemPtr

Func _cveInputArrayFromVectorOfTesseractResult(ByRef $vec)
    ; CVAPI(cv::_InputArray*) cveInputArrayFromVectorOfTesseractResult(std::vector< TesseractResult >* vec);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfTesseractResultCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfTesseractResultPush($vecVec, $vec[$i])
        Next
    Else
        $vecVec = $vec
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveInputArrayFromVectorOfTesseractResult", "ptr", $vecVec), "cveInputArrayFromVectorOfTesseractResult", @error)

    If $bVecIsArray Then
        _VectorOfTesseractResultRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveInputArrayFromVectorOfTesseractResult

Func _cveOutputArrayFromVectorOfTesseractResult(ByRef $vec)
    ; CVAPI(cv::_OutputArray*) cveOutputArrayFromVectorOfTesseractResult(std::vector< TesseractResult >* vec);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfTesseractResultCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfTesseractResultPush($vecVec, $vec[$i])
        Next
    Else
        $vecVec = $vec
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveOutputArrayFromVectorOfTesseractResult", "ptr", $vecVec), "cveOutputArrayFromVectorOfTesseractResult", @error)

    If $bVecIsArray Then
        _VectorOfTesseractResultRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveOutputArrayFromVectorOfTesseractResult

Func _cveInputOutputArrayFromVectorOfTesseractResult(ByRef $vec)
    ; CVAPI(cv::_InputOutputArray*) cveInputOutputArrayFromVectorOfTesseractResult(std::vector< TesseractResult >* vec);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfTesseractResultCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfTesseractResultPush($vecVec, $vec[$i])
        Next
    Else
        $vecVec = $vec
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveInputOutputArrayFromVectorOfTesseractResult", "ptr", $vecVec), "cveInputOutputArrayFromVectorOfTesseractResult", @error)

    If $bVecIsArray Then
        _VectorOfTesseractResultRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveInputOutputArrayFromVectorOfTesseractResult

Func _VectorOfTesseractResultSizeOfItemInBytes()
    ; CVAPI(int) VectorOfTesseractResultSizeOfItemInBytes();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "VectorOfTesseractResultSizeOfItemInBytes"), "VectorOfTesseractResultSizeOfItemInBytes", @error)
EndFunc   ;==>_VectorOfTesseractResultSizeOfItemInBytes