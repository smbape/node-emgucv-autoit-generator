#include-once
#include <..\CVEUtils.au3>

Func _VectorOfERStatCreate()
    ; CVAPI(std::vector< cv::text::ERStat >*) VectorOfERStatCreate();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfERStatCreate"), "VectorOfERStatCreate", @error)
EndFunc   ;==>_VectorOfERStatCreate

Func _VectorOfERStatCreateSize($size)
    ; CVAPI(std::vector< cv::text::ERStat >*) VectorOfERStatCreateSize(int size);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfERStatCreateSize", "int", $size), "VectorOfERStatCreateSize", @error)
EndFunc   ;==>_VectorOfERStatCreateSize

Func _VectorOfERStatGetSize(ByRef $v)
    ; CVAPI(int) VectorOfERStatGetSize(std::vector< cv::text::ERStat >* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfERStatCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfERStatPush($vecV, $v[$i])
        Next
    Else
        $vecV = $v
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "VectorOfERStatGetSize", "ptr", $vecV), "VectorOfERStatGetSize", @error)

    If $bVIsArray Then
        _VectorOfERStatRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfERStatGetSize

Func _VectorOfERStatPush(ByRef $v, ByRef $value)
    ; CVAPI(void) VectorOfERStatPush(std::vector< cv::text::ERStat >* v, cv::text::ERStat* value);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfERStatCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfERStatPush($vecV, $v[$i])
        Next
    Else
        $vecV = $v
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfERStatPush", "ptr", $vecV, "ptr", $value), "VectorOfERStatPush", @error)

    If $bVIsArray Then
        _VectorOfERStatRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfERStatPush

Func _VectorOfERStatPushMulti(ByRef $v, ByRef $values, $count)
    ; CVAPI(void) VectorOfERStatPushMulti(std::vector< cv::text::ERStat >* v, cv::text::ERStat* values, int count);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfERStatCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfERStatPush($vecV, $v[$i])
        Next
    Else
        $vecV = $v
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfERStatPushMulti", "ptr", $vecV, "ptr", $values, "int", $count), "VectorOfERStatPushMulti", @error)

    If $bVIsArray Then
        _VectorOfERStatRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfERStatPushMulti

Func _VectorOfERStatPushVector(ByRef $v, ByRef $other)
    ; CVAPI(void) VectorOfERStatPushVector(std::vector< cv::text::ERStat >* v, std::vector< cv::text::ERStat >* other);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfERStatCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfERStatPush($vecV, $v[$i])
        Next
    Else
        $vecV = $v
    EndIf

    Local $vecOther, $iArrOtherSize
    Local $bOtherIsArray = VarGetType($other) == "Array"

    If $bOtherIsArray Then
        $vecOther = _VectorOfERStatCreate()

        $iArrOtherSize = UBound($other)
        For $i = 0 To $iArrOtherSize - 1
            _VectorOfERStatPush($vecOther, $other[$i])
        Next
    Else
        $vecOther = $other
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfERStatPushVector", "ptr", $vecV, "ptr", $vecOther), "VectorOfERStatPushVector", @error)

    If $bOtherIsArray Then
        _VectorOfERStatRelease($vecOther)
    EndIf

    If $bVIsArray Then
        _VectorOfERStatRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfERStatPushVector

Func _VectorOfERStatClear(ByRef $v)
    ; CVAPI(void) VectorOfERStatClear(std::vector< cv::text::ERStat >* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfERStatCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfERStatPush($vecV, $v[$i])
        Next
    Else
        $vecV = $v
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfERStatClear", "ptr", $vecV), "VectorOfERStatClear", @error)

    If $bVIsArray Then
        _VectorOfERStatRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfERStatClear

Func _VectorOfERStatRelease(ByRef $v)
    ; CVAPI(void) VectorOfERStatRelease(std::vector< cv::text::ERStat >** v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfERStatCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfERStatPush($vecV, $v[$i])
        Next
    Else
        $vecV = $v
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfERStatRelease", "ptr*", $vecV), "VectorOfERStatRelease", @error)

    If $bVIsArray Then
        _VectorOfERStatRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfERStatRelease

Func _VectorOfERStatCopyData(ByRef $v, ByRef $data)
    ; CVAPI(void) VectorOfERStatCopyData(std::vector< cv::text::ERStat >* v, cv::text::ERStat* data);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfERStatCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfERStatPush($vecV, $v[$i])
        Next
    Else
        $vecV = $v
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfERStatCopyData", "ptr", $vecV, "ptr", $data), "VectorOfERStatCopyData", @error)

    If $bVIsArray Then
        _VectorOfERStatRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfERStatCopyData

Func _VectorOfERStatGetStartAddress(ByRef $v)
    ; CVAPI(cv::text::ERStat*) VectorOfERStatGetStartAddress(std::vector< cv::text::ERStat >* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfERStatCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfERStatPush($vecV, $v[$i])
        Next
    Else
        $vecV = $v
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfERStatGetStartAddress", "ptr", $vecV), "VectorOfERStatGetStartAddress", @error)

    If $bVIsArray Then
        _VectorOfERStatRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfERStatGetStartAddress

Func _VectorOfERStatGetEndAddress(ByRef $v)
    ; CVAPI(void*) VectorOfERStatGetEndAddress(std::vector< cv::text::ERStat >* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfERStatCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfERStatPush($vecV, $v[$i])
        Next
    Else
        $vecV = $v
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfERStatGetEndAddress", "ptr", $vecV), "VectorOfERStatGetEndAddress", @error)

    If $bVIsArray Then
        _VectorOfERStatRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfERStatGetEndAddress

Func _VectorOfERStatGetItem(ByRef $vec, $index, ByRef $element)
    ; CVAPI(void) VectorOfERStatGetItem(std::vector<  cv::text::ERStat >* vec, int index, cv::text::ERStat* element);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfERStatCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfERStatPush($vecVec, $vec[$i])
        Next
    Else
        $vecVec = $vec
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfERStatGetItem", "ptr", $vecVec, "int", $index, "ptr", $element), "VectorOfERStatGetItem", @error)

    If $bVecIsArray Then
        _VectorOfERStatRelease($vecVec)
    EndIf
EndFunc   ;==>_VectorOfERStatGetItem

Func _VectorOfERStatGetItemPtr(ByRef $vec, $index, ByRef $element)
    ; CVAPI(void) VectorOfERStatGetItemPtr(std::vector<  cv::text::ERStat >* vec, int index, cv::text::ERStat** element);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfERStatCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfERStatPush($vecVec, $vec[$i])
        Next
    Else
        $vecVec = $vec
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfERStatGetItemPtr", "ptr", $vecVec, "int", $index, "ptr*", $element), "VectorOfERStatGetItemPtr", @error)

    If $bVecIsArray Then
        _VectorOfERStatRelease($vecVec)
    EndIf
EndFunc   ;==>_VectorOfERStatGetItemPtr

Func _cveInputArrayFromVectorOfERStat(ByRef $vec)
    ; CVAPI(cv::_InputArray*) cveInputArrayFromVectorOfERStat(std::vector< cv::text::ERStat >* vec);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfERStatCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfERStatPush($vecVec, $vec[$i])
        Next
    Else
        $vecVec = $vec
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveInputArrayFromVectorOfERStat", "ptr", $vecVec), "cveInputArrayFromVectorOfERStat", @error)

    If $bVecIsArray Then
        _VectorOfERStatRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveInputArrayFromVectorOfERStat

Func _cveOutputArrayFromVectorOfERStat(ByRef $vec)
    ; CVAPI(cv::_OutputArray*) cveOutputArrayFromVectorOfERStat(std::vector< cv::text::ERStat >* vec);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfERStatCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfERStatPush($vecVec, $vec[$i])
        Next
    Else
        $vecVec = $vec
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveOutputArrayFromVectorOfERStat", "ptr", $vecVec), "cveOutputArrayFromVectorOfERStat", @error)

    If $bVecIsArray Then
        _VectorOfERStatRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveOutputArrayFromVectorOfERStat

Func _cveInputOutputArrayFromVectorOfERStat(ByRef $vec)
    ; CVAPI(cv::_InputOutputArray*) cveInputOutputArrayFromVectorOfERStat(std::vector< cv::text::ERStat >* vec);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfERStatCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfERStatPush($vecVec, $vec[$i])
        Next
    Else
        $vecVec = $vec
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveInputOutputArrayFromVectorOfERStat", "ptr", $vecVec), "cveInputOutputArrayFromVectorOfERStat", @error)

    If $bVecIsArray Then
        _VectorOfERStatRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveInputOutputArrayFromVectorOfERStat

Func _VectorOfERStatSizeOfItemInBytes()
    ; CVAPI(int) VectorOfERStatSizeOfItemInBytes();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "VectorOfERStatSizeOfItemInBytes"), "VectorOfERStatSizeOfItemInBytes", @error)
EndFunc   ;==>_VectorOfERStatSizeOfItemInBytes