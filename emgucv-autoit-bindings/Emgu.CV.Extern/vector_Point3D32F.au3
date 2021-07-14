#include-once
#include <..\CVEUtils.au3>

Func _VectorOfPoint3D32FCreate()
    ; CVAPI(std::vector< cv::Point3f >*) VectorOfPoint3D32FCreate();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfPoint3D32FCreate"), "VectorOfPoint3D32FCreate", @error)
EndFunc   ;==>_VectorOfPoint3D32FCreate

Func _VectorOfPoint3D32FCreateSize($size)
    ; CVAPI(std::vector< cv::Point3f >*) VectorOfPoint3D32FCreateSize(int size);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfPoint3D32FCreateSize", "int", $size), "VectorOfPoint3D32FCreateSize", @error)
EndFunc   ;==>_VectorOfPoint3D32FCreateSize

Func _VectorOfPoint3D32FGetSize(ByRef $v)
    ; CVAPI(int) VectorOfPoint3D32FGetSize(std::vector< cv::Point3f >* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfPoint3D32FCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfPoint3D32FPush($vecV, $v[$i])
        Next
    Else
        $vecV = $v
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "VectorOfPoint3D32FGetSize", "ptr", $vecV), "VectorOfPoint3D32FGetSize", @error)

    If $bVIsArray Then
        _VectorOfPoint3D32FRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfPoint3D32FGetSize

Func _VectorOfPoint3D32FPush(ByRef $v, ByRef $value)
    ; CVAPI(void) VectorOfPoint3D32FPush(std::vector< cv::Point3f >* v, cv::Point3f* value);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfPoint3D32FCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfPoint3D32FPush($vecV, $v[$i])
        Next
    Else
        $vecV = $v
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfPoint3D32FPush", "ptr", $vecV, "ptr", $value), "VectorOfPoint3D32FPush", @error)

    If $bVIsArray Then
        _VectorOfPoint3D32FRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfPoint3D32FPush

Func _VectorOfPoint3D32FPushMulti(ByRef $v, ByRef $values, $count)
    ; CVAPI(void) VectorOfPoint3D32FPushMulti(std::vector< cv::Point3f >* v, cv::Point3f* values, int count);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfPoint3D32FCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfPoint3D32FPush($vecV, $v[$i])
        Next
    Else
        $vecV = $v
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfPoint3D32FPushMulti", "ptr", $vecV, "ptr", $values, "int", $count), "VectorOfPoint3D32FPushMulti", @error)

    If $bVIsArray Then
        _VectorOfPoint3D32FRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfPoint3D32FPushMulti

Func _VectorOfPoint3D32FPushVector(ByRef $v, ByRef $other)
    ; CVAPI(void) VectorOfPoint3D32FPushVector(std::vector< cv::Point3f >* v, std::vector< cv::Point3f >* other);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfPoint3D32FCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfPoint3D32FPush($vecV, $v[$i])
        Next
    Else
        $vecV = $v
    EndIf

    Local $vecOther, $iArrOtherSize
    Local $bOtherIsArray = VarGetType($other) == "Array"

    If $bOtherIsArray Then
        $vecOther = _VectorOfPoint3D32FCreate()

        $iArrOtherSize = UBound($other)
        For $i = 0 To $iArrOtherSize - 1
            _VectorOfPoint3D32FPush($vecOther, $other[$i])
        Next
    Else
        $vecOther = $other
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfPoint3D32FPushVector", "ptr", $vecV, "ptr", $vecOther), "VectorOfPoint3D32FPushVector", @error)

    If $bOtherIsArray Then
        _VectorOfPoint3D32FRelease($vecOther)
    EndIf

    If $bVIsArray Then
        _VectorOfPoint3D32FRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfPoint3D32FPushVector

Func _VectorOfPoint3D32FClear(ByRef $v)
    ; CVAPI(void) VectorOfPoint3D32FClear(std::vector< cv::Point3f >* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfPoint3D32FCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfPoint3D32FPush($vecV, $v[$i])
        Next
    Else
        $vecV = $v
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfPoint3D32FClear", "ptr", $vecV), "VectorOfPoint3D32FClear", @error)

    If $bVIsArray Then
        _VectorOfPoint3D32FRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfPoint3D32FClear

Func _VectorOfPoint3D32FRelease(ByRef $v)
    ; CVAPI(void) VectorOfPoint3D32FRelease(std::vector< cv::Point3f >** v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfPoint3D32FCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfPoint3D32FPush($vecV, $v[$i])
        Next
    Else
        $vecV = $v
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfPoint3D32FRelease", "ptr*", $vecV), "VectorOfPoint3D32FRelease", @error)

    If $bVIsArray Then
        _VectorOfPoint3D32FRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfPoint3D32FRelease

Func _VectorOfPoint3D32FCopyData(ByRef $v, ByRef $data)
    ; CVAPI(void) VectorOfPoint3D32FCopyData(std::vector< cv::Point3f >* v, cv::Point3f* data);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfPoint3D32FCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfPoint3D32FPush($vecV, $v[$i])
        Next
    Else
        $vecV = $v
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfPoint3D32FCopyData", "ptr", $vecV, "ptr", $data), "VectorOfPoint3D32FCopyData", @error)

    If $bVIsArray Then
        _VectorOfPoint3D32FRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfPoint3D32FCopyData

Func _VectorOfPoint3D32FGetStartAddress(ByRef $v)
    ; CVAPI(cv::Point3f*) VectorOfPoint3D32FGetStartAddress(std::vector< cv::Point3f >* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfPoint3D32FCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfPoint3D32FPush($vecV, $v[$i])
        Next
    Else
        $vecV = $v
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfPoint3D32FGetStartAddress", "ptr", $vecV), "VectorOfPoint3D32FGetStartAddress", @error)

    If $bVIsArray Then
        _VectorOfPoint3D32FRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfPoint3D32FGetStartAddress

Func _VectorOfPoint3D32FGetEndAddress(ByRef $v)
    ; CVAPI(void*) VectorOfPoint3D32FGetEndAddress(std::vector< cv::Point3f >* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfPoint3D32FCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfPoint3D32FPush($vecV, $v[$i])
        Next
    Else
        $vecV = $v
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfPoint3D32FGetEndAddress", "ptr", $vecV), "VectorOfPoint3D32FGetEndAddress", @error)

    If $bVIsArray Then
        _VectorOfPoint3D32FRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfPoint3D32FGetEndAddress

Func _VectorOfPoint3D32FGetItem(ByRef $vec, $index, ByRef $element)
    ; CVAPI(void) VectorOfPoint3D32FGetItem(std::vector<  cv::Point3f >* vec, int index, cv::Point3f* element);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfPoint3D32FCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfPoint3D32FPush($vecVec, $vec[$i])
        Next
    Else
        $vecVec = $vec
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfPoint3D32FGetItem", "ptr", $vecVec, "int", $index, "ptr", $element), "VectorOfPoint3D32FGetItem", @error)

    If $bVecIsArray Then
        _VectorOfPoint3D32FRelease($vecVec)
    EndIf
EndFunc   ;==>_VectorOfPoint3D32FGetItem

Func _VectorOfPoint3D32FGetItemPtr(ByRef $vec, $index, ByRef $element)
    ; CVAPI(void) VectorOfPoint3D32FGetItemPtr(std::vector<  cv::Point3f >* vec, int index, cv::Point3f** element);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfPoint3D32FCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfPoint3D32FPush($vecVec, $vec[$i])
        Next
    Else
        $vecVec = $vec
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfPoint3D32FGetItemPtr", "ptr", $vecVec, "int", $index, "ptr*", $element), "VectorOfPoint3D32FGetItemPtr", @error)

    If $bVecIsArray Then
        _VectorOfPoint3D32FRelease($vecVec)
    EndIf
EndFunc   ;==>_VectorOfPoint3D32FGetItemPtr

Func _cveInputArrayFromVectorOfPoint3D32F(ByRef $vec)
    ; CVAPI(cv::_InputArray*) cveInputArrayFromVectorOfPoint3D32F(std::vector< cv::Point3f >* vec);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfPoint3D32FCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfPoint3D32FPush($vecVec, $vec[$i])
        Next
    Else
        $vecVec = $vec
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveInputArrayFromVectorOfPoint3D32F", "ptr", $vecVec), "cveInputArrayFromVectorOfPoint3D32F", @error)

    If $bVecIsArray Then
        _VectorOfPoint3D32FRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveInputArrayFromVectorOfPoint3D32F

Func _cveOutputArrayFromVectorOfPoint3D32F(ByRef $vec)
    ; CVAPI(cv::_OutputArray*) cveOutputArrayFromVectorOfPoint3D32F(std::vector< cv::Point3f >* vec);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfPoint3D32FCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfPoint3D32FPush($vecVec, $vec[$i])
        Next
    Else
        $vecVec = $vec
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveOutputArrayFromVectorOfPoint3D32F", "ptr", $vecVec), "cveOutputArrayFromVectorOfPoint3D32F", @error)

    If $bVecIsArray Then
        _VectorOfPoint3D32FRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveOutputArrayFromVectorOfPoint3D32F

Func _cveInputOutputArrayFromVectorOfPoint3D32F(ByRef $vec)
    ; CVAPI(cv::_InputOutputArray*) cveInputOutputArrayFromVectorOfPoint3D32F(std::vector< cv::Point3f >* vec);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfPoint3D32FCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfPoint3D32FPush($vecVec, $vec[$i])
        Next
    Else
        $vecVec = $vec
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveInputOutputArrayFromVectorOfPoint3D32F", "ptr", $vecVec), "cveInputOutputArrayFromVectorOfPoint3D32F", @error)

    If $bVecIsArray Then
        _VectorOfPoint3D32FRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveInputOutputArrayFromVectorOfPoint3D32F

Func _VectorOfPoint3D32FSizeOfItemInBytes()
    ; CVAPI(int) VectorOfPoint3D32FSizeOfItemInBytes();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "VectorOfPoint3D32FSizeOfItemInBytes"), "VectorOfPoint3D32FSizeOfItemInBytes", @error)
EndFunc   ;==>_VectorOfPoint3D32FSizeOfItemInBytes