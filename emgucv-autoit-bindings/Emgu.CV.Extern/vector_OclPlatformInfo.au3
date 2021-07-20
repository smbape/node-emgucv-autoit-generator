#include-once
#include "..\CVEUtils.au3"

Func _VectorOfOclPlatformInfoCreate()
    ; CVAPI(std::vector< cv::ocl::PlatformInfo >*) VectorOfOclPlatformInfoCreate();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfOclPlatformInfoCreate"), "VectorOfOclPlatformInfoCreate", @error)
EndFunc   ;==>_VectorOfOclPlatformInfoCreate

Func _VectorOfOclPlatformInfoCreateSize($size)
    ; CVAPI(std::vector< cv::ocl::PlatformInfo >*) VectorOfOclPlatformInfoCreateSize(int size);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfOclPlatformInfoCreateSize", "int", $size), "VectorOfOclPlatformInfoCreateSize", @error)
EndFunc   ;==>_VectorOfOclPlatformInfoCreateSize

Func _VectorOfOclPlatformInfoGetSize($v)
    ; CVAPI(int) VectorOfOclPlatformInfoGetSize(std::vector< cv::ocl::PlatformInfo >* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfOclPlatformInfoCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfOclPlatformInfoPush($vecV, $v[$i])
        Next
    Else
        $vecV = $v
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "VectorOfOclPlatformInfoGetSize", "ptr", $vecV), "VectorOfOclPlatformInfoGetSize", @error)

    If $bVIsArray Then
        _VectorOfOclPlatformInfoRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfOclPlatformInfoGetSize

Func _VectorOfOclPlatformInfoPush($v, $value)
    ; CVAPI(void) VectorOfOclPlatformInfoPush(std::vector< cv::ocl::PlatformInfo >* v, cv::ocl::PlatformInfo* value);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfOclPlatformInfoCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfOclPlatformInfoPush($vecV, $v[$i])
        Next
    Else
        $vecV = $v
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfOclPlatformInfoPush", "ptr", $vecV, "ptr", $value), "VectorOfOclPlatformInfoPush", @error)

    If $bVIsArray Then
        _VectorOfOclPlatformInfoRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfOclPlatformInfoPush

Func _VectorOfOclPlatformInfoPushVector($v, $other)
    ; CVAPI(void) VectorOfOclPlatformInfoPushVector(std::vector< cv::ocl::PlatformInfo >* v, std::vector< cv::ocl::PlatformInfo >* other);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfOclPlatformInfoCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfOclPlatformInfoPush($vecV, $v[$i])
        Next
    Else
        $vecV = $v
    EndIf

    Local $vecOther, $iArrOtherSize
    Local $bOtherIsArray = VarGetType($other) == "Array"

    If $bOtherIsArray Then
        $vecOther = _VectorOfOclPlatformInfoCreate()

        $iArrOtherSize = UBound($other)
        For $i = 0 To $iArrOtherSize - 1
            _VectorOfOclPlatformInfoPush($vecOther, $other[$i])
        Next
    Else
        $vecOther = $other
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfOclPlatformInfoPushVector", "ptr", $vecV, "ptr", $vecOther), "VectorOfOclPlatformInfoPushVector", @error)

    If $bOtherIsArray Then
        _VectorOfOclPlatformInfoRelease($vecOther)
    EndIf

    If $bVIsArray Then
        _VectorOfOclPlatformInfoRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfOclPlatformInfoPushVector

Func _VectorOfOclPlatformInfoGetStartAddress($v)
    ; CVAPI(cv::ocl::PlatformInfo*) VectorOfOclPlatformInfoGetStartAddress(std::vector< cv::ocl::PlatformInfo >* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfOclPlatformInfoCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfOclPlatformInfoPush($vecV, $v[$i])
        Next
    Else
        $vecV = $v
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfOclPlatformInfoGetStartAddress", "ptr", $vecV), "VectorOfOclPlatformInfoGetStartAddress", @error)

    If $bVIsArray Then
        _VectorOfOclPlatformInfoRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfOclPlatformInfoGetStartAddress

Func _VectorOfOclPlatformInfoGetEndAddress($v)
    ; CVAPI(void*) VectorOfOclPlatformInfoGetEndAddress(std::vector< cv::ocl::PlatformInfo >* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfOclPlatformInfoCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfOclPlatformInfoPush($vecV, $v[$i])
        Next
    Else
        $vecV = $v
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfOclPlatformInfoGetEndAddress", "ptr", $vecV), "VectorOfOclPlatformInfoGetEndAddress", @error)

    If $bVIsArray Then
        _VectorOfOclPlatformInfoRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfOclPlatformInfoGetEndAddress

Func _VectorOfOclPlatformInfoClear($v)
    ; CVAPI(void) VectorOfOclPlatformInfoClear(std::vector< cv::ocl::PlatformInfo >* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfOclPlatformInfoCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfOclPlatformInfoPush($vecV, $v[$i])
        Next
    Else
        $vecV = $v
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfOclPlatformInfoClear", "ptr", $vecV), "VectorOfOclPlatformInfoClear", @error)

    If $bVIsArray Then
        _VectorOfOclPlatformInfoRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfOclPlatformInfoClear

Func _VectorOfOclPlatformInfoRelease($v)
    ; CVAPI(void) VectorOfOclPlatformInfoRelease(std::vector< cv::ocl::PlatformInfo >** v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfOclPlatformInfoCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfOclPlatformInfoPush($vecV, $v[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfOclPlatformInfoRelease", $bVDllType, $vecV), "VectorOfOclPlatformInfoRelease", @error)

    If $bVIsArray Then
        _VectorOfOclPlatformInfoRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfOclPlatformInfoRelease

Func _VectorOfOclPlatformInfoCopyData($v, $data)
    ; CVAPI(void) VectorOfOclPlatformInfoCopyData(std::vector< cv::ocl::PlatformInfo >* v, cv::ocl::PlatformInfo* data);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfOclPlatformInfoCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfOclPlatformInfoPush($vecV, $v[$i])
        Next
    Else
        $vecV = $v
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfOclPlatformInfoCopyData", "ptr", $vecV, "ptr", $data), "VectorOfOclPlatformInfoCopyData", @error)

    If $bVIsArray Then
        _VectorOfOclPlatformInfoRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfOclPlatformInfoCopyData

Func _VectorOfOclPlatformInfoGetItemPtr($vec, $index, $element)
    ; CVAPI(void) VectorOfOclPlatformInfoGetItemPtr(std::vector<  cv::ocl::PlatformInfo >* vec, int index, cv::ocl::PlatformInfo** element);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfOclPlatformInfoCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfOclPlatformInfoPush($vecVec, $vec[$i])
        Next
    Else
        $vecVec = $vec
    EndIf

    Local $bElementDllType
    If VarGetType($element) == "DLLStruct" Then
        $bElementDllType = "struct*"
    Else
        $bElementDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfOclPlatformInfoGetItemPtr", "ptr", $vecVec, "int", $index, $bElementDllType, $element), "VectorOfOclPlatformInfoGetItemPtr", @error)

    If $bVecIsArray Then
        _VectorOfOclPlatformInfoRelease($vecVec)
    EndIf
EndFunc   ;==>_VectorOfOclPlatformInfoGetItemPtr

Func _cveInputArrayFromVectorOfOclPlatformInfo($vec)
    ; CVAPI(cv::_InputArray*) cveInputArrayFromVectorOfOclPlatformInfo(std::vector< cv::ocl::PlatformInfo >* vec);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfOclPlatformInfoCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfOclPlatformInfoPush($vecVec, $vec[$i])
        Next
    Else
        $vecVec = $vec
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveInputArrayFromVectorOfOclPlatformInfo", "ptr", $vecVec), "cveInputArrayFromVectorOfOclPlatformInfo", @error)

    If $bVecIsArray Then
        _VectorOfOclPlatformInfoRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveInputArrayFromVectorOfOclPlatformInfo

Func _cveOutputArrayFromVectorOfOclPlatformInfo($vec)
    ; CVAPI(cv::_OutputArray*) cveOutputArrayFromVectorOfOclPlatformInfo(std::vector< cv::ocl::PlatformInfo >* vec);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfOclPlatformInfoCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfOclPlatformInfoPush($vecVec, $vec[$i])
        Next
    Else
        $vecVec = $vec
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveOutputArrayFromVectorOfOclPlatformInfo", "ptr", $vecVec), "cveOutputArrayFromVectorOfOclPlatformInfo", @error)

    If $bVecIsArray Then
        _VectorOfOclPlatformInfoRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveOutputArrayFromVectorOfOclPlatformInfo

Func _cveInputOutputArrayFromVectorOfOclPlatformInfo($vec)
    ; CVAPI(cv::_InputOutputArray*) cveInputOutputArrayFromVectorOfOclPlatformInfo(std::vector< cv::ocl::PlatformInfo >* vec);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfOclPlatformInfoCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfOclPlatformInfoPush($vecVec, $vec[$i])
        Next
    Else
        $vecVec = $vec
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveInputOutputArrayFromVectorOfOclPlatformInfo", "ptr", $vecVec), "cveInputOutputArrayFromVectorOfOclPlatformInfo", @error)

    If $bVecIsArray Then
        _VectorOfOclPlatformInfoRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveInputOutputArrayFromVectorOfOclPlatformInfo

Func _VectorOfOclPlatformInfoSizeOfItemInBytes()
    ; CVAPI(int) VectorOfOclPlatformInfoSizeOfItemInBytes();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "VectorOfOclPlatformInfoSizeOfItemInBytes"), "VectorOfOclPlatformInfoSizeOfItemInBytes", @error)
EndFunc   ;==>_VectorOfOclPlatformInfoSizeOfItemInBytes