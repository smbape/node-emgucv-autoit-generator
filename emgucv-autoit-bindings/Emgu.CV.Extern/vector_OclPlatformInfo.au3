#include-once
#include "..\CVEUtils.au3"

Func _VectorOfOclPlatformInfoCreate()
    ; CVAPI(std::vector<cv::ocl::PlatformInfo>*) VectorOfOclPlatformInfoCreate();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfOclPlatformInfoCreate"), "VectorOfOclPlatformInfoCreate", @error)
EndFunc   ;==>_VectorOfOclPlatformInfoCreate

Func _VectorOfOclPlatformInfoCreateSize($size)
    ; CVAPI(std::vector<cv::ocl::PlatformInfo>*) VectorOfOclPlatformInfoCreateSize(int size);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfOclPlatformInfoCreateSize", "int", $size), "VectorOfOclPlatformInfoCreateSize", @error)
EndFunc   ;==>_VectorOfOclPlatformInfoCreateSize

Func _VectorOfOclPlatformInfoGetSize($v)
    ; CVAPI(int) VectorOfOclPlatformInfoGetSize(std::vector<cv::ocl::PlatformInfo>* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = IsArray($v)

    If $bVIsArray Then
        $vecV = _VectorOfOclPlatformInfoCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfOclPlatformInfoPush($vecV, $v[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "VectorOfOclPlatformInfoGetSize", $sVDllType, $vecV), "VectorOfOclPlatformInfoGetSize", @error)

    If $bVIsArray Then
        _VectorOfOclPlatformInfoRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfOclPlatformInfoGetSize

Func _VectorOfOclPlatformInfoPush($v, $value)
    ; CVAPI(void) VectorOfOclPlatformInfoPush(std::vector<cv::ocl::PlatformInfo>* v, cv::ocl::PlatformInfo* value);

    Local $vecV, $iArrVSize
    Local $bVIsArray = IsArray($v)

    If $bVIsArray Then
        $vecV = _VectorOfOclPlatformInfoCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfOclPlatformInfoPush($vecV, $v[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfOclPlatformInfoPush", $sVDllType, $vecV, $sValueDllType, $value), "VectorOfOclPlatformInfoPush", @error)

    If $bVIsArray Then
        _VectorOfOclPlatformInfoRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfOclPlatformInfoPush

Func _VectorOfOclPlatformInfoPushVector($v, $other)
    ; CVAPI(void) VectorOfOclPlatformInfoPushVector(std::vector<cv::ocl::PlatformInfo>* v, std::vector<cv::ocl::PlatformInfo>* other);

    Local $vecV, $iArrVSize
    Local $bVIsArray = IsArray($v)

    If $bVIsArray Then
        $vecV = _VectorOfOclPlatformInfoCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfOclPlatformInfoPush($vecV, $v[$i])
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
        $vecOther = _VectorOfOclPlatformInfoCreate()

        $iArrOtherSize = UBound($other)
        For $i = 0 To $iArrOtherSize - 1
            _VectorOfOclPlatformInfoPush($vecOther, $other[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfOclPlatformInfoPushVector", $sVDllType, $vecV, $sOtherDllType, $vecOther), "VectorOfOclPlatformInfoPushVector", @error)

    If $bOtherIsArray Then
        _VectorOfOclPlatformInfoRelease($vecOther)
    EndIf

    If $bVIsArray Then
        _VectorOfOclPlatformInfoRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfOclPlatformInfoPushVector

Func _VectorOfOclPlatformInfoGetStartAddress($v)
    ; CVAPI(cv::ocl::PlatformInfo*) VectorOfOclPlatformInfoGetStartAddress(std::vector<cv::ocl::PlatformInfo>* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = IsArray($v)

    If $bVIsArray Then
        $vecV = _VectorOfOclPlatformInfoCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfOclPlatformInfoPush($vecV, $v[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfOclPlatformInfoGetStartAddress", $sVDllType, $vecV), "VectorOfOclPlatformInfoGetStartAddress", @error)

    If $bVIsArray Then
        _VectorOfOclPlatformInfoRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfOclPlatformInfoGetStartAddress

Func _VectorOfOclPlatformInfoGetEndAddress($v)
    ; CVAPI(void*) VectorOfOclPlatformInfoGetEndAddress(std::vector<cv::ocl::PlatformInfo>* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = IsArray($v)

    If $bVIsArray Then
        $vecV = _VectorOfOclPlatformInfoCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfOclPlatformInfoPush($vecV, $v[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "VectorOfOclPlatformInfoGetEndAddress", $sVDllType, $vecV), "VectorOfOclPlatformInfoGetEndAddress", @error)

    If $bVIsArray Then
        _VectorOfOclPlatformInfoRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfOclPlatformInfoGetEndAddress

Func _VectorOfOclPlatformInfoClear($v)
    ; CVAPI(void) VectorOfOclPlatformInfoClear(std::vector<cv::ocl::PlatformInfo>* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = IsArray($v)

    If $bVIsArray Then
        $vecV = _VectorOfOclPlatformInfoCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfOclPlatformInfoPush($vecV, $v[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfOclPlatformInfoClear", $sVDllType, $vecV), "VectorOfOclPlatformInfoClear", @error)

    If $bVIsArray Then
        _VectorOfOclPlatformInfoRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfOclPlatformInfoClear

Func _VectorOfOclPlatformInfoRelease($v)
    ; CVAPI(void) VectorOfOclPlatformInfoRelease(std::vector<cv::ocl::PlatformInfo>** v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = IsArray($v)

    If $bVIsArray Then
        $vecV = _VectorOfOclPlatformInfoCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfOclPlatformInfoPush($vecV, $v[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfOclPlatformInfoRelease", $sVDllType, $vecV), "VectorOfOclPlatformInfoRelease", @error)

    If $bVIsArray Then
        _VectorOfOclPlatformInfoRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfOclPlatformInfoRelease

Func _VectorOfOclPlatformInfoCopyData($v, $data)
    ; CVAPI(void) VectorOfOclPlatformInfoCopyData(std::vector<cv::ocl::PlatformInfo>* v, cv::ocl::PlatformInfo* data);

    Local $vecV, $iArrVSize
    Local $bVIsArray = IsArray($v)

    If $bVIsArray Then
        $vecV = _VectorOfOclPlatformInfoCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfOclPlatformInfoPush($vecV, $v[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfOclPlatformInfoCopyData", $sVDllType, $vecV, $sDataDllType, $data), "VectorOfOclPlatformInfoCopyData", @error)

    If $bVIsArray Then
        _VectorOfOclPlatformInfoRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfOclPlatformInfoCopyData

Func _VectorOfOclPlatformInfoGetItemPtr($vec, $index, $element)
    ; CVAPI(void) VectorOfOclPlatformInfoGetItemPtr(std::vector<cv::ocl::PlatformInfo>* vec, int index, cv::ocl::PlatformInfo** element);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = IsArray($vec)

    If $bVecIsArray Then
        $vecVec = _VectorOfOclPlatformInfoCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfOclPlatformInfoPush($vecVec, $vec[$i])
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfOclPlatformInfoGetItemPtr", $sVecDllType, $vecVec, "int", $index, $sElementDllType, $element), "VectorOfOclPlatformInfoGetItemPtr", @error)

    If $bVecIsArray Then
        _VectorOfOclPlatformInfoRelease($vecVec)
    EndIf
EndFunc   ;==>_VectorOfOclPlatformInfoGetItemPtr

Func _cveInputArrayFromVectorOfOclPlatformInfo($vec)
    ; CVAPI(cv::_InputArray*) cveInputArrayFromVectorOfOclPlatformInfo(std::vector<cv::ocl::PlatformInfo>* vec);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = IsArray($vec)

    If $bVecIsArray Then
        $vecVec = _VectorOfOclPlatformInfoCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfOclPlatformInfoPush($vecVec, $vec[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveInputArrayFromVectorOfOclPlatformInfo", $sVecDllType, $vecVec), "cveInputArrayFromVectorOfOclPlatformInfo", @error)

    If $bVecIsArray Then
        _VectorOfOclPlatformInfoRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveInputArrayFromVectorOfOclPlatformInfo

Func _cveOutputArrayFromVectorOfOclPlatformInfo($vec)
    ; CVAPI(cv::_OutputArray*) cveOutputArrayFromVectorOfOclPlatformInfo(std::vector<cv::ocl::PlatformInfo>* vec);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = IsArray($vec)

    If $bVecIsArray Then
        $vecVec = _VectorOfOclPlatformInfoCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfOclPlatformInfoPush($vecVec, $vec[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveOutputArrayFromVectorOfOclPlatformInfo", $sVecDllType, $vecVec), "cveOutputArrayFromVectorOfOclPlatformInfo", @error)

    If $bVecIsArray Then
        _VectorOfOclPlatformInfoRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveOutputArrayFromVectorOfOclPlatformInfo

Func _cveInputOutputArrayFromVectorOfOclPlatformInfo($vec)
    ; CVAPI(cv::_InputOutputArray*) cveInputOutputArrayFromVectorOfOclPlatformInfo(std::vector<cv::ocl::PlatformInfo>* vec);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = IsArray($vec)

    If $bVecIsArray Then
        $vecVec = _VectorOfOclPlatformInfoCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfOclPlatformInfoPush($vecVec, $vec[$i])
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveInputOutputArrayFromVectorOfOclPlatformInfo", $sVecDllType, $vecVec), "cveInputOutputArrayFromVectorOfOclPlatformInfo", @error)

    If $bVecIsArray Then
        _VectorOfOclPlatformInfoRelease($vecVec)
    EndIf

    Return $retval
EndFunc   ;==>_cveInputOutputArrayFromVectorOfOclPlatformInfo

Func _VectorOfOclPlatformInfoSizeOfItemInBytes()
    ; CVAPI(int) VectorOfOclPlatformInfoSizeOfItemInBytes();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "VectorOfOclPlatformInfoSizeOfItemInBytes"), "VectorOfOclPlatformInfoSizeOfItemInBytes", @error)
EndFunc   ;==>_VectorOfOclPlatformInfoSizeOfItemInBytes