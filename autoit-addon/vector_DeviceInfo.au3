#include-once
#include "addon_utils.au3"

Func _VectorOfDeviceInfoCreate()
    ; AUTOIT_EXPORTS (std::vector< AUTOIT_MODULE_NAME::DeviceInfo >*) VectorOfDeviceInfoCreate();
    Return CVEDllCallResult(DllCall($addon_dll, "ptr:cdecl", "VectorOfDeviceInfoCreate"), "VectorOfDeviceInfoCreate", @error)
EndFunc   ;==>_VectorOfDeviceInfoCreate

Func _VectorOfDeviceInfoCreateSize($size)
    ; AUTOIT_EXPORTS (std::vector< AUTOIT_MODULE_NAME::DeviceInfo >*) VectorOfDeviceInfoCreateSize(int size);
    Return CVEDllCallResult(DllCall($addon_dll, "ptr:cdecl", "VectorOfDeviceInfoCreateSize", "int", $size), "VectorOfDeviceInfoCreateSize", @error)
EndFunc   ;==>_VectorOfDeviceInfoCreateSize

Func _VectorOfDeviceInfoGetSize($v)
    ; AUTOIT_EXPORTS (int) VectorOfDeviceInfoGetSize(std::vector< AUTOIT_MODULE_NAME::DeviceInfo >* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfDeviceInfoCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfDeviceInfoPush($vecV, $v[$i])
        Next
    Else
        $vecV = $v
    EndIf

    Local $bVDllType
    If VarGetType($v) == "DLLStruct" Then
        $bVDllType = "struct*"
    Else
        $bVDllType = "ptr"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($addon_dll, "int:cdecl", "VectorOfDeviceInfoGetSize", $bVDllType, $vecV), "VectorOfDeviceInfoGetSize", @error)

    If $bVIsArray Then
        _VectorOfDeviceInfoRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfDeviceInfoGetSize

Func _VectorOfDeviceInfoPush($v, $value)
    ; AUTOIT_EXPORTS (void) VectorOfDeviceInfoPush(std::vector< AUTOIT_MODULE_NAME::DeviceInfo >* v, AUTOIT_MODULE_NAME::DeviceInfo* value);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfDeviceInfoCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfDeviceInfoPush($vecV, $v[$i])
        Next
    Else
        $vecV = $v
    EndIf

    Local $bVDllType
    If VarGetType($v) == "DLLStruct" Then
        $bVDllType = "struct*"
    Else
        $bVDllType = "ptr"
    EndIf

    Local $bValueDllType
    If VarGetType($value) == "DLLStruct" Then
        $bValueDllType = "struct*"
    Else
        $bValueDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($addon_dll, "none:cdecl", "VectorOfDeviceInfoPush", $bVDllType, $vecV, $bValueDllType, $value), "VectorOfDeviceInfoPush", @error)

    If $bVIsArray Then
        _VectorOfDeviceInfoRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfDeviceInfoPush

Func _VectorOfDeviceInfoPushMulti($v, $values, $count)
    ; AUTOIT_EXPORTS (void) VectorOfDeviceInfoPushMulti(std::vector< AUTOIT_MODULE_NAME::DeviceInfo >* v, AUTOIT_MODULE_NAME::DeviceInfo* values, int count);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfDeviceInfoCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfDeviceInfoPush($vecV, $v[$i])
        Next
    Else
        $vecV = $v
    EndIf

    Local $bVDllType
    If VarGetType($v) == "DLLStruct" Then
        $bVDllType = "struct*"
    Else
        $bVDllType = "ptr"
    EndIf

    Local $bValuesDllType
    If VarGetType($values) == "DLLStruct" Then
        $bValuesDllType = "struct*"
    Else
        $bValuesDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($addon_dll, "none:cdecl", "VectorOfDeviceInfoPushMulti", $bVDllType, $vecV, $bValuesDllType, $values, "int", $count), "VectorOfDeviceInfoPushMulti", @error)

    If $bVIsArray Then
        _VectorOfDeviceInfoRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfDeviceInfoPushMulti

Func _VectorOfDeviceInfoPushVector($v, $other)
    ; AUTOIT_EXPORTS (void) VectorOfDeviceInfoPushVector(std::vector< AUTOIT_MODULE_NAME::DeviceInfo >* v, std::vector< AUTOIT_MODULE_NAME::DeviceInfo >* other);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfDeviceInfoCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfDeviceInfoPush($vecV, $v[$i])
        Next
    Else
        $vecV = $v
    EndIf

    Local $bVDllType
    If VarGetType($v) == "DLLStruct" Then
        $bVDllType = "struct*"
    Else
        $bVDllType = "ptr"
    EndIf

    Local $vecOther, $iArrOtherSize
    Local $bOtherIsArray = VarGetType($other) == "Array"

    If $bOtherIsArray Then
        $vecOther = _VectorOfDeviceInfoCreate()

        $iArrOtherSize = UBound($other)
        For $i = 0 To $iArrOtherSize - 1
            _VectorOfDeviceInfoPush($vecOther, $other[$i])
        Next
    Else
        $vecOther = $other
    EndIf

    Local $bOtherDllType
    If VarGetType($other) == "DLLStruct" Then
        $bOtherDllType = "struct*"
    Else
        $bOtherDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($addon_dll, "none:cdecl", "VectorOfDeviceInfoPushVector", $bVDllType, $vecV, $bOtherDllType, $vecOther), "VectorOfDeviceInfoPushVector", @error)

    If $bOtherIsArray Then
        _VectorOfDeviceInfoRelease($vecOther)
    EndIf

    If $bVIsArray Then
        _VectorOfDeviceInfoRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfDeviceInfoPushVector

Func _VectorOfDeviceInfoClear($v)
    ; AUTOIT_EXPORTS (void) VectorOfDeviceInfoClear(std::vector< AUTOIT_MODULE_NAME::DeviceInfo >* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfDeviceInfoCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfDeviceInfoPush($vecV, $v[$i])
        Next
    Else
        $vecV = $v
    EndIf

    Local $bVDllType
    If VarGetType($v) == "DLLStruct" Then
        $bVDllType = "struct*"
    Else
        $bVDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($addon_dll, "none:cdecl", "VectorOfDeviceInfoClear", $bVDllType, $vecV), "VectorOfDeviceInfoClear", @error)

    If $bVIsArray Then
        _VectorOfDeviceInfoRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfDeviceInfoClear

Func _VectorOfDeviceInfoRelease($v)
    ; AUTOIT_EXPORTS (void) VectorOfDeviceInfoRelease(std::vector< AUTOIT_MODULE_NAME::DeviceInfo >** v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfDeviceInfoCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfDeviceInfoPush($vecV, $v[$i])
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

    CVEDllCallResult(DllCall($addon_dll, "none:cdecl", "VectorOfDeviceInfoRelease", $bVDllType, $vecV), "VectorOfDeviceInfoRelease", @error)

    If $bVIsArray Then
        _VectorOfDeviceInfoRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfDeviceInfoRelease

Func _VectorOfDeviceInfoCopyData($v, $data)
    ; AUTOIT_EXPORTS (void) VectorOfDeviceInfoCopyData(std::vector< AUTOIT_MODULE_NAME::DeviceInfo >* v, AUTOIT_MODULE_NAME::DeviceInfo* data);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfDeviceInfoCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfDeviceInfoPush($vecV, $v[$i])
        Next
    Else
        $vecV = $v
    EndIf

    Local $bVDllType
    If VarGetType($v) == "DLLStruct" Then
        $bVDllType = "struct*"
    Else
        $bVDllType = "ptr"
    EndIf

    Local $bDataDllType
    If VarGetType($data) == "DLLStruct" Then
        $bDataDllType = "struct*"
    Else
        $bDataDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($addon_dll, "none:cdecl", "VectorOfDeviceInfoCopyData", $bVDllType, $vecV, $bDataDllType, $data), "VectorOfDeviceInfoCopyData", @error)

    If $bVIsArray Then
        _VectorOfDeviceInfoRelease($vecV)
    EndIf
EndFunc   ;==>_VectorOfDeviceInfoCopyData

Func _VectorOfDeviceInfoGetStartAddress($v)
    ; AUTOIT_EXPORTS (AUTOIT_MODULE_NAME::DeviceInfo*) VectorOfDeviceInfoGetStartAddress(std::vector< AUTOIT_MODULE_NAME::DeviceInfo >* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfDeviceInfoCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfDeviceInfoPush($vecV, $v[$i])
        Next
    Else
        $vecV = $v
    EndIf

    Local $bVDllType
    If VarGetType($v) == "DLLStruct" Then
        $bVDllType = "struct*"
    Else
        $bVDllType = "ptr"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($addon_dll, "ptr:cdecl", "VectorOfDeviceInfoGetStartAddress", $bVDllType, $vecV), "VectorOfDeviceInfoGetStartAddress", @error)

    If $bVIsArray Then
        _VectorOfDeviceInfoRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfDeviceInfoGetStartAddress

Func _VectorOfDeviceInfoGetEndAddress($v)
    ; AUTOIT_EXPORTS (void*) VectorOfDeviceInfoGetEndAddress(std::vector< AUTOIT_MODULE_NAME::DeviceInfo >* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfDeviceInfoCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfDeviceInfoPush($vecV, $v[$i])
        Next
    Else
        $vecV = $v
    EndIf

    Local $bVDllType
    If VarGetType($v) == "DLLStruct" Then
        $bVDllType = "struct*"
    Else
        $bVDllType = "ptr"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($addon_dll, "ptr:cdecl", "VectorOfDeviceInfoGetEndAddress", $bVDllType, $vecV), "VectorOfDeviceInfoGetEndAddress", @error)

    If $bVIsArray Then
        _VectorOfDeviceInfoRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_VectorOfDeviceInfoGetEndAddress

Func _VectorOfDeviceInfoGetItem($vec, $index, $element)
    ; AUTOIT_EXPORTS (void) VectorOfDeviceInfoGetItem(std::vector<  AUTOIT_MODULE_NAME::DeviceInfo >* vec, int index, AUTOIT_MODULE_NAME::DeviceInfo* element);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfDeviceInfoCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfDeviceInfoPush($vecVec, $vec[$i])
        Next
    Else
        $vecVec = $vec
    EndIf

    Local $bVecDllType
    If VarGetType($vec) == "DLLStruct" Then
        $bVecDllType = "struct*"
    Else
        $bVecDllType = "ptr"
    EndIf

    Local $bElementDllType
    If VarGetType($element) == "DLLStruct" Then
        $bElementDllType = "struct*"
    Else
        $bElementDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($addon_dll, "none:cdecl", "VectorOfDeviceInfoGetItem", $bVecDllType, $vecVec, "int", $index, $bElementDllType, $element), "VectorOfDeviceInfoGetItem", @error)

    If $bVecIsArray Then
        _VectorOfDeviceInfoRelease($vecVec)
    EndIf
EndFunc   ;==>_VectorOfDeviceInfoGetItem

Func _VectorOfDeviceInfoGetItemPtr($vec, $index, $element)
    ; AUTOIT_EXPORTS (void) VectorOfDeviceInfoGetItemPtr(std::vector<  AUTOIT_MODULE_NAME::DeviceInfo >* vec, int index, AUTOIT_MODULE_NAME::DeviceInfo** element);

    Local $vecVec, $iArrVecSize
    Local $bVecIsArray = VarGetType($vec) == "Array"

    If $bVecIsArray Then
        $vecVec = _VectorOfDeviceInfoCreate()

        $iArrVecSize = UBound($vec)
        For $i = 0 To $iArrVecSize - 1
            _VectorOfDeviceInfoPush($vecVec, $vec[$i])
        Next
    Else
        $vecVec = $vec
    EndIf

    Local $bVecDllType
    If VarGetType($vec) == "DLLStruct" Then
        $bVecDllType = "struct*"
    Else
        $bVecDllType = "ptr"
    EndIf

    Local $bElementDllType
    If VarGetType($element) == "DLLStruct" Then
        $bElementDllType = "struct*"
    Else
        $bElementDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($addon_dll, "none:cdecl", "VectorOfDeviceInfoGetItemPtr", $bVecDllType, $vecVec, "int", $index, $bElementDllType, $element), "VectorOfDeviceInfoGetItemPtr", @error)

    If $bVecIsArray Then
        _VectorOfDeviceInfoRelease($vecVec)
    EndIf
EndFunc   ;==>_VectorOfDeviceInfoGetItemPtr

Func _VectorOfDeviceInfoSizeOfItemInBytes()
    ; AUTOIT_EXPORTS (int) VectorOfDeviceInfoSizeOfItemInBytes();
    Return CVEDllCallResult(DllCall($addon_dll, "int:cdecl", "VectorOfDeviceInfoSizeOfItemInBytes"), "VectorOfDeviceInfoSizeOfItemInBytes", @error)
EndFunc   ;==>_VectorOfDeviceInfoSizeOfItemInBytes
