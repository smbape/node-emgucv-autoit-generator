#include-once
#include "..\..\CVEUtils.au3"

Func _cveFrameMetadataGetCameraName($obj, $val)
    ; CVAPI(void) cveFrameMetadataGetCameraName(FrameMetadata* obj, cv::String* val);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    Local $bValIsString = VarGetType($val) == "String"
    If $bValIsString Then
        $val = _cveStringCreateFromStr($val)
    EndIf

    Local $sValDllType
    If IsDllStruct($val) Then
        $sValDllType = "struct*"
    Else
        $sValDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFrameMetadataGetCameraName", $sObjDllType, $obj, $sValDllType, $val), "cveFrameMetadataGetCameraName", @error)

    If $bValIsString Then
        _cveStringRelease($val)
    EndIf
EndFunc   ;==>_cveFrameMetadataGetCameraName

Func _cveFrameMetadataGetSequenceNum($obj)
    ; CVAPI(int) cveFrameMetadataGetSequenceNum(FrameMetadata* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveFrameMetadataGetSequenceNum", $sObjDllType, $obj), "cveFrameMetadataGetSequenceNum", @error)
EndFunc   ;==>_cveFrameMetadataGetSequenceNum

Func _cveFrameMetadataGetInstanceNum($obj)
    ; CVAPI(int) cveFrameMetadataGetInstanceNum(FrameMetadata* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveFrameMetadataGetInstanceNum", $sObjDllType, $obj), "cveFrameMetadataGetInstanceNum", @error)
EndFunc   ;==>_cveFrameMetadataGetInstanceNum

Func _cveFrameMetadataGetCategory($obj)
    ; CVAPI(int) cveFrameMetadataGetCategory(FrameMetadata* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveFrameMetadataGetCategory", $sObjDllType, $obj), "cveFrameMetadataGetCategory", @error)
EndFunc   ;==>_cveFrameMetadataGetCategory

Func _cveFrameMetadataGetStride($obj)
    ; CVAPI(unsigned int) cveFrameMetadataGetStride(FrameMetadata* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "uint:cdecl", "cveFrameMetadataGetStride", $sObjDllType, $obj), "cveFrameMetadataGetStride", @error)
EndFunc   ;==>_cveFrameMetadataGetStride

Func _cveFrameMetadataGetFrameBytesPP($obj)
    ; CVAPI(unsigned int) cveFrameMetadataGetFrameBytesPP(FrameMetadata* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "uint:cdecl", "cveFrameMetadataGetFrameBytesPP", $sObjDllType, $obj), "cveFrameMetadataGetFrameBytesPP", @error)
EndFunc   ;==>_cveFrameMetadataGetFrameBytesPP

Func _cveFrameMetadataGetFrameHeight($obj)
    ; CVAPI(unsigned int) cveFrameMetadataGetFrameHeight(FrameMetadata* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "uint:cdecl", "cveFrameMetadataGetFrameHeight", $sObjDllType, $obj), "cveFrameMetadataGetFrameHeight", @error)
EndFunc   ;==>_cveFrameMetadataGetFrameHeight

Func _cveFrameMetadataGetFrameWidth($obj)
    ; CVAPI(unsigned int) cveFrameMetadataGetFrameWidth(FrameMetadata* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "uint:cdecl", "cveFrameMetadataGetFrameWidth", $sObjDllType, $obj), "cveFrameMetadataGetFrameWidth", @error)
EndFunc   ;==>_cveFrameMetadataGetFrameWidth

Func _cveFrameMetadataGetFrameType($obj)
    ; CVAPI(int) cveFrameMetadataGetFrameType(FrameMetadata* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveFrameMetadataGetFrameType", $sObjDllType, $obj), "cveFrameMetadataGetFrameType", @error)
EndFunc   ;==>_cveFrameMetadataGetFrameType

Func _cveFrameMetadataGetTimestamp($obj)
    ; CVAPI(double) cveFrameMetadataGetTimestamp(FrameMetadata* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveFrameMetadataGetTimestamp", $sObjDllType, $obj), "cveFrameMetadataGetTimestamp", @error)
EndFunc   ;==>_cveFrameMetadataGetTimestamp

Func _cveFrameMetadataIsValid($obj)
    ; CVAPI(bool) cveFrameMetadataIsValid(FrameMetadata* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveFrameMetadataIsValid", $sObjDllType, $obj), "cveFrameMetadataIsValid", @error)
EndFunc   ;==>_cveFrameMetadataIsValid