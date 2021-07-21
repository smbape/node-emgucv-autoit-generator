#include-once
#include "..\..\CVEUtils.au3"

Func _cveFrameMetadataGetCameraName($obj, $val)
    ; CVAPI(void) cveFrameMetadataGetCameraName(FrameMetadata* obj, cv::String* val);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    Local $bValIsString = VarGetType($val) == "String"
    If $bValIsString Then
        $val = _cveStringCreateFromStr($val)
    EndIf

    Local $bValDllType
    If VarGetType($val) == "DLLStruct" Then
        $bValDllType = "struct*"
    Else
        $bValDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFrameMetadataGetCameraName", $bObjDllType, $obj, $bValDllType, $val), "cveFrameMetadataGetCameraName", @error)

    If $bValIsString Then
        _cveStringRelease($val)
    EndIf
EndFunc   ;==>_cveFrameMetadataGetCameraName

Func _cveFrameMetadataGetSequenceNum($obj)
    ; CVAPI(int) cveFrameMetadataGetSequenceNum(FrameMetadata* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveFrameMetadataGetSequenceNum", $bObjDllType, $obj), "cveFrameMetadataGetSequenceNum", @error)
EndFunc   ;==>_cveFrameMetadataGetSequenceNum

Func _cveFrameMetadataGetInstanceNum($obj)
    ; CVAPI(int) cveFrameMetadataGetInstanceNum(FrameMetadata* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveFrameMetadataGetInstanceNum", $bObjDllType, $obj), "cveFrameMetadataGetInstanceNum", @error)
EndFunc   ;==>_cveFrameMetadataGetInstanceNum

Func _cveFrameMetadataGetCategory($obj)
    ; CVAPI(int) cveFrameMetadataGetCategory(FrameMetadata* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveFrameMetadataGetCategory", $bObjDllType, $obj), "cveFrameMetadataGetCategory", @error)
EndFunc   ;==>_cveFrameMetadataGetCategory

Func _cveFrameMetadataGetStride($obj)
    ; CVAPI(unsigned) cveFrameMetadataGetStride(FrameMetadata* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "unsigned:cdecl", "cveFrameMetadataGetStride", $bObjDllType, $obj), "cveFrameMetadataGetStride", @error)
EndFunc   ;==>_cveFrameMetadataGetStride

Func _cveFrameMetadataGetFrameBytesPP($obj)
    ; CVAPI(unsigned) cveFrameMetadataGetFrameBytesPP(FrameMetadata* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "unsigned:cdecl", "cveFrameMetadataGetFrameBytesPP", $bObjDllType, $obj), "cveFrameMetadataGetFrameBytesPP", @error)
EndFunc   ;==>_cveFrameMetadataGetFrameBytesPP

Func _cveFrameMetadataGetFrameHeight($obj)
    ; CVAPI(unsigned) cveFrameMetadataGetFrameHeight(FrameMetadata* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "unsigned:cdecl", "cveFrameMetadataGetFrameHeight", $bObjDllType, $obj), "cveFrameMetadataGetFrameHeight", @error)
EndFunc   ;==>_cveFrameMetadataGetFrameHeight

Func _cveFrameMetadataGetFrameWidth($obj)
    ; CVAPI(unsigned) cveFrameMetadataGetFrameWidth(FrameMetadata* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "unsigned:cdecl", "cveFrameMetadataGetFrameWidth", $bObjDllType, $obj), "cveFrameMetadataGetFrameWidth", @error)
EndFunc   ;==>_cveFrameMetadataGetFrameWidth

Func _cveFrameMetadataGetFrameType($obj)
    ; CVAPI(int) cveFrameMetadataGetFrameType(FrameMetadata* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveFrameMetadataGetFrameType", $bObjDllType, $obj), "cveFrameMetadataGetFrameType", @error)
EndFunc   ;==>_cveFrameMetadataGetFrameType

Func _cveFrameMetadataGetTimestamp($obj)
    ; CVAPI(double) cveFrameMetadataGetTimestamp(FrameMetadata* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveFrameMetadataGetTimestamp", $bObjDllType, $obj), "cveFrameMetadataGetTimestamp", @error)
EndFunc   ;==>_cveFrameMetadataGetTimestamp

Func _cveFrameMetadataIsValid($obj)
    ; CVAPI(bool) cveFrameMetadataIsValid(FrameMetadata* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveFrameMetadataIsValid", $bObjDllType, $obj), "cveFrameMetadataIsValid", @error)
EndFunc   ;==>_cveFrameMetadataIsValid