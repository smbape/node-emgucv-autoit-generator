#include-once
#include <..\..\CVEUtils.au3>

Func _cveFrameMetadataGetCameraName(ByRef $obj, $val)
    ; CVAPI(void) cveFrameMetadataGetCameraName(FrameMetadata* obj, cv::String* val);

    Local $bValIsString = VarGetType($val) == "String"
    If $bValIsString Then
        $val = _cveStringCreateFromStr($val)
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFrameMetadataGetCameraName", "struct*", $obj, "ptr", $val), "cveFrameMetadataGetCameraName", @error)

    If $bValIsString Then
        _cveStringRelease($val)
    EndIf
EndFunc   ;==>_cveFrameMetadataGetCameraName

Func _cveFrameMetadataGetSequenceNum(ByRef $obj)
    ; CVAPI(int) cveFrameMetadataGetSequenceNum(FrameMetadata* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveFrameMetadataGetSequenceNum", "struct*", $obj), "cveFrameMetadataGetSequenceNum", @error)
EndFunc   ;==>_cveFrameMetadataGetSequenceNum

Func _cveFrameMetadataGetInstanceNum(ByRef $obj)
    ; CVAPI(int) cveFrameMetadataGetInstanceNum(FrameMetadata* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveFrameMetadataGetInstanceNum", "struct*", $obj), "cveFrameMetadataGetInstanceNum", @error)
EndFunc   ;==>_cveFrameMetadataGetInstanceNum

Func _cveFrameMetadataGetCategory(ByRef $obj)
    ; CVAPI(int) cveFrameMetadataGetCategory(FrameMetadata* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveFrameMetadataGetCategory", "struct*", $obj), "cveFrameMetadataGetCategory", @error)
EndFunc   ;==>_cveFrameMetadataGetCategory

Func _cveFrameMetadataGetStride(ByRef $obj)
    ; CVAPI(unsigned) cveFrameMetadataGetStride(FrameMetadata* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "unsigned:cdecl", "cveFrameMetadataGetStride", "struct*", $obj), "cveFrameMetadataGetStride", @error)
EndFunc   ;==>_cveFrameMetadataGetStride

Func _cveFrameMetadataGetFrameBytesPP(ByRef $obj)
    ; CVAPI(unsigned) cveFrameMetadataGetFrameBytesPP(FrameMetadata* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "unsigned:cdecl", "cveFrameMetadataGetFrameBytesPP", "struct*", $obj), "cveFrameMetadataGetFrameBytesPP", @error)
EndFunc   ;==>_cveFrameMetadataGetFrameBytesPP

Func _cveFrameMetadataGetFrameHeight(ByRef $obj)
    ; CVAPI(unsigned) cveFrameMetadataGetFrameHeight(FrameMetadata* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "unsigned:cdecl", "cveFrameMetadataGetFrameHeight", "struct*", $obj), "cveFrameMetadataGetFrameHeight", @error)
EndFunc   ;==>_cveFrameMetadataGetFrameHeight

Func _cveFrameMetadataGetFrameWidth(ByRef $obj)
    ; CVAPI(unsigned) cveFrameMetadataGetFrameWidth(FrameMetadata* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "unsigned:cdecl", "cveFrameMetadataGetFrameWidth", "struct*", $obj), "cveFrameMetadataGetFrameWidth", @error)
EndFunc   ;==>_cveFrameMetadataGetFrameWidth

Func _cveFrameMetadataGetFrameType(ByRef $obj)
    ; CVAPI(int) cveFrameMetadataGetFrameType(FrameMetadata* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveFrameMetadataGetFrameType", "struct*", $obj), "cveFrameMetadataGetFrameType", @error)
EndFunc   ;==>_cveFrameMetadataGetFrameType

Func _cveFrameMetadataGetTimestamp(ByRef $obj)
    ; CVAPI(double) cveFrameMetadataGetTimestamp(FrameMetadata* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveFrameMetadataGetTimestamp", "struct*", $obj), "cveFrameMetadataGetTimestamp", @error)
EndFunc   ;==>_cveFrameMetadataGetTimestamp

Func _cveFrameMetadataIsValid(ByRef $obj)
    ; CVAPI(bool) cveFrameMetadataIsValid(FrameMetadata* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveFrameMetadataIsValid", "struct*", $obj), "cveFrameMetadataIsValid", @error)
EndFunc   ;==>_cveFrameMetadataIsValid