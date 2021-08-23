#include-once
#include "..\..\CVEUtils.au3"

Func _cveTonemapDurandGetSaturation($obj)
    ; CVAPI(float) cveTonemapDurandGetSaturation(cv::xphoto::TonemapDurand* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cveTonemapDurandGetSaturation", $sObjDllType, $obj), "cveTonemapDurandGetSaturation", @error)
EndFunc   ;==>_cveTonemapDurandGetSaturation

Func _cveTonemapDurandSetSaturation($obj, $value)
    ; CVAPI(void) cveTonemapDurandSetSaturation(cv::xphoto::TonemapDurand* obj, float value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveTonemapDurandSetSaturation", $sObjDllType, $obj, "float", $value), "cveTonemapDurandSetSaturation", @error)
EndFunc   ;==>_cveTonemapDurandSetSaturation

Func _cveTonemapDurandGetContrast($obj)
    ; CVAPI(float) cveTonemapDurandGetContrast(cv::xphoto::TonemapDurand* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cveTonemapDurandGetContrast", $sObjDllType, $obj), "cveTonemapDurandGetContrast", @error)
EndFunc   ;==>_cveTonemapDurandGetContrast

Func _cveTonemapDurandSetContrast($obj, $value)
    ; CVAPI(void) cveTonemapDurandSetContrast(cv::xphoto::TonemapDurand* obj, float value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveTonemapDurandSetContrast", $sObjDllType, $obj, "float", $value), "cveTonemapDurandSetContrast", @error)
EndFunc   ;==>_cveTonemapDurandSetContrast

Func _cveTonemapDurandGetSigmaSpace($obj)
    ; CVAPI(float) cveTonemapDurandGetSigmaSpace(cv::xphoto::TonemapDurand* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cveTonemapDurandGetSigmaSpace", $sObjDllType, $obj), "cveTonemapDurandGetSigmaSpace", @error)
EndFunc   ;==>_cveTonemapDurandGetSigmaSpace

Func _cveTonemapDurandSetSigmaSpace($obj, $value)
    ; CVAPI(void) cveTonemapDurandSetSigmaSpace(cv::xphoto::TonemapDurand* obj, float value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveTonemapDurandSetSigmaSpace", $sObjDllType, $obj, "float", $value), "cveTonemapDurandSetSigmaSpace", @error)
EndFunc   ;==>_cveTonemapDurandSetSigmaSpace

Func _cveTonemapDurandGetSigmaColor($obj)
    ; CVAPI(float) cveTonemapDurandGetSigmaColor(cv::xphoto::TonemapDurand* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cveTonemapDurandGetSigmaColor", $sObjDllType, $obj), "cveTonemapDurandGetSigmaColor", @error)
EndFunc   ;==>_cveTonemapDurandGetSigmaColor

Func _cveTonemapDurandSetSigmaColor($obj, $value)
    ; CVAPI(void) cveTonemapDurandSetSigmaColor(cv::xphoto::TonemapDurand* obj, float value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveTonemapDurandSetSigmaColor", $sObjDllType, $obj, "float", $value), "cveTonemapDurandSetSigmaColor", @error)
EndFunc   ;==>_cveTonemapDurandSetSigmaColor