#include-once
#include "..\..\CVEUtils.au3"

Func _cveTonemapDurandGetSaturation(ByRef $obj)
    ; CVAPI(float) cveTonemapDurandGetSaturation(cv::xphoto::TonemapDurand* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cveTonemapDurandGetSaturation", "ptr", $obj), "cveTonemapDurandGetSaturation", @error)
EndFunc   ;==>_cveTonemapDurandGetSaturation

Func _cveTonemapDurandSetSaturation(ByRef $obj, $value)
    ; CVAPI(void) cveTonemapDurandSetSaturation(cv::xphoto::TonemapDurand* obj, float value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveTonemapDurandSetSaturation", "ptr", $obj, "float", $value), "cveTonemapDurandSetSaturation", @error)
EndFunc   ;==>_cveTonemapDurandSetSaturation

Func _cveTonemapDurandGetContrast(ByRef $obj)
    ; CVAPI(float) cveTonemapDurandGetContrast(cv::xphoto::TonemapDurand* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cveTonemapDurandGetContrast", "ptr", $obj), "cveTonemapDurandGetContrast", @error)
EndFunc   ;==>_cveTonemapDurandGetContrast

Func _cveTonemapDurandSetContrast(ByRef $obj, $value)
    ; CVAPI(void) cveTonemapDurandSetContrast(cv::xphoto::TonemapDurand* obj, float value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveTonemapDurandSetContrast", "ptr", $obj, "float", $value), "cveTonemapDurandSetContrast", @error)
EndFunc   ;==>_cveTonemapDurandSetContrast

Func _cveTonemapDurandGetSigmaSpace(ByRef $obj)
    ; CVAPI(float) cveTonemapDurandGetSigmaSpace(cv::xphoto::TonemapDurand* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cveTonemapDurandGetSigmaSpace", "ptr", $obj), "cveTonemapDurandGetSigmaSpace", @error)
EndFunc   ;==>_cveTonemapDurandGetSigmaSpace

Func _cveTonemapDurandSetSigmaSpace(ByRef $obj, $value)
    ; CVAPI(void) cveTonemapDurandSetSigmaSpace(cv::xphoto::TonemapDurand* obj, float value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveTonemapDurandSetSigmaSpace", "ptr", $obj, "float", $value), "cveTonemapDurandSetSigmaSpace", @error)
EndFunc   ;==>_cveTonemapDurandSetSigmaSpace

Func _cveTonemapDurandGetSigmaColor(ByRef $obj)
    ; CVAPI(float) cveTonemapDurandGetSigmaColor(cv::xphoto::TonemapDurand* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cveTonemapDurandGetSigmaColor", "ptr", $obj), "cveTonemapDurandGetSigmaColor", @error)
EndFunc   ;==>_cveTonemapDurandGetSigmaColor

Func _cveTonemapDurandSetSigmaColor(ByRef $obj, $value)
    ; CVAPI(void) cveTonemapDurandSetSigmaColor(cv::xphoto::TonemapDurand* obj, float value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveTonemapDurandSetSigmaColor", "ptr", $obj, "float", $value), "cveTonemapDurandSetSigmaColor", @error)
EndFunc   ;==>_cveTonemapDurandSetSigmaColor