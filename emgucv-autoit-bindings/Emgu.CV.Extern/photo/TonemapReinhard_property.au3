#include-once
#include "..\..\CVEUtils.au3"

Func _cveTonemapReinhardGetIntensity($obj)
    ; CVAPI(float) cveTonemapReinhardGetIntensity(cv::TonemapReinhard* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cveTonemapReinhardGetIntensity", $sObjDllType, $obj), "cveTonemapReinhardGetIntensity", @error)
EndFunc   ;==>_cveTonemapReinhardGetIntensity

Func _cveTonemapReinhardSetIntensity($obj, $value)
    ; CVAPI(void) cveTonemapReinhardSetIntensity(cv::TonemapReinhard* obj, float value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveTonemapReinhardSetIntensity", $sObjDllType, $obj, "float", $value), "cveTonemapReinhardSetIntensity", @error)
EndFunc   ;==>_cveTonemapReinhardSetIntensity

Func _cveTonemapReinhardGetLightAdaptation($obj)
    ; CVAPI(float) cveTonemapReinhardGetLightAdaptation(cv::TonemapReinhard* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cveTonemapReinhardGetLightAdaptation", $sObjDllType, $obj), "cveTonemapReinhardGetLightAdaptation", @error)
EndFunc   ;==>_cveTonemapReinhardGetLightAdaptation

Func _cveTonemapReinhardSetLightAdaptation($obj, $value)
    ; CVAPI(void) cveTonemapReinhardSetLightAdaptation(cv::TonemapReinhard* obj, float value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveTonemapReinhardSetLightAdaptation", $sObjDllType, $obj, "float", $value), "cveTonemapReinhardSetLightAdaptation", @error)
EndFunc   ;==>_cveTonemapReinhardSetLightAdaptation

Func _cveTonemapReinhardGetColorAdaptation($obj)
    ; CVAPI(float) cveTonemapReinhardGetColorAdaptation(cv::TonemapReinhard* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cveTonemapReinhardGetColorAdaptation", $sObjDllType, $obj), "cveTonemapReinhardGetColorAdaptation", @error)
EndFunc   ;==>_cveTonemapReinhardGetColorAdaptation

Func _cveTonemapReinhardSetColorAdaptation($obj, $value)
    ; CVAPI(void) cveTonemapReinhardSetColorAdaptation(cv::TonemapReinhard* obj, float value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveTonemapReinhardSetColorAdaptation", $sObjDllType, $obj, "float", $value), "cveTonemapReinhardSetColorAdaptation", @error)
EndFunc   ;==>_cveTonemapReinhardSetColorAdaptation