#include-once
#include <..\..\CVEUtils.au3>

Func _cveLayerGetName(ByRef $obj, $str)
    ; CVAPI(void) cveLayerGetName(cv::dnn::Layer* obj, cv::String* str);

    Local $bStrIsString = VarGetType($str) == "String"
    If $bStrIsString Then
        $str = _cveStringCreateFromStr($str)
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveLayerGetName", "ptr", $obj, "ptr", $str), "cveLayerGetName", @error)

    If $bStrIsString Then
        _cveStringRelease($str)
    EndIf
EndFunc   ;==>_cveLayerGetName

Func _cveLayerGetType(ByRef $obj, $str)
    ; CVAPI(void) cveLayerGetType(cv::dnn::Layer* obj, cv::String* str);

    Local $bStrIsString = VarGetType($str) == "String"
    If $bStrIsString Then
        $str = _cveStringCreateFromStr($str)
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveLayerGetType", "ptr", $obj, "ptr", $str), "cveLayerGetType", @error)

    If $bStrIsString Then
        _cveStringRelease($str)
    EndIf
EndFunc   ;==>_cveLayerGetType

Func _cveLayerGetPreferableTarget(ByRef $obj)
    ; CVAPI(int) cveLayerGetPreferableTarget(cv::dnn::Layer* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveLayerGetPreferableTarget", "ptr", $obj), "cveLayerGetPreferableTarget", @error)
EndFunc   ;==>_cveLayerGetPreferableTarget