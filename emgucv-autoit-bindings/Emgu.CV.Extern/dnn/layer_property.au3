#include-once
#include "..\..\CVEUtils.au3"

Func _cveLayerGetName($obj, $str)
    ; CVAPI(void) cveLayerGetName(cv::dnn::Layer* obj, cv::String* str);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    Local $bStrIsString = IsString($str)
    If $bStrIsString Then
        $str = _cveStringCreateFromStr($str)
    EndIf

    Local $sStrDllType
    If IsDllStruct($str) Then
        $sStrDllType = "struct*"
    Else
        $sStrDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveLayerGetName", $sObjDllType, $obj, $sStrDllType, $str), "cveLayerGetName", @error)

    If $bStrIsString Then
        _cveStringRelease($str)
    EndIf
EndFunc   ;==>_cveLayerGetName

Func _cveLayerGetType($obj, $str)
    ; CVAPI(void) cveLayerGetType(cv::dnn::Layer* obj, cv::String* str);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    Local $bStrIsString = IsString($str)
    If $bStrIsString Then
        $str = _cveStringCreateFromStr($str)
    EndIf

    Local $sStrDllType
    If IsDllStruct($str) Then
        $sStrDllType = "struct*"
    Else
        $sStrDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveLayerGetType", $sObjDllType, $obj, $sStrDllType, $str), "cveLayerGetType", @error)

    If $bStrIsString Then
        _cveStringRelease($str)
    EndIf
EndFunc   ;==>_cveLayerGetType

Func _cveLayerGetPreferableTarget($obj)
    ; CVAPI(int) cveLayerGetPreferableTarget(cv::dnn::Layer* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveLayerGetPreferableTarget", $sObjDllType, $obj), "cveLayerGetPreferableTarget", @error)
EndFunc   ;==>_cveLayerGetPreferableTarget