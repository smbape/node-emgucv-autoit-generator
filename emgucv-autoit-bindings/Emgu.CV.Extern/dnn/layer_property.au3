#include-once
#include "..\..\CVEUtils.au3"

Func _cveLayerGetName($obj, $str)
    ; CVAPI(void) cveLayerGetName(cv::dnn::Layer* obj, cv::String* str);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    Local $bStrIsString = VarGetType($str) == "String"
    If $bStrIsString Then
        $str = _cveStringCreateFromStr($str)
    EndIf

    Local $bStrDllType
    If VarGetType($str) == "DLLStruct" Then
        $bStrDllType = "struct*"
    Else
        $bStrDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveLayerGetName", $bObjDllType, $obj, $bStrDllType, $str), "cveLayerGetName", @error)

    If $bStrIsString Then
        _cveStringRelease($str)
    EndIf
EndFunc   ;==>_cveLayerGetName

Func _cveLayerGetType($obj, $str)
    ; CVAPI(void) cveLayerGetType(cv::dnn::Layer* obj, cv::String* str);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    Local $bStrIsString = VarGetType($str) == "String"
    If $bStrIsString Then
        $str = _cveStringCreateFromStr($str)
    EndIf

    Local $bStrDllType
    If VarGetType($str) == "DLLStruct" Then
        $bStrDllType = "struct*"
    Else
        $bStrDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveLayerGetType", $bObjDllType, $obj, $bStrDllType, $str), "cveLayerGetType", @error)

    If $bStrIsString Then
        _cveStringRelease($str)
    EndIf
EndFunc   ;==>_cveLayerGetType

Func _cveLayerGetPreferableTarget($obj)
    ; CVAPI(int) cveLayerGetPreferableTarget(cv::dnn::Layer* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveLayerGetPreferableTarget", $bObjDllType, $obj), "cveLayerGetPreferableTarget", @error)
EndFunc   ;==>_cveLayerGetPreferableTarget