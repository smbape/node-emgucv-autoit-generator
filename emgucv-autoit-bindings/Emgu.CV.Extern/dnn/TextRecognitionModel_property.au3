#include-once
#include "..\..\CVEUtils.au3"

Func _cveTextRecognitionModelGetDecodeType($obj, $str)
    ; CVAPI(void) cveTextRecognitionModelGetDecodeType(cv::dnn::TextRecognitionModel* obj, cv::String* str);

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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveTextRecognitionModelGetDecodeType", $sObjDllType, $obj, $sStrDllType, $str), "cveTextRecognitionModelGetDecodeType", @error)

    If $bStrIsString Then
        _cveStringRelease($str)
    EndIf
EndFunc   ;==>_cveTextRecognitionModelGetDecodeType

Func _cveTextRecognitionModelSetDecodeType($obj, $str)
    ; CVAPI(void) cveTextRecognitionModelSetDecodeType(cv::dnn::TextRecognitionModel* obj, cv::String* str);

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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveTextRecognitionModelSetDecodeType", $sObjDllType, $obj, $sStrDllType, $str), "cveTextRecognitionModelSetDecodeType", @error)

    If $bStrIsString Then
        _cveStringRelease($str)
    EndIf
EndFunc   ;==>_cveTextRecognitionModelSetDecodeType