#include-once
#include "..\..\CVEUtils.au3"

Func _cveTextRecognitionModelGetDecodeType($obj, $str)
    ; CVAPI(void) cveTextRecognitionModelGetDecodeType(cv::dnn::TextRecognitionModel* obj, cv::String* str);

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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveTextRecognitionModelGetDecodeType", $bObjDllType, $obj, $bStrDllType, $str), "cveTextRecognitionModelGetDecodeType", @error)

    If $bStrIsString Then
        _cveStringRelease($str)
    EndIf
EndFunc   ;==>_cveTextRecognitionModelGetDecodeType

Func _cveTextRecognitionModelSetDecodeType($obj, $str)
    ; CVAPI(void) cveTextRecognitionModelSetDecodeType(cv::dnn::TextRecognitionModel* obj, cv::String* str);

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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveTextRecognitionModelSetDecodeType", $bObjDllType, $obj, $bStrDllType, $str), "cveTextRecognitionModelSetDecodeType", @error)

    If $bStrIsString Then
        _cveStringRelease($str)
    EndIf
EndFunc   ;==>_cveTextRecognitionModelSetDecodeType