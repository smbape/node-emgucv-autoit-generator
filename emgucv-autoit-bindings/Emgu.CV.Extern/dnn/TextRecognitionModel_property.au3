#include-once
#include "..\..\CVEUtils.au3"

Func _cveTextRecognitionModelGetDecodeType(ByRef $obj, $str)
    ; CVAPI(void) cveTextRecognitionModelGetDecodeType(cv::dnn::TextRecognitionModel* obj, cv::String* str);

    Local $bStrIsString = VarGetType($str) == "String"
    If $bStrIsString Then
        $str = _cveStringCreateFromStr($str)
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveTextRecognitionModelGetDecodeType", "ptr", $obj, "ptr", $str), "cveTextRecognitionModelGetDecodeType", @error)

    If $bStrIsString Then
        _cveStringRelease($str)
    EndIf
EndFunc   ;==>_cveTextRecognitionModelGetDecodeType

Func _cveTextRecognitionModelSetDecodeType(ByRef $obj, $str)
    ; CVAPI(void) cveTextRecognitionModelSetDecodeType(cv::dnn::TextRecognitionModel* obj, cv::String* str);

    Local $bStrIsString = VarGetType($str) == "String"
    If $bStrIsString Then
        $str = _cveStringCreateFromStr($str)
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveTextRecognitionModelSetDecodeType", "ptr", $obj, "ptr", $str), "cveTextRecognitionModelSetDecodeType", @error)

    If $bStrIsString Then
        _cveStringRelease($str)
    EndIf
EndFunc   ;==>_cveTextRecognitionModelSetDecodeType