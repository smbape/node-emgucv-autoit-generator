#include-once
#include "..\..\CVEUtils.au3"

Func _cveObjectnessBINGGetW($obj)
    ; CVAPI(int) cveObjectnessBINGGetW(cv::saliency::ObjectnessBING* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveObjectnessBINGGetW", $bObjDllType, $obj), "cveObjectnessBINGGetW", @error)
EndFunc   ;==>_cveObjectnessBINGGetW

Func _cveObjectnessBINGSetW($obj, $value)
    ; CVAPI(void) cveObjectnessBINGSetW(cv::saliency::ObjectnessBING* obj, int value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveObjectnessBINGSetW", $bObjDllType, $obj, "int", $value), "cveObjectnessBINGSetW", @error)
EndFunc   ;==>_cveObjectnessBINGSetW

Func _cveObjectnessBINGGetNSS($obj)
    ; CVAPI(int) cveObjectnessBINGGetNSS(cv::saliency::ObjectnessBING* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveObjectnessBINGGetNSS", $bObjDllType, $obj), "cveObjectnessBINGGetNSS", @error)
EndFunc   ;==>_cveObjectnessBINGGetNSS

Func _cveObjectnessBINGSetNSS($obj, $value)
    ; CVAPI(void) cveObjectnessBINGSetNSS(cv::saliency::ObjectnessBING* obj, int value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveObjectnessBINGSetNSS", $bObjDllType, $obj, "int", $value), "cveObjectnessBINGSetNSS", @error)
EndFunc   ;==>_cveObjectnessBINGSetNSS