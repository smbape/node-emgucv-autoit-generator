#include-once
#include "..\..\CVEUtils.au3"

Func _cveObjectnessBINGGetW($obj)
    ; CVAPI(int) cveObjectnessBINGGetW(cv::saliency::ObjectnessBING* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveObjectnessBINGGetW", $sObjDllType, $obj), "cveObjectnessBINGGetW", @error)
EndFunc   ;==>_cveObjectnessBINGGetW

Func _cveObjectnessBINGSetW($obj, $value)
    ; CVAPI(void) cveObjectnessBINGSetW(cv::saliency::ObjectnessBING* obj, int value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveObjectnessBINGSetW", $sObjDllType, $obj, "int", $value), "cveObjectnessBINGSetW", @error)
EndFunc   ;==>_cveObjectnessBINGSetW

Func _cveObjectnessBINGGetNSS($obj)
    ; CVAPI(int) cveObjectnessBINGGetNSS(cv::saliency::ObjectnessBING* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveObjectnessBINGGetNSS", $sObjDllType, $obj), "cveObjectnessBINGGetNSS", @error)
EndFunc   ;==>_cveObjectnessBINGGetNSS

Func _cveObjectnessBINGSetNSS($obj, $value)
    ; CVAPI(void) cveObjectnessBINGSetNSS(cv::saliency::ObjectnessBING* obj, int value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveObjectnessBINGSetNSS", $sObjDllType, $obj, "int", $value), "cveObjectnessBINGSetNSS", @error)
EndFunc   ;==>_cveObjectnessBINGSetNSS