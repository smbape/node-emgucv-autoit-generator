#include-once
#include "..\..\CVEUtils.au3"

Func _cveSimpleWBGetInputMin($obj)
    ; CVAPI(float) cveSimpleWBGetInputMin(cv::xphoto::SimpleWB* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cveSimpleWBGetInputMin", $bObjDllType, $obj), "cveSimpleWBGetInputMin", @error)
EndFunc   ;==>_cveSimpleWBGetInputMin

Func _cveSimpleWBSetInputMin($obj, $value)
    ; CVAPI(void) cveSimpleWBSetInputMin(cv::xphoto::SimpleWB* obj, float value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSimpleWBSetInputMin", $bObjDllType, $obj, "float", $value), "cveSimpleWBSetInputMin", @error)
EndFunc   ;==>_cveSimpleWBSetInputMin

Func _cveSimpleWBGetInputMax($obj)
    ; CVAPI(float) cveSimpleWBGetInputMax(cv::xphoto::SimpleWB* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cveSimpleWBGetInputMax", $bObjDllType, $obj), "cveSimpleWBGetInputMax", @error)
EndFunc   ;==>_cveSimpleWBGetInputMax

Func _cveSimpleWBSetInputMax($obj, $value)
    ; CVAPI(void) cveSimpleWBSetInputMax(cv::xphoto::SimpleWB* obj, float value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSimpleWBSetInputMax", $bObjDllType, $obj, "float", $value), "cveSimpleWBSetInputMax", @error)
EndFunc   ;==>_cveSimpleWBSetInputMax

Func _cveSimpleWBGetOutputMin($obj)
    ; CVAPI(float) cveSimpleWBGetOutputMin(cv::xphoto::SimpleWB* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cveSimpleWBGetOutputMin", $bObjDllType, $obj), "cveSimpleWBGetOutputMin", @error)
EndFunc   ;==>_cveSimpleWBGetOutputMin

Func _cveSimpleWBSetOutputMin($obj, $value)
    ; CVAPI(void) cveSimpleWBSetOutputMin(cv::xphoto::SimpleWB* obj, float value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSimpleWBSetOutputMin", $bObjDllType, $obj, "float", $value), "cveSimpleWBSetOutputMin", @error)
EndFunc   ;==>_cveSimpleWBSetOutputMin

Func _cveSimpleWBGetOutputMax($obj)
    ; CVAPI(float) cveSimpleWBGetOutputMax(cv::xphoto::SimpleWB* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cveSimpleWBGetOutputMax", $bObjDllType, $obj), "cveSimpleWBGetOutputMax", @error)
EndFunc   ;==>_cveSimpleWBGetOutputMax

Func _cveSimpleWBSetOutputMax($obj, $value)
    ; CVAPI(void) cveSimpleWBSetOutputMax(cv::xphoto::SimpleWB* obj, float value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSimpleWBSetOutputMax", $bObjDllType, $obj, "float", $value), "cveSimpleWBSetOutputMax", @error)
EndFunc   ;==>_cveSimpleWBSetOutputMax

Func _cveSimpleWBGetP($obj)
    ; CVAPI(float) cveSimpleWBGetP(cv::xphoto::SimpleWB* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cveSimpleWBGetP", $bObjDllType, $obj), "cveSimpleWBGetP", @error)
EndFunc   ;==>_cveSimpleWBGetP

Func _cveSimpleWBSetP($obj, $value)
    ; CVAPI(void) cveSimpleWBSetP(cv::xphoto::SimpleWB* obj, float value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSimpleWBSetP", $bObjDllType, $obj, "float", $value), "cveSimpleWBSetP", @error)
EndFunc   ;==>_cveSimpleWBSetP