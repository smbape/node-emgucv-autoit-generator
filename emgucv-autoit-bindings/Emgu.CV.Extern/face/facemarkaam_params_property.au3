#include-once
#include "..\..\CVEUtils.au3"

Func _cveFacemarkAAMParamsGetModelFile($obj, $str)
    ; CVAPI(void) cveFacemarkAAMParamsGetModelFile(cv::face::FacemarkAAM::Params* obj, cv::String* str);

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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFacemarkAAMParamsGetModelFile", $sObjDllType, $obj, $sStrDllType, $str), "cveFacemarkAAMParamsGetModelFile", @error)

    If $bStrIsString Then
        _cveStringRelease($str)
    EndIf
EndFunc   ;==>_cveFacemarkAAMParamsGetModelFile

Func _cveFacemarkAAMParamsSetModelFile($obj, $str)
    ; CVAPI(void) cveFacemarkAAMParamsSetModelFile(cv::face::FacemarkAAM::Params* obj, cv::String* str);

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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFacemarkAAMParamsSetModelFile", $sObjDllType, $obj, $sStrDllType, $str), "cveFacemarkAAMParamsSetModelFile", @error)

    If $bStrIsString Then
        _cveStringRelease($str)
    EndIf
EndFunc   ;==>_cveFacemarkAAMParamsSetModelFile

Func _cveFacemarkAAMParamsGetM($obj)
    ; CVAPI(int) cveFacemarkAAMParamsGetM(cv::face::FacemarkAAM::Params* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveFacemarkAAMParamsGetM", $sObjDllType, $obj), "cveFacemarkAAMParamsGetM", @error)
EndFunc   ;==>_cveFacemarkAAMParamsGetM

Func _cveFacemarkAAMParamsSetM($obj, $value)
    ; CVAPI(void) cveFacemarkAAMParamsSetM(cv::face::FacemarkAAM::Params* obj, int value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFacemarkAAMParamsSetM", $sObjDllType, $obj, "int", $value), "cveFacemarkAAMParamsSetM", @error)
EndFunc   ;==>_cveFacemarkAAMParamsSetM

Func _cveFacemarkAAMParamsGetN($obj)
    ; CVAPI(int) cveFacemarkAAMParamsGetN(cv::face::FacemarkAAM::Params* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveFacemarkAAMParamsGetN", $sObjDllType, $obj), "cveFacemarkAAMParamsGetN", @error)
EndFunc   ;==>_cveFacemarkAAMParamsGetN

Func _cveFacemarkAAMParamsSetN($obj, $value)
    ; CVAPI(void) cveFacemarkAAMParamsSetN(cv::face::FacemarkAAM::Params* obj, int value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFacemarkAAMParamsSetN", $sObjDllType, $obj, "int", $value), "cveFacemarkAAMParamsSetN", @error)
EndFunc   ;==>_cveFacemarkAAMParamsSetN

Func _cveFacemarkAAMParamsGetNIter($obj)
    ; CVAPI(int) cveFacemarkAAMParamsGetNIter(cv::face::FacemarkAAM::Params* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveFacemarkAAMParamsGetNIter", $sObjDllType, $obj), "cveFacemarkAAMParamsGetNIter", @error)
EndFunc   ;==>_cveFacemarkAAMParamsGetNIter

Func _cveFacemarkAAMParamsSetNIter($obj, $value)
    ; CVAPI(void) cveFacemarkAAMParamsSetNIter(cv::face::FacemarkAAM::Params* obj, int value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFacemarkAAMParamsSetNIter", $sObjDllType, $obj, "int", $value), "cveFacemarkAAMParamsSetNIter", @error)
EndFunc   ;==>_cveFacemarkAAMParamsSetNIter

Func _cveFacemarkAAMParamsGetVerbose($obj)
    ; CVAPI(bool) cveFacemarkAAMParamsGetVerbose(cv::face::FacemarkAAM::Params* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveFacemarkAAMParamsGetVerbose", $sObjDllType, $obj), "cveFacemarkAAMParamsGetVerbose", @error)
EndFunc   ;==>_cveFacemarkAAMParamsGetVerbose

Func _cveFacemarkAAMParamsSetVerbose($obj, $value)
    ; CVAPI(void) cveFacemarkAAMParamsSetVerbose(cv::face::FacemarkAAM::Params* obj, bool value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFacemarkAAMParamsSetVerbose", $sObjDllType, $obj, "boolean", $value), "cveFacemarkAAMParamsSetVerbose", @error)
EndFunc   ;==>_cveFacemarkAAMParamsSetVerbose

Func _cveFacemarkAAMParamsGetSaveModel($obj)
    ; CVAPI(bool) cveFacemarkAAMParamsGetSaveModel(cv::face::FacemarkAAM::Params* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveFacemarkAAMParamsGetSaveModel", $sObjDllType, $obj), "cveFacemarkAAMParamsGetSaveModel", @error)
EndFunc   ;==>_cveFacemarkAAMParamsGetSaveModel

Func _cveFacemarkAAMParamsSetSaveModel($obj, $value)
    ; CVAPI(void) cveFacemarkAAMParamsSetSaveModel(cv::face::FacemarkAAM::Params* obj, bool value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFacemarkAAMParamsSetSaveModel", $sObjDllType, $obj, "boolean", $value), "cveFacemarkAAMParamsSetSaveModel", @error)
EndFunc   ;==>_cveFacemarkAAMParamsSetSaveModel

Func _cveFacemarkAAMParamsGetMaxM($obj)
    ; CVAPI(int) cveFacemarkAAMParamsGetMaxM(cv::face::FacemarkAAM::Params* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveFacemarkAAMParamsGetMaxM", $sObjDllType, $obj), "cveFacemarkAAMParamsGetMaxM", @error)
EndFunc   ;==>_cveFacemarkAAMParamsGetMaxM

Func _cveFacemarkAAMParamsSetMaxM($obj, $value)
    ; CVAPI(void) cveFacemarkAAMParamsSetMaxM(cv::face::FacemarkAAM::Params* obj, int value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFacemarkAAMParamsSetMaxM", $sObjDllType, $obj, "int", $value), "cveFacemarkAAMParamsSetMaxM", @error)
EndFunc   ;==>_cveFacemarkAAMParamsSetMaxM

Func _cveFacemarkAAMParamsGetMaxN($obj)
    ; CVAPI(int) cveFacemarkAAMParamsGetMaxN(cv::face::FacemarkAAM::Params* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveFacemarkAAMParamsGetMaxN", $sObjDllType, $obj), "cveFacemarkAAMParamsGetMaxN", @error)
EndFunc   ;==>_cveFacemarkAAMParamsGetMaxN

Func _cveFacemarkAAMParamsSetMaxN($obj, $value)
    ; CVAPI(void) cveFacemarkAAMParamsSetMaxN(cv::face::FacemarkAAM::Params* obj, int value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFacemarkAAMParamsSetMaxN", $sObjDllType, $obj, "int", $value), "cveFacemarkAAMParamsSetMaxN", @error)
EndFunc   ;==>_cveFacemarkAAMParamsSetMaxN