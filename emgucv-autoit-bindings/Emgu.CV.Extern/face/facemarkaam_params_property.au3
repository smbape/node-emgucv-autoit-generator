#include-once
#include "..\..\CVEUtils.au3"

Func _cveFacemarkAAMParamsGetModelFile($obj, $str)
    ; CVAPI(void) cveFacemarkAAMParamsGetModelFile(cv::face::FacemarkAAM::Params* obj, cv::String* str);

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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFacemarkAAMParamsGetModelFile", $bObjDllType, $obj, $bStrDllType, $str), "cveFacemarkAAMParamsGetModelFile", @error)

    If $bStrIsString Then
        _cveStringRelease($str)
    EndIf
EndFunc   ;==>_cveFacemarkAAMParamsGetModelFile

Func _cveFacemarkAAMParamsSetModelFile($obj, $str)
    ; CVAPI(void) cveFacemarkAAMParamsSetModelFile(cv::face::FacemarkAAM::Params* obj, cv::String* str);

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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFacemarkAAMParamsSetModelFile", $bObjDllType, $obj, $bStrDllType, $str), "cveFacemarkAAMParamsSetModelFile", @error)

    If $bStrIsString Then
        _cveStringRelease($str)
    EndIf
EndFunc   ;==>_cveFacemarkAAMParamsSetModelFile

Func _cveFacemarkAAMParamsGetM($obj)
    ; CVAPI(int) cveFacemarkAAMParamsGetM(cv::face::FacemarkAAM::Params* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveFacemarkAAMParamsGetM", $bObjDllType, $obj), "cveFacemarkAAMParamsGetM", @error)
EndFunc   ;==>_cveFacemarkAAMParamsGetM

Func _cveFacemarkAAMParamsSetM($obj, $value)
    ; CVAPI(void) cveFacemarkAAMParamsSetM(cv::face::FacemarkAAM::Params* obj, int value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFacemarkAAMParamsSetM", $bObjDllType, $obj, "int", $value), "cveFacemarkAAMParamsSetM", @error)
EndFunc   ;==>_cveFacemarkAAMParamsSetM

Func _cveFacemarkAAMParamsGetN($obj)
    ; CVAPI(int) cveFacemarkAAMParamsGetN(cv::face::FacemarkAAM::Params* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveFacemarkAAMParamsGetN", $bObjDllType, $obj), "cveFacemarkAAMParamsGetN", @error)
EndFunc   ;==>_cveFacemarkAAMParamsGetN

Func _cveFacemarkAAMParamsSetN($obj, $value)
    ; CVAPI(void) cveFacemarkAAMParamsSetN(cv::face::FacemarkAAM::Params* obj, int value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFacemarkAAMParamsSetN", $bObjDllType, $obj, "int", $value), "cveFacemarkAAMParamsSetN", @error)
EndFunc   ;==>_cveFacemarkAAMParamsSetN

Func _cveFacemarkAAMParamsGetNIter($obj)
    ; CVAPI(int) cveFacemarkAAMParamsGetNIter(cv::face::FacemarkAAM::Params* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveFacemarkAAMParamsGetNIter", $bObjDllType, $obj), "cveFacemarkAAMParamsGetNIter", @error)
EndFunc   ;==>_cveFacemarkAAMParamsGetNIter

Func _cveFacemarkAAMParamsSetNIter($obj, $value)
    ; CVAPI(void) cveFacemarkAAMParamsSetNIter(cv::face::FacemarkAAM::Params* obj, int value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFacemarkAAMParamsSetNIter", $bObjDllType, $obj, "int", $value), "cveFacemarkAAMParamsSetNIter", @error)
EndFunc   ;==>_cveFacemarkAAMParamsSetNIter

Func _cveFacemarkAAMParamsGetVerbose($obj)
    ; CVAPI(bool) cveFacemarkAAMParamsGetVerbose(cv::face::FacemarkAAM::Params* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveFacemarkAAMParamsGetVerbose", $bObjDllType, $obj), "cveFacemarkAAMParamsGetVerbose", @error)
EndFunc   ;==>_cveFacemarkAAMParamsGetVerbose

Func _cveFacemarkAAMParamsSetVerbose($obj, $value)
    ; CVAPI(void) cveFacemarkAAMParamsSetVerbose(cv::face::FacemarkAAM::Params* obj, bool value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFacemarkAAMParamsSetVerbose", $bObjDllType, $obj, "boolean", $value), "cveFacemarkAAMParamsSetVerbose", @error)
EndFunc   ;==>_cveFacemarkAAMParamsSetVerbose

Func _cveFacemarkAAMParamsGetSaveModel($obj)
    ; CVAPI(bool) cveFacemarkAAMParamsGetSaveModel(cv::face::FacemarkAAM::Params* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveFacemarkAAMParamsGetSaveModel", $bObjDllType, $obj), "cveFacemarkAAMParamsGetSaveModel", @error)
EndFunc   ;==>_cveFacemarkAAMParamsGetSaveModel

Func _cveFacemarkAAMParamsSetSaveModel($obj, $value)
    ; CVAPI(void) cveFacemarkAAMParamsSetSaveModel(cv::face::FacemarkAAM::Params* obj, bool value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFacemarkAAMParamsSetSaveModel", $bObjDllType, $obj, "boolean", $value), "cveFacemarkAAMParamsSetSaveModel", @error)
EndFunc   ;==>_cveFacemarkAAMParamsSetSaveModel

Func _cveFacemarkAAMParamsGetMaxM($obj)
    ; CVAPI(int) cveFacemarkAAMParamsGetMaxM(cv::face::FacemarkAAM::Params* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveFacemarkAAMParamsGetMaxM", $bObjDllType, $obj), "cveFacemarkAAMParamsGetMaxM", @error)
EndFunc   ;==>_cveFacemarkAAMParamsGetMaxM

Func _cveFacemarkAAMParamsSetMaxM($obj, $value)
    ; CVAPI(void) cveFacemarkAAMParamsSetMaxM(cv::face::FacemarkAAM::Params* obj, int value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFacemarkAAMParamsSetMaxM", $bObjDllType, $obj, "int", $value), "cveFacemarkAAMParamsSetMaxM", @error)
EndFunc   ;==>_cveFacemarkAAMParamsSetMaxM

Func _cveFacemarkAAMParamsGetMaxN($obj)
    ; CVAPI(int) cveFacemarkAAMParamsGetMaxN(cv::face::FacemarkAAM::Params* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveFacemarkAAMParamsGetMaxN", $bObjDllType, $obj), "cveFacemarkAAMParamsGetMaxN", @error)
EndFunc   ;==>_cveFacemarkAAMParamsGetMaxN

Func _cveFacemarkAAMParamsSetMaxN($obj, $value)
    ; CVAPI(void) cveFacemarkAAMParamsSetMaxN(cv::face::FacemarkAAM::Params* obj, int value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFacemarkAAMParamsSetMaxN", $bObjDllType, $obj, "int", $value), "cveFacemarkAAMParamsSetMaxN", @error)
EndFunc   ;==>_cveFacemarkAAMParamsSetMaxN