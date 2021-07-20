#include-once
#include "..\..\CVEUtils.au3"

Func _cveFacemarkAAMParamsGetModelFile($obj, $str)
    ; CVAPI(void) cveFacemarkAAMParamsGetModelFile(cv::face::FacemarkAAM::Params* obj, cv::String* str);

    Local $bStrIsString = VarGetType($str) == "String"
    If $bStrIsString Then
        $str = _cveStringCreateFromStr($str)
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFacemarkAAMParamsGetModelFile", "ptr", $obj, "ptr", $str), "cveFacemarkAAMParamsGetModelFile", @error)

    If $bStrIsString Then
        _cveStringRelease($str)
    EndIf
EndFunc   ;==>_cveFacemarkAAMParamsGetModelFile

Func _cveFacemarkAAMParamsSetModelFile($obj, $str)
    ; CVAPI(void) cveFacemarkAAMParamsSetModelFile(cv::face::FacemarkAAM::Params* obj, cv::String* str);

    Local $bStrIsString = VarGetType($str) == "String"
    If $bStrIsString Then
        $str = _cveStringCreateFromStr($str)
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFacemarkAAMParamsSetModelFile", "ptr", $obj, "ptr", $str), "cveFacemarkAAMParamsSetModelFile", @error)

    If $bStrIsString Then
        _cveStringRelease($str)
    EndIf
EndFunc   ;==>_cveFacemarkAAMParamsSetModelFile

Func _cveFacemarkAAMParamsGetM($obj)
    ; CVAPI(int) cveFacemarkAAMParamsGetM(cv::face::FacemarkAAM::Params* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveFacemarkAAMParamsGetM", "ptr", $obj), "cveFacemarkAAMParamsGetM", @error)
EndFunc   ;==>_cveFacemarkAAMParamsGetM

Func _cveFacemarkAAMParamsSetM($obj, $value)
    ; CVAPI(void) cveFacemarkAAMParamsSetM(cv::face::FacemarkAAM::Params* obj, int value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFacemarkAAMParamsSetM", "ptr", $obj, "int", $value), "cveFacemarkAAMParamsSetM", @error)
EndFunc   ;==>_cveFacemarkAAMParamsSetM

Func _cveFacemarkAAMParamsGetN($obj)
    ; CVAPI(int) cveFacemarkAAMParamsGetN(cv::face::FacemarkAAM::Params* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveFacemarkAAMParamsGetN", "ptr", $obj), "cveFacemarkAAMParamsGetN", @error)
EndFunc   ;==>_cveFacemarkAAMParamsGetN

Func _cveFacemarkAAMParamsSetN($obj, $value)
    ; CVAPI(void) cveFacemarkAAMParamsSetN(cv::face::FacemarkAAM::Params* obj, int value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFacemarkAAMParamsSetN", "ptr", $obj, "int", $value), "cveFacemarkAAMParamsSetN", @error)
EndFunc   ;==>_cveFacemarkAAMParamsSetN

Func _cveFacemarkAAMParamsGetNIter($obj)
    ; CVAPI(int) cveFacemarkAAMParamsGetNIter(cv::face::FacemarkAAM::Params* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveFacemarkAAMParamsGetNIter", "ptr", $obj), "cveFacemarkAAMParamsGetNIter", @error)
EndFunc   ;==>_cveFacemarkAAMParamsGetNIter

Func _cveFacemarkAAMParamsSetNIter($obj, $value)
    ; CVAPI(void) cveFacemarkAAMParamsSetNIter(cv::face::FacemarkAAM::Params* obj, int value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFacemarkAAMParamsSetNIter", "ptr", $obj, "int", $value), "cveFacemarkAAMParamsSetNIter", @error)
EndFunc   ;==>_cveFacemarkAAMParamsSetNIter

Func _cveFacemarkAAMParamsGetVerbose($obj)
    ; CVAPI(bool) cveFacemarkAAMParamsGetVerbose(cv::face::FacemarkAAM::Params* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveFacemarkAAMParamsGetVerbose", "ptr", $obj), "cveFacemarkAAMParamsGetVerbose", @error)
EndFunc   ;==>_cveFacemarkAAMParamsGetVerbose

Func _cveFacemarkAAMParamsSetVerbose($obj, $value)
    ; CVAPI(void) cveFacemarkAAMParamsSetVerbose(cv::face::FacemarkAAM::Params* obj, bool value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFacemarkAAMParamsSetVerbose", "ptr", $obj, "boolean", $value), "cveFacemarkAAMParamsSetVerbose", @error)
EndFunc   ;==>_cveFacemarkAAMParamsSetVerbose

Func _cveFacemarkAAMParamsGetSaveModel($obj)
    ; CVAPI(bool) cveFacemarkAAMParamsGetSaveModel(cv::face::FacemarkAAM::Params* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveFacemarkAAMParamsGetSaveModel", "ptr", $obj), "cveFacemarkAAMParamsGetSaveModel", @error)
EndFunc   ;==>_cveFacemarkAAMParamsGetSaveModel

Func _cveFacemarkAAMParamsSetSaveModel($obj, $value)
    ; CVAPI(void) cveFacemarkAAMParamsSetSaveModel(cv::face::FacemarkAAM::Params* obj, bool value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFacemarkAAMParamsSetSaveModel", "ptr", $obj, "boolean", $value), "cveFacemarkAAMParamsSetSaveModel", @error)
EndFunc   ;==>_cveFacemarkAAMParamsSetSaveModel

Func _cveFacemarkAAMParamsGetMaxM($obj)
    ; CVAPI(int) cveFacemarkAAMParamsGetMaxM(cv::face::FacemarkAAM::Params* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveFacemarkAAMParamsGetMaxM", "ptr", $obj), "cveFacemarkAAMParamsGetMaxM", @error)
EndFunc   ;==>_cveFacemarkAAMParamsGetMaxM

Func _cveFacemarkAAMParamsSetMaxM($obj, $value)
    ; CVAPI(void) cveFacemarkAAMParamsSetMaxM(cv::face::FacemarkAAM::Params* obj, int value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFacemarkAAMParamsSetMaxM", "ptr", $obj, "int", $value), "cveFacemarkAAMParamsSetMaxM", @error)
EndFunc   ;==>_cveFacemarkAAMParamsSetMaxM

Func _cveFacemarkAAMParamsGetMaxN($obj)
    ; CVAPI(int) cveFacemarkAAMParamsGetMaxN(cv::face::FacemarkAAM::Params* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveFacemarkAAMParamsGetMaxN", "ptr", $obj), "cveFacemarkAAMParamsGetMaxN", @error)
EndFunc   ;==>_cveFacemarkAAMParamsGetMaxN

Func _cveFacemarkAAMParamsSetMaxN($obj, $value)
    ; CVAPI(void) cveFacemarkAAMParamsSetMaxN(cv::face::FacemarkAAM::Params* obj, int value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFacemarkAAMParamsSetMaxN", "ptr", $obj, "int", $value), "cveFacemarkAAMParamsSetMaxN", @error)
EndFunc   ;==>_cveFacemarkAAMParamsSetMaxN