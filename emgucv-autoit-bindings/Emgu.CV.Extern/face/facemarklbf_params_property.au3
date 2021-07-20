#include-once
#include "..\..\CVEUtils.au3"

Func _cveFacemarkLBFParamsGetShapeOffset($obj)
    ; CVAPI(double) cveFacemarkLBFParamsGetShapeOffset(cv::face::FacemarkLBF::Params* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveFacemarkLBFParamsGetShapeOffset", "ptr", $obj), "cveFacemarkLBFParamsGetShapeOffset", @error)
EndFunc   ;==>_cveFacemarkLBFParamsGetShapeOffset

Func _cveFacemarkLBFParamsSetShapeOffset($obj, $value)
    ; CVAPI(void) cveFacemarkLBFParamsSetShapeOffset(cv::face::FacemarkLBF::Params* obj, double value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFacemarkLBFParamsSetShapeOffset", "ptr", $obj, "double", $value), "cveFacemarkLBFParamsSetShapeOffset", @error)
EndFunc   ;==>_cveFacemarkLBFParamsSetShapeOffset

Func _cveFacemarkLBFParamsGetVerbose($obj)
    ; CVAPI(bool) cveFacemarkLBFParamsGetVerbose(cv::face::FacemarkLBF::Params* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveFacemarkLBFParamsGetVerbose", "ptr", $obj), "cveFacemarkLBFParamsGetVerbose", @error)
EndFunc   ;==>_cveFacemarkLBFParamsGetVerbose

Func _cveFacemarkLBFParamsSetVerbose($obj, $value)
    ; CVAPI(void) cveFacemarkLBFParamsSetVerbose(cv::face::FacemarkLBF::Params* obj, bool value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFacemarkLBFParamsSetVerbose", "ptr", $obj, "boolean", $value), "cveFacemarkLBFParamsSetVerbose", @error)
EndFunc   ;==>_cveFacemarkLBFParamsSetVerbose

Func _cveFacemarkLBFParamsGetNLandmarks($obj)
    ; CVAPI(int) cveFacemarkLBFParamsGetNLandmarks(cv::face::FacemarkLBF::Params* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveFacemarkLBFParamsGetNLandmarks", "ptr", $obj), "cveFacemarkLBFParamsGetNLandmarks", @error)
EndFunc   ;==>_cveFacemarkLBFParamsGetNLandmarks

Func _cveFacemarkLBFParamsSetNLandmarks($obj, $value)
    ; CVAPI(void) cveFacemarkLBFParamsSetNLandmarks(cv::face::FacemarkLBF::Params* obj, int value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFacemarkLBFParamsSetNLandmarks", "ptr", $obj, "int", $value), "cveFacemarkLBFParamsSetNLandmarks", @error)
EndFunc   ;==>_cveFacemarkLBFParamsSetNLandmarks

Func _cveFacemarkLBFParamsGetInitShapeN($obj)
    ; CVAPI(int) cveFacemarkLBFParamsGetInitShapeN(cv::face::FacemarkLBF::Params* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveFacemarkLBFParamsGetInitShapeN", "ptr", $obj), "cveFacemarkLBFParamsGetInitShapeN", @error)
EndFunc   ;==>_cveFacemarkLBFParamsGetInitShapeN

Func _cveFacemarkLBFParamsSetInitShapeN($obj, $value)
    ; CVAPI(void) cveFacemarkLBFParamsSetInitShapeN(cv::face::FacemarkLBF::Params* obj, int value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFacemarkLBFParamsSetInitShapeN", "ptr", $obj, "int", $value), "cveFacemarkLBFParamsSetInitShapeN", @error)
EndFunc   ;==>_cveFacemarkLBFParamsSetInitShapeN

Func _cveFacemarkLBFParamsGetStagesN($obj)
    ; CVAPI(int) cveFacemarkLBFParamsGetStagesN(cv::face::FacemarkLBF::Params* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveFacemarkLBFParamsGetStagesN", "ptr", $obj), "cveFacemarkLBFParamsGetStagesN", @error)
EndFunc   ;==>_cveFacemarkLBFParamsGetStagesN

Func _cveFacemarkLBFParamsSetStagesN($obj, $value)
    ; CVAPI(void) cveFacemarkLBFParamsSetStagesN(cv::face::FacemarkLBF::Params* obj, int value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFacemarkLBFParamsSetStagesN", "ptr", $obj, "int", $value), "cveFacemarkLBFParamsSetStagesN", @error)
EndFunc   ;==>_cveFacemarkLBFParamsSetStagesN

Func _cveFacemarkLBFParamsGetTreeN($obj)
    ; CVAPI(int) cveFacemarkLBFParamsGetTreeN(cv::face::FacemarkLBF::Params* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveFacemarkLBFParamsGetTreeN", "ptr", $obj), "cveFacemarkLBFParamsGetTreeN", @error)
EndFunc   ;==>_cveFacemarkLBFParamsGetTreeN

Func _cveFacemarkLBFParamsSetTreeN($obj, $value)
    ; CVAPI(void) cveFacemarkLBFParamsSetTreeN(cv::face::FacemarkLBF::Params* obj, int value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFacemarkLBFParamsSetTreeN", "ptr", $obj, "int", $value), "cveFacemarkLBFParamsSetTreeN", @error)
EndFunc   ;==>_cveFacemarkLBFParamsSetTreeN

Func _cveFacemarkLBFParamsGetTreeDepth($obj)
    ; CVAPI(int) cveFacemarkLBFParamsGetTreeDepth(cv::face::FacemarkLBF::Params* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveFacemarkLBFParamsGetTreeDepth", "ptr", $obj), "cveFacemarkLBFParamsGetTreeDepth", @error)
EndFunc   ;==>_cveFacemarkLBFParamsGetTreeDepth

Func _cveFacemarkLBFParamsSetTreeDepth($obj, $value)
    ; CVAPI(void) cveFacemarkLBFParamsSetTreeDepth(cv::face::FacemarkLBF::Params* obj, int value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFacemarkLBFParamsSetTreeDepth", "ptr", $obj, "int", $value), "cveFacemarkLBFParamsSetTreeDepth", @error)
EndFunc   ;==>_cveFacemarkLBFParamsSetTreeDepth

Func _cveFacemarkLBFParamsGetBaggingOverlap($obj)
    ; CVAPI(double) cveFacemarkLBFParamsGetBaggingOverlap(cv::face::FacemarkLBF::Params* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveFacemarkLBFParamsGetBaggingOverlap", "ptr", $obj), "cveFacemarkLBFParamsGetBaggingOverlap", @error)
EndFunc   ;==>_cveFacemarkLBFParamsGetBaggingOverlap

Func _cveFacemarkLBFParamsSetBaggingOverlap($obj, $value)
    ; CVAPI(void) cveFacemarkLBFParamsSetBaggingOverlap(cv::face::FacemarkLBF::Params* obj, double value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFacemarkLBFParamsSetBaggingOverlap", "ptr", $obj, "double", $value), "cveFacemarkLBFParamsSetBaggingOverlap", @error)
EndFunc   ;==>_cveFacemarkLBFParamsSetBaggingOverlap

Func _cveFacemarkLBFParamsGetSaveModel($obj)
    ; CVAPI(bool) cveFacemarkLBFParamsGetSaveModel(cv::face::FacemarkLBF::Params* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveFacemarkLBFParamsGetSaveModel", "ptr", $obj), "cveFacemarkLBFParamsGetSaveModel", @error)
EndFunc   ;==>_cveFacemarkLBFParamsGetSaveModel

Func _cveFacemarkLBFParamsSetSaveModel($obj, $value)
    ; CVAPI(void) cveFacemarkLBFParamsSetSaveModel(cv::face::FacemarkLBF::Params* obj, bool value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFacemarkLBFParamsSetSaveModel", "ptr", $obj, "boolean", $value), "cveFacemarkLBFParamsSetSaveModel", @error)
EndFunc   ;==>_cveFacemarkLBFParamsSetSaveModel

Func _cveFacemarkLBFParamsGetCascadeFace($obj, $str)
    ; CVAPI(void) cveFacemarkLBFParamsGetCascadeFace(cv::face::FacemarkLBF::Params* obj, cv::String* str);

    Local $bStrIsString = VarGetType($str) == "String"
    If $bStrIsString Then
        $str = _cveStringCreateFromStr($str)
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFacemarkLBFParamsGetCascadeFace", "ptr", $obj, "ptr", $str), "cveFacemarkLBFParamsGetCascadeFace", @error)

    If $bStrIsString Then
        _cveStringRelease($str)
    EndIf
EndFunc   ;==>_cveFacemarkLBFParamsGetCascadeFace

Func _cveFacemarkLBFParamsSetCascadeFace($obj, $str)
    ; CVAPI(void) cveFacemarkLBFParamsSetCascadeFace(cv::face::FacemarkLBF::Params* obj, cv::String* str);

    Local $bStrIsString = VarGetType($str) == "String"
    If $bStrIsString Then
        $str = _cveStringCreateFromStr($str)
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFacemarkLBFParamsSetCascadeFace", "ptr", $obj, "ptr", $str), "cveFacemarkLBFParamsSetCascadeFace", @error)

    If $bStrIsString Then
        _cveStringRelease($str)
    EndIf
EndFunc   ;==>_cveFacemarkLBFParamsSetCascadeFace

Func _cveFacemarkLBFParamsGetModelFile($obj, $str)
    ; CVAPI(void) cveFacemarkLBFParamsGetModelFile(cv::face::FacemarkLBF::Params* obj, cv::String* str);

    Local $bStrIsString = VarGetType($str) == "String"
    If $bStrIsString Then
        $str = _cveStringCreateFromStr($str)
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFacemarkLBFParamsGetModelFile", "ptr", $obj, "ptr", $str), "cveFacemarkLBFParamsGetModelFile", @error)

    If $bStrIsString Then
        _cveStringRelease($str)
    EndIf
EndFunc   ;==>_cveFacemarkLBFParamsGetModelFile

Func _cveFacemarkLBFParamsSetModelFile($obj, $str)
    ; CVAPI(void) cveFacemarkLBFParamsSetModelFile(cv::face::FacemarkLBF::Params* obj, cv::String* str);

    Local $bStrIsString = VarGetType($str) == "String"
    If $bStrIsString Then
        $str = _cveStringCreateFromStr($str)
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFacemarkLBFParamsSetModelFile", "ptr", $obj, "ptr", $str), "cveFacemarkLBFParamsSetModelFile", @error)

    If $bStrIsString Then
        _cveStringRelease($str)
    EndIf
EndFunc   ;==>_cveFacemarkLBFParamsSetModelFile