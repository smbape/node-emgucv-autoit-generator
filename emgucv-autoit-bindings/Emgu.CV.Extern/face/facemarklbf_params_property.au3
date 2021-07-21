#include-once
#include "..\..\CVEUtils.au3"

Func _cveFacemarkLBFParamsGetShapeOffset($obj)
    ; CVAPI(double) cveFacemarkLBFParamsGetShapeOffset(cv::face::FacemarkLBF::Params* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveFacemarkLBFParamsGetShapeOffset", $bObjDllType, $obj), "cveFacemarkLBFParamsGetShapeOffset", @error)
EndFunc   ;==>_cveFacemarkLBFParamsGetShapeOffset

Func _cveFacemarkLBFParamsSetShapeOffset($obj, $value)
    ; CVAPI(void) cveFacemarkLBFParamsSetShapeOffset(cv::face::FacemarkLBF::Params* obj, double value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFacemarkLBFParamsSetShapeOffset", $bObjDllType, $obj, "double", $value), "cveFacemarkLBFParamsSetShapeOffset", @error)
EndFunc   ;==>_cveFacemarkLBFParamsSetShapeOffset

Func _cveFacemarkLBFParamsGetVerbose($obj)
    ; CVAPI(bool) cveFacemarkLBFParamsGetVerbose(cv::face::FacemarkLBF::Params* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveFacemarkLBFParamsGetVerbose", $bObjDllType, $obj), "cveFacemarkLBFParamsGetVerbose", @error)
EndFunc   ;==>_cveFacemarkLBFParamsGetVerbose

Func _cveFacemarkLBFParamsSetVerbose($obj, $value)
    ; CVAPI(void) cveFacemarkLBFParamsSetVerbose(cv::face::FacemarkLBF::Params* obj, bool value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFacemarkLBFParamsSetVerbose", $bObjDllType, $obj, "boolean", $value), "cveFacemarkLBFParamsSetVerbose", @error)
EndFunc   ;==>_cveFacemarkLBFParamsSetVerbose

Func _cveFacemarkLBFParamsGetNLandmarks($obj)
    ; CVAPI(int) cveFacemarkLBFParamsGetNLandmarks(cv::face::FacemarkLBF::Params* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveFacemarkLBFParamsGetNLandmarks", $bObjDllType, $obj), "cveFacemarkLBFParamsGetNLandmarks", @error)
EndFunc   ;==>_cveFacemarkLBFParamsGetNLandmarks

Func _cveFacemarkLBFParamsSetNLandmarks($obj, $value)
    ; CVAPI(void) cveFacemarkLBFParamsSetNLandmarks(cv::face::FacemarkLBF::Params* obj, int value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFacemarkLBFParamsSetNLandmarks", $bObjDllType, $obj, "int", $value), "cveFacemarkLBFParamsSetNLandmarks", @error)
EndFunc   ;==>_cveFacemarkLBFParamsSetNLandmarks

Func _cveFacemarkLBFParamsGetInitShapeN($obj)
    ; CVAPI(int) cveFacemarkLBFParamsGetInitShapeN(cv::face::FacemarkLBF::Params* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveFacemarkLBFParamsGetInitShapeN", $bObjDllType, $obj), "cveFacemarkLBFParamsGetInitShapeN", @error)
EndFunc   ;==>_cveFacemarkLBFParamsGetInitShapeN

Func _cveFacemarkLBFParamsSetInitShapeN($obj, $value)
    ; CVAPI(void) cveFacemarkLBFParamsSetInitShapeN(cv::face::FacemarkLBF::Params* obj, int value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFacemarkLBFParamsSetInitShapeN", $bObjDllType, $obj, "int", $value), "cveFacemarkLBFParamsSetInitShapeN", @error)
EndFunc   ;==>_cveFacemarkLBFParamsSetInitShapeN

Func _cveFacemarkLBFParamsGetStagesN($obj)
    ; CVAPI(int) cveFacemarkLBFParamsGetStagesN(cv::face::FacemarkLBF::Params* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveFacemarkLBFParamsGetStagesN", $bObjDllType, $obj), "cveFacemarkLBFParamsGetStagesN", @error)
EndFunc   ;==>_cveFacemarkLBFParamsGetStagesN

Func _cveFacemarkLBFParamsSetStagesN($obj, $value)
    ; CVAPI(void) cveFacemarkLBFParamsSetStagesN(cv::face::FacemarkLBF::Params* obj, int value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFacemarkLBFParamsSetStagesN", $bObjDllType, $obj, "int", $value), "cveFacemarkLBFParamsSetStagesN", @error)
EndFunc   ;==>_cveFacemarkLBFParamsSetStagesN

Func _cveFacemarkLBFParamsGetTreeN($obj)
    ; CVAPI(int) cveFacemarkLBFParamsGetTreeN(cv::face::FacemarkLBF::Params* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveFacemarkLBFParamsGetTreeN", $bObjDllType, $obj), "cveFacemarkLBFParamsGetTreeN", @error)
EndFunc   ;==>_cveFacemarkLBFParamsGetTreeN

Func _cveFacemarkLBFParamsSetTreeN($obj, $value)
    ; CVAPI(void) cveFacemarkLBFParamsSetTreeN(cv::face::FacemarkLBF::Params* obj, int value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFacemarkLBFParamsSetTreeN", $bObjDllType, $obj, "int", $value), "cveFacemarkLBFParamsSetTreeN", @error)
EndFunc   ;==>_cveFacemarkLBFParamsSetTreeN

Func _cveFacemarkLBFParamsGetTreeDepth($obj)
    ; CVAPI(int) cveFacemarkLBFParamsGetTreeDepth(cv::face::FacemarkLBF::Params* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveFacemarkLBFParamsGetTreeDepth", $bObjDllType, $obj), "cveFacemarkLBFParamsGetTreeDepth", @error)
EndFunc   ;==>_cveFacemarkLBFParamsGetTreeDepth

Func _cveFacemarkLBFParamsSetTreeDepth($obj, $value)
    ; CVAPI(void) cveFacemarkLBFParamsSetTreeDepth(cv::face::FacemarkLBF::Params* obj, int value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFacemarkLBFParamsSetTreeDepth", $bObjDllType, $obj, "int", $value), "cveFacemarkLBFParamsSetTreeDepth", @error)
EndFunc   ;==>_cveFacemarkLBFParamsSetTreeDepth

Func _cveFacemarkLBFParamsGetBaggingOverlap($obj)
    ; CVAPI(double) cveFacemarkLBFParamsGetBaggingOverlap(cv::face::FacemarkLBF::Params* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveFacemarkLBFParamsGetBaggingOverlap", $bObjDllType, $obj), "cveFacemarkLBFParamsGetBaggingOverlap", @error)
EndFunc   ;==>_cveFacemarkLBFParamsGetBaggingOverlap

Func _cveFacemarkLBFParamsSetBaggingOverlap($obj, $value)
    ; CVAPI(void) cveFacemarkLBFParamsSetBaggingOverlap(cv::face::FacemarkLBF::Params* obj, double value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFacemarkLBFParamsSetBaggingOverlap", $bObjDllType, $obj, "double", $value), "cveFacemarkLBFParamsSetBaggingOverlap", @error)
EndFunc   ;==>_cveFacemarkLBFParamsSetBaggingOverlap

Func _cveFacemarkLBFParamsGetSaveModel($obj)
    ; CVAPI(bool) cveFacemarkLBFParamsGetSaveModel(cv::face::FacemarkLBF::Params* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveFacemarkLBFParamsGetSaveModel", $bObjDllType, $obj), "cveFacemarkLBFParamsGetSaveModel", @error)
EndFunc   ;==>_cveFacemarkLBFParamsGetSaveModel

Func _cveFacemarkLBFParamsSetSaveModel($obj, $value)
    ; CVAPI(void) cveFacemarkLBFParamsSetSaveModel(cv::face::FacemarkLBF::Params* obj, bool value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFacemarkLBFParamsSetSaveModel", $bObjDllType, $obj, "boolean", $value), "cveFacemarkLBFParamsSetSaveModel", @error)
EndFunc   ;==>_cveFacemarkLBFParamsSetSaveModel

Func _cveFacemarkLBFParamsGetCascadeFace($obj, $str)
    ; CVAPI(void) cveFacemarkLBFParamsGetCascadeFace(cv::face::FacemarkLBF::Params* obj, cv::String* str);

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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFacemarkLBFParamsGetCascadeFace", $bObjDllType, $obj, $bStrDllType, $str), "cveFacemarkLBFParamsGetCascadeFace", @error)

    If $bStrIsString Then
        _cveStringRelease($str)
    EndIf
EndFunc   ;==>_cveFacemarkLBFParamsGetCascadeFace

Func _cveFacemarkLBFParamsSetCascadeFace($obj, $str)
    ; CVAPI(void) cveFacemarkLBFParamsSetCascadeFace(cv::face::FacemarkLBF::Params* obj, cv::String* str);

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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFacemarkLBFParamsSetCascadeFace", $bObjDllType, $obj, $bStrDllType, $str), "cveFacemarkLBFParamsSetCascadeFace", @error)

    If $bStrIsString Then
        _cveStringRelease($str)
    EndIf
EndFunc   ;==>_cveFacemarkLBFParamsSetCascadeFace

Func _cveFacemarkLBFParamsGetModelFile($obj, $str)
    ; CVAPI(void) cveFacemarkLBFParamsGetModelFile(cv::face::FacemarkLBF::Params* obj, cv::String* str);

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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFacemarkLBFParamsGetModelFile", $bObjDllType, $obj, $bStrDllType, $str), "cveFacemarkLBFParamsGetModelFile", @error)

    If $bStrIsString Then
        _cveStringRelease($str)
    EndIf
EndFunc   ;==>_cveFacemarkLBFParamsGetModelFile

Func _cveFacemarkLBFParamsSetModelFile($obj, $str)
    ; CVAPI(void) cveFacemarkLBFParamsSetModelFile(cv::face::FacemarkLBF::Params* obj, cv::String* str);

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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFacemarkLBFParamsSetModelFile", $bObjDllType, $obj, $bStrDllType, $str), "cveFacemarkLBFParamsSetModelFile", @error)

    If $bStrIsString Then
        _cveStringRelease($str)
    EndIf
EndFunc   ;==>_cveFacemarkLBFParamsSetModelFile