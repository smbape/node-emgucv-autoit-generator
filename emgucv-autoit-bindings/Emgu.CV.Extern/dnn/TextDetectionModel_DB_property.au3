#include-once
#include "..\..\CVEUtils.au3"

Func _cveTextDetectionModel_DBGetBinaryThreshold($obj)
    ; CVAPI(float) cveTextDetectionModel_DBGetBinaryThreshold(cv::dnn::TextDetectionModel_DB* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cveTextDetectionModel_DBGetBinaryThreshold", $sObjDllType, $obj), "cveTextDetectionModel_DBGetBinaryThreshold", @error)
EndFunc   ;==>_cveTextDetectionModel_DBGetBinaryThreshold

Func _cveTextDetectionModel_DBSetBinaryThreshold($obj, $value)
    ; CVAPI(void) cveTextDetectionModel_DBSetBinaryThreshold(cv::dnn::TextDetectionModel_DB* obj, float value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveTextDetectionModel_DBSetBinaryThreshold", $sObjDllType, $obj, "float", $value), "cveTextDetectionModel_DBSetBinaryThreshold", @error)
EndFunc   ;==>_cveTextDetectionModel_DBSetBinaryThreshold

Func _cveTextDetectionModel_DBGetPolygonThreshold($obj)
    ; CVAPI(float) cveTextDetectionModel_DBGetPolygonThreshold(cv::dnn::TextDetectionModel_DB* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cveTextDetectionModel_DBGetPolygonThreshold", $sObjDllType, $obj), "cveTextDetectionModel_DBGetPolygonThreshold", @error)
EndFunc   ;==>_cveTextDetectionModel_DBGetPolygonThreshold

Func _cveTextDetectionModel_DBSetPolygonThreshold($obj, $value)
    ; CVAPI(void) cveTextDetectionModel_DBSetPolygonThreshold(cv::dnn::TextDetectionModel_DB* obj, float value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveTextDetectionModel_DBSetPolygonThreshold", $sObjDllType, $obj, "float", $value), "cveTextDetectionModel_DBSetPolygonThreshold", @error)
EndFunc   ;==>_cveTextDetectionModel_DBSetPolygonThreshold

Func _cveTextDetectionModel_DBGetUnclipRatio($obj)
    ; CVAPI(double) cveTextDetectionModel_DBGetUnclipRatio(cv::dnn::TextDetectionModel_DB* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveTextDetectionModel_DBGetUnclipRatio", $sObjDllType, $obj), "cveTextDetectionModel_DBGetUnclipRatio", @error)
EndFunc   ;==>_cveTextDetectionModel_DBGetUnclipRatio

Func _cveTextDetectionModel_DBSetUnclipRatio($obj, $value)
    ; CVAPI(void) cveTextDetectionModel_DBSetUnclipRatio(cv::dnn::TextDetectionModel_DB* obj, double value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveTextDetectionModel_DBSetUnclipRatio", $sObjDllType, $obj, "double", $value), "cveTextDetectionModel_DBSetUnclipRatio", @error)
EndFunc   ;==>_cveTextDetectionModel_DBSetUnclipRatio

Func _cveTextDetectionModel_DBGetMaxCandidates($obj)
    ; CVAPI(int) cveTextDetectionModel_DBGetMaxCandidates(cv::dnn::TextDetectionModel_DB* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveTextDetectionModel_DBGetMaxCandidates", $sObjDllType, $obj), "cveTextDetectionModel_DBGetMaxCandidates", @error)
EndFunc   ;==>_cveTextDetectionModel_DBGetMaxCandidates

Func _cveTextDetectionModel_DBSetMaxCandidates($obj, $value)
    ; CVAPI(void) cveTextDetectionModel_DBSetMaxCandidates(cv::dnn::TextDetectionModel_DB* obj, int value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveTextDetectionModel_DBSetMaxCandidates", $sObjDllType, $obj, "int", $value), "cveTextDetectionModel_DBSetMaxCandidates", @error)
EndFunc   ;==>_cveTextDetectionModel_DBSetMaxCandidates