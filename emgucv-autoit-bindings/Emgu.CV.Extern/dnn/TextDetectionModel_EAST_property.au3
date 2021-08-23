#include-once
#include "..\..\CVEUtils.au3"

Func _cveTextDetectionModel_EASTGetConfidenceThreshold($obj)
    ; CVAPI(float) cveTextDetectionModel_EASTGetConfidenceThreshold(cv::dnn::TextDetectionModel_EAST* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cveTextDetectionModel_EASTGetConfidenceThreshold", $sObjDllType, $obj), "cveTextDetectionModel_EASTGetConfidenceThreshold", @error)
EndFunc   ;==>_cveTextDetectionModel_EASTGetConfidenceThreshold

Func _cveTextDetectionModel_EASTSetConfidenceThreshold($obj, $value)
    ; CVAPI(void) cveTextDetectionModel_EASTSetConfidenceThreshold(cv::dnn::TextDetectionModel_EAST* obj, float value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveTextDetectionModel_EASTSetConfidenceThreshold", $sObjDllType, $obj, "float", $value), "cveTextDetectionModel_EASTSetConfidenceThreshold", @error)
EndFunc   ;==>_cveTextDetectionModel_EASTSetConfidenceThreshold

Func _cveTextDetectionModel_EASTGetNMSThreshold($obj)
    ; CVAPI(float) cveTextDetectionModel_EASTGetNMSThreshold(cv::dnn::TextDetectionModel_EAST* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cveTextDetectionModel_EASTGetNMSThreshold", $sObjDllType, $obj), "cveTextDetectionModel_EASTGetNMSThreshold", @error)
EndFunc   ;==>_cveTextDetectionModel_EASTGetNMSThreshold

Func _cveTextDetectionModel_EASTSetNMSThreshold($obj, $value)
    ; CVAPI(void) cveTextDetectionModel_EASTSetNMSThreshold(cv::dnn::TextDetectionModel_EAST* obj, float value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveTextDetectionModel_EASTSetNMSThreshold", $sObjDllType, $obj, "float", $value), "cveTextDetectionModel_EASTSetNMSThreshold", @error)
EndFunc   ;==>_cveTextDetectionModel_EASTSetNMSThreshold