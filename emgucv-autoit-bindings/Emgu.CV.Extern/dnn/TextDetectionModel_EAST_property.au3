#include-once
#include "..\..\CVEUtils.au3"

Func _cveTextDetectionModel_EASTGetConfidenceThreshold($obj)
    ; CVAPI(float) cveTextDetectionModel_EASTGetConfidenceThreshold(cv::dnn::TextDetectionModel_EAST* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cveTextDetectionModel_EASTGetConfidenceThreshold", "ptr", $obj), "cveTextDetectionModel_EASTGetConfidenceThreshold", @error)
EndFunc   ;==>_cveTextDetectionModel_EASTGetConfidenceThreshold

Func _cveTextDetectionModel_EASTSetConfidenceThreshold($obj, $value)
    ; CVAPI(void) cveTextDetectionModel_EASTSetConfidenceThreshold(cv::dnn::TextDetectionModel_EAST* obj, float value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveTextDetectionModel_EASTSetConfidenceThreshold", "ptr", $obj, "float", $value), "cveTextDetectionModel_EASTSetConfidenceThreshold", @error)
EndFunc   ;==>_cveTextDetectionModel_EASTSetConfidenceThreshold

Func _cveTextDetectionModel_EASTGetNMSThreshold($obj)
    ; CVAPI(float) cveTextDetectionModel_EASTGetNMSThreshold(cv::dnn::TextDetectionModel_EAST* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cveTextDetectionModel_EASTGetNMSThreshold", "ptr", $obj), "cveTextDetectionModel_EASTGetNMSThreshold", @error)
EndFunc   ;==>_cveTextDetectionModel_EASTGetNMSThreshold

Func _cveTextDetectionModel_EASTSetNMSThreshold($obj, $value)
    ; CVAPI(void) cveTextDetectionModel_EASTSetNMSThreshold(cv::dnn::TextDetectionModel_EAST* obj, float value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveTextDetectionModel_EASTSetNMSThreshold", "ptr", $obj, "float", $value), "cveTextDetectionModel_EASTSetNMSThreshold", @error)
EndFunc   ;==>_cveTextDetectionModel_EASTSetNMSThreshold