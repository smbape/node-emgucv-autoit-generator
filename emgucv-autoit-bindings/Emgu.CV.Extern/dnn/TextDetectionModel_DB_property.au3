#include-once
#include <..\..\CVEUtils.au3>

Func _cveTextDetectionModel_DBGetBinaryThreshold(ByRef $obj)
    ; CVAPI(float) cveTextDetectionModel_DBGetBinaryThreshold(cv::dnn::TextDetectionModel_DB* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cveTextDetectionModel_DBGetBinaryThreshold", "ptr", $obj), "cveTextDetectionModel_DBGetBinaryThreshold", @error)
EndFunc   ;==>_cveTextDetectionModel_DBGetBinaryThreshold

Func _cveTextDetectionModel_DBSetBinaryThreshold(ByRef $obj, $value)
    ; CVAPI(void) cveTextDetectionModel_DBSetBinaryThreshold(cv::dnn::TextDetectionModel_DB* obj, float value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveTextDetectionModel_DBSetBinaryThreshold", "ptr", $obj, "float", $value), "cveTextDetectionModel_DBSetBinaryThreshold", @error)
EndFunc   ;==>_cveTextDetectionModel_DBSetBinaryThreshold

Func _cveTextDetectionModel_DBGetPolygonThreshold(ByRef $obj)
    ; CVAPI(float) cveTextDetectionModel_DBGetPolygonThreshold(cv::dnn::TextDetectionModel_DB* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cveTextDetectionModel_DBGetPolygonThreshold", "ptr", $obj), "cveTextDetectionModel_DBGetPolygonThreshold", @error)
EndFunc   ;==>_cveTextDetectionModel_DBGetPolygonThreshold

Func _cveTextDetectionModel_DBSetPolygonThreshold(ByRef $obj, $value)
    ; CVAPI(void) cveTextDetectionModel_DBSetPolygonThreshold(cv::dnn::TextDetectionModel_DB* obj, float value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveTextDetectionModel_DBSetPolygonThreshold", "ptr", $obj, "float", $value), "cveTextDetectionModel_DBSetPolygonThreshold", @error)
EndFunc   ;==>_cveTextDetectionModel_DBSetPolygonThreshold

Func _cveTextDetectionModel_DBGetUnclipRatio(ByRef $obj)
    ; CVAPI(double) cveTextDetectionModel_DBGetUnclipRatio(cv::dnn::TextDetectionModel_DB* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveTextDetectionModel_DBGetUnclipRatio", "ptr", $obj), "cveTextDetectionModel_DBGetUnclipRatio", @error)
EndFunc   ;==>_cveTextDetectionModel_DBGetUnclipRatio

Func _cveTextDetectionModel_DBSetUnclipRatio(ByRef $obj, $value)
    ; CVAPI(void) cveTextDetectionModel_DBSetUnclipRatio(cv::dnn::TextDetectionModel_DB* obj, double value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveTextDetectionModel_DBSetUnclipRatio", "ptr", $obj, "double", $value), "cveTextDetectionModel_DBSetUnclipRatio", @error)
EndFunc   ;==>_cveTextDetectionModel_DBSetUnclipRatio

Func _cveTextDetectionModel_DBGetMaxCandidates(ByRef $obj)
    ; CVAPI(int) cveTextDetectionModel_DBGetMaxCandidates(cv::dnn::TextDetectionModel_DB* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveTextDetectionModel_DBGetMaxCandidates", "ptr", $obj), "cveTextDetectionModel_DBGetMaxCandidates", @error)
EndFunc   ;==>_cveTextDetectionModel_DBGetMaxCandidates

Func _cveTextDetectionModel_DBSetMaxCandidates(ByRef $obj, $value)
    ; CVAPI(void) cveTextDetectionModel_DBSetMaxCandidates(cv::dnn::TextDetectionModel_DB* obj, int value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveTextDetectionModel_DBSetMaxCandidates", "ptr", $obj, "int", $value), "cveTextDetectionModel_DBSetMaxCandidates", @error)
EndFunc   ;==>_cveTextDetectionModel_DBSetMaxCandidates