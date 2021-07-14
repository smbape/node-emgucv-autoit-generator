#include-once
#include <..\..\CVEUtils.au3>

Func _cveInferBboxCreate(ByRef $deltaBbox, ByRef $classScores, ByRef $confScores)
    ; CVAPI(cv::dnn_objdetect::InferBbox*) cveInferBboxCreate(cv::Mat* deltaBbox, cv::Mat* classScores, cv::Mat* confScores);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveInferBboxCreate", "ptr", $deltaBbox, "ptr", $classScores, "ptr", $confScores), "cveInferBboxCreate", @error)
EndFunc   ;==>_cveInferBboxCreate

Func _cveInferBboxFilter(ByRef $inferBbox, $thresh)
    ; CVAPI(void) cveInferBboxFilter(cv::dnn_objdetect::InferBbox* inferBbox, double thresh);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveInferBboxFilter", "ptr", $inferBbox, "double", $thresh), "cveInferBboxFilter", @error)
EndFunc   ;==>_cveInferBboxFilter

Func _cveInferBboxRelease(ByRef $inferBbox)
    ; CVAPI(void) cveInferBboxRelease(cv::dnn_objdetect::InferBbox** inferBbox);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveInferBboxRelease", "ptr*", $inferBbox), "cveInferBboxRelease", @error)
EndFunc   ;==>_cveInferBboxRelease