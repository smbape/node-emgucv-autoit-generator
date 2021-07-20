#include-once
#include "..\..\CVEUtils.au3"

Func _cveDetectionModelGetNmsAcrossClasses($obj)
    ; CVAPI(bool) cveDetectionModelGetNmsAcrossClasses(cv::dnn::DetectionModel* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveDetectionModelGetNmsAcrossClasses", "ptr", $obj), "cveDetectionModelGetNmsAcrossClasses", @error)
EndFunc   ;==>_cveDetectionModelGetNmsAcrossClasses

Func _cveDetectionModelSetNmsAcrossClasses($obj, $value)
    ; CVAPI(void) cveDetectionModelSetNmsAcrossClasses(cv::dnn::DetectionModel* obj, bool value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDetectionModelSetNmsAcrossClasses", "ptr", $obj, "boolean", $value), "cveDetectionModelSetNmsAcrossClasses", @error)
EndFunc   ;==>_cveDetectionModelSetNmsAcrossClasses