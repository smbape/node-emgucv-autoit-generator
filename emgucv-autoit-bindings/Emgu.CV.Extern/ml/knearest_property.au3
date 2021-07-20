#include-once
#include "..\..\CVEUtils.au3"

Func _cveKNearestGetDefaultK($obj)
    ; CVAPI(int) cveKNearestGetDefaultK(cv::ml::KNearest* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveKNearestGetDefaultK", "ptr", $obj), "cveKNearestGetDefaultK", @error)
EndFunc   ;==>_cveKNearestGetDefaultK

Func _cveKNearestSetDefaultK($obj, $value)
    ; CVAPI(void) cveKNearestSetDefaultK(cv::ml::KNearest* obj, int value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveKNearestSetDefaultK", "ptr", $obj, "int", $value), "cveKNearestSetDefaultK", @error)
EndFunc   ;==>_cveKNearestSetDefaultK

Func _cveKNearestGetIsClassifier($obj)
    ; CVAPI(bool) cveKNearestGetIsClassifier(cv::ml::KNearest* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveKNearestGetIsClassifier", "ptr", $obj), "cveKNearestGetIsClassifier", @error)
EndFunc   ;==>_cveKNearestGetIsClassifier

Func _cveKNearestSetIsClassifier($obj, $value)
    ; CVAPI(void) cveKNearestSetIsClassifier(cv::ml::KNearest* obj, bool value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveKNearestSetIsClassifier", "ptr", $obj, "boolean", $value), "cveKNearestSetIsClassifier", @error)
EndFunc   ;==>_cveKNearestSetIsClassifier

Func _cveKNearestGetEmax($obj)
    ; CVAPI(int) cveKNearestGetEmax(cv::ml::KNearest* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveKNearestGetEmax", "ptr", $obj), "cveKNearestGetEmax", @error)
EndFunc   ;==>_cveKNearestGetEmax

Func _cveKNearestSetEmax($obj, $value)
    ; CVAPI(void) cveKNearestSetEmax(cv::ml::KNearest* obj, int value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveKNearestSetEmax", "ptr", $obj, "int", $value), "cveKNearestSetEmax", @error)
EndFunc   ;==>_cveKNearestSetEmax

Func _cveKNearestGetAlgorithmType($obj)
    ; CVAPI(int) cveKNearestGetAlgorithmType(cv::ml::KNearest* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveKNearestGetAlgorithmType", "ptr", $obj), "cveKNearestGetAlgorithmType", @error)
EndFunc   ;==>_cveKNearestGetAlgorithmType

Func _cveKNearestSetAlgorithmType($obj, $value)
    ; CVAPI(void) cveKNearestSetAlgorithmType(cv::ml::KNearest* obj, int value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveKNearestSetAlgorithmType", "ptr", $obj, "int", $value), "cveKNearestSetAlgorithmType", @error)
EndFunc   ;==>_cveKNearestSetAlgorithmType