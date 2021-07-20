#include-once
#include "..\..\CVEUtils.au3"

Func _cveEMGetClustersNumber($obj)
    ; CVAPI(int) cveEMGetClustersNumber(cv::ml::EM* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveEMGetClustersNumber", "ptr", $obj), "cveEMGetClustersNumber", @error)
EndFunc   ;==>_cveEMGetClustersNumber

Func _cveEMSetClustersNumber($obj, $value)
    ; CVAPI(void) cveEMSetClustersNumber(cv::ml::EM* obj, int value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveEMSetClustersNumber", "ptr", $obj, "int", $value), "cveEMSetClustersNumber", @error)
EndFunc   ;==>_cveEMSetClustersNumber

Func _cveEMGetCovarianceMatrixType($obj)
    ; CVAPI(int) cveEMGetCovarianceMatrixType(cv::ml::EM* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveEMGetCovarianceMatrixType", "ptr", $obj), "cveEMGetCovarianceMatrixType", @error)
EndFunc   ;==>_cveEMGetCovarianceMatrixType

Func _cveEMSetCovarianceMatrixType($obj, $value)
    ; CVAPI(void) cveEMSetCovarianceMatrixType(cv::ml::EM* obj, int value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveEMSetCovarianceMatrixType", "ptr", $obj, "int", $value), "cveEMSetCovarianceMatrixType", @error)
EndFunc   ;==>_cveEMSetCovarianceMatrixType

Func _cveEMGetTermCriteria($obj, $value)
    ; CVAPI(void) cveEMGetTermCriteria(cv::ml::EM* obj, CvTermCriteria* value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveEMGetTermCriteria", "ptr", $obj, "struct*", $value), "cveEMGetTermCriteria", @error)
EndFunc   ;==>_cveEMGetTermCriteria

Func _cveEMSetTermCriteria($obj, $value)
    ; CVAPI(void) cveEMSetTermCriteria(cv::ml::EM* obj, CvTermCriteria* value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveEMSetTermCriteria", "ptr", $obj, "struct*", $value), "cveEMSetTermCriteria", @error)
EndFunc   ;==>_cveEMSetTermCriteria