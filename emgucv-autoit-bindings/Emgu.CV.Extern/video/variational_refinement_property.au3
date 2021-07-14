#include-once
#include <..\..\CVEUtils.au3>

Func _cveVariationalRefinementGetFixedPointIterations(ByRef $obj)
    ; CVAPI(int) cveVariationalRefinementGetFixedPointIterations(cv::VariationalRefinement* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveVariationalRefinementGetFixedPointIterations", "ptr", $obj), "cveVariationalRefinementGetFixedPointIterations", @error)
EndFunc   ;==>_cveVariationalRefinementGetFixedPointIterations

Func _cveVariationalRefinementSetFixedPointIterations(ByRef $obj, $value)
    ; CVAPI(void) cveVariationalRefinementSetFixedPointIterations(cv::VariationalRefinement* obj, int value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveVariationalRefinementSetFixedPointIterations", "ptr", $obj, "int", $value), "cveVariationalRefinementSetFixedPointIterations", @error)
EndFunc   ;==>_cveVariationalRefinementSetFixedPointIterations

Func _cveVariationalRefinementGetSorIterations(ByRef $obj)
    ; CVAPI(int) cveVariationalRefinementGetSorIterations(cv::VariationalRefinement* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveVariationalRefinementGetSorIterations", "ptr", $obj), "cveVariationalRefinementGetSorIterations", @error)
EndFunc   ;==>_cveVariationalRefinementGetSorIterations

Func _cveVariationalRefinementSetSorIterations(ByRef $obj, $value)
    ; CVAPI(void) cveVariationalRefinementSetSorIterations(cv::VariationalRefinement* obj, int value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveVariationalRefinementSetSorIterations", "ptr", $obj, "int", $value), "cveVariationalRefinementSetSorIterations", @error)
EndFunc   ;==>_cveVariationalRefinementSetSorIterations

Func _cveVariationalRefinementGetOmega(ByRef $obj)
    ; CVAPI(float) cveVariationalRefinementGetOmega(cv::VariationalRefinement* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cveVariationalRefinementGetOmega", "ptr", $obj), "cveVariationalRefinementGetOmega", @error)
EndFunc   ;==>_cveVariationalRefinementGetOmega

Func _cveVariationalRefinementSetOmega(ByRef $obj, $value)
    ; CVAPI(void) cveVariationalRefinementSetOmega(cv::VariationalRefinement* obj, float value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveVariationalRefinementSetOmega", "ptr", $obj, "float", $value), "cveVariationalRefinementSetOmega", @error)
EndFunc   ;==>_cveVariationalRefinementSetOmega

Func _cveVariationalRefinementGetAlpha(ByRef $obj)
    ; CVAPI(float) cveVariationalRefinementGetAlpha(cv::VariationalRefinement* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cveVariationalRefinementGetAlpha", "ptr", $obj), "cveVariationalRefinementGetAlpha", @error)
EndFunc   ;==>_cveVariationalRefinementGetAlpha

Func _cveVariationalRefinementSetAlpha(ByRef $obj, $value)
    ; CVAPI(void) cveVariationalRefinementSetAlpha(cv::VariationalRefinement* obj, float value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveVariationalRefinementSetAlpha", "ptr", $obj, "float", $value), "cveVariationalRefinementSetAlpha", @error)
EndFunc   ;==>_cveVariationalRefinementSetAlpha

Func _cveVariationalRefinementGetDelta(ByRef $obj)
    ; CVAPI(float) cveVariationalRefinementGetDelta(cv::VariationalRefinement* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cveVariationalRefinementGetDelta", "ptr", $obj), "cveVariationalRefinementGetDelta", @error)
EndFunc   ;==>_cveVariationalRefinementGetDelta

Func _cveVariationalRefinementSetDelta(ByRef $obj, $value)
    ; CVAPI(void) cveVariationalRefinementSetDelta(cv::VariationalRefinement* obj, float value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveVariationalRefinementSetDelta", "ptr", $obj, "float", $value), "cveVariationalRefinementSetDelta", @error)
EndFunc   ;==>_cveVariationalRefinementSetDelta

Func _cveVariationalRefinementGetGamma(ByRef $obj)
    ; CVAPI(float) cveVariationalRefinementGetGamma(cv::VariationalRefinement* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cveVariationalRefinementGetGamma", "ptr", $obj), "cveVariationalRefinementGetGamma", @error)
EndFunc   ;==>_cveVariationalRefinementGetGamma

Func _cveVariationalRefinementSetGamma(ByRef $obj, $value)
    ; CVAPI(void) cveVariationalRefinementSetGamma(cv::VariationalRefinement* obj, float value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveVariationalRefinementSetGamma", "ptr", $obj, "float", $value), "cveVariationalRefinementSetGamma", @error)
EndFunc   ;==>_cveVariationalRefinementSetGamma