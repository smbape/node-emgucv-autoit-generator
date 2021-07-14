#include-once
#include "..\..\CVEUtils.au3"

Func _cveANN_MLPGetTermCriteria(ByRef $obj, ByRef $value)
    ; CVAPI(void) cveANN_MLPGetTermCriteria(cv::ml::ANN_MLP* obj, CvTermCriteria* value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveANN_MLPGetTermCriteria", "ptr", $obj, "struct*", $value), "cveANN_MLPGetTermCriteria", @error)
EndFunc   ;==>_cveANN_MLPGetTermCriteria

Func _cveANN_MLPSetTermCriteria(ByRef $obj, ByRef $value)
    ; CVAPI(void) cveANN_MLPSetTermCriteria(cv::ml::ANN_MLP* obj, CvTermCriteria* value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveANN_MLPSetTermCriteria", "ptr", $obj, "struct*", $value), "cveANN_MLPSetTermCriteria", @error)
EndFunc   ;==>_cveANN_MLPSetTermCriteria

Func _cveANN_MLPGetBackpropWeightScale(ByRef $obj)
    ; CVAPI(double) cveANN_MLPGetBackpropWeightScale(cv::ml::ANN_MLP* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveANN_MLPGetBackpropWeightScale", "ptr", $obj), "cveANN_MLPGetBackpropWeightScale", @error)
EndFunc   ;==>_cveANN_MLPGetBackpropWeightScale

Func _cveANN_MLPSetBackpropWeightScale(ByRef $obj, $value)
    ; CVAPI(void) cveANN_MLPSetBackpropWeightScale(cv::ml::ANN_MLP* obj, double value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveANN_MLPSetBackpropWeightScale", "ptr", $obj, "double", $value), "cveANN_MLPSetBackpropWeightScale", @error)
EndFunc   ;==>_cveANN_MLPSetBackpropWeightScale

Func _cveANN_MLPGetBackpropMomentumScale(ByRef $obj)
    ; CVAPI(double) cveANN_MLPGetBackpropMomentumScale(cv::ml::ANN_MLP* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveANN_MLPGetBackpropMomentumScale", "ptr", $obj), "cveANN_MLPGetBackpropMomentumScale", @error)
EndFunc   ;==>_cveANN_MLPGetBackpropMomentumScale

Func _cveANN_MLPSetBackpropMomentumScale(ByRef $obj, $value)
    ; CVAPI(void) cveANN_MLPSetBackpropMomentumScale(cv::ml::ANN_MLP* obj, double value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveANN_MLPSetBackpropMomentumScale", "ptr", $obj, "double", $value), "cveANN_MLPSetBackpropMomentumScale", @error)
EndFunc   ;==>_cveANN_MLPSetBackpropMomentumScale

Func _cveANN_MLPGetRpropDW0(ByRef $obj)
    ; CVAPI(double) cveANN_MLPGetRpropDW0(cv::ml::ANN_MLP* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveANN_MLPGetRpropDW0", "ptr", $obj), "cveANN_MLPGetRpropDW0", @error)
EndFunc   ;==>_cveANN_MLPGetRpropDW0

Func _cveANN_MLPSetRpropDW0(ByRef $obj, $value)
    ; CVAPI(void) cveANN_MLPSetRpropDW0(cv::ml::ANN_MLP* obj, double value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveANN_MLPSetRpropDW0", "ptr", $obj, "double", $value), "cveANN_MLPSetRpropDW0", @error)
EndFunc   ;==>_cveANN_MLPSetRpropDW0

Func _cveANN_MLPGetRpropDWPlus(ByRef $obj)
    ; CVAPI(double) cveANN_MLPGetRpropDWPlus(cv::ml::ANN_MLP* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveANN_MLPGetRpropDWPlus", "ptr", $obj), "cveANN_MLPGetRpropDWPlus", @error)
EndFunc   ;==>_cveANN_MLPGetRpropDWPlus

Func _cveANN_MLPSetRpropDWPlus(ByRef $obj, $value)
    ; CVAPI(void) cveANN_MLPSetRpropDWPlus(cv::ml::ANN_MLP* obj, double value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveANN_MLPSetRpropDWPlus", "ptr", $obj, "double", $value), "cveANN_MLPSetRpropDWPlus", @error)
EndFunc   ;==>_cveANN_MLPSetRpropDWPlus

Func _cveANN_MLPGetRpropDWMinus(ByRef $obj)
    ; CVAPI(double) cveANN_MLPGetRpropDWMinus(cv::ml::ANN_MLP* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveANN_MLPGetRpropDWMinus", "ptr", $obj), "cveANN_MLPGetRpropDWMinus", @error)
EndFunc   ;==>_cveANN_MLPGetRpropDWMinus

Func _cveANN_MLPSetRpropDWMinus(ByRef $obj, $value)
    ; CVAPI(void) cveANN_MLPSetRpropDWMinus(cv::ml::ANN_MLP* obj, double value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveANN_MLPSetRpropDWMinus", "ptr", $obj, "double", $value), "cveANN_MLPSetRpropDWMinus", @error)
EndFunc   ;==>_cveANN_MLPSetRpropDWMinus

Func _cveANN_MLPGetRpropDWMin(ByRef $obj)
    ; CVAPI(double) cveANN_MLPGetRpropDWMin(cv::ml::ANN_MLP* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveANN_MLPGetRpropDWMin", "ptr", $obj), "cveANN_MLPGetRpropDWMin", @error)
EndFunc   ;==>_cveANN_MLPGetRpropDWMin

Func _cveANN_MLPSetRpropDWMin(ByRef $obj, $value)
    ; CVAPI(void) cveANN_MLPSetRpropDWMin(cv::ml::ANN_MLP* obj, double value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveANN_MLPSetRpropDWMin", "ptr", $obj, "double", $value), "cveANN_MLPSetRpropDWMin", @error)
EndFunc   ;==>_cveANN_MLPSetRpropDWMin

Func _cveANN_MLPGetRpropDWMax(ByRef $obj)
    ; CVAPI(double) cveANN_MLPGetRpropDWMax(cv::ml::ANN_MLP* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveANN_MLPGetRpropDWMax", "ptr", $obj), "cveANN_MLPGetRpropDWMax", @error)
EndFunc   ;==>_cveANN_MLPGetRpropDWMax

Func _cveANN_MLPSetRpropDWMax(ByRef $obj, $value)
    ; CVAPI(void) cveANN_MLPSetRpropDWMax(cv::ml::ANN_MLP* obj, double value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveANN_MLPSetRpropDWMax", "ptr", $obj, "double", $value), "cveANN_MLPSetRpropDWMax", @error)
EndFunc   ;==>_cveANN_MLPSetRpropDWMax

Func _cveANN_MLPGetAnnealInitialT(ByRef $obj)
    ; CVAPI(double) cveANN_MLPGetAnnealInitialT(cv::ml::ANN_MLP* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveANN_MLPGetAnnealInitialT", "ptr", $obj), "cveANN_MLPGetAnnealInitialT", @error)
EndFunc   ;==>_cveANN_MLPGetAnnealInitialT

Func _cveANN_MLPSetAnnealInitialT(ByRef $obj, $value)
    ; CVAPI(void) cveANN_MLPSetAnnealInitialT(cv::ml::ANN_MLP* obj, double value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveANN_MLPSetAnnealInitialT", "ptr", $obj, "double", $value), "cveANN_MLPSetAnnealInitialT", @error)
EndFunc   ;==>_cveANN_MLPSetAnnealInitialT

Func _cveANN_MLPGetAnnealFinalT(ByRef $obj)
    ; CVAPI(double) cveANN_MLPGetAnnealFinalT(cv::ml::ANN_MLP* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveANN_MLPGetAnnealFinalT", "ptr", $obj), "cveANN_MLPGetAnnealFinalT", @error)
EndFunc   ;==>_cveANN_MLPGetAnnealFinalT

Func _cveANN_MLPSetAnnealFinalT(ByRef $obj, $value)
    ; CVAPI(void) cveANN_MLPSetAnnealFinalT(cv::ml::ANN_MLP* obj, double value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveANN_MLPSetAnnealFinalT", "ptr", $obj, "double", $value), "cveANN_MLPSetAnnealFinalT", @error)
EndFunc   ;==>_cveANN_MLPSetAnnealFinalT

Func _cveANN_MLPGetAnnealCoolingRatio(ByRef $obj)
    ; CVAPI(double) cveANN_MLPGetAnnealCoolingRatio(cv::ml::ANN_MLP* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveANN_MLPGetAnnealCoolingRatio", "ptr", $obj), "cveANN_MLPGetAnnealCoolingRatio", @error)
EndFunc   ;==>_cveANN_MLPGetAnnealCoolingRatio

Func _cveANN_MLPSetAnnealCoolingRatio(ByRef $obj, $value)
    ; CVAPI(void) cveANN_MLPSetAnnealCoolingRatio(cv::ml::ANN_MLP* obj, double value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveANN_MLPSetAnnealCoolingRatio", "ptr", $obj, "double", $value), "cveANN_MLPSetAnnealCoolingRatio", @error)
EndFunc   ;==>_cveANN_MLPSetAnnealCoolingRatio

Func _cveANN_MLPGetAnnealItePerStep(ByRef $obj)
    ; CVAPI(int) cveANN_MLPGetAnnealItePerStep(cv::ml::ANN_MLP* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveANN_MLPGetAnnealItePerStep", "ptr", $obj), "cveANN_MLPGetAnnealItePerStep", @error)
EndFunc   ;==>_cveANN_MLPGetAnnealItePerStep

Func _cveANN_MLPSetAnnealItePerStep(ByRef $obj, $value)
    ; CVAPI(void) cveANN_MLPSetAnnealItePerStep(cv::ml::ANN_MLP* obj, int value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveANN_MLPSetAnnealItePerStep", "ptr", $obj, "int", $value), "cveANN_MLPSetAnnealItePerStep", @error)
EndFunc   ;==>_cveANN_MLPSetAnnealItePerStep