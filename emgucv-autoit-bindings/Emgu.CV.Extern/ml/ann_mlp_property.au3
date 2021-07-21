#include-once
#include "..\..\CVEUtils.au3"

Func _cveANN_MLPGetTermCriteria($obj, $value)
    ; CVAPI(void) cveANN_MLPGetTermCriteria(cv::ml::ANN_MLP* obj, CvTermCriteria* value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    Local $bValueDllType
    If VarGetType($value) == "DLLStruct" Then
        $bValueDllType = "struct*"
    Else
        $bValueDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveANN_MLPGetTermCriteria", $bObjDllType, $obj, $bValueDllType, $value), "cveANN_MLPGetTermCriteria", @error)
EndFunc   ;==>_cveANN_MLPGetTermCriteria

Func _cveANN_MLPSetTermCriteria($obj, $value)
    ; CVAPI(void) cveANN_MLPSetTermCriteria(cv::ml::ANN_MLP* obj, CvTermCriteria* value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    Local $bValueDllType
    If VarGetType($value) == "DLLStruct" Then
        $bValueDllType = "struct*"
    Else
        $bValueDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveANN_MLPSetTermCriteria", $bObjDllType, $obj, $bValueDllType, $value), "cveANN_MLPSetTermCriteria", @error)
EndFunc   ;==>_cveANN_MLPSetTermCriteria

Func _cveANN_MLPGetBackpropWeightScale($obj)
    ; CVAPI(double) cveANN_MLPGetBackpropWeightScale(cv::ml::ANN_MLP* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveANN_MLPGetBackpropWeightScale", $bObjDllType, $obj), "cveANN_MLPGetBackpropWeightScale", @error)
EndFunc   ;==>_cveANN_MLPGetBackpropWeightScale

Func _cveANN_MLPSetBackpropWeightScale($obj, $value)
    ; CVAPI(void) cveANN_MLPSetBackpropWeightScale(cv::ml::ANN_MLP* obj, double value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveANN_MLPSetBackpropWeightScale", $bObjDllType, $obj, "double", $value), "cveANN_MLPSetBackpropWeightScale", @error)
EndFunc   ;==>_cveANN_MLPSetBackpropWeightScale

Func _cveANN_MLPGetBackpropMomentumScale($obj)
    ; CVAPI(double) cveANN_MLPGetBackpropMomentumScale(cv::ml::ANN_MLP* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveANN_MLPGetBackpropMomentumScale", $bObjDllType, $obj), "cveANN_MLPGetBackpropMomentumScale", @error)
EndFunc   ;==>_cveANN_MLPGetBackpropMomentumScale

Func _cveANN_MLPSetBackpropMomentumScale($obj, $value)
    ; CVAPI(void) cveANN_MLPSetBackpropMomentumScale(cv::ml::ANN_MLP* obj, double value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveANN_MLPSetBackpropMomentumScale", $bObjDllType, $obj, "double", $value), "cveANN_MLPSetBackpropMomentumScale", @error)
EndFunc   ;==>_cveANN_MLPSetBackpropMomentumScale

Func _cveANN_MLPGetRpropDW0($obj)
    ; CVAPI(double) cveANN_MLPGetRpropDW0(cv::ml::ANN_MLP* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveANN_MLPGetRpropDW0", $bObjDllType, $obj), "cveANN_MLPGetRpropDW0", @error)
EndFunc   ;==>_cveANN_MLPGetRpropDW0

Func _cveANN_MLPSetRpropDW0($obj, $value)
    ; CVAPI(void) cveANN_MLPSetRpropDW0(cv::ml::ANN_MLP* obj, double value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveANN_MLPSetRpropDW0", $bObjDllType, $obj, "double", $value), "cveANN_MLPSetRpropDW0", @error)
EndFunc   ;==>_cveANN_MLPSetRpropDW0

Func _cveANN_MLPGetRpropDWPlus($obj)
    ; CVAPI(double) cveANN_MLPGetRpropDWPlus(cv::ml::ANN_MLP* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveANN_MLPGetRpropDWPlus", $bObjDllType, $obj), "cveANN_MLPGetRpropDWPlus", @error)
EndFunc   ;==>_cveANN_MLPGetRpropDWPlus

Func _cveANN_MLPSetRpropDWPlus($obj, $value)
    ; CVAPI(void) cveANN_MLPSetRpropDWPlus(cv::ml::ANN_MLP* obj, double value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveANN_MLPSetRpropDWPlus", $bObjDllType, $obj, "double", $value), "cveANN_MLPSetRpropDWPlus", @error)
EndFunc   ;==>_cveANN_MLPSetRpropDWPlus

Func _cveANN_MLPGetRpropDWMinus($obj)
    ; CVAPI(double) cveANN_MLPGetRpropDWMinus(cv::ml::ANN_MLP* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveANN_MLPGetRpropDWMinus", $bObjDllType, $obj), "cveANN_MLPGetRpropDWMinus", @error)
EndFunc   ;==>_cveANN_MLPGetRpropDWMinus

Func _cveANN_MLPSetRpropDWMinus($obj, $value)
    ; CVAPI(void) cveANN_MLPSetRpropDWMinus(cv::ml::ANN_MLP* obj, double value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveANN_MLPSetRpropDWMinus", $bObjDllType, $obj, "double", $value), "cveANN_MLPSetRpropDWMinus", @error)
EndFunc   ;==>_cveANN_MLPSetRpropDWMinus

Func _cveANN_MLPGetRpropDWMin($obj)
    ; CVAPI(double) cveANN_MLPGetRpropDWMin(cv::ml::ANN_MLP* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveANN_MLPGetRpropDWMin", $bObjDllType, $obj), "cveANN_MLPGetRpropDWMin", @error)
EndFunc   ;==>_cveANN_MLPGetRpropDWMin

Func _cveANN_MLPSetRpropDWMin($obj, $value)
    ; CVAPI(void) cveANN_MLPSetRpropDWMin(cv::ml::ANN_MLP* obj, double value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveANN_MLPSetRpropDWMin", $bObjDllType, $obj, "double", $value), "cveANN_MLPSetRpropDWMin", @error)
EndFunc   ;==>_cveANN_MLPSetRpropDWMin

Func _cveANN_MLPGetRpropDWMax($obj)
    ; CVAPI(double) cveANN_MLPGetRpropDWMax(cv::ml::ANN_MLP* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveANN_MLPGetRpropDWMax", $bObjDllType, $obj), "cveANN_MLPGetRpropDWMax", @error)
EndFunc   ;==>_cveANN_MLPGetRpropDWMax

Func _cveANN_MLPSetRpropDWMax($obj, $value)
    ; CVAPI(void) cveANN_MLPSetRpropDWMax(cv::ml::ANN_MLP* obj, double value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveANN_MLPSetRpropDWMax", $bObjDllType, $obj, "double", $value), "cveANN_MLPSetRpropDWMax", @error)
EndFunc   ;==>_cveANN_MLPSetRpropDWMax

Func _cveANN_MLPGetAnnealInitialT($obj)
    ; CVAPI(double) cveANN_MLPGetAnnealInitialT(cv::ml::ANN_MLP* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveANN_MLPGetAnnealInitialT", $bObjDllType, $obj), "cveANN_MLPGetAnnealInitialT", @error)
EndFunc   ;==>_cveANN_MLPGetAnnealInitialT

Func _cveANN_MLPSetAnnealInitialT($obj, $value)
    ; CVAPI(void) cveANN_MLPSetAnnealInitialT(cv::ml::ANN_MLP* obj, double value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveANN_MLPSetAnnealInitialT", $bObjDllType, $obj, "double", $value), "cveANN_MLPSetAnnealInitialT", @error)
EndFunc   ;==>_cveANN_MLPSetAnnealInitialT

Func _cveANN_MLPGetAnnealFinalT($obj)
    ; CVAPI(double) cveANN_MLPGetAnnealFinalT(cv::ml::ANN_MLP* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveANN_MLPGetAnnealFinalT", $bObjDllType, $obj), "cveANN_MLPGetAnnealFinalT", @error)
EndFunc   ;==>_cveANN_MLPGetAnnealFinalT

Func _cveANN_MLPSetAnnealFinalT($obj, $value)
    ; CVAPI(void) cveANN_MLPSetAnnealFinalT(cv::ml::ANN_MLP* obj, double value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveANN_MLPSetAnnealFinalT", $bObjDllType, $obj, "double", $value), "cveANN_MLPSetAnnealFinalT", @error)
EndFunc   ;==>_cveANN_MLPSetAnnealFinalT

Func _cveANN_MLPGetAnnealCoolingRatio($obj)
    ; CVAPI(double) cveANN_MLPGetAnnealCoolingRatio(cv::ml::ANN_MLP* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveANN_MLPGetAnnealCoolingRatio", $bObjDllType, $obj), "cveANN_MLPGetAnnealCoolingRatio", @error)
EndFunc   ;==>_cveANN_MLPGetAnnealCoolingRatio

Func _cveANN_MLPSetAnnealCoolingRatio($obj, $value)
    ; CVAPI(void) cveANN_MLPSetAnnealCoolingRatio(cv::ml::ANN_MLP* obj, double value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveANN_MLPSetAnnealCoolingRatio", $bObjDllType, $obj, "double", $value), "cveANN_MLPSetAnnealCoolingRatio", @error)
EndFunc   ;==>_cveANN_MLPSetAnnealCoolingRatio

Func _cveANN_MLPGetAnnealItePerStep($obj)
    ; CVAPI(int) cveANN_MLPGetAnnealItePerStep(cv::ml::ANN_MLP* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveANN_MLPGetAnnealItePerStep", $bObjDllType, $obj), "cveANN_MLPGetAnnealItePerStep", @error)
EndFunc   ;==>_cveANN_MLPGetAnnealItePerStep

Func _cveANN_MLPSetAnnealItePerStep($obj, $value)
    ; CVAPI(void) cveANN_MLPSetAnnealItePerStep(cv::ml::ANN_MLP* obj, int value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveANN_MLPSetAnnealItePerStep", $bObjDllType, $obj, "int", $value), "cveANN_MLPSetAnnealItePerStep", @error)
EndFunc   ;==>_cveANN_MLPSetAnnealItePerStep