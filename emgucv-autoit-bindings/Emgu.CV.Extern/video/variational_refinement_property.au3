#include-once
#include "..\..\CVEUtils.au3"

Func _cveVariationalRefinementGetFixedPointIterations($obj)
    ; CVAPI(int) cveVariationalRefinementGetFixedPointIterations(cv::VariationalRefinement* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveVariationalRefinementGetFixedPointIterations", $sObjDllType, $obj), "cveVariationalRefinementGetFixedPointIterations", @error)
EndFunc   ;==>_cveVariationalRefinementGetFixedPointIterations

Func _cveVariationalRefinementSetFixedPointIterations($obj, $value)
    ; CVAPI(void) cveVariationalRefinementSetFixedPointIterations(cv::VariationalRefinement* obj, int value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveVariationalRefinementSetFixedPointIterations", $sObjDllType, $obj, "int", $value), "cveVariationalRefinementSetFixedPointIterations", @error)
EndFunc   ;==>_cveVariationalRefinementSetFixedPointIterations

Func _cveVariationalRefinementGetSorIterations($obj)
    ; CVAPI(int) cveVariationalRefinementGetSorIterations(cv::VariationalRefinement* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveVariationalRefinementGetSorIterations", $sObjDllType, $obj), "cveVariationalRefinementGetSorIterations", @error)
EndFunc   ;==>_cveVariationalRefinementGetSorIterations

Func _cveVariationalRefinementSetSorIterations($obj, $value)
    ; CVAPI(void) cveVariationalRefinementSetSorIterations(cv::VariationalRefinement* obj, int value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveVariationalRefinementSetSorIterations", $sObjDllType, $obj, "int", $value), "cveVariationalRefinementSetSorIterations", @error)
EndFunc   ;==>_cveVariationalRefinementSetSorIterations

Func _cveVariationalRefinementGetOmega($obj)
    ; CVAPI(float) cveVariationalRefinementGetOmega(cv::VariationalRefinement* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cveVariationalRefinementGetOmega", $sObjDllType, $obj), "cveVariationalRefinementGetOmega", @error)
EndFunc   ;==>_cveVariationalRefinementGetOmega

Func _cveVariationalRefinementSetOmega($obj, $value)
    ; CVAPI(void) cveVariationalRefinementSetOmega(cv::VariationalRefinement* obj, float value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveVariationalRefinementSetOmega", $sObjDllType, $obj, "float", $value), "cveVariationalRefinementSetOmega", @error)
EndFunc   ;==>_cveVariationalRefinementSetOmega

Func _cveVariationalRefinementGetAlpha($obj)
    ; CVAPI(float) cveVariationalRefinementGetAlpha(cv::VariationalRefinement* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cveVariationalRefinementGetAlpha", $sObjDllType, $obj), "cveVariationalRefinementGetAlpha", @error)
EndFunc   ;==>_cveVariationalRefinementGetAlpha

Func _cveVariationalRefinementSetAlpha($obj, $value)
    ; CVAPI(void) cveVariationalRefinementSetAlpha(cv::VariationalRefinement* obj, float value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveVariationalRefinementSetAlpha", $sObjDllType, $obj, "float", $value), "cveVariationalRefinementSetAlpha", @error)
EndFunc   ;==>_cveVariationalRefinementSetAlpha

Func _cveVariationalRefinementGetDelta($obj)
    ; CVAPI(float) cveVariationalRefinementGetDelta(cv::VariationalRefinement* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cveVariationalRefinementGetDelta", $sObjDllType, $obj), "cveVariationalRefinementGetDelta", @error)
EndFunc   ;==>_cveVariationalRefinementGetDelta

Func _cveVariationalRefinementSetDelta($obj, $value)
    ; CVAPI(void) cveVariationalRefinementSetDelta(cv::VariationalRefinement* obj, float value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveVariationalRefinementSetDelta", $sObjDllType, $obj, "float", $value), "cveVariationalRefinementSetDelta", @error)
EndFunc   ;==>_cveVariationalRefinementSetDelta

Func _cveVariationalRefinementGetGamma($obj)
    ; CVAPI(float) cveVariationalRefinementGetGamma(cv::VariationalRefinement* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cveVariationalRefinementGetGamma", $sObjDllType, $obj), "cveVariationalRefinementGetGamma", @error)
EndFunc   ;==>_cveVariationalRefinementGetGamma

Func _cveVariationalRefinementSetGamma($obj, $value)
    ; CVAPI(void) cveVariationalRefinementSetGamma(cv::VariationalRefinement* obj, float value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveVariationalRefinementSetGamma", $sObjDllType, $obj, "float", $value), "cveVariationalRefinementSetGamma", @error)
EndFunc   ;==>_cveVariationalRefinementSetGamma