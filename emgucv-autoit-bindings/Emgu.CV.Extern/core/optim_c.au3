#include-once
#include "..\..\CVEUtils.au3"

Func _cveSolveLP($Func, $Constr, $z)
    ; CVAPI(int) cveSolveLP(const cv::Mat* Func, const cv::Mat* Constr, cv::Mat* z);

    Local $bFuncDllType
    If VarGetType($Func) == "DLLStruct" Then
        $bFuncDllType = "struct*"
    Else
        $bFuncDllType = "ptr"
    EndIf

    Local $bConstrDllType
    If VarGetType($Constr) == "DLLStruct" Then
        $bConstrDllType = "struct*"
    Else
        $bConstrDllType = "ptr"
    EndIf

    Local $bZDllType
    If VarGetType($z) == "DLLStruct" Then
        $bZDllType = "struct*"
    Else
        $bZDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveSolveLP", $bFuncDllType, $Func, $bConstrDllType, $Constr, $bZDllType, $z), "cveSolveLP", @error)
EndFunc   ;==>_cveSolveLP