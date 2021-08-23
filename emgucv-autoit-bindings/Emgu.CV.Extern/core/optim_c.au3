#include-once
#include "..\..\CVEUtils.au3"

Func _cveSolveLP($Func, $Constr, $z)
    ; CVAPI(int) cveSolveLP(const cv::Mat* Func, const cv::Mat* Constr, cv::Mat* z);

    Local $sFuncDllType
    If IsDllStruct($Func) Then
        $sFuncDllType = "struct*"
    Else
        $sFuncDllType = "ptr"
    EndIf

    Local $sConstrDllType
    If IsDllStruct($Constr) Then
        $sConstrDllType = "struct*"
    Else
        $sConstrDllType = "ptr"
    EndIf

    Local $sZDllType
    If IsDllStruct($z) Then
        $sZDllType = "struct*"
    Else
        $sZDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveSolveLP", $sFuncDllType, $Func, $sConstrDllType, $Constr, $sZDllType, $z), "cveSolveLP", @error)
EndFunc   ;==>_cveSolveLP