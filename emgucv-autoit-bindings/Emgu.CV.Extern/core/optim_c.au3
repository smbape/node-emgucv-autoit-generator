#include-once
#include "..\..\CVEUtils.au3"

Func _cveSolveLP($Func, $Constr, ByRef $z)
    ; CVAPI(int) cveSolveLP(const cv::Mat* Func, const cv::Mat* Constr, cv::Mat* z);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveSolveLP", "ptr", $Func, "ptr", $Constr, "ptr", $z), "cveSolveLP", @error)
EndFunc   ;==>_cveSolveLP