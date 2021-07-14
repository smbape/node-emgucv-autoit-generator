#include-once
#include <..\..\CVEUtils.au3>

Func _cveCCheckerGetTarget(ByRef $obj)
    ; CVAPI(cv::mcc::TYPECHART) cveCCheckerGetTarget(cv::mcc::CChecker* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "cv::mcc::TYPECHART:cdecl", "cveCCheckerGetTarget", "ptr", $obj), "cveCCheckerGetTarget", @error)
EndFunc   ;==>_cveCCheckerGetTarget

Func _cveCCheckerSetTarget(ByRef $obj, $value)
    ; CVAPI(void) cveCCheckerSetTarget(cv::mcc::CChecker* obj, cv::mcc::TYPECHART value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCCheckerSetTarget", "ptr", $obj, "cv::mcc::TYPECHART", $value), "cveCCheckerSetTarget", @error)
EndFunc   ;==>_cveCCheckerSetTarget

Func _cveCCheckerGetCost(ByRef $obj)
    ; CVAPI(float) cveCCheckerGetCost(cv::mcc::CChecker* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cveCCheckerGetCost", "ptr", $obj), "cveCCheckerGetCost", @error)
EndFunc   ;==>_cveCCheckerGetCost

Func _cveCCheckerSetCost(ByRef $obj, $value)
    ; CVAPI(void) cveCCheckerSetCost(cv::mcc::CChecker* obj, float value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCCheckerSetCost", "ptr", $obj, "float", $value), "cveCCheckerSetCost", @error)
EndFunc   ;==>_cveCCheckerSetCost