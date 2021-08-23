#include-once
#include "..\..\CVEUtils.au3"

Func _cveCCheckerGetTarget($obj)
    ; CVAPI(cv::mcc::TYPECHART) cveCCheckerGetTarget(cv::mcc::CChecker* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveCCheckerGetTarget", $sObjDllType, $obj), "cveCCheckerGetTarget", @error)
EndFunc   ;==>_cveCCheckerGetTarget

Func _cveCCheckerSetTarget($obj, $value)
    ; CVAPI(void) cveCCheckerSetTarget(cv::mcc::CChecker* obj, cv::mcc::TYPECHART value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCCheckerSetTarget", $sObjDllType, $obj, "int", $value), "cveCCheckerSetTarget", @error)
EndFunc   ;==>_cveCCheckerSetTarget

Func _cveCCheckerGetCost($obj)
    ; CVAPI(float) cveCCheckerGetCost(cv::mcc::CChecker* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cveCCheckerGetCost", $sObjDllType, $obj), "cveCCheckerGetCost", @error)
EndFunc   ;==>_cveCCheckerGetCost

Func _cveCCheckerSetCost($obj, $value)
    ; CVAPI(void) cveCCheckerSetCost(cv::mcc::CChecker* obj, float value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCCheckerSetCost", $sObjDllType, $obj, "float", $value), "cveCCheckerSetCost", @error)
EndFunc   ;==>_cveCCheckerSetCost