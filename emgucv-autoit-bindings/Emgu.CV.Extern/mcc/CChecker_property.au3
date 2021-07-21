#include-once
#include "..\..\CVEUtils.au3"

Func _cveCCheckerGetTarget($obj)
    ; CVAPI(cv::mcc::TYPECHART) cveCCheckerGetTarget(cv::mcc::CChecker* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "cv::mcc::TYPECHART:cdecl", "cveCCheckerGetTarget", $bObjDllType, $obj), "cveCCheckerGetTarget", @error)
EndFunc   ;==>_cveCCheckerGetTarget

Func _cveCCheckerSetTarget($obj, $value)
    ; CVAPI(void) cveCCheckerSetTarget(cv::mcc::CChecker* obj, cv::mcc::TYPECHART value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCCheckerSetTarget", $bObjDllType, $obj, "cv::mcc::TYPECHART", $value), "cveCCheckerSetTarget", @error)
EndFunc   ;==>_cveCCheckerSetTarget

Func _cveCCheckerGetCost($obj)
    ; CVAPI(float) cveCCheckerGetCost(cv::mcc::CChecker* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cveCCheckerGetCost", $bObjDllType, $obj), "cveCCheckerGetCost", @error)
EndFunc   ;==>_cveCCheckerGetCost

Func _cveCCheckerSetCost($obj, $value)
    ; CVAPI(void) cveCCheckerSetCost(cv::mcc::CChecker* obj, float value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCCheckerSetCost", $bObjDllType, $obj, "float", $value), "cveCCheckerSetCost", @error)
EndFunc   ;==>_cveCCheckerSetCost