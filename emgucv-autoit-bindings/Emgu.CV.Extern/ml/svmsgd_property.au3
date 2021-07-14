#include-once
#include "..\..\CVEUtils.au3"

Func _cveSVMSGDGetType(ByRef $obj)
    ; CVAPI(int) cveSVMSGDGetType(cv::ml::SVMSGD* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveSVMSGDGetType", "ptr", $obj), "cveSVMSGDGetType", @error)
EndFunc   ;==>_cveSVMSGDGetType

Func _cveSVMSGDSetType(ByRef $obj, $value)
    ; CVAPI(void) cveSVMSGDSetType(cv::ml::SVMSGD* obj, int value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSVMSGDSetType", "ptr", $obj, "int", $value), "cveSVMSGDSetType", @error)
EndFunc   ;==>_cveSVMSGDSetType

Func _cveSVMSGDGetMargin(ByRef $obj)
    ; CVAPI(int) cveSVMSGDGetMargin(cv::ml::SVMSGD* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveSVMSGDGetMargin", "ptr", $obj), "cveSVMSGDGetMargin", @error)
EndFunc   ;==>_cveSVMSGDGetMargin

Func _cveSVMSGDSetMargin(ByRef $obj, $value)
    ; CVAPI(void) cveSVMSGDSetMargin(cv::ml::SVMSGD* obj, int value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSVMSGDSetMargin", "ptr", $obj, "int", $value), "cveSVMSGDSetMargin", @error)
EndFunc   ;==>_cveSVMSGDSetMargin

Func _cveSVMSGDGetMarginRegularization(ByRef $obj)
    ; CVAPI(float) cveSVMSGDGetMarginRegularization(cv::ml::SVMSGD* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cveSVMSGDGetMarginRegularization", "ptr", $obj), "cveSVMSGDGetMarginRegularization", @error)
EndFunc   ;==>_cveSVMSGDGetMarginRegularization

Func _cveSVMSGDSetMarginRegularization(ByRef $obj, $value)
    ; CVAPI(void) cveSVMSGDSetMarginRegularization(cv::ml::SVMSGD* obj, float value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSVMSGDSetMarginRegularization", "ptr", $obj, "float", $value), "cveSVMSGDSetMarginRegularization", @error)
EndFunc   ;==>_cveSVMSGDSetMarginRegularization

Func _cveSVMSGDGetInitialStepSize(ByRef $obj)
    ; CVAPI(float) cveSVMSGDGetInitialStepSize(cv::ml::SVMSGD* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cveSVMSGDGetInitialStepSize", "ptr", $obj), "cveSVMSGDGetInitialStepSize", @error)
EndFunc   ;==>_cveSVMSGDGetInitialStepSize

Func _cveSVMSGDSetInitialStepSize(ByRef $obj, $value)
    ; CVAPI(void) cveSVMSGDSetInitialStepSize(cv::ml::SVMSGD* obj, float value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSVMSGDSetInitialStepSize", "ptr", $obj, "float", $value), "cveSVMSGDSetInitialStepSize", @error)
EndFunc   ;==>_cveSVMSGDSetInitialStepSize

Func _cveSVMSGDGetStepDecreasingPower(ByRef $obj)
    ; CVAPI(float) cveSVMSGDGetStepDecreasingPower(cv::ml::SVMSGD* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cveSVMSGDGetStepDecreasingPower", "ptr", $obj), "cveSVMSGDGetStepDecreasingPower", @error)
EndFunc   ;==>_cveSVMSGDGetStepDecreasingPower

Func _cveSVMSGDSetStepDecreasingPower(ByRef $obj, $value)
    ; CVAPI(void) cveSVMSGDSetStepDecreasingPower(cv::ml::SVMSGD* obj, float value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSVMSGDSetStepDecreasingPower", "ptr", $obj, "float", $value), "cveSVMSGDSetStepDecreasingPower", @error)
EndFunc   ;==>_cveSVMSGDSetStepDecreasingPower

Func _cveSVMSGDGetTermCriteria(ByRef $obj, ByRef $value)
    ; CVAPI(void) cveSVMSGDGetTermCriteria(cv::ml::SVMSGD* obj, CvTermCriteria* value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSVMSGDGetTermCriteria", "ptr", $obj, "struct*", $value), "cveSVMSGDGetTermCriteria", @error)
EndFunc   ;==>_cveSVMSGDGetTermCriteria

Func _cveSVMSGDSetTermCriteria(ByRef $obj, ByRef $value)
    ; CVAPI(void) cveSVMSGDSetTermCriteria(cv::ml::SVMSGD* obj, CvTermCriteria* value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSVMSGDSetTermCriteria", "ptr", $obj, "struct*", $value), "cveSVMSGDSetTermCriteria", @error)
EndFunc   ;==>_cveSVMSGDSetTermCriteria