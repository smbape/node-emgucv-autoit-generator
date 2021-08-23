#include-once
#include "..\..\CVEUtils.au3"

Func _cveSVMSGDGetType($obj)
    ; CVAPI(int) cveSVMSGDGetType(cv::ml::SVMSGD* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveSVMSGDGetType", $sObjDllType, $obj), "cveSVMSGDGetType", @error)
EndFunc   ;==>_cveSVMSGDGetType

Func _cveSVMSGDSetType($obj, $value)
    ; CVAPI(void) cveSVMSGDSetType(cv::ml::SVMSGD* obj, int value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSVMSGDSetType", $sObjDllType, $obj, "int", $value), "cveSVMSGDSetType", @error)
EndFunc   ;==>_cveSVMSGDSetType

Func _cveSVMSGDGetMargin($obj)
    ; CVAPI(int) cveSVMSGDGetMargin(cv::ml::SVMSGD* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveSVMSGDGetMargin", $sObjDllType, $obj), "cveSVMSGDGetMargin", @error)
EndFunc   ;==>_cveSVMSGDGetMargin

Func _cveSVMSGDSetMargin($obj, $value)
    ; CVAPI(void) cveSVMSGDSetMargin(cv::ml::SVMSGD* obj, int value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSVMSGDSetMargin", $sObjDllType, $obj, "int", $value), "cveSVMSGDSetMargin", @error)
EndFunc   ;==>_cveSVMSGDSetMargin

Func _cveSVMSGDGetMarginRegularization($obj)
    ; CVAPI(float) cveSVMSGDGetMarginRegularization(cv::ml::SVMSGD* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cveSVMSGDGetMarginRegularization", $sObjDllType, $obj), "cveSVMSGDGetMarginRegularization", @error)
EndFunc   ;==>_cveSVMSGDGetMarginRegularization

Func _cveSVMSGDSetMarginRegularization($obj, $value)
    ; CVAPI(void) cveSVMSGDSetMarginRegularization(cv::ml::SVMSGD* obj, float value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSVMSGDSetMarginRegularization", $sObjDllType, $obj, "float", $value), "cveSVMSGDSetMarginRegularization", @error)
EndFunc   ;==>_cveSVMSGDSetMarginRegularization

Func _cveSVMSGDGetInitialStepSize($obj)
    ; CVAPI(float) cveSVMSGDGetInitialStepSize(cv::ml::SVMSGD* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cveSVMSGDGetInitialStepSize", $sObjDllType, $obj), "cveSVMSGDGetInitialStepSize", @error)
EndFunc   ;==>_cveSVMSGDGetInitialStepSize

Func _cveSVMSGDSetInitialStepSize($obj, $value)
    ; CVAPI(void) cveSVMSGDSetInitialStepSize(cv::ml::SVMSGD* obj, float value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSVMSGDSetInitialStepSize", $sObjDllType, $obj, "float", $value), "cveSVMSGDSetInitialStepSize", @error)
EndFunc   ;==>_cveSVMSGDSetInitialStepSize

Func _cveSVMSGDGetStepDecreasingPower($obj)
    ; CVAPI(float) cveSVMSGDGetStepDecreasingPower(cv::ml::SVMSGD* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cveSVMSGDGetStepDecreasingPower", $sObjDllType, $obj), "cveSVMSGDGetStepDecreasingPower", @error)
EndFunc   ;==>_cveSVMSGDGetStepDecreasingPower

Func _cveSVMSGDSetStepDecreasingPower($obj, $value)
    ; CVAPI(void) cveSVMSGDSetStepDecreasingPower(cv::ml::SVMSGD* obj, float value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSVMSGDSetStepDecreasingPower", $sObjDllType, $obj, "float", $value), "cveSVMSGDSetStepDecreasingPower", @error)
EndFunc   ;==>_cveSVMSGDSetStepDecreasingPower

Func _cveSVMSGDGetTermCriteria($obj, $value)
    ; CVAPI(void) cveSVMSGDGetTermCriteria(cv::ml::SVMSGD* obj, CvTermCriteria* value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    Local $sValueDllType
    If IsDllStruct($value) Then
        $sValueDllType = "struct*"
    Else
        $sValueDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSVMSGDGetTermCriteria", $sObjDllType, $obj, $sValueDllType, $value), "cveSVMSGDGetTermCriteria", @error)
EndFunc   ;==>_cveSVMSGDGetTermCriteria

Func _cveSVMSGDSetTermCriteria($obj, $value)
    ; CVAPI(void) cveSVMSGDSetTermCriteria(cv::ml::SVMSGD* obj, CvTermCriteria* value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    Local $sValueDllType
    If IsDllStruct($value) Then
        $sValueDllType = "struct*"
    Else
        $sValueDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSVMSGDSetTermCriteria", $sObjDllType, $obj, $sValueDllType, $value), "cveSVMSGDSetTermCriteria", @error)
EndFunc   ;==>_cveSVMSGDSetTermCriteria