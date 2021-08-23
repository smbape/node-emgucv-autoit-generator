#include-once
#include "..\..\CVEUtils.au3"

Func _cveLearningBasedWBGetRangeMaxVal($obj)
    ; CVAPI(int) cveLearningBasedWBGetRangeMaxVal(cv::xphoto::LearningBasedWB* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveLearningBasedWBGetRangeMaxVal", $sObjDllType, $obj), "cveLearningBasedWBGetRangeMaxVal", @error)
EndFunc   ;==>_cveLearningBasedWBGetRangeMaxVal

Func _cveLearningBasedWBSetRangeMaxVal($obj, $value)
    ; CVAPI(void) cveLearningBasedWBSetRangeMaxVal(cv::xphoto::LearningBasedWB* obj, int value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveLearningBasedWBSetRangeMaxVal", $sObjDllType, $obj, "int", $value), "cveLearningBasedWBSetRangeMaxVal", @error)
EndFunc   ;==>_cveLearningBasedWBSetRangeMaxVal

Func _cveLearningBasedWBGetSaturationThreshold($obj)
    ; CVAPI(float) cveLearningBasedWBGetSaturationThreshold(cv::xphoto::LearningBasedWB* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cveLearningBasedWBGetSaturationThreshold", $sObjDllType, $obj), "cveLearningBasedWBGetSaturationThreshold", @error)
EndFunc   ;==>_cveLearningBasedWBGetSaturationThreshold

Func _cveLearningBasedWBSetSaturationThreshold($obj, $value)
    ; CVAPI(void) cveLearningBasedWBSetSaturationThreshold(cv::xphoto::LearningBasedWB* obj, float value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveLearningBasedWBSetSaturationThreshold", $sObjDllType, $obj, "float", $value), "cveLearningBasedWBSetSaturationThreshold", @error)
EndFunc   ;==>_cveLearningBasedWBSetSaturationThreshold

Func _cveLearningBasedWBGetHistBinNum($obj)
    ; CVAPI(int) cveLearningBasedWBGetHistBinNum(cv::xphoto::LearningBasedWB* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveLearningBasedWBGetHistBinNum", $sObjDllType, $obj), "cveLearningBasedWBGetHistBinNum", @error)
EndFunc   ;==>_cveLearningBasedWBGetHistBinNum

Func _cveLearningBasedWBSetHistBinNum($obj, $value)
    ; CVAPI(void) cveLearningBasedWBSetHistBinNum(cv::xphoto::LearningBasedWB* obj, int value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveLearningBasedWBSetHistBinNum", $sObjDllType, $obj, "int", $value), "cveLearningBasedWBSetHistBinNum", @error)
EndFunc   ;==>_cveLearningBasedWBSetHistBinNum