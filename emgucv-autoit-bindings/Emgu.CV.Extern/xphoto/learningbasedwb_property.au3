#include-once
#include "..\..\CVEUtils.au3"

Func _cveLearningBasedWBGetRangeMaxVal($obj)
    ; CVAPI(int) cveLearningBasedWBGetRangeMaxVal(cv::xphoto::LearningBasedWB* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveLearningBasedWBGetRangeMaxVal", $bObjDllType, $obj), "cveLearningBasedWBGetRangeMaxVal", @error)
EndFunc   ;==>_cveLearningBasedWBGetRangeMaxVal

Func _cveLearningBasedWBSetRangeMaxVal($obj, $value)
    ; CVAPI(void) cveLearningBasedWBSetRangeMaxVal(cv::xphoto::LearningBasedWB* obj, int value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveLearningBasedWBSetRangeMaxVal", $bObjDllType, $obj, "int", $value), "cveLearningBasedWBSetRangeMaxVal", @error)
EndFunc   ;==>_cveLearningBasedWBSetRangeMaxVal

Func _cveLearningBasedWBGetSaturationThreshold($obj)
    ; CVAPI(float) cveLearningBasedWBGetSaturationThreshold(cv::xphoto::LearningBasedWB* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cveLearningBasedWBGetSaturationThreshold", $bObjDllType, $obj), "cveLearningBasedWBGetSaturationThreshold", @error)
EndFunc   ;==>_cveLearningBasedWBGetSaturationThreshold

Func _cveLearningBasedWBSetSaturationThreshold($obj, $value)
    ; CVAPI(void) cveLearningBasedWBSetSaturationThreshold(cv::xphoto::LearningBasedWB* obj, float value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveLearningBasedWBSetSaturationThreshold", $bObjDllType, $obj, "float", $value), "cveLearningBasedWBSetSaturationThreshold", @error)
EndFunc   ;==>_cveLearningBasedWBSetSaturationThreshold

Func _cveLearningBasedWBGetHistBinNum($obj)
    ; CVAPI(int) cveLearningBasedWBGetHistBinNum(cv::xphoto::LearningBasedWB* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveLearningBasedWBGetHistBinNum", $bObjDllType, $obj), "cveLearningBasedWBGetHistBinNum", @error)
EndFunc   ;==>_cveLearningBasedWBGetHistBinNum

Func _cveLearningBasedWBSetHistBinNum($obj, $value)
    ; CVAPI(void) cveLearningBasedWBSetHistBinNum(cv::xphoto::LearningBasedWB* obj, int value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveLearningBasedWBSetHistBinNum", $bObjDllType, $obj, "int", $value), "cveLearningBasedWBSetHistBinNum", @error)
EndFunc   ;==>_cveLearningBasedWBSetHistBinNum