#include-once
#include <..\..\CVEUtils.au3>

Func _cveLearningBasedWBGetRangeMaxVal(ByRef $obj)
    ; CVAPI(int) cveLearningBasedWBGetRangeMaxVal(cv::xphoto::LearningBasedWB* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveLearningBasedWBGetRangeMaxVal", "ptr", $obj), "cveLearningBasedWBGetRangeMaxVal", @error)
EndFunc   ;==>_cveLearningBasedWBGetRangeMaxVal

Func _cveLearningBasedWBSetRangeMaxVal(ByRef $obj, $value)
    ; CVAPI(void) cveLearningBasedWBSetRangeMaxVal(cv::xphoto::LearningBasedWB* obj, int value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveLearningBasedWBSetRangeMaxVal", "ptr", $obj, "int", $value), "cveLearningBasedWBSetRangeMaxVal", @error)
EndFunc   ;==>_cveLearningBasedWBSetRangeMaxVal

Func _cveLearningBasedWBGetSaturationThreshold(ByRef $obj)
    ; CVAPI(float) cveLearningBasedWBGetSaturationThreshold(cv::xphoto::LearningBasedWB* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cveLearningBasedWBGetSaturationThreshold", "ptr", $obj), "cveLearningBasedWBGetSaturationThreshold", @error)
EndFunc   ;==>_cveLearningBasedWBGetSaturationThreshold

Func _cveLearningBasedWBSetSaturationThreshold(ByRef $obj, $value)
    ; CVAPI(void) cveLearningBasedWBSetSaturationThreshold(cv::xphoto::LearningBasedWB* obj, float value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveLearningBasedWBSetSaturationThreshold", "ptr", $obj, "float", $value), "cveLearningBasedWBSetSaturationThreshold", @error)
EndFunc   ;==>_cveLearningBasedWBSetSaturationThreshold

Func _cveLearningBasedWBGetHistBinNum(ByRef $obj)
    ; CVAPI(int) cveLearningBasedWBGetHistBinNum(cv::xphoto::LearningBasedWB* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveLearningBasedWBGetHistBinNum", "ptr", $obj), "cveLearningBasedWBGetHistBinNum", @error)
EndFunc   ;==>_cveLearningBasedWBGetHistBinNum

Func _cveLearningBasedWBSetHistBinNum(ByRef $obj, $value)
    ; CVAPI(void) cveLearningBasedWBSetHistBinNum(cv::xphoto::LearningBasedWB* obj, int value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveLearningBasedWBSetHistBinNum", "ptr", $obj, "int", $value), "cveLearningBasedWBSetHistBinNum", @error)
EndFunc   ;==>_cveLearningBasedWBSetHistBinNum