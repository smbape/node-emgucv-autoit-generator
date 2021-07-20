#include-once
#include "..\..\CVEUtils.au3"

Func _cveMatIsContinuous($obj)
    ; CVAPI(bool) cveMatIsContinuous(cv::Mat* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveMatIsContinuous", "ptr", $obj), "cveMatIsContinuous", @error)
EndFunc   ;==>_cveMatIsContinuous

Func _cveMatIsSubmatrix($obj)
    ; CVAPI(bool) cveMatIsSubmatrix(cv::Mat* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveMatIsSubmatrix", "ptr", $obj), "cveMatIsSubmatrix", @error)
EndFunc   ;==>_cveMatIsSubmatrix

Func _cveMatDepth($obj)
    ; CVAPI(int) cveMatDepth(cv::Mat* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveMatDepth", "ptr", $obj), "cveMatDepth", @error)
EndFunc   ;==>_cveMatDepth

Func _cveMatIsEmpty($obj)
    ; CVAPI(bool) cveMatIsEmpty(cv::Mat* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveMatIsEmpty", "ptr", $obj), "cveMatIsEmpty", @error)
EndFunc   ;==>_cveMatIsEmpty

Func _cveMatNumberOfChannels($obj)
    ; CVAPI(int) cveMatNumberOfChannels(cv::Mat* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveMatNumberOfChannels", "ptr", $obj), "cveMatNumberOfChannels", @error)
EndFunc   ;==>_cveMatNumberOfChannels

Func _cveMatPopBack($obj, $value)
    ; CVAPI(void) cveMatPopBack(cv::Mat* obj, int value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMatPopBack", "ptr", $obj, "int", $value), "cveMatPopBack", @error)
EndFunc   ;==>_cveMatPopBack

Func _cveMatPushBack($obj, $value)
    ; CVAPI(void) cveMatPushBack(cv::Mat* obj, cv::Mat* value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMatPushBack", "ptr", $obj, "ptr", $value), "cveMatPushBack", @error)
EndFunc   ;==>_cveMatPushBack

Func _cveMatTotal($obj)
    ; CVAPI(size_t) cveMatTotal(cv::Mat* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ulong_ptr:cdecl", "cveMatTotal", "ptr", $obj), "cveMatTotal", @error)
EndFunc   ;==>_cveMatTotal

Func _cveMatGetDims($obj)
    ; CVAPI(int) cveMatGetDims(cv::Mat* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveMatGetDims", "ptr", $obj), "cveMatGetDims", @error)
EndFunc   ;==>_cveMatGetDims