#include-once
#include "..\..\CVEUtils.au3"

Func _cveUMatIsContinuous(ByRef $obj)
    ; CVAPI(bool) cveUMatIsContinuous(cv::UMat* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveUMatIsContinuous", "ptr", $obj), "cveUMatIsContinuous", @error)
EndFunc   ;==>_cveUMatIsContinuous

Func _cveUMatIsSubmatrix(ByRef $obj)
    ; CVAPI(bool) cveUMatIsSubmatrix(cv::UMat* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveUMatIsSubmatrix", "ptr", $obj), "cveUMatIsSubmatrix", @error)
EndFunc   ;==>_cveUMatIsSubmatrix

Func _cveUMatDepth(ByRef $obj)
    ; CVAPI(int) cveUMatDepth(cv::UMat* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveUMatDepth", "ptr", $obj), "cveUMatDepth", @error)
EndFunc   ;==>_cveUMatDepth

Func _cveUMatIsEmpty(ByRef $obj)
    ; CVAPI(bool) cveUMatIsEmpty(cv::UMat* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveUMatIsEmpty", "ptr", $obj), "cveUMatIsEmpty", @error)
EndFunc   ;==>_cveUMatIsEmpty

Func _cveUMatNumberOfChannels(ByRef $obj)
    ; CVAPI(int) cveUMatNumberOfChannels(cv::UMat* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveUMatNumberOfChannels", "ptr", $obj), "cveUMatNumberOfChannels", @error)
EndFunc   ;==>_cveUMatNumberOfChannels

Func _cveUMatTotal(ByRef $obj)
    ; CVAPI(size_t) cveUMatTotal(cv::UMat* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ulong_ptr:cdecl", "cveUMatTotal", "ptr", $obj), "cveUMatTotal", @error)
EndFunc   ;==>_cveUMatTotal

Func _cveUMatGetDims(ByRef $obj)
    ; CVAPI(int) cveUMatGetDims(cv::UMat* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveUMatGetDims", "ptr", $obj), "cveUMatGetDims", @error)
EndFunc   ;==>_cveUMatGetDims