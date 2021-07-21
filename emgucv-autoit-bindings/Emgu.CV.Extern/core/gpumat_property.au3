#include-once
#include "..\..\CVEUtils.au3"

Func _cveGpuMatIsContinuous($obj)
    ; CVAPI(bool) cveGpuMatIsContinuous(cv::cuda::GpuMat* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveGpuMatIsContinuous", $bObjDllType, $obj), "cveGpuMatIsContinuous", @error)
EndFunc   ;==>_cveGpuMatIsContinuous

Func _cveGpuMatDepth($obj)
    ; CVAPI(int) cveGpuMatDepth(cv::cuda::GpuMat* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveGpuMatDepth", $bObjDllType, $obj), "cveGpuMatDepth", @error)
EndFunc   ;==>_cveGpuMatDepth

Func _cveGpuMatIsEmpty($obj)
    ; CVAPI(bool) cveGpuMatIsEmpty(cv::cuda::GpuMat* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveGpuMatIsEmpty", $bObjDllType, $obj), "cveGpuMatIsEmpty", @error)
EndFunc   ;==>_cveGpuMatIsEmpty

Func _cveGpuMatNumberOfChannels($obj)
    ; CVAPI(int) cveGpuMatNumberOfChannels(cv::cuda::GpuMat* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveGpuMatNumberOfChannels", $bObjDllType, $obj), "cveGpuMatNumberOfChannels", @error)
EndFunc   ;==>_cveGpuMatNumberOfChannels