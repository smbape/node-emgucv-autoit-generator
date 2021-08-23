#include-once
#include "..\..\CVEUtils.au3"

Func _cveGpuMatIsContinuous($obj)
    ; CVAPI(bool) cveGpuMatIsContinuous(cv::cuda::GpuMat* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveGpuMatIsContinuous", $sObjDllType, $obj), "cveGpuMatIsContinuous", @error)
EndFunc   ;==>_cveGpuMatIsContinuous

Func _cveGpuMatDepth($obj)
    ; CVAPI(int) cveGpuMatDepth(cv::cuda::GpuMat* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveGpuMatDepth", $sObjDllType, $obj), "cveGpuMatDepth", @error)
EndFunc   ;==>_cveGpuMatDepth

Func _cveGpuMatIsEmpty($obj)
    ; CVAPI(bool) cveGpuMatIsEmpty(cv::cuda::GpuMat* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveGpuMatIsEmpty", $sObjDllType, $obj), "cveGpuMatIsEmpty", @error)
EndFunc   ;==>_cveGpuMatIsEmpty

Func _cveGpuMatNumberOfChannels($obj)
    ; CVAPI(int) cveGpuMatNumberOfChannels(cv::cuda::GpuMat* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveGpuMatNumberOfChannels", $sObjDllType, $obj), "cveGpuMatNumberOfChannels", @error)
EndFunc   ;==>_cveGpuMatNumberOfChannels