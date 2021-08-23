#include-once
#include "..\..\CVEUtils.au3"

Func _cveOclKernelEmpty($obj)
    ; CVAPI(bool) cveOclKernelEmpty(cv::ocl::Kernel* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveOclKernelEmpty", $sObjDllType, $obj), "cveOclKernelEmpty", @error)
EndFunc   ;==>_cveOclKernelEmpty

Func _cveOclKernelNativeKernelPtr($obj)
    ; CVAPI(void*) cveOclKernelNativeKernelPtr(cv::ocl::Kernel* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveOclKernelNativeKernelPtr", $sObjDllType, $obj), "cveOclKernelNativeKernelPtr", @error)
EndFunc   ;==>_cveOclKernelNativeKernelPtr