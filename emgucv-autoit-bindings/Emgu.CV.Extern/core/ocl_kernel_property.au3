#include-once
#include "..\..\CVEUtils.au3"

Func _cveOclKernelEmpty($obj)
    ; CVAPI(bool) cveOclKernelEmpty(cv::ocl::Kernel* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveOclKernelEmpty", $bObjDllType, $obj), "cveOclKernelEmpty", @error)
EndFunc   ;==>_cveOclKernelEmpty

Func _cveOclKernelNativeKernelPtr($obj)
    ; CVAPI(void*) cveOclKernelNativeKernelPtr(cv::ocl::Kernel* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveOclKernelNativeKernelPtr", $bObjDllType, $obj), "cveOclKernelNativeKernelPtr", @error)
EndFunc   ;==>_cveOclKernelNativeKernelPtr