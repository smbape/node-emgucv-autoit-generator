#include-once
#include "..\..\CVEUtils.au3"

Func _cveOclKernelEmpty(ByRef $obj)
    ; CVAPI(bool) cveOclKernelEmpty(cv::ocl::Kernel* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveOclKernelEmpty", "ptr", $obj), "cveOclKernelEmpty", @error)
EndFunc   ;==>_cveOclKernelEmpty

Func _cveOclKernelNativeKernelPtr(ByRef $obj)
    ; CVAPI(void*) cveOclKernelNativeKernelPtr(cv::ocl::Kernel* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveOclKernelNativeKernelPtr", "ptr", $obj), "cveOclKernelNativeKernelPtr", @error)
EndFunc   ;==>_cveOclKernelNativeKernelPtr