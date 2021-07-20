#include-once
#include "..\..\CVEUtils.au3"

Func _cveSVMGetType($obj)
    ; CVAPI(int) cveSVMGetType(cv::ml::SVM* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveSVMGetType", "ptr", $obj), "cveSVMGetType", @error)
EndFunc   ;==>_cveSVMGetType

Func _cveSVMSetType($obj, $value)
    ; CVAPI(void) cveSVMSetType(cv::ml::SVM* obj, int value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSVMSetType", "ptr", $obj, "int", $value), "cveSVMSetType", @error)
EndFunc   ;==>_cveSVMSetType

Func _cveSVMGetGamma($obj)
    ; CVAPI(double) cveSVMGetGamma(cv::ml::SVM* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveSVMGetGamma", "ptr", $obj), "cveSVMGetGamma", @error)
EndFunc   ;==>_cveSVMGetGamma

Func _cveSVMSetGamma($obj, $value)
    ; CVAPI(void) cveSVMSetGamma(cv::ml::SVM* obj, double value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSVMSetGamma", "ptr", $obj, "double", $value), "cveSVMSetGamma", @error)
EndFunc   ;==>_cveSVMSetGamma

Func _cveSVMGetCoef0($obj)
    ; CVAPI(double) cveSVMGetCoef0(cv::ml::SVM* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveSVMGetCoef0", "ptr", $obj), "cveSVMGetCoef0", @error)
EndFunc   ;==>_cveSVMGetCoef0

Func _cveSVMSetCoef0($obj, $value)
    ; CVAPI(void) cveSVMSetCoef0(cv::ml::SVM* obj, double value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSVMSetCoef0", "ptr", $obj, "double", $value), "cveSVMSetCoef0", @error)
EndFunc   ;==>_cveSVMSetCoef0

Func _cveSVMGetDegree($obj)
    ; CVAPI(double) cveSVMGetDegree(cv::ml::SVM* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveSVMGetDegree", "ptr", $obj), "cveSVMGetDegree", @error)
EndFunc   ;==>_cveSVMGetDegree

Func _cveSVMSetDegree($obj, $value)
    ; CVAPI(void) cveSVMSetDegree(cv::ml::SVM* obj, double value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSVMSetDegree", "ptr", $obj, "double", $value), "cveSVMSetDegree", @error)
EndFunc   ;==>_cveSVMSetDegree

Func _cveSVMGetC($obj)
    ; CVAPI(double) cveSVMGetC(cv::ml::SVM* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveSVMGetC", "ptr", $obj), "cveSVMGetC", @error)
EndFunc   ;==>_cveSVMGetC

Func _cveSVMSetC($obj, $value)
    ; CVAPI(void) cveSVMSetC(cv::ml::SVM* obj, double value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSVMSetC", "ptr", $obj, "double", $value), "cveSVMSetC", @error)
EndFunc   ;==>_cveSVMSetC

Func _cveSVMGetNu($obj)
    ; CVAPI(double) cveSVMGetNu(cv::ml::SVM* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveSVMGetNu", "ptr", $obj), "cveSVMGetNu", @error)
EndFunc   ;==>_cveSVMGetNu

Func _cveSVMSetNu($obj, $value)
    ; CVAPI(void) cveSVMSetNu(cv::ml::SVM* obj, double value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSVMSetNu", "ptr", $obj, "double", $value), "cveSVMSetNu", @error)
EndFunc   ;==>_cveSVMSetNu

Func _cveSVMGetP($obj)
    ; CVAPI(double) cveSVMGetP(cv::ml::SVM* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveSVMGetP", "ptr", $obj), "cveSVMGetP", @error)
EndFunc   ;==>_cveSVMGetP

Func _cveSVMSetP($obj, $value)
    ; CVAPI(void) cveSVMSetP(cv::ml::SVM* obj, double value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSVMSetP", "ptr", $obj, "double", $value), "cveSVMSetP", @error)
EndFunc   ;==>_cveSVMSetP

Func _cveSVMSetKernel($obj, $value)
    ; CVAPI(void) cveSVMSetKernel(cv::ml::SVM* obj, int value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSVMSetKernel", "ptr", $obj, "int", $value), "cveSVMSetKernel", @error)
EndFunc   ;==>_cveSVMSetKernel

Func _cveSVMGetTermCriteria($obj, $value)
    ; CVAPI(void) cveSVMGetTermCriteria(cv::ml::SVM* obj, CvTermCriteria* value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSVMGetTermCriteria", "ptr", $obj, "struct*", $value), "cveSVMGetTermCriteria", @error)
EndFunc   ;==>_cveSVMGetTermCriteria

Func _cveSVMSetTermCriteria($obj, $value)
    ; CVAPI(void) cveSVMSetTermCriteria(cv::ml::SVM* obj, CvTermCriteria* value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSVMSetTermCriteria", "ptr", $obj, "struct*", $value), "cveSVMSetTermCriteria", @error)
EndFunc   ;==>_cveSVMSetTermCriteria

Func _cveSVMGetKernelType($obj)
    ; CVAPI(int) cveSVMGetKernelType(cv::ml::SVM* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveSVMGetKernelType", "ptr", $obj), "cveSVMGetKernelType", @error)
EndFunc   ;==>_cveSVMGetKernelType