#include-once
#include "..\..\CVEUtils.au3"

Func _cveSVMGetType($obj)
    ; CVAPI(int) cveSVMGetType(cv::ml::SVM* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveSVMGetType", $bObjDllType, $obj), "cveSVMGetType", @error)
EndFunc   ;==>_cveSVMGetType

Func _cveSVMSetType($obj, $value)
    ; CVAPI(void) cveSVMSetType(cv::ml::SVM* obj, int value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSVMSetType", $bObjDllType, $obj, "int", $value), "cveSVMSetType", @error)
EndFunc   ;==>_cveSVMSetType

Func _cveSVMGetGamma($obj)
    ; CVAPI(double) cveSVMGetGamma(cv::ml::SVM* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveSVMGetGamma", $bObjDllType, $obj), "cveSVMGetGamma", @error)
EndFunc   ;==>_cveSVMGetGamma

Func _cveSVMSetGamma($obj, $value)
    ; CVAPI(void) cveSVMSetGamma(cv::ml::SVM* obj, double value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSVMSetGamma", $bObjDllType, $obj, "double", $value), "cveSVMSetGamma", @error)
EndFunc   ;==>_cveSVMSetGamma

Func _cveSVMGetCoef0($obj)
    ; CVAPI(double) cveSVMGetCoef0(cv::ml::SVM* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveSVMGetCoef0", $bObjDllType, $obj), "cveSVMGetCoef0", @error)
EndFunc   ;==>_cveSVMGetCoef0

Func _cveSVMSetCoef0($obj, $value)
    ; CVAPI(void) cveSVMSetCoef0(cv::ml::SVM* obj, double value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSVMSetCoef0", $bObjDllType, $obj, "double", $value), "cveSVMSetCoef0", @error)
EndFunc   ;==>_cveSVMSetCoef0

Func _cveSVMGetDegree($obj)
    ; CVAPI(double) cveSVMGetDegree(cv::ml::SVM* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveSVMGetDegree", $bObjDllType, $obj), "cveSVMGetDegree", @error)
EndFunc   ;==>_cveSVMGetDegree

Func _cveSVMSetDegree($obj, $value)
    ; CVAPI(void) cveSVMSetDegree(cv::ml::SVM* obj, double value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSVMSetDegree", $bObjDllType, $obj, "double", $value), "cveSVMSetDegree", @error)
EndFunc   ;==>_cveSVMSetDegree

Func _cveSVMGetC($obj)
    ; CVAPI(double) cveSVMGetC(cv::ml::SVM* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveSVMGetC", $bObjDllType, $obj), "cveSVMGetC", @error)
EndFunc   ;==>_cveSVMGetC

Func _cveSVMSetC($obj, $value)
    ; CVAPI(void) cveSVMSetC(cv::ml::SVM* obj, double value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSVMSetC", $bObjDllType, $obj, "double", $value), "cveSVMSetC", @error)
EndFunc   ;==>_cveSVMSetC

Func _cveSVMGetNu($obj)
    ; CVAPI(double) cveSVMGetNu(cv::ml::SVM* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveSVMGetNu", $bObjDllType, $obj), "cveSVMGetNu", @error)
EndFunc   ;==>_cveSVMGetNu

Func _cveSVMSetNu($obj, $value)
    ; CVAPI(void) cveSVMSetNu(cv::ml::SVM* obj, double value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSVMSetNu", $bObjDllType, $obj, "double", $value), "cveSVMSetNu", @error)
EndFunc   ;==>_cveSVMSetNu

Func _cveSVMGetP($obj)
    ; CVAPI(double) cveSVMGetP(cv::ml::SVM* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveSVMGetP", $bObjDllType, $obj), "cveSVMGetP", @error)
EndFunc   ;==>_cveSVMGetP

Func _cveSVMSetP($obj, $value)
    ; CVAPI(void) cveSVMSetP(cv::ml::SVM* obj, double value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSVMSetP", $bObjDllType, $obj, "double", $value), "cveSVMSetP", @error)
EndFunc   ;==>_cveSVMSetP

Func _cveSVMSetKernel($obj, $value)
    ; CVAPI(void) cveSVMSetKernel(cv::ml::SVM* obj, int value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSVMSetKernel", $bObjDllType, $obj, "int", $value), "cveSVMSetKernel", @error)
EndFunc   ;==>_cveSVMSetKernel

Func _cveSVMGetTermCriteria($obj, $value)
    ; CVAPI(void) cveSVMGetTermCriteria(cv::ml::SVM* obj, CvTermCriteria* value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    Local $bValueDllType
    If VarGetType($value) == "DLLStruct" Then
        $bValueDllType = "struct*"
    Else
        $bValueDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSVMGetTermCriteria", $bObjDllType, $obj, $bValueDllType, $value), "cveSVMGetTermCriteria", @error)
EndFunc   ;==>_cveSVMGetTermCriteria

Func _cveSVMSetTermCriteria($obj, $value)
    ; CVAPI(void) cveSVMSetTermCriteria(cv::ml::SVM* obj, CvTermCriteria* value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    Local $bValueDllType
    If VarGetType($value) == "DLLStruct" Then
        $bValueDllType = "struct*"
    Else
        $bValueDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSVMSetTermCriteria", $bObjDllType, $obj, $bValueDllType, $value), "cveSVMSetTermCriteria", @error)
EndFunc   ;==>_cveSVMSetTermCriteria

Func _cveSVMGetKernelType($obj)
    ; CVAPI(int) cveSVMGetKernelType(cv::ml::SVM* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveSVMGetKernelType", $bObjDllType, $obj), "cveSVMGetKernelType", @error)
EndFunc   ;==>_cveSVMGetKernelType