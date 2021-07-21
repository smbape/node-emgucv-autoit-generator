#include-once
#include "..\..\CVEUtils.au3"

Func _cveEMGetClustersNumber($obj)
    ; CVAPI(int) cveEMGetClustersNumber(cv::ml::EM* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveEMGetClustersNumber", $bObjDllType, $obj), "cveEMGetClustersNumber", @error)
EndFunc   ;==>_cveEMGetClustersNumber

Func _cveEMSetClustersNumber($obj, $value)
    ; CVAPI(void) cveEMSetClustersNumber(cv::ml::EM* obj, int value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveEMSetClustersNumber", $bObjDllType, $obj, "int", $value), "cveEMSetClustersNumber", @error)
EndFunc   ;==>_cveEMSetClustersNumber

Func _cveEMGetCovarianceMatrixType($obj)
    ; CVAPI(int) cveEMGetCovarianceMatrixType(cv::ml::EM* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveEMGetCovarianceMatrixType", $bObjDllType, $obj), "cveEMGetCovarianceMatrixType", @error)
EndFunc   ;==>_cveEMGetCovarianceMatrixType

Func _cveEMSetCovarianceMatrixType($obj, $value)
    ; CVAPI(void) cveEMSetCovarianceMatrixType(cv::ml::EM* obj, int value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveEMSetCovarianceMatrixType", $bObjDllType, $obj, "int", $value), "cveEMSetCovarianceMatrixType", @error)
EndFunc   ;==>_cveEMSetCovarianceMatrixType

Func _cveEMGetTermCriteria($obj, $value)
    ; CVAPI(void) cveEMGetTermCriteria(cv::ml::EM* obj, CvTermCriteria* value);

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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveEMGetTermCriteria", $bObjDllType, $obj, $bValueDllType, $value), "cveEMGetTermCriteria", @error)
EndFunc   ;==>_cveEMGetTermCriteria

Func _cveEMSetTermCriteria($obj, $value)
    ; CVAPI(void) cveEMSetTermCriteria(cv::ml::EM* obj, CvTermCriteria* value);

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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveEMSetTermCriteria", $bObjDllType, $obj, $bValueDllType, $value), "cveEMSetTermCriteria", @error)
EndFunc   ;==>_cveEMSetTermCriteria