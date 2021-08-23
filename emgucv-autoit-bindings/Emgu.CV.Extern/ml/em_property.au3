#include-once
#include "..\..\CVEUtils.au3"

Func _cveEMGetClustersNumber($obj)
    ; CVAPI(int) cveEMGetClustersNumber(cv::ml::EM* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveEMGetClustersNumber", $sObjDllType, $obj), "cveEMGetClustersNumber", @error)
EndFunc   ;==>_cveEMGetClustersNumber

Func _cveEMSetClustersNumber($obj, $value)
    ; CVAPI(void) cveEMSetClustersNumber(cv::ml::EM* obj, int value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveEMSetClustersNumber", $sObjDllType, $obj, "int", $value), "cveEMSetClustersNumber", @error)
EndFunc   ;==>_cveEMSetClustersNumber

Func _cveEMGetCovarianceMatrixType($obj)
    ; CVAPI(int) cveEMGetCovarianceMatrixType(cv::ml::EM* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveEMGetCovarianceMatrixType", $sObjDllType, $obj), "cveEMGetCovarianceMatrixType", @error)
EndFunc   ;==>_cveEMGetCovarianceMatrixType

Func _cveEMSetCovarianceMatrixType($obj, $value)
    ; CVAPI(void) cveEMSetCovarianceMatrixType(cv::ml::EM* obj, int value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveEMSetCovarianceMatrixType", $sObjDllType, $obj, "int", $value), "cveEMSetCovarianceMatrixType", @error)
EndFunc   ;==>_cveEMSetCovarianceMatrixType

Func _cveEMGetTermCriteria($obj, $value)
    ; CVAPI(void) cveEMGetTermCriteria(cv::ml::EM* obj, CvTermCriteria* value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    Local $sValueDllType
    If IsDllStruct($value) Then
        $sValueDllType = "struct*"
    Else
        $sValueDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveEMGetTermCriteria", $sObjDllType, $obj, $sValueDllType, $value), "cveEMGetTermCriteria", @error)
EndFunc   ;==>_cveEMGetTermCriteria

Func _cveEMSetTermCriteria($obj, $value)
    ; CVAPI(void) cveEMSetTermCriteria(cv::ml::EM* obj, CvTermCriteria* value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    Local $sValueDllType
    If IsDllStruct($value) Then
        $sValueDllType = "struct*"
    Else
        $sValueDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveEMSetTermCriteria", $sObjDllType, $obj, $sValueDllType, $value), "cveEMSetTermCriteria", @error)
EndFunc   ;==>_cveEMSetTermCriteria