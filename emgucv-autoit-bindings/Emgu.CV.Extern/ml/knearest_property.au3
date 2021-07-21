#include-once
#include "..\..\CVEUtils.au3"

Func _cveKNearestGetDefaultK($obj)
    ; CVAPI(int) cveKNearestGetDefaultK(cv::ml::KNearest* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveKNearestGetDefaultK", $bObjDllType, $obj), "cveKNearestGetDefaultK", @error)
EndFunc   ;==>_cveKNearestGetDefaultK

Func _cveKNearestSetDefaultK($obj, $value)
    ; CVAPI(void) cveKNearestSetDefaultK(cv::ml::KNearest* obj, int value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveKNearestSetDefaultK", $bObjDllType, $obj, "int", $value), "cveKNearestSetDefaultK", @error)
EndFunc   ;==>_cveKNearestSetDefaultK

Func _cveKNearestGetIsClassifier($obj)
    ; CVAPI(bool) cveKNearestGetIsClassifier(cv::ml::KNearest* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveKNearestGetIsClassifier", $bObjDllType, $obj), "cveKNearestGetIsClassifier", @error)
EndFunc   ;==>_cveKNearestGetIsClassifier

Func _cveKNearestSetIsClassifier($obj, $value)
    ; CVAPI(void) cveKNearestSetIsClassifier(cv::ml::KNearest* obj, bool value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveKNearestSetIsClassifier", $bObjDllType, $obj, "boolean", $value), "cveKNearestSetIsClassifier", @error)
EndFunc   ;==>_cveKNearestSetIsClassifier

Func _cveKNearestGetEmax($obj)
    ; CVAPI(int) cveKNearestGetEmax(cv::ml::KNearest* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveKNearestGetEmax", $bObjDllType, $obj), "cveKNearestGetEmax", @error)
EndFunc   ;==>_cveKNearestGetEmax

Func _cveKNearestSetEmax($obj, $value)
    ; CVAPI(void) cveKNearestSetEmax(cv::ml::KNearest* obj, int value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveKNearestSetEmax", $bObjDllType, $obj, "int", $value), "cveKNearestSetEmax", @error)
EndFunc   ;==>_cveKNearestSetEmax

Func _cveKNearestGetAlgorithmType($obj)
    ; CVAPI(int) cveKNearestGetAlgorithmType(cv::ml::KNearest* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveKNearestGetAlgorithmType", $bObjDllType, $obj), "cveKNearestGetAlgorithmType", @error)
EndFunc   ;==>_cveKNearestGetAlgorithmType

Func _cveKNearestSetAlgorithmType($obj, $value)
    ; CVAPI(void) cveKNearestSetAlgorithmType(cv::ml::KNearest* obj, int value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveKNearestSetAlgorithmType", $bObjDllType, $obj, "int", $value), "cveKNearestSetAlgorithmType", @error)
EndFunc   ;==>_cveKNearestSetAlgorithmType