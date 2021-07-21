#include-once
#include "..\..\CVEUtils.au3"

Func _cveUMatIsContinuous($obj)
    ; CVAPI(bool) cveUMatIsContinuous(cv::UMat* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveUMatIsContinuous", $bObjDllType, $obj), "cveUMatIsContinuous", @error)
EndFunc   ;==>_cveUMatIsContinuous

Func _cveUMatIsSubmatrix($obj)
    ; CVAPI(bool) cveUMatIsSubmatrix(cv::UMat* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveUMatIsSubmatrix", $bObjDllType, $obj), "cveUMatIsSubmatrix", @error)
EndFunc   ;==>_cveUMatIsSubmatrix

Func _cveUMatDepth($obj)
    ; CVAPI(int) cveUMatDepth(cv::UMat* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveUMatDepth", $bObjDllType, $obj), "cveUMatDepth", @error)
EndFunc   ;==>_cveUMatDepth

Func _cveUMatIsEmpty($obj)
    ; CVAPI(bool) cveUMatIsEmpty(cv::UMat* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveUMatIsEmpty", $bObjDllType, $obj), "cveUMatIsEmpty", @error)
EndFunc   ;==>_cveUMatIsEmpty

Func _cveUMatNumberOfChannels($obj)
    ; CVAPI(int) cveUMatNumberOfChannels(cv::UMat* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveUMatNumberOfChannels", $bObjDllType, $obj), "cveUMatNumberOfChannels", @error)
EndFunc   ;==>_cveUMatNumberOfChannels

Func _cveUMatTotal($obj)
    ; CVAPI(size_t) cveUMatTotal(cv::UMat* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ulong_ptr:cdecl", "cveUMatTotal", $bObjDllType, $obj), "cveUMatTotal", @error)
EndFunc   ;==>_cveUMatTotal

Func _cveUMatGetDims($obj)
    ; CVAPI(int) cveUMatGetDims(cv::UMat* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveUMatGetDims", $bObjDllType, $obj), "cveUMatGetDims", @error)
EndFunc   ;==>_cveUMatGetDims