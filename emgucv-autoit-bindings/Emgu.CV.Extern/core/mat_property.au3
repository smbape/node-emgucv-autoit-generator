#include-once
#include "..\..\CVEUtils.au3"

Func _cveMatIsContinuous($obj)
    ; CVAPI(bool) cveMatIsContinuous(cv::Mat* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveMatIsContinuous", $bObjDllType, $obj), "cveMatIsContinuous", @error)
EndFunc   ;==>_cveMatIsContinuous

Func _cveMatIsSubmatrix($obj)
    ; CVAPI(bool) cveMatIsSubmatrix(cv::Mat* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveMatIsSubmatrix", $bObjDllType, $obj), "cveMatIsSubmatrix", @error)
EndFunc   ;==>_cveMatIsSubmatrix

Func _cveMatDepth($obj)
    ; CVAPI(int) cveMatDepth(cv::Mat* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveMatDepth", $bObjDllType, $obj), "cveMatDepth", @error)
EndFunc   ;==>_cveMatDepth

Func _cveMatIsEmpty($obj)
    ; CVAPI(bool) cveMatIsEmpty(cv::Mat* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveMatIsEmpty", $bObjDllType, $obj), "cveMatIsEmpty", @error)
EndFunc   ;==>_cveMatIsEmpty

Func _cveMatNumberOfChannels($obj)
    ; CVAPI(int) cveMatNumberOfChannels(cv::Mat* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveMatNumberOfChannels", $bObjDllType, $obj), "cveMatNumberOfChannels", @error)
EndFunc   ;==>_cveMatNumberOfChannels

Func _cveMatPopBack($obj, $value)
    ; CVAPI(void) cveMatPopBack(cv::Mat* obj, int value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMatPopBack", $bObjDllType, $obj, "int", $value), "cveMatPopBack", @error)
EndFunc   ;==>_cveMatPopBack

Func _cveMatPushBack($obj, $value)
    ; CVAPI(void) cveMatPushBack(cv::Mat* obj, cv::Mat* value);

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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMatPushBack", $bObjDllType, $obj, $bValueDllType, $value), "cveMatPushBack", @error)
EndFunc   ;==>_cveMatPushBack

Func _cveMatTotal($obj)
    ; CVAPI(size_t) cveMatTotal(cv::Mat* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ulong_ptr:cdecl", "cveMatTotal", $bObjDllType, $obj), "cveMatTotal", @error)
EndFunc   ;==>_cveMatTotal

Func _cveMatGetDims($obj)
    ; CVAPI(int) cveMatGetDims(cv::Mat* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveMatGetDims", $bObjDllType, $obj), "cveMatGetDims", @error)
EndFunc   ;==>_cveMatGetDims