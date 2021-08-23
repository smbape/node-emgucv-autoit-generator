#include-once
#include "..\..\CVEUtils.au3"

Func _cveMatIsContinuous($obj)
    ; CVAPI(bool) cveMatIsContinuous(cv::Mat* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveMatIsContinuous", $sObjDllType, $obj), "cveMatIsContinuous", @error)
EndFunc   ;==>_cveMatIsContinuous

Func _cveMatIsSubmatrix($obj)
    ; CVAPI(bool) cveMatIsSubmatrix(cv::Mat* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveMatIsSubmatrix", $sObjDllType, $obj), "cveMatIsSubmatrix", @error)
EndFunc   ;==>_cveMatIsSubmatrix

Func _cveMatDepth($obj)
    ; CVAPI(int) cveMatDepth(cv::Mat* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveMatDepth", $sObjDllType, $obj), "cveMatDepth", @error)
EndFunc   ;==>_cveMatDepth

Func _cveMatIsEmpty($obj)
    ; CVAPI(bool) cveMatIsEmpty(cv::Mat* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveMatIsEmpty", $sObjDllType, $obj), "cveMatIsEmpty", @error)
EndFunc   ;==>_cveMatIsEmpty

Func _cveMatNumberOfChannels($obj)
    ; CVAPI(int) cveMatNumberOfChannels(cv::Mat* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveMatNumberOfChannels", $sObjDllType, $obj), "cveMatNumberOfChannels", @error)
EndFunc   ;==>_cveMatNumberOfChannels

Func _cveMatPopBack($obj, $value)
    ; CVAPI(void) cveMatPopBack(cv::Mat* obj, int value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMatPopBack", $sObjDllType, $obj, "int", $value), "cveMatPopBack", @error)
EndFunc   ;==>_cveMatPopBack

Func _cveMatPushBack($obj, $value)
    ; CVAPI(void) cveMatPushBack(cv::Mat* obj, cv::Mat* value);

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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMatPushBack", $sObjDllType, $obj, $sValueDllType, $value), "cveMatPushBack", @error)
EndFunc   ;==>_cveMatPushBack

Func _cveMatTotal($obj)
    ; CVAPI(size_t) cveMatTotal(cv::Mat* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ulong_ptr:cdecl", "cveMatTotal", $sObjDllType, $obj), "cveMatTotal", @error)
EndFunc   ;==>_cveMatTotal

Func _cveMatGetDims($obj)
    ; CVAPI(int) cveMatGetDims(cv::Mat* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveMatGetDims", $sObjDllType, $obj), "cveMatGetDims", @error)
EndFunc   ;==>_cveMatGetDims