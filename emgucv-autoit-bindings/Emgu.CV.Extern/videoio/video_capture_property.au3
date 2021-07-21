#include-once
#include "..\..\CVEUtils.au3"

Func _cveVideoCaptureIsOpened($obj)
    ; CVAPI(bool) cveVideoCaptureIsOpened(cv::VideoCapture* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveVideoCaptureIsOpened", $bObjDllType, $obj), "cveVideoCaptureIsOpened", @error)
EndFunc   ;==>_cveVideoCaptureIsOpened

Func _cveVideoCaptureGetExceptionMode($obj)
    ; CVAPI(bool) cveVideoCaptureGetExceptionMode(cv::VideoCapture* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveVideoCaptureGetExceptionMode", $bObjDllType, $obj), "cveVideoCaptureGetExceptionMode", @error)
EndFunc   ;==>_cveVideoCaptureGetExceptionMode

Func _cveVideoCaptureSetExceptionMode($obj, $value)
    ; CVAPI(void) cveVideoCaptureSetExceptionMode(cv::VideoCapture* obj, bool value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveVideoCaptureSetExceptionMode", $bObjDllType, $obj, "boolean", $value), "cveVideoCaptureSetExceptionMode", @error)
EndFunc   ;==>_cveVideoCaptureSetExceptionMode