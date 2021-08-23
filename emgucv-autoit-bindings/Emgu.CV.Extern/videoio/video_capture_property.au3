#include-once
#include "..\..\CVEUtils.au3"

Func _cveVideoCaptureIsOpened($obj)
    ; CVAPI(bool) cveVideoCaptureIsOpened(cv::VideoCapture* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveVideoCaptureIsOpened", $sObjDllType, $obj), "cveVideoCaptureIsOpened", @error)
EndFunc   ;==>_cveVideoCaptureIsOpened

Func _cveVideoCaptureGetExceptionMode($obj)
    ; CVAPI(bool) cveVideoCaptureGetExceptionMode(cv::VideoCapture* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveVideoCaptureGetExceptionMode", $sObjDllType, $obj), "cveVideoCaptureGetExceptionMode", @error)
EndFunc   ;==>_cveVideoCaptureGetExceptionMode

Func _cveVideoCaptureSetExceptionMode($obj, $value)
    ; CVAPI(void) cveVideoCaptureSetExceptionMode(cv::VideoCapture* obj, bool value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveVideoCaptureSetExceptionMode", $sObjDllType, $obj, "boolean", $value), "cveVideoCaptureSetExceptionMode", @error)
EndFunc   ;==>_cveVideoCaptureSetExceptionMode