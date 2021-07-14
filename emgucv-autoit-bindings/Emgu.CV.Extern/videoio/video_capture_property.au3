#include-once
#include "..\..\CVEUtils.au3"

Func _cveVideoCaptureIsOpened(ByRef $obj)
    ; CVAPI(bool) cveVideoCaptureIsOpened(cv::VideoCapture* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveVideoCaptureIsOpened", "ptr", $obj), "cveVideoCaptureIsOpened", @error)
EndFunc   ;==>_cveVideoCaptureIsOpened

Func _cveVideoCaptureGetExceptionMode(ByRef $obj)
    ; CVAPI(bool) cveVideoCaptureGetExceptionMode(cv::VideoCapture* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveVideoCaptureGetExceptionMode", "ptr", $obj), "cveVideoCaptureGetExceptionMode", @error)
EndFunc   ;==>_cveVideoCaptureGetExceptionMode

Func _cveVideoCaptureSetExceptionMode(ByRef $obj, $value)
    ; CVAPI(void) cveVideoCaptureSetExceptionMode(cv::VideoCapture* obj, bool value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveVideoCaptureSetExceptionMode", "ptr", $obj, "boolean", $value), "cveVideoCaptureSetExceptionMode", @error)
EndFunc   ;==>_cveVideoCaptureSetExceptionMode