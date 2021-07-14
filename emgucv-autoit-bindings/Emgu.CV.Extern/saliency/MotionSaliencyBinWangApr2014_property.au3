#include-once
#include <..\..\CVEUtils.au3>

Func _cveMotionSaliencyBinWangApr2014GetImageWidth(ByRef $obj)
    ; CVAPI(int) cveMotionSaliencyBinWangApr2014GetImageWidth(cv::saliency::MotionSaliencyBinWangApr2014* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveMotionSaliencyBinWangApr2014GetImageWidth", "ptr", $obj), "cveMotionSaliencyBinWangApr2014GetImageWidth", @error)
EndFunc   ;==>_cveMotionSaliencyBinWangApr2014GetImageWidth

Func _cveMotionSaliencyBinWangApr2014SetImageWidth(ByRef $obj, $value)
    ; CVAPI(void) cveMotionSaliencyBinWangApr2014SetImageWidth(cv::saliency::MotionSaliencyBinWangApr2014* obj, int value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMotionSaliencyBinWangApr2014SetImageWidth", "ptr", $obj, "int", $value), "cveMotionSaliencyBinWangApr2014SetImageWidth", @error)
EndFunc   ;==>_cveMotionSaliencyBinWangApr2014SetImageWidth

Func _cveMotionSaliencyBinWangApr2014GetImageHeight(ByRef $obj)
    ; CVAPI(int) cveMotionSaliencyBinWangApr2014GetImageHeight(cv::saliency::MotionSaliencyBinWangApr2014* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveMotionSaliencyBinWangApr2014GetImageHeight", "ptr", $obj), "cveMotionSaliencyBinWangApr2014GetImageHeight", @error)
EndFunc   ;==>_cveMotionSaliencyBinWangApr2014GetImageHeight

Func _cveMotionSaliencyBinWangApr2014SetImageHeight(ByRef $obj, $value)
    ; CVAPI(void) cveMotionSaliencyBinWangApr2014SetImageHeight(cv::saliency::MotionSaliencyBinWangApr2014* obj, int value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMotionSaliencyBinWangApr2014SetImageHeight", "ptr", $obj, "int", $value), "cveMotionSaliencyBinWangApr2014SetImageHeight", @error)
EndFunc   ;==>_cveMotionSaliencyBinWangApr2014SetImageHeight

Func _cveMotionSaliencyBinWangApr2014Init(ByRef $obj)
    ; CVAPI(bool) cveMotionSaliencyBinWangApr2014Init(cv::saliency::MotionSaliencyBinWangApr2014* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveMotionSaliencyBinWangApr2014Init", "ptr", $obj), "cveMotionSaliencyBinWangApr2014Init", @error)
EndFunc   ;==>_cveMotionSaliencyBinWangApr2014Init