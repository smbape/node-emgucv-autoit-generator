#include-once
#include "..\CVEUtils.au3"

Func _cveGetCvStructSizes($sizes)
    ; CVAPI(void) cveGetCvStructSizes(emgu::cvStructSizes* sizes);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveGetCvStructSizes", "ptr", $sizes), "cveGetCvStructSizes", @error)
EndFunc   ;==>_cveGetCvStructSizes

Func _testDrawLine($img, $startX, $startY, $endX, $endY, $c)
    ; CVAPI(void) testDrawLine(IplImage* img, int startX, int startY, int endX, int endY, CvScalar c);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "testDrawLine", "struct*", $img, "int", $startX, "int", $startY, "int", $endX, "int", $endY, "CvScalar", $c), "testDrawLine", @error)
EndFunc   ;==>_testDrawLine

Func _cveMemcpy($dst, $src, $length)
    ; CVAPI(void) cveMemcpy(void* dst, void* src, int length);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMemcpy", "struct*", $dst, "struct*", $src, "int", $length), "cveMemcpy", @error)
EndFunc   ;==>_cveMemcpy