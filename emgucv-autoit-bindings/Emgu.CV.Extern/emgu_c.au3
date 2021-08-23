#include-once
#include "..\CVEUtils.au3"

Func _cveGetCvStructSizes($sizes)
    ; CVAPI(void) cveGetCvStructSizes(emgu::cvStructSizes* sizes);

    Local $sSizesDllType
    If IsDllStruct($sizes) Then
        $sSizesDllType = "struct*"
    Else
        $sSizesDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveGetCvStructSizes", $sSizesDllType, $sizes), "cveGetCvStructSizes", @error)
EndFunc   ;==>_cveGetCvStructSizes

Func _testDrawLine($img, $startX, $startY, $endX, $endY, $c)
    ; CVAPI(void) testDrawLine(IplImage* img, int startX, int startY, int endX, int endY, CvScalar c);

    Local $sImgDllType
    If IsDllStruct($img) Then
        $sImgDllType = "struct*"
    Else
        $sImgDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "testDrawLine", $sImgDllType, $img, "int", $startX, "int", $startY, "int", $endX, "int", $endY, "ptr", $c), "testDrawLine", @error)
EndFunc   ;==>_testDrawLine

Func _cveMemcpy($dst, $src, $length)
    ; CVAPI(void) cveMemcpy(void* dst, void* src, int length);

    Local $sDstDllType
    If IsDllStruct($dst) Then
        $sDstDllType = "struct*"
    Else
        $sDstDllType = "ptr"
    EndIf

    Local $sSrcDllType
    If IsDllStruct($src) Then
        $sSrcDllType = "struct*"
    Else
        $sSrcDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMemcpy", $sDstDllType, $dst, $sSrcDllType, $src, "int", $length), "cveMemcpy", @error)
EndFunc   ;==>_cveMemcpy