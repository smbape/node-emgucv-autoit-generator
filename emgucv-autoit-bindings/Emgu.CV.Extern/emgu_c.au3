#include-once
#include "..\CVEUtils.au3"

Func _cveGetCvStructSizes($sizes)
    ; CVAPI(void) cveGetCvStructSizes(emgu::cvStructSizes* sizes);

    Local $bSizesDllType
    If VarGetType($sizes) == "DLLStruct" Then
        $bSizesDllType = "struct*"
    Else
        $bSizesDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveGetCvStructSizes", $bSizesDllType, $sizes), "cveGetCvStructSizes", @error)
EndFunc   ;==>_cveGetCvStructSizes

Func _testDrawLine($img, $startX, $startY, $endX, $endY, $c)
    ; CVAPI(void) testDrawLine(IplImage* img, int startX, int startY, int endX, int endY, CvScalar c);

    Local $bImgDllType
    If VarGetType($img) == "DLLStruct" Then
        $bImgDllType = "struct*"
    Else
        $bImgDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "testDrawLine", $bImgDllType, $img, "int", $startX, "int", $startY, "int", $endX, "int", $endY, "CvScalar", $c), "testDrawLine", @error)
EndFunc   ;==>_testDrawLine

Func _cveMemcpy($dst, $src, $length)
    ; CVAPI(void) cveMemcpy(void* dst, void* src, int length);

    Local $bDstDllType
    If VarGetType($dst) == "DLLStruct" Then
        $bDstDllType = "struct*"
    Else
        $bDstDllType = "ptr"
    EndIf

    Local $bSrcDllType
    If VarGetType($src) == "DLLStruct" Then
        $bSrcDllType = "struct*"
    Else
        $bSrcDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMemcpy", $bDstDllType, $dst, $bSrcDllType, $src, "int", $length), "cveMemcpy", @error)
EndFunc   ;==>_cveMemcpy