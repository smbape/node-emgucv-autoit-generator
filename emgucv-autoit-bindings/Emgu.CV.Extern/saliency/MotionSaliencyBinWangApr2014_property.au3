#include-once
#include "..\..\CVEUtils.au3"

Func _cveMotionSaliencyBinWangApr2014GetImageWidth($obj)
    ; CVAPI(int) cveMotionSaliencyBinWangApr2014GetImageWidth(cv::saliency::MotionSaliencyBinWangApr2014* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveMotionSaliencyBinWangApr2014GetImageWidth", $bObjDllType, $obj), "cveMotionSaliencyBinWangApr2014GetImageWidth", @error)
EndFunc   ;==>_cveMotionSaliencyBinWangApr2014GetImageWidth

Func _cveMotionSaliencyBinWangApr2014SetImageWidth($obj, $value)
    ; CVAPI(void) cveMotionSaliencyBinWangApr2014SetImageWidth(cv::saliency::MotionSaliencyBinWangApr2014* obj, int value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMotionSaliencyBinWangApr2014SetImageWidth", $bObjDllType, $obj, "int", $value), "cveMotionSaliencyBinWangApr2014SetImageWidth", @error)
EndFunc   ;==>_cveMotionSaliencyBinWangApr2014SetImageWidth

Func _cveMotionSaliencyBinWangApr2014GetImageHeight($obj)
    ; CVAPI(int) cveMotionSaliencyBinWangApr2014GetImageHeight(cv::saliency::MotionSaliencyBinWangApr2014* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveMotionSaliencyBinWangApr2014GetImageHeight", $bObjDllType, $obj), "cveMotionSaliencyBinWangApr2014GetImageHeight", @error)
EndFunc   ;==>_cveMotionSaliencyBinWangApr2014GetImageHeight

Func _cveMotionSaliencyBinWangApr2014SetImageHeight($obj, $value)
    ; CVAPI(void) cveMotionSaliencyBinWangApr2014SetImageHeight(cv::saliency::MotionSaliencyBinWangApr2014* obj, int value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMotionSaliencyBinWangApr2014SetImageHeight", $bObjDllType, $obj, "int", $value), "cveMotionSaliencyBinWangApr2014SetImageHeight", @error)
EndFunc   ;==>_cveMotionSaliencyBinWangApr2014SetImageHeight

Func _cveMotionSaliencyBinWangApr2014Init($obj)
    ; CVAPI(bool) cveMotionSaliencyBinWangApr2014Init(cv::saliency::MotionSaliencyBinWangApr2014* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveMotionSaliencyBinWangApr2014Init", $bObjDllType, $obj), "cveMotionSaliencyBinWangApr2014Init", @error)
EndFunc   ;==>_cveMotionSaliencyBinWangApr2014Init