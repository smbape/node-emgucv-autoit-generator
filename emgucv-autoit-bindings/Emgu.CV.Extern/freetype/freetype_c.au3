#include-once
#include "..\..\CVEUtils.au3"

Func _cveFreeType2Create(ByRef $algorithmPtr, ByRef $sharedPtr)
    ; CVAPI(cv::freetype::FreeType2*) cveFreeType2Create(cv::Algorithm** algorithmPtr, cv::Ptr<cv::freetype::FreeType2>** sharedPtr);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveFreeType2Create", "ptr*", $algorithmPtr, "ptr*", $sharedPtr), "cveFreeType2Create", @error)
EndFunc   ;==>_cveFreeType2Create

Func _cveFreeType2Release(ByRef $sharedPtr)
    ; CVAPI(void) cveFreeType2Release(cv::Ptr<cv::freetype::FreeType2>** sharedPtr);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFreeType2Release", "ptr*", $sharedPtr), "cveFreeType2Release", @error)
EndFunc   ;==>_cveFreeType2Release

Func _cveFreeType2LoadFontData(ByRef $freetype, $fontFileName, $id)
    ; CVAPI(void) cveFreeType2LoadFontData(cv::freetype::FreeType2* freetype, cv::String* fontFileName, int id);

    Local $bFontFileNameIsString = VarGetType($fontFileName) == "String"
    If $bFontFileNameIsString Then
        $fontFileName = _cveStringCreateFromStr($fontFileName)
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFreeType2LoadFontData", "ptr", $freetype, "ptr", $fontFileName, "int", $id), "cveFreeType2LoadFontData", @error)

    If $bFontFileNameIsString Then
        _cveStringRelease($fontFileName)
    EndIf
EndFunc   ;==>_cveFreeType2LoadFontData

Func _cveFreeType2SetSplitNumber(ByRef $freetype, $num)
    ; CVAPI(void) cveFreeType2SetSplitNumber(cv::freetype::FreeType2* freetype, int num);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFreeType2SetSplitNumber", "ptr", $freetype, "int", $num), "cveFreeType2SetSplitNumber", @error)
EndFunc   ;==>_cveFreeType2SetSplitNumber

Func _cveFreeType2PutText(ByRef $freetype, ByRef $img, $text, ByRef $org, $fontHeight, ByRef $color, $thickness, $lineType, $bottomLeftOrigin)
    ; CVAPI(void) cveFreeType2PutText(cv::freetype::FreeType2* freetype, cv::_InputOutputArray* img, cv::String* text, CvPoint* org, int fontHeight, CvScalar* color, int thickness, int lineType, bool bottomLeftOrigin);

    Local $bTextIsString = VarGetType($text) == "String"
    If $bTextIsString Then
        $text = _cveStringCreateFromStr($text)
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFreeType2PutText", "ptr", $freetype, "ptr", $img, "ptr", $text, "struct*", $org, "int", $fontHeight, "struct*", $color, "int", $thickness, "int", $lineType, "boolean", $bottomLeftOrigin), "cveFreeType2PutText", @error)

    If $bTextIsString Then
        _cveStringRelease($text)
    EndIf
EndFunc   ;==>_cveFreeType2PutText

Func _cveFreeType2PutTextMat(ByRef $freetype, ByRef $matImg, $text, ByRef $org, $fontHeight, ByRef $color, $thickness, $lineType, $bottomLeftOrigin)
    ; cveFreeType2PutText using cv::Mat instead of _*Array

    Local $ioArrImg, $vectorOfMatImg, $iArrImgSize
    Local $bImgIsArray = VarGetType($matImg) == "Array"

    If $bImgIsArray Then
        $vectorOfMatImg = _VectorOfMatCreate()

        $iArrImgSize = UBound($matImg)
        For $i = 0 To $iArrImgSize - 1
            _VectorOfMatPush($vectorOfMatImg, $matImg[$i])
        Next

        $ioArrImg = _cveInputOutputArrayFromVectorOfMat($vectorOfMatImg)
    Else
        $ioArrImg = _cveInputOutputArrayFromMat($matImg)
    EndIf

    _cveFreeType2PutText($freetype, $ioArrImg, $text, $org, $fontHeight, $color, $thickness, $lineType, $bottomLeftOrigin)

    If $bImgIsArray Then
        _VectorOfMatRelease($vectorOfMatImg)
    EndIf

    _cveInputOutputArrayRelease($ioArrImg)
EndFunc   ;==>_cveFreeType2PutTextMat

Func _cveFreeType2GetTextSize(ByRef $freetype, $text, $fontHeight, $thickness, ByRef $baseLine, ByRef $size)
    ; CVAPI(void) cveFreeType2GetTextSize(cv::freetype::FreeType2* freetype, cv::String* text, int fontHeight, int thickness, int* baseLine, CvSize* size);

    Local $bTextIsString = VarGetType($text) == "String"
    If $bTextIsString Then
        $text = _cveStringCreateFromStr($text)
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFreeType2GetTextSize", "ptr", $freetype, "ptr", $text, "int", $fontHeight, "int", $thickness, "struct*", $baseLine, "struct*", $size), "cveFreeType2GetTextSize", @error)

    If $bTextIsString Then
        _cveStringRelease($text)
    EndIf
EndFunc   ;==>_cveFreeType2GetTextSize