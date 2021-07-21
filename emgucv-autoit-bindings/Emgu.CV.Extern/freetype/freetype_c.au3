#include-once
#include "..\..\CVEUtils.au3"

Func _cveFreeType2Create($algorithmPtr, $sharedPtr)
    ; CVAPI(cv::freetype::FreeType2*) cveFreeType2Create(cv::Algorithm** algorithmPtr, cv::Ptr<cv::freetype::FreeType2>** sharedPtr);

    Local $bAlgorithmPtrDllType
    If VarGetType($algorithmPtr) == "DLLStruct" Then
        $bAlgorithmPtrDllType = "struct*"
    Else
        $bAlgorithmPtrDllType = "ptr*"
    EndIf

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveFreeType2Create", $bAlgorithmPtrDllType, $algorithmPtr, $bSharedPtrDllType, $sharedPtr), "cveFreeType2Create", @error)
EndFunc   ;==>_cveFreeType2Create

Func _cveFreeType2Release($sharedPtr)
    ; CVAPI(void) cveFreeType2Release(cv::Ptr<cv::freetype::FreeType2>** sharedPtr);

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFreeType2Release", $bSharedPtrDllType, $sharedPtr), "cveFreeType2Release", @error)
EndFunc   ;==>_cveFreeType2Release

Func _cveFreeType2LoadFontData($freetype, $fontFileName, $id)
    ; CVAPI(void) cveFreeType2LoadFontData(cv::freetype::FreeType2* freetype, cv::String* fontFileName, int id);

    Local $bFreetypeDllType
    If VarGetType($freetype) == "DLLStruct" Then
        $bFreetypeDllType = "struct*"
    Else
        $bFreetypeDllType = "ptr"
    EndIf

    Local $bFontFileNameIsString = VarGetType($fontFileName) == "String"
    If $bFontFileNameIsString Then
        $fontFileName = _cveStringCreateFromStr($fontFileName)
    EndIf

    Local $bFontFileNameDllType
    If VarGetType($fontFileName) == "DLLStruct" Then
        $bFontFileNameDllType = "struct*"
    Else
        $bFontFileNameDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFreeType2LoadFontData", $bFreetypeDllType, $freetype, $bFontFileNameDllType, $fontFileName, "int", $id), "cveFreeType2LoadFontData", @error)

    If $bFontFileNameIsString Then
        _cveStringRelease($fontFileName)
    EndIf
EndFunc   ;==>_cveFreeType2LoadFontData

Func _cveFreeType2SetSplitNumber($freetype, $num)
    ; CVAPI(void) cveFreeType2SetSplitNumber(cv::freetype::FreeType2* freetype, int num);

    Local $bFreetypeDllType
    If VarGetType($freetype) == "DLLStruct" Then
        $bFreetypeDllType = "struct*"
    Else
        $bFreetypeDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFreeType2SetSplitNumber", $bFreetypeDllType, $freetype, "int", $num), "cveFreeType2SetSplitNumber", @error)
EndFunc   ;==>_cveFreeType2SetSplitNumber

Func _cveFreeType2PutText($freetype, $img, $text, $org, $fontHeight, $color, $thickness, $lineType, $bottomLeftOrigin)
    ; CVAPI(void) cveFreeType2PutText(cv::freetype::FreeType2* freetype, cv::_InputOutputArray* img, cv::String* text, CvPoint* org, int fontHeight, CvScalar* color, int thickness, int lineType, bool bottomLeftOrigin);

    Local $bFreetypeDllType
    If VarGetType($freetype) == "DLLStruct" Then
        $bFreetypeDllType = "struct*"
    Else
        $bFreetypeDllType = "ptr"
    EndIf

    Local $bImgDllType
    If VarGetType($img) == "DLLStruct" Then
        $bImgDllType = "struct*"
    Else
        $bImgDllType = "ptr"
    EndIf

    Local $bTextIsString = VarGetType($text) == "String"
    If $bTextIsString Then
        $text = _cveStringCreateFromStr($text)
    EndIf

    Local $bTextDllType
    If VarGetType($text) == "DLLStruct" Then
        $bTextDllType = "struct*"
    Else
        $bTextDllType = "ptr"
    EndIf

    Local $bOrgDllType
    If VarGetType($org) == "DLLStruct" Then
        $bOrgDllType = "struct*"
    Else
        $bOrgDllType = "ptr"
    EndIf

    Local $bColorDllType
    If VarGetType($color) == "DLLStruct" Then
        $bColorDllType = "struct*"
    Else
        $bColorDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFreeType2PutText", $bFreetypeDllType, $freetype, $bImgDllType, $img, $bTextDllType, $text, $bOrgDllType, $org, "int", $fontHeight, $bColorDllType, $color, "int", $thickness, "int", $lineType, "boolean", $bottomLeftOrigin), "cveFreeType2PutText", @error)

    If $bTextIsString Then
        _cveStringRelease($text)
    EndIf
EndFunc   ;==>_cveFreeType2PutText

Func _cveFreeType2PutTextMat($freetype, $matImg, $text, $org, $fontHeight, $color, $thickness, $lineType, $bottomLeftOrigin)
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

Func _cveFreeType2GetTextSize($freetype, $text, $fontHeight, $thickness, $baseLine, $size)
    ; CVAPI(void) cveFreeType2GetTextSize(cv::freetype::FreeType2* freetype, cv::String* text, int fontHeight, int thickness, int* baseLine, CvSize* size);

    Local $bFreetypeDllType
    If VarGetType($freetype) == "DLLStruct" Then
        $bFreetypeDllType = "struct*"
    Else
        $bFreetypeDllType = "ptr"
    EndIf

    Local $bTextIsString = VarGetType($text) == "String"
    If $bTextIsString Then
        $text = _cveStringCreateFromStr($text)
    EndIf

    Local $bTextDllType
    If VarGetType($text) == "DLLStruct" Then
        $bTextDllType = "struct*"
    Else
        $bTextDllType = "ptr"
    EndIf

    Local $bBaseLineDllType
    If VarGetType($baseLine) == "DLLStruct" Then
        $bBaseLineDllType = "struct*"
    Else
        $bBaseLineDllType = "int*"
    EndIf

    Local $bSizeDllType
    If VarGetType($size) == "DLLStruct" Then
        $bSizeDllType = "struct*"
    Else
        $bSizeDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFreeType2GetTextSize", $bFreetypeDllType, $freetype, $bTextDllType, $text, "int", $fontHeight, "int", $thickness, $bBaseLineDllType, $baseLine, $bSizeDllType, $size), "cveFreeType2GetTextSize", @error)

    If $bTextIsString Then
        _cveStringRelease($text)
    EndIf
EndFunc   ;==>_cveFreeType2GetTextSize