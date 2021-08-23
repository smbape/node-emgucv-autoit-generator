#include-once
#include "..\..\CVEUtils.au3"

Func _cveFreeType2Create($algorithmPtr, $sharedPtr)
    ; CVAPI(cv::freetype::FreeType2*) cveFreeType2Create(cv::Algorithm** algorithmPtr, cv::Ptr<cv::freetype::FreeType2>** sharedPtr);

    Local $sAlgorithmPtrDllType
    If IsDllStruct($algorithmPtr) Then
        $sAlgorithmPtrDllType = "struct*"
    ElseIf $algorithmPtr == Null Then
        $sAlgorithmPtrDllType = "ptr"
    Else
        $sAlgorithmPtrDllType = "ptr*"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveFreeType2Create", $sAlgorithmPtrDllType, $algorithmPtr, $sSharedPtrDllType, $sharedPtr), "cveFreeType2Create", @error)
EndFunc   ;==>_cveFreeType2Create

Func _cveFreeType2Release($sharedPtr)
    ; CVAPI(void) cveFreeType2Release(cv::Ptr<cv::freetype::FreeType2>** sharedPtr);

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFreeType2Release", $sSharedPtrDllType, $sharedPtr), "cveFreeType2Release", @error)
EndFunc   ;==>_cveFreeType2Release

Func _cveFreeType2LoadFontData($freetype, $fontFileName, $id)
    ; CVAPI(void) cveFreeType2LoadFontData(cv::freetype::FreeType2* freetype, cv::String* fontFileName, int id);

    Local $sFreetypeDllType
    If IsDllStruct($freetype) Then
        $sFreetypeDllType = "struct*"
    Else
        $sFreetypeDllType = "ptr"
    EndIf

    Local $bFontFileNameIsString = VarGetType($fontFileName) == "String"
    If $bFontFileNameIsString Then
        $fontFileName = _cveStringCreateFromStr($fontFileName)
    EndIf

    Local $sFontFileNameDllType
    If IsDllStruct($fontFileName) Then
        $sFontFileNameDllType = "struct*"
    Else
        $sFontFileNameDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFreeType2LoadFontData", $sFreetypeDllType, $freetype, $sFontFileNameDllType, $fontFileName, "int", $id), "cveFreeType2LoadFontData", @error)

    If $bFontFileNameIsString Then
        _cveStringRelease($fontFileName)
    EndIf
EndFunc   ;==>_cveFreeType2LoadFontData

Func _cveFreeType2SetSplitNumber($freetype, $num)
    ; CVAPI(void) cveFreeType2SetSplitNumber(cv::freetype::FreeType2* freetype, int num);

    Local $sFreetypeDllType
    If IsDllStruct($freetype) Then
        $sFreetypeDllType = "struct*"
    Else
        $sFreetypeDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFreeType2SetSplitNumber", $sFreetypeDllType, $freetype, "int", $num), "cveFreeType2SetSplitNumber", @error)
EndFunc   ;==>_cveFreeType2SetSplitNumber

Func _cveFreeType2PutText($freetype, $img, $text, $org, $fontHeight, $color, $thickness, $lineType, $bottomLeftOrigin)
    ; CVAPI(void) cveFreeType2PutText(cv::freetype::FreeType2* freetype, cv::_InputOutputArray* img, cv::String* text, CvPoint* org, int fontHeight, CvScalar* color, int thickness, int lineType, bool bottomLeftOrigin);

    Local $sFreetypeDllType
    If IsDllStruct($freetype) Then
        $sFreetypeDllType = "struct*"
    Else
        $sFreetypeDllType = "ptr"
    EndIf

    Local $sImgDllType
    If IsDllStruct($img) Then
        $sImgDllType = "struct*"
    Else
        $sImgDllType = "ptr"
    EndIf

    Local $bTextIsString = VarGetType($text) == "String"
    If $bTextIsString Then
        $text = _cveStringCreateFromStr($text)
    EndIf

    Local $sTextDllType
    If IsDllStruct($text) Then
        $sTextDllType = "struct*"
    Else
        $sTextDllType = "ptr"
    EndIf

    Local $sOrgDllType
    If IsDllStruct($org) Then
        $sOrgDllType = "struct*"
    Else
        $sOrgDllType = "ptr"
    EndIf

    Local $sColorDllType
    If IsDllStruct($color) Then
        $sColorDllType = "struct*"
    Else
        $sColorDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFreeType2PutText", $sFreetypeDllType, $freetype, $sImgDllType, $img, $sTextDllType, $text, $sOrgDllType, $org, "int", $fontHeight, $sColorDllType, $color, "int", $thickness, "int", $lineType, "boolean", $bottomLeftOrigin), "cveFreeType2PutText", @error)

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

    Local $sFreetypeDllType
    If IsDllStruct($freetype) Then
        $sFreetypeDllType = "struct*"
    Else
        $sFreetypeDllType = "ptr"
    EndIf

    Local $bTextIsString = VarGetType($text) == "String"
    If $bTextIsString Then
        $text = _cveStringCreateFromStr($text)
    EndIf

    Local $sTextDllType
    If IsDllStruct($text) Then
        $sTextDllType = "struct*"
    Else
        $sTextDllType = "ptr"
    EndIf

    Local $sBaseLineDllType
    If IsDllStruct($baseLine) Then
        $sBaseLineDllType = "struct*"
    Else
        $sBaseLineDllType = "int*"
    EndIf

    Local $sSizeDllType
    If IsDllStruct($size) Then
        $sSizeDllType = "struct*"
    Else
        $sSizeDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFreeType2GetTextSize", $sFreetypeDllType, $freetype, $sTextDllType, $text, "int", $fontHeight, "int", $thickness, $sBaseLineDllType, $baseLine, $sSizeDllType, $size), "cveFreeType2GetTextSize", @error)

    If $bTextIsString Then
        _cveStringRelease($text)
    EndIf
EndFunc   ;==>_cveFreeType2GetTextSize