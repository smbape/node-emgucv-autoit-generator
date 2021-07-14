#include-once
#include "..\..\CVEUtils.au3"

Func _cveAlphamatInfoFlow(ByRef $image, ByRef $tmap, ByRef $result)
    ; CVAPI(void) cveAlphamatInfoFlow(cv::_InputArray* image, cv::_InputArray* tmap, cv::_OutputArray* result);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveAlphamatInfoFlow", "ptr", $image, "ptr", $tmap, "ptr", $result), "cveAlphamatInfoFlow", @error)
EndFunc   ;==>_cveAlphamatInfoFlow

Func _cveAlphamatInfoFlowMat(ByRef $matImage, ByRef $matTmap, ByRef $matResult)
    ; cveAlphamatInfoFlow using cv::Mat instead of _*Array

    Local $iArrImage, $vectorOfMatImage, $iArrImageSize
    Local $bImageIsArray = VarGetType($matImage) == "Array"

    If $bImageIsArray Then
        $vectorOfMatImage = _VectorOfMatCreate()

        $iArrImageSize = UBound($matImage)
        For $i = 0 To $iArrImageSize - 1
            _VectorOfMatPush($vectorOfMatImage, $matImage[$i])
        Next

        $iArrImage = _cveInputArrayFromVectorOfMat($vectorOfMatImage)
    Else
        $iArrImage = _cveInputArrayFromMat($matImage)
    EndIf

    Local $iArrTmap, $vectorOfMatTmap, $iArrTmapSize
    Local $bTmapIsArray = VarGetType($matTmap) == "Array"

    If $bTmapIsArray Then
        $vectorOfMatTmap = _VectorOfMatCreate()

        $iArrTmapSize = UBound($matTmap)
        For $i = 0 To $iArrTmapSize - 1
            _VectorOfMatPush($vectorOfMatTmap, $matTmap[$i])
        Next

        $iArrTmap = _cveInputArrayFromVectorOfMat($vectorOfMatTmap)
    Else
        $iArrTmap = _cveInputArrayFromMat($matTmap)
    EndIf

    Local $oArrResult, $vectorOfMatResult, $iArrResultSize
    Local $bResultIsArray = VarGetType($matResult) == "Array"

    If $bResultIsArray Then
        $vectorOfMatResult = _VectorOfMatCreate()

        $iArrResultSize = UBound($matResult)
        For $i = 0 To $iArrResultSize - 1
            _VectorOfMatPush($vectorOfMatResult, $matResult[$i])
        Next

        $oArrResult = _cveOutputArrayFromVectorOfMat($vectorOfMatResult)
    Else
        $oArrResult = _cveOutputArrayFromMat($matResult)
    EndIf

    _cveAlphamatInfoFlow($iArrImage, $iArrTmap, $oArrResult)

    If $bResultIsArray Then
        _VectorOfMatRelease($vectorOfMatResult)
    EndIf

    _cveOutputArrayRelease($oArrResult)

    If $bTmapIsArray Then
        _VectorOfMatRelease($vectorOfMatTmap)
    EndIf

    _cveInputArrayRelease($iArrTmap)

    If $bImageIsArray Then
        _VectorOfMatRelease($vectorOfMatImage)
    EndIf

    _cveInputArrayRelease($iArrImage)
EndFunc   ;==>_cveAlphamatInfoFlowMat