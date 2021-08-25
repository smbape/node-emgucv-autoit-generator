#include-once
#include "..\..\CVEUtils.au3"

Func _cveAlphamatInfoFlow($image, $tmap, $result)
    ; CVAPI(void) cveAlphamatInfoFlow(cv::_InputArray* image, cv::_InputArray* tmap, cv::_OutputArray* result);

    Local $sImageDllType
    If IsDllStruct($image) Then
        $sImageDllType = "struct*"
    Else
        $sImageDllType = "ptr"
    EndIf

    Local $sTmapDllType
    If IsDllStruct($tmap) Then
        $sTmapDllType = "struct*"
    Else
        $sTmapDllType = "ptr"
    EndIf

    Local $sResultDllType
    If IsDllStruct($result) Then
        $sResultDllType = "struct*"
    Else
        $sResultDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveAlphamatInfoFlow", $sImageDllType, $image, $sTmapDllType, $tmap, $sResultDllType, $result), "cveAlphamatInfoFlow", @error)
EndFunc   ;==>_cveAlphamatInfoFlow

Func _cveAlphamatInfoFlowTyped($typeOfImage, $image, $typeOfTmap, $tmap, $typeOfResult, $result)

    Local $iArrImage, $vectorImage, $iArrImageSize
    Local $bImageIsArray = IsArray($image)
    Local $bImageCreate = IsDllStruct($image) And $typeOfImage == "Scalar"

    If $typeOfImage == Default Then
        $iArrImage = $image
    ElseIf $bImageIsArray Then
        $vectorImage = Call("_VectorOf" & $typeOfImage & "Create")

        $iArrImageSize = UBound($image)
        For $i = 0 To $iArrImageSize - 1
            Call("_VectorOf" & $typeOfImage & "Push", $vectorImage, $image[$i])
        Next

        $iArrImage = Call("_cveInputArrayFromVectorOf" & $typeOfImage, $vectorImage)
    Else
        If $bImageCreate Then
            $image = Call("_cve" & $typeOfImage & "Create", $image)
        EndIf
        $iArrImage = Call("_cveInputArrayFrom" & $typeOfImage, $image)
    EndIf

    Local $iArrTmap, $vectorTmap, $iArrTmapSize
    Local $bTmapIsArray = IsArray($tmap)
    Local $bTmapCreate = IsDllStruct($tmap) And $typeOfTmap == "Scalar"

    If $typeOfTmap == Default Then
        $iArrTmap = $tmap
    ElseIf $bTmapIsArray Then
        $vectorTmap = Call("_VectorOf" & $typeOfTmap & "Create")

        $iArrTmapSize = UBound($tmap)
        For $i = 0 To $iArrTmapSize - 1
            Call("_VectorOf" & $typeOfTmap & "Push", $vectorTmap, $tmap[$i])
        Next

        $iArrTmap = Call("_cveInputArrayFromVectorOf" & $typeOfTmap, $vectorTmap)
    Else
        If $bTmapCreate Then
            $tmap = Call("_cve" & $typeOfTmap & "Create", $tmap)
        EndIf
        $iArrTmap = Call("_cveInputArrayFrom" & $typeOfTmap, $tmap)
    EndIf

    Local $oArrResult, $vectorResult, $iArrResultSize
    Local $bResultIsArray = IsArray($result)
    Local $bResultCreate = IsDllStruct($result) And $typeOfResult == "Scalar"

    If $typeOfResult == Default Then
        $oArrResult = $result
    ElseIf $bResultIsArray Then
        $vectorResult = Call("_VectorOf" & $typeOfResult & "Create")

        $iArrResultSize = UBound($result)
        For $i = 0 To $iArrResultSize - 1
            Call("_VectorOf" & $typeOfResult & "Push", $vectorResult, $result[$i])
        Next

        $oArrResult = Call("_cveOutputArrayFromVectorOf" & $typeOfResult, $vectorResult)
    Else
        If $bResultCreate Then
            $result = Call("_cve" & $typeOfResult & "Create", $result)
        EndIf
        $oArrResult = Call("_cveOutputArrayFrom" & $typeOfResult, $result)
    EndIf

    _cveAlphamatInfoFlow($iArrImage, $iArrTmap, $oArrResult)

    If $bResultIsArray Then
        Call("_VectorOf" & $typeOfResult & "Release", $vectorResult)
    EndIf

    If $typeOfResult <> Default Then
        _cveOutputArrayRelease($oArrResult)
        If $bResultCreate Then
            Call("_cve" & $typeOfResult & "Release", $result)
        EndIf
    EndIf

    If $bTmapIsArray Then
        Call("_VectorOf" & $typeOfTmap & "Release", $vectorTmap)
    EndIf

    If $typeOfTmap <> Default Then
        _cveInputArrayRelease($iArrTmap)
        If $bTmapCreate Then
            Call("_cve" & $typeOfTmap & "Release", $tmap)
        EndIf
    EndIf

    If $bImageIsArray Then
        Call("_VectorOf" & $typeOfImage & "Release", $vectorImage)
    EndIf

    If $typeOfImage <> Default Then
        _cveInputArrayRelease($iArrImage)
        If $bImageCreate Then
            Call("_cve" & $typeOfImage & "Release", $image)
        EndIf
    EndIf
EndFunc   ;==>_cveAlphamatInfoFlowTyped

Func _cveAlphamatInfoFlowMat($image, $tmap, $result)
    ; cveAlphamatInfoFlow using cv::Mat instead of _*Array
    _cveAlphamatInfoFlowTyped("Mat", $image, "Mat", $tmap, "Mat", $result)
EndFunc   ;==>_cveAlphamatInfoFlowMat