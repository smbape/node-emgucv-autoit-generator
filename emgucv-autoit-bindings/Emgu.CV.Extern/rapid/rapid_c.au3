#include-once
#include "..\..\CVEUtils.au3"

Func _cveDrawCorrespondencies(ByRef $bundle, ByRef $cols, ByRef $colors)
    ; CVAPI(void) cveDrawCorrespondencies(cv::_InputOutputArray* bundle, cv::_InputArray* cols, cv::_InputArray* colors);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDrawCorrespondencies", "ptr", $bundle, "ptr", $cols, "ptr", $colors), "cveDrawCorrespondencies", @error)
EndFunc   ;==>_cveDrawCorrespondencies

Func _cveDrawCorrespondenciesMat(ByRef $matBundle, ByRef $matCols, ByRef $matColors)
    ; cveDrawCorrespondencies using cv::Mat instead of _*Array

    Local $ioArrBundle, $vectorOfMatBundle, $iArrBundleSize
    Local $bBundleIsArray = VarGetType($matBundle) == "Array"

    If $bBundleIsArray Then
        $vectorOfMatBundle = _VectorOfMatCreate()

        $iArrBundleSize = UBound($matBundle)
        For $i = 0 To $iArrBundleSize - 1
            _VectorOfMatPush($vectorOfMatBundle, $matBundle[$i])
        Next

        $ioArrBundle = _cveInputOutputArrayFromVectorOfMat($vectorOfMatBundle)
    Else
        $ioArrBundle = _cveInputOutputArrayFromMat($matBundle)
    EndIf

    Local $iArrCols, $vectorOfMatCols, $iArrColsSize
    Local $bColsIsArray = VarGetType($matCols) == "Array"

    If $bColsIsArray Then
        $vectorOfMatCols = _VectorOfMatCreate()

        $iArrColsSize = UBound($matCols)
        For $i = 0 To $iArrColsSize - 1
            _VectorOfMatPush($vectorOfMatCols, $matCols[$i])
        Next

        $iArrCols = _cveInputArrayFromVectorOfMat($vectorOfMatCols)
    Else
        $iArrCols = _cveInputArrayFromMat($matCols)
    EndIf

    Local $iArrColors, $vectorOfMatColors, $iArrColorsSize
    Local $bColorsIsArray = VarGetType($matColors) == "Array"

    If $bColorsIsArray Then
        $vectorOfMatColors = _VectorOfMatCreate()

        $iArrColorsSize = UBound($matColors)
        For $i = 0 To $iArrColorsSize - 1
            _VectorOfMatPush($vectorOfMatColors, $matColors[$i])
        Next

        $iArrColors = _cveInputArrayFromVectorOfMat($vectorOfMatColors)
    Else
        $iArrColors = _cveInputArrayFromMat($matColors)
    EndIf

    _cveDrawCorrespondencies($ioArrBundle, $iArrCols, $iArrColors)

    If $bColorsIsArray Then
        _VectorOfMatRelease($vectorOfMatColors)
    EndIf

    _cveInputArrayRelease($iArrColors)

    If $bColsIsArray Then
        _VectorOfMatRelease($vectorOfMatCols)
    EndIf

    _cveInputArrayRelease($iArrCols)

    If $bBundleIsArray Then
        _VectorOfMatRelease($vectorOfMatBundle)
    EndIf

    _cveInputOutputArrayRelease($ioArrBundle)
EndFunc   ;==>_cveDrawCorrespondenciesMat

Func _cveDrawSearchLines(ByRef $img, ByRef $locations, ByRef $color)
    ; CVAPI(void) cveDrawSearchLines(cv::_InputOutputArray* img, cv::_InputArray* locations, CvScalar* color);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDrawSearchLines", "ptr", $img, "ptr", $locations, "struct*", $color), "cveDrawSearchLines", @error)
EndFunc   ;==>_cveDrawSearchLines

Func _cveDrawSearchLinesMat(ByRef $matImg, ByRef $matLocations, ByRef $color)
    ; cveDrawSearchLines using cv::Mat instead of _*Array

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

    Local $iArrLocations, $vectorOfMatLocations, $iArrLocationsSize
    Local $bLocationsIsArray = VarGetType($matLocations) == "Array"

    If $bLocationsIsArray Then
        $vectorOfMatLocations = _VectorOfMatCreate()

        $iArrLocationsSize = UBound($matLocations)
        For $i = 0 To $iArrLocationsSize - 1
            _VectorOfMatPush($vectorOfMatLocations, $matLocations[$i])
        Next

        $iArrLocations = _cveInputArrayFromVectorOfMat($vectorOfMatLocations)
    Else
        $iArrLocations = _cveInputArrayFromMat($matLocations)
    EndIf

    _cveDrawSearchLines($ioArrImg, $iArrLocations, $color)

    If $bLocationsIsArray Then
        _VectorOfMatRelease($vectorOfMatLocations)
    EndIf

    _cveInputArrayRelease($iArrLocations)

    If $bImgIsArray Then
        _VectorOfMatRelease($vectorOfMatImg)
    EndIf

    _cveInputOutputArrayRelease($ioArrImg)
EndFunc   ;==>_cveDrawSearchLinesMat

Func _cveDrawWireframe(ByRef $img, ByRef $pts2d, ByRef $tris, ByRef $color, $type, $cullBackface)
    ; CVAPI(void) cveDrawWireframe(cv::_InputOutputArray* img, cv::_InputArray* pts2d, cv::_InputArray* tris, CvScalar* color, int type, bool cullBackface);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDrawWireframe", "ptr", $img, "ptr", $pts2d, "ptr", $tris, "struct*", $color, "int", $type, "boolean", $cullBackface), "cveDrawWireframe", @error)
EndFunc   ;==>_cveDrawWireframe

Func _cveDrawWireframeMat(ByRef $matImg, ByRef $matPts2d, ByRef $matTris, ByRef $color, $type, $cullBackface)
    ; cveDrawWireframe using cv::Mat instead of _*Array

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

    Local $iArrPts2d, $vectorOfMatPts2d, $iArrPts2dSize
    Local $bPts2dIsArray = VarGetType($matPts2d) == "Array"

    If $bPts2dIsArray Then
        $vectorOfMatPts2d = _VectorOfMatCreate()

        $iArrPts2dSize = UBound($matPts2d)
        For $i = 0 To $iArrPts2dSize - 1
            _VectorOfMatPush($vectorOfMatPts2d, $matPts2d[$i])
        Next

        $iArrPts2d = _cveInputArrayFromVectorOfMat($vectorOfMatPts2d)
    Else
        $iArrPts2d = _cveInputArrayFromMat($matPts2d)
    EndIf

    Local $iArrTris, $vectorOfMatTris, $iArrTrisSize
    Local $bTrisIsArray = VarGetType($matTris) == "Array"

    If $bTrisIsArray Then
        $vectorOfMatTris = _VectorOfMatCreate()

        $iArrTrisSize = UBound($matTris)
        For $i = 0 To $iArrTrisSize - 1
            _VectorOfMatPush($vectorOfMatTris, $matTris[$i])
        Next

        $iArrTris = _cveInputArrayFromVectorOfMat($vectorOfMatTris)
    Else
        $iArrTris = _cveInputArrayFromMat($matTris)
    EndIf

    _cveDrawWireframe($ioArrImg, $iArrPts2d, $iArrTris, $color, $type, $cullBackface)

    If $bTrisIsArray Then
        _VectorOfMatRelease($vectorOfMatTris)
    EndIf

    _cveInputArrayRelease($iArrTris)

    If $bPts2dIsArray Then
        _VectorOfMatRelease($vectorOfMatPts2d)
    EndIf

    _cveInputArrayRelease($iArrPts2d)

    If $bImgIsArray Then
        _VectorOfMatRelease($vectorOfMatImg)
    EndIf

    _cveInputOutputArrayRelease($ioArrImg)
EndFunc   ;==>_cveDrawWireframeMat

Func _cveExtractControlPoints($num, $len, ByRef $pts3d, ByRef $rvec, ByRef $tvec, ByRef $K, ByRef $imsize, ByRef $tris, ByRef $ctl2d, ByRef $ctl3d)
    ; CVAPI(void) cveExtractControlPoints(int num, int len, cv::_InputArray* pts3d, cv::_InputArray* rvec, cv::_InputArray* tvec, cv::_InputArray* K, CvSize* imsize, cv::_InputArray* tris, cv::_OutputArray* ctl2d, cv::_OutputArray* ctl3d);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveExtractControlPoints", "int", $num, "int", $len, "ptr", $pts3d, "ptr", $rvec, "ptr", $tvec, "ptr", $K, "struct*", $imsize, "ptr", $tris, "ptr", $ctl2d, "ptr", $ctl3d), "cveExtractControlPoints", @error)
EndFunc   ;==>_cveExtractControlPoints

Func _cveExtractControlPointsMat($num, $len, ByRef $matPts3d, ByRef $matRvec, ByRef $matTvec, ByRef $matK, ByRef $imsize, ByRef $matTris, ByRef $matCtl2d, ByRef $matCtl3d)
    ; cveExtractControlPoints using cv::Mat instead of _*Array

    Local $iArrPts3d, $vectorOfMatPts3d, $iArrPts3dSize
    Local $bPts3dIsArray = VarGetType($matPts3d) == "Array"

    If $bPts3dIsArray Then
        $vectorOfMatPts3d = _VectorOfMatCreate()

        $iArrPts3dSize = UBound($matPts3d)
        For $i = 0 To $iArrPts3dSize - 1
            _VectorOfMatPush($vectorOfMatPts3d, $matPts3d[$i])
        Next

        $iArrPts3d = _cveInputArrayFromVectorOfMat($vectorOfMatPts3d)
    Else
        $iArrPts3d = _cveInputArrayFromMat($matPts3d)
    EndIf

    Local $iArrRvec, $vectorOfMatRvec, $iArrRvecSize
    Local $bRvecIsArray = VarGetType($matRvec) == "Array"

    If $bRvecIsArray Then
        $vectorOfMatRvec = _VectorOfMatCreate()

        $iArrRvecSize = UBound($matRvec)
        For $i = 0 To $iArrRvecSize - 1
            _VectorOfMatPush($vectorOfMatRvec, $matRvec[$i])
        Next

        $iArrRvec = _cveInputArrayFromVectorOfMat($vectorOfMatRvec)
    Else
        $iArrRvec = _cveInputArrayFromMat($matRvec)
    EndIf

    Local $iArrTvec, $vectorOfMatTvec, $iArrTvecSize
    Local $bTvecIsArray = VarGetType($matTvec) == "Array"

    If $bTvecIsArray Then
        $vectorOfMatTvec = _VectorOfMatCreate()

        $iArrTvecSize = UBound($matTvec)
        For $i = 0 To $iArrTvecSize - 1
            _VectorOfMatPush($vectorOfMatTvec, $matTvec[$i])
        Next

        $iArrTvec = _cveInputArrayFromVectorOfMat($vectorOfMatTvec)
    Else
        $iArrTvec = _cveInputArrayFromMat($matTvec)
    EndIf

    Local $iArrK, $vectorOfMatK, $iArrKSize
    Local $bKIsArray = VarGetType($matK) == "Array"

    If $bKIsArray Then
        $vectorOfMatK = _VectorOfMatCreate()

        $iArrKSize = UBound($matK)
        For $i = 0 To $iArrKSize - 1
            _VectorOfMatPush($vectorOfMatK, $matK[$i])
        Next

        $iArrK = _cveInputArrayFromVectorOfMat($vectorOfMatK)
    Else
        $iArrK = _cveInputArrayFromMat($matK)
    EndIf

    Local $iArrTris, $vectorOfMatTris, $iArrTrisSize
    Local $bTrisIsArray = VarGetType($matTris) == "Array"

    If $bTrisIsArray Then
        $vectorOfMatTris = _VectorOfMatCreate()

        $iArrTrisSize = UBound($matTris)
        For $i = 0 To $iArrTrisSize - 1
            _VectorOfMatPush($vectorOfMatTris, $matTris[$i])
        Next

        $iArrTris = _cveInputArrayFromVectorOfMat($vectorOfMatTris)
    Else
        $iArrTris = _cveInputArrayFromMat($matTris)
    EndIf

    Local $oArrCtl2d, $vectorOfMatCtl2d, $iArrCtl2dSize
    Local $bCtl2dIsArray = VarGetType($matCtl2d) == "Array"

    If $bCtl2dIsArray Then
        $vectorOfMatCtl2d = _VectorOfMatCreate()

        $iArrCtl2dSize = UBound($matCtl2d)
        For $i = 0 To $iArrCtl2dSize - 1
            _VectorOfMatPush($vectorOfMatCtl2d, $matCtl2d[$i])
        Next

        $oArrCtl2d = _cveOutputArrayFromVectorOfMat($vectorOfMatCtl2d)
    Else
        $oArrCtl2d = _cveOutputArrayFromMat($matCtl2d)
    EndIf

    Local $oArrCtl3d, $vectorOfMatCtl3d, $iArrCtl3dSize
    Local $bCtl3dIsArray = VarGetType($matCtl3d) == "Array"

    If $bCtl3dIsArray Then
        $vectorOfMatCtl3d = _VectorOfMatCreate()

        $iArrCtl3dSize = UBound($matCtl3d)
        For $i = 0 To $iArrCtl3dSize - 1
            _VectorOfMatPush($vectorOfMatCtl3d, $matCtl3d[$i])
        Next

        $oArrCtl3d = _cveOutputArrayFromVectorOfMat($vectorOfMatCtl3d)
    Else
        $oArrCtl3d = _cveOutputArrayFromMat($matCtl3d)
    EndIf

    _cveExtractControlPoints($num, $len, $iArrPts3d, $iArrRvec, $iArrTvec, $iArrK, $imsize, $iArrTris, $oArrCtl2d, $oArrCtl3d)

    If $bCtl3dIsArray Then
        _VectorOfMatRelease($vectorOfMatCtl3d)
    EndIf

    _cveOutputArrayRelease($oArrCtl3d)

    If $bCtl2dIsArray Then
        _VectorOfMatRelease($vectorOfMatCtl2d)
    EndIf

    _cveOutputArrayRelease($oArrCtl2d)

    If $bTrisIsArray Then
        _VectorOfMatRelease($vectorOfMatTris)
    EndIf

    _cveInputArrayRelease($iArrTris)

    If $bKIsArray Then
        _VectorOfMatRelease($vectorOfMatK)
    EndIf

    _cveInputArrayRelease($iArrK)

    If $bTvecIsArray Then
        _VectorOfMatRelease($vectorOfMatTvec)
    EndIf

    _cveInputArrayRelease($iArrTvec)

    If $bRvecIsArray Then
        _VectorOfMatRelease($vectorOfMatRvec)
    EndIf

    _cveInputArrayRelease($iArrRvec)

    If $bPts3dIsArray Then
        _VectorOfMatRelease($vectorOfMatPts3d)
    EndIf

    _cveInputArrayRelease($iArrPts3d)
EndFunc   ;==>_cveExtractControlPointsMat

Func _cveExtractLineBundle($len, ByRef $ctl2d, ByRef $img, ByRef $bundle, ByRef $srcLocations)
    ; CVAPI(void) cveExtractLineBundle(int len, cv::_InputArray* ctl2d, cv::_InputArray* img, cv::_OutputArray* bundle, cv::_OutputArray* srcLocations);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveExtractLineBundle", "int", $len, "ptr", $ctl2d, "ptr", $img, "ptr", $bundle, "ptr", $srcLocations), "cveExtractLineBundle", @error)
EndFunc   ;==>_cveExtractLineBundle

Func _cveExtractLineBundleMat($len, ByRef $matCtl2d, ByRef $matImg, ByRef $matBundle, ByRef $matSrcLocations)
    ; cveExtractLineBundle using cv::Mat instead of _*Array

    Local $iArrCtl2d, $vectorOfMatCtl2d, $iArrCtl2dSize
    Local $bCtl2dIsArray = VarGetType($matCtl2d) == "Array"

    If $bCtl2dIsArray Then
        $vectorOfMatCtl2d = _VectorOfMatCreate()

        $iArrCtl2dSize = UBound($matCtl2d)
        For $i = 0 To $iArrCtl2dSize - 1
            _VectorOfMatPush($vectorOfMatCtl2d, $matCtl2d[$i])
        Next

        $iArrCtl2d = _cveInputArrayFromVectorOfMat($vectorOfMatCtl2d)
    Else
        $iArrCtl2d = _cveInputArrayFromMat($matCtl2d)
    EndIf

    Local $iArrImg, $vectorOfMatImg, $iArrImgSize
    Local $bImgIsArray = VarGetType($matImg) == "Array"

    If $bImgIsArray Then
        $vectorOfMatImg = _VectorOfMatCreate()

        $iArrImgSize = UBound($matImg)
        For $i = 0 To $iArrImgSize - 1
            _VectorOfMatPush($vectorOfMatImg, $matImg[$i])
        Next

        $iArrImg = _cveInputArrayFromVectorOfMat($vectorOfMatImg)
    Else
        $iArrImg = _cveInputArrayFromMat($matImg)
    EndIf

    Local $oArrBundle, $vectorOfMatBundle, $iArrBundleSize
    Local $bBundleIsArray = VarGetType($matBundle) == "Array"

    If $bBundleIsArray Then
        $vectorOfMatBundle = _VectorOfMatCreate()

        $iArrBundleSize = UBound($matBundle)
        For $i = 0 To $iArrBundleSize - 1
            _VectorOfMatPush($vectorOfMatBundle, $matBundle[$i])
        Next

        $oArrBundle = _cveOutputArrayFromVectorOfMat($vectorOfMatBundle)
    Else
        $oArrBundle = _cveOutputArrayFromMat($matBundle)
    EndIf

    Local $oArrSrcLocations, $vectorOfMatSrcLocations, $iArrSrcLocationsSize
    Local $bSrcLocationsIsArray = VarGetType($matSrcLocations) == "Array"

    If $bSrcLocationsIsArray Then
        $vectorOfMatSrcLocations = _VectorOfMatCreate()

        $iArrSrcLocationsSize = UBound($matSrcLocations)
        For $i = 0 To $iArrSrcLocationsSize - 1
            _VectorOfMatPush($vectorOfMatSrcLocations, $matSrcLocations[$i])
        Next

        $oArrSrcLocations = _cveOutputArrayFromVectorOfMat($vectorOfMatSrcLocations)
    Else
        $oArrSrcLocations = _cveOutputArrayFromMat($matSrcLocations)
    EndIf

    _cveExtractLineBundle($len, $iArrCtl2d, $iArrImg, $oArrBundle, $oArrSrcLocations)

    If $bSrcLocationsIsArray Then
        _VectorOfMatRelease($vectorOfMatSrcLocations)
    EndIf

    _cveOutputArrayRelease($oArrSrcLocations)

    If $bBundleIsArray Then
        _VectorOfMatRelease($vectorOfMatBundle)
    EndIf

    _cveOutputArrayRelease($oArrBundle)

    If $bImgIsArray Then
        _VectorOfMatRelease($vectorOfMatImg)
    EndIf

    _cveInputArrayRelease($iArrImg)

    If $bCtl2dIsArray Then
        _VectorOfMatRelease($vectorOfMatCtl2d)
    EndIf

    _cveInputArrayRelease($iArrCtl2d)
EndFunc   ;==>_cveExtractLineBundleMat

Func _cveFindCorrespondencies(ByRef $bundle, ByRef $cols, ByRef $response)
    ; CVAPI(void) cveFindCorrespondencies(cv::_InputArray* bundle, cv::_OutputArray* cols, cv::_OutputArray* response);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFindCorrespondencies", "ptr", $bundle, "ptr", $cols, "ptr", $response), "cveFindCorrespondencies", @error)
EndFunc   ;==>_cveFindCorrespondencies

Func _cveFindCorrespondenciesMat(ByRef $matBundle, ByRef $matCols, ByRef $matResponse)
    ; cveFindCorrespondencies using cv::Mat instead of _*Array

    Local $iArrBundle, $vectorOfMatBundle, $iArrBundleSize
    Local $bBundleIsArray = VarGetType($matBundle) == "Array"

    If $bBundleIsArray Then
        $vectorOfMatBundle = _VectorOfMatCreate()

        $iArrBundleSize = UBound($matBundle)
        For $i = 0 To $iArrBundleSize - 1
            _VectorOfMatPush($vectorOfMatBundle, $matBundle[$i])
        Next

        $iArrBundle = _cveInputArrayFromVectorOfMat($vectorOfMatBundle)
    Else
        $iArrBundle = _cveInputArrayFromMat($matBundle)
    EndIf

    Local $oArrCols, $vectorOfMatCols, $iArrColsSize
    Local $bColsIsArray = VarGetType($matCols) == "Array"

    If $bColsIsArray Then
        $vectorOfMatCols = _VectorOfMatCreate()

        $iArrColsSize = UBound($matCols)
        For $i = 0 To $iArrColsSize - 1
            _VectorOfMatPush($vectorOfMatCols, $matCols[$i])
        Next

        $oArrCols = _cveOutputArrayFromVectorOfMat($vectorOfMatCols)
    Else
        $oArrCols = _cveOutputArrayFromMat($matCols)
    EndIf

    Local $oArrResponse, $vectorOfMatResponse, $iArrResponseSize
    Local $bResponseIsArray = VarGetType($matResponse) == "Array"

    If $bResponseIsArray Then
        $vectorOfMatResponse = _VectorOfMatCreate()

        $iArrResponseSize = UBound($matResponse)
        For $i = 0 To $iArrResponseSize - 1
            _VectorOfMatPush($vectorOfMatResponse, $matResponse[$i])
        Next

        $oArrResponse = _cveOutputArrayFromVectorOfMat($vectorOfMatResponse)
    Else
        $oArrResponse = _cveOutputArrayFromMat($matResponse)
    EndIf

    _cveFindCorrespondencies($iArrBundle, $oArrCols, $oArrResponse)

    If $bResponseIsArray Then
        _VectorOfMatRelease($vectorOfMatResponse)
    EndIf

    _cveOutputArrayRelease($oArrResponse)

    If $bColsIsArray Then
        _VectorOfMatRelease($vectorOfMatCols)
    EndIf

    _cveOutputArrayRelease($oArrCols)

    If $bBundleIsArray Then
        _VectorOfMatRelease($vectorOfMatBundle)
    EndIf

    _cveInputArrayRelease($iArrBundle)
EndFunc   ;==>_cveFindCorrespondenciesMat

Func _cveConvertCorrespondencies(ByRef $cols, ByRef $srcLocations, ByRef $pts2d, ByRef $pts3d, ByRef $mask)
    ; CVAPI(void) cveConvertCorrespondencies(cv::_InputArray* cols, cv::_InputArray* srcLocations, cv::_OutputArray* pts2d, cv::_InputOutputArray* pts3d, cv::_InputArray* mask);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveConvertCorrespondencies", "ptr", $cols, "ptr", $srcLocations, "ptr", $pts2d, "ptr", $pts3d, "ptr", $mask), "cveConvertCorrespondencies", @error)
EndFunc   ;==>_cveConvertCorrespondencies

Func _cveConvertCorrespondenciesMat(ByRef $matCols, ByRef $matSrcLocations, ByRef $matPts2d, ByRef $matPts3d, ByRef $matMask)
    ; cveConvertCorrespondencies using cv::Mat instead of _*Array

    Local $iArrCols, $vectorOfMatCols, $iArrColsSize
    Local $bColsIsArray = VarGetType($matCols) == "Array"

    If $bColsIsArray Then
        $vectorOfMatCols = _VectorOfMatCreate()

        $iArrColsSize = UBound($matCols)
        For $i = 0 To $iArrColsSize - 1
            _VectorOfMatPush($vectorOfMatCols, $matCols[$i])
        Next

        $iArrCols = _cveInputArrayFromVectorOfMat($vectorOfMatCols)
    Else
        $iArrCols = _cveInputArrayFromMat($matCols)
    EndIf

    Local $iArrSrcLocations, $vectorOfMatSrcLocations, $iArrSrcLocationsSize
    Local $bSrcLocationsIsArray = VarGetType($matSrcLocations) == "Array"

    If $bSrcLocationsIsArray Then
        $vectorOfMatSrcLocations = _VectorOfMatCreate()

        $iArrSrcLocationsSize = UBound($matSrcLocations)
        For $i = 0 To $iArrSrcLocationsSize - 1
            _VectorOfMatPush($vectorOfMatSrcLocations, $matSrcLocations[$i])
        Next

        $iArrSrcLocations = _cveInputArrayFromVectorOfMat($vectorOfMatSrcLocations)
    Else
        $iArrSrcLocations = _cveInputArrayFromMat($matSrcLocations)
    EndIf

    Local $oArrPts2d, $vectorOfMatPts2d, $iArrPts2dSize
    Local $bPts2dIsArray = VarGetType($matPts2d) == "Array"

    If $bPts2dIsArray Then
        $vectorOfMatPts2d = _VectorOfMatCreate()

        $iArrPts2dSize = UBound($matPts2d)
        For $i = 0 To $iArrPts2dSize - 1
            _VectorOfMatPush($vectorOfMatPts2d, $matPts2d[$i])
        Next

        $oArrPts2d = _cveOutputArrayFromVectorOfMat($vectorOfMatPts2d)
    Else
        $oArrPts2d = _cveOutputArrayFromMat($matPts2d)
    EndIf

    Local $ioArrPts3d, $vectorOfMatPts3d, $iArrPts3dSize
    Local $bPts3dIsArray = VarGetType($matPts3d) == "Array"

    If $bPts3dIsArray Then
        $vectorOfMatPts3d = _VectorOfMatCreate()

        $iArrPts3dSize = UBound($matPts3d)
        For $i = 0 To $iArrPts3dSize - 1
            _VectorOfMatPush($vectorOfMatPts3d, $matPts3d[$i])
        Next

        $ioArrPts3d = _cveInputOutputArrayFromVectorOfMat($vectorOfMatPts3d)
    Else
        $ioArrPts3d = _cveInputOutputArrayFromMat($matPts3d)
    EndIf

    Local $iArrMask, $vectorOfMatMask, $iArrMaskSize
    Local $bMaskIsArray = VarGetType($matMask) == "Array"

    If $bMaskIsArray Then
        $vectorOfMatMask = _VectorOfMatCreate()

        $iArrMaskSize = UBound($matMask)
        For $i = 0 To $iArrMaskSize - 1
            _VectorOfMatPush($vectorOfMatMask, $matMask[$i])
        Next

        $iArrMask = _cveInputArrayFromVectorOfMat($vectorOfMatMask)
    Else
        $iArrMask = _cveInputArrayFromMat($matMask)
    EndIf

    _cveConvertCorrespondencies($iArrCols, $iArrSrcLocations, $oArrPts2d, $ioArrPts3d, $iArrMask)

    If $bMaskIsArray Then
        _VectorOfMatRelease($vectorOfMatMask)
    EndIf

    _cveInputArrayRelease($iArrMask)

    If $bPts3dIsArray Then
        _VectorOfMatRelease($vectorOfMatPts3d)
    EndIf

    _cveInputOutputArrayRelease($ioArrPts3d)

    If $bPts2dIsArray Then
        _VectorOfMatRelease($vectorOfMatPts2d)
    EndIf

    _cveOutputArrayRelease($oArrPts2d)

    If $bSrcLocationsIsArray Then
        _VectorOfMatRelease($vectorOfMatSrcLocations)
    EndIf

    _cveInputArrayRelease($iArrSrcLocations)

    If $bColsIsArray Then
        _VectorOfMatRelease($vectorOfMatCols)
    EndIf

    _cveInputArrayRelease($iArrCols)
EndFunc   ;==>_cveConvertCorrespondenciesMat

Func _cveRapid(ByRef $img, $num, $len, ByRef $pts3d, ByRef $tris, ByRef $K, ByRef $rvec, ByRef $tvec, ByRef $rmsd)
    ; CVAPI(float) cveRapid(cv::_InputArray* img, int num, int len, cv::_InputArray* pts3d, cv::_InputArray* tris, cv::_InputArray* K, cv::_InputOutputArray* rvec, cv::_InputOutputArray* tvec, double* rmsd);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cveRapid", "ptr", $img, "int", $num, "int", $len, "ptr", $pts3d, "ptr", $tris, "ptr", $K, "ptr", $rvec, "ptr", $tvec, "struct*", $rmsd), "cveRapid", @error)
EndFunc   ;==>_cveRapid

Func _cveRapidMat(ByRef $matImg, $num, $len, ByRef $matPts3d, ByRef $matTris, ByRef $matK, ByRef $matRvec, ByRef $matTvec, ByRef $rmsd)
    ; cveRapid using cv::Mat instead of _*Array

    Local $iArrImg, $vectorOfMatImg, $iArrImgSize
    Local $bImgIsArray = VarGetType($matImg) == "Array"

    If $bImgIsArray Then
        $vectorOfMatImg = _VectorOfMatCreate()

        $iArrImgSize = UBound($matImg)
        For $i = 0 To $iArrImgSize - 1
            _VectorOfMatPush($vectorOfMatImg, $matImg[$i])
        Next

        $iArrImg = _cveInputArrayFromVectorOfMat($vectorOfMatImg)
    Else
        $iArrImg = _cveInputArrayFromMat($matImg)
    EndIf

    Local $iArrPts3d, $vectorOfMatPts3d, $iArrPts3dSize
    Local $bPts3dIsArray = VarGetType($matPts3d) == "Array"

    If $bPts3dIsArray Then
        $vectorOfMatPts3d = _VectorOfMatCreate()

        $iArrPts3dSize = UBound($matPts3d)
        For $i = 0 To $iArrPts3dSize - 1
            _VectorOfMatPush($vectorOfMatPts3d, $matPts3d[$i])
        Next

        $iArrPts3d = _cveInputArrayFromVectorOfMat($vectorOfMatPts3d)
    Else
        $iArrPts3d = _cveInputArrayFromMat($matPts3d)
    EndIf

    Local $iArrTris, $vectorOfMatTris, $iArrTrisSize
    Local $bTrisIsArray = VarGetType($matTris) == "Array"

    If $bTrisIsArray Then
        $vectorOfMatTris = _VectorOfMatCreate()

        $iArrTrisSize = UBound($matTris)
        For $i = 0 To $iArrTrisSize - 1
            _VectorOfMatPush($vectorOfMatTris, $matTris[$i])
        Next

        $iArrTris = _cveInputArrayFromVectorOfMat($vectorOfMatTris)
    Else
        $iArrTris = _cveInputArrayFromMat($matTris)
    EndIf

    Local $iArrK, $vectorOfMatK, $iArrKSize
    Local $bKIsArray = VarGetType($matK) == "Array"

    If $bKIsArray Then
        $vectorOfMatK = _VectorOfMatCreate()

        $iArrKSize = UBound($matK)
        For $i = 0 To $iArrKSize - 1
            _VectorOfMatPush($vectorOfMatK, $matK[$i])
        Next

        $iArrK = _cveInputArrayFromVectorOfMat($vectorOfMatK)
    Else
        $iArrK = _cveInputArrayFromMat($matK)
    EndIf

    Local $ioArrRvec, $vectorOfMatRvec, $iArrRvecSize
    Local $bRvecIsArray = VarGetType($matRvec) == "Array"

    If $bRvecIsArray Then
        $vectorOfMatRvec = _VectorOfMatCreate()

        $iArrRvecSize = UBound($matRvec)
        For $i = 0 To $iArrRvecSize - 1
            _VectorOfMatPush($vectorOfMatRvec, $matRvec[$i])
        Next

        $ioArrRvec = _cveInputOutputArrayFromVectorOfMat($vectorOfMatRvec)
    Else
        $ioArrRvec = _cveInputOutputArrayFromMat($matRvec)
    EndIf

    Local $ioArrTvec, $vectorOfMatTvec, $iArrTvecSize
    Local $bTvecIsArray = VarGetType($matTvec) == "Array"

    If $bTvecIsArray Then
        $vectorOfMatTvec = _VectorOfMatCreate()

        $iArrTvecSize = UBound($matTvec)
        For $i = 0 To $iArrTvecSize - 1
            _VectorOfMatPush($vectorOfMatTvec, $matTvec[$i])
        Next

        $ioArrTvec = _cveInputOutputArrayFromVectorOfMat($vectorOfMatTvec)
    Else
        $ioArrTvec = _cveInputOutputArrayFromMat($matTvec)
    EndIf

    Local $retval = _cveRapid($iArrImg, $num, $len, $iArrPts3d, $iArrTris, $iArrK, $ioArrRvec, $ioArrTvec, $rmsd)

    If $bTvecIsArray Then
        _VectorOfMatRelease($vectorOfMatTvec)
    EndIf

    _cveInputOutputArrayRelease($ioArrTvec)

    If $bRvecIsArray Then
        _VectorOfMatRelease($vectorOfMatRvec)
    EndIf

    _cveInputOutputArrayRelease($ioArrRvec)

    If $bKIsArray Then
        _VectorOfMatRelease($vectorOfMatK)
    EndIf

    _cveInputArrayRelease($iArrK)

    If $bTrisIsArray Then
        _VectorOfMatRelease($vectorOfMatTris)
    EndIf

    _cveInputArrayRelease($iArrTris)

    If $bPts3dIsArray Then
        _VectorOfMatRelease($vectorOfMatPts3d)
    EndIf

    _cveInputArrayRelease($iArrPts3d)

    If $bImgIsArray Then
        _VectorOfMatRelease($vectorOfMatImg)
    EndIf

    _cveInputArrayRelease($iArrImg)

    Return $retval
EndFunc   ;==>_cveRapidMat

Func _cveTrackerCompute(ByRef $tracker, ByRef $img, $num, $len, ByRef $K, ByRef $rvec, ByRef $tvec, ByRef $termcrit)
    ; CVAPI(float) cveTrackerCompute(cv::rapid::Tracker* tracker, cv::_InputArray* img, int num, int len, cv::_InputArray* K, cv::_InputOutputArray* rvec, cv::_InputOutputArray* tvec, CvTermCriteria* termcrit);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cveTrackerCompute", "ptr", $tracker, "ptr", $img, "int", $num, "int", $len, "ptr", $K, "ptr", $rvec, "ptr", $tvec, "struct*", $termcrit), "cveTrackerCompute", @error)
EndFunc   ;==>_cveTrackerCompute

Func _cveTrackerComputeMat(ByRef $tracker, ByRef $matImg, $num, $len, ByRef $matK, ByRef $matRvec, ByRef $matTvec, ByRef $termcrit)
    ; cveTrackerCompute using cv::Mat instead of _*Array

    Local $iArrImg, $vectorOfMatImg, $iArrImgSize
    Local $bImgIsArray = VarGetType($matImg) == "Array"

    If $bImgIsArray Then
        $vectorOfMatImg = _VectorOfMatCreate()

        $iArrImgSize = UBound($matImg)
        For $i = 0 To $iArrImgSize - 1
            _VectorOfMatPush($vectorOfMatImg, $matImg[$i])
        Next

        $iArrImg = _cveInputArrayFromVectorOfMat($vectorOfMatImg)
    Else
        $iArrImg = _cveInputArrayFromMat($matImg)
    EndIf

    Local $iArrK, $vectorOfMatK, $iArrKSize
    Local $bKIsArray = VarGetType($matK) == "Array"

    If $bKIsArray Then
        $vectorOfMatK = _VectorOfMatCreate()

        $iArrKSize = UBound($matK)
        For $i = 0 To $iArrKSize - 1
            _VectorOfMatPush($vectorOfMatK, $matK[$i])
        Next

        $iArrK = _cveInputArrayFromVectorOfMat($vectorOfMatK)
    Else
        $iArrK = _cveInputArrayFromMat($matK)
    EndIf

    Local $ioArrRvec, $vectorOfMatRvec, $iArrRvecSize
    Local $bRvecIsArray = VarGetType($matRvec) == "Array"

    If $bRvecIsArray Then
        $vectorOfMatRvec = _VectorOfMatCreate()

        $iArrRvecSize = UBound($matRvec)
        For $i = 0 To $iArrRvecSize - 1
            _VectorOfMatPush($vectorOfMatRvec, $matRvec[$i])
        Next

        $ioArrRvec = _cveInputOutputArrayFromVectorOfMat($vectorOfMatRvec)
    Else
        $ioArrRvec = _cveInputOutputArrayFromMat($matRvec)
    EndIf

    Local $ioArrTvec, $vectorOfMatTvec, $iArrTvecSize
    Local $bTvecIsArray = VarGetType($matTvec) == "Array"

    If $bTvecIsArray Then
        $vectorOfMatTvec = _VectorOfMatCreate()

        $iArrTvecSize = UBound($matTvec)
        For $i = 0 To $iArrTvecSize - 1
            _VectorOfMatPush($vectorOfMatTvec, $matTvec[$i])
        Next

        $ioArrTvec = _cveInputOutputArrayFromVectorOfMat($vectorOfMatTvec)
    Else
        $ioArrTvec = _cveInputOutputArrayFromMat($matTvec)
    EndIf

    Local $retval = _cveTrackerCompute($tracker, $iArrImg, $num, $len, $iArrK, $ioArrRvec, $ioArrTvec, $termcrit)

    If $bTvecIsArray Then
        _VectorOfMatRelease($vectorOfMatTvec)
    EndIf

    _cveInputOutputArrayRelease($ioArrTvec)

    If $bRvecIsArray Then
        _VectorOfMatRelease($vectorOfMatRvec)
    EndIf

    _cveInputOutputArrayRelease($ioArrRvec)

    If $bKIsArray Then
        _VectorOfMatRelease($vectorOfMatK)
    EndIf

    _cveInputArrayRelease($iArrK)

    If $bImgIsArray Then
        _VectorOfMatRelease($vectorOfMatImg)
    EndIf

    _cveInputArrayRelease($iArrImg)

    Return $retval
EndFunc   ;==>_cveTrackerComputeMat

Func _cveTrackerClearState(ByRef $tracker)
    ; CVAPI(void) cveTrackerClearState(cv::rapid::Tracker* tracker);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveTrackerClearState", "ptr", $tracker), "cveTrackerClearState", @error)
EndFunc   ;==>_cveTrackerClearState

Func _cveRapidCreate(ByRef $pts3d, ByRef $tris, ByRef $tracker, ByRef $algorithm, ByRef $sharedPtr)
    ; CVAPI(cv::rapid::Rapid*) cveRapidCreate(cv::_InputArray* pts3d, cv::_InputArray* tris, cv::rapid::Tracker** tracker, cv::Algorithm** algorithm, cv::Ptr<cv::rapid::Rapid>** sharedPtr);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveRapidCreate", "ptr", $pts3d, "ptr", $tris, "ptr*", $tracker, "ptr*", $algorithm, "ptr*", $sharedPtr), "cveRapidCreate", @error)
EndFunc   ;==>_cveRapidCreate

Func _cveRapidCreateMat(ByRef $matPts3d, ByRef $matTris, ByRef $tracker, ByRef $algorithm, ByRef $sharedPtr)
    ; cveRapidCreate using cv::Mat instead of _*Array

    Local $iArrPts3d, $vectorOfMatPts3d, $iArrPts3dSize
    Local $bPts3dIsArray = VarGetType($matPts3d) == "Array"

    If $bPts3dIsArray Then
        $vectorOfMatPts3d = _VectorOfMatCreate()

        $iArrPts3dSize = UBound($matPts3d)
        For $i = 0 To $iArrPts3dSize - 1
            _VectorOfMatPush($vectorOfMatPts3d, $matPts3d[$i])
        Next

        $iArrPts3d = _cveInputArrayFromVectorOfMat($vectorOfMatPts3d)
    Else
        $iArrPts3d = _cveInputArrayFromMat($matPts3d)
    EndIf

    Local $iArrTris, $vectorOfMatTris, $iArrTrisSize
    Local $bTrisIsArray = VarGetType($matTris) == "Array"

    If $bTrisIsArray Then
        $vectorOfMatTris = _VectorOfMatCreate()

        $iArrTrisSize = UBound($matTris)
        For $i = 0 To $iArrTrisSize - 1
            _VectorOfMatPush($vectorOfMatTris, $matTris[$i])
        Next

        $iArrTris = _cveInputArrayFromVectorOfMat($vectorOfMatTris)
    Else
        $iArrTris = _cveInputArrayFromMat($matTris)
    EndIf

    Local $retval = _cveRapidCreate($iArrPts3d, $iArrTris, $tracker, $algorithm, $sharedPtr)

    If $bTrisIsArray Then
        _VectorOfMatRelease($vectorOfMatTris)
    EndIf

    _cveInputArrayRelease($iArrTris)

    If $bPts3dIsArray Then
        _VectorOfMatRelease($vectorOfMatPts3d)
    EndIf

    _cveInputArrayRelease($iArrPts3d)

    Return $retval
EndFunc   ;==>_cveRapidCreateMat

Func _cveRapidRelease(ByRef $sharedPtr)
    ; CVAPI(void) cveRapidRelease(cv::Ptr<cv::rapid::Rapid>** sharedPtr);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveRapidRelease", "ptr*", $sharedPtr), "cveRapidRelease", @error)
EndFunc   ;==>_cveRapidRelease

Func _cveOLSTrackerCreate(ByRef $pts3d, ByRef $tris, $histBins, $sobelThesh, ByRef $tracker, ByRef $algorithm, ByRef $sharedPtr)
    ; CVAPI(cv::rapid::OLSTracker*) cveOLSTrackerCreate(cv::_InputArray* pts3d, cv::_InputArray* tris, int histBins, uchar sobelThesh, cv::rapid::Tracker** tracker, cv::Algorithm** algorithm, cv::Ptr<cv::rapid::OLSTracker>** sharedPtr);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveOLSTrackerCreate", "ptr", $pts3d, "ptr", $tris, "int", $histBins, "uchar", $sobelThesh, "ptr*", $tracker, "ptr*", $algorithm, "ptr*", $sharedPtr), "cveOLSTrackerCreate", @error)
EndFunc   ;==>_cveOLSTrackerCreate

Func _cveOLSTrackerCreateMat(ByRef $matPts3d, ByRef $matTris, $histBins, $sobelThesh, ByRef $tracker, ByRef $algorithm, ByRef $sharedPtr)
    ; cveOLSTrackerCreate using cv::Mat instead of _*Array

    Local $iArrPts3d, $vectorOfMatPts3d, $iArrPts3dSize
    Local $bPts3dIsArray = VarGetType($matPts3d) == "Array"

    If $bPts3dIsArray Then
        $vectorOfMatPts3d = _VectorOfMatCreate()

        $iArrPts3dSize = UBound($matPts3d)
        For $i = 0 To $iArrPts3dSize - 1
            _VectorOfMatPush($vectorOfMatPts3d, $matPts3d[$i])
        Next

        $iArrPts3d = _cveInputArrayFromVectorOfMat($vectorOfMatPts3d)
    Else
        $iArrPts3d = _cveInputArrayFromMat($matPts3d)
    EndIf

    Local $iArrTris, $vectorOfMatTris, $iArrTrisSize
    Local $bTrisIsArray = VarGetType($matTris) == "Array"

    If $bTrisIsArray Then
        $vectorOfMatTris = _VectorOfMatCreate()

        $iArrTrisSize = UBound($matTris)
        For $i = 0 To $iArrTrisSize - 1
            _VectorOfMatPush($vectorOfMatTris, $matTris[$i])
        Next

        $iArrTris = _cveInputArrayFromVectorOfMat($vectorOfMatTris)
    Else
        $iArrTris = _cveInputArrayFromMat($matTris)
    EndIf

    Local $retval = _cveOLSTrackerCreate($iArrPts3d, $iArrTris, $histBins, $sobelThesh, $tracker, $algorithm, $sharedPtr)

    If $bTrisIsArray Then
        _VectorOfMatRelease($vectorOfMatTris)
    EndIf

    _cveInputArrayRelease($iArrTris)

    If $bPts3dIsArray Then
        _VectorOfMatRelease($vectorOfMatPts3d)
    EndIf

    _cveInputArrayRelease($iArrPts3d)

    Return $retval
EndFunc   ;==>_cveOLSTrackerCreateMat

Func _cveOLSTrackerRelease(ByRef $sharedPtr)
    ; CVAPI(void) cveOLSTrackerRelease(cv::Ptr<cv::rapid::OLSTracker>** sharedPtr);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveOLSTrackerRelease", "ptr*", $sharedPtr), "cveOLSTrackerRelease", @error)
EndFunc   ;==>_cveOLSTrackerRelease