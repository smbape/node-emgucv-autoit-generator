#include-once
#include "..\..\CVEUtils.au3"

Func _cveDrawCorrespondencies($bundle, $cols, $colors = _cveNoArray())
    ; CVAPI(void) cveDrawCorrespondencies(cv::_InputOutputArray* bundle, cv::_InputArray* cols, cv::_InputArray* colors);

    Local $sBundleDllType
    If IsDllStruct($bundle) Then
        $sBundleDllType = "struct*"
    Else
        $sBundleDllType = "ptr"
    EndIf

    Local $sColsDllType
    If IsDllStruct($cols) Then
        $sColsDllType = "struct*"
    Else
        $sColsDllType = "ptr"
    EndIf

    Local $sColorsDllType
    If IsDllStruct($colors) Then
        $sColorsDllType = "struct*"
    Else
        $sColorsDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDrawCorrespondencies", $sBundleDllType, $bundle, $sColsDllType, $cols, $sColorsDllType, $colors), "cveDrawCorrespondencies", @error)
EndFunc   ;==>_cveDrawCorrespondencies

Func _cveDrawCorrespondenciesMat($matBundle, $matCols, $matColors = _cveNoArrayMat())
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

Func _cveDrawSearchLines($img, $locations, $color)
    ; CVAPI(void) cveDrawSearchLines(cv::_InputOutputArray* img, cv::_InputArray* locations, CvScalar* color);

    Local $sImgDllType
    If IsDllStruct($img) Then
        $sImgDllType = "struct*"
    Else
        $sImgDllType = "ptr"
    EndIf

    Local $sLocationsDllType
    If IsDllStruct($locations) Then
        $sLocationsDllType = "struct*"
    Else
        $sLocationsDllType = "ptr"
    EndIf

    Local $sColorDllType
    If IsDllStruct($color) Then
        $sColorDllType = "struct*"
    Else
        $sColorDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDrawSearchLines", $sImgDllType, $img, $sLocationsDllType, $locations, $sColorDllType, $color), "cveDrawSearchLines", @error)
EndFunc   ;==>_cveDrawSearchLines

Func _cveDrawSearchLinesMat($matImg, $matLocations, $color)
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

Func _cveDrawWireframe($img, $pts2d, $tris, $color, $type = $CV_LINE_8, $cullBackface = false)
    ; CVAPI(void) cveDrawWireframe(cv::_InputOutputArray* img, cv::_InputArray* pts2d, cv::_InputArray* tris, CvScalar* color, int type, bool cullBackface);

    Local $sImgDllType
    If IsDllStruct($img) Then
        $sImgDllType = "struct*"
    Else
        $sImgDllType = "ptr"
    EndIf

    Local $sPts2dDllType
    If IsDllStruct($pts2d) Then
        $sPts2dDllType = "struct*"
    Else
        $sPts2dDllType = "ptr"
    EndIf

    Local $sTrisDllType
    If IsDllStruct($tris) Then
        $sTrisDllType = "struct*"
    Else
        $sTrisDllType = "ptr"
    EndIf

    Local $sColorDllType
    If IsDllStruct($color) Then
        $sColorDllType = "struct*"
    Else
        $sColorDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDrawWireframe", $sImgDllType, $img, $sPts2dDllType, $pts2d, $sTrisDllType, $tris, $sColorDllType, $color, "int", $type, "boolean", $cullBackface), "cveDrawWireframe", @error)
EndFunc   ;==>_cveDrawWireframe

Func _cveDrawWireframeMat($matImg, $matPts2d, $matTris, $color, $type = $CV_LINE_8, $cullBackface = false)
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

Func _cveExtractControlPoints($num, $len, $pts3d, $rvec, $tvec, $K, $imsize, $tris, $ctl2d, $ctl3d)
    ; CVAPI(void) cveExtractControlPoints(int num, int len, cv::_InputArray* pts3d, cv::_InputArray* rvec, cv::_InputArray* tvec, cv::_InputArray* K, CvSize* imsize, cv::_InputArray* tris, cv::_OutputArray* ctl2d, cv::_OutputArray* ctl3d);

    Local $sPts3dDllType
    If IsDllStruct($pts3d) Then
        $sPts3dDllType = "struct*"
    Else
        $sPts3dDllType = "ptr"
    EndIf

    Local $sRvecDllType
    If IsDllStruct($rvec) Then
        $sRvecDllType = "struct*"
    Else
        $sRvecDllType = "ptr"
    EndIf

    Local $sTvecDllType
    If IsDllStruct($tvec) Then
        $sTvecDllType = "struct*"
    Else
        $sTvecDllType = "ptr"
    EndIf

    Local $sKDllType
    If IsDllStruct($K) Then
        $sKDllType = "struct*"
    Else
        $sKDllType = "ptr"
    EndIf

    Local $sImsizeDllType
    If IsDllStruct($imsize) Then
        $sImsizeDllType = "struct*"
    Else
        $sImsizeDllType = "ptr"
    EndIf

    Local $sTrisDllType
    If IsDllStruct($tris) Then
        $sTrisDllType = "struct*"
    Else
        $sTrisDllType = "ptr"
    EndIf

    Local $sCtl2dDllType
    If IsDllStruct($ctl2d) Then
        $sCtl2dDllType = "struct*"
    Else
        $sCtl2dDllType = "ptr"
    EndIf

    Local $sCtl3dDllType
    If IsDllStruct($ctl3d) Then
        $sCtl3dDllType = "struct*"
    Else
        $sCtl3dDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveExtractControlPoints", "int", $num, "int", $len, $sPts3dDllType, $pts3d, $sRvecDllType, $rvec, $sTvecDllType, $tvec, $sKDllType, $K, $sImsizeDllType, $imsize, $sTrisDllType, $tris, $sCtl2dDllType, $ctl2d, $sCtl3dDllType, $ctl3d), "cveExtractControlPoints", @error)
EndFunc   ;==>_cveExtractControlPoints

Func _cveExtractControlPointsMat($num, $len, $matPts3d, $matRvec, $matTvec, $matK, $imsize, $matTris, $matCtl2d, $matCtl3d)
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

Func _cveExtractLineBundle($len, $ctl2d, $img, $bundle, $srcLocations)
    ; CVAPI(void) cveExtractLineBundle(int len, cv::_InputArray* ctl2d, cv::_InputArray* img, cv::_OutputArray* bundle, cv::_OutputArray* srcLocations);

    Local $sCtl2dDllType
    If IsDllStruct($ctl2d) Then
        $sCtl2dDllType = "struct*"
    Else
        $sCtl2dDllType = "ptr"
    EndIf

    Local $sImgDllType
    If IsDllStruct($img) Then
        $sImgDllType = "struct*"
    Else
        $sImgDllType = "ptr"
    EndIf

    Local $sBundleDllType
    If IsDllStruct($bundle) Then
        $sBundleDllType = "struct*"
    Else
        $sBundleDllType = "ptr"
    EndIf

    Local $sSrcLocationsDllType
    If IsDllStruct($srcLocations) Then
        $sSrcLocationsDllType = "struct*"
    Else
        $sSrcLocationsDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveExtractLineBundle", "int", $len, $sCtl2dDllType, $ctl2d, $sImgDllType, $img, $sBundleDllType, $bundle, $sSrcLocationsDllType, $srcLocations), "cveExtractLineBundle", @error)
EndFunc   ;==>_cveExtractLineBundle

Func _cveExtractLineBundleMat($len, $matCtl2d, $matImg, $matBundle, $matSrcLocations)
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

Func _cveFindCorrespondencies($bundle, $cols, $response = _cveNoArray())
    ; CVAPI(void) cveFindCorrespondencies(cv::_InputArray* bundle, cv::_OutputArray* cols, cv::_OutputArray* response);

    Local $sBundleDllType
    If IsDllStruct($bundle) Then
        $sBundleDllType = "struct*"
    Else
        $sBundleDllType = "ptr"
    EndIf

    Local $sColsDllType
    If IsDllStruct($cols) Then
        $sColsDllType = "struct*"
    Else
        $sColsDllType = "ptr"
    EndIf

    Local $sResponseDllType
    If IsDllStruct($response) Then
        $sResponseDllType = "struct*"
    Else
        $sResponseDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFindCorrespondencies", $sBundleDllType, $bundle, $sColsDllType, $cols, $sResponseDllType, $response), "cveFindCorrespondencies", @error)
EndFunc   ;==>_cveFindCorrespondencies

Func _cveFindCorrespondenciesMat($matBundle, $matCols, $matResponse = _cveNoArrayMat())
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

Func _cveConvertCorrespondencies($cols, $srcLocations, $pts2d, $pts3d = _cveNoArray(), $mask = _cveNoArray())
    ; CVAPI(void) cveConvertCorrespondencies(cv::_InputArray* cols, cv::_InputArray* srcLocations, cv::_OutputArray* pts2d, cv::_InputOutputArray* pts3d, cv::_InputArray* mask);

    Local $sColsDllType
    If IsDllStruct($cols) Then
        $sColsDllType = "struct*"
    Else
        $sColsDllType = "ptr"
    EndIf

    Local $sSrcLocationsDllType
    If IsDllStruct($srcLocations) Then
        $sSrcLocationsDllType = "struct*"
    Else
        $sSrcLocationsDllType = "ptr"
    EndIf

    Local $sPts2dDllType
    If IsDllStruct($pts2d) Then
        $sPts2dDllType = "struct*"
    Else
        $sPts2dDllType = "ptr"
    EndIf

    Local $sPts3dDllType
    If IsDllStruct($pts3d) Then
        $sPts3dDllType = "struct*"
    Else
        $sPts3dDllType = "ptr"
    EndIf

    Local $sMaskDllType
    If IsDllStruct($mask) Then
        $sMaskDllType = "struct*"
    Else
        $sMaskDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveConvertCorrespondencies", $sColsDllType, $cols, $sSrcLocationsDllType, $srcLocations, $sPts2dDllType, $pts2d, $sPts3dDllType, $pts3d, $sMaskDllType, $mask), "cveConvertCorrespondencies", @error)
EndFunc   ;==>_cveConvertCorrespondencies

Func _cveConvertCorrespondenciesMat($matCols, $matSrcLocations, $matPts2d, $matPts3d = _cveNoArrayMat(), $matMask = _cveNoArrayMat())
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

Func _cveRapid($img, $num, $len, $pts3d, $tris, $K, $rvec, $tvec, $rmsd = 0)
    ; CVAPI(float) cveRapid(cv::_InputArray* img, int num, int len, cv::_InputArray* pts3d, cv::_InputArray* tris, cv::_InputArray* K, cv::_InputOutputArray* rvec, cv::_InputOutputArray* tvec, double* rmsd);

    Local $sImgDllType
    If IsDllStruct($img) Then
        $sImgDllType = "struct*"
    Else
        $sImgDllType = "ptr"
    EndIf

    Local $sPts3dDllType
    If IsDllStruct($pts3d) Then
        $sPts3dDllType = "struct*"
    Else
        $sPts3dDllType = "ptr"
    EndIf

    Local $sTrisDllType
    If IsDllStruct($tris) Then
        $sTrisDllType = "struct*"
    Else
        $sTrisDllType = "ptr"
    EndIf

    Local $sKDllType
    If IsDllStruct($K) Then
        $sKDllType = "struct*"
    Else
        $sKDllType = "ptr"
    EndIf

    Local $sRvecDllType
    If IsDllStruct($rvec) Then
        $sRvecDllType = "struct*"
    Else
        $sRvecDllType = "ptr"
    EndIf

    Local $sTvecDllType
    If IsDllStruct($tvec) Then
        $sTvecDllType = "struct*"
    Else
        $sTvecDllType = "ptr"
    EndIf

    Local $sRmsdDllType
    If IsDllStruct($rmsd) Then
        $sRmsdDllType = "struct*"
    Else
        $sRmsdDllType = "double*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cveRapid", $sImgDllType, $img, "int", $num, "int", $len, $sPts3dDllType, $pts3d, $sTrisDllType, $tris, $sKDllType, $K, $sRvecDllType, $rvec, $sTvecDllType, $tvec, $sRmsdDllType, $rmsd), "cveRapid", @error)
EndFunc   ;==>_cveRapid

Func _cveRapidMat($matImg, $num, $len, $matPts3d, $matTris, $matK, $matRvec, $matTvec, $rmsd = 0)
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

Func _cveTrackerCompute($tracker, $img, $num, $len, $K, $rvec, $tvec, $termcrit)
    ; CVAPI(float) cveTrackerCompute(cv::rapid::Tracker* tracker, cv::_InputArray* img, int num, int len, cv::_InputArray* K, cv::_InputOutputArray* rvec, cv::_InputOutputArray* tvec, CvTermCriteria* termcrit);

    Local $sTrackerDllType
    If IsDllStruct($tracker) Then
        $sTrackerDllType = "struct*"
    Else
        $sTrackerDllType = "ptr"
    EndIf

    Local $sImgDllType
    If IsDllStruct($img) Then
        $sImgDllType = "struct*"
    Else
        $sImgDllType = "ptr"
    EndIf

    Local $sKDllType
    If IsDllStruct($K) Then
        $sKDllType = "struct*"
    Else
        $sKDllType = "ptr"
    EndIf

    Local $sRvecDllType
    If IsDllStruct($rvec) Then
        $sRvecDllType = "struct*"
    Else
        $sRvecDllType = "ptr"
    EndIf

    Local $sTvecDllType
    If IsDllStruct($tvec) Then
        $sTvecDllType = "struct*"
    Else
        $sTvecDllType = "ptr"
    EndIf

    Local $sTermcritDllType
    If IsDllStruct($termcrit) Then
        $sTermcritDllType = "struct*"
    Else
        $sTermcritDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cveTrackerCompute", $sTrackerDllType, $tracker, $sImgDllType, $img, "int", $num, "int", $len, $sKDllType, $K, $sRvecDllType, $rvec, $sTvecDllType, $tvec, $sTermcritDllType, $termcrit), "cveTrackerCompute", @error)
EndFunc   ;==>_cveTrackerCompute

Func _cveTrackerComputeMat($tracker, $matImg, $num, $len, $matK, $matRvec, $matTvec, $termcrit)
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

Func _cveTrackerClearState($tracker)
    ; CVAPI(void) cveTrackerClearState(cv::rapid::Tracker* tracker);

    Local $sTrackerDllType
    If IsDllStruct($tracker) Then
        $sTrackerDllType = "struct*"
    Else
        $sTrackerDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveTrackerClearState", $sTrackerDllType, $tracker), "cveTrackerClearState", @error)
EndFunc   ;==>_cveTrackerClearState

Func _cveRapidCreate($pts3d, $tris, $tracker, $algorithm, $sharedPtr)
    ; CVAPI(cv::rapid::Rapid*) cveRapidCreate(cv::_InputArray* pts3d, cv::_InputArray* tris, cv::rapid::Tracker** tracker, cv::Algorithm** algorithm, cv::Ptr<cv::rapid::Rapid>** sharedPtr);

    Local $sPts3dDllType
    If IsDllStruct($pts3d) Then
        $sPts3dDllType = "struct*"
    Else
        $sPts3dDllType = "ptr"
    EndIf

    Local $sTrisDllType
    If IsDllStruct($tris) Then
        $sTrisDllType = "struct*"
    Else
        $sTrisDllType = "ptr"
    EndIf

    Local $sTrackerDllType
    If IsDllStruct($tracker) Then
        $sTrackerDllType = "struct*"
    ElseIf $tracker == Null Then
        $sTrackerDllType = "ptr"
    Else
        $sTrackerDllType = "ptr*"
    EndIf

    Local $sAlgorithmDllType
    If IsDllStruct($algorithm) Then
        $sAlgorithmDllType = "struct*"
    ElseIf $algorithm == Null Then
        $sAlgorithmDllType = "ptr"
    Else
        $sAlgorithmDllType = "ptr*"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveRapidCreate", $sPts3dDllType, $pts3d, $sTrisDllType, $tris, $sTrackerDllType, $tracker, $sAlgorithmDllType, $algorithm, $sSharedPtrDllType, $sharedPtr), "cveRapidCreate", @error)
EndFunc   ;==>_cveRapidCreate

Func _cveRapidCreateMat($matPts3d, $matTris, $tracker, $algorithm, $sharedPtr)
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

Func _cveRapidRelease($sharedPtr)
    ; CVAPI(void) cveRapidRelease(cv::Ptr<cv::rapid::Rapid>** sharedPtr);

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveRapidRelease", $sSharedPtrDllType, $sharedPtr), "cveRapidRelease", @error)
EndFunc   ;==>_cveRapidRelease

Func _cveOLSTrackerCreate($pts3d, $tris, $histBins, $sobelThesh, $tracker, $algorithm, $sharedPtr)
    ; CVAPI(cv::rapid::OLSTracker*) cveOLSTrackerCreate(cv::_InputArray* pts3d, cv::_InputArray* tris, int histBins, uchar sobelThesh, cv::rapid::Tracker** tracker, cv::Algorithm** algorithm, cv::Ptr<cv::rapid::OLSTracker>** sharedPtr);

    Local $sPts3dDllType
    If IsDllStruct($pts3d) Then
        $sPts3dDllType = "struct*"
    Else
        $sPts3dDllType = "ptr"
    EndIf

    Local $sTrisDllType
    If IsDllStruct($tris) Then
        $sTrisDllType = "struct*"
    Else
        $sTrisDllType = "ptr"
    EndIf

    Local $sTrackerDllType
    If IsDllStruct($tracker) Then
        $sTrackerDllType = "struct*"
    ElseIf $tracker == Null Then
        $sTrackerDllType = "ptr"
    Else
        $sTrackerDllType = "ptr*"
    EndIf

    Local $sAlgorithmDllType
    If IsDllStruct($algorithm) Then
        $sAlgorithmDllType = "struct*"
    ElseIf $algorithm == Null Then
        $sAlgorithmDllType = "ptr"
    Else
        $sAlgorithmDllType = "ptr*"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveOLSTrackerCreate", $sPts3dDllType, $pts3d, $sTrisDllType, $tris, "int", $histBins, "byte", $sobelThesh, $sTrackerDllType, $tracker, $sAlgorithmDllType, $algorithm, $sSharedPtrDllType, $sharedPtr), "cveOLSTrackerCreate", @error)
EndFunc   ;==>_cveOLSTrackerCreate

Func _cveOLSTrackerCreateMat($matPts3d, $matTris, $histBins, $sobelThesh, $tracker, $algorithm, $sharedPtr)
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

Func _cveOLSTrackerRelease($sharedPtr)
    ; CVAPI(void) cveOLSTrackerRelease(cv::Ptr<cv::rapid::OLSTracker>** sharedPtr);

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveOLSTrackerRelease", $sSharedPtrDllType, $sharedPtr), "cveOLSTrackerRelease", @error)
EndFunc   ;==>_cveOLSTrackerRelease