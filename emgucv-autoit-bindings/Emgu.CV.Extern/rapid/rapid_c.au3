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

Func _cveDrawCorrespondenciesTyped($typeOfBundle, $bundle, $typeOfCols, $cols, $typeOfColors = Default, $colors = _cveNoArray())

    Local $ioArrBundle, $vectorBundle, $iArrBundleSize
    Local $bBundleIsArray = IsArray($bundle)
    Local $bBundleCreate = IsDllStruct($bundle) And $typeOfBundle == "Scalar"

    If $typeOfBundle == Default Then
        $ioArrBundle = $bundle
    ElseIf $bBundleIsArray Then
        $vectorBundle = Call("_VectorOf" & $typeOfBundle & "Create")

        $iArrBundleSize = UBound($bundle)
        For $i = 0 To $iArrBundleSize - 1
            Call("_VectorOf" & $typeOfBundle & "Push", $vectorBundle, $bundle[$i])
        Next

        $ioArrBundle = Call("_cveInputOutputArrayFromVectorOf" & $typeOfBundle, $vectorBundle)
    Else
        If $bBundleCreate Then
            $bundle = Call("_cve" & $typeOfBundle & "Create", $bundle)
        EndIf
        $ioArrBundle = Call("_cveInputOutputArrayFrom" & $typeOfBundle, $bundle)
    EndIf

    Local $iArrCols, $vectorCols, $iArrColsSize
    Local $bColsIsArray = IsArray($cols)
    Local $bColsCreate = IsDllStruct($cols) And $typeOfCols == "Scalar"

    If $typeOfCols == Default Then
        $iArrCols = $cols
    ElseIf $bColsIsArray Then
        $vectorCols = Call("_VectorOf" & $typeOfCols & "Create")

        $iArrColsSize = UBound($cols)
        For $i = 0 To $iArrColsSize - 1
            Call("_VectorOf" & $typeOfCols & "Push", $vectorCols, $cols[$i])
        Next

        $iArrCols = Call("_cveInputArrayFromVectorOf" & $typeOfCols, $vectorCols)
    Else
        If $bColsCreate Then
            $cols = Call("_cve" & $typeOfCols & "Create", $cols)
        EndIf
        $iArrCols = Call("_cveInputArrayFrom" & $typeOfCols, $cols)
    EndIf

    Local $iArrColors, $vectorColors, $iArrColorsSize
    Local $bColorsIsArray = IsArray($colors)
    Local $bColorsCreate = IsDllStruct($colors) And $typeOfColors == "Scalar"

    If $typeOfColors == Default Then
        $iArrColors = $colors
    ElseIf $bColorsIsArray Then
        $vectorColors = Call("_VectorOf" & $typeOfColors & "Create")

        $iArrColorsSize = UBound($colors)
        For $i = 0 To $iArrColorsSize - 1
            Call("_VectorOf" & $typeOfColors & "Push", $vectorColors, $colors[$i])
        Next

        $iArrColors = Call("_cveInputArrayFromVectorOf" & $typeOfColors, $vectorColors)
    Else
        If $bColorsCreate Then
            $colors = Call("_cve" & $typeOfColors & "Create", $colors)
        EndIf
        $iArrColors = Call("_cveInputArrayFrom" & $typeOfColors, $colors)
    EndIf

    _cveDrawCorrespondencies($ioArrBundle, $iArrCols, $iArrColors)

    If $bColorsIsArray Then
        Call("_VectorOf" & $typeOfColors & "Release", $vectorColors)
    EndIf

    If $typeOfColors <> Default Then
        _cveInputArrayRelease($iArrColors)
        If $bColorsCreate Then
            Call("_cve" & $typeOfColors & "Release", $colors)
        EndIf
    EndIf

    If $bColsIsArray Then
        Call("_VectorOf" & $typeOfCols & "Release", $vectorCols)
    EndIf

    If $typeOfCols <> Default Then
        _cveInputArrayRelease($iArrCols)
        If $bColsCreate Then
            Call("_cve" & $typeOfCols & "Release", $cols)
        EndIf
    EndIf

    If $bBundleIsArray Then
        Call("_VectorOf" & $typeOfBundle & "Release", $vectorBundle)
    EndIf

    If $typeOfBundle <> Default Then
        _cveInputOutputArrayRelease($ioArrBundle)
        If $bBundleCreate Then
            Call("_cve" & $typeOfBundle & "Release", $bundle)
        EndIf
    EndIf
EndFunc   ;==>_cveDrawCorrespondenciesTyped

Func _cveDrawCorrespondenciesMat($bundle, $cols, $colors = _cveNoArrayMat())
    ; cveDrawCorrespondencies using cv::Mat instead of _*Array
    _cveDrawCorrespondenciesTyped("Mat", $bundle, "Mat", $cols, "Mat", $colors)
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

Func _cveDrawSearchLinesTyped($typeOfImg, $img, $typeOfLocations, $locations, $color)

    Local $ioArrImg, $vectorImg, $iArrImgSize
    Local $bImgIsArray = IsArray($img)
    Local $bImgCreate = IsDllStruct($img) And $typeOfImg == "Scalar"

    If $typeOfImg == Default Then
        $ioArrImg = $img
    ElseIf $bImgIsArray Then
        $vectorImg = Call("_VectorOf" & $typeOfImg & "Create")

        $iArrImgSize = UBound($img)
        For $i = 0 To $iArrImgSize - 1
            Call("_VectorOf" & $typeOfImg & "Push", $vectorImg, $img[$i])
        Next

        $ioArrImg = Call("_cveInputOutputArrayFromVectorOf" & $typeOfImg, $vectorImg)
    Else
        If $bImgCreate Then
            $img = Call("_cve" & $typeOfImg & "Create", $img)
        EndIf
        $ioArrImg = Call("_cveInputOutputArrayFrom" & $typeOfImg, $img)
    EndIf

    Local $iArrLocations, $vectorLocations, $iArrLocationsSize
    Local $bLocationsIsArray = IsArray($locations)
    Local $bLocationsCreate = IsDllStruct($locations) And $typeOfLocations == "Scalar"

    If $typeOfLocations == Default Then
        $iArrLocations = $locations
    ElseIf $bLocationsIsArray Then
        $vectorLocations = Call("_VectorOf" & $typeOfLocations & "Create")

        $iArrLocationsSize = UBound($locations)
        For $i = 0 To $iArrLocationsSize - 1
            Call("_VectorOf" & $typeOfLocations & "Push", $vectorLocations, $locations[$i])
        Next

        $iArrLocations = Call("_cveInputArrayFromVectorOf" & $typeOfLocations, $vectorLocations)
    Else
        If $bLocationsCreate Then
            $locations = Call("_cve" & $typeOfLocations & "Create", $locations)
        EndIf
        $iArrLocations = Call("_cveInputArrayFrom" & $typeOfLocations, $locations)
    EndIf

    _cveDrawSearchLines($ioArrImg, $iArrLocations, $color)

    If $bLocationsIsArray Then
        Call("_VectorOf" & $typeOfLocations & "Release", $vectorLocations)
    EndIf

    If $typeOfLocations <> Default Then
        _cveInputArrayRelease($iArrLocations)
        If $bLocationsCreate Then
            Call("_cve" & $typeOfLocations & "Release", $locations)
        EndIf
    EndIf

    If $bImgIsArray Then
        Call("_VectorOf" & $typeOfImg & "Release", $vectorImg)
    EndIf

    If $typeOfImg <> Default Then
        _cveInputOutputArrayRelease($ioArrImg)
        If $bImgCreate Then
            Call("_cve" & $typeOfImg & "Release", $img)
        EndIf
    EndIf
EndFunc   ;==>_cveDrawSearchLinesTyped

Func _cveDrawSearchLinesMat($img, $locations, $color)
    ; cveDrawSearchLines using cv::Mat instead of _*Array
    _cveDrawSearchLinesTyped("Mat", $img, "Mat", $locations, $color)
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

Func _cveDrawWireframeTyped($typeOfImg, $img, $typeOfPts2d, $pts2d, $typeOfTris, $tris, $color, $type = $CV_LINE_8, $cullBackface = false)

    Local $ioArrImg, $vectorImg, $iArrImgSize
    Local $bImgIsArray = IsArray($img)
    Local $bImgCreate = IsDllStruct($img) And $typeOfImg == "Scalar"

    If $typeOfImg == Default Then
        $ioArrImg = $img
    ElseIf $bImgIsArray Then
        $vectorImg = Call("_VectorOf" & $typeOfImg & "Create")

        $iArrImgSize = UBound($img)
        For $i = 0 To $iArrImgSize - 1
            Call("_VectorOf" & $typeOfImg & "Push", $vectorImg, $img[$i])
        Next

        $ioArrImg = Call("_cveInputOutputArrayFromVectorOf" & $typeOfImg, $vectorImg)
    Else
        If $bImgCreate Then
            $img = Call("_cve" & $typeOfImg & "Create", $img)
        EndIf
        $ioArrImg = Call("_cveInputOutputArrayFrom" & $typeOfImg, $img)
    EndIf

    Local $iArrPts2d, $vectorPts2d, $iArrPts2dSize
    Local $bPts2dIsArray = IsArray($pts2d)
    Local $bPts2dCreate = IsDllStruct($pts2d) And $typeOfPts2d == "Scalar"

    If $typeOfPts2d == Default Then
        $iArrPts2d = $pts2d
    ElseIf $bPts2dIsArray Then
        $vectorPts2d = Call("_VectorOf" & $typeOfPts2d & "Create")

        $iArrPts2dSize = UBound($pts2d)
        For $i = 0 To $iArrPts2dSize - 1
            Call("_VectorOf" & $typeOfPts2d & "Push", $vectorPts2d, $pts2d[$i])
        Next

        $iArrPts2d = Call("_cveInputArrayFromVectorOf" & $typeOfPts2d, $vectorPts2d)
    Else
        If $bPts2dCreate Then
            $pts2d = Call("_cve" & $typeOfPts2d & "Create", $pts2d)
        EndIf
        $iArrPts2d = Call("_cveInputArrayFrom" & $typeOfPts2d, $pts2d)
    EndIf

    Local $iArrTris, $vectorTris, $iArrTrisSize
    Local $bTrisIsArray = IsArray($tris)
    Local $bTrisCreate = IsDllStruct($tris) And $typeOfTris == "Scalar"

    If $typeOfTris == Default Then
        $iArrTris = $tris
    ElseIf $bTrisIsArray Then
        $vectorTris = Call("_VectorOf" & $typeOfTris & "Create")

        $iArrTrisSize = UBound($tris)
        For $i = 0 To $iArrTrisSize - 1
            Call("_VectorOf" & $typeOfTris & "Push", $vectorTris, $tris[$i])
        Next

        $iArrTris = Call("_cveInputArrayFromVectorOf" & $typeOfTris, $vectorTris)
    Else
        If $bTrisCreate Then
            $tris = Call("_cve" & $typeOfTris & "Create", $tris)
        EndIf
        $iArrTris = Call("_cveInputArrayFrom" & $typeOfTris, $tris)
    EndIf

    _cveDrawWireframe($ioArrImg, $iArrPts2d, $iArrTris, $color, $type, $cullBackface)

    If $bTrisIsArray Then
        Call("_VectorOf" & $typeOfTris & "Release", $vectorTris)
    EndIf

    If $typeOfTris <> Default Then
        _cveInputArrayRelease($iArrTris)
        If $bTrisCreate Then
            Call("_cve" & $typeOfTris & "Release", $tris)
        EndIf
    EndIf

    If $bPts2dIsArray Then
        Call("_VectorOf" & $typeOfPts2d & "Release", $vectorPts2d)
    EndIf

    If $typeOfPts2d <> Default Then
        _cveInputArrayRelease($iArrPts2d)
        If $bPts2dCreate Then
            Call("_cve" & $typeOfPts2d & "Release", $pts2d)
        EndIf
    EndIf

    If $bImgIsArray Then
        Call("_VectorOf" & $typeOfImg & "Release", $vectorImg)
    EndIf

    If $typeOfImg <> Default Then
        _cveInputOutputArrayRelease($ioArrImg)
        If $bImgCreate Then
            Call("_cve" & $typeOfImg & "Release", $img)
        EndIf
    EndIf
EndFunc   ;==>_cveDrawWireframeTyped

Func _cveDrawWireframeMat($img, $pts2d, $tris, $color, $type = $CV_LINE_8, $cullBackface = false)
    ; cveDrawWireframe using cv::Mat instead of _*Array
    _cveDrawWireframeTyped("Mat", $img, "Mat", $pts2d, "Mat", $tris, $color, $type, $cullBackface)
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

Func _cveExtractControlPointsTyped($num, $len, $typeOfPts3d, $pts3d, $typeOfRvec, $rvec, $typeOfTvec, $tvec, $typeOfK, $K, $imsize, $typeOfTris, $tris, $typeOfCtl2d, $ctl2d, $typeOfCtl3d, $ctl3d)

    Local $iArrPts3d, $vectorPts3d, $iArrPts3dSize
    Local $bPts3dIsArray = IsArray($pts3d)
    Local $bPts3dCreate = IsDllStruct($pts3d) And $typeOfPts3d == "Scalar"

    If $typeOfPts3d == Default Then
        $iArrPts3d = $pts3d
    ElseIf $bPts3dIsArray Then
        $vectorPts3d = Call("_VectorOf" & $typeOfPts3d & "Create")

        $iArrPts3dSize = UBound($pts3d)
        For $i = 0 To $iArrPts3dSize - 1
            Call("_VectorOf" & $typeOfPts3d & "Push", $vectorPts3d, $pts3d[$i])
        Next

        $iArrPts3d = Call("_cveInputArrayFromVectorOf" & $typeOfPts3d, $vectorPts3d)
    Else
        If $bPts3dCreate Then
            $pts3d = Call("_cve" & $typeOfPts3d & "Create", $pts3d)
        EndIf
        $iArrPts3d = Call("_cveInputArrayFrom" & $typeOfPts3d, $pts3d)
    EndIf

    Local $iArrRvec, $vectorRvec, $iArrRvecSize
    Local $bRvecIsArray = IsArray($rvec)
    Local $bRvecCreate = IsDllStruct($rvec) And $typeOfRvec == "Scalar"

    If $typeOfRvec == Default Then
        $iArrRvec = $rvec
    ElseIf $bRvecIsArray Then
        $vectorRvec = Call("_VectorOf" & $typeOfRvec & "Create")

        $iArrRvecSize = UBound($rvec)
        For $i = 0 To $iArrRvecSize - 1
            Call("_VectorOf" & $typeOfRvec & "Push", $vectorRvec, $rvec[$i])
        Next

        $iArrRvec = Call("_cveInputArrayFromVectorOf" & $typeOfRvec, $vectorRvec)
    Else
        If $bRvecCreate Then
            $rvec = Call("_cve" & $typeOfRvec & "Create", $rvec)
        EndIf
        $iArrRvec = Call("_cveInputArrayFrom" & $typeOfRvec, $rvec)
    EndIf

    Local $iArrTvec, $vectorTvec, $iArrTvecSize
    Local $bTvecIsArray = IsArray($tvec)
    Local $bTvecCreate = IsDllStruct($tvec) And $typeOfTvec == "Scalar"

    If $typeOfTvec == Default Then
        $iArrTvec = $tvec
    ElseIf $bTvecIsArray Then
        $vectorTvec = Call("_VectorOf" & $typeOfTvec & "Create")

        $iArrTvecSize = UBound($tvec)
        For $i = 0 To $iArrTvecSize - 1
            Call("_VectorOf" & $typeOfTvec & "Push", $vectorTvec, $tvec[$i])
        Next

        $iArrTvec = Call("_cveInputArrayFromVectorOf" & $typeOfTvec, $vectorTvec)
    Else
        If $bTvecCreate Then
            $tvec = Call("_cve" & $typeOfTvec & "Create", $tvec)
        EndIf
        $iArrTvec = Call("_cveInputArrayFrom" & $typeOfTvec, $tvec)
    EndIf

    Local $iArrK, $vectorK, $iArrKSize
    Local $bKIsArray = IsArray($K)
    Local $bKCreate = IsDllStruct($K) And $typeOfK == "Scalar"

    If $typeOfK == Default Then
        $iArrK = $K
    ElseIf $bKIsArray Then
        $vectorK = Call("_VectorOf" & $typeOfK & "Create")

        $iArrKSize = UBound($K)
        For $i = 0 To $iArrKSize - 1
            Call("_VectorOf" & $typeOfK & "Push", $vectorK, $K[$i])
        Next

        $iArrK = Call("_cveInputArrayFromVectorOf" & $typeOfK, $vectorK)
    Else
        If $bKCreate Then
            $K = Call("_cve" & $typeOfK & "Create", $K)
        EndIf
        $iArrK = Call("_cveInputArrayFrom" & $typeOfK, $K)
    EndIf

    Local $iArrTris, $vectorTris, $iArrTrisSize
    Local $bTrisIsArray = IsArray($tris)
    Local $bTrisCreate = IsDllStruct($tris) And $typeOfTris == "Scalar"

    If $typeOfTris == Default Then
        $iArrTris = $tris
    ElseIf $bTrisIsArray Then
        $vectorTris = Call("_VectorOf" & $typeOfTris & "Create")

        $iArrTrisSize = UBound($tris)
        For $i = 0 To $iArrTrisSize - 1
            Call("_VectorOf" & $typeOfTris & "Push", $vectorTris, $tris[$i])
        Next

        $iArrTris = Call("_cveInputArrayFromVectorOf" & $typeOfTris, $vectorTris)
    Else
        If $bTrisCreate Then
            $tris = Call("_cve" & $typeOfTris & "Create", $tris)
        EndIf
        $iArrTris = Call("_cveInputArrayFrom" & $typeOfTris, $tris)
    EndIf

    Local $oArrCtl2d, $vectorCtl2d, $iArrCtl2dSize
    Local $bCtl2dIsArray = IsArray($ctl2d)
    Local $bCtl2dCreate = IsDllStruct($ctl2d) And $typeOfCtl2d == "Scalar"

    If $typeOfCtl2d == Default Then
        $oArrCtl2d = $ctl2d
    ElseIf $bCtl2dIsArray Then
        $vectorCtl2d = Call("_VectorOf" & $typeOfCtl2d & "Create")

        $iArrCtl2dSize = UBound($ctl2d)
        For $i = 0 To $iArrCtl2dSize - 1
            Call("_VectorOf" & $typeOfCtl2d & "Push", $vectorCtl2d, $ctl2d[$i])
        Next

        $oArrCtl2d = Call("_cveOutputArrayFromVectorOf" & $typeOfCtl2d, $vectorCtl2d)
    Else
        If $bCtl2dCreate Then
            $ctl2d = Call("_cve" & $typeOfCtl2d & "Create", $ctl2d)
        EndIf
        $oArrCtl2d = Call("_cveOutputArrayFrom" & $typeOfCtl2d, $ctl2d)
    EndIf

    Local $oArrCtl3d, $vectorCtl3d, $iArrCtl3dSize
    Local $bCtl3dIsArray = IsArray($ctl3d)
    Local $bCtl3dCreate = IsDllStruct($ctl3d) And $typeOfCtl3d == "Scalar"

    If $typeOfCtl3d == Default Then
        $oArrCtl3d = $ctl3d
    ElseIf $bCtl3dIsArray Then
        $vectorCtl3d = Call("_VectorOf" & $typeOfCtl3d & "Create")

        $iArrCtl3dSize = UBound($ctl3d)
        For $i = 0 To $iArrCtl3dSize - 1
            Call("_VectorOf" & $typeOfCtl3d & "Push", $vectorCtl3d, $ctl3d[$i])
        Next

        $oArrCtl3d = Call("_cveOutputArrayFromVectorOf" & $typeOfCtl3d, $vectorCtl3d)
    Else
        If $bCtl3dCreate Then
            $ctl3d = Call("_cve" & $typeOfCtl3d & "Create", $ctl3d)
        EndIf
        $oArrCtl3d = Call("_cveOutputArrayFrom" & $typeOfCtl3d, $ctl3d)
    EndIf

    _cveExtractControlPoints($num, $len, $iArrPts3d, $iArrRvec, $iArrTvec, $iArrK, $imsize, $iArrTris, $oArrCtl2d, $oArrCtl3d)

    If $bCtl3dIsArray Then
        Call("_VectorOf" & $typeOfCtl3d & "Release", $vectorCtl3d)
    EndIf

    If $typeOfCtl3d <> Default Then
        _cveOutputArrayRelease($oArrCtl3d)
        If $bCtl3dCreate Then
            Call("_cve" & $typeOfCtl3d & "Release", $ctl3d)
        EndIf
    EndIf

    If $bCtl2dIsArray Then
        Call("_VectorOf" & $typeOfCtl2d & "Release", $vectorCtl2d)
    EndIf

    If $typeOfCtl2d <> Default Then
        _cveOutputArrayRelease($oArrCtl2d)
        If $bCtl2dCreate Then
            Call("_cve" & $typeOfCtl2d & "Release", $ctl2d)
        EndIf
    EndIf

    If $bTrisIsArray Then
        Call("_VectorOf" & $typeOfTris & "Release", $vectorTris)
    EndIf

    If $typeOfTris <> Default Then
        _cveInputArrayRelease($iArrTris)
        If $bTrisCreate Then
            Call("_cve" & $typeOfTris & "Release", $tris)
        EndIf
    EndIf

    If $bKIsArray Then
        Call("_VectorOf" & $typeOfK & "Release", $vectorK)
    EndIf

    If $typeOfK <> Default Then
        _cveInputArrayRelease($iArrK)
        If $bKCreate Then
            Call("_cve" & $typeOfK & "Release", $K)
        EndIf
    EndIf

    If $bTvecIsArray Then
        Call("_VectorOf" & $typeOfTvec & "Release", $vectorTvec)
    EndIf

    If $typeOfTvec <> Default Then
        _cveInputArrayRelease($iArrTvec)
        If $bTvecCreate Then
            Call("_cve" & $typeOfTvec & "Release", $tvec)
        EndIf
    EndIf

    If $bRvecIsArray Then
        Call("_VectorOf" & $typeOfRvec & "Release", $vectorRvec)
    EndIf

    If $typeOfRvec <> Default Then
        _cveInputArrayRelease($iArrRvec)
        If $bRvecCreate Then
            Call("_cve" & $typeOfRvec & "Release", $rvec)
        EndIf
    EndIf

    If $bPts3dIsArray Then
        Call("_VectorOf" & $typeOfPts3d & "Release", $vectorPts3d)
    EndIf

    If $typeOfPts3d <> Default Then
        _cveInputArrayRelease($iArrPts3d)
        If $bPts3dCreate Then
            Call("_cve" & $typeOfPts3d & "Release", $pts3d)
        EndIf
    EndIf
EndFunc   ;==>_cveExtractControlPointsTyped

Func _cveExtractControlPointsMat($num, $len, $pts3d, $rvec, $tvec, $K, $imsize, $tris, $ctl2d, $ctl3d)
    ; cveExtractControlPoints using cv::Mat instead of _*Array
    _cveExtractControlPointsTyped($num, $len, "Mat", $pts3d, "Mat", $rvec, "Mat", $tvec, "Mat", $K, $imsize, "Mat", $tris, "Mat", $ctl2d, "Mat", $ctl3d)
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

Func _cveExtractLineBundleTyped($len, $typeOfCtl2d, $ctl2d, $typeOfImg, $img, $typeOfBundle, $bundle, $typeOfSrcLocations, $srcLocations)

    Local $iArrCtl2d, $vectorCtl2d, $iArrCtl2dSize
    Local $bCtl2dIsArray = IsArray($ctl2d)
    Local $bCtl2dCreate = IsDllStruct($ctl2d) And $typeOfCtl2d == "Scalar"

    If $typeOfCtl2d == Default Then
        $iArrCtl2d = $ctl2d
    ElseIf $bCtl2dIsArray Then
        $vectorCtl2d = Call("_VectorOf" & $typeOfCtl2d & "Create")

        $iArrCtl2dSize = UBound($ctl2d)
        For $i = 0 To $iArrCtl2dSize - 1
            Call("_VectorOf" & $typeOfCtl2d & "Push", $vectorCtl2d, $ctl2d[$i])
        Next

        $iArrCtl2d = Call("_cveInputArrayFromVectorOf" & $typeOfCtl2d, $vectorCtl2d)
    Else
        If $bCtl2dCreate Then
            $ctl2d = Call("_cve" & $typeOfCtl2d & "Create", $ctl2d)
        EndIf
        $iArrCtl2d = Call("_cveInputArrayFrom" & $typeOfCtl2d, $ctl2d)
    EndIf

    Local $iArrImg, $vectorImg, $iArrImgSize
    Local $bImgIsArray = IsArray($img)
    Local $bImgCreate = IsDllStruct($img) And $typeOfImg == "Scalar"

    If $typeOfImg == Default Then
        $iArrImg = $img
    ElseIf $bImgIsArray Then
        $vectorImg = Call("_VectorOf" & $typeOfImg & "Create")

        $iArrImgSize = UBound($img)
        For $i = 0 To $iArrImgSize - 1
            Call("_VectorOf" & $typeOfImg & "Push", $vectorImg, $img[$i])
        Next

        $iArrImg = Call("_cveInputArrayFromVectorOf" & $typeOfImg, $vectorImg)
    Else
        If $bImgCreate Then
            $img = Call("_cve" & $typeOfImg & "Create", $img)
        EndIf
        $iArrImg = Call("_cveInputArrayFrom" & $typeOfImg, $img)
    EndIf

    Local $oArrBundle, $vectorBundle, $iArrBundleSize
    Local $bBundleIsArray = IsArray($bundle)
    Local $bBundleCreate = IsDllStruct($bundle) And $typeOfBundle == "Scalar"

    If $typeOfBundle == Default Then
        $oArrBundle = $bundle
    ElseIf $bBundleIsArray Then
        $vectorBundle = Call("_VectorOf" & $typeOfBundle & "Create")

        $iArrBundleSize = UBound($bundle)
        For $i = 0 To $iArrBundleSize - 1
            Call("_VectorOf" & $typeOfBundle & "Push", $vectorBundle, $bundle[$i])
        Next

        $oArrBundle = Call("_cveOutputArrayFromVectorOf" & $typeOfBundle, $vectorBundle)
    Else
        If $bBundleCreate Then
            $bundle = Call("_cve" & $typeOfBundle & "Create", $bundle)
        EndIf
        $oArrBundle = Call("_cveOutputArrayFrom" & $typeOfBundle, $bundle)
    EndIf

    Local $oArrSrcLocations, $vectorSrcLocations, $iArrSrcLocationsSize
    Local $bSrcLocationsIsArray = IsArray($srcLocations)
    Local $bSrcLocationsCreate = IsDllStruct($srcLocations) And $typeOfSrcLocations == "Scalar"

    If $typeOfSrcLocations == Default Then
        $oArrSrcLocations = $srcLocations
    ElseIf $bSrcLocationsIsArray Then
        $vectorSrcLocations = Call("_VectorOf" & $typeOfSrcLocations & "Create")

        $iArrSrcLocationsSize = UBound($srcLocations)
        For $i = 0 To $iArrSrcLocationsSize - 1
            Call("_VectorOf" & $typeOfSrcLocations & "Push", $vectorSrcLocations, $srcLocations[$i])
        Next

        $oArrSrcLocations = Call("_cveOutputArrayFromVectorOf" & $typeOfSrcLocations, $vectorSrcLocations)
    Else
        If $bSrcLocationsCreate Then
            $srcLocations = Call("_cve" & $typeOfSrcLocations & "Create", $srcLocations)
        EndIf
        $oArrSrcLocations = Call("_cveOutputArrayFrom" & $typeOfSrcLocations, $srcLocations)
    EndIf

    _cveExtractLineBundle($len, $iArrCtl2d, $iArrImg, $oArrBundle, $oArrSrcLocations)

    If $bSrcLocationsIsArray Then
        Call("_VectorOf" & $typeOfSrcLocations & "Release", $vectorSrcLocations)
    EndIf

    If $typeOfSrcLocations <> Default Then
        _cveOutputArrayRelease($oArrSrcLocations)
        If $bSrcLocationsCreate Then
            Call("_cve" & $typeOfSrcLocations & "Release", $srcLocations)
        EndIf
    EndIf

    If $bBundleIsArray Then
        Call("_VectorOf" & $typeOfBundle & "Release", $vectorBundle)
    EndIf

    If $typeOfBundle <> Default Then
        _cveOutputArrayRelease($oArrBundle)
        If $bBundleCreate Then
            Call("_cve" & $typeOfBundle & "Release", $bundle)
        EndIf
    EndIf

    If $bImgIsArray Then
        Call("_VectorOf" & $typeOfImg & "Release", $vectorImg)
    EndIf

    If $typeOfImg <> Default Then
        _cveInputArrayRelease($iArrImg)
        If $bImgCreate Then
            Call("_cve" & $typeOfImg & "Release", $img)
        EndIf
    EndIf

    If $bCtl2dIsArray Then
        Call("_VectorOf" & $typeOfCtl2d & "Release", $vectorCtl2d)
    EndIf

    If $typeOfCtl2d <> Default Then
        _cveInputArrayRelease($iArrCtl2d)
        If $bCtl2dCreate Then
            Call("_cve" & $typeOfCtl2d & "Release", $ctl2d)
        EndIf
    EndIf
EndFunc   ;==>_cveExtractLineBundleTyped

Func _cveExtractLineBundleMat($len, $ctl2d, $img, $bundle, $srcLocations)
    ; cveExtractLineBundle using cv::Mat instead of _*Array
    _cveExtractLineBundleTyped($len, "Mat", $ctl2d, "Mat", $img, "Mat", $bundle, "Mat", $srcLocations)
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

Func _cveFindCorrespondenciesTyped($typeOfBundle, $bundle, $typeOfCols, $cols, $typeOfResponse = Default, $response = _cveNoArray())

    Local $iArrBundle, $vectorBundle, $iArrBundleSize
    Local $bBundleIsArray = IsArray($bundle)
    Local $bBundleCreate = IsDllStruct($bundle) And $typeOfBundle == "Scalar"

    If $typeOfBundle == Default Then
        $iArrBundle = $bundle
    ElseIf $bBundleIsArray Then
        $vectorBundle = Call("_VectorOf" & $typeOfBundle & "Create")

        $iArrBundleSize = UBound($bundle)
        For $i = 0 To $iArrBundleSize - 1
            Call("_VectorOf" & $typeOfBundle & "Push", $vectorBundle, $bundle[$i])
        Next

        $iArrBundle = Call("_cveInputArrayFromVectorOf" & $typeOfBundle, $vectorBundle)
    Else
        If $bBundleCreate Then
            $bundle = Call("_cve" & $typeOfBundle & "Create", $bundle)
        EndIf
        $iArrBundle = Call("_cveInputArrayFrom" & $typeOfBundle, $bundle)
    EndIf

    Local $oArrCols, $vectorCols, $iArrColsSize
    Local $bColsIsArray = IsArray($cols)
    Local $bColsCreate = IsDllStruct($cols) And $typeOfCols == "Scalar"

    If $typeOfCols == Default Then
        $oArrCols = $cols
    ElseIf $bColsIsArray Then
        $vectorCols = Call("_VectorOf" & $typeOfCols & "Create")

        $iArrColsSize = UBound($cols)
        For $i = 0 To $iArrColsSize - 1
            Call("_VectorOf" & $typeOfCols & "Push", $vectorCols, $cols[$i])
        Next

        $oArrCols = Call("_cveOutputArrayFromVectorOf" & $typeOfCols, $vectorCols)
    Else
        If $bColsCreate Then
            $cols = Call("_cve" & $typeOfCols & "Create", $cols)
        EndIf
        $oArrCols = Call("_cveOutputArrayFrom" & $typeOfCols, $cols)
    EndIf

    Local $oArrResponse, $vectorResponse, $iArrResponseSize
    Local $bResponseIsArray = IsArray($response)
    Local $bResponseCreate = IsDllStruct($response) And $typeOfResponse == "Scalar"

    If $typeOfResponse == Default Then
        $oArrResponse = $response
    ElseIf $bResponseIsArray Then
        $vectorResponse = Call("_VectorOf" & $typeOfResponse & "Create")

        $iArrResponseSize = UBound($response)
        For $i = 0 To $iArrResponseSize - 1
            Call("_VectorOf" & $typeOfResponse & "Push", $vectorResponse, $response[$i])
        Next

        $oArrResponse = Call("_cveOutputArrayFromVectorOf" & $typeOfResponse, $vectorResponse)
    Else
        If $bResponseCreate Then
            $response = Call("_cve" & $typeOfResponse & "Create", $response)
        EndIf
        $oArrResponse = Call("_cveOutputArrayFrom" & $typeOfResponse, $response)
    EndIf

    _cveFindCorrespondencies($iArrBundle, $oArrCols, $oArrResponse)

    If $bResponseIsArray Then
        Call("_VectorOf" & $typeOfResponse & "Release", $vectorResponse)
    EndIf

    If $typeOfResponse <> Default Then
        _cveOutputArrayRelease($oArrResponse)
        If $bResponseCreate Then
            Call("_cve" & $typeOfResponse & "Release", $response)
        EndIf
    EndIf

    If $bColsIsArray Then
        Call("_VectorOf" & $typeOfCols & "Release", $vectorCols)
    EndIf

    If $typeOfCols <> Default Then
        _cveOutputArrayRelease($oArrCols)
        If $bColsCreate Then
            Call("_cve" & $typeOfCols & "Release", $cols)
        EndIf
    EndIf

    If $bBundleIsArray Then
        Call("_VectorOf" & $typeOfBundle & "Release", $vectorBundle)
    EndIf

    If $typeOfBundle <> Default Then
        _cveInputArrayRelease($iArrBundle)
        If $bBundleCreate Then
            Call("_cve" & $typeOfBundle & "Release", $bundle)
        EndIf
    EndIf
EndFunc   ;==>_cveFindCorrespondenciesTyped

Func _cveFindCorrespondenciesMat($bundle, $cols, $response = _cveNoArrayMat())
    ; cveFindCorrespondencies using cv::Mat instead of _*Array
    _cveFindCorrespondenciesTyped("Mat", $bundle, "Mat", $cols, "Mat", $response)
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

Func _cveConvertCorrespondenciesTyped($typeOfCols, $cols, $typeOfSrcLocations, $srcLocations, $typeOfPts2d, $pts2d, $typeOfPts3d = Default, $pts3d = _cveNoArray(), $typeOfMask = Default, $mask = _cveNoArray())

    Local $iArrCols, $vectorCols, $iArrColsSize
    Local $bColsIsArray = IsArray($cols)
    Local $bColsCreate = IsDllStruct($cols) And $typeOfCols == "Scalar"

    If $typeOfCols == Default Then
        $iArrCols = $cols
    ElseIf $bColsIsArray Then
        $vectorCols = Call("_VectorOf" & $typeOfCols & "Create")

        $iArrColsSize = UBound($cols)
        For $i = 0 To $iArrColsSize - 1
            Call("_VectorOf" & $typeOfCols & "Push", $vectorCols, $cols[$i])
        Next

        $iArrCols = Call("_cveInputArrayFromVectorOf" & $typeOfCols, $vectorCols)
    Else
        If $bColsCreate Then
            $cols = Call("_cve" & $typeOfCols & "Create", $cols)
        EndIf
        $iArrCols = Call("_cveInputArrayFrom" & $typeOfCols, $cols)
    EndIf

    Local $iArrSrcLocations, $vectorSrcLocations, $iArrSrcLocationsSize
    Local $bSrcLocationsIsArray = IsArray($srcLocations)
    Local $bSrcLocationsCreate = IsDllStruct($srcLocations) And $typeOfSrcLocations == "Scalar"

    If $typeOfSrcLocations == Default Then
        $iArrSrcLocations = $srcLocations
    ElseIf $bSrcLocationsIsArray Then
        $vectorSrcLocations = Call("_VectorOf" & $typeOfSrcLocations & "Create")

        $iArrSrcLocationsSize = UBound($srcLocations)
        For $i = 0 To $iArrSrcLocationsSize - 1
            Call("_VectorOf" & $typeOfSrcLocations & "Push", $vectorSrcLocations, $srcLocations[$i])
        Next

        $iArrSrcLocations = Call("_cveInputArrayFromVectorOf" & $typeOfSrcLocations, $vectorSrcLocations)
    Else
        If $bSrcLocationsCreate Then
            $srcLocations = Call("_cve" & $typeOfSrcLocations & "Create", $srcLocations)
        EndIf
        $iArrSrcLocations = Call("_cveInputArrayFrom" & $typeOfSrcLocations, $srcLocations)
    EndIf

    Local $oArrPts2d, $vectorPts2d, $iArrPts2dSize
    Local $bPts2dIsArray = IsArray($pts2d)
    Local $bPts2dCreate = IsDllStruct($pts2d) And $typeOfPts2d == "Scalar"

    If $typeOfPts2d == Default Then
        $oArrPts2d = $pts2d
    ElseIf $bPts2dIsArray Then
        $vectorPts2d = Call("_VectorOf" & $typeOfPts2d & "Create")

        $iArrPts2dSize = UBound($pts2d)
        For $i = 0 To $iArrPts2dSize - 1
            Call("_VectorOf" & $typeOfPts2d & "Push", $vectorPts2d, $pts2d[$i])
        Next

        $oArrPts2d = Call("_cveOutputArrayFromVectorOf" & $typeOfPts2d, $vectorPts2d)
    Else
        If $bPts2dCreate Then
            $pts2d = Call("_cve" & $typeOfPts2d & "Create", $pts2d)
        EndIf
        $oArrPts2d = Call("_cveOutputArrayFrom" & $typeOfPts2d, $pts2d)
    EndIf

    Local $ioArrPts3d, $vectorPts3d, $iArrPts3dSize
    Local $bPts3dIsArray = IsArray($pts3d)
    Local $bPts3dCreate = IsDllStruct($pts3d) And $typeOfPts3d == "Scalar"

    If $typeOfPts3d == Default Then
        $ioArrPts3d = $pts3d
    ElseIf $bPts3dIsArray Then
        $vectorPts3d = Call("_VectorOf" & $typeOfPts3d & "Create")

        $iArrPts3dSize = UBound($pts3d)
        For $i = 0 To $iArrPts3dSize - 1
            Call("_VectorOf" & $typeOfPts3d & "Push", $vectorPts3d, $pts3d[$i])
        Next

        $ioArrPts3d = Call("_cveInputOutputArrayFromVectorOf" & $typeOfPts3d, $vectorPts3d)
    Else
        If $bPts3dCreate Then
            $pts3d = Call("_cve" & $typeOfPts3d & "Create", $pts3d)
        EndIf
        $ioArrPts3d = Call("_cveInputOutputArrayFrom" & $typeOfPts3d, $pts3d)
    EndIf

    Local $iArrMask, $vectorMask, $iArrMaskSize
    Local $bMaskIsArray = IsArray($mask)
    Local $bMaskCreate = IsDllStruct($mask) And $typeOfMask == "Scalar"

    If $typeOfMask == Default Then
        $iArrMask = $mask
    ElseIf $bMaskIsArray Then
        $vectorMask = Call("_VectorOf" & $typeOfMask & "Create")

        $iArrMaskSize = UBound($mask)
        For $i = 0 To $iArrMaskSize - 1
            Call("_VectorOf" & $typeOfMask & "Push", $vectorMask, $mask[$i])
        Next

        $iArrMask = Call("_cveInputArrayFromVectorOf" & $typeOfMask, $vectorMask)
    Else
        If $bMaskCreate Then
            $mask = Call("_cve" & $typeOfMask & "Create", $mask)
        EndIf
        $iArrMask = Call("_cveInputArrayFrom" & $typeOfMask, $mask)
    EndIf

    _cveConvertCorrespondencies($iArrCols, $iArrSrcLocations, $oArrPts2d, $ioArrPts3d, $iArrMask)

    If $bMaskIsArray Then
        Call("_VectorOf" & $typeOfMask & "Release", $vectorMask)
    EndIf

    If $typeOfMask <> Default Then
        _cveInputArrayRelease($iArrMask)
        If $bMaskCreate Then
            Call("_cve" & $typeOfMask & "Release", $mask)
        EndIf
    EndIf

    If $bPts3dIsArray Then
        Call("_VectorOf" & $typeOfPts3d & "Release", $vectorPts3d)
    EndIf

    If $typeOfPts3d <> Default Then
        _cveInputOutputArrayRelease($ioArrPts3d)
        If $bPts3dCreate Then
            Call("_cve" & $typeOfPts3d & "Release", $pts3d)
        EndIf
    EndIf

    If $bPts2dIsArray Then
        Call("_VectorOf" & $typeOfPts2d & "Release", $vectorPts2d)
    EndIf

    If $typeOfPts2d <> Default Then
        _cveOutputArrayRelease($oArrPts2d)
        If $bPts2dCreate Then
            Call("_cve" & $typeOfPts2d & "Release", $pts2d)
        EndIf
    EndIf

    If $bSrcLocationsIsArray Then
        Call("_VectorOf" & $typeOfSrcLocations & "Release", $vectorSrcLocations)
    EndIf

    If $typeOfSrcLocations <> Default Then
        _cveInputArrayRelease($iArrSrcLocations)
        If $bSrcLocationsCreate Then
            Call("_cve" & $typeOfSrcLocations & "Release", $srcLocations)
        EndIf
    EndIf

    If $bColsIsArray Then
        Call("_VectorOf" & $typeOfCols & "Release", $vectorCols)
    EndIf

    If $typeOfCols <> Default Then
        _cveInputArrayRelease($iArrCols)
        If $bColsCreate Then
            Call("_cve" & $typeOfCols & "Release", $cols)
        EndIf
    EndIf
EndFunc   ;==>_cveConvertCorrespondenciesTyped

Func _cveConvertCorrespondenciesMat($cols, $srcLocations, $pts2d, $pts3d = _cveNoArrayMat(), $mask = _cveNoArrayMat())
    ; cveConvertCorrespondencies using cv::Mat instead of _*Array
    _cveConvertCorrespondenciesTyped("Mat", $cols, "Mat", $srcLocations, "Mat", $pts2d, "Mat", $pts3d, "Mat", $mask)
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

Func _cveRapidTyped($typeOfImg, $img, $num, $len, $typeOfPts3d, $pts3d, $typeOfTris, $tris, $typeOfK, $K, $typeOfRvec, $rvec, $typeOfTvec, $tvec, $rmsd = 0)

    Local $iArrImg, $vectorImg, $iArrImgSize
    Local $bImgIsArray = IsArray($img)
    Local $bImgCreate = IsDllStruct($img) And $typeOfImg == "Scalar"

    If $typeOfImg == Default Then
        $iArrImg = $img
    ElseIf $bImgIsArray Then
        $vectorImg = Call("_VectorOf" & $typeOfImg & "Create")

        $iArrImgSize = UBound($img)
        For $i = 0 To $iArrImgSize - 1
            Call("_VectorOf" & $typeOfImg & "Push", $vectorImg, $img[$i])
        Next

        $iArrImg = Call("_cveInputArrayFromVectorOf" & $typeOfImg, $vectorImg)
    Else
        If $bImgCreate Then
            $img = Call("_cve" & $typeOfImg & "Create", $img)
        EndIf
        $iArrImg = Call("_cveInputArrayFrom" & $typeOfImg, $img)
    EndIf

    Local $iArrPts3d, $vectorPts3d, $iArrPts3dSize
    Local $bPts3dIsArray = IsArray($pts3d)
    Local $bPts3dCreate = IsDllStruct($pts3d) And $typeOfPts3d == "Scalar"

    If $typeOfPts3d == Default Then
        $iArrPts3d = $pts3d
    ElseIf $bPts3dIsArray Then
        $vectorPts3d = Call("_VectorOf" & $typeOfPts3d & "Create")

        $iArrPts3dSize = UBound($pts3d)
        For $i = 0 To $iArrPts3dSize - 1
            Call("_VectorOf" & $typeOfPts3d & "Push", $vectorPts3d, $pts3d[$i])
        Next

        $iArrPts3d = Call("_cveInputArrayFromVectorOf" & $typeOfPts3d, $vectorPts3d)
    Else
        If $bPts3dCreate Then
            $pts3d = Call("_cve" & $typeOfPts3d & "Create", $pts3d)
        EndIf
        $iArrPts3d = Call("_cveInputArrayFrom" & $typeOfPts3d, $pts3d)
    EndIf

    Local $iArrTris, $vectorTris, $iArrTrisSize
    Local $bTrisIsArray = IsArray($tris)
    Local $bTrisCreate = IsDllStruct($tris) And $typeOfTris == "Scalar"

    If $typeOfTris == Default Then
        $iArrTris = $tris
    ElseIf $bTrisIsArray Then
        $vectorTris = Call("_VectorOf" & $typeOfTris & "Create")

        $iArrTrisSize = UBound($tris)
        For $i = 0 To $iArrTrisSize - 1
            Call("_VectorOf" & $typeOfTris & "Push", $vectorTris, $tris[$i])
        Next

        $iArrTris = Call("_cveInputArrayFromVectorOf" & $typeOfTris, $vectorTris)
    Else
        If $bTrisCreate Then
            $tris = Call("_cve" & $typeOfTris & "Create", $tris)
        EndIf
        $iArrTris = Call("_cveInputArrayFrom" & $typeOfTris, $tris)
    EndIf

    Local $iArrK, $vectorK, $iArrKSize
    Local $bKIsArray = IsArray($K)
    Local $bKCreate = IsDllStruct($K) And $typeOfK == "Scalar"

    If $typeOfK == Default Then
        $iArrK = $K
    ElseIf $bKIsArray Then
        $vectorK = Call("_VectorOf" & $typeOfK & "Create")

        $iArrKSize = UBound($K)
        For $i = 0 To $iArrKSize - 1
            Call("_VectorOf" & $typeOfK & "Push", $vectorK, $K[$i])
        Next

        $iArrK = Call("_cveInputArrayFromVectorOf" & $typeOfK, $vectorK)
    Else
        If $bKCreate Then
            $K = Call("_cve" & $typeOfK & "Create", $K)
        EndIf
        $iArrK = Call("_cveInputArrayFrom" & $typeOfK, $K)
    EndIf

    Local $ioArrRvec, $vectorRvec, $iArrRvecSize
    Local $bRvecIsArray = IsArray($rvec)
    Local $bRvecCreate = IsDllStruct($rvec) And $typeOfRvec == "Scalar"

    If $typeOfRvec == Default Then
        $ioArrRvec = $rvec
    ElseIf $bRvecIsArray Then
        $vectorRvec = Call("_VectorOf" & $typeOfRvec & "Create")

        $iArrRvecSize = UBound($rvec)
        For $i = 0 To $iArrRvecSize - 1
            Call("_VectorOf" & $typeOfRvec & "Push", $vectorRvec, $rvec[$i])
        Next

        $ioArrRvec = Call("_cveInputOutputArrayFromVectorOf" & $typeOfRvec, $vectorRvec)
    Else
        If $bRvecCreate Then
            $rvec = Call("_cve" & $typeOfRvec & "Create", $rvec)
        EndIf
        $ioArrRvec = Call("_cveInputOutputArrayFrom" & $typeOfRvec, $rvec)
    EndIf

    Local $ioArrTvec, $vectorTvec, $iArrTvecSize
    Local $bTvecIsArray = IsArray($tvec)
    Local $bTvecCreate = IsDllStruct($tvec) And $typeOfTvec == "Scalar"

    If $typeOfTvec == Default Then
        $ioArrTvec = $tvec
    ElseIf $bTvecIsArray Then
        $vectorTvec = Call("_VectorOf" & $typeOfTvec & "Create")

        $iArrTvecSize = UBound($tvec)
        For $i = 0 To $iArrTvecSize - 1
            Call("_VectorOf" & $typeOfTvec & "Push", $vectorTvec, $tvec[$i])
        Next

        $ioArrTvec = Call("_cveInputOutputArrayFromVectorOf" & $typeOfTvec, $vectorTvec)
    Else
        If $bTvecCreate Then
            $tvec = Call("_cve" & $typeOfTvec & "Create", $tvec)
        EndIf
        $ioArrTvec = Call("_cveInputOutputArrayFrom" & $typeOfTvec, $tvec)
    EndIf

    Local $retval = _cveRapid($iArrImg, $num, $len, $iArrPts3d, $iArrTris, $iArrK, $ioArrRvec, $ioArrTvec, $rmsd)

    If $bTvecIsArray Then
        Call("_VectorOf" & $typeOfTvec & "Release", $vectorTvec)
    EndIf

    If $typeOfTvec <> Default Then
        _cveInputOutputArrayRelease($ioArrTvec)
        If $bTvecCreate Then
            Call("_cve" & $typeOfTvec & "Release", $tvec)
        EndIf
    EndIf

    If $bRvecIsArray Then
        Call("_VectorOf" & $typeOfRvec & "Release", $vectorRvec)
    EndIf

    If $typeOfRvec <> Default Then
        _cveInputOutputArrayRelease($ioArrRvec)
        If $bRvecCreate Then
            Call("_cve" & $typeOfRvec & "Release", $rvec)
        EndIf
    EndIf

    If $bKIsArray Then
        Call("_VectorOf" & $typeOfK & "Release", $vectorK)
    EndIf

    If $typeOfK <> Default Then
        _cveInputArrayRelease($iArrK)
        If $bKCreate Then
            Call("_cve" & $typeOfK & "Release", $K)
        EndIf
    EndIf

    If $bTrisIsArray Then
        Call("_VectorOf" & $typeOfTris & "Release", $vectorTris)
    EndIf

    If $typeOfTris <> Default Then
        _cveInputArrayRelease($iArrTris)
        If $bTrisCreate Then
            Call("_cve" & $typeOfTris & "Release", $tris)
        EndIf
    EndIf

    If $bPts3dIsArray Then
        Call("_VectorOf" & $typeOfPts3d & "Release", $vectorPts3d)
    EndIf

    If $typeOfPts3d <> Default Then
        _cveInputArrayRelease($iArrPts3d)
        If $bPts3dCreate Then
            Call("_cve" & $typeOfPts3d & "Release", $pts3d)
        EndIf
    EndIf

    If $bImgIsArray Then
        Call("_VectorOf" & $typeOfImg & "Release", $vectorImg)
    EndIf

    If $typeOfImg <> Default Then
        _cveInputArrayRelease($iArrImg)
        If $bImgCreate Then
            Call("_cve" & $typeOfImg & "Release", $img)
        EndIf
    EndIf

    Return $retval
EndFunc   ;==>_cveRapidTyped

Func _cveRapidMat($img, $num, $len, $pts3d, $tris, $K, $rvec, $tvec, $rmsd = 0)
    ; cveRapid using cv::Mat instead of _*Array
    Local $retval = _cveRapidTyped("Mat", $img, $num, $len, "Mat", $pts3d, "Mat", $tris, "Mat", $K, "Mat", $rvec, "Mat", $tvec, $rmsd)

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

Func _cveTrackerComputeTyped($tracker, $typeOfImg, $img, $num, $len, $typeOfK, $K, $typeOfRvec, $rvec, $typeOfTvec, $tvec, $termcrit)

    Local $iArrImg, $vectorImg, $iArrImgSize
    Local $bImgIsArray = IsArray($img)
    Local $bImgCreate = IsDllStruct($img) And $typeOfImg == "Scalar"

    If $typeOfImg == Default Then
        $iArrImg = $img
    ElseIf $bImgIsArray Then
        $vectorImg = Call("_VectorOf" & $typeOfImg & "Create")

        $iArrImgSize = UBound($img)
        For $i = 0 To $iArrImgSize - 1
            Call("_VectorOf" & $typeOfImg & "Push", $vectorImg, $img[$i])
        Next

        $iArrImg = Call("_cveInputArrayFromVectorOf" & $typeOfImg, $vectorImg)
    Else
        If $bImgCreate Then
            $img = Call("_cve" & $typeOfImg & "Create", $img)
        EndIf
        $iArrImg = Call("_cveInputArrayFrom" & $typeOfImg, $img)
    EndIf

    Local $iArrK, $vectorK, $iArrKSize
    Local $bKIsArray = IsArray($K)
    Local $bKCreate = IsDllStruct($K) And $typeOfK == "Scalar"

    If $typeOfK == Default Then
        $iArrK = $K
    ElseIf $bKIsArray Then
        $vectorK = Call("_VectorOf" & $typeOfK & "Create")

        $iArrKSize = UBound($K)
        For $i = 0 To $iArrKSize - 1
            Call("_VectorOf" & $typeOfK & "Push", $vectorK, $K[$i])
        Next

        $iArrK = Call("_cveInputArrayFromVectorOf" & $typeOfK, $vectorK)
    Else
        If $bKCreate Then
            $K = Call("_cve" & $typeOfK & "Create", $K)
        EndIf
        $iArrK = Call("_cveInputArrayFrom" & $typeOfK, $K)
    EndIf

    Local $ioArrRvec, $vectorRvec, $iArrRvecSize
    Local $bRvecIsArray = IsArray($rvec)
    Local $bRvecCreate = IsDllStruct($rvec) And $typeOfRvec == "Scalar"

    If $typeOfRvec == Default Then
        $ioArrRvec = $rvec
    ElseIf $bRvecIsArray Then
        $vectorRvec = Call("_VectorOf" & $typeOfRvec & "Create")

        $iArrRvecSize = UBound($rvec)
        For $i = 0 To $iArrRvecSize - 1
            Call("_VectorOf" & $typeOfRvec & "Push", $vectorRvec, $rvec[$i])
        Next

        $ioArrRvec = Call("_cveInputOutputArrayFromVectorOf" & $typeOfRvec, $vectorRvec)
    Else
        If $bRvecCreate Then
            $rvec = Call("_cve" & $typeOfRvec & "Create", $rvec)
        EndIf
        $ioArrRvec = Call("_cveInputOutputArrayFrom" & $typeOfRvec, $rvec)
    EndIf

    Local $ioArrTvec, $vectorTvec, $iArrTvecSize
    Local $bTvecIsArray = IsArray($tvec)
    Local $bTvecCreate = IsDllStruct($tvec) And $typeOfTvec == "Scalar"

    If $typeOfTvec == Default Then
        $ioArrTvec = $tvec
    ElseIf $bTvecIsArray Then
        $vectorTvec = Call("_VectorOf" & $typeOfTvec & "Create")

        $iArrTvecSize = UBound($tvec)
        For $i = 0 To $iArrTvecSize - 1
            Call("_VectorOf" & $typeOfTvec & "Push", $vectorTvec, $tvec[$i])
        Next

        $ioArrTvec = Call("_cveInputOutputArrayFromVectorOf" & $typeOfTvec, $vectorTvec)
    Else
        If $bTvecCreate Then
            $tvec = Call("_cve" & $typeOfTvec & "Create", $tvec)
        EndIf
        $ioArrTvec = Call("_cveInputOutputArrayFrom" & $typeOfTvec, $tvec)
    EndIf

    Local $retval = _cveTrackerCompute($tracker, $iArrImg, $num, $len, $iArrK, $ioArrRvec, $ioArrTvec, $termcrit)

    If $bTvecIsArray Then
        Call("_VectorOf" & $typeOfTvec & "Release", $vectorTvec)
    EndIf

    If $typeOfTvec <> Default Then
        _cveInputOutputArrayRelease($ioArrTvec)
        If $bTvecCreate Then
            Call("_cve" & $typeOfTvec & "Release", $tvec)
        EndIf
    EndIf

    If $bRvecIsArray Then
        Call("_VectorOf" & $typeOfRvec & "Release", $vectorRvec)
    EndIf

    If $typeOfRvec <> Default Then
        _cveInputOutputArrayRelease($ioArrRvec)
        If $bRvecCreate Then
            Call("_cve" & $typeOfRvec & "Release", $rvec)
        EndIf
    EndIf

    If $bKIsArray Then
        Call("_VectorOf" & $typeOfK & "Release", $vectorK)
    EndIf

    If $typeOfK <> Default Then
        _cveInputArrayRelease($iArrK)
        If $bKCreate Then
            Call("_cve" & $typeOfK & "Release", $K)
        EndIf
    EndIf

    If $bImgIsArray Then
        Call("_VectorOf" & $typeOfImg & "Release", $vectorImg)
    EndIf

    If $typeOfImg <> Default Then
        _cveInputArrayRelease($iArrImg)
        If $bImgCreate Then
            Call("_cve" & $typeOfImg & "Release", $img)
        EndIf
    EndIf

    Return $retval
EndFunc   ;==>_cveTrackerComputeTyped

Func _cveTrackerComputeMat($tracker, $img, $num, $len, $K, $rvec, $tvec, $termcrit)
    ; cveTrackerCompute using cv::Mat instead of _*Array
    Local $retval = _cveTrackerComputeTyped($tracker, "Mat", $img, $num, $len, "Mat", $K, "Mat", $rvec, "Mat", $tvec, $termcrit)

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

Func _cveRapidCreateTyped($typeOfPts3d, $pts3d, $typeOfTris, $tris, $tracker, $algorithm, $sharedPtr)

    Local $iArrPts3d, $vectorPts3d, $iArrPts3dSize
    Local $bPts3dIsArray = IsArray($pts3d)
    Local $bPts3dCreate = IsDllStruct($pts3d) And $typeOfPts3d == "Scalar"

    If $typeOfPts3d == Default Then
        $iArrPts3d = $pts3d
    ElseIf $bPts3dIsArray Then
        $vectorPts3d = Call("_VectorOf" & $typeOfPts3d & "Create")

        $iArrPts3dSize = UBound($pts3d)
        For $i = 0 To $iArrPts3dSize - 1
            Call("_VectorOf" & $typeOfPts3d & "Push", $vectorPts3d, $pts3d[$i])
        Next

        $iArrPts3d = Call("_cveInputArrayFromVectorOf" & $typeOfPts3d, $vectorPts3d)
    Else
        If $bPts3dCreate Then
            $pts3d = Call("_cve" & $typeOfPts3d & "Create", $pts3d)
        EndIf
        $iArrPts3d = Call("_cveInputArrayFrom" & $typeOfPts3d, $pts3d)
    EndIf

    Local $iArrTris, $vectorTris, $iArrTrisSize
    Local $bTrisIsArray = IsArray($tris)
    Local $bTrisCreate = IsDllStruct($tris) And $typeOfTris == "Scalar"

    If $typeOfTris == Default Then
        $iArrTris = $tris
    ElseIf $bTrisIsArray Then
        $vectorTris = Call("_VectorOf" & $typeOfTris & "Create")

        $iArrTrisSize = UBound($tris)
        For $i = 0 To $iArrTrisSize - 1
            Call("_VectorOf" & $typeOfTris & "Push", $vectorTris, $tris[$i])
        Next

        $iArrTris = Call("_cveInputArrayFromVectorOf" & $typeOfTris, $vectorTris)
    Else
        If $bTrisCreate Then
            $tris = Call("_cve" & $typeOfTris & "Create", $tris)
        EndIf
        $iArrTris = Call("_cveInputArrayFrom" & $typeOfTris, $tris)
    EndIf

    Local $retval = _cveRapidCreate($iArrPts3d, $iArrTris, $tracker, $algorithm, $sharedPtr)

    If $bTrisIsArray Then
        Call("_VectorOf" & $typeOfTris & "Release", $vectorTris)
    EndIf

    If $typeOfTris <> Default Then
        _cveInputArrayRelease($iArrTris)
        If $bTrisCreate Then
            Call("_cve" & $typeOfTris & "Release", $tris)
        EndIf
    EndIf

    If $bPts3dIsArray Then
        Call("_VectorOf" & $typeOfPts3d & "Release", $vectorPts3d)
    EndIf

    If $typeOfPts3d <> Default Then
        _cveInputArrayRelease($iArrPts3d)
        If $bPts3dCreate Then
            Call("_cve" & $typeOfPts3d & "Release", $pts3d)
        EndIf
    EndIf

    Return $retval
EndFunc   ;==>_cveRapidCreateTyped

Func _cveRapidCreateMat($pts3d, $tris, $tracker, $algorithm, $sharedPtr)
    ; cveRapidCreate using cv::Mat instead of _*Array
    Local $retval = _cveRapidCreateTyped("Mat", $pts3d, "Mat", $tris, $tracker, $algorithm, $sharedPtr)

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

Func _cveOLSTrackerCreateTyped($typeOfPts3d, $pts3d, $typeOfTris, $tris, $histBins, $sobelThesh, $tracker, $algorithm, $sharedPtr)

    Local $iArrPts3d, $vectorPts3d, $iArrPts3dSize
    Local $bPts3dIsArray = IsArray($pts3d)
    Local $bPts3dCreate = IsDllStruct($pts3d) And $typeOfPts3d == "Scalar"

    If $typeOfPts3d == Default Then
        $iArrPts3d = $pts3d
    ElseIf $bPts3dIsArray Then
        $vectorPts3d = Call("_VectorOf" & $typeOfPts3d & "Create")

        $iArrPts3dSize = UBound($pts3d)
        For $i = 0 To $iArrPts3dSize - 1
            Call("_VectorOf" & $typeOfPts3d & "Push", $vectorPts3d, $pts3d[$i])
        Next

        $iArrPts3d = Call("_cveInputArrayFromVectorOf" & $typeOfPts3d, $vectorPts3d)
    Else
        If $bPts3dCreate Then
            $pts3d = Call("_cve" & $typeOfPts3d & "Create", $pts3d)
        EndIf
        $iArrPts3d = Call("_cveInputArrayFrom" & $typeOfPts3d, $pts3d)
    EndIf

    Local $iArrTris, $vectorTris, $iArrTrisSize
    Local $bTrisIsArray = IsArray($tris)
    Local $bTrisCreate = IsDllStruct($tris) And $typeOfTris == "Scalar"

    If $typeOfTris == Default Then
        $iArrTris = $tris
    ElseIf $bTrisIsArray Then
        $vectorTris = Call("_VectorOf" & $typeOfTris & "Create")

        $iArrTrisSize = UBound($tris)
        For $i = 0 To $iArrTrisSize - 1
            Call("_VectorOf" & $typeOfTris & "Push", $vectorTris, $tris[$i])
        Next

        $iArrTris = Call("_cveInputArrayFromVectorOf" & $typeOfTris, $vectorTris)
    Else
        If $bTrisCreate Then
            $tris = Call("_cve" & $typeOfTris & "Create", $tris)
        EndIf
        $iArrTris = Call("_cveInputArrayFrom" & $typeOfTris, $tris)
    EndIf

    Local $retval = _cveOLSTrackerCreate($iArrPts3d, $iArrTris, $histBins, $sobelThesh, $tracker, $algorithm, $sharedPtr)

    If $bTrisIsArray Then
        Call("_VectorOf" & $typeOfTris & "Release", $vectorTris)
    EndIf

    If $typeOfTris <> Default Then
        _cveInputArrayRelease($iArrTris)
        If $bTrisCreate Then
            Call("_cve" & $typeOfTris & "Release", $tris)
        EndIf
    EndIf

    If $bPts3dIsArray Then
        Call("_VectorOf" & $typeOfPts3d & "Release", $vectorPts3d)
    EndIf

    If $typeOfPts3d <> Default Then
        _cveInputArrayRelease($iArrPts3d)
        If $bPts3dCreate Then
            Call("_cve" & $typeOfPts3d & "Release", $pts3d)
        EndIf
    EndIf

    Return $retval
EndFunc   ;==>_cveOLSTrackerCreateTyped

Func _cveOLSTrackerCreateMat($pts3d, $tris, $histBins, $sobelThesh, $tracker, $algorithm, $sharedPtr)
    ; cveOLSTrackerCreate using cv::Mat instead of _*Array
    Local $retval = _cveOLSTrackerCreateTyped("Mat", $pts3d, "Mat", $tris, $histBins, $sobelThesh, $tracker, $algorithm, $sharedPtr)

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