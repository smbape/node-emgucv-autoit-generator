#include-once
#include "..\..\CVEUtils.au3"

Func _cveArucoGetPredefinedDictionary($name, $sharedPtr)
    ; CVAPI(cv::aruco::Dictionary*) cveArucoGetPredefinedDictionary(int name, cv::Ptr<cv::aruco::Dictionary>** sharedPtr);

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveArucoGetPredefinedDictionary", "int", $name, $sSharedPtrDllType, $sharedPtr), "cveArucoGetPredefinedDictionary", @error)
EndFunc   ;==>_cveArucoGetPredefinedDictionary

Func _cveArucoDictionaryCreate1($nMarkers, $markerSize, $sharedPtr)
    ; CVAPI(cv::aruco::Dictionary*) cveArucoDictionaryCreate1(int nMarkers, int markerSize, cv::Ptr<cv::aruco::Dictionary>** sharedPtr);

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveArucoDictionaryCreate1", "int", $nMarkers, "int", $markerSize, $sSharedPtrDllType, $sharedPtr), "cveArucoDictionaryCreate1", @error)
EndFunc   ;==>_cveArucoDictionaryCreate1

Func _cveArucoDictionaryCreate2($nMarkers, $markerSize, $baseDictionary, $sharedPtr)
    ; CVAPI(cv::aruco::Dictionary*) cveArucoDictionaryCreate2(int nMarkers, int markerSize, cv::Ptr<cv::aruco::Dictionary>* baseDictionary, cv::Ptr<cv::aruco::Dictionary>** sharedPtr);

    Local $sBaseDictionaryDllType
    If IsDllStruct($baseDictionary) Then
        $sBaseDictionaryDllType = "struct*"
    Else
        $sBaseDictionaryDllType = "ptr"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveArucoDictionaryCreate2", "int", $nMarkers, "int", $markerSize, $sBaseDictionaryDllType, $baseDictionary, $sSharedPtrDllType, $sharedPtr), "cveArucoDictionaryCreate2", @error)
EndFunc   ;==>_cveArucoDictionaryCreate2

Func _cveArucoDictionaryRelease($dict, $sharedPtr)
    ; CVAPI(void) cveArucoDictionaryRelease(cv::aruco::Dictionary** dict, cv::Ptr<cv::aruco::Dictionary>** sharedPtr);

    Local $sDictDllType
    If IsDllStruct($dict) Then
        $sDictDllType = "struct*"
    ElseIf $dict == Null Then
        $sDictDllType = "ptr"
    Else
        $sDictDllType = "ptr*"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveArucoDictionaryRelease", $sDictDllType, $dict, $sSharedPtrDllType, $sharedPtr), "cveArucoDictionaryRelease", @error)
EndFunc   ;==>_cveArucoDictionaryRelease

Func _cveArucoDrawMarker($dictionary, $id, $sidePixels, $img, $borderBits)
    ; CVAPI(void) cveArucoDrawMarker(cv::aruco::Dictionary* dictionary, int id, int sidePixels, cv::_OutputArray* img, int borderBits);

    Local $sDictionaryDllType
    If IsDllStruct($dictionary) Then
        $sDictionaryDllType = "struct*"
    Else
        $sDictionaryDllType = "ptr"
    EndIf

    Local $sImgDllType
    If IsDllStruct($img) Then
        $sImgDllType = "struct*"
    Else
        $sImgDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveArucoDrawMarker", $sDictionaryDllType, $dictionary, "int", $id, "int", $sidePixels, $sImgDllType, $img, "int", $borderBits), "cveArucoDrawMarker", @error)
EndFunc   ;==>_cveArucoDrawMarker

Func _cveArucoDrawMarkerTyped($dictionary, $id, $sidePixels, $typeOfImg, $img, $borderBits)

    Local $oArrImg, $vectorImg, $iArrImgSize
    Local $bImgIsArray = IsArray($img)
    Local $bImgCreate = IsDllStruct($img) And $typeOfImg == "Scalar"

    If $typeOfImg == Default Then
        $oArrImg = $img
    ElseIf $bImgIsArray Then
        $vectorImg = Call("_VectorOf" & $typeOfImg & "Create")

        $iArrImgSize = UBound($img)
        For $i = 0 To $iArrImgSize - 1
            Call("_VectorOf" & $typeOfImg & "Push", $vectorImg, $img[$i])
        Next

        $oArrImg = Call("_cveOutputArrayFromVectorOf" & $typeOfImg, $vectorImg)
    Else
        If $bImgCreate Then
            $img = Call("_cve" & $typeOfImg & "Create", $img)
        EndIf
        $oArrImg = Call("_cveOutputArrayFrom" & $typeOfImg, $img)
    EndIf

    _cveArucoDrawMarker($dictionary, $id, $sidePixels, $oArrImg, $borderBits)

    If $bImgIsArray Then
        Call("_VectorOf" & $typeOfImg & "Release", $vectorImg)
    EndIf

    If $typeOfImg <> Default Then
        _cveOutputArrayRelease($oArrImg)
        If $bImgCreate Then
            Call("_cve" & $typeOfImg & "Release", $img)
        EndIf
    EndIf
EndFunc   ;==>_cveArucoDrawMarkerTyped

Func _cveArucoDrawMarkerMat($dictionary, $id, $sidePixels, $img, $borderBits)
    ; cveArucoDrawMarker using cv::Mat instead of _*Array
    _cveArucoDrawMarkerTyped($dictionary, $id, $sidePixels, "Mat", $img, $borderBits)
EndFunc   ;==>_cveArucoDrawMarkerMat

Func _cveArucoDrawAxis($image, $cameraMatrix, $distCoeffs, $rvec, $tvec, $length)
    ; CVAPI(void) cveArucoDrawAxis(cv::_InputOutputArray* image, cv::_InputArray* cameraMatrix, cv::_InputArray* distCoeffs, cv::_InputArray* rvec, cv::_InputArray* tvec, float length);

    Local $sImageDllType
    If IsDllStruct($image) Then
        $sImageDllType = "struct*"
    Else
        $sImageDllType = "ptr"
    EndIf

    Local $sCameraMatrixDllType
    If IsDllStruct($cameraMatrix) Then
        $sCameraMatrixDllType = "struct*"
    Else
        $sCameraMatrixDllType = "ptr"
    EndIf

    Local $sDistCoeffsDllType
    If IsDllStruct($distCoeffs) Then
        $sDistCoeffsDllType = "struct*"
    Else
        $sDistCoeffsDllType = "ptr"
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveArucoDrawAxis", $sImageDllType, $image, $sCameraMatrixDllType, $cameraMatrix, $sDistCoeffsDllType, $distCoeffs, $sRvecDllType, $rvec, $sTvecDllType, $tvec, "float", $length), "cveArucoDrawAxis", @error)
EndFunc   ;==>_cveArucoDrawAxis

Func _cveArucoDrawAxisTyped($typeOfImage, $image, $typeOfCameraMatrix, $cameraMatrix, $typeOfDistCoeffs, $distCoeffs, $typeOfRvec, $rvec, $typeOfTvec, $tvec, $length)

    Local $ioArrImage, $vectorImage, $iArrImageSize
    Local $bImageIsArray = IsArray($image)
    Local $bImageCreate = IsDllStruct($image) And $typeOfImage == "Scalar"

    If $typeOfImage == Default Then
        $ioArrImage = $image
    ElseIf $bImageIsArray Then
        $vectorImage = Call("_VectorOf" & $typeOfImage & "Create")

        $iArrImageSize = UBound($image)
        For $i = 0 To $iArrImageSize - 1
            Call("_VectorOf" & $typeOfImage & "Push", $vectorImage, $image[$i])
        Next

        $ioArrImage = Call("_cveInputOutputArrayFromVectorOf" & $typeOfImage, $vectorImage)
    Else
        If $bImageCreate Then
            $image = Call("_cve" & $typeOfImage & "Create", $image)
        EndIf
        $ioArrImage = Call("_cveInputOutputArrayFrom" & $typeOfImage, $image)
    EndIf

    Local $iArrCameraMatrix, $vectorCameraMatrix, $iArrCameraMatrixSize
    Local $bCameraMatrixIsArray = IsArray($cameraMatrix)
    Local $bCameraMatrixCreate = IsDllStruct($cameraMatrix) And $typeOfCameraMatrix == "Scalar"

    If $typeOfCameraMatrix == Default Then
        $iArrCameraMatrix = $cameraMatrix
    ElseIf $bCameraMatrixIsArray Then
        $vectorCameraMatrix = Call("_VectorOf" & $typeOfCameraMatrix & "Create")

        $iArrCameraMatrixSize = UBound($cameraMatrix)
        For $i = 0 To $iArrCameraMatrixSize - 1
            Call("_VectorOf" & $typeOfCameraMatrix & "Push", $vectorCameraMatrix, $cameraMatrix[$i])
        Next

        $iArrCameraMatrix = Call("_cveInputArrayFromVectorOf" & $typeOfCameraMatrix, $vectorCameraMatrix)
    Else
        If $bCameraMatrixCreate Then
            $cameraMatrix = Call("_cve" & $typeOfCameraMatrix & "Create", $cameraMatrix)
        EndIf
        $iArrCameraMatrix = Call("_cveInputArrayFrom" & $typeOfCameraMatrix, $cameraMatrix)
    EndIf

    Local $iArrDistCoeffs, $vectorDistCoeffs, $iArrDistCoeffsSize
    Local $bDistCoeffsIsArray = IsArray($distCoeffs)
    Local $bDistCoeffsCreate = IsDllStruct($distCoeffs) And $typeOfDistCoeffs == "Scalar"

    If $typeOfDistCoeffs == Default Then
        $iArrDistCoeffs = $distCoeffs
    ElseIf $bDistCoeffsIsArray Then
        $vectorDistCoeffs = Call("_VectorOf" & $typeOfDistCoeffs & "Create")

        $iArrDistCoeffsSize = UBound($distCoeffs)
        For $i = 0 To $iArrDistCoeffsSize - 1
            Call("_VectorOf" & $typeOfDistCoeffs & "Push", $vectorDistCoeffs, $distCoeffs[$i])
        Next

        $iArrDistCoeffs = Call("_cveInputArrayFromVectorOf" & $typeOfDistCoeffs, $vectorDistCoeffs)
    Else
        If $bDistCoeffsCreate Then
            $distCoeffs = Call("_cve" & $typeOfDistCoeffs & "Create", $distCoeffs)
        EndIf
        $iArrDistCoeffs = Call("_cveInputArrayFrom" & $typeOfDistCoeffs, $distCoeffs)
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

    _cveArucoDrawAxis($ioArrImage, $iArrCameraMatrix, $iArrDistCoeffs, $iArrRvec, $iArrTvec, $length)

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

    If $bDistCoeffsIsArray Then
        Call("_VectorOf" & $typeOfDistCoeffs & "Release", $vectorDistCoeffs)
    EndIf

    If $typeOfDistCoeffs <> Default Then
        _cveInputArrayRelease($iArrDistCoeffs)
        If $bDistCoeffsCreate Then
            Call("_cve" & $typeOfDistCoeffs & "Release", $distCoeffs)
        EndIf
    EndIf

    If $bCameraMatrixIsArray Then
        Call("_VectorOf" & $typeOfCameraMatrix & "Release", $vectorCameraMatrix)
    EndIf

    If $typeOfCameraMatrix <> Default Then
        _cveInputArrayRelease($iArrCameraMatrix)
        If $bCameraMatrixCreate Then
            Call("_cve" & $typeOfCameraMatrix & "Release", $cameraMatrix)
        EndIf
    EndIf

    If $bImageIsArray Then
        Call("_VectorOf" & $typeOfImage & "Release", $vectorImage)
    EndIf

    If $typeOfImage <> Default Then
        _cveInputOutputArrayRelease($ioArrImage)
        If $bImageCreate Then
            Call("_cve" & $typeOfImage & "Release", $image)
        EndIf
    EndIf
EndFunc   ;==>_cveArucoDrawAxisTyped

Func _cveArucoDrawAxisMat($image, $cameraMatrix, $distCoeffs, $rvec, $tvec, $length)
    ; cveArucoDrawAxis using cv::Mat instead of _*Array
    _cveArucoDrawAxisTyped("Mat", $image, "Mat", $cameraMatrix, "Mat", $distCoeffs, "Mat", $rvec, "Mat", $tvec, $length)
EndFunc   ;==>_cveArucoDrawAxisMat

Func _cveArucoDetectMarkers($image, $dictionary, $corners, $ids, $parameters, $rejectedImgPoints)
    ; CVAPI(void) cveArucoDetectMarkers(cv::_InputArray* image, cv::aruco::Dictionary* dictionary, cv::_OutputArray* corners, cv::_OutputArray* ids, cv::aruco::DetectorParameters* parameters, cv::_OutputArray* rejectedImgPoints);

    Local $sImageDllType
    If IsDllStruct($image) Then
        $sImageDllType = "struct*"
    Else
        $sImageDllType = "ptr"
    EndIf

    Local $sDictionaryDllType
    If IsDllStruct($dictionary) Then
        $sDictionaryDllType = "struct*"
    Else
        $sDictionaryDllType = "ptr"
    EndIf

    Local $sCornersDllType
    If IsDllStruct($corners) Then
        $sCornersDllType = "struct*"
    Else
        $sCornersDllType = "ptr"
    EndIf

    Local $sIdsDllType
    If IsDllStruct($ids) Then
        $sIdsDllType = "struct*"
    Else
        $sIdsDllType = "ptr"
    EndIf

    Local $sParametersDllType
    If IsDllStruct($parameters) Then
        $sParametersDllType = "struct*"
    Else
        $sParametersDllType = "ptr"
    EndIf

    Local $sRejectedImgPointsDllType
    If IsDllStruct($rejectedImgPoints) Then
        $sRejectedImgPointsDllType = "struct*"
    Else
        $sRejectedImgPointsDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveArucoDetectMarkers", $sImageDllType, $image, $sDictionaryDllType, $dictionary, $sCornersDllType, $corners, $sIdsDllType, $ids, $sParametersDllType, $parameters, $sRejectedImgPointsDllType, $rejectedImgPoints), "cveArucoDetectMarkers", @error)
EndFunc   ;==>_cveArucoDetectMarkers

Func _cveArucoDetectMarkersTyped($typeOfImage, $image, $dictionary, $typeOfCorners, $corners, $typeOfIds, $ids, $parameters, $typeOfRejectedImgPoints, $rejectedImgPoints)

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

    Local $oArrCorners, $vectorCorners, $iArrCornersSize
    Local $bCornersIsArray = IsArray($corners)
    Local $bCornersCreate = IsDllStruct($corners) And $typeOfCorners == "Scalar"

    If $typeOfCorners == Default Then
        $oArrCorners = $corners
    ElseIf $bCornersIsArray Then
        $vectorCorners = Call("_VectorOf" & $typeOfCorners & "Create")

        $iArrCornersSize = UBound($corners)
        For $i = 0 To $iArrCornersSize - 1
            Call("_VectorOf" & $typeOfCorners & "Push", $vectorCorners, $corners[$i])
        Next

        $oArrCorners = Call("_cveOutputArrayFromVectorOf" & $typeOfCorners, $vectorCorners)
    Else
        If $bCornersCreate Then
            $corners = Call("_cve" & $typeOfCorners & "Create", $corners)
        EndIf
        $oArrCorners = Call("_cveOutputArrayFrom" & $typeOfCorners, $corners)
    EndIf

    Local $oArrIds, $vectorIds, $iArrIdsSize
    Local $bIdsIsArray = IsArray($ids)
    Local $bIdsCreate = IsDllStruct($ids) And $typeOfIds == "Scalar"

    If $typeOfIds == Default Then
        $oArrIds = $ids
    ElseIf $bIdsIsArray Then
        $vectorIds = Call("_VectorOf" & $typeOfIds & "Create")

        $iArrIdsSize = UBound($ids)
        For $i = 0 To $iArrIdsSize - 1
            Call("_VectorOf" & $typeOfIds & "Push", $vectorIds, $ids[$i])
        Next

        $oArrIds = Call("_cveOutputArrayFromVectorOf" & $typeOfIds, $vectorIds)
    Else
        If $bIdsCreate Then
            $ids = Call("_cve" & $typeOfIds & "Create", $ids)
        EndIf
        $oArrIds = Call("_cveOutputArrayFrom" & $typeOfIds, $ids)
    EndIf

    Local $oArrRejectedImgPoints, $vectorRejectedImgPoints, $iArrRejectedImgPointsSize
    Local $bRejectedImgPointsIsArray = IsArray($rejectedImgPoints)
    Local $bRejectedImgPointsCreate = IsDllStruct($rejectedImgPoints) And $typeOfRejectedImgPoints == "Scalar"

    If $typeOfRejectedImgPoints == Default Then
        $oArrRejectedImgPoints = $rejectedImgPoints
    ElseIf $bRejectedImgPointsIsArray Then
        $vectorRejectedImgPoints = Call("_VectorOf" & $typeOfRejectedImgPoints & "Create")

        $iArrRejectedImgPointsSize = UBound($rejectedImgPoints)
        For $i = 0 To $iArrRejectedImgPointsSize - 1
            Call("_VectorOf" & $typeOfRejectedImgPoints & "Push", $vectorRejectedImgPoints, $rejectedImgPoints[$i])
        Next

        $oArrRejectedImgPoints = Call("_cveOutputArrayFromVectorOf" & $typeOfRejectedImgPoints, $vectorRejectedImgPoints)
    Else
        If $bRejectedImgPointsCreate Then
            $rejectedImgPoints = Call("_cve" & $typeOfRejectedImgPoints & "Create", $rejectedImgPoints)
        EndIf
        $oArrRejectedImgPoints = Call("_cveOutputArrayFrom" & $typeOfRejectedImgPoints, $rejectedImgPoints)
    EndIf

    _cveArucoDetectMarkers($iArrImage, $dictionary, $oArrCorners, $oArrIds, $parameters, $oArrRejectedImgPoints)

    If $bRejectedImgPointsIsArray Then
        Call("_VectorOf" & $typeOfRejectedImgPoints & "Release", $vectorRejectedImgPoints)
    EndIf

    If $typeOfRejectedImgPoints <> Default Then
        _cveOutputArrayRelease($oArrRejectedImgPoints)
        If $bRejectedImgPointsCreate Then
            Call("_cve" & $typeOfRejectedImgPoints & "Release", $rejectedImgPoints)
        EndIf
    EndIf

    If $bIdsIsArray Then
        Call("_VectorOf" & $typeOfIds & "Release", $vectorIds)
    EndIf

    If $typeOfIds <> Default Then
        _cveOutputArrayRelease($oArrIds)
        If $bIdsCreate Then
            Call("_cve" & $typeOfIds & "Release", $ids)
        EndIf
    EndIf

    If $bCornersIsArray Then
        Call("_VectorOf" & $typeOfCorners & "Release", $vectorCorners)
    EndIf

    If $typeOfCorners <> Default Then
        _cveOutputArrayRelease($oArrCorners)
        If $bCornersCreate Then
            Call("_cve" & $typeOfCorners & "Release", $corners)
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
EndFunc   ;==>_cveArucoDetectMarkersTyped

Func _cveArucoDetectMarkersMat($image, $dictionary, $corners, $ids, $parameters, $rejectedImgPoints)
    ; cveArucoDetectMarkers using cv::Mat instead of _*Array
    _cveArucoDetectMarkersTyped("Mat", $image, $dictionary, "Mat", $corners, "Mat", $ids, $parameters, "Mat", $rejectedImgPoints)
EndFunc   ;==>_cveArucoDetectMarkersMat

Func _cveArucoEstimatePoseSingleMarkers($corners, $markerLength, $cameraMatrix, $distCoeffs, $rvecs, $tvecs)
    ; CVAPI(void) cveArucoEstimatePoseSingleMarkers(cv::_InputArray* corners, float markerLength, cv::_InputArray* cameraMatrix, cv::_InputArray* distCoeffs, cv::_OutputArray* rvecs, cv::_OutputArray* tvecs);

    Local $sCornersDllType
    If IsDllStruct($corners) Then
        $sCornersDllType = "struct*"
    Else
        $sCornersDllType = "ptr"
    EndIf

    Local $sCameraMatrixDllType
    If IsDllStruct($cameraMatrix) Then
        $sCameraMatrixDllType = "struct*"
    Else
        $sCameraMatrixDllType = "ptr"
    EndIf

    Local $sDistCoeffsDllType
    If IsDllStruct($distCoeffs) Then
        $sDistCoeffsDllType = "struct*"
    Else
        $sDistCoeffsDllType = "ptr"
    EndIf

    Local $sRvecsDllType
    If IsDllStruct($rvecs) Then
        $sRvecsDllType = "struct*"
    Else
        $sRvecsDllType = "ptr"
    EndIf

    Local $sTvecsDllType
    If IsDllStruct($tvecs) Then
        $sTvecsDllType = "struct*"
    Else
        $sTvecsDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveArucoEstimatePoseSingleMarkers", $sCornersDllType, $corners, "float", $markerLength, $sCameraMatrixDllType, $cameraMatrix, $sDistCoeffsDllType, $distCoeffs, $sRvecsDllType, $rvecs, $sTvecsDllType, $tvecs), "cveArucoEstimatePoseSingleMarkers", @error)
EndFunc   ;==>_cveArucoEstimatePoseSingleMarkers

Func _cveArucoEstimatePoseSingleMarkersTyped($typeOfCorners, $corners, $markerLength, $typeOfCameraMatrix, $cameraMatrix, $typeOfDistCoeffs, $distCoeffs, $typeOfRvecs, $rvecs, $typeOfTvecs, $tvecs)

    Local $iArrCorners, $vectorCorners, $iArrCornersSize
    Local $bCornersIsArray = IsArray($corners)
    Local $bCornersCreate = IsDllStruct($corners) And $typeOfCorners == "Scalar"

    If $typeOfCorners == Default Then
        $iArrCorners = $corners
    ElseIf $bCornersIsArray Then
        $vectorCorners = Call("_VectorOf" & $typeOfCorners & "Create")

        $iArrCornersSize = UBound($corners)
        For $i = 0 To $iArrCornersSize - 1
            Call("_VectorOf" & $typeOfCorners & "Push", $vectorCorners, $corners[$i])
        Next

        $iArrCorners = Call("_cveInputArrayFromVectorOf" & $typeOfCorners, $vectorCorners)
    Else
        If $bCornersCreate Then
            $corners = Call("_cve" & $typeOfCorners & "Create", $corners)
        EndIf
        $iArrCorners = Call("_cveInputArrayFrom" & $typeOfCorners, $corners)
    EndIf

    Local $iArrCameraMatrix, $vectorCameraMatrix, $iArrCameraMatrixSize
    Local $bCameraMatrixIsArray = IsArray($cameraMatrix)
    Local $bCameraMatrixCreate = IsDllStruct($cameraMatrix) And $typeOfCameraMatrix == "Scalar"

    If $typeOfCameraMatrix == Default Then
        $iArrCameraMatrix = $cameraMatrix
    ElseIf $bCameraMatrixIsArray Then
        $vectorCameraMatrix = Call("_VectorOf" & $typeOfCameraMatrix & "Create")

        $iArrCameraMatrixSize = UBound($cameraMatrix)
        For $i = 0 To $iArrCameraMatrixSize - 1
            Call("_VectorOf" & $typeOfCameraMatrix & "Push", $vectorCameraMatrix, $cameraMatrix[$i])
        Next

        $iArrCameraMatrix = Call("_cveInputArrayFromVectorOf" & $typeOfCameraMatrix, $vectorCameraMatrix)
    Else
        If $bCameraMatrixCreate Then
            $cameraMatrix = Call("_cve" & $typeOfCameraMatrix & "Create", $cameraMatrix)
        EndIf
        $iArrCameraMatrix = Call("_cveInputArrayFrom" & $typeOfCameraMatrix, $cameraMatrix)
    EndIf

    Local $iArrDistCoeffs, $vectorDistCoeffs, $iArrDistCoeffsSize
    Local $bDistCoeffsIsArray = IsArray($distCoeffs)
    Local $bDistCoeffsCreate = IsDllStruct($distCoeffs) And $typeOfDistCoeffs == "Scalar"

    If $typeOfDistCoeffs == Default Then
        $iArrDistCoeffs = $distCoeffs
    ElseIf $bDistCoeffsIsArray Then
        $vectorDistCoeffs = Call("_VectorOf" & $typeOfDistCoeffs & "Create")

        $iArrDistCoeffsSize = UBound($distCoeffs)
        For $i = 0 To $iArrDistCoeffsSize - 1
            Call("_VectorOf" & $typeOfDistCoeffs & "Push", $vectorDistCoeffs, $distCoeffs[$i])
        Next

        $iArrDistCoeffs = Call("_cveInputArrayFromVectorOf" & $typeOfDistCoeffs, $vectorDistCoeffs)
    Else
        If $bDistCoeffsCreate Then
            $distCoeffs = Call("_cve" & $typeOfDistCoeffs & "Create", $distCoeffs)
        EndIf
        $iArrDistCoeffs = Call("_cveInputArrayFrom" & $typeOfDistCoeffs, $distCoeffs)
    EndIf

    Local $oArrRvecs, $vectorRvecs, $iArrRvecsSize
    Local $bRvecsIsArray = IsArray($rvecs)
    Local $bRvecsCreate = IsDllStruct($rvecs) And $typeOfRvecs == "Scalar"

    If $typeOfRvecs == Default Then
        $oArrRvecs = $rvecs
    ElseIf $bRvecsIsArray Then
        $vectorRvecs = Call("_VectorOf" & $typeOfRvecs & "Create")

        $iArrRvecsSize = UBound($rvecs)
        For $i = 0 To $iArrRvecsSize - 1
            Call("_VectorOf" & $typeOfRvecs & "Push", $vectorRvecs, $rvecs[$i])
        Next

        $oArrRvecs = Call("_cveOutputArrayFromVectorOf" & $typeOfRvecs, $vectorRvecs)
    Else
        If $bRvecsCreate Then
            $rvecs = Call("_cve" & $typeOfRvecs & "Create", $rvecs)
        EndIf
        $oArrRvecs = Call("_cveOutputArrayFrom" & $typeOfRvecs, $rvecs)
    EndIf

    Local $oArrTvecs, $vectorTvecs, $iArrTvecsSize
    Local $bTvecsIsArray = IsArray($tvecs)
    Local $bTvecsCreate = IsDllStruct($tvecs) And $typeOfTvecs == "Scalar"

    If $typeOfTvecs == Default Then
        $oArrTvecs = $tvecs
    ElseIf $bTvecsIsArray Then
        $vectorTvecs = Call("_VectorOf" & $typeOfTvecs & "Create")

        $iArrTvecsSize = UBound($tvecs)
        For $i = 0 To $iArrTvecsSize - 1
            Call("_VectorOf" & $typeOfTvecs & "Push", $vectorTvecs, $tvecs[$i])
        Next

        $oArrTvecs = Call("_cveOutputArrayFromVectorOf" & $typeOfTvecs, $vectorTvecs)
    Else
        If $bTvecsCreate Then
            $tvecs = Call("_cve" & $typeOfTvecs & "Create", $tvecs)
        EndIf
        $oArrTvecs = Call("_cveOutputArrayFrom" & $typeOfTvecs, $tvecs)
    EndIf

    _cveArucoEstimatePoseSingleMarkers($iArrCorners, $markerLength, $iArrCameraMatrix, $iArrDistCoeffs, $oArrRvecs, $oArrTvecs)

    If $bTvecsIsArray Then
        Call("_VectorOf" & $typeOfTvecs & "Release", $vectorTvecs)
    EndIf

    If $typeOfTvecs <> Default Then
        _cveOutputArrayRelease($oArrTvecs)
        If $bTvecsCreate Then
            Call("_cve" & $typeOfTvecs & "Release", $tvecs)
        EndIf
    EndIf

    If $bRvecsIsArray Then
        Call("_VectorOf" & $typeOfRvecs & "Release", $vectorRvecs)
    EndIf

    If $typeOfRvecs <> Default Then
        _cveOutputArrayRelease($oArrRvecs)
        If $bRvecsCreate Then
            Call("_cve" & $typeOfRvecs & "Release", $rvecs)
        EndIf
    EndIf

    If $bDistCoeffsIsArray Then
        Call("_VectorOf" & $typeOfDistCoeffs & "Release", $vectorDistCoeffs)
    EndIf

    If $typeOfDistCoeffs <> Default Then
        _cveInputArrayRelease($iArrDistCoeffs)
        If $bDistCoeffsCreate Then
            Call("_cve" & $typeOfDistCoeffs & "Release", $distCoeffs)
        EndIf
    EndIf

    If $bCameraMatrixIsArray Then
        Call("_VectorOf" & $typeOfCameraMatrix & "Release", $vectorCameraMatrix)
    EndIf

    If $typeOfCameraMatrix <> Default Then
        _cveInputArrayRelease($iArrCameraMatrix)
        If $bCameraMatrixCreate Then
            Call("_cve" & $typeOfCameraMatrix & "Release", $cameraMatrix)
        EndIf
    EndIf

    If $bCornersIsArray Then
        Call("_VectorOf" & $typeOfCorners & "Release", $vectorCorners)
    EndIf

    If $typeOfCorners <> Default Then
        _cveInputArrayRelease($iArrCorners)
        If $bCornersCreate Then
            Call("_cve" & $typeOfCorners & "Release", $corners)
        EndIf
    EndIf
EndFunc   ;==>_cveArucoEstimatePoseSingleMarkersTyped

Func _cveArucoEstimatePoseSingleMarkersMat($corners, $markerLength, $cameraMatrix, $distCoeffs, $rvecs, $tvecs)
    ; cveArucoEstimatePoseSingleMarkers using cv::Mat instead of _*Array
    _cveArucoEstimatePoseSingleMarkersTyped("Mat", $corners, $markerLength, "Mat", $cameraMatrix, "Mat", $distCoeffs, "Mat", $rvecs, "Mat", $tvecs)
EndFunc   ;==>_cveArucoEstimatePoseSingleMarkersMat

Func _cveArucoGridBoardCreate($markersX, $markersY, $markerLength, $markerSeparation, $dictionary, $firstMarker, $boardPtr, $sharedPtr)
    ; CVAPI(cv::aruco::GridBoard*) cveArucoGridBoardCreate(int markersX, int markersY, float markerLength, float markerSeparation, cv::aruco::Dictionary* dictionary, int firstMarker, cv::aruco::Board** boardPtr, cv::Ptr<cv::aruco::GridBoard>** sharedPtr);

    Local $sDictionaryDllType
    If IsDllStruct($dictionary) Then
        $sDictionaryDllType = "struct*"
    Else
        $sDictionaryDllType = "ptr"
    EndIf

    Local $sBoardPtrDllType
    If IsDllStruct($boardPtr) Then
        $sBoardPtrDllType = "struct*"
    ElseIf $boardPtr == Null Then
        $sBoardPtrDllType = "ptr"
    Else
        $sBoardPtrDllType = "ptr*"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveArucoGridBoardCreate", "int", $markersX, "int", $markersY, "float", $markerLength, "float", $markerSeparation, $sDictionaryDllType, $dictionary, "int", $firstMarker, $sBoardPtrDllType, $boardPtr, $sSharedPtrDllType, $sharedPtr), "cveArucoGridBoardCreate", @error)
EndFunc   ;==>_cveArucoGridBoardCreate

Func _cveArucoGridBoardDraw($gridBoard, $outSize, $img, $marginSize, $borderBits)
    ; CVAPI(void) cveArucoGridBoardDraw(cv::aruco::GridBoard* gridBoard, CvSize* outSize, cv::_OutputArray* img, int marginSize, int borderBits);

    Local $sGridBoardDllType
    If IsDllStruct($gridBoard) Then
        $sGridBoardDllType = "struct*"
    Else
        $sGridBoardDllType = "ptr"
    EndIf

    Local $sOutSizeDllType
    If IsDllStruct($outSize) Then
        $sOutSizeDllType = "struct*"
    Else
        $sOutSizeDllType = "ptr"
    EndIf

    Local $sImgDllType
    If IsDllStruct($img) Then
        $sImgDllType = "struct*"
    Else
        $sImgDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveArucoGridBoardDraw", $sGridBoardDllType, $gridBoard, $sOutSizeDllType, $outSize, $sImgDllType, $img, "int", $marginSize, "int", $borderBits), "cveArucoGridBoardDraw", @error)
EndFunc   ;==>_cveArucoGridBoardDraw

Func _cveArucoGridBoardDrawTyped($gridBoard, $outSize, $typeOfImg, $img, $marginSize, $borderBits)

    Local $oArrImg, $vectorImg, $iArrImgSize
    Local $bImgIsArray = IsArray($img)
    Local $bImgCreate = IsDllStruct($img) And $typeOfImg == "Scalar"

    If $typeOfImg == Default Then
        $oArrImg = $img
    ElseIf $bImgIsArray Then
        $vectorImg = Call("_VectorOf" & $typeOfImg & "Create")

        $iArrImgSize = UBound($img)
        For $i = 0 To $iArrImgSize - 1
            Call("_VectorOf" & $typeOfImg & "Push", $vectorImg, $img[$i])
        Next

        $oArrImg = Call("_cveOutputArrayFromVectorOf" & $typeOfImg, $vectorImg)
    Else
        If $bImgCreate Then
            $img = Call("_cve" & $typeOfImg & "Create", $img)
        EndIf
        $oArrImg = Call("_cveOutputArrayFrom" & $typeOfImg, $img)
    EndIf

    _cveArucoGridBoardDraw($gridBoard, $outSize, $oArrImg, $marginSize, $borderBits)

    If $bImgIsArray Then
        Call("_VectorOf" & $typeOfImg & "Release", $vectorImg)
    EndIf

    If $typeOfImg <> Default Then
        _cveOutputArrayRelease($oArrImg)
        If $bImgCreate Then
            Call("_cve" & $typeOfImg & "Release", $img)
        EndIf
    EndIf
EndFunc   ;==>_cveArucoGridBoardDrawTyped

Func _cveArucoGridBoardDrawMat($gridBoard, $outSize, $img, $marginSize, $borderBits)
    ; cveArucoGridBoardDraw using cv::Mat instead of _*Array
    _cveArucoGridBoardDrawTyped($gridBoard, $outSize, "Mat", $img, $marginSize, $borderBits)
EndFunc   ;==>_cveArucoGridBoardDrawMat

Func _cveArucoGridBoardRelease($gridBoard, $sharedPtr)
    ; CVAPI(void) cveArucoGridBoardRelease(cv::aruco::GridBoard** gridBoard, cv::Ptr<cv::aruco::GridBoard>** sharedPtr);

    Local $sGridBoardDllType
    If IsDllStruct($gridBoard) Then
        $sGridBoardDllType = "struct*"
    ElseIf $gridBoard == Null Then
        $sGridBoardDllType = "ptr"
    Else
        $sGridBoardDllType = "ptr*"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveArucoGridBoardRelease", $sGridBoardDllType, $gridBoard, $sSharedPtrDllType, $sharedPtr), "cveArucoGridBoardRelease", @error)
EndFunc   ;==>_cveArucoGridBoardRelease

Func _cveCharucoBoardCreate($squaresX, $squaresY, $squareLength, $markerLength, $dictionary, $boardPtr, $sharedPtr)
    ; CVAPI(cv::aruco::CharucoBoard*) cveCharucoBoardCreate(int squaresX, int squaresY, float squareLength, float markerLength, cv::aruco::Dictionary* dictionary, cv::aruco::Board** boardPtr, cv::Ptr<cv::aruco::CharucoBoard>** sharedPtr);

    Local $sDictionaryDllType
    If IsDllStruct($dictionary) Then
        $sDictionaryDllType = "struct*"
    Else
        $sDictionaryDllType = "ptr"
    EndIf

    Local $sBoardPtrDllType
    If IsDllStruct($boardPtr) Then
        $sBoardPtrDllType = "struct*"
    ElseIf $boardPtr == Null Then
        $sBoardPtrDllType = "ptr"
    Else
        $sBoardPtrDllType = "ptr*"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveCharucoBoardCreate", "int", $squaresX, "int", $squaresY, "float", $squareLength, "float", $markerLength, $sDictionaryDllType, $dictionary, $sBoardPtrDllType, $boardPtr, $sSharedPtrDllType, $sharedPtr), "cveCharucoBoardCreate", @error)
EndFunc   ;==>_cveCharucoBoardCreate

Func _cveCharucoBoardDraw($charucoBoard, $outSize, $img, $marginSize, $borderBits)
    ; CVAPI(void) cveCharucoBoardDraw(cv::aruco::CharucoBoard* charucoBoard, CvSize* outSize, cv::_OutputArray* img, int marginSize, int borderBits);

    Local $sCharucoBoardDllType
    If IsDllStruct($charucoBoard) Then
        $sCharucoBoardDllType = "struct*"
    Else
        $sCharucoBoardDllType = "ptr"
    EndIf

    Local $sOutSizeDllType
    If IsDllStruct($outSize) Then
        $sOutSizeDllType = "struct*"
    Else
        $sOutSizeDllType = "ptr"
    EndIf

    Local $sImgDllType
    If IsDllStruct($img) Then
        $sImgDllType = "struct*"
    Else
        $sImgDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCharucoBoardDraw", $sCharucoBoardDllType, $charucoBoard, $sOutSizeDllType, $outSize, $sImgDllType, $img, "int", $marginSize, "int", $borderBits), "cveCharucoBoardDraw", @error)
EndFunc   ;==>_cveCharucoBoardDraw

Func _cveCharucoBoardDrawTyped($charucoBoard, $outSize, $typeOfImg, $img, $marginSize, $borderBits)

    Local $oArrImg, $vectorImg, $iArrImgSize
    Local $bImgIsArray = IsArray($img)
    Local $bImgCreate = IsDllStruct($img) And $typeOfImg == "Scalar"

    If $typeOfImg == Default Then
        $oArrImg = $img
    ElseIf $bImgIsArray Then
        $vectorImg = Call("_VectorOf" & $typeOfImg & "Create")

        $iArrImgSize = UBound($img)
        For $i = 0 To $iArrImgSize - 1
            Call("_VectorOf" & $typeOfImg & "Push", $vectorImg, $img[$i])
        Next

        $oArrImg = Call("_cveOutputArrayFromVectorOf" & $typeOfImg, $vectorImg)
    Else
        If $bImgCreate Then
            $img = Call("_cve" & $typeOfImg & "Create", $img)
        EndIf
        $oArrImg = Call("_cveOutputArrayFrom" & $typeOfImg, $img)
    EndIf

    _cveCharucoBoardDraw($charucoBoard, $outSize, $oArrImg, $marginSize, $borderBits)

    If $bImgIsArray Then
        Call("_VectorOf" & $typeOfImg & "Release", $vectorImg)
    EndIf

    If $typeOfImg <> Default Then
        _cveOutputArrayRelease($oArrImg)
        If $bImgCreate Then
            Call("_cve" & $typeOfImg & "Release", $img)
        EndIf
    EndIf
EndFunc   ;==>_cveCharucoBoardDrawTyped

Func _cveCharucoBoardDrawMat($charucoBoard, $outSize, $img, $marginSize, $borderBits)
    ; cveCharucoBoardDraw using cv::Mat instead of _*Array
    _cveCharucoBoardDrawTyped($charucoBoard, $outSize, "Mat", $img, $marginSize, $borderBits)
EndFunc   ;==>_cveCharucoBoardDrawMat

Func _cveCharucoBoardRelease($charucoBoard, $sharedPtr)
    ; CVAPI(void) cveCharucoBoardRelease(cv::aruco::CharucoBoard** charucoBoard, cv::Ptr<cv::aruco::CharucoBoard>** sharedPtr);

    Local $sCharucoBoardDllType
    If IsDllStruct($charucoBoard) Then
        $sCharucoBoardDllType = "struct*"
    ElseIf $charucoBoard == Null Then
        $sCharucoBoardDllType = "ptr"
    Else
        $sCharucoBoardDllType = "ptr*"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCharucoBoardRelease", $sCharucoBoardDllType, $charucoBoard, $sSharedPtrDllType, $sharedPtr), "cveCharucoBoardRelease", @error)
EndFunc   ;==>_cveCharucoBoardRelease

Func _cveArucoRefineDetectedMarkers($image, $board, $detectedCorners, $detectedIds, $rejectedCorners, $cameraMatrix, $distCoeffs, $minRepDistance, $errorCorrectionRate, $checkAllOrders, $recoveredIdxs, $parameters)
    ; CVAPI(void) cveArucoRefineDetectedMarkers(cv::_InputArray* image, cv::aruco::Board* board, cv::_InputOutputArray* detectedCorners, cv::_InputOutputArray* detectedIds, cv::_InputOutputArray* rejectedCorners, cv::_InputArray* cameraMatrix, cv::_InputArray* distCoeffs, float minRepDistance, float errorCorrectionRate, bool checkAllOrders, cv::_OutputArray* recoveredIdxs, cv::aruco::DetectorParameters* parameters);

    Local $sImageDllType
    If IsDllStruct($image) Then
        $sImageDllType = "struct*"
    Else
        $sImageDllType = "ptr"
    EndIf

    Local $sBoardDllType
    If IsDllStruct($board) Then
        $sBoardDllType = "struct*"
    Else
        $sBoardDllType = "ptr"
    EndIf

    Local $sDetectedCornersDllType
    If IsDllStruct($detectedCorners) Then
        $sDetectedCornersDllType = "struct*"
    Else
        $sDetectedCornersDllType = "ptr"
    EndIf

    Local $sDetectedIdsDllType
    If IsDllStruct($detectedIds) Then
        $sDetectedIdsDllType = "struct*"
    Else
        $sDetectedIdsDllType = "ptr"
    EndIf

    Local $sRejectedCornersDllType
    If IsDllStruct($rejectedCorners) Then
        $sRejectedCornersDllType = "struct*"
    Else
        $sRejectedCornersDllType = "ptr"
    EndIf

    Local $sCameraMatrixDllType
    If IsDllStruct($cameraMatrix) Then
        $sCameraMatrixDllType = "struct*"
    Else
        $sCameraMatrixDllType = "ptr"
    EndIf

    Local $sDistCoeffsDllType
    If IsDllStruct($distCoeffs) Then
        $sDistCoeffsDllType = "struct*"
    Else
        $sDistCoeffsDllType = "ptr"
    EndIf

    Local $sRecoveredIdxsDllType
    If IsDllStruct($recoveredIdxs) Then
        $sRecoveredIdxsDllType = "struct*"
    Else
        $sRecoveredIdxsDllType = "ptr"
    EndIf

    Local $sParametersDllType
    If IsDllStruct($parameters) Then
        $sParametersDllType = "struct*"
    Else
        $sParametersDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveArucoRefineDetectedMarkers", $sImageDllType, $image, $sBoardDllType, $board, $sDetectedCornersDllType, $detectedCorners, $sDetectedIdsDllType, $detectedIds, $sRejectedCornersDllType, $rejectedCorners, $sCameraMatrixDllType, $cameraMatrix, $sDistCoeffsDllType, $distCoeffs, "float", $minRepDistance, "float", $errorCorrectionRate, "boolean", $checkAllOrders, $sRecoveredIdxsDllType, $recoveredIdxs, $sParametersDllType, $parameters), "cveArucoRefineDetectedMarkers", @error)
EndFunc   ;==>_cveArucoRefineDetectedMarkers

Func _cveArucoRefineDetectedMarkersTyped($typeOfImage, $image, $board, $typeOfDetectedCorners, $detectedCorners, $typeOfDetectedIds, $detectedIds, $typeOfRejectedCorners, $rejectedCorners, $typeOfCameraMatrix, $cameraMatrix, $typeOfDistCoeffs, $distCoeffs, $minRepDistance, $errorCorrectionRate, $checkAllOrders, $typeOfRecoveredIdxs, $recoveredIdxs, $parameters)

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

    Local $ioArrDetectedCorners, $vectorDetectedCorners, $iArrDetectedCornersSize
    Local $bDetectedCornersIsArray = IsArray($detectedCorners)
    Local $bDetectedCornersCreate = IsDllStruct($detectedCorners) And $typeOfDetectedCorners == "Scalar"

    If $typeOfDetectedCorners == Default Then
        $ioArrDetectedCorners = $detectedCorners
    ElseIf $bDetectedCornersIsArray Then
        $vectorDetectedCorners = Call("_VectorOf" & $typeOfDetectedCorners & "Create")

        $iArrDetectedCornersSize = UBound($detectedCorners)
        For $i = 0 To $iArrDetectedCornersSize - 1
            Call("_VectorOf" & $typeOfDetectedCorners & "Push", $vectorDetectedCorners, $detectedCorners[$i])
        Next

        $ioArrDetectedCorners = Call("_cveInputOutputArrayFromVectorOf" & $typeOfDetectedCorners, $vectorDetectedCorners)
    Else
        If $bDetectedCornersCreate Then
            $detectedCorners = Call("_cve" & $typeOfDetectedCorners & "Create", $detectedCorners)
        EndIf
        $ioArrDetectedCorners = Call("_cveInputOutputArrayFrom" & $typeOfDetectedCorners, $detectedCorners)
    EndIf

    Local $ioArrDetectedIds, $vectorDetectedIds, $iArrDetectedIdsSize
    Local $bDetectedIdsIsArray = IsArray($detectedIds)
    Local $bDetectedIdsCreate = IsDllStruct($detectedIds) And $typeOfDetectedIds == "Scalar"

    If $typeOfDetectedIds == Default Then
        $ioArrDetectedIds = $detectedIds
    ElseIf $bDetectedIdsIsArray Then
        $vectorDetectedIds = Call("_VectorOf" & $typeOfDetectedIds & "Create")

        $iArrDetectedIdsSize = UBound($detectedIds)
        For $i = 0 To $iArrDetectedIdsSize - 1
            Call("_VectorOf" & $typeOfDetectedIds & "Push", $vectorDetectedIds, $detectedIds[$i])
        Next

        $ioArrDetectedIds = Call("_cveInputOutputArrayFromVectorOf" & $typeOfDetectedIds, $vectorDetectedIds)
    Else
        If $bDetectedIdsCreate Then
            $detectedIds = Call("_cve" & $typeOfDetectedIds & "Create", $detectedIds)
        EndIf
        $ioArrDetectedIds = Call("_cveInputOutputArrayFrom" & $typeOfDetectedIds, $detectedIds)
    EndIf

    Local $ioArrRejectedCorners, $vectorRejectedCorners, $iArrRejectedCornersSize
    Local $bRejectedCornersIsArray = IsArray($rejectedCorners)
    Local $bRejectedCornersCreate = IsDllStruct($rejectedCorners) And $typeOfRejectedCorners == "Scalar"

    If $typeOfRejectedCorners == Default Then
        $ioArrRejectedCorners = $rejectedCorners
    ElseIf $bRejectedCornersIsArray Then
        $vectorRejectedCorners = Call("_VectorOf" & $typeOfRejectedCorners & "Create")

        $iArrRejectedCornersSize = UBound($rejectedCorners)
        For $i = 0 To $iArrRejectedCornersSize - 1
            Call("_VectorOf" & $typeOfRejectedCorners & "Push", $vectorRejectedCorners, $rejectedCorners[$i])
        Next

        $ioArrRejectedCorners = Call("_cveInputOutputArrayFromVectorOf" & $typeOfRejectedCorners, $vectorRejectedCorners)
    Else
        If $bRejectedCornersCreate Then
            $rejectedCorners = Call("_cve" & $typeOfRejectedCorners & "Create", $rejectedCorners)
        EndIf
        $ioArrRejectedCorners = Call("_cveInputOutputArrayFrom" & $typeOfRejectedCorners, $rejectedCorners)
    EndIf

    Local $iArrCameraMatrix, $vectorCameraMatrix, $iArrCameraMatrixSize
    Local $bCameraMatrixIsArray = IsArray($cameraMatrix)
    Local $bCameraMatrixCreate = IsDllStruct($cameraMatrix) And $typeOfCameraMatrix == "Scalar"

    If $typeOfCameraMatrix == Default Then
        $iArrCameraMatrix = $cameraMatrix
    ElseIf $bCameraMatrixIsArray Then
        $vectorCameraMatrix = Call("_VectorOf" & $typeOfCameraMatrix & "Create")

        $iArrCameraMatrixSize = UBound($cameraMatrix)
        For $i = 0 To $iArrCameraMatrixSize - 1
            Call("_VectorOf" & $typeOfCameraMatrix & "Push", $vectorCameraMatrix, $cameraMatrix[$i])
        Next

        $iArrCameraMatrix = Call("_cveInputArrayFromVectorOf" & $typeOfCameraMatrix, $vectorCameraMatrix)
    Else
        If $bCameraMatrixCreate Then
            $cameraMatrix = Call("_cve" & $typeOfCameraMatrix & "Create", $cameraMatrix)
        EndIf
        $iArrCameraMatrix = Call("_cveInputArrayFrom" & $typeOfCameraMatrix, $cameraMatrix)
    EndIf

    Local $iArrDistCoeffs, $vectorDistCoeffs, $iArrDistCoeffsSize
    Local $bDistCoeffsIsArray = IsArray($distCoeffs)
    Local $bDistCoeffsCreate = IsDllStruct($distCoeffs) And $typeOfDistCoeffs == "Scalar"

    If $typeOfDistCoeffs == Default Then
        $iArrDistCoeffs = $distCoeffs
    ElseIf $bDistCoeffsIsArray Then
        $vectorDistCoeffs = Call("_VectorOf" & $typeOfDistCoeffs & "Create")

        $iArrDistCoeffsSize = UBound($distCoeffs)
        For $i = 0 To $iArrDistCoeffsSize - 1
            Call("_VectorOf" & $typeOfDistCoeffs & "Push", $vectorDistCoeffs, $distCoeffs[$i])
        Next

        $iArrDistCoeffs = Call("_cveInputArrayFromVectorOf" & $typeOfDistCoeffs, $vectorDistCoeffs)
    Else
        If $bDistCoeffsCreate Then
            $distCoeffs = Call("_cve" & $typeOfDistCoeffs & "Create", $distCoeffs)
        EndIf
        $iArrDistCoeffs = Call("_cveInputArrayFrom" & $typeOfDistCoeffs, $distCoeffs)
    EndIf

    Local $oArrRecoveredIdxs, $vectorRecoveredIdxs, $iArrRecoveredIdxsSize
    Local $bRecoveredIdxsIsArray = IsArray($recoveredIdxs)
    Local $bRecoveredIdxsCreate = IsDllStruct($recoveredIdxs) And $typeOfRecoveredIdxs == "Scalar"

    If $typeOfRecoveredIdxs == Default Then
        $oArrRecoveredIdxs = $recoveredIdxs
    ElseIf $bRecoveredIdxsIsArray Then
        $vectorRecoveredIdxs = Call("_VectorOf" & $typeOfRecoveredIdxs & "Create")

        $iArrRecoveredIdxsSize = UBound($recoveredIdxs)
        For $i = 0 To $iArrRecoveredIdxsSize - 1
            Call("_VectorOf" & $typeOfRecoveredIdxs & "Push", $vectorRecoveredIdxs, $recoveredIdxs[$i])
        Next

        $oArrRecoveredIdxs = Call("_cveOutputArrayFromVectorOf" & $typeOfRecoveredIdxs, $vectorRecoveredIdxs)
    Else
        If $bRecoveredIdxsCreate Then
            $recoveredIdxs = Call("_cve" & $typeOfRecoveredIdxs & "Create", $recoveredIdxs)
        EndIf
        $oArrRecoveredIdxs = Call("_cveOutputArrayFrom" & $typeOfRecoveredIdxs, $recoveredIdxs)
    EndIf

    _cveArucoRefineDetectedMarkers($iArrImage, $board, $ioArrDetectedCorners, $ioArrDetectedIds, $ioArrRejectedCorners, $iArrCameraMatrix, $iArrDistCoeffs, $minRepDistance, $errorCorrectionRate, $checkAllOrders, $oArrRecoveredIdxs, $parameters)

    If $bRecoveredIdxsIsArray Then
        Call("_VectorOf" & $typeOfRecoveredIdxs & "Release", $vectorRecoveredIdxs)
    EndIf

    If $typeOfRecoveredIdxs <> Default Then
        _cveOutputArrayRelease($oArrRecoveredIdxs)
        If $bRecoveredIdxsCreate Then
            Call("_cve" & $typeOfRecoveredIdxs & "Release", $recoveredIdxs)
        EndIf
    EndIf

    If $bDistCoeffsIsArray Then
        Call("_VectorOf" & $typeOfDistCoeffs & "Release", $vectorDistCoeffs)
    EndIf

    If $typeOfDistCoeffs <> Default Then
        _cveInputArrayRelease($iArrDistCoeffs)
        If $bDistCoeffsCreate Then
            Call("_cve" & $typeOfDistCoeffs & "Release", $distCoeffs)
        EndIf
    EndIf

    If $bCameraMatrixIsArray Then
        Call("_VectorOf" & $typeOfCameraMatrix & "Release", $vectorCameraMatrix)
    EndIf

    If $typeOfCameraMatrix <> Default Then
        _cveInputArrayRelease($iArrCameraMatrix)
        If $bCameraMatrixCreate Then
            Call("_cve" & $typeOfCameraMatrix & "Release", $cameraMatrix)
        EndIf
    EndIf

    If $bRejectedCornersIsArray Then
        Call("_VectorOf" & $typeOfRejectedCorners & "Release", $vectorRejectedCorners)
    EndIf

    If $typeOfRejectedCorners <> Default Then
        _cveInputOutputArrayRelease($ioArrRejectedCorners)
        If $bRejectedCornersCreate Then
            Call("_cve" & $typeOfRejectedCorners & "Release", $rejectedCorners)
        EndIf
    EndIf

    If $bDetectedIdsIsArray Then
        Call("_VectorOf" & $typeOfDetectedIds & "Release", $vectorDetectedIds)
    EndIf

    If $typeOfDetectedIds <> Default Then
        _cveInputOutputArrayRelease($ioArrDetectedIds)
        If $bDetectedIdsCreate Then
            Call("_cve" & $typeOfDetectedIds & "Release", $detectedIds)
        EndIf
    EndIf

    If $bDetectedCornersIsArray Then
        Call("_VectorOf" & $typeOfDetectedCorners & "Release", $vectorDetectedCorners)
    EndIf

    If $typeOfDetectedCorners <> Default Then
        _cveInputOutputArrayRelease($ioArrDetectedCorners)
        If $bDetectedCornersCreate Then
            Call("_cve" & $typeOfDetectedCorners & "Release", $detectedCorners)
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
EndFunc   ;==>_cveArucoRefineDetectedMarkersTyped

Func _cveArucoRefineDetectedMarkersMat($image, $board, $detectedCorners, $detectedIds, $rejectedCorners, $cameraMatrix, $distCoeffs, $minRepDistance, $errorCorrectionRate, $checkAllOrders, $recoveredIdxs, $parameters)
    ; cveArucoRefineDetectedMarkers using cv::Mat instead of _*Array
    _cveArucoRefineDetectedMarkersTyped("Mat", $image, $board, "Mat", $detectedCorners, "Mat", $detectedIds, "Mat", $rejectedCorners, "Mat", $cameraMatrix, "Mat", $distCoeffs, $minRepDistance, $errorCorrectionRate, $checkAllOrders, "Mat", $recoveredIdxs, $parameters)
EndFunc   ;==>_cveArucoRefineDetectedMarkersMat

Func _cveArucoDrawDetectedMarkers($image, $corners, $ids, $borderColor)
    ; CVAPI(void) cveArucoDrawDetectedMarkers(cv::_InputOutputArray* image, cv::_InputArray* corners, cv::_InputArray* ids, CvScalar* borderColor);

    Local $sImageDllType
    If IsDllStruct($image) Then
        $sImageDllType = "struct*"
    Else
        $sImageDllType = "ptr"
    EndIf

    Local $sCornersDllType
    If IsDllStruct($corners) Then
        $sCornersDllType = "struct*"
    Else
        $sCornersDllType = "ptr"
    EndIf

    Local $sIdsDllType
    If IsDllStruct($ids) Then
        $sIdsDllType = "struct*"
    Else
        $sIdsDllType = "ptr"
    EndIf

    Local $sBorderColorDllType
    If IsDllStruct($borderColor) Then
        $sBorderColorDllType = "struct*"
    Else
        $sBorderColorDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveArucoDrawDetectedMarkers", $sImageDllType, $image, $sCornersDllType, $corners, $sIdsDllType, $ids, $sBorderColorDllType, $borderColor), "cveArucoDrawDetectedMarkers", @error)
EndFunc   ;==>_cveArucoDrawDetectedMarkers

Func _cveArucoDrawDetectedMarkersTyped($typeOfImage, $image, $typeOfCorners, $corners, $typeOfIds, $ids, $borderColor)

    Local $ioArrImage, $vectorImage, $iArrImageSize
    Local $bImageIsArray = IsArray($image)
    Local $bImageCreate = IsDllStruct($image) And $typeOfImage == "Scalar"

    If $typeOfImage == Default Then
        $ioArrImage = $image
    ElseIf $bImageIsArray Then
        $vectorImage = Call("_VectorOf" & $typeOfImage & "Create")

        $iArrImageSize = UBound($image)
        For $i = 0 To $iArrImageSize - 1
            Call("_VectorOf" & $typeOfImage & "Push", $vectorImage, $image[$i])
        Next

        $ioArrImage = Call("_cveInputOutputArrayFromVectorOf" & $typeOfImage, $vectorImage)
    Else
        If $bImageCreate Then
            $image = Call("_cve" & $typeOfImage & "Create", $image)
        EndIf
        $ioArrImage = Call("_cveInputOutputArrayFrom" & $typeOfImage, $image)
    EndIf

    Local $iArrCorners, $vectorCorners, $iArrCornersSize
    Local $bCornersIsArray = IsArray($corners)
    Local $bCornersCreate = IsDllStruct($corners) And $typeOfCorners == "Scalar"

    If $typeOfCorners == Default Then
        $iArrCorners = $corners
    ElseIf $bCornersIsArray Then
        $vectorCorners = Call("_VectorOf" & $typeOfCorners & "Create")

        $iArrCornersSize = UBound($corners)
        For $i = 0 To $iArrCornersSize - 1
            Call("_VectorOf" & $typeOfCorners & "Push", $vectorCorners, $corners[$i])
        Next

        $iArrCorners = Call("_cveInputArrayFromVectorOf" & $typeOfCorners, $vectorCorners)
    Else
        If $bCornersCreate Then
            $corners = Call("_cve" & $typeOfCorners & "Create", $corners)
        EndIf
        $iArrCorners = Call("_cveInputArrayFrom" & $typeOfCorners, $corners)
    EndIf

    Local $iArrIds, $vectorIds, $iArrIdsSize
    Local $bIdsIsArray = IsArray($ids)
    Local $bIdsCreate = IsDllStruct($ids) And $typeOfIds == "Scalar"

    If $typeOfIds == Default Then
        $iArrIds = $ids
    ElseIf $bIdsIsArray Then
        $vectorIds = Call("_VectorOf" & $typeOfIds & "Create")

        $iArrIdsSize = UBound($ids)
        For $i = 0 To $iArrIdsSize - 1
            Call("_VectorOf" & $typeOfIds & "Push", $vectorIds, $ids[$i])
        Next

        $iArrIds = Call("_cveInputArrayFromVectorOf" & $typeOfIds, $vectorIds)
    Else
        If $bIdsCreate Then
            $ids = Call("_cve" & $typeOfIds & "Create", $ids)
        EndIf
        $iArrIds = Call("_cveInputArrayFrom" & $typeOfIds, $ids)
    EndIf

    _cveArucoDrawDetectedMarkers($ioArrImage, $iArrCorners, $iArrIds, $borderColor)

    If $bIdsIsArray Then
        Call("_VectorOf" & $typeOfIds & "Release", $vectorIds)
    EndIf

    If $typeOfIds <> Default Then
        _cveInputArrayRelease($iArrIds)
        If $bIdsCreate Then
            Call("_cve" & $typeOfIds & "Release", $ids)
        EndIf
    EndIf

    If $bCornersIsArray Then
        Call("_VectorOf" & $typeOfCorners & "Release", $vectorCorners)
    EndIf

    If $typeOfCorners <> Default Then
        _cveInputArrayRelease($iArrCorners)
        If $bCornersCreate Then
            Call("_cve" & $typeOfCorners & "Release", $corners)
        EndIf
    EndIf

    If $bImageIsArray Then
        Call("_VectorOf" & $typeOfImage & "Release", $vectorImage)
    EndIf

    If $typeOfImage <> Default Then
        _cveInputOutputArrayRelease($ioArrImage)
        If $bImageCreate Then
            Call("_cve" & $typeOfImage & "Release", $image)
        EndIf
    EndIf
EndFunc   ;==>_cveArucoDrawDetectedMarkersTyped

Func _cveArucoDrawDetectedMarkersMat($image, $corners, $ids, $borderColor)
    ; cveArucoDrawDetectedMarkers using cv::Mat instead of _*Array
    _cveArucoDrawDetectedMarkersTyped("Mat", $image, "Mat", $corners, "Mat", $ids, $borderColor)
EndFunc   ;==>_cveArucoDrawDetectedMarkersMat

Func _cveArucoCalibrateCameraAruco($corners, $ids, $counter, $board, $imageSize, $cameraMatrix, $distCoeffs, $rvecs, $tvecs, $stdDeviationsIntrinsics, $stdDeviationsExtrinsics, $perViewErrors, $flags, $criteria)
    ; CVAPI(double) cveArucoCalibrateCameraAruco(cv::_InputArray* corners, cv::_InputArray* ids, cv::_InputArray* counter, cv::aruco::Board* board, CvSize* imageSize, cv::_InputOutputArray* cameraMatrix, cv::_InputOutputArray* distCoeffs, cv::_OutputArray* rvecs, cv::_OutputArray* tvecs, cv::_OutputArray* stdDeviationsIntrinsics, cv::_OutputArray* stdDeviationsExtrinsics, cv::_OutputArray* perViewErrors, int flags, CvTermCriteria* criteria);

    Local $sCornersDllType
    If IsDllStruct($corners) Then
        $sCornersDllType = "struct*"
    Else
        $sCornersDllType = "ptr"
    EndIf

    Local $sIdsDllType
    If IsDllStruct($ids) Then
        $sIdsDllType = "struct*"
    Else
        $sIdsDllType = "ptr"
    EndIf

    Local $sCounterDllType
    If IsDllStruct($counter) Then
        $sCounterDllType = "struct*"
    Else
        $sCounterDllType = "ptr"
    EndIf

    Local $sBoardDllType
    If IsDllStruct($board) Then
        $sBoardDllType = "struct*"
    Else
        $sBoardDllType = "ptr"
    EndIf

    Local $sImageSizeDllType
    If IsDllStruct($imageSize) Then
        $sImageSizeDllType = "struct*"
    Else
        $sImageSizeDllType = "ptr"
    EndIf

    Local $sCameraMatrixDllType
    If IsDllStruct($cameraMatrix) Then
        $sCameraMatrixDllType = "struct*"
    Else
        $sCameraMatrixDllType = "ptr"
    EndIf

    Local $sDistCoeffsDllType
    If IsDllStruct($distCoeffs) Then
        $sDistCoeffsDllType = "struct*"
    Else
        $sDistCoeffsDllType = "ptr"
    EndIf

    Local $sRvecsDllType
    If IsDllStruct($rvecs) Then
        $sRvecsDllType = "struct*"
    Else
        $sRvecsDllType = "ptr"
    EndIf

    Local $sTvecsDllType
    If IsDllStruct($tvecs) Then
        $sTvecsDllType = "struct*"
    Else
        $sTvecsDllType = "ptr"
    EndIf

    Local $sStdDeviationsIntrinsicsDllType
    If IsDllStruct($stdDeviationsIntrinsics) Then
        $sStdDeviationsIntrinsicsDllType = "struct*"
    Else
        $sStdDeviationsIntrinsicsDllType = "ptr"
    EndIf

    Local $sStdDeviationsExtrinsicsDllType
    If IsDllStruct($stdDeviationsExtrinsics) Then
        $sStdDeviationsExtrinsicsDllType = "struct*"
    Else
        $sStdDeviationsExtrinsicsDllType = "ptr"
    EndIf

    Local $sPerViewErrorsDllType
    If IsDllStruct($perViewErrors) Then
        $sPerViewErrorsDllType = "struct*"
    Else
        $sPerViewErrorsDllType = "ptr"
    EndIf

    Local $sCriteriaDllType
    If IsDllStruct($criteria) Then
        $sCriteriaDllType = "struct*"
    Else
        $sCriteriaDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveArucoCalibrateCameraAruco", $sCornersDllType, $corners, $sIdsDllType, $ids, $sCounterDllType, $counter, $sBoardDllType, $board, $sImageSizeDllType, $imageSize, $sCameraMatrixDllType, $cameraMatrix, $sDistCoeffsDllType, $distCoeffs, $sRvecsDllType, $rvecs, $sTvecsDllType, $tvecs, $sStdDeviationsIntrinsicsDllType, $stdDeviationsIntrinsics, $sStdDeviationsExtrinsicsDllType, $stdDeviationsExtrinsics, $sPerViewErrorsDllType, $perViewErrors, "int", $flags, $sCriteriaDllType, $criteria), "cveArucoCalibrateCameraAruco", @error)
EndFunc   ;==>_cveArucoCalibrateCameraAruco

Func _cveArucoCalibrateCameraArucoTyped($typeOfCorners, $corners, $typeOfIds, $ids, $typeOfCounter, $counter, $board, $imageSize, $typeOfCameraMatrix, $cameraMatrix, $typeOfDistCoeffs, $distCoeffs, $typeOfRvecs, $rvecs, $typeOfTvecs, $tvecs, $typeOfStdDeviationsIntrinsics, $stdDeviationsIntrinsics, $typeOfStdDeviationsExtrinsics, $stdDeviationsExtrinsics, $typeOfPerViewErrors, $perViewErrors, $flags, $criteria)

    Local $iArrCorners, $vectorCorners, $iArrCornersSize
    Local $bCornersIsArray = IsArray($corners)
    Local $bCornersCreate = IsDllStruct($corners) And $typeOfCorners == "Scalar"

    If $typeOfCorners == Default Then
        $iArrCorners = $corners
    ElseIf $bCornersIsArray Then
        $vectorCorners = Call("_VectorOf" & $typeOfCorners & "Create")

        $iArrCornersSize = UBound($corners)
        For $i = 0 To $iArrCornersSize - 1
            Call("_VectorOf" & $typeOfCorners & "Push", $vectorCorners, $corners[$i])
        Next

        $iArrCorners = Call("_cveInputArrayFromVectorOf" & $typeOfCorners, $vectorCorners)
    Else
        If $bCornersCreate Then
            $corners = Call("_cve" & $typeOfCorners & "Create", $corners)
        EndIf
        $iArrCorners = Call("_cveInputArrayFrom" & $typeOfCorners, $corners)
    EndIf

    Local $iArrIds, $vectorIds, $iArrIdsSize
    Local $bIdsIsArray = IsArray($ids)
    Local $bIdsCreate = IsDllStruct($ids) And $typeOfIds == "Scalar"

    If $typeOfIds == Default Then
        $iArrIds = $ids
    ElseIf $bIdsIsArray Then
        $vectorIds = Call("_VectorOf" & $typeOfIds & "Create")

        $iArrIdsSize = UBound($ids)
        For $i = 0 To $iArrIdsSize - 1
            Call("_VectorOf" & $typeOfIds & "Push", $vectorIds, $ids[$i])
        Next

        $iArrIds = Call("_cveInputArrayFromVectorOf" & $typeOfIds, $vectorIds)
    Else
        If $bIdsCreate Then
            $ids = Call("_cve" & $typeOfIds & "Create", $ids)
        EndIf
        $iArrIds = Call("_cveInputArrayFrom" & $typeOfIds, $ids)
    EndIf

    Local $iArrCounter, $vectorCounter, $iArrCounterSize
    Local $bCounterIsArray = IsArray($counter)
    Local $bCounterCreate = IsDllStruct($counter) And $typeOfCounter == "Scalar"

    If $typeOfCounter == Default Then
        $iArrCounter = $counter
    ElseIf $bCounterIsArray Then
        $vectorCounter = Call("_VectorOf" & $typeOfCounter & "Create")

        $iArrCounterSize = UBound($counter)
        For $i = 0 To $iArrCounterSize - 1
            Call("_VectorOf" & $typeOfCounter & "Push", $vectorCounter, $counter[$i])
        Next

        $iArrCounter = Call("_cveInputArrayFromVectorOf" & $typeOfCounter, $vectorCounter)
    Else
        If $bCounterCreate Then
            $counter = Call("_cve" & $typeOfCounter & "Create", $counter)
        EndIf
        $iArrCounter = Call("_cveInputArrayFrom" & $typeOfCounter, $counter)
    EndIf

    Local $ioArrCameraMatrix, $vectorCameraMatrix, $iArrCameraMatrixSize
    Local $bCameraMatrixIsArray = IsArray($cameraMatrix)
    Local $bCameraMatrixCreate = IsDllStruct($cameraMatrix) And $typeOfCameraMatrix == "Scalar"

    If $typeOfCameraMatrix == Default Then
        $ioArrCameraMatrix = $cameraMatrix
    ElseIf $bCameraMatrixIsArray Then
        $vectorCameraMatrix = Call("_VectorOf" & $typeOfCameraMatrix & "Create")

        $iArrCameraMatrixSize = UBound($cameraMatrix)
        For $i = 0 To $iArrCameraMatrixSize - 1
            Call("_VectorOf" & $typeOfCameraMatrix & "Push", $vectorCameraMatrix, $cameraMatrix[$i])
        Next

        $ioArrCameraMatrix = Call("_cveInputOutputArrayFromVectorOf" & $typeOfCameraMatrix, $vectorCameraMatrix)
    Else
        If $bCameraMatrixCreate Then
            $cameraMatrix = Call("_cve" & $typeOfCameraMatrix & "Create", $cameraMatrix)
        EndIf
        $ioArrCameraMatrix = Call("_cveInputOutputArrayFrom" & $typeOfCameraMatrix, $cameraMatrix)
    EndIf

    Local $ioArrDistCoeffs, $vectorDistCoeffs, $iArrDistCoeffsSize
    Local $bDistCoeffsIsArray = IsArray($distCoeffs)
    Local $bDistCoeffsCreate = IsDllStruct($distCoeffs) And $typeOfDistCoeffs == "Scalar"

    If $typeOfDistCoeffs == Default Then
        $ioArrDistCoeffs = $distCoeffs
    ElseIf $bDistCoeffsIsArray Then
        $vectorDistCoeffs = Call("_VectorOf" & $typeOfDistCoeffs & "Create")

        $iArrDistCoeffsSize = UBound($distCoeffs)
        For $i = 0 To $iArrDistCoeffsSize - 1
            Call("_VectorOf" & $typeOfDistCoeffs & "Push", $vectorDistCoeffs, $distCoeffs[$i])
        Next

        $ioArrDistCoeffs = Call("_cveInputOutputArrayFromVectorOf" & $typeOfDistCoeffs, $vectorDistCoeffs)
    Else
        If $bDistCoeffsCreate Then
            $distCoeffs = Call("_cve" & $typeOfDistCoeffs & "Create", $distCoeffs)
        EndIf
        $ioArrDistCoeffs = Call("_cveInputOutputArrayFrom" & $typeOfDistCoeffs, $distCoeffs)
    EndIf

    Local $oArrRvecs, $vectorRvecs, $iArrRvecsSize
    Local $bRvecsIsArray = IsArray($rvecs)
    Local $bRvecsCreate = IsDllStruct($rvecs) And $typeOfRvecs == "Scalar"

    If $typeOfRvecs == Default Then
        $oArrRvecs = $rvecs
    ElseIf $bRvecsIsArray Then
        $vectorRvecs = Call("_VectorOf" & $typeOfRvecs & "Create")

        $iArrRvecsSize = UBound($rvecs)
        For $i = 0 To $iArrRvecsSize - 1
            Call("_VectorOf" & $typeOfRvecs & "Push", $vectorRvecs, $rvecs[$i])
        Next

        $oArrRvecs = Call("_cveOutputArrayFromVectorOf" & $typeOfRvecs, $vectorRvecs)
    Else
        If $bRvecsCreate Then
            $rvecs = Call("_cve" & $typeOfRvecs & "Create", $rvecs)
        EndIf
        $oArrRvecs = Call("_cveOutputArrayFrom" & $typeOfRvecs, $rvecs)
    EndIf

    Local $oArrTvecs, $vectorTvecs, $iArrTvecsSize
    Local $bTvecsIsArray = IsArray($tvecs)
    Local $bTvecsCreate = IsDllStruct($tvecs) And $typeOfTvecs == "Scalar"

    If $typeOfTvecs == Default Then
        $oArrTvecs = $tvecs
    ElseIf $bTvecsIsArray Then
        $vectorTvecs = Call("_VectorOf" & $typeOfTvecs & "Create")

        $iArrTvecsSize = UBound($tvecs)
        For $i = 0 To $iArrTvecsSize - 1
            Call("_VectorOf" & $typeOfTvecs & "Push", $vectorTvecs, $tvecs[$i])
        Next

        $oArrTvecs = Call("_cveOutputArrayFromVectorOf" & $typeOfTvecs, $vectorTvecs)
    Else
        If $bTvecsCreate Then
            $tvecs = Call("_cve" & $typeOfTvecs & "Create", $tvecs)
        EndIf
        $oArrTvecs = Call("_cveOutputArrayFrom" & $typeOfTvecs, $tvecs)
    EndIf

    Local $oArrStdDeviationsIntrinsics, $vectorStdDeviationsIntrinsics, $iArrStdDeviationsIntrinsicsSize
    Local $bStdDeviationsIntrinsicsIsArray = IsArray($stdDeviationsIntrinsics)
    Local $bStdDeviationsIntrinsicsCreate = IsDllStruct($stdDeviationsIntrinsics) And $typeOfStdDeviationsIntrinsics == "Scalar"

    If $typeOfStdDeviationsIntrinsics == Default Then
        $oArrStdDeviationsIntrinsics = $stdDeviationsIntrinsics
    ElseIf $bStdDeviationsIntrinsicsIsArray Then
        $vectorStdDeviationsIntrinsics = Call("_VectorOf" & $typeOfStdDeviationsIntrinsics & "Create")

        $iArrStdDeviationsIntrinsicsSize = UBound($stdDeviationsIntrinsics)
        For $i = 0 To $iArrStdDeviationsIntrinsicsSize - 1
            Call("_VectorOf" & $typeOfStdDeviationsIntrinsics & "Push", $vectorStdDeviationsIntrinsics, $stdDeviationsIntrinsics[$i])
        Next

        $oArrStdDeviationsIntrinsics = Call("_cveOutputArrayFromVectorOf" & $typeOfStdDeviationsIntrinsics, $vectorStdDeviationsIntrinsics)
    Else
        If $bStdDeviationsIntrinsicsCreate Then
            $stdDeviationsIntrinsics = Call("_cve" & $typeOfStdDeviationsIntrinsics & "Create", $stdDeviationsIntrinsics)
        EndIf
        $oArrStdDeviationsIntrinsics = Call("_cveOutputArrayFrom" & $typeOfStdDeviationsIntrinsics, $stdDeviationsIntrinsics)
    EndIf

    Local $oArrStdDeviationsExtrinsics, $vectorStdDeviationsExtrinsics, $iArrStdDeviationsExtrinsicsSize
    Local $bStdDeviationsExtrinsicsIsArray = IsArray($stdDeviationsExtrinsics)
    Local $bStdDeviationsExtrinsicsCreate = IsDllStruct($stdDeviationsExtrinsics) And $typeOfStdDeviationsExtrinsics == "Scalar"

    If $typeOfStdDeviationsExtrinsics == Default Then
        $oArrStdDeviationsExtrinsics = $stdDeviationsExtrinsics
    ElseIf $bStdDeviationsExtrinsicsIsArray Then
        $vectorStdDeviationsExtrinsics = Call("_VectorOf" & $typeOfStdDeviationsExtrinsics & "Create")

        $iArrStdDeviationsExtrinsicsSize = UBound($stdDeviationsExtrinsics)
        For $i = 0 To $iArrStdDeviationsExtrinsicsSize - 1
            Call("_VectorOf" & $typeOfStdDeviationsExtrinsics & "Push", $vectorStdDeviationsExtrinsics, $stdDeviationsExtrinsics[$i])
        Next

        $oArrStdDeviationsExtrinsics = Call("_cveOutputArrayFromVectorOf" & $typeOfStdDeviationsExtrinsics, $vectorStdDeviationsExtrinsics)
    Else
        If $bStdDeviationsExtrinsicsCreate Then
            $stdDeviationsExtrinsics = Call("_cve" & $typeOfStdDeviationsExtrinsics & "Create", $stdDeviationsExtrinsics)
        EndIf
        $oArrStdDeviationsExtrinsics = Call("_cveOutputArrayFrom" & $typeOfStdDeviationsExtrinsics, $stdDeviationsExtrinsics)
    EndIf

    Local $oArrPerViewErrors, $vectorPerViewErrors, $iArrPerViewErrorsSize
    Local $bPerViewErrorsIsArray = IsArray($perViewErrors)
    Local $bPerViewErrorsCreate = IsDllStruct($perViewErrors) And $typeOfPerViewErrors == "Scalar"

    If $typeOfPerViewErrors == Default Then
        $oArrPerViewErrors = $perViewErrors
    ElseIf $bPerViewErrorsIsArray Then
        $vectorPerViewErrors = Call("_VectorOf" & $typeOfPerViewErrors & "Create")

        $iArrPerViewErrorsSize = UBound($perViewErrors)
        For $i = 0 To $iArrPerViewErrorsSize - 1
            Call("_VectorOf" & $typeOfPerViewErrors & "Push", $vectorPerViewErrors, $perViewErrors[$i])
        Next

        $oArrPerViewErrors = Call("_cveOutputArrayFromVectorOf" & $typeOfPerViewErrors, $vectorPerViewErrors)
    Else
        If $bPerViewErrorsCreate Then
            $perViewErrors = Call("_cve" & $typeOfPerViewErrors & "Create", $perViewErrors)
        EndIf
        $oArrPerViewErrors = Call("_cveOutputArrayFrom" & $typeOfPerViewErrors, $perViewErrors)
    EndIf

    Local $retval = _cveArucoCalibrateCameraAruco($iArrCorners, $iArrIds, $iArrCounter, $board, $imageSize, $ioArrCameraMatrix, $ioArrDistCoeffs, $oArrRvecs, $oArrTvecs, $oArrStdDeviationsIntrinsics, $oArrStdDeviationsExtrinsics, $oArrPerViewErrors, $flags, $criteria)

    If $bPerViewErrorsIsArray Then
        Call("_VectorOf" & $typeOfPerViewErrors & "Release", $vectorPerViewErrors)
    EndIf

    If $typeOfPerViewErrors <> Default Then
        _cveOutputArrayRelease($oArrPerViewErrors)
        If $bPerViewErrorsCreate Then
            Call("_cve" & $typeOfPerViewErrors & "Release", $perViewErrors)
        EndIf
    EndIf

    If $bStdDeviationsExtrinsicsIsArray Then
        Call("_VectorOf" & $typeOfStdDeviationsExtrinsics & "Release", $vectorStdDeviationsExtrinsics)
    EndIf

    If $typeOfStdDeviationsExtrinsics <> Default Then
        _cveOutputArrayRelease($oArrStdDeviationsExtrinsics)
        If $bStdDeviationsExtrinsicsCreate Then
            Call("_cve" & $typeOfStdDeviationsExtrinsics & "Release", $stdDeviationsExtrinsics)
        EndIf
    EndIf

    If $bStdDeviationsIntrinsicsIsArray Then
        Call("_VectorOf" & $typeOfStdDeviationsIntrinsics & "Release", $vectorStdDeviationsIntrinsics)
    EndIf

    If $typeOfStdDeviationsIntrinsics <> Default Then
        _cveOutputArrayRelease($oArrStdDeviationsIntrinsics)
        If $bStdDeviationsIntrinsicsCreate Then
            Call("_cve" & $typeOfStdDeviationsIntrinsics & "Release", $stdDeviationsIntrinsics)
        EndIf
    EndIf

    If $bTvecsIsArray Then
        Call("_VectorOf" & $typeOfTvecs & "Release", $vectorTvecs)
    EndIf

    If $typeOfTvecs <> Default Then
        _cveOutputArrayRelease($oArrTvecs)
        If $bTvecsCreate Then
            Call("_cve" & $typeOfTvecs & "Release", $tvecs)
        EndIf
    EndIf

    If $bRvecsIsArray Then
        Call("_VectorOf" & $typeOfRvecs & "Release", $vectorRvecs)
    EndIf

    If $typeOfRvecs <> Default Then
        _cveOutputArrayRelease($oArrRvecs)
        If $bRvecsCreate Then
            Call("_cve" & $typeOfRvecs & "Release", $rvecs)
        EndIf
    EndIf

    If $bDistCoeffsIsArray Then
        Call("_VectorOf" & $typeOfDistCoeffs & "Release", $vectorDistCoeffs)
    EndIf

    If $typeOfDistCoeffs <> Default Then
        _cveInputOutputArrayRelease($ioArrDistCoeffs)
        If $bDistCoeffsCreate Then
            Call("_cve" & $typeOfDistCoeffs & "Release", $distCoeffs)
        EndIf
    EndIf

    If $bCameraMatrixIsArray Then
        Call("_VectorOf" & $typeOfCameraMatrix & "Release", $vectorCameraMatrix)
    EndIf

    If $typeOfCameraMatrix <> Default Then
        _cveInputOutputArrayRelease($ioArrCameraMatrix)
        If $bCameraMatrixCreate Then
            Call("_cve" & $typeOfCameraMatrix & "Release", $cameraMatrix)
        EndIf
    EndIf

    If $bCounterIsArray Then
        Call("_VectorOf" & $typeOfCounter & "Release", $vectorCounter)
    EndIf

    If $typeOfCounter <> Default Then
        _cveInputArrayRelease($iArrCounter)
        If $bCounterCreate Then
            Call("_cve" & $typeOfCounter & "Release", $counter)
        EndIf
    EndIf

    If $bIdsIsArray Then
        Call("_VectorOf" & $typeOfIds & "Release", $vectorIds)
    EndIf

    If $typeOfIds <> Default Then
        _cveInputArrayRelease($iArrIds)
        If $bIdsCreate Then
            Call("_cve" & $typeOfIds & "Release", $ids)
        EndIf
    EndIf

    If $bCornersIsArray Then
        Call("_VectorOf" & $typeOfCorners & "Release", $vectorCorners)
    EndIf

    If $typeOfCorners <> Default Then
        _cveInputArrayRelease($iArrCorners)
        If $bCornersCreate Then
            Call("_cve" & $typeOfCorners & "Release", $corners)
        EndIf
    EndIf

    Return $retval
EndFunc   ;==>_cveArucoCalibrateCameraArucoTyped

Func _cveArucoCalibrateCameraArucoMat($corners, $ids, $counter, $board, $imageSize, $cameraMatrix, $distCoeffs, $rvecs, $tvecs, $stdDeviationsIntrinsics, $stdDeviationsExtrinsics, $perViewErrors, $flags, $criteria)
    ; cveArucoCalibrateCameraAruco using cv::Mat instead of _*Array
    Local $retval = _cveArucoCalibrateCameraArucoTyped("Mat", $corners, "Mat", $ids, "Mat", $counter, $board, $imageSize, "Mat", $cameraMatrix, "Mat", $distCoeffs, "Mat", $rvecs, "Mat", $tvecs, "Mat", $stdDeviationsIntrinsics, "Mat", $stdDeviationsExtrinsics, "Mat", $perViewErrors, $flags, $criteria)

    Return $retval
EndFunc   ;==>_cveArucoCalibrateCameraArucoMat

Func _cveArucoCalibrateCameraCharuco($charucoCorners, $charucoIds, $board, $imageSize, $cameraMatrix, $distCoeffs, $rvecs, $tvecs, $stdDeviationsIntrinsics, $stdDeviationsExtrinsics, $perViewErrors, $flags, $criteria)
    ; CVAPI(double) cveArucoCalibrateCameraCharuco(cv::_InputArray* charucoCorners, cv::_InputArray* charucoIds, cv::aruco::CharucoBoard* board, CvSize* imageSize, cv::_InputOutputArray* cameraMatrix, cv::_InputOutputArray* distCoeffs, cv::_OutputArray* rvecs, cv::_OutputArray* tvecs, cv::_OutputArray* stdDeviationsIntrinsics, cv::_OutputArray* stdDeviationsExtrinsics, cv::_OutputArray* perViewErrors, int flags, CvTermCriteria* criteria);

    Local $sCharucoCornersDllType
    If IsDllStruct($charucoCorners) Then
        $sCharucoCornersDllType = "struct*"
    Else
        $sCharucoCornersDllType = "ptr"
    EndIf

    Local $sCharucoIdsDllType
    If IsDllStruct($charucoIds) Then
        $sCharucoIdsDllType = "struct*"
    Else
        $sCharucoIdsDllType = "ptr"
    EndIf

    Local $sBoardDllType
    If IsDllStruct($board) Then
        $sBoardDllType = "struct*"
    Else
        $sBoardDllType = "ptr"
    EndIf

    Local $sImageSizeDllType
    If IsDllStruct($imageSize) Then
        $sImageSizeDllType = "struct*"
    Else
        $sImageSizeDllType = "ptr"
    EndIf

    Local $sCameraMatrixDllType
    If IsDllStruct($cameraMatrix) Then
        $sCameraMatrixDllType = "struct*"
    Else
        $sCameraMatrixDllType = "ptr"
    EndIf

    Local $sDistCoeffsDllType
    If IsDllStruct($distCoeffs) Then
        $sDistCoeffsDllType = "struct*"
    Else
        $sDistCoeffsDllType = "ptr"
    EndIf

    Local $sRvecsDllType
    If IsDllStruct($rvecs) Then
        $sRvecsDllType = "struct*"
    Else
        $sRvecsDllType = "ptr"
    EndIf

    Local $sTvecsDllType
    If IsDllStruct($tvecs) Then
        $sTvecsDllType = "struct*"
    Else
        $sTvecsDllType = "ptr"
    EndIf

    Local $sStdDeviationsIntrinsicsDllType
    If IsDllStruct($stdDeviationsIntrinsics) Then
        $sStdDeviationsIntrinsicsDllType = "struct*"
    Else
        $sStdDeviationsIntrinsicsDllType = "ptr"
    EndIf

    Local $sStdDeviationsExtrinsicsDllType
    If IsDllStruct($stdDeviationsExtrinsics) Then
        $sStdDeviationsExtrinsicsDllType = "struct*"
    Else
        $sStdDeviationsExtrinsicsDllType = "ptr"
    EndIf

    Local $sPerViewErrorsDllType
    If IsDllStruct($perViewErrors) Then
        $sPerViewErrorsDllType = "struct*"
    Else
        $sPerViewErrorsDllType = "ptr"
    EndIf

    Local $sCriteriaDllType
    If IsDllStruct($criteria) Then
        $sCriteriaDllType = "struct*"
    Else
        $sCriteriaDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveArucoCalibrateCameraCharuco", $sCharucoCornersDllType, $charucoCorners, $sCharucoIdsDllType, $charucoIds, $sBoardDllType, $board, $sImageSizeDllType, $imageSize, $sCameraMatrixDllType, $cameraMatrix, $sDistCoeffsDllType, $distCoeffs, $sRvecsDllType, $rvecs, $sTvecsDllType, $tvecs, $sStdDeviationsIntrinsicsDllType, $stdDeviationsIntrinsics, $sStdDeviationsExtrinsicsDllType, $stdDeviationsExtrinsics, $sPerViewErrorsDllType, $perViewErrors, "int", $flags, $sCriteriaDllType, $criteria), "cveArucoCalibrateCameraCharuco", @error)
EndFunc   ;==>_cveArucoCalibrateCameraCharuco

Func _cveArucoCalibrateCameraCharucoTyped($typeOfCharucoCorners, $charucoCorners, $typeOfCharucoIds, $charucoIds, $board, $imageSize, $typeOfCameraMatrix, $cameraMatrix, $typeOfDistCoeffs, $distCoeffs, $typeOfRvecs, $rvecs, $typeOfTvecs, $tvecs, $typeOfStdDeviationsIntrinsics, $stdDeviationsIntrinsics, $typeOfStdDeviationsExtrinsics, $stdDeviationsExtrinsics, $typeOfPerViewErrors, $perViewErrors, $flags, $criteria)

    Local $iArrCharucoCorners, $vectorCharucoCorners, $iArrCharucoCornersSize
    Local $bCharucoCornersIsArray = IsArray($charucoCorners)
    Local $bCharucoCornersCreate = IsDllStruct($charucoCorners) And $typeOfCharucoCorners == "Scalar"

    If $typeOfCharucoCorners == Default Then
        $iArrCharucoCorners = $charucoCorners
    ElseIf $bCharucoCornersIsArray Then
        $vectorCharucoCorners = Call("_VectorOf" & $typeOfCharucoCorners & "Create")

        $iArrCharucoCornersSize = UBound($charucoCorners)
        For $i = 0 To $iArrCharucoCornersSize - 1
            Call("_VectorOf" & $typeOfCharucoCorners & "Push", $vectorCharucoCorners, $charucoCorners[$i])
        Next

        $iArrCharucoCorners = Call("_cveInputArrayFromVectorOf" & $typeOfCharucoCorners, $vectorCharucoCorners)
    Else
        If $bCharucoCornersCreate Then
            $charucoCorners = Call("_cve" & $typeOfCharucoCorners & "Create", $charucoCorners)
        EndIf
        $iArrCharucoCorners = Call("_cveInputArrayFrom" & $typeOfCharucoCorners, $charucoCorners)
    EndIf

    Local $iArrCharucoIds, $vectorCharucoIds, $iArrCharucoIdsSize
    Local $bCharucoIdsIsArray = IsArray($charucoIds)
    Local $bCharucoIdsCreate = IsDllStruct($charucoIds) And $typeOfCharucoIds == "Scalar"

    If $typeOfCharucoIds == Default Then
        $iArrCharucoIds = $charucoIds
    ElseIf $bCharucoIdsIsArray Then
        $vectorCharucoIds = Call("_VectorOf" & $typeOfCharucoIds & "Create")

        $iArrCharucoIdsSize = UBound($charucoIds)
        For $i = 0 To $iArrCharucoIdsSize - 1
            Call("_VectorOf" & $typeOfCharucoIds & "Push", $vectorCharucoIds, $charucoIds[$i])
        Next

        $iArrCharucoIds = Call("_cveInputArrayFromVectorOf" & $typeOfCharucoIds, $vectorCharucoIds)
    Else
        If $bCharucoIdsCreate Then
            $charucoIds = Call("_cve" & $typeOfCharucoIds & "Create", $charucoIds)
        EndIf
        $iArrCharucoIds = Call("_cveInputArrayFrom" & $typeOfCharucoIds, $charucoIds)
    EndIf

    Local $ioArrCameraMatrix, $vectorCameraMatrix, $iArrCameraMatrixSize
    Local $bCameraMatrixIsArray = IsArray($cameraMatrix)
    Local $bCameraMatrixCreate = IsDllStruct($cameraMatrix) And $typeOfCameraMatrix == "Scalar"

    If $typeOfCameraMatrix == Default Then
        $ioArrCameraMatrix = $cameraMatrix
    ElseIf $bCameraMatrixIsArray Then
        $vectorCameraMatrix = Call("_VectorOf" & $typeOfCameraMatrix & "Create")

        $iArrCameraMatrixSize = UBound($cameraMatrix)
        For $i = 0 To $iArrCameraMatrixSize - 1
            Call("_VectorOf" & $typeOfCameraMatrix & "Push", $vectorCameraMatrix, $cameraMatrix[$i])
        Next

        $ioArrCameraMatrix = Call("_cveInputOutputArrayFromVectorOf" & $typeOfCameraMatrix, $vectorCameraMatrix)
    Else
        If $bCameraMatrixCreate Then
            $cameraMatrix = Call("_cve" & $typeOfCameraMatrix & "Create", $cameraMatrix)
        EndIf
        $ioArrCameraMatrix = Call("_cveInputOutputArrayFrom" & $typeOfCameraMatrix, $cameraMatrix)
    EndIf

    Local $ioArrDistCoeffs, $vectorDistCoeffs, $iArrDistCoeffsSize
    Local $bDistCoeffsIsArray = IsArray($distCoeffs)
    Local $bDistCoeffsCreate = IsDllStruct($distCoeffs) And $typeOfDistCoeffs == "Scalar"

    If $typeOfDistCoeffs == Default Then
        $ioArrDistCoeffs = $distCoeffs
    ElseIf $bDistCoeffsIsArray Then
        $vectorDistCoeffs = Call("_VectorOf" & $typeOfDistCoeffs & "Create")

        $iArrDistCoeffsSize = UBound($distCoeffs)
        For $i = 0 To $iArrDistCoeffsSize - 1
            Call("_VectorOf" & $typeOfDistCoeffs & "Push", $vectorDistCoeffs, $distCoeffs[$i])
        Next

        $ioArrDistCoeffs = Call("_cveInputOutputArrayFromVectorOf" & $typeOfDistCoeffs, $vectorDistCoeffs)
    Else
        If $bDistCoeffsCreate Then
            $distCoeffs = Call("_cve" & $typeOfDistCoeffs & "Create", $distCoeffs)
        EndIf
        $ioArrDistCoeffs = Call("_cveInputOutputArrayFrom" & $typeOfDistCoeffs, $distCoeffs)
    EndIf

    Local $oArrRvecs, $vectorRvecs, $iArrRvecsSize
    Local $bRvecsIsArray = IsArray($rvecs)
    Local $bRvecsCreate = IsDllStruct($rvecs) And $typeOfRvecs == "Scalar"

    If $typeOfRvecs == Default Then
        $oArrRvecs = $rvecs
    ElseIf $bRvecsIsArray Then
        $vectorRvecs = Call("_VectorOf" & $typeOfRvecs & "Create")

        $iArrRvecsSize = UBound($rvecs)
        For $i = 0 To $iArrRvecsSize - 1
            Call("_VectorOf" & $typeOfRvecs & "Push", $vectorRvecs, $rvecs[$i])
        Next

        $oArrRvecs = Call("_cveOutputArrayFromVectorOf" & $typeOfRvecs, $vectorRvecs)
    Else
        If $bRvecsCreate Then
            $rvecs = Call("_cve" & $typeOfRvecs & "Create", $rvecs)
        EndIf
        $oArrRvecs = Call("_cveOutputArrayFrom" & $typeOfRvecs, $rvecs)
    EndIf

    Local $oArrTvecs, $vectorTvecs, $iArrTvecsSize
    Local $bTvecsIsArray = IsArray($tvecs)
    Local $bTvecsCreate = IsDllStruct($tvecs) And $typeOfTvecs == "Scalar"

    If $typeOfTvecs == Default Then
        $oArrTvecs = $tvecs
    ElseIf $bTvecsIsArray Then
        $vectorTvecs = Call("_VectorOf" & $typeOfTvecs & "Create")

        $iArrTvecsSize = UBound($tvecs)
        For $i = 0 To $iArrTvecsSize - 1
            Call("_VectorOf" & $typeOfTvecs & "Push", $vectorTvecs, $tvecs[$i])
        Next

        $oArrTvecs = Call("_cveOutputArrayFromVectorOf" & $typeOfTvecs, $vectorTvecs)
    Else
        If $bTvecsCreate Then
            $tvecs = Call("_cve" & $typeOfTvecs & "Create", $tvecs)
        EndIf
        $oArrTvecs = Call("_cveOutputArrayFrom" & $typeOfTvecs, $tvecs)
    EndIf

    Local $oArrStdDeviationsIntrinsics, $vectorStdDeviationsIntrinsics, $iArrStdDeviationsIntrinsicsSize
    Local $bStdDeviationsIntrinsicsIsArray = IsArray($stdDeviationsIntrinsics)
    Local $bStdDeviationsIntrinsicsCreate = IsDllStruct($stdDeviationsIntrinsics) And $typeOfStdDeviationsIntrinsics == "Scalar"

    If $typeOfStdDeviationsIntrinsics == Default Then
        $oArrStdDeviationsIntrinsics = $stdDeviationsIntrinsics
    ElseIf $bStdDeviationsIntrinsicsIsArray Then
        $vectorStdDeviationsIntrinsics = Call("_VectorOf" & $typeOfStdDeviationsIntrinsics & "Create")

        $iArrStdDeviationsIntrinsicsSize = UBound($stdDeviationsIntrinsics)
        For $i = 0 To $iArrStdDeviationsIntrinsicsSize - 1
            Call("_VectorOf" & $typeOfStdDeviationsIntrinsics & "Push", $vectorStdDeviationsIntrinsics, $stdDeviationsIntrinsics[$i])
        Next

        $oArrStdDeviationsIntrinsics = Call("_cveOutputArrayFromVectorOf" & $typeOfStdDeviationsIntrinsics, $vectorStdDeviationsIntrinsics)
    Else
        If $bStdDeviationsIntrinsicsCreate Then
            $stdDeviationsIntrinsics = Call("_cve" & $typeOfStdDeviationsIntrinsics & "Create", $stdDeviationsIntrinsics)
        EndIf
        $oArrStdDeviationsIntrinsics = Call("_cveOutputArrayFrom" & $typeOfStdDeviationsIntrinsics, $stdDeviationsIntrinsics)
    EndIf

    Local $oArrStdDeviationsExtrinsics, $vectorStdDeviationsExtrinsics, $iArrStdDeviationsExtrinsicsSize
    Local $bStdDeviationsExtrinsicsIsArray = IsArray($stdDeviationsExtrinsics)
    Local $bStdDeviationsExtrinsicsCreate = IsDllStruct($stdDeviationsExtrinsics) And $typeOfStdDeviationsExtrinsics == "Scalar"

    If $typeOfStdDeviationsExtrinsics == Default Then
        $oArrStdDeviationsExtrinsics = $stdDeviationsExtrinsics
    ElseIf $bStdDeviationsExtrinsicsIsArray Then
        $vectorStdDeviationsExtrinsics = Call("_VectorOf" & $typeOfStdDeviationsExtrinsics & "Create")

        $iArrStdDeviationsExtrinsicsSize = UBound($stdDeviationsExtrinsics)
        For $i = 0 To $iArrStdDeviationsExtrinsicsSize - 1
            Call("_VectorOf" & $typeOfStdDeviationsExtrinsics & "Push", $vectorStdDeviationsExtrinsics, $stdDeviationsExtrinsics[$i])
        Next

        $oArrStdDeviationsExtrinsics = Call("_cveOutputArrayFromVectorOf" & $typeOfStdDeviationsExtrinsics, $vectorStdDeviationsExtrinsics)
    Else
        If $bStdDeviationsExtrinsicsCreate Then
            $stdDeviationsExtrinsics = Call("_cve" & $typeOfStdDeviationsExtrinsics & "Create", $stdDeviationsExtrinsics)
        EndIf
        $oArrStdDeviationsExtrinsics = Call("_cveOutputArrayFrom" & $typeOfStdDeviationsExtrinsics, $stdDeviationsExtrinsics)
    EndIf

    Local $oArrPerViewErrors, $vectorPerViewErrors, $iArrPerViewErrorsSize
    Local $bPerViewErrorsIsArray = IsArray($perViewErrors)
    Local $bPerViewErrorsCreate = IsDllStruct($perViewErrors) And $typeOfPerViewErrors == "Scalar"

    If $typeOfPerViewErrors == Default Then
        $oArrPerViewErrors = $perViewErrors
    ElseIf $bPerViewErrorsIsArray Then
        $vectorPerViewErrors = Call("_VectorOf" & $typeOfPerViewErrors & "Create")

        $iArrPerViewErrorsSize = UBound($perViewErrors)
        For $i = 0 To $iArrPerViewErrorsSize - 1
            Call("_VectorOf" & $typeOfPerViewErrors & "Push", $vectorPerViewErrors, $perViewErrors[$i])
        Next

        $oArrPerViewErrors = Call("_cveOutputArrayFromVectorOf" & $typeOfPerViewErrors, $vectorPerViewErrors)
    Else
        If $bPerViewErrorsCreate Then
            $perViewErrors = Call("_cve" & $typeOfPerViewErrors & "Create", $perViewErrors)
        EndIf
        $oArrPerViewErrors = Call("_cveOutputArrayFrom" & $typeOfPerViewErrors, $perViewErrors)
    EndIf

    Local $retval = _cveArucoCalibrateCameraCharuco($iArrCharucoCorners, $iArrCharucoIds, $board, $imageSize, $ioArrCameraMatrix, $ioArrDistCoeffs, $oArrRvecs, $oArrTvecs, $oArrStdDeviationsIntrinsics, $oArrStdDeviationsExtrinsics, $oArrPerViewErrors, $flags, $criteria)

    If $bPerViewErrorsIsArray Then
        Call("_VectorOf" & $typeOfPerViewErrors & "Release", $vectorPerViewErrors)
    EndIf

    If $typeOfPerViewErrors <> Default Then
        _cveOutputArrayRelease($oArrPerViewErrors)
        If $bPerViewErrorsCreate Then
            Call("_cve" & $typeOfPerViewErrors & "Release", $perViewErrors)
        EndIf
    EndIf

    If $bStdDeviationsExtrinsicsIsArray Then
        Call("_VectorOf" & $typeOfStdDeviationsExtrinsics & "Release", $vectorStdDeviationsExtrinsics)
    EndIf

    If $typeOfStdDeviationsExtrinsics <> Default Then
        _cveOutputArrayRelease($oArrStdDeviationsExtrinsics)
        If $bStdDeviationsExtrinsicsCreate Then
            Call("_cve" & $typeOfStdDeviationsExtrinsics & "Release", $stdDeviationsExtrinsics)
        EndIf
    EndIf

    If $bStdDeviationsIntrinsicsIsArray Then
        Call("_VectorOf" & $typeOfStdDeviationsIntrinsics & "Release", $vectorStdDeviationsIntrinsics)
    EndIf

    If $typeOfStdDeviationsIntrinsics <> Default Then
        _cveOutputArrayRelease($oArrStdDeviationsIntrinsics)
        If $bStdDeviationsIntrinsicsCreate Then
            Call("_cve" & $typeOfStdDeviationsIntrinsics & "Release", $stdDeviationsIntrinsics)
        EndIf
    EndIf

    If $bTvecsIsArray Then
        Call("_VectorOf" & $typeOfTvecs & "Release", $vectorTvecs)
    EndIf

    If $typeOfTvecs <> Default Then
        _cveOutputArrayRelease($oArrTvecs)
        If $bTvecsCreate Then
            Call("_cve" & $typeOfTvecs & "Release", $tvecs)
        EndIf
    EndIf

    If $bRvecsIsArray Then
        Call("_VectorOf" & $typeOfRvecs & "Release", $vectorRvecs)
    EndIf

    If $typeOfRvecs <> Default Then
        _cveOutputArrayRelease($oArrRvecs)
        If $bRvecsCreate Then
            Call("_cve" & $typeOfRvecs & "Release", $rvecs)
        EndIf
    EndIf

    If $bDistCoeffsIsArray Then
        Call("_VectorOf" & $typeOfDistCoeffs & "Release", $vectorDistCoeffs)
    EndIf

    If $typeOfDistCoeffs <> Default Then
        _cveInputOutputArrayRelease($ioArrDistCoeffs)
        If $bDistCoeffsCreate Then
            Call("_cve" & $typeOfDistCoeffs & "Release", $distCoeffs)
        EndIf
    EndIf

    If $bCameraMatrixIsArray Then
        Call("_VectorOf" & $typeOfCameraMatrix & "Release", $vectorCameraMatrix)
    EndIf

    If $typeOfCameraMatrix <> Default Then
        _cveInputOutputArrayRelease($ioArrCameraMatrix)
        If $bCameraMatrixCreate Then
            Call("_cve" & $typeOfCameraMatrix & "Release", $cameraMatrix)
        EndIf
    EndIf

    If $bCharucoIdsIsArray Then
        Call("_VectorOf" & $typeOfCharucoIds & "Release", $vectorCharucoIds)
    EndIf

    If $typeOfCharucoIds <> Default Then
        _cveInputArrayRelease($iArrCharucoIds)
        If $bCharucoIdsCreate Then
            Call("_cve" & $typeOfCharucoIds & "Release", $charucoIds)
        EndIf
    EndIf

    If $bCharucoCornersIsArray Then
        Call("_VectorOf" & $typeOfCharucoCorners & "Release", $vectorCharucoCorners)
    EndIf

    If $typeOfCharucoCorners <> Default Then
        _cveInputArrayRelease($iArrCharucoCorners)
        If $bCharucoCornersCreate Then
            Call("_cve" & $typeOfCharucoCorners & "Release", $charucoCorners)
        EndIf
    EndIf

    Return $retval
EndFunc   ;==>_cveArucoCalibrateCameraCharucoTyped

Func _cveArucoCalibrateCameraCharucoMat($charucoCorners, $charucoIds, $board, $imageSize, $cameraMatrix, $distCoeffs, $rvecs, $tvecs, $stdDeviationsIntrinsics, $stdDeviationsExtrinsics, $perViewErrors, $flags, $criteria)
    ; cveArucoCalibrateCameraCharuco using cv::Mat instead of _*Array
    Local $retval = _cveArucoCalibrateCameraCharucoTyped("Mat", $charucoCorners, "Mat", $charucoIds, $board, $imageSize, "Mat", $cameraMatrix, "Mat", $distCoeffs, "Mat", $rvecs, "Mat", $tvecs, "Mat", $stdDeviationsIntrinsics, "Mat", $stdDeviationsExtrinsics, "Mat", $perViewErrors, $flags, $criteria)

    Return $retval
EndFunc   ;==>_cveArucoCalibrateCameraCharucoMat

Func _cveArucoDetectorParametersGetDefault($parameters)
    ; CVAPI(void) cveArucoDetectorParametersGetDefault(cv::aruco::DetectorParameters* parameters);

    Local $sParametersDllType
    If IsDllStruct($parameters) Then
        $sParametersDllType = "struct*"
    Else
        $sParametersDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveArucoDetectorParametersGetDefault", $sParametersDllType, $parameters), "cveArucoDetectorParametersGetDefault", @error)
EndFunc   ;==>_cveArucoDetectorParametersGetDefault

Func _cveArucoInterpolateCornersCharuco($markerCorners, $markerIds, $image, $board, $charucoCorners, $charucoIds, $cameraMatrix, $distCoeffs, $minMarkers)
    ; CVAPI(int) cveArucoInterpolateCornersCharuco(cv::_InputArray* markerCorners, cv::_InputArray* markerIds, cv::_InputArray* image, cv::aruco::CharucoBoard* board, cv::_OutputArray* charucoCorners, cv::_OutputArray* charucoIds, cv::_InputArray* cameraMatrix, cv::_InputArray* distCoeffs, int minMarkers);

    Local $sMarkerCornersDllType
    If IsDllStruct($markerCorners) Then
        $sMarkerCornersDllType = "struct*"
    Else
        $sMarkerCornersDllType = "ptr"
    EndIf

    Local $sMarkerIdsDllType
    If IsDllStruct($markerIds) Then
        $sMarkerIdsDllType = "struct*"
    Else
        $sMarkerIdsDllType = "ptr"
    EndIf

    Local $sImageDllType
    If IsDllStruct($image) Then
        $sImageDllType = "struct*"
    Else
        $sImageDllType = "ptr"
    EndIf

    Local $sBoardDllType
    If IsDllStruct($board) Then
        $sBoardDllType = "struct*"
    Else
        $sBoardDllType = "ptr"
    EndIf

    Local $sCharucoCornersDllType
    If IsDllStruct($charucoCorners) Then
        $sCharucoCornersDllType = "struct*"
    Else
        $sCharucoCornersDllType = "ptr"
    EndIf

    Local $sCharucoIdsDllType
    If IsDllStruct($charucoIds) Then
        $sCharucoIdsDllType = "struct*"
    Else
        $sCharucoIdsDllType = "ptr"
    EndIf

    Local $sCameraMatrixDllType
    If IsDllStruct($cameraMatrix) Then
        $sCameraMatrixDllType = "struct*"
    Else
        $sCameraMatrixDllType = "ptr"
    EndIf

    Local $sDistCoeffsDllType
    If IsDllStruct($distCoeffs) Then
        $sDistCoeffsDllType = "struct*"
    Else
        $sDistCoeffsDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveArucoInterpolateCornersCharuco", $sMarkerCornersDllType, $markerCorners, $sMarkerIdsDllType, $markerIds, $sImageDllType, $image, $sBoardDllType, $board, $sCharucoCornersDllType, $charucoCorners, $sCharucoIdsDllType, $charucoIds, $sCameraMatrixDllType, $cameraMatrix, $sDistCoeffsDllType, $distCoeffs, "int", $minMarkers), "cveArucoInterpolateCornersCharuco", @error)
EndFunc   ;==>_cveArucoInterpolateCornersCharuco

Func _cveArucoInterpolateCornersCharucoTyped($typeOfMarkerCorners, $markerCorners, $typeOfMarkerIds, $markerIds, $typeOfImage, $image, $board, $typeOfCharucoCorners, $charucoCorners, $typeOfCharucoIds, $charucoIds, $typeOfCameraMatrix, $cameraMatrix, $typeOfDistCoeffs, $distCoeffs, $minMarkers)

    Local $iArrMarkerCorners, $vectorMarkerCorners, $iArrMarkerCornersSize
    Local $bMarkerCornersIsArray = IsArray($markerCorners)
    Local $bMarkerCornersCreate = IsDllStruct($markerCorners) And $typeOfMarkerCorners == "Scalar"

    If $typeOfMarkerCorners == Default Then
        $iArrMarkerCorners = $markerCorners
    ElseIf $bMarkerCornersIsArray Then
        $vectorMarkerCorners = Call("_VectorOf" & $typeOfMarkerCorners & "Create")

        $iArrMarkerCornersSize = UBound($markerCorners)
        For $i = 0 To $iArrMarkerCornersSize - 1
            Call("_VectorOf" & $typeOfMarkerCorners & "Push", $vectorMarkerCorners, $markerCorners[$i])
        Next

        $iArrMarkerCorners = Call("_cveInputArrayFromVectorOf" & $typeOfMarkerCorners, $vectorMarkerCorners)
    Else
        If $bMarkerCornersCreate Then
            $markerCorners = Call("_cve" & $typeOfMarkerCorners & "Create", $markerCorners)
        EndIf
        $iArrMarkerCorners = Call("_cveInputArrayFrom" & $typeOfMarkerCorners, $markerCorners)
    EndIf

    Local $iArrMarkerIds, $vectorMarkerIds, $iArrMarkerIdsSize
    Local $bMarkerIdsIsArray = IsArray($markerIds)
    Local $bMarkerIdsCreate = IsDllStruct($markerIds) And $typeOfMarkerIds == "Scalar"

    If $typeOfMarkerIds == Default Then
        $iArrMarkerIds = $markerIds
    ElseIf $bMarkerIdsIsArray Then
        $vectorMarkerIds = Call("_VectorOf" & $typeOfMarkerIds & "Create")

        $iArrMarkerIdsSize = UBound($markerIds)
        For $i = 0 To $iArrMarkerIdsSize - 1
            Call("_VectorOf" & $typeOfMarkerIds & "Push", $vectorMarkerIds, $markerIds[$i])
        Next

        $iArrMarkerIds = Call("_cveInputArrayFromVectorOf" & $typeOfMarkerIds, $vectorMarkerIds)
    Else
        If $bMarkerIdsCreate Then
            $markerIds = Call("_cve" & $typeOfMarkerIds & "Create", $markerIds)
        EndIf
        $iArrMarkerIds = Call("_cveInputArrayFrom" & $typeOfMarkerIds, $markerIds)
    EndIf

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

    Local $oArrCharucoCorners, $vectorCharucoCorners, $iArrCharucoCornersSize
    Local $bCharucoCornersIsArray = IsArray($charucoCorners)
    Local $bCharucoCornersCreate = IsDllStruct($charucoCorners) And $typeOfCharucoCorners == "Scalar"

    If $typeOfCharucoCorners == Default Then
        $oArrCharucoCorners = $charucoCorners
    ElseIf $bCharucoCornersIsArray Then
        $vectorCharucoCorners = Call("_VectorOf" & $typeOfCharucoCorners & "Create")

        $iArrCharucoCornersSize = UBound($charucoCorners)
        For $i = 0 To $iArrCharucoCornersSize - 1
            Call("_VectorOf" & $typeOfCharucoCorners & "Push", $vectorCharucoCorners, $charucoCorners[$i])
        Next

        $oArrCharucoCorners = Call("_cveOutputArrayFromVectorOf" & $typeOfCharucoCorners, $vectorCharucoCorners)
    Else
        If $bCharucoCornersCreate Then
            $charucoCorners = Call("_cve" & $typeOfCharucoCorners & "Create", $charucoCorners)
        EndIf
        $oArrCharucoCorners = Call("_cveOutputArrayFrom" & $typeOfCharucoCorners, $charucoCorners)
    EndIf

    Local $oArrCharucoIds, $vectorCharucoIds, $iArrCharucoIdsSize
    Local $bCharucoIdsIsArray = IsArray($charucoIds)
    Local $bCharucoIdsCreate = IsDllStruct($charucoIds) And $typeOfCharucoIds == "Scalar"

    If $typeOfCharucoIds == Default Then
        $oArrCharucoIds = $charucoIds
    ElseIf $bCharucoIdsIsArray Then
        $vectorCharucoIds = Call("_VectorOf" & $typeOfCharucoIds & "Create")

        $iArrCharucoIdsSize = UBound($charucoIds)
        For $i = 0 To $iArrCharucoIdsSize - 1
            Call("_VectorOf" & $typeOfCharucoIds & "Push", $vectorCharucoIds, $charucoIds[$i])
        Next

        $oArrCharucoIds = Call("_cveOutputArrayFromVectorOf" & $typeOfCharucoIds, $vectorCharucoIds)
    Else
        If $bCharucoIdsCreate Then
            $charucoIds = Call("_cve" & $typeOfCharucoIds & "Create", $charucoIds)
        EndIf
        $oArrCharucoIds = Call("_cveOutputArrayFrom" & $typeOfCharucoIds, $charucoIds)
    EndIf

    Local $iArrCameraMatrix, $vectorCameraMatrix, $iArrCameraMatrixSize
    Local $bCameraMatrixIsArray = IsArray($cameraMatrix)
    Local $bCameraMatrixCreate = IsDllStruct($cameraMatrix) And $typeOfCameraMatrix == "Scalar"

    If $typeOfCameraMatrix == Default Then
        $iArrCameraMatrix = $cameraMatrix
    ElseIf $bCameraMatrixIsArray Then
        $vectorCameraMatrix = Call("_VectorOf" & $typeOfCameraMatrix & "Create")

        $iArrCameraMatrixSize = UBound($cameraMatrix)
        For $i = 0 To $iArrCameraMatrixSize - 1
            Call("_VectorOf" & $typeOfCameraMatrix & "Push", $vectorCameraMatrix, $cameraMatrix[$i])
        Next

        $iArrCameraMatrix = Call("_cveInputArrayFromVectorOf" & $typeOfCameraMatrix, $vectorCameraMatrix)
    Else
        If $bCameraMatrixCreate Then
            $cameraMatrix = Call("_cve" & $typeOfCameraMatrix & "Create", $cameraMatrix)
        EndIf
        $iArrCameraMatrix = Call("_cveInputArrayFrom" & $typeOfCameraMatrix, $cameraMatrix)
    EndIf

    Local $iArrDistCoeffs, $vectorDistCoeffs, $iArrDistCoeffsSize
    Local $bDistCoeffsIsArray = IsArray($distCoeffs)
    Local $bDistCoeffsCreate = IsDllStruct($distCoeffs) And $typeOfDistCoeffs == "Scalar"

    If $typeOfDistCoeffs == Default Then
        $iArrDistCoeffs = $distCoeffs
    ElseIf $bDistCoeffsIsArray Then
        $vectorDistCoeffs = Call("_VectorOf" & $typeOfDistCoeffs & "Create")

        $iArrDistCoeffsSize = UBound($distCoeffs)
        For $i = 0 To $iArrDistCoeffsSize - 1
            Call("_VectorOf" & $typeOfDistCoeffs & "Push", $vectorDistCoeffs, $distCoeffs[$i])
        Next

        $iArrDistCoeffs = Call("_cveInputArrayFromVectorOf" & $typeOfDistCoeffs, $vectorDistCoeffs)
    Else
        If $bDistCoeffsCreate Then
            $distCoeffs = Call("_cve" & $typeOfDistCoeffs & "Create", $distCoeffs)
        EndIf
        $iArrDistCoeffs = Call("_cveInputArrayFrom" & $typeOfDistCoeffs, $distCoeffs)
    EndIf

    Local $retval = _cveArucoInterpolateCornersCharuco($iArrMarkerCorners, $iArrMarkerIds, $iArrImage, $board, $oArrCharucoCorners, $oArrCharucoIds, $iArrCameraMatrix, $iArrDistCoeffs, $minMarkers)

    If $bDistCoeffsIsArray Then
        Call("_VectorOf" & $typeOfDistCoeffs & "Release", $vectorDistCoeffs)
    EndIf

    If $typeOfDistCoeffs <> Default Then
        _cveInputArrayRelease($iArrDistCoeffs)
        If $bDistCoeffsCreate Then
            Call("_cve" & $typeOfDistCoeffs & "Release", $distCoeffs)
        EndIf
    EndIf

    If $bCameraMatrixIsArray Then
        Call("_VectorOf" & $typeOfCameraMatrix & "Release", $vectorCameraMatrix)
    EndIf

    If $typeOfCameraMatrix <> Default Then
        _cveInputArrayRelease($iArrCameraMatrix)
        If $bCameraMatrixCreate Then
            Call("_cve" & $typeOfCameraMatrix & "Release", $cameraMatrix)
        EndIf
    EndIf

    If $bCharucoIdsIsArray Then
        Call("_VectorOf" & $typeOfCharucoIds & "Release", $vectorCharucoIds)
    EndIf

    If $typeOfCharucoIds <> Default Then
        _cveOutputArrayRelease($oArrCharucoIds)
        If $bCharucoIdsCreate Then
            Call("_cve" & $typeOfCharucoIds & "Release", $charucoIds)
        EndIf
    EndIf

    If $bCharucoCornersIsArray Then
        Call("_VectorOf" & $typeOfCharucoCorners & "Release", $vectorCharucoCorners)
    EndIf

    If $typeOfCharucoCorners <> Default Then
        _cveOutputArrayRelease($oArrCharucoCorners)
        If $bCharucoCornersCreate Then
            Call("_cve" & $typeOfCharucoCorners & "Release", $charucoCorners)
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

    If $bMarkerIdsIsArray Then
        Call("_VectorOf" & $typeOfMarkerIds & "Release", $vectorMarkerIds)
    EndIf

    If $typeOfMarkerIds <> Default Then
        _cveInputArrayRelease($iArrMarkerIds)
        If $bMarkerIdsCreate Then
            Call("_cve" & $typeOfMarkerIds & "Release", $markerIds)
        EndIf
    EndIf

    If $bMarkerCornersIsArray Then
        Call("_VectorOf" & $typeOfMarkerCorners & "Release", $vectorMarkerCorners)
    EndIf

    If $typeOfMarkerCorners <> Default Then
        _cveInputArrayRelease($iArrMarkerCorners)
        If $bMarkerCornersCreate Then
            Call("_cve" & $typeOfMarkerCorners & "Release", $markerCorners)
        EndIf
    EndIf

    Return $retval
EndFunc   ;==>_cveArucoInterpolateCornersCharucoTyped

Func _cveArucoInterpolateCornersCharucoMat($markerCorners, $markerIds, $image, $board, $charucoCorners, $charucoIds, $cameraMatrix, $distCoeffs, $minMarkers)
    ; cveArucoInterpolateCornersCharuco using cv::Mat instead of _*Array
    Local $retval = _cveArucoInterpolateCornersCharucoTyped("Mat", $markerCorners, "Mat", $markerIds, "Mat", $image, $board, "Mat", $charucoCorners, "Mat", $charucoIds, "Mat", $cameraMatrix, "Mat", $distCoeffs, $minMarkers)

    Return $retval
EndFunc   ;==>_cveArucoInterpolateCornersCharucoMat

Func _cveArucoDrawDetectedCornersCharuco($image, $charucoCorners, $charucoIds, $cornerColor)
    ; CVAPI(void) cveArucoDrawDetectedCornersCharuco(cv::_InputOutputArray* image, cv::_InputArray* charucoCorners, cv::_InputArray* charucoIds, CvScalar* cornerColor);

    Local $sImageDllType
    If IsDllStruct($image) Then
        $sImageDllType = "struct*"
    Else
        $sImageDllType = "ptr"
    EndIf

    Local $sCharucoCornersDllType
    If IsDllStruct($charucoCorners) Then
        $sCharucoCornersDllType = "struct*"
    Else
        $sCharucoCornersDllType = "ptr"
    EndIf

    Local $sCharucoIdsDllType
    If IsDllStruct($charucoIds) Then
        $sCharucoIdsDllType = "struct*"
    Else
        $sCharucoIdsDllType = "ptr"
    EndIf

    Local $sCornerColorDllType
    If IsDllStruct($cornerColor) Then
        $sCornerColorDllType = "struct*"
    Else
        $sCornerColorDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveArucoDrawDetectedCornersCharuco", $sImageDllType, $image, $sCharucoCornersDllType, $charucoCorners, $sCharucoIdsDllType, $charucoIds, $sCornerColorDllType, $cornerColor), "cveArucoDrawDetectedCornersCharuco", @error)
EndFunc   ;==>_cveArucoDrawDetectedCornersCharuco

Func _cveArucoDrawDetectedCornersCharucoTyped($typeOfImage, $image, $typeOfCharucoCorners, $charucoCorners, $typeOfCharucoIds, $charucoIds, $cornerColor)

    Local $ioArrImage, $vectorImage, $iArrImageSize
    Local $bImageIsArray = IsArray($image)
    Local $bImageCreate = IsDllStruct($image) And $typeOfImage == "Scalar"

    If $typeOfImage == Default Then
        $ioArrImage = $image
    ElseIf $bImageIsArray Then
        $vectorImage = Call("_VectorOf" & $typeOfImage & "Create")

        $iArrImageSize = UBound($image)
        For $i = 0 To $iArrImageSize - 1
            Call("_VectorOf" & $typeOfImage & "Push", $vectorImage, $image[$i])
        Next

        $ioArrImage = Call("_cveInputOutputArrayFromVectorOf" & $typeOfImage, $vectorImage)
    Else
        If $bImageCreate Then
            $image = Call("_cve" & $typeOfImage & "Create", $image)
        EndIf
        $ioArrImage = Call("_cveInputOutputArrayFrom" & $typeOfImage, $image)
    EndIf

    Local $iArrCharucoCorners, $vectorCharucoCorners, $iArrCharucoCornersSize
    Local $bCharucoCornersIsArray = IsArray($charucoCorners)
    Local $bCharucoCornersCreate = IsDllStruct($charucoCorners) And $typeOfCharucoCorners == "Scalar"

    If $typeOfCharucoCorners == Default Then
        $iArrCharucoCorners = $charucoCorners
    ElseIf $bCharucoCornersIsArray Then
        $vectorCharucoCorners = Call("_VectorOf" & $typeOfCharucoCorners & "Create")

        $iArrCharucoCornersSize = UBound($charucoCorners)
        For $i = 0 To $iArrCharucoCornersSize - 1
            Call("_VectorOf" & $typeOfCharucoCorners & "Push", $vectorCharucoCorners, $charucoCorners[$i])
        Next

        $iArrCharucoCorners = Call("_cveInputArrayFromVectorOf" & $typeOfCharucoCorners, $vectorCharucoCorners)
    Else
        If $bCharucoCornersCreate Then
            $charucoCorners = Call("_cve" & $typeOfCharucoCorners & "Create", $charucoCorners)
        EndIf
        $iArrCharucoCorners = Call("_cveInputArrayFrom" & $typeOfCharucoCorners, $charucoCorners)
    EndIf

    Local $iArrCharucoIds, $vectorCharucoIds, $iArrCharucoIdsSize
    Local $bCharucoIdsIsArray = IsArray($charucoIds)
    Local $bCharucoIdsCreate = IsDllStruct($charucoIds) And $typeOfCharucoIds == "Scalar"

    If $typeOfCharucoIds == Default Then
        $iArrCharucoIds = $charucoIds
    ElseIf $bCharucoIdsIsArray Then
        $vectorCharucoIds = Call("_VectorOf" & $typeOfCharucoIds & "Create")

        $iArrCharucoIdsSize = UBound($charucoIds)
        For $i = 0 To $iArrCharucoIdsSize - 1
            Call("_VectorOf" & $typeOfCharucoIds & "Push", $vectorCharucoIds, $charucoIds[$i])
        Next

        $iArrCharucoIds = Call("_cveInputArrayFromVectorOf" & $typeOfCharucoIds, $vectorCharucoIds)
    Else
        If $bCharucoIdsCreate Then
            $charucoIds = Call("_cve" & $typeOfCharucoIds & "Create", $charucoIds)
        EndIf
        $iArrCharucoIds = Call("_cveInputArrayFrom" & $typeOfCharucoIds, $charucoIds)
    EndIf

    _cveArucoDrawDetectedCornersCharuco($ioArrImage, $iArrCharucoCorners, $iArrCharucoIds, $cornerColor)

    If $bCharucoIdsIsArray Then
        Call("_VectorOf" & $typeOfCharucoIds & "Release", $vectorCharucoIds)
    EndIf

    If $typeOfCharucoIds <> Default Then
        _cveInputArrayRelease($iArrCharucoIds)
        If $bCharucoIdsCreate Then
            Call("_cve" & $typeOfCharucoIds & "Release", $charucoIds)
        EndIf
    EndIf

    If $bCharucoCornersIsArray Then
        Call("_VectorOf" & $typeOfCharucoCorners & "Release", $vectorCharucoCorners)
    EndIf

    If $typeOfCharucoCorners <> Default Then
        _cveInputArrayRelease($iArrCharucoCorners)
        If $bCharucoCornersCreate Then
            Call("_cve" & $typeOfCharucoCorners & "Release", $charucoCorners)
        EndIf
    EndIf

    If $bImageIsArray Then
        Call("_VectorOf" & $typeOfImage & "Release", $vectorImage)
    EndIf

    If $typeOfImage <> Default Then
        _cveInputOutputArrayRelease($ioArrImage)
        If $bImageCreate Then
            Call("_cve" & $typeOfImage & "Release", $image)
        EndIf
    EndIf
EndFunc   ;==>_cveArucoDrawDetectedCornersCharucoTyped

Func _cveArucoDrawDetectedCornersCharucoMat($image, $charucoCorners, $charucoIds, $cornerColor)
    ; cveArucoDrawDetectedCornersCharuco using cv::Mat instead of _*Array
    _cveArucoDrawDetectedCornersCharucoTyped("Mat", $image, "Mat", $charucoCorners, "Mat", $charucoIds, $cornerColor)
EndFunc   ;==>_cveArucoDrawDetectedCornersCharucoMat

Func _cveArucoEstimatePoseCharucoBoard($charucoCorners, $charucoIds, $board, $cameraMatrix, $distCoeffs, $rvec, $tvec, $useExtrinsicGuess)
    ; CVAPI(bool) cveArucoEstimatePoseCharucoBoard(cv::_InputArray* charucoCorners, cv::_InputArray* charucoIds, cv::aruco::CharucoBoard* board, cv::_InputArray* cameraMatrix, cv::_InputArray* distCoeffs, cv::_InputOutputArray* rvec, cv::_InputOutputArray* tvec, bool useExtrinsicGuess);

    Local $sCharucoCornersDllType
    If IsDllStruct($charucoCorners) Then
        $sCharucoCornersDllType = "struct*"
    Else
        $sCharucoCornersDllType = "ptr"
    EndIf

    Local $sCharucoIdsDllType
    If IsDllStruct($charucoIds) Then
        $sCharucoIdsDllType = "struct*"
    Else
        $sCharucoIdsDllType = "ptr"
    EndIf

    Local $sBoardDllType
    If IsDllStruct($board) Then
        $sBoardDllType = "struct*"
    Else
        $sBoardDllType = "ptr"
    EndIf

    Local $sCameraMatrixDllType
    If IsDllStruct($cameraMatrix) Then
        $sCameraMatrixDllType = "struct*"
    Else
        $sCameraMatrixDllType = "ptr"
    EndIf

    Local $sDistCoeffsDllType
    If IsDllStruct($distCoeffs) Then
        $sDistCoeffsDllType = "struct*"
    Else
        $sDistCoeffsDllType = "ptr"
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
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveArucoEstimatePoseCharucoBoard", $sCharucoCornersDllType, $charucoCorners, $sCharucoIdsDllType, $charucoIds, $sBoardDllType, $board, $sCameraMatrixDllType, $cameraMatrix, $sDistCoeffsDllType, $distCoeffs, $sRvecDllType, $rvec, $sTvecDllType, $tvec, "boolean", $useExtrinsicGuess), "cveArucoEstimatePoseCharucoBoard", @error)
EndFunc   ;==>_cveArucoEstimatePoseCharucoBoard

Func _cveArucoEstimatePoseCharucoBoardTyped($typeOfCharucoCorners, $charucoCorners, $typeOfCharucoIds, $charucoIds, $board, $typeOfCameraMatrix, $cameraMatrix, $typeOfDistCoeffs, $distCoeffs, $typeOfRvec, $rvec, $typeOfTvec, $tvec, $useExtrinsicGuess)

    Local $iArrCharucoCorners, $vectorCharucoCorners, $iArrCharucoCornersSize
    Local $bCharucoCornersIsArray = IsArray($charucoCorners)
    Local $bCharucoCornersCreate = IsDllStruct($charucoCorners) And $typeOfCharucoCorners == "Scalar"

    If $typeOfCharucoCorners == Default Then
        $iArrCharucoCorners = $charucoCorners
    ElseIf $bCharucoCornersIsArray Then
        $vectorCharucoCorners = Call("_VectorOf" & $typeOfCharucoCorners & "Create")

        $iArrCharucoCornersSize = UBound($charucoCorners)
        For $i = 0 To $iArrCharucoCornersSize - 1
            Call("_VectorOf" & $typeOfCharucoCorners & "Push", $vectorCharucoCorners, $charucoCorners[$i])
        Next

        $iArrCharucoCorners = Call("_cveInputArrayFromVectorOf" & $typeOfCharucoCorners, $vectorCharucoCorners)
    Else
        If $bCharucoCornersCreate Then
            $charucoCorners = Call("_cve" & $typeOfCharucoCorners & "Create", $charucoCorners)
        EndIf
        $iArrCharucoCorners = Call("_cveInputArrayFrom" & $typeOfCharucoCorners, $charucoCorners)
    EndIf

    Local $iArrCharucoIds, $vectorCharucoIds, $iArrCharucoIdsSize
    Local $bCharucoIdsIsArray = IsArray($charucoIds)
    Local $bCharucoIdsCreate = IsDllStruct($charucoIds) And $typeOfCharucoIds == "Scalar"

    If $typeOfCharucoIds == Default Then
        $iArrCharucoIds = $charucoIds
    ElseIf $bCharucoIdsIsArray Then
        $vectorCharucoIds = Call("_VectorOf" & $typeOfCharucoIds & "Create")

        $iArrCharucoIdsSize = UBound($charucoIds)
        For $i = 0 To $iArrCharucoIdsSize - 1
            Call("_VectorOf" & $typeOfCharucoIds & "Push", $vectorCharucoIds, $charucoIds[$i])
        Next

        $iArrCharucoIds = Call("_cveInputArrayFromVectorOf" & $typeOfCharucoIds, $vectorCharucoIds)
    Else
        If $bCharucoIdsCreate Then
            $charucoIds = Call("_cve" & $typeOfCharucoIds & "Create", $charucoIds)
        EndIf
        $iArrCharucoIds = Call("_cveInputArrayFrom" & $typeOfCharucoIds, $charucoIds)
    EndIf

    Local $iArrCameraMatrix, $vectorCameraMatrix, $iArrCameraMatrixSize
    Local $bCameraMatrixIsArray = IsArray($cameraMatrix)
    Local $bCameraMatrixCreate = IsDllStruct($cameraMatrix) And $typeOfCameraMatrix == "Scalar"

    If $typeOfCameraMatrix == Default Then
        $iArrCameraMatrix = $cameraMatrix
    ElseIf $bCameraMatrixIsArray Then
        $vectorCameraMatrix = Call("_VectorOf" & $typeOfCameraMatrix & "Create")

        $iArrCameraMatrixSize = UBound($cameraMatrix)
        For $i = 0 To $iArrCameraMatrixSize - 1
            Call("_VectorOf" & $typeOfCameraMatrix & "Push", $vectorCameraMatrix, $cameraMatrix[$i])
        Next

        $iArrCameraMatrix = Call("_cveInputArrayFromVectorOf" & $typeOfCameraMatrix, $vectorCameraMatrix)
    Else
        If $bCameraMatrixCreate Then
            $cameraMatrix = Call("_cve" & $typeOfCameraMatrix & "Create", $cameraMatrix)
        EndIf
        $iArrCameraMatrix = Call("_cveInputArrayFrom" & $typeOfCameraMatrix, $cameraMatrix)
    EndIf

    Local $iArrDistCoeffs, $vectorDistCoeffs, $iArrDistCoeffsSize
    Local $bDistCoeffsIsArray = IsArray($distCoeffs)
    Local $bDistCoeffsCreate = IsDllStruct($distCoeffs) And $typeOfDistCoeffs == "Scalar"

    If $typeOfDistCoeffs == Default Then
        $iArrDistCoeffs = $distCoeffs
    ElseIf $bDistCoeffsIsArray Then
        $vectorDistCoeffs = Call("_VectorOf" & $typeOfDistCoeffs & "Create")

        $iArrDistCoeffsSize = UBound($distCoeffs)
        For $i = 0 To $iArrDistCoeffsSize - 1
            Call("_VectorOf" & $typeOfDistCoeffs & "Push", $vectorDistCoeffs, $distCoeffs[$i])
        Next

        $iArrDistCoeffs = Call("_cveInputArrayFromVectorOf" & $typeOfDistCoeffs, $vectorDistCoeffs)
    Else
        If $bDistCoeffsCreate Then
            $distCoeffs = Call("_cve" & $typeOfDistCoeffs & "Create", $distCoeffs)
        EndIf
        $iArrDistCoeffs = Call("_cveInputArrayFrom" & $typeOfDistCoeffs, $distCoeffs)
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

    Local $retval = _cveArucoEstimatePoseCharucoBoard($iArrCharucoCorners, $iArrCharucoIds, $board, $iArrCameraMatrix, $iArrDistCoeffs, $ioArrRvec, $ioArrTvec, $useExtrinsicGuess)

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

    If $bDistCoeffsIsArray Then
        Call("_VectorOf" & $typeOfDistCoeffs & "Release", $vectorDistCoeffs)
    EndIf

    If $typeOfDistCoeffs <> Default Then
        _cveInputArrayRelease($iArrDistCoeffs)
        If $bDistCoeffsCreate Then
            Call("_cve" & $typeOfDistCoeffs & "Release", $distCoeffs)
        EndIf
    EndIf

    If $bCameraMatrixIsArray Then
        Call("_VectorOf" & $typeOfCameraMatrix & "Release", $vectorCameraMatrix)
    EndIf

    If $typeOfCameraMatrix <> Default Then
        _cveInputArrayRelease($iArrCameraMatrix)
        If $bCameraMatrixCreate Then
            Call("_cve" & $typeOfCameraMatrix & "Release", $cameraMatrix)
        EndIf
    EndIf

    If $bCharucoIdsIsArray Then
        Call("_VectorOf" & $typeOfCharucoIds & "Release", $vectorCharucoIds)
    EndIf

    If $typeOfCharucoIds <> Default Then
        _cveInputArrayRelease($iArrCharucoIds)
        If $bCharucoIdsCreate Then
            Call("_cve" & $typeOfCharucoIds & "Release", $charucoIds)
        EndIf
    EndIf

    If $bCharucoCornersIsArray Then
        Call("_VectorOf" & $typeOfCharucoCorners & "Release", $vectorCharucoCorners)
    EndIf

    If $typeOfCharucoCorners <> Default Then
        _cveInputArrayRelease($iArrCharucoCorners)
        If $bCharucoCornersCreate Then
            Call("_cve" & $typeOfCharucoCorners & "Release", $charucoCorners)
        EndIf
    EndIf

    Return $retval
EndFunc   ;==>_cveArucoEstimatePoseCharucoBoardTyped

Func _cveArucoEstimatePoseCharucoBoardMat($charucoCorners, $charucoIds, $board, $cameraMatrix, $distCoeffs, $rvec, $tvec, $useExtrinsicGuess)
    ; cveArucoEstimatePoseCharucoBoard using cv::Mat instead of _*Array
    Local $retval = _cveArucoEstimatePoseCharucoBoardTyped("Mat", $charucoCorners, "Mat", $charucoIds, $board, "Mat", $cameraMatrix, "Mat", $distCoeffs, "Mat", $rvec, "Mat", $tvec, $useExtrinsicGuess)

    Return $retval
EndFunc   ;==>_cveArucoEstimatePoseCharucoBoardMat

Func _cveArucoDetectCharucoDiamond($image, $markerCorners, $markerIds, $squareMarkerLengthRate, $diamondCorners, $diamondIds, $cameraMatrix, $distCoeffs)
    ; CVAPI(void) cveArucoDetectCharucoDiamond(cv::_InputArray* image, cv::_InputArray* markerCorners, cv::_InputArray* markerIds, float squareMarkerLengthRate, cv::_OutputArray* diamondCorners, cv::_OutputArray* diamondIds, cv::_InputArray* cameraMatrix, cv::_InputArray* distCoeffs);

    Local $sImageDllType
    If IsDllStruct($image) Then
        $sImageDllType = "struct*"
    Else
        $sImageDllType = "ptr"
    EndIf

    Local $sMarkerCornersDllType
    If IsDllStruct($markerCorners) Then
        $sMarkerCornersDllType = "struct*"
    Else
        $sMarkerCornersDllType = "ptr"
    EndIf

    Local $sMarkerIdsDllType
    If IsDllStruct($markerIds) Then
        $sMarkerIdsDllType = "struct*"
    Else
        $sMarkerIdsDllType = "ptr"
    EndIf

    Local $sDiamondCornersDllType
    If IsDllStruct($diamondCorners) Then
        $sDiamondCornersDllType = "struct*"
    Else
        $sDiamondCornersDllType = "ptr"
    EndIf

    Local $sDiamondIdsDllType
    If IsDllStruct($diamondIds) Then
        $sDiamondIdsDllType = "struct*"
    Else
        $sDiamondIdsDllType = "ptr"
    EndIf

    Local $sCameraMatrixDllType
    If IsDllStruct($cameraMatrix) Then
        $sCameraMatrixDllType = "struct*"
    Else
        $sCameraMatrixDllType = "ptr"
    EndIf

    Local $sDistCoeffsDllType
    If IsDllStruct($distCoeffs) Then
        $sDistCoeffsDllType = "struct*"
    Else
        $sDistCoeffsDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveArucoDetectCharucoDiamond", $sImageDllType, $image, $sMarkerCornersDllType, $markerCorners, $sMarkerIdsDllType, $markerIds, "float", $squareMarkerLengthRate, $sDiamondCornersDllType, $diamondCorners, $sDiamondIdsDllType, $diamondIds, $sCameraMatrixDllType, $cameraMatrix, $sDistCoeffsDllType, $distCoeffs), "cveArucoDetectCharucoDiamond", @error)
EndFunc   ;==>_cveArucoDetectCharucoDiamond

Func _cveArucoDetectCharucoDiamondTyped($typeOfImage, $image, $typeOfMarkerCorners, $markerCorners, $typeOfMarkerIds, $markerIds, $squareMarkerLengthRate, $typeOfDiamondCorners, $diamondCorners, $typeOfDiamondIds, $diamondIds, $typeOfCameraMatrix, $cameraMatrix, $typeOfDistCoeffs, $distCoeffs)

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

    Local $iArrMarkerCorners, $vectorMarkerCorners, $iArrMarkerCornersSize
    Local $bMarkerCornersIsArray = IsArray($markerCorners)
    Local $bMarkerCornersCreate = IsDllStruct($markerCorners) And $typeOfMarkerCorners == "Scalar"

    If $typeOfMarkerCorners == Default Then
        $iArrMarkerCorners = $markerCorners
    ElseIf $bMarkerCornersIsArray Then
        $vectorMarkerCorners = Call("_VectorOf" & $typeOfMarkerCorners & "Create")

        $iArrMarkerCornersSize = UBound($markerCorners)
        For $i = 0 To $iArrMarkerCornersSize - 1
            Call("_VectorOf" & $typeOfMarkerCorners & "Push", $vectorMarkerCorners, $markerCorners[$i])
        Next

        $iArrMarkerCorners = Call("_cveInputArrayFromVectorOf" & $typeOfMarkerCorners, $vectorMarkerCorners)
    Else
        If $bMarkerCornersCreate Then
            $markerCorners = Call("_cve" & $typeOfMarkerCorners & "Create", $markerCorners)
        EndIf
        $iArrMarkerCorners = Call("_cveInputArrayFrom" & $typeOfMarkerCorners, $markerCorners)
    EndIf

    Local $iArrMarkerIds, $vectorMarkerIds, $iArrMarkerIdsSize
    Local $bMarkerIdsIsArray = IsArray($markerIds)
    Local $bMarkerIdsCreate = IsDllStruct($markerIds) And $typeOfMarkerIds == "Scalar"

    If $typeOfMarkerIds == Default Then
        $iArrMarkerIds = $markerIds
    ElseIf $bMarkerIdsIsArray Then
        $vectorMarkerIds = Call("_VectorOf" & $typeOfMarkerIds & "Create")

        $iArrMarkerIdsSize = UBound($markerIds)
        For $i = 0 To $iArrMarkerIdsSize - 1
            Call("_VectorOf" & $typeOfMarkerIds & "Push", $vectorMarkerIds, $markerIds[$i])
        Next

        $iArrMarkerIds = Call("_cveInputArrayFromVectorOf" & $typeOfMarkerIds, $vectorMarkerIds)
    Else
        If $bMarkerIdsCreate Then
            $markerIds = Call("_cve" & $typeOfMarkerIds & "Create", $markerIds)
        EndIf
        $iArrMarkerIds = Call("_cveInputArrayFrom" & $typeOfMarkerIds, $markerIds)
    EndIf

    Local $oArrDiamondCorners, $vectorDiamondCorners, $iArrDiamondCornersSize
    Local $bDiamondCornersIsArray = IsArray($diamondCorners)
    Local $bDiamondCornersCreate = IsDllStruct($diamondCorners) And $typeOfDiamondCorners == "Scalar"

    If $typeOfDiamondCorners == Default Then
        $oArrDiamondCorners = $diamondCorners
    ElseIf $bDiamondCornersIsArray Then
        $vectorDiamondCorners = Call("_VectorOf" & $typeOfDiamondCorners & "Create")

        $iArrDiamondCornersSize = UBound($diamondCorners)
        For $i = 0 To $iArrDiamondCornersSize - 1
            Call("_VectorOf" & $typeOfDiamondCorners & "Push", $vectorDiamondCorners, $diamondCorners[$i])
        Next

        $oArrDiamondCorners = Call("_cveOutputArrayFromVectorOf" & $typeOfDiamondCorners, $vectorDiamondCorners)
    Else
        If $bDiamondCornersCreate Then
            $diamondCorners = Call("_cve" & $typeOfDiamondCorners & "Create", $diamondCorners)
        EndIf
        $oArrDiamondCorners = Call("_cveOutputArrayFrom" & $typeOfDiamondCorners, $diamondCorners)
    EndIf

    Local $oArrDiamondIds, $vectorDiamondIds, $iArrDiamondIdsSize
    Local $bDiamondIdsIsArray = IsArray($diamondIds)
    Local $bDiamondIdsCreate = IsDllStruct($diamondIds) And $typeOfDiamondIds == "Scalar"

    If $typeOfDiamondIds == Default Then
        $oArrDiamondIds = $diamondIds
    ElseIf $bDiamondIdsIsArray Then
        $vectorDiamondIds = Call("_VectorOf" & $typeOfDiamondIds & "Create")

        $iArrDiamondIdsSize = UBound($diamondIds)
        For $i = 0 To $iArrDiamondIdsSize - 1
            Call("_VectorOf" & $typeOfDiamondIds & "Push", $vectorDiamondIds, $diamondIds[$i])
        Next

        $oArrDiamondIds = Call("_cveOutputArrayFromVectorOf" & $typeOfDiamondIds, $vectorDiamondIds)
    Else
        If $bDiamondIdsCreate Then
            $diamondIds = Call("_cve" & $typeOfDiamondIds & "Create", $diamondIds)
        EndIf
        $oArrDiamondIds = Call("_cveOutputArrayFrom" & $typeOfDiamondIds, $diamondIds)
    EndIf

    Local $iArrCameraMatrix, $vectorCameraMatrix, $iArrCameraMatrixSize
    Local $bCameraMatrixIsArray = IsArray($cameraMatrix)
    Local $bCameraMatrixCreate = IsDllStruct($cameraMatrix) And $typeOfCameraMatrix == "Scalar"

    If $typeOfCameraMatrix == Default Then
        $iArrCameraMatrix = $cameraMatrix
    ElseIf $bCameraMatrixIsArray Then
        $vectorCameraMatrix = Call("_VectorOf" & $typeOfCameraMatrix & "Create")

        $iArrCameraMatrixSize = UBound($cameraMatrix)
        For $i = 0 To $iArrCameraMatrixSize - 1
            Call("_VectorOf" & $typeOfCameraMatrix & "Push", $vectorCameraMatrix, $cameraMatrix[$i])
        Next

        $iArrCameraMatrix = Call("_cveInputArrayFromVectorOf" & $typeOfCameraMatrix, $vectorCameraMatrix)
    Else
        If $bCameraMatrixCreate Then
            $cameraMatrix = Call("_cve" & $typeOfCameraMatrix & "Create", $cameraMatrix)
        EndIf
        $iArrCameraMatrix = Call("_cveInputArrayFrom" & $typeOfCameraMatrix, $cameraMatrix)
    EndIf

    Local $iArrDistCoeffs, $vectorDistCoeffs, $iArrDistCoeffsSize
    Local $bDistCoeffsIsArray = IsArray($distCoeffs)
    Local $bDistCoeffsCreate = IsDllStruct($distCoeffs) And $typeOfDistCoeffs == "Scalar"

    If $typeOfDistCoeffs == Default Then
        $iArrDistCoeffs = $distCoeffs
    ElseIf $bDistCoeffsIsArray Then
        $vectorDistCoeffs = Call("_VectorOf" & $typeOfDistCoeffs & "Create")

        $iArrDistCoeffsSize = UBound($distCoeffs)
        For $i = 0 To $iArrDistCoeffsSize - 1
            Call("_VectorOf" & $typeOfDistCoeffs & "Push", $vectorDistCoeffs, $distCoeffs[$i])
        Next

        $iArrDistCoeffs = Call("_cveInputArrayFromVectorOf" & $typeOfDistCoeffs, $vectorDistCoeffs)
    Else
        If $bDistCoeffsCreate Then
            $distCoeffs = Call("_cve" & $typeOfDistCoeffs & "Create", $distCoeffs)
        EndIf
        $iArrDistCoeffs = Call("_cveInputArrayFrom" & $typeOfDistCoeffs, $distCoeffs)
    EndIf

    _cveArucoDetectCharucoDiamond($iArrImage, $iArrMarkerCorners, $iArrMarkerIds, $squareMarkerLengthRate, $oArrDiamondCorners, $oArrDiamondIds, $iArrCameraMatrix, $iArrDistCoeffs)

    If $bDistCoeffsIsArray Then
        Call("_VectorOf" & $typeOfDistCoeffs & "Release", $vectorDistCoeffs)
    EndIf

    If $typeOfDistCoeffs <> Default Then
        _cveInputArrayRelease($iArrDistCoeffs)
        If $bDistCoeffsCreate Then
            Call("_cve" & $typeOfDistCoeffs & "Release", $distCoeffs)
        EndIf
    EndIf

    If $bCameraMatrixIsArray Then
        Call("_VectorOf" & $typeOfCameraMatrix & "Release", $vectorCameraMatrix)
    EndIf

    If $typeOfCameraMatrix <> Default Then
        _cveInputArrayRelease($iArrCameraMatrix)
        If $bCameraMatrixCreate Then
            Call("_cve" & $typeOfCameraMatrix & "Release", $cameraMatrix)
        EndIf
    EndIf

    If $bDiamondIdsIsArray Then
        Call("_VectorOf" & $typeOfDiamondIds & "Release", $vectorDiamondIds)
    EndIf

    If $typeOfDiamondIds <> Default Then
        _cveOutputArrayRelease($oArrDiamondIds)
        If $bDiamondIdsCreate Then
            Call("_cve" & $typeOfDiamondIds & "Release", $diamondIds)
        EndIf
    EndIf

    If $bDiamondCornersIsArray Then
        Call("_VectorOf" & $typeOfDiamondCorners & "Release", $vectorDiamondCorners)
    EndIf

    If $typeOfDiamondCorners <> Default Then
        _cveOutputArrayRelease($oArrDiamondCorners)
        If $bDiamondCornersCreate Then
            Call("_cve" & $typeOfDiamondCorners & "Release", $diamondCorners)
        EndIf
    EndIf

    If $bMarkerIdsIsArray Then
        Call("_VectorOf" & $typeOfMarkerIds & "Release", $vectorMarkerIds)
    EndIf

    If $typeOfMarkerIds <> Default Then
        _cveInputArrayRelease($iArrMarkerIds)
        If $bMarkerIdsCreate Then
            Call("_cve" & $typeOfMarkerIds & "Release", $markerIds)
        EndIf
    EndIf

    If $bMarkerCornersIsArray Then
        Call("_VectorOf" & $typeOfMarkerCorners & "Release", $vectorMarkerCorners)
    EndIf

    If $typeOfMarkerCorners <> Default Then
        _cveInputArrayRelease($iArrMarkerCorners)
        If $bMarkerCornersCreate Then
            Call("_cve" & $typeOfMarkerCorners & "Release", $markerCorners)
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
EndFunc   ;==>_cveArucoDetectCharucoDiamondTyped

Func _cveArucoDetectCharucoDiamondMat($image, $markerCorners, $markerIds, $squareMarkerLengthRate, $diamondCorners, $diamondIds, $cameraMatrix, $distCoeffs)
    ; cveArucoDetectCharucoDiamond using cv::Mat instead of _*Array
    _cveArucoDetectCharucoDiamondTyped("Mat", $image, "Mat", $markerCorners, "Mat", $markerIds, $squareMarkerLengthRate, "Mat", $diamondCorners, "Mat", $diamondIds, "Mat", $cameraMatrix, "Mat", $distCoeffs)
EndFunc   ;==>_cveArucoDetectCharucoDiamondMat

Func _cveArucoDrawDetectedDiamonds($image, $diamondCorners, $diamondIds, $borderColor)
    ; CVAPI(void) cveArucoDrawDetectedDiamonds(cv::_InputOutputArray* image, cv::_InputArray* diamondCorners, cv::_InputArray* diamondIds, CvScalar* borderColor);

    Local $sImageDllType
    If IsDllStruct($image) Then
        $sImageDllType = "struct*"
    Else
        $sImageDllType = "ptr"
    EndIf

    Local $sDiamondCornersDllType
    If IsDllStruct($diamondCorners) Then
        $sDiamondCornersDllType = "struct*"
    Else
        $sDiamondCornersDllType = "ptr"
    EndIf

    Local $sDiamondIdsDllType
    If IsDllStruct($diamondIds) Then
        $sDiamondIdsDllType = "struct*"
    Else
        $sDiamondIdsDllType = "ptr"
    EndIf

    Local $sBorderColorDllType
    If IsDllStruct($borderColor) Then
        $sBorderColorDllType = "struct*"
    Else
        $sBorderColorDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveArucoDrawDetectedDiamonds", $sImageDllType, $image, $sDiamondCornersDllType, $diamondCorners, $sDiamondIdsDllType, $diamondIds, $sBorderColorDllType, $borderColor), "cveArucoDrawDetectedDiamonds", @error)
EndFunc   ;==>_cveArucoDrawDetectedDiamonds

Func _cveArucoDrawDetectedDiamondsTyped($typeOfImage, $image, $typeOfDiamondCorners, $diamondCorners, $typeOfDiamondIds, $diamondIds, $borderColor)

    Local $ioArrImage, $vectorImage, $iArrImageSize
    Local $bImageIsArray = IsArray($image)
    Local $bImageCreate = IsDllStruct($image) And $typeOfImage == "Scalar"

    If $typeOfImage == Default Then
        $ioArrImage = $image
    ElseIf $bImageIsArray Then
        $vectorImage = Call("_VectorOf" & $typeOfImage & "Create")

        $iArrImageSize = UBound($image)
        For $i = 0 To $iArrImageSize - 1
            Call("_VectorOf" & $typeOfImage & "Push", $vectorImage, $image[$i])
        Next

        $ioArrImage = Call("_cveInputOutputArrayFromVectorOf" & $typeOfImage, $vectorImage)
    Else
        If $bImageCreate Then
            $image = Call("_cve" & $typeOfImage & "Create", $image)
        EndIf
        $ioArrImage = Call("_cveInputOutputArrayFrom" & $typeOfImage, $image)
    EndIf

    Local $iArrDiamondCorners, $vectorDiamondCorners, $iArrDiamondCornersSize
    Local $bDiamondCornersIsArray = IsArray($diamondCorners)
    Local $bDiamondCornersCreate = IsDllStruct($diamondCorners) And $typeOfDiamondCorners == "Scalar"

    If $typeOfDiamondCorners == Default Then
        $iArrDiamondCorners = $diamondCorners
    ElseIf $bDiamondCornersIsArray Then
        $vectorDiamondCorners = Call("_VectorOf" & $typeOfDiamondCorners & "Create")

        $iArrDiamondCornersSize = UBound($diamondCorners)
        For $i = 0 To $iArrDiamondCornersSize - 1
            Call("_VectorOf" & $typeOfDiamondCorners & "Push", $vectorDiamondCorners, $diamondCorners[$i])
        Next

        $iArrDiamondCorners = Call("_cveInputArrayFromVectorOf" & $typeOfDiamondCorners, $vectorDiamondCorners)
    Else
        If $bDiamondCornersCreate Then
            $diamondCorners = Call("_cve" & $typeOfDiamondCorners & "Create", $diamondCorners)
        EndIf
        $iArrDiamondCorners = Call("_cveInputArrayFrom" & $typeOfDiamondCorners, $diamondCorners)
    EndIf

    Local $iArrDiamondIds, $vectorDiamondIds, $iArrDiamondIdsSize
    Local $bDiamondIdsIsArray = IsArray($diamondIds)
    Local $bDiamondIdsCreate = IsDllStruct($diamondIds) And $typeOfDiamondIds == "Scalar"

    If $typeOfDiamondIds == Default Then
        $iArrDiamondIds = $diamondIds
    ElseIf $bDiamondIdsIsArray Then
        $vectorDiamondIds = Call("_VectorOf" & $typeOfDiamondIds & "Create")

        $iArrDiamondIdsSize = UBound($diamondIds)
        For $i = 0 To $iArrDiamondIdsSize - 1
            Call("_VectorOf" & $typeOfDiamondIds & "Push", $vectorDiamondIds, $diamondIds[$i])
        Next

        $iArrDiamondIds = Call("_cveInputArrayFromVectorOf" & $typeOfDiamondIds, $vectorDiamondIds)
    Else
        If $bDiamondIdsCreate Then
            $diamondIds = Call("_cve" & $typeOfDiamondIds & "Create", $diamondIds)
        EndIf
        $iArrDiamondIds = Call("_cveInputArrayFrom" & $typeOfDiamondIds, $diamondIds)
    EndIf

    _cveArucoDrawDetectedDiamonds($ioArrImage, $iArrDiamondCorners, $iArrDiamondIds, $borderColor)

    If $bDiamondIdsIsArray Then
        Call("_VectorOf" & $typeOfDiamondIds & "Release", $vectorDiamondIds)
    EndIf

    If $typeOfDiamondIds <> Default Then
        _cveInputArrayRelease($iArrDiamondIds)
        If $bDiamondIdsCreate Then
            Call("_cve" & $typeOfDiamondIds & "Release", $diamondIds)
        EndIf
    EndIf

    If $bDiamondCornersIsArray Then
        Call("_VectorOf" & $typeOfDiamondCorners & "Release", $vectorDiamondCorners)
    EndIf

    If $typeOfDiamondCorners <> Default Then
        _cveInputArrayRelease($iArrDiamondCorners)
        If $bDiamondCornersCreate Then
            Call("_cve" & $typeOfDiamondCorners & "Release", $diamondCorners)
        EndIf
    EndIf

    If $bImageIsArray Then
        Call("_VectorOf" & $typeOfImage & "Release", $vectorImage)
    EndIf

    If $typeOfImage <> Default Then
        _cveInputOutputArrayRelease($ioArrImage)
        If $bImageCreate Then
            Call("_cve" & $typeOfImage & "Release", $image)
        EndIf
    EndIf
EndFunc   ;==>_cveArucoDrawDetectedDiamondsTyped

Func _cveArucoDrawDetectedDiamondsMat($image, $diamondCorners, $diamondIds, $borderColor)
    ; cveArucoDrawDetectedDiamonds using cv::Mat instead of _*Array
    _cveArucoDrawDetectedDiamondsTyped("Mat", $image, "Mat", $diamondCorners, "Mat", $diamondIds, $borderColor)
EndFunc   ;==>_cveArucoDrawDetectedDiamondsMat

Func _cveArucoDrawCharucoDiamond($dictionary, $ids, $squareLength, $markerLength, $img, $marginSize, $borderBits)
    ; CVAPI(void) cveArucoDrawCharucoDiamond(cv::aruco::Dictionary* dictionary, int* ids, int squareLength, int markerLength, cv::_OutputArray* img, int marginSize, int borderBits);

    Local $sDictionaryDllType
    If IsDllStruct($dictionary) Then
        $sDictionaryDllType = "struct*"
    Else
        $sDictionaryDllType = "ptr"
    EndIf

    Local $sIdsDllType
    If IsDllStruct($ids) Then
        $sIdsDllType = "struct*"
    Else
        $sIdsDllType = "int*"
    EndIf

    Local $sImgDllType
    If IsDllStruct($img) Then
        $sImgDllType = "struct*"
    Else
        $sImgDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveArucoDrawCharucoDiamond", $sDictionaryDllType, $dictionary, $sIdsDllType, $ids, "int", $squareLength, "int", $markerLength, $sImgDllType, $img, "int", $marginSize, "int", $borderBits), "cveArucoDrawCharucoDiamond", @error)
EndFunc   ;==>_cveArucoDrawCharucoDiamond

Func _cveArucoDrawCharucoDiamondTyped($dictionary, $ids, $squareLength, $markerLength, $typeOfImg, $img, $marginSize, $borderBits)

    Local $oArrImg, $vectorImg, $iArrImgSize
    Local $bImgIsArray = IsArray($img)
    Local $bImgCreate = IsDllStruct($img) And $typeOfImg == "Scalar"

    If $typeOfImg == Default Then
        $oArrImg = $img
    ElseIf $bImgIsArray Then
        $vectorImg = Call("_VectorOf" & $typeOfImg & "Create")

        $iArrImgSize = UBound($img)
        For $i = 0 To $iArrImgSize - 1
            Call("_VectorOf" & $typeOfImg & "Push", $vectorImg, $img[$i])
        Next

        $oArrImg = Call("_cveOutputArrayFromVectorOf" & $typeOfImg, $vectorImg)
    Else
        If $bImgCreate Then
            $img = Call("_cve" & $typeOfImg & "Create", $img)
        EndIf
        $oArrImg = Call("_cveOutputArrayFrom" & $typeOfImg, $img)
    EndIf

    _cveArucoDrawCharucoDiamond($dictionary, $ids, $squareLength, $markerLength, $oArrImg, $marginSize, $borderBits)

    If $bImgIsArray Then
        Call("_VectorOf" & $typeOfImg & "Release", $vectorImg)
    EndIf

    If $typeOfImg <> Default Then
        _cveOutputArrayRelease($oArrImg)
        If $bImgCreate Then
            Call("_cve" & $typeOfImg & "Release", $img)
        EndIf
    EndIf
EndFunc   ;==>_cveArucoDrawCharucoDiamondTyped

Func _cveArucoDrawCharucoDiamondMat($dictionary, $ids, $squareLength, $markerLength, $img, $marginSize, $borderBits)
    ; cveArucoDrawCharucoDiamond using cv::Mat instead of _*Array
    _cveArucoDrawCharucoDiamondTyped($dictionary, $ids, $squareLength, $markerLength, "Mat", $img, $marginSize, $borderBits)
EndFunc   ;==>_cveArucoDrawCharucoDiamondMat

Func _cveArucoDrawPlanarBoard($board, $outSize, $img, $marginSize, $borderBits)
    ; CVAPI(void) cveArucoDrawPlanarBoard(cv::aruco::Board* board, CvSize* outSize, cv::_OutputArray* img, int marginSize, int borderBits);

    Local $sBoardDllType
    If IsDllStruct($board) Then
        $sBoardDllType = "struct*"
    Else
        $sBoardDllType = "ptr"
    EndIf

    Local $sOutSizeDllType
    If IsDllStruct($outSize) Then
        $sOutSizeDllType = "struct*"
    Else
        $sOutSizeDllType = "ptr"
    EndIf

    Local $sImgDllType
    If IsDllStruct($img) Then
        $sImgDllType = "struct*"
    Else
        $sImgDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveArucoDrawPlanarBoard", $sBoardDllType, $board, $sOutSizeDllType, $outSize, $sImgDllType, $img, "int", $marginSize, "int", $borderBits), "cveArucoDrawPlanarBoard", @error)
EndFunc   ;==>_cveArucoDrawPlanarBoard

Func _cveArucoDrawPlanarBoardTyped($board, $outSize, $typeOfImg, $img, $marginSize, $borderBits)

    Local $oArrImg, $vectorImg, $iArrImgSize
    Local $bImgIsArray = IsArray($img)
    Local $bImgCreate = IsDllStruct($img) And $typeOfImg == "Scalar"

    If $typeOfImg == Default Then
        $oArrImg = $img
    ElseIf $bImgIsArray Then
        $vectorImg = Call("_VectorOf" & $typeOfImg & "Create")

        $iArrImgSize = UBound($img)
        For $i = 0 To $iArrImgSize - 1
            Call("_VectorOf" & $typeOfImg & "Push", $vectorImg, $img[$i])
        Next

        $oArrImg = Call("_cveOutputArrayFromVectorOf" & $typeOfImg, $vectorImg)
    Else
        If $bImgCreate Then
            $img = Call("_cve" & $typeOfImg & "Create", $img)
        EndIf
        $oArrImg = Call("_cveOutputArrayFrom" & $typeOfImg, $img)
    EndIf

    _cveArucoDrawPlanarBoard($board, $outSize, $oArrImg, $marginSize, $borderBits)

    If $bImgIsArray Then
        Call("_VectorOf" & $typeOfImg & "Release", $vectorImg)
    EndIf

    If $typeOfImg <> Default Then
        _cveOutputArrayRelease($oArrImg)
        If $bImgCreate Then
            Call("_cve" & $typeOfImg & "Release", $img)
        EndIf
    EndIf
EndFunc   ;==>_cveArucoDrawPlanarBoardTyped

Func _cveArucoDrawPlanarBoardMat($board, $outSize, $img, $marginSize, $borderBits)
    ; cveArucoDrawPlanarBoard using cv::Mat instead of _*Array
    _cveArucoDrawPlanarBoardTyped($board, $outSize, "Mat", $img, $marginSize, $borderBits)
EndFunc   ;==>_cveArucoDrawPlanarBoardMat

Func _cveArucoEstimatePoseBoard($corners, $ids, $board, $cameraMatrix, $distCoeffs, $rvec, $tvec, $useExtrinsicGuess)
    ; CVAPI(int) cveArucoEstimatePoseBoard(cv::_InputArray* corners, cv::_InputArray* ids, cv::aruco::Board* board, cv::_InputArray* cameraMatrix, cv::_InputArray* distCoeffs, cv::_InputOutputArray* rvec, cv::_InputOutputArray* tvec, bool useExtrinsicGuess);

    Local $sCornersDllType
    If IsDllStruct($corners) Then
        $sCornersDllType = "struct*"
    Else
        $sCornersDllType = "ptr"
    EndIf

    Local $sIdsDllType
    If IsDllStruct($ids) Then
        $sIdsDllType = "struct*"
    Else
        $sIdsDllType = "ptr"
    EndIf

    Local $sBoardDllType
    If IsDllStruct($board) Then
        $sBoardDllType = "struct*"
    Else
        $sBoardDllType = "ptr"
    EndIf

    Local $sCameraMatrixDllType
    If IsDllStruct($cameraMatrix) Then
        $sCameraMatrixDllType = "struct*"
    Else
        $sCameraMatrixDllType = "ptr"
    EndIf

    Local $sDistCoeffsDllType
    If IsDllStruct($distCoeffs) Then
        $sDistCoeffsDllType = "struct*"
    Else
        $sDistCoeffsDllType = "ptr"
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
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveArucoEstimatePoseBoard", $sCornersDllType, $corners, $sIdsDllType, $ids, $sBoardDllType, $board, $sCameraMatrixDllType, $cameraMatrix, $sDistCoeffsDllType, $distCoeffs, $sRvecDllType, $rvec, $sTvecDllType, $tvec, "boolean", $useExtrinsicGuess), "cveArucoEstimatePoseBoard", @error)
EndFunc   ;==>_cveArucoEstimatePoseBoard

Func _cveArucoEstimatePoseBoardTyped($typeOfCorners, $corners, $typeOfIds, $ids, $board, $typeOfCameraMatrix, $cameraMatrix, $typeOfDistCoeffs, $distCoeffs, $typeOfRvec, $rvec, $typeOfTvec, $tvec, $useExtrinsicGuess)

    Local $iArrCorners, $vectorCorners, $iArrCornersSize
    Local $bCornersIsArray = IsArray($corners)
    Local $bCornersCreate = IsDllStruct($corners) And $typeOfCorners == "Scalar"

    If $typeOfCorners == Default Then
        $iArrCorners = $corners
    ElseIf $bCornersIsArray Then
        $vectorCorners = Call("_VectorOf" & $typeOfCorners & "Create")

        $iArrCornersSize = UBound($corners)
        For $i = 0 To $iArrCornersSize - 1
            Call("_VectorOf" & $typeOfCorners & "Push", $vectorCorners, $corners[$i])
        Next

        $iArrCorners = Call("_cveInputArrayFromVectorOf" & $typeOfCorners, $vectorCorners)
    Else
        If $bCornersCreate Then
            $corners = Call("_cve" & $typeOfCorners & "Create", $corners)
        EndIf
        $iArrCorners = Call("_cveInputArrayFrom" & $typeOfCorners, $corners)
    EndIf

    Local $iArrIds, $vectorIds, $iArrIdsSize
    Local $bIdsIsArray = IsArray($ids)
    Local $bIdsCreate = IsDllStruct($ids) And $typeOfIds == "Scalar"

    If $typeOfIds == Default Then
        $iArrIds = $ids
    ElseIf $bIdsIsArray Then
        $vectorIds = Call("_VectorOf" & $typeOfIds & "Create")

        $iArrIdsSize = UBound($ids)
        For $i = 0 To $iArrIdsSize - 1
            Call("_VectorOf" & $typeOfIds & "Push", $vectorIds, $ids[$i])
        Next

        $iArrIds = Call("_cveInputArrayFromVectorOf" & $typeOfIds, $vectorIds)
    Else
        If $bIdsCreate Then
            $ids = Call("_cve" & $typeOfIds & "Create", $ids)
        EndIf
        $iArrIds = Call("_cveInputArrayFrom" & $typeOfIds, $ids)
    EndIf

    Local $iArrCameraMatrix, $vectorCameraMatrix, $iArrCameraMatrixSize
    Local $bCameraMatrixIsArray = IsArray($cameraMatrix)
    Local $bCameraMatrixCreate = IsDllStruct($cameraMatrix) And $typeOfCameraMatrix == "Scalar"

    If $typeOfCameraMatrix == Default Then
        $iArrCameraMatrix = $cameraMatrix
    ElseIf $bCameraMatrixIsArray Then
        $vectorCameraMatrix = Call("_VectorOf" & $typeOfCameraMatrix & "Create")

        $iArrCameraMatrixSize = UBound($cameraMatrix)
        For $i = 0 To $iArrCameraMatrixSize - 1
            Call("_VectorOf" & $typeOfCameraMatrix & "Push", $vectorCameraMatrix, $cameraMatrix[$i])
        Next

        $iArrCameraMatrix = Call("_cveInputArrayFromVectorOf" & $typeOfCameraMatrix, $vectorCameraMatrix)
    Else
        If $bCameraMatrixCreate Then
            $cameraMatrix = Call("_cve" & $typeOfCameraMatrix & "Create", $cameraMatrix)
        EndIf
        $iArrCameraMatrix = Call("_cveInputArrayFrom" & $typeOfCameraMatrix, $cameraMatrix)
    EndIf

    Local $iArrDistCoeffs, $vectorDistCoeffs, $iArrDistCoeffsSize
    Local $bDistCoeffsIsArray = IsArray($distCoeffs)
    Local $bDistCoeffsCreate = IsDllStruct($distCoeffs) And $typeOfDistCoeffs == "Scalar"

    If $typeOfDistCoeffs == Default Then
        $iArrDistCoeffs = $distCoeffs
    ElseIf $bDistCoeffsIsArray Then
        $vectorDistCoeffs = Call("_VectorOf" & $typeOfDistCoeffs & "Create")

        $iArrDistCoeffsSize = UBound($distCoeffs)
        For $i = 0 To $iArrDistCoeffsSize - 1
            Call("_VectorOf" & $typeOfDistCoeffs & "Push", $vectorDistCoeffs, $distCoeffs[$i])
        Next

        $iArrDistCoeffs = Call("_cveInputArrayFromVectorOf" & $typeOfDistCoeffs, $vectorDistCoeffs)
    Else
        If $bDistCoeffsCreate Then
            $distCoeffs = Call("_cve" & $typeOfDistCoeffs & "Create", $distCoeffs)
        EndIf
        $iArrDistCoeffs = Call("_cveInputArrayFrom" & $typeOfDistCoeffs, $distCoeffs)
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

    Local $retval = _cveArucoEstimatePoseBoard($iArrCorners, $iArrIds, $board, $iArrCameraMatrix, $iArrDistCoeffs, $ioArrRvec, $ioArrTvec, $useExtrinsicGuess)

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

    If $bDistCoeffsIsArray Then
        Call("_VectorOf" & $typeOfDistCoeffs & "Release", $vectorDistCoeffs)
    EndIf

    If $typeOfDistCoeffs <> Default Then
        _cveInputArrayRelease($iArrDistCoeffs)
        If $bDistCoeffsCreate Then
            Call("_cve" & $typeOfDistCoeffs & "Release", $distCoeffs)
        EndIf
    EndIf

    If $bCameraMatrixIsArray Then
        Call("_VectorOf" & $typeOfCameraMatrix & "Release", $vectorCameraMatrix)
    EndIf

    If $typeOfCameraMatrix <> Default Then
        _cveInputArrayRelease($iArrCameraMatrix)
        If $bCameraMatrixCreate Then
            Call("_cve" & $typeOfCameraMatrix & "Release", $cameraMatrix)
        EndIf
    EndIf

    If $bIdsIsArray Then
        Call("_VectorOf" & $typeOfIds & "Release", $vectorIds)
    EndIf

    If $typeOfIds <> Default Then
        _cveInputArrayRelease($iArrIds)
        If $bIdsCreate Then
            Call("_cve" & $typeOfIds & "Release", $ids)
        EndIf
    EndIf

    If $bCornersIsArray Then
        Call("_VectorOf" & $typeOfCorners & "Release", $vectorCorners)
    EndIf

    If $typeOfCorners <> Default Then
        _cveInputArrayRelease($iArrCorners)
        If $bCornersCreate Then
            Call("_cve" & $typeOfCorners & "Release", $corners)
        EndIf
    EndIf

    Return $retval
EndFunc   ;==>_cveArucoEstimatePoseBoardTyped

Func _cveArucoEstimatePoseBoardMat($corners, $ids, $board, $cameraMatrix, $distCoeffs, $rvec, $tvec, $useExtrinsicGuess)
    ; cveArucoEstimatePoseBoard using cv::Mat instead of _*Array
    Local $retval = _cveArucoEstimatePoseBoardTyped("Mat", $corners, "Mat", $ids, $board, "Mat", $cameraMatrix, "Mat", $distCoeffs, "Mat", $rvec, "Mat", $tvec, $useExtrinsicGuess)

    Return $retval
EndFunc   ;==>_cveArucoEstimatePoseBoardMat

Func _cveArucoGetBoardObjectAndImagePoints($board, $detectedCorners, $detectedIds, $objPoints, $imgPoints)
    ; CVAPI(void) cveArucoGetBoardObjectAndImagePoints(cv::aruco::Board* board, cv::_InputArray* detectedCorners, cv::_InputArray* detectedIds, cv::_OutputArray* objPoints, cv::_OutputArray* imgPoints);

    Local $sBoardDllType
    If IsDllStruct($board) Then
        $sBoardDllType = "struct*"
    Else
        $sBoardDllType = "ptr"
    EndIf

    Local $sDetectedCornersDllType
    If IsDllStruct($detectedCorners) Then
        $sDetectedCornersDllType = "struct*"
    Else
        $sDetectedCornersDllType = "ptr"
    EndIf

    Local $sDetectedIdsDllType
    If IsDllStruct($detectedIds) Then
        $sDetectedIdsDllType = "struct*"
    Else
        $sDetectedIdsDllType = "ptr"
    EndIf

    Local $sObjPointsDllType
    If IsDllStruct($objPoints) Then
        $sObjPointsDllType = "struct*"
    Else
        $sObjPointsDllType = "ptr"
    EndIf

    Local $sImgPointsDllType
    If IsDllStruct($imgPoints) Then
        $sImgPointsDllType = "struct*"
    Else
        $sImgPointsDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveArucoGetBoardObjectAndImagePoints", $sBoardDllType, $board, $sDetectedCornersDllType, $detectedCorners, $sDetectedIdsDllType, $detectedIds, $sObjPointsDllType, $objPoints, $sImgPointsDllType, $imgPoints), "cveArucoGetBoardObjectAndImagePoints", @error)
EndFunc   ;==>_cveArucoGetBoardObjectAndImagePoints

Func _cveArucoGetBoardObjectAndImagePointsTyped($board, $typeOfDetectedCorners, $detectedCorners, $typeOfDetectedIds, $detectedIds, $typeOfObjPoints, $objPoints, $typeOfImgPoints, $imgPoints)

    Local $iArrDetectedCorners, $vectorDetectedCorners, $iArrDetectedCornersSize
    Local $bDetectedCornersIsArray = IsArray($detectedCorners)
    Local $bDetectedCornersCreate = IsDllStruct($detectedCorners) And $typeOfDetectedCorners == "Scalar"

    If $typeOfDetectedCorners == Default Then
        $iArrDetectedCorners = $detectedCorners
    ElseIf $bDetectedCornersIsArray Then
        $vectorDetectedCorners = Call("_VectorOf" & $typeOfDetectedCorners & "Create")

        $iArrDetectedCornersSize = UBound($detectedCorners)
        For $i = 0 To $iArrDetectedCornersSize - 1
            Call("_VectorOf" & $typeOfDetectedCorners & "Push", $vectorDetectedCorners, $detectedCorners[$i])
        Next

        $iArrDetectedCorners = Call("_cveInputArrayFromVectorOf" & $typeOfDetectedCorners, $vectorDetectedCorners)
    Else
        If $bDetectedCornersCreate Then
            $detectedCorners = Call("_cve" & $typeOfDetectedCorners & "Create", $detectedCorners)
        EndIf
        $iArrDetectedCorners = Call("_cveInputArrayFrom" & $typeOfDetectedCorners, $detectedCorners)
    EndIf

    Local $iArrDetectedIds, $vectorDetectedIds, $iArrDetectedIdsSize
    Local $bDetectedIdsIsArray = IsArray($detectedIds)
    Local $bDetectedIdsCreate = IsDllStruct($detectedIds) And $typeOfDetectedIds == "Scalar"

    If $typeOfDetectedIds == Default Then
        $iArrDetectedIds = $detectedIds
    ElseIf $bDetectedIdsIsArray Then
        $vectorDetectedIds = Call("_VectorOf" & $typeOfDetectedIds & "Create")

        $iArrDetectedIdsSize = UBound($detectedIds)
        For $i = 0 To $iArrDetectedIdsSize - 1
            Call("_VectorOf" & $typeOfDetectedIds & "Push", $vectorDetectedIds, $detectedIds[$i])
        Next

        $iArrDetectedIds = Call("_cveInputArrayFromVectorOf" & $typeOfDetectedIds, $vectorDetectedIds)
    Else
        If $bDetectedIdsCreate Then
            $detectedIds = Call("_cve" & $typeOfDetectedIds & "Create", $detectedIds)
        EndIf
        $iArrDetectedIds = Call("_cveInputArrayFrom" & $typeOfDetectedIds, $detectedIds)
    EndIf

    Local $oArrObjPoints, $vectorObjPoints, $iArrObjPointsSize
    Local $bObjPointsIsArray = IsArray($objPoints)
    Local $bObjPointsCreate = IsDllStruct($objPoints) And $typeOfObjPoints == "Scalar"

    If $typeOfObjPoints == Default Then
        $oArrObjPoints = $objPoints
    ElseIf $bObjPointsIsArray Then
        $vectorObjPoints = Call("_VectorOf" & $typeOfObjPoints & "Create")

        $iArrObjPointsSize = UBound($objPoints)
        For $i = 0 To $iArrObjPointsSize - 1
            Call("_VectorOf" & $typeOfObjPoints & "Push", $vectorObjPoints, $objPoints[$i])
        Next

        $oArrObjPoints = Call("_cveOutputArrayFromVectorOf" & $typeOfObjPoints, $vectorObjPoints)
    Else
        If $bObjPointsCreate Then
            $objPoints = Call("_cve" & $typeOfObjPoints & "Create", $objPoints)
        EndIf
        $oArrObjPoints = Call("_cveOutputArrayFrom" & $typeOfObjPoints, $objPoints)
    EndIf

    Local $oArrImgPoints, $vectorImgPoints, $iArrImgPointsSize
    Local $bImgPointsIsArray = IsArray($imgPoints)
    Local $bImgPointsCreate = IsDllStruct($imgPoints) And $typeOfImgPoints == "Scalar"

    If $typeOfImgPoints == Default Then
        $oArrImgPoints = $imgPoints
    ElseIf $bImgPointsIsArray Then
        $vectorImgPoints = Call("_VectorOf" & $typeOfImgPoints & "Create")

        $iArrImgPointsSize = UBound($imgPoints)
        For $i = 0 To $iArrImgPointsSize - 1
            Call("_VectorOf" & $typeOfImgPoints & "Push", $vectorImgPoints, $imgPoints[$i])
        Next

        $oArrImgPoints = Call("_cveOutputArrayFromVectorOf" & $typeOfImgPoints, $vectorImgPoints)
    Else
        If $bImgPointsCreate Then
            $imgPoints = Call("_cve" & $typeOfImgPoints & "Create", $imgPoints)
        EndIf
        $oArrImgPoints = Call("_cveOutputArrayFrom" & $typeOfImgPoints, $imgPoints)
    EndIf

    _cveArucoGetBoardObjectAndImagePoints($board, $iArrDetectedCorners, $iArrDetectedIds, $oArrObjPoints, $oArrImgPoints)

    If $bImgPointsIsArray Then
        Call("_VectorOf" & $typeOfImgPoints & "Release", $vectorImgPoints)
    EndIf

    If $typeOfImgPoints <> Default Then
        _cveOutputArrayRelease($oArrImgPoints)
        If $bImgPointsCreate Then
            Call("_cve" & $typeOfImgPoints & "Release", $imgPoints)
        EndIf
    EndIf

    If $bObjPointsIsArray Then
        Call("_VectorOf" & $typeOfObjPoints & "Release", $vectorObjPoints)
    EndIf

    If $typeOfObjPoints <> Default Then
        _cveOutputArrayRelease($oArrObjPoints)
        If $bObjPointsCreate Then
            Call("_cve" & $typeOfObjPoints & "Release", $objPoints)
        EndIf
    EndIf

    If $bDetectedIdsIsArray Then
        Call("_VectorOf" & $typeOfDetectedIds & "Release", $vectorDetectedIds)
    EndIf

    If $typeOfDetectedIds <> Default Then
        _cveInputArrayRelease($iArrDetectedIds)
        If $bDetectedIdsCreate Then
            Call("_cve" & $typeOfDetectedIds & "Release", $detectedIds)
        EndIf
    EndIf

    If $bDetectedCornersIsArray Then
        Call("_VectorOf" & $typeOfDetectedCorners & "Release", $vectorDetectedCorners)
    EndIf

    If $typeOfDetectedCorners <> Default Then
        _cveInputArrayRelease($iArrDetectedCorners)
        If $bDetectedCornersCreate Then
            Call("_cve" & $typeOfDetectedCorners & "Release", $detectedCorners)
        EndIf
    EndIf
EndFunc   ;==>_cveArucoGetBoardObjectAndImagePointsTyped

Func _cveArucoGetBoardObjectAndImagePointsMat($board, $detectedCorners, $detectedIds, $objPoints, $imgPoints)
    ; cveArucoGetBoardObjectAndImagePoints using cv::Mat instead of _*Array
    _cveArucoGetBoardObjectAndImagePointsTyped($board, "Mat", $detectedCorners, "Mat", $detectedIds, "Mat", $objPoints, "Mat", $imgPoints)
EndFunc   ;==>_cveArucoGetBoardObjectAndImagePointsMat