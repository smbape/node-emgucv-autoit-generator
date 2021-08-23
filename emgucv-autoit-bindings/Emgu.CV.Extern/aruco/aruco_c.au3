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

Func _cveArucoDrawMarkerMat($dictionary, $id, $sidePixels, $matImg, $borderBits)
    ; cveArucoDrawMarker using cv::Mat instead of _*Array

    Local $oArrImg, $vectorOfMatImg, $iArrImgSize
    Local $bImgIsArray = VarGetType($matImg) == "Array"

    If $bImgIsArray Then
        $vectorOfMatImg = _VectorOfMatCreate()

        $iArrImgSize = UBound($matImg)
        For $i = 0 To $iArrImgSize - 1
            _VectorOfMatPush($vectorOfMatImg, $matImg[$i])
        Next

        $oArrImg = _cveOutputArrayFromVectorOfMat($vectorOfMatImg)
    Else
        $oArrImg = _cveOutputArrayFromMat($matImg)
    EndIf

    _cveArucoDrawMarker($dictionary, $id, $sidePixels, $oArrImg, $borderBits)

    If $bImgIsArray Then
        _VectorOfMatRelease($vectorOfMatImg)
    EndIf

    _cveOutputArrayRelease($oArrImg)
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

Func _cveArucoDrawAxisMat($matImage, $matCameraMatrix, $matDistCoeffs, $matRvec, $matTvec, $length)
    ; cveArucoDrawAxis using cv::Mat instead of _*Array

    Local $ioArrImage, $vectorOfMatImage, $iArrImageSize
    Local $bImageIsArray = VarGetType($matImage) == "Array"

    If $bImageIsArray Then
        $vectorOfMatImage = _VectorOfMatCreate()

        $iArrImageSize = UBound($matImage)
        For $i = 0 To $iArrImageSize - 1
            _VectorOfMatPush($vectorOfMatImage, $matImage[$i])
        Next

        $ioArrImage = _cveInputOutputArrayFromVectorOfMat($vectorOfMatImage)
    Else
        $ioArrImage = _cveInputOutputArrayFromMat($matImage)
    EndIf

    Local $iArrCameraMatrix, $vectorOfMatCameraMatrix, $iArrCameraMatrixSize
    Local $bCameraMatrixIsArray = VarGetType($matCameraMatrix) == "Array"

    If $bCameraMatrixIsArray Then
        $vectorOfMatCameraMatrix = _VectorOfMatCreate()

        $iArrCameraMatrixSize = UBound($matCameraMatrix)
        For $i = 0 To $iArrCameraMatrixSize - 1
            _VectorOfMatPush($vectorOfMatCameraMatrix, $matCameraMatrix[$i])
        Next

        $iArrCameraMatrix = _cveInputArrayFromVectorOfMat($vectorOfMatCameraMatrix)
    Else
        $iArrCameraMatrix = _cveInputArrayFromMat($matCameraMatrix)
    EndIf

    Local $iArrDistCoeffs, $vectorOfMatDistCoeffs, $iArrDistCoeffsSize
    Local $bDistCoeffsIsArray = VarGetType($matDistCoeffs) == "Array"

    If $bDistCoeffsIsArray Then
        $vectorOfMatDistCoeffs = _VectorOfMatCreate()

        $iArrDistCoeffsSize = UBound($matDistCoeffs)
        For $i = 0 To $iArrDistCoeffsSize - 1
            _VectorOfMatPush($vectorOfMatDistCoeffs, $matDistCoeffs[$i])
        Next

        $iArrDistCoeffs = _cveInputArrayFromVectorOfMat($vectorOfMatDistCoeffs)
    Else
        $iArrDistCoeffs = _cveInputArrayFromMat($matDistCoeffs)
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

    _cveArucoDrawAxis($ioArrImage, $iArrCameraMatrix, $iArrDistCoeffs, $iArrRvec, $iArrTvec, $length)

    If $bTvecIsArray Then
        _VectorOfMatRelease($vectorOfMatTvec)
    EndIf

    _cveInputArrayRelease($iArrTvec)

    If $bRvecIsArray Then
        _VectorOfMatRelease($vectorOfMatRvec)
    EndIf

    _cveInputArrayRelease($iArrRvec)

    If $bDistCoeffsIsArray Then
        _VectorOfMatRelease($vectorOfMatDistCoeffs)
    EndIf

    _cveInputArrayRelease($iArrDistCoeffs)

    If $bCameraMatrixIsArray Then
        _VectorOfMatRelease($vectorOfMatCameraMatrix)
    EndIf

    _cveInputArrayRelease($iArrCameraMatrix)

    If $bImageIsArray Then
        _VectorOfMatRelease($vectorOfMatImage)
    EndIf

    _cveInputOutputArrayRelease($ioArrImage)
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

Func _cveArucoDetectMarkersMat($matImage, $dictionary, $matCorners, $matIds, $parameters, $matRejectedImgPoints)
    ; cveArucoDetectMarkers using cv::Mat instead of _*Array

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

    Local $oArrCorners, $vectorOfMatCorners, $iArrCornersSize
    Local $bCornersIsArray = VarGetType($matCorners) == "Array"

    If $bCornersIsArray Then
        $vectorOfMatCorners = _VectorOfMatCreate()

        $iArrCornersSize = UBound($matCorners)
        For $i = 0 To $iArrCornersSize - 1
            _VectorOfMatPush($vectorOfMatCorners, $matCorners[$i])
        Next

        $oArrCorners = _cveOutputArrayFromVectorOfMat($vectorOfMatCorners)
    Else
        $oArrCorners = _cveOutputArrayFromMat($matCorners)
    EndIf

    Local $oArrIds, $vectorOfMatIds, $iArrIdsSize
    Local $bIdsIsArray = VarGetType($matIds) == "Array"

    If $bIdsIsArray Then
        $vectorOfMatIds = _VectorOfMatCreate()

        $iArrIdsSize = UBound($matIds)
        For $i = 0 To $iArrIdsSize - 1
            _VectorOfMatPush($vectorOfMatIds, $matIds[$i])
        Next

        $oArrIds = _cveOutputArrayFromVectorOfMat($vectorOfMatIds)
    Else
        $oArrIds = _cveOutputArrayFromMat($matIds)
    EndIf

    Local $oArrRejectedImgPoints, $vectorOfMatRejectedImgPoints, $iArrRejectedImgPointsSize
    Local $bRejectedImgPointsIsArray = VarGetType($matRejectedImgPoints) == "Array"

    If $bRejectedImgPointsIsArray Then
        $vectorOfMatRejectedImgPoints = _VectorOfMatCreate()

        $iArrRejectedImgPointsSize = UBound($matRejectedImgPoints)
        For $i = 0 To $iArrRejectedImgPointsSize - 1
            _VectorOfMatPush($vectorOfMatRejectedImgPoints, $matRejectedImgPoints[$i])
        Next

        $oArrRejectedImgPoints = _cveOutputArrayFromVectorOfMat($vectorOfMatRejectedImgPoints)
    Else
        $oArrRejectedImgPoints = _cveOutputArrayFromMat($matRejectedImgPoints)
    EndIf

    _cveArucoDetectMarkers($iArrImage, $dictionary, $oArrCorners, $oArrIds, $parameters, $oArrRejectedImgPoints)

    If $bRejectedImgPointsIsArray Then
        _VectorOfMatRelease($vectorOfMatRejectedImgPoints)
    EndIf

    _cveOutputArrayRelease($oArrRejectedImgPoints)

    If $bIdsIsArray Then
        _VectorOfMatRelease($vectorOfMatIds)
    EndIf

    _cveOutputArrayRelease($oArrIds)

    If $bCornersIsArray Then
        _VectorOfMatRelease($vectorOfMatCorners)
    EndIf

    _cveOutputArrayRelease($oArrCorners)

    If $bImageIsArray Then
        _VectorOfMatRelease($vectorOfMatImage)
    EndIf

    _cveInputArrayRelease($iArrImage)
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

Func _cveArucoEstimatePoseSingleMarkersMat($matCorners, $markerLength, $matCameraMatrix, $matDistCoeffs, $matRvecs, $matTvecs)
    ; cveArucoEstimatePoseSingleMarkers using cv::Mat instead of _*Array

    Local $iArrCorners, $vectorOfMatCorners, $iArrCornersSize
    Local $bCornersIsArray = VarGetType($matCorners) == "Array"

    If $bCornersIsArray Then
        $vectorOfMatCorners = _VectorOfMatCreate()

        $iArrCornersSize = UBound($matCorners)
        For $i = 0 To $iArrCornersSize - 1
            _VectorOfMatPush($vectorOfMatCorners, $matCorners[$i])
        Next

        $iArrCorners = _cveInputArrayFromVectorOfMat($vectorOfMatCorners)
    Else
        $iArrCorners = _cveInputArrayFromMat($matCorners)
    EndIf

    Local $iArrCameraMatrix, $vectorOfMatCameraMatrix, $iArrCameraMatrixSize
    Local $bCameraMatrixIsArray = VarGetType($matCameraMatrix) == "Array"

    If $bCameraMatrixIsArray Then
        $vectorOfMatCameraMatrix = _VectorOfMatCreate()

        $iArrCameraMatrixSize = UBound($matCameraMatrix)
        For $i = 0 To $iArrCameraMatrixSize - 1
            _VectorOfMatPush($vectorOfMatCameraMatrix, $matCameraMatrix[$i])
        Next

        $iArrCameraMatrix = _cveInputArrayFromVectorOfMat($vectorOfMatCameraMatrix)
    Else
        $iArrCameraMatrix = _cveInputArrayFromMat($matCameraMatrix)
    EndIf

    Local $iArrDistCoeffs, $vectorOfMatDistCoeffs, $iArrDistCoeffsSize
    Local $bDistCoeffsIsArray = VarGetType($matDistCoeffs) == "Array"

    If $bDistCoeffsIsArray Then
        $vectorOfMatDistCoeffs = _VectorOfMatCreate()

        $iArrDistCoeffsSize = UBound($matDistCoeffs)
        For $i = 0 To $iArrDistCoeffsSize - 1
            _VectorOfMatPush($vectorOfMatDistCoeffs, $matDistCoeffs[$i])
        Next

        $iArrDistCoeffs = _cveInputArrayFromVectorOfMat($vectorOfMatDistCoeffs)
    Else
        $iArrDistCoeffs = _cveInputArrayFromMat($matDistCoeffs)
    EndIf

    Local $oArrRvecs, $vectorOfMatRvecs, $iArrRvecsSize
    Local $bRvecsIsArray = VarGetType($matRvecs) == "Array"

    If $bRvecsIsArray Then
        $vectorOfMatRvecs = _VectorOfMatCreate()

        $iArrRvecsSize = UBound($matRvecs)
        For $i = 0 To $iArrRvecsSize - 1
            _VectorOfMatPush($vectorOfMatRvecs, $matRvecs[$i])
        Next

        $oArrRvecs = _cveOutputArrayFromVectorOfMat($vectorOfMatRvecs)
    Else
        $oArrRvecs = _cveOutputArrayFromMat($matRvecs)
    EndIf

    Local $oArrTvecs, $vectorOfMatTvecs, $iArrTvecsSize
    Local $bTvecsIsArray = VarGetType($matTvecs) == "Array"

    If $bTvecsIsArray Then
        $vectorOfMatTvecs = _VectorOfMatCreate()

        $iArrTvecsSize = UBound($matTvecs)
        For $i = 0 To $iArrTvecsSize - 1
            _VectorOfMatPush($vectorOfMatTvecs, $matTvecs[$i])
        Next

        $oArrTvecs = _cveOutputArrayFromVectorOfMat($vectorOfMatTvecs)
    Else
        $oArrTvecs = _cveOutputArrayFromMat($matTvecs)
    EndIf

    _cveArucoEstimatePoseSingleMarkers($iArrCorners, $markerLength, $iArrCameraMatrix, $iArrDistCoeffs, $oArrRvecs, $oArrTvecs)

    If $bTvecsIsArray Then
        _VectorOfMatRelease($vectorOfMatTvecs)
    EndIf

    _cveOutputArrayRelease($oArrTvecs)

    If $bRvecsIsArray Then
        _VectorOfMatRelease($vectorOfMatRvecs)
    EndIf

    _cveOutputArrayRelease($oArrRvecs)

    If $bDistCoeffsIsArray Then
        _VectorOfMatRelease($vectorOfMatDistCoeffs)
    EndIf

    _cveInputArrayRelease($iArrDistCoeffs)

    If $bCameraMatrixIsArray Then
        _VectorOfMatRelease($vectorOfMatCameraMatrix)
    EndIf

    _cveInputArrayRelease($iArrCameraMatrix)

    If $bCornersIsArray Then
        _VectorOfMatRelease($vectorOfMatCorners)
    EndIf

    _cveInputArrayRelease($iArrCorners)
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

Func _cveArucoGridBoardDrawMat($gridBoard, $outSize, $matImg, $marginSize, $borderBits)
    ; cveArucoGridBoardDraw using cv::Mat instead of _*Array

    Local $oArrImg, $vectorOfMatImg, $iArrImgSize
    Local $bImgIsArray = VarGetType($matImg) == "Array"

    If $bImgIsArray Then
        $vectorOfMatImg = _VectorOfMatCreate()

        $iArrImgSize = UBound($matImg)
        For $i = 0 To $iArrImgSize - 1
            _VectorOfMatPush($vectorOfMatImg, $matImg[$i])
        Next

        $oArrImg = _cveOutputArrayFromVectorOfMat($vectorOfMatImg)
    Else
        $oArrImg = _cveOutputArrayFromMat($matImg)
    EndIf

    _cveArucoGridBoardDraw($gridBoard, $outSize, $oArrImg, $marginSize, $borderBits)

    If $bImgIsArray Then
        _VectorOfMatRelease($vectorOfMatImg)
    EndIf

    _cveOutputArrayRelease($oArrImg)
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

Func _cveCharucoBoardDrawMat($charucoBoard, $outSize, $matImg, $marginSize, $borderBits)
    ; cveCharucoBoardDraw using cv::Mat instead of _*Array

    Local $oArrImg, $vectorOfMatImg, $iArrImgSize
    Local $bImgIsArray = VarGetType($matImg) == "Array"

    If $bImgIsArray Then
        $vectorOfMatImg = _VectorOfMatCreate()

        $iArrImgSize = UBound($matImg)
        For $i = 0 To $iArrImgSize - 1
            _VectorOfMatPush($vectorOfMatImg, $matImg[$i])
        Next

        $oArrImg = _cveOutputArrayFromVectorOfMat($vectorOfMatImg)
    Else
        $oArrImg = _cveOutputArrayFromMat($matImg)
    EndIf

    _cveCharucoBoardDraw($charucoBoard, $outSize, $oArrImg, $marginSize, $borderBits)

    If $bImgIsArray Then
        _VectorOfMatRelease($vectorOfMatImg)
    EndIf

    _cveOutputArrayRelease($oArrImg)
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

Func _cveArucoRefineDetectedMarkersMat($matImage, $board, $matDetectedCorners, $matDetectedIds, $matRejectedCorners, $matCameraMatrix, $matDistCoeffs, $minRepDistance, $errorCorrectionRate, $checkAllOrders, $matRecoveredIdxs, $parameters)
    ; cveArucoRefineDetectedMarkers using cv::Mat instead of _*Array

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

    Local $ioArrDetectedCorners, $vectorOfMatDetectedCorners, $iArrDetectedCornersSize
    Local $bDetectedCornersIsArray = VarGetType($matDetectedCorners) == "Array"

    If $bDetectedCornersIsArray Then
        $vectorOfMatDetectedCorners = _VectorOfMatCreate()

        $iArrDetectedCornersSize = UBound($matDetectedCorners)
        For $i = 0 To $iArrDetectedCornersSize - 1
            _VectorOfMatPush($vectorOfMatDetectedCorners, $matDetectedCorners[$i])
        Next

        $ioArrDetectedCorners = _cveInputOutputArrayFromVectorOfMat($vectorOfMatDetectedCorners)
    Else
        $ioArrDetectedCorners = _cveInputOutputArrayFromMat($matDetectedCorners)
    EndIf

    Local $ioArrDetectedIds, $vectorOfMatDetectedIds, $iArrDetectedIdsSize
    Local $bDetectedIdsIsArray = VarGetType($matDetectedIds) == "Array"

    If $bDetectedIdsIsArray Then
        $vectorOfMatDetectedIds = _VectorOfMatCreate()

        $iArrDetectedIdsSize = UBound($matDetectedIds)
        For $i = 0 To $iArrDetectedIdsSize - 1
            _VectorOfMatPush($vectorOfMatDetectedIds, $matDetectedIds[$i])
        Next

        $ioArrDetectedIds = _cveInputOutputArrayFromVectorOfMat($vectorOfMatDetectedIds)
    Else
        $ioArrDetectedIds = _cveInputOutputArrayFromMat($matDetectedIds)
    EndIf

    Local $ioArrRejectedCorners, $vectorOfMatRejectedCorners, $iArrRejectedCornersSize
    Local $bRejectedCornersIsArray = VarGetType($matRejectedCorners) == "Array"

    If $bRejectedCornersIsArray Then
        $vectorOfMatRejectedCorners = _VectorOfMatCreate()

        $iArrRejectedCornersSize = UBound($matRejectedCorners)
        For $i = 0 To $iArrRejectedCornersSize - 1
            _VectorOfMatPush($vectorOfMatRejectedCorners, $matRejectedCorners[$i])
        Next

        $ioArrRejectedCorners = _cveInputOutputArrayFromVectorOfMat($vectorOfMatRejectedCorners)
    Else
        $ioArrRejectedCorners = _cveInputOutputArrayFromMat($matRejectedCorners)
    EndIf

    Local $iArrCameraMatrix, $vectorOfMatCameraMatrix, $iArrCameraMatrixSize
    Local $bCameraMatrixIsArray = VarGetType($matCameraMatrix) == "Array"

    If $bCameraMatrixIsArray Then
        $vectorOfMatCameraMatrix = _VectorOfMatCreate()

        $iArrCameraMatrixSize = UBound($matCameraMatrix)
        For $i = 0 To $iArrCameraMatrixSize - 1
            _VectorOfMatPush($vectorOfMatCameraMatrix, $matCameraMatrix[$i])
        Next

        $iArrCameraMatrix = _cveInputArrayFromVectorOfMat($vectorOfMatCameraMatrix)
    Else
        $iArrCameraMatrix = _cveInputArrayFromMat($matCameraMatrix)
    EndIf

    Local $iArrDistCoeffs, $vectorOfMatDistCoeffs, $iArrDistCoeffsSize
    Local $bDistCoeffsIsArray = VarGetType($matDistCoeffs) == "Array"

    If $bDistCoeffsIsArray Then
        $vectorOfMatDistCoeffs = _VectorOfMatCreate()

        $iArrDistCoeffsSize = UBound($matDistCoeffs)
        For $i = 0 To $iArrDistCoeffsSize - 1
            _VectorOfMatPush($vectorOfMatDistCoeffs, $matDistCoeffs[$i])
        Next

        $iArrDistCoeffs = _cveInputArrayFromVectorOfMat($vectorOfMatDistCoeffs)
    Else
        $iArrDistCoeffs = _cveInputArrayFromMat($matDistCoeffs)
    EndIf

    Local $oArrRecoveredIdxs, $vectorOfMatRecoveredIdxs, $iArrRecoveredIdxsSize
    Local $bRecoveredIdxsIsArray = VarGetType($matRecoveredIdxs) == "Array"

    If $bRecoveredIdxsIsArray Then
        $vectorOfMatRecoveredIdxs = _VectorOfMatCreate()

        $iArrRecoveredIdxsSize = UBound($matRecoveredIdxs)
        For $i = 0 To $iArrRecoveredIdxsSize - 1
            _VectorOfMatPush($vectorOfMatRecoveredIdxs, $matRecoveredIdxs[$i])
        Next

        $oArrRecoveredIdxs = _cveOutputArrayFromVectorOfMat($vectorOfMatRecoveredIdxs)
    Else
        $oArrRecoveredIdxs = _cveOutputArrayFromMat($matRecoveredIdxs)
    EndIf

    _cveArucoRefineDetectedMarkers($iArrImage, $board, $ioArrDetectedCorners, $ioArrDetectedIds, $ioArrRejectedCorners, $iArrCameraMatrix, $iArrDistCoeffs, $minRepDistance, $errorCorrectionRate, $checkAllOrders, $oArrRecoveredIdxs, $parameters)

    If $bRecoveredIdxsIsArray Then
        _VectorOfMatRelease($vectorOfMatRecoveredIdxs)
    EndIf

    _cveOutputArrayRelease($oArrRecoveredIdxs)

    If $bDistCoeffsIsArray Then
        _VectorOfMatRelease($vectorOfMatDistCoeffs)
    EndIf

    _cveInputArrayRelease($iArrDistCoeffs)

    If $bCameraMatrixIsArray Then
        _VectorOfMatRelease($vectorOfMatCameraMatrix)
    EndIf

    _cveInputArrayRelease($iArrCameraMatrix)

    If $bRejectedCornersIsArray Then
        _VectorOfMatRelease($vectorOfMatRejectedCorners)
    EndIf

    _cveInputOutputArrayRelease($ioArrRejectedCorners)

    If $bDetectedIdsIsArray Then
        _VectorOfMatRelease($vectorOfMatDetectedIds)
    EndIf

    _cveInputOutputArrayRelease($ioArrDetectedIds)

    If $bDetectedCornersIsArray Then
        _VectorOfMatRelease($vectorOfMatDetectedCorners)
    EndIf

    _cveInputOutputArrayRelease($ioArrDetectedCorners)

    If $bImageIsArray Then
        _VectorOfMatRelease($vectorOfMatImage)
    EndIf

    _cveInputArrayRelease($iArrImage)
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

Func _cveArucoDrawDetectedMarkersMat($matImage, $matCorners, $matIds, $borderColor)
    ; cveArucoDrawDetectedMarkers using cv::Mat instead of _*Array

    Local $ioArrImage, $vectorOfMatImage, $iArrImageSize
    Local $bImageIsArray = VarGetType($matImage) == "Array"

    If $bImageIsArray Then
        $vectorOfMatImage = _VectorOfMatCreate()

        $iArrImageSize = UBound($matImage)
        For $i = 0 To $iArrImageSize - 1
            _VectorOfMatPush($vectorOfMatImage, $matImage[$i])
        Next

        $ioArrImage = _cveInputOutputArrayFromVectorOfMat($vectorOfMatImage)
    Else
        $ioArrImage = _cveInputOutputArrayFromMat($matImage)
    EndIf

    Local $iArrCorners, $vectorOfMatCorners, $iArrCornersSize
    Local $bCornersIsArray = VarGetType($matCorners) == "Array"

    If $bCornersIsArray Then
        $vectorOfMatCorners = _VectorOfMatCreate()

        $iArrCornersSize = UBound($matCorners)
        For $i = 0 To $iArrCornersSize - 1
            _VectorOfMatPush($vectorOfMatCorners, $matCorners[$i])
        Next

        $iArrCorners = _cveInputArrayFromVectorOfMat($vectorOfMatCorners)
    Else
        $iArrCorners = _cveInputArrayFromMat($matCorners)
    EndIf

    Local $iArrIds, $vectorOfMatIds, $iArrIdsSize
    Local $bIdsIsArray = VarGetType($matIds) == "Array"

    If $bIdsIsArray Then
        $vectorOfMatIds = _VectorOfMatCreate()

        $iArrIdsSize = UBound($matIds)
        For $i = 0 To $iArrIdsSize - 1
            _VectorOfMatPush($vectorOfMatIds, $matIds[$i])
        Next

        $iArrIds = _cveInputArrayFromVectorOfMat($vectorOfMatIds)
    Else
        $iArrIds = _cveInputArrayFromMat($matIds)
    EndIf

    _cveArucoDrawDetectedMarkers($ioArrImage, $iArrCorners, $iArrIds, $borderColor)

    If $bIdsIsArray Then
        _VectorOfMatRelease($vectorOfMatIds)
    EndIf

    _cveInputArrayRelease($iArrIds)

    If $bCornersIsArray Then
        _VectorOfMatRelease($vectorOfMatCorners)
    EndIf

    _cveInputArrayRelease($iArrCorners)

    If $bImageIsArray Then
        _VectorOfMatRelease($vectorOfMatImage)
    EndIf

    _cveInputOutputArrayRelease($ioArrImage)
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

Func _cveArucoCalibrateCameraArucoMat($matCorners, $matIds, $matCounter, $board, $imageSize, $matCameraMatrix, $matDistCoeffs, $matRvecs, $matTvecs, $matStdDeviationsIntrinsics, $matStdDeviationsExtrinsics, $matPerViewErrors, $flags, $criteria)
    ; cveArucoCalibrateCameraAruco using cv::Mat instead of _*Array

    Local $iArrCorners, $vectorOfMatCorners, $iArrCornersSize
    Local $bCornersIsArray = VarGetType($matCorners) == "Array"

    If $bCornersIsArray Then
        $vectorOfMatCorners = _VectorOfMatCreate()

        $iArrCornersSize = UBound($matCorners)
        For $i = 0 To $iArrCornersSize - 1
            _VectorOfMatPush($vectorOfMatCorners, $matCorners[$i])
        Next

        $iArrCorners = _cveInputArrayFromVectorOfMat($vectorOfMatCorners)
    Else
        $iArrCorners = _cveInputArrayFromMat($matCorners)
    EndIf

    Local $iArrIds, $vectorOfMatIds, $iArrIdsSize
    Local $bIdsIsArray = VarGetType($matIds) == "Array"

    If $bIdsIsArray Then
        $vectorOfMatIds = _VectorOfMatCreate()

        $iArrIdsSize = UBound($matIds)
        For $i = 0 To $iArrIdsSize - 1
            _VectorOfMatPush($vectorOfMatIds, $matIds[$i])
        Next

        $iArrIds = _cveInputArrayFromVectorOfMat($vectorOfMatIds)
    Else
        $iArrIds = _cveInputArrayFromMat($matIds)
    EndIf

    Local $iArrCounter, $vectorOfMatCounter, $iArrCounterSize
    Local $bCounterIsArray = VarGetType($matCounter) == "Array"

    If $bCounterIsArray Then
        $vectorOfMatCounter = _VectorOfMatCreate()

        $iArrCounterSize = UBound($matCounter)
        For $i = 0 To $iArrCounterSize - 1
            _VectorOfMatPush($vectorOfMatCounter, $matCounter[$i])
        Next

        $iArrCounter = _cveInputArrayFromVectorOfMat($vectorOfMatCounter)
    Else
        $iArrCounter = _cveInputArrayFromMat($matCounter)
    EndIf

    Local $ioArrCameraMatrix, $vectorOfMatCameraMatrix, $iArrCameraMatrixSize
    Local $bCameraMatrixIsArray = VarGetType($matCameraMatrix) == "Array"

    If $bCameraMatrixIsArray Then
        $vectorOfMatCameraMatrix = _VectorOfMatCreate()

        $iArrCameraMatrixSize = UBound($matCameraMatrix)
        For $i = 0 To $iArrCameraMatrixSize - 1
            _VectorOfMatPush($vectorOfMatCameraMatrix, $matCameraMatrix[$i])
        Next

        $ioArrCameraMatrix = _cveInputOutputArrayFromVectorOfMat($vectorOfMatCameraMatrix)
    Else
        $ioArrCameraMatrix = _cveInputOutputArrayFromMat($matCameraMatrix)
    EndIf

    Local $ioArrDistCoeffs, $vectorOfMatDistCoeffs, $iArrDistCoeffsSize
    Local $bDistCoeffsIsArray = VarGetType($matDistCoeffs) == "Array"

    If $bDistCoeffsIsArray Then
        $vectorOfMatDistCoeffs = _VectorOfMatCreate()

        $iArrDistCoeffsSize = UBound($matDistCoeffs)
        For $i = 0 To $iArrDistCoeffsSize - 1
            _VectorOfMatPush($vectorOfMatDistCoeffs, $matDistCoeffs[$i])
        Next

        $ioArrDistCoeffs = _cveInputOutputArrayFromVectorOfMat($vectorOfMatDistCoeffs)
    Else
        $ioArrDistCoeffs = _cveInputOutputArrayFromMat($matDistCoeffs)
    EndIf

    Local $oArrRvecs, $vectorOfMatRvecs, $iArrRvecsSize
    Local $bRvecsIsArray = VarGetType($matRvecs) == "Array"

    If $bRvecsIsArray Then
        $vectorOfMatRvecs = _VectorOfMatCreate()

        $iArrRvecsSize = UBound($matRvecs)
        For $i = 0 To $iArrRvecsSize - 1
            _VectorOfMatPush($vectorOfMatRvecs, $matRvecs[$i])
        Next

        $oArrRvecs = _cveOutputArrayFromVectorOfMat($vectorOfMatRvecs)
    Else
        $oArrRvecs = _cveOutputArrayFromMat($matRvecs)
    EndIf

    Local $oArrTvecs, $vectorOfMatTvecs, $iArrTvecsSize
    Local $bTvecsIsArray = VarGetType($matTvecs) == "Array"

    If $bTvecsIsArray Then
        $vectorOfMatTvecs = _VectorOfMatCreate()

        $iArrTvecsSize = UBound($matTvecs)
        For $i = 0 To $iArrTvecsSize - 1
            _VectorOfMatPush($vectorOfMatTvecs, $matTvecs[$i])
        Next

        $oArrTvecs = _cveOutputArrayFromVectorOfMat($vectorOfMatTvecs)
    Else
        $oArrTvecs = _cveOutputArrayFromMat($matTvecs)
    EndIf

    Local $oArrStdDeviationsIntrinsics, $vectorOfMatStdDeviationsIntrinsics, $iArrStdDeviationsIntrinsicsSize
    Local $bStdDeviationsIntrinsicsIsArray = VarGetType($matStdDeviationsIntrinsics) == "Array"

    If $bStdDeviationsIntrinsicsIsArray Then
        $vectorOfMatStdDeviationsIntrinsics = _VectorOfMatCreate()

        $iArrStdDeviationsIntrinsicsSize = UBound($matStdDeviationsIntrinsics)
        For $i = 0 To $iArrStdDeviationsIntrinsicsSize - 1
            _VectorOfMatPush($vectorOfMatStdDeviationsIntrinsics, $matStdDeviationsIntrinsics[$i])
        Next

        $oArrStdDeviationsIntrinsics = _cveOutputArrayFromVectorOfMat($vectorOfMatStdDeviationsIntrinsics)
    Else
        $oArrStdDeviationsIntrinsics = _cveOutputArrayFromMat($matStdDeviationsIntrinsics)
    EndIf

    Local $oArrStdDeviationsExtrinsics, $vectorOfMatStdDeviationsExtrinsics, $iArrStdDeviationsExtrinsicsSize
    Local $bStdDeviationsExtrinsicsIsArray = VarGetType($matStdDeviationsExtrinsics) == "Array"

    If $bStdDeviationsExtrinsicsIsArray Then
        $vectorOfMatStdDeviationsExtrinsics = _VectorOfMatCreate()

        $iArrStdDeviationsExtrinsicsSize = UBound($matStdDeviationsExtrinsics)
        For $i = 0 To $iArrStdDeviationsExtrinsicsSize - 1
            _VectorOfMatPush($vectorOfMatStdDeviationsExtrinsics, $matStdDeviationsExtrinsics[$i])
        Next

        $oArrStdDeviationsExtrinsics = _cveOutputArrayFromVectorOfMat($vectorOfMatStdDeviationsExtrinsics)
    Else
        $oArrStdDeviationsExtrinsics = _cveOutputArrayFromMat($matStdDeviationsExtrinsics)
    EndIf

    Local $oArrPerViewErrors, $vectorOfMatPerViewErrors, $iArrPerViewErrorsSize
    Local $bPerViewErrorsIsArray = VarGetType($matPerViewErrors) == "Array"

    If $bPerViewErrorsIsArray Then
        $vectorOfMatPerViewErrors = _VectorOfMatCreate()

        $iArrPerViewErrorsSize = UBound($matPerViewErrors)
        For $i = 0 To $iArrPerViewErrorsSize - 1
            _VectorOfMatPush($vectorOfMatPerViewErrors, $matPerViewErrors[$i])
        Next

        $oArrPerViewErrors = _cveOutputArrayFromVectorOfMat($vectorOfMatPerViewErrors)
    Else
        $oArrPerViewErrors = _cveOutputArrayFromMat($matPerViewErrors)
    EndIf

    Local $retval = _cveArucoCalibrateCameraAruco($iArrCorners, $iArrIds, $iArrCounter, $board, $imageSize, $ioArrCameraMatrix, $ioArrDistCoeffs, $oArrRvecs, $oArrTvecs, $oArrStdDeviationsIntrinsics, $oArrStdDeviationsExtrinsics, $oArrPerViewErrors, $flags, $criteria)

    If $bPerViewErrorsIsArray Then
        _VectorOfMatRelease($vectorOfMatPerViewErrors)
    EndIf

    _cveOutputArrayRelease($oArrPerViewErrors)

    If $bStdDeviationsExtrinsicsIsArray Then
        _VectorOfMatRelease($vectorOfMatStdDeviationsExtrinsics)
    EndIf

    _cveOutputArrayRelease($oArrStdDeviationsExtrinsics)

    If $bStdDeviationsIntrinsicsIsArray Then
        _VectorOfMatRelease($vectorOfMatStdDeviationsIntrinsics)
    EndIf

    _cveOutputArrayRelease($oArrStdDeviationsIntrinsics)

    If $bTvecsIsArray Then
        _VectorOfMatRelease($vectorOfMatTvecs)
    EndIf

    _cveOutputArrayRelease($oArrTvecs)

    If $bRvecsIsArray Then
        _VectorOfMatRelease($vectorOfMatRvecs)
    EndIf

    _cveOutputArrayRelease($oArrRvecs)

    If $bDistCoeffsIsArray Then
        _VectorOfMatRelease($vectorOfMatDistCoeffs)
    EndIf

    _cveInputOutputArrayRelease($ioArrDistCoeffs)

    If $bCameraMatrixIsArray Then
        _VectorOfMatRelease($vectorOfMatCameraMatrix)
    EndIf

    _cveInputOutputArrayRelease($ioArrCameraMatrix)

    If $bCounterIsArray Then
        _VectorOfMatRelease($vectorOfMatCounter)
    EndIf

    _cveInputArrayRelease($iArrCounter)

    If $bIdsIsArray Then
        _VectorOfMatRelease($vectorOfMatIds)
    EndIf

    _cveInputArrayRelease($iArrIds)

    If $bCornersIsArray Then
        _VectorOfMatRelease($vectorOfMatCorners)
    EndIf

    _cveInputArrayRelease($iArrCorners)

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

Func _cveArucoCalibrateCameraCharucoMat($matCharucoCorners, $matCharucoIds, $board, $imageSize, $matCameraMatrix, $matDistCoeffs, $matRvecs, $matTvecs, $matStdDeviationsIntrinsics, $matStdDeviationsExtrinsics, $matPerViewErrors, $flags, $criteria)
    ; cveArucoCalibrateCameraCharuco using cv::Mat instead of _*Array

    Local $iArrCharucoCorners, $vectorOfMatCharucoCorners, $iArrCharucoCornersSize
    Local $bCharucoCornersIsArray = VarGetType($matCharucoCorners) == "Array"

    If $bCharucoCornersIsArray Then
        $vectorOfMatCharucoCorners = _VectorOfMatCreate()

        $iArrCharucoCornersSize = UBound($matCharucoCorners)
        For $i = 0 To $iArrCharucoCornersSize - 1
            _VectorOfMatPush($vectorOfMatCharucoCorners, $matCharucoCorners[$i])
        Next

        $iArrCharucoCorners = _cveInputArrayFromVectorOfMat($vectorOfMatCharucoCorners)
    Else
        $iArrCharucoCorners = _cveInputArrayFromMat($matCharucoCorners)
    EndIf

    Local $iArrCharucoIds, $vectorOfMatCharucoIds, $iArrCharucoIdsSize
    Local $bCharucoIdsIsArray = VarGetType($matCharucoIds) == "Array"

    If $bCharucoIdsIsArray Then
        $vectorOfMatCharucoIds = _VectorOfMatCreate()

        $iArrCharucoIdsSize = UBound($matCharucoIds)
        For $i = 0 To $iArrCharucoIdsSize - 1
            _VectorOfMatPush($vectorOfMatCharucoIds, $matCharucoIds[$i])
        Next

        $iArrCharucoIds = _cveInputArrayFromVectorOfMat($vectorOfMatCharucoIds)
    Else
        $iArrCharucoIds = _cveInputArrayFromMat($matCharucoIds)
    EndIf

    Local $ioArrCameraMatrix, $vectorOfMatCameraMatrix, $iArrCameraMatrixSize
    Local $bCameraMatrixIsArray = VarGetType($matCameraMatrix) == "Array"

    If $bCameraMatrixIsArray Then
        $vectorOfMatCameraMatrix = _VectorOfMatCreate()

        $iArrCameraMatrixSize = UBound($matCameraMatrix)
        For $i = 0 To $iArrCameraMatrixSize - 1
            _VectorOfMatPush($vectorOfMatCameraMatrix, $matCameraMatrix[$i])
        Next

        $ioArrCameraMatrix = _cveInputOutputArrayFromVectorOfMat($vectorOfMatCameraMatrix)
    Else
        $ioArrCameraMatrix = _cveInputOutputArrayFromMat($matCameraMatrix)
    EndIf

    Local $ioArrDistCoeffs, $vectorOfMatDistCoeffs, $iArrDistCoeffsSize
    Local $bDistCoeffsIsArray = VarGetType($matDistCoeffs) == "Array"

    If $bDistCoeffsIsArray Then
        $vectorOfMatDistCoeffs = _VectorOfMatCreate()

        $iArrDistCoeffsSize = UBound($matDistCoeffs)
        For $i = 0 To $iArrDistCoeffsSize - 1
            _VectorOfMatPush($vectorOfMatDistCoeffs, $matDistCoeffs[$i])
        Next

        $ioArrDistCoeffs = _cveInputOutputArrayFromVectorOfMat($vectorOfMatDistCoeffs)
    Else
        $ioArrDistCoeffs = _cveInputOutputArrayFromMat($matDistCoeffs)
    EndIf

    Local $oArrRvecs, $vectorOfMatRvecs, $iArrRvecsSize
    Local $bRvecsIsArray = VarGetType($matRvecs) == "Array"

    If $bRvecsIsArray Then
        $vectorOfMatRvecs = _VectorOfMatCreate()

        $iArrRvecsSize = UBound($matRvecs)
        For $i = 0 To $iArrRvecsSize - 1
            _VectorOfMatPush($vectorOfMatRvecs, $matRvecs[$i])
        Next

        $oArrRvecs = _cveOutputArrayFromVectorOfMat($vectorOfMatRvecs)
    Else
        $oArrRvecs = _cveOutputArrayFromMat($matRvecs)
    EndIf

    Local $oArrTvecs, $vectorOfMatTvecs, $iArrTvecsSize
    Local $bTvecsIsArray = VarGetType($matTvecs) == "Array"

    If $bTvecsIsArray Then
        $vectorOfMatTvecs = _VectorOfMatCreate()

        $iArrTvecsSize = UBound($matTvecs)
        For $i = 0 To $iArrTvecsSize - 1
            _VectorOfMatPush($vectorOfMatTvecs, $matTvecs[$i])
        Next

        $oArrTvecs = _cveOutputArrayFromVectorOfMat($vectorOfMatTvecs)
    Else
        $oArrTvecs = _cveOutputArrayFromMat($matTvecs)
    EndIf

    Local $oArrStdDeviationsIntrinsics, $vectorOfMatStdDeviationsIntrinsics, $iArrStdDeviationsIntrinsicsSize
    Local $bStdDeviationsIntrinsicsIsArray = VarGetType($matStdDeviationsIntrinsics) == "Array"

    If $bStdDeviationsIntrinsicsIsArray Then
        $vectorOfMatStdDeviationsIntrinsics = _VectorOfMatCreate()

        $iArrStdDeviationsIntrinsicsSize = UBound($matStdDeviationsIntrinsics)
        For $i = 0 To $iArrStdDeviationsIntrinsicsSize - 1
            _VectorOfMatPush($vectorOfMatStdDeviationsIntrinsics, $matStdDeviationsIntrinsics[$i])
        Next

        $oArrStdDeviationsIntrinsics = _cveOutputArrayFromVectorOfMat($vectorOfMatStdDeviationsIntrinsics)
    Else
        $oArrStdDeviationsIntrinsics = _cveOutputArrayFromMat($matStdDeviationsIntrinsics)
    EndIf

    Local $oArrStdDeviationsExtrinsics, $vectorOfMatStdDeviationsExtrinsics, $iArrStdDeviationsExtrinsicsSize
    Local $bStdDeviationsExtrinsicsIsArray = VarGetType($matStdDeviationsExtrinsics) == "Array"

    If $bStdDeviationsExtrinsicsIsArray Then
        $vectorOfMatStdDeviationsExtrinsics = _VectorOfMatCreate()

        $iArrStdDeviationsExtrinsicsSize = UBound($matStdDeviationsExtrinsics)
        For $i = 0 To $iArrStdDeviationsExtrinsicsSize - 1
            _VectorOfMatPush($vectorOfMatStdDeviationsExtrinsics, $matStdDeviationsExtrinsics[$i])
        Next

        $oArrStdDeviationsExtrinsics = _cveOutputArrayFromVectorOfMat($vectorOfMatStdDeviationsExtrinsics)
    Else
        $oArrStdDeviationsExtrinsics = _cveOutputArrayFromMat($matStdDeviationsExtrinsics)
    EndIf

    Local $oArrPerViewErrors, $vectorOfMatPerViewErrors, $iArrPerViewErrorsSize
    Local $bPerViewErrorsIsArray = VarGetType($matPerViewErrors) == "Array"

    If $bPerViewErrorsIsArray Then
        $vectorOfMatPerViewErrors = _VectorOfMatCreate()

        $iArrPerViewErrorsSize = UBound($matPerViewErrors)
        For $i = 0 To $iArrPerViewErrorsSize - 1
            _VectorOfMatPush($vectorOfMatPerViewErrors, $matPerViewErrors[$i])
        Next

        $oArrPerViewErrors = _cveOutputArrayFromVectorOfMat($vectorOfMatPerViewErrors)
    Else
        $oArrPerViewErrors = _cveOutputArrayFromMat($matPerViewErrors)
    EndIf

    Local $retval = _cveArucoCalibrateCameraCharuco($iArrCharucoCorners, $iArrCharucoIds, $board, $imageSize, $ioArrCameraMatrix, $ioArrDistCoeffs, $oArrRvecs, $oArrTvecs, $oArrStdDeviationsIntrinsics, $oArrStdDeviationsExtrinsics, $oArrPerViewErrors, $flags, $criteria)

    If $bPerViewErrorsIsArray Then
        _VectorOfMatRelease($vectorOfMatPerViewErrors)
    EndIf

    _cveOutputArrayRelease($oArrPerViewErrors)

    If $bStdDeviationsExtrinsicsIsArray Then
        _VectorOfMatRelease($vectorOfMatStdDeviationsExtrinsics)
    EndIf

    _cveOutputArrayRelease($oArrStdDeviationsExtrinsics)

    If $bStdDeviationsIntrinsicsIsArray Then
        _VectorOfMatRelease($vectorOfMatStdDeviationsIntrinsics)
    EndIf

    _cveOutputArrayRelease($oArrStdDeviationsIntrinsics)

    If $bTvecsIsArray Then
        _VectorOfMatRelease($vectorOfMatTvecs)
    EndIf

    _cveOutputArrayRelease($oArrTvecs)

    If $bRvecsIsArray Then
        _VectorOfMatRelease($vectorOfMatRvecs)
    EndIf

    _cveOutputArrayRelease($oArrRvecs)

    If $bDistCoeffsIsArray Then
        _VectorOfMatRelease($vectorOfMatDistCoeffs)
    EndIf

    _cveInputOutputArrayRelease($ioArrDistCoeffs)

    If $bCameraMatrixIsArray Then
        _VectorOfMatRelease($vectorOfMatCameraMatrix)
    EndIf

    _cveInputOutputArrayRelease($ioArrCameraMatrix)

    If $bCharucoIdsIsArray Then
        _VectorOfMatRelease($vectorOfMatCharucoIds)
    EndIf

    _cveInputArrayRelease($iArrCharucoIds)

    If $bCharucoCornersIsArray Then
        _VectorOfMatRelease($vectorOfMatCharucoCorners)
    EndIf

    _cveInputArrayRelease($iArrCharucoCorners)

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

Func _cveArucoInterpolateCornersCharucoMat($matMarkerCorners, $matMarkerIds, $matImage, $board, $matCharucoCorners, $matCharucoIds, $matCameraMatrix, $matDistCoeffs, $minMarkers)
    ; cveArucoInterpolateCornersCharuco using cv::Mat instead of _*Array

    Local $iArrMarkerCorners, $vectorOfMatMarkerCorners, $iArrMarkerCornersSize
    Local $bMarkerCornersIsArray = VarGetType($matMarkerCorners) == "Array"

    If $bMarkerCornersIsArray Then
        $vectorOfMatMarkerCorners = _VectorOfMatCreate()

        $iArrMarkerCornersSize = UBound($matMarkerCorners)
        For $i = 0 To $iArrMarkerCornersSize - 1
            _VectorOfMatPush($vectorOfMatMarkerCorners, $matMarkerCorners[$i])
        Next

        $iArrMarkerCorners = _cveInputArrayFromVectorOfMat($vectorOfMatMarkerCorners)
    Else
        $iArrMarkerCorners = _cveInputArrayFromMat($matMarkerCorners)
    EndIf

    Local $iArrMarkerIds, $vectorOfMatMarkerIds, $iArrMarkerIdsSize
    Local $bMarkerIdsIsArray = VarGetType($matMarkerIds) == "Array"

    If $bMarkerIdsIsArray Then
        $vectorOfMatMarkerIds = _VectorOfMatCreate()

        $iArrMarkerIdsSize = UBound($matMarkerIds)
        For $i = 0 To $iArrMarkerIdsSize - 1
            _VectorOfMatPush($vectorOfMatMarkerIds, $matMarkerIds[$i])
        Next

        $iArrMarkerIds = _cveInputArrayFromVectorOfMat($vectorOfMatMarkerIds)
    Else
        $iArrMarkerIds = _cveInputArrayFromMat($matMarkerIds)
    EndIf

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

    Local $oArrCharucoCorners, $vectorOfMatCharucoCorners, $iArrCharucoCornersSize
    Local $bCharucoCornersIsArray = VarGetType($matCharucoCorners) == "Array"

    If $bCharucoCornersIsArray Then
        $vectorOfMatCharucoCorners = _VectorOfMatCreate()

        $iArrCharucoCornersSize = UBound($matCharucoCorners)
        For $i = 0 To $iArrCharucoCornersSize - 1
            _VectorOfMatPush($vectorOfMatCharucoCorners, $matCharucoCorners[$i])
        Next

        $oArrCharucoCorners = _cveOutputArrayFromVectorOfMat($vectorOfMatCharucoCorners)
    Else
        $oArrCharucoCorners = _cveOutputArrayFromMat($matCharucoCorners)
    EndIf

    Local $oArrCharucoIds, $vectorOfMatCharucoIds, $iArrCharucoIdsSize
    Local $bCharucoIdsIsArray = VarGetType($matCharucoIds) == "Array"

    If $bCharucoIdsIsArray Then
        $vectorOfMatCharucoIds = _VectorOfMatCreate()

        $iArrCharucoIdsSize = UBound($matCharucoIds)
        For $i = 0 To $iArrCharucoIdsSize - 1
            _VectorOfMatPush($vectorOfMatCharucoIds, $matCharucoIds[$i])
        Next

        $oArrCharucoIds = _cveOutputArrayFromVectorOfMat($vectorOfMatCharucoIds)
    Else
        $oArrCharucoIds = _cveOutputArrayFromMat($matCharucoIds)
    EndIf

    Local $iArrCameraMatrix, $vectorOfMatCameraMatrix, $iArrCameraMatrixSize
    Local $bCameraMatrixIsArray = VarGetType($matCameraMatrix) == "Array"

    If $bCameraMatrixIsArray Then
        $vectorOfMatCameraMatrix = _VectorOfMatCreate()

        $iArrCameraMatrixSize = UBound($matCameraMatrix)
        For $i = 0 To $iArrCameraMatrixSize - 1
            _VectorOfMatPush($vectorOfMatCameraMatrix, $matCameraMatrix[$i])
        Next

        $iArrCameraMatrix = _cveInputArrayFromVectorOfMat($vectorOfMatCameraMatrix)
    Else
        $iArrCameraMatrix = _cveInputArrayFromMat($matCameraMatrix)
    EndIf

    Local $iArrDistCoeffs, $vectorOfMatDistCoeffs, $iArrDistCoeffsSize
    Local $bDistCoeffsIsArray = VarGetType($matDistCoeffs) == "Array"

    If $bDistCoeffsIsArray Then
        $vectorOfMatDistCoeffs = _VectorOfMatCreate()

        $iArrDistCoeffsSize = UBound($matDistCoeffs)
        For $i = 0 To $iArrDistCoeffsSize - 1
            _VectorOfMatPush($vectorOfMatDistCoeffs, $matDistCoeffs[$i])
        Next

        $iArrDistCoeffs = _cveInputArrayFromVectorOfMat($vectorOfMatDistCoeffs)
    Else
        $iArrDistCoeffs = _cveInputArrayFromMat($matDistCoeffs)
    EndIf

    Local $retval = _cveArucoInterpolateCornersCharuco($iArrMarkerCorners, $iArrMarkerIds, $iArrImage, $board, $oArrCharucoCorners, $oArrCharucoIds, $iArrCameraMatrix, $iArrDistCoeffs, $minMarkers)

    If $bDistCoeffsIsArray Then
        _VectorOfMatRelease($vectorOfMatDistCoeffs)
    EndIf

    _cveInputArrayRelease($iArrDistCoeffs)

    If $bCameraMatrixIsArray Then
        _VectorOfMatRelease($vectorOfMatCameraMatrix)
    EndIf

    _cveInputArrayRelease($iArrCameraMatrix)

    If $bCharucoIdsIsArray Then
        _VectorOfMatRelease($vectorOfMatCharucoIds)
    EndIf

    _cveOutputArrayRelease($oArrCharucoIds)

    If $bCharucoCornersIsArray Then
        _VectorOfMatRelease($vectorOfMatCharucoCorners)
    EndIf

    _cveOutputArrayRelease($oArrCharucoCorners)

    If $bImageIsArray Then
        _VectorOfMatRelease($vectorOfMatImage)
    EndIf

    _cveInputArrayRelease($iArrImage)

    If $bMarkerIdsIsArray Then
        _VectorOfMatRelease($vectorOfMatMarkerIds)
    EndIf

    _cveInputArrayRelease($iArrMarkerIds)

    If $bMarkerCornersIsArray Then
        _VectorOfMatRelease($vectorOfMatMarkerCorners)
    EndIf

    _cveInputArrayRelease($iArrMarkerCorners)

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

Func _cveArucoDrawDetectedCornersCharucoMat($matImage, $matCharucoCorners, $matCharucoIds, $cornerColor)
    ; cveArucoDrawDetectedCornersCharuco using cv::Mat instead of _*Array

    Local $ioArrImage, $vectorOfMatImage, $iArrImageSize
    Local $bImageIsArray = VarGetType($matImage) == "Array"

    If $bImageIsArray Then
        $vectorOfMatImage = _VectorOfMatCreate()

        $iArrImageSize = UBound($matImage)
        For $i = 0 To $iArrImageSize - 1
            _VectorOfMatPush($vectorOfMatImage, $matImage[$i])
        Next

        $ioArrImage = _cveInputOutputArrayFromVectorOfMat($vectorOfMatImage)
    Else
        $ioArrImage = _cveInputOutputArrayFromMat($matImage)
    EndIf

    Local $iArrCharucoCorners, $vectorOfMatCharucoCorners, $iArrCharucoCornersSize
    Local $bCharucoCornersIsArray = VarGetType($matCharucoCorners) == "Array"

    If $bCharucoCornersIsArray Then
        $vectorOfMatCharucoCorners = _VectorOfMatCreate()

        $iArrCharucoCornersSize = UBound($matCharucoCorners)
        For $i = 0 To $iArrCharucoCornersSize - 1
            _VectorOfMatPush($vectorOfMatCharucoCorners, $matCharucoCorners[$i])
        Next

        $iArrCharucoCorners = _cveInputArrayFromVectorOfMat($vectorOfMatCharucoCorners)
    Else
        $iArrCharucoCorners = _cveInputArrayFromMat($matCharucoCorners)
    EndIf

    Local $iArrCharucoIds, $vectorOfMatCharucoIds, $iArrCharucoIdsSize
    Local $bCharucoIdsIsArray = VarGetType($matCharucoIds) == "Array"

    If $bCharucoIdsIsArray Then
        $vectorOfMatCharucoIds = _VectorOfMatCreate()

        $iArrCharucoIdsSize = UBound($matCharucoIds)
        For $i = 0 To $iArrCharucoIdsSize - 1
            _VectorOfMatPush($vectorOfMatCharucoIds, $matCharucoIds[$i])
        Next

        $iArrCharucoIds = _cveInputArrayFromVectorOfMat($vectorOfMatCharucoIds)
    Else
        $iArrCharucoIds = _cveInputArrayFromMat($matCharucoIds)
    EndIf

    _cveArucoDrawDetectedCornersCharuco($ioArrImage, $iArrCharucoCorners, $iArrCharucoIds, $cornerColor)

    If $bCharucoIdsIsArray Then
        _VectorOfMatRelease($vectorOfMatCharucoIds)
    EndIf

    _cveInputArrayRelease($iArrCharucoIds)

    If $bCharucoCornersIsArray Then
        _VectorOfMatRelease($vectorOfMatCharucoCorners)
    EndIf

    _cveInputArrayRelease($iArrCharucoCorners)

    If $bImageIsArray Then
        _VectorOfMatRelease($vectorOfMatImage)
    EndIf

    _cveInputOutputArrayRelease($ioArrImage)
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

Func _cveArucoEstimatePoseCharucoBoardMat($matCharucoCorners, $matCharucoIds, $board, $matCameraMatrix, $matDistCoeffs, $matRvec, $matTvec, $useExtrinsicGuess)
    ; cveArucoEstimatePoseCharucoBoard using cv::Mat instead of _*Array

    Local $iArrCharucoCorners, $vectorOfMatCharucoCorners, $iArrCharucoCornersSize
    Local $bCharucoCornersIsArray = VarGetType($matCharucoCorners) == "Array"

    If $bCharucoCornersIsArray Then
        $vectorOfMatCharucoCorners = _VectorOfMatCreate()

        $iArrCharucoCornersSize = UBound($matCharucoCorners)
        For $i = 0 To $iArrCharucoCornersSize - 1
            _VectorOfMatPush($vectorOfMatCharucoCorners, $matCharucoCorners[$i])
        Next

        $iArrCharucoCorners = _cveInputArrayFromVectorOfMat($vectorOfMatCharucoCorners)
    Else
        $iArrCharucoCorners = _cveInputArrayFromMat($matCharucoCorners)
    EndIf

    Local $iArrCharucoIds, $vectorOfMatCharucoIds, $iArrCharucoIdsSize
    Local $bCharucoIdsIsArray = VarGetType($matCharucoIds) == "Array"

    If $bCharucoIdsIsArray Then
        $vectorOfMatCharucoIds = _VectorOfMatCreate()

        $iArrCharucoIdsSize = UBound($matCharucoIds)
        For $i = 0 To $iArrCharucoIdsSize - 1
            _VectorOfMatPush($vectorOfMatCharucoIds, $matCharucoIds[$i])
        Next

        $iArrCharucoIds = _cveInputArrayFromVectorOfMat($vectorOfMatCharucoIds)
    Else
        $iArrCharucoIds = _cveInputArrayFromMat($matCharucoIds)
    EndIf

    Local $iArrCameraMatrix, $vectorOfMatCameraMatrix, $iArrCameraMatrixSize
    Local $bCameraMatrixIsArray = VarGetType($matCameraMatrix) == "Array"

    If $bCameraMatrixIsArray Then
        $vectorOfMatCameraMatrix = _VectorOfMatCreate()

        $iArrCameraMatrixSize = UBound($matCameraMatrix)
        For $i = 0 To $iArrCameraMatrixSize - 1
            _VectorOfMatPush($vectorOfMatCameraMatrix, $matCameraMatrix[$i])
        Next

        $iArrCameraMatrix = _cveInputArrayFromVectorOfMat($vectorOfMatCameraMatrix)
    Else
        $iArrCameraMatrix = _cveInputArrayFromMat($matCameraMatrix)
    EndIf

    Local $iArrDistCoeffs, $vectorOfMatDistCoeffs, $iArrDistCoeffsSize
    Local $bDistCoeffsIsArray = VarGetType($matDistCoeffs) == "Array"

    If $bDistCoeffsIsArray Then
        $vectorOfMatDistCoeffs = _VectorOfMatCreate()

        $iArrDistCoeffsSize = UBound($matDistCoeffs)
        For $i = 0 To $iArrDistCoeffsSize - 1
            _VectorOfMatPush($vectorOfMatDistCoeffs, $matDistCoeffs[$i])
        Next

        $iArrDistCoeffs = _cveInputArrayFromVectorOfMat($vectorOfMatDistCoeffs)
    Else
        $iArrDistCoeffs = _cveInputArrayFromMat($matDistCoeffs)
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

    Local $retval = _cveArucoEstimatePoseCharucoBoard($iArrCharucoCorners, $iArrCharucoIds, $board, $iArrCameraMatrix, $iArrDistCoeffs, $ioArrRvec, $ioArrTvec, $useExtrinsicGuess)

    If $bTvecIsArray Then
        _VectorOfMatRelease($vectorOfMatTvec)
    EndIf

    _cveInputOutputArrayRelease($ioArrTvec)

    If $bRvecIsArray Then
        _VectorOfMatRelease($vectorOfMatRvec)
    EndIf

    _cveInputOutputArrayRelease($ioArrRvec)

    If $bDistCoeffsIsArray Then
        _VectorOfMatRelease($vectorOfMatDistCoeffs)
    EndIf

    _cveInputArrayRelease($iArrDistCoeffs)

    If $bCameraMatrixIsArray Then
        _VectorOfMatRelease($vectorOfMatCameraMatrix)
    EndIf

    _cveInputArrayRelease($iArrCameraMatrix)

    If $bCharucoIdsIsArray Then
        _VectorOfMatRelease($vectorOfMatCharucoIds)
    EndIf

    _cveInputArrayRelease($iArrCharucoIds)

    If $bCharucoCornersIsArray Then
        _VectorOfMatRelease($vectorOfMatCharucoCorners)
    EndIf

    _cveInputArrayRelease($iArrCharucoCorners)

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

Func _cveArucoDetectCharucoDiamondMat($matImage, $matMarkerCorners, $matMarkerIds, $squareMarkerLengthRate, $matDiamondCorners, $matDiamondIds, $matCameraMatrix, $matDistCoeffs)
    ; cveArucoDetectCharucoDiamond using cv::Mat instead of _*Array

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

    Local $iArrMarkerCorners, $vectorOfMatMarkerCorners, $iArrMarkerCornersSize
    Local $bMarkerCornersIsArray = VarGetType($matMarkerCorners) == "Array"

    If $bMarkerCornersIsArray Then
        $vectorOfMatMarkerCorners = _VectorOfMatCreate()

        $iArrMarkerCornersSize = UBound($matMarkerCorners)
        For $i = 0 To $iArrMarkerCornersSize - 1
            _VectorOfMatPush($vectorOfMatMarkerCorners, $matMarkerCorners[$i])
        Next

        $iArrMarkerCorners = _cveInputArrayFromVectorOfMat($vectorOfMatMarkerCorners)
    Else
        $iArrMarkerCorners = _cveInputArrayFromMat($matMarkerCorners)
    EndIf

    Local $iArrMarkerIds, $vectorOfMatMarkerIds, $iArrMarkerIdsSize
    Local $bMarkerIdsIsArray = VarGetType($matMarkerIds) == "Array"

    If $bMarkerIdsIsArray Then
        $vectorOfMatMarkerIds = _VectorOfMatCreate()

        $iArrMarkerIdsSize = UBound($matMarkerIds)
        For $i = 0 To $iArrMarkerIdsSize - 1
            _VectorOfMatPush($vectorOfMatMarkerIds, $matMarkerIds[$i])
        Next

        $iArrMarkerIds = _cveInputArrayFromVectorOfMat($vectorOfMatMarkerIds)
    Else
        $iArrMarkerIds = _cveInputArrayFromMat($matMarkerIds)
    EndIf

    Local $oArrDiamondCorners, $vectorOfMatDiamondCorners, $iArrDiamondCornersSize
    Local $bDiamondCornersIsArray = VarGetType($matDiamondCorners) == "Array"

    If $bDiamondCornersIsArray Then
        $vectorOfMatDiamondCorners = _VectorOfMatCreate()

        $iArrDiamondCornersSize = UBound($matDiamondCorners)
        For $i = 0 To $iArrDiamondCornersSize - 1
            _VectorOfMatPush($vectorOfMatDiamondCorners, $matDiamondCorners[$i])
        Next

        $oArrDiamondCorners = _cveOutputArrayFromVectorOfMat($vectorOfMatDiamondCorners)
    Else
        $oArrDiamondCorners = _cveOutputArrayFromMat($matDiamondCorners)
    EndIf

    Local $oArrDiamondIds, $vectorOfMatDiamondIds, $iArrDiamondIdsSize
    Local $bDiamondIdsIsArray = VarGetType($matDiamondIds) == "Array"

    If $bDiamondIdsIsArray Then
        $vectorOfMatDiamondIds = _VectorOfMatCreate()

        $iArrDiamondIdsSize = UBound($matDiamondIds)
        For $i = 0 To $iArrDiamondIdsSize - 1
            _VectorOfMatPush($vectorOfMatDiamondIds, $matDiamondIds[$i])
        Next

        $oArrDiamondIds = _cveOutputArrayFromVectorOfMat($vectorOfMatDiamondIds)
    Else
        $oArrDiamondIds = _cveOutputArrayFromMat($matDiamondIds)
    EndIf

    Local $iArrCameraMatrix, $vectorOfMatCameraMatrix, $iArrCameraMatrixSize
    Local $bCameraMatrixIsArray = VarGetType($matCameraMatrix) == "Array"

    If $bCameraMatrixIsArray Then
        $vectorOfMatCameraMatrix = _VectorOfMatCreate()

        $iArrCameraMatrixSize = UBound($matCameraMatrix)
        For $i = 0 To $iArrCameraMatrixSize - 1
            _VectorOfMatPush($vectorOfMatCameraMatrix, $matCameraMatrix[$i])
        Next

        $iArrCameraMatrix = _cveInputArrayFromVectorOfMat($vectorOfMatCameraMatrix)
    Else
        $iArrCameraMatrix = _cveInputArrayFromMat($matCameraMatrix)
    EndIf

    Local $iArrDistCoeffs, $vectorOfMatDistCoeffs, $iArrDistCoeffsSize
    Local $bDistCoeffsIsArray = VarGetType($matDistCoeffs) == "Array"

    If $bDistCoeffsIsArray Then
        $vectorOfMatDistCoeffs = _VectorOfMatCreate()

        $iArrDistCoeffsSize = UBound($matDistCoeffs)
        For $i = 0 To $iArrDistCoeffsSize - 1
            _VectorOfMatPush($vectorOfMatDistCoeffs, $matDistCoeffs[$i])
        Next

        $iArrDistCoeffs = _cveInputArrayFromVectorOfMat($vectorOfMatDistCoeffs)
    Else
        $iArrDistCoeffs = _cveInputArrayFromMat($matDistCoeffs)
    EndIf

    _cveArucoDetectCharucoDiamond($iArrImage, $iArrMarkerCorners, $iArrMarkerIds, $squareMarkerLengthRate, $oArrDiamondCorners, $oArrDiamondIds, $iArrCameraMatrix, $iArrDistCoeffs)

    If $bDistCoeffsIsArray Then
        _VectorOfMatRelease($vectorOfMatDistCoeffs)
    EndIf

    _cveInputArrayRelease($iArrDistCoeffs)

    If $bCameraMatrixIsArray Then
        _VectorOfMatRelease($vectorOfMatCameraMatrix)
    EndIf

    _cveInputArrayRelease($iArrCameraMatrix)

    If $bDiamondIdsIsArray Then
        _VectorOfMatRelease($vectorOfMatDiamondIds)
    EndIf

    _cveOutputArrayRelease($oArrDiamondIds)

    If $bDiamondCornersIsArray Then
        _VectorOfMatRelease($vectorOfMatDiamondCorners)
    EndIf

    _cveOutputArrayRelease($oArrDiamondCorners)

    If $bMarkerIdsIsArray Then
        _VectorOfMatRelease($vectorOfMatMarkerIds)
    EndIf

    _cveInputArrayRelease($iArrMarkerIds)

    If $bMarkerCornersIsArray Then
        _VectorOfMatRelease($vectorOfMatMarkerCorners)
    EndIf

    _cveInputArrayRelease($iArrMarkerCorners)

    If $bImageIsArray Then
        _VectorOfMatRelease($vectorOfMatImage)
    EndIf

    _cveInputArrayRelease($iArrImage)
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

Func _cveArucoDrawDetectedDiamondsMat($matImage, $matDiamondCorners, $matDiamondIds, $borderColor)
    ; cveArucoDrawDetectedDiamonds using cv::Mat instead of _*Array

    Local $ioArrImage, $vectorOfMatImage, $iArrImageSize
    Local $bImageIsArray = VarGetType($matImage) == "Array"

    If $bImageIsArray Then
        $vectorOfMatImage = _VectorOfMatCreate()

        $iArrImageSize = UBound($matImage)
        For $i = 0 To $iArrImageSize - 1
            _VectorOfMatPush($vectorOfMatImage, $matImage[$i])
        Next

        $ioArrImage = _cveInputOutputArrayFromVectorOfMat($vectorOfMatImage)
    Else
        $ioArrImage = _cveInputOutputArrayFromMat($matImage)
    EndIf

    Local $iArrDiamondCorners, $vectorOfMatDiamondCorners, $iArrDiamondCornersSize
    Local $bDiamondCornersIsArray = VarGetType($matDiamondCorners) == "Array"

    If $bDiamondCornersIsArray Then
        $vectorOfMatDiamondCorners = _VectorOfMatCreate()

        $iArrDiamondCornersSize = UBound($matDiamondCorners)
        For $i = 0 To $iArrDiamondCornersSize - 1
            _VectorOfMatPush($vectorOfMatDiamondCorners, $matDiamondCorners[$i])
        Next

        $iArrDiamondCorners = _cveInputArrayFromVectorOfMat($vectorOfMatDiamondCorners)
    Else
        $iArrDiamondCorners = _cveInputArrayFromMat($matDiamondCorners)
    EndIf

    Local $iArrDiamondIds, $vectorOfMatDiamondIds, $iArrDiamondIdsSize
    Local $bDiamondIdsIsArray = VarGetType($matDiamondIds) == "Array"

    If $bDiamondIdsIsArray Then
        $vectorOfMatDiamondIds = _VectorOfMatCreate()

        $iArrDiamondIdsSize = UBound($matDiamondIds)
        For $i = 0 To $iArrDiamondIdsSize - 1
            _VectorOfMatPush($vectorOfMatDiamondIds, $matDiamondIds[$i])
        Next

        $iArrDiamondIds = _cveInputArrayFromVectorOfMat($vectorOfMatDiamondIds)
    Else
        $iArrDiamondIds = _cveInputArrayFromMat($matDiamondIds)
    EndIf

    _cveArucoDrawDetectedDiamonds($ioArrImage, $iArrDiamondCorners, $iArrDiamondIds, $borderColor)

    If $bDiamondIdsIsArray Then
        _VectorOfMatRelease($vectorOfMatDiamondIds)
    EndIf

    _cveInputArrayRelease($iArrDiamondIds)

    If $bDiamondCornersIsArray Then
        _VectorOfMatRelease($vectorOfMatDiamondCorners)
    EndIf

    _cveInputArrayRelease($iArrDiamondCorners)

    If $bImageIsArray Then
        _VectorOfMatRelease($vectorOfMatImage)
    EndIf

    _cveInputOutputArrayRelease($ioArrImage)
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

Func _cveArucoDrawCharucoDiamondMat($dictionary, $ids, $squareLength, $markerLength, $matImg, $marginSize, $borderBits)
    ; cveArucoDrawCharucoDiamond using cv::Mat instead of _*Array

    Local $oArrImg, $vectorOfMatImg, $iArrImgSize
    Local $bImgIsArray = VarGetType($matImg) == "Array"

    If $bImgIsArray Then
        $vectorOfMatImg = _VectorOfMatCreate()

        $iArrImgSize = UBound($matImg)
        For $i = 0 To $iArrImgSize - 1
            _VectorOfMatPush($vectorOfMatImg, $matImg[$i])
        Next

        $oArrImg = _cveOutputArrayFromVectorOfMat($vectorOfMatImg)
    Else
        $oArrImg = _cveOutputArrayFromMat($matImg)
    EndIf

    _cveArucoDrawCharucoDiamond($dictionary, $ids, $squareLength, $markerLength, $oArrImg, $marginSize, $borderBits)

    If $bImgIsArray Then
        _VectorOfMatRelease($vectorOfMatImg)
    EndIf

    _cveOutputArrayRelease($oArrImg)
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

Func _cveArucoDrawPlanarBoardMat($board, $outSize, $matImg, $marginSize, $borderBits)
    ; cveArucoDrawPlanarBoard using cv::Mat instead of _*Array

    Local $oArrImg, $vectorOfMatImg, $iArrImgSize
    Local $bImgIsArray = VarGetType($matImg) == "Array"

    If $bImgIsArray Then
        $vectorOfMatImg = _VectorOfMatCreate()

        $iArrImgSize = UBound($matImg)
        For $i = 0 To $iArrImgSize - 1
            _VectorOfMatPush($vectorOfMatImg, $matImg[$i])
        Next

        $oArrImg = _cveOutputArrayFromVectorOfMat($vectorOfMatImg)
    Else
        $oArrImg = _cveOutputArrayFromMat($matImg)
    EndIf

    _cveArucoDrawPlanarBoard($board, $outSize, $oArrImg, $marginSize, $borderBits)

    If $bImgIsArray Then
        _VectorOfMatRelease($vectorOfMatImg)
    EndIf

    _cveOutputArrayRelease($oArrImg)
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

Func _cveArucoEstimatePoseBoardMat($matCorners, $matIds, $board, $matCameraMatrix, $matDistCoeffs, $matRvec, $matTvec, $useExtrinsicGuess)
    ; cveArucoEstimatePoseBoard using cv::Mat instead of _*Array

    Local $iArrCorners, $vectorOfMatCorners, $iArrCornersSize
    Local $bCornersIsArray = VarGetType($matCorners) == "Array"

    If $bCornersIsArray Then
        $vectorOfMatCorners = _VectorOfMatCreate()

        $iArrCornersSize = UBound($matCorners)
        For $i = 0 To $iArrCornersSize - 1
            _VectorOfMatPush($vectorOfMatCorners, $matCorners[$i])
        Next

        $iArrCorners = _cveInputArrayFromVectorOfMat($vectorOfMatCorners)
    Else
        $iArrCorners = _cveInputArrayFromMat($matCorners)
    EndIf

    Local $iArrIds, $vectorOfMatIds, $iArrIdsSize
    Local $bIdsIsArray = VarGetType($matIds) == "Array"

    If $bIdsIsArray Then
        $vectorOfMatIds = _VectorOfMatCreate()

        $iArrIdsSize = UBound($matIds)
        For $i = 0 To $iArrIdsSize - 1
            _VectorOfMatPush($vectorOfMatIds, $matIds[$i])
        Next

        $iArrIds = _cveInputArrayFromVectorOfMat($vectorOfMatIds)
    Else
        $iArrIds = _cveInputArrayFromMat($matIds)
    EndIf

    Local $iArrCameraMatrix, $vectorOfMatCameraMatrix, $iArrCameraMatrixSize
    Local $bCameraMatrixIsArray = VarGetType($matCameraMatrix) == "Array"

    If $bCameraMatrixIsArray Then
        $vectorOfMatCameraMatrix = _VectorOfMatCreate()

        $iArrCameraMatrixSize = UBound($matCameraMatrix)
        For $i = 0 To $iArrCameraMatrixSize - 1
            _VectorOfMatPush($vectorOfMatCameraMatrix, $matCameraMatrix[$i])
        Next

        $iArrCameraMatrix = _cveInputArrayFromVectorOfMat($vectorOfMatCameraMatrix)
    Else
        $iArrCameraMatrix = _cveInputArrayFromMat($matCameraMatrix)
    EndIf

    Local $iArrDistCoeffs, $vectorOfMatDistCoeffs, $iArrDistCoeffsSize
    Local $bDistCoeffsIsArray = VarGetType($matDistCoeffs) == "Array"

    If $bDistCoeffsIsArray Then
        $vectorOfMatDistCoeffs = _VectorOfMatCreate()

        $iArrDistCoeffsSize = UBound($matDistCoeffs)
        For $i = 0 To $iArrDistCoeffsSize - 1
            _VectorOfMatPush($vectorOfMatDistCoeffs, $matDistCoeffs[$i])
        Next

        $iArrDistCoeffs = _cveInputArrayFromVectorOfMat($vectorOfMatDistCoeffs)
    Else
        $iArrDistCoeffs = _cveInputArrayFromMat($matDistCoeffs)
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

    Local $retval = _cveArucoEstimatePoseBoard($iArrCorners, $iArrIds, $board, $iArrCameraMatrix, $iArrDistCoeffs, $ioArrRvec, $ioArrTvec, $useExtrinsicGuess)

    If $bTvecIsArray Then
        _VectorOfMatRelease($vectorOfMatTvec)
    EndIf

    _cveInputOutputArrayRelease($ioArrTvec)

    If $bRvecIsArray Then
        _VectorOfMatRelease($vectorOfMatRvec)
    EndIf

    _cveInputOutputArrayRelease($ioArrRvec)

    If $bDistCoeffsIsArray Then
        _VectorOfMatRelease($vectorOfMatDistCoeffs)
    EndIf

    _cveInputArrayRelease($iArrDistCoeffs)

    If $bCameraMatrixIsArray Then
        _VectorOfMatRelease($vectorOfMatCameraMatrix)
    EndIf

    _cveInputArrayRelease($iArrCameraMatrix)

    If $bIdsIsArray Then
        _VectorOfMatRelease($vectorOfMatIds)
    EndIf

    _cveInputArrayRelease($iArrIds)

    If $bCornersIsArray Then
        _VectorOfMatRelease($vectorOfMatCorners)
    EndIf

    _cveInputArrayRelease($iArrCorners)

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

Func _cveArucoGetBoardObjectAndImagePointsMat($board, $matDetectedCorners, $matDetectedIds, $matObjPoints, $matImgPoints)
    ; cveArucoGetBoardObjectAndImagePoints using cv::Mat instead of _*Array

    Local $iArrDetectedCorners, $vectorOfMatDetectedCorners, $iArrDetectedCornersSize
    Local $bDetectedCornersIsArray = VarGetType($matDetectedCorners) == "Array"

    If $bDetectedCornersIsArray Then
        $vectorOfMatDetectedCorners = _VectorOfMatCreate()

        $iArrDetectedCornersSize = UBound($matDetectedCorners)
        For $i = 0 To $iArrDetectedCornersSize - 1
            _VectorOfMatPush($vectorOfMatDetectedCorners, $matDetectedCorners[$i])
        Next

        $iArrDetectedCorners = _cveInputArrayFromVectorOfMat($vectorOfMatDetectedCorners)
    Else
        $iArrDetectedCorners = _cveInputArrayFromMat($matDetectedCorners)
    EndIf

    Local $iArrDetectedIds, $vectorOfMatDetectedIds, $iArrDetectedIdsSize
    Local $bDetectedIdsIsArray = VarGetType($matDetectedIds) == "Array"

    If $bDetectedIdsIsArray Then
        $vectorOfMatDetectedIds = _VectorOfMatCreate()

        $iArrDetectedIdsSize = UBound($matDetectedIds)
        For $i = 0 To $iArrDetectedIdsSize - 1
            _VectorOfMatPush($vectorOfMatDetectedIds, $matDetectedIds[$i])
        Next

        $iArrDetectedIds = _cveInputArrayFromVectorOfMat($vectorOfMatDetectedIds)
    Else
        $iArrDetectedIds = _cveInputArrayFromMat($matDetectedIds)
    EndIf

    Local $oArrObjPoints, $vectorOfMatObjPoints, $iArrObjPointsSize
    Local $bObjPointsIsArray = VarGetType($matObjPoints) == "Array"

    If $bObjPointsIsArray Then
        $vectorOfMatObjPoints = _VectorOfMatCreate()

        $iArrObjPointsSize = UBound($matObjPoints)
        For $i = 0 To $iArrObjPointsSize - 1
            _VectorOfMatPush($vectorOfMatObjPoints, $matObjPoints[$i])
        Next

        $oArrObjPoints = _cveOutputArrayFromVectorOfMat($vectorOfMatObjPoints)
    Else
        $oArrObjPoints = _cveOutputArrayFromMat($matObjPoints)
    EndIf

    Local $oArrImgPoints, $vectorOfMatImgPoints, $iArrImgPointsSize
    Local $bImgPointsIsArray = VarGetType($matImgPoints) == "Array"

    If $bImgPointsIsArray Then
        $vectorOfMatImgPoints = _VectorOfMatCreate()

        $iArrImgPointsSize = UBound($matImgPoints)
        For $i = 0 To $iArrImgPointsSize - 1
            _VectorOfMatPush($vectorOfMatImgPoints, $matImgPoints[$i])
        Next

        $oArrImgPoints = _cveOutputArrayFromVectorOfMat($vectorOfMatImgPoints)
    Else
        $oArrImgPoints = _cveOutputArrayFromMat($matImgPoints)
    EndIf

    _cveArucoGetBoardObjectAndImagePoints($board, $iArrDetectedCorners, $iArrDetectedIds, $oArrObjPoints, $oArrImgPoints)

    If $bImgPointsIsArray Then
        _VectorOfMatRelease($vectorOfMatImgPoints)
    EndIf

    _cveOutputArrayRelease($oArrImgPoints)

    If $bObjPointsIsArray Then
        _VectorOfMatRelease($vectorOfMatObjPoints)
    EndIf

    _cveOutputArrayRelease($oArrObjPoints)

    If $bDetectedIdsIsArray Then
        _VectorOfMatRelease($vectorOfMatDetectedIds)
    EndIf

    _cveInputArrayRelease($iArrDetectedIds)

    If $bDetectedCornersIsArray Then
        _VectorOfMatRelease($vectorOfMatDetectedCorners)
    EndIf

    _cveInputArrayRelease($iArrDetectedCorners)
EndFunc   ;==>_cveArucoGetBoardObjectAndImagePointsMat