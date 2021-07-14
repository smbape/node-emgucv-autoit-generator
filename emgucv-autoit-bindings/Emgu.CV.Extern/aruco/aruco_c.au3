#include-once
#include "..\..\CVEUtils.au3"

Func _cveArucoGetPredefinedDictionary($name, ByRef $sharedPtr)
    ; CVAPI(cv::aruco::Dictionary*) cveArucoGetPredefinedDictionary(int name, cv::Ptr<cv::aruco::Dictionary>** sharedPtr);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveArucoGetPredefinedDictionary", "int", $name, "ptr*", $sharedPtr), "cveArucoGetPredefinedDictionary", @error)
EndFunc   ;==>_cveArucoGetPredefinedDictionary

Func _cveArucoDictionaryCreate1($nMarkers, $markerSize, ByRef $sharedPtr)
    ; CVAPI(cv::aruco::Dictionary*) cveArucoDictionaryCreate1(int nMarkers, int markerSize, cv::Ptr<cv::aruco::Dictionary>** sharedPtr);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveArucoDictionaryCreate1", "int", $nMarkers, "int", $markerSize, "ptr*", $sharedPtr), "cveArucoDictionaryCreate1", @error)
EndFunc   ;==>_cveArucoDictionaryCreate1

Func _cveArucoDictionaryCreate2($nMarkers, $markerSize, ByRef $baseDictionary, ByRef $sharedPtr)
    ; CVAPI(cv::aruco::Dictionary*) cveArucoDictionaryCreate2(int nMarkers, int markerSize, cv::Ptr<cv::aruco::Dictionary>* baseDictionary, cv::Ptr<cv::aruco::Dictionary>** sharedPtr);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveArucoDictionaryCreate2", "int", $nMarkers, "int", $markerSize, "ptr", $baseDictionary, "ptr*", $sharedPtr), "cveArucoDictionaryCreate2", @error)
EndFunc   ;==>_cveArucoDictionaryCreate2

Func _cveArucoDictionaryRelease(ByRef $dict, ByRef $sharedPtr)
    ; CVAPI(void) cveArucoDictionaryRelease(cv::aruco::Dictionary** dict, cv::Ptr<cv::aruco::Dictionary>** sharedPtr);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveArucoDictionaryRelease", "ptr*", $dict, "ptr*", $sharedPtr), "cveArucoDictionaryRelease", @error)
EndFunc   ;==>_cveArucoDictionaryRelease

Func _cveArucoDrawMarker(ByRef $dictionary, $id, $sidePixels, ByRef $img, $borderBits)
    ; CVAPI(void) cveArucoDrawMarker(cv::aruco::Dictionary* dictionary, int id, int sidePixels, cv::_OutputArray* img, int borderBits);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveArucoDrawMarker", "ptr", $dictionary, "int", $id, "int", $sidePixels, "ptr", $img, "int", $borderBits), "cveArucoDrawMarker", @error)
EndFunc   ;==>_cveArucoDrawMarker

Func _cveArucoDrawMarkerMat(ByRef $dictionary, $id, $sidePixels, ByRef $matImg, $borderBits)
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

Func _cveArucoDrawAxis(ByRef $image, ByRef $cameraMatrix, ByRef $distCoeffs, ByRef $rvec, ByRef $tvec, $length)
    ; CVAPI(void) cveArucoDrawAxis(cv::_InputOutputArray* image, cv::_InputArray* cameraMatrix, cv::_InputArray* distCoeffs, cv::_InputArray* rvec, cv::_InputArray* tvec, float length);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveArucoDrawAxis", "ptr", $image, "ptr", $cameraMatrix, "ptr", $distCoeffs, "ptr", $rvec, "ptr", $tvec, "float", $length), "cveArucoDrawAxis", @error)
EndFunc   ;==>_cveArucoDrawAxis

Func _cveArucoDrawAxisMat(ByRef $matImage, ByRef $matCameraMatrix, ByRef $matDistCoeffs, ByRef $matRvec, ByRef $matTvec, $length)
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

Func _cveArucoDetectMarkers(ByRef $image, ByRef $dictionary, ByRef $corners, ByRef $ids, ByRef $parameters, ByRef $rejectedImgPoints)
    ; CVAPI(void) cveArucoDetectMarkers(cv::_InputArray* image, cv::aruco::Dictionary* dictionary, cv::_OutputArray* corners, cv::_OutputArray* ids, cv::aruco::DetectorParameters* parameters, cv::_OutputArray* rejectedImgPoints);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveArucoDetectMarkers", "ptr", $image, "ptr", $dictionary, "ptr", $corners, "ptr", $ids, "ptr", $parameters, "ptr", $rejectedImgPoints), "cveArucoDetectMarkers", @error)
EndFunc   ;==>_cveArucoDetectMarkers

Func _cveArucoDetectMarkersMat(ByRef $matImage, ByRef $dictionary, ByRef $matCorners, ByRef $matIds, ByRef $parameters, ByRef $matRejectedImgPoints)
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

Func _cveArucoEstimatePoseSingleMarkers(ByRef $corners, $markerLength, ByRef $cameraMatrix, ByRef $distCoeffs, ByRef $rvecs, ByRef $tvecs)
    ; CVAPI(void) cveArucoEstimatePoseSingleMarkers(cv::_InputArray* corners, float markerLength, cv::_InputArray* cameraMatrix, cv::_InputArray* distCoeffs, cv::_OutputArray* rvecs, cv::_OutputArray* tvecs);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveArucoEstimatePoseSingleMarkers", "ptr", $corners, "float", $markerLength, "ptr", $cameraMatrix, "ptr", $distCoeffs, "ptr", $rvecs, "ptr", $tvecs), "cveArucoEstimatePoseSingleMarkers", @error)
EndFunc   ;==>_cveArucoEstimatePoseSingleMarkers

Func _cveArucoEstimatePoseSingleMarkersMat(ByRef $matCorners, $markerLength, ByRef $matCameraMatrix, ByRef $matDistCoeffs, ByRef $matRvecs, ByRef $matTvecs)
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

Func _cveArucoGridBoardCreate($markersX, $markersY, $markerLength, $markerSeparation, ByRef $dictionary, $firstMarker, ByRef $boardPtr, ByRef $sharedPtr)
    ; CVAPI(cv::aruco::GridBoard*) cveArucoGridBoardCreate(int markersX, int markersY, float markerLength, float markerSeparation, cv::aruco::Dictionary* dictionary, int firstMarker, cv::aruco::Board** boardPtr, cv::Ptr<cv::aruco::GridBoard>** sharedPtr);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveArucoGridBoardCreate", "int", $markersX, "int", $markersY, "float", $markerLength, "float", $markerSeparation, "ptr", $dictionary, "int", $firstMarker, "ptr*", $boardPtr, "ptr*", $sharedPtr), "cveArucoGridBoardCreate", @error)
EndFunc   ;==>_cveArucoGridBoardCreate

Func _cveArucoGridBoardDraw(ByRef $gridBoard, ByRef $outSize, ByRef $img, $marginSize, $borderBits)
    ; CVAPI(void) cveArucoGridBoardDraw(cv::aruco::GridBoard* gridBoard, CvSize* outSize, cv::_OutputArray* img, int marginSize, int borderBits);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveArucoGridBoardDraw", "ptr", $gridBoard, "struct*", $outSize, "ptr", $img, "int", $marginSize, "int", $borderBits), "cveArucoGridBoardDraw", @error)
EndFunc   ;==>_cveArucoGridBoardDraw

Func _cveArucoGridBoardDrawMat(ByRef $gridBoard, ByRef $outSize, ByRef $matImg, $marginSize, $borderBits)
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

Func _cveArucoGridBoardRelease(ByRef $gridBoard, ByRef $sharedPtr)
    ; CVAPI(void) cveArucoGridBoardRelease(cv::aruco::GridBoard** gridBoard, cv::Ptr<cv::aruco::GridBoard>** sharedPtr);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveArucoGridBoardRelease", "ptr*", $gridBoard, "ptr*", $sharedPtr), "cveArucoGridBoardRelease", @error)
EndFunc   ;==>_cveArucoGridBoardRelease

Func _cveCharucoBoardCreate($squaresX, $squaresY, $squareLength, $markerLength, ByRef $dictionary, ByRef $boardPtr, ByRef $sharedPtr)
    ; CVAPI(cv::aruco::CharucoBoard*) cveCharucoBoardCreate(int squaresX, int squaresY, float squareLength, float markerLength, cv::aruco::Dictionary* dictionary, cv::aruco::Board** boardPtr, cv::Ptr<cv::aruco::CharucoBoard>** sharedPtr);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveCharucoBoardCreate", "int", $squaresX, "int", $squaresY, "float", $squareLength, "float", $markerLength, "ptr", $dictionary, "ptr*", $boardPtr, "ptr*", $sharedPtr), "cveCharucoBoardCreate", @error)
EndFunc   ;==>_cveCharucoBoardCreate

Func _cveCharucoBoardDraw(ByRef $charucoBoard, ByRef $outSize, ByRef $img, $marginSize, $borderBits)
    ; CVAPI(void) cveCharucoBoardDraw(cv::aruco::CharucoBoard* charucoBoard, CvSize* outSize, cv::_OutputArray* img, int marginSize, int borderBits);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCharucoBoardDraw", "ptr", $charucoBoard, "struct*", $outSize, "ptr", $img, "int", $marginSize, "int", $borderBits), "cveCharucoBoardDraw", @error)
EndFunc   ;==>_cveCharucoBoardDraw

Func _cveCharucoBoardDrawMat(ByRef $charucoBoard, ByRef $outSize, ByRef $matImg, $marginSize, $borderBits)
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

Func _cveCharucoBoardRelease(ByRef $charucoBoard, ByRef $sharedPtr)
    ; CVAPI(void) cveCharucoBoardRelease(cv::aruco::CharucoBoard** charucoBoard, cv::Ptr<cv::aruco::CharucoBoard>** sharedPtr);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCharucoBoardRelease", "ptr*", $charucoBoard, "ptr*", $sharedPtr), "cveCharucoBoardRelease", @error)
EndFunc   ;==>_cveCharucoBoardRelease

Func _cveArucoRefineDetectedMarkers(ByRef $image, ByRef $board, ByRef $detectedCorners, ByRef $detectedIds, ByRef $rejectedCorners, ByRef $cameraMatrix, ByRef $distCoeffs, $minRepDistance, $errorCorrectionRate, $checkAllOrders, ByRef $recoveredIdxs, ByRef $parameters)
    ; CVAPI(void) cveArucoRefineDetectedMarkers(cv::_InputArray* image, cv::aruco::Board* board, cv::_InputOutputArray* detectedCorners, cv::_InputOutputArray* detectedIds, cv::_InputOutputArray* rejectedCorners, cv::_InputArray* cameraMatrix, cv::_InputArray* distCoeffs, float minRepDistance, float errorCorrectionRate, bool checkAllOrders, cv::_OutputArray* recoveredIdxs, cv::aruco::DetectorParameters* parameters);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveArucoRefineDetectedMarkers", "ptr", $image, "ptr", $board, "ptr", $detectedCorners, "ptr", $detectedIds, "ptr", $rejectedCorners, "ptr", $cameraMatrix, "ptr", $distCoeffs, "float", $minRepDistance, "float", $errorCorrectionRate, "boolean", $checkAllOrders, "ptr", $recoveredIdxs, "ptr", $parameters), "cveArucoRefineDetectedMarkers", @error)
EndFunc   ;==>_cveArucoRefineDetectedMarkers

Func _cveArucoRefineDetectedMarkersMat(ByRef $matImage, ByRef $board, ByRef $matDetectedCorners, ByRef $matDetectedIds, ByRef $matRejectedCorners, ByRef $matCameraMatrix, ByRef $matDistCoeffs, $minRepDistance, $errorCorrectionRate, $checkAllOrders, ByRef $matRecoveredIdxs, ByRef $parameters)
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

Func _cveArucoDrawDetectedMarkers(ByRef $image, ByRef $corners, ByRef $ids, ByRef $borderColor)
    ; CVAPI(void) cveArucoDrawDetectedMarkers(cv::_InputOutputArray* image, cv::_InputArray* corners, cv::_InputArray* ids, CvScalar* borderColor);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveArucoDrawDetectedMarkers", "ptr", $image, "ptr", $corners, "ptr", $ids, "struct*", $borderColor), "cveArucoDrawDetectedMarkers", @error)
EndFunc   ;==>_cveArucoDrawDetectedMarkers

Func _cveArucoDrawDetectedMarkersMat(ByRef $matImage, ByRef $matCorners, ByRef $matIds, ByRef $borderColor)
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

Func _cveArucoCalibrateCameraAruco(ByRef $corners, ByRef $ids, ByRef $counter, ByRef $board, ByRef $imageSize, ByRef $cameraMatrix, ByRef $distCoeffs, ByRef $rvecs, ByRef $tvecs, ByRef $stdDeviationsIntrinsics, ByRef $stdDeviationsExtrinsics, ByRef $perViewErrors, $flags, ByRef $criteria)
    ; CVAPI(double) cveArucoCalibrateCameraAruco(cv::_InputArray* corners, cv::_InputArray* ids, cv::_InputArray* counter, cv::aruco::Board* board, CvSize* imageSize, cv::_InputOutputArray* cameraMatrix, cv::_InputOutputArray* distCoeffs, cv::_OutputArray* rvecs, cv::_OutputArray* tvecs, cv::_OutputArray* stdDeviationsIntrinsics, cv::_OutputArray* stdDeviationsExtrinsics, cv::_OutputArray* perViewErrors, int flags, CvTermCriteria* criteria);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveArucoCalibrateCameraAruco", "ptr", $corners, "ptr", $ids, "ptr", $counter, "ptr", $board, "struct*", $imageSize, "ptr", $cameraMatrix, "ptr", $distCoeffs, "ptr", $rvecs, "ptr", $tvecs, "ptr", $stdDeviationsIntrinsics, "ptr", $stdDeviationsExtrinsics, "ptr", $perViewErrors, "int", $flags, "struct*", $criteria), "cveArucoCalibrateCameraAruco", @error)
EndFunc   ;==>_cveArucoCalibrateCameraAruco

Func _cveArucoCalibrateCameraArucoMat(ByRef $matCorners, ByRef $matIds, ByRef $matCounter, ByRef $board, ByRef $imageSize, ByRef $matCameraMatrix, ByRef $matDistCoeffs, ByRef $matRvecs, ByRef $matTvecs, ByRef $matStdDeviationsIntrinsics, ByRef $matStdDeviationsExtrinsics, ByRef $matPerViewErrors, $flags, ByRef $criteria)
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

Func _cveArucoCalibrateCameraCharuco(ByRef $charucoCorners, ByRef $charucoIds, ByRef $board, ByRef $imageSize, ByRef $cameraMatrix, ByRef $distCoeffs, ByRef $rvecs, ByRef $tvecs, ByRef $stdDeviationsIntrinsics, ByRef $stdDeviationsExtrinsics, ByRef $perViewErrors, $flags, ByRef $criteria)
    ; CVAPI(double) cveArucoCalibrateCameraCharuco(cv::_InputArray* charucoCorners, cv::_InputArray* charucoIds, cv::aruco::CharucoBoard* board, CvSize* imageSize, cv::_InputOutputArray* cameraMatrix, cv::_InputOutputArray* distCoeffs, cv::_OutputArray* rvecs, cv::_OutputArray* tvecs, cv::_OutputArray* stdDeviationsIntrinsics, cv::_OutputArray* stdDeviationsExtrinsics, cv::_OutputArray* perViewErrors, int flags, CvTermCriteria* criteria);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveArucoCalibrateCameraCharuco", "ptr", $charucoCorners, "ptr", $charucoIds, "ptr", $board, "struct*", $imageSize, "ptr", $cameraMatrix, "ptr", $distCoeffs, "ptr", $rvecs, "ptr", $tvecs, "ptr", $stdDeviationsIntrinsics, "ptr", $stdDeviationsExtrinsics, "ptr", $perViewErrors, "int", $flags, "struct*", $criteria), "cveArucoCalibrateCameraCharuco", @error)
EndFunc   ;==>_cveArucoCalibrateCameraCharuco

Func _cveArucoCalibrateCameraCharucoMat(ByRef $matCharucoCorners, ByRef $matCharucoIds, ByRef $board, ByRef $imageSize, ByRef $matCameraMatrix, ByRef $matDistCoeffs, ByRef $matRvecs, ByRef $matTvecs, ByRef $matStdDeviationsIntrinsics, ByRef $matStdDeviationsExtrinsics, ByRef $matPerViewErrors, $flags, ByRef $criteria)
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

Func _cveArucoDetectorParametersGetDefault(ByRef $parameters)
    ; CVAPI(void) cveArucoDetectorParametersGetDefault(cv::aruco::DetectorParameters* parameters);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveArucoDetectorParametersGetDefault", "ptr", $parameters), "cveArucoDetectorParametersGetDefault", @error)
EndFunc   ;==>_cveArucoDetectorParametersGetDefault

Func _cveArucoInterpolateCornersCharuco(ByRef $markerCorners, ByRef $markerIds, ByRef $image, ByRef $board, ByRef $charucoCorners, ByRef $charucoIds, ByRef $cameraMatrix, ByRef $distCoeffs, $minMarkers)
    ; CVAPI(int) cveArucoInterpolateCornersCharuco(cv::_InputArray* markerCorners, cv::_InputArray* markerIds, cv::_InputArray* image, cv::aruco::CharucoBoard* board, cv::_OutputArray* charucoCorners, cv::_OutputArray* charucoIds, cv::_InputArray* cameraMatrix, cv::_InputArray* distCoeffs, int minMarkers);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveArucoInterpolateCornersCharuco", "ptr", $markerCorners, "ptr", $markerIds, "ptr", $image, "ptr", $board, "ptr", $charucoCorners, "ptr", $charucoIds, "ptr", $cameraMatrix, "ptr", $distCoeffs, "int", $minMarkers), "cveArucoInterpolateCornersCharuco", @error)
EndFunc   ;==>_cveArucoInterpolateCornersCharuco

Func _cveArucoInterpolateCornersCharucoMat(ByRef $matMarkerCorners, ByRef $matMarkerIds, ByRef $matImage, ByRef $board, ByRef $matCharucoCorners, ByRef $matCharucoIds, ByRef $matCameraMatrix, ByRef $matDistCoeffs, $minMarkers)
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

Func _cveArucoDrawDetectedCornersCharuco(ByRef $image, ByRef $charucoCorners, ByRef $charucoIds, ByRef $cornerColor)
    ; CVAPI(void) cveArucoDrawDetectedCornersCharuco(cv::_InputOutputArray* image, cv::_InputArray* charucoCorners, cv::_InputArray* charucoIds, CvScalar* cornerColor);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveArucoDrawDetectedCornersCharuco", "ptr", $image, "ptr", $charucoCorners, "ptr", $charucoIds, "struct*", $cornerColor), "cveArucoDrawDetectedCornersCharuco", @error)
EndFunc   ;==>_cveArucoDrawDetectedCornersCharuco

Func _cveArucoDrawDetectedCornersCharucoMat(ByRef $matImage, ByRef $matCharucoCorners, ByRef $matCharucoIds, ByRef $cornerColor)
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

Func _cveArucoEstimatePoseCharucoBoard(ByRef $charucoCorners, ByRef $charucoIds, ByRef $board, ByRef $cameraMatrix, ByRef $distCoeffs, ByRef $rvec, ByRef $tvec, $useExtrinsicGuess)
    ; CVAPI(bool) cveArucoEstimatePoseCharucoBoard(cv::_InputArray* charucoCorners, cv::_InputArray* charucoIds, cv::aruco::CharucoBoard* board, cv::_InputArray* cameraMatrix, cv::_InputArray* distCoeffs, cv::_InputOutputArray* rvec, cv::_InputOutputArray* tvec, bool useExtrinsicGuess);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveArucoEstimatePoseCharucoBoard", "ptr", $charucoCorners, "ptr", $charucoIds, "ptr", $board, "ptr", $cameraMatrix, "ptr", $distCoeffs, "ptr", $rvec, "ptr", $tvec, "boolean", $useExtrinsicGuess), "cveArucoEstimatePoseCharucoBoard", @error)
EndFunc   ;==>_cveArucoEstimatePoseCharucoBoard

Func _cveArucoEstimatePoseCharucoBoardMat(ByRef $matCharucoCorners, ByRef $matCharucoIds, ByRef $board, ByRef $matCameraMatrix, ByRef $matDistCoeffs, ByRef $matRvec, ByRef $matTvec, $useExtrinsicGuess)
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

Func _cveArucoDetectCharucoDiamond(ByRef $image, ByRef $markerCorners, ByRef $markerIds, $squareMarkerLengthRate, ByRef $diamondCorners, ByRef $diamondIds, ByRef $cameraMatrix, ByRef $distCoeffs)
    ; CVAPI(void) cveArucoDetectCharucoDiamond(cv::_InputArray* image, cv::_InputArray* markerCorners, cv::_InputArray* markerIds, float squareMarkerLengthRate, cv::_OutputArray* diamondCorners, cv::_OutputArray* diamondIds, cv::_InputArray* cameraMatrix, cv::_InputArray* distCoeffs);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveArucoDetectCharucoDiamond", "ptr", $image, "ptr", $markerCorners, "ptr", $markerIds, "float", $squareMarkerLengthRate, "ptr", $diamondCorners, "ptr", $diamondIds, "ptr", $cameraMatrix, "ptr", $distCoeffs), "cveArucoDetectCharucoDiamond", @error)
EndFunc   ;==>_cveArucoDetectCharucoDiamond

Func _cveArucoDetectCharucoDiamondMat(ByRef $matImage, ByRef $matMarkerCorners, ByRef $matMarkerIds, $squareMarkerLengthRate, ByRef $matDiamondCorners, ByRef $matDiamondIds, ByRef $matCameraMatrix, ByRef $matDistCoeffs)
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

Func _cveArucoDrawDetectedDiamonds(ByRef $image, ByRef $diamondCorners, ByRef $diamondIds, ByRef $borderColor)
    ; CVAPI(void) cveArucoDrawDetectedDiamonds(cv::_InputOutputArray* image, cv::_InputArray* diamondCorners, cv::_InputArray* diamondIds, CvScalar* borderColor);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveArucoDrawDetectedDiamonds", "ptr", $image, "ptr", $diamondCorners, "ptr", $diamondIds, "struct*", $borderColor), "cveArucoDrawDetectedDiamonds", @error)
EndFunc   ;==>_cveArucoDrawDetectedDiamonds

Func _cveArucoDrawDetectedDiamondsMat(ByRef $matImage, ByRef $matDiamondCorners, ByRef $matDiamondIds, ByRef $borderColor)
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

Func _cveArucoDrawCharucoDiamond(ByRef $dictionary, ByRef $ids, $squareLength, $markerLength, ByRef $img, $marginSize, $borderBits)
    ; CVAPI(void) cveArucoDrawCharucoDiamond(cv::aruco::Dictionary* dictionary, int* ids, int squareLength, int markerLength, cv::_OutputArray* img, int marginSize, int borderBits);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveArucoDrawCharucoDiamond", "ptr", $dictionary, "struct*", $ids, "int", $squareLength, "int", $markerLength, "ptr", $img, "int", $marginSize, "int", $borderBits), "cveArucoDrawCharucoDiamond", @error)
EndFunc   ;==>_cveArucoDrawCharucoDiamond

Func _cveArucoDrawCharucoDiamondMat(ByRef $dictionary, ByRef $ids, $squareLength, $markerLength, ByRef $matImg, $marginSize, $borderBits)
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

Func _cveArucoDrawPlanarBoard(ByRef $board, ByRef $outSize, ByRef $img, $marginSize, $borderBits)
    ; CVAPI(void) cveArucoDrawPlanarBoard(cv::aruco::Board* board, CvSize* outSize, cv::_OutputArray* img, int marginSize, int borderBits);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveArucoDrawPlanarBoard", "ptr", $board, "struct*", $outSize, "ptr", $img, "int", $marginSize, "int", $borderBits), "cveArucoDrawPlanarBoard", @error)
EndFunc   ;==>_cveArucoDrawPlanarBoard

Func _cveArucoDrawPlanarBoardMat(ByRef $board, ByRef $outSize, ByRef $matImg, $marginSize, $borderBits)
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

Func _cveArucoEstimatePoseBoard(ByRef $corners, ByRef $ids, ByRef $board, ByRef $cameraMatrix, ByRef $distCoeffs, ByRef $rvec, ByRef $tvec, $useExtrinsicGuess)
    ; CVAPI(int) cveArucoEstimatePoseBoard(cv::_InputArray* corners, cv::_InputArray* ids, cv::aruco::Board* board, cv::_InputArray* cameraMatrix, cv::_InputArray* distCoeffs, cv::_InputOutputArray* rvec, cv::_InputOutputArray* tvec, bool useExtrinsicGuess);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveArucoEstimatePoseBoard", "ptr", $corners, "ptr", $ids, "ptr", $board, "ptr", $cameraMatrix, "ptr", $distCoeffs, "ptr", $rvec, "ptr", $tvec, "boolean", $useExtrinsicGuess), "cveArucoEstimatePoseBoard", @error)
EndFunc   ;==>_cveArucoEstimatePoseBoard

Func _cveArucoEstimatePoseBoardMat(ByRef $matCorners, ByRef $matIds, ByRef $board, ByRef $matCameraMatrix, ByRef $matDistCoeffs, ByRef $matRvec, ByRef $matTvec, $useExtrinsicGuess)
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

Func _cveArucoGetBoardObjectAndImagePoints(ByRef $board, ByRef $detectedCorners, ByRef $detectedIds, ByRef $objPoints, ByRef $imgPoints)
    ; CVAPI(void) cveArucoGetBoardObjectAndImagePoints(cv::aruco::Board* board, cv::_InputArray* detectedCorners, cv::_InputArray* detectedIds, cv::_OutputArray* objPoints, cv::_OutputArray* imgPoints);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveArucoGetBoardObjectAndImagePoints", "ptr", $board, "ptr", $detectedCorners, "ptr", $detectedIds, "ptr", $objPoints, "ptr", $imgPoints), "cveArucoGetBoardObjectAndImagePoints", @error)
EndFunc   ;==>_cveArucoGetBoardObjectAndImagePoints

Func _cveArucoGetBoardObjectAndImagePointsMat(ByRef $board, ByRef $matDetectedCorners, ByRef $matDetectedIds, ByRef $matObjPoints, ByRef $matImgPoints)
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