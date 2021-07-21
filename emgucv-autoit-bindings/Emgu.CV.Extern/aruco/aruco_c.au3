#include-once
#include "..\..\CVEUtils.au3"

Func _cveArucoGetPredefinedDictionary($name, $sharedPtr)
    ; CVAPI(cv::aruco::Dictionary*) cveArucoGetPredefinedDictionary(int name, cv::Ptr<cv::aruco::Dictionary>** sharedPtr);

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveArucoGetPredefinedDictionary", "int", $name, $bSharedPtrDllType, $sharedPtr), "cveArucoGetPredefinedDictionary", @error)
EndFunc   ;==>_cveArucoGetPredefinedDictionary

Func _cveArucoDictionaryCreate1($nMarkers, $markerSize, $sharedPtr)
    ; CVAPI(cv::aruco::Dictionary*) cveArucoDictionaryCreate1(int nMarkers, int markerSize, cv::Ptr<cv::aruco::Dictionary>** sharedPtr);

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveArucoDictionaryCreate1", "int", $nMarkers, "int", $markerSize, $bSharedPtrDllType, $sharedPtr), "cveArucoDictionaryCreate1", @error)
EndFunc   ;==>_cveArucoDictionaryCreate1

Func _cveArucoDictionaryCreate2($nMarkers, $markerSize, $baseDictionary, $sharedPtr)
    ; CVAPI(cv::aruco::Dictionary*) cveArucoDictionaryCreate2(int nMarkers, int markerSize, cv::Ptr<cv::aruco::Dictionary>* baseDictionary, cv::Ptr<cv::aruco::Dictionary>** sharedPtr);

    Local $bBaseDictionaryDllType
    If VarGetType($baseDictionary) == "DLLStruct" Then
        $bBaseDictionaryDllType = "struct*"
    Else
        $bBaseDictionaryDllType = "ptr"
    EndIf

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveArucoDictionaryCreate2", "int", $nMarkers, "int", $markerSize, $bBaseDictionaryDllType, $baseDictionary, $bSharedPtrDllType, $sharedPtr), "cveArucoDictionaryCreate2", @error)
EndFunc   ;==>_cveArucoDictionaryCreate2

Func _cveArucoDictionaryRelease($dict, $sharedPtr)
    ; CVAPI(void) cveArucoDictionaryRelease(cv::aruco::Dictionary** dict, cv::Ptr<cv::aruco::Dictionary>** sharedPtr);

    Local $bDictDllType
    If VarGetType($dict) == "DLLStruct" Then
        $bDictDllType = "struct*"
    Else
        $bDictDllType = "ptr*"
    EndIf

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveArucoDictionaryRelease", $bDictDllType, $dict, $bSharedPtrDllType, $sharedPtr), "cveArucoDictionaryRelease", @error)
EndFunc   ;==>_cveArucoDictionaryRelease

Func _cveArucoDrawMarker($dictionary, $id, $sidePixels, $img, $borderBits)
    ; CVAPI(void) cveArucoDrawMarker(cv::aruco::Dictionary* dictionary, int id, int sidePixels, cv::_OutputArray* img, int borderBits);

    Local $bDictionaryDllType
    If VarGetType($dictionary) == "DLLStruct" Then
        $bDictionaryDllType = "struct*"
    Else
        $bDictionaryDllType = "ptr"
    EndIf

    Local $bImgDllType
    If VarGetType($img) == "DLLStruct" Then
        $bImgDllType = "struct*"
    Else
        $bImgDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveArucoDrawMarker", $bDictionaryDllType, $dictionary, "int", $id, "int", $sidePixels, $bImgDllType, $img, "int", $borderBits), "cveArucoDrawMarker", @error)
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

    Local $bImageDllType
    If VarGetType($image) == "DLLStruct" Then
        $bImageDllType = "struct*"
    Else
        $bImageDllType = "ptr"
    EndIf

    Local $bCameraMatrixDllType
    If VarGetType($cameraMatrix) == "DLLStruct" Then
        $bCameraMatrixDllType = "struct*"
    Else
        $bCameraMatrixDllType = "ptr"
    EndIf

    Local $bDistCoeffsDllType
    If VarGetType($distCoeffs) == "DLLStruct" Then
        $bDistCoeffsDllType = "struct*"
    Else
        $bDistCoeffsDllType = "ptr"
    EndIf

    Local $bRvecDllType
    If VarGetType($rvec) == "DLLStruct" Then
        $bRvecDllType = "struct*"
    Else
        $bRvecDllType = "ptr"
    EndIf

    Local $bTvecDllType
    If VarGetType($tvec) == "DLLStruct" Then
        $bTvecDllType = "struct*"
    Else
        $bTvecDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveArucoDrawAxis", $bImageDllType, $image, $bCameraMatrixDllType, $cameraMatrix, $bDistCoeffsDllType, $distCoeffs, $bRvecDllType, $rvec, $bTvecDllType, $tvec, "float", $length), "cveArucoDrawAxis", @error)
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

    Local $bImageDllType
    If VarGetType($image) == "DLLStruct" Then
        $bImageDllType = "struct*"
    Else
        $bImageDllType = "ptr"
    EndIf

    Local $bDictionaryDllType
    If VarGetType($dictionary) == "DLLStruct" Then
        $bDictionaryDllType = "struct*"
    Else
        $bDictionaryDllType = "ptr"
    EndIf

    Local $bCornersDllType
    If VarGetType($corners) == "DLLStruct" Then
        $bCornersDllType = "struct*"
    Else
        $bCornersDllType = "ptr"
    EndIf

    Local $bIdsDllType
    If VarGetType($ids) == "DLLStruct" Then
        $bIdsDllType = "struct*"
    Else
        $bIdsDllType = "ptr"
    EndIf

    Local $bParametersDllType
    If VarGetType($parameters) == "DLLStruct" Then
        $bParametersDllType = "struct*"
    Else
        $bParametersDllType = "ptr"
    EndIf

    Local $bRejectedImgPointsDllType
    If VarGetType($rejectedImgPoints) == "DLLStruct" Then
        $bRejectedImgPointsDllType = "struct*"
    Else
        $bRejectedImgPointsDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveArucoDetectMarkers", $bImageDllType, $image, $bDictionaryDllType, $dictionary, $bCornersDllType, $corners, $bIdsDllType, $ids, $bParametersDllType, $parameters, $bRejectedImgPointsDllType, $rejectedImgPoints), "cveArucoDetectMarkers", @error)
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

    Local $bCornersDllType
    If VarGetType($corners) == "DLLStruct" Then
        $bCornersDllType = "struct*"
    Else
        $bCornersDllType = "ptr"
    EndIf

    Local $bCameraMatrixDllType
    If VarGetType($cameraMatrix) == "DLLStruct" Then
        $bCameraMatrixDllType = "struct*"
    Else
        $bCameraMatrixDllType = "ptr"
    EndIf

    Local $bDistCoeffsDllType
    If VarGetType($distCoeffs) == "DLLStruct" Then
        $bDistCoeffsDllType = "struct*"
    Else
        $bDistCoeffsDllType = "ptr"
    EndIf

    Local $bRvecsDllType
    If VarGetType($rvecs) == "DLLStruct" Then
        $bRvecsDllType = "struct*"
    Else
        $bRvecsDllType = "ptr"
    EndIf

    Local $bTvecsDllType
    If VarGetType($tvecs) == "DLLStruct" Then
        $bTvecsDllType = "struct*"
    Else
        $bTvecsDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveArucoEstimatePoseSingleMarkers", $bCornersDllType, $corners, "float", $markerLength, $bCameraMatrixDllType, $cameraMatrix, $bDistCoeffsDllType, $distCoeffs, $bRvecsDllType, $rvecs, $bTvecsDllType, $tvecs), "cveArucoEstimatePoseSingleMarkers", @error)
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

    Local $bDictionaryDllType
    If VarGetType($dictionary) == "DLLStruct" Then
        $bDictionaryDllType = "struct*"
    Else
        $bDictionaryDllType = "ptr"
    EndIf

    Local $bBoardPtrDllType
    If VarGetType($boardPtr) == "DLLStruct" Then
        $bBoardPtrDllType = "struct*"
    Else
        $bBoardPtrDllType = "ptr*"
    EndIf

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveArucoGridBoardCreate", "int", $markersX, "int", $markersY, "float", $markerLength, "float", $markerSeparation, $bDictionaryDllType, $dictionary, "int", $firstMarker, $bBoardPtrDllType, $boardPtr, $bSharedPtrDllType, $sharedPtr), "cveArucoGridBoardCreate", @error)
EndFunc   ;==>_cveArucoGridBoardCreate

Func _cveArucoGridBoardDraw($gridBoard, $outSize, $img, $marginSize, $borderBits)
    ; CVAPI(void) cveArucoGridBoardDraw(cv::aruco::GridBoard* gridBoard, CvSize* outSize, cv::_OutputArray* img, int marginSize, int borderBits);

    Local $bGridBoardDllType
    If VarGetType($gridBoard) == "DLLStruct" Then
        $bGridBoardDllType = "struct*"
    Else
        $bGridBoardDllType = "ptr"
    EndIf

    Local $bOutSizeDllType
    If VarGetType($outSize) == "DLLStruct" Then
        $bOutSizeDllType = "struct*"
    Else
        $bOutSizeDllType = "ptr"
    EndIf

    Local $bImgDllType
    If VarGetType($img) == "DLLStruct" Then
        $bImgDllType = "struct*"
    Else
        $bImgDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveArucoGridBoardDraw", $bGridBoardDllType, $gridBoard, $bOutSizeDllType, $outSize, $bImgDllType, $img, "int", $marginSize, "int", $borderBits), "cveArucoGridBoardDraw", @error)
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

    Local $bGridBoardDllType
    If VarGetType($gridBoard) == "DLLStruct" Then
        $bGridBoardDllType = "struct*"
    Else
        $bGridBoardDllType = "ptr*"
    EndIf

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveArucoGridBoardRelease", $bGridBoardDllType, $gridBoard, $bSharedPtrDllType, $sharedPtr), "cveArucoGridBoardRelease", @error)
EndFunc   ;==>_cveArucoGridBoardRelease

Func _cveCharucoBoardCreate($squaresX, $squaresY, $squareLength, $markerLength, $dictionary, $boardPtr, $sharedPtr)
    ; CVAPI(cv::aruco::CharucoBoard*) cveCharucoBoardCreate(int squaresX, int squaresY, float squareLength, float markerLength, cv::aruco::Dictionary* dictionary, cv::aruco::Board** boardPtr, cv::Ptr<cv::aruco::CharucoBoard>** sharedPtr);

    Local $bDictionaryDllType
    If VarGetType($dictionary) == "DLLStruct" Then
        $bDictionaryDllType = "struct*"
    Else
        $bDictionaryDllType = "ptr"
    EndIf

    Local $bBoardPtrDllType
    If VarGetType($boardPtr) == "DLLStruct" Then
        $bBoardPtrDllType = "struct*"
    Else
        $bBoardPtrDllType = "ptr*"
    EndIf

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveCharucoBoardCreate", "int", $squaresX, "int", $squaresY, "float", $squareLength, "float", $markerLength, $bDictionaryDllType, $dictionary, $bBoardPtrDllType, $boardPtr, $bSharedPtrDllType, $sharedPtr), "cveCharucoBoardCreate", @error)
EndFunc   ;==>_cveCharucoBoardCreate

Func _cveCharucoBoardDraw($charucoBoard, $outSize, $img, $marginSize, $borderBits)
    ; CVAPI(void) cveCharucoBoardDraw(cv::aruco::CharucoBoard* charucoBoard, CvSize* outSize, cv::_OutputArray* img, int marginSize, int borderBits);

    Local $bCharucoBoardDllType
    If VarGetType($charucoBoard) == "DLLStruct" Then
        $bCharucoBoardDllType = "struct*"
    Else
        $bCharucoBoardDllType = "ptr"
    EndIf

    Local $bOutSizeDllType
    If VarGetType($outSize) == "DLLStruct" Then
        $bOutSizeDllType = "struct*"
    Else
        $bOutSizeDllType = "ptr"
    EndIf

    Local $bImgDllType
    If VarGetType($img) == "DLLStruct" Then
        $bImgDllType = "struct*"
    Else
        $bImgDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCharucoBoardDraw", $bCharucoBoardDllType, $charucoBoard, $bOutSizeDllType, $outSize, $bImgDllType, $img, "int", $marginSize, "int", $borderBits), "cveCharucoBoardDraw", @error)
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

    Local $bCharucoBoardDllType
    If VarGetType($charucoBoard) == "DLLStruct" Then
        $bCharucoBoardDllType = "struct*"
    Else
        $bCharucoBoardDllType = "ptr*"
    EndIf

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCharucoBoardRelease", $bCharucoBoardDllType, $charucoBoard, $bSharedPtrDllType, $sharedPtr), "cveCharucoBoardRelease", @error)
EndFunc   ;==>_cveCharucoBoardRelease

Func _cveArucoRefineDetectedMarkers($image, $board, $detectedCorners, $detectedIds, $rejectedCorners, $cameraMatrix, $distCoeffs, $minRepDistance, $errorCorrectionRate, $checkAllOrders, $recoveredIdxs, $parameters)
    ; CVAPI(void) cveArucoRefineDetectedMarkers(cv::_InputArray* image, cv::aruco::Board* board, cv::_InputOutputArray* detectedCorners, cv::_InputOutputArray* detectedIds, cv::_InputOutputArray* rejectedCorners, cv::_InputArray* cameraMatrix, cv::_InputArray* distCoeffs, float minRepDistance, float errorCorrectionRate, bool checkAllOrders, cv::_OutputArray* recoveredIdxs, cv::aruco::DetectorParameters* parameters);

    Local $bImageDllType
    If VarGetType($image) == "DLLStruct" Then
        $bImageDllType = "struct*"
    Else
        $bImageDllType = "ptr"
    EndIf

    Local $bBoardDllType
    If VarGetType($board) == "DLLStruct" Then
        $bBoardDllType = "struct*"
    Else
        $bBoardDllType = "ptr"
    EndIf

    Local $bDetectedCornersDllType
    If VarGetType($detectedCorners) == "DLLStruct" Then
        $bDetectedCornersDllType = "struct*"
    Else
        $bDetectedCornersDllType = "ptr"
    EndIf

    Local $bDetectedIdsDllType
    If VarGetType($detectedIds) == "DLLStruct" Then
        $bDetectedIdsDllType = "struct*"
    Else
        $bDetectedIdsDllType = "ptr"
    EndIf

    Local $bRejectedCornersDllType
    If VarGetType($rejectedCorners) == "DLLStruct" Then
        $bRejectedCornersDllType = "struct*"
    Else
        $bRejectedCornersDllType = "ptr"
    EndIf

    Local $bCameraMatrixDllType
    If VarGetType($cameraMatrix) == "DLLStruct" Then
        $bCameraMatrixDllType = "struct*"
    Else
        $bCameraMatrixDllType = "ptr"
    EndIf

    Local $bDistCoeffsDllType
    If VarGetType($distCoeffs) == "DLLStruct" Then
        $bDistCoeffsDllType = "struct*"
    Else
        $bDistCoeffsDllType = "ptr"
    EndIf

    Local $bRecoveredIdxsDllType
    If VarGetType($recoveredIdxs) == "DLLStruct" Then
        $bRecoveredIdxsDllType = "struct*"
    Else
        $bRecoveredIdxsDllType = "ptr"
    EndIf

    Local $bParametersDllType
    If VarGetType($parameters) == "DLLStruct" Then
        $bParametersDllType = "struct*"
    Else
        $bParametersDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveArucoRefineDetectedMarkers", $bImageDllType, $image, $bBoardDllType, $board, $bDetectedCornersDllType, $detectedCorners, $bDetectedIdsDllType, $detectedIds, $bRejectedCornersDllType, $rejectedCorners, $bCameraMatrixDllType, $cameraMatrix, $bDistCoeffsDllType, $distCoeffs, "float", $minRepDistance, "float", $errorCorrectionRate, "boolean", $checkAllOrders, $bRecoveredIdxsDllType, $recoveredIdxs, $bParametersDllType, $parameters), "cveArucoRefineDetectedMarkers", @error)
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

    Local $bImageDllType
    If VarGetType($image) == "DLLStruct" Then
        $bImageDllType = "struct*"
    Else
        $bImageDllType = "ptr"
    EndIf

    Local $bCornersDllType
    If VarGetType($corners) == "DLLStruct" Then
        $bCornersDllType = "struct*"
    Else
        $bCornersDllType = "ptr"
    EndIf

    Local $bIdsDllType
    If VarGetType($ids) == "DLLStruct" Then
        $bIdsDllType = "struct*"
    Else
        $bIdsDllType = "ptr"
    EndIf

    Local $bBorderColorDllType
    If VarGetType($borderColor) == "DLLStruct" Then
        $bBorderColorDllType = "struct*"
    Else
        $bBorderColorDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveArucoDrawDetectedMarkers", $bImageDllType, $image, $bCornersDllType, $corners, $bIdsDllType, $ids, $bBorderColorDllType, $borderColor), "cveArucoDrawDetectedMarkers", @error)
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

    Local $bCornersDllType
    If VarGetType($corners) == "DLLStruct" Then
        $bCornersDllType = "struct*"
    Else
        $bCornersDllType = "ptr"
    EndIf

    Local $bIdsDllType
    If VarGetType($ids) == "DLLStruct" Then
        $bIdsDllType = "struct*"
    Else
        $bIdsDllType = "ptr"
    EndIf

    Local $bCounterDllType
    If VarGetType($counter) == "DLLStruct" Then
        $bCounterDllType = "struct*"
    Else
        $bCounterDllType = "ptr"
    EndIf

    Local $bBoardDllType
    If VarGetType($board) == "DLLStruct" Then
        $bBoardDllType = "struct*"
    Else
        $bBoardDllType = "ptr"
    EndIf

    Local $bImageSizeDllType
    If VarGetType($imageSize) == "DLLStruct" Then
        $bImageSizeDllType = "struct*"
    Else
        $bImageSizeDllType = "ptr"
    EndIf

    Local $bCameraMatrixDllType
    If VarGetType($cameraMatrix) == "DLLStruct" Then
        $bCameraMatrixDllType = "struct*"
    Else
        $bCameraMatrixDllType = "ptr"
    EndIf

    Local $bDistCoeffsDllType
    If VarGetType($distCoeffs) == "DLLStruct" Then
        $bDistCoeffsDllType = "struct*"
    Else
        $bDistCoeffsDllType = "ptr"
    EndIf

    Local $bRvecsDllType
    If VarGetType($rvecs) == "DLLStruct" Then
        $bRvecsDllType = "struct*"
    Else
        $bRvecsDllType = "ptr"
    EndIf

    Local $bTvecsDllType
    If VarGetType($tvecs) == "DLLStruct" Then
        $bTvecsDllType = "struct*"
    Else
        $bTvecsDllType = "ptr"
    EndIf

    Local $bStdDeviationsIntrinsicsDllType
    If VarGetType($stdDeviationsIntrinsics) == "DLLStruct" Then
        $bStdDeviationsIntrinsicsDllType = "struct*"
    Else
        $bStdDeviationsIntrinsicsDllType = "ptr"
    EndIf

    Local $bStdDeviationsExtrinsicsDllType
    If VarGetType($stdDeviationsExtrinsics) == "DLLStruct" Then
        $bStdDeviationsExtrinsicsDllType = "struct*"
    Else
        $bStdDeviationsExtrinsicsDllType = "ptr"
    EndIf

    Local $bPerViewErrorsDllType
    If VarGetType($perViewErrors) == "DLLStruct" Then
        $bPerViewErrorsDllType = "struct*"
    Else
        $bPerViewErrorsDllType = "ptr"
    EndIf

    Local $bCriteriaDllType
    If VarGetType($criteria) == "DLLStruct" Then
        $bCriteriaDllType = "struct*"
    Else
        $bCriteriaDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveArucoCalibrateCameraAruco", $bCornersDllType, $corners, $bIdsDllType, $ids, $bCounterDllType, $counter, $bBoardDllType, $board, $bImageSizeDllType, $imageSize, $bCameraMatrixDllType, $cameraMatrix, $bDistCoeffsDllType, $distCoeffs, $bRvecsDllType, $rvecs, $bTvecsDllType, $tvecs, $bStdDeviationsIntrinsicsDllType, $stdDeviationsIntrinsics, $bStdDeviationsExtrinsicsDllType, $stdDeviationsExtrinsics, $bPerViewErrorsDllType, $perViewErrors, "int", $flags, $bCriteriaDllType, $criteria), "cveArucoCalibrateCameraAruco", @error)
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

    Local $bCharucoCornersDllType
    If VarGetType($charucoCorners) == "DLLStruct" Then
        $bCharucoCornersDllType = "struct*"
    Else
        $bCharucoCornersDllType = "ptr"
    EndIf

    Local $bCharucoIdsDllType
    If VarGetType($charucoIds) == "DLLStruct" Then
        $bCharucoIdsDllType = "struct*"
    Else
        $bCharucoIdsDllType = "ptr"
    EndIf

    Local $bBoardDllType
    If VarGetType($board) == "DLLStruct" Then
        $bBoardDllType = "struct*"
    Else
        $bBoardDllType = "ptr"
    EndIf

    Local $bImageSizeDllType
    If VarGetType($imageSize) == "DLLStruct" Then
        $bImageSizeDllType = "struct*"
    Else
        $bImageSizeDllType = "ptr"
    EndIf

    Local $bCameraMatrixDllType
    If VarGetType($cameraMatrix) == "DLLStruct" Then
        $bCameraMatrixDllType = "struct*"
    Else
        $bCameraMatrixDllType = "ptr"
    EndIf

    Local $bDistCoeffsDllType
    If VarGetType($distCoeffs) == "DLLStruct" Then
        $bDistCoeffsDllType = "struct*"
    Else
        $bDistCoeffsDllType = "ptr"
    EndIf

    Local $bRvecsDllType
    If VarGetType($rvecs) == "DLLStruct" Then
        $bRvecsDllType = "struct*"
    Else
        $bRvecsDllType = "ptr"
    EndIf

    Local $bTvecsDllType
    If VarGetType($tvecs) == "DLLStruct" Then
        $bTvecsDllType = "struct*"
    Else
        $bTvecsDllType = "ptr"
    EndIf

    Local $bStdDeviationsIntrinsicsDllType
    If VarGetType($stdDeviationsIntrinsics) == "DLLStruct" Then
        $bStdDeviationsIntrinsicsDllType = "struct*"
    Else
        $bStdDeviationsIntrinsicsDllType = "ptr"
    EndIf

    Local $bStdDeviationsExtrinsicsDllType
    If VarGetType($stdDeviationsExtrinsics) == "DLLStruct" Then
        $bStdDeviationsExtrinsicsDllType = "struct*"
    Else
        $bStdDeviationsExtrinsicsDllType = "ptr"
    EndIf

    Local $bPerViewErrorsDllType
    If VarGetType($perViewErrors) == "DLLStruct" Then
        $bPerViewErrorsDllType = "struct*"
    Else
        $bPerViewErrorsDllType = "ptr"
    EndIf

    Local $bCriteriaDllType
    If VarGetType($criteria) == "DLLStruct" Then
        $bCriteriaDllType = "struct*"
    Else
        $bCriteriaDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveArucoCalibrateCameraCharuco", $bCharucoCornersDllType, $charucoCorners, $bCharucoIdsDllType, $charucoIds, $bBoardDllType, $board, $bImageSizeDllType, $imageSize, $bCameraMatrixDllType, $cameraMatrix, $bDistCoeffsDllType, $distCoeffs, $bRvecsDllType, $rvecs, $bTvecsDllType, $tvecs, $bStdDeviationsIntrinsicsDllType, $stdDeviationsIntrinsics, $bStdDeviationsExtrinsicsDllType, $stdDeviationsExtrinsics, $bPerViewErrorsDllType, $perViewErrors, "int", $flags, $bCriteriaDllType, $criteria), "cveArucoCalibrateCameraCharuco", @error)
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

    Local $bParametersDllType
    If VarGetType($parameters) == "DLLStruct" Then
        $bParametersDllType = "struct*"
    Else
        $bParametersDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveArucoDetectorParametersGetDefault", $bParametersDllType, $parameters), "cveArucoDetectorParametersGetDefault", @error)
EndFunc   ;==>_cveArucoDetectorParametersGetDefault

Func _cveArucoInterpolateCornersCharuco($markerCorners, $markerIds, $image, $board, $charucoCorners, $charucoIds, $cameraMatrix, $distCoeffs, $minMarkers)
    ; CVAPI(int) cveArucoInterpolateCornersCharuco(cv::_InputArray* markerCorners, cv::_InputArray* markerIds, cv::_InputArray* image, cv::aruco::CharucoBoard* board, cv::_OutputArray* charucoCorners, cv::_OutputArray* charucoIds, cv::_InputArray* cameraMatrix, cv::_InputArray* distCoeffs, int minMarkers);

    Local $bMarkerCornersDllType
    If VarGetType($markerCorners) == "DLLStruct" Then
        $bMarkerCornersDllType = "struct*"
    Else
        $bMarkerCornersDllType = "ptr"
    EndIf

    Local $bMarkerIdsDllType
    If VarGetType($markerIds) == "DLLStruct" Then
        $bMarkerIdsDllType = "struct*"
    Else
        $bMarkerIdsDllType = "ptr"
    EndIf

    Local $bImageDllType
    If VarGetType($image) == "DLLStruct" Then
        $bImageDllType = "struct*"
    Else
        $bImageDllType = "ptr"
    EndIf

    Local $bBoardDllType
    If VarGetType($board) == "DLLStruct" Then
        $bBoardDllType = "struct*"
    Else
        $bBoardDllType = "ptr"
    EndIf

    Local $bCharucoCornersDllType
    If VarGetType($charucoCorners) == "DLLStruct" Then
        $bCharucoCornersDllType = "struct*"
    Else
        $bCharucoCornersDllType = "ptr"
    EndIf

    Local $bCharucoIdsDllType
    If VarGetType($charucoIds) == "DLLStruct" Then
        $bCharucoIdsDllType = "struct*"
    Else
        $bCharucoIdsDllType = "ptr"
    EndIf

    Local $bCameraMatrixDllType
    If VarGetType($cameraMatrix) == "DLLStruct" Then
        $bCameraMatrixDllType = "struct*"
    Else
        $bCameraMatrixDllType = "ptr"
    EndIf

    Local $bDistCoeffsDllType
    If VarGetType($distCoeffs) == "DLLStruct" Then
        $bDistCoeffsDllType = "struct*"
    Else
        $bDistCoeffsDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveArucoInterpolateCornersCharuco", $bMarkerCornersDllType, $markerCorners, $bMarkerIdsDllType, $markerIds, $bImageDllType, $image, $bBoardDllType, $board, $bCharucoCornersDllType, $charucoCorners, $bCharucoIdsDllType, $charucoIds, $bCameraMatrixDllType, $cameraMatrix, $bDistCoeffsDllType, $distCoeffs, "int", $minMarkers), "cveArucoInterpolateCornersCharuco", @error)
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

    Local $bImageDllType
    If VarGetType($image) == "DLLStruct" Then
        $bImageDllType = "struct*"
    Else
        $bImageDllType = "ptr"
    EndIf

    Local $bCharucoCornersDllType
    If VarGetType($charucoCorners) == "DLLStruct" Then
        $bCharucoCornersDllType = "struct*"
    Else
        $bCharucoCornersDllType = "ptr"
    EndIf

    Local $bCharucoIdsDllType
    If VarGetType($charucoIds) == "DLLStruct" Then
        $bCharucoIdsDllType = "struct*"
    Else
        $bCharucoIdsDllType = "ptr"
    EndIf

    Local $bCornerColorDllType
    If VarGetType($cornerColor) == "DLLStruct" Then
        $bCornerColorDllType = "struct*"
    Else
        $bCornerColorDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveArucoDrawDetectedCornersCharuco", $bImageDllType, $image, $bCharucoCornersDllType, $charucoCorners, $bCharucoIdsDllType, $charucoIds, $bCornerColorDllType, $cornerColor), "cveArucoDrawDetectedCornersCharuco", @error)
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

    Local $bCharucoCornersDllType
    If VarGetType($charucoCorners) == "DLLStruct" Then
        $bCharucoCornersDllType = "struct*"
    Else
        $bCharucoCornersDllType = "ptr"
    EndIf

    Local $bCharucoIdsDllType
    If VarGetType($charucoIds) == "DLLStruct" Then
        $bCharucoIdsDllType = "struct*"
    Else
        $bCharucoIdsDllType = "ptr"
    EndIf

    Local $bBoardDllType
    If VarGetType($board) == "DLLStruct" Then
        $bBoardDllType = "struct*"
    Else
        $bBoardDllType = "ptr"
    EndIf

    Local $bCameraMatrixDllType
    If VarGetType($cameraMatrix) == "DLLStruct" Then
        $bCameraMatrixDllType = "struct*"
    Else
        $bCameraMatrixDllType = "ptr"
    EndIf

    Local $bDistCoeffsDllType
    If VarGetType($distCoeffs) == "DLLStruct" Then
        $bDistCoeffsDllType = "struct*"
    Else
        $bDistCoeffsDllType = "ptr"
    EndIf

    Local $bRvecDllType
    If VarGetType($rvec) == "DLLStruct" Then
        $bRvecDllType = "struct*"
    Else
        $bRvecDllType = "ptr"
    EndIf

    Local $bTvecDllType
    If VarGetType($tvec) == "DLLStruct" Then
        $bTvecDllType = "struct*"
    Else
        $bTvecDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveArucoEstimatePoseCharucoBoard", $bCharucoCornersDllType, $charucoCorners, $bCharucoIdsDllType, $charucoIds, $bBoardDllType, $board, $bCameraMatrixDllType, $cameraMatrix, $bDistCoeffsDllType, $distCoeffs, $bRvecDllType, $rvec, $bTvecDllType, $tvec, "boolean", $useExtrinsicGuess), "cveArucoEstimatePoseCharucoBoard", @error)
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

    Local $bImageDllType
    If VarGetType($image) == "DLLStruct" Then
        $bImageDllType = "struct*"
    Else
        $bImageDllType = "ptr"
    EndIf

    Local $bMarkerCornersDllType
    If VarGetType($markerCorners) == "DLLStruct" Then
        $bMarkerCornersDllType = "struct*"
    Else
        $bMarkerCornersDllType = "ptr"
    EndIf

    Local $bMarkerIdsDllType
    If VarGetType($markerIds) == "DLLStruct" Then
        $bMarkerIdsDllType = "struct*"
    Else
        $bMarkerIdsDllType = "ptr"
    EndIf

    Local $bDiamondCornersDllType
    If VarGetType($diamondCorners) == "DLLStruct" Then
        $bDiamondCornersDllType = "struct*"
    Else
        $bDiamondCornersDllType = "ptr"
    EndIf

    Local $bDiamondIdsDllType
    If VarGetType($diamondIds) == "DLLStruct" Then
        $bDiamondIdsDllType = "struct*"
    Else
        $bDiamondIdsDllType = "ptr"
    EndIf

    Local $bCameraMatrixDllType
    If VarGetType($cameraMatrix) == "DLLStruct" Then
        $bCameraMatrixDllType = "struct*"
    Else
        $bCameraMatrixDllType = "ptr"
    EndIf

    Local $bDistCoeffsDllType
    If VarGetType($distCoeffs) == "DLLStruct" Then
        $bDistCoeffsDllType = "struct*"
    Else
        $bDistCoeffsDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveArucoDetectCharucoDiamond", $bImageDllType, $image, $bMarkerCornersDllType, $markerCorners, $bMarkerIdsDllType, $markerIds, "float", $squareMarkerLengthRate, $bDiamondCornersDllType, $diamondCorners, $bDiamondIdsDllType, $diamondIds, $bCameraMatrixDllType, $cameraMatrix, $bDistCoeffsDllType, $distCoeffs), "cveArucoDetectCharucoDiamond", @error)
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

    Local $bImageDllType
    If VarGetType($image) == "DLLStruct" Then
        $bImageDllType = "struct*"
    Else
        $bImageDllType = "ptr"
    EndIf

    Local $bDiamondCornersDllType
    If VarGetType($diamondCorners) == "DLLStruct" Then
        $bDiamondCornersDllType = "struct*"
    Else
        $bDiamondCornersDllType = "ptr"
    EndIf

    Local $bDiamondIdsDllType
    If VarGetType($diamondIds) == "DLLStruct" Then
        $bDiamondIdsDllType = "struct*"
    Else
        $bDiamondIdsDllType = "ptr"
    EndIf

    Local $bBorderColorDllType
    If VarGetType($borderColor) == "DLLStruct" Then
        $bBorderColorDllType = "struct*"
    Else
        $bBorderColorDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveArucoDrawDetectedDiamonds", $bImageDllType, $image, $bDiamondCornersDllType, $diamondCorners, $bDiamondIdsDllType, $diamondIds, $bBorderColorDllType, $borderColor), "cveArucoDrawDetectedDiamonds", @error)
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

    Local $bDictionaryDllType
    If VarGetType($dictionary) == "DLLStruct" Then
        $bDictionaryDllType = "struct*"
    Else
        $bDictionaryDllType = "ptr"
    EndIf

    Local $bIdsDllType
    If VarGetType($ids) == "DLLStruct" Then
        $bIdsDllType = "struct*"
    Else
        $bIdsDllType = "int*"
    EndIf

    Local $bImgDllType
    If VarGetType($img) == "DLLStruct" Then
        $bImgDllType = "struct*"
    Else
        $bImgDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveArucoDrawCharucoDiamond", $bDictionaryDllType, $dictionary, $bIdsDllType, $ids, "int", $squareLength, "int", $markerLength, $bImgDllType, $img, "int", $marginSize, "int", $borderBits), "cveArucoDrawCharucoDiamond", @error)
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

    Local $bBoardDllType
    If VarGetType($board) == "DLLStruct" Then
        $bBoardDllType = "struct*"
    Else
        $bBoardDllType = "ptr"
    EndIf

    Local $bOutSizeDllType
    If VarGetType($outSize) == "DLLStruct" Then
        $bOutSizeDllType = "struct*"
    Else
        $bOutSizeDllType = "ptr"
    EndIf

    Local $bImgDllType
    If VarGetType($img) == "DLLStruct" Then
        $bImgDllType = "struct*"
    Else
        $bImgDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveArucoDrawPlanarBoard", $bBoardDllType, $board, $bOutSizeDllType, $outSize, $bImgDllType, $img, "int", $marginSize, "int", $borderBits), "cveArucoDrawPlanarBoard", @error)
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

    Local $bCornersDllType
    If VarGetType($corners) == "DLLStruct" Then
        $bCornersDllType = "struct*"
    Else
        $bCornersDllType = "ptr"
    EndIf

    Local $bIdsDllType
    If VarGetType($ids) == "DLLStruct" Then
        $bIdsDllType = "struct*"
    Else
        $bIdsDllType = "ptr"
    EndIf

    Local $bBoardDllType
    If VarGetType($board) == "DLLStruct" Then
        $bBoardDllType = "struct*"
    Else
        $bBoardDllType = "ptr"
    EndIf

    Local $bCameraMatrixDllType
    If VarGetType($cameraMatrix) == "DLLStruct" Then
        $bCameraMatrixDllType = "struct*"
    Else
        $bCameraMatrixDllType = "ptr"
    EndIf

    Local $bDistCoeffsDllType
    If VarGetType($distCoeffs) == "DLLStruct" Then
        $bDistCoeffsDllType = "struct*"
    Else
        $bDistCoeffsDllType = "ptr"
    EndIf

    Local $bRvecDllType
    If VarGetType($rvec) == "DLLStruct" Then
        $bRvecDllType = "struct*"
    Else
        $bRvecDllType = "ptr"
    EndIf

    Local $bTvecDllType
    If VarGetType($tvec) == "DLLStruct" Then
        $bTvecDllType = "struct*"
    Else
        $bTvecDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveArucoEstimatePoseBoard", $bCornersDllType, $corners, $bIdsDllType, $ids, $bBoardDllType, $board, $bCameraMatrixDllType, $cameraMatrix, $bDistCoeffsDllType, $distCoeffs, $bRvecDllType, $rvec, $bTvecDllType, $tvec, "boolean", $useExtrinsicGuess), "cveArucoEstimatePoseBoard", @error)
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

    Local $bBoardDllType
    If VarGetType($board) == "DLLStruct" Then
        $bBoardDllType = "struct*"
    Else
        $bBoardDllType = "ptr"
    EndIf

    Local $bDetectedCornersDllType
    If VarGetType($detectedCorners) == "DLLStruct" Then
        $bDetectedCornersDllType = "struct*"
    Else
        $bDetectedCornersDllType = "ptr"
    EndIf

    Local $bDetectedIdsDllType
    If VarGetType($detectedIds) == "DLLStruct" Then
        $bDetectedIdsDllType = "struct*"
    Else
        $bDetectedIdsDllType = "ptr"
    EndIf

    Local $bObjPointsDllType
    If VarGetType($objPoints) == "DLLStruct" Then
        $bObjPointsDllType = "struct*"
    Else
        $bObjPointsDllType = "ptr"
    EndIf

    Local $bImgPointsDllType
    If VarGetType($imgPoints) == "DLLStruct" Then
        $bImgPointsDllType = "struct*"
    Else
        $bImgPointsDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveArucoGetBoardObjectAndImagePoints", $bBoardDllType, $board, $bDetectedCornersDllType, $detectedCorners, $bDetectedIdsDllType, $detectedIds, $bObjPointsDllType, $objPoints, $bImgPointsDllType, $imgPoints), "cveArucoGetBoardObjectAndImagePoints", @error)
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