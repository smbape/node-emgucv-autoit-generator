#include-once
#include "..\..\CVEUtils.au3"

Func _cveEstimateAffine3D(ByRef $src, ByRef $dst, ByRef $out, ByRef $inliers, $ransacThreshold, $confidence)
    ; CVAPI(int) cveEstimateAffine3D(cv::_InputArray* src, cv::_InputArray* dst, cv::_OutputArray* out, cv::_OutputArray* inliers, double ransacThreshold, double confidence);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveEstimateAffine3D", "ptr", $src, "ptr", $dst, "ptr", $out, "ptr", $inliers, "double", $ransacThreshold, "double", $confidence), "cveEstimateAffine3D", @error)
EndFunc   ;==>_cveEstimateAffine3D

Func _cveEstimateAffine3DMat(ByRef $matSrc, ByRef $matDst, ByRef $matOut, ByRef $matInliers, $ransacThreshold, $confidence)
    ; cveEstimateAffine3D using cv::Mat instead of _*Array

    Local $iArrSrc, $vectorOfMatSrc, $iArrSrcSize
    Local $bSrcIsArray = VarGetType($matSrc) == "Array"

    If $bSrcIsArray Then
        $vectorOfMatSrc = _VectorOfMatCreate()

        $iArrSrcSize = UBound($matSrc)
        For $i = 0 To $iArrSrcSize - 1
            _VectorOfMatPush($vectorOfMatSrc, $matSrc[$i])
        Next

        $iArrSrc = _cveInputArrayFromVectorOfMat($vectorOfMatSrc)
    Else
        $iArrSrc = _cveInputArrayFromMat($matSrc)
    EndIf

    Local $iArrDst, $vectorOfMatDst, $iArrDstSize
    Local $bDstIsArray = VarGetType($matDst) == "Array"

    If $bDstIsArray Then
        $vectorOfMatDst = _VectorOfMatCreate()

        $iArrDstSize = UBound($matDst)
        For $i = 0 To $iArrDstSize - 1
            _VectorOfMatPush($vectorOfMatDst, $matDst[$i])
        Next

        $iArrDst = _cveInputArrayFromVectorOfMat($vectorOfMatDst)
    Else
        $iArrDst = _cveInputArrayFromMat($matDst)
    EndIf

    Local $oArrOut, $vectorOfMatOut, $iArrOutSize
    Local $bOutIsArray = VarGetType($matOut) == "Array"

    If $bOutIsArray Then
        $vectorOfMatOut = _VectorOfMatCreate()

        $iArrOutSize = UBound($matOut)
        For $i = 0 To $iArrOutSize - 1
            _VectorOfMatPush($vectorOfMatOut, $matOut[$i])
        Next

        $oArrOut = _cveOutputArrayFromVectorOfMat($vectorOfMatOut)
    Else
        $oArrOut = _cveOutputArrayFromMat($matOut)
    EndIf

    Local $oArrInliers, $vectorOfMatInliers, $iArrInliersSize
    Local $bInliersIsArray = VarGetType($matInliers) == "Array"

    If $bInliersIsArray Then
        $vectorOfMatInliers = _VectorOfMatCreate()

        $iArrInliersSize = UBound($matInliers)
        For $i = 0 To $iArrInliersSize - 1
            _VectorOfMatPush($vectorOfMatInliers, $matInliers[$i])
        Next

        $oArrInliers = _cveOutputArrayFromVectorOfMat($vectorOfMatInliers)
    Else
        $oArrInliers = _cveOutputArrayFromMat($matInliers)
    EndIf

    Local $retval = _cveEstimateAffine3D($iArrSrc, $iArrDst, $oArrOut, $oArrInliers, $ransacThreshold, $confidence)

    If $bInliersIsArray Then
        _VectorOfMatRelease($vectorOfMatInliers)
    EndIf

    _cveOutputArrayRelease($oArrInliers)

    If $bOutIsArray Then
        _VectorOfMatRelease($vectorOfMatOut)
    EndIf

    _cveOutputArrayRelease($oArrOut)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveInputArrayRelease($iArrDst)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)

    Return $retval
EndFunc   ;==>_cveEstimateAffine3DMat

Func _cveStereoSGBMCreate($minDisparity, $numDisparities, $blockSize, $P1, $P2, $disp12MaxDiff, $preFilterCap, $uniquenessRatio, $speckleWindowSize, $speckleRange, $mode, ByRef $stereoMatcher, ByRef $sharedPtr)
    ; CVAPI(cv::StereoSGBM*) cveStereoSGBMCreate(int minDisparity, int numDisparities, int blockSize, int P1, int P2, int disp12MaxDiff, int preFilterCap, int uniquenessRatio, int speckleWindowSize, int speckleRange, int mode, cv::StereoMatcher** stereoMatcher, cv::Ptr<cv::StereoSGBM>** sharedPtr);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveStereoSGBMCreate", "int", $minDisparity, "int", $numDisparities, "int", $blockSize, "int", $P1, "int", $P2, "int", $disp12MaxDiff, "int", $preFilterCap, "int", $uniquenessRatio, "int", $speckleWindowSize, "int", $speckleRange, "int", $mode, "ptr*", $stereoMatcher, "ptr*", $sharedPtr), "cveStereoSGBMCreate", @error)
EndFunc   ;==>_cveStereoSGBMCreate

Func _cveStereoSGBMRelease(ByRef $sharedPtr)
    ; CVAPI(void) cveStereoSGBMRelease(cv::Ptr<cv::StereoSGBM>** sharedPtr);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveStereoSGBMRelease", "ptr*", $sharedPtr), "cveStereoSGBMRelease", @error)
EndFunc   ;==>_cveStereoSGBMRelease

Func _cveStereoBMCreate($mode, $numberOfDisparities, ByRef $sharedPtr)
    ; CVAPI(cv::StereoMatcher*) cveStereoBMCreate(int mode, int numberOfDisparities, cv::Ptr<cv::StereoMatcher>** sharedPtr);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveStereoBMCreate", "int", $mode, "int", $numberOfDisparities, "ptr*", $sharedPtr), "cveStereoBMCreate", @error)
EndFunc   ;==>_cveStereoBMCreate

Func _cveStereoMatcherCompute(ByRef $disparitySolver, ByRef $left, ByRef $right, ByRef $disparity)
    ; CVAPI(void) cveStereoMatcherCompute(cv::StereoMatcher* disparitySolver, cv::_InputArray* left, cv::_InputArray* right, cv::_OutputArray* disparity);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveStereoMatcherCompute", "ptr", $disparitySolver, "ptr", $left, "ptr", $right, "ptr", $disparity), "cveStereoMatcherCompute", @error)
EndFunc   ;==>_cveStereoMatcherCompute

Func _cveStereoMatcherComputeMat(ByRef $disparitySolver, ByRef $matLeft, ByRef $matRight, ByRef $matDisparity)
    ; cveStereoMatcherCompute using cv::Mat instead of _*Array

    Local $iArrLeft, $vectorOfMatLeft, $iArrLeftSize
    Local $bLeftIsArray = VarGetType($matLeft) == "Array"

    If $bLeftIsArray Then
        $vectorOfMatLeft = _VectorOfMatCreate()

        $iArrLeftSize = UBound($matLeft)
        For $i = 0 To $iArrLeftSize - 1
            _VectorOfMatPush($vectorOfMatLeft, $matLeft[$i])
        Next

        $iArrLeft = _cveInputArrayFromVectorOfMat($vectorOfMatLeft)
    Else
        $iArrLeft = _cveInputArrayFromMat($matLeft)
    EndIf

    Local $iArrRight, $vectorOfMatRight, $iArrRightSize
    Local $bRightIsArray = VarGetType($matRight) == "Array"

    If $bRightIsArray Then
        $vectorOfMatRight = _VectorOfMatCreate()

        $iArrRightSize = UBound($matRight)
        For $i = 0 To $iArrRightSize - 1
            _VectorOfMatPush($vectorOfMatRight, $matRight[$i])
        Next

        $iArrRight = _cveInputArrayFromVectorOfMat($vectorOfMatRight)
    Else
        $iArrRight = _cveInputArrayFromMat($matRight)
    EndIf

    Local $oArrDisparity, $vectorOfMatDisparity, $iArrDisparitySize
    Local $bDisparityIsArray = VarGetType($matDisparity) == "Array"

    If $bDisparityIsArray Then
        $vectorOfMatDisparity = _VectorOfMatCreate()

        $iArrDisparitySize = UBound($matDisparity)
        For $i = 0 To $iArrDisparitySize - 1
            _VectorOfMatPush($vectorOfMatDisparity, $matDisparity[$i])
        Next

        $oArrDisparity = _cveOutputArrayFromVectorOfMat($vectorOfMatDisparity)
    Else
        $oArrDisparity = _cveOutputArrayFromMat($matDisparity)
    EndIf

    _cveStereoMatcherCompute($disparitySolver, $iArrLeft, $iArrRight, $oArrDisparity)

    If $bDisparityIsArray Then
        _VectorOfMatRelease($vectorOfMatDisparity)
    EndIf

    _cveOutputArrayRelease($oArrDisparity)

    If $bRightIsArray Then
        _VectorOfMatRelease($vectorOfMatRight)
    EndIf

    _cveInputArrayRelease($iArrRight)

    If $bLeftIsArray Then
        _VectorOfMatRelease($vectorOfMatLeft)
    EndIf

    _cveInputArrayRelease($iArrLeft)
EndFunc   ;==>_cveStereoMatcherComputeMat

Func _cveStereoMatcherRelease(ByRef $sharedPtr)
    ; CVAPI(void) cveStereoMatcherRelease(cv::Ptr<cv::StereoMatcher>** sharedPtr);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveStereoMatcherRelease", "ptr*", $sharedPtr), "cveStereoMatcherRelease", @error)
EndFunc   ;==>_cveStereoMatcherRelease

Func _getHomographyMatrixFromMatchedFeatures(ByRef $model, ByRef $observed, ByRef $matches, ByRef $mask, $randsacThreshold, ByRef $homography)
    ; CVAPI(bool) getHomographyMatrixFromMatchedFeatures(std::vector<cv::KeyPoint>* model, std::vector<cv::KeyPoint>* observed, std::vector< std::vector< cv::DMatch > >* matches, cv::Mat* mask, double randsacThreshold, cv::Mat* homography);

    Local $vecModel, $iArrModelSize
    Local $bModelIsArray = VarGetType($model) == "Array"

    If $bModelIsArray Then
        $vecModel = _VectorOfKeyPointCreate()

        $iArrModelSize = UBound($model)
        For $i = 0 To $iArrModelSize - 1
            _VectorOfKeyPointPush($vecModel, $model[$i])
        Next
    Else
        $vecModel = $model
    EndIf

    Local $vecObserved, $iArrObservedSize
    Local $bObservedIsArray = VarGetType($observed) == "Array"

    If $bObservedIsArray Then
        $vecObserved = _VectorOfKeyPointCreate()

        $iArrObservedSize = UBound($observed)
        For $i = 0 To $iArrObservedSize - 1
            _VectorOfKeyPointPush($vecObserved, $observed[$i])
        Next
    Else
        $vecObserved = $observed
    EndIf

    Local $vecMatches, $iArrMatchesSize
    Local $bMatchesIsArray = VarGetType($matches) == "Array"

    If $bMatchesIsArray Then
        $vecMatches = _VectorOfVectorOfDMatchCreate()

        $iArrMatchesSize = UBound($matches)
        For $i = 0 To $iArrMatchesSize - 1
            _VectorOfVectorOfDMatchPush($vecMatches, $matches[$i])
        Next
    Else
        $vecMatches = $matches
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "getHomographyMatrixFromMatchedFeatures", "ptr", $vecModel, "ptr", $vecObserved, "ptr", $vecMatches, "ptr", $mask, "double", $randsacThreshold, "ptr", $homography), "getHomographyMatrixFromMatchedFeatures", @error)

    If $bMatchesIsArray Then
        _VectorOfVectorOfDMatchRelease($vecMatches)
    EndIf

    If $bObservedIsArray Then
        _VectorOfKeyPointRelease($vecObserved)
    EndIf

    If $bModelIsArray Then
        _VectorOfKeyPointRelease($vecModel)
    EndIf

    Return $retval
EndFunc   ;==>_getHomographyMatrixFromMatchedFeatures

Func _cveFindCirclesGrid(ByRef $image, ByRef $patternSize, ByRef $centers, $flags, ByRef $blobDetector)
    ; CVAPI(bool) cveFindCirclesGrid(cv::_InputArray* image, CvSize* patternSize, cv::_OutputArray* centers, int flags, cv::Feature2D* blobDetector);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveFindCirclesGrid", "ptr", $image, "struct*", $patternSize, "ptr", $centers, "int", $flags, "ptr", $blobDetector), "cveFindCirclesGrid", @error)
EndFunc   ;==>_cveFindCirclesGrid

Func _cveFindCirclesGridMat(ByRef $matImage, ByRef $patternSize, ByRef $matCenters, $flags, ByRef $blobDetector)
    ; cveFindCirclesGrid using cv::Mat instead of _*Array

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

    Local $oArrCenters, $vectorOfMatCenters, $iArrCentersSize
    Local $bCentersIsArray = VarGetType($matCenters) == "Array"

    If $bCentersIsArray Then
        $vectorOfMatCenters = _VectorOfMatCreate()

        $iArrCentersSize = UBound($matCenters)
        For $i = 0 To $iArrCentersSize - 1
            _VectorOfMatPush($vectorOfMatCenters, $matCenters[$i])
        Next

        $oArrCenters = _cveOutputArrayFromVectorOfMat($vectorOfMatCenters)
    Else
        $oArrCenters = _cveOutputArrayFromMat($matCenters)
    EndIf

    Local $retval = _cveFindCirclesGrid($iArrImage, $patternSize, $oArrCenters, $flags, $blobDetector)

    If $bCentersIsArray Then
        _VectorOfMatRelease($vectorOfMatCenters)
    EndIf

    _cveOutputArrayRelease($oArrCenters)

    If $bImageIsArray Then
        _VectorOfMatRelease($vectorOfMatImage)
    EndIf

    _cveInputArrayRelease($iArrImage)

    Return $retval
EndFunc   ;==>_cveFindCirclesGridMat

Func _cveTriangulatePoints(ByRef $projMat1, ByRef $projMat2, ByRef $projPoints1, ByRef $projPoints2, ByRef $points4D)
    ; CVAPI(void) cveTriangulatePoints(cv::_InputArray* projMat1, cv::_InputArray* projMat2, cv::_InputArray* projPoints1, cv::_InputArray* projPoints2, cv::_OutputArray* points4D);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveTriangulatePoints", "ptr", $projMat1, "ptr", $projMat2, "ptr", $projPoints1, "ptr", $projPoints2, "ptr", $points4D), "cveTriangulatePoints", @error)
EndFunc   ;==>_cveTriangulatePoints

Func _cveTriangulatePointsMat(ByRef $matProjMat1, ByRef $matProjMat2, ByRef $matProjPoints1, ByRef $matProjPoints2, ByRef $matPoints4D)
    ; cveTriangulatePoints using cv::Mat instead of _*Array

    Local $iArrProjMat1, $vectorOfMatProjMat1, $iArrProjMat1Size
    Local $bProjMat1IsArray = VarGetType($matProjMat1) == "Array"

    If $bProjMat1IsArray Then
        $vectorOfMatProjMat1 = _VectorOfMatCreate()

        $iArrProjMat1Size = UBound($matProjMat1)
        For $i = 0 To $iArrProjMat1Size - 1
            _VectorOfMatPush($vectorOfMatProjMat1, $matProjMat1[$i])
        Next

        $iArrProjMat1 = _cveInputArrayFromVectorOfMat($vectorOfMatProjMat1)
    Else
        $iArrProjMat1 = _cveInputArrayFromMat($matProjMat1)
    EndIf

    Local $iArrProjMat2, $vectorOfMatProjMat2, $iArrProjMat2Size
    Local $bProjMat2IsArray = VarGetType($matProjMat2) == "Array"

    If $bProjMat2IsArray Then
        $vectorOfMatProjMat2 = _VectorOfMatCreate()

        $iArrProjMat2Size = UBound($matProjMat2)
        For $i = 0 To $iArrProjMat2Size - 1
            _VectorOfMatPush($vectorOfMatProjMat2, $matProjMat2[$i])
        Next

        $iArrProjMat2 = _cveInputArrayFromVectorOfMat($vectorOfMatProjMat2)
    Else
        $iArrProjMat2 = _cveInputArrayFromMat($matProjMat2)
    EndIf

    Local $iArrProjPoints1, $vectorOfMatProjPoints1, $iArrProjPoints1Size
    Local $bProjPoints1IsArray = VarGetType($matProjPoints1) == "Array"

    If $bProjPoints1IsArray Then
        $vectorOfMatProjPoints1 = _VectorOfMatCreate()

        $iArrProjPoints1Size = UBound($matProjPoints1)
        For $i = 0 To $iArrProjPoints1Size - 1
            _VectorOfMatPush($vectorOfMatProjPoints1, $matProjPoints1[$i])
        Next

        $iArrProjPoints1 = _cveInputArrayFromVectorOfMat($vectorOfMatProjPoints1)
    Else
        $iArrProjPoints1 = _cveInputArrayFromMat($matProjPoints1)
    EndIf

    Local $iArrProjPoints2, $vectorOfMatProjPoints2, $iArrProjPoints2Size
    Local $bProjPoints2IsArray = VarGetType($matProjPoints2) == "Array"

    If $bProjPoints2IsArray Then
        $vectorOfMatProjPoints2 = _VectorOfMatCreate()

        $iArrProjPoints2Size = UBound($matProjPoints2)
        For $i = 0 To $iArrProjPoints2Size - 1
            _VectorOfMatPush($vectorOfMatProjPoints2, $matProjPoints2[$i])
        Next

        $iArrProjPoints2 = _cveInputArrayFromVectorOfMat($vectorOfMatProjPoints2)
    Else
        $iArrProjPoints2 = _cveInputArrayFromMat($matProjPoints2)
    EndIf

    Local $oArrPoints4D, $vectorOfMatPoints4D, $iArrPoints4DSize
    Local $bPoints4DIsArray = VarGetType($matPoints4D) == "Array"

    If $bPoints4DIsArray Then
        $vectorOfMatPoints4D = _VectorOfMatCreate()

        $iArrPoints4DSize = UBound($matPoints4D)
        For $i = 0 To $iArrPoints4DSize - 1
            _VectorOfMatPush($vectorOfMatPoints4D, $matPoints4D[$i])
        Next

        $oArrPoints4D = _cveOutputArrayFromVectorOfMat($vectorOfMatPoints4D)
    Else
        $oArrPoints4D = _cveOutputArrayFromMat($matPoints4D)
    EndIf

    _cveTriangulatePoints($iArrProjMat1, $iArrProjMat2, $iArrProjPoints1, $iArrProjPoints2, $oArrPoints4D)

    If $bPoints4DIsArray Then
        _VectorOfMatRelease($vectorOfMatPoints4D)
    EndIf

    _cveOutputArrayRelease($oArrPoints4D)

    If $bProjPoints2IsArray Then
        _VectorOfMatRelease($vectorOfMatProjPoints2)
    EndIf

    _cveInputArrayRelease($iArrProjPoints2)

    If $bProjPoints1IsArray Then
        _VectorOfMatRelease($vectorOfMatProjPoints1)
    EndIf

    _cveInputArrayRelease($iArrProjPoints1)

    If $bProjMat2IsArray Then
        _VectorOfMatRelease($vectorOfMatProjMat2)
    EndIf

    _cveInputArrayRelease($iArrProjMat2)

    If $bProjMat1IsArray Then
        _VectorOfMatRelease($vectorOfMatProjMat1)
    EndIf

    _cveInputArrayRelease($iArrProjMat1)
EndFunc   ;==>_cveTriangulatePointsMat

Func _cveCorrectMatches(ByRef $f, ByRef $points1, ByRef $points2, ByRef $newPoints1, ByRef $newPoints2)
    ; CVAPI(void) cveCorrectMatches(cv::_InputArray* f, cv::_InputArray* points1, cv::_InputArray* points2, cv::_OutputArray* newPoints1, cv::_OutputArray* newPoints2);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCorrectMatches", "ptr", $f, "ptr", $points1, "ptr", $points2, "ptr", $newPoints1, "ptr", $newPoints2), "cveCorrectMatches", @error)
EndFunc   ;==>_cveCorrectMatches

Func _cveCorrectMatchesMat(ByRef $matF, ByRef $matPoints1, ByRef $matPoints2, ByRef $matNewPoints1, ByRef $matNewPoints2)
    ; cveCorrectMatches using cv::Mat instead of _*Array

    Local $iArrF, $vectorOfMatF, $iArrFSize
    Local $bFIsArray = VarGetType($matF) == "Array"

    If $bFIsArray Then
        $vectorOfMatF = _VectorOfMatCreate()

        $iArrFSize = UBound($matF)
        For $i = 0 To $iArrFSize - 1
            _VectorOfMatPush($vectorOfMatF, $matF[$i])
        Next

        $iArrF = _cveInputArrayFromVectorOfMat($vectorOfMatF)
    Else
        $iArrF = _cveInputArrayFromMat($matF)
    EndIf

    Local $iArrPoints1, $vectorOfMatPoints1, $iArrPoints1Size
    Local $bPoints1IsArray = VarGetType($matPoints1) == "Array"

    If $bPoints1IsArray Then
        $vectorOfMatPoints1 = _VectorOfMatCreate()

        $iArrPoints1Size = UBound($matPoints1)
        For $i = 0 To $iArrPoints1Size - 1
            _VectorOfMatPush($vectorOfMatPoints1, $matPoints1[$i])
        Next

        $iArrPoints1 = _cveInputArrayFromVectorOfMat($vectorOfMatPoints1)
    Else
        $iArrPoints1 = _cveInputArrayFromMat($matPoints1)
    EndIf

    Local $iArrPoints2, $vectorOfMatPoints2, $iArrPoints2Size
    Local $bPoints2IsArray = VarGetType($matPoints2) == "Array"

    If $bPoints2IsArray Then
        $vectorOfMatPoints2 = _VectorOfMatCreate()

        $iArrPoints2Size = UBound($matPoints2)
        For $i = 0 To $iArrPoints2Size - 1
            _VectorOfMatPush($vectorOfMatPoints2, $matPoints2[$i])
        Next

        $iArrPoints2 = _cveInputArrayFromVectorOfMat($vectorOfMatPoints2)
    Else
        $iArrPoints2 = _cveInputArrayFromMat($matPoints2)
    EndIf

    Local $oArrNewPoints1, $vectorOfMatNewPoints1, $iArrNewPoints1Size
    Local $bNewPoints1IsArray = VarGetType($matNewPoints1) == "Array"

    If $bNewPoints1IsArray Then
        $vectorOfMatNewPoints1 = _VectorOfMatCreate()

        $iArrNewPoints1Size = UBound($matNewPoints1)
        For $i = 0 To $iArrNewPoints1Size - 1
            _VectorOfMatPush($vectorOfMatNewPoints1, $matNewPoints1[$i])
        Next

        $oArrNewPoints1 = _cveOutputArrayFromVectorOfMat($vectorOfMatNewPoints1)
    Else
        $oArrNewPoints1 = _cveOutputArrayFromMat($matNewPoints1)
    EndIf

    Local $oArrNewPoints2, $vectorOfMatNewPoints2, $iArrNewPoints2Size
    Local $bNewPoints2IsArray = VarGetType($matNewPoints2) == "Array"

    If $bNewPoints2IsArray Then
        $vectorOfMatNewPoints2 = _VectorOfMatCreate()

        $iArrNewPoints2Size = UBound($matNewPoints2)
        For $i = 0 To $iArrNewPoints2Size - 1
            _VectorOfMatPush($vectorOfMatNewPoints2, $matNewPoints2[$i])
        Next

        $oArrNewPoints2 = _cveOutputArrayFromVectorOfMat($vectorOfMatNewPoints2)
    Else
        $oArrNewPoints2 = _cveOutputArrayFromMat($matNewPoints2)
    EndIf

    _cveCorrectMatches($iArrF, $iArrPoints1, $iArrPoints2, $oArrNewPoints1, $oArrNewPoints2)

    If $bNewPoints2IsArray Then
        _VectorOfMatRelease($vectorOfMatNewPoints2)
    EndIf

    _cveOutputArrayRelease($oArrNewPoints2)

    If $bNewPoints1IsArray Then
        _VectorOfMatRelease($vectorOfMatNewPoints1)
    EndIf

    _cveOutputArrayRelease($oArrNewPoints1)

    If $bPoints2IsArray Then
        _VectorOfMatRelease($vectorOfMatPoints2)
    EndIf

    _cveInputArrayRelease($iArrPoints2)

    If $bPoints1IsArray Then
        _VectorOfMatRelease($vectorOfMatPoints1)
    EndIf

    _cveInputArrayRelease($iArrPoints1)

    If $bFIsArray Then
        _VectorOfMatRelease($vectorOfMatF)
    EndIf

    _cveInputArrayRelease($iArrF)
EndFunc   ;==>_cveCorrectMatchesMat

Func _cveFindChessboardCornersSB(ByRef $image, ByRef $patternSize, ByRef $corners, $flags)
    ; CVAPI(bool) cveFindChessboardCornersSB(cv::_InputArray* image, CvSize* patternSize, cv::_OutputArray* corners, int flags);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveFindChessboardCornersSB", "ptr", $image, "struct*", $patternSize, "ptr", $corners, "int", $flags), "cveFindChessboardCornersSB", @error)
EndFunc   ;==>_cveFindChessboardCornersSB

Func _cveFindChessboardCornersSBMat(ByRef $matImage, ByRef $patternSize, ByRef $matCorners, $flags)
    ; cveFindChessboardCornersSB using cv::Mat instead of _*Array

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

    Local $retval = _cveFindChessboardCornersSB($iArrImage, $patternSize, $oArrCorners, $flags)

    If $bCornersIsArray Then
        _VectorOfMatRelease($vectorOfMatCorners)
    EndIf

    _cveOutputArrayRelease($oArrCorners)

    If $bImageIsArray Then
        _VectorOfMatRelease($vectorOfMatImage)
    EndIf

    _cveInputArrayRelease($iArrImage)

    Return $retval
EndFunc   ;==>_cveFindChessboardCornersSBMat

Func _cveEstimateChessboardSharpness(ByRef $image, ByRef $patternSize, ByRef $corners, $riseDistance, $vertical, ByRef $sharpness, ByRef $result)
    ; CVAPI(void) cveEstimateChessboardSharpness(cv::_InputArray* image, CvSize* patternSize, cv::_InputArray* corners, float riseDistance, bool vertical, cv::_OutputArray* sharpness, CvScalar* result);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveEstimateChessboardSharpness", "ptr", $image, "struct*", $patternSize, "ptr", $corners, "float", $riseDistance, "boolean", $vertical, "ptr", $sharpness, "struct*", $result), "cveEstimateChessboardSharpness", @error)
EndFunc   ;==>_cveEstimateChessboardSharpness

Func _cveEstimateChessboardSharpnessMat(ByRef $matImage, ByRef $patternSize, ByRef $matCorners, $riseDistance, $vertical, ByRef $matSharpness, ByRef $result)
    ; cveEstimateChessboardSharpness using cv::Mat instead of _*Array

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

    Local $oArrSharpness, $vectorOfMatSharpness, $iArrSharpnessSize
    Local $bSharpnessIsArray = VarGetType($matSharpness) == "Array"

    If $bSharpnessIsArray Then
        $vectorOfMatSharpness = _VectorOfMatCreate()

        $iArrSharpnessSize = UBound($matSharpness)
        For $i = 0 To $iArrSharpnessSize - 1
            _VectorOfMatPush($vectorOfMatSharpness, $matSharpness[$i])
        Next

        $oArrSharpness = _cveOutputArrayFromVectorOfMat($vectorOfMatSharpness)
    Else
        $oArrSharpness = _cveOutputArrayFromMat($matSharpness)
    EndIf

    _cveEstimateChessboardSharpness($iArrImage, $patternSize, $iArrCorners, $riseDistance, $vertical, $oArrSharpness, $result)

    If $bSharpnessIsArray Then
        _VectorOfMatRelease($vectorOfMatSharpness)
    EndIf

    _cveOutputArrayRelease($oArrSharpness)

    If $bCornersIsArray Then
        _VectorOfMatRelease($vectorOfMatCorners)
    EndIf

    _cveInputArrayRelease($iArrCorners)

    If $bImageIsArray Then
        _VectorOfMatRelease($vectorOfMatImage)
    EndIf

    _cveInputArrayRelease($iArrImage)
EndFunc   ;==>_cveEstimateChessboardSharpnessMat

Func _cveDrawChessboardCorners(ByRef $image, ByRef $patternSize, ByRef $corners, $patternWasFound)
    ; CVAPI(void) cveDrawChessboardCorners(cv::_InputOutputArray* image, CvSize* patternSize, cv::_InputArray* corners, bool patternWasFound);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDrawChessboardCorners", "ptr", $image, "struct*", $patternSize, "ptr", $corners, "boolean", $patternWasFound), "cveDrawChessboardCorners", @error)
EndFunc   ;==>_cveDrawChessboardCorners

Func _cveDrawChessboardCornersMat(ByRef $matImage, ByRef $patternSize, ByRef $matCorners, $patternWasFound)
    ; cveDrawChessboardCorners using cv::Mat instead of _*Array

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

    _cveDrawChessboardCorners($ioArrImage, $patternSize, $iArrCorners, $patternWasFound)

    If $bCornersIsArray Then
        _VectorOfMatRelease($vectorOfMatCorners)
    EndIf

    _cveInputArrayRelease($iArrCorners)

    If $bImageIsArray Then
        _VectorOfMatRelease($vectorOfMatImage)
    EndIf

    _cveInputOutputArrayRelease($ioArrImage)
EndFunc   ;==>_cveDrawChessboardCornersMat

Func _cveFilterSpeckles(ByRef $img, $newVal, $maxSpeckleSize, $maxDiff, ByRef $buf)
    ; CVAPI(void) cveFilterSpeckles(cv::_InputOutputArray* img, double newVal, int maxSpeckleSize, double maxDiff, cv::_InputOutputArray* buf);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFilterSpeckles", "ptr", $img, "double", $newVal, "int", $maxSpeckleSize, "double", $maxDiff, "ptr", $buf), "cveFilterSpeckles", @error)
EndFunc   ;==>_cveFilterSpeckles

Func _cveFilterSpecklesMat(ByRef $matImg, $newVal, $maxSpeckleSize, $maxDiff, ByRef $matBuf)
    ; cveFilterSpeckles using cv::Mat instead of _*Array

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

    Local $ioArrBuf, $vectorOfMatBuf, $iArrBufSize
    Local $bBufIsArray = VarGetType($matBuf) == "Array"

    If $bBufIsArray Then
        $vectorOfMatBuf = _VectorOfMatCreate()

        $iArrBufSize = UBound($matBuf)
        For $i = 0 To $iArrBufSize - 1
            _VectorOfMatPush($vectorOfMatBuf, $matBuf[$i])
        Next

        $ioArrBuf = _cveInputOutputArrayFromVectorOfMat($vectorOfMatBuf)
    Else
        $ioArrBuf = _cveInputOutputArrayFromMat($matBuf)
    EndIf

    _cveFilterSpeckles($ioArrImg, $newVal, $maxSpeckleSize, $maxDiff, $ioArrBuf)

    If $bBufIsArray Then
        _VectorOfMatRelease($vectorOfMatBuf)
    EndIf

    _cveInputOutputArrayRelease($ioArrBuf)

    If $bImgIsArray Then
        _VectorOfMatRelease($vectorOfMatImg)
    EndIf

    _cveInputOutputArrayRelease($ioArrImg)
EndFunc   ;==>_cveFilterSpecklesMat

Func _cveFindChessboardCorners(ByRef $image, ByRef $patternSize, ByRef $corners, $flags)
    ; CVAPI(bool) cveFindChessboardCorners(cv::_InputArray* image, CvSize* patternSize, cv::_OutputArray* corners, int flags);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveFindChessboardCorners", "ptr", $image, "struct*", $patternSize, "ptr", $corners, "int", $flags), "cveFindChessboardCorners", @error)
EndFunc   ;==>_cveFindChessboardCorners

Func _cveFindChessboardCornersMat(ByRef $matImage, ByRef $patternSize, ByRef $matCorners, $flags)
    ; cveFindChessboardCorners using cv::Mat instead of _*Array

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

    Local $retval = _cveFindChessboardCorners($iArrImage, $patternSize, $oArrCorners, $flags)

    If $bCornersIsArray Then
        _VectorOfMatRelease($vectorOfMatCorners)
    EndIf

    _cveOutputArrayRelease($oArrCorners)

    If $bImageIsArray Then
        _VectorOfMatRelease($vectorOfMatImage)
    EndIf

    _cveInputArrayRelease($iArrImage)

    Return $retval
EndFunc   ;==>_cveFindChessboardCornersMat

Func _cveFind4QuadCornerSubpix(ByRef $image, ByRef $corners, ByRef $regionSize)
    ; CVAPI(bool) cveFind4QuadCornerSubpix(cv::_InputArray* image, cv::_InputOutputArray* corners, CvSize* regionSize);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveFind4QuadCornerSubpix", "ptr", $image, "ptr", $corners, "struct*", $regionSize), "cveFind4QuadCornerSubpix", @error)
EndFunc   ;==>_cveFind4QuadCornerSubpix

Func _cveFind4QuadCornerSubpixMat(ByRef $matImage, ByRef $matCorners, ByRef $regionSize)
    ; cveFind4QuadCornerSubpix using cv::Mat instead of _*Array

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

    Local $ioArrCorners, $vectorOfMatCorners, $iArrCornersSize
    Local $bCornersIsArray = VarGetType($matCorners) == "Array"

    If $bCornersIsArray Then
        $vectorOfMatCorners = _VectorOfMatCreate()

        $iArrCornersSize = UBound($matCorners)
        For $i = 0 To $iArrCornersSize - 1
            _VectorOfMatPush($vectorOfMatCorners, $matCorners[$i])
        Next

        $ioArrCorners = _cveInputOutputArrayFromVectorOfMat($vectorOfMatCorners)
    Else
        $ioArrCorners = _cveInputOutputArrayFromMat($matCorners)
    EndIf

    Local $retval = _cveFind4QuadCornerSubpix($iArrImage, $ioArrCorners, $regionSize)

    If $bCornersIsArray Then
        _VectorOfMatRelease($vectorOfMatCorners)
    EndIf

    _cveInputOutputArrayRelease($ioArrCorners)

    If $bImageIsArray Then
        _VectorOfMatRelease($vectorOfMatImage)
    EndIf

    _cveInputArrayRelease($iArrImage)

    Return $retval
EndFunc   ;==>_cveFind4QuadCornerSubpixMat

Func _cveStereoRectifyUncalibrated(ByRef $points1, ByRef $points2, ByRef $f, ByRef $imgSize, ByRef $h1, ByRef $h2, $threshold)
    ; CVAPI(bool) cveStereoRectifyUncalibrated(cv::_InputArray* points1, cv::_InputArray* points2, cv::_InputArray* f, CvSize* imgSize, cv::_OutputArray* h1, cv::_OutputArray* h2, double threshold);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveStereoRectifyUncalibrated", "ptr", $points1, "ptr", $points2, "ptr", $f, "struct*", $imgSize, "ptr", $h1, "ptr", $h2, "double", $threshold), "cveStereoRectifyUncalibrated", @error)
EndFunc   ;==>_cveStereoRectifyUncalibrated

Func _cveStereoRectifyUncalibratedMat(ByRef $matPoints1, ByRef $matPoints2, ByRef $matF, ByRef $imgSize, ByRef $matH1, ByRef $matH2, $threshold)
    ; cveStereoRectifyUncalibrated using cv::Mat instead of _*Array

    Local $iArrPoints1, $vectorOfMatPoints1, $iArrPoints1Size
    Local $bPoints1IsArray = VarGetType($matPoints1) == "Array"

    If $bPoints1IsArray Then
        $vectorOfMatPoints1 = _VectorOfMatCreate()

        $iArrPoints1Size = UBound($matPoints1)
        For $i = 0 To $iArrPoints1Size - 1
            _VectorOfMatPush($vectorOfMatPoints1, $matPoints1[$i])
        Next

        $iArrPoints1 = _cveInputArrayFromVectorOfMat($vectorOfMatPoints1)
    Else
        $iArrPoints1 = _cveInputArrayFromMat($matPoints1)
    EndIf

    Local $iArrPoints2, $vectorOfMatPoints2, $iArrPoints2Size
    Local $bPoints2IsArray = VarGetType($matPoints2) == "Array"

    If $bPoints2IsArray Then
        $vectorOfMatPoints2 = _VectorOfMatCreate()

        $iArrPoints2Size = UBound($matPoints2)
        For $i = 0 To $iArrPoints2Size - 1
            _VectorOfMatPush($vectorOfMatPoints2, $matPoints2[$i])
        Next

        $iArrPoints2 = _cveInputArrayFromVectorOfMat($vectorOfMatPoints2)
    Else
        $iArrPoints2 = _cveInputArrayFromMat($matPoints2)
    EndIf

    Local $iArrF, $vectorOfMatF, $iArrFSize
    Local $bFIsArray = VarGetType($matF) == "Array"

    If $bFIsArray Then
        $vectorOfMatF = _VectorOfMatCreate()

        $iArrFSize = UBound($matF)
        For $i = 0 To $iArrFSize - 1
            _VectorOfMatPush($vectorOfMatF, $matF[$i])
        Next

        $iArrF = _cveInputArrayFromVectorOfMat($vectorOfMatF)
    Else
        $iArrF = _cveInputArrayFromMat($matF)
    EndIf

    Local $oArrH1, $vectorOfMatH1, $iArrH1Size
    Local $bH1IsArray = VarGetType($matH1) == "Array"

    If $bH1IsArray Then
        $vectorOfMatH1 = _VectorOfMatCreate()

        $iArrH1Size = UBound($matH1)
        For $i = 0 To $iArrH1Size - 1
            _VectorOfMatPush($vectorOfMatH1, $matH1[$i])
        Next

        $oArrH1 = _cveOutputArrayFromVectorOfMat($vectorOfMatH1)
    Else
        $oArrH1 = _cveOutputArrayFromMat($matH1)
    EndIf

    Local $oArrH2, $vectorOfMatH2, $iArrH2Size
    Local $bH2IsArray = VarGetType($matH2) == "Array"

    If $bH2IsArray Then
        $vectorOfMatH2 = _VectorOfMatCreate()

        $iArrH2Size = UBound($matH2)
        For $i = 0 To $iArrH2Size - 1
            _VectorOfMatPush($vectorOfMatH2, $matH2[$i])
        Next

        $oArrH2 = _cveOutputArrayFromVectorOfMat($vectorOfMatH2)
    Else
        $oArrH2 = _cveOutputArrayFromMat($matH2)
    EndIf

    Local $retval = _cveStereoRectifyUncalibrated($iArrPoints1, $iArrPoints2, $iArrF, $imgSize, $oArrH1, $oArrH2, $threshold)

    If $bH2IsArray Then
        _VectorOfMatRelease($vectorOfMatH2)
    EndIf

    _cveOutputArrayRelease($oArrH2)

    If $bH1IsArray Then
        _VectorOfMatRelease($vectorOfMatH1)
    EndIf

    _cveOutputArrayRelease($oArrH1)

    If $bFIsArray Then
        _VectorOfMatRelease($vectorOfMatF)
    EndIf

    _cveInputArrayRelease($iArrF)

    If $bPoints2IsArray Then
        _VectorOfMatRelease($vectorOfMatPoints2)
    EndIf

    _cveInputArrayRelease($iArrPoints2)

    If $bPoints1IsArray Then
        _VectorOfMatRelease($vectorOfMatPoints1)
    EndIf

    _cveInputArrayRelease($iArrPoints1)

    Return $retval
EndFunc   ;==>_cveStereoRectifyUncalibratedMat

Func _cveStereoRectify(ByRef $cameraMatrix1, ByRef $distCoeffs1, ByRef $cameraMatrix2, ByRef $distCoeffs2, ByRef $imageSize, ByRef $r, ByRef $t, ByRef $r1, ByRef $r2, ByRef $p1, ByRef $p2, ByRef $q, $flags, $alpha, ByRef $newImageSize, ByRef $validPixROI1, ByRef $validPixROI2)
    ; CVAPI(void) cveStereoRectify(cv::_InputArray* cameraMatrix1, cv::_InputArray* distCoeffs1, cv::_InputArray* cameraMatrix2, cv::_InputArray* distCoeffs2, CvSize* imageSize, cv::_InputArray* r, cv::_InputArray* t, cv::_OutputArray* r1, cv::_OutputArray* r2, cv::_OutputArray* p1, cv::_OutputArray* p2, cv::_OutputArray* q, int flags, double alpha, CvSize* newImageSize, CvRect* validPixROI1, CvRect* validPixROI2);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveStereoRectify", "ptr", $cameraMatrix1, "ptr", $distCoeffs1, "ptr", $cameraMatrix2, "ptr", $distCoeffs2, "struct*", $imageSize, "ptr", $r, "ptr", $t, "ptr", $r1, "ptr", $r2, "ptr", $p1, "ptr", $p2, "ptr", $q, "int", $flags, "double", $alpha, "struct*", $newImageSize, "struct*", $validPixROI1, "struct*", $validPixROI2), "cveStereoRectify", @error)
EndFunc   ;==>_cveStereoRectify

Func _cveStereoRectifyMat(ByRef $matCameraMatrix1, ByRef $matDistCoeffs1, ByRef $matCameraMatrix2, ByRef $matDistCoeffs2, ByRef $imageSize, ByRef $matR, ByRef $matT, ByRef $matR1, ByRef $matR2, ByRef $matP1, ByRef $matP2, ByRef $matQ, $flags, $alpha, ByRef $newImageSize, ByRef $validPixROI1, ByRef $validPixROI2)
    ; cveStereoRectify using cv::Mat instead of _*Array

    Local $iArrCameraMatrix1, $vectorOfMatCameraMatrix1, $iArrCameraMatrix1Size
    Local $bCameraMatrix1IsArray = VarGetType($matCameraMatrix1) == "Array"

    If $bCameraMatrix1IsArray Then
        $vectorOfMatCameraMatrix1 = _VectorOfMatCreate()

        $iArrCameraMatrix1Size = UBound($matCameraMatrix1)
        For $i = 0 To $iArrCameraMatrix1Size - 1
            _VectorOfMatPush($vectorOfMatCameraMatrix1, $matCameraMatrix1[$i])
        Next

        $iArrCameraMatrix1 = _cveInputArrayFromVectorOfMat($vectorOfMatCameraMatrix1)
    Else
        $iArrCameraMatrix1 = _cveInputArrayFromMat($matCameraMatrix1)
    EndIf

    Local $iArrDistCoeffs1, $vectorOfMatDistCoeffs1, $iArrDistCoeffs1Size
    Local $bDistCoeffs1IsArray = VarGetType($matDistCoeffs1) == "Array"

    If $bDistCoeffs1IsArray Then
        $vectorOfMatDistCoeffs1 = _VectorOfMatCreate()

        $iArrDistCoeffs1Size = UBound($matDistCoeffs1)
        For $i = 0 To $iArrDistCoeffs1Size - 1
            _VectorOfMatPush($vectorOfMatDistCoeffs1, $matDistCoeffs1[$i])
        Next

        $iArrDistCoeffs1 = _cveInputArrayFromVectorOfMat($vectorOfMatDistCoeffs1)
    Else
        $iArrDistCoeffs1 = _cveInputArrayFromMat($matDistCoeffs1)
    EndIf

    Local $iArrCameraMatrix2, $vectorOfMatCameraMatrix2, $iArrCameraMatrix2Size
    Local $bCameraMatrix2IsArray = VarGetType($matCameraMatrix2) == "Array"

    If $bCameraMatrix2IsArray Then
        $vectorOfMatCameraMatrix2 = _VectorOfMatCreate()

        $iArrCameraMatrix2Size = UBound($matCameraMatrix2)
        For $i = 0 To $iArrCameraMatrix2Size - 1
            _VectorOfMatPush($vectorOfMatCameraMatrix2, $matCameraMatrix2[$i])
        Next

        $iArrCameraMatrix2 = _cveInputArrayFromVectorOfMat($vectorOfMatCameraMatrix2)
    Else
        $iArrCameraMatrix2 = _cveInputArrayFromMat($matCameraMatrix2)
    EndIf

    Local $iArrDistCoeffs2, $vectorOfMatDistCoeffs2, $iArrDistCoeffs2Size
    Local $bDistCoeffs2IsArray = VarGetType($matDistCoeffs2) == "Array"

    If $bDistCoeffs2IsArray Then
        $vectorOfMatDistCoeffs2 = _VectorOfMatCreate()

        $iArrDistCoeffs2Size = UBound($matDistCoeffs2)
        For $i = 0 To $iArrDistCoeffs2Size - 1
            _VectorOfMatPush($vectorOfMatDistCoeffs2, $matDistCoeffs2[$i])
        Next

        $iArrDistCoeffs2 = _cveInputArrayFromVectorOfMat($vectorOfMatDistCoeffs2)
    Else
        $iArrDistCoeffs2 = _cveInputArrayFromMat($matDistCoeffs2)
    EndIf

    Local $iArrR, $vectorOfMatR, $iArrRSize
    Local $bRIsArray = VarGetType($matR) == "Array"

    If $bRIsArray Then
        $vectorOfMatR = _VectorOfMatCreate()

        $iArrRSize = UBound($matR)
        For $i = 0 To $iArrRSize - 1
            _VectorOfMatPush($vectorOfMatR, $matR[$i])
        Next

        $iArrR = _cveInputArrayFromVectorOfMat($vectorOfMatR)
    Else
        $iArrR = _cveInputArrayFromMat($matR)
    EndIf

    Local $iArrT, $vectorOfMatT, $iArrTSize
    Local $bTIsArray = VarGetType($matT) == "Array"

    If $bTIsArray Then
        $vectorOfMatT = _VectorOfMatCreate()

        $iArrTSize = UBound($matT)
        For $i = 0 To $iArrTSize - 1
            _VectorOfMatPush($vectorOfMatT, $matT[$i])
        Next

        $iArrT = _cveInputArrayFromVectorOfMat($vectorOfMatT)
    Else
        $iArrT = _cveInputArrayFromMat($matT)
    EndIf

    Local $oArrR1, $vectorOfMatR1, $iArrR1Size
    Local $bR1IsArray = VarGetType($matR1) == "Array"

    If $bR1IsArray Then
        $vectorOfMatR1 = _VectorOfMatCreate()

        $iArrR1Size = UBound($matR1)
        For $i = 0 To $iArrR1Size - 1
            _VectorOfMatPush($vectorOfMatR1, $matR1[$i])
        Next

        $oArrR1 = _cveOutputArrayFromVectorOfMat($vectorOfMatR1)
    Else
        $oArrR1 = _cveOutputArrayFromMat($matR1)
    EndIf

    Local $oArrR2, $vectorOfMatR2, $iArrR2Size
    Local $bR2IsArray = VarGetType($matR2) == "Array"

    If $bR2IsArray Then
        $vectorOfMatR2 = _VectorOfMatCreate()

        $iArrR2Size = UBound($matR2)
        For $i = 0 To $iArrR2Size - 1
            _VectorOfMatPush($vectorOfMatR2, $matR2[$i])
        Next

        $oArrR2 = _cveOutputArrayFromVectorOfMat($vectorOfMatR2)
    Else
        $oArrR2 = _cveOutputArrayFromMat($matR2)
    EndIf

    Local $oArrP1, $vectorOfMatP1, $iArrP1Size
    Local $bP1IsArray = VarGetType($matP1) == "Array"

    If $bP1IsArray Then
        $vectorOfMatP1 = _VectorOfMatCreate()

        $iArrP1Size = UBound($matP1)
        For $i = 0 To $iArrP1Size - 1
            _VectorOfMatPush($vectorOfMatP1, $matP1[$i])
        Next

        $oArrP1 = _cveOutputArrayFromVectorOfMat($vectorOfMatP1)
    Else
        $oArrP1 = _cveOutputArrayFromMat($matP1)
    EndIf

    Local $oArrP2, $vectorOfMatP2, $iArrP2Size
    Local $bP2IsArray = VarGetType($matP2) == "Array"

    If $bP2IsArray Then
        $vectorOfMatP2 = _VectorOfMatCreate()

        $iArrP2Size = UBound($matP2)
        For $i = 0 To $iArrP2Size - 1
            _VectorOfMatPush($vectorOfMatP2, $matP2[$i])
        Next

        $oArrP2 = _cveOutputArrayFromVectorOfMat($vectorOfMatP2)
    Else
        $oArrP2 = _cveOutputArrayFromMat($matP2)
    EndIf

    Local $oArrQ, $vectorOfMatQ, $iArrQSize
    Local $bQIsArray = VarGetType($matQ) == "Array"

    If $bQIsArray Then
        $vectorOfMatQ = _VectorOfMatCreate()

        $iArrQSize = UBound($matQ)
        For $i = 0 To $iArrQSize - 1
            _VectorOfMatPush($vectorOfMatQ, $matQ[$i])
        Next

        $oArrQ = _cveOutputArrayFromVectorOfMat($vectorOfMatQ)
    Else
        $oArrQ = _cveOutputArrayFromMat($matQ)
    EndIf

    _cveStereoRectify($iArrCameraMatrix1, $iArrDistCoeffs1, $iArrCameraMatrix2, $iArrDistCoeffs2, $imageSize, $iArrR, $iArrT, $oArrR1, $oArrR2, $oArrP1, $oArrP2, $oArrQ, $flags, $alpha, $newImageSize, $validPixROI1, $validPixROI2)

    If $bQIsArray Then
        _VectorOfMatRelease($vectorOfMatQ)
    EndIf

    _cveOutputArrayRelease($oArrQ)

    If $bP2IsArray Then
        _VectorOfMatRelease($vectorOfMatP2)
    EndIf

    _cveOutputArrayRelease($oArrP2)

    If $bP1IsArray Then
        _VectorOfMatRelease($vectorOfMatP1)
    EndIf

    _cveOutputArrayRelease($oArrP1)

    If $bR2IsArray Then
        _VectorOfMatRelease($vectorOfMatR2)
    EndIf

    _cveOutputArrayRelease($oArrR2)

    If $bR1IsArray Then
        _VectorOfMatRelease($vectorOfMatR1)
    EndIf

    _cveOutputArrayRelease($oArrR1)

    If $bTIsArray Then
        _VectorOfMatRelease($vectorOfMatT)
    EndIf

    _cveInputArrayRelease($iArrT)

    If $bRIsArray Then
        _VectorOfMatRelease($vectorOfMatR)
    EndIf

    _cveInputArrayRelease($iArrR)

    If $bDistCoeffs2IsArray Then
        _VectorOfMatRelease($vectorOfMatDistCoeffs2)
    EndIf

    _cveInputArrayRelease($iArrDistCoeffs2)

    If $bCameraMatrix2IsArray Then
        _VectorOfMatRelease($vectorOfMatCameraMatrix2)
    EndIf

    _cveInputArrayRelease($iArrCameraMatrix2)

    If $bDistCoeffs1IsArray Then
        _VectorOfMatRelease($vectorOfMatDistCoeffs1)
    EndIf

    _cveInputArrayRelease($iArrDistCoeffs1)

    If $bCameraMatrix1IsArray Then
        _VectorOfMatRelease($vectorOfMatCameraMatrix1)
    EndIf

    _cveInputArrayRelease($iArrCameraMatrix1)
EndFunc   ;==>_cveStereoRectifyMat

Func _cveRodrigues(ByRef $src, ByRef $dst, ByRef $jacobian)
    ; CVAPI(void) cveRodrigues(cv::_InputArray* src, cv::_OutputArray* dst, cv::_OutputArray* jacobian);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveRodrigues", "ptr", $src, "ptr", $dst, "ptr", $jacobian), "cveRodrigues", @error)
EndFunc   ;==>_cveRodrigues

Func _cveRodriguesMat(ByRef $matSrc, ByRef $matDst, ByRef $matJacobian)
    ; cveRodrigues using cv::Mat instead of _*Array

    Local $iArrSrc, $vectorOfMatSrc, $iArrSrcSize
    Local $bSrcIsArray = VarGetType($matSrc) == "Array"

    If $bSrcIsArray Then
        $vectorOfMatSrc = _VectorOfMatCreate()

        $iArrSrcSize = UBound($matSrc)
        For $i = 0 To $iArrSrcSize - 1
            _VectorOfMatPush($vectorOfMatSrc, $matSrc[$i])
        Next

        $iArrSrc = _cveInputArrayFromVectorOfMat($vectorOfMatSrc)
    Else
        $iArrSrc = _cveInputArrayFromMat($matSrc)
    EndIf

    Local $oArrDst, $vectorOfMatDst, $iArrDstSize
    Local $bDstIsArray = VarGetType($matDst) == "Array"

    If $bDstIsArray Then
        $vectorOfMatDst = _VectorOfMatCreate()

        $iArrDstSize = UBound($matDst)
        For $i = 0 To $iArrDstSize - 1
            _VectorOfMatPush($vectorOfMatDst, $matDst[$i])
        Next

        $oArrDst = _cveOutputArrayFromVectorOfMat($vectorOfMatDst)
    Else
        $oArrDst = _cveOutputArrayFromMat($matDst)
    EndIf

    Local $oArrJacobian, $vectorOfMatJacobian, $iArrJacobianSize
    Local $bJacobianIsArray = VarGetType($matJacobian) == "Array"

    If $bJacobianIsArray Then
        $vectorOfMatJacobian = _VectorOfMatCreate()

        $iArrJacobianSize = UBound($matJacobian)
        For $i = 0 To $iArrJacobianSize - 1
            _VectorOfMatPush($vectorOfMatJacobian, $matJacobian[$i])
        Next

        $oArrJacobian = _cveOutputArrayFromVectorOfMat($vectorOfMatJacobian)
    Else
        $oArrJacobian = _cveOutputArrayFromMat($matJacobian)
    EndIf

    _cveRodrigues($iArrSrc, $oArrDst, $oArrJacobian)

    If $bJacobianIsArray Then
        _VectorOfMatRelease($vectorOfMatJacobian)
    EndIf

    _cveOutputArrayRelease($oArrJacobian)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveOutputArrayRelease($oArrDst)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)
EndFunc   ;==>_cveRodriguesMat

Func _cveCalibrateCamera(ByRef $objectPoints, ByRef $imagePoints, ByRef $imageSize, ByRef $cameraMatrix, ByRef $distCoeffs, ByRef $rvecs, ByRef $tvecs, $flags, ByRef $criteria)
    ; CVAPI(double) cveCalibrateCamera(cv::_InputArray* objectPoints, cv::_InputArray* imagePoints, CvSize* imageSize, cv::_InputOutputArray* cameraMatrix, cv::_InputOutputArray* distCoeffs, cv::_OutputArray* rvecs, cv::_OutputArray* tvecs, int flags, CvTermCriteria* criteria);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveCalibrateCamera", "ptr", $objectPoints, "ptr", $imagePoints, "struct*", $imageSize, "ptr", $cameraMatrix, "ptr", $distCoeffs, "ptr", $rvecs, "ptr", $tvecs, "int", $flags, "struct*", $criteria), "cveCalibrateCamera", @error)
EndFunc   ;==>_cveCalibrateCamera

Func _cveCalibrateCameraMat(ByRef $matObjectPoints, ByRef $matImagePoints, ByRef $imageSize, ByRef $matCameraMatrix, ByRef $matDistCoeffs, ByRef $matRvecs, ByRef $matTvecs, $flags, ByRef $criteria)
    ; cveCalibrateCamera using cv::Mat instead of _*Array

    Local $iArrObjectPoints, $vectorOfMatObjectPoints, $iArrObjectPointsSize
    Local $bObjectPointsIsArray = VarGetType($matObjectPoints) == "Array"

    If $bObjectPointsIsArray Then
        $vectorOfMatObjectPoints = _VectorOfMatCreate()

        $iArrObjectPointsSize = UBound($matObjectPoints)
        For $i = 0 To $iArrObjectPointsSize - 1
            _VectorOfMatPush($vectorOfMatObjectPoints, $matObjectPoints[$i])
        Next

        $iArrObjectPoints = _cveInputArrayFromVectorOfMat($vectorOfMatObjectPoints)
    Else
        $iArrObjectPoints = _cveInputArrayFromMat($matObjectPoints)
    EndIf

    Local $iArrImagePoints, $vectorOfMatImagePoints, $iArrImagePointsSize
    Local $bImagePointsIsArray = VarGetType($matImagePoints) == "Array"

    If $bImagePointsIsArray Then
        $vectorOfMatImagePoints = _VectorOfMatCreate()

        $iArrImagePointsSize = UBound($matImagePoints)
        For $i = 0 To $iArrImagePointsSize - 1
            _VectorOfMatPush($vectorOfMatImagePoints, $matImagePoints[$i])
        Next

        $iArrImagePoints = _cveInputArrayFromVectorOfMat($vectorOfMatImagePoints)
    Else
        $iArrImagePoints = _cveInputArrayFromMat($matImagePoints)
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

    Local $retval = _cveCalibrateCamera($iArrObjectPoints, $iArrImagePoints, $imageSize, $ioArrCameraMatrix, $ioArrDistCoeffs, $oArrRvecs, $oArrTvecs, $flags, $criteria)

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

    If $bImagePointsIsArray Then
        _VectorOfMatRelease($vectorOfMatImagePoints)
    EndIf

    _cveInputArrayRelease($iArrImagePoints)

    If $bObjectPointsIsArray Then
        _VectorOfMatRelease($vectorOfMatObjectPoints)
    EndIf

    _cveInputArrayRelease($iArrObjectPoints)

    Return $retval
EndFunc   ;==>_cveCalibrateCameraMat

Func _cveReprojectImageTo3D(ByRef $disparity, ByRef $threeDImage, ByRef $q, $handleMissingValues, $ddepth)
    ; CVAPI(void) cveReprojectImageTo3D(cv::_InputArray* disparity, cv::_OutputArray* threeDImage, cv::_InputArray* q, bool handleMissingValues, int ddepth);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveReprojectImageTo3D", "ptr", $disparity, "ptr", $threeDImage, "ptr", $q, "boolean", $handleMissingValues, "int", $ddepth), "cveReprojectImageTo3D", @error)
EndFunc   ;==>_cveReprojectImageTo3D

Func _cveReprojectImageTo3DMat(ByRef $matDisparity, ByRef $matThreeDImage, ByRef $matQ, $handleMissingValues, $ddepth)
    ; cveReprojectImageTo3D using cv::Mat instead of _*Array

    Local $iArrDisparity, $vectorOfMatDisparity, $iArrDisparitySize
    Local $bDisparityIsArray = VarGetType($matDisparity) == "Array"

    If $bDisparityIsArray Then
        $vectorOfMatDisparity = _VectorOfMatCreate()

        $iArrDisparitySize = UBound($matDisparity)
        For $i = 0 To $iArrDisparitySize - 1
            _VectorOfMatPush($vectorOfMatDisparity, $matDisparity[$i])
        Next

        $iArrDisparity = _cveInputArrayFromVectorOfMat($vectorOfMatDisparity)
    Else
        $iArrDisparity = _cveInputArrayFromMat($matDisparity)
    EndIf

    Local $oArrThreeDImage, $vectorOfMatThreeDImage, $iArrThreeDImageSize
    Local $bThreeDImageIsArray = VarGetType($matThreeDImage) == "Array"

    If $bThreeDImageIsArray Then
        $vectorOfMatThreeDImage = _VectorOfMatCreate()

        $iArrThreeDImageSize = UBound($matThreeDImage)
        For $i = 0 To $iArrThreeDImageSize - 1
            _VectorOfMatPush($vectorOfMatThreeDImage, $matThreeDImage[$i])
        Next

        $oArrThreeDImage = _cveOutputArrayFromVectorOfMat($vectorOfMatThreeDImage)
    Else
        $oArrThreeDImage = _cveOutputArrayFromMat($matThreeDImage)
    EndIf

    Local $iArrQ, $vectorOfMatQ, $iArrQSize
    Local $bQIsArray = VarGetType($matQ) == "Array"

    If $bQIsArray Then
        $vectorOfMatQ = _VectorOfMatCreate()

        $iArrQSize = UBound($matQ)
        For $i = 0 To $iArrQSize - 1
            _VectorOfMatPush($vectorOfMatQ, $matQ[$i])
        Next

        $iArrQ = _cveInputArrayFromVectorOfMat($vectorOfMatQ)
    Else
        $iArrQ = _cveInputArrayFromMat($matQ)
    EndIf

    _cveReprojectImageTo3D($iArrDisparity, $oArrThreeDImage, $iArrQ, $handleMissingValues, $ddepth)

    If $bQIsArray Then
        _VectorOfMatRelease($vectorOfMatQ)
    EndIf

    _cveInputArrayRelease($iArrQ)

    If $bThreeDImageIsArray Then
        _VectorOfMatRelease($vectorOfMatThreeDImage)
    EndIf

    _cveOutputArrayRelease($oArrThreeDImage)

    If $bDisparityIsArray Then
        _VectorOfMatRelease($vectorOfMatDisparity)
    EndIf

    _cveInputArrayRelease($iArrDisparity)
EndFunc   ;==>_cveReprojectImageTo3DMat

Func _cveConvertPointsToHomogeneous(ByRef $src, ByRef $dst)
    ; CVAPI(void) cveConvertPointsToHomogeneous(cv::_InputArray* src, cv::_OutputArray* dst);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveConvertPointsToHomogeneous", "ptr", $src, "ptr", $dst), "cveConvertPointsToHomogeneous", @error)
EndFunc   ;==>_cveConvertPointsToHomogeneous

Func _cveConvertPointsToHomogeneousMat(ByRef $matSrc, ByRef $matDst)
    ; cveConvertPointsToHomogeneous using cv::Mat instead of _*Array

    Local $iArrSrc, $vectorOfMatSrc, $iArrSrcSize
    Local $bSrcIsArray = VarGetType($matSrc) == "Array"

    If $bSrcIsArray Then
        $vectorOfMatSrc = _VectorOfMatCreate()

        $iArrSrcSize = UBound($matSrc)
        For $i = 0 To $iArrSrcSize - 1
            _VectorOfMatPush($vectorOfMatSrc, $matSrc[$i])
        Next

        $iArrSrc = _cveInputArrayFromVectorOfMat($vectorOfMatSrc)
    Else
        $iArrSrc = _cveInputArrayFromMat($matSrc)
    EndIf

    Local $oArrDst, $vectorOfMatDst, $iArrDstSize
    Local $bDstIsArray = VarGetType($matDst) == "Array"

    If $bDstIsArray Then
        $vectorOfMatDst = _VectorOfMatCreate()

        $iArrDstSize = UBound($matDst)
        For $i = 0 To $iArrDstSize - 1
            _VectorOfMatPush($vectorOfMatDst, $matDst[$i])
        Next

        $oArrDst = _cveOutputArrayFromVectorOfMat($vectorOfMatDst)
    Else
        $oArrDst = _cveOutputArrayFromMat($matDst)
    EndIf

    _cveConvertPointsToHomogeneous($iArrSrc, $oArrDst)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveOutputArrayRelease($oArrDst)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)
EndFunc   ;==>_cveConvertPointsToHomogeneousMat

Func _cveConvertPointsFromHomogeneous(ByRef $src, ByRef $dst)
    ; CVAPI(void) cveConvertPointsFromHomogeneous(cv::_InputArray* src, cv::_OutputArray* dst);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveConvertPointsFromHomogeneous", "ptr", $src, "ptr", $dst), "cveConvertPointsFromHomogeneous", @error)
EndFunc   ;==>_cveConvertPointsFromHomogeneous

Func _cveConvertPointsFromHomogeneousMat(ByRef $matSrc, ByRef $matDst)
    ; cveConvertPointsFromHomogeneous using cv::Mat instead of _*Array

    Local $iArrSrc, $vectorOfMatSrc, $iArrSrcSize
    Local $bSrcIsArray = VarGetType($matSrc) == "Array"

    If $bSrcIsArray Then
        $vectorOfMatSrc = _VectorOfMatCreate()

        $iArrSrcSize = UBound($matSrc)
        For $i = 0 To $iArrSrcSize - 1
            _VectorOfMatPush($vectorOfMatSrc, $matSrc[$i])
        Next

        $iArrSrc = _cveInputArrayFromVectorOfMat($vectorOfMatSrc)
    Else
        $iArrSrc = _cveInputArrayFromMat($matSrc)
    EndIf

    Local $oArrDst, $vectorOfMatDst, $iArrDstSize
    Local $bDstIsArray = VarGetType($matDst) == "Array"

    If $bDstIsArray Then
        $vectorOfMatDst = _VectorOfMatCreate()

        $iArrDstSize = UBound($matDst)
        For $i = 0 To $iArrDstSize - 1
            _VectorOfMatPush($vectorOfMatDst, $matDst[$i])
        Next

        $oArrDst = _cveOutputArrayFromVectorOfMat($vectorOfMatDst)
    Else
        $oArrDst = _cveOutputArrayFromMat($matDst)
    EndIf

    _cveConvertPointsFromHomogeneous($iArrSrc, $oArrDst)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveOutputArrayRelease($oArrDst)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)
EndFunc   ;==>_cveConvertPointsFromHomogeneousMat

Func _cveFindEssentialMat(ByRef $points1, ByRef $points2, ByRef $cameraMatrix, $method, $prob, $threshold, ByRef $mask, ByRef $essentialMat)
    ; CVAPI(void) cveFindEssentialMat(cv::_InputArray* points1, cv::_InputArray* points2, cv::_InputArray* cameraMatrix, int method, double prob, double threshold, cv::_OutputArray* mask, cv::Mat* essentialMat);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFindEssentialMat", "ptr", $points1, "ptr", $points2, "ptr", $cameraMatrix, "int", $method, "double", $prob, "double", $threshold, "ptr", $mask, "ptr", $essentialMat), "cveFindEssentialMat", @error)
EndFunc   ;==>_cveFindEssentialMat

Func _cveFindEssentialMatMat(ByRef $matPoints1, ByRef $matPoints2, ByRef $matCameraMatrix, $method, $prob, $threshold, ByRef $matMask, ByRef $essentialMat)
    ; cveFindEssentialMat using cv::Mat instead of _*Array

    Local $iArrPoints1, $vectorOfMatPoints1, $iArrPoints1Size
    Local $bPoints1IsArray = VarGetType($matPoints1) == "Array"

    If $bPoints1IsArray Then
        $vectorOfMatPoints1 = _VectorOfMatCreate()

        $iArrPoints1Size = UBound($matPoints1)
        For $i = 0 To $iArrPoints1Size - 1
            _VectorOfMatPush($vectorOfMatPoints1, $matPoints1[$i])
        Next

        $iArrPoints1 = _cveInputArrayFromVectorOfMat($vectorOfMatPoints1)
    Else
        $iArrPoints1 = _cveInputArrayFromMat($matPoints1)
    EndIf

    Local $iArrPoints2, $vectorOfMatPoints2, $iArrPoints2Size
    Local $bPoints2IsArray = VarGetType($matPoints2) == "Array"

    If $bPoints2IsArray Then
        $vectorOfMatPoints2 = _VectorOfMatCreate()

        $iArrPoints2Size = UBound($matPoints2)
        For $i = 0 To $iArrPoints2Size - 1
            _VectorOfMatPush($vectorOfMatPoints2, $matPoints2[$i])
        Next

        $iArrPoints2 = _cveInputArrayFromVectorOfMat($vectorOfMatPoints2)
    Else
        $iArrPoints2 = _cveInputArrayFromMat($matPoints2)
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

    Local $oArrMask, $vectorOfMatMask, $iArrMaskSize
    Local $bMaskIsArray = VarGetType($matMask) == "Array"

    If $bMaskIsArray Then
        $vectorOfMatMask = _VectorOfMatCreate()

        $iArrMaskSize = UBound($matMask)
        For $i = 0 To $iArrMaskSize - 1
            _VectorOfMatPush($vectorOfMatMask, $matMask[$i])
        Next

        $oArrMask = _cveOutputArrayFromVectorOfMat($vectorOfMatMask)
    Else
        $oArrMask = _cveOutputArrayFromMat($matMask)
    EndIf

    _cveFindEssentialMat($iArrPoints1, $iArrPoints2, $iArrCameraMatrix, $method, $prob, $threshold, $oArrMask, $essentialMat)

    If $bMaskIsArray Then
        _VectorOfMatRelease($vectorOfMatMask)
    EndIf

    _cveOutputArrayRelease($oArrMask)

    If $bCameraMatrixIsArray Then
        _VectorOfMatRelease($vectorOfMatCameraMatrix)
    EndIf

    _cveInputArrayRelease($iArrCameraMatrix)

    If $bPoints2IsArray Then
        _VectorOfMatRelease($vectorOfMatPoints2)
    EndIf

    _cveInputArrayRelease($iArrPoints2)

    If $bPoints1IsArray Then
        _VectorOfMatRelease($vectorOfMatPoints1)
    EndIf

    _cveInputArrayRelease($iArrPoints1)
EndFunc   ;==>_cveFindEssentialMatMat

Func _cveFindFundamentalMat(ByRef $points1, ByRef $points2, ByRef $dst, $method, $param1, $param2, ByRef $mask)
    ; CVAPI(void) cveFindFundamentalMat(cv::_InputArray* points1, cv::_InputArray* points2, cv::_OutputArray* dst, int method, double param1, double param2, cv::_OutputArray* mask);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFindFundamentalMat", "ptr", $points1, "ptr", $points2, "ptr", $dst, "int", $method, "double", $param1, "double", $param2, "ptr", $mask), "cveFindFundamentalMat", @error)
EndFunc   ;==>_cveFindFundamentalMat

Func _cveFindFundamentalMatMat(ByRef $matPoints1, ByRef $matPoints2, ByRef $matDst, $method, $param1, $param2, ByRef $matMask)
    ; cveFindFundamentalMat using cv::Mat instead of _*Array

    Local $iArrPoints1, $vectorOfMatPoints1, $iArrPoints1Size
    Local $bPoints1IsArray = VarGetType($matPoints1) == "Array"

    If $bPoints1IsArray Then
        $vectorOfMatPoints1 = _VectorOfMatCreate()

        $iArrPoints1Size = UBound($matPoints1)
        For $i = 0 To $iArrPoints1Size - 1
            _VectorOfMatPush($vectorOfMatPoints1, $matPoints1[$i])
        Next

        $iArrPoints1 = _cveInputArrayFromVectorOfMat($vectorOfMatPoints1)
    Else
        $iArrPoints1 = _cveInputArrayFromMat($matPoints1)
    EndIf

    Local $iArrPoints2, $vectorOfMatPoints2, $iArrPoints2Size
    Local $bPoints2IsArray = VarGetType($matPoints2) == "Array"

    If $bPoints2IsArray Then
        $vectorOfMatPoints2 = _VectorOfMatCreate()

        $iArrPoints2Size = UBound($matPoints2)
        For $i = 0 To $iArrPoints2Size - 1
            _VectorOfMatPush($vectorOfMatPoints2, $matPoints2[$i])
        Next

        $iArrPoints2 = _cveInputArrayFromVectorOfMat($vectorOfMatPoints2)
    Else
        $iArrPoints2 = _cveInputArrayFromMat($matPoints2)
    EndIf

    Local $oArrDst, $vectorOfMatDst, $iArrDstSize
    Local $bDstIsArray = VarGetType($matDst) == "Array"

    If $bDstIsArray Then
        $vectorOfMatDst = _VectorOfMatCreate()

        $iArrDstSize = UBound($matDst)
        For $i = 0 To $iArrDstSize - 1
            _VectorOfMatPush($vectorOfMatDst, $matDst[$i])
        Next

        $oArrDst = _cveOutputArrayFromVectorOfMat($vectorOfMatDst)
    Else
        $oArrDst = _cveOutputArrayFromMat($matDst)
    EndIf

    Local $oArrMask, $vectorOfMatMask, $iArrMaskSize
    Local $bMaskIsArray = VarGetType($matMask) == "Array"

    If $bMaskIsArray Then
        $vectorOfMatMask = _VectorOfMatCreate()

        $iArrMaskSize = UBound($matMask)
        For $i = 0 To $iArrMaskSize - 1
            _VectorOfMatPush($vectorOfMatMask, $matMask[$i])
        Next

        $oArrMask = _cveOutputArrayFromVectorOfMat($vectorOfMatMask)
    Else
        $oArrMask = _cveOutputArrayFromMat($matMask)
    EndIf

    _cveFindFundamentalMat($iArrPoints1, $iArrPoints2, $oArrDst, $method, $param1, $param2, $oArrMask)

    If $bMaskIsArray Then
        _VectorOfMatRelease($vectorOfMatMask)
    EndIf

    _cveOutputArrayRelease($oArrMask)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveOutputArrayRelease($oArrDst)

    If $bPoints2IsArray Then
        _VectorOfMatRelease($vectorOfMatPoints2)
    EndIf

    _cveInputArrayRelease($iArrPoints2)

    If $bPoints1IsArray Then
        _VectorOfMatRelease($vectorOfMatPoints1)
    EndIf

    _cveInputArrayRelease($iArrPoints1)
EndFunc   ;==>_cveFindFundamentalMatMat

Func _cveFindHomography(ByRef $srcPoints, ByRef $dstPoints, ByRef $dst, $method, $ransacReprojThreshold, ByRef $mask)
    ; CVAPI(void) cveFindHomography(cv::_InputArray* srcPoints, cv::_InputArray* dstPoints, cv::_OutputArray* dst, int method, double ransacReprojThreshold, cv::_OutputArray* mask);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFindHomography", "ptr", $srcPoints, "ptr", $dstPoints, "ptr", $dst, "int", $method, "double", $ransacReprojThreshold, "ptr", $mask), "cveFindHomography", @error)
EndFunc   ;==>_cveFindHomography

Func _cveFindHomographyMat(ByRef $matSrcPoints, ByRef $matDstPoints, ByRef $matDst, $method, $ransacReprojThreshold, ByRef $matMask)
    ; cveFindHomography using cv::Mat instead of _*Array

    Local $iArrSrcPoints, $vectorOfMatSrcPoints, $iArrSrcPointsSize
    Local $bSrcPointsIsArray = VarGetType($matSrcPoints) == "Array"

    If $bSrcPointsIsArray Then
        $vectorOfMatSrcPoints = _VectorOfMatCreate()

        $iArrSrcPointsSize = UBound($matSrcPoints)
        For $i = 0 To $iArrSrcPointsSize - 1
            _VectorOfMatPush($vectorOfMatSrcPoints, $matSrcPoints[$i])
        Next

        $iArrSrcPoints = _cveInputArrayFromVectorOfMat($vectorOfMatSrcPoints)
    Else
        $iArrSrcPoints = _cveInputArrayFromMat($matSrcPoints)
    EndIf

    Local $iArrDstPoints, $vectorOfMatDstPoints, $iArrDstPointsSize
    Local $bDstPointsIsArray = VarGetType($matDstPoints) == "Array"

    If $bDstPointsIsArray Then
        $vectorOfMatDstPoints = _VectorOfMatCreate()

        $iArrDstPointsSize = UBound($matDstPoints)
        For $i = 0 To $iArrDstPointsSize - 1
            _VectorOfMatPush($vectorOfMatDstPoints, $matDstPoints[$i])
        Next

        $iArrDstPoints = _cveInputArrayFromVectorOfMat($vectorOfMatDstPoints)
    Else
        $iArrDstPoints = _cveInputArrayFromMat($matDstPoints)
    EndIf

    Local $oArrDst, $vectorOfMatDst, $iArrDstSize
    Local $bDstIsArray = VarGetType($matDst) == "Array"

    If $bDstIsArray Then
        $vectorOfMatDst = _VectorOfMatCreate()

        $iArrDstSize = UBound($matDst)
        For $i = 0 To $iArrDstSize - 1
            _VectorOfMatPush($vectorOfMatDst, $matDst[$i])
        Next

        $oArrDst = _cveOutputArrayFromVectorOfMat($vectorOfMatDst)
    Else
        $oArrDst = _cveOutputArrayFromMat($matDst)
    EndIf

    Local $oArrMask, $vectorOfMatMask, $iArrMaskSize
    Local $bMaskIsArray = VarGetType($matMask) == "Array"

    If $bMaskIsArray Then
        $vectorOfMatMask = _VectorOfMatCreate()

        $iArrMaskSize = UBound($matMask)
        For $i = 0 To $iArrMaskSize - 1
            _VectorOfMatPush($vectorOfMatMask, $matMask[$i])
        Next

        $oArrMask = _cveOutputArrayFromVectorOfMat($vectorOfMatMask)
    Else
        $oArrMask = _cveOutputArrayFromMat($matMask)
    EndIf

    _cveFindHomography($iArrSrcPoints, $iArrDstPoints, $oArrDst, $method, $ransacReprojThreshold, $oArrMask)

    If $bMaskIsArray Then
        _VectorOfMatRelease($vectorOfMatMask)
    EndIf

    _cveOutputArrayRelease($oArrMask)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveOutputArrayRelease($oArrDst)

    If $bDstPointsIsArray Then
        _VectorOfMatRelease($vectorOfMatDstPoints)
    EndIf

    _cveInputArrayRelease($iArrDstPoints)

    If $bSrcPointsIsArray Then
        _VectorOfMatRelease($vectorOfMatSrcPoints)
    EndIf

    _cveInputArrayRelease($iArrSrcPoints)
EndFunc   ;==>_cveFindHomographyMat

Func _cveComputeCorrespondEpilines(ByRef $points, $whichImage, ByRef $f, ByRef $lines)
    ; CVAPI(void) cveComputeCorrespondEpilines(cv::_InputArray* points, int whichImage, cv::_InputArray* f, cv::_OutputArray* lines);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveComputeCorrespondEpilines", "ptr", $points, "int", $whichImage, "ptr", $f, "ptr", $lines), "cveComputeCorrespondEpilines", @error)
EndFunc   ;==>_cveComputeCorrespondEpilines

Func _cveComputeCorrespondEpilinesMat(ByRef $matPoints, $whichImage, ByRef $matF, ByRef $matLines)
    ; cveComputeCorrespondEpilines using cv::Mat instead of _*Array

    Local $iArrPoints, $vectorOfMatPoints, $iArrPointsSize
    Local $bPointsIsArray = VarGetType($matPoints) == "Array"

    If $bPointsIsArray Then
        $vectorOfMatPoints = _VectorOfMatCreate()

        $iArrPointsSize = UBound($matPoints)
        For $i = 0 To $iArrPointsSize - 1
            _VectorOfMatPush($vectorOfMatPoints, $matPoints[$i])
        Next

        $iArrPoints = _cveInputArrayFromVectorOfMat($vectorOfMatPoints)
    Else
        $iArrPoints = _cveInputArrayFromMat($matPoints)
    EndIf

    Local $iArrF, $vectorOfMatF, $iArrFSize
    Local $bFIsArray = VarGetType($matF) == "Array"

    If $bFIsArray Then
        $vectorOfMatF = _VectorOfMatCreate()

        $iArrFSize = UBound($matF)
        For $i = 0 To $iArrFSize - 1
            _VectorOfMatPush($vectorOfMatF, $matF[$i])
        Next

        $iArrF = _cveInputArrayFromVectorOfMat($vectorOfMatF)
    Else
        $iArrF = _cveInputArrayFromMat($matF)
    EndIf

    Local $oArrLines, $vectorOfMatLines, $iArrLinesSize
    Local $bLinesIsArray = VarGetType($matLines) == "Array"

    If $bLinesIsArray Then
        $vectorOfMatLines = _VectorOfMatCreate()

        $iArrLinesSize = UBound($matLines)
        For $i = 0 To $iArrLinesSize - 1
            _VectorOfMatPush($vectorOfMatLines, $matLines[$i])
        Next

        $oArrLines = _cveOutputArrayFromVectorOfMat($vectorOfMatLines)
    Else
        $oArrLines = _cveOutputArrayFromMat($matLines)
    EndIf

    _cveComputeCorrespondEpilines($iArrPoints, $whichImage, $iArrF, $oArrLines)

    If $bLinesIsArray Then
        _VectorOfMatRelease($vectorOfMatLines)
    EndIf

    _cveOutputArrayRelease($oArrLines)

    If $bFIsArray Then
        _VectorOfMatRelease($vectorOfMatF)
    EndIf

    _cveInputArrayRelease($iArrF)

    If $bPointsIsArray Then
        _VectorOfMatRelease($vectorOfMatPoints)
    EndIf

    _cveInputArrayRelease($iArrPoints)
EndFunc   ;==>_cveComputeCorrespondEpilinesMat

Func _cveProjectPoints(ByRef $objPoints, ByRef $rvec, ByRef $tvec, ByRef $cameraMatrix, ByRef $distCoeffs, ByRef $imagePoints, ByRef $jacobian, $aspectRatio)
    ; CVAPI(void) cveProjectPoints(cv::_InputArray* objPoints, cv::_InputArray* rvec, cv::_InputArray* tvec, cv::_InputArray* cameraMatrix, cv::_InputArray* distCoeffs, cv::_OutputArray* imagePoints, cv::_OutputArray* jacobian, double aspectRatio);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveProjectPoints", "ptr", $objPoints, "ptr", $rvec, "ptr", $tvec, "ptr", $cameraMatrix, "ptr", $distCoeffs, "ptr", $imagePoints, "ptr", $jacobian, "double", $aspectRatio), "cveProjectPoints", @error)
EndFunc   ;==>_cveProjectPoints

Func _cveProjectPointsMat(ByRef $matObjPoints, ByRef $matRvec, ByRef $matTvec, ByRef $matCameraMatrix, ByRef $matDistCoeffs, ByRef $matImagePoints, ByRef $matJacobian, $aspectRatio)
    ; cveProjectPoints using cv::Mat instead of _*Array

    Local $iArrObjPoints, $vectorOfMatObjPoints, $iArrObjPointsSize
    Local $bObjPointsIsArray = VarGetType($matObjPoints) == "Array"

    If $bObjPointsIsArray Then
        $vectorOfMatObjPoints = _VectorOfMatCreate()

        $iArrObjPointsSize = UBound($matObjPoints)
        For $i = 0 To $iArrObjPointsSize - 1
            _VectorOfMatPush($vectorOfMatObjPoints, $matObjPoints[$i])
        Next

        $iArrObjPoints = _cveInputArrayFromVectorOfMat($vectorOfMatObjPoints)
    Else
        $iArrObjPoints = _cveInputArrayFromMat($matObjPoints)
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

    Local $oArrImagePoints, $vectorOfMatImagePoints, $iArrImagePointsSize
    Local $bImagePointsIsArray = VarGetType($matImagePoints) == "Array"

    If $bImagePointsIsArray Then
        $vectorOfMatImagePoints = _VectorOfMatCreate()

        $iArrImagePointsSize = UBound($matImagePoints)
        For $i = 0 To $iArrImagePointsSize - 1
            _VectorOfMatPush($vectorOfMatImagePoints, $matImagePoints[$i])
        Next

        $oArrImagePoints = _cveOutputArrayFromVectorOfMat($vectorOfMatImagePoints)
    Else
        $oArrImagePoints = _cveOutputArrayFromMat($matImagePoints)
    EndIf

    Local $oArrJacobian, $vectorOfMatJacobian, $iArrJacobianSize
    Local $bJacobianIsArray = VarGetType($matJacobian) == "Array"

    If $bJacobianIsArray Then
        $vectorOfMatJacobian = _VectorOfMatCreate()

        $iArrJacobianSize = UBound($matJacobian)
        For $i = 0 To $iArrJacobianSize - 1
            _VectorOfMatPush($vectorOfMatJacobian, $matJacobian[$i])
        Next

        $oArrJacobian = _cveOutputArrayFromVectorOfMat($vectorOfMatJacobian)
    Else
        $oArrJacobian = _cveOutputArrayFromMat($matJacobian)
    EndIf

    _cveProjectPoints($iArrObjPoints, $iArrRvec, $iArrTvec, $iArrCameraMatrix, $iArrDistCoeffs, $oArrImagePoints, $oArrJacobian, $aspectRatio)

    If $bJacobianIsArray Then
        _VectorOfMatRelease($vectorOfMatJacobian)
    EndIf

    _cveOutputArrayRelease($oArrJacobian)

    If $bImagePointsIsArray Then
        _VectorOfMatRelease($vectorOfMatImagePoints)
    EndIf

    _cveOutputArrayRelease($oArrImagePoints)

    If $bDistCoeffsIsArray Then
        _VectorOfMatRelease($vectorOfMatDistCoeffs)
    EndIf

    _cveInputArrayRelease($iArrDistCoeffs)

    If $bCameraMatrixIsArray Then
        _VectorOfMatRelease($vectorOfMatCameraMatrix)
    EndIf

    _cveInputArrayRelease($iArrCameraMatrix)

    If $bTvecIsArray Then
        _VectorOfMatRelease($vectorOfMatTvec)
    EndIf

    _cveInputArrayRelease($iArrTvec)

    If $bRvecIsArray Then
        _VectorOfMatRelease($vectorOfMatRvec)
    EndIf

    _cveInputArrayRelease($iArrRvec)

    If $bObjPointsIsArray Then
        _VectorOfMatRelease($vectorOfMatObjPoints)
    EndIf

    _cveInputArrayRelease($iArrObjPoints)
EndFunc   ;==>_cveProjectPointsMat

Func _cveCalibrationMatrixValues(ByRef $cameraMatrix, ByRef $imageSize, $apertureWidth, $apertureHeight, ByRef $fovx, ByRef $fovy, ByRef $focalLength, ByRef $principalPoint, ByRef $aspectRatio)
    ; CVAPI(void) cveCalibrationMatrixValues(cv::_InputArray* cameraMatrix, CvSize* imageSize, double apertureWidth, double apertureHeight, double* fovx, double* fovy, double* focalLength, CvPoint2D64f* principalPoint, double* aspectRatio);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCalibrationMatrixValues", "ptr", $cameraMatrix, "struct*", $imageSize, "double", $apertureWidth, "double", $apertureHeight, "struct*", $fovx, "struct*", $fovy, "struct*", $focalLength, "struct*", $principalPoint, "struct*", $aspectRatio), "cveCalibrationMatrixValues", @error)
EndFunc   ;==>_cveCalibrationMatrixValues

Func _cveCalibrationMatrixValuesMat(ByRef $matCameraMatrix, ByRef $imageSize, $apertureWidth, $apertureHeight, ByRef $fovx, ByRef $fovy, ByRef $focalLength, ByRef $principalPoint, ByRef $aspectRatio)
    ; cveCalibrationMatrixValues using cv::Mat instead of _*Array

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

    _cveCalibrationMatrixValues($iArrCameraMatrix, $imageSize, $apertureWidth, $apertureHeight, $fovx, $fovy, $focalLength, $principalPoint, $aspectRatio)

    If $bCameraMatrixIsArray Then
        _VectorOfMatRelease($vectorOfMatCameraMatrix)
    EndIf

    _cveInputArrayRelease($iArrCameraMatrix)
EndFunc   ;==>_cveCalibrationMatrixValuesMat

Func _cveStereoCalibrate(ByRef $objectPoints, ByRef $imagePoints1, ByRef $imagePoints2, ByRef $cameraMatrix1, ByRef $distCoeffs1, ByRef $cameraMatrix2, ByRef $distCoeffs2, ByRef $imageSize, ByRef $r, ByRef $t, ByRef $e, ByRef $f, $flags, ByRef $criteria)
    ; CVAPI(double) cveStereoCalibrate(cv::_InputArray* objectPoints, cv::_InputArray* imagePoints1, cv::_InputArray* imagePoints2, cv::_InputOutputArray* cameraMatrix1, cv::_InputOutputArray* distCoeffs1, cv::_InputOutputArray* cameraMatrix2, cv::_InputOutputArray* distCoeffs2, CvSize* imageSize, cv::_OutputArray* r, cv::_OutputArray* t, cv::_OutputArray* e, cv::_OutputArray* f, int flags, CvTermCriteria* criteria);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveStereoCalibrate", "ptr", $objectPoints, "ptr", $imagePoints1, "ptr", $imagePoints2, "ptr", $cameraMatrix1, "ptr", $distCoeffs1, "ptr", $cameraMatrix2, "ptr", $distCoeffs2, "struct*", $imageSize, "ptr", $r, "ptr", $t, "ptr", $e, "ptr", $f, "int", $flags, "struct*", $criteria), "cveStereoCalibrate", @error)
EndFunc   ;==>_cveStereoCalibrate

Func _cveStereoCalibrateMat(ByRef $matObjectPoints, ByRef $matImagePoints1, ByRef $matImagePoints2, ByRef $matCameraMatrix1, ByRef $matDistCoeffs1, ByRef $matCameraMatrix2, ByRef $matDistCoeffs2, ByRef $imageSize, ByRef $matR, ByRef $matT, ByRef $matE, ByRef $matF, $flags, ByRef $criteria)
    ; cveStereoCalibrate using cv::Mat instead of _*Array

    Local $iArrObjectPoints, $vectorOfMatObjectPoints, $iArrObjectPointsSize
    Local $bObjectPointsIsArray = VarGetType($matObjectPoints) == "Array"

    If $bObjectPointsIsArray Then
        $vectorOfMatObjectPoints = _VectorOfMatCreate()

        $iArrObjectPointsSize = UBound($matObjectPoints)
        For $i = 0 To $iArrObjectPointsSize - 1
            _VectorOfMatPush($vectorOfMatObjectPoints, $matObjectPoints[$i])
        Next

        $iArrObjectPoints = _cveInputArrayFromVectorOfMat($vectorOfMatObjectPoints)
    Else
        $iArrObjectPoints = _cveInputArrayFromMat($matObjectPoints)
    EndIf

    Local $iArrImagePoints1, $vectorOfMatImagePoints1, $iArrImagePoints1Size
    Local $bImagePoints1IsArray = VarGetType($matImagePoints1) == "Array"

    If $bImagePoints1IsArray Then
        $vectorOfMatImagePoints1 = _VectorOfMatCreate()

        $iArrImagePoints1Size = UBound($matImagePoints1)
        For $i = 0 To $iArrImagePoints1Size - 1
            _VectorOfMatPush($vectorOfMatImagePoints1, $matImagePoints1[$i])
        Next

        $iArrImagePoints1 = _cveInputArrayFromVectorOfMat($vectorOfMatImagePoints1)
    Else
        $iArrImagePoints1 = _cveInputArrayFromMat($matImagePoints1)
    EndIf

    Local $iArrImagePoints2, $vectorOfMatImagePoints2, $iArrImagePoints2Size
    Local $bImagePoints2IsArray = VarGetType($matImagePoints2) == "Array"

    If $bImagePoints2IsArray Then
        $vectorOfMatImagePoints2 = _VectorOfMatCreate()

        $iArrImagePoints2Size = UBound($matImagePoints2)
        For $i = 0 To $iArrImagePoints2Size - 1
            _VectorOfMatPush($vectorOfMatImagePoints2, $matImagePoints2[$i])
        Next

        $iArrImagePoints2 = _cveInputArrayFromVectorOfMat($vectorOfMatImagePoints2)
    Else
        $iArrImagePoints2 = _cveInputArrayFromMat($matImagePoints2)
    EndIf

    Local $ioArrCameraMatrix1, $vectorOfMatCameraMatrix1, $iArrCameraMatrix1Size
    Local $bCameraMatrix1IsArray = VarGetType($matCameraMatrix1) == "Array"

    If $bCameraMatrix1IsArray Then
        $vectorOfMatCameraMatrix1 = _VectorOfMatCreate()

        $iArrCameraMatrix1Size = UBound($matCameraMatrix1)
        For $i = 0 To $iArrCameraMatrix1Size - 1
            _VectorOfMatPush($vectorOfMatCameraMatrix1, $matCameraMatrix1[$i])
        Next

        $ioArrCameraMatrix1 = _cveInputOutputArrayFromVectorOfMat($vectorOfMatCameraMatrix1)
    Else
        $ioArrCameraMatrix1 = _cveInputOutputArrayFromMat($matCameraMatrix1)
    EndIf

    Local $ioArrDistCoeffs1, $vectorOfMatDistCoeffs1, $iArrDistCoeffs1Size
    Local $bDistCoeffs1IsArray = VarGetType($matDistCoeffs1) == "Array"

    If $bDistCoeffs1IsArray Then
        $vectorOfMatDistCoeffs1 = _VectorOfMatCreate()

        $iArrDistCoeffs1Size = UBound($matDistCoeffs1)
        For $i = 0 To $iArrDistCoeffs1Size - 1
            _VectorOfMatPush($vectorOfMatDistCoeffs1, $matDistCoeffs1[$i])
        Next

        $ioArrDistCoeffs1 = _cveInputOutputArrayFromVectorOfMat($vectorOfMatDistCoeffs1)
    Else
        $ioArrDistCoeffs1 = _cveInputOutputArrayFromMat($matDistCoeffs1)
    EndIf

    Local $ioArrCameraMatrix2, $vectorOfMatCameraMatrix2, $iArrCameraMatrix2Size
    Local $bCameraMatrix2IsArray = VarGetType($matCameraMatrix2) == "Array"

    If $bCameraMatrix2IsArray Then
        $vectorOfMatCameraMatrix2 = _VectorOfMatCreate()

        $iArrCameraMatrix2Size = UBound($matCameraMatrix2)
        For $i = 0 To $iArrCameraMatrix2Size - 1
            _VectorOfMatPush($vectorOfMatCameraMatrix2, $matCameraMatrix2[$i])
        Next

        $ioArrCameraMatrix2 = _cveInputOutputArrayFromVectorOfMat($vectorOfMatCameraMatrix2)
    Else
        $ioArrCameraMatrix2 = _cveInputOutputArrayFromMat($matCameraMatrix2)
    EndIf

    Local $ioArrDistCoeffs2, $vectorOfMatDistCoeffs2, $iArrDistCoeffs2Size
    Local $bDistCoeffs2IsArray = VarGetType($matDistCoeffs2) == "Array"

    If $bDistCoeffs2IsArray Then
        $vectorOfMatDistCoeffs2 = _VectorOfMatCreate()

        $iArrDistCoeffs2Size = UBound($matDistCoeffs2)
        For $i = 0 To $iArrDistCoeffs2Size - 1
            _VectorOfMatPush($vectorOfMatDistCoeffs2, $matDistCoeffs2[$i])
        Next

        $ioArrDistCoeffs2 = _cveInputOutputArrayFromVectorOfMat($vectorOfMatDistCoeffs2)
    Else
        $ioArrDistCoeffs2 = _cveInputOutputArrayFromMat($matDistCoeffs2)
    EndIf

    Local $oArrR, $vectorOfMatR, $iArrRSize
    Local $bRIsArray = VarGetType($matR) == "Array"

    If $bRIsArray Then
        $vectorOfMatR = _VectorOfMatCreate()

        $iArrRSize = UBound($matR)
        For $i = 0 To $iArrRSize - 1
            _VectorOfMatPush($vectorOfMatR, $matR[$i])
        Next

        $oArrR = _cveOutputArrayFromVectorOfMat($vectorOfMatR)
    Else
        $oArrR = _cveOutputArrayFromMat($matR)
    EndIf

    Local $oArrT, $vectorOfMatT, $iArrTSize
    Local $bTIsArray = VarGetType($matT) == "Array"

    If $bTIsArray Then
        $vectorOfMatT = _VectorOfMatCreate()

        $iArrTSize = UBound($matT)
        For $i = 0 To $iArrTSize - 1
            _VectorOfMatPush($vectorOfMatT, $matT[$i])
        Next

        $oArrT = _cveOutputArrayFromVectorOfMat($vectorOfMatT)
    Else
        $oArrT = _cveOutputArrayFromMat($matT)
    EndIf

    Local $oArrE, $vectorOfMatE, $iArrESize
    Local $bEIsArray = VarGetType($matE) == "Array"

    If $bEIsArray Then
        $vectorOfMatE = _VectorOfMatCreate()

        $iArrESize = UBound($matE)
        For $i = 0 To $iArrESize - 1
            _VectorOfMatPush($vectorOfMatE, $matE[$i])
        Next

        $oArrE = _cveOutputArrayFromVectorOfMat($vectorOfMatE)
    Else
        $oArrE = _cveOutputArrayFromMat($matE)
    EndIf

    Local $oArrF, $vectorOfMatF, $iArrFSize
    Local $bFIsArray = VarGetType($matF) == "Array"

    If $bFIsArray Then
        $vectorOfMatF = _VectorOfMatCreate()

        $iArrFSize = UBound($matF)
        For $i = 0 To $iArrFSize - 1
            _VectorOfMatPush($vectorOfMatF, $matF[$i])
        Next

        $oArrF = _cveOutputArrayFromVectorOfMat($vectorOfMatF)
    Else
        $oArrF = _cveOutputArrayFromMat($matF)
    EndIf

    Local $retval = _cveStereoCalibrate($iArrObjectPoints, $iArrImagePoints1, $iArrImagePoints2, $ioArrCameraMatrix1, $ioArrDistCoeffs1, $ioArrCameraMatrix2, $ioArrDistCoeffs2, $imageSize, $oArrR, $oArrT, $oArrE, $oArrF, $flags, $criteria)

    If $bFIsArray Then
        _VectorOfMatRelease($vectorOfMatF)
    EndIf

    _cveOutputArrayRelease($oArrF)

    If $bEIsArray Then
        _VectorOfMatRelease($vectorOfMatE)
    EndIf

    _cveOutputArrayRelease($oArrE)

    If $bTIsArray Then
        _VectorOfMatRelease($vectorOfMatT)
    EndIf

    _cveOutputArrayRelease($oArrT)

    If $bRIsArray Then
        _VectorOfMatRelease($vectorOfMatR)
    EndIf

    _cveOutputArrayRelease($oArrR)

    If $bDistCoeffs2IsArray Then
        _VectorOfMatRelease($vectorOfMatDistCoeffs2)
    EndIf

    _cveInputOutputArrayRelease($ioArrDistCoeffs2)

    If $bCameraMatrix2IsArray Then
        _VectorOfMatRelease($vectorOfMatCameraMatrix2)
    EndIf

    _cveInputOutputArrayRelease($ioArrCameraMatrix2)

    If $bDistCoeffs1IsArray Then
        _VectorOfMatRelease($vectorOfMatDistCoeffs1)
    EndIf

    _cveInputOutputArrayRelease($ioArrDistCoeffs1)

    If $bCameraMatrix1IsArray Then
        _VectorOfMatRelease($vectorOfMatCameraMatrix1)
    EndIf

    _cveInputOutputArrayRelease($ioArrCameraMatrix1)

    If $bImagePoints2IsArray Then
        _VectorOfMatRelease($vectorOfMatImagePoints2)
    EndIf

    _cveInputArrayRelease($iArrImagePoints2)

    If $bImagePoints1IsArray Then
        _VectorOfMatRelease($vectorOfMatImagePoints1)
    EndIf

    _cveInputArrayRelease($iArrImagePoints1)

    If $bObjectPointsIsArray Then
        _VectorOfMatRelease($vectorOfMatObjectPoints)
    EndIf

    _cveInputArrayRelease($iArrObjectPoints)

    Return $retval
EndFunc   ;==>_cveStereoCalibrateMat

Func _cveSolvePnP(ByRef $objectPoints, ByRef $imagePoints, ByRef $cameraMatrix, ByRef $distCoeffs, ByRef $rvec, ByRef $tvec, $useExtrinsicGuess, $flags)
    ; CVAPI(bool) cveSolvePnP(cv::_InputArray* objectPoints, cv::_InputArray* imagePoints, cv::_InputArray* cameraMatrix, cv::_InputArray* distCoeffs, cv::_OutputArray* rvec, cv::_OutputArray* tvec, bool useExtrinsicGuess, int flags);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveSolvePnP", "ptr", $objectPoints, "ptr", $imagePoints, "ptr", $cameraMatrix, "ptr", $distCoeffs, "ptr", $rvec, "ptr", $tvec, "boolean", $useExtrinsicGuess, "int", $flags), "cveSolvePnP", @error)
EndFunc   ;==>_cveSolvePnP

Func _cveSolvePnPMat(ByRef $matObjectPoints, ByRef $matImagePoints, ByRef $matCameraMatrix, ByRef $matDistCoeffs, ByRef $matRvec, ByRef $matTvec, $useExtrinsicGuess, $flags)
    ; cveSolvePnP using cv::Mat instead of _*Array

    Local $iArrObjectPoints, $vectorOfMatObjectPoints, $iArrObjectPointsSize
    Local $bObjectPointsIsArray = VarGetType($matObjectPoints) == "Array"

    If $bObjectPointsIsArray Then
        $vectorOfMatObjectPoints = _VectorOfMatCreate()

        $iArrObjectPointsSize = UBound($matObjectPoints)
        For $i = 0 To $iArrObjectPointsSize - 1
            _VectorOfMatPush($vectorOfMatObjectPoints, $matObjectPoints[$i])
        Next

        $iArrObjectPoints = _cveInputArrayFromVectorOfMat($vectorOfMatObjectPoints)
    Else
        $iArrObjectPoints = _cveInputArrayFromMat($matObjectPoints)
    EndIf

    Local $iArrImagePoints, $vectorOfMatImagePoints, $iArrImagePointsSize
    Local $bImagePointsIsArray = VarGetType($matImagePoints) == "Array"

    If $bImagePointsIsArray Then
        $vectorOfMatImagePoints = _VectorOfMatCreate()

        $iArrImagePointsSize = UBound($matImagePoints)
        For $i = 0 To $iArrImagePointsSize - 1
            _VectorOfMatPush($vectorOfMatImagePoints, $matImagePoints[$i])
        Next

        $iArrImagePoints = _cveInputArrayFromVectorOfMat($vectorOfMatImagePoints)
    Else
        $iArrImagePoints = _cveInputArrayFromMat($matImagePoints)
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

    Local $oArrRvec, $vectorOfMatRvec, $iArrRvecSize
    Local $bRvecIsArray = VarGetType($matRvec) == "Array"

    If $bRvecIsArray Then
        $vectorOfMatRvec = _VectorOfMatCreate()

        $iArrRvecSize = UBound($matRvec)
        For $i = 0 To $iArrRvecSize - 1
            _VectorOfMatPush($vectorOfMatRvec, $matRvec[$i])
        Next

        $oArrRvec = _cveOutputArrayFromVectorOfMat($vectorOfMatRvec)
    Else
        $oArrRvec = _cveOutputArrayFromMat($matRvec)
    EndIf

    Local $oArrTvec, $vectorOfMatTvec, $iArrTvecSize
    Local $bTvecIsArray = VarGetType($matTvec) == "Array"

    If $bTvecIsArray Then
        $vectorOfMatTvec = _VectorOfMatCreate()

        $iArrTvecSize = UBound($matTvec)
        For $i = 0 To $iArrTvecSize - 1
            _VectorOfMatPush($vectorOfMatTvec, $matTvec[$i])
        Next

        $oArrTvec = _cveOutputArrayFromVectorOfMat($vectorOfMatTvec)
    Else
        $oArrTvec = _cveOutputArrayFromMat($matTvec)
    EndIf

    Local $retval = _cveSolvePnP($iArrObjectPoints, $iArrImagePoints, $iArrCameraMatrix, $iArrDistCoeffs, $oArrRvec, $oArrTvec, $useExtrinsicGuess, $flags)

    If $bTvecIsArray Then
        _VectorOfMatRelease($vectorOfMatTvec)
    EndIf

    _cveOutputArrayRelease($oArrTvec)

    If $bRvecIsArray Then
        _VectorOfMatRelease($vectorOfMatRvec)
    EndIf

    _cveOutputArrayRelease($oArrRvec)

    If $bDistCoeffsIsArray Then
        _VectorOfMatRelease($vectorOfMatDistCoeffs)
    EndIf

    _cveInputArrayRelease($iArrDistCoeffs)

    If $bCameraMatrixIsArray Then
        _VectorOfMatRelease($vectorOfMatCameraMatrix)
    EndIf

    _cveInputArrayRelease($iArrCameraMatrix)

    If $bImagePointsIsArray Then
        _VectorOfMatRelease($vectorOfMatImagePoints)
    EndIf

    _cveInputArrayRelease($iArrImagePoints)

    If $bObjectPointsIsArray Then
        _VectorOfMatRelease($vectorOfMatObjectPoints)
    EndIf

    _cveInputArrayRelease($iArrObjectPoints)

    Return $retval
EndFunc   ;==>_cveSolvePnPMat

Func _cveSolvePnPRansac(ByRef $objectPoints, ByRef $imagePoints, ByRef $cameraMatrix, ByRef $distCoeffs, ByRef $rvec, ByRef $tvec, $useExtrinsicGuess, $iterationsCount, $reprojectionError, $confident, ByRef $inliers, $flags)
    ; CVAPI(bool) cveSolvePnPRansac(cv::_InputArray* objectPoints, cv::_InputArray* imagePoints, cv::_InputArray* cameraMatrix, cv::_InputArray* distCoeffs, cv::_OutputArray* rvec, cv::_OutputArray* tvec, bool useExtrinsicGuess, int iterationsCount, float reprojectionError, double confident, cv::_OutputArray* inliers, int flags);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveSolvePnPRansac", "ptr", $objectPoints, "ptr", $imagePoints, "ptr", $cameraMatrix, "ptr", $distCoeffs, "ptr", $rvec, "ptr", $tvec, "boolean", $useExtrinsicGuess, "int", $iterationsCount, "float", $reprojectionError, "double", $confident, "ptr", $inliers, "int", $flags), "cveSolvePnPRansac", @error)
EndFunc   ;==>_cveSolvePnPRansac

Func _cveSolvePnPRansacMat(ByRef $matObjectPoints, ByRef $matImagePoints, ByRef $matCameraMatrix, ByRef $matDistCoeffs, ByRef $matRvec, ByRef $matTvec, $useExtrinsicGuess, $iterationsCount, $reprojectionError, $confident, ByRef $matInliers, $flags)
    ; cveSolvePnPRansac using cv::Mat instead of _*Array

    Local $iArrObjectPoints, $vectorOfMatObjectPoints, $iArrObjectPointsSize
    Local $bObjectPointsIsArray = VarGetType($matObjectPoints) == "Array"

    If $bObjectPointsIsArray Then
        $vectorOfMatObjectPoints = _VectorOfMatCreate()

        $iArrObjectPointsSize = UBound($matObjectPoints)
        For $i = 0 To $iArrObjectPointsSize - 1
            _VectorOfMatPush($vectorOfMatObjectPoints, $matObjectPoints[$i])
        Next

        $iArrObjectPoints = _cveInputArrayFromVectorOfMat($vectorOfMatObjectPoints)
    Else
        $iArrObjectPoints = _cveInputArrayFromMat($matObjectPoints)
    EndIf

    Local $iArrImagePoints, $vectorOfMatImagePoints, $iArrImagePointsSize
    Local $bImagePointsIsArray = VarGetType($matImagePoints) == "Array"

    If $bImagePointsIsArray Then
        $vectorOfMatImagePoints = _VectorOfMatCreate()

        $iArrImagePointsSize = UBound($matImagePoints)
        For $i = 0 To $iArrImagePointsSize - 1
            _VectorOfMatPush($vectorOfMatImagePoints, $matImagePoints[$i])
        Next

        $iArrImagePoints = _cveInputArrayFromVectorOfMat($vectorOfMatImagePoints)
    Else
        $iArrImagePoints = _cveInputArrayFromMat($matImagePoints)
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

    Local $oArrRvec, $vectorOfMatRvec, $iArrRvecSize
    Local $bRvecIsArray = VarGetType($matRvec) == "Array"

    If $bRvecIsArray Then
        $vectorOfMatRvec = _VectorOfMatCreate()

        $iArrRvecSize = UBound($matRvec)
        For $i = 0 To $iArrRvecSize - 1
            _VectorOfMatPush($vectorOfMatRvec, $matRvec[$i])
        Next

        $oArrRvec = _cveOutputArrayFromVectorOfMat($vectorOfMatRvec)
    Else
        $oArrRvec = _cveOutputArrayFromMat($matRvec)
    EndIf

    Local $oArrTvec, $vectorOfMatTvec, $iArrTvecSize
    Local $bTvecIsArray = VarGetType($matTvec) == "Array"

    If $bTvecIsArray Then
        $vectorOfMatTvec = _VectorOfMatCreate()

        $iArrTvecSize = UBound($matTvec)
        For $i = 0 To $iArrTvecSize - 1
            _VectorOfMatPush($vectorOfMatTvec, $matTvec[$i])
        Next

        $oArrTvec = _cveOutputArrayFromVectorOfMat($vectorOfMatTvec)
    Else
        $oArrTvec = _cveOutputArrayFromMat($matTvec)
    EndIf

    Local $oArrInliers, $vectorOfMatInliers, $iArrInliersSize
    Local $bInliersIsArray = VarGetType($matInliers) == "Array"

    If $bInliersIsArray Then
        $vectorOfMatInliers = _VectorOfMatCreate()

        $iArrInliersSize = UBound($matInliers)
        For $i = 0 To $iArrInliersSize - 1
            _VectorOfMatPush($vectorOfMatInliers, $matInliers[$i])
        Next

        $oArrInliers = _cveOutputArrayFromVectorOfMat($vectorOfMatInliers)
    Else
        $oArrInliers = _cveOutputArrayFromMat($matInliers)
    EndIf

    Local $retval = _cveSolvePnPRansac($iArrObjectPoints, $iArrImagePoints, $iArrCameraMatrix, $iArrDistCoeffs, $oArrRvec, $oArrTvec, $useExtrinsicGuess, $iterationsCount, $reprojectionError, $confident, $oArrInliers, $flags)

    If $bInliersIsArray Then
        _VectorOfMatRelease($vectorOfMatInliers)
    EndIf

    _cveOutputArrayRelease($oArrInliers)

    If $bTvecIsArray Then
        _VectorOfMatRelease($vectorOfMatTvec)
    EndIf

    _cveOutputArrayRelease($oArrTvec)

    If $bRvecIsArray Then
        _VectorOfMatRelease($vectorOfMatRvec)
    EndIf

    _cveOutputArrayRelease($oArrRvec)

    If $bDistCoeffsIsArray Then
        _VectorOfMatRelease($vectorOfMatDistCoeffs)
    EndIf

    _cveInputArrayRelease($iArrDistCoeffs)

    If $bCameraMatrixIsArray Then
        _VectorOfMatRelease($vectorOfMatCameraMatrix)
    EndIf

    _cveInputArrayRelease($iArrCameraMatrix)

    If $bImagePointsIsArray Then
        _VectorOfMatRelease($vectorOfMatImagePoints)
    EndIf

    _cveInputArrayRelease($iArrImagePoints)

    If $bObjectPointsIsArray Then
        _VectorOfMatRelease($vectorOfMatObjectPoints)
    EndIf

    _cveInputArrayRelease($iArrObjectPoints)

    Return $retval
EndFunc   ;==>_cveSolvePnPRansacMat

Func _cveSolveP3P(ByRef $objectPoints, ByRef $imagePoints, ByRef $cameraMatrix, ByRef $distCoeffs, ByRef $rvecs, ByRef $tvecs, $flags)
    ; CVAPI(int) cveSolveP3P(cv::_InputArray* objectPoints, cv::_InputArray* imagePoints, cv::_InputArray* cameraMatrix, cv::_InputArray* distCoeffs, cv::_OutputArray* rvecs, cv::_OutputArray* tvecs, int flags);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveSolveP3P", "ptr", $objectPoints, "ptr", $imagePoints, "ptr", $cameraMatrix, "ptr", $distCoeffs, "ptr", $rvecs, "ptr", $tvecs, "int", $flags), "cveSolveP3P", @error)
EndFunc   ;==>_cveSolveP3P

Func _cveSolveP3PMat(ByRef $matObjectPoints, ByRef $matImagePoints, ByRef $matCameraMatrix, ByRef $matDistCoeffs, ByRef $matRvecs, ByRef $matTvecs, $flags)
    ; cveSolveP3P using cv::Mat instead of _*Array

    Local $iArrObjectPoints, $vectorOfMatObjectPoints, $iArrObjectPointsSize
    Local $bObjectPointsIsArray = VarGetType($matObjectPoints) == "Array"

    If $bObjectPointsIsArray Then
        $vectorOfMatObjectPoints = _VectorOfMatCreate()

        $iArrObjectPointsSize = UBound($matObjectPoints)
        For $i = 0 To $iArrObjectPointsSize - 1
            _VectorOfMatPush($vectorOfMatObjectPoints, $matObjectPoints[$i])
        Next

        $iArrObjectPoints = _cveInputArrayFromVectorOfMat($vectorOfMatObjectPoints)
    Else
        $iArrObjectPoints = _cveInputArrayFromMat($matObjectPoints)
    EndIf

    Local $iArrImagePoints, $vectorOfMatImagePoints, $iArrImagePointsSize
    Local $bImagePointsIsArray = VarGetType($matImagePoints) == "Array"

    If $bImagePointsIsArray Then
        $vectorOfMatImagePoints = _VectorOfMatCreate()

        $iArrImagePointsSize = UBound($matImagePoints)
        For $i = 0 To $iArrImagePointsSize - 1
            _VectorOfMatPush($vectorOfMatImagePoints, $matImagePoints[$i])
        Next

        $iArrImagePoints = _cveInputArrayFromVectorOfMat($vectorOfMatImagePoints)
    Else
        $iArrImagePoints = _cveInputArrayFromMat($matImagePoints)
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

    Local $retval = _cveSolveP3P($iArrObjectPoints, $iArrImagePoints, $iArrCameraMatrix, $iArrDistCoeffs, $oArrRvecs, $oArrTvecs, $flags)

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

    If $bImagePointsIsArray Then
        _VectorOfMatRelease($vectorOfMatImagePoints)
    EndIf

    _cveInputArrayRelease($iArrImagePoints)

    If $bObjectPointsIsArray Then
        _VectorOfMatRelease($vectorOfMatObjectPoints)
    EndIf

    _cveInputArrayRelease($iArrObjectPoints)

    Return $retval
EndFunc   ;==>_cveSolveP3PMat

Func _cveSolvePnPRefineLM(ByRef $objectPoints, ByRef $imagePoints, ByRef $cameraMatrix, ByRef $distCoeffs, ByRef $rvec, ByRef $tvec, ByRef $criteria)
    ; CVAPI(void) cveSolvePnPRefineLM(cv::_InputArray* objectPoints, cv::_InputArray* imagePoints, cv::_InputArray* cameraMatrix, cv::_InputArray* distCoeffs, cv::_InputOutputArray* rvec, cv::_InputOutputArray* tvec, CvTermCriteria* criteria);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSolvePnPRefineLM", "ptr", $objectPoints, "ptr", $imagePoints, "ptr", $cameraMatrix, "ptr", $distCoeffs, "ptr", $rvec, "ptr", $tvec, "struct*", $criteria), "cveSolvePnPRefineLM", @error)
EndFunc   ;==>_cveSolvePnPRefineLM

Func _cveSolvePnPRefineLMMat(ByRef $matObjectPoints, ByRef $matImagePoints, ByRef $matCameraMatrix, ByRef $matDistCoeffs, ByRef $matRvec, ByRef $matTvec, ByRef $criteria)
    ; cveSolvePnPRefineLM using cv::Mat instead of _*Array

    Local $iArrObjectPoints, $vectorOfMatObjectPoints, $iArrObjectPointsSize
    Local $bObjectPointsIsArray = VarGetType($matObjectPoints) == "Array"

    If $bObjectPointsIsArray Then
        $vectorOfMatObjectPoints = _VectorOfMatCreate()

        $iArrObjectPointsSize = UBound($matObjectPoints)
        For $i = 0 To $iArrObjectPointsSize - 1
            _VectorOfMatPush($vectorOfMatObjectPoints, $matObjectPoints[$i])
        Next

        $iArrObjectPoints = _cveInputArrayFromVectorOfMat($vectorOfMatObjectPoints)
    Else
        $iArrObjectPoints = _cveInputArrayFromMat($matObjectPoints)
    EndIf

    Local $iArrImagePoints, $vectorOfMatImagePoints, $iArrImagePointsSize
    Local $bImagePointsIsArray = VarGetType($matImagePoints) == "Array"

    If $bImagePointsIsArray Then
        $vectorOfMatImagePoints = _VectorOfMatCreate()

        $iArrImagePointsSize = UBound($matImagePoints)
        For $i = 0 To $iArrImagePointsSize - 1
            _VectorOfMatPush($vectorOfMatImagePoints, $matImagePoints[$i])
        Next

        $iArrImagePoints = _cveInputArrayFromVectorOfMat($vectorOfMatImagePoints)
    Else
        $iArrImagePoints = _cveInputArrayFromMat($matImagePoints)
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

    _cveSolvePnPRefineLM($iArrObjectPoints, $iArrImagePoints, $iArrCameraMatrix, $iArrDistCoeffs, $ioArrRvec, $ioArrTvec, $criteria)

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

    If $bImagePointsIsArray Then
        _VectorOfMatRelease($vectorOfMatImagePoints)
    EndIf

    _cveInputArrayRelease($iArrImagePoints)

    If $bObjectPointsIsArray Then
        _VectorOfMatRelease($vectorOfMatObjectPoints)
    EndIf

    _cveInputArrayRelease($iArrObjectPoints)
EndFunc   ;==>_cveSolvePnPRefineLMMat

Func _cveSolvePnPRefineVVS(ByRef $objectPoints, ByRef $imagePoints, ByRef $cameraMatrix, ByRef $distCoeffs, ByRef $rvec, ByRef $tvec, ByRef $criteria, $VVSlambda)
    ; CVAPI(void) cveSolvePnPRefineVVS(cv::_InputArray* objectPoints, cv::_InputArray* imagePoints, cv::_InputArray* cameraMatrix, cv::_InputArray* distCoeffs, cv::_InputOutputArray* rvec, cv::_InputOutputArray* tvec, CvTermCriteria* criteria, double VVSlambda);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSolvePnPRefineVVS", "ptr", $objectPoints, "ptr", $imagePoints, "ptr", $cameraMatrix, "ptr", $distCoeffs, "ptr", $rvec, "ptr", $tvec, "struct*", $criteria, "double", $VVSlambda), "cveSolvePnPRefineVVS", @error)
EndFunc   ;==>_cveSolvePnPRefineVVS

Func _cveSolvePnPRefineVVSMat(ByRef $matObjectPoints, ByRef $matImagePoints, ByRef $matCameraMatrix, ByRef $matDistCoeffs, ByRef $matRvec, ByRef $matTvec, ByRef $criteria, $VVSlambda)
    ; cveSolvePnPRefineVVS using cv::Mat instead of _*Array

    Local $iArrObjectPoints, $vectorOfMatObjectPoints, $iArrObjectPointsSize
    Local $bObjectPointsIsArray = VarGetType($matObjectPoints) == "Array"

    If $bObjectPointsIsArray Then
        $vectorOfMatObjectPoints = _VectorOfMatCreate()

        $iArrObjectPointsSize = UBound($matObjectPoints)
        For $i = 0 To $iArrObjectPointsSize - 1
            _VectorOfMatPush($vectorOfMatObjectPoints, $matObjectPoints[$i])
        Next

        $iArrObjectPoints = _cveInputArrayFromVectorOfMat($vectorOfMatObjectPoints)
    Else
        $iArrObjectPoints = _cveInputArrayFromMat($matObjectPoints)
    EndIf

    Local $iArrImagePoints, $vectorOfMatImagePoints, $iArrImagePointsSize
    Local $bImagePointsIsArray = VarGetType($matImagePoints) == "Array"

    If $bImagePointsIsArray Then
        $vectorOfMatImagePoints = _VectorOfMatCreate()

        $iArrImagePointsSize = UBound($matImagePoints)
        For $i = 0 To $iArrImagePointsSize - 1
            _VectorOfMatPush($vectorOfMatImagePoints, $matImagePoints[$i])
        Next

        $iArrImagePoints = _cveInputArrayFromVectorOfMat($vectorOfMatImagePoints)
    Else
        $iArrImagePoints = _cveInputArrayFromMat($matImagePoints)
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

    _cveSolvePnPRefineVVS($iArrObjectPoints, $iArrImagePoints, $iArrCameraMatrix, $iArrDistCoeffs, $ioArrRvec, $ioArrTvec, $criteria, $VVSlambda)

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

    If $bImagePointsIsArray Then
        _VectorOfMatRelease($vectorOfMatImagePoints)
    EndIf

    _cveInputArrayRelease($iArrImagePoints)

    If $bObjectPointsIsArray Then
        _VectorOfMatRelease($vectorOfMatObjectPoints)
    EndIf

    _cveInputArrayRelease($iArrObjectPoints)
EndFunc   ;==>_cveSolvePnPRefineVVSMat

Func _cveSolvePnPGeneric(ByRef $objectPoints, ByRef $imagePoints, ByRef $cameraMatrix, ByRef $distCoeffs, ByRef $rvecs, ByRef $tvecs, $useExtrinsicGuess, $flags, ByRef $rvec, ByRef $tvec, ByRef $reprojectionError)
    ; CVAPI(int) cveSolvePnPGeneric(cv::_InputArray* objectPoints, cv::_InputArray* imagePoints, cv::_InputArray* cameraMatrix, cv::_InputArray* distCoeffs, cv::_OutputArray* rvecs, cv::_OutputArray* tvecs, bool useExtrinsicGuess, int flags, cv::_InputArray* rvec, cv::_InputArray* tvec, cv::_OutputArray* reprojectionError);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveSolvePnPGeneric", "ptr", $objectPoints, "ptr", $imagePoints, "ptr", $cameraMatrix, "ptr", $distCoeffs, "ptr", $rvecs, "ptr", $tvecs, "boolean", $useExtrinsicGuess, "int", $flags, "ptr", $rvec, "ptr", $tvec, "ptr", $reprojectionError), "cveSolvePnPGeneric", @error)
EndFunc   ;==>_cveSolvePnPGeneric

Func _cveSolvePnPGenericMat(ByRef $matObjectPoints, ByRef $matImagePoints, ByRef $matCameraMatrix, ByRef $matDistCoeffs, ByRef $matRvecs, ByRef $matTvecs, $useExtrinsicGuess, $flags, ByRef $matRvec, ByRef $matTvec, ByRef $matReprojectionError)
    ; cveSolvePnPGeneric using cv::Mat instead of _*Array

    Local $iArrObjectPoints, $vectorOfMatObjectPoints, $iArrObjectPointsSize
    Local $bObjectPointsIsArray = VarGetType($matObjectPoints) == "Array"

    If $bObjectPointsIsArray Then
        $vectorOfMatObjectPoints = _VectorOfMatCreate()

        $iArrObjectPointsSize = UBound($matObjectPoints)
        For $i = 0 To $iArrObjectPointsSize - 1
            _VectorOfMatPush($vectorOfMatObjectPoints, $matObjectPoints[$i])
        Next

        $iArrObjectPoints = _cveInputArrayFromVectorOfMat($vectorOfMatObjectPoints)
    Else
        $iArrObjectPoints = _cveInputArrayFromMat($matObjectPoints)
    EndIf

    Local $iArrImagePoints, $vectorOfMatImagePoints, $iArrImagePointsSize
    Local $bImagePointsIsArray = VarGetType($matImagePoints) == "Array"

    If $bImagePointsIsArray Then
        $vectorOfMatImagePoints = _VectorOfMatCreate()

        $iArrImagePointsSize = UBound($matImagePoints)
        For $i = 0 To $iArrImagePointsSize - 1
            _VectorOfMatPush($vectorOfMatImagePoints, $matImagePoints[$i])
        Next

        $iArrImagePoints = _cveInputArrayFromVectorOfMat($vectorOfMatImagePoints)
    Else
        $iArrImagePoints = _cveInputArrayFromMat($matImagePoints)
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

    Local $oArrReprojectionError, $vectorOfMatReprojectionError, $iArrReprojectionErrorSize
    Local $bReprojectionErrorIsArray = VarGetType($matReprojectionError) == "Array"

    If $bReprojectionErrorIsArray Then
        $vectorOfMatReprojectionError = _VectorOfMatCreate()

        $iArrReprojectionErrorSize = UBound($matReprojectionError)
        For $i = 0 To $iArrReprojectionErrorSize - 1
            _VectorOfMatPush($vectorOfMatReprojectionError, $matReprojectionError[$i])
        Next

        $oArrReprojectionError = _cveOutputArrayFromVectorOfMat($vectorOfMatReprojectionError)
    Else
        $oArrReprojectionError = _cveOutputArrayFromMat($matReprojectionError)
    EndIf

    Local $retval = _cveSolvePnPGeneric($iArrObjectPoints, $iArrImagePoints, $iArrCameraMatrix, $iArrDistCoeffs, $oArrRvecs, $oArrTvecs, $useExtrinsicGuess, $flags, $iArrRvec, $iArrTvec, $oArrReprojectionError)

    If $bReprojectionErrorIsArray Then
        _VectorOfMatRelease($vectorOfMatReprojectionError)
    EndIf

    _cveOutputArrayRelease($oArrReprojectionError)

    If $bTvecIsArray Then
        _VectorOfMatRelease($vectorOfMatTvec)
    EndIf

    _cveInputArrayRelease($iArrTvec)

    If $bRvecIsArray Then
        _VectorOfMatRelease($vectorOfMatRvec)
    EndIf

    _cveInputArrayRelease($iArrRvec)

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

    If $bImagePointsIsArray Then
        _VectorOfMatRelease($vectorOfMatImagePoints)
    EndIf

    _cveInputArrayRelease($iArrImagePoints)

    If $bObjectPointsIsArray Then
        _VectorOfMatRelease($vectorOfMatObjectPoints)
    EndIf

    _cveInputArrayRelease($iArrObjectPoints)

    Return $retval
EndFunc   ;==>_cveSolvePnPGenericMat

Func _cveGetOptimalNewCameraMatrix(ByRef $cameraMatrix, ByRef $distCoeffs, ByRef $imageSize, $alpha, ByRef $newImgSize, ByRef $validPixROI, $centerPrincipalPoint, ByRef $newCameraMatrix)
    ; CVAPI(void) cveGetOptimalNewCameraMatrix(cv::_InputArray* cameraMatrix, cv::_InputArray* distCoeffs, CvSize* imageSize, double alpha, CvSize* newImgSize, CvRect* validPixROI, bool centerPrincipalPoint, cv::Mat* newCameraMatrix);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveGetOptimalNewCameraMatrix", "ptr", $cameraMatrix, "ptr", $distCoeffs, "struct*", $imageSize, "double", $alpha, "struct*", $newImgSize, "struct*", $validPixROI, "boolean", $centerPrincipalPoint, "ptr", $newCameraMatrix), "cveGetOptimalNewCameraMatrix", @error)
EndFunc   ;==>_cveGetOptimalNewCameraMatrix

Func _cveGetOptimalNewCameraMatrixMat(ByRef $matCameraMatrix, ByRef $matDistCoeffs, ByRef $imageSize, $alpha, ByRef $newImgSize, ByRef $validPixROI, $centerPrincipalPoint, ByRef $newCameraMatrix)
    ; cveGetOptimalNewCameraMatrix using cv::Mat instead of _*Array

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

    _cveGetOptimalNewCameraMatrix($iArrCameraMatrix, $iArrDistCoeffs, $imageSize, $alpha, $newImgSize, $validPixROI, $centerPrincipalPoint, $newCameraMatrix)

    If $bDistCoeffsIsArray Then
        _VectorOfMatRelease($vectorOfMatDistCoeffs)
    EndIf

    _cveInputArrayRelease($iArrDistCoeffs)

    If $bCameraMatrixIsArray Then
        _VectorOfMatRelease($vectorOfMatCameraMatrix)
    EndIf

    _cveInputArrayRelease($iArrCameraMatrix)
EndFunc   ;==>_cveGetOptimalNewCameraMatrixMat

Func _cveInitCameraMatrix2D(ByRef $objectPoints, ByRef $imagePoints, ByRef $imageSize, $aspectRatio, ByRef $cameraMatrix)
    ; CVAPI(void) cveInitCameraMatrix2D(cv::_InputArray* objectPoints, cv::_InputArray* imagePoints, CvSize* imageSize, double aspectRatio, cv::Mat* cameraMatrix);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveInitCameraMatrix2D", "ptr", $objectPoints, "ptr", $imagePoints, "struct*", $imageSize, "double", $aspectRatio, "ptr", $cameraMatrix), "cveInitCameraMatrix2D", @error)
EndFunc   ;==>_cveInitCameraMatrix2D

Func _cveInitCameraMatrix2DMat(ByRef $matObjectPoints, ByRef $matImagePoints, ByRef $imageSize, $aspectRatio, ByRef $cameraMatrix)
    ; cveInitCameraMatrix2D using cv::Mat instead of _*Array

    Local $iArrObjectPoints, $vectorOfMatObjectPoints, $iArrObjectPointsSize
    Local $bObjectPointsIsArray = VarGetType($matObjectPoints) == "Array"

    If $bObjectPointsIsArray Then
        $vectorOfMatObjectPoints = _VectorOfMatCreate()

        $iArrObjectPointsSize = UBound($matObjectPoints)
        For $i = 0 To $iArrObjectPointsSize - 1
            _VectorOfMatPush($vectorOfMatObjectPoints, $matObjectPoints[$i])
        Next

        $iArrObjectPoints = _cveInputArrayFromVectorOfMat($vectorOfMatObjectPoints)
    Else
        $iArrObjectPoints = _cveInputArrayFromMat($matObjectPoints)
    EndIf

    Local $iArrImagePoints, $vectorOfMatImagePoints, $iArrImagePointsSize
    Local $bImagePointsIsArray = VarGetType($matImagePoints) == "Array"

    If $bImagePointsIsArray Then
        $vectorOfMatImagePoints = _VectorOfMatCreate()

        $iArrImagePointsSize = UBound($matImagePoints)
        For $i = 0 To $iArrImagePointsSize - 1
            _VectorOfMatPush($vectorOfMatImagePoints, $matImagePoints[$i])
        Next

        $iArrImagePoints = _cveInputArrayFromVectorOfMat($vectorOfMatImagePoints)
    Else
        $iArrImagePoints = _cveInputArrayFromMat($matImagePoints)
    EndIf

    _cveInitCameraMatrix2D($iArrObjectPoints, $iArrImagePoints, $imageSize, $aspectRatio, $cameraMatrix)

    If $bImagePointsIsArray Then
        _VectorOfMatRelease($vectorOfMatImagePoints)
    EndIf

    _cveInputArrayRelease($iArrImagePoints)

    If $bObjectPointsIsArray Then
        _VectorOfMatRelease($vectorOfMatObjectPoints)
    EndIf

    _cveInputArrayRelease($iArrObjectPoints)
EndFunc   ;==>_cveInitCameraMatrix2DMat

Func _cveFisheyeProjectPoints(ByRef $objectPoints, ByRef $imagePoints, ByRef $rvec, ByRef $tvec, ByRef $K, ByRef $D, $alpha, ByRef $jacobian)
    ; CVAPI(void) cveFisheyeProjectPoints(cv::_InputArray* objectPoints, cv::_OutputArray* imagePoints, cv::_InputArray* rvec, cv::_InputArray* tvec, cv::_InputArray* K, cv::_InputArray* D, double alpha, cv::_OutputArray* jacobian);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFisheyeProjectPoints", "ptr", $objectPoints, "ptr", $imagePoints, "ptr", $rvec, "ptr", $tvec, "ptr", $K, "ptr", $D, "double", $alpha, "ptr", $jacobian), "cveFisheyeProjectPoints", @error)
EndFunc   ;==>_cveFisheyeProjectPoints

Func _cveFisheyeProjectPointsMat(ByRef $matObjectPoints, ByRef $matImagePoints, ByRef $matRvec, ByRef $matTvec, ByRef $matK, ByRef $matD, $alpha, ByRef $matJacobian)
    ; cveFisheyeProjectPoints using cv::Mat instead of _*Array

    Local $iArrObjectPoints, $vectorOfMatObjectPoints, $iArrObjectPointsSize
    Local $bObjectPointsIsArray = VarGetType($matObjectPoints) == "Array"

    If $bObjectPointsIsArray Then
        $vectorOfMatObjectPoints = _VectorOfMatCreate()

        $iArrObjectPointsSize = UBound($matObjectPoints)
        For $i = 0 To $iArrObjectPointsSize - 1
            _VectorOfMatPush($vectorOfMatObjectPoints, $matObjectPoints[$i])
        Next

        $iArrObjectPoints = _cveInputArrayFromVectorOfMat($vectorOfMatObjectPoints)
    Else
        $iArrObjectPoints = _cveInputArrayFromMat($matObjectPoints)
    EndIf

    Local $oArrImagePoints, $vectorOfMatImagePoints, $iArrImagePointsSize
    Local $bImagePointsIsArray = VarGetType($matImagePoints) == "Array"

    If $bImagePointsIsArray Then
        $vectorOfMatImagePoints = _VectorOfMatCreate()

        $iArrImagePointsSize = UBound($matImagePoints)
        For $i = 0 To $iArrImagePointsSize - 1
            _VectorOfMatPush($vectorOfMatImagePoints, $matImagePoints[$i])
        Next

        $oArrImagePoints = _cveOutputArrayFromVectorOfMat($vectorOfMatImagePoints)
    Else
        $oArrImagePoints = _cveOutputArrayFromMat($matImagePoints)
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

    Local $iArrD, $vectorOfMatD, $iArrDSize
    Local $bDIsArray = VarGetType($matD) == "Array"

    If $bDIsArray Then
        $vectorOfMatD = _VectorOfMatCreate()

        $iArrDSize = UBound($matD)
        For $i = 0 To $iArrDSize - 1
            _VectorOfMatPush($vectorOfMatD, $matD[$i])
        Next

        $iArrD = _cveInputArrayFromVectorOfMat($vectorOfMatD)
    Else
        $iArrD = _cveInputArrayFromMat($matD)
    EndIf

    Local $oArrJacobian, $vectorOfMatJacobian, $iArrJacobianSize
    Local $bJacobianIsArray = VarGetType($matJacobian) == "Array"

    If $bJacobianIsArray Then
        $vectorOfMatJacobian = _VectorOfMatCreate()

        $iArrJacobianSize = UBound($matJacobian)
        For $i = 0 To $iArrJacobianSize - 1
            _VectorOfMatPush($vectorOfMatJacobian, $matJacobian[$i])
        Next

        $oArrJacobian = _cveOutputArrayFromVectorOfMat($vectorOfMatJacobian)
    Else
        $oArrJacobian = _cveOutputArrayFromMat($matJacobian)
    EndIf

    _cveFisheyeProjectPoints($iArrObjectPoints, $oArrImagePoints, $iArrRvec, $iArrTvec, $iArrK, $iArrD, $alpha, $oArrJacobian)

    If $bJacobianIsArray Then
        _VectorOfMatRelease($vectorOfMatJacobian)
    EndIf

    _cveOutputArrayRelease($oArrJacobian)

    If $bDIsArray Then
        _VectorOfMatRelease($vectorOfMatD)
    EndIf

    _cveInputArrayRelease($iArrD)

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

    If $bImagePointsIsArray Then
        _VectorOfMatRelease($vectorOfMatImagePoints)
    EndIf

    _cveOutputArrayRelease($oArrImagePoints)

    If $bObjectPointsIsArray Then
        _VectorOfMatRelease($vectorOfMatObjectPoints)
    EndIf

    _cveInputArrayRelease($iArrObjectPoints)
EndFunc   ;==>_cveFisheyeProjectPointsMat

Func _cveFisheyeDistortPoints(ByRef $undistored, ByRef $distorted, ByRef $K, ByRef $D, $alpha)
    ; CVAPI(void) cveFisheyeDistortPoints(cv::_InputArray* undistored, cv::_OutputArray* distorted, cv::_InputArray* K, cv::_InputArray* D, double alpha);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFisheyeDistortPoints", "ptr", $undistored, "ptr", $distorted, "ptr", $K, "ptr", $D, "double", $alpha), "cveFisheyeDistortPoints", @error)
EndFunc   ;==>_cveFisheyeDistortPoints

Func _cveFisheyeDistortPointsMat(ByRef $matUndistored, ByRef $matDistorted, ByRef $matK, ByRef $matD, $alpha)
    ; cveFisheyeDistortPoints using cv::Mat instead of _*Array

    Local $iArrUndistored, $vectorOfMatUndistored, $iArrUndistoredSize
    Local $bUndistoredIsArray = VarGetType($matUndistored) == "Array"

    If $bUndistoredIsArray Then
        $vectorOfMatUndistored = _VectorOfMatCreate()

        $iArrUndistoredSize = UBound($matUndistored)
        For $i = 0 To $iArrUndistoredSize - 1
            _VectorOfMatPush($vectorOfMatUndistored, $matUndistored[$i])
        Next

        $iArrUndistored = _cveInputArrayFromVectorOfMat($vectorOfMatUndistored)
    Else
        $iArrUndistored = _cveInputArrayFromMat($matUndistored)
    EndIf

    Local $oArrDistorted, $vectorOfMatDistorted, $iArrDistortedSize
    Local $bDistortedIsArray = VarGetType($matDistorted) == "Array"

    If $bDistortedIsArray Then
        $vectorOfMatDistorted = _VectorOfMatCreate()

        $iArrDistortedSize = UBound($matDistorted)
        For $i = 0 To $iArrDistortedSize - 1
            _VectorOfMatPush($vectorOfMatDistorted, $matDistorted[$i])
        Next

        $oArrDistorted = _cveOutputArrayFromVectorOfMat($vectorOfMatDistorted)
    Else
        $oArrDistorted = _cveOutputArrayFromMat($matDistorted)
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

    Local $iArrD, $vectorOfMatD, $iArrDSize
    Local $bDIsArray = VarGetType($matD) == "Array"

    If $bDIsArray Then
        $vectorOfMatD = _VectorOfMatCreate()

        $iArrDSize = UBound($matD)
        For $i = 0 To $iArrDSize - 1
            _VectorOfMatPush($vectorOfMatD, $matD[$i])
        Next

        $iArrD = _cveInputArrayFromVectorOfMat($vectorOfMatD)
    Else
        $iArrD = _cveInputArrayFromMat($matD)
    EndIf

    _cveFisheyeDistortPoints($iArrUndistored, $oArrDistorted, $iArrK, $iArrD, $alpha)

    If $bDIsArray Then
        _VectorOfMatRelease($vectorOfMatD)
    EndIf

    _cveInputArrayRelease($iArrD)

    If $bKIsArray Then
        _VectorOfMatRelease($vectorOfMatK)
    EndIf

    _cveInputArrayRelease($iArrK)

    If $bDistortedIsArray Then
        _VectorOfMatRelease($vectorOfMatDistorted)
    EndIf

    _cveOutputArrayRelease($oArrDistorted)

    If $bUndistoredIsArray Then
        _VectorOfMatRelease($vectorOfMatUndistored)
    EndIf

    _cveInputArrayRelease($iArrUndistored)
EndFunc   ;==>_cveFisheyeDistortPointsMat

Func _cveFisheyeUndistorPoints(ByRef $distorted, ByRef $undistorted, ByRef $K, ByRef $D, ByRef $R, ByRef $P)
    ; CVAPI(void) cveFisheyeUndistorPoints(cv::_InputArray* distorted, cv::_OutputArray* undistorted, cv::_InputArray* K, cv::_InputArray* D, cv::_InputArray* R, cv::_InputArray* P);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFisheyeUndistorPoints", "ptr", $distorted, "ptr", $undistorted, "ptr", $K, "ptr", $D, "ptr", $R, "ptr", $P), "cveFisheyeUndistorPoints", @error)
EndFunc   ;==>_cveFisheyeUndistorPoints

Func _cveFisheyeUndistorPointsMat(ByRef $matDistorted, ByRef $matUndistorted, ByRef $matK, ByRef $matD, ByRef $matR, ByRef $matP)
    ; cveFisheyeUndistorPoints using cv::Mat instead of _*Array

    Local $iArrDistorted, $vectorOfMatDistorted, $iArrDistortedSize
    Local $bDistortedIsArray = VarGetType($matDistorted) == "Array"

    If $bDistortedIsArray Then
        $vectorOfMatDistorted = _VectorOfMatCreate()

        $iArrDistortedSize = UBound($matDistorted)
        For $i = 0 To $iArrDistortedSize - 1
            _VectorOfMatPush($vectorOfMatDistorted, $matDistorted[$i])
        Next

        $iArrDistorted = _cveInputArrayFromVectorOfMat($vectorOfMatDistorted)
    Else
        $iArrDistorted = _cveInputArrayFromMat($matDistorted)
    EndIf

    Local $oArrUndistorted, $vectorOfMatUndistorted, $iArrUndistortedSize
    Local $bUndistortedIsArray = VarGetType($matUndistorted) == "Array"

    If $bUndistortedIsArray Then
        $vectorOfMatUndistorted = _VectorOfMatCreate()

        $iArrUndistortedSize = UBound($matUndistorted)
        For $i = 0 To $iArrUndistortedSize - 1
            _VectorOfMatPush($vectorOfMatUndistorted, $matUndistorted[$i])
        Next

        $oArrUndistorted = _cveOutputArrayFromVectorOfMat($vectorOfMatUndistorted)
    Else
        $oArrUndistorted = _cveOutputArrayFromMat($matUndistorted)
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

    Local $iArrD, $vectorOfMatD, $iArrDSize
    Local $bDIsArray = VarGetType($matD) == "Array"

    If $bDIsArray Then
        $vectorOfMatD = _VectorOfMatCreate()

        $iArrDSize = UBound($matD)
        For $i = 0 To $iArrDSize - 1
            _VectorOfMatPush($vectorOfMatD, $matD[$i])
        Next

        $iArrD = _cveInputArrayFromVectorOfMat($vectorOfMatD)
    Else
        $iArrD = _cveInputArrayFromMat($matD)
    EndIf

    Local $iArrR, $vectorOfMatR, $iArrRSize
    Local $bRIsArray = VarGetType($matR) == "Array"

    If $bRIsArray Then
        $vectorOfMatR = _VectorOfMatCreate()

        $iArrRSize = UBound($matR)
        For $i = 0 To $iArrRSize - 1
            _VectorOfMatPush($vectorOfMatR, $matR[$i])
        Next

        $iArrR = _cveInputArrayFromVectorOfMat($vectorOfMatR)
    Else
        $iArrR = _cveInputArrayFromMat($matR)
    EndIf

    Local $iArrP, $vectorOfMatP, $iArrPSize
    Local $bPIsArray = VarGetType($matP) == "Array"

    If $bPIsArray Then
        $vectorOfMatP = _VectorOfMatCreate()

        $iArrPSize = UBound($matP)
        For $i = 0 To $iArrPSize - 1
            _VectorOfMatPush($vectorOfMatP, $matP[$i])
        Next

        $iArrP = _cveInputArrayFromVectorOfMat($vectorOfMatP)
    Else
        $iArrP = _cveInputArrayFromMat($matP)
    EndIf

    _cveFisheyeUndistorPoints($iArrDistorted, $oArrUndistorted, $iArrK, $iArrD, $iArrR, $iArrP)

    If $bPIsArray Then
        _VectorOfMatRelease($vectorOfMatP)
    EndIf

    _cveInputArrayRelease($iArrP)

    If $bRIsArray Then
        _VectorOfMatRelease($vectorOfMatR)
    EndIf

    _cveInputArrayRelease($iArrR)

    If $bDIsArray Then
        _VectorOfMatRelease($vectorOfMatD)
    EndIf

    _cveInputArrayRelease($iArrD)

    If $bKIsArray Then
        _VectorOfMatRelease($vectorOfMatK)
    EndIf

    _cveInputArrayRelease($iArrK)

    If $bUndistortedIsArray Then
        _VectorOfMatRelease($vectorOfMatUndistorted)
    EndIf

    _cveOutputArrayRelease($oArrUndistorted)

    If $bDistortedIsArray Then
        _VectorOfMatRelease($vectorOfMatDistorted)
    EndIf

    _cveInputArrayRelease($iArrDistorted)
EndFunc   ;==>_cveFisheyeUndistorPointsMat

Func _cveFisheyeInitUndistorRectifyMap(ByRef $K, ByRef $D, ByRef $R, ByRef $P, ByRef $size, $m1Type, ByRef $map1, ByRef $map2)
    ; CVAPI(void) cveFisheyeInitUndistorRectifyMap(cv::_InputArray* K, cv::_InputArray* D, cv::_InputArray* R, cv::_InputArray* P, CvSize* size, int m1Type, cv::_OutputArray* map1, cv::_OutputArray* map2);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFisheyeInitUndistorRectifyMap", "ptr", $K, "ptr", $D, "ptr", $R, "ptr", $P, "struct*", $size, "int", $m1Type, "ptr", $map1, "ptr", $map2), "cveFisheyeInitUndistorRectifyMap", @error)
EndFunc   ;==>_cveFisheyeInitUndistorRectifyMap

Func _cveFisheyeInitUndistorRectifyMapMat(ByRef $matK, ByRef $matD, ByRef $matR, ByRef $matP, ByRef $size, $m1Type, ByRef $matMap1, ByRef $matMap2)
    ; cveFisheyeInitUndistorRectifyMap using cv::Mat instead of _*Array

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

    Local $iArrD, $vectorOfMatD, $iArrDSize
    Local $bDIsArray = VarGetType($matD) == "Array"

    If $bDIsArray Then
        $vectorOfMatD = _VectorOfMatCreate()

        $iArrDSize = UBound($matD)
        For $i = 0 To $iArrDSize - 1
            _VectorOfMatPush($vectorOfMatD, $matD[$i])
        Next

        $iArrD = _cveInputArrayFromVectorOfMat($vectorOfMatD)
    Else
        $iArrD = _cveInputArrayFromMat($matD)
    EndIf

    Local $iArrR, $vectorOfMatR, $iArrRSize
    Local $bRIsArray = VarGetType($matR) == "Array"

    If $bRIsArray Then
        $vectorOfMatR = _VectorOfMatCreate()

        $iArrRSize = UBound($matR)
        For $i = 0 To $iArrRSize - 1
            _VectorOfMatPush($vectorOfMatR, $matR[$i])
        Next

        $iArrR = _cveInputArrayFromVectorOfMat($vectorOfMatR)
    Else
        $iArrR = _cveInputArrayFromMat($matR)
    EndIf

    Local $iArrP, $vectorOfMatP, $iArrPSize
    Local $bPIsArray = VarGetType($matP) == "Array"

    If $bPIsArray Then
        $vectorOfMatP = _VectorOfMatCreate()

        $iArrPSize = UBound($matP)
        For $i = 0 To $iArrPSize - 1
            _VectorOfMatPush($vectorOfMatP, $matP[$i])
        Next

        $iArrP = _cveInputArrayFromVectorOfMat($vectorOfMatP)
    Else
        $iArrP = _cveInputArrayFromMat($matP)
    EndIf

    Local $oArrMap1, $vectorOfMatMap1, $iArrMap1Size
    Local $bMap1IsArray = VarGetType($matMap1) == "Array"

    If $bMap1IsArray Then
        $vectorOfMatMap1 = _VectorOfMatCreate()

        $iArrMap1Size = UBound($matMap1)
        For $i = 0 To $iArrMap1Size - 1
            _VectorOfMatPush($vectorOfMatMap1, $matMap1[$i])
        Next

        $oArrMap1 = _cveOutputArrayFromVectorOfMat($vectorOfMatMap1)
    Else
        $oArrMap1 = _cveOutputArrayFromMat($matMap1)
    EndIf

    Local $oArrMap2, $vectorOfMatMap2, $iArrMap2Size
    Local $bMap2IsArray = VarGetType($matMap2) == "Array"

    If $bMap2IsArray Then
        $vectorOfMatMap2 = _VectorOfMatCreate()

        $iArrMap2Size = UBound($matMap2)
        For $i = 0 To $iArrMap2Size - 1
            _VectorOfMatPush($vectorOfMatMap2, $matMap2[$i])
        Next

        $oArrMap2 = _cveOutputArrayFromVectorOfMat($vectorOfMatMap2)
    Else
        $oArrMap2 = _cveOutputArrayFromMat($matMap2)
    EndIf

    _cveFisheyeInitUndistorRectifyMap($iArrK, $iArrD, $iArrR, $iArrP, $size, $m1Type, $oArrMap1, $oArrMap2)

    If $bMap2IsArray Then
        _VectorOfMatRelease($vectorOfMatMap2)
    EndIf

    _cveOutputArrayRelease($oArrMap2)

    If $bMap1IsArray Then
        _VectorOfMatRelease($vectorOfMatMap1)
    EndIf

    _cveOutputArrayRelease($oArrMap1)

    If $bPIsArray Then
        _VectorOfMatRelease($vectorOfMatP)
    EndIf

    _cveInputArrayRelease($iArrP)

    If $bRIsArray Then
        _VectorOfMatRelease($vectorOfMatR)
    EndIf

    _cveInputArrayRelease($iArrR)

    If $bDIsArray Then
        _VectorOfMatRelease($vectorOfMatD)
    EndIf

    _cveInputArrayRelease($iArrD)

    If $bKIsArray Then
        _VectorOfMatRelease($vectorOfMatK)
    EndIf

    _cveInputArrayRelease($iArrK)
EndFunc   ;==>_cveFisheyeInitUndistorRectifyMapMat

Func _cveFisheyeUndistorImage(ByRef $distorted, ByRef $undistored, ByRef $K, ByRef $D, ByRef $Knew, ByRef $newSize)
    ; CVAPI(void) cveFisheyeUndistorImage(cv::_InputArray* distorted, cv::_OutputArray* undistored, cv::_InputArray* K, cv::_InputArray* D, cv::_InputArray* Knew, CvSize* newSize);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFisheyeUndistorImage", "ptr", $distorted, "ptr", $undistored, "ptr", $K, "ptr", $D, "ptr", $Knew, "struct*", $newSize), "cveFisheyeUndistorImage", @error)
EndFunc   ;==>_cveFisheyeUndistorImage

Func _cveFisheyeUndistorImageMat(ByRef $matDistorted, ByRef $matUndistored, ByRef $matK, ByRef $matD, ByRef $matKnew, ByRef $newSize)
    ; cveFisheyeUndistorImage using cv::Mat instead of _*Array

    Local $iArrDistorted, $vectorOfMatDistorted, $iArrDistortedSize
    Local $bDistortedIsArray = VarGetType($matDistorted) == "Array"

    If $bDistortedIsArray Then
        $vectorOfMatDistorted = _VectorOfMatCreate()

        $iArrDistortedSize = UBound($matDistorted)
        For $i = 0 To $iArrDistortedSize - 1
            _VectorOfMatPush($vectorOfMatDistorted, $matDistorted[$i])
        Next

        $iArrDistorted = _cveInputArrayFromVectorOfMat($vectorOfMatDistorted)
    Else
        $iArrDistorted = _cveInputArrayFromMat($matDistorted)
    EndIf

    Local $oArrUndistored, $vectorOfMatUndistored, $iArrUndistoredSize
    Local $bUndistoredIsArray = VarGetType($matUndistored) == "Array"

    If $bUndistoredIsArray Then
        $vectorOfMatUndistored = _VectorOfMatCreate()

        $iArrUndistoredSize = UBound($matUndistored)
        For $i = 0 To $iArrUndistoredSize - 1
            _VectorOfMatPush($vectorOfMatUndistored, $matUndistored[$i])
        Next

        $oArrUndistored = _cveOutputArrayFromVectorOfMat($vectorOfMatUndistored)
    Else
        $oArrUndistored = _cveOutputArrayFromMat($matUndistored)
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

    Local $iArrD, $vectorOfMatD, $iArrDSize
    Local $bDIsArray = VarGetType($matD) == "Array"

    If $bDIsArray Then
        $vectorOfMatD = _VectorOfMatCreate()

        $iArrDSize = UBound($matD)
        For $i = 0 To $iArrDSize - 1
            _VectorOfMatPush($vectorOfMatD, $matD[$i])
        Next

        $iArrD = _cveInputArrayFromVectorOfMat($vectorOfMatD)
    Else
        $iArrD = _cveInputArrayFromMat($matD)
    EndIf

    Local $iArrKnew, $vectorOfMatKnew, $iArrKnewSize
    Local $bKnewIsArray = VarGetType($matKnew) == "Array"

    If $bKnewIsArray Then
        $vectorOfMatKnew = _VectorOfMatCreate()

        $iArrKnewSize = UBound($matKnew)
        For $i = 0 To $iArrKnewSize - 1
            _VectorOfMatPush($vectorOfMatKnew, $matKnew[$i])
        Next

        $iArrKnew = _cveInputArrayFromVectorOfMat($vectorOfMatKnew)
    Else
        $iArrKnew = _cveInputArrayFromMat($matKnew)
    EndIf

    _cveFisheyeUndistorImage($iArrDistorted, $oArrUndistored, $iArrK, $iArrD, $iArrKnew, $newSize)

    If $bKnewIsArray Then
        _VectorOfMatRelease($vectorOfMatKnew)
    EndIf

    _cveInputArrayRelease($iArrKnew)

    If $bDIsArray Then
        _VectorOfMatRelease($vectorOfMatD)
    EndIf

    _cveInputArrayRelease($iArrD)

    If $bKIsArray Then
        _VectorOfMatRelease($vectorOfMatK)
    EndIf

    _cveInputArrayRelease($iArrK)

    If $bUndistoredIsArray Then
        _VectorOfMatRelease($vectorOfMatUndistored)
    EndIf

    _cveOutputArrayRelease($oArrUndistored)

    If $bDistortedIsArray Then
        _VectorOfMatRelease($vectorOfMatDistorted)
    EndIf

    _cveInputArrayRelease($iArrDistorted)
EndFunc   ;==>_cveFisheyeUndistorImageMat

Func _cveFisheyeEstimateNewCameraMatrixForUndistorRectify(ByRef $K, ByRef $D, ByRef $imageSize, ByRef $R, ByRef $P, $balance, ByRef $newSize, $fovScale)
    ; CVAPI(void) cveFisheyeEstimateNewCameraMatrixForUndistorRectify(cv::_InputArray* K, cv::_InputArray* D, CvSize* imageSize, cv::_InputArray* R, cv::_OutputArray* P, double balance, CvSize* newSize, double fovScale);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFisheyeEstimateNewCameraMatrixForUndistorRectify", "ptr", $K, "ptr", $D, "struct*", $imageSize, "ptr", $R, "ptr", $P, "double", $balance, "struct*", $newSize, "double", $fovScale), "cveFisheyeEstimateNewCameraMatrixForUndistorRectify", @error)
EndFunc   ;==>_cveFisheyeEstimateNewCameraMatrixForUndistorRectify

Func _cveFisheyeEstimateNewCameraMatrixForUndistorRectifyMat(ByRef $matK, ByRef $matD, ByRef $imageSize, ByRef $matR, ByRef $matP, $balance, ByRef $newSize, $fovScale)
    ; cveFisheyeEstimateNewCameraMatrixForUndistorRectify using cv::Mat instead of _*Array

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

    Local $iArrD, $vectorOfMatD, $iArrDSize
    Local $bDIsArray = VarGetType($matD) == "Array"

    If $bDIsArray Then
        $vectorOfMatD = _VectorOfMatCreate()

        $iArrDSize = UBound($matD)
        For $i = 0 To $iArrDSize - 1
            _VectorOfMatPush($vectorOfMatD, $matD[$i])
        Next

        $iArrD = _cveInputArrayFromVectorOfMat($vectorOfMatD)
    Else
        $iArrD = _cveInputArrayFromMat($matD)
    EndIf

    Local $iArrR, $vectorOfMatR, $iArrRSize
    Local $bRIsArray = VarGetType($matR) == "Array"

    If $bRIsArray Then
        $vectorOfMatR = _VectorOfMatCreate()

        $iArrRSize = UBound($matR)
        For $i = 0 To $iArrRSize - 1
            _VectorOfMatPush($vectorOfMatR, $matR[$i])
        Next

        $iArrR = _cveInputArrayFromVectorOfMat($vectorOfMatR)
    Else
        $iArrR = _cveInputArrayFromMat($matR)
    EndIf

    Local $oArrP, $vectorOfMatP, $iArrPSize
    Local $bPIsArray = VarGetType($matP) == "Array"

    If $bPIsArray Then
        $vectorOfMatP = _VectorOfMatCreate()

        $iArrPSize = UBound($matP)
        For $i = 0 To $iArrPSize - 1
            _VectorOfMatPush($vectorOfMatP, $matP[$i])
        Next

        $oArrP = _cveOutputArrayFromVectorOfMat($vectorOfMatP)
    Else
        $oArrP = _cveOutputArrayFromMat($matP)
    EndIf

    _cveFisheyeEstimateNewCameraMatrixForUndistorRectify($iArrK, $iArrD, $imageSize, $iArrR, $oArrP, $balance, $newSize, $fovScale)

    If $bPIsArray Then
        _VectorOfMatRelease($vectorOfMatP)
    EndIf

    _cveOutputArrayRelease($oArrP)

    If $bRIsArray Then
        _VectorOfMatRelease($vectorOfMatR)
    EndIf

    _cveInputArrayRelease($iArrR)

    If $bDIsArray Then
        _VectorOfMatRelease($vectorOfMatD)
    EndIf

    _cveInputArrayRelease($iArrD)

    If $bKIsArray Then
        _VectorOfMatRelease($vectorOfMatK)
    EndIf

    _cveInputArrayRelease($iArrK)
EndFunc   ;==>_cveFisheyeEstimateNewCameraMatrixForUndistorRectifyMat

Func _cveFisheyeStereoRectify(ByRef $K1, ByRef $D1, ByRef $K2, ByRef $D2, ByRef $imageSize, ByRef $R, ByRef $tvec, ByRef $R1, ByRef $R2, ByRef $P1, ByRef $P2, ByRef $Q, $flags, ByRef $newImageSize, $balance, $fovScale)
    ; CVAPI(void) cveFisheyeStereoRectify(cv::_InputArray* K1, cv::_InputArray* D1, cv::_InputArray* K2, cv::_InputArray* D2, CvSize* imageSize, cv::_InputArray* R, cv::_InputArray* tvec, cv::_OutputArray* R1, cv::_OutputArray* R2, cv::_OutputArray* P1, cv::_OutputArray* P2, cv::_OutputArray* Q, int flags, CvSize* newImageSize, double balance, double fovScale);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFisheyeStereoRectify", "ptr", $K1, "ptr", $D1, "ptr", $K2, "ptr", $D2, "struct*", $imageSize, "ptr", $R, "ptr", $tvec, "ptr", $R1, "ptr", $R2, "ptr", $P1, "ptr", $P2, "ptr", $Q, "int", $flags, "struct*", $newImageSize, "double", $balance, "double", $fovScale), "cveFisheyeStereoRectify", @error)
EndFunc   ;==>_cveFisheyeStereoRectify

Func _cveFisheyeStereoRectifyMat(ByRef $matK1, ByRef $matD1, ByRef $matK2, ByRef $matD2, ByRef $imageSize, ByRef $matR, ByRef $matTvec, ByRef $matR1, ByRef $matR2, ByRef $matP1, ByRef $matP2, ByRef $matQ, $flags, ByRef $newImageSize, $balance, $fovScale)
    ; cveFisheyeStereoRectify using cv::Mat instead of _*Array

    Local $iArrK1, $vectorOfMatK1, $iArrK1Size
    Local $bK1IsArray = VarGetType($matK1) == "Array"

    If $bK1IsArray Then
        $vectorOfMatK1 = _VectorOfMatCreate()

        $iArrK1Size = UBound($matK1)
        For $i = 0 To $iArrK1Size - 1
            _VectorOfMatPush($vectorOfMatK1, $matK1[$i])
        Next

        $iArrK1 = _cveInputArrayFromVectorOfMat($vectorOfMatK1)
    Else
        $iArrK1 = _cveInputArrayFromMat($matK1)
    EndIf

    Local $iArrD1, $vectorOfMatD1, $iArrD1Size
    Local $bD1IsArray = VarGetType($matD1) == "Array"

    If $bD1IsArray Then
        $vectorOfMatD1 = _VectorOfMatCreate()

        $iArrD1Size = UBound($matD1)
        For $i = 0 To $iArrD1Size - 1
            _VectorOfMatPush($vectorOfMatD1, $matD1[$i])
        Next

        $iArrD1 = _cveInputArrayFromVectorOfMat($vectorOfMatD1)
    Else
        $iArrD1 = _cveInputArrayFromMat($matD1)
    EndIf

    Local $iArrK2, $vectorOfMatK2, $iArrK2Size
    Local $bK2IsArray = VarGetType($matK2) == "Array"

    If $bK2IsArray Then
        $vectorOfMatK2 = _VectorOfMatCreate()

        $iArrK2Size = UBound($matK2)
        For $i = 0 To $iArrK2Size - 1
            _VectorOfMatPush($vectorOfMatK2, $matK2[$i])
        Next

        $iArrK2 = _cveInputArrayFromVectorOfMat($vectorOfMatK2)
    Else
        $iArrK2 = _cveInputArrayFromMat($matK2)
    EndIf

    Local $iArrD2, $vectorOfMatD2, $iArrD2Size
    Local $bD2IsArray = VarGetType($matD2) == "Array"

    If $bD2IsArray Then
        $vectorOfMatD2 = _VectorOfMatCreate()

        $iArrD2Size = UBound($matD2)
        For $i = 0 To $iArrD2Size - 1
            _VectorOfMatPush($vectorOfMatD2, $matD2[$i])
        Next

        $iArrD2 = _cveInputArrayFromVectorOfMat($vectorOfMatD2)
    Else
        $iArrD2 = _cveInputArrayFromMat($matD2)
    EndIf

    Local $iArrR, $vectorOfMatR, $iArrRSize
    Local $bRIsArray = VarGetType($matR) == "Array"

    If $bRIsArray Then
        $vectorOfMatR = _VectorOfMatCreate()

        $iArrRSize = UBound($matR)
        For $i = 0 To $iArrRSize - 1
            _VectorOfMatPush($vectorOfMatR, $matR[$i])
        Next

        $iArrR = _cveInputArrayFromVectorOfMat($vectorOfMatR)
    Else
        $iArrR = _cveInputArrayFromMat($matR)
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

    Local $oArrR1, $vectorOfMatR1, $iArrR1Size
    Local $bR1IsArray = VarGetType($matR1) == "Array"

    If $bR1IsArray Then
        $vectorOfMatR1 = _VectorOfMatCreate()

        $iArrR1Size = UBound($matR1)
        For $i = 0 To $iArrR1Size - 1
            _VectorOfMatPush($vectorOfMatR1, $matR1[$i])
        Next

        $oArrR1 = _cveOutputArrayFromVectorOfMat($vectorOfMatR1)
    Else
        $oArrR1 = _cveOutputArrayFromMat($matR1)
    EndIf

    Local $oArrR2, $vectorOfMatR2, $iArrR2Size
    Local $bR2IsArray = VarGetType($matR2) == "Array"

    If $bR2IsArray Then
        $vectorOfMatR2 = _VectorOfMatCreate()

        $iArrR2Size = UBound($matR2)
        For $i = 0 To $iArrR2Size - 1
            _VectorOfMatPush($vectorOfMatR2, $matR2[$i])
        Next

        $oArrR2 = _cveOutputArrayFromVectorOfMat($vectorOfMatR2)
    Else
        $oArrR2 = _cveOutputArrayFromMat($matR2)
    EndIf

    Local $oArrP1, $vectorOfMatP1, $iArrP1Size
    Local $bP1IsArray = VarGetType($matP1) == "Array"

    If $bP1IsArray Then
        $vectorOfMatP1 = _VectorOfMatCreate()

        $iArrP1Size = UBound($matP1)
        For $i = 0 To $iArrP1Size - 1
            _VectorOfMatPush($vectorOfMatP1, $matP1[$i])
        Next

        $oArrP1 = _cveOutputArrayFromVectorOfMat($vectorOfMatP1)
    Else
        $oArrP1 = _cveOutputArrayFromMat($matP1)
    EndIf

    Local $oArrP2, $vectorOfMatP2, $iArrP2Size
    Local $bP2IsArray = VarGetType($matP2) == "Array"

    If $bP2IsArray Then
        $vectorOfMatP2 = _VectorOfMatCreate()

        $iArrP2Size = UBound($matP2)
        For $i = 0 To $iArrP2Size - 1
            _VectorOfMatPush($vectorOfMatP2, $matP2[$i])
        Next

        $oArrP2 = _cveOutputArrayFromVectorOfMat($vectorOfMatP2)
    Else
        $oArrP2 = _cveOutputArrayFromMat($matP2)
    EndIf

    Local $oArrQ, $vectorOfMatQ, $iArrQSize
    Local $bQIsArray = VarGetType($matQ) == "Array"

    If $bQIsArray Then
        $vectorOfMatQ = _VectorOfMatCreate()

        $iArrQSize = UBound($matQ)
        For $i = 0 To $iArrQSize - 1
            _VectorOfMatPush($vectorOfMatQ, $matQ[$i])
        Next

        $oArrQ = _cveOutputArrayFromVectorOfMat($vectorOfMatQ)
    Else
        $oArrQ = _cveOutputArrayFromMat($matQ)
    EndIf

    _cveFisheyeStereoRectify($iArrK1, $iArrD1, $iArrK2, $iArrD2, $imageSize, $iArrR, $iArrTvec, $oArrR1, $oArrR2, $oArrP1, $oArrP2, $oArrQ, $flags, $newImageSize, $balance, $fovScale)

    If $bQIsArray Then
        _VectorOfMatRelease($vectorOfMatQ)
    EndIf

    _cveOutputArrayRelease($oArrQ)

    If $bP2IsArray Then
        _VectorOfMatRelease($vectorOfMatP2)
    EndIf

    _cveOutputArrayRelease($oArrP2)

    If $bP1IsArray Then
        _VectorOfMatRelease($vectorOfMatP1)
    EndIf

    _cveOutputArrayRelease($oArrP1)

    If $bR2IsArray Then
        _VectorOfMatRelease($vectorOfMatR2)
    EndIf

    _cveOutputArrayRelease($oArrR2)

    If $bR1IsArray Then
        _VectorOfMatRelease($vectorOfMatR1)
    EndIf

    _cveOutputArrayRelease($oArrR1)

    If $bTvecIsArray Then
        _VectorOfMatRelease($vectorOfMatTvec)
    EndIf

    _cveInputArrayRelease($iArrTvec)

    If $bRIsArray Then
        _VectorOfMatRelease($vectorOfMatR)
    EndIf

    _cveInputArrayRelease($iArrR)

    If $bD2IsArray Then
        _VectorOfMatRelease($vectorOfMatD2)
    EndIf

    _cveInputArrayRelease($iArrD2)

    If $bK2IsArray Then
        _VectorOfMatRelease($vectorOfMatK2)
    EndIf

    _cveInputArrayRelease($iArrK2)

    If $bD1IsArray Then
        _VectorOfMatRelease($vectorOfMatD1)
    EndIf

    _cveInputArrayRelease($iArrD1)

    If $bK1IsArray Then
        _VectorOfMatRelease($vectorOfMatK1)
    EndIf

    _cveInputArrayRelease($iArrK1)
EndFunc   ;==>_cveFisheyeStereoRectifyMat

Func _cveFisheyeCalibrate(ByRef $objectPoints, ByRef $imagePoints, ByRef $imageSize, ByRef $K, ByRef $D, ByRef $rvecs, ByRef $tvecs, $flags, ByRef $criteria)
    ; CVAPI(void) cveFisheyeCalibrate(cv::_InputArray* objectPoints, cv::_InputArray* imagePoints, CvSize* imageSize, cv::_InputOutputArray* K, cv::_InputOutputArray* D, cv::_OutputArray* rvecs, cv::_OutputArray* tvecs, int flags, CvTermCriteria* criteria);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFisheyeCalibrate", "ptr", $objectPoints, "ptr", $imagePoints, "struct*", $imageSize, "ptr", $K, "ptr", $D, "ptr", $rvecs, "ptr", $tvecs, "int", $flags, "struct*", $criteria), "cveFisheyeCalibrate", @error)
EndFunc   ;==>_cveFisheyeCalibrate

Func _cveFisheyeCalibrateMat(ByRef $matObjectPoints, ByRef $matImagePoints, ByRef $imageSize, ByRef $matK, ByRef $matD, ByRef $matRvecs, ByRef $matTvecs, $flags, ByRef $criteria)
    ; cveFisheyeCalibrate using cv::Mat instead of _*Array

    Local $iArrObjectPoints, $vectorOfMatObjectPoints, $iArrObjectPointsSize
    Local $bObjectPointsIsArray = VarGetType($matObjectPoints) == "Array"

    If $bObjectPointsIsArray Then
        $vectorOfMatObjectPoints = _VectorOfMatCreate()

        $iArrObjectPointsSize = UBound($matObjectPoints)
        For $i = 0 To $iArrObjectPointsSize - 1
            _VectorOfMatPush($vectorOfMatObjectPoints, $matObjectPoints[$i])
        Next

        $iArrObjectPoints = _cveInputArrayFromVectorOfMat($vectorOfMatObjectPoints)
    Else
        $iArrObjectPoints = _cveInputArrayFromMat($matObjectPoints)
    EndIf

    Local $iArrImagePoints, $vectorOfMatImagePoints, $iArrImagePointsSize
    Local $bImagePointsIsArray = VarGetType($matImagePoints) == "Array"

    If $bImagePointsIsArray Then
        $vectorOfMatImagePoints = _VectorOfMatCreate()

        $iArrImagePointsSize = UBound($matImagePoints)
        For $i = 0 To $iArrImagePointsSize - 1
            _VectorOfMatPush($vectorOfMatImagePoints, $matImagePoints[$i])
        Next

        $iArrImagePoints = _cveInputArrayFromVectorOfMat($vectorOfMatImagePoints)
    Else
        $iArrImagePoints = _cveInputArrayFromMat($matImagePoints)
    EndIf

    Local $ioArrK, $vectorOfMatK, $iArrKSize
    Local $bKIsArray = VarGetType($matK) == "Array"

    If $bKIsArray Then
        $vectorOfMatK = _VectorOfMatCreate()

        $iArrKSize = UBound($matK)
        For $i = 0 To $iArrKSize - 1
            _VectorOfMatPush($vectorOfMatK, $matK[$i])
        Next

        $ioArrK = _cveInputOutputArrayFromVectorOfMat($vectorOfMatK)
    Else
        $ioArrK = _cveInputOutputArrayFromMat($matK)
    EndIf

    Local $ioArrD, $vectorOfMatD, $iArrDSize
    Local $bDIsArray = VarGetType($matD) == "Array"

    If $bDIsArray Then
        $vectorOfMatD = _VectorOfMatCreate()

        $iArrDSize = UBound($matD)
        For $i = 0 To $iArrDSize - 1
            _VectorOfMatPush($vectorOfMatD, $matD[$i])
        Next

        $ioArrD = _cveInputOutputArrayFromVectorOfMat($vectorOfMatD)
    Else
        $ioArrD = _cveInputOutputArrayFromMat($matD)
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

    _cveFisheyeCalibrate($iArrObjectPoints, $iArrImagePoints, $imageSize, $ioArrK, $ioArrD, $oArrRvecs, $oArrTvecs, $flags, $criteria)

    If $bTvecsIsArray Then
        _VectorOfMatRelease($vectorOfMatTvecs)
    EndIf

    _cveOutputArrayRelease($oArrTvecs)

    If $bRvecsIsArray Then
        _VectorOfMatRelease($vectorOfMatRvecs)
    EndIf

    _cveOutputArrayRelease($oArrRvecs)

    If $bDIsArray Then
        _VectorOfMatRelease($vectorOfMatD)
    EndIf

    _cveInputOutputArrayRelease($ioArrD)

    If $bKIsArray Then
        _VectorOfMatRelease($vectorOfMatK)
    EndIf

    _cveInputOutputArrayRelease($ioArrK)

    If $bImagePointsIsArray Then
        _VectorOfMatRelease($vectorOfMatImagePoints)
    EndIf

    _cveInputArrayRelease($iArrImagePoints)

    If $bObjectPointsIsArray Then
        _VectorOfMatRelease($vectorOfMatObjectPoints)
    EndIf

    _cveInputArrayRelease($iArrObjectPoints)
EndFunc   ;==>_cveFisheyeCalibrateMat

Func _cveFisheyeStereoCalibrate(ByRef $objectPoints, ByRef $imagePoints1, ByRef $imagePoints2, ByRef $K1, ByRef $D1, ByRef $K2, ByRef $D2, ByRef $imageSize, ByRef $R, ByRef $T, $flags, ByRef $criteria)
    ; CVAPI(void) cveFisheyeStereoCalibrate(cv::_InputArray* objectPoints, cv::_InputArray* imagePoints1, cv::_InputArray* imagePoints2, cv::_InputOutputArray* K1, cv::_InputOutputArray* D1, cv::_InputOutputArray* K2, cv::_InputOutputArray* D2, CvSize* imageSize, cv::_OutputArray* R, cv::_OutputArray* T, int flags, CvTermCriteria* criteria);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFisheyeStereoCalibrate", "ptr", $objectPoints, "ptr", $imagePoints1, "ptr", $imagePoints2, "ptr", $K1, "ptr", $D1, "ptr", $K2, "ptr", $D2, "struct*", $imageSize, "ptr", $R, "ptr", $T, "int", $flags, "struct*", $criteria), "cveFisheyeStereoCalibrate", @error)
EndFunc   ;==>_cveFisheyeStereoCalibrate

Func _cveFisheyeStereoCalibrateMat(ByRef $matObjectPoints, ByRef $matImagePoints1, ByRef $matImagePoints2, ByRef $matK1, ByRef $matD1, ByRef $matK2, ByRef $matD2, ByRef $imageSize, ByRef $matR, ByRef $matT, $flags, ByRef $criteria)
    ; cveFisheyeStereoCalibrate using cv::Mat instead of _*Array

    Local $iArrObjectPoints, $vectorOfMatObjectPoints, $iArrObjectPointsSize
    Local $bObjectPointsIsArray = VarGetType($matObjectPoints) == "Array"

    If $bObjectPointsIsArray Then
        $vectorOfMatObjectPoints = _VectorOfMatCreate()

        $iArrObjectPointsSize = UBound($matObjectPoints)
        For $i = 0 To $iArrObjectPointsSize - 1
            _VectorOfMatPush($vectorOfMatObjectPoints, $matObjectPoints[$i])
        Next

        $iArrObjectPoints = _cveInputArrayFromVectorOfMat($vectorOfMatObjectPoints)
    Else
        $iArrObjectPoints = _cveInputArrayFromMat($matObjectPoints)
    EndIf

    Local $iArrImagePoints1, $vectorOfMatImagePoints1, $iArrImagePoints1Size
    Local $bImagePoints1IsArray = VarGetType($matImagePoints1) == "Array"

    If $bImagePoints1IsArray Then
        $vectorOfMatImagePoints1 = _VectorOfMatCreate()

        $iArrImagePoints1Size = UBound($matImagePoints1)
        For $i = 0 To $iArrImagePoints1Size - 1
            _VectorOfMatPush($vectorOfMatImagePoints1, $matImagePoints1[$i])
        Next

        $iArrImagePoints1 = _cveInputArrayFromVectorOfMat($vectorOfMatImagePoints1)
    Else
        $iArrImagePoints1 = _cveInputArrayFromMat($matImagePoints1)
    EndIf

    Local $iArrImagePoints2, $vectorOfMatImagePoints2, $iArrImagePoints2Size
    Local $bImagePoints2IsArray = VarGetType($matImagePoints2) == "Array"

    If $bImagePoints2IsArray Then
        $vectorOfMatImagePoints2 = _VectorOfMatCreate()

        $iArrImagePoints2Size = UBound($matImagePoints2)
        For $i = 0 To $iArrImagePoints2Size - 1
            _VectorOfMatPush($vectorOfMatImagePoints2, $matImagePoints2[$i])
        Next

        $iArrImagePoints2 = _cveInputArrayFromVectorOfMat($vectorOfMatImagePoints2)
    Else
        $iArrImagePoints2 = _cveInputArrayFromMat($matImagePoints2)
    EndIf

    Local $ioArrK1, $vectorOfMatK1, $iArrK1Size
    Local $bK1IsArray = VarGetType($matK1) == "Array"

    If $bK1IsArray Then
        $vectorOfMatK1 = _VectorOfMatCreate()

        $iArrK1Size = UBound($matK1)
        For $i = 0 To $iArrK1Size - 1
            _VectorOfMatPush($vectorOfMatK1, $matK1[$i])
        Next

        $ioArrK1 = _cveInputOutputArrayFromVectorOfMat($vectorOfMatK1)
    Else
        $ioArrK1 = _cveInputOutputArrayFromMat($matK1)
    EndIf

    Local $ioArrD1, $vectorOfMatD1, $iArrD1Size
    Local $bD1IsArray = VarGetType($matD1) == "Array"

    If $bD1IsArray Then
        $vectorOfMatD1 = _VectorOfMatCreate()

        $iArrD1Size = UBound($matD1)
        For $i = 0 To $iArrD1Size - 1
            _VectorOfMatPush($vectorOfMatD1, $matD1[$i])
        Next

        $ioArrD1 = _cveInputOutputArrayFromVectorOfMat($vectorOfMatD1)
    Else
        $ioArrD1 = _cveInputOutputArrayFromMat($matD1)
    EndIf

    Local $ioArrK2, $vectorOfMatK2, $iArrK2Size
    Local $bK2IsArray = VarGetType($matK2) == "Array"

    If $bK2IsArray Then
        $vectorOfMatK2 = _VectorOfMatCreate()

        $iArrK2Size = UBound($matK2)
        For $i = 0 To $iArrK2Size - 1
            _VectorOfMatPush($vectorOfMatK2, $matK2[$i])
        Next

        $ioArrK2 = _cveInputOutputArrayFromVectorOfMat($vectorOfMatK2)
    Else
        $ioArrK2 = _cveInputOutputArrayFromMat($matK2)
    EndIf

    Local $ioArrD2, $vectorOfMatD2, $iArrD2Size
    Local $bD2IsArray = VarGetType($matD2) == "Array"

    If $bD2IsArray Then
        $vectorOfMatD2 = _VectorOfMatCreate()

        $iArrD2Size = UBound($matD2)
        For $i = 0 To $iArrD2Size - 1
            _VectorOfMatPush($vectorOfMatD2, $matD2[$i])
        Next

        $ioArrD2 = _cveInputOutputArrayFromVectorOfMat($vectorOfMatD2)
    Else
        $ioArrD2 = _cveInputOutputArrayFromMat($matD2)
    EndIf

    Local $oArrR, $vectorOfMatR, $iArrRSize
    Local $bRIsArray = VarGetType($matR) == "Array"

    If $bRIsArray Then
        $vectorOfMatR = _VectorOfMatCreate()

        $iArrRSize = UBound($matR)
        For $i = 0 To $iArrRSize - 1
            _VectorOfMatPush($vectorOfMatR, $matR[$i])
        Next

        $oArrR = _cveOutputArrayFromVectorOfMat($vectorOfMatR)
    Else
        $oArrR = _cveOutputArrayFromMat($matR)
    EndIf

    Local $oArrT, $vectorOfMatT, $iArrTSize
    Local $bTIsArray = VarGetType($matT) == "Array"

    If $bTIsArray Then
        $vectorOfMatT = _VectorOfMatCreate()

        $iArrTSize = UBound($matT)
        For $i = 0 To $iArrTSize - 1
            _VectorOfMatPush($vectorOfMatT, $matT[$i])
        Next

        $oArrT = _cveOutputArrayFromVectorOfMat($vectorOfMatT)
    Else
        $oArrT = _cveOutputArrayFromMat($matT)
    EndIf

    _cveFisheyeStereoCalibrate($iArrObjectPoints, $iArrImagePoints1, $iArrImagePoints2, $ioArrK1, $ioArrD1, $ioArrK2, $ioArrD2, $imageSize, $oArrR, $oArrT, $flags, $criteria)

    If $bTIsArray Then
        _VectorOfMatRelease($vectorOfMatT)
    EndIf

    _cveOutputArrayRelease($oArrT)

    If $bRIsArray Then
        _VectorOfMatRelease($vectorOfMatR)
    EndIf

    _cveOutputArrayRelease($oArrR)

    If $bD2IsArray Then
        _VectorOfMatRelease($vectorOfMatD2)
    EndIf

    _cveInputOutputArrayRelease($ioArrD2)

    If $bK2IsArray Then
        _VectorOfMatRelease($vectorOfMatK2)
    EndIf

    _cveInputOutputArrayRelease($ioArrK2)

    If $bD1IsArray Then
        _VectorOfMatRelease($vectorOfMatD1)
    EndIf

    _cveInputOutputArrayRelease($ioArrD1)

    If $bK1IsArray Then
        _VectorOfMatRelease($vectorOfMatK1)
    EndIf

    _cveInputOutputArrayRelease($ioArrK1)

    If $bImagePoints2IsArray Then
        _VectorOfMatRelease($vectorOfMatImagePoints2)
    EndIf

    _cveInputArrayRelease($iArrImagePoints2)

    If $bImagePoints1IsArray Then
        _VectorOfMatRelease($vectorOfMatImagePoints1)
    EndIf

    _cveInputArrayRelease($iArrImagePoints1)

    If $bObjectPointsIsArray Then
        _VectorOfMatRelease($vectorOfMatObjectPoints)
    EndIf

    _cveInputArrayRelease($iArrObjectPoints)
EndFunc   ;==>_cveFisheyeStereoCalibrateMat

Func _cveInitUndistortRectifyMap(ByRef $cameraMatrix, ByRef $distCoeffs, ByRef $r, ByRef $newCameraMatrix, ByRef $size, $m1type, ByRef $map1, ByRef $map2)
    ; CVAPI(void) cveInitUndistortRectifyMap(cv::_InputArray* cameraMatrix, cv::_InputArray* distCoeffs, cv::_InputArray* r, cv::_InputArray* newCameraMatrix, CvSize* size, int m1type, cv::_OutputArray* map1, cv::_OutputArray* map2);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveInitUndistortRectifyMap", "ptr", $cameraMatrix, "ptr", $distCoeffs, "ptr", $r, "ptr", $newCameraMatrix, "struct*", $size, "int", $m1type, "ptr", $map1, "ptr", $map2), "cveInitUndistortRectifyMap", @error)
EndFunc   ;==>_cveInitUndistortRectifyMap

Func _cveInitUndistortRectifyMapMat(ByRef $matCameraMatrix, ByRef $matDistCoeffs, ByRef $matR, ByRef $matNewCameraMatrix, ByRef $size, $m1type, ByRef $matMap1, ByRef $matMap2)
    ; cveInitUndistortRectifyMap using cv::Mat instead of _*Array

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

    Local $iArrR, $vectorOfMatR, $iArrRSize
    Local $bRIsArray = VarGetType($matR) == "Array"

    If $bRIsArray Then
        $vectorOfMatR = _VectorOfMatCreate()

        $iArrRSize = UBound($matR)
        For $i = 0 To $iArrRSize - 1
            _VectorOfMatPush($vectorOfMatR, $matR[$i])
        Next

        $iArrR = _cveInputArrayFromVectorOfMat($vectorOfMatR)
    Else
        $iArrR = _cveInputArrayFromMat($matR)
    EndIf

    Local $iArrNewCameraMatrix, $vectorOfMatNewCameraMatrix, $iArrNewCameraMatrixSize
    Local $bNewCameraMatrixIsArray = VarGetType($matNewCameraMatrix) == "Array"

    If $bNewCameraMatrixIsArray Then
        $vectorOfMatNewCameraMatrix = _VectorOfMatCreate()

        $iArrNewCameraMatrixSize = UBound($matNewCameraMatrix)
        For $i = 0 To $iArrNewCameraMatrixSize - 1
            _VectorOfMatPush($vectorOfMatNewCameraMatrix, $matNewCameraMatrix[$i])
        Next

        $iArrNewCameraMatrix = _cveInputArrayFromVectorOfMat($vectorOfMatNewCameraMatrix)
    Else
        $iArrNewCameraMatrix = _cveInputArrayFromMat($matNewCameraMatrix)
    EndIf

    Local $oArrMap1, $vectorOfMatMap1, $iArrMap1Size
    Local $bMap1IsArray = VarGetType($matMap1) == "Array"

    If $bMap1IsArray Then
        $vectorOfMatMap1 = _VectorOfMatCreate()

        $iArrMap1Size = UBound($matMap1)
        For $i = 0 To $iArrMap1Size - 1
            _VectorOfMatPush($vectorOfMatMap1, $matMap1[$i])
        Next

        $oArrMap1 = _cveOutputArrayFromVectorOfMat($vectorOfMatMap1)
    Else
        $oArrMap1 = _cveOutputArrayFromMat($matMap1)
    EndIf

    Local $oArrMap2, $vectorOfMatMap2, $iArrMap2Size
    Local $bMap2IsArray = VarGetType($matMap2) == "Array"

    If $bMap2IsArray Then
        $vectorOfMatMap2 = _VectorOfMatCreate()

        $iArrMap2Size = UBound($matMap2)
        For $i = 0 To $iArrMap2Size - 1
            _VectorOfMatPush($vectorOfMatMap2, $matMap2[$i])
        Next

        $oArrMap2 = _cveOutputArrayFromVectorOfMat($vectorOfMatMap2)
    Else
        $oArrMap2 = _cveOutputArrayFromMat($matMap2)
    EndIf

    _cveInitUndistortRectifyMap($iArrCameraMatrix, $iArrDistCoeffs, $iArrR, $iArrNewCameraMatrix, $size, $m1type, $oArrMap1, $oArrMap2)

    If $bMap2IsArray Then
        _VectorOfMatRelease($vectorOfMatMap2)
    EndIf

    _cveOutputArrayRelease($oArrMap2)

    If $bMap1IsArray Then
        _VectorOfMatRelease($vectorOfMatMap1)
    EndIf

    _cveOutputArrayRelease($oArrMap1)

    If $bNewCameraMatrixIsArray Then
        _VectorOfMatRelease($vectorOfMatNewCameraMatrix)
    EndIf

    _cveInputArrayRelease($iArrNewCameraMatrix)

    If $bRIsArray Then
        _VectorOfMatRelease($vectorOfMatR)
    EndIf

    _cveInputArrayRelease($iArrR)

    If $bDistCoeffsIsArray Then
        _VectorOfMatRelease($vectorOfMatDistCoeffs)
    EndIf

    _cveInputArrayRelease($iArrDistCoeffs)

    If $bCameraMatrixIsArray Then
        _VectorOfMatRelease($vectorOfMatCameraMatrix)
    EndIf

    _cveInputArrayRelease($iArrCameraMatrix)
EndFunc   ;==>_cveInitUndistortRectifyMapMat

Func _cveUndistort(ByRef $src, ByRef $dst, ByRef $cameraMatrix, ByRef $distorCoeffs, ByRef $newCameraMatrix)
    ; CVAPI(void) cveUndistort(cv::_InputArray* src, cv::_OutputArray* dst, cv::_InputArray* cameraMatrix, cv::_InputArray* distorCoeffs, cv::_InputArray* newCameraMatrix);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveUndistort", "ptr", $src, "ptr", $dst, "ptr", $cameraMatrix, "ptr", $distorCoeffs, "ptr", $newCameraMatrix), "cveUndistort", @error)
EndFunc   ;==>_cveUndistort

Func _cveUndistortMat(ByRef $matSrc, ByRef $matDst, ByRef $matCameraMatrix, ByRef $matDistorCoeffs, ByRef $matNewCameraMatrix)
    ; cveUndistort using cv::Mat instead of _*Array

    Local $iArrSrc, $vectorOfMatSrc, $iArrSrcSize
    Local $bSrcIsArray = VarGetType($matSrc) == "Array"

    If $bSrcIsArray Then
        $vectorOfMatSrc = _VectorOfMatCreate()

        $iArrSrcSize = UBound($matSrc)
        For $i = 0 To $iArrSrcSize - 1
            _VectorOfMatPush($vectorOfMatSrc, $matSrc[$i])
        Next

        $iArrSrc = _cveInputArrayFromVectorOfMat($vectorOfMatSrc)
    Else
        $iArrSrc = _cveInputArrayFromMat($matSrc)
    EndIf

    Local $oArrDst, $vectorOfMatDst, $iArrDstSize
    Local $bDstIsArray = VarGetType($matDst) == "Array"

    If $bDstIsArray Then
        $vectorOfMatDst = _VectorOfMatCreate()

        $iArrDstSize = UBound($matDst)
        For $i = 0 To $iArrDstSize - 1
            _VectorOfMatPush($vectorOfMatDst, $matDst[$i])
        Next

        $oArrDst = _cveOutputArrayFromVectorOfMat($vectorOfMatDst)
    Else
        $oArrDst = _cveOutputArrayFromMat($matDst)
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

    Local $iArrDistorCoeffs, $vectorOfMatDistorCoeffs, $iArrDistorCoeffsSize
    Local $bDistorCoeffsIsArray = VarGetType($matDistorCoeffs) == "Array"

    If $bDistorCoeffsIsArray Then
        $vectorOfMatDistorCoeffs = _VectorOfMatCreate()

        $iArrDistorCoeffsSize = UBound($matDistorCoeffs)
        For $i = 0 To $iArrDistorCoeffsSize - 1
            _VectorOfMatPush($vectorOfMatDistorCoeffs, $matDistorCoeffs[$i])
        Next

        $iArrDistorCoeffs = _cveInputArrayFromVectorOfMat($vectorOfMatDistorCoeffs)
    Else
        $iArrDistorCoeffs = _cveInputArrayFromMat($matDistorCoeffs)
    EndIf

    Local $iArrNewCameraMatrix, $vectorOfMatNewCameraMatrix, $iArrNewCameraMatrixSize
    Local $bNewCameraMatrixIsArray = VarGetType($matNewCameraMatrix) == "Array"

    If $bNewCameraMatrixIsArray Then
        $vectorOfMatNewCameraMatrix = _VectorOfMatCreate()

        $iArrNewCameraMatrixSize = UBound($matNewCameraMatrix)
        For $i = 0 To $iArrNewCameraMatrixSize - 1
            _VectorOfMatPush($vectorOfMatNewCameraMatrix, $matNewCameraMatrix[$i])
        Next

        $iArrNewCameraMatrix = _cveInputArrayFromVectorOfMat($vectorOfMatNewCameraMatrix)
    Else
        $iArrNewCameraMatrix = _cveInputArrayFromMat($matNewCameraMatrix)
    EndIf

    _cveUndistort($iArrSrc, $oArrDst, $iArrCameraMatrix, $iArrDistorCoeffs, $iArrNewCameraMatrix)

    If $bNewCameraMatrixIsArray Then
        _VectorOfMatRelease($vectorOfMatNewCameraMatrix)
    EndIf

    _cveInputArrayRelease($iArrNewCameraMatrix)

    If $bDistorCoeffsIsArray Then
        _VectorOfMatRelease($vectorOfMatDistorCoeffs)
    EndIf

    _cveInputArrayRelease($iArrDistorCoeffs)

    If $bCameraMatrixIsArray Then
        _VectorOfMatRelease($vectorOfMatCameraMatrix)
    EndIf

    _cveInputArrayRelease($iArrCameraMatrix)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveOutputArrayRelease($oArrDst)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)
EndFunc   ;==>_cveUndistortMat

Func _cveUndistortPoints(ByRef $src, ByRef $dst, ByRef $cameraMatrix, ByRef $distCoeffs, ByRef $r, ByRef $p)
    ; CVAPI(void) cveUndistortPoints(cv::_InputArray* src, cv::_OutputArray* dst, cv::_InputArray* cameraMatrix, cv::_InputArray* distCoeffs, cv::_InputArray* r, cv::_InputArray* p);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveUndistortPoints", "ptr", $src, "ptr", $dst, "ptr", $cameraMatrix, "ptr", $distCoeffs, "ptr", $r, "ptr", $p), "cveUndistortPoints", @error)
EndFunc   ;==>_cveUndistortPoints

Func _cveUndistortPointsMat(ByRef $matSrc, ByRef $matDst, ByRef $matCameraMatrix, ByRef $matDistCoeffs, ByRef $matR, ByRef $matP)
    ; cveUndistortPoints using cv::Mat instead of _*Array

    Local $iArrSrc, $vectorOfMatSrc, $iArrSrcSize
    Local $bSrcIsArray = VarGetType($matSrc) == "Array"

    If $bSrcIsArray Then
        $vectorOfMatSrc = _VectorOfMatCreate()

        $iArrSrcSize = UBound($matSrc)
        For $i = 0 To $iArrSrcSize - 1
            _VectorOfMatPush($vectorOfMatSrc, $matSrc[$i])
        Next

        $iArrSrc = _cveInputArrayFromVectorOfMat($vectorOfMatSrc)
    Else
        $iArrSrc = _cveInputArrayFromMat($matSrc)
    EndIf

    Local $oArrDst, $vectorOfMatDst, $iArrDstSize
    Local $bDstIsArray = VarGetType($matDst) == "Array"

    If $bDstIsArray Then
        $vectorOfMatDst = _VectorOfMatCreate()

        $iArrDstSize = UBound($matDst)
        For $i = 0 To $iArrDstSize - 1
            _VectorOfMatPush($vectorOfMatDst, $matDst[$i])
        Next

        $oArrDst = _cveOutputArrayFromVectorOfMat($vectorOfMatDst)
    Else
        $oArrDst = _cveOutputArrayFromMat($matDst)
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

    Local $iArrR, $vectorOfMatR, $iArrRSize
    Local $bRIsArray = VarGetType($matR) == "Array"

    If $bRIsArray Then
        $vectorOfMatR = _VectorOfMatCreate()

        $iArrRSize = UBound($matR)
        For $i = 0 To $iArrRSize - 1
            _VectorOfMatPush($vectorOfMatR, $matR[$i])
        Next

        $iArrR = _cveInputArrayFromVectorOfMat($vectorOfMatR)
    Else
        $iArrR = _cveInputArrayFromMat($matR)
    EndIf

    Local $iArrP, $vectorOfMatP, $iArrPSize
    Local $bPIsArray = VarGetType($matP) == "Array"

    If $bPIsArray Then
        $vectorOfMatP = _VectorOfMatCreate()

        $iArrPSize = UBound($matP)
        For $i = 0 To $iArrPSize - 1
            _VectorOfMatPush($vectorOfMatP, $matP[$i])
        Next

        $iArrP = _cveInputArrayFromVectorOfMat($vectorOfMatP)
    Else
        $iArrP = _cveInputArrayFromMat($matP)
    EndIf

    _cveUndistortPoints($iArrSrc, $oArrDst, $iArrCameraMatrix, $iArrDistCoeffs, $iArrR, $iArrP)

    If $bPIsArray Then
        _VectorOfMatRelease($vectorOfMatP)
    EndIf

    _cveInputArrayRelease($iArrP)

    If $bRIsArray Then
        _VectorOfMatRelease($vectorOfMatR)
    EndIf

    _cveInputArrayRelease($iArrR)

    If $bDistCoeffsIsArray Then
        _VectorOfMatRelease($vectorOfMatDistCoeffs)
    EndIf

    _cveInputArrayRelease($iArrDistCoeffs)

    If $bCameraMatrixIsArray Then
        _VectorOfMatRelease($vectorOfMatCameraMatrix)
    EndIf

    _cveInputArrayRelease($iArrCameraMatrix)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveOutputArrayRelease($oArrDst)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)
EndFunc   ;==>_cveUndistortPointsMat

Func _cveGetDefaultNewCameraMatrix(ByRef $cameraMatrix, ByRef $imgsize, $centerPrincipalPoint, ByRef $cm)
    ; CVAPI(void) cveGetDefaultNewCameraMatrix(cv::_InputArray* cameraMatrix, CvSize* imgsize, bool centerPrincipalPoint, cv::Mat* cm);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveGetDefaultNewCameraMatrix", "ptr", $cameraMatrix, "struct*", $imgsize, "boolean", $centerPrincipalPoint, "ptr", $cm), "cveGetDefaultNewCameraMatrix", @error)
EndFunc   ;==>_cveGetDefaultNewCameraMatrix

Func _cveGetDefaultNewCameraMatrixMat(ByRef $matCameraMatrix, ByRef $imgsize, $centerPrincipalPoint, ByRef $cm)
    ; cveGetDefaultNewCameraMatrix using cv::Mat instead of _*Array

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

    _cveGetDefaultNewCameraMatrix($iArrCameraMatrix, $imgsize, $centerPrincipalPoint, $cm)

    If $bCameraMatrixIsArray Then
        _VectorOfMatRelease($vectorOfMatCameraMatrix)
    EndIf

    _cveInputArrayRelease($iArrCameraMatrix)
EndFunc   ;==>_cveGetDefaultNewCameraMatrixMat

Func _cveEstimateAffine2D(ByRef $from, ByRef $to, ByRef $inliers, $method, $ransacReprojThreshold, $maxIters, $confidence, $refineIters, ByRef $affine)
    ; CVAPI(void) cveEstimateAffine2D(cv::_InputArray* from, cv::_InputArray* to, cv::_OutputArray* inliers, int method, double ransacReprojThreshold, int maxIters, double confidence, int refineIters, cv::Mat* affine);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveEstimateAffine2D", "ptr", $from, "ptr", $to, "ptr", $inliers, "int", $method, "double", $ransacReprojThreshold, "int", $maxIters, "double", $confidence, "int", $refineIters, "ptr", $affine), "cveEstimateAffine2D", @error)
EndFunc   ;==>_cveEstimateAffine2D

Func _cveEstimateAffine2DMat(ByRef $matFrom, ByRef $matTo, ByRef $matInliers, $method, $ransacReprojThreshold, $maxIters, $confidence, $refineIters, ByRef $affine)
    ; cveEstimateAffine2D using cv::Mat instead of _*Array

    Local $iArrFrom, $vectorOfMatFrom, $iArrFromSize
    Local $bFromIsArray = VarGetType($matFrom) == "Array"

    If $bFromIsArray Then
        $vectorOfMatFrom = _VectorOfMatCreate()

        $iArrFromSize = UBound($matFrom)
        For $i = 0 To $iArrFromSize - 1
            _VectorOfMatPush($vectorOfMatFrom, $matFrom[$i])
        Next

        $iArrFrom = _cveInputArrayFromVectorOfMat($vectorOfMatFrom)
    Else
        $iArrFrom = _cveInputArrayFromMat($matFrom)
    EndIf

    Local $iArrTo, $vectorOfMatTo, $iArrToSize
    Local $bToIsArray = VarGetType($matTo) == "Array"

    If $bToIsArray Then
        $vectorOfMatTo = _VectorOfMatCreate()

        $iArrToSize = UBound($matTo)
        For $i = 0 To $iArrToSize - 1
            _VectorOfMatPush($vectorOfMatTo, $matTo[$i])
        Next

        $iArrTo = _cveInputArrayFromVectorOfMat($vectorOfMatTo)
    Else
        $iArrTo = _cveInputArrayFromMat($matTo)
    EndIf

    Local $oArrInliers, $vectorOfMatInliers, $iArrInliersSize
    Local $bInliersIsArray = VarGetType($matInliers) == "Array"

    If $bInliersIsArray Then
        $vectorOfMatInliers = _VectorOfMatCreate()

        $iArrInliersSize = UBound($matInliers)
        For $i = 0 To $iArrInliersSize - 1
            _VectorOfMatPush($vectorOfMatInliers, $matInliers[$i])
        Next

        $oArrInliers = _cveOutputArrayFromVectorOfMat($vectorOfMatInliers)
    Else
        $oArrInliers = _cveOutputArrayFromMat($matInliers)
    EndIf

    _cveEstimateAffine2D($iArrFrom, $iArrTo, $oArrInliers, $method, $ransacReprojThreshold, $maxIters, $confidence, $refineIters, $affine)

    If $bInliersIsArray Then
        _VectorOfMatRelease($vectorOfMatInliers)
    EndIf

    _cveOutputArrayRelease($oArrInliers)

    If $bToIsArray Then
        _VectorOfMatRelease($vectorOfMatTo)
    EndIf

    _cveInputArrayRelease($iArrTo)

    If $bFromIsArray Then
        _VectorOfMatRelease($vectorOfMatFrom)
    EndIf

    _cveInputArrayRelease($iArrFrom)
EndFunc   ;==>_cveEstimateAffine2DMat

Func _cveEstimateAffinePartial2D(ByRef $from, ByRef $to, ByRef $inliers, $method, $ransacReprojThreshold, $maxIters, $confidence, $refineIters, ByRef $affine)
    ; CVAPI(void) cveEstimateAffinePartial2D(cv::_InputArray* from, cv::_InputArray* to, cv::_OutputArray* inliers, int method, double ransacReprojThreshold, int maxIters, double confidence, int refineIters, cv::Mat* affine);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveEstimateAffinePartial2D", "ptr", $from, "ptr", $to, "ptr", $inliers, "int", $method, "double", $ransacReprojThreshold, "int", $maxIters, "double", $confidence, "int", $refineIters, "ptr", $affine), "cveEstimateAffinePartial2D", @error)
EndFunc   ;==>_cveEstimateAffinePartial2D

Func _cveEstimateAffinePartial2DMat(ByRef $matFrom, ByRef $matTo, ByRef $matInliers, $method, $ransacReprojThreshold, $maxIters, $confidence, $refineIters, ByRef $affine)
    ; cveEstimateAffinePartial2D using cv::Mat instead of _*Array

    Local $iArrFrom, $vectorOfMatFrom, $iArrFromSize
    Local $bFromIsArray = VarGetType($matFrom) == "Array"

    If $bFromIsArray Then
        $vectorOfMatFrom = _VectorOfMatCreate()

        $iArrFromSize = UBound($matFrom)
        For $i = 0 To $iArrFromSize - 1
            _VectorOfMatPush($vectorOfMatFrom, $matFrom[$i])
        Next

        $iArrFrom = _cveInputArrayFromVectorOfMat($vectorOfMatFrom)
    Else
        $iArrFrom = _cveInputArrayFromMat($matFrom)
    EndIf

    Local $iArrTo, $vectorOfMatTo, $iArrToSize
    Local $bToIsArray = VarGetType($matTo) == "Array"

    If $bToIsArray Then
        $vectorOfMatTo = _VectorOfMatCreate()

        $iArrToSize = UBound($matTo)
        For $i = 0 To $iArrToSize - 1
            _VectorOfMatPush($vectorOfMatTo, $matTo[$i])
        Next

        $iArrTo = _cveInputArrayFromVectorOfMat($vectorOfMatTo)
    Else
        $iArrTo = _cveInputArrayFromMat($matTo)
    EndIf

    Local $oArrInliers, $vectorOfMatInliers, $iArrInliersSize
    Local $bInliersIsArray = VarGetType($matInliers) == "Array"

    If $bInliersIsArray Then
        $vectorOfMatInliers = _VectorOfMatCreate()

        $iArrInliersSize = UBound($matInliers)
        For $i = 0 To $iArrInliersSize - 1
            _VectorOfMatPush($vectorOfMatInliers, $matInliers[$i])
        Next

        $oArrInliers = _cveOutputArrayFromVectorOfMat($vectorOfMatInliers)
    Else
        $oArrInliers = _cveOutputArrayFromMat($matInliers)
    EndIf

    _cveEstimateAffinePartial2D($iArrFrom, $iArrTo, $oArrInliers, $method, $ransacReprojThreshold, $maxIters, $confidence, $refineIters, $affine)

    If $bInliersIsArray Then
        _VectorOfMatRelease($vectorOfMatInliers)
    EndIf

    _cveOutputArrayRelease($oArrInliers)

    If $bToIsArray Then
        _VectorOfMatRelease($vectorOfMatTo)
    EndIf

    _cveInputArrayRelease($iArrTo)

    If $bFromIsArray Then
        _VectorOfMatRelease($vectorOfMatFrom)
    EndIf

    _cveInputArrayRelease($iArrFrom)
EndFunc   ;==>_cveEstimateAffinePartial2DMat

Func _cveCalibrateHandEye(ByRef $R_gripper2base, ByRef $t_gripper2base, ByRef $R_target2cam, ByRef $t_target2cam, ByRef $R_cam2gripper, ByRef $t_cam2gripper, $method)
    ; CVAPI(void) cveCalibrateHandEye(cv::_InputArray* R_gripper2base, cv::_InputArray* t_gripper2base, cv::_InputArray* R_target2cam, cv::_InputArray* t_target2cam, cv::_OutputArray* R_cam2gripper, cv::_OutputArray* t_cam2gripper, int method);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCalibrateHandEye", "ptr", $R_gripper2base, "ptr", $t_gripper2base, "ptr", $R_target2cam, "ptr", $t_target2cam, "ptr", $R_cam2gripper, "ptr", $t_cam2gripper, "int", $method), "cveCalibrateHandEye", @error)
EndFunc   ;==>_cveCalibrateHandEye

Func _cveCalibrateHandEyeMat(ByRef $matR_gripper2base, ByRef $matT_gripper2base, ByRef $matR_target2cam, ByRef $matT_target2cam, ByRef $matR_cam2gripper, ByRef $matT_cam2gripper, $method)
    ; cveCalibrateHandEye using cv::Mat instead of _*Array

    Local $iArrR_gripper2base, $vectorOfMatR_gripper2base, $iArrR_gripper2baseSize
    Local $bR_gripper2baseIsArray = VarGetType($matR_gripper2base) == "Array"

    If $bR_gripper2baseIsArray Then
        $vectorOfMatR_gripper2base = _VectorOfMatCreate()

        $iArrR_gripper2baseSize = UBound($matR_gripper2base)
        For $i = 0 To $iArrR_gripper2baseSize - 1
            _VectorOfMatPush($vectorOfMatR_gripper2base, $matR_gripper2base[$i])
        Next

        $iArrR_gripper2base = _cveInputArrayFromVectorOfMat($vectorOfMatR_gripper2base)
    Else
        $iArrR_gripper2base = _cveInputArrayFromMat($matR_gripper2base)
    EndIf

    Local $iArrT_gripper2base, $vectorOfMatT_gripper2base, $iArrT_gripper2baseSize
    Local $bT_gripper2baseIsArray = VarGetType($matT_gripper2base) == "Array"

    If $bT_gripper2baseIsArray Then
        $vectorOfMatT_gripper2base = _VectorOfMatCreate()

        $iArrT_gripper2baseSize = UBound($matT_gripper2base)
        For $i = 0 To $iArrT_gripper2baseSize - 1
            _VectorOfMatPush($vectorOfMatT_gripper2base, $matT_gripper2base[$i])
        Next

        $iArrT_gripper2base = _cveInputArrayFromVectorOfMat($vectorOfMatT_gripper2base)
    Else
        $iArrT_gripper2base = _cveInputArrayFromMat($matT_gripper2base)
    EndIf

    Local $iArrR_target2cam, $vectorOfMatR_target2cam, $iArrR_target2camSize
    Local $bR_target2camIsArray = VarGetType($matR_target2cam) == "Array"

    If $bR_target2camIsArray Then
        $vectorOfMatR_target2cam = _VectorOfMatCreate()

        $iArrR_target2camSize = UBound($matR_target2cam)
        For $i = 0 To $iArrR_target2camSize - 1
            _VectorOfMatPush($vectorOfMatR_target2cam, $matR_target2cam[$i])
        Next

        $iArrR_target2cam = _cveInputArrayFromVectorOfMat($vectorOfMatR_target2cam)
    Else
        $iArrR_target2cam = _cveInputArrayFromMat($matR_target2cam)
    EndIf

    Local $iArrT_target2cam, $vectorOfMatT_target2cam, $iArrT_target2camSize
    Local $bT_target2camIsArray = VarGetType($matT_target2cam) == "Array"

    If $bT_target2camIsArray Then
        $vectorOfMatT_target2cam = _VectorOfMatCreate()

        $iArrT_target2camSize = UBound($matT_target2cam)
        For $i = 0 To $iArrT_target2camSize - 1
            _VectorOfMatPush($vectorOfMatT_target2cam, $matT_target2cam[$i])
        Next

        $iArrT_target2cam = _cveInputArrayFromVectorOfMat($vectorOfMatT_target2cam)
    Else
        $iArrT_target2cam = _cveInputArrayFromMat($matT_target2cam)
    EndIf

    Local $oArrR_cam2gripper, $vectorOfMatR_cam2gripper, $iArrR_cam2gripperSize
    Local $bR_cam2gripperIsArray = VarGetType($matR_cam2gripper) == "Array"

    If $bR_cam2gripperIsArray Then
        $vectorOfMatR_cam2gripper = _VectorOfMatCreate()

        $iArrR_cam2gripperSize = UBound($matR_cam2gripper)
        For $i = 0 To $iArrR_cam2gripperSize - 1
            _VectorOfMatPush($vectorOfMatR_cam2gripper, $matR_cam2gripper[$i])
        Next

        $oArrR_cam2gripper = _cveOutputArrayFromVectorOfMat($vectorOfMatR_cam2gripper)
    Else
        $oArrR_cam2gripper = _cveOutputArrayFromMat($matR_cam2gripper)
    EndIf

    Local $oArrT_cam2gripper, $vectorOfMatT_cam2gripper, $iArrT_cam2gripperSize
    Local $bT_cam2gripperIsArray = VarGetType($matT_cam2gripper) == "Array"

    If $bT_cam2gripperIsArray Then
        $vectorOfMatT_cam2gripper = _VectorOfMatCreate()

        $iArrT_cam2gripperSize = UBound($matT_cam2gripper)
        For $i = 0 To $iArrT_cam2gripperSize - 1
            _VectorOfMatPush($vectorOfMatT_cam2gripper, $matT_cam2gripper[$i])
        Next

        $oArrT_cam2gripper = _cveOutputArrayFromVectorOfMat($vectorOfMatT_cam2gripper)
    Else
        $oArrT_cam2gripper = _cveOutputArrayFromMat($matT_cam2gripper)
    EndIf

    _cveCalibrateHandEye($iArrR_gripper2base, $iArrT_gripper2base, $iArrR_target2cam, $iArrT_target2cam, $oArrR_cam2gripper, $oArrT_cam2gripper, $method)

    If $bT_cam2gripperIsArray Then
        _VectorOfMatRelease($vectorOfMatT_cam2gripper)
    EndIf

    _cveOutputArrayRelease($oArrT_cam2gripper)

    If $bR_cam2gripperIsArray Then
        _VectorOfMatRelease($vectorOfMatR_cam2gripper)
    EndIf

    _cveOutputArrayRelease($oArrR_cam2gripper)

    If $bT_target2camIsArray Then
        _VectorOfMatRelease($vectorOfMatT_target2cam)
    EndIf

    _cveInputArrayRelease($iArrT_target2cam)

    If $bR_target2camIsArray Then
        _VectorOfMatRelease($vectorOfMatR_target2cam)
    EndIf

    _cveInputArrayRelease($iArrR_target2cam)

    If $bT_gripper2baseIsArray Then
        _VectorOfMatRelease($vectorOfMatT_gripper2base)
    EndIf

    _cveInputArrayRelease($iArrT_gripper2base)

    If $bR_gripper2baseIsArray Then
        _VectorOfMatRelease($vectorOfMatR_gripper2base)
    EndIf

    _cveInputArrayRelease($iArrR_gripper2base)
EndFunc   ;==>_cveCalibrateHandEyeMat

Func _cveRQDecomp3x3(ByRef $src, ByRef $out, ByRef $mtxR, ByRef $mtxQ, ByRef $Qx, ByRef $Qy, ByRef $Qz)
    ; CVAPI(void) cveRQDecomp3x3(cv::_InputArray* src, CvPoint3D64f* out, cv::_OutputArray* mtxR, cv::_OutputArray* mtxQ, cv::_OutputArray* Qx, cv::_OutputArray* Qy, cv::_OutputArray* Qz);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveRQDecomp3x3", "ptr", $src, "struct*", $out, "ptr", $mtxR, "ptr", $mtxQ, "ptr", $Qx, "ptr", $Qy, "ptr", $Qz), "cveRQDecomp3x3", @error)
EndFunc   ;==>_cveRQDecomp3x3

Func _cveRQDecomp3x3Mat(ByRef $matSrc, ByRef $out, ByRef $matMtxR, ByRef $matMtxQ, ByRef $matQx, ByRef $matQy, ByRef $matQz)
    ; cveRQDecomp3x3 using cv::Mat instead of _*Array

    Local $iArrSrc, $vectorOfMatSrc, $iArrSrcSize
    Local $bSrcIsArray = VarGetType($matSrc) == "Array"

    If $bSrcIsArray Then
        $vectorOfMatSrc = _VectorOfMatCreate()

        $iArrSrcSize = UBound($matSrc)
        For $i = 0 To $iArrSrcSize - 1
            _VectorOfMatPush($vectorOfMatSrc, $matSrc[$i])
        Next

        $iArrSrc = _cveInputArrayFromVectorOfMat($vectorOfMatSrc)
    Else
        $iArrSrc = _cveInputArrayFromMat($matSrc)
    EndIf

    Local $oArrMtxR, $vectorOfMatMtxR, $iArrMtxRSize
    Local $bMtxRIsArray = VarGetType($matMtxR) == "Array"

    If $bMtxRIsArray Then
        $vectorOfMatMtxR = _VectorOfMatCreate()

        $iArrMtxRSize = UBound($matMtxR)
        For $i = 0 To $iArrMtxRSize - 1
            _VectorOfMatPush($vectorOfMatMtxR, $matMtxR[$i])
        Next

        $oArrMtxR = _cveOutputArrayFromVectorOfMat($vectorOfMatMtxR)
    Else
        $oArrMtxR = _cveOutputArrayFromMat($matMtxR)
    EndIf

    Local $oArrMtxQ, $vectorOfMatMtxQ, $iArrMtxQSize
    Local $bMtxQIsArray = VarGetType($matMtxQ) == "Array"

    If $bMtxQIsArray Then
        $vectorOfMatMtxQ = _VectorOfMatCreate()

        $iArrMtxQSize = UBound($matMtxQ)
        For $i = 0 To $iArrMtxQSize - 1
            _VectorOfMatPush($vectorOfMatMtxQ, $matMtxQ[$i])
        Next

        $oArrMtxQ = _cveOutputArrayFromVectorOfMat($vectorOfMatMtxQ)
    Else
        $oArrMtxQ = _cveOutputArrayFromMat($matMtxQ)
    EndIf

    Local $oArrQx, $vectorOfMatQx, $iArrQxSize
    Local $bQxIsArray = VarGetType($matQx) == "Array"

    If $bQxIsArray Then
        $vectorOfMatQx = _VectorOfMatCreate()

        $iArrQxSize = UBound($matQx)
        For $i = 0 To $iArrQxSize - 1
            _VectorOfMatPush($vectorOfMatQx, $matQx[$i])
        Next

        $oArrQx = _cveOutputArrayFromVectorOfMat($vectorOfMatQx)
    Else
        $oArrQx = _cveOutputArrayFromMat($matQx)
    EndIf

    Local $oArrQy, $vectorOfMatQy, $iArrQySize
    Local $bQyIsArray = VarGetType($matQy) == "Array"

    If $bQyIsArray Then
        $vectorOfMatQy = _VectorOfMatCreate()

        $iArrQySize = UBound($matQy)
        For $i = 0 To $iArrQySize - 1
            _VectorOfMatPush($vectorOfMatQy, $matQy[$i])
        Next

        $oArrQy = _cveOutputArrayFromVectorOfMat($vectorOfMatQy)
    Else
        $oArrQy = _cveOutputArrayFromMat($matQy)
    EndIf

    Local $oArrQz, $vectorOfMatQz, $iArrQzSize
    Local $bQzIsArray = VarGetType($matQz) == "Array"

    If $bQzIsArray Then
        $vectorOfMatQz = _VectorOfMatCreate()

        $iArrQzSize = UBound($matQz)
        For $i = 0 To $iArrQzSize - 1
            _VectorOfMatPush($vectorOfMatQz, $matQz[$i])
        Next

        $oArrQz = _cveOutputArrayFromVectorOfMat($vectorOfMatQz)
    Else
        $oArrQz = _cveOutputArrayFromMat($matQz)
    EndIf

    _cveRQDecomp3x3($iArrSrc, $out, $oArrMtxR, $oArrMtxQ, $oArrQx, $oArrQy, $oArrQz)

    If $bQzIsArray Then
        _VectorOfMatRelease($vectorOfMatQz)
    EndIf

    _cveOutputArrayRelease($oArrQz)

    If $bQyIsArray Then
        _VectorOfMatRelease($vectorOfMatQy)
    EndIf

    _cveOutputArrayRelease($oArrQy)

    If $bQxIsArray Then
        _VectorOfMatRelease($vectorOfMatQx)
    EndIf

    _cveOutputArrayRelease($oArrQx)

    If $bMtxQIsArray Then
        _VectorOfMatRelease($vectorOfMatMtxQ)
    EndIf

    _cveOutputArrayRelease($oArrMtxQ)

    If $bMtxRIsArray Then
        _VectorOfMatRelease($vectorOfMatMtxR)
    EndIf

    _cveOutputArrayRelease($oArrMtxR)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)
EndFunc   ;==>_cveRQDecomp3x3Mat

Func _cveDecomposeProjectionMatrix(ByRef $projMatrix, ByRef $cameraMatrix, ByRef $rotMatrix, ByRef $transVect, ByRef $rotMatrixX, ByRef $rotMatrixY, ByRef $rotMatrixZ, ByRef $eulerAngles)
    ; CVAPI(void) cveDecomposeProjectionMatrix(cv::_InputArray* projMatrix, cv::_OutputArray* cameraMatrix, cv::_OutputArray* rotMatrix, cv::_OutputArray* transVect, cv::_OutputArray* rotMatrixX, cv::_OutputArray* rotMatrixY, cv::_OutputArray* rotMatrixZ, cv::_OutputArray* eulerAngles);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDecomposeProjectionMatrix", "ptr", $projMatrix, "ptr", $cameraMatrix, "ptr", $rotMatrix, "ptr", $transVect, "ptr", $rotMatrixX, "ptr", $rotMatrixY, "ptr", $rotMatrixZ, "ptr", $eulerAngles), "cveDecomposeProjectionMatrix", @error)
EndFunc   ;==>_cveDecomposeProjectionMatrix

Func _cveDecomposeProjectionMatrixMat(ByRef $matProjMatrix, ByRef $matCameraMatrix, ByRef $matRotMatrix, ByRef $matTransVect, ByRef $matRotMatrixX, ByRef $matRotMatrixY, ByRef $matRotMatrixZ, ByRef $matEulerAngles)
    ; cveDecomposeProjectionMatrix using cv::Mat instead of _*Array

    Local $iArrProjMatrix, $vectorOfMatProjMatrix, $iArrProjMatrixSize
    Local $bProjMatrixIsArray = VarGetType($matProjMatrix) == "Array"

    If $bProjMatrixIsArray Then
        $vectorOfMatProjMatrix = _VectorOfMatCreate()

        $iArrProjMatrixSize = UBound($matProjMatrix)
        For $i = 0 To $iArrProjMatrixSize - 1
            _VectorOfMatPush($vectorOfMatProjMatrix, $matProjMatrix[$i])
        Next

        $iArrProjMatrix = _cveInputArrayFromVectorOfMat($vectorOfMatProjMatrix)
    Else
        $iArrProjMatrix = _cveInputArrayFromMat($matProjMatrix)
    EndIf

    Local $oArrCameraMatrix, $vectorOfMatCameraMatrix, $iArrCameraMatrixSize
    Local $bCameraMatrixIsArray = VarGetType($matCameraMatrix) == "Array"

    If $bCameraMatrixIsArray Then
        $vectorOfMatCameraMatrix = _VectorOfMatCreate()

        $iArrCameraMatrixSize = UBound($matCameraMatrix)
        For $i = 0 To $iArrCameraMatrixSize - 1
            _VectorOfMatPush($vectorOfMatCameraMatrix, $matCameraMatrix[$i])
        Next

        $oArrCameraMatrix = _cveOutputArrayFromVectorOfMat($vectorOfMatCameraMatrix)
    Else
        $oArrCameraMatrix = _cveOutputArrayFromMat($matCameraMatrix)
    EndIf

    Local $oArrRotMatrix, $vectorOfMatRotMatrix, $iArrRotMatrixSize
    Local $bRotMatrixIsArray = VarGetType($matRotMatrix) == "Array"

    If $bRotMatrixIsArray Then
        $vectorOfMatRotMatrix = _VectorOfMatCreate()

        $iArrRotMatrixSize = UBound($matRotMatrix)
        For $i = 0 To $iArrRotMatrixSize - 1
            _VectorOfMatPush($vectorOfMatRotMatrix, $matRotMatrix[$i])
        Next

        $oArrRotMatrix = _cveOutputArrayFromVectorOfMat($vectorOfMatRotMatrix)
    Else
        $oArrRotMatrix = _cveOutputArrayFromMat($matRotMatrix)
    EndIf

    Local $oArrTransVect, $vectorOfMatTransVect, $iArrTransVectSize
    Local $bTransVectIsArray = VarGetType($matTransVect) == "Array"

    If $bTransVectIsArray Then
        $vectorOfMatTransVect = _VectorOfMatCreate()

        $iArrTransVectSize = UBound($matTransVect)
        For $i = 0 To $iArrTransVectSize - 1
            _VectorOfMatPush($vectorOfMatTransVect, $matTransVect[$i])
        Next

        $oArrTransVect = _cveOutputArrayFromVectorOfMat($vectorOfMatTransVect)
    Else
        $oArrTransVect = _cveOutputArrayFromMat($matTransVect)
    EndIf

    Local $oArrRotMatrixX, $vectorOfMatRotMatrixX, $iArrRotMatrixXSize
    Local $bRotMatrixXIsArray = VarGetType($matRotMatrixX) == "Array"

    If $bRotMatrixXIsArray Then
        $vectorOfMatRotMatrixX = _VectorOfMatCreate()

        $iArrRotMatrixXSize = UBound($matRotMatrixX)
        For $i = 0 To $iArrRotMatrixXSize - 1
            _VectorOfMatPush($vectorOfMatRotMatrixX, $matRotMatrixX[$i])
        Next

        $oArrRotMatrixX = _cveOutputArrayFromVectorOfMat($vectorOfMatRotMatrixX)
    Else
        $oArrRotMatrixX = _cveOutputArrayFromMat($matRotMatrixX)
    EndIf

    Local $oArrRotMatrixY, $vectorOfMatRotMatrixY, $iArrRotMatrixYSize
    Local $bRotMatrixYIsArray = VarGetType($matRotMatrixY) == "Array"

    If $bRotMatrixYIsArray Then
        $vectorOfMatRotMatrixY = _VectorOfMatCreate()

        $iArrRotMatrixYSize = UBound($matRotMatrixY)
        For $i = 0 To $iArrRotMatrixYSize - 1
            _VectorOfMatPush($vectorOfMatRotMatrixY, $matRotMatrixY[$i])
        Next

        $oArrRotMatrixY = _cveOutputArrayFromVectorOfMat($vectorOfMatRotMatrixY)
    Else
        $oArrRotMatrixY = _cveOutputArrayFromMat($matRotMatrixY)
    EndIf

    Local $oArrRotMatrixZ, $vectorOfMatRotMatrixZ, $iArrRotMatrixZSize
    Local $bRotMatrixZIsArray = VarGetType($matRotMatrixZ) == "Array"

    If $bRotMatrixZIsArray Then
        $vectorOfMatRotMatrixZ = _VectorOfMatCreate()

        $iArrRotMatrixZSize = UBound($matRotMatrixZ)
        For $i = 0 To $iArrRotMatrixZSize - 1
            _VectorOfMatPush($vectorOfMatRotMatrixZ, $matRotMatrixZ[$i])
        Next

        $oArrRotMatrixZ = _cveOutputArrayFromVectorOfMat($vectorOfMatRotMatrixZ)
    Else
        $oArrRotMatrixZ = _cveOutputArrayFromMat($matRotMatrixZ)
    EndIf

    Local $oArrEulerAngles, $vectorOfMatEulerAngles, $iArrEulerAnglesSize
    Local $bEulerAnglesIsArray = VarGetType($matEulerAngles) == "Array"

    If $bEulerAnglesIsArray Then
        $vectorOfMatEulerAngles = _VectorOfMatCreate()

        $iArrEulerAnglesSize = UBound($matEulerAngles)
        For $i = 0 To $iArrEulerAnglesSize - 1
            _VectorOfMatPush($vectorOfMatEulerAngles, $matEulerAngles[$i])
        Next

        $oArrEulerAngles = _cveOutputArrayFromVectorOfMat($vectorOfMatEulerAngles)
    Else
        $oArrEulerAngles = _cveOutputArrayFromMat($matEulerAngles)
    EndIf

    _cveDecomposeProjectionMatrix($iArrProjMatrix, $oArrCameraMatrix, $oArrRotMatrix, $oArrTransVect, $oArrRotMatrixX, $oArrRotMatrixY, $oArrRotMatrixZ, $oArrEulerAngles)

    If $bEulerAnglesIsArray Then
        _VectorOfMatRelease($vectorOfMatEulerAngles)
    EndIf

    _cveOutputArrayRelease($oArrEulerAngles)

    If $bRotMatrixZIsArray Then
        _VectorOfMatRelease($vectorOfMatRotMatrixZ)
    EndIf

    _cveOutputArrayRelease($oArrRotMatrixZ)

    If $bRotMatrixYIsArray Then
        _VectorOfMatRelease($vectorOfMatRotMatrixY)
    EndIf

    _cveOutputArrayRelease($oArrRotMatrixY)

    If $bRotMatrixXIsArray Then
        _VectorOfMatRelease($vectorOfMatRotMatrixX)
    EndIf

    _cveOutputArrayRelease($oArrRotMatrixX)

    If $bTransVectIsArray Then
        _VectorOfMatRelease($vectorOfMatTransVect)
    EndIf

    _cveOutputArrayRelease($oArrTransVect)

    If $bRotMatrixIsArray Then
        _VectorOfMatRelease($vectorOfMatRotMatrix)
    EndIf

    _cveOutputArrayRelease($oArrRotMatrix)

    If $bCameraMatrixIsArray Then
        _VectorOfMatRelease($vectorOfMatCameraMatrix)
    EndIf

    _cveOutputArrayRelease($oArrCameraMatrix)

    If $bProjMatrixIsArray Then
        _VectorOfMatRelease($vectorOfMatProjMatrix)
    EndIf

    _cveInputArrayRelease($iArrProjMatrix)
EndFunc   ;==>_cveDecomposeProjectionMatrixMat