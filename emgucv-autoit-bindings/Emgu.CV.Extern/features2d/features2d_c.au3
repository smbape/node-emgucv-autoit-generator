#include-once
#include "..\..\CVEUtils.au3"

Func _cveOrbCreate($numberOfFeatures, $scaleFactor, $nLevels, $edgeThreshold, $firstLevel, $WTA_K, $scoreType, $patchSize, $fastThreshold, ByRef $feature2D, ByRef $sharedPtr)
    ; CVAPI(cv::ORB*) cveOrbCreate(int numberOfFeatures, float scaleFactor, int nLevels, int edgeThreshold, int firstLevel, int WTA_K, int scoreType, int patchSize, int fastThreshold, cv::Feature2D** feature2D, cv::Ptr<cv::ORB>** sharedPtr);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveOrbCreate", "int", $numberOfFeatures, "float", $scaleFactor, "int", $nLevels, "int", $edgeThreshold, "int", $firstLevel, "int", $WTA_K, "int", $scoreType, "int", $patchSize, "int", $fastThreshold, "ptr*", $feature2D, "ptr*", $sharedPtr), "cveOrbCreate", @error)
EndFunc   ;==>_cveOrbCreate

Func _cveOrbRelease(ByRef $sharedPtr)
    ; CVAPI(void) cveOrbRelease(cv::Ptr<cv::ORB>** sharedPtr);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveOrbRelease", "ptr*", $sharedPtr), "cveOrbRelease", @error)
EndFunc   ;==>_cveOrbRelease

Func _cveBriskCreate($thresh, $octaves, $patternScale, ByRef $feature2D, ByRef $sharedPtr)
    ; CVAPI(cv::BRISK*) cveBriskCreate(int thresh, int octaves, float patternScale, cv::Feature2D** feature2D, cv::Ptr<cv::BRISK>** sharedPtr);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveBriskCreate", "int", $thresh, "int", $octaves, "float", $patternScale, "ptr*", $feature2D, "ptr*", $sharedPtr), "cveBriskCreate", @error)
EndFunc   ;==>_cveBriskCreate

Func _cveBriskRelease(ByRef $sharedPtr)
    ; CVAPI(void) cveBriskRelease(cv::Ptr<cv::BRISK>** sharedPtr);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBriskRelease", "ptr*", $sharedPtr), "cveBriskRelease", @error)
EndFunc   ;==>_cveBriskRelease

Func _cveFASTFeatureDetectorCreate($threshold, $nonmax_supression, $type, ByRef $feature2D, ByRef $sharedPtr)
    ; CVAPI(cv::FastFeatureDetector*) cveFASTFeatureDetectorCreate(int threshold, bool nonmax_supression, int type, cv::Feature2D** feature2D, cv::Ptr<cv::FastFeatureDetector>** sharedPtr);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveFASTFeatureDetectorCreate", "int", $threshold, "boolean", $nonmax_supression, "int", $type, "ptr*", $feature2D, "ptr*", $sharedPtr), "cveFASTFeatureDetectorCreate", @error)
EndFunc   ;==>_cveFASTFeatureDetectorCreate

Func _cveFASTFeatureDetectorRelease(ByRef $sharedPtr)
    ; CVAPI(void) cveFASTFeatureDetectorRelease(cv::Ptr<cv::FastFeatureDetector>** sharedPtr);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFASTFeatureDetectorRelease", "ptr*", $sharedPtr), "cveFASTFeatureDetectorRelease", @error)
EndFunc   ;==>_cveFASTFeatureDetectorRelease

Func _cveGFTTDetectorCreate($maxCorners, $qualityLevel, $minDistance, $blockSize, $useHarrisDetector, $k, ByRef $feature2D, ByRef $sharedPtr)
    ; CVAPI(cv::GFTTDetector*) cveGFTTDetectorCreate(int maxCorners, double qualityLevel, double minDistance, int blockSize, bool useHarrisDetector, double k, cv::Feature2D** feature2D, cv::Ptr<cv::GFTTDetector>** sharedPtr);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGFTTDetectorCreate", "int", $maxCorners, "double", $qualityLevel, "double", $minDistance, "int", $blockSize, "boolean", $useHarrisDetector, "double", $k, "ptr*", $feature2D, "ptr*", $sharedPtr), "cveGFTTDetectorCreate", @error)
EndFunc   ;==>_cveGFTTDetectorCreate

Func _cveGFTTDetectorRelease(ByRef $sharedPtr)
    ; CVAPI(void) cveGFTTDetectorRelease(cv::Ptr<cv::GFTTDetector>** sharedPtr);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveGFTTDetectorRelease", "ptr*", $sharedPtr), "cveGFTTDetectorRelease", @error)
EndFunc   ;==>_cveGFTTDetectorRelease

Func _cveMserCreate($delta, $minArea, $maxArea, $maxVariation, $minDiversity, $maxEvolution, $areaThreshold, $minMargin, $edgeBlurSize, ByRef $feature2D, ByRef $sharedPtr)
    ; CVAPI(cv::MSER*) cveMserCreate(int delta, int minArea, int maxArea, double maxVariation, double minDiversity, int maxEvolution, double areaThreshold, double minMargin, int edgeBlurSize, cv::Feature2D** feature2D, cv::Ptr<cv::MSER>** sharedPtr);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveMserCreate", "int", $delta, "int", $minArea, "int", $maxArea, "double", $maxVariation, "double", $minDiversity, "int", $maxEvolution, "double", $areaThreshold, "double", $minMargin, "int", $edgeBlurSize, "ptr*", $feature2D, "ptr*", $sharedPtr), "cveMserCreate", @error)
EndFunc   ;==>_cveMserCreate

Func _cveMserDetectRegions(ByRef $mserPtr, ByRef $image, ByRef $msers, ByRef $bboxes)
    ; CVAPI(void) cveMserDetectRegions(cv::MSER* mserPtr, cv::_InputArray* image, std::vector< std::vector<cv::Point> >* msers, std::vector< cv::Rect >* bboxes);

    Local $vecMsers, $iArrMsersSize
    Local $bMsersIsArray = VarGetType($msers) == "Array"

    If $bMsersIsArray Then
        $vecMsers = _VectorOfVectorOfPointCreate()

        $iArrMsersSize = UBound($msers)
        For $i = 0 To $iArrMsersSize - 1
            _VectorOfVectorOfPointPush($vecMsers, $msers[$i])
        Next
    Else
        $vecMsers = $msers
    EndIf

    Local $vecBboxes, $iArrBboxesSize
    Local $bBboxesIsArray = VarGetType($bboxes) == "Array"

    If $bBboxesIsArray Then
        $vecBboxes = _VectorOfRectCreate()

        $iArrBboxesSize = UBound($bboxes)
        For $i = 0 To $iArrBboxesSize - 1
            _VectorOfRectPush($vecBboxes, $bboxes[$i])
        Next
    Else
        $vecBboxes = $bboxes
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMserDetectRegions", "ptr", $mserPtr, "ptr", $image, "ptr", $vecMsers, "ptr", $vecBboxes), "cveMserDetectRegions", @error)

    If $bBboxesIsArray Then
        _VectorOfRectRelease($vecBboxes)
    EndIf

    If $bMsersIsArray Then
        _VectorOfVectorOfPointRelease($vecMsers)
    EndIf
EndFunc   ;==>_cveMserDetectRegions

Func _cveMserDetectRegionsMat(ByRef $mserPtr, ByRef $matImage, ByRef $msers, ByRef $bboxes)
    ; cveMserDetectRegions using cv::Mat instead of _*Array

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

    _cveMserDetectRegions($mserPtr, $iArrImage, $msers, $bboxes)

    If $bImageIsArray Then
        _VectorOfMatRelease($vectorOfMatImage)
    EndIf

    _cveInputArrayRelease($iArrImage)
EndFunc   ;==>_cveMserDetectRegionsMat

Func _cveMserRelease(ByRef $sharedPtr)
    ; CVAPI(void) cveMserRelease(cv::Ptr<cv::MSER>** sharedPtr);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMserRelease", "ptr*", $sharedPtr), "cveMserRelease", @error)
EndFunc   ;==>_cveMserRelease

Func _cveSimpleBlobDetectorCreate(ByRef $feature2DPtr, ByRef $sharedPtr)
    ; CVAPI(cv::SimpleBlobDetector*) cveSimpleBlobDetectorCreate(cv::Feature2D** feature2DPtr, cv::Ptr<cv::SimpleBlobDetector>** sharedPtr);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveSimpleBlobDetectorCreate", "ptr*", $feature2DPtr, "ptr*", $sharedPtr), "cveSimpleBlobDetectorCreate", @error)
EndFunc   ;==>_cveSimpleBlobDetectorCreate

Func _cveSimpleBlobDetectorCreateWithParams(ByRef $feature2DPtr, ByRef $params, ByRef $sharedPtr)
    ; CVAPI(cv::SimpleBlobDetector*) cveSimpleBlobDetectorCreateWithParams(cv::Feature2D** feature2DPtr, cv::SimpleBlobDetector::Params* params, cv::Ptr<cv::SimpleBlobDetector>** sharedPtr);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveSimpleBlobDetectorCreateWithParams", "ptr*", $feature2DPtr, "ptr", $params, "ptr*", $sharedPtr), "cveSimpleBlobDetectorCreateWithParams", @error)
EndFunc   ;==>_cveSimpleBlobDetectorCreateWithParams

Func _cveSimpleBlobDetectorRelease(ByRef $sharedPtr)
    ; CVAPI(void) cveSimpleBlobDetectorRelease(cv::Ptr<cv::SimpleBlobDetector>** sharedPtr);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSimpleBlobDetectorRelease", "ptr*", $sharedPtr), "cveSimpleBlobDetectorRelease", @error)
EndFunc   ;==>_cveSimpleBlobDetectorRelease

Func _cveSimpleBlobDetectorParamsCreate()
    ; CVAPI(cv::SimpleBlobDetector::Params*) cveSimpleBlobDetectorParamsCreate();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveSimpleBlobDetectorParamsCreate"), "cveSimpleBlobDetectorParamsCreate", @error)
EndFunc   ;==>_cveSimpleBlobDetectorParamsCreate

Func _cveSimpleBlobDetectorParamsRelease(ByRef $params)
    ; CVAPI(void) cveSimpleBlobDetectorParamsRelease(cv::SimpleBlobDetector::Params** params);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSimpleBlobDetectorParamsRelease", "ptr*", $params), "cveSimpleBlobDetectorParamsRelease", @error)
EndFunc   ;==>_cveSimpleBlobDetectorParamsRelease

Func _drawKeypoints(ByRef $image, $keypoints, ByRef $outImage, $color = _cvScalarAll(-1), $flags = $CV_DRAW_MATCHES_FLAGS_DEFAULT)
    ; CVAPI(void) drawKeypoints(cv::_InputArray* image, const std::vector<cv::KeyPoint>* keypoints, cv::_InputOutputArray* outImage, const CvScalar* color, int flags);

    Local $vecKeypoints, $iArrKeypointsSize
    Local $bKeypointsIsArray = VarGetType($keypoints) == "Array"

    If $bKeypointsIsArray Then
        $vecKeypoints = _VectorOfKeyPointCreate()

        $iArrKeypointsSize = UBound($keypoints)
        For $i = 0 To $iArrKeypointsSize - 1
            _VectorOfKeyPointPush($vecKeypoints, $keypoints[$i])
        Next
    Else
        $vecKeypoints = $keypoints
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "drawKeypoints", "ptr", $image, "ptr", $vecKeypoints, "ptr", $outImage, "ptr", $color, "int", $flags), "drawKeypoints", @error)

    If $bKeypointsIsArray Then
        _VectorOfKeyPointRelease($vecKeypoints)
    EndIf
EndFunc   ;==>_drawKeypoints

Func _drawKeypointsMat(ByRef $matImage, $keypoints, ByRef $matOutImage, $color = _cvScalarAll(-1), $flags = $CV_DRAW_MATCHES_FLAGS_DEFAULT)
    ; drawKeypoints using cv::Mat instead of _*Array

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

    Local $ioArrOutImage, $vectorOfMatOutImage, $iArrOutImageSize
    Local $bOutImageIsArray = VarGetType($matOutImage) == "Array"

    If $bOutImageIsArray Then
        $vectorOfMatOutImage = _VectorOfMatCreate()

        $iArrOutImageSize = UBound($matOutImage)
        For $i = 0 To $iArrOutImageSize - 1
            _VectorOfMatPush($vectorOfMatOutImage, $matOutImage[$i])
        Next

        $ioArrOutImage = _cveInputOutputArrayFromVectorOfMat($vectorOfMatOutImage)
    Else
        $ioArrOutImage = _cveInputOutputArrayFromMat($matOutImage)
    EndIf

    _drawKeypoints($iArrImage, $keypoints, $ioArrOutImage, $color, $flags)

    If $bOutImageIsArray Then
        _VectorOfMatRelease($vectorOfMatOutImage)
    EndIf

    _cveInputOutputArrayRelease($ioArrOutImage)

    If $bImageIsArray Then
        _VectorOfMatRelease($vectorOfMatImage)
    EndIf

    _cveInputArrayRelease($iArrImage)
EndFunc   ;==>_drawKeypointsMat

Func _drawMatchedFeatures1(ByRef $img1, $keypoints1, ByRef $img2, $keypoints2, ByRef $matches, ByRef $outImg, $matchColor, $singlePointColor, ByRef $matchesMask, $flags)
    ; CVAPI(void) drawMatchedFeatures1(cv::_InputArray* img1, const std::vector<cv::KeyPoint>* keypoints1, cv::_InputArray* img2, const std::vector<cv::KeyPoint>* keypoints2, std::vector< cv::DMatch >* matches, cv::_InputOutputArray* outImg, const CvScalar* matchColor, const CvScalar* singlePointColor, std::vector< unsigned char >* matchesMask, int flags);

    Local $vecKeypoints1, $iArrKeypoints1Size
    Local $bKeypoints1IsArray = VarGetType($keypoints1) == "Array"

    If $bKeypoints1IsArray Then
        $vecKeypoints1 = _VectorOfKeyPointCreate()

        $iArrKeypoints1Size = UBound($keypoints1)
        For $i = 0 To $iArrKeypoints1Size - 1
            _VectorOfKeyPointPush($vecKeypoints1, $keypoints1[$i])
        Next
    Else
        $vecKeypoints1 = $keypoints1
    EndIf

    Local $vecKeypoints2, $iArrKeypoints2Size
    Local $bKeypoints2IsArray = VarGetType($keypoints2) == "Array"

    If $bKeypoints2IsArray Then
        $vecKeypoints2 = _VectorOfKeyPointCreate()

        $iArrKeypoints2Size = UBound($keypoints2)
        For $i = 0 To $iArrKeypoints2Size - 1
            _VectorOfKeyPointPush($vecKeypoints2, $keypoints2[$i])
        Next
    Else
        $vecKeypoints2 = $keypoints2
    EndIf

    Local $vecMatches, $iArrMatchesSize
    Local $bMatchesIsArray = VarGetType($matches) == "Array"

    If $bMatchesIsArray Then
        $vecMatches = _VectorOfDMatchCreate()

        $iArrMatchesSize = UBound($matches)
        For $i = 0 To $iArrMatchesSize - 1
            _VectorOfDMatchPush($vecMatches, $matches[$i])
        Next
    Else
        $vecMatches = $matches
    EndIf

    Local $vecMatchesMask, $iArrMatchesMaskSize
    Local $bMatchesMaskIsArray = VarGetType($matchesMask) == "Array"

    If $bMatchesMaskIsArray Then
        $vecMatchesMask = _VectorOfByteCreate()

        $iArrMatchesMaskSize = UBound($matchesMask)
        For $i = 0 To $iArrMatchesMaskSize - 1
            _VectorOfBytePush($vecMatchesMask, $matchesMask[$i])
        Next
    Else
        $vecMatchesMask = $matchesMask
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "drawMatchedFeatures1", "ptr", $img1, "ptr", $vecKeypoints1, "ptr", $img2, "ptr", $vecKeypoints2, "ptr", $vecMatches, "ptr", $outImg, "ptr", $matchColor, "ptr", $singlePointColor, "ptr", $vecMatchesMask, "int", $flags), "drawMatchedFeatures1", @error)

    If $bMatchesMaskIsArray Then
        _VectorOfByteRelease($vecMatchesMask)
    EndIf

    If $bMatchesIsArray Then
        _VectorOfDMatchRelease($vecMatches)
    EndIf

    If $bKeypoints2IsArray Then
        _VectorOfKeyPointRelease($vecKeypoints2)
    EndIf

    If $bKeypoints1IsArray Then
        _VectorOfKeyPointRelease($vecKeypoints1)
    EndIf
EndFunc   ;==>_drawMatchedFeatures1

Func _drawMatchedFeatures1Mat(ByRef $matImg1, $keypoints1, ByRef $matImg2, $keypoints2, ByRef $matches, ByRef $matOutImg, $matchColor, $singlePointColor, ByRef $matchesMask, $flags)
    ; drawMatchedFeatures1 using cv::Mat instead of _*Array

    Local $iArrImg1, $vectorOfMatImg1, $iArrImg1Size
    Local $bImg1IsArray = VarGetType($matImg1) == "Array"

    If $bImg1IsArray Then
        $vectorOfMatImg1 = _VectorOfMatCreate()

        $iArrImg1Size = UBound($matImg1)
        For $i = 0 To $iArrImg1Size - 1
            _VectorOfMatPush($vectorOfMatImg1, $matImg1[$i])
        Next

        $iArrImg1 = _cveInputArrayFromVectorOfMat($vectorOfMatImg1)
    Else
        $iArrImg1 = _cveInputArrayFromMat($matImg1)
    EndIf

    Local $iArrImg2, $vectorOfMatImg2, $iArrImg2Size
    Local $bImg2IsArray = VarGetType($matImg2) == "Array"

    If $bImg2IsArray Then
        $vectorOfMatImg2 = _VectorOfMatCreate()

        $iArrImg2Size = UBound($matImg2)
        For $i = 0 To $iArrImg2Size - 1
            _VectorOfMatPush($vectorOfMatImg2, $matImg2[$i])
        Next

        $iArrImg2 = _cveInputArrayFromVectorOfMat($vectorOfMatImg2)
    Else
        $iArrImg2 = _cveInputArrayFromMat($matImg2)
    EndIf

    Local $ioArrOutImg, $vectorOfMatOutImg, $iArrOutImgSize
    Local $bOutImgIsArray = VarGetType($matOutImg) == "Array"

    If $bOutImgIsArray Then
        $vectorOfMatOutImg = _VectorOfMatCreate()

        $iArrOutImgSize = UBound($matOutImg)
        For $i = 0 To $iArrOutImgSize - 1
            _VectorOfMatPush($vectorOfMatOutImg, $matOutImg[$i])
        Next

        $ioArrOutImg = _cveInputOutputArrayFromVectorOfMat($vectorOfMatOutImg)
    Else
        $ioArrOutImg = _cveInputOutputArrayFromMat($matOutImg)
    EndIf

    _drawMatchedFeatures1($iArrImg1, $keypoints1, $iArrImg2, $keypoints2, $matches, $ioArrOutImg, $matchColor, $singlePointColor, $matchesMask, $flags)

    If $bOutImgIsArray Then
        _VectorOfMatRelease($vectorOfMatOutImg)
    EndIf

    _cveInputOutputArrayRelease($ioArrOutImg)

    If $bImg2IsArray Then
        _VectorOfMatRelease($vectorOfMatImg2)
    EndIf

    _cveInputArrayRelease($iArrImg2)

    If $bImg1IsArray Then
        _VectorOfMatRelease($vectorOfMatImg1)
    EndIf

    _cveInputArrayRelease($iArrImg1)
EndFunc   ;==>_drawMatchedFeatures1Mat

Func _drawMatchedFeatures2(ByRef $img1, $keypoints1, ByRef $img2, $keypoints2, ByRef $matches, ByRef $outImg, $matchColor, $singlePointColor, ByRef $matchesMask, $flags)
    ; CVAPI(void) drawMatchedFeatures2(cv::_InputArray* img1, const std::vector<cv::KeyPoint>* keypoints1, cv::_InputArray* img2, const std::vector<cv::KeyPoint>* keypoints2, std::vector< std::vector< cv::DMatch > >* matches, cv::_InputOutputArray* outImg, const CvScalar* matchColor, const CvScalar* singlePointColor, std::vector< std::vector< unsigned char > >* matchesMask, int flags);

    Local $vecKeypoints1, $iArrKeypoints1Size
    Local $bKeypoints1IsArray = VarGetType($keypoints1) == "Array"

    If $bKeypoints1IsArray Then
        $vecKeypoints1 = _VectorOfKeyPointCreate()

        $iArrKeypoints1Size = UBound($keypoints1)
        For $i = 0 To $iArrKeypoints1Size - 1
            _VectorOfKeyPointPush($vecKeypoints1, $keypoints1[$i])
        Next
    Else
        $vecKeypoints1 = $keypoints1
    EndIf

    Local $vecKeypoints2, $iArrKeypoints2Size
    Local $bKeypoints2IsArray = VarGetType($keypoints2) == "Array"

    If $bKeypoints2IsArray Then
        $vecKeypoints2 = _VectorOfKeyPointCreate()

        $iArrKeypoints2Size = UBound($keypoints2)
        For $i = 0 To $iArrKeypoints2Size - 1
            _VectorOfKeyPointPush($vecKeypoints2, $keypoints2[$i])
        Next
    Else
        $vecKeypoints2 = $keypoints2
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

    Local $vecMatchesMask, $iArrMatchesMaskSize
    Local $bMatchesMaskIsArray = VarGetType($matchesMask) == "Array"

    If $bMatchesMaskIsArray Then
        $vecMatchesMask = _VectorOfVectorOfByteCreate()

        $iArrMatchesMaskSize = UBound($matchesMask)
        For $i = 0 To $iArrMatchesMaskSize - 1
            _VectorOfVectorOfBytePush($vecMatchesMask, $matchesMask[$i])
        Next
    Else
        $vecMatchesMask = $matchesMask
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "drawMatchedFeatures2", "ptr", $img1, "ptr", $vecKeypoints1, "ptr", $img2, "ptr", $vecKeypoints2, "ptr", $vecMatches, "ptr", $outImg, "ptr", $matchColor, "ptr", $singlePointColor, "ptr", $vecMatchesMask, "int", $flags), "drawMatchedFeatures2", @error)

    If $bMatchesMaskIsArray Then
        _VectorOfVectorOfByteRelease($vecMatchesMask)
    EndIf

    If $bMatchesIsArray Then
        _VectorOfVectorOfDMatchRelease($vecMatches)
    EndIf

    If $bKeypoints2IsArray Then
        _VectorOfKeyPointRelease($vecKeypoints2)
    EndIf

    If $bKeypoints1IsArray Then
        _VectorOfKeyPointRelease($vecKeypoints1)
    EndIf
EndFunc   ;==>_drawMatchedFeatures2

Func _drawMatchedFeatures2Mat(ByRef $matImg1, $keypoints1, ByRef $matImg2, $keypoints2, ByRef $matches, ByRef $matOutImg, $matchColor, $singlePointColor, ByRef $matchesMask, $flags)
    ; drawMatchedFeatures2 using cv::Mat instead of _*Array

    Local $iArrImg1, $vectorOfMatImg1, $iArrImg1Size
    Local $bImg1IsArray = VarGetType($matImg1) == "Array"

    If $bImg1IsArray Then
        $vectorOfMatImg1 = _VectorOfMatCreate()

        $iArrImg1Size = UBound($matImg1)
        For $i = 0 To $iArrImg1Size - 1
            _VectorOfMatPush($vectorOfMatImg1, $matImg1[$i])
        Next

        $iArrImg1 = _cveInputArrayFromVectorOfMat($vectorOfMatImg1)
    Else
        $iArrImg1 = _cveInputArrayFromMat($matImg1)
    EndIf

    Local $iArrImg2, $vectorOfMatImg2, $iArrImg2Size
    Local $bImg2IsArray = VarGetType($matImg2) == "Array"

    If $bImg2IsArray Then
        $vectorOfMatImg2 = _VectorOfMatCreate()

        $iArrImg2Size = UBound($matImg2)
        For $i = 0 To $iArrImg2Size - 1
            _VectorOfMatPush($vectorOfMatImg2, $matImg2[$i])
        Next

        $iArrImg2 = _cveInputArrayFromVectorOfMat($vectorOfMatImg2)
    Else
        $iArrImg2 = _cveInputArrayFromMat($matImg2)
    EndIf

    Local $ioArrOutImg, $vectorOfMatOutImg, $iArrOutImgSize
    Local $bOutImgIsArray = VarGetType($matOutImg) == "Array"

    If $bOutImgIsArray Then
        $vectorOfMatOutImg = _VectorOfMatCreate()

        $iArrOutImgSize = UBound($matOutImg)
        For $i = 0 To $iArrOutImgSize - 1
            _VectorOfMatPush($vectorOfMatOutImg, $matOutImg[$i])
        Next

        $ioArrOutImg = _cveInputOutputArrayFromVectorOfMat($vectorOfMatOutImg)
    Else
        $ioArrOutImg = _cveInputOutputArrayFromMat($matOutImg)
    EndIf

    _drawMatchedFeatures2($iArrImg1, $keypoints1, $iArrImg2, $keypoints2, $matches, $ioArrOutImg, $matchColor, $singlePointColor, $matchesMask, $flags)

    If $bOutImgIsArray Then
        _VectorOfMatRelease($vectorOfMatOutImg)
    EndIf

    _cveInputOutputArrayRelease($ioArrOutImg)

    If $bImg2IsArray Then
        _VectorOfMatRelease($vectorOfMatImg2)
    EndIf

    _cveInputArrayRelease($iArrImg2)

    If $bImg1IsArray Then
        _VectorOfMatRelease($vectorOfMatImg1)
    EndIf

    _cveInputArrayRelease($iArrImg1)
EndFunc   ;==>_drawMatchedFeatures2Mat

Func _drawMatchedFeatures3(ByRef $img1, $keypoints1, ByRef $img2, $keypoints2, ByRef $matches, ByRef $outImg, $matchColor, $singlePointColor, ByRef $matchesMask, $flags)
    ; CVAPI(void) drawMatchedFeatures3(cv::_InputArray* img1, const std::vector<cv::KeyPoint>* keypoints1, cv::_InputArray* img2, const std::vector<cv::KeyPoint>* keypoints2, std::vector< std::vector< cv::DMatch > >* matches, cv::_InputOutputArray* outImg, const CvScalar* matchColor, const CvScalar* singlePointColor, cv::_InputArray* matchesMask, int flags);

    Local $vecKeypoints1, $iArrKeypoints1Size
    Local $bKeypoints1IsArray = VarGetType($keypoints1) == "Array"

    If $bKeypoints1IsArray Then
        $vecKeypoints1 = _VectorOfKeyPointCreate()

        $iArrKeypoints1Size = UBound($keypoints1)
        For $i = 0 To $iArrKeypoints1Size - 1
            _VectorOfKeyPointPush($vecKeypoints1, $keypoints1[$i])
        Next
    Else
        $vecKeypoints1 = $keypoints1
    EndIf

    Local $vecKeypoints2, $iArrKeypoints2Size
    Local $bKeypoints2IsArray = VarGetType($keypoints2) == "Array"

    If $bKeypoints2IsArray Then
        $vecKeypoints2 = _VectorOfKeyPointCreate()

        $iArrKeypoints2Size = UBound($keypoints2)
        For $i = 0 To $iArrKeypoints2Size - 1
            _VectorOfKeyPointPush($vecKeypoints2, $keypoints2[$i])
        Next
    Else
        $vecKeypoints2 = $keypoints2
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "drawMatchedFeatures3", "ptr", $img1, "ptr", $vecKeypoints1, "ptr", $img2, "ptr", $vecKeypoints2, "ptr", $vecMatches, "ptr", $outImg, "ptr", $matchColor, "ptr", $singlePointColor, "ptr", $matchesMask, "int", $flags), "drawMatchedFeatures3", @error)

    If $bMatchesIsArray Then
        _VectorOfVectorOfDMatchRelease($vecMatches)
    EndIf

    If $bKeypoints2IsArray Then
        _VectorOfKeyPointRelease($vecKeypoints2)
    EndIf

    If $bKeypoints1IsArray Then
        _VectorOfKeyPointRelease($vecKeypoints1)
    EndIf
EndFunc   ;==>_drawMatchedFeatures3

Func _drawMatchedFeatures3Mat(ByRef $matImg1, $keypoints1, ByRef $matImg2, $keypoints2, ByRef $matches, ByRef $matOutImg, $matchColor, $singlePointColor, ByRef $matMatchesMask, $flags)
    ; drawMatchedFeatures3 using cv::Mat instead of _*Array

    Local $iArrImg1, $vectorOfMatImg1, $iArrImg1Size
    Local $bImg1IsArray = VarGetType($matImg1) == "Array"

    If $bImg1IsArray Then
        $vectorOfMatImg1 = _VectorOfMatCreate()

        $iArrImg1Size = UBound($matImg1)
        For $i = 0 To $iArrImg1Size - 1
            _VectorOfMatPush($vectorOfMatImg1, $matImg1[$i])
        Next

        $iArrImg1 = _cveInputArrayFromVectorOfMat($vectorOfMatImg1)
    Else
        $iArrImg1 = _cveInputArrayFromMat($matImg1)
    EndIf

    Local $iArrImg2, $vectorOfMatImg2, $iArrImg2Size
    Local $bImg2IsArray = VarGetType($matImg2) == "Array"

    If $bImg2IsArray Then
        $vectorOfMatImg2 = _VectorOfMatCreate()

        $iArrImg2Size = UBound($matImg2)
        For $i = 0 To $iArrImg2Size - 1
            _VectorOfMatPush($vectorOfMatImg2, $matImg2[$i])
        Next

        $iArrImg2 = _cveInputArrayFromVectorOfMat($vectorOfMatImg2)
    Else
        $iArrImg2 = _cveInputArrayFromMat($matImg2)
    EndIf

    Local $ioArrOutImg, $vectorOfMatOutImg, $iArrOutImgSize
    Local $bOutImgIsArray = VarGetType($matOutImg) == "Array"

    If $bOutImgIsArray Then
        $vectorOfMatOutImg = _VectorOfMatCreate()

        $iArrOutImgSize = UBound($matOutImg)
        For $i = 0 To $iArrOutImgSize - 1
            _VectorOfMatPush($vectorOfMatOutImg, $matOutImg[$i])
        Next

        $ioArrOutImg = _cveInputOutputArrayFromVectorOfMat($vectorOfMatOutImg)
    Else
        $ioArrOutImg = _cveInputOutputArrayFromMat($matOutImg)
    EndIf

    Local $iArrMatchesMask, $vectorOfMatMatchesMask, $iArrMatchesMaskSize
    Local $bMatchesMaskIsArray = VarGetType($matMatchesMask) == "Array"

    If $bMatchesMaskIsArray Then
        $vectorOfMatMatchesMask = _VectorOfMatCreate()

        $iArrMatchesMaskSize = UBound($matMatchesMask)
        For $i = 0 To $iArrMatchesMaskSize - 1
            _VectorOfMatPush($vectorOfMatMatchesMask, $matMatchesMask[$i])
        Next

        $iArrMatchesMask = _cveInputArrayFromVectorOfMat($vectorOfMatMatchesMask)
    Else
        $iArrMatchesMask = _cveInputArrayFromMat($matMatchesMask)
    EndIf

    _drawMatchedFeatures3($iArrImg1, $keypoints1, $iArrImg2, $keypoints2, $matches, $ioArrOutImg, $matchColor, $singlePointColor, $iArrMatchesMask, $flags)

    If $bMatchesMaskIsArray Then
        _VectorOfMatRelease($vectorOfMatMatchesMask)
    EndIf

    _cveInputArrayRelease($iArrMatchesMask)

    If $bOutImgIsArray Then
        _VectorOfMatRelease($vectorOfMatOutImg)
    EndIf

    _cveInputOutputArrayRelease($ioArrOutImg)

    If $bImg2IsArray Then
        _VectorOfMatRelease($vectorOfMatImg2)
    EndIf

    _cveInputArrayRelease($iArrImg2)

    If $bImg1IsArray Then
        _VectorOfMatRelease($vectorOfMatImg1)
    EndIf

    _cveInputArrayRelease($iArrImg1)
EndFunc   ;==>_drawMatchedFeatures3Mat

Func _cveDescriptorMatcherAdd(ByRef $matcher, ByRef $trainDescriptors)
    ; CVAPI(void) cveDescriptorMatcherAdd(cv::DescriptorMatcher* matcher, cv::_InputArray* trainDescriptors);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDescriptorMatcherAdd", "ptr", $matcher, "ptr", $trainDescriptors), "cveDescriptorMatcherAdd", @error)
EndFunc   ;==>_cveDescriptorMatcherAdd

Func _cveDescriptorMatcherAddMat(ByRef $matcher, ByRef $matTrainDescriptors)
    ; cveDescriptorMatcherAdd using cv::Mat instead of _*Array

    Local $iArrTrainDescriptors, $vectorOfMatTrainDescriptors, $iArrTrainDescriptorsSize
    Local $bTrainDescriptorsIsArray = VarGetType($matTrainDescriptors) == "Array"

    If $bTrainDescriptorsIsArray Then
        $vectorOfMatTrainDescriptors = _VectorOfMatCreate()

        $iArrTrainDescriptorsSize = UBound($matTrainDescriptors)
        For $i = 0 To $iArrTrainDescriptorsSize - 1
            _VectorOfMatPush($vectorOfMatTrainDescriptors, $matTrainDescriptors[$i])
        Next

        $iArrTrainDescriptors = _cveInputArrayFromVectorOfMat($vectorOfMatTrainDescriptors)
    Else
        $iArrTrainDescriptors = _cveInputArrayFromMat($matTrainDescriptors)
    EndIf

    _cveDescriptorMatcherAdd($matcher, $iArrTrainDescriptors)

    If $bTrainDescriptorsIsArray Then
        _VectorOfMatRelease($vectorOfMatTrainDescriptors)
    EndIf

    _cveInputArrayRelease($iArrTrainDescriptors)
EndFunc   ;==>_cveDescriptorMatcherAddMat

Func _cveDescriptorMatcherKnnMatch1(ByRef $matcher, ByRef $queryDescriptors, ByRef $trainDescriptors, ByRef $matches, $k, ByRef $mask, $compactResult)
    ; CVAPI(void) cveDescriptorMatcherKnnMatch1(cv::DescriptorMatcher* matcher, cv::_InputArray* queryDescriptors, cv::_InputArray* trainDescriptors, std::vector< std::vector< cv::DMatch > >* matches, int k, cv::_InputArray* mask, bool compactResult);

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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDescriptorMatcherKnnMatch1", "ptr", $matcher, "ptr", $queryDescriptors, "ptr", $trainDescriptors, "ptr", $vecMatches, "int", $k, "ptr", $mask, "boolean", $compactResult), "cveDescriptorMatcherKnnMatch1", @error)

    If $bMatchesIsArray Then
        _VectorOfVectorOfDMatchRelease($vecMatches)
    EndIf
EndFunc   ;==>_cveDescriptorMatcherKnnMatch1

Func _cveDescriptorMatcherKnnMatch1Mat(ByRef $matcher, ByRef $matQueryDescriptors, ByRef $matTrainDescriptors, ByRef $matches, $k, ByRef $matMask, $compactResult)
    ; cveDescriptorMatcherKnnMatch1 using cv::Mat instead of _*Array

    Local $iArrQueryDescriptors, $vectorOfMatQueryDescriptors, $iArrQueryDescriptorsSize
    Local $bQueryDescriptorsIsArray = VarGetType($matQueryDescriptors) == "Array"

    If $bQueryDescriptorsIsArray Then
        $vectorOfMatQueryDescriptors = _VectorOfMatCreate()

        $iArrQueryDescriptorsSize = UBound($matQueryDescriptors)
        For $i = 0 To $iArrQueryDescriptorsSize - 1
            _VectorOfMatPush($vectorOfMatQueryDescriptors, $matQueryDescriptors[$i])
        Next

        $iArrQueryDescriptors = _cveInputArrayFromVectorOfMat($vectorOfMatQueryDescriptors)
    Else
        $iArrQueryDescriptors = _cveInputArrayFromMat($matQueryDescriptors)
    EndIf

    Local $iArrTrainDescriptors, $vectorOfMatTrainDescriptors, $iArrTrainDescriptorsSize
    Local $bTrainDescriptorsIsArray = VarGetType($matTrainDescriptors) == "Array"

    If $bTrainDescriptorsIsArray Then
        $vectorOfMatTrainDescriptors = _VectorOfMatCreate()

        $iArrTrainDescriptorsSize = UBound($matTrainDescriptors)
        For $i = 0 To $iArrTrainDescriptorsSize - 1
            _VectorOfMatPush($vectorOfMatTrainDescriptors, $matTrainDescriptors[$i])
        Next

        $iArrTrainDescriptors = _cveInputArrayFromVectorOfMat($vectorOfMatTrainDescriptors)
    Else
        $iArrTrainDescriptors = _cveInputArrayFromMat($matTrainDescriptors)
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

    _cveDescriptorMatcherKnnMatch1($matcher, $iArrQueryDescriptors, $iArrTrainDescriptors, $matches, $k, $iArrMask, $compactResult)

    If $bMaskIsArray Then
        _VectorOfMatRelease($vectorOfMatMask)
    EndIf

    _cveInputArrayRelease($iArrMask)

    If $bTrainDescriptorsIsArray Then
        _VectorOfMatRelease($vectorOfMatTrainDescriptors)
    EndIf

    _cveInputArrayRelease($iArrTrainDescriptors)

    If $bQueryDescriptorsIsArray Then
        _VectorOfMatRelease($vectorOfMatQueryDescriptors)
    EndIf

    _cveInputArrayRelease($iArrQueryDescriptors)
EndFunc   ;==>_cveDescriptorMatcherKnnMatch1Mat

Func _cveDescriptorMatcherKnnMatch2(ByRef $matcher, ByRef $queryDescriptors, ByRef $matches, $k, ByRef $mask, $compactResult)
    ; CVAPI(void) cveDescriptorMatcherKnnMatch2(cv::DescriptorMatcher* matcher, cv::_InputArray* queryDescriptors, std::vector< std::vector< cv::DMatch > >* matches, int k, cv::_InputArray* mask, bool compactResult);

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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDescriptorMatcherKnnMatch2", "ptr", $matcher, "ptr", $queryDescriptors, "ptr", $vecMatches, "int", $k, "ptr", $mask, "boolean", $compactResult), "cveDescriptorMatcherKnnMatch2", @error)

    If $bMatchesIsArray Then
        _VectorOfVectorOfDMatchRelease($vecMatches)
    EndIf
EndFunc   ;==>_cveDescriptorMatcherKnnMatch2

Func _cveDescriptorMatcherKnnMatch2Mat(ByRef $matcher, ByRef $matQueryDescriptors, ByRef $matches, $k, ByRef $matMask, $compactResult)
    ; cveDescriptorMatcherKnnMatch2 using cv::Mat instead of _*Array

    Local $iArrQueryDescriptors, $vectorOfMatQueryDescriptors, $iArrQueryDescriptorsSize
    Local $bQueryDescriptorsIsArray = VarGetType($matQueryDescriptors) == "Array"

    If $bQueryDescriptorsIsArray Then
        $vectorOfMatQueryDescriptors = _VectorOfMatCreate()

        $iArrQueryDescriptorsSize = UBound($matQueryDescriptors)
        For $i = 0 To $iArrQueryDescriptorsSize - 1
            _VectorOfMatPush($vectorOfMatQueryDescriptors, $matQueryDescriptors[$i])
        Next

        $iArrQueryDescriptors = _cveInputArrayFromVectorOfMat($vectorOfMatQueryDescriptors)
    Else
        $iArrQueryDescriptors = _cveInputArrayFromMat($matQueryDescriptors)
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

    _cveDescriptorMatcherKnnMatch2($matcher, $iArrQueryDescriptors, $matches, $k, $iArrMask, $compactResult)

    If $bMaskIsArray Then
        _VectorOfMatRelease($vectorOfMatMask)
    EndIf

    _cveInputArrayRelease($iArrMask)

    If $bQueryDescriptorsIsArray Then
        _VectorOfMatRelease($vectorOfMatQueryDescriptors)
    EndIf

    _cveInputArrayRelease($iArrQueryDescriptors)
EndFunc   ;==>_cveDescriptorMatcherKnnMatch2Mat

Func _cveDescriptorMatcherGetAlgorithm(ByRef $matcher)
    ; CVAPI(cv::Algorithm*) cveDescriptorMatcherGetAlgorithm(cv::DescriptorMatcher* matcher);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveDescriptorMatcherGetAlgorithm", "ptr", $matcher), "cveDescriptorMatcherGetAlgorithm", @error)
EndFunc   ;==>_cveDescriptorMatcherGetAlgorithm

Func _cveDescriptorMatcherClear(ByRef $matcher)
    ; CVAPI(void) cveDescriptorMatcherClear(cv::DescriptorMatcher* matcher);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDescriptorMatcherClear", "ptr", $matcher), "cveDescriptorMatcherClear", @error)
EndFunc   ;==>_cveDescriptorMatcherClear

Func _cveDescriptorMatcherEmpty(ByRef $matcher)
    ; CVAPI(bool) cveDescriptorMatcherEmpty(cv::DescriptorMatcher* matcher);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveDescriptorMatcherEmpty", "ptr", $matcher), "cveDescriptorMatcherEmpty", @error)
EndFunc   ;==>_cveDescriptorMatcherEmpty

Func _cveDescriptorMatcherIsMaskSupported(ByRef $matcher)
    ; CVAPI(bool) cveDescriptorMatcherIsMaskSupported(cv::DescriptorMatcher* matcher);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveDescriptorMatcherIsMaskSupported", "ptr", $matcher), "cveDescriptorMatcherIsMaskSupported", @error)
EndFunc   ;==>_cveDescriptorMatcherIsMaskSupported

Func _cveDescriptorMatcherTrain(ByRef $matcher)
    ; CVAPI(void) cveDescriptorMatcherTrain(cv::DescriptorMatcher* matcher);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDescriptorMatcherTrain", "ptr", $matcher), "cveDescriptorMatcherTrain", @error)
EndFunc   ;==>_cveDescriptorMatcherTrain

Func _cveDescriptorMatcherMatch1(ByRef $matcher, ByRef $queryDescriptors, ByRef $trainDescriptors, ByRef $matches, ByRef $mask)
    ; CVAPI(void) cveDescriptorMatcherMatch1(cv::DescriptorMatcher* matcher, cv::_InputArray* queryDescriptors, cv::_InputArray* trainDescriptors, std::vector< cv::DMatch >* matches, cv::_InputArray* mask);

    Local $vecMatches, $iArrMatchesSize
    Local $bMatchesIsArray = VarGetType($matches) == "Array"

    If $bMatchesIsArray Then
        $vecMatches = _VectorOfDMatchCreate()

        $iArrMatchesSize = UBound($matches)
        For $i = 0 To $iArrMatchesSize - 1
            _VectorOfDMatchPush($vecMatches, $matches[$i])
        Next
    Else
        $vecMatches = $matches
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDescriptorMatcherMatch1", "ptr", $matcher, "ptr", $queryDescriptors, "ptr", $trainDescriptors, "ptr", $vecMatches, "ptr", $mask), "cveDescriptorMatcherMatch1", @error)

    If $bMatchesIsArray Then
        _VectorOfDMatchRelease($vecMatches)
    EndIf
EndFunc   ;==>_cveDescriptorMatcherMatch1

Func _cveDescriptorMatcherMatch1Mat(ByRef $matcher, ByRef $matQueryDescriptors, ByRef $matTrainDescriptors, ByRef $matches, ByRef $matMask)
    ; cveDescriptorMatcherMatch1 using cv::Mat instead of _*Array

    Local $iArrQueryDescriptors, $vectorOfMatQueryDescriptors, $iArrQueryDescriptorsSize
    Local $bQueryDescriptorsIsArray = VarGetType($matQueryDescriptors) == "Array"

    If $bQueryDescriptorsIsArray Then
        $vectorOfMatQueryDescriptors = _VectorOfMatCreate()

        $iArrQueryDescriptorsSize = UBound($matQueryDescriptors)
        For $i = 0 To $iArrQueryDescriptorsSize - 1
            _VectorOfMatPush($vectorOfMatQueryDescriptors, $matQueryDescriptors[$i])
        Next

        $iArrQueryDescriptors = _cveInputArrayFromVectorOfMat($vectorOfMatQueryDescriptors)
    Else
        $iArrQueryDescriptors = _cveInputArrayFromMat($matQueryDescriptors)
    EndIf

    Local $iArrTrainDescriptors, $vectorOfMatTrainDescriptors, $iArrTrainDescriptorsSize
    Local $bTrainDescriptorsIsArray = VarGetType($matTrainDescriptors) == "Array"

    If $bTrainDescriptorsIsArray Then
        $vectorOfMatTrainDescriptors = _VectorOfMatCreate()

        $iArrTrainDescriptorsSize = UBound($matTrainDescriptors)
        For $i = 0 To $iArrTrainDescriptorsSize - 1
            _VectorOfMatPush($vectorOfMatTrainDescriptors, $matTrainDescriptors[$i])
        Next

        $iArrTrainDescriptors = _cveInputArrayFromVectorOfMat($vectorOfMatTrainDescriptors)
    Else
        $iArrTrainDescriptors = _cveInputArrayFromMat($matTrainDescriptors)
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

    _cveDescriptorMatcherMatch1($matcher, $iArrQueryDescriptors, $iArrTrainDescriptors, $matches, $iArrMask)

    If $bMaskIsArray Then
        _VectorOfMatRelease($vectorOfMatMask)
    EndIf

    _cveInputArrayRelease($iArrMask)

    If $bTrainDescriptorsIsArray Then
        _VectorOfMatRelease($vectorOfMatTrainDescriptors)
    EndIf

    _cveInputArrayRelease($iArrTrainDescriptors)

    If $bQueryDescriptorsIsArray Then
        _VectorOfMatRelease($vectorOfMatQueryDescriptors)
    EndIf

    _cveInputArrayRelease($iArrQueryDescriptors)
EndFunc   ;==>_cveDescriptorMatcherMatch1Mat

Func _cveDescriptorMatcherMatch2(ByRef $matcher, ByRef $queryDescriptors, ByRef $matches, ByRef $masks)
    ; CVAPI(void) cveDescriptorMatcherMatch2(cv::DescriptorMatcher* matcher, cv::_InputArray* queryDescriptors, std::vector< cv::DMatch >* matches, cv::_InputArray* masks);

    Local $vecMatches, $iArrMatchesSize
    Local $bMatchesIsArray = VarGetType($matches) == "Array"

    If $bMatchesIsArray Then
        $vecMatches = _VectorOfDMatchCreate()

        $iArrMatchesSize = UBound($matches)
        For $i = 0 To $iArrMatchesSize - 1
            _VectorOfDMatchPush($vecMatches, $matches[$i])
        Next
    Else
        $vecMatches = $matches
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDescriptorMatcherMatch2", "ptr", $matcher, "ptr", $queryDescriptors, "ptr", $vecMatches, "ptr", $masks), "cveDescriptorMatcherMatch2", @error)

    If $bMatchesIsArray Then
        _VectorOfDMatchRelease($vecMatches)
    EndIf
EndFunc   ;==>_cveDescriptorMatcherMatch2

Func _cveDescriptorMatcherMatch2Mat(ByRef $matcher, ByRef $matQueryDescriptors, ByRef $matches, ByRef $matMasks)
    ; cveDescriptorMatcherMatch2 using cv::Mat instead of _*Array

    Local $iArrQueryDescriptors, $vectorOfMatQueryDescriptors, $iArrQueryDescriptorsSize
    Local $bQueryDescriptorsIsArray = VarGetType($matQueryDescriptors) == "Array"

    If $bQueryDescriptorsIsArray Then
        $vectorOfMatQueryDescriptors = _VectorOfMatCreate()

        $iArrQueryDescriptorsSize = UBound($matQueryDescriptors)
        For $i = 0 To $iArrQueryDescriptorsSize - 1
            _VectorOfMatPush($vectorOfMatQueryDescriptors, $matQueryDescriptors[$i])
        Next

        $iArrQueryDescriptors = _cveInputArrayFromVectorOfMat($vectorOfMatQueryDescriptors)
    Else
        $iArrQueryDescriptors = _cveInputArrayFromMat($matQueryDescriptors)
    EndIf

    Local $iArrMasks, $vectorOfMatMasks, $iArrMasksSize
    Local $bMasksIsArray = VarGetType($matMasks) == "Array"

    If $bMasksIsArray Then
        $vectorOfMatMasks = _VectorOfMatCreate()

        $iArrMasksSize = UBound($matMasks)
        For $i = 0 To $iArrMasksSize - 1
            _VectorOfMatPush($vectorOfMatMasks, $matMasks[$i])
        Next

        $iArrMasks = _cveInputArrayFromVectorOfMat($vectorOfMatMasks)
    Else
        $iArrMasks = _cveInputArrayFromMat($matMasks)
    EndIf

    _cveDescriptorMatcherMatch2($matcher, $iArrQueryDescriptors, $matches, $iArrMasks)

    If $bMasksIsArray Then
        _VectorOfMatRelease($vectorOfMatMasks)
    EndIf

    _cveInputArrayRelease($iArrMasks)

    If $bQueryDescriptorsIsArray Then
        _VectorOfMatRelease($vectorOfMatQueryDescriptors)
    EndIf

    _cveInputArrayRelease($iArrQueryDescriptors)
EndFunc   ;==>_cveDescriptorMatcherMatch2Mat

Func _cveDescriptorMatcherRadiusMatch1(ByRef $matcher, ByRef $queryDescriptors, ByRef $trainDescriptors, ByRef $matches, $maxDistance, ByRef $mask, $compactResult)
    ; CVAPI(void) cveDescriptorMatcherRadiusMatch1(cv::DescriptorMatcher* matcher, cv::_InputArray* queryDescriptors, cv::_InputArray* trainDescriptors, std::vector< std::vector<cv::DMatch> >* matches, float maxDistance, cv::_InputArray* mask, bool compactResult);

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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDescriptorMatcherRadiusMatch1", "ptr", $matcher, "ptr", $queryDescriptors, "ptr", $trainDescriptors, "ptr", $vecMatches, "float", $maxDistance, "ptr", $mask, "boolean", $compactResult), "cveDescriptorMatcherRadiusMatch1", @error)

    If $bMatchesIsArray Then
        _VectorOfVectorOfDMatchRelease($vecMatches)
    EndIf
EndFunc   ;==>_cveDescriptorMatcherRadiusMatch1

Func _cveDescriptorMatcherRadiusMatch1Mat(ByRef $matcher, ByRef $matQueryDescriptors, ByRef $matTrainDescriptors, ByRef $matches, $maxDistance, ByRef $matMask, $compactResult)
    ; cveDescriptorMatcherRadiusMatch1 using cv::Mat instead of _*Array

    Local $iArrQueryDescriptors, $vectorOfMatQueryDescriptors, $iArrQueryDescriptorsSize
    Local $bQueryDescriptorsIsArray = VarGetType($matQueryDescriptors) == "Array"

    If $bQueryDescriptorsIsArray Then
        $vectorOfMatQueryDescriptors = _VectorOfMatCreate()

        $iArrQueryDescriptorsSize = UBound($matQueryDescriptors)
        For $i = 0 To $iArrQueryDescriptorsSize - 1
            _VectorOfMatPush($vectorOfMatQueryDescriptors, $matQueryDescriptors[$i])
        Next

        $iArrQueryDescriptors = _cveInputArrayFromVectorOfMat($vectorOfMatQueryDescriptors)
    Else
        $iArrQueryDescriptors = _cveInputArrayFromMat($matQueryDescriptors)
    EndIf

    Local $iArrTrainDescriptors, $vectorOfMatTrainDescriptors, $iArrTrainDescriptorsSize
    Local $bTrainDescriptorsIsArray = VarGetType($matTrainDescriptors) == "Array"

    If $bTrainDescriptorsIsArray Then
        $vectorOfMatTrainDescriptors = _VectorOfMatCreate()

        $iArrTrainDescriptorsSize = UBound($matTrainDescriptors)
        For $i = 0 To $iArrTrainDescriptorsSize - 1
            _VectorOfMatPush($vectorOfMatTrainDescriptors, $matTrainDescriptors[$i])
        Next

        $iArrTrainDescriptors = _cveInputArrayFromVectorOfMat($vectorOfMatTrainDescriptors)
    Else
        $iArrTrainDescriptors = _cveInputArrayFromMat($matTrainDescriptors)
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

    _cveDescriptorMatcherRadiusMatch1($matcher, $iArrQueryDescriptors, $iArrTrainDescriptors, $matches, $maxDistance, $iArrMask, $compactResult)

    If $bMaskIsArray Then
        _VectorOfMatRelease($vectorOfMatMask)
    EndIf

    _cveInputArrayRelease($iArrMask)

    If $bTrainDescriptorsIsArray Then
        _VectorOfMatRelease($vectorOfMatTrainDescriptors)
    EndIf

    _cveInputArrayRelease($iArrTrainDescriptors)

    If $bQueryDescriptorsIsArray Then
        _VectorOfMatRelease($vectorOfMatQueryDescriptors)
    EndIf

    _cveInputArrayRelease($iArrQueryDescriptors)
EndFunc   ;==>_cveDescriptorMatcherRadiusMatch1Mat

Func _cveDescriptorMatcherRadiusMatch2(ByRef $matcher, ByRef $queryDescriptors, ByRef $matches, $maxDistance, ByRef $masks, $compactResult)
    ; CVAPI(void) cveDescriptorMatcherRadiusMatch2(cv::DescriptorMatcher* matcher, cv::_InputArray* queryDescriptors, std::vector< std::vector<cv::DMatch> >* matches, float maxDistance, cv::_InputArray* masks, bool compactResult);

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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDescriptorMatcherRadiusMatch2", "ptr", $matcher, "ptr", $queryDescriptors, "ptr", $vecMatches, "float", $maxDistance, "ptr", $masks, "boolean", $compactResult), "cveDescriptorMatcherRadiusMatch2", @error)

    If $bMatchesIsArray Then
        _VectorOfVectorOfDMatchRelease($vecMatches)
    EndIf
EndFunc   ;==>_cveDescriptorMatcherRadiusMatch2

Func _cveDescriptorMatcherRadiusMatch2Mat(ByRef $matcher, ByRef $matQueryDescriptors, ByRef $matches, $maxDistance, ByRef $matMasks, $compactResult)
    ; cveDescriptorMatcherRadiusMatch2 using cv::Mat instead of _*Array

    Local $iArrQueryDescriptors, $vectorOfMatQueryDescriptors, $iArrQueryDescriptorsSize
    Local $bQueryDescriptorsIsArray = VarGetType($matQueryDescriptors) == "Array"

    If $bQueryDescriptorsIsArray Then
        $vectorOfMatQueryDescriptors = _VectorOfMatCreate()

        $iArrQueryDescriptorsSize = UBound($matQueryDescriptors)
        For $i = 0 To $iArrQueryDescriptorsSize - 1
            _VectorOfMatPush($vectorOfMatQueryDescriptors, $matQueryDescriptors[$i])
        Next

        $iArrQueryDescriptors = _cveInputArrayFromVectorOfMat($vectorOfMatQueryDescriptors)
    Else
        $iArrQueryDescriptors = _cveInputArrayFromMat($matQueryDescriptors)
    EndIf

    Local $iArrMasks, $vectorOfMatMasks, $iArrMasksSize
    Local $bMasksIsArray = VarGetType($matMasks) == "Array"

    If $bMasksIsArray Then
        $vectorOfMatMasks = _VectorOfMatCreate()

        $iArrMasksSize = UBound($matMasks)
        For $i = 0 To $iArrMasksSize - 1
            _VectorOfMatPush($vectorOfMatMasks, $matMasks[$i])
        Next

        $iArrMasks = _cveInputArrayFromVectorOfMat($vectorOfMatMasks)
    Else
        $iArrMasks = _cveInputArrayFromMat($matMasks)
    EndIf

    _cveDescriptorMatcherRadiusMatch2($matcher, $iArrQueryDescriptors, $matches, $maxDistance, $iArrMasks, $compactResult)

    If $bMasksIsArray Then
        _VectorOfMatRelease($vectorOfMatMasks)
    EndIf

    _cveInputArrayRelease($iArrMasks)

    If $bQueryDescriptorsIsArray Then
        _VectorOfMatRelease($vectorOfMatQueryDescriptors)
    EndIf

    _cveInputArrayRelease($iArrQueryDescriptors)
EndFunc   ;==>_cveDescriptorMatcherRadiusMatch2Mat

Func _cveBFMatcherCreate($distanceType, $crossCheck, ByRef $m)
    ; CVAPI(cv::BFMatcher*) cveBFMatcherCreate(int distanceType, bool crossCheck, cv::DescriptorMatcher** m);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveBFMatcherCreate", "int", $distanceType, "boolean", $crossCheck, "ptr*", $m), "cveBFMatcherCreate", @error)
EndFunc   ;==>_cveBFMatcherCreate

Func _cveBFMatcherRelease(ByRef $matcher)
    ; CVAPI(void) cveBFMatcherRelease(cv::BFMatcher** matcher);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBFMatcherRelease", "ptr*", $matcher), "cveBFMatcherRelease", @error)
EndFunc   ;==>_cveBFMatcherRelease

Func _cveFlannBasedMatcherCreate(ByRef $indexParams, ByRef $searchParams, ByRef $m)
    ; CVAPI(cv::FlannBasedMatcher*) cveFlannBasedMatcherCreate(cv::flann::IndexParams* indexParams, cv::flann::SearchParams* searchParams, cv::DescriptorMatcher** m);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveFlannBasedMatcherCreate", "ptr", $indexParams, "ptr", $searchParams, "ptr*", $m), "cveFlannBasedMatcherCreate", @error)
EndFunc   ;==>_cveFlannBasedMatcherCreate

Func _cveFlannBasedMatcherRelease(ByRef $matcher)
    ; CVAPI(void) cveFlannBasedMatcherRelease(cv::FlannBasedMatcher** matcher);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFlannBasedMatcherRelease", "ptr*", $matcher), "cveFlannBasedMatcherRelease", @error)
EndFunc   ;==>_cveFlannBasedMatcherRelease

Func _voteForSizeAndOrientation(ByRef $modelKeyPoints, ByRef $observedKeyPoints, ByRef $matches, ByRef $mask, $scaleIncrement, $rotationBins)
    ; CVAPI(int) voteForSizeAndOrientation(std::vector<cv::KeyPoint>* modelKeyPoints, std::vector<cv::KeyPoint>* observedKeyPoints, std::vector< std::vector< cv::DMatch > >* matches, cv::Mat* mask, double scaleIncrement, int rotationBins);

    Local $vecModelKeyPoints, $iArrModelKeyPointsSize
    Local $bModelKeyPointsIsArray = VarGetType($modelKeyPoints) == "Array"

    If $bModelKeyPointsIsArray Then
        $vecModelKeyPoints = _VectorOfKeyPointCreate()

        $iArrModelKeyPointsSize = UBound($modelKeyPoints)
        For $i = 0 To $iArrModelKeyPointsSize - 1
            _VectorOfKeyPointPush($vecModelKeyPoints, $modelKeyPoints[$i])
        Next
    Else
        $vecModelKeyPoints = $modelKeyPoints
    EndIf

    Local $vecObservedKeyPoints, $iArrObservedKeyPointsSize
    Local $bObservedKeyPointsIsArray = VarGetType($observedKeyPoints) == "Array"

    If $bObservedKeyPointsIsArray Then
        $vecObservedKeyPoints = _VectorOfKeyPointCreate()

        $iArrObservedKeyPointsSize = UBound($observedKeyPoints)
        For $i = 0 To $iArrObservedKeyPointsSize - 1
            _VectorOfKeyPointPush($vecObservedKeyPoints, $observedKeyPoints[$i])
        Next
    Else
        $vecObservedKeyPoints = $observedKeyPoints
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "voteForSizeAndOrientation", "ptr", $vecModelKeyPoints, "ptr", $vecObservedKeyPoints, "ptr", $vecMatches, "ptr", $mask, "double", $scaleIncrement, "int", $rotationBins), "voteForSizeAndOrientation", @error)

    If $bMatchesIsArray Then
        _VectorOfVectorOfDMatchRelease($vecMatches)
    EndIf

    If $bObservedKeyPointsIsArray Then
        _VectorOfKeyPointRelease($vecObservedKeyPoints)
    EndIf

    If $bModelKeyPointsIsArray Then
        _VectorOfKeyPointRelease($vecModelKeyPoints)
    EndIf

    Return $retval
EndFunc   ;==>_voteForSizeAndOrientation

Func _CvFeature2DDetectAndCompute(ByRef $feature2D, ByRef $image, ByRef $mask, ByRef $keypoints, ByRef $descriptors, $useProvidedKeyPoints)
    ; CVAPI(void) CvFeature2DDetectAndCompute(cv::Feature2D* feature2D, cv::_InputArray* image, cv::_InputArray* mask, std::vector<cv::KeyPoint>* keypoints, cv::_OutputArray* descriptors, bool useProvidedKeyPoints);

    Local $vecKeypoints, $iArrKeypointsSize
    Local $bKeypointsIsArray = VarGetType($keypoints) == "Array"

    If $bKeypointsIsArray Then
        $vecKeypoints = _VectorOfKeyPointCreate()

        $iArrKeypointsSize = UBound($keypoints)
        For $i = 0 To $iArrKeypointsSize - 1
            _VectorOfKeyPointPush($vecKeypoints, $keypoints[$i])
        Next
    Else
        $vecKeypoints = $keypoints
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "CvFeature2DDetectAndCompute", "ptr", $feature2D, "ptr", $image, "ptr", $mask, "ptr", $vecKeypoints, "ptr", $descriptors, "boolean", $useProvidedKeyPoints), "CvFeature2DDetectAndCompute", @error)

    If $bKeypointsIsArray Then
        _VectorOfKeyPointRelease($vecKeypoints)
    EndIf
EndFunc   ;==>_CvFeature2DDetectAndCompute

Func _CvFeature2DDetectAndComputeMat(ByRef $feature2D, ByRef $matImage, ByRef $matMask, ByRef $keypoints, ByRef $matDescriptors, $useProvidedKeyPoints)
    ; CvFeature2DDetectAndCompute using cv::Mat instead of _*Array

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

    Local $oArrDescriptors, $vectorOfMatDescriptors, $iArrDescriptorsSize
    Local $bDescriptorsIsArray = VarGetType($matDescriptors) == "Array"

    If $bDescriptorsIsArray Then
        $vectorOfMatDescriptors = _VectorOfMatCreate()

        $iArrDescriptorsSize = UBound($matDescriptors)
        For $i = 0 To $iArrDescriptorsSize - 1
            _VectorOfMatPush($vectorOfMatDescriptors, $matDescriptors[$i])
        Next

        $oArrDescriptors = _cveOutputArrayFromVectorOfMat($vectorOfMatDescriptors)
    Else
        $oArrDescriptors = _cveOutputArrayFromMat($matDescriptors)
    EndIf

    _CvFeature2DDetectAndCompute($feature2D, $iArrImage, $iArrMask, $keypoints, $oArrDescriptors, $useProvidedKeyPoints)

    If $bDescriptorsIsArray Then
        _VectorOfMatRelease($vectorOfMatDescriptors)
    EndIf

    _cveOutputArrayRelease($oArrDescriptors)

    If $bMaskIsArray Then
        _VectorOfMatRelease($vectorOfMatMask)
    EndIf

    _cveInputArrayRelease($iArrMask)

    If $bImageIsArray Then
        _VectorOfMatRelease($vectorOfMatImage)
    EndIf

    _cveInputArrayRelease($iArrImage)
EndFunc   ;==>_CvFeature2DDetectAndComputeMat

Func _CvFeature2DDetect(ByRef $feature2D, ByRef $image, ByRef $keypoints, ByRef $mask)
    ; CVAPI(void) CvFeature2DDetect(cv::Feature2D* feature2D, cv::_InputArray* image, std::vector<cv::KeyPoint>* keypoints, cv::_InputArray* mask);

    Local $vecKeypoints, $iArrKeypointsSize
    Local $bKeypointsIsArray = VarGetType($keypoints) == "Array"

    If $bKeypointsIsArray Then
        $vecKeypoints = _VectorOfKeyPointCreate()

        $iArrKeypointsSize = UBound($keypoints)
        For $i = 0 To $iArrKeypointsSize - 1
            _VectorOfKeyPointPush($vecKeypoints, $keypoints[$i])
        Next
    Else
        $vecKeypoints = $keypoints
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "CvFeature2DDetect", "ptr", $feature2D, "ptr", $image, "ptr", $vecKeypoints, "ptr", $mask), "CvFeature2DDetect", @error)

    If $bKeypointsIsArray Then
        _VectorOfKeyPointRelease($vecKeypoints)
    EndIf
EndFunc   ;==>_CvFeature2DDetect

Func _CvFeature2DDetectMat(ByRef $feature2D, ByRef $matImage, ByRef $keypoints, ByRef $matMask)
    ; CvFeature2DDetect using cv::Mat instead of _*Array

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

    _CvFeature2DDetect($feature2D, $iArrImage, $keypoints, $iArrMask)

    If $bMaskIsArray Then
        _VectorOfMatRelease($vectorOfMatMask)
    EndIf

    _cveInputArrayRelease($iArrMask)

    If $bImageIsArray Then
        _VectorOfMatRelease($vectorOfMatImage)
    EndIf

    _cveInputArrayRelease($iArrImage)
EndFunc   ;==>_CvFeature2DDetectMat

Func _CvFeature2DCompute(ByRef $feature2D, ByRef $image, ByRef $keypoints, ByRef $descriptors)
    ; CVAPI(void) CvFeature2DCompute(cv::Feature2D* feature2D, cv::_InputArray* image, std::vector<cv::KeyPoint>* keypoints, cv::_OutputArray* descriptors);

    Local $vecKeypoints, $iArrKeypointsSize
    Local $bKeypointsIsArray = VarGetType($keypoints) == "Array"

    If $bKeypointsIsArray Then
        $vecKeypoints = _VectorOfKeyPointCreate()

        $iArrKeypointsSize = UBound($keypoints)
        For $i = 0 To $iArrKeypointsSize - 1
            _VectorOfKeyPointPush($vecKeypoints, $keypoints[$i])
        Next
    Else
        $vecKeypoints = $keypoints
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "CvFeature2DCompute", "ptr", $feature2D, "ptr", $image, "ptr", $vecKeypoints, "ptr", $descriptors), "CvFeature2DCompute", @error)

    If $bKeypointsIsArray Then
        _VectorOfKeyPointRelease($vecKeypoints)
    EndIf
EndFunc   ;==>_CvFeature2DCompute

Func _CvFeature2DComputeMat(ByRef $feature2D, ByRef $matImage, ByRef $keypoints, ByRef $matDescriptors)
    ; CvFeature2DCompute using cv::Mat instead of _*Array

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

    Local $oArrDescriptors, $vectorOfMatDescriptors, $iArrDescriptorsSize
    Local $bDescriptorsIsArray = VarGetType($matDescriptors) == "Array"

    If $bDescriptorsIsArray Then
        $vectorOfMatDescriptors = _VectorOfMatCreate()

        $iArrDescriptorsSize = UBound($matDescriptors)
        For $i = 0 To $iArrDescriptorsSize - 1
            _VectorOfMatPush($vectorOfMatDescriptors, $matDescriptors[$i])
        Next

        $oArrDescriptors = _cveOutputArrayFromVectorOfMat($vectorOfMatDescriptors)
    Else
        $oArrDescriptors = _cveOutputArrayFromMat($matDescriptors)
    EndIf

    _CvFeature2DCompute($feature2D, $iArrImage, $keypoints, $oArrDescriptors)

    If $bDescriptorsIsArray Then
        _VectorOfMatRelease($vectorOfMatDescriptors)
    EndIf

    _cveOutputArrayRelease($oArrDescriptors)

    If $bImageIsArray Then
        _VectorOfMatRelease($vectorOfMatImage)
    EndIf

    _cveInputArrayRelease($iArrImage)
EndFunc   ;==>_CvFeature2DComputeMat

Func _CvFeature2DGetDescriptorSize(ByRef $feature2D)
    ; CVAPI(int) CvFeature2DGetDescriptorSize(cv::Feature2D* feature2D);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "CvFeature2DGetDescriptorSize", "ptr", $feature2D), "CvFeature2DGetDescriptorSize", @error)
EndFunc   ;==>_CvFeature2DGetDescriptorSize

Func _CvFeature2DGetAlgorithm(ByRef $feature2D)
    ; CVAPI(cv::Algorithm*) CvFeature2DGetAlgorithm(cv::Feature2D* feature2D);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "CvFeature2DGetAlgorithm", "ptr", $feature2D), "CvFeature2DGetAlgorithm", @error)
EndFunc   ;==>_CvFeature2DGetAlgorithm

Func _cveBOWKMeansTrainerCreate($clusterCount, $termcrit, $attempts, $flags)
    ; CVAPI(cv::BOWKMeansTrainer*) cveBOWKMeansTrainerCreate(int clusterCount, const CvTermCriteria* termcrit, int attempts, int flags);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveBOWKMeansTrainerCreate", "int", $clusterCount, "ptr", $termcrit, "int", $attempts, "int", $flags), "cveBOWKMeansTrainerCreate", @error)
EndFunc   ;==>_cveBOWKMeansTrainerCreate

Func _cveBOWKMeansTrainerRelease(ByRef $trainer)
    ; CVAPI(void) cveBOWKMeansTrainerRelease(cv::BOWKMeansTrainer** trainer);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBOWKMeansTrainerRelease", "ptr*", $trainer), "cveBOWKMeansTrainerRelease", @error)
EndFunc   ;==>_cveBOWKMeansTrainerRelease

Func _cveBOWKMeansTrainerGetDescriptorCount(ByRef $trainer)
    ; CVAPI(int) cveBOWKMeansTrainerGetDescriptorCount(cv::BOWKMeansTrainer* trainer);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveBOWKMeansTrainerGetDescriptorCount", "ptr", $trainer), "cveBOWKMeansTrainerGetDescriptorCount", @error)
EndFunc   ;==>_cveBOWKMeansTrainerGetDescriptorCount

Func _cveBOWKMeansTrainerAdd(ByRef $trainer, ByRef $descriptors)
    ; CVAPI(void) cveBOWKMeansTrainerAdd(cv::BOWKMeansTrainer* trainer, cv::Mat* descriptors);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBOWKMeansTrainerAdd", "ptr", $trainer, "ptr", $descriptors), "cveBOWKMeansTrainerAdd", @error)
EndFunc   ;==>_cveBOWKMeansTrainerAdd

Func _cveBOWKMeansTrainerCluster(ByRef $trainer, ByRef $cluster)
    ; CVAPI(void) cveBOWKMeansTrainerCluster(cv::BOWKMeansTrainer* trainer, cv::_OutputArray* cluster);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBOWKMeansTrainerCluster", "ptr", $trainer, "ptr", $cluster), "cveBOWKMeansTrainerCluster", @error)
EndFunc   ;==>_cveBOWKMeansTrainerCluster

Func _cveBOWKMeansTrainerClusterMat(ByRef $trainer, ByRef $matCluster)
    ; cveBOWKMeansTrainerCluster using cv::Mat instead of _*Array

    Local $oArrCluster, $vectorOfMatCluster, $iArrClusterSize
    Local $bClusterIsArray = VarGetType($matCluster) == "Array"

    If $bClusterIsArray Then
        $vectorOfMatCluster = _VectorOfMatCreate()

        $iArrClusterSize = UBound($matCluster)
        For $i = 0 To $iArrClusterSize - 1
            _VectorOfMatPush($vectorOfMatCluster, $matCluster[$i])
        Next

        $oArrCluster = _cveOutputArrayFromVectorOfMat($vectorOfMatCluster)
    Else
        $oArrCluster = _cveOutputArrayFromMat($matCluster)
    EndIf

    _cveBOWKMeansTrainerCluster($trainer, $oArrCluster)

    If $bClusterIsArray Then
        _VectorOfMatRelease($vectorOfMatCluster)
    EndIf

    _cveOutputArrayRelease($oArrCluster)
EndFunc   ;==>_cveBOWKMeansTrainerClusterMat

Func _cveBOWImgDescriptorExtractorCreate(ByRef $descriptorExtractor, ByRef $descriptorMatcher)
    ; CVAPI(cv::BOWImgDescriptorExtractor*) cveBOWImgDescriptorExtractorCreate(cv::Feature2D* descriptorExtractor, cv::DescriptorMatcher* descriptorMatcher);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveBOWImgDescriptorExtractorCreate", "ptr", $descriptorExtractor, "ptr", $descriptorMatcher), "cveBOWImgDescriptorExtractorCreate", @error)
EndFunc   ;==>_cveBOWImgDescriptorExtractorCreate

Func _cveBOWImgDescriptorExtractorRelease(ByRef $descriptorExtractor)
    ; CVAPI(void) cveBOWImgDescriptorExtractorRelease(cv::BOWImgDescriptorExtractor** descriptorExtractor);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBOWImgDescriptorExtractorRelease", "ptr*", $descriptorExtractor), "cveBOWImgDescriptorExtractorRelease", @error)
EndFunc   ;==>_cveBOWImgDescriptorExtractorRelease

Func _cveBOWImgDescriptorExtractorSetVocabulary(ByRef $bowImgDescriptorExtractor, ByRef $vocabulary)
    ; CVAPI(void) cveBOWImgDescriptorExtractorSetVocabulary(cv::BOWImgDescriptorExtractor* bowImgDescriptorExtractor, cv::Mat* vocabulary);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBOWImgDescriptorExtractorSetVocabulary", "ptr", $bowImgDescriptorExtractor, "ptr", $vocabulary), "cveBOWImgDescriptorExtractorSetVocabulary", @error)
EndFunc   ;==>_cveBOWImgDescriptorExtractorSetVocabulary

Func _cveBOWImgDescriptorExtractorCompute(ByRef $bowImgDescriptorExtractor, ByRef $image, ByRef $keypoints, ByRef $imgDescriptor)
    ; CVAPI(void) cveBOWImgDescriptorExtractorCompute(cv::BOWImgDescriptorExtractor* bowImgDescriptorExtractor, cv::_InputArray* image, std::vector<cv::KeyPoint>* keypoints, cv::Mat* imgDescriptor);

    Local $vecKeypoints, $iArrKeypointsSize
    Local $bKeypointsIsArray = VarGetType($keypoints) == "Array"

    If $bKeypointsIsArray Then
        $vecKeypoints = _VectorOfKeyPointCreate()

        $iArrKeypointsSize = UBound($keypoints)
        For $i = 0 To $iArrKeypointsSize - 1
            _VectorOfKeyPointPush($vecKeypoints, $keypoints[$i])
        Next
    Else
        $vecKeypoints = $keypoints
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBOWImgDescriptorExtractorCompute", "ptr", $bowImgDescriptorExtractor, "ptr", $image, "ptr", $vecKeypoints, "ptr", $imgDescriptor), "cveBOWImgDescriptorExtractorCompute", @error)

    If $bKeypointsIsArray Then
        _VectorOfKeyPointRelease($vecKeypoints)
    EndIf
EndFunc   ;==>_cveBOWImgDescriptorExtractorCompute

Func _cveBOWImgDescriptorExtractorComputeMat(ByRef $bowImgDescriptorExtractor, ByRef $matImage, ByRef $keypoints, ByRef $imgDescriptor)
    ; cveBOWImgDescriptorExtractorCompute using cv::Mat instead of _*Array

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

    _cveBOWImgDescriptorExtractorCompute($bowImgDescriptorExtractor, $iArrImage, $keypoints, $imgDescriptor)

    If $bImageIsArray Then
        _VectorOfMatRelease($vectorOfMatImage)
    EndIf

    _cveInputArrayRelease($iArrImage)
EndFunc   ;==>_cveBOWImgDescriptorExtractorComputeMat

Func _cveKAZEDetectorCreate($extended, $upright, $threshold, $octaves, $sublevels, $diffusivity, ByRef $feature2D, ByRef $sharedPtr)
    ; CVAPI(cv::KAZE*) cveKAZEDetectorCreate(bool extended, bool upright, float threshold, int octaves, int sublevels, int diffusivity, cv::Feature2D** feature2D, cv::Ptr<cv::KAZE>** sharedPtr);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveKAZEDetectorCreate", "boolean", $extended, "boolean", $upright, "float", $threshold, "int", $octaves, "int", $sublevels, "int", $diffusivity, "ptr*", $feature2D, "ptr*", $sharedPtr), "cveKAZEDetectorCreate", @error)
EndFunc   ;==>_cveKAZEDetectorCreate

Func _cveKAZEDetectorRelease(ByRef $sharedPtr)
    ; CVAPI(void) cveKAZEDetectorRelease(cv::Ptr<cv::KAZE>** sharedPtr);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveKAZEDetectorRelease", "ptr*", $sharedPtr), "cveKAZEDetectorRelease", @error)
EndFunc   ;==>_cveKAZEDetectorRelease

Func _cveAKAZEDetectorCreate($descriptorType, $descriptorSize, $descriptorChannels, $threshold, $octaves, $sublevels, $diffusivity, ByRef $feature2D, ByRef $sharedPtr)
    ; CVAPI(cv::AKAZE*) cveAKAZEDetectorCreate(int descriptorType, int descriptorSize, int descriptorChannels, float threshold, int octaves, int sublevels, int diffusivity, cv::Feature2D** feature2D, cv::Ptr<cv::AKAZE>** sharedPtr);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveAKAZEDetectorCreate", "int", $descriptorType, "int", $descriptorSize, "int", $descriptorChannels, "float", $threshold, "int", $octaves, "int", $sublevels, "int", $diffusivity, "ptr*", $feature2D, "ptr*", $sharedPtr), "cveAKAZEDetectorCreate", @error)
EndFunc   ;==>_cveAKAZEDetectorCreate

Func _cveAKAZEDetectorRelease(ByRef $sharedPtr)
    ; CVAPI(void) cveAKAZEDetectorRelease(cv::Ptr<cv::AKAZE>** sharedPtr);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveAKAZEDetectorRelease", "ptr*", $sharedPtr), "cveAKAZEDetectorRelease", @error)
EndFunc   ;==>_cveAKAZEDetectorRelease

Func _cveAgastFeatureDetectorCreate($threshold, $nonmaxSuppression, $type, ByRef $feature2D, ByRef $sharedPtr)
    ; CVAPI(cv::AgastFeatureDetector*) cveAgastFeatureDetectorCreate(int threshold, bool nonmaxSuppression, int type, cv::Feature2D** feature2D, cv::Ptr<cv::AgastFeatureDetector>** sharedPtr);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveAgastFeatureDetectorCreate", "int", $threshold, "boolean", $nonmaxSuppression, "int", $type, "ptr*", $feature2D, "ptr*", $sharedPtr), "cveAgastFeatureDetectorCreate", @error)
EndFunc   ;==>_cveAgastFeatureDetectorCreate

Func _cveAgastFeatureDetectorRelease(ByRef $sharedPtr)
    ; CVAPI(void) cveAgastFeatureDetectorRelease(cv::Ptr<cv::AgastFeatureDetector>** sharedPtr);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveAgastFeatureDetectorRelease", "ptr*", $sharedPtr), "cveAgastFeatureDetectorRelease", @error)
EndFunc   ;==>_cveAgastFeatureDetectorRelease

Func _cveSIFTCreate($nFeatures, $nOctaveLayers, $contrastThreshold, $edgeThreshold, $sigma, ByRef $feature2D, ByRef $sharedPtr)
    ; CVAPI(cv::SIFT*) cveSIFTCreate(int nFeatures, int nOctaveLayers, double contrastThreshold, double edgeThreshold, double sigma, cv::Feature2D** feature2D, cv::Ptr<cv::SIFT>** sharedPtr);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveSIFTCreate", "int", $nFeatures, "int", $nOctaveLayers, "double", $contrastThreshold, "double", $edgeThreshold, "double", $sigma, "ptr*", $feature2D, "ptr*", $sharedPtr), "cveSIFTCreate", @error)
EndFunc   ;==>_cveSIFTCreate

Func _cveSIFTRelease(ByRef $sharedPtr)
    ; CVAPI(void) cveSIFTRelease(cv::Ptr<cv::SIFT>** sharedPtr);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSIFTRelease", "ptr*", $sharedPtr), "cveSIFTRelease", @error)
EndFunc   ;==>_cveSIFTRelease