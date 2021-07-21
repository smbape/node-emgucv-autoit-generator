#include-once
#include "..\..\CVEUtils.au3"

Func _cveOrbCreate($numberOfFeatures, $scaleFactor, $nLevels, $edgeThreshold, $firstLevel, $WTA_K, $scoreType, $patchSize, $fastThreshold, $feature2D, $sharedPtr)
    ; CVAPI(cv::ORB*) cveOrbCreate(int numberOfFeatures, float scaleFactor, int nLevels, int edgeThreshold, int firstLevel, int WTA_K, int scoreType, int patchSize, int fastThreshold, cv::Feature2D** feature2D, cv::Ptr<cv::ORB>** sharedPtr);

    Local $bFeature2DDllType
    If VarGetType($feature2D) == "DLLStruct" Then
        $bFeature2DDllType = "struct*"
    Else
        $bFeature2DDllType = "ptr*"
    EndIf

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveOrbCreate", "int", $numberOfFeatures, "float", $scaleFactor, "int", $nLevels, "int", $edgeThreshold, "int", $firstLevel, "int", $WTA_K, "int", $scoreType, "int", $patchSize, "int", $fastThreshold, $bFeature2DDllType, $feature2D, $bSharedPtrDllType, $sharedPtr), "cveOrbCreate", @error)
EndFunc   ;==>_cveOrbCreate

Func _cveOrbRelease($sharedPtr)
    ; CVAPI(void) cveOrbRelease(cv::Ptr<cv::ORB>** sharedPtr);

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveOrbRelease", $bSharedPtrDllType, $sharedPtr), "cveOrbRelease", @error)
EndFunc   ;==>_cveOrbRelease

Func _cveBriskCreate($thresh, $octaves, $patternScale, $feature2D, $sharedPtr)
    ; CVAPI(cv::BRISK*) cveBriskCreate(int thresh, int octaves, float patternScale, cv::Feature2D** feature2D, cv::Ptr<cv::BRISK>** sharedPtr);

    Local $bFeature2DDllType
    If VarGetType($feature2D) == "DLLStruct" Then
        $bFeature2DDllType = "struct*"
    Else
        $bFeature2DDllType = "ptr*"
    EndIf

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveBriskCreate", "int", $thresh, "int", $octaves, "float", $patternScale, $bFeature2DDllType, $feature2D, $bSharedPtrDllType, $sharedPtr), "cveBriskCreate", @error)
EndFunc   ;==>_cveBriskCreate

Func _cveBriskRelease($sharedPtr)
    ; CVAPI(void) cveBriskRelease(cv::Ptr<cv::BRISK>** sharedPtr);

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBriskRelease", $bSharedPtrDllType, $sharedPtr), "cveBriskRelease", @error)
EndFunc   ;==>_cveBriskRelease

Func _cveFASTFeatureDetectorCreate($threshold, $nonmax_supression, $type, $feature2D, $sharedPtr)
    ; CVAPI(cv::FastFeatureDetector*) cveFASTFeatureDetectorCreate(int threshold, bool nonmax_supression, int type, cv::Feature2D** feature2D, cv::Ptr<cv::FastFeatureDetector>** sharedPtr);

    Local $bFeature2DDllType
    If VarGetType($feature2D) == "DLLStruct" Then
        $bFeature2DDllType = "struct*"
    Else
        $bFeature2DDllType = "ptr*"
    EndIf

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveFASTFeatureDetectorCreate", "int", $threshold, "boolean", $nonmax_supression, "int", $type, $bFeature2DDllType, $feature2D, $bSharedPtrDllType, $sharedPtr), "cveFASTFeatureDetectorCreate", @error)
EndFunc   ;==>_cveFASTFeatureDetectorCreate

Func _cveFASTFeatureDetectorRelease($sharedPtr)
    ; CVAPI(void) cveFASTFeatureDetectorRelease(cv::Ptr<cv::FastFeatureDetector>** sharedPtr);

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFASTFeatureDetectorRelease", $bSharedPtrDllType, $sharedPtr), "cveFASTFeatureDetectorRelease", @error)
EndFunc   ;==>_cveFASTFeatureDetectorRelease

Func _cveGFTTDetectorCreate($maxCorners, $qualityLevel, $minDistance, $blockSize, $useHarrisDetector, $k, $feature2D, $sharedPtr)
    ; CVAPI(cv::GFTTDetector*) cveGFTTDetectorCreate(int maxCorners, double qualityLevel, double minDistance, int blockSize, bool useHarrisDetector, double k, cv::Feature2D** feature2D, cv::Ptr<cv::GFTTDetector>** sharedPtr);

    Local $bFeature2DDllType
    If VarGetType($feature2D) == "DLLStruct" Then
        $bFeature2DDllType = "struct*"
    Else
        $bFeature2DDllType = "ptr*"
    EndIf

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGFTTDetectorCreate", "int", $maxCorners, "double", $qualityLevel, "double", $minDistance, "int", $blockSize, "boolean", $useHarrisDetector, "double", $k, $bFeature2DDllType, $feature2D, $bSharedPtrDllType, $sharedPtr), "cveGFTTDetectorCreate", @error)
EndFunc   ;==>_cveGFTTDetectorCreate

Func _cveGFTTDetectorRelease($sharedPtr)
    ; CVAPI(void) cveGFTTDetectorRelease(cv::Ptr<cv::GFTTDetector>** sharedPtr);

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveGFTTDetectorRelease", $bSharedPtrDllType, $sharedPtr), "cveGFTTDetectorRelease", @error)
EndFunc   ;==>_cveGFTTDetectorRelease

Func _cveMserCreate($delta, $minArea, $maxArea, $maxVariation, $minDiversity, $maxEvolution, $areaThreshold, $minMargin, $edgeBlurSize, $feature2D, $sharedPtr)
    ; CVAPI(cv::MSER*) cveMserCreate(int delta, int minArea, int maxArea, double maxVariation, double minDiversity, int maxEvolution, double areaThreshold, double minMargin, int edgeBlurSize, cv::Feature2D** feature2D, cv::Ptr<cv::MSER>** sharedPtr);

    Local $bFeature2DDllType
    If VarGetType($feature2D) == "DLLStruct" Then
        $bFeature2DDllType = "struct*"
    Else
        $bFeature2DDllType = "ptr*"
    EndIf

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveMserCreate", "int", $delta, "int", $minArea, "int", $maxArea, "double", $maxVariation, "double", $minDiversity, "int", $maxEvolution, "double", $areaThreshold, "double", $minMargin, "int", $edgeBlurSize, $bFeature2DDllType, $feature2D, $bSharedPtrDllType, $sharedPtr), "cveMserCreate", @error)
EndFunc   ;==>_cveMserCreate

Func _cveMserDetectRegions($mserPtr, $image, $msers, $bboxes)
    ; CVAPI(void) cveMserDetectRegions(cv::MSER* mserPtr, cv::_InputArray* image, std::vector< std::vector<cv::Point> >* msers, std::vector< cv::Rect >* bboxes);

    Local $bMserPtrDllType
    If VarGetType($mserPtr) == "DLLStruct" Then
        $bMserPtrDllType = "struct*"
    Else
        $bMserPtrDllType = "ptr"
    EndIf

    Local $bImageDllType
    If VarGetType($image) == "DLLStruct" Then
        $bImageDllType = "struct*"
    Else
        $bImageDllType = "ptr"
    EndIf

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

    Local $bMsersDllType
    If VarGetType($msers) == "DLLStruct" Then
        $bMsersDllType = "struct*"
    Else
        $bMsersDllType = "ptr"
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

    Local $bBboxesDllType
    If VarGetType($bboxes) == "DLLStruct" Then
        $bBboxesDllType = "struct*"
    Else
        $bBboxesDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMserDetectRegions", $bMserPtrDllType, $mserPtr, $bImageDllType, $image, $bMsersDllType, $vecMsers, $bBboxesDllType, $vecBboxes), "cveMserDetectRegions", @error)

    If $bBboxesIsArray Then
        _VectorOfRectRelease($vecBboxes)
    EndIf

    If $bMsersIsArray Then
        _VectorOfVectorOfPointRelease($vecMsers)
    EndIf
EndFunc   ;==>_cveMserDetectRegions

Func _cveMserDetectRegionsMat($mserPtr, $matImage, $msers, $bboxes)
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

Func _cveMserRelease($sharedPtr)
    ; CVAPI(void) cveMserRelease(cv::Ptr<cv::MSER>** sharedPtr);

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMserRelease", $bSharedPtrDllType, $sharedPtr), "cveMserRelease", @error)
EndFunc   ;==>_cveMserRelease

Func _cveSimpleBlobDetectorCreate($feature2DPtr, $sharedPtr)
    ; CVAPI(cv::SimpleBlobDetector*) cveSimpleBlobDetectorCreate(cv::Feature2D** feature2DPtr, cv::Ptr<cv::SimpleBlobDetector>** sharedPtr);

    Local $bFeature2DPtrDllType
    If VarGetType($feature2DPtr) == "DLLStruct" Then
        $bFeature2DPtrDllType = "struct*"
    Else
        $bFeature2DPtrDllType = "ptr*"
    EndIf

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveSimpleBlobDetectorCreate", $bFeature2DPtrDllType, $feature2DPtr, $bSharedPtrDllType, $sharedPtr), "cveSimpleBlobDetectorCreate", @error)
EndFunc   ;==>_cveSimpleBlobDetectorCreate

Func _cveSimpleBlobDetectorCreateWithParams($feature2DPtr, $params, $sharedPtr)
    ; CVAPI(cv::SimpleBlobDetector*) cveSimpleBlobDetectorCreateWithParams(cv::Feature2D** feature2DPtr, cv::SimpleBlobDetector::Params* params, cv::Ptr<cv::SimpleBlobDetector>** sharedPtr);

    Local $bFeature2DPtrDllType
    If VarGetType($feature2DPtr) == "DLLStruct" Then
        $bFeature2DPtrDllType = "struct*"
    Else
        $bFeature2DPtrDllType = "ptr*"
    EndIf

    Local $bParamsDllType
    If VarGetType($params) == "DLLStruct" Then
        $bParamsDllType = "struct*"
    Else
        $bParamsDllType = "ptr"
    EndIf

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveSimpleBlobDetectorCreateWithParams", $bFeature2DPtrDllType, $feature2DPtr, $bParamsDllType, $params, $bSharedPtrDllType, $sharedPtr), "cveSimpleBlobDetectorCreateWithParams", @error)
EndFunc   ;==>_cveSimpleBlobDetectorCreateWithParams

Func _cveSimpleBlobDetectorRelease($sharedPtr)
    ; CVAPI(void) cveSimpleBlobDetectorRelease(cv::Ptr<cv::SimpleBlobDetector>** sharedPtr);

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSimpleBlobDetectorRelease", $bSharedPtrDllType, $sharedPtr), "cveSimpleBlobDetectorRelease", @error)
EndFunc   ;==>_cveSimpleBlobDetectorRelease

Func _cveSimpleBlobDetectorParamsCreate()
    ; CVAPI(cv::SimpleBlobDetector::Params*) cveSimpleBlobDetectorParamsCreate();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveSimpleBlobDetectorParamsCreate"), "cveSimpleBlobDetectorParamsCreate", @error)
EndFunc   ;==>_cveSimpleBlobDetectorParamsCreate

Func _cveSimpleBlobDetectorParamsRelease($params)
    ; CVAPI(void) cveSimpleBlobDetectorParamsRelease(cv::SimpleBlobDetector::Params** params);

    Local $bParamsDllType
    If VarGetType($params) == "DLLStruct" Then
        $bParamsDllType = "struct*"
    Else
        $bParamsDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSimpleBlobDetectorParamsRelease", $bParamsDllType, $params), "cveSimpleBlobDetectorParamsRelease", @error)
EndFunc   ;==>_cveSimpleBlobDetectorParamsRelease

Func _drawKeypoints($image, $keypoints, $outImage, $color = _cvScalarAll(-1), $flags = $CV_DRAW_MATCHES_FLAGS_DEFAULT)
    ; CVAPI(void) drawKeypoints(cv::_InputArray* image, const std::vector<cv::KeyPoint>* keypoints, cv::_InputOutputArray* outImage, const CvScalar* color, int flags);

    Local $bImageDllType
    If VarGetType($image) == "DLLStruct" Then
        $bImageDllType = "struct*"
    Else
        $bImageDllType = "ptr"
    EndIf

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

    Local $bKeypointsDllType
    If VarGetType($keypoints) == "DLLStruct" Then
        $bKeypointsDllType = "struct*"
    Else
        $bKeypointsDllType = "ptr"
    EndIf

    Local $bOutImageDllType
    If VarGetType($outImage) == "DLLStruct" Then
        $bOutImageDllType = "struct*"
    Else
        $bOutImageDllType = "ptr"
    EndIf

    Local $bColorDllType
    If VarGetType($color) == "DLLStruct" Then
        $bColorDllType = "struct*"
    Else
        $bColorDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "drawKeypoints", $bImageDllType, $image, $bKeypointsDllType, $vecKeypoints, $bOutImageDllType, $outImage, $bColorDllType, $color, "int", $flags), "drawKeypoints", @error)

    If $bKeypointsIsArray Then
        _VectorOfKeyPointRelease($vecKeypoints)
    EndIf
EndFunc   ;==>_drawKeypoints

Func _drawKeypointsMat($matImage, $keypoints, $matOutImage, $color = _cvScalarAll(-1), $flags = $CV_DRAW_MATCHES_FLAGS_DEFAULT)
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

Func _drawMatchedFeatures1($img1, $keypoints1, $img2, $keypoints2, $matches, $outImg, $matchColor, $singlePointColor, $matchesMask, $flags)
    ; CVAPI(void) drawMatchedFeatures1(cv::_InputArray* img1, const std::vector<cv::KeyPoint>* keypoints1, cv::_InputArray* img2, const std::vector<cv::KeyPoint>* keypoints2, std::vector< cv::DMatch >* matches, cv::_InputOutputArray* outImg, const CvScalar* matchColor, const CvScalar* singlePointColor, std::vector< unsigned char >* matchesMask, int flags);

    Local $bImg1DllType
    If VarGetType($img1) == "DLLStruct" Then
        $bImg1DllType = "struct*"
    Else
        $bImg1DllType = "ptr"
    EndIf

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

    Local $bKeypoints1DllType
    If VarGetType($keypoints1) == "DLLStruct" Then
        $bKeypoints1DllType = "struct*"
    Else
        $bKeypoints1DllType = "ptr"
    EndIf

    Local $bImg2DllType
    If VarGetType($img2) == "DLLStruct" Then
        $bImg2DllType = "struct*"
    Else
        $bImg2DllType = "ptr"
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

    Local $bKeypoints2DllType
    If VarGetType($keypoints2) == "DLLStruct" Then
        $bKeypoints2DllType = "struct*"
    Else
        $bKeypoints2DllType = "ptr"
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

    Local $bMatchesDllType
    If VarGetType($matches) == "DLLStruct" Then
        $bMatchesDllType = "struct*"
    Else
        $bMatchesDllType = "ptr"
    EndIf

    Local $bOutImgDllType
    If VarGetType($outImg) == "DLLStruct" Then
        $bOutImgDllType = "struct*"
    Else
        $bOutImgDllType = "ptr"
    EndIf

    Local $bMatchColorDllType
    If VarGetType($matchColor) == "DLLStruct" Then
        $bMatchColorDllType = "struct*"
    Else
        $bMatchColorDllType = "ptr"
    EndIf

    Local $bSinglePointColorDllType
    If VarGetType($singlePointColor) == "DLLStruct" Then
        $bSinglePointColorDllType = "struct*"
    Else
        $bSinglePointColorDllType = "ptr"
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

    Local $bMatchesMaskDllType
    If VarGetType($matchesMask) == "DLLStruct" Then
        $bMatchesMaskDllType = "struct*"
    Else
        $bMatchesMaskDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "drawMatchedFeatures1", $bImg1DllType, $img1, $bKeypoints1DllType, $vecKeypoints1, $bImg2DllType, $img2, $bKeypoints2DllType, $vecKeypoints2, $bMatchesDllType, $vecMatches, $bOutImgDllType, $outImg, $bMatchColorDllType, $matchColor, $bSinglePointColorDllType, $singlePointColor, $bMatchesMaskDllType, $vecMatchesMask, "int", $flags), "drawMatchedFeatures1", @error)

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

Func _drawMatchedFeatures1Mat($matImg1, $keypoints1, $matImg2, $keypoints2, $matches, $matOutImg, $matchColor, $singlePointColor, $matchesMask, $flags)
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

Func _drawMatchedFeatures2($img1, $keypoints1, $img2, $keypoints2, $matches, $outImg, $matchColor, $singlePointColor, $matchesMask, $flags)
    ; CVAPI(void) drawMatchedFeatures2(cv::_InputArray* img1, const std::vector<cv::KeyPoint>* keypoints1, cv::_InputArray* img2, const std::vector<cv::KeyPoint>* keypoints2, std::vector< std::vector< cv::DMatch > >* matches, cv::_InputOutputArray* outImg, const CvScalar* matchColor, const CvScalar* singlePointColor, std::vector< std::vector< unsigned char > >* matchesMask, int flags);

    Local $bImg1DllType
    If VarGetType($img1) == "DLLStruct" Then
        $bImg1DllType = "struct*"
    Else
        $bImg1DllType = "ptr"
    EndIf

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

    Local $bKeypoints1DllType
    If VarGetType($keypoints1) == "DLLStruct" Then
        $bKeypoints1DllType = "struct*"
    Else
        $bKeypoints1DllType = "ptr"
    EndIf

    Local $bImg2DllType
    If VarGetType($img2) == "DLLStruct" Then
        $bImg2DllType = "struct*"
    Else
        $bImg2DllType = "ptr"
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

    Local $bKeypoints2DllType
    If VarGetType($keypoints2) == "DLLStruct" Then
        $bKeypoints2DllType = "struct*"
    Else
        $bKeypoints2DllType = "ptr"
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

    Local $bMatchesDllType
    If VarGetType($matches) == "DLLStruct" Then
        $bMatchesDllType = "struct*"
    Else
        $bMatchesDllType = "ptr"
    EndIf

    Local $bOutImgDllType
    If VarGetType($outImg) == "DLLStruct" Then
        $bOutImgDllType = "struct*"
    Else
        $bOutImgDllType = "ptr"
    EndIf

    Local $bMatchColorDllType
    If VarGetType($matchColor) == "DLLStruct" Then
        $bMatchColorDllType = "struct*"
    Else
        $bMatchColorDllType = "ptr"
    EndIf

    Local $bSinglePointColorDllType
    If VarGetType($singlePointColor) == "DLLStruct" Then
        $bSinglePointColorDllType = "struct*"
    Else
        $bSinglePointColorDllType = "ptr"
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

    Local $bMatchesMaskDllType
    If VarGetType($matchesMask) == "DLLStruct" Then
        $bMatchesMaskDllType = "struct*"
    Else
        $bMatchesMaskDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "drawMatchedFeatures2", $bImg1DllType, $img1, $bKeypoints1DllType, $vecKeypoints1, $bImg2DllType, $img2, $bKeypoints2DllType, $vecKeypoints2, $bMatchesDllType, $vecMatches, $bOutImgDllType, $outImg, $bMatchColorDllType, $matchColor, $bSinglePointColorDllType, $singlePointColor, $bMatchesMaskDllType, $vecMatchesMask, "int", $flags), "drawMatchedFeatures2", @error)

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

Func _drawMatchedFeatures2Mat($matImg1, $keypoints1, $matImg2, $keypoints2, $matches, $matOutImg, $matchColor, $singlePointColor, $matchesMask, $flags)
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

Func _drawMatchedFeatures3($img1, $keypoints1, $img2, $keypoints2, $matches, $outImg, $matchColor, $singlePointColor, $matchesMask, $flags)
    ; CVAPI(void) drawMatchedFeatures3(cv::_InputArray* img1, const std::vector<cv::KeyPoint>* keypoints1, cv::_InputArray* img2, const std::vector<cv::KeyPoint>* keypoints2, std::vector< std::vector< cv::DMatch > >* matches, cv::_InputOutputArray* outImg, const CvScalar* matchColor, const CvScalar* singlePointColor, cv::_InputArray* matchesMask, int flags);

    Local $bImg1DllType
    If VarGetType($img1) == "DLLStruct" Then
        $bImg1DllType = "struct*"
    Else
        $bImg1DllType = "ptr"
    EndIf

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

    Local $bKeypoints1DllType
    If VarGetType($keypoints1) == "DLLStruct" Then
        $bKeypoints1DllType = "struct*"
    Else
        $bKeypoints1DllType = "ptr"
    EndIf

    Local $bImg2DllType
    If VarGetType($img2) == "DLLStruct" Then
        $bImg2DllType = "struct*"
    Else
        $bImg2DllType = "ptr"
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

    Local $bKeypoints2DllType
    If VarGetType($keypoints2) == "DLLStruct" Then
        $bKeypoints2DllType = "struct*"
    Else
        $bKeypoints2DllType = "ptr"
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

    Local $bMatchesDllType
    If VarGetType($matches) == "DLLStruct" Then
        $bMatchesDllType = "struct*"
    Else
        $bMatchesDllType = "ptr"
    EndIf

    Local $bOutImgDllType
    If VarGetType($outImg) == "DLLStruct" Then
        $bOutImgDllType = "struct*"
    Else
        $bOutImgDllType = "ptr"
    EndIf

    Local $bMatchColorDllType
    If VarGetType($matchColor) == "DLLStruct" Then
        $bMatchColorDllType = "struct*"
    Else
        $bMatchColorDllType = "ptr"
    EndIf

    Local $bSinglePointColorDllType
    If VarGetType($singlePointColor) == "DLLStruct" Then
        $bSinglePointColorDllType = "struct*"
    Else
        $bSinglePointColorDllType = "ptr"
    EndIf

    Local $bMatchesMaskDllType
    If VarGetType($matchesMask) == "DLLStruct" Then
        $bMatchesMaskDllType = "struct*"
    Else
        $bMatchesMaskDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "drawMatchedFeatures3", $bImg1DllType, $img1, $bKeypoints1DllType, $vecKeypoints1, $bImg2DllType, $img2, $bKeypoints2DllType, $vecKeypoints2, $bMatchesDllType, $vecMatches, $bOutImgDllType, $outImg, $bMatchColorDllType, $matchColor, $bSinglePointColorDllType, $singlePointColor, $bMatchesMaskDllType, $matchesMask, "int", $flags), "drawMatchedFeatures3", @error)

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

Func _drawMatchedFeatures3Mat($matImg1, $keypoints1, $matImg2, $keypoints2, $matches, $matOutImg, $matchColor, $singlePointColor, $matMatchesMask, $flags)
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

Func _cveDescriptorMatcherAdd($matcher, $trainDescriptors)
    ; CVAPI(void) cveDescriptorMatcherAdd(cv::DescriptorMatcher* matcher, cv::_InputArray* trainDescriptors);

    Local $bMatcherDllType
    If VarGetType($matcher) == "DLLStruct" Then
        $bMatcherDllType = "struct*"
    Else
        $bMatcherDllType = "ptr"
    EndIf

    Local $bTrainDescriptorsDllType
    If VarGetType($trainDescriptors) == "DLLStruct" Then
        $bTrainDescriptorsDllType = "struct*"
    Else
        $bTrainDescriptorsDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDescriptorMatcherAdd", $bMatcherDllType, $matcher, $bTrainDescriptorsDllType, $trainDescriptors), "cveDescriptorMatcherAdd", @error)
EndFunc   ;==>_cveDescriptorMatcherAdd

Func _cveDescriptorMatcherAddMat($matcher, $matTrainDescriptors)
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

Func _cveDescriptorMatcherKnnMatch1($matcher, $queryDescriptors, $trainDescriptors, $matches, $k, $mask, $compactResult)
    ; CVAPI(void) cveDescriptorMatcherKnnMatch1(cv::DescriptorMatcher* matcher, cv::_InputArray* queryDescriptors, cv::_InputArray* trainDescriptors, std::vector< std::vector< cv::DMatch > >* matches, int k, cv::_InputArray* mask, bool compactResult);

    Local $bMatcherDllType
    If VarGetType($matcher) == "DLLStruct" Then
        $bMatcherDllType = "struct*"
    Else
        $bMatcherDllType = "ptr"
    EndIf

    Local $bQueryDescriptorsDllType
    If VarGetType($queryDescriptors) == "DLLStruct" Then
        $bQueryDescriptorsDllType = "struct*"
    Else
        $bQueryDescriptorsDllType = "ptr"
    EndIf

    Local $bTrainDescriptorsDllType
    If VarGetType($trainDescriptors) == "DLLStruct" Then
        $bTrainDescriptorsDllType = "struct*"
    Else
        $bTrainDescriptorsDllType = "ptr"
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

    Local $bMatchesDllType
    If VarGetType($matches) == "DLLStruct" Then
        $bMatchesDllType = "struct*"
    Else
        $bMatchesDllType = "ptr"
    EndIf

    Local $bMaskDllType
    If VarGetType($mask) == "DLLStruct" Then
        $bMaskDllType = "struct*"
    Else
        $bMaskDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDescriptorMatcherKnnMatch1", $bMatcherDllType, $matcher, $bQueryDescriptorsDllType, $queryDescriptors, $bTrainDescriptorsDllType, $trainDescriptors, $bMatchesDllType, $vecMatches, "int", $k, $bMaskDllType, $mask, "boolean", $compactResult), "cveDescriptorMatcherKnnMatch1", @error)

    If $bMatchesIsArray Then
        _VectorOfVectorOfDMatchRelease($vecMatches)
    EndIf
EndFunc   ;==>_cveDescriptorMatcherKnnMatch1

Func _cveDescriptorMatcherKnnMatch1Mat($matcher, $matQueryDescriptors, $matTrainDescriptors, $matches, $k, $matMask, $compactResult)
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

Func _cveDescriptorMatcherKnnMatch2($matcher, $queryDescriptors, $matches, $k, $mask, $compactResult)
    ; CVAPI(void) cveDescriptorMatcherKnnMatch2(cv::DescriptorMatcher* matcher, cv::_InputArray* queryDescriptors, std::vector< std::vector< cv::DMatch > >* matches, int k, cv::_InputArray* mask, bool compactResult);

    Local $bMatcherDllType
    If VarGetType($matcher) == "DLLStruct" Then
        $bMatcherDllType = "struct*"
    Else
        $bMatcherDllType = "ptr"
    EndIf

    Local $bQueryDescriptorsDllType
    If VarGetType($queryDescriptors) == "DLLStruct" Then
        $bQueryDescriptorsDllType = "struct*"
    Else
        $bQueryDescriptorsDllType = "ptr"
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

    Local $bMatchesDllType
    If VarGetType($matches) == "DLLStruct" Then
        $bMatchesDllType = "struct*"
    Else
        $bMatchesDllType = "ptr"
    EndIf

    Local $bMaskDllType
    If VarGetType($mask) == "DLLStruct" Then
        $bMaskDllType = "struct*"
    Else
        $bMaskDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDescriptorMatcherKnnMatch2", $bMatcherDllType, $matcher, $bQueryDescriptorsDllType, $queryDescriptors, $bMatchesDllType, $vecMatches, "int", $k, $bMaskDllType, $mask, "boolean", $compactResult), "cveDescriptorMatcherKnnMatch2", @error)

    If $bMatchesIsArray Then
        _VectorOfVectorOfDMatchRelease($vecMatches)
    EndIf
EndFunc   ;==>_cveDescriptorMatcherKnnMatch2

Func _cveDescriptorMatcherKnnMatch2Mat($matcher, $matQueryDescriptors, $matches, $k, $matMask, $compactResult)
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

Func _cveDescriptorMatcherGetAlgorithm($matcher)
    ; CVAPI(cv::Algorithm*) cveDescriptorMatcherGetAlgorithm(cv::DescriptorMatcher* matcher);

    Local $bMatcherDllType
    If VarGetType($matcher) == "DLLStruct" Then
        $bMatcherDllType = "struct*"
    Else
        $bMatcherDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveDescriptorMatcherGetAlgorithm", $bMatcherDllType, $matcher), "cveDescriptorMatcherGetAlgorithm", @error)
EndFunc   ;==>_cveDescriptorMatcherGetAlgorithm

Func _cveDescriptorMatcherClear($matcher)
    ; CVAPI(void) cveDescriptorMatcherClear(cv::DescriptorMatcher* matcher);

    Local $bMatcherDllType
    If VarGetType($matcher) == "DLLStruct" Then
        $bMatcherDllType = "struct*"
    Else
        $bMatcherDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDescriptorMatcherClear", $bMatcherDllType, $matcher), "cveDescriptorMatcherClear", @error)
EndFunc   ;==>_cveDescriptorMatcherClear

Func _cveDescriptorMatcherEmpty($matcher)
    ; CVAPI(bool) cveDescriptorMatcherEmpty(cv::DescriptorMatcher* matcher);

    Local $bMatcherDllType
    If VarGetType($matcher) == "DLLStruct" Then
        $bMatcherDllType = "struct*"
    Else
        $bMatcherDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveDescriptorMatcherEmpty", $bMatcherDllType, $matcher), "cveDescriptorMatcherEmpty", @error)
EndFunc   ;==>_cveDescriptorMatcherEmpty

Func _cveDescriptorMatcherIsMaskSupported($matcher)
    ; CVAPI(bool) cveDescriptorMatcherIsMaskSupported(cv::DescriptorMatcher* matcher);

    Local $bMatcherDllType
    If VarGetType($matcher) == "DLLStruct" Then
        $bMatcherDllType = "struct*"
    Else
        $bMatcherDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveDescriptorMatcherIsMaskSupported", $bMatcherDllType, $matcher), "cveDescriptorMatcherIsMaskSupported", @error)
EndFunc   ;==>_cveDescriptorMatcherIsMaskSupported

Func _cveDescriptorMatcherTrain($matcher)
    ; CVAPI(void) cveDescriptorMatcherTrain(cv::DescriptorMatcher* matcher);

    Local $bMatcherDllType
    If VarGetType($matcher) == "DLLStruct" Then
        $bMatcherDllType = "struct*"
    Else
        $bMatcherDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDescriptorMatcherTrain", $bMatcherDllType, $matcher), "cveDescriptorMatcherTrain", @error)
EndFunc   ;==>_cveDescriptorMatcherTrain

Func _cveDescriptorMatcherMatch1($matcher, $queryDescriptors, $trainDescriptors, $matches, $mask)
    ; CVAPI(void) cveDescriptorMatcherMatch1(cv::DescriptorMatcher* matcher, cv::_InputArray* queryDescriptors, cv::_InputArray* trainDescriptors, std::vector< cv::DMatch >* matches, cv::_InputArray* mask);

    Local $bMatcherDllType
    If VarGetType($matcher) == "DLLStruct" Then
        $bMatcherDllType = "struct*"
    Else
        $bMatcherDllType = "ptr"
    EndIf

    Local $bQueryDescriptorsDllType
    If VarGetType($queryDescriptors) == "DLLStruct" Then
        $bQueryDescriptorsDllType = "struct*"
    Else
        $bQueryDescriptorsDllType = "ptr"
    EndIf

    Local $bTrainDescriptorsDllType
    If VarGetType($trainDescriptors) == "DLLStruct" Then
        $bTrainDescriptorsDllType = "struct*"
    Else
        $bTrainDescriptorsDllType = "ptr"
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

    Local $bMatchesDllType
    If VarGetType($matches) == "DLLStruct" Then
        $bMatchesDllType = "struct*"
    Else
        $bMatchesDllType = "ptr"
    EndIf

    Local $bMaskDllType
    If VarGetType($mask) == "DLLStruct" Then
        $bMaskDllType = "struct*"
    Else
        $bMaskDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDescriptorMatcherMatch1", $bMatcherDllType, $matcher, $bQueryDescriptorsDllType, $queryDescriptors, $bTrainDescriptorsDllType, $trainDescriptors, $bMatchesDllType, $vecMatches, $bMaskDllType, $mask), "cveDescriptorMatcherMatch1", @error)

    If $bMatchesIsArray Then
        _VectorOfDMatchRelease($vecMatches)
    EndIf
EndFunc   ;==>_cveDescriptorMatcherMatch1

Func _cveDescriptorMatcherMatch1Mat($matcher, $matQueryDescriptors, $matTrainDescriptors, $matches, $matMask)
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

Func _cveDescriptorMatcherMatch2($matcher, $queryDescriptors, $matches, $masks)
    ; CVAPI(void) cveDescriptorMatcherMatch2(cv::DescriptorMatcher* matcher, cv::_InputArray* queryDescriptors, std::vector< cv::DMatch >* matches, cv::_InputArray* masks);

    Local $bMatcherDllType
    If VarGetType($matcher) == "DLLStruct" Then
        $bMatcherDllType = "struct*"
    Else
        $bMatcherDllType = "ptr"
    EndIf

    Local $bQueryDescriptorsDllType
    If VarGetType($queryDescriptors) == "DLLStruct" Then
        $bQueryDescriptorsDllType = "struct*"
    Else
        $bQueryDescriptorsDllType = "ptr"
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

    Local $bMatchesDllType
    If VarGetType($matches) == "DLLStruct" Then
        $bMatchesDllType = "struct*"
    Else
        $bMatchesDllType = "ptr"
    EndIf

    Local $bMasksDllType
    If VarGetType($masks) == "DLLStruct" Then
        $bMasksDllType = "struct*"
    Else
        $bMasksDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDescriptorMatcherMatch2", $bMatcherDllType, $matcher, $bQueryDescriptorsDllType, $queryDescriptors, $bMatchesDllType, $vecMatches, $bMasksDllType, $masks), "cveDescriptorMatcherMatch2", @error)

    If $bMatchesIsArray Then
        _VectorOfDMatchRelease($vecMatches)
    EndIf
EndFunc   ;==>_cveDescriptorMatcherMatch2

Func _cveDescriptorMatcherMatch2Mat($matcher, $matQueryDescriptors, $matches, $matMasks)
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

Func _cveDescriptorMatcherRadiusMatch1($matcher, $queryDescriptors, $trainDescriptors, $matches, $maxDistance, $mask, $compactResult)
    ; CVAPI(void) cveDescriptorMatcherRadiusMatch1(cv::DescriptorMatcher* matcher, cv::_InputArray* queryDescriptors, cv::_InputArray* trainDescriptors, std::vector< std::vector<cv::DMatch> >* matches, float maxDistance, cv::_InputArray* mask, bool compactResult);

    Local $bMatcherDllType
    If VarGetType($matcher) == "DLLStruct" Then
        $bMatcherDllType = "struct*"
    Else
        $bMatcherDllType = "ptr"
    EndIf

    Local $bQueryDescriptorsDllType
    If VarGetType($queryDescriptors) == "DLLStruct" Then
        $bQueryDescriptorsDllType = "struct*"
    Else
        $bQueryDescriptorsDllType = "ptr"
    EndIf

    Local $bTrainDescriptorsDllType
    If VarGetType($trainDescriptors) == "DLLStruct" Then
        $bTrainDescriptorsDllType = "struct*"
    Else
        $bTrainDescriptorsDllType = "ptr"
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

    Local $bMatchesDllType
    If VarGetType($matches) == "DLLStruct" Then
        $bMatchesDllType = "struct*"
    Else
        $bMatchesDllType = "ptr"
    EndIf

    Local $bMaskDllType
    If VarGetType($mask) == "DLLStruct" Then
        $bMaskDllType = "struct*"
    Else
        $bMaskDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDescriptorMatcherRadiusMatch1", $bMatcherDllType, $matcher, $bQueryDescriptorsDllType, $queryDescriptors, $bTrainDescriptorsDllType, $trainDescriptors, $bMatchesDllType, $vecMatches, "float", $maxDistance, $bMaskDllType, $mask, "boolean", $compactResult), "cveDescriptorMatcherRadiusMatch1", @error)

    If $bMatchesIsArray Then
        _VectorOfVectorOfDMatchRelease($vecMatches)
    EndIf
EndFunc   ;==>_cveDescriptorMatcherRadiusMatch1

Func _cveDescriptorMatcherRadiusMatch1Mat($matcher, $matQueryDescriptors, $matTrainDescriptors, $matches, $maxDistance, $matMask, $compactResult)
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

Func _cveDescriptorMatcherRadiusMatch2($matcher, $queryDescriptors, $matches, $maxDistance, $masks, $compactResult)
    ; CVAPI(void) cveDescriptorMatcherRadiusMatch2(cv::DescriptorMatcher* matcher, cv::_InputArray* queryDescriptors, std::vector< std::vector<cv::DMatch> >* matches, float maxDistance, cv::_InputArray* masks, bool compactResult);

    Local $bMatcherDllType
    If VarGetType($matcher) == "DLLStruct" Then
        $bMatcherDllType = "struct*"
    Else
        $bMatcherDllType = "ptr"
    EndIf

    Local $bQueryDescriptorsDllType
    If VarGetType($queryDescriptors) == "DLLStruct" Then
        $bQueryDescriptorsDllType = "struct*"
    Else
        $bQueryDescriptorsDllType = "ptr"
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

    Local $bMatchesDllType
    If VarGetType($matches) == "DLLStruct" Then
        $bMatchesDllType = "struct*"
    Else
        $bMatchesDllType = "ptr"
    EndIf

    Local $bMasksDllType
    If VarGetType($masks) == "DLLStruct" Then
        $bMasksDllType = "struct*"
    Else
        $bMasksDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDescriptorMatcherRadiusMatch2", $bMatcherDllType, $matcher, $bQueryDescriptorsDllType, $queryDescriptors, $bMatchesDllType, $vecMatches, "float", $maxDistance, $bMasksDllType, $masks, "boolean", $compactResult), "cveDescriptorMatcherRadiusMatch2", @error)

    If $bMatchesIsArray Then
        _VectorOfVectorOfDMatchRelease($vecMatches)
    EndIf
EndFunc   ;==>_cveDescriptorMatcherRadiusMatch2

Func _cveDescriptorMatcherRadiusMatch2Mat($matcher, $matQueryDescriptors, $matches, $maxDistance, $matMasks, $compactResult)
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

Func _cveBFMatcherCreate($distanceType, $crossCheck, $m)
    ; CVAPI(cv::BFMatcher*) cveBFMatcherCreate(int distanceType, bool crossCheck, cv::DescriptorMatcher** m);

    Local $bMDllType
    If VarGetType($m) == "DLLStruct" Then
        $bMDllType = "struct*"
    Else
        $bMDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveBFMatcherCreate", "int", $distanceType, "boolean", $crossCheck, $bMDllType, $m), "cveBFMatcherCreate", @error)
EndFunc   ;==>_cveBFMatcherCreate

Func _cveBFMatcherRelease($matcher)
    ; CVAPI(void) cveBFMatcherRelease(cv::BFMatcher** matcher);

    Local $bMatcherDllType
    If VarGetType($matcher) == "DLLStruct" Then
        $bMatcherDllType = "struct*"
    Else
        $bMatcherDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBFMatcherRelease", $bMatcherDllType, $matcher), "cveBFMatcherRelease", @error)
EndFunc   ;==>_cveBFMatcherRelease

Func _cveFlannBasedMatcherCreate($indexParams, $searchParams, $m)
    ; CVAPI(cv::FlannBasedMatcher*) cveFlannBasedMatcherCreate(cv::flann::IndexParams* indexParams, cv::flann::SearchParams* searchParams, cv::DescriptorMatcher** m);

    Local $bIndexParamsDllType
    If VarGetType($indexParams) == "DLLStruct" Then
        $bIndexParamsDllType = "struct*"
    Else
        $bIndexParamsDllType = "ptr"
    EndIf

    Local $bSearchParamsDllType
    If VarGetType($searchParams) == "DLLStruct" Then
        $bSearchParamsDllType = "struct*"
    Else
        $bSearchParamsDllType = "ptr"
    EndIf

    Local $bMDllType
    If VarGetType($m) == "DLLStruct" Then
        $bMDllType = "struct*"
    Else
        $bMDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveFlannBasedMatcherCreate", $bIndexParamsDllType, $indexParams, $bSearchParamsDllType, $searchParams, $bMDllType, $m), "cveFlannBasedMatcherCreate", @error)
EndFunc   ;==>_cveFlannBasedMatcherCreate

Func _cveFlannBasedMatcherRelease($matcher)
    ; CVAPI(void) cveFlannBasedMatcherRelease(cv::FlannBasedMatcher** matcher);

    Local $bMatcherDllType
    If VarGetType($matcher) == "DLLStruct" Then
        $bMatcherDllType = "struct*"
    Else
        $bMatcherDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFlannBasedMatcherRelease", $bMatcherDllType, $matcher), "cveFlannBasedMatcherRelease", @error)
EndFunc   ;==>_cveFlannBasedMatcherRelease

Func _voteForSizeAndOrientation($modelKeyPoints, $observedKeyPoints, $matches, $mask, $scaleIncrement, $rotationBins)
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

    Local $bModelKeyPointsDllType
    If VarGetType($modelKeyPoints) == "DLLStruct" Then
        $bModelKeyPointsDllType = "struct*"
    Else
        $bModelKeyPointsDllType = "ptr"
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

    Local $bObservedKeyPointsDllType
    If VarGetType($observedKeyPoints) == "DLLStruct" Then
        $bObservedKeyPointsDllType = "struct*"
    Else
        $bObservedKeyPointsDllType = "ptr"
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

    Local $bMatchesDllType
    If VarGetType($matches) == "DLLStruct" Then
        $bMatchesDllType = "struct*"
    Else
        $bMatchesDllType = "ptr"
    EndIf

    Local $bMaskDllType
    If VarGetType($mask) == "DLLStruct" Then
        $bMaskDllType = "struct*"
    Else
        $bMaskDllType = "ptr"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "voteForSizeAndOrientation", $bModelKeyPointsDllType, $vecModelKeyPoints, $bObservedKeyPointsDllType, $vecObservedKeyPoints, $bMatchesDllType, $vecMatches, $bMaskDllType, $mask, "double", $scaleIncrement, "int", $rotationBins), "voteForSizeAndOrientation", @error)

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

Func _CvFeature2DDetectAndCompute($feature2D, $image, $mask, $keypoints, $descriptors, $useProvidedKeyPoints)
    ; CVAPI(void) CvFeature2DDetectAndCompute(cv::Feature2D* feature2D, cv::_InputArray* image, cv::_InputArray* mask, std::vector<cv::KeyPoint>* keypoints, cv::_OutputArray* descriptors, bool useProvidedKeyPoints);

    Local $bFeature2DDllType
    If VarGetType($feature2D) == "DLLStruct" Then
        $bFeature2DDllType = "struct*"
    Else
        $bFeature2DDllType = "ptr"
    EndIf

    Local $bImageDllType
    If VarGetType($image) == "DLLStruct" Then
        $bImageDllType = "struct*"
    Else
        $bImageDllType = "ptr"
    EndIf

    Local $bMaskDllType
    If VarGetType($mask) == "DLLStruct" Then
        $bMaskDllType = "struct*"
    Else
        $bMaskDllType = "ptr"
    EndIf

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

    Local $bKeypointsDllType
    If VarGetType($keypoints) == "DLLStruct" Then
        $bKeypointsDllType = "struct*"
    Else
        $bKeypointsDllType = "ptr"
    EndIf

    Local $bDescriptorsDllType
    If VarGetType($descriptors) == "DLLStruct" Then
        $bDescriptorsDllType = "struct*"
    Else
        $bDescriptorsDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "CvFeature2DDetectAndCompute", $bFeature2DDllType, $feature2D, $bImageDllType, $image, $bMaskDllType, $mask, $bKeypointsDllType, $vecKeypoints, $bDescriptorsDllType, $descriptors, "boolean", $useProvidedKeyPoints), "CvFeature2DDetectAndCompute", @error)

    If $bKeypointsIsArray Then
        _VectorOfKeyPointRelease($vecKeypoints)
    EndIf
EndFunc   ;==>_CvFeature2DDetectAndCompute

Func _CvFeature2DDetectAndComputeMat($feature2D, $matImage, $matMask, $keypoints, $matDescriptors, $useProvidedKeyPoints)
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

Func _CvFeature2DDetect($feature2D, $image, $keypoints, $mask)
    ; CVAPI(void) CvFeature2DDetect(cv::Feature2D* feature2D, cv::_InputArray* image, std::vector<cv::KeyPoint>* keypoints, cv::_InputArray* mask);

    Local $bFeature2DDllType
    If VarGetType($feature2D) == "DLLStruct" Then
        $bFeature2DDllType = "struct*"
    Else
        $bFeature2DDllType = "ptr"
    EndIf

    Local $bImageDllType
    If VarGetType($image) == "DLLStruct" Then
        $bImageDllType = "struct*"
    Else
        $bImageDllType = "ptr"
    EndIf

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

    Local $bKeypointsDllType
    If VarGetType($keypoints) == "DLLStruct" Then
        $bKeypointsDllType = "struct*"
    Else
        $bKeypointsDllType = "ptr"
    EndIf

    Local $bMaskDllType
    If VarGetType($mask) == "DLLStruct" Then
        $bMaskDllType = "struct*"
    Else
        $bMaskDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "CvFeature2DDetect", $bFeature2DDllType, $feature2D, $bImageDllType, $image, $bKeypointsDllType, $vecKeypoints, $bMaskDllType, $mask), "CvFeature2DDetect", @error)

    If $bKeypointsIsArray Then
        _VectorOfKeyPointRelease($vecKeypoints)
    EndIf
EndFunc   ;==>_CvFeature2DDetect

Func _CvFeature2DDetectMat($feature2D, $matImage, $keypoints, $matMask)
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

Func _CvFeature2DCompute($feature2D, $image, $keypoints, $descriptors)
    ; CVAPI(void) CvFeature2DCompute(cv::Feature2D* feature2D, cv::_InputArray* image, std::vector<cv::KeyPoint>* keypoints, cv::_OutputArray* descriptors);

    Local $bFeature2DDllType
    If VarGetType($feature2D) == "DLLStruct" Then
        $bFeature2DDllType = "struct*"
    Else
        $bFeature2DDllType = "ptr"
    EndIf

    Local $bImageDllType
    If VarGetType($image) == "DLLStruct" Then
        $bImageDllType = "struct*"
    Else
        $bImageDllType = "ptr"
    EndIf

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

    Local $bKeypointsDllType
    If VarGetType($keypoints) == "DLLStruct" Then
        $bKeypointsDllType = "struct*"
    Else
        $bKeypointsDllType = "ptr"
    EndIf

    Local $bDescriptorsDllType
    If VarGetType($descriptors) == "DLLStruct" Then
        $bDescriptorsDllType = "struct*"
    Else
        $bDescriptorsDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "CvFeature2DCompute", $bFeature2DDllType, $feature2D, $bImageDllType, $image, $bKeypointsDllType, $vecKeypoints, $bDescriptorsDllType, $descriptors), "CvFeature2DCompute", @error)

    If $bKeypointsIsArray Then
        _VectorOfKeyPointRelease($vecKeypoints)
    EndIf
EndFunc   ;==>_CvFeature2DCompute

Func _CvFeature2DComputeMat($feature2D, $matImage, $keypoints, $matDescriptors)
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

Func _CvFeature2DGetDescriptorSize($feature2D)
    ; CVAPI(int) CvFeature2DGetDescriptorSize(cv::Feature2D* feature2D);

    Local $bFeature2DDllType
    If VarGetType($feature2D) == "DLLStruct" Then
        $bFeature2DDllType = "struct*"
    Else
        $bFeature2DDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "CvFeature2DGetDescriptorSize", $bFeature2DDllType, $feature2D), "CvFeature2DGetDescriptorSize", @error)
EndFunc   ;==>_CvFeature2DGetDescriptorSize

Func _CvFeature2DGetAlgorithm($feature2D)
    ; CVAPI(cv::Algorithm*) CvFeature2DGetAlgorithm(cv::Feature2D* feature2D);

    Local $bFeature2DDllType
    If VarGetType($feature2D) == "DLLStruct" Then
        $bFeature2DDllType = "struct*"
    Else
        $bFeature2DDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "CvFeature2DGetAlgorithm", $bFeature2DDllType, $feature2D), "CvFeature2DGetAlgorithm", @error)
EndFunc   ;==>_CvFeature2DGetAlgorithm

Func _cveBOWKMeansTrainerCreate($clusterCount, $termcrit, $attempts, $flags)
    ; CVAPI(cv::BOWKMeansTrainer*) cveBOWKMeansTrainerCreate(int clusterCount, const CvTermCriteria* termcrit, int attempts, int flags);

    Local $bTermcritDllType
    If VarGetType($termcrit) == "DLLStruct" Then
        $bTermcritDllType = "struct*"
    Else
        $bTermcritDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveBOWKMeansTrainerCreate", "int", $clusterCount, $bTermcritDllType, $termcrit, "int", $attempts, "int", $flags), "cveBOWKMeansTrainerCreate", @error)
EndFunc   ;==>_cveBOWKMeansTrainerCreate

Func _cveBOWKMeansTrainerRelease($trainer)
    ; CVAPI(void) cveBOWKMeansTrainerRelease(cv::BOWKMeansTrainer** trainer);

    Local $bTrainerDllType
    If VarGetType($trainer) == "DLLStruct" Then
        $bTrainerDllType = "struct*"
    Else
        $bTrainerDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBOWKMeansTrainerRelease", $bTrainerDllType, $trainer), "cveBOWKMeansTrainerRelease", @error)
EndFunc   ;==>_cveBOWKMeansTrainerRelease

Func _cveBOWKMeansTrainerGetDescriptorCount($trainer)
    ; CVAPI(int) cveBOWKMeansTrainerGetDescriptorCount(cv::BOWKMeansTrainer* trainer);

    Local $bTrainerDllType
    If VarGetType($trainer) == "DLLStruct" Then
        $bTrainerDllType = "struct*"
    Else
        $bTrainerDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveBOWKMeansTrainerGetDescriptorCount", $bTrainerDllType, $trainer), "cveBOWKMeansTrainerGetDescriptorCount", @error)
EndFunc   ;==>_cveBOWKMeansTrainerGetDescriptorCount

Func _cveBOWKMeansTrainerAdd($trainer, $descriptors)
    ; CVAPI(void) cveBOWKMeansTrainerAdd(cv::BOWKMeansTrainer* trainer, cv::Mat* descriptors);

    Local $bTrainerDllType
    If VarGetType($trainer) == "DLLStruct" Then
        $bTrainerDllType = "struct*"
    Else
        $bTrainerDllType = "ptr"
    EndIf

    Local $bDescriptorsDllType
    If VarGetType($descriptors) == "DLLStruct" Then
        $bDescriptorsDllType = "struct*"
    Else
        $bDescriptorsDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBOWKMeansTrainerAdd", $bTrainerDllType, $trainer, $bDescriptorsDllType, $descriptors), "cveBOWKMeansTrainerAdd", @error)
EndFunc   ;==>_cveBOWKMeansTrainerAdd

Func _cveBOWKMeansTrainerCluster($trainer, $cluster)
    ; CVAPI(void) cveBOWKMeansTrainerCluster(cv::BOWKMeansTrainer* trainer, cv::_OutputArray* cluster);

    Local $bTrainerDllType
    If VarGetType($trainer) == "DLLStruct" Then
        $bTrainerDllType = "struct*"
    Else
        $bTrainerDllType = "ptr"
    EndIf

    Local $bClusterDllType
    If VarGetType($cluster) == "DLLStruct" Then
        $bClusterDllType = "struct*"
    Else
        $bClusterDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBOWKMeansTrainerCluster", $bTrainerDllType, $trainer, $bClusterDllType, $cluster), "cveBOWKMeansTrainerCluster", @error)
EndFunc   ;==>_cveBOWKMeansTrainerCluster

Func _cveBOWKMeansTrainerClusterMat($trainer, $matCluster)
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

Func _cveBOWImgDescriptorExtractorCreate($descriptorExtractor, $descriptorMatcher)
    ; CVAPI(cv::BOWImgDescriptorExtractor*) cveBOWImgDescriptorExtractorCreate(cv::Feature2D* descriptorExtractor, cv::DescriptorMatcher* descriptorMatcher);

    Local $bDescriptorExtractorDllType
    If VarGetType($descriptorExtractor) == "DLLStruct" Then
        $bDescriptorExtractorDllType = "struct*"
    Else
        $bDescriptorExtractorDllType = "ptr"
    EndIf

    Local $bDescriptorMatcherDllType
    If VarGetType($descriptorMatcher) == "DLLStruct" Then
        $bDescriptorMatcherDllType = "struct*"
    Else
        $bDescriptorMatcherDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveBOWImgDescriptorExtractorCreate", $bDescriptorExtractorDllType, $descriptorExtractor, $bDescriptorMatcherDllType, $descriptorMatcher), "cveBOWImgDescriptorExtractorCreate", @error)
EndFunc   ;==>_cveBOWImgDescriptorExtractorCreate

Func _cveBOWImgDescriptorExtractorRelease($descriptorExtractor)
    ; CVAPI(void) cveBOWImgDescriptorExtractorRelease(cv::BOWImgDescriptorExtractor** descriptorExtractor);

    Local $bDescriptorExtractorDllType
    If VarGetType($descriptorExtractor) == "DLLStruct" Then
        $bDescriptorExtractorDllType = "struct*"
    Else
        $bDescriptorExtractorDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBOWImgDescriptorExtractorRelease", $bDescriptorExtractorDllType, $descriptorExtractor), "cveBOWImgDescriptorExtractorRelease", @error)
EndFunc   ;==>_cveBOWImgDescriptorExtractorRelease

Func _cveBOWImgDescriptorExtractorSetVocabulary($bowImgDescriptorExtractor, $vocabulary)
    ; CVAPI(void) cveBOWImgDescriptorExtractorSetVocabulary(cv::BOWImgDescriptorExtractor* bowImgDescriptorExtractor, cv::Mat* vocabulary);

    Local $bBowImgDescriptorExtractorDllType
    If VarGetType($bowImgDescriptorExtractor) == "DLLStruct" Then
        $bBowImgDescriptorExtractorDllType = "struct*"
    Else
        $bBowImgDescriptorExtractorDllType = "ptr"
    EndIf

    Local $bVocabularyDllType
    If VarGetType($vocabulary) == "DLLStruct" Then
        $bVocabularyDllType = "struct*"
    Else
        $bVocabularyDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBOWImgDescriptorExtractorSetVocabulary", $bBowImgDescriptorExtractorDllType, $bowImgDescriptorExtractor, $bVocabularyDllType, $vocabulary), "cveBOWImgDescriptorExtractorSetVocabulary", @error)
EndFunc   ;==>_cveBOWImgDescriptorExtractorSetVocabulary

Func _cveBOWImgDescriptorExtractorCompute($bowImgDescriptorExtractor, $image, $keypoints, $imgDescriptor)
    ; CVAPI(void) cveBOWImgDescriptorExtractorCompute(cv::BOWImgDescriptorExtractor* bowImgDescriptorExtractor, cv::_InputArray* image, std::vector<cv::KeyPoint>* keypoints, cv::Mat* imgDescriptor);

    Local $bBowImgDescriptorExtractorDllType
    If VarGetType($bowImgDescriptorExtractor) == "DLLStruct" Then
        $bBowImgDescriptorExtractorDllType = "struct*"
    Else
        $bBowImgDescriptorExtractorDllType = "ptr"
    EndIf

    Local $bImageDllType
    If VarGetType($image) == "DLLStruct" Then
        $bImageDllType = "struct*"
    Else
        $bImageDllType = "ptr"
    EndIf

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

    Local $bKeypointsDllType
    If VarGetType($keypoints) == "DLLStruct" Then
        $bKeypointsDllType = "struct*"
    Else
        $bKeypointsDllType = "ptr"
    EndIf

    Local $bImgDescriptorDllType
    If VarGetType($imgDescriptor) == "DLLStruct" Then
        $bImgDescriptorDllType = "struct*"
    Else
        $bImgDescriptorDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBOWImgDescriptorExtractorCompute", $bBowImgDescriptorExtractorDllType, $bowImgDescriptorExtractor, $bImageDllType, $image, $bKeypointsDllType, $vecKeypoints, $bImgDescriptorDllType, $imgDescriptor), "cveBOWImgDescriptorExtractorCompute", @error)

    If $bKeypointsIsArray Then
        _VectorOfKeyPointRelease($vecKeypoints)
    EndIf
EndFunc   ;==>_cveBOWImgDescriptorExtractorCompute

Func _cveBOWImgDescriptorExtractorComputeMat($bowImgDescriptorExtractor, $matImage, $keypoints, $imgDescriptor)
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

Func _cveKAZEDetectorCreate($extended, $upright, $threshold, $octaves, $sublevels, $diffusivity, $feature2D, $sharedPtr)
    ; CVAPI(cv::KAZE*) cveKAZEDetectorCreate(bool extended, bool upright, float threshold, int octaves, int sublevels, int diffusivity, cv::Feature2D** feature2D, cv::Ptr<cv::KAZE>** sharedPtr);

    Local $bFeature2DDllType
    If VarGetType($feature2D) == "DLLStruct" Then
        $bFeature2DDllType = "struct*"
    Else
        $bFeature2DDllType = "ptr*"
    EndIf

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveKAZEDetectorCreate", "boolean", $extended, "boolean", $upright, "float", $threshold, "int", $octaves, "int", $sublevels, "int", $diffusivity, $bFeature2DDllType, $feature2D, $bSharedPtrDllType, $sharedPtr), "cveKAZEDetectorCreate", @error)
EndFunc   ;==>_cveKAZEDetectorCreate

Func _cveKAZEDetectorRelease($sharedPtr)
    ; CVAPI(void) cveKAZEDetectorRelease(cv::Ptr<cv::KAZE>** sharedPtr);

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveKAZEDetectorRelease", $bSharedPtrDllType, $sharedPtr), "cveKAZEDetectorRelease", @error)
EndFunc   ;==>_cveKAZEDetectorRelease

Func _cveAKAZEDetectorCreate($descriptorType, $descriptorSize, $descriptorChannels, $threshold, $octaves, $sublevels, $diffusivity, $feature2D, $sharedPtr)
    ; CVAPI(cv::AKAZE*) cveAKAZEDetectorCreate(int descriptorType, int descriptorSize, int descriptorChannels, float threshold, int octaves, int sublevels, int diffusivity, cv::Feature2D** feature2D, cv::Ptr<cv::AKAZE>** sharedPtr);

    Local $bFeature2DDllType
    If VarGetType($feature2D) == "DLLStruct" Then
        $bFeature2DDllType = "struct*"
    Else
        $bFeature2DDllType = "ptr*"
    EndIf

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveAKAZEDetectorCreate", "int", $descriptorType, "int", $descriptorSize, "int", $descriptorChannels, "float", $threshold, "int", $octaves, "int", $sublevels, "int", $diffusivity, $bFeature2DDllType, $feature2D, $bSharedPtrDllType, $sharedPtr), "cveAKAZEDetectorCreate", @error)
EndFunc   ;==>_cveAKAZEDetectorCreate

Func _cveAKAZEDetectorRelease($sharedPtr)
    ; CVAPI(void) cveAKAZEDetectorRelease(cv::Ptr<cv::AKAZE>** sharedPtr);

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveAKAZEDetectorRelease", $bSharedPtrDllType, $sharedPtr), "cveAKAZEDetectorRelease", @error)
EndFunc   ;==>_cveAKAZEDetectorRelease

Func _cveAgastFeatureDetectorCreate($threshold, $nonmaxSuppression, $type, $feature2D, $sharedPtr)
    ; CVAPI(cv::AgastFeatureDetector*) cveAgastFeatureDetectorCreate(int threshold, bool nonmaxSuppression, int type, cv::Feature2D** feature2D, cv::Ptr<cv::AgastFeatureDetector>** sharedPtr);

    Local $bFeature2DDllType
    If VarGetType($feature2D) == "DLLStruct" Then
        $bFeature2DDllType = "struct*"
    Else
        $bFeature2DDllType = "ptr*"
    EndIf

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveAgastFeatureDetectorCreate", "int", $threshold, "boolean", $nonmaxSuppression, "int", $type, $bFeature2DDllType, $feature2D, $bSharedPtrDllType, $sharedPtr), "cveAgastFeatureDetectorCreate", @error)
EndFunc   ;==>_cveAgastFeatureDetectorCreate

Func _cveAgastFeatureDetectorRelease($sharedPtr)
    ; CVAPI(void) cveAgastFeatureDetectorRelease(cv::Ptr<cv::AgastFeatureDetector>** sharedPtr);

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveAgastFeatureDetectorRelease", $bSharedPtrDllType, $sharedPtr), "cveAgastFeatureDetectorRelease", @error)
EndFunc   ;==>_cveAgastFeatureDetectorRelease

Func _cveSIFTCreate($nFeatures, $nOctaveLayers, $contrastThreshold, $edgeThreshold, $sigma, $feature2D, $sharedPtr)
    ; CVAPI(cv::SIFT*) cveSIFTCreate(int nFeatures, int nOctaveLayers, double contrastThreshold, double edgeThreshold, double sigma, cv::Feature2D** feature2D, cv::Ptr<cv::SIFT>** sharedPtr);

    Local $bFeature2DDllType
    If VarGetType($feature2D) == "DLLStruct" Then
        $bFeature2DDllType = "struct*"
    Else
        $bFeature2DDllType = "ptr*"
    EndIf

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveSIFTCreate", "int", $nFeatures, "int", $nOctaveLayers, "double", $contrastThreshold, "double", $edgeThreshold, "double", $sigma, $bFeature2DDllType, $feature2D, $bSharedPtrDllType, $sharedPtr), "cveSIFTCreate", @error)
EndFunc   ;==>_cveSIFTCreate

Func _cveSIFTRelease($sharedPtr)
    ; CVAPI(void) cveSIFTRelease(cv::Ptr<cv::SIFT>** sharedPtr);

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSIFTRelease", $bSharedPtrDllType, $sharedPtr), "cveSIFTRelease", @error)
EndFunc   ;==>_cveSIFTRelease