#include-once
#include "..\..\CVEUtils.au3"

Func _cveOrbCreate($numberOfFeatures, $scaleFactor, $nLevels, $edgeThreshold, $firstLevel, $WTA_K, $scoreType, $patchSize, $fastThreshold, $feature2D, $sharedPtr)
    ; CVAPI(cv::ORB*) cveOrbCreate(int numberOfFeatures, float scaleFactor, int nLevels, int edgeThreshold, int firstLevel, int WTA_K, int scoreType, int patchSize, int fastThreshold, cv::Feature2D** feature2D, cv::Ptr<cv::ORB>** sharedPtr);

    Local $sFeature2DDllType
    If IsDllStruct($feature2D) Then
        $sFeature2DDllType = "struct*"
    ElseIf $feature2D == Null Then
        $sFeature2DDllType = "ptr"
    Else
        $sFeature2DDllType = "ptr*"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveOrbCreate", "int", $numberOfFeatures, "float", $scaleFactor, "int", $nLevels, "int", $edgeThreshold, "int", $firstLevel, "int", $WTA_K, "int", $scoreType, "int", $patchSize, "int", $fastThreshold, $sFeature2DDllType, $feature2D, $sSharedPtrDllType, $sharedPtr), "cveOrbCreate", @error)
EndFunc   ;==>_cveOrbCreate

Func _cveOrbRelease($sharedPtr)
    ; CVAPI(void) cveOrbRelease(cv::Ptr<cv::ORB>** sharedPtr);

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveOrbRelease", $sSharedPtrDllType, $sharedPtr), "cveOrbRelease", @error)
EndFunc   ;==>_cveOrbRelease

Func _cveBriskCreate($thresh, $octaves, $patternScale, $feature2D, $sharedPtr)
    ; CVAPI(cv::BRISK*) cveBriskCreate(int thresh, int octaves, float patternScale, cv::Feature2D** feature2D, cv::Ptr<cv::BRISK>** sharedPtr);

    Local $sFeature2DDllType
    If IsDllStruct($feature2D) Then
        $sFeature2DDllType = "struct*"
    ElseIf $feature2D == Null Then
        $sFeature2DDllType = "ptr"
    Else
        $sFeature2DDllType = "ptr*"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveBriskCreate", "int", $thresh, "int", $octaves, "float", $patternScale, $sFeature2DDllType, $feature2D, $sSharedPtrDllType, $sharedPtr), "cveBriskCreate", @error)
EndFunc   ;==>_cveBriskCreate

Func _cveBriskRelease($sharedPtr)
    ; CVAPI(void) cveBriskRelease(cv::Ptr<cv::BRISK>** sharedPtr);

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBriskRelease", $sSharedPtrDllType, $sharedPtr), "cveBriskRelease", @error)
EndFunc   ;==>_cveBriskRelease

Func _cveFASTFeatureDetectorCreate($threshold, $nonmax_supression, $type, $feature2D, $sharedPtr)
    ; CVAPI(cv::FastFeatureDetector*) cveFASTFeatureDetectorCreate(int threshold, bool nonmax_supression, int type, cv::Feature2D** feature2D, cv::Ptr<cv::FastFeatureDetector>** sharedPtr);

    Local $sFeature2DDllType
    If IsDllStruct($feature2D) Then
        $sFeature2DDllType = "struct*"
    ElseIf $feature2D == Null Then
        $sFeature2DDllType = "ptr"
    Else
        $sFeature2DDllType = "ptr*"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveFASTFeatureDetectorCreate", "int", $threshold, "boolean", $nonmax_supression, "int", $type, $sFeature2DDllType, $feature2D, $sSharedPtrDllType, $sharedPtr), "cveFASTFeatureDetectorCreate", @error)
EndFunc   ;==>_cveFASTFeatureDetectorCreate

Func _cveFASTFeatureDetectorRelease($sharedPtr)
    ; CVAPI(void) cveFASTFeatureDetectorRelease(cv::Ptr<cv::FastFeatureDetector>** sharedPtr);

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFASTFeatureDetectorRelease", $sSharedPtrDllType, $sharedPtr), "cveFASTFeatureDetectorRelease", @error)
EndFunc   ;==>_cveFASTFeatureDetectorRelease

Func _cveGFTTDetectorCreate($maxCorners, $qualityLevel, $minDistance, $blockSize, $useHarrisDetector, $k, $feature2D, $sharedPtr)
    ; CVAPI(cv::GFTTDetector*) cveGFTTDetectorCreate(int maxCorners, double qualityLevel, double minDistance, int blockSize, bool useHarrisDetector, double k, cv::Feature2D** feature2D, cv::Ptr<cv::GFTTDetector>** sharedPtr);

    Local $sFeature2DDllType
    If IsDllStruct($feature2D) Then
        $sFeature2DDllType = "struct*"
    ElseIf $feature2D == Null Then
        $sFeature2DDllType = "ptr"
    Else
        $sFeature2DDllType = "ptr*"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGFTTDetectorCreate", "int", $maxCorners, "double", $qualityLevel, "double", $minDistance, "int", $blockSize, "boolean", $useHarrisDetector, "double", $k, $sFeature2DDllType, $feature2D, $sSharedPtrDllType, $sharedPtr), "cveGFTTDetectorCreate", @error)
EndFunc   ;==>_cveGFTTDetectorCreate

Func _cveGFTTDetectorRelease($sharedPtr)
    ; CVAPI(void) cveGFTTDetectorRelease(cv::Ptr<cv::GFTTDetector>** sharedPtr);

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveGFTTDetectorRelease", $sSharedPtrDllType, $sharedPtr), "cveGFTTDetectorRelease", @error)
EndFunc   ;==>_cveGFTTDetectorRelease

Func _cveMserCreate($delta, $minArea, $maxArea, $maxVariation, $minDiversity, $maxEvolution, $areaThreshold, $minMargin, $edgeBlurSize, $feature2D, $sharedPtr)
    ; CVAPI(cv::MSER*) cveMserCreate(int delta, int minArea, int maxArea, double maxVariation, double minDiversity, int maxEvolution, double areaThreshold, double minMargin, int edgeBlurSize, cv::Feature2D** feature2D, cv::Ptr<cv::MSER>** sharedPtr);

    Local $sFeature2DDllType
    If IsDllStruct($feature2D) Then
        $sFeature2DDllType = "struct*"
    ElseIf $feature2D == Null Then
        $sFeature2DDllType = "ptr"
    Else
        $sFeature2DDllType = "ptr*"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveMserCreate", "int", $delta, "int", $minArea, "int", $maxArea, "double", $maxVariation, "double", $minDiversity, "int", $maxEvolution, "double", $areaThreshold, "double", $minMargin, "int", $edgeBlurSize, $sFeature2DDllType, $feature2D, $sSharedPtrDllType, $sharedPtr), "cveMserCreate", @error)
EndFunc   ;==>_cveMserCreate

Func _cveMserDetectRegions($mserPtr, $image, $msers, $bboxes)
    ; CVAPI(void) cveMserDetectRegions(cv::MSER* mserPtr, cv::_InputArray* image, std::vector<std::vector<cv::Point>>* msers, std::vector<cv::Rect>* bboxes);

    Local $sMserPtrDllType
    If IsDllStruct($mserPtr) Then
        $sMserPtrDllType = "struct*"
    Else
        $sMserPtrDllType = "ptr"
    EndIf

    Local $sImageDllType
    If IsDllStruct($image) Then
        $sImageDllType = "struct*"
    Else
        $sImageDllType = "ptr"
    EndIf

    Local $vecMsers, $iArrMsersSize
    Local $bMsersIsArray = IsArray($msers)

    If $bMsersIsArray Then
        $vecMsers = _VectorOfVectorOfPointCreate()

        $iArrMsersSize = UBound($msers)
        For $i = 0 To $iArrMsersSize - 1
            _VectorOfVectorOfPointPush($vecMsers, $msers[$i])
        Next
    Else
        $vecMsers = $msers
    EndIf

    Local $sMsersDllType
    If IsDllStruct($msers) Then
        $sMsersDllType = "struct*"
    Else
        $sMsersDllType = "ptr"
    EndIf

    Local $vecBboxes, $iArrBboxesSize
    Local $bBboxesIsArray = IsArray($bboxes)

    If $bBboxesIsArray Then
        $vecBboxes = _VectorOfRectCreate()

        $iArrBboxesSize = UBound($bboxes)
        For $i = 0 To $iArrBboxesSize - 1
            _VectorOfRectPush($vecBboxes, $bboxes[$i])
        Next
    Else
        $vecBboxes = $bboxes
    EndIf

    Local $sBboxesDllType
    If IsDllStruct($bboxes) Then
        $sBboxesDllType = "struct*"
    Else
        $sBboxesDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMserDetectRegions", $sMserPtrDllType, $mserPtr, $sImageDllType, $image, $sMsersDllType, $vecMsers, $sBboxesDllType, $vecBboxes), "cveMserDetectRegions", @error)

    If $bBboxesIsArray Then
        _VectorOfRectRelease($vecBboxes)
    EndIf

    If $bMsersIsArray Then
        _VectorOfVectorOfPointRelease($vecMsers)
    EndIf
EndFunc   ;==>_cveMserDetectRegions

Func _cveMserDetectRegionsTyped($mserPtr, $typeOfImage, $image, $msers, $bboxes)

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

    _cveMserDetectRegions($mserPtr, $iArrImage, $msers, $bboxes)

    If $bImageIsArray Then
        Call("_VectorOf" & $typeOfImage & "Release", $vectorImage)
    EndIf

    If $typeOfImage <> Default Then
        _cveInputArrayRelease($iArrImage)
        If $bImageCreate Then
            Call("_cve" & $typeOfImage & "Release", $image)
        EndIf
    EndIf
EndFunc   ;==>_cveMserDetectRegionsTyped

Func _cveMserDetectRegionsMat($mserPtr, $image, $msers, $bboxes)
    ; cveMserDetectRegions using cv::Mat instead of _*Array
    _cveMserDetectRegionsTyped($mserPtr, "Mat", $image, $msers, $bboxes)
EndFunc   ;==>_cveMserDetectRegionsMat

Func _cveMserRelease($sharedPtr)
    ; CVAPI(void) cveMserRelease(cv::Ptr<cv::MSER>** sharedPtr);

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMserRelease", $sSharedPtrDllType, $sharedPtr), "cveMserRelease", @error)
EndFunc   ;==>_cveMserRelease

Func _cveSimpleBlobDetectorCreate($feature2DPtr, $sharedPtr)
    ; CVAPI(cv::SimpleBlobDetector*) cveSimpleBlobDetectorCreate(cv::Feature2D** feature2DPtr, cv::Ptr<cv::SimpleBlobDetector>** sharedPtr);

    Local $sFeature2DPtrDllType
    If IsDllStruct($feature2DPtr) Then
        $sFeature2DPtrDllType = "struct*"
    ElseIf $feature2DPtr == Null Then
        $sFeature2DPtrDllType = "ptr"
    Else
        $sFeature2DPtrDllType = "ptr*"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveSimpleBlobDetectorCreate", $sFeature2DPtrDllType, $feature2DPtr, $sSharedPtrDllType, $sharedPtr), "cveSimpleBlobDetectorCreate", @error)
EndFunc   ;==>_cveSimpleBlobDetectorCreate

Func _cveSimpleBlobDetectorCreateWithParams($feature2DPtr, $params, $sharedPtr)
    ; CVAPI(cv::SimpleBlobDetector*) cveSimpleBlobDetectorCreateWithParams(cv::Feature2D** feature2DPtr, cv::SimpleBlobDetector::Params* params, cv::Ptr<cv::SimpleBlobDetector>** sharedPtr);

    Local $sFeature2DPtrDllType
    If IsDllStruct($feature2DPtr) Then
        $sFeature2DPtrDllType = "struct*"
    ElseIf $feature2DPtr == Null Then
        $sFeature2DPtrDllType = "ptr"
    Else
        $sFeature2DPtrDllType = "ptr*"
    EndIf

    Local $sParamsDllType
    If IsDllStruct($params) Then
        $sParamsDllType = "struct*"
    Else
        $sParamsDllType = "ptr"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveSimpleBlobDetectorCreateWithParams", $sFeature2DPtrDllType, $feature2DPtr, $sParamsDllType, $params, $sSharedPtrDllType, $sharedPtr), "cveSimpleBlobDetectorCreateWithParams", @error)
EndFunc   ;==>_cveSimpleBlobDetectorCreateWithParams

Func _cveSimpleBlobDetectorRelease($sharedPtr)
    ; CVAPI(void) cveSimpleBlobDetectorRelease(cv::Ptr<cv::SimpleBlobDetector>** sharedPtr);

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSimpleBlobDetectorRelease", $sSharedPtrDllType, $sharedPtr), "cveSimpleBlobDetectorRelease", @error)
EndFunc   ;==>_cveSimpleBlobDetectorRelease

Func _cveSimpleBlobDetectorParamsCreate()
    ; CVAPI(cv::SimpleBlobDetector::Params*) cveSimpleBlobDetectorParamsCreate();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveSimpleBlobDetectorParamsCreate"), "cveSimpleBlobDetectorParamsCreate", @error)
EndFunc   ;==>_cveSimpleBlobDetectorParamsCreate

Func _cveSimpleBlobDetectorParamsRelease($params)
    ; CVAPI(void) cveSimpleBlobDetectorParamsRelease(cv::SimpleBlobDetector::Params** params);

    Local $sParamsDllType
    If IsDllStruct($params) Then
        $sParamsDllType = "struct*"
    ElseIf $params == Null Then
        $sParamsDllType = "ptr"
    Else
        $sParamsDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSimpleBlobDetectorParamsRelease", $sParamsDllType, $params), "cveSimpleBlobDetectorParamsRelease", @error)
EndFunc   ;==>_cveSimpleBlobDetectorParamsRelease

Func _drawKeypoints($image, $keypoints, $outImage, $color = _cvScalarAll(-1), $flags = $CV_DRAW_MATCHES_FLAGS_DEFAULT)
    ; CVAPI(void) drawKeypoints(cv::_InputArray* image, const std::vector<cv::KeyPoint>* keypoints, cv::_InputOutputArray* outImage, const CvScalar* color, int flags);

    Local $sImageDllType
    If IsDllStruct($image) Then
        $sImageDllType = "struct*"
    Else
        $sImageDllType = "ptr"
    EndIf

    Local $vecKeypoints, $iArrKeypointsSize
    Local $bKeypointsIsArray = IsArray($keypoints)

    If $bKeypointsIsArray Then
        $vecKeypoints = _VectorOfKeyPointCreate()

        $iArrKeypointsSize = UBound($keypoints)
        For $i = 0 To $iArrKeypointsSize - 1
            _VectorOfKeyPointPush($vecKeypoints, $keypoints[$i])
        Next
    Else
        $vecKeypoints = $keypoints
    EndIf

    Local $sKeypointsDllType
    If IsDllStruct($keypoints) Then
        $sKeypointsDllType = "struct*"
    Else
        $sKeypointsDllType = "ptr"
    EndIf

    Local $sOutImageDllType
    If IsDllStruct($outImage) Then
        $sOutImageDllType = "struct*"
    Else
        $sOutImageDllType = "ptr"
    EndIf

    Local $sColorDllType
    If IsDllStruct($color) Then
        $sColorDllType = "struct*"
    Else
        $sColorDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "drawKeypoints", $sImageDllType, $image, $sKeypointsDllType, $vecKeypoints, $sOutImageDllType, $outImage, $sColorDllType, $color, "int", $flags), "drawKeypoints", @error)

    If $bKeypointsIsArray Then
        _VectorOfKeyPointRelease($vecKeypoints)
    EndIf
EndFunc   ;==>_drawKeypoints

Func _drawKeypointsTyped($typeOfImage, $image, $keypoints, $typeOfOutImage, $outImage, $color = _cvScalarAll(-1), $flags = $CV_DRAW_MATCHES_FLAGS_DEFAULT)

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

    Local $ioArrOutImage, $vectorOutImage, $iArrOutImageSize
    Local $bOutImageIsArray = IsArray($outImage)
    Local $bOutImageCreate = IsDllStruct($outImage) And $typeOfOutImage == "Scalar"

    If $typeOfOutImage == Default Then
        $ioArrOutImage = $outImage
    ElseIf $bOutImageIsArray Then
        $vectorOutImage = Call("_VectorOf" & $typeOfOutImage & "Create")

        $iArrOutImageSize = UBound($outImage)
        For $i = 0 To $iArrOutImageSize - 1
            Call("_VectorOf" & $typeOfOutImage & "Push", $vectorOutImage, $outImage[$i])
        Next

        $ioArrOutImage = Call("_cveInputOutputArrayFromVectorOf" & $typeOfOutImage, $vectorOutImage)
    Else
        If $bOutImageCreate Then
            $outImage = Call("_cve" & $typeOfOutImage & "Create", $outImage)
        EndIf
        $ioArrOutImage = Call("_cveInputOutputArrayFrom" & $typeOfOutImage, $outImage)
    EndIf

    _drawKeypoints($iArrImage, $keypoints, $ioArrOutImage, $color, $flags)

    If $bOutImageIsArray Then
        Call("_VectorOf" & $typeOfOutImage & "Release", $vectorOutImage)
    EndIf

    If $typeOfOutImage <> Default Then
        _cveInputOutputArrayRelease($ioArrOutImage)
        If $bOutImageCreate Then
            Call("_cve" & $typeOfOutImage & "Release", $outImage)
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
EndFunc   ;==>_drawKeypointsTyped

Func _drawKeypointsMat($image, $keypoints, $outImage, $color = _cvScalarAll(-1), $flags = $CV_DRAW_MATCHES_FLAGS_DEFAULT)
    ; drawKeypoints using cv::Mat instead of _*Array
    _drawKeypointsTyped("Mat", $image, $keypoints, "Mat", $outImage, $color, $flags)
EndFunc   ;==>_drawKeypointsMat

Func _drawMatchedFeatures1($img1, $keypoints1, $img2, $keypoints2, $matches, $outImg, $matchColor, $singlePointColor, $matchesMask, $flags)
    ; CVAPI(void) drawMatchedFeatures1(cv::_InputArray* img1, const std::vector<cv::KeyPoint>* keypoints1, cv::_InputArray* img2, const std::vector<cv::KeyPoint>* keypoints2, std::vector<cv::DMatch>* matches, cv::_InputOutputArray* outImg, const CvScalar* matchColor, const CvScalar* singlePointColor, std::vector<unsigned char>* matchesMask, int flags);

    Local $sImg1DllType
    If IsDllStruct($img1) Then
        $sImg1DllType = "struct*"
    Else
        $sImg1DllType = "ptr"
    EndIf

    Local $vecKeypoints1, $iArrKeypoints1Size
    Local $bKeypoints1IsArray = IsArray($keypoints1)

    If $bKeypoints1IsArray Then
        $vecKeypoints1 = _VectorOfKeyPointCreate()

        $iArrKeypoints1Size = UBound($keypoints1)
        For $i = 0 To $iArrKeypoints1Size - 1
            _VectorOfKeyPointPush($vecKeypoints1, $keypoints1[$i])
        Next
    Else
        $vecKeypoints1 = $keypoints1
    EndIf

    Local $sKeypoints1DllType
    If IsDllStruct($keypoints1) Then
        $sKeypoints1DllType = "struct*"
    Else
        $sKeypoints1DllType = "ptr"
    EndIf

    Local $sImg2DllType
    If IsDllStruct($img2) Then
        $sImg2DllType = "struct*"
    Else
        $sImg2DllType = "ptr"
    EndIf

    Local $vecKeypoints2, $iArrKeypoints2Size
    Local $bKeypoints2IsArray = IsArray($keypoints2)

    If $bKeypoints2IsArray Then
        $vecKeypoints2 = _VectorOfKeyPointCreate()

        $iArrKeypoints2Size = UBound($keypoints2)
        For $i = 0 To $iArrKeypoints2Size - 1
            _VectorOfKeyPointPush($vecKeypoints2, $keypoints2[$i])
        Next
    Else
        $vecKeypoints2 = $keypoints2
    EndIf

    Local $sKeypoints2DllType
    If IsDllStruct($keypoints2) Then
        $sKeypoints2DllType = "struct*"
    Else
        $sKeypoints2DllType = "ptr"
    EndIf

    Local $vecMatches, $iArrMatchesSize
    Local $bMatchesIsArray = IsArray($matches)

    If $bMatchesIsArray Then
        $vecMatches = _VectorOfDMatchCreate()

        $iArrMatchesSize = UBound($matches)
        For $i = 0 To $iArrMatchesSize - 1
            _VectorOfDMatchPush($vecMatches, $matches[$i])
        Next
    Else
        $vecMatches = $matches
    EndIf

    Local $sMatchesDllType
    If IsDllStruct($matches) Then
        $sMatchesDllType = "struct*"
    Else
        $sMatchesDllType = "ptr"
    EndIf

    Local $sOutImgDllType
    If IsDllStruct($outImg) Then
        $sOutImgDllType = "struct*"
    Else
        $sOutImgDllType = "ptr"
    EndIf

    Local $sMatchColorDllType
    If IsDllStruct($matchColor) Then
        $sMatchColorDllType = "struct*"
    Else
        $sMatchColorDllType = "ptr"
    EndIf

    Local $sSinglePointColorDllType
    If IsDllStruct($singlePointColor) Then
        $sSinglePointColorDllType = "struct*"
    Else
        $sSinglePointColorDllType = "ptr"
    EndIf

    Local $vecMatchesMask, $iArrMatchesMaskSize
    Local $bMatchesMaskIsArray = IsArray($matchesMask)

    If $bMatchesMaskIsArray Then
        $vecMatchesMask = _VectorOfByteCreate()

        $iArrMatchesMaskSize = UBound($matchesMask)
        For $i = 0 To $iArrMatchesMaskSize - 1
            _VectorOfBytePush($vecMatchesMask, $matchesMask[$i])
        Next
    Else
        $vecMatchesMask = $matchesMask
    EndIf

    Local $sMatchesMaskDllType
    If IsDllStruct($matchesMask) Then
        $sMatchesMaskDllType = "struct*"
    Else
        $sMatchesMaskDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "drawMatchedFeatures1", $sImg1DllType, $img1, $sKeypoints1DllType, $vecKeypoints1, $sImg2DllType, $img2, $sKeypoints2DllType, $vecKeypoints2, $sMatchesDllType, $vecMatches, $sOutImgDllType, $outImg, $sMatchColorDllType, $matchColor, $sSinglePointColorDllType, $singlePointColor, $sMatchesMaskDllType, $vecMatchesMask, "int", $flags), "drawMatchedFeatures1", @error)

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

Func _drawMatchedFeatures1Typed($typeOfImg1, $img1, $keypoints1, $typeOfImg2, $img2, $keypoints2, $matches, $typeOfOutImg, $outImg, $matchColor, $singlePointColor, $matchesMask, $flags)

    Local $iArrImg1, $vectorImg1, $iArrImg1Size
    Local $bImg1IsArray = IsArray($img1)
    Local $bImg1Create = IsDllStruct($img1) And $typeOfImg1 == "Scalar"

    If $typeOfImg1 == Default Then
        $iArrImg1 = $img1
    ElseIf $bImg1IsArray Then
        $vectorImg1 = Call("_VectorOf" & $typeOfImg1 & "Create")

        $iArrImg1Size = UBound($img1)
        For $i = 0 To $iArrImg1Size - 1
            Call("_VectorOf" & $typeOfImg1 & "Push", $vectorImg1, $img1[$i])
        Next

        $iArrImg1 = Call("_cveInputArrayFromVectorOf" & $typeOfImg1, $vectorImg1)
    Else
        If $bImg1Create Then
            $img1 = Call("_cve" & $typeOfImg1 & "Create", $img1)
        EndIf
        $iArrImg1 = Call("_cveInputArrayFrom" & $typeOfImg1, $img1)
    EndIf

    Local $iArrImg2, $vectorImg2, $iArrImg2Size
    Local $bImg2IsArray = IsArray($img2)
    Local $bImg2Create = IsDllStruct($img2) And $typeOfImg2 == "Scalar"

    If $typeOfImg2 == Default Then
        $iArrImg2 = $img2
    ElseIf $bImg2IsArray Then
        $vectorImg2 = Call("_VectorOf" & $typeOfImg2 & "Create")

        $iArrImg2Size = UBound($img2)
        For $i = 0 To $iArrImg2Size - 1
            Call("_VectorOf" & $typeOfImg2 & "Push", $vectorImg2, $img2[$i])
        Next

        $iArrImg2 = Call("_cveInputArrayFromVectorOf" & $typeOfImg2, $vectorImg2)
    Else
        If $bImg2Create Then
            $img2 = Call("_cve" & $typeOfImg2 & "Create", $img2)
        EndIf
        $iArrImg2 = Call("_cveInputArrayFrom" & $typeOfImg2, $img2)
    EndIf

    Local $ioArrOutImg, $vectorOutImg, $iArrOutImgSize
    Local $bOutImgIsArray = IsArray($outImg)
    Local $bOutImgCreate = IsDllStruct($outImg) And $typeOfOutImg == "Scalar"

    If $typeOfOutImg == Default Then
        $ioArrOutImg = $outImg
    ElseIf $bOutImgIsArray Then
        $vectorOutImg = Call("_VectorOf" & $typeOfOutImg & "Create")

        $iArrOutImgSize = UBound($outImg)
        For $i = 0 To $iArrOutImgSize - 1
            Call("_VectorOf" & $typeOfOutImg & "Push", $vectorOutImg, $outImg[$i])
        Next

        $ioArrOutImg = Call("_cveInputOutputArrayFromVectorOf" & $typeOfOutImg, $vectorOutImg)
    Else
        If $bOutImgCreate Then
            $outImg = Call("_cve" & $typeOfOutImg & "Create", $outImg)
        EndIf
        $ioArrOutImg = Call("_cveInputOutputArrayFrom" & $typeOfOutImg, $outImg)
    EndIf

    _drawMatchedFeatures1($iArrImg1, $keypoints1, $iArrImg2, $keypoints2, $matches, $ioArrOutImg, $matchColor, $singlePointColor, $matchesMask, $flags)

    If $bOutImgIsArray Then
        Call("_VectorOf" & $typeOfOutImg & "Release", $vectorOutImg)
    EndIf

    If $typeOfOutImg <> Default Then
        _cveInputOutputArrayRelease($ioArrOutImg)
        If $bOutImgCreate Then
            Call("_cve" & $typeOfOutImg & "Release", $outImg)
        EndIf
    EndIf

    If $bImg2IsArray Then
        Call("_VectorOf" & $typeOfImg2 & "Release", $vectorImg2)
    EndIf

    If $typeOfImg2 <> Default Then
        _cveInputArrayRelease($iArrImg2)
        If $bImg2Create Then
            Call("_cve" & $typeOfImg2 & "Release", $img2)
        EndIf
    EndIf

    If $bImg1IsArray Then
        Call("_VectorOf" & $typeOfImg1 & "Release", $vectorImg1)
    EndIf

    If $typeOfImg1 <> Default Then
        _cveInputArrayRelease($iArrImg1)
        If $bImg1Create Then
            Call("_cve" & $typeOfImg1 & "Release", $img1)
        EndIf
    EndIf
EndFunc   ;==>_drawMatchedFeatures1Typed

Func _drawMatchedFeatures1Mat($img1, $keypoints1, $img2, $keypoints2, $matches, $outImg, $matchColor, $singlePointColor, $matchesMask, $flags)
    ; drawMatchedFeatures1 using cv::Mat instead of _*Array
    _drawMatchedFeatures1Typed("Mat", $img1, $keypoints1, "Mat", $img2, $keypoints2, $matches, "Mat", $outImg, $matchColor, $singlePointColor, $matchesMask, $flags)
EndFunc   ;==>_drawMatchedFeatures1Mat

Func _drawMatchedFeatures2($img1, $keypoints1, $img2, $keypoints2, $matches, $outImg, $matchColor, $singlePointColor, $matchesMask, $flags)
    ; CVAPI(void) drawMatchedFeatures2(cv::_InputArray* img1, const std::vector<cv::KeyPoint>* keypoints1, cv::_InputArray* img2, const std::vector<cv::KeyPoint>* keypoints2, std::vector<std::vector<cv::DMatch>>* matches, cv::_InputOutputArray* outImg, const CvScalar* matchColor, const CvScalar* singlePointColor, std::vector<std::vector<unsigned char>>* matchesMask, int flags);

    Local $sImg1DllType
    If IsDllStruct($img1) Then
        $sImg1DllType = "struct*"
    Else
        $sImg1DllType = "ptr"
    EndIf

    Local $vecKeypoints1, $iArrKeypoints1Size
    Local $bKeypoints1IsArray = IsArray($keypoints1)

    If $bKeypoints1IsArray Then
        $vecKeypoints1 = _VectorOfKeyPointCreate()

        $iArrKeypoints1Size = UBound($keypoints1)
        For $i = 0 To $iArrKeypoints1Size - 1
            _VectorOfKeyPointPush($vecKeypoints1, $keypoints1[$i])
        Next
    Else
        $vecKeypoints1 = $keypoints1
    EndIf

    Local $sKeypoints1DllType
    If IsDllStruct($keypoints1) Then
        $sKeypoints1DllType = "struct*"
    Else
        $sKeypoints1DllType = "ptr"
    EndIf

    Local $sImg2DllType
    If IsDllStruct($img2) Then
        $sImg2DllType = "struct*"
    Else
        $sImg2DllType = "ptr"
    EndIf

    Local $vecKeypoints2, $iArrKeypoints2Size
    Local $bKeypoints2IsArray = IsArray($keypoints2)

    If $bKeypoints2IsArray Then
        $vecKeypoints2 = _VectorOfKeyPointCreate()

        $iArrKeypoints2Size = UBound($keypoints2)
        For $i = 0 To $iArrKeypoints2Size - 1
            _VectorOfKeyPointPush($vecKeypoints2, $keypoints2[$i])
        Next
    Else
        $vecKeypoints2 = $keypoints2
    EndIf

    Local $sKeypoints2DllType
    If IsDllStruct($keypoints2) Then
        $sKeypoints2DllType = "struct*"
    Else
        $sKeypoints2DllType = "ptr"
    EndIf

    Local $vecMatches, $iArrMatchesSize
    Local $bMatchesIsArray = IsArray($matches)

    If $bMatchesIsArray Then
        $vecMatches = _VectorOfVectorOfDMatchCreate()

        $iArrMatchesSize = UBound($matches)
        For $i = 0 To $iArrMatchesSize - 1
            _VectorOfVectorOfDMatchPush($vecMatches, $matches[$i])
        Next
    Else
        $vecMatches = $matches
    EndIf

    Local $sMatchesDllType
    If IsDllStruct($matches) Then
        $sMatchesDllType = "struct*"
    Else
        $sMatchesDllType = "ptr"
    EndIf

    Local $sOutImgDllType
    If IsDllStruct($outImg) Then
        $sOutImgDllType = "struct*"
    Else
        $sOutImgDllType = "ptr"
    EndIf

    Local $sMatchColorDllType
    If IsDllStruct($matchColor) Then
        $sMatchColorDllType = "struct*"
    Else
        $sMatchColorDllType = "ptr"
    EndIf

    Local $sSinglePointColorDllType
    If IsDllStruct($singlePointColor) Then
        $sSinglePointColorDllType = "struct*"
    Else
        $sSinglePointColorDllType = "ptr"
    EndIf

    Local $vecMatchesMask, $iArrMatchesMaskSize
    Local $bMatchesMaskIsArray = IsArray($matchesMask)

    If $bMatchesMaskIsArray Then
        $vecMatchesMask = _VectorOfVectorOfByteCreate()

        $iArrMatchesMaskSize = UBound($matchesMask)
        For $i = 0 To $iArrMatchesMaskSize - 1
            _VectorOfVectorOfBytePush($vecMatchesMask, $matchesMask[$i])
        Next
    Else
        $vecMatchesMask = $matchesMask
    EndIf

    Local $sMatchesMaskDllType
    If IsDllStruct($matchesMask) Then
        $sMatchesMaskDllType = "struct*"
    Else
        $sMatchesMaskDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "drawMatchedFeatures2", $sImg1DllType, $img1, $sKeypoints1DllType, $vecKeypoints1, $sImg2DllType, $img2, $sKeypoints2DllType, $vecKeypoints2, $sMatchesDllType, $vecMatches, $sOutImgDllType, $outImg, $sMatchColorDllType, $matchColor, $sSinglePointColorDllType, $singlePointColor, $sMatchesMaskDllType, $vecMatchesMask, "int", $flags), "drawMatchedFeatures2", @error)

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

Func _drawMatchedFeatures2Typed($typeOfImg1, $img1, $keypoints1, $typeOfImg2, $img2, $keypoints2, $matches, $typeOfOutImg, $outImg, $matchColor, $singlePointColor, $matchesMask, $flags)

    Local $iArrImg1, $vectorImg1, $iArrImg1Size
    Local $bImg1IsArray = IsArray($img1)
    Local $bImg1Create = IsDllStruct($img1) And $typeOfImg1 == "Scalar"

    If $typeOfImg1 == Default Then
        $iArrImg1 = $img1
    ElseIf $bImg1IsArray Then
        $vectorImg1 = Call("_VectorOf" & $typeOfImg1 & "Create")

        $iArrImg1Size = UBound($img1)
        For $i = 0 To $iArrImg1Size - 1
            Call("_VectorOf" & $typeOfImg1 & "Push", $vectorImg1, $img1[$i])
        Next

        $iArrImg1 = Call("_cveInputArrayFromVectorOf" & $typeOfImg1, $vectorImg1)
    Else
        If $bImg1Create Then
            $img1 = Call("_cve" & $typeOfImg1 & "Create", $img1)
        EndIf
        $iArrImg1 = Call("_cveInputArrayFrom" & $typeOfImg1, $img1)
    EndIf

    Local $iArrImg2, $vectorImg2, $iArrImg2Size
    Local $bImg2IsArray = IsArray($img2)
    Local $bImg2Create = IsDllStruct($img2) And $typeOfImg2 == "Scalar"

    If $typeOfImg2 == Default Then
        $iArrImg2 = $img2
    ElseIf $bImg2IsArray Then
        $vectorImg2 = Call("_VectorOf" & $typeOfImg2 & "Create")

        $iArrImg2Size = UBound($img2)
        For $i = 0 To $iArrImg2Size - 1
            Call("_VectorOf" & $typeOfImg2 & "Push", $vectorImg2, $img2[$i])
        Next

        $iArrImg2 = Call("_cveInputArrayFromVectorOf" & $typeOfImg2, $vectorImg2)
    Else
        If $bImg2Create Then
            $img2 = Call("_cve" & $typeOfImg2 & "Create", $img2)
        EndIf
        $iArrImg2 = Call("_cveInputArrayFrom" & $typeOfImg2, $img2)
    EndIf

    Local $ioArrOutImg, $vectorOutImg, $iArrOutImgSize
    Local $bOutImgIsArray = IsArray($outImg)
    Local $bOutImgCreate = IsDllStruct($outImg) And $typeOfOutImg == "Scalar"

    If $typeOfOutImg == Default Then
        $ioArrOutImg = $outImg
    ElseIf $bOutImgIsArray Then
        $vectorOutImg = Call("_VectorOf" & $typeOfOutImg & "Create")

        $iArrOutImgSize = UBound($outImg)
        For $i = 0 To $iArrOutImgSize - 1
            Call("_VectorOf" & $typeOfOutImg & "Push", $vectorOutImg, $outImg[$i])
        Next

        $ioArrOutImg = Call("_cveInputOutputArrayFromVectorOf" & $typeOfOutImg, $vectorOutImg)
    Else
        If $bOutImgCreate Then
            $outImg = Call("_cve" & $typeOfOutImg & "Create", $outImg)
        EndIf
        $ioArrOutImg = Call("_cveInputOutputArrayFrom" & $typeOfOutImg, $outImg)
    EndIf

    _drawMatchedFeatures2($iArrImg1, $keypoints1, $iArrImg2, $keypoints2, $matches, $ioArrOutImg, $matchColor, $singlePointColor, $matchesMask, $flags)

    If $bOutImgIsArray Then
        Call("_VectorOf" & $typeOfOutImg & "Release", $vectorOutImg)
    EndIf

    If $typeOfOutImg <> Default Then
        _cveInputOutputArrayRelease($ioArrOutImg)
        If $bOutImgCreate Then
            Call("_cve" & $typeOfOutImg & "Release", $outImg)
        EndIf
    EndIf

    If $bImg2IsArray Then
        Call("_VectorOf" & $typeOfImg2 & "Release", $vectorImg2)
    EndIf

    If $typeOfImg2 <> Default Then
        _cveInputArrayRelease($iArrImg2)
        If $bImg2Create Then
            Call("_cve" & $typeOfImg2 & "Release", $img2)
        EndIf
    EndIf

    If $bImg1IsArray Then
        Call("_VectorOf" & $typeOfImg1 & "Release", $vectorImg1)
    EndIf

    If $typeOfImg1 <> Default Then
        _cveInputArrayRelease($iArrImg1)
        If $bImg1Create Then
            Call("_cve" & $typeOfImg1 & "Release", $img1)
        EndIf
    EndIf
EndFunc   ;==>_drawMatchedFeatures2Typed

Func _drawMatchedFeatures2Mat($img1, $keypoints1, $img2, $keypoints2, $matches, $outImg, $matchColor, $singlePointColor, $matchesMask, $flags)
    ; drawMatchedFeatures2 using cv::Mat instead of _*Array
    _drawMatchedFeatures2Typed("Mat", $img1, $keypoints1, "Mat", $img2, $keypoints2, $matches, "Mat", $outImg, $matchColor, $singlePointColor, $matchesMask, $flags)
EndFunc   ;==>_drawMatchedFeatures2Mat

Func _drawMatchedFeatures3($img1, $keypoints1, $img2, $keypoints2, $matches, $outImg, $matchColor, $singlePointColor, $matchesMask, $flags)
    ; CVAPI(void) drawMatchedFeatures3(cv::_InputArray* img1, const std::vector<cv::KeyPoint>* keypoints1, cv::_InputArray* img2, const std::vector<cv::KeyPoint>* keypoints2, std::vector<std::vector<cv::DMatch>>* matches, cv::_InputOutputArray* outImg, const CvScalar* matchColor, const CvScalar* singlePointColor, cv::_InputArray* matchesMask, int flags);

    Local $sImg1DllType
    If IsDllStruct($img1) Then
        $sImg1DllType = "struct*"
    Else
        $sImg1DllType = "ptr"
    EndIf

    Local $vecKeypoints1, $iArrKeypoints1Size
    Local $bKeypoints1IsArray = IsArray($keypoints1)

    If $bKeypoints1IsArray Then
        $vecKeypoints1 = _VectorOfKeyPointCreate()

        $iArrKeypoints1Size = UBound($keypoints1)
        For $i = 0 To $iArrKeypoints1Size - 1
            _VectorOfKeyPointPush($vecKeypoints1, $keypoints1[$i])
        Next
    Else
        $vecKeypoints1 = $keypoints1
    EndIf

    Local $sKeypoints1DllType
    If IsDllStruct($keypoints1) Then
        $sKeypoints1DllType = "struct*"
    Else
        $sKeypoints1DllType = "ptr"
    EndIf

    Local $sImg2DllType
    If IsDllStruct($img2) Then
        $sImg2DllType = "struct*"
    Else
        $sImg2DllType = "ptr"
    EndIf

    Local $vecKeypoints2, $iArrKeypoints2Size
    Local $bKeypoints2IsArray = IsArray($keypoints2)

    If $bKeypoints2IsArray Then
        $vecKeypoints2 = _VectorOfKeyPointCreate()

        $iArrKeypoints2Size = UBound($keypoints2)
        For $i = 0 To $iArrKeypoints2Size - 1
            _VectorOfKeyPointPush($vecKeypoints2, $keypoints2[$i])
        Next
    Else
        $vecKeypoints2 = $keypoints2
    EndIf

    Local $sKeypoints2DllType
    If IsDllStruct($keypoints2) Then
        $sKeypoints2DllType = "struct*"
    Else
        $sKeypoints2DllType = "ptr"
    EndIf

    Local $vecMatches, $iArrMatchesSize
    Local $bMatchesIsArray = IsArray($matches)

    If $bMatchesIsArray Then
        $vecMatches = _VectorOfVectorOfDMatchCreate()

        $iArrMatchesSize = UBound($matches)
        For $i = 0 To $iArrMatchesSize - 1
            _VectorOfVectorOfDMatchPush($vecMatches, $matches[$i])
        Next
    Else
        $vecMatches = $matches
    EndIf

    Local $sMatchesDllType
    If IsDllStruct($matches) Then
        $sMatchesDllType = "struct*"
    Else
        $sMatchesDllType = "ptr"
    EndIf

    Local $sOutImgDllType
    If IsDllStruct($outImg) Then
        $sOutImgDllType = "struct*"
    Else
        $sOutImgDllType = "ptr"
    EndIf

    Local $sMatchColorDllType
    If IsDllStruct($matchColor) Then
        $sMatchColorDllType = "struct*"
    Else
        $sMatchColorDllType = "ptr"
    EndIf

    Local $sSinglePointColorDllType
    If IsDllStruct($singlePointColor) Then
        $sSinglePointColorDllType = "struct*"
    Else
        $sSinglePointColorDllType = "ptr"
    EndIf

    Local $sMatchesMaskDllType
    If IsDllStruct($matchesMask) Then
        $sMatchesMaskDllType = "struct*"
    Else
        $sMatchesMaskDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "drawMatchedFeatures3", $sImg1DllType, $img1, $sKeypoints1DllType, $vecKeypoints1, $sImg2DllType, $img2, $sKeypoints2DllType, $vecKeypoints2, $sMatchesDllType, $vecMatches, $sOutImgDllType, $outImg, $sMatchColorDllType, $matchColor, $sSinglePointColorDllType, $singlePointColor, $sMatchesMaskDllType, $matchesMask, "int", $flags), "drawMatchedFeatures3", @error)

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

Func _drawMatchedFeatures3Typed($typeOfImg1, $img1, $keypoints1, $typeOfImg2, $img2, $keypoints2, $matches, $typeOfOutImg, $outImg, $matchColor, $singlePointColor, $typeOfMatchesMask, $matchesMask, $flags)

    Local $iArrImg1, $vectorImg1, $iArrImg1Size
    Local $bImg1IsArray = IsArray($img1)
    Local $bImg1Create = IsDllStruct($img1) And $typeOfImg1 == "Scalar"

    If $typeOfImg1 == Default Then
        $iArrImg1 = $img1
    ElseIf $bImg1IsArray Then
        $vectorImg1 = Call("_VectorOf" & $typeOfImg1 & "Create")

        $iArrImg1Size = UBound($img1)
        For $i = 0 To $iArrImg1Size - 1
            Call("_VectorOf" & $typeOfImg1 & "Push", $vectorImg1, $img1[$i])
        Next

        $iArrImg1 = Call("_cveInputArrayFromVectorOf" & $typeOfImg1, $vectorImg1)
    Else
        If $bImg1Create Then
            $img1 = Call("_cve" & $typeOfImg1 & "Create", $img1)
        EndIf
        $iArrImg1 = Call("_cveInputArrayFrom" & $typeOfImg1, $img1)
    EndIf

    Local $iArrImg2, $vectorImg2, $iArrImg2Size
    Local $bImg2IsArray = IsArray($img2)
    Local $bImg2Create = IsDllStruct($img2) And $typeOfImg2 == "Scalar"

    If $typeOfImg2 == Default Then
        $iArrImg2 = $img2
    ElseIf $bImg2IsArray Then
        $vectorImg2 = Call("_VectorOf" & $typeOfImg2 & "Create")

        $iArrImg2Size = UBound($img2)
        For $i = 0 To $iArrImg2Size - 1
            Call("_VectorOf" & $typeOfImg2 & "Push", $vectorImg2, $img2[$i])
        Next

        $iArrImg2 = Call("_cveInputArrayFromVectorOf" & $typeOfImg2, $vectorImg2)
    Else
        If $bImg2Create Then
            $img2 = Call("_cve" & $typeOfImg2 & "Create", $img2)
        EndIf
        $iArrImg2 = Call("_cveInputArrayFrom" & $typeOfImg2, $img2)
    EndIf

    Local $ioArrOutImg, $vectorOutImg, $iArrOutImgSize
    Local $bOutImgIsArray = IsArray($outImg)
    Local $bOutImgCreate = IsDllStruct($outImg) And $typeOfOutImg == "Scalar"

    If $typeOfOutImg == Default Then
        $ioArrOutImg = $outImg
    ElseIf $bOutImgIsArray Then
        $vectorOutImg = Call("_VectorOf" & $typeOfOutImg & "Create")

        $iArrOutImgSize = UBound($outImg)
        For $i = 0 To $iArrOutImgSize - 1
            Call("_VectorOf" & $typeOfOutImg & "Push", $vectorOutImg, $outImg[$i])
        Next

        $ioArrOutImg = Call("_cveInputOutputArrayFromVectorOf" & $typeOfOutImg, $vectorOutImg)
    Else
        If $bOutImgCreate Then
            $outImg = Call("_cve" & $typeOfOutImg & "Create", $outImg)
        EndIf
        $ioArrOutImg = Call("_cveInputOutputArrayFrom" & $typeOfOutImg, $outImg)
    EndIf

    Local $iArrMatchesMask, $vectorMatchesMask, $iArrMatchesMaskSize
    Local $bMatchesMaskIsArray = IsArray($matchesMask)
    Local $bMatchesMaskCreate = IsDllStruct($matchesMask) And $typeOfMatchesMask == "Scalar"

    If $typeOfMatchesMask == Default Then
        $iArrMatchesMask = $matchesMask
    ElseIf $bMatchesMaskIsArray Then
        $vectorMatchesMask = Call("_VectorOf" & $typeOfMatchesMask & "Create")

        $iArrMatchesMaskSize = UBound($matchesMask)
        For $i = 0 To $iArrMatchesMaskSize - 1
            Call("_VectorOf" & $typeOfMatchesMask & "Push", $vectorMatchesMask, $matchesMask[$i])
        Next

        $iArrMatchesMask = Call("_cveInputArrayFromVectorOf" & $typeOfMatchesMask, $vectorMatchesMask)
    Else
        If $bMatchesMaskCreate Then
            $matchesMask = Call("_cve" & $typeOfMatchesMask & "Create", $matchesMask)
        EndIf
        $iArrMatchesMask = Call("_cveInputArrayFrom" & $typeOfMatchesMask, $matchesMask)
    EndIf

    _drawMatchedFeatures3($iArrImg1, $keypoints1, $iArrImg2, $keypoints2, $matches, $ioArrOutImg, $matchColor, $singlePointColor, $iArrMatchesMask, $flags)

    If $bMatchesMaskIsArray Then
        Call("_VectorOf" & $typeOfMatchesMask & "Release", $vectorMatchesMask)
    EndIf

    If $typeOfMatchesMask <> Default Then
        _cveInputArrayRelease($iArrMatchesMask)
        If $bMatchesMaskCreate Then
            Call("_cve" & $typeOfMatchesMask & "Release", $matchesMask)
        EndIf
    EndIf

    If $bOutImgIsArray Then
        Call("_VectorOf" & $typeOfOutImg & "Release", $vectorOutImg)
    EndIf

    If $typeOfOutImg <> Default Then
        _cveInputOutputArrayRelease($ioArrOutImg)
        If $bOutImgCreate Then
            Call("_cve" & $typeOfOutImg & "Release", $outImg)
        EndIf
    EndIf

    If $bImg2IsArray Then
        Call("_VectorOf" & $typeOfImg2 & "Release", $vectorImg2)
    EndIf

    If $typeOfImg2 <> Default Then
        _cveInputArrayRelease($iArrImg2)
        If $bImg2Create Then
            Call("_cve" & $typeOfImg2 & "Release", $img2)
        EndIf
    EndIf

    If $bImg1IsArray Then
        Call("_VectorOf" & $typeOfImg1 & "Release", $vectorImg1)
    EndIf

    If $typeOfImg1 <> Default Then
        _cveInputArrayRelease($iArrImg1)
        If $bImg1Create Then
            Call("_cve" & $typeOfImg1 & "Release", $img1)
        EndIf
    EndIf
EndFunc   ;==>_drawMatchedFeatures3Typed

Func _drawMatchedFeatures3Mat($img1, $keypoints1, $img2, $keypoints2, $matches, $outImg, $matchColor, $singlePointColor, $matchesMask, $flags)
    ; drawMatchedFeatures3 using cv::Mat instead of _*Array
    _drawMatchedFeatures3Typed("Mat", $img1, $keypoints1, "Mat", $img2, $keypoints2, $matches, "Mat", $outImg, $matchColor, $singlePointColor, "Mat", $matchesMask, $flags)
EndFunc   ;==>_drawMatchedFeatures3Mat

Func _cveDescriptorMatcherAdd($matcher, $trainDescriptors)
    ; CVAPI(void) cveDescriptorMatcherAdd(cv::DescriptorMatcher* matcher, cv::_InputArray* trainDescriptors);

    Local $sMatcherDllType
    If IsDllStruct($matcher) Then
        $sMatcherDllType = "struct*"
    Else
        $sMatcherDllType = "ptr"
    EndIf

    Local $sTrainDescriptorsDllType
    If IsDllStruct($trainDescriptors) Then
        $sTrainDescriptorsDllType = "struct*"
    Else
        $sTrainDescriptorsDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDescriptorMatcherAdd", $sMatcherDllType, $matcher, $sTrainDescriptorsDllType, $trainDescriptors), "cveDescriptorMatcherAdd", @error)
EndFunc   ;==>_cveDescriptorMatcherAdd

Func _cveDescriptorMatcherAddTyped($matcher, $typeOfTrainDescriptors, $trainDescriptors)

    Local $iArrTrainDescriptors, $vectorTrainDescriptors, $iArrTrainDescriptorsSize
    Local $bTrainDescriptorsIsArray = IsArray($trainDescriptors)
    Local $bTrainDescriptorsCreate = IsDllStruct($trainDescriptors) And $typeOfTrainDescriptors == "Scalar"

    If $typeOfTrainDescriptors == Default Then
        $iArrTrainDescriptors = $trainDescriptors
    ElseIf $bTrainDescriptorsIsArray Then
        $vectorTrainDescriptors = Call("_VectorOf" & $typeOfTrainDescriptors & "Create")

        $iArrTrainDescriptorsSize = UBound($trainDescriptors)
        For $i = 0 To $iArrTrainDescriptorsSize - 1
            Call("_VectorOf" & $typeOfTrainDescriptors & "Push", $vectorTrainDescriptors, $trainDescriptors[$i])
        Next

        $iArrTrainDescriptors = Call("_cveInputArrayFromVectorOf" & $typeOfTrainDescriptors, $vectorTrainDescriptors)
    Else
        If $bTrainDescriptorsCreate Then
            $trainDescriptors = Call("_cve" & $typeOfTrainDescriptors & "Create", $trainDescriptors)
        EndIf
        $iArrTrainDescriptors = Call("_cveInputArrayFrom" & $typeOfTrainDescriptors, $trainDescriptors)
    EndIf

    _cveDescriptorMatcherAdd($matcher, $iArrTrainDescriptors)

    If $bTrainDescriptorsIsArray Then
        Call("_VectorOf" & $typeOfTrainDescriptors & "Release", $vectorTrainDescriptors)
    EndIf

    If $typeOfTrainDescriptors <> Default Then
        _cveInputArrayRelease($iArrTrainDescriptors)
        If $bTrainDescriptorsCreate Then
            Call("_cve" & $typeOfTrainDescriptors & "Release", $trainDescriptors)
        EndIf
    EndIf
EndFunc   ;==>_cveDescriptorMatcherAddTyped

Func _cveDescriptorMatcherAddMat($matcher, $trainDescriptors)
    ; cveDescriptorMatcherAdd using cv::Mat instead of _*Array
    _cveDescriptorMatcherAddTyped($matcher, "Mat", $trainDescriptors)
EndFunc   ;==>_cveDescriptorMatcherAddMat

Func _cveDescriptorMatcherKnnMatch1($matcher, $queryDescriptors, $trainDescriptors, $matches, $k, $mask, $compactResult)
    ; CVAPI(void) cveDescriptorMatcherKnnMatch1(cv::DescriptorMatcher* matcher, cv::_InputArray* queryDescriptors, cv::_InputArray* trainDescriptors, std::vector<std::vector<cv::DMatch>>* matches, int k, cv::_InputArray* mask, bool compactResult);

    Local $sMatcherDllType
    If IsDllStruct($matcher) Then
        $sMatcherDllType = "struct*"
    Else
        $sMatcherDllType = "ptr"
    EndIf

    Local $sQueryDescriptorsDllType
    If IsDllStruct($queryDescriptors) Then
        $sQueryDescriptorsDllType = "struct*"
    Else
        $sQueryDescriptorsDllType = "ptr"
    EndIf

    Local $sTrainDescriptorsDllType
    If IsDllStruct($trainDescriptors) Then
        $sTrainDescriptorsDllType = "struct*"
    Else
        $sTrainDescriptorsDllType = "ptr"
    EndIf

    Local $vecMatches, $iArrMatchesSize
    Local $bMatchesIsArray = IsArray($matches)

    If $bMatchesIsArray Then
        $vecMatches = _VectorOfVectorOfDMatchCreate()

        $iArrMatchesSize = UBound($matches)
        For $i = 0 To $iArrMatchesSize - 1
            _VectorOfVectorOfDMatchPush($vecMatches, $matches[$i])
        Next
    Else
        $vecMatches = $matches
    EndIf

    Local $sMatchesDllType
    If IsDllStruct($matches) Then
        $sMatchesDllType = "struct*"
    Else
        $sMatchesDllType = "ptr"
    EndIf

    Local $sMaskDllType
    If IsDllStruct($mask) Then
        $sMaskDllType = "struct*"
    Else
        $sMaskDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDescriptorMatcherKnnMatch1", $sMatcherDllType, $matcher, $sQueryDescriptorsDllType, $queryDescriptors, $sTrainDescriptorsDllType, $trainDescriptors, $sMatchesDllType, $vecMatches, "int", $k, $sMaskDllType, $mask, "boolean", $compactResult), "cveDescriptorMatcherKnnMatch1", @error)

    If $bMatchesIsArray Then
        _VectorOfVectorOfDMatchRelease($vecMatches)
    EndIf
EndFunc   ;==>_cveDescriptorMatcherKnnMatch1

Func _cveDescriptorMatcherKnnMatch1Typed($matcher, $typeOfQueryDescriptors, $queryDescriptors, $typeOfTrainDescriptors, $trainDescriptors, $matches, $k, $typeOfMask, $mask, $compactResult)

    Local $iArrQueryDescriptors, $vectorQueryDescriptors, $iArrQueryDescriptorsSize
    Local $bQueryDescriptorsIsArray = IsArray($queryDescriptors)
    Local $bQueryDescriptorsCreate = IsDllStruct($queryDescriptors) And $typeOfQueryDescriptors == "Scalar"

    If $typeOfQueryDescriptors == Default Then
        $iArrQueryDescriptors = $queryDescriptors
    ElseIf $bQueryDescriptorsIsArray Then
        $vectorQueryDescriptors = Call("_VectorOf" & $typeOfQueryDescriptors & "Create")

        $iArrQueryDescriptorsSize = UBound($queryDescriptors)
        For $i = 0 To $iArrQueryDescriptorsSize - 1
            Call("_VectorOf" & $typeOfQueryDescriptors & "Push", $vectorQueryDescriptors, $queryDescriptors[$i])
        Next

        $iArrQueryDescriptors = Call("_cveInputArrayFromVectorOf" & $typeOfQueryDescriptors, $vectorQueryDescriptors)
    Else
        If $bQueryDescriptorsCreate Then
            $queryDescriptors = Call("_cve" & $typeOfQueryDescriptors & "Create", $queryDescriptors)
        EndIf
        $iArrQueryDescriptors = Call("_cveInputArrayFrom" & $typeOfQueryDescriptors, $queryDescriptors)
    EndIf

    Local $iArrTrainDescriptors, $vectorTrainDescriptors, $iArrTrainDescriptorsSize
    Local $bTrainDescriptorsIsArray = IsArray($trainDescriptors)
    Local $bTrainDescriptorsCreate = IsDllStruct($trainDescriptors) And $typeOfTrainDescriptors == "Scalar"

    If $typeOfTrainDescriptors == Default Then
        $iArrTrainDescriptors = $trainDescriptors
    ElseIf $bTrainDescriptorsIsArray Then
        $vectorTrainDescriptors = Call("_VectorOf" & $typeOfTrainDescriptors & "Create")

        $iArrTrainDescriptorsSize = UBound($trainDescriptors)
        For $i = 0 To $iArrTrainDescriptorsSize - 1
            Call("_VectorOf" & $typeOfTrainDescriptors & "Push", $vectorTrainDescriptors, $trainDescriptors[$i])
        Next

        $iArrTrainDescriptors = Call("_cveInputArrayFromVectorOf" & $typeOfTrainDescriptors, $vectorTrainDescriptors)
    Else
        If $bTrainDescriptorsCreate Then
            $trainDescriptors = Call("_cve" & $typeOfTrainDescriptors & "Create", $trainDescriptors)
        EndIf
        $iArrTrainDescriptors = Call("_cveInputArrayFrom" & $typeOfTrainDescriptors, $trainDescriptors)
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

    _cveDescriptorMatcherKnnMatch1($matcher, $iArrQueryDescriptors, $iArrTrainDescriptors, $matches, $k, $iArrMask, $compactResult)

    If $bMaskIsArray Then
        Call("_VectorOf" & $typeOfMask & "Release", $vectorMask)
    EndIf

    If $typeOfMask <> Default Then
        _cveInputArrayRelease($iArrMask)
        If $bMaskCreate Then
            Call("_cve" & $typeOfMask & "Release", $mask)
        EndIf
    EndIf

    If $bTrainDescriptorsIsArray Then
        Call("_VectorOf" & $typeOfTrainDescriptors & "Release", $vectorTrainDescriptors)
    EndIf

    If $typeOfTrainDescriptors <> Default Then
        _cveInputArrayRelease($iArrTrainDescriptors)
        If $bTrainDescriptorsCreate Then
            Call("_cve" & $typeOfTrainDescriptors & "Release", $trainDescriptors)
        EndIf
    EndIf

    If $bQueryDescriptorsIsArray Then
        Call("_VectorOf" & $typeOfQueryDescriptors & "Release", $vectorQueryDescriptors)
    EndIf

    If $typeOfQueryDescriptors <> Default Then
        _cveInputArrayRelease($iArrQueryDescriptors)
        If $bQueryDescriptorsCreate Then
            Call("_cve" & $typeOfQueryDescriptors & "Release", $queryDescriptors)
        EndIf
    EndIf
EndFunc   ;==>_cveDescriptorMatcherKnnMatch1Typed

Func _cveDescriptorMatcherKnnMatch1Mat($matcher, $queryDescriptors, $trainDescriptors, $matches, $k, $mask, $compactResult)
    ; cveDescriptorMatcherKnnMatch1 using cv::Mat instead of _*Array
    _cveDescriptorMatcherKnnMatch1Typed($matcher, "Mat", $queryDescriptors, "Mat", $trainDescriptors, $matches, $k, "Mat", $mask, $compactResult)
EndFunc   ;==>_cveDescriptorMatcherKnnMatch1Mat

Func _cveDescriptorMatcherKnnMatch2($matcher, $queryDescriptors, $matches, $k, $mask, $compactResult)
    ; CVAPI(void) cveDescriptorMatcherKnnMatch2(cv::DescriptorMatcher* matcher, cv::_InputArray* queryDescriptors, std::vector<std::vector<cv::DMatch>>* matches, int k, cv::_InputArray* mask, bool compactResult);

    Local $sMatcherDllType
    If IsDllStruct($matcher) Then
        $sMatcherDllType = "struct*"
    Else
        $sMatcherDllType = "ptr"
    EndIf

    Local $sQueryDescriptorsDllType
    If IsDllStruct($queryDescriptors) Then
        $sQueryDescriptorsDllType = "struct*"
    Else
        $sQueryDescriptorsDllType = "ptr"
    EndIf

    Local $vecMatches, $iArrMatchesSize
    Local $bMatchesIsArray = IsArray($matches)

    If $bMatchesIsArray Then
        $vecMatches = _VectorOfVectorOfDMatchCreate()

        $iArrMatchesSize = UBound($matches)
        For $i = 0 To $iArrMatchesSize - 1
            _VectorOfVectorOfDMatchPush($vecMatches, $matches[$i])
        Next
    Else
        $vecMatches = $matches
    EndIf

    Local $sMatchesDllType
    If IsDllStruct($matches) Then
        $sMatchesDllType = "struct*"
    Else
        $sMatchesDllType = "ptr"
    EndIf

    Local $sMaskDllType
    If IsDllStruct($mask) Then
        $sMaskDllType = "struct*"
    Else
        $sMaskDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDescriptorMatcherKnnMatch2", $sMatcherDllType, $matcher, $sQueryDescriptorsDllType, $queryDescriptors, $sMatchesDllType, $vecMatches, "int", $k, $sMaskDllType, $mask, "boolean", $compactResult), "cveDescriptorMatcherKnnMatch2", @error)

    If $bMatchesIsArray Then
        _VectorOfVectorOfDMatchRelease($vecMatches)
    EndIf
EndFunc   ;==>_cveDescriptorMatcherKnnMatch2

Func _cveDescriptorMatcherKnnMatch2Typed($matcher, $typeOfQueryDescriptors, $queryDescriptors, $matches, $k, $typeOfMask, $mask, $compactResult)

    Local $iArrQueryDescriptors, $vectorQueryDescriptors, $iArrQueryDescriptorsSize
    Local $bQueryDescriptorsIsArray = IsArray($queryDescriptors)
    Local $bQueryDescriptorsCreate = IsDllStruct($queryDescriptors) And $typeOfQueryDescriptors == "Scalar"

    If $typeOfQueryDescriptors == Default Then
        $iArrQueryDescriptors = $queryDescriptors
    ElseIf $bQueryDescriptorsIsArray Then
        $vectorQueryDescriptors = Call("_VectorOf" & $typeOfQueryDescriptors & "Create")

        $iArrQueryDescriptorsSize = UBound($queryDescriptors)
        For $i = 0 To $iArrQueryDescriptorsSize - 1
            Call("_VectorOf" & $typeOfQueryDescriptors & "Push", $vectorQueryDescriptors, $queryDescriptors[$i])
        Next

        $iArrQueryDescriptors = Call("_cveInputArrayFromVectorOf" & $typeOfQueryDescriptors, $vectorQueryDescriptors)
    Else
        If $bQueryDescriptorsCreate Then
            $queryDescriptors = Call("_cve" & $typeOfQueryDescriptors & "Create", $queryDescriptors)
        EndIf
        $iArrQueryDescriptors = Call("_cveInputArrayFrom" & $typeOfQueryDescriptors, $queryDescriptors)
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

    _cveDescriptorMatcherKnnMatch2($matcher, $iArrQueryDescriptors, $matches, $k, $iArrMask, $compactResult)

    If $bMaskIsArray Then
        Call("_VectorOf" & $typeOfMask & "Release", $vectorMask)
    EndIf

    If $typeOfMask <> Default Then
        _cveInputArrayRelease($iArrMask)
        If $bMaskCreate Then
            Call("_cve" & $typeOfMask & "Release", $mask)
        EndIf
    EndIf

    If $bQueryDescriptorsIsArray Then
        Call("_VectorOf" & $typeOfQueryDescriptors & "Release", $vectorQueryDescriptors)
    EndIf

    If $typeOfQueryDescriptors <> Default Then
        _cveInputArrayRelease($iArrQueryDescriptors)
        If $bQueryDescriptorsCreate Then
            Call("_cve" & $typeOfQueryDescriptors & "Release", $queryDescriptors)
        EndIf
    EndIf
EndFunc   ;==>_cveDescriptorMatcherKnnMatch2Typed

Func _cveDescriptorMatcherKnnMatch2Mat($matcher, $queryDescriptors, $matches, $k, $mask, $compactResult)
    ; cveDescriptorMatcherKnnMatch2 using cv::Mat instead of _*Array
    _cveDescriptorMatcherKnnMatch2Typed($matcher, "Mat", $queryDescriptors, $matches, $k, "Mat", $mask, $compactResult)
EndFunc   ;==>_cveDescriptorMatcherKnnMatch2Mat

Func _cveDescriptorMatcherGetAlgorithm($matcher)
    ; CVAPI(cv::Algorithm*) cveDescriptorMatcherGetAlgorithm(cv::DescriptorMatcher* matcher);

    Local $sMatcherDllType
    If IsDllStruct($matcher) Then
        $sMatcherDllType = "struct*"
    Else
        $sMatcherDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveDescriptorMatcherGetAlgorithm", $sMatcherDllType, $matcher), "cveDescriptorMatcherGetAlgorithm", @error)
EndFunc   ;==>_cveDescriptorMatcherGetAlgorithm

Func _cveDescriptorMatcherClear($matcher)
    ; CVAPI(void) cveDescriptorMatcherClear(cv::DescriptorMatcher* matcher);

    Local $sMatcherDllType
    If IsDllStruct($matcher) Then
        $sMatcherDllType = "struct*"
    Else
        $sMatcherDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDescriptorMatcherClear", $sMatcherDllType, $matcher), "cveDescriptorMatcherClear", @error)
EndFunc   ;==>_cveDescriptorMatcherClear

Func _cveDescriptorMatcherEmpty($matcher)
    ; CVAPI(bool) cveDescriptorMatcherEmpty(cv::DescriptorMatcher* matcher);

    Local $sMatcherDllType
    If IsDllStruct($matcher) Then
        $sMatcherDllType = "struct*"
    Else
        $sMatcherDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveDescriptorMatcherEmpty", $sMatcherDllType, $matcher), "cveDescriptorMatcherEmpty", @error)
EndFunc   ;==>_cveDescriptorMatcherEmpty

Func _cveDescriptorMatcherIsMaskSupported($matcher)
    ; CVAPI(bool) cveDescriptorMatcherIsMaskSupported(cv::DescriptorMatcher* matcher);

    Local $sMatcherDllType
    If IsDllStruct($matcher) Then
        $sMatcherDllType = "struct*"
    Else
        $sMatcherDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveDescriptorMatcherIsMaskSupported", $sMatcherDllType, $matcher), "cveDescriptorMatcherIsMaskSupported", @error)
EndFunc   ;==>_cveDescriptorMatcherIsMaskSupported

Func _cveDescriptorMatcherTrain($matcher)
    ; CVAPI(void) cveDescriptorMatcherTrain(cv::DescriptorMatcher* matcher);

    Local $sMatcherDllType
    If IsDllStruct($matcher) Then
        $sMatcherDllType = "struct*"
    Else
        $sMatcherDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDescriptorMatcherTrain", $sMatcherDllType, $matcher), "cveDescriptorMatcherTrain", @error)
EndFunc   ;==>_cveDescriptorMatcherTrain

Func _cveDescriptorMatcherMatch1($matcher, $queryDescriptors, $trainDescriptors, $matches, $mask)
    ; CVAPI(void) cveDescriptorMatcherMatch1(cv::DescriptorMatcher* matcher, cv::_InputArray* queryDescriptors, cv::_InputArray* trainDescriptors, std::vector<cv::DMatch>* matches, cv::_InputArray* mask);

    Local $sMatcherDllType
    If IsDllStruct($matcher) Then
        $sMatcherDllType = "struct*"
    Else
        $sMatcherDllType = "ptr"
    EndIf

    Local $sQueryDescriptorsDllType
    If IsDllStruct($queryDescriptors) Then
        $sQueryDescriptorsDllType = "struct*"
    Else
        $sQueryDescriptorsDllType = "ptr"
    EndIf

    Local $sTrainDescriptorsDllType
    If IsDllStruct($trainDescriptors) Then
        $sTrainDescriptorsDllType = "struct*"
    Else
        $sTrainDescriptorsDllType = "ptr"
    EndIf

    Local $vecMatches, $iArrMatchesSize
    Local $bMatchesIsArray = IsArray($matches)

    If $bMatchesIsArray Then
        $vecMatches = _VectorOfDMatchCreate()

        $iArrMatchesSize = UBound($matches)
        For $i = 0 To $iArrMatchesSize - 1
            _VectorOfDMatchPush($vecMatches, $matches[$i])
        Next
    Else
        $vecMatches = $matches
    EndIf

    Local $sMatchesDllType
    If IsDllStruct($matches) Then
        $sMatchesDllType = "struct*"
    Else
        $sMatchesDllType = "ptr"
    EndIf

    Local $sMaskDllType
    If IsDllStruct($mask) Then
        $sMaskDllType = "struct*"
    Else
        $sMaskDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDescriptorMatcherMatch1", $sMatcherDllType, $matcher, $sQueryDescriptorsDllType, $queryDescriptors, $sTrainDescriptorsDllType, $trainDescriptors, $sMatchesDllType, $vecMatches, $sMaskDllType, $mask), "cveDescriptorMatcherMatch1", @error)

    If $bMatchesIsArray Then
        _VectorOfDMatchRelease($vecMatches)
    EndIf
EndFunc   ;==>_cveDescriptorMatcherMatch1

Func _cveDescriptorMatcherMatch1Typed($matcher, $typeOfQueryDescriptors, $queryDescriptors, $typeOfTrainDescriptors, $trainDescriptors, $matches, $typeOfMask, $mask)

    Local $iArrQueryDescriptors, $vectorQueryDescriptors, $iArrQueryDescriptorsSize
    Local $bQueryDescriptorsIsArray = IsArray($queryDescriptors)
    Local $bQueryDescriptorsCreate = IsDllStruct($queryDescriptors) And $typeOfQueryDescriptors == "Scalar"

    If $typeOfQueryDescriptors == Default Then
        $iArrQueryDescriptors = $queryDescriptors
    ElseIf $bQueryDescriptorsIsArray Then
        $vectorQueryDescriptors = Call("_VectorOf" & $typeOfQueryDescriptors & "Create")

        $iArrQueryDescriptorsSize = UBound($queryDescriptors)
        For $i = 0 To $iArrQueryDescriptorsSize - 1
            Call("_VectorOf" & $typeOfQueryDescriptors & "Push", $vectorQueryDescriptors, $queryDescriptors[$i])
        Next

        $iArrQueryDescriptors = Call("_cveInputArrayFromVectorOf" & $typeOfQueryDescriptors, $vectorQueryDescriptors)
    Else
        If $bQueryDescriptorsCreate Then
            $queryDescriptors = Call("_cve" & $typeOfQueryDescriptors & "Create", $queryDescriptors)
        EndIf
        $iArrQueryDescriptors = Call("_cveInputArrayFrom" & $typeOfQueryDescriptors, $queryDescriptors)
    EndIf

    Local $iArrTrainDescriptors, $vectorTrainDescriptors, $iArrTrainDescriptorsSize
    Local $bTrainDescriptorsIsArray = IsArray($trainDescriptors)
    Local $bTrainDescriptorsCreate = IsDllStruct($trainDescriptors) And $typeOfTrainDescriptors == "Scalar"

    If $typeOfTrainDescriptors == Default Then
        $iArrTrainDescriptors = $trainDescriptors
    ElseIf $bTrainDescriptorsIsArray Then
        $vectorTrainDescriptors = Call("_VectorOf" & $typeOfTrainDescriptors & "Create")

        $iArrTrainDescriptorsSize = UBound($trainDescriptors)
        For $i = 0 To $iArrTrainDescriptorsSize - 1
            Call("_VectorOf" & $typeOfTrainDescriptors & "Push", $vectorTrainDescriptors, $trainDescriptors[$i])
        Next

        $iArrTrainDescriptors = Call("_cveInputArrayFromVectorOf" & $typeOfTrainDescriptors, $vectorTrainDescriptors)
    Else
        If $bTrainDescriptorsCreate Then
            $trainDescriptors = Call("_cve" & $typeOfTrainDescriptors & "Create", $trainDescriptors)
        EndIf
        $iArrTrainDescriptors = Call("_cveInputArrayFrom" & $typeOfTrainDescriptors, $trainDescriptors)
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

    _cveDescriptorMatcherMatch1($matcher, $iArrQueryDescriptors, $iArrTrainDescriptors, $matches, $iArrMask)

    If $bMaskIsArray Then
        Call("_VectorOf" & $typeOfMask & "Release", $vectorMask)
    EndIf

    If $typeOfMask <> Default Then
        _cveInputArrayRelease($iArrMask)
        If $bMaskCreate Then
            Call("_cve" & $typeOfMask & "Release", $mask)
        EndIf
    EndIf

    If $bTrainDescriptorsIsArray Then
        Call("_VectorOf" & $typeOfTrainDescriptors & "Release", $vectorTrainDescriptors)
    EndIf

    If $typeOfTrainDescriptors <> Default Then
        _cveInputArrayRelease($iArrTrainDescriptors)
        If $bTrainDescriptorsCreate Then
            Call("_cve" & $typeOfTrainDescriptors & "Release", $trainDescriptors)
        EndIf
    EndIf

    If $bQueryDescriptorsIsArray Then
        Call("_VectorOf" & $typeOfQueryDescriptors & "Release", $vectorQueryDescriptors)
    EndIf

    If $typeOfQueryDescriptors <> Default Then
        _cveInputArrayRelease($iArrQueryDescriptors)
        If $bQueryDescriptorsCreate Then
            Call("_cve" & $typeOfQueryDescriptors & "Release", $queryDescriptors)
        EndIf
    EndIf
EndFunc   ;==>_cveDescriptorMatcherMatch1Typed

Func _cveDescriptorMatcherMatch1Mat($matcher, $queryDescriptors, $trainDescriptors, $matches, $mask)
    ; cveDescriptorMatcherMatch1 using cv::Mat instead of _*Array
    _cveDescriptorMatcherMatch1Typed($matcher, "Mat", $queryDescriptors, "Mat", $trainDescriptors, $matches, "Mat", $mask)
EndFunc   ;==>_cveDescriptorMatcherMatch1Mat

Func _cveDescriptorMatcherMatch2($matcher, $queryDescriptors, $matches, $masks)
    ; CVAPI(void) cveDescriptorMatcherMatch2(cv::DescriptorMatcher* matcher, cv::_InputArray* queryDescriptors, std::vector<cv::DMatch>* matches, cv::_InputArray* masks);

    Local $sMatcherDllType
    If IsDllStruct($matcher) Then
        $sMatcherDllType = "struct*"
    Else
        $sMatcherDllType = "ptr"
    EndIf

    Local $sQueryDescriptorsDllType
    If IsDllStruct($queryDescriptors) Then
        $sQueryDescriptorsDllType = "struct*"
    Else
        $sQueryDescriptorsDllType = "ptr"
    EndIf

    Local $vecMatches, $iArrMatchesSize
    Local $bMatchesIsArray = IsArray($matches)

    If $bMatchesIsArray Then
        $vecMatches = _VectorOfDMatchCreate()

        $iArrMatchesSize = UBound($matches)
        For $i = 0 To $iArrMatchesSize - 1
            _VectorOfDMatchPush($vecMatches, $matches[$i])
        Next
    Else
        $vecMatches = $matches
    EndIf

    Local $sMatchesDllType
    If IsDllStruct($matches) Then
        $sMatchesDllType = "struct*"
    Else
        $sMatchesDllType = "ptr"
    EndIf

    Local $sMasksDllType
    If IsDllStruct($masks) Then
        $sMasksDllType = "struct*"
    Else
        $sMasksDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDescriptorMatcherMatch2", $sMatcherDllType, $matcher, $sQueryDescriptorsDllType, $queryDescriptors, $sMatchesDllType, $vecMatches, $sMasksDllType, $masks), "cveDescriptorMatcherMatch2", @error)

    If $bMatchesIsArray Then
        _VectorOfDMatchRelease($vecMatches)
    EndIf
EndFunc   ;==>_cveDescriptorMatcherMatch2

Func _cveDescriptorMatcherMatch2Typed($matcher, $typeOfQueryDescriptors, $queryDescriptors, $matches, $typeOfMasks, $masks)

    Local $iArrQueryDescriptors, $vectorQueryDescriptors, $iArrQueryDescriptorsSize
    Local $bQueryDescriptorsIsArray = IsArray($queryDescriptors)
    Local $bQueryDescriptorsCreate = IsDllStruct($queryDescriptors) And $typeOfQueryDescriptors == "Scalar"

    If $typeOfQueryDescriptors == Default Then
        $iArrQueryDescriptors = $queryDescriptors
    ElseIf $bQueryDescriptorsIsArray Then
        $vectorQueryDescriptors = Call("_VectorOf" & $typeOfQueryDescriptors & "Create")

        $iArrQueryDescriptorsSize = UBound($queryDescriptors)
        For $i = 0 To $iArrQueryDescriptorsSize - 1
            Call("_VectorOf" & $typeOfQueryDescriptors & "Push", $vectorQueryDescriptors, $queryDescriptors[$i])
        Next

        $iArrQueryDescriptors = Call("_cveInputArrayFromVectorOf" & $typeOfQueryDescriptors, $vectorQueryDescriptors)
    Else
        If $bQueryDescriptorsCreate Then
            $queryDescriptors = Call("_cve" & $typeOfQueryDescriptors & "Create", $queryDescriptors)
        EndIf
        $iArrQueryDescriptors = Call("_cveInputArrayFrom" & $typeOfQueryDescriptors, $queryDescriptors)
    EndIf

    Local $iArrMasks, $vectorMasks, $iArrMasksSize
    Local $bMasksIsArray = IsArray($masks)
    Local $bMasksCreate = IsDllStruct($masks) And $typeOfMasks == "Scalar"

    If $typeOfMasks == Default Then
        $iArrMasks = $masks
    ElseIf $bMasksIsArray Then
        $vectorMasks = Call("_VectorOf" & $typeOfMasks & "Create")

        $iArrMasksSize = UBound($masks)
        For $i = 0 To $iArrMasksSize - 1
            Call("_VectorOf" & $typeOfMasks & "Push", $vectorMasks, $masks[$i])
        Next

        $iArrMasks = Call("_cveInputArrayFromVectorOf" & $typeOfMasks, $vectorMasks)
    Else
        If $bMasksCreate Then
            $masks = Call("_cve" & $typeOfMasks & "Create", $masks)
        EndIf
        $iArrMasks = Call("_cveInputArrayFrom" & $typeOfMasks, $masks)
    EndIf

    _cveDescriptorMatcherMatch2($matcher, $iArrQueryDescriptors, $matches, $iArrMasks)

    If $bMasksIsArray Then
        Call("_VectorOf" & $typeOfMasks & "Release", $vectorMasks)
    EndIf

    If $typeOfMasks <> Default Then
        _cveInputArrayRelease($iArrMasks)
        If $bMasksCreate Then
            Call("_cve" & $typeOfMasks & "Release", $masks)
        EndIf
    EndIf

    If $bQueryDescriptorsIsArray Then
        Call("_VectorOf" & $typeOfQueryDescriptors & "Release", $vectorQueryDescriptors)
    EndIf

    If $typeOfQueryDescriptors <> Default Then
        _cveInputArrayRelease($iArrQueryDescriptors)
        If $bQueryDescriptorsCreate Then
            Call("_cve" & $typeOfQueryDescriptors & "Release", $queryDescriptors)
        EndIf
    EndIf
EndFunc   ;==>_cveDescriptorMatcherMatch2Typed

Func _cveDescriptorMatcherMatch2Mat($matcher, $queryDescriptors, $matches, $masks)
    ; cveDescriptorMatcherMatch2 using cv::Mat instead of _*Array
    _cveDescriptorMatcherMatch2Typed($matcher, "Mat", $queryDescriptors, $matches, "Mat", $masks)
EndFunc   ;==>_cveDescriptorMatcherMatch2Mat

Func _cveDescriptorMatcherRadiusMatch1($matcher, $queryDescriptors, $trainDescriptors, $matches, $maxDistance, $mask, $compactResult)
    ; CVAPI(void) cveDescriptorMatcherRadiusMatch1(cv::DescriptorMatcher* matcher, cv::_InputArray* queryDescriptors, cv::_InputArray* trainDescriptors, std::vector<std::vector<cv::DMatch>>* matches, float maxDistance, cv::_InputArray* mask, bool compactResult);

    Local $sMatcherDllType
    If IsDllStruct($matcher) Then
        $sMatcherDllType = "struct*"
    Else
        $sMatcherDllType = "ptr"
    EndIf

    Local $sQueryDescriptorsDllType
    If IsDllStruct($queryDescriptors) Then
        $sQueryDescriptorsDllType = "struct*"
    Else
        $sQueryDescriptorsDllType = "ptr"
    EndIf

    Local $sTrainDescriptorsDllType
    If IsDllStruct($trainDescriptors) Then
        $sTrainDescriptorsDllType = "struct*"
    Else
        $sTrainDescriptorsDllType = "ptr"
    EndIf

    Local $vecMatches, $iArrMatchesSize
    Local $bMatchesIsArray = IsArray($matches)

    If $bMatchesIsArray Then
        $vecMatches = _VectorOfVectorOfDMatchCreate()

        $iArrMatchesSize = UBound($matches)
        For $i = 0 To $iArrMatchesSize - 1
            _VectorOfVectorOfDMatchPush($vecMatches, $matches[$i])
        Next
    Else
        $vecMatches = $matches
    EndIf

    Local $sMatchesDllType
    If IsDllStruct($matches) Then
        $sMatchesDllType = "struct*"
    Else
        $sMatchesDllType = "ptr"
    EndIf

    Local $sMaskDllType
    If IsDllStruct($mask) Then
        $sMaskDllType = "struct*"
    Else
        $sMaskDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDescriptorMatcherRadiusMatch1", $sMatcherDllType, $matcher, $sQueryDescriptorsDllType, $queryDescriptors, $sTrainDescriptorsDllType, $trainDescriptors, $sMatchesDllType, $vecMatches, "float", $maxDistance, $sMaskDllType, $mask, "boolean", $compactResult), "cveDescriptorMatcherRadiusMatch1", @error)

    If $bMatchesIsArray Then
        _VectorOfVectorOfDMatchRelease($vecMatches)
    EndIf
EndFunc   ;==>_cveDescriptorMatcherRadiusMatch1

Func _cveDescriptorMatcherRadiusMatch1Typed($matcher, $typeOfQueryDescriptors, $queryDescriptors, $typeOfTrainDescriptors, $trainDescriptors, $matches, $maxDistance, $typeOfMask, $mask, $compactResult)

    Local $iArrQueryDescriptors, $vectorQueryDescriptors, $iArrQueryDescriptorsSize
    Local $bQueryDescriptorsIsArray = IsArray($queryDescriptors)
    Local $bQueryDescriptorsCreate = IsDllStruct($queryDescriptors) And $typeOfQueryDescriptors == "Scalar"

    If $typeOfQueryDescriptors == Default Then
        $iArrQueryDescriptors = $queryDescriptors
    ElseIf $bQueryDescriptorsIsArray Then
        $vectorQueryDescriptors = Call("_VectorOf" & $typeOfQueryDescriptors & "Create")

        $iArrQueryDescriptorsSize = UBound($queryDescriptors)
        For $i = 0 To $iArrQueryDescriptorsSize - 1
            Call("_VectorOf" & $typeOfQueryDescriptors & "Push", $vectorQueryDescriptors, $queryDescriptors[$i])
        Next

        $iArrQueryDescriptors = Call("_cveInputArrayFromVectorOf" & $typeOfQueryDescriptors, $vectorQueryDescriptors)
    Else
        If $bQueryDescriptorsCreate Then
            $queryDescriptors = Call("_cve" & $typeOfQueryDescriptors & "Create", $queryDescriptors)
        EndIf
        $iArrQueryDescriptors = Call("_cveInputArrayFrom" & $typeOfQueryDescriptors, $queryDescriptors)
    EndIf

    Local $iArrTrainDescriptors, $vectorTrainDescriptors, $iArrTrainDescriptorsSize
    Local $bTrainDescriptorsIsArray = IsArray($trainDescriptors)
    Local $bTrainDescriptorsCreate = IsDllStruct($trainDescriptors) And $typeOfTrainDescriptors == "Scalar"

    If $typeOfTrainDescriptors == Default Then
        $iArrTrainDescriptors = $trainDescriptors
    ElseIf $bTrainDescriptorsIsArray Then
        $vectorTrainDescriptors = Call("_VectorOf" & $typeOfTrainDescriptors & "Create")

        $iArrTrainDescriptorsSize = UBound($trainDescriptors)
        For $i = 0 To $iArrTrainDescriptorsSize - 1
            Call("_VectorOf" & $typeOfTrainDescriptors & "Push", $vectorTrainDescriptors, $trainDescriptors[$i])
        Next

        $iArrTrainDescriptors = Call("_cveInputArrayFromVectorOf" & $typeOfTrainDescriptors, $vectorTrainDescriptors)
    Else
        If $bTrainDescriptorsCreate Then
            $trainDescriptors = Call("_cve" & $typeOfTrainDescriptors & "Create", $trainDescriptors)
        EndIf
        $iArrTrainDescriptors = Call("_cveInputArrayFrom" & $typeOfTrainDescriptors, $trainDescriptors)
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

    _cveDescriptorMatcherRadiusMatch1($matcher, $iArrQueryDescriptors, $iArrTrainDescriptors, $matches, $maxDistance, $iArrMask, $compactResult)

    If $bMaskIsArray Then
        Call("_VectorOf" & $typeOfMask & "Release", $vectorMask)
    EndIf

    If $typeOfMask <> Default Then
        _cveInputArrayRelease($iArrMask)
        If $bMaskCreate Then
            Call("_cve" & $typeOfMask & "Release", $mask)
        EndIf
    EndIf

    If $bTrainDescriptorsIsArray Then
        Call("_VectorOf" & $typeOfTrainDescriptors & "Release", $vectorTrainDescriptors)
    EndIf

    If $typeOfTrainDescriptors <> Default Then
        _cveInputArrayRelease($iArrTrainDescriptors)
        If $bTrainDescriptorsCreate Then
            Call("_cve" & $typeOfTrainDescriptors & "Release", $trainDescriptors)
        EndIf
    EndIf

    If $bQueryDescriptorsIsArray Then
        Call("_VectorOf" & $typeOfQueryDescriptors & "Release", $vectorQueryDescriptors)
    EndIf

    If $typeOfQueryDescriptors <> Default Then
        _cveInputArrayRelease($iArrQueryDescriptors)
        If $bQueryDescriptorsCreate Then
            Call("_cve" & $typeOfQueryDescriptors & "Release", $queryDescriptors)
        EndIf
    EndIf
EndFunc   ;==>_cveDescriptorMatcherRadiusMatch1Typed

Func _cveDescriptorMatcherRadiusMatch1Mat($matcher, $queryDescriptors, $trainDescriptors, $matches, $maxDistance, $mask, $compactResult)
    ; cveDescriptorMatcherRadiusMatch1 using cv::Mat instead of _*Array
    _cveDescriptorMatcherRadiusMatch1Typed($matcher, "Mat", $queryDescriptors, "Mat", $trainDescriptors, $matches, $maxDistance, "Mat", $mask, $compactResult)
EndFunc   ;==>_cveDescriptorMatcherRadiusMatch1Mat

Func _cveDescriptorMatcherRadiusMatch2($matcher, $queryDescriptors, $matches, $maxDistance, $masks, $compactResult)
    ; CVAPI(void) cveDescriptorMatcherRadiusMatch2(cv::DescriptorMatcher* matcher, cv::_InputArray* queryDescriptors, std::vector<std::vector<cv::DMatch>>* matches, float maxDistance, cv::_InputArray* masks, bool compactResult);

    Local $sMatcherDllType
    If IsDllStruct($matcher) Then
        $sMatcherDllType = "struct*"
    Else
        $sMatcherDllType = "ptr"
    EndIf

    Local $sQueryDescriptorsDllType
    If IsDllStruct($queryDescriptors) Then
        $sQueryDescriptorsDllType = "struct*"
    Else
        $sQueryDescriptorsDllType = "ptr"
    EndIf

    Local $vecMatches, $iArrMatchesSize
    Local $bMatchesIsArray = IsArray($matches)

    If $bMatchesIsArray Then
        $vecMatches = _VectorOfVectorOfDMatchCreate()

        $iArrMatchesSize = UBound($matches)
        For $i = 0 To $iArrMatchesSize - 1
            _VectorOfVectorOfDMatchPush($vecMatches, $matches[$i])
        Next
    Else
        $vecMatches = $matches
    EndIf

    Local $sMatchesDllType
    If IsDllStruct($matches) Then
        $sMatchesDllType = "struct*"
    Else
        $sMatchesDllType = "ptr"
    EndIf

    Local $sMasksDllType
    If IsDllStruct($masks) Then
        $sMasksDllType = "struct*"
    Else
        $sMasksDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDescriptorMatcherRadiusMatch2", $sMatcherDllType, $matcher, $sQueryDescriptorsDllType, $queryDescriptors, $sMatchesDllType, $vecMatches, "float", $maxDistance, $sMasksDllType, $masks, "boolean", $compactResult), "cveDescriptorMatcherRadiusMatch2", @error)

    If $bMatchesIsArray Then
        _VectorOfVectorOfDMatchRelease($vecMatches)
    EndIf
EndFunc   ;==>_cveDescriptorMatcherRadiusMatch2

Func _cveDescriptorMatcherRadiusMatch2Typed($matcher, $typeOfQueryDescriptors, $queryDescriptors, $matches, $maxDistance, $typeOfMasks, $masks, $compactResult)

    Local $iArrQueryDescriptors, $vectorQueryDescriptors, $iArrQueryDescriptorsSize
    Local $bQueryDescriptorsIsArray = IsArray($queryDescriptors)
    Local $bQueryDescriptorsCreate = IsDllStruct($queryDescriptors) And $typeOfQueryDescriptors == "Scalar"

    If $typeOfQueryDescriptors == Default Then
        $iArrQueryDescriptors = $queryDescriptors
    ElseIf $bQueryDescriptorsIsArray Then
        $vectorQueryDescriptors = Call("_VectorOf" & $typeOfQueryDescriptors & "Create")

        $iArrQueryDescriptorsSize = UBound($queryDescriptors)
        For $i = 0 To $iArrQueryDescriptorsSize - 1
            Call("_VectorOf" & $typeOfQueryDescriptors & "Push", $vectorQueryDescriptors, $queryDescriptors[$i])
        Next

        $iArrQueryDescriptors = Call("_cveInputArrayFromVectorOf" & $typeOfQueryDescriptors, $vectorQueryDescriptors)
    Else
        If $bQueryDescriptorsCreate Then
            $queryDescriptors = Call("_cve" & $typeOfQueryDescriptors & "Create", $queryDescriptors)
        EndIf
        $iArrQueryDescriptors = Call("_cveInputArrayFrom" & $typeOfQueryDescriptors, $queryDescriptors)
    EndIf

    Local $iArrMasks, $vectorMasks, $iArrMasksSize
    Local $bMasksIsArray = IsArray($masks)
    Local $bMasksCreate = IsDllStruct($masks) And $typeOfMasks == "Scalar"

    If $typeOfMasks == Default Then
        $iArrMasks = $masks
    ElseIf $bMasksIsArray Then
        $vectorMasks = Call("_VectorOf" & $typeOfMasks & "Create")

        $iArrMasksSize = UBound($masks)
        For $i = 0 To $iArrMasksSize - 1
            Call("_VectorOf" & $typeOfMasks & "Push", $vectorMasks, $masks[$i])
        Next

        $iArrMasks = Call("_cveInputArrayFromVectorOf" & $typeOfMasks, $vectorMasks)
    Else
        If $bMasksCreate Then
            $masks = Call("_cve" & $typeOfMasks & "Create", $masks)
        EndIf
        $iArrMasks = Call("_cveInputArrayFrom" & $typeOfMasks, $masks)
    EndIf

    _cveDescriptorMatcherRadiusMatch2($matcher, $iArrQueryDescriptors, $matches, $maxDistance, $iArrMasks, $compactResult)

    If $bMasksIsArray Then
        Call("_VectorOf" & $typeOfMasks & "Release", $vectorMasks)
    EndIf

    If $typeOfMasks <> Default Then
        _cveInputArrayRelease($iArrMasks)
        If $bMasksCreate Then
            Call("_cve" & $typeOfMasks & "Release", $masks)
        EndIf
    EndIf

    If $bQueryDescriptorsIsArray Then
        Call("_VectorOf" & $typeOfQueryDescriptors & "Release", $vectorQueryDescriptors)
    EndIf

    If $typeOfQueryDescriptors <> Default Then
        _cveInputArrayRelease($iArrQueryDescriptors)
        If $bQueryDescriptorsCreate Then
            Call("_cve" & $typeOfQueryDescriptors & "Release", $queryDescriptors)
        EndIf
    EndIf
EndFunc   ;==>_cveDescriptorMatcherRadiusMatch2Typed

Func _cveDescriptorMatcherRadiusMatch2Mat($matcher, $queryDescriptors, $matches, $maxDistance, $masks, $compactResult)
    ; cveDescriptorMatcherRadiusMatch2 using cv::Mat instead of _*Array
    _cveDescriptorMatcherRadiusMatch2Typed($matcher, "Mat", $queryDescriptors, $matches, $maxDistance, "Mat", $masks, $compactResult)
EndFunc   ;==>_cveDescriptorMatcherRadiusMatch2Mat

Func _cveBFMatcherCreate($distanceType, $crossCheck, $m)
    ; CVAPI(cv::BFMatcher*) cveBFMatcherCreate(int distanceType, bool crossCheck, cv::DescriptorMatcher** m);

    Local $sMDllType
    If IsDllStruct($m) Then
        $sMDllType = "struct*"
    ElseIf $m == Null Then
        $sMDllType = "ptr"
    Else
        $sMDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveBFMatcherCreate", "int", $distanceType, "boolean", $crossCheck, $sMDllType, $m), "cveBFMatcherCreate", @error)
EndFunc   ;==>_cveBFMatcherCreate

Func _cveBFMatcherRelease($matcher)
    ; CVAPI(void) cveBFMatcherRelease(cv::BFMatcher** matcher);

    Local $sMatcherDllType
    If IsDllStruct($matcher) Then
        $sMatcherDllType = "struct*"
    ElseIf $matcher == Null Then
        $sMatcherDllType = "ptr"
    Else
        $sMatcherDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBFMatcherRelease", $sMatcherDllType, $matcher), "cveBFMatcherRelease", @error)
EndFunc   ;==>_cveBFMatcherRelease

Func _cveFlannBasedMatcherCreate($indexParams, $searchParams, $m)
    ; CVAPI(cv::FlannBasedMatcher*) cveFlannBasedMatcherCreate(cv::flann::IndexParams* indexParams, cv::flann::SearchParams* searchParams, cv::DescriptorMatcher** m);

    Local $sIndexParamsDllType
    If IsDllStruct($indexParams) Then
        $sIndexParamsDllType = "struct*"
    Else
        $sIndexParamsDllType = "ptr"
    EndIf

    Local $sSearchParamsDllType
    If IsDllStruct($searchParams) Then
        $sSearchParamsDllType = "struct*"
    Else
        $sSearchParamsDllType = "ptr"
    EndIf

    Local $sMDllType
    If IsDllStruct($m) Then
        $sMDllType = "struct*"
    ElseIf $m == Null Then
        $sMDllType = "ptr"
    Else
        $sMDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveFlannBasedMatcherCreate", $sIndexParamsDllType, $indexParams, $sSearchParamsDllType, $searchParams, $sMDllType, $m), "cveFlannBasedMatcherCreate", @error)
EndFunc   ;==>_cveFlannBasedMatcherCreate

Func _cveFlannBasedMatcherRelease($matcher)
    ; CVAPI(void) cveFlannBasedMatcherRelease(cv::FlannBasedMatcher** matcher);

    Local $sMatcherDllType
    If IsDllStruct($matcher) Then
        $sMatcherDllType = "struct*"
    ElseIf $matcher == Null Then
        $sMatcherDllType = "ptr"
    Else
        $sMatcherDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFlannBasedMatcherRelease", $sMatcherDllType, $matcher), "cveFlannBasedMatcherRelease", @error)
EndFunc   ;==>_cveFlannBasedMatcherRelease

Func _voteForSizeAndOrientation($modelKeyPoints, $observedKeyPoints, $matches, $mask, $scaleIncrement, $rotationBins)
    ; CVAPI(int) voteForSizeAndOrientation(std::vector<cv::KeyPoint>* modelKeyPoints, std::vector<cv::KeyPoint>* observedKeyPoints, std::vector<std::vector<cv::DMatch>>* matches, cv::Mat* mask, double scaleIncrement, int rotationBins);

    Local $vecModelKeyPoints, $iArrModelKeyPointsSize
    Local $bModelKeyPointsIsArray = IsArray($modelKeyPoints)

    If $bModelKeyPointsIsArray Then
        $vecModelKeyPoints = _VectorOfKeyPointCreate()

        $iArrModelKeyPointsSize = UBound($modelKeyPoints)
        For $i = 0 To $iArrModelKeyPointsSize - 1
            _VectorOfKeyPointPush($vecModelKeyPoints, $modelKeyPoints[$i])
        Next
    Else
        $vecModelKeyPoints = $modelKeyPoints
    EndIf

    Local $sModelKeyPointsDllType
    If IsDllStruct($modelKeyPoints) Then
        $sModelKeyPointsDllType = "struct*"
    Else
        $sModelKeyPointsDllType = "ptr"
    EndIf

    Local $vecObservedKeyPoints, $iArrObservedKeyPointsSize
    Local $bObservedKeyPointsIsArray = IsArray($observedKeyPoints)

    If $bObservedKeyPointsIsArray Then
        $vecObservedKeyPoints = _VectorOfKeyPointCreate()

        $iArrObservedKeyPointsSize = UBound($observedKeyPoints)
        For $i = 0 To $iArrObservedKeyPointsSize - 1
            _VectorOfKeyPointPush($vecObservedKeyPoints, $observedKeyPoints[$i])
        Next
    Else
        $vecObservedKeyPoints = $observedKeyPoints
    EndIf

    Local $sObservedKeyPointsDllType
    If IsDllStruct($observedKeyPoints) Then
        $sObservedKeyPointsDllType = "struct*"
    Else
        $sObservedKeyPointsDllType = "ptr"
    EndIf

    Local $vecMatches, $iArrMatchesSize
    Local $bMatchesIsArray = IsArray($matches)

    If $bMatchesIsArray Then
        $vecMatches = _VectorOfVectorOfDMatchCreate()

        $iArrMatchesSize = UBound($matches)
        For $i = 0 To $iArrMatchesSize - 1
            _VectorOfVectorOfDMatchPush($vecMatches, $matches[$i])
        Next
    Else
        $vecMatches = $matches
    EndIf

    Local $sMatchesDllType
    If IsDllStruct($matches) Then
        $sMatchesDllType = "struct*"
    Else
        $sMatchesDllType = "ptr"
    EndIf

    Local $sMaskDllType
    If IsDllStruct($mask) Then
        $sMaskDllType = "struct*"
    Else
        $sMaskDllType = "ptr"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "voteForSizeAndOrientation", $sModelKeyPointsDllType, $vecModelKeyPoints, $sObservedKeyPointsDllType, $vecObservedKeyPoints, $sMatchesDllType, $vecMatches, $sMaskDllType, $mask, "double", $scaleIncrement, "int", $rotationBins), "voteForSizeAndOrientation", @error)

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

    Local $sFeature2DDllType
    If IsDllStruct($feature2D) Then
        $sFeature2DDllType = "struct*"
    Else
        $sFeature2DDllType = "ptr"
    EndIf

    Local $sImageDllType
    If IsDllStruct($image) Then
        $sImageDllType = "struct*"
    Else
        $sImageDllType = "ptr"
    EndIf

    Local $sMaskDllType
    If IsDllStruct($mask) Then
        $sMaskDllType = "struct*"
    Else
        $sMaskDllType = "ptr"
    EndIf

    Local $vecKeypoints, $iArrKeypointsSize
    Local $bKeypointsIsArray = IsArray($keypoints)

    If $bKeypointsIsArray Then
        $vecKeypoints = _VectorOfKeyPointCreate()

        $iArrKeypointsSize = UBound($keypoints)
        For $i = 0 To $iArrKeypointsSize - 1
            _VectorOfKeyPointPush($vecKeypoints, $keypoints[$i])
        Next
    Else
        $vecKeypoints = $keypoints
    EndIf

    Local $sKeypointsDllType
    If IsDllStruct($keypoints) Then
        $sKeypointsDllType = "struct*"
    Else
        $sKeypointsDllType = "ptr"
    EndIf

    Local $sDescriptorsDllType
    If IsDllStruct($descriptors) Then
        $sDescriptorsDllType = "struct*"
    Else
        $sDescriptorsDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "CvFeature2DDetectAndCompute", $sFeature2DDllType, $feature2D, $sImageDllType, $image, $sMaskDllType, $mask, $sKeypointsDllType, $vecKeypoints, $sDescriptorsDllType, $descriptors, "boolean", $useProvidedKeyPoints), "CvFeature2DDetectAndCompute", @error)

    If $bKeypointsIsArray Then
        _VectorOfKeyPointRelease($vecKeypoints)
    EndIf
EndFunc   ;==>_CvFeature2DDetectAndCompute

Func _CvFeature2DDetectAndComputeTyped($feature2D, $typeOfImage, $image, $typeOfMask, $mask, $keypoints, $typeOfDescriptors, $descriptors, $useProvidedKeyPoints)

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

    Local $oArrDescriptors, $vectorDescriptors, $iArrDescriptorsSize
    Local $bDescriptorsIsArray = IsArray($descriptors)
    Local $bDescriptorsCreate = IsDllStruct($descriptors) And $typeOfDescriptors == "Scalar"

    If $typeOfDescriptors == Default Then
        $oArrDescriptors = $descriptors
    ElseIf $bDescriptorsIsArray Then
        $vectorDescriptors = Call("_VectorOf" & $typeOfDescriptors & "Create")

        $iArrDescriptorsSize = UBound($descriptors)
        For $i = 0 To $iArrDescriptorsSize - 1
            Call("_VectorOf" & $typeOfDescriptors & "Push", $vectorDescriptors, $descriptors[$i])
        Next

        $oArrDescriptors = Call("_cveOutputArrayFromVectorOf" & $typeOfDescriptors, $vectorDescriptors)
    Else
        If $bDescriptorsCreate Then
            $descriptors = Call("_cve" & $typeOfDescriptors & "Create", $descriptors)
        EndIf
        $oArrDescriptors = Call("_cveOutputArrayFrom" & $typeOfDescriptors, $descriptors)
    EndIf

    _CvFeature2DDetectAndCompute($feature2D, $iArrImage, $iArrMask, $keypoints, $oArrDescriptors, $useProvidedKeyPoints)

    If $bDescriptorsIsArray Then
        Call("_VectorOf" & $typeOfDescriptors & "Release", $vectorDescriptors)
    EndIf

    If $typeOfDescriptors <> Default Then
        _cveOutputArrayRelease($oArrDescriptors)
        If $bDescriptorsCreate Then
            Call("_cve" & $typeOfDescriptors & "Release", $descriptors)
        EndIf
    EndIf

    If $bMaskIsArray Then
        Call("_VectorOf" & $typeOfMask & "Release", $vectorMask)
    EndIf

    If $typeOfMask <> Default Then
        _cveInputArrayRelease($iArrMask)
        If $bMaskCreate Then
            Call("_cve" & $typeOfMask & "Release", $mask)
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
EndFunc   ;==>_CvFeature2DDetectAndComputeTyped

Func _CvFeature2DDetectAndComputeMat($feature2D, $image, $mask, $keypoints, $descriptors, $useProvidedKeyPoints)
    ; CvFeature2DDetectAndCompute using cv::Mat instead of _*Array
    _CvFeature2DDetectAndComputeTyped($feature2D, "Mat", $image, "Mat", $mask, $keypoints, "Mat", $descriptors, $useProvidedKeyPoints)
EndFunc   ;==>_CvFeature2DDetectAndComputeMat

Func _CvFeature2DDetect($feature2D, $image, $keypoints, $mask)
    ; CVAPI(void) CvFeature2DDetect(cv::Feature2D* feature2D, cv::_InputArray* image, std::vector<cv::KeyPoint>* keypoints, cv::_InputArray* mask);

    Local $sFeature2DDllType
    If IsDllStruct($feature2D) Then
        $sFeature2DDllType = "struct*"
    Else
        $sFeature2DDllType = "ptr"
    EndIf

    Local $sImageDllType
    If IsDllStruct($image) Then
        $sImageDllType = "struct*"
    Else
        $sImageDllType = "ptr"
    EndIf

    Local $vecKeypoints, $iArrKeypointsSize
    Local $bKeypointsIsArray = IsArray($keypoints)

    If $bKeypointsIsArray Then
        $vecKeypoints = _VectorOfKeyPointCreate()

        $iArrKeypointsSize = UBound($keypoints)
        For $i = 0 To $iArrKeypointsSize - 1
            _VectorOfKeyPointPush($vecKeypoints, $keypoints[$i])
        Next
    Else
        $vecKeypoints = $keypoints
    EndIf

    Local $sKeypointsDllType
    If IsDllStruct($keypoints) Then
        $sKeypointsDllType = "struct*"
    Else
        $sKeypointsDllType = "ptr"
    EndIf

    Local $sMaskDllType
    If IsDllStruct($mask) Then
        $sMaskDllType = "struct*"
    Else
        $sMaskDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "CvFeature2DDetect", $sFeature2DDllType, $feature2D, $sImageDllType, $image, $sKeypointsDllType, $vecKeypoints, $sMaskDllType, $mask), "CvFeature2DDetect", @error)

    If $bKeypointsIsArray Then
        _VectorOfKeyPointRelease($vecKeypoints)
    EndIf
EndFunc   ;==>_CvFeature2DDetect

Func _CvFeature2DDetectTyped($feature2D, $typeOfImage, $image, $keypoints, $typeOfMask, $mask)

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

    _CvFeature2DDetect($feature2D, $iArrImage, $keypoints, $iArrMask)

    If $bMaskIsArray Then
        Call("_VectorOf" & $typeOfMask & "Release", $vectorMask)
    EndIf

    If $typeOfMask <> Default Then
        _cveInputArrayRelease($iArrMask)
        If $bMaskCreate Then
            Call("_cve" & $typeOfMask & "Release", $mask)
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
EndFunc   ;==>_CvFeature2DDetectTyped

Func _CvFeature2DDetectMat($feature2D, $image, $keypoints, $mask)
    ; CvFeature2DDetect using cv::Mat instead of _*Array
    _CvFeature2DDetectTyped($feature2D, "Mat", $image, $keypoints, "Mat", $mask)
EndFunc   ;==>_CvFeature2DDetectMat

Func _CvFeature2DCompute($feature2D, $image, $keypoints, $descriptors)
    ; CVAPI(void) CvFeature2DCompute(cv::Feature2D* feature2D, cv::_InputArray* image, std::vector<cv::KeyPoint>* keypoints, cv::_OutputArray* descriptors);

    Local $sFeature2DDllType
    If IsDllStruct($feature2D) Then
        $sFeature2DDllType = "struct*"
    Else
        $sFeature2DDllType = "ptr"
    EndIf

    Local $sImageDllType
    If IsDllStruct($image) Then
        $sImageDllType = "struct*"
    Else
        $sImageDllType = "ptr"
    EndIf

    Local $vecKeypoints, $iArrKeypointsSize
    Local $bKeypointsIsArray = IsArray($keypoints)

    If $bKeypointsIsArray Then
        $vecKeypoints = _VectorOfKeyPointCreate()

        $iArrKeypointsSize = UBound($keypoints)
        For $i = 0 To $iArrKeypointsSize - 1
            _VectorOfKeyPointPush($vecKeypoints, $keypoints[$i])
        Next
    Else
        $vecKeypoints = $keypoints
    EndIf

    Local $sKeypointsDllType
    If IsDllStruct($keypoints) Then
        $sKeypointsDllType = "struct*"
    Else
        $sKeypointsDllType = "ptr"
    EndIf

    Local $sDescriptorsDllType
    If IsDllStruct($descriptors) Then
        $sDescriptorsDllType = "struct*"
    Else
        $sDescriptorsDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "CvFeature2DCompute", $sFeature2DDllType, $feature2D, $sImageDllType, $image, $sKeypointsDllType, $vecKeypoints, $sDescriptorsDllType, $descriptors), "CvFeature2DCompute", @error)

    If $bKeypointsIsArray Then
        _VectorOfKeyPointRelease($vecKeypoints)
    EndIf
EndFunc   ;==>_CvFeature2DCompute

Func _CvFeature2DComputeTyped($feature2D, $typeOfImage, $image, $keypoints, $typeOfDescriptors, $descriptors)

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

    Local $oArrDescriptors, $vectorDescriptors, $iArrDescriptorsSize
    Local $bDescriptorsIsArray = IsArray($descriptors)
    Local $bDescriptorsCreate = IsDllStruct($descriptors) And $typeOfDescriptors == "Scalar"

    If $typeOfDescriptors == Default Then
        $oArrDescriptors = $descriptors
    ElseIf $bDescriptorsIsArray Then
        $vectorDescriptors = Call("_VectorOf" & $typeOfDescriptors & "Create")

        $iArrDescriptorsSize = UBound($descriptors)
        For $i = 0 To $iArrDescriptorsSize - 1
            Call("_VectorOf" & $typeOfDescriptors & "Push", $vectorDescriptors, $descriptors[$i])
        Next

        $oArrDescriptors = Call("_cveOutputArrayFromVectorOf" & $typeOfDescriptors, $vectorDescriptors)
    Else
        If $bDescriptorsCreate Then
            $descriptors = Call("_cve" & $typeOfDescriptors & "Create", $descriptors)
        EndIf
        $oArrDescriptors = Call("_cveOutputArrayFrom" & $typeOfDescriptors, $descriptors)
    EndIf

    _CvFeature2DCompute($feature2D, $iArrImage, $keypoints, $oArrDescriptors)

    If $bDescriptorsIsArray Then
        Call("_VectorOf" & $typeOfDescriptors & "Release", $vectorDescriptors)
    EndIf

    If $typeOfDescriptors <> Default Then
        _cveOutputArrayRelease($oArrDescriptors)
        If $bDescriptorsCreate Then
            Call("_cve" & $typeOfDescriptors & "Release", $descriptors)
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
EndFunc   ;==>_CvFeature2DComputeTyped

Func _CvFeature2DComputeMat($feature2D, $image, $keypoints, $descriptors)
    ; CvFeature2DCompute using cv::Mat instead of _*Array
    _CvFeature2DComputeTyped($feature2D, "Mat", $image, $keypoints, "Mat", $descriptors)
EndFunc   ;==>_CvFeature2DComputeMat

Func _CvFeature2DGetDescriptorSize($feature2D)
    ; CVAPI(int) CvFeature2DGetDescriptorSize(cv::Feature2D* feature2D);

    Local $sFeature2DDllType
    If IsDllStruct($feature2D) Then
        $sFeature2DDllType = "struct*"
    Else
        $sFeature2DDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "CvFeature2DGetDescriptorSize", $sFeature2DDllType, $feature2D), "CvFeature2DGetDescriptorSize", @error)
EndFunc   ;==>_CvFeature2DGetDescriptorSize

Func _CvFeature2DGetAlgorithm($feature2D)
    ; CVAPI(cv::Algorithm*) CvFeature2DGetAlgorithm(cv::Feature2D* feature2D);

    Local $sFeature2DDllType
    If IsDllStruct($feature2D) Then
        $sFeature2DDllType = "struct*"
    Else
        $sFeature2DDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "CvFeature2DGetAlgorithm", $sFeature2DDllType, $feature2D), "CvFeature2DGetAlgorithm", @error)
EndFunc   ;==>_CvFeature2DGetAlgorithm

Func _cveBOWKMeansTrainerCreate($clusterCount, $termcrit, $attempts, $flags)
    ; CVAPI(cv::BOWKMeansTrainer*) cveBOWKMeansTrainerCreate(int clusterCount, const CvTermCriteria* termcrit, int attempts, int flags);

    Local $sTermcritDllType
    If IsDllStruct($termcrit) Then
        $sTermcritDllType = "struct*"
    Else
        $sTermcritDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveBOWKMeansTrainerCreate", "int", $clusterCount, $sTermcritDllType, $termcrit, "int", $attempts, "int", $flags), "cveBOWKMeansTrainerCreate", @error)
EndFunc   ;==>_cveBOWKMeansTrainerCreate

Func _cveBOWKMeansTrainerRelease($trainer)
    ; CVAPI(void) cveBOWKMeansTrainerRelease(cv::BOWKMeansTrainer** trainer);

    Local $sTrainerDllType
    If IsDllStruct($trainer) Then
        $sTrainerDllType = "struct*"
    ElseIf $trainer == Null Then
        $sTrainerDllType = "ptr"
    Else
        $sTrainerDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBOWKMeansTrainerRelease", $sTrainerDllType, $trainer), "cveBOWKMeansTrainerRelease", @error)
EndFunc   ;==>_cveBOWKMeansTrainerRelease

Func _cveBOWKMeansTrainerGetDescriptorCount($trainer)
    ; CVAPI(int) cveBOWKMeansTrainerGetDescriptorCount(cv::BOWKMeansTrainer* trainer);

    Local $sTrainerDllType
    If IsDllStruct($trainer) Then
        $sTrainerDllType = "struct*"
    Else
        $sTrainerDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveBOWKMeansTrainerGetDescriptorCount", $sTrainerDllType, $trainer), "cveBOWKMeansTrainerGetDescriptorCount", @error)
EndFunc   ;==>_cveBOWKMeansTrainerGetDescriptorCount

Func _cveBOWKMeansTrainerAdd($trainer, $descriptors)
    ; CVAPI(void) cveBOWKMeansTrainerAdd(cv::BOWKMeansTrainer* trainer, cv::Mat* descriptors);

    Local $sTrainerDllType
    If IsDllStruct($trainer) Then
        $sTrainerDllType = "struct*"
    Else
        $sTrainerDllType = "ptr"
    EndIf

    Local $sDescriptorsDllType
    If IsDllStruct($descriptors) Then
        $sDescriptorsDllType = "struct*"
    Else
        $sDescriptorsDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBOWKMeansTrainerAdd", $sTrainerDllType, $trainer, $sDescriptorsDllType, $descriptors), "cveBOWKMeansTrainerAdd", @error)
EndFunc   ;==>_cveBOWKMeansTrainerAdd

Func _cveBOWKMeansTrainerCluster($trainer, $cluster)
    ; CVAPI(void) cveBOWKMeansTrainerCluster(cv::BOWKMeansTrainer* trainer, cv::_OutputArray* cluster);

    Local $sTrainerDllType
    If IsDllStruct($trainer) Then
        $sTrainerDllType = "struct*"
    Else
        $sTrainerDllType = "ptr"
    EndIf

    Local $sClusterDllType
    If IsDllStruct($cluster) Then
        $sClusterDllType = "struct*"
    Else
        $sClusterDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBOWKMeansTrainerCluster", $sTrainerDllType, $trainer, $sClusterDllType, $cluster), "cveBOWKMeansTrainerCluster", @error)
EndFunc   ;==>_cveBOWKMeansTrainerCluster

Func _cveBOWKMeansTrainerClusterTyped($trainer, $typeOfCluster, $cluster)

    Local $oArrCluster, $vectorCluster, $iArrClusterSize
    Local $bClusterIsArray = IsArray($cluster)
    Local $bClusterCreate = IsDllStruct($cluster) And $typeOfCluster == "Scalar"

    If $typeOfCluster == Default Then
        $oArrCluster = $cluster
    ElseIf $bClusterIsArray Then
        $vectorCluster = Call("_VectorOf" & $typeOfCluster & "Create")

        $iArrClusterSize = UBound($cluster)
        For $i = 0 To $iArrClusterSize - 1
            Call("_VectorOf" & $typeOfCluster & "Push", $vectorCluster, $cluster[$i])
        Next

        $oArrCluster = Call("_cveOutputArrayFromVectorOf" & $typeOfCluster, $vectorCluster)
    Else
        If $bClusterCreate Then
            $cluster = Call("_cve" & $typeOfCluster & "Create", $cluster)
        EndIf
        $oArrCluster = Call("_cveOutputArrayFrom" & $typeOfCluster, $cluster)
    EndIf

    _cveBOWKMeansTrainerCluster($trainer, $oArrCluster)

    If $bClusterIsArray Then
        Call("_VectorOf" & $typeOfCluster & "Release", $vectorCluster)
    EndIf

    If $typeOfCluster <> Default Then
        _cveOutputArrayRelease($oArrCluster)
        If $bClusterCreate Then
            Call("_cve" & $typeOfCluster & "Release", $cluster)
        EndIf
    EndIf
EndFunc   ;==>_cveBOWKMeansTrainerClusterTyped

Func _cveBOWKMeansTrainerClusterMat($trainer, $cluster)
    ; cveBOWKMeansTrainerCluster using cv::Mat instead of _*Array
    _cveBOWKMeansTrainerClusterTyped($trainer, "Mat", $cluster)
EndFunc   ;==>_cveBOWKMeansTrainerClusterMat

Func _cveBOWImgDescriptorExtractorCreate($descriptorExtractor, $descriptorMatcher)
    ; CVAPI(cv::BOWImgDescriptorExtractor*) cveBOWImgDescriptorExtractorCreate(cv::Feature2D* descriptorExtractor, cv::DescriptorMatcher* descriptorMatcher);

    Local $sDescriptorExtractorDllType
    If IsDllStruct($descriptorExtractor) Then
        $sDescriptorExtractorDllType = "struct*"
    Else
        $sDescriptorExtractorDllType = "ptr"
    EndIf

    Local $sDescriptorMatcherDllType
    If IsDllStruct($descriptorMatcher) Then
        $sDescriptorMatcherDllType = "struct*"
    Else
        $sDescriptorMatcherDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveBOWImgDescriptorExtractorCreate", $sDescriptorExtractorDllType, $descriptorExtractor, $sDescriptorMatcherDllType, $descriptorMatcher), "cveBOWImgDescriptorExtractorCreate", @error)
EndFunc   ;==>_cveBOWImgDescriptorExtractorCreate

Func _cveBOWImgDescriptorExtractorRelease($descriptorExtractor)
    ; CVAPI(void) cveBOWImgDescriptorExtractorRelease(cv::BOWImgDescriptorExtractor** descriptorExtractor);

    Local $sDescriptorExtractorDllType
    If IsDllStruct($descriptorExtractor) Then
        $sDescriptorExtractorDllType = "struct*"
    ElseIf $descriptorExtractor == Null Then
        $sDescriptorExtractorDllType = "ptr"
    Else
        $sDescriptorExtractorDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBOWImgDescriptorExtractorRelease", $sDescriptorExtractorDllType, $descriptorExtractor), "cveBOWImgDescriptorExtractorRelease", @error)
EndFunc   ;==>_cveBOWImgDescriptorExtractorRelease

Func _cveBOWImgDescriptorExtractorSetVocabulary($bowImgDescriptorExtractor, $vocabulary)
    ; CVAPI(void) cveBOWImgDescriptorExtractorSetVocabulary(cv::BOWImgDescriptorExtractor* bowImgDescriptorExtractor, cv::Mat* vocabulary);

    Local $sBowImgDescriptorExtractorDllType
    If IsDllStruct($bowImgDescriptorExtractor) Then
        $sBowImgDescriptorExtractorDllType = "struct*"
    Else
        $sBowImgDescriptorExtractorDllType = "ptr"
    EndIf

    Local $sVocabularyDllType
    If IsDllStruct($vocabulary) Then
        $sVocabularyDllType = "struct*"
    Else
        $sVocabularyDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBOWImgDescriptorExtractorSetVocabulary", $sBowImgDescriptorExtractorDllType, $bowImgDescriptorExtractor, $sVocabularyDllType, $vocabulary), "cveBOWImgDescriptorExtractorSetVocabulary", @error)
EndFunc   ;==>_cveBOWImgDescriptorExtractorSetVocabulary

Func _cveBOWImgDescriptorExtractorCompute($bowImgDescriptorExtractor, $image, $keypoints, $imgDescriptor)
    ; CVAPI(void) cveBOWImgDescriptorExtractorCompute(cv::BOWImgDescriptorExtractor* bowImgDescriptorExtractor, cv::_InputArray* image, std::vector<cv::KeyPoint>* keypoints, cv::Mat* imgDescriptor);

    Local $sBowImgDescriptorExtractorDllType
    If IsDllStruct($bowImgDescriptorExtractor) Then
        $sBowImgDescriptorExtractorDllType = "struct*"
    Else
        $sBowImgDescriptorExtractorDllType = "ptr"
    EndIf

    Local $sImageDllType
    If IsDllStruct($image) Then
        $sImageDllType = "struct*"
    Else
        $sImageDllType = "ptr"
    EndIf

    Local $vecKeypoints, $iArrKeypointsSize
    Local $bKeypointsIsArray = IsArray($keypoints)

    If $bKeypointsIsArray Then
        $vecKeypoints = _VectorOfKeyPointCreate()

        $iArrKeypointsSize = UBound($keypoints)
        For $i = 0 To $iArrKeypointsSize - 1
            _VectorOfKeyPointPush($vecKeypoints, $keypoints[$i])
        Next
    Else
        $vecKeypoints = $keypoints
    EndIf

    Local $sKeypointsDllType
    If IsDllStruct($keypoints) Then
        $sKeypointsDllType = "struct*"
    Else
        $sKeypointsDllType = "ptr"
    EndIf

    Local $sImgDescriptorDllType
    If IsDllStruct($imgDescriptor) Then
        $sImgDescriptorDllType = "struct*"
    Else
        $sImgDescriptorDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBOWImgDescriptorExtractorCompute", $sBowImgDescriptorExtractorDllType, $bowImgDescriptorExtractor, $sImageDllType, $image, $sKeypointsDllType, $vecKeypoints, $sImgDescriptorDllType, $imgDescriptor), "cveBOWImgDescriptorExtractorCompute", @error)

    If $bKeypointsIsArray Then
        _VectorOfKeyPointRelease($vecKeypoints)
    EndIf
EndFunc   ;==>_cveBOWImgDescriptorExtractorCompute

Func _cveBOWImgDescriptorExtractorComputeTyped($bowImgDescriptorExtractor, $typeOfImage, $image, $keypoints, $imgDescriptor)

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

    _cveBOWImgDescriptorExtractorCompute($bowImgDescriptorExtractor, $iArrImage, $keypoints, $imgDescriptor)

    If $bImageIsArray Then
        Call("_VectorOf" & $typeOfImage & "Release", $vectorImage)
    EndIf

    If $typeOfImage <> Default Then
        _cveInputArrayRelease($iArrImage)
        If $bImageCreate Then
            Call("_cve" & $typeOfImage & "Release", $image)
        EndIf
    EndIf
EndFunc   ;==>_cveBOWImgDescriptorExtractorComputeTyped

Func _cveBOWImgDescriptorExtractorComputeMat($bowImgDescriptorExtractor, $image, $keypoints, $imgDescriptor)
    ; cveBOWImgDescriptorExtractorCompute using cv::Mat instead of _*Array
    _cveBOWImgDescriptorExtractorComputeTyped($bowImgDescriptorExtractor, "Mat", $image, $keypoints, $imgDescriptor)
EndFunc   ;==>_cveBOWImgDescriptorExtractorComputeMat

Func _cveKAZEDetectorCreate($extended, $upright, $threshold, $octaves, $sublevels, $diffusivity, $feature2D, $sharedPtr)
    ; CVAPI(cv::KAZE*) cveKAZEDetectorCreate(bool extended, bool upright, float threshold, int octaves, int sublevels, int diffusivity, cv::Feature2D** feature2D, cv::Ptr<cv::KAZE>** sharedPtr);

    Local $sFeature2DDllType
    If IsDllStruct($feature2D) Then
        $sFeature2DDllType = "struct*"
    ElseIf $feature2D == Null Then
        $sFeature2DDllType = "ptr"
    Else
        $sFeature2DDllType = "ptr*"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveKAZEDetectorCreate", "boolean", $extended, "boolean", $upright, "float", $threshold, "int", $octaves, "int", $sublevels, "int", $diffusivity, $sFeature2DDllType, $feature2D, $sSharedPtrDllType, $sharedPtr), "cveKAZEDetectorCreate", @error)
EndFunc   ;==>_cveKAZEDetectorCreate

Func _cveKAZEDetectorRelease($sharedPtr)
    ; CVAPI(void) cveKAZEDetectorRelease(cv::Ptr<cv::KAZE>** sharedPtr);

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveKAZEDetectorRelease", $sSharedPtrDllType, $sharedPtr), "cveKAZEDetectorRelease", @error)
EndFunc   ;==>_cveKAZEDetectorRelease

Func _cveAKAZEDetectorCreate($descriptorType, $descriptorSize, $descriptorChannels, $threshold, $octaves, $sublevels, $diffusivity, $feature2D, $sharedPtr)
    ; CVAPI(cv::AKAZE*) cveAKAZEDetectorCreate(int descriptorType, int descriptorSize, int descriptorChannels, float threshold, int octaves, int sublevels, int diffusivity, cv::Feature2D** feature2D, cv::Ptr<cv::AKAZE>** sharedPtr);

    Local $sFeature2DDllType
    If IsDllStruct($feature2D) Then
        $sFeature2DDllType = "struct*"
    ElseIf $feature2D == Null Then
        $sFeature2DDllType = "ptr"
    Else
        $sFeature2DDllType = "ptr*"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveAKAZEDetectorCreate", "int", $descriptorType, "int", $descriptorSize, "int", $descriptorChannels, "float", $threshold, "int", $octaves, "int", $sublevels, "int", $diffusivity, $sFeature2DDllType, $feature2D, $sSharedPtrDllType, $sharedPtr), "cveAKAZEDetectorCreate", @error)
EndFunc   ;==>_cveAKAZEDetectorCreate

Func _cveAKAZEDetectorRelease($sharedPtr)
    ; CVAPI(void) cveAKAZEDetectorRelease(cv::Ptr<cv::AKAZE>** sharedPtr);

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveAKAZEDetectorRelease", $sSharedPtrDllType, $sharedPtr), "cveAKAZEDetectorRelease", @error)
EndFunc   ;==>_cveAKAZEDetectorRelease

Func _cveAgastFeatureDetectorCreate($threshold, $nonmaxSuppression, $type, $feature2D, $sharedPtr)
    ; CVAPI(cv::AgastFeatureDetector*) cveAgastFeatureDetectorCreate(int threshold, bool nonmaxSuppression, int type, cv::Feature2D** feature2D, cv::Ptr<cv::AgastFeatureDetector>** sharedPtr);

    Local $sFeature2DDllType
    If IsDllStruct($feature2D) Then
        $sFeature2DDllType = "struct*"
    ElseIf $feature2D == Null Then
        $sFeature2DDllType = "ptr"
    Else
        $sFeature2DDllType = "ptr*"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveAgastFeatureDetectorCreate", "int", $threshold, "boolean", $nonmaxSuppression, "int", $type, $sFeature2DDllType, $feature2D, $sSharedPtrDllType, $sharedPtr), "cveAgastFeatureDetectorCreate", @error)
EndFunc   ;==>_cveAgastFeatureDetectorCreate

Func _cveAgastFeatureDetectorRelease($sharedPtr)
    ; CVAPI(void) cveAgastFeatureDetectorRelease(cv::Ptr<cv::AgastFeatureDetector>** sharedPtr);

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveAgastFeatureDetectorRelease", $sSharedPtrDllType, $sharedPtr), "cveAgastFeatureDetectorRelease", @error)
EndFunc   ;==>_cveAgastFeatureDetectorRelease

Func _cveSIFTCreate($nFeatures, $nOctaveLayers, $contrastThreshold, $edgeThreshold, $sigma, $feature2D, $sharedPtr)
    ; CVAPI(cv::SIFT*) cveSIFTCreate(int nFeatures, int nOctaveLayers, double contrastThreshold, double edgeThreshold, double sigma, cv::Feature2D** feature2D, cv::Ptr<cv::SIFT>** sharedPtr);

    Local $sFeature2DDllType
    If IsDllStruct($feature2D) Then
        $sFeature2DDllType = "struct*"
    ElseIf $feature2D == Null Then
        $sFeature2DDllType = "ptr"
    Else
        $sFeature2DDllType = "ptr*"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveSIFTCreate", "int", $nFeatures, "int", $nOctaveLayers, "double", $contrastThreshold, "double", $edgeThreshold, "double", $sigma, $sFeature2DDllType, $feature2D, $sSharedPtrDllType, $sharedPtr), "cveSIFTCreate", @error)
EndFunc   ;==>_cveSIFTCreate

Func _cveSIFTRelease($sharedPtr)
    ; CVAPI(void) cveSIFTRelease(cv::Ptr<cv::SIFT>** sharedPtr);

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSIFTRelease", $sSharedPtrDllType, $sharedPtr), "cveSIFTRelease", @error)
EndFunc   ;==>_cveSIFTRelease