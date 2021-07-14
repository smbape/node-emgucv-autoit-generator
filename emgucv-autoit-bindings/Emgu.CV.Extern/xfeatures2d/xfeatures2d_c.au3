#include-once
#include <..\..\CVEUtils.au3>

Func _cveBEBLIDCreate($scaleFactor, $nBits, ByRef $feature2D, ByRef $sharedPtr)
    ; CVAPI(cv::xfeatures2d::BEBLID*) cveBEBLIDCreate(float scaleFactor, int nBits, cv::Feature2D** feature2D, cv::Ptr<cv::xfeatures2d::BEBLID>** sharedPtr);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveBEBLIDCreate", "float", $scaleFactor, "int", $nBits, "ptr*", $feature2D, "ptr*", $sharedPtr), "cveBEBLIDCreate", @error)
EndFunc   ;==>_cveBEBLIDCreate

Func _cveBEBLIDRelease(ByRef $sharedPtr)
    ; CVAPI(void) cveBEBLIDRelease(cv::Ptr<cv::xfeatures2d::BEBLID>** sharedPtr);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBEBLIDRelease", "ptr*", $sharedPtr), "cveBEBLIDRelease", @error)
EndFunc   ;==>_cveBEBLIDRelease

Func _cveTBMRCreate($minArea, $maxAreaRelative, $scaleFactor, $nScales, ByRef $feature2D, ByRef $sharedPtr)
    ; CVAPI(cv::xfeatures2d::TBMR*) cveTBMRCreate(int minArea, float maxAreaRelative, float scaleFactor, int nScales, cv::Feature2D** feature2D, cv::Ptr<cv::xfeatures2d::TBMR>** sharedPtr);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveTBMRCreate", "int", $minArea, "float", $maxAreaRelative, "float", $scaleFactor, "int", $nScales, "ptr*", $feature2D, "ptr*", $sharedPtr), "cveTBMRCreate", @error)
EndFunc   ;==>_cveTBMRCreate

Func _cveTBMRRelease(ByRef $sharedPtr)
    ; CVAPI(void) cveTBMRRelease(cv::Ptr<cv::xfeatures2d::TBMR>** sharedPtr);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveTBMRRelease", "ptr*", $sharedPtr), "cveTBMRRelease", @error)
EndFunc   ;==>_cveTBMRRelease

Func _cveStarDetectorCreate($maxSize, $responseThreshold, $lineThresholdProjected, $lineThresholdBinarized, $suppressNonmaxSize, ByRef $feature2D, ByRef $sharedPtr)
    ; CVAPI(cv::xfeatures2d::StarDetector*) cveStarDetectorCreate(int maxSize, int responseThreshold, int lineThresholdProjected, int lineThresholdBinarized, int suppressNonmaxSize, cv::Feature2D** feature2D, cv::Ptr<cv::xfeatures2d::StarDetector>** sharedPtr);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveStarDetectorCreate", "int", $maxSize, "int", $responseThreshold, "int", $lineThresholdProjected, "int", $lineThresholdBinarized, "int", $suppressNonmaxSize, "ptr*", $feature2D, "ptr*", $sharedPtr), "cveStarDetectorCreate", @error)
EndFunc   ;==>_cveStarDetectorCreate

Func _cveStarDetectorRelease(ByRef $sharedPtr)
    ; CVAPI(void) cveStarDetectorRelease(cv::Ptr<cv::xfeatures2d::StarDetector>** sharedPtr);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveStarDetectorRelease", "ptr*", $sharedPtr), "cveStarDetectorRelease", @error)
EndFunc   ;==>_cveStarDetectorRelease

Func _cveFreakCreate($orientationNormalized, $scaleNormalized, $patternScale, $nOctaves, ByRef $descriptorExtractor, ByRef $sharedPtr)
    ; CVAPI(cv::xfeatures2d::FREAK*) cveFreakCreate(bool orientationNormalized, bool scaleNormalized, float patternScale, int nOctaves, cv::Feature2D** descriptorExtractor, cv::Ptr<cv::xfeatures2d::FREAK>** sharedPtr);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveFreakCreate", "boolean", $orientationNormalized, "boolean", $scaleNormalized, "float", $patternScale, "int", $nOctaves, "ptr*", $descriptorExtractor, "ptr*", $sharedPtr), "cveFreakCreate", @error)
EndFunc   ;==>_cveFreakCreate

Func _cveFreakRelease(ByRef $sharedPtr)
    ; CVAPI(void) cveFreakRelease(cv::Ptr<cv::xfeatures2d::FREAK>** sharedPtr);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFreakRelease", "ptr*", $sharedPtr), "cveFreakRelease", @error)
EndFunc   ;==>_cveFreakRelease

Func _cveBriefDescriptorExtractorCreate($descriptorSize, ByRef $feature2D, ByRef $sharedPtr)
    ; CVAPI(cv::xfeatures2d::BriefDescriptorExtractor*) cveBriefDescriptorExtractorCreate(int descriptorSize, cv::Feature2D** feature2D, cv::Ptr<cv::xfeatures2d::BriefDescriptorExtractor>** sharedPtr);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveBriefDescriptorExtractorCreate", "int", $descriptorSize, "ptr*", $feature2D, "ptr*", $sharedPtr), "cveBriefDescriptorExtractorCreate", @error)
EndFunc   ;==>_cveBriefDescriptorExtractorCreate

Func _cveBriefDescriptorExtractorRelease(ByRef $sharedPtr)
    ; CVAPI(void) cveBriefDescriptorExtractorRelease(cv::Ptr<cv::xfeatures2d::BriefDescriptorExtractor>** sharedPtr);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBriefDescriptorExtractorRelease", "ptr*", $sharedPtr), "cveBriefDescriptorExtractorRelease", @error)
EndFunc   ;==>_cveBriefDescriptorExtractorRelease

Func _cveLUCIDCreate($lucidKernel, $blurKernel, ByRef $feature2D, ByRef $sharedPtr)
    ; CVAPI(cv::xfeatures2d::LUCID*) cveLUCIDCreate(int lucidKernel, int blurKernel, cv::Feature2D** feature2D, cv::Ptr<cv::xfeatures2d::LUCID>** sharedPtr);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveLUCIDCreate", "int", $lucidKernel, "int", $blurKernel, "ptr*", $feature2D, "ptr*", $sharedPtr), "cveLUCIDCreate", @error)
EndFunc   ;==>_cveLUCIDCreate

Func _cveLUCIDRelease(ByRef $sharedPtr)
    ; CVAPI(void) cveLUCIDRelease(cv::Ptr<cv::xfeatures2d::LUCID>** sharedPtr);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveLUCIDRelease", "ptr*", $sharedPtr), "cveLUCIDRelease", @error)
EndFunc   ;==>_cveLUCIDRelease

Func _cveLATCHCreate($bytes, $rotationInvariance, $halfSsdSize, ByRef $extractor, ByRef $sharedPtr)
    ; CVAPI(cv::xfeatures2d::LATCH*) cveLATCHCreate(int bytes, bool rotationInvariance, int halfSsdSize, cv::Feature2D** extractor, cv::Ptr<cv::xfeatures2d::LATCH>** sharedPtr);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveLATCHCreate", "int", $bytes, "boolean", $rotationInvariance, "int", $halfSsdSize, "ptr*", $extractor, "ptr*", $sharedPtr), "cveLATCHCreate", @error)
EndFunc   ;==>_cveLATCHCreate

Func _cveLATCHRelease(ByRef $sharedPtr)
    ; CVAPI(void) cveLATCHRelease(cv::Ptr<cv::xfeatures2d::LATCH>** sharedPtr);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveLATCHRelease", "ptr*", $sharedPtr), "cveLATCHRelease", @error)
EndFunc   ;==>_cveLATCHRelease

Func _cveDAISYCreate($radius, $qRadius, $qTheta, $qHist, $norm, ByRef $H, $interpolation, $useOrientation, ByRef $extractor, ByRef $sharedPtr)
    ; CVAPI(cv::xfeatures2d::DAISY*) cveDAISYCreate(float radius, int qRadius, int qTheta, int qHist, int norm, cv::_InputArray* H, bool interpolation, bool useOrientation, cv::Feature2D** extractor, cv::Ptr<cv::xfeatures2d::DAISY>** sharedPtr);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveDAISYCreate", "float", $radius, "int", $qRadius, "int", $qTheta, "int", $qHist, "int", $norm, "ptr", $H, "boolean", $interpolation, "boolean", $useOrientation, "ptr*", $extractor, "ptr*", $sharedPtr), "cveDAISYCreate", @error)
EndFunc   ;==>_cveDAISYCreate

Func _cveDAISYCreateMat($radius, $qRadius, $qTheta, $qHist, $norm, ByRef $matH, $interpolation, $useOrientation, ByRef $extractor, ByRef $sharedPtr)
    ; cveDAISYCreate using cv::Mat instead of _*Array

    Local $iArrH, $vectorOfMatH, $iArrHSize
    Local $bHIsArray = VarGetType($matH) == "Array"

    If $bHIsArray Then
        $vectorOfMatH = _VectorOfMatCreate()

        $iArrHSize = UBound($matH)
        For $i = 0 To $iArrHSize - 1
            _VectorOfMatPush($vectorOfMatH, $matH[$i])
        Next

        $iArrH = _cveInputArrayFromVectorOfMat($vectorOfMatH)
    Else
        $iArrH = _cveInputArrayFromMat($matH)
    EndIf

    Local $retval = _cveDAISYCreate($radius, $qRadius, $qTheta, $qHist, $norm, $iArrH, $interpolation, $useOrientation, $extractor, $sharedPtr)

    If $bHIsArray Then
        _VectorOfMatRelease($vectorOfMatH)
    EndIf

    _cveInputArrayRelease($iArrH)

    Return $retval
EndFunc   ;==>_cveDAISYCreateMat

Func _cveDAISYRelease(ByRef $sharedPtr)
    ; CVAPI(void) cveDAISYRelease(cv::Ptr<cv::xfeatures2d::DAISY>** sharedPtr);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDAISYRelease", "ptr*", $sharedPtr), "cveDAISYRelease", @error)
EndFunc   ;==>_cveDAISYRelease

Func _cveBoostDescCreate($desc, $useScaleOrientation, $scalefactor, ByRef $feature2D, ByRef $sharedPtr)
    ; CVAPI(cv::xfeatures2d::BoostDesc*) cveBoostDescCreate(int desc, bool useScaleOrientation, float scalefactor, cv::Feature2D** feature2D, cv::Ptr<cv::xfeatures2d::BoostDesc>** sharedPtr);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveBoostDescCreate", "int", $desc, "boolean", $useScaleOrientation, "float", $scalefactor, "ptr*", $feature2D, "ptr*", $sharedPtr), "cveBoostDescCreate", @error)
EndFunc   ;==>_cveBoostDescCreate

Func _cveBoostDescRelease(ByRef $sharedPtr)
    ; CVAPI(void) cveBoostDescRelease(cv::Ptr<cv::xfeatures2d::BoostDesc>** sharedPtr);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBoostDescRelease", "ptr*", $sharedPtr), "cveBoostDescRelease", @error)
EndFunc   ;==>_cveBoostDescRelease

Func _cveMSDDetectorCreate($m_patch_radius, $m_search_area_radius, $m_nms_radius, $m_nms_scale_radius, $m_th_saliency, $m_kNN, $m_scale_factor, $m_n_scales, $m_compute_orientation, ByRef $feature2D, ByRef $sharedPtr)
    ; CVAPI(cv::xfeatures2d::MSDDetector*) cveMSDDetectorCreate(int m_patch_radius, int m_search_area_radius, int m_nms_radius, int m_nms_scale_radius, float m_th_saliency, int m_kNN, float m_scale_factor, int m_n_scales, bool m_compute_orientation, cv::Feature2D** feature2D, cv::Ptr<cv::xfeatures2d::MSDDetector>** sharedPtr);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveMSDDetectorCreate", "int", $m_patch_radius, "int", $m_search_area_radius, "int", $m_nms_radius, "int", $m_nms_scale_radius, "float", $m_th_saliency, "int", $m_kNN, "float", $m_scale_factor, "int", $m_n_scales, "boolean", $m_compute_orientation, "ptr*", $feature2D, "ptr*", $sharedPtr), "cveMSDDetectorCreate", @error)
EndFunc   ;==>_cveMSDDetectorCreate

Func _cveMSDDetectorRelease(ByRef $sharedPtr)
    ; CVAPI(void) cveMSDDetectorRelease(cv::Ptr<cv::xfeatures2d::MSDDetector>** sharedPtr);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMSDDetectorRelease", "ptr*", $sharedPtr), "cveMSDDetectorRelease", @error)
EndFunc   ;==>_cveMSDDetectorRelease

Func _cveVGGCreate($desc, $isigma, $imgNormalize, $useScaleOrientation, $scaleFactor, $dscNormalize, ByRef $feature2D, ByRef $sharedPtr)
    ; CVAPI(cv::xfeatures2d::VGG*) cveVGGCreate(int desc, float isigma, bool imgNormalize, bool useScaleOrientation, float scaleFactor, bool dscNormalize, cv::Feature2D** feature2D, cv::Ptr<cv::xfeatures2d::VGG>** sharedPtr);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveVGGCreate", "int", $desc, "float", $isigma, "boolean", $imgNormalize, "boolean", $useScaleOrientation, "float", $scaleFactor, "boolean", $dscNormalize, "ptr*", $feature2D, "ptr*", $sharedPtr), "cveVGGCreate", @error)
EndFunc   ;==>_cveVGGCreate

Func _cveVGGRelease(ByRef $sharedPtr)
    ; CVAPI(void) cveVGGRelease(cv::Ptr<cv::xfeatures2d::VGG>** sharedPtr);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveVGGRelease", "ptr*", $sharedPtr), "cveVGGRelease", @error)
EndFunc   ;==>_cveVGGRelease

Func _cvePCTSignaturesCreate($initSampleCount, $initSeedCount, $pointDistribution, ByRef $sharedPtr)
    ; CVAPI(cv::xfeatures2d::PCTSignatures*) cvePCTSignaturesCreate(int initSampleCount, int initSeedCount, int pointDistribution, cv::Ptr<cv::xfeatures2d::PCTSignatures>** sharedPtr);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cvePCTSignaturesCreate", "int", $initSampleCount, "int", $initSeedCount, "int", $pointDistribution, "ptr*", $sharedPtr), "cvePCTSignaturesCreate", @error)
EndFunc   ;==>_cvePCTSignaturesCreate

Func _cvePCTSignaturesCreate2(ByRef $initSamplingPoints, $initSeedCount, ByRef $sharedPtr)
    ; CVAPI(cv::xfeatures2d::PCTSignatures*) cvePCTSignaturesCreate2(std::vector<cv::Point2f>* initSamplingPoints, int initSeedCount, cv::Ptr<cv::xfeatures2d::PCTSignatures>** sharedPtr);

    Local $vecInitSamplingPoints, $iArrInitSamplingPointsSize
    Local $bInitSamplingPointsIsArray = VarGetType($initSamplingPoints) == "Array"

    If $bInitSamplingPointsIsArray Then
        $vecInitSamplingPoints = _VectorOfPointFCreate()

        $iArrInitSamplingPointsSize = UBound($initSamplingPoints)
        For $i = 0 To $iArrInitSamplingPointsSize - 1
            _VectorOfPointFPush($vecInitSamplingPoints, $initSamplingPoints[$i])
        Next
    Else
        $vecInitSamplingPoints = $initSamplingPoints
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cvePCTSignaturesCreate2", "ptr", $vecInitSamplingPoints, "int", $initSeedCount, "ptr*", $sharedPtr), "cvePCTSignaturesCreate2", @error)

    If $bInitSamplingPointsIsArray Then
        _VectorOfPointFRelease($vecInitSamplingPoints)
    EndIf

    Return $retval
EndFunc   ;==>_cvePCTSignaturesCreate2

Func _cvePCTSignaturesCreate3(ByRef $initSamplingPoints, ByRef $initClusterSeedIndexes, ByRef $sharedPtr)
    ; CVAPI(cv::xfeatures2d::PCTSignatures*) cvePCTSignaturesCreate3(std::vector<cv::Point2f>* initSamplingPoints, std::vector<int>* initClusterSeedIndexes, cv::Ptr<cv::xfeatures2d::PCTSignatures>** sharedPtr);

    Local $vecInitSamplingPoints, $iArrInitSamplingPointsSize
    Local $bInitSamplingPointsIsArray = VarGetType($initSamplingPoints) == "Array"

    If $bInitSamplingPointsIsArray Then
        $vecInitSamplingPoints = _VectorOfPointFCreate()

        $iArrInitSamplingPointsSize = UBound($initSamplingPoints)
        For $i = 0 To $iArrInitSamplingPointsSize - 1
            _VectorOfPointFPush($vecInitSamplingPoints, $initSamplingPoints[$i])
        Next
    Else
        $vecInitSamplingPoints = $initSamplingPoints
    EndIf

    Local $vecInitClusterSeedIndexes, $iArrInitClusterSeedIndexesSize
    Local $bInitClusterSeedIndexesIsArray = VarGetType($initClusterSeedIndexes) == "Array"

    If $bInitClusterSeedIndexesIsArray Then
        $vecInitClusterSeedIndexes = _VectorOfIntCreate()

        $iArrInitClusterSeedIndexesSize = UBound($initClusterSeedIndexes)
        For $i = 0 To $iArrInitClusterSeedIndexesSize - 1
            _VectorOfIntPush($vecInitClusterSeedIndexes, $initClusterSeedIndexes[$i])
        Next
    Else
        $vecInitClusterSeedIndexes = $initClusterSeedIndexes
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cvePCTSignaturesCreate3", "ptr", $vecInitSamplingPoints, "ptr", $vecInitClusterSeedIndexes, "ptr*", $sharedPtr), "cvePCTSignaturesCreate3", @error)

    If $bInitClusterSeedIndexesIsArray Then
        _VectorOfIntRelease($vecInitClusterSeedIndexes)
    EndIf

    If $bInitSamplingPointsIsArray Then
        _VectorOfPointFRelease($vecInitSamplingPoints)
    EndIf

    Return $retval
EndFunc   ;==>_cvePCTSignaturesCreate3

Func _cvePCTSignaturesRelease(ByRef $sharedPtr)
    ; CVAPI(void) cvePCTSignaturesRelease(cv::Ptr<cv::xfeatures2d::PCTSignatures>** sharedPtr);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cvePCTSignaturesRelease", "ptr*", $sharedPtr), "cvePCTSignaturesRelease", @error)
EndFunc   ;==>_cvePCTSignaturesRelease

Func _cvePCTSignaturesComputeSignature(ByRef $pct, ByRef $image, ByRef $signature)
    ; CVAPI(void) cvePCTSignaturesComputeSignature(cv::xfeatures2d::PCTSignatures* pct, cv::_InputArray* image, cv::_OutputArray* signature);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cvePCTSignaturesComputeSignature", "ptr", $pct, "ptr", $image, "ptr", $signature), "cvePCTSignaturesComputeSignature", @error)
EndFunc   ;==>_cvePCTSignaturesComputeSignature

Func _cvePCTSignaturesComputeSignatureMat(ByRef $pct, ByRef $matImage, ByRef $matSignature)
    ; cvePCTSignaturesComputeSignature using cv::Mat instead of _*Array

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

    Local $oArrSignature, $vectorOfMatSignature, $iArrSignatureSize
    Local $bSignatureIsArray = VarGetType($matSignature) == "Array"

    If $bSignatureIsArray Then
        $vectorOfMatSignature = _VectorOfMatCreate()

        $iArrSignatureSize = UBound($matSignature)
        For $i = 0 To $iArrSignatureSize - 1
            _VectorOfMatPush($vectorOfMatSignature, $matSignature[$i])
        Next

        $oArrSignature = _cveOutputArrayFromVectorOfMat($vectorOfMatSignature)
    Else
        $oArrSignature = _cveOutputArrayFromMat($matSignature)
    EndIf

    _cvePCTSignaturesComputeSignature($pct, $iArrImage, $oArrSignature)

    If $bSignatureIsArray Then
        _VectorOfMatRelease($vectorOfMatSignature)
    EndIf

    _cveOutputArrayRelease($oArrSignature)

    If $bImageIsArray Then
        _VectorOfMatRelease($vectorOfMatImage)
    EndIf

    _cveInputArrayRelease($iArrImage)
EndFunc   ;==>_cvePCTSignaturesComputeSignatureMat

Func _cvePCTSignaturesDrawSignature(ByRef $source, ByRef $signature, ByRef $result, $radiusToShorterSideRatio, $borderThickness)
    ; CVAPI(void) cvePCTSignaturesDrawSignature(cv::_InputArray* source, cv::_InputArray* signature, cv::_OutputArray* result, float radiusToShorterSideRatio, int borderThickness);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cvePCTSignaturesDrawSignature", "ptr", $source, "ptr", $signature, "ptr", $result, "float", $radiusToShorterSideRatio, "int", $borderThickness), "cvePCTSignaturesDrawSignature", @error)
EndFunc   ;==>_cvePCTSignaturesDrawSignature

Func _cvePCTSignaturesDrawSignatureMat(ByRef $matSource, ByRef $matSignature, ByRef $matResult, $radiusToShorterSideRatio, $borderThickness)
    ; cvePCTSignaturesDrawSignature using cv::Mat instead of _*Array

    Local $iArrSource, $vectorOfMatSource, $iArrSourceSize
    Local $bSourceIsArray = VarGetType($matSource) == "Array"

    If $bSourceIsArray Then
        $vectorOfMatSource = _VectorOfMatCreate()

        $iArrSourceSize = UBound($matSource)
        For $i = 0 To $iArrSourceSize - 1
            _VectorOfMatPush($vectorOfMatSource, $matSource[$i])
        Next

        $iArrSource = _cveInputArrayFromVectorOfMat($vectorOfMatSource)
    Else
        $iArrSource = _cveInputArrayFromMat($matSource)
    EndIf

    Local $iArrSignature, $vectorOfMatSignature, $iArrSignatureSize
    Local $bSignatureIsArray = VarGetType($matSignature) == "Array"

    If $bSignatureIsArray Then
        $vectorOfMatSignature = _VectorOfMatCreate()

        $iArrSignatureSize = UBound($matSignature)
        For $i = 0 To $iArrSignatureSize - 1
            _VectorOfMatPush($vectorOfMatSignature, $matSignature[$i])
        Next

        $iArrSignature = _cveInputArrayFromVectorOfMat($vectorOfMatSignature)
    Else
        $iArrSignature = _cveInputArrayFromMat($matSignature)
    EndIf

    Local $oArrResult, $vectorOfMatResult, $iArrResultSize
    Local $bResultIsArray = VarGetType($matResult) == "Array"

    If $bResultIsArray Then
        $vectorOfMatResult = _VectorOfMatCreate()

        $iArrResultSize = UBound($matResult)
        For $i = 0 To $iArrResultSize - 1
            _VectorOfMatPush($vectorOfMatResult, $matResult[$i])
        Next

        $oArrResult = _cveOutputArrayFromVectorOfMat($vectorOfMatResult)
    Else
        $oArrResult = _cveOutputArrayFromMat($matResult)
    EndIf

    _cvePCTSignaturesDrawSignature($iArrSource, $iArrSignature, $oArrResult, $radiusToShorterSideRatio, $borderThickness)

    If $bResultIsArray Then
        _VectorOfMatRelease($vectorOfMatResult)
    EndIf

    _cveOutputArrayRelease($oArrResult)

    If $bSignatureIsArray Then
        _VectorOfMatRelease($vectorOfMatSignature)
    EndIf

    _cveInputArrayRelease($iArrSignature)

    If $bSourceIsArray Then
        _VectorOfMatRelease($vectorOfMatSource)
    EndIf

    _cveInputArrayRelease($iArrSource)
EndFunc   ;==>_cvePCTSignaturesDrawSignatureMat

Func _cvePCTSignaturesSQFDCreate($distanceFunction, $similarityFunction, $similarityParameter, ByRef $sharedPtr)
    ; CVAPI(cv::xfeatures2d::PCTSignaturesSQFD*) cvePCTSignaturesSQFDCreate(int distanceFunction, int similarityFunction, float similarityParameter, cv::Ptr<cv::xfeatures2d::PCTSignaturesSQFD>** sharedPtr);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cvePCTSignaturesSQFDCreate", "int", $distanceFunction, "int", $similarityFunction, "float", $similarityParameter, "ptr*", $sharedPtr), "cvePCTSignaturesSQFDCreate", @error)
EndFunc   ;==>_cvePCTSignaturesSQFDCreate

Func _cvePCTSignaturesSQFDComputeQuadraticFormDistance(ByRef $sqfd, ByRef $signature0, ByRef $signature1)
    ; CVAPI(float) cvePCTSignaturesSQFDComputeQuadraticFormDistance(cv::xfeatures2d::PCTSignaturesSQFD* sqfd, cv::_InputArray* signature0, cv::_InputArray* signature1);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cvePCTSignaturesSQFDComputeQuadraticFormDistance", "ptr", $sqfd, "ptr", $signature0, "ptr", $signature1), "cvePCTSignaturesSQFDComputeQuadraticFormDistance", @error)
EndFunc   ;==>_cvePCTSignaturesSQFDComputeQuadraticFormDistance

Func _cvePCTSignaturesSQFDComputeQuadraticFormDistanceMat(ByRef $sqfd, ByRef $matSignature0, ByRef $matSignature1)
    ; cvePCTSignaturesSQFDComputeQuadraticFormDistance using cv::Mat instead of _*Array

    Local $iArrSignature0, $vectorOfMatSignature0, $iArrSignature0Size
    Local $bSignature0IsArray = VarGetType($matSignature0) == "Array"

    If $bSignature0IsArray Then
        $vectorOfMatSignature0 = _VectorOfMatCreate()

        $iArrSignature0Size = UBound($matSignature0)
        For $i = 0 To $iArrSignature0Size - 1
            _VectorOfMatPush($vectorOfMatSignature0, $matSignature0[$i])
        Next

        $iArrSignature0 = _cveInputArrayFromVectorOfMat($vectorOfMatSignature0)
    Else
        $iArrSignature0 = _cveInputArrayFromMat($matSignature0)
    EndIf

    Local $iArrSignature1, $vectorOfMatSignature1, $iArrSignature1Size
    Local $bSignature1IsArray = VarGetType($matSignature1) == "Array"

    If $bSignature1IsArray Then
        $vectorOfMatSignature1 = _VectorOfMatCreate()

        $iArrSignature1Size = UBound($matSignature1)
        For $i = 0 To $iArrSignature1Size - 1
            _VectorOfMatPush($vectorOfMatSignature1, $matSignature1[$i])
        Next

        $iArrSignature1 = _cveInputArrayFromVectorOfMat($vectorOfMatSignature1)
    Else
        $iArrSignature1 = _cveInputArrayFromMat($matSignature1)
    EndIf

    Local $retval = _cvePCTSignaturesSQFDComputeQuadraticFormDistance($sqfd, $iArrSignature0, $iArrSignature1)

    If $bSignature1IsArray Then
        _VectorOfMatRelease($vectorOfMatSignature1)
    EndIf

    _cveInputArrayRelease($iArrSignature1)

    If $bSignature0IsArray Then
        _VectorOfMatRelease($vectorOfMatSignature0)
    EndIf

    _cveInputArrayRelease($iArrSignature0)

    Return $retval
EndFunc   ;==>_cvePCTSignaturesSQFDComputeQuadraticFormDistanceMat

Func _cvePCTSignaturesSQFDComputeQuadraticFormDistances(ByRef $sqfd, ByRef $sourceSignature, ByRef $imageSignatures, ByRef $distances)
    ; CVAPI(void) cvePCTSignaturesSQFDComputeQuadraticFormDistances(cv::xfeatures2d::PCTSignaturesSQFD* sqfd, cv::Mat* sourceSignature, std::vector<cv::Mat>* imageSignatures, std::vector<float>* distances);

    Local $vecImageSignatures, $iArrImageSignaturesSize
    Local $bImageSignaturesIsArray = VarGetType($imageSignatures) == "Array"

    If $bImageSignaturesIsArray Then
        $vecImageSignatures = _VectorOfMatCreate()

        $iArrImageSignaturesSize = UBound($imageSignatures)
        For $i = 0 To $iArrImageSignaturesSize - 1
            _VectorOfMatPush($vecImageSignatures, $imageSignatures[$i])
        Next
    Else
        $vecImageSignatures = $imageSignatures
    EndIf

    Local $vecDistances, $iArrDistancesSize
    Local $bDistancesIsArray = VarGetType($distances) == "Array"

    If $bDistancesIsArray Then
        $vecDistances = _VectorOfFloatCreate()

        $iArrDistancesSize = UBound($distances)
        For $i = 0 To $iArrDistancesSize - 1
            _VectorOfFloatPush($vecDistances, $distances[$i])
        Next
    Else
        $vecDistances = $distances
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cvePCTSignaturesSQFDComputeQuadraticFormDistances", "ptr", $sqfd, "ptr", $sourceSignature, "ptr", $vecImageSignatures, "ptr", $vecDistances), "cvePCTSignaturesSQFDComputeQuadraticFormDistances", @error)

    If $bDistancesIsArray Then
        _VectorOfFloatRelease($vecDistances)
    EndIf

    If $bImageSignaturesIsArray Then
        _VectorOfMatRelease($vecImageSignatures)
    EndIf
EndFunc   ;==>_cvePCTSignaturesSQFDComputeQuadraticFormDistances

Func _cvePCTSignaturesSQFDRelease(ByRef $sharedPtr)
    ; CVAPI(void) cvePCTSignaturesSQFDRelease(cv::Ptr<cv::xfeatures2d::PCTSignaturesSQFD>** sharedPtr);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cvePCTSignaturesSQFDRelease", "ptr*", $sharedPtr), "cvePCTSignaturesSQFDRelease", @error)
EndFunc   ;==>_cvePCTSignaturesSQFDRelease

Func _cveHarrisLaplaceFeatureDetectorCreate($numOctaves, $corn_thresh, $DOG_thresh, $maxCorners, $num_layers, ByRef $sharedPtr)
    ; CVAPI(cv::xfeatures2d::HarrisLaplaceFeatureDetector*) cveHarrisLaplaceFeatureDetectorCreate(int numOctaves, float corn_thresh, float DOG_thresh, int maxCorners, int num_layers, cv::Ptr<cv::xfeatures2d::HarrisLaplaceFeatureDetector>** sharedPtr);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveHarrisLaplaceFeatureDetectorCreate", "int", $numOctaves, "float", $corn_thresh, "float", $DOG_thresh, "int", $maxCorners, "int", $num_layers, "ptr*", $sharedPtr), "cveHarrisLaplaceFeatureDetectorCreate", @error)
EndFunc   ;==>_cveHarrisLaplaceFeatureDetectorCreate

Func _cveHarrisLaplaceFeatureDetectorRelease(ByRef $sharedPtr)
    ; CVAPI(void) cveHarrisLaplaceFeatureDetectorRelease(cv::Ptr<cv::xfeatures2d::HarrisLaplaceFeatureDetector>** sharedPtr);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveHarrisLaplaceFeatureDetectorRelease", "ptr*", $sharedPtr), "cveHarrisLaplaceFeatureDetectorRelease", @error)
EndFunc   ;==>_cveHarrisLaplaceFeatureDetectorRelease

Func _cveMatchGMS(ByRef $size1, ByRef $size2, ByRef $keypoints1, ByRef $keypoints2, ByRef $matches1to2, ByRef $matchesGMS, $withRotation, $withScale, $thresholdFactor)
    ; CVAPI(void) cveMatchGMS(CvSize* size1, CvSize* size2, std::vector< cv::KeyPoint >* keypoints1, std::vector< cv::KeyPoint >* keypoints2, std::vector< cv::DMatch >* matches1to2, std::vector< cv::DMatch >* matchesGMS, bool withRotation, bool withScale, double thresholdFactor);

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

    Local $vecMatches1to2, $iArrMatches1to2Size
    Local $bMatches1to2IsArray = VarGetType($matches1to2) == "Array"

    If $bMatches1to2IsArray Then
        $vecMatches1to2 = _VectorOfDMatchCreate()

        $iArrMatches1to2Size = UBound($matches1to2)
        For $i = 0 To $iArrMatches1to2Size - 1
            _VectorOfDMatchPush($vecMatches1to2, $matches1to2[$i])
        Next
    Else
        $vecMatches1to2 = $matches1to2
    EndIf

    Local $vecMatchesGMS, $iArrMatchesGMSSize
    Local $bMatchesGMSIsArray = VarGetType($matchesGMS) == "Array"

    If $bMatchesGMSIsArray Then
        $vecMatchesGMS = _VectorOfDMatchCreate()

        $iArrMatchesGMSSize = UBound($matchesGMS)
        For $i = 0 To $iArrMatchesGMSSize - 1
            _VectorOfDMatchPush($vecMatchesGMS, $matchesGMS[$i])
        Next
    Else
        $vecMatchesGMS = $matchesGMS
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMatchGMS", "struct*", $size1, "struct*", $size2, "ptr", $vecKeypoints1, "ptr", $vecKeypoints2, "ptr", $vecMatches1to2, "ptr", $vecMatchesGMS, "boolean", $withRotation, "boolean", $withScale, "double", $thresholdFactor), "cveMatchGMS", @error)

    If $bMatchesGMSIsArray Then
        _VectorOfDMatchRelease($vecMatchesGMS)
    EndIf

    If $bMatches1to2IsArray Then
        _VectorOfDMatchRelease($vecMatches1to2)
    EndIf

    If $bKeypoints2IsArray Then
        _VectorOfKeyPointRelease($vecKeypoints2)
    EndIf

    If $bKeypoints1IsArray Then
        _VectorOfKeyPointRelease($vecKeypoints1)
    EndIf
EndFunc   ;==>_cveMatchGMS

Func _cveMatchLOGOS(ByRef $keypoints1, ByRef $keypoints2, ByRef $nn1, ByRef $nn2, ByRef $matches1to2)
    ; CVAPI(void) cveMatchLOGOS(std::vector< cv::KeyPoint >* keypoints1, std::vector< cv::KeyPoint >* keypoints2, std::vector< int >* nn1, std::vector< int >* nn2, std::vector< cv::DMatch >* matches1to2);

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

    Local $vecNn1, $iArrNn1Size
    Local $bNn1IsArray = VarGetType($nn1) == "Array"

    If $bNn1IsArray Then
        $vecNn1 = _VectorOfIntCreate()

        $iArrNn1Size = UBound($nn1)
        For $i = 0 To $iArrNn1Size - 1
            _VectorOfIntPush($vecNn1, $nn1[$i])
        Next
    Else
        $vecNn1 = $nn1
    EndIf

    Local $vecNn2, $iArrNn2Size
    Local $bNn2IsArray = VarGetType($nn2) == "Array"

    If $bNn2IsArray Then
        $vecNn2 = _VectorOfIntCreate()

        $iArrNn2Size = UBound($nn2)
        For $i = 0 To $iArrNn2Size - 1
            _VectorOfIntPush($vecNn2, $nn2[$i])
        Next
    Else
        $vecNn2 = $nn2
    EndIf

    Local $vecMatches1to2, $iArrMatches1to2Size
    Local $bMatches1to2IsArray = VarGetType($matches1to2) == "Array"

    If $bMatches1to2IsArray Then
        $vecMatches1to2 = _VectorOfDMatchCreate()

        $iArrMatches1to2Size = UBound($matches1to2)
        For $i = 0 To $iArrMatches1to2Size - 1
            _VectorOfDMatchPush($vecMatches1to2, $matches1to2[$i])
        Next
    Else
        $vecMatches1to2 = $matches1to2
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMatchLOGOS", "ptr", $vecKeypoints1, "ptr", $vecKeypoints2, "ptr", $vecNn1, "ptr", $vecNn2, "ptr", $vecMatches1to2), "cveMatchLOGOS", @error)

    If $bMatches1to2IsArray Then
        _VectorOfDMatchRelease($vecMatches1to2)
    EndIf

    If $bNn2IsArray Then
        _VectorOfIntRelease($vecNn2)
    EndIf

    If $bNn1IsArray Then
        _VectorOfIntRelease($vecNn1)
    EndIf

    If $bKeypoints2IsArray Then
        _VectorOfKeyPointRelease($vecKeypoints2)
    EndIf

    If $bKeypoints1IsArray Then
        _VectorOfKeyPointRelease($vecKeypoints1)
    EndIf
EndFunc   ;==>_cveMatchLOGOS