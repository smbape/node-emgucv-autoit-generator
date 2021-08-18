#include-once
#include "..\..\CVEUtils.au3"

Func _cveBEBLIDCreate($scaleFactor, $nBits, $feature2D, $sharedPtr)
    ; CVAPI(cv::xfeatures2d::BEBLID*) cveBEBLIDCreate(float scaleFactor, int nBits, cv::Feature2D** feature2D, cv::Ptr<cv::xfeatures2d::BEBLID>** sharedPtr);

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
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveBEBLIDCreate", "float", $scaleFactor, "int", $nBits, $bFeature2DDllType, $feature2D, $bSharedPtrDllType, $sharedPtr), "cveBEBLIDCreate", @error)
EndFunc   ;==>_cveBEBLIDCreate

Func _cveBEBLIDRelease($sharedPtr)
    ; CVAPI(void) cveBEBLIDRelease(cv::Ptr<cv::xfeatures2d::BEBLID>** sharedPtr);

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBEBLIDRelease", $bSharedPtrDllType, $sharedPtr), "cveBEBLIDRelease", @error)
EndFunc   ;==>_cveBEBLIDRelease

Func _cveTBMRCreate($minArea, $maxAreaRelative, $scaleFactor, $nScales, $feature2D, $sharedPtr)
    ; CVAPI(cv::xfeatures2d::TBMR*) cveTBMRCreate(int minArea, float maxAreaRelative, float scaleFactor, int nScales, cv::Feature2D** feature2D, cv::Ptr<cv::xfeatures2d::TBMR>** sharedPtr);

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
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveTBMRCreate", "int", $minArea, "float", $maxAreaRelative, "float", $scaleFactor, "int", $nScales, $bFeature2DDllType, $feature2D, $bSharedPtrDllType, $sharedPtr), "cveTBMRCreate", @error)
EndFunc   ;==>_cveTBMRCreate

Func _cveTBMRRelease($sharedPtr)
    ; CVAPI(void) cveTBMRRelease(cv::Ptr<cv::xfeatures2d::TBMR>** sharedPtr);

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveTBMRRelease", $bSharedPtrDllType, $sharedPtr), "cveTBMRRelease", @error)
EndFunc   ;==>_cveTBMRRelease

Func _cveStarDetectorCreate($maxSize, $responseThreshold, $lineThresholdProjected, $lineThresholdBinarized, $suppressNonmaxSize, $feature2D, $sharedPtr)
    ; CVAPI(cv::xfeatures2d::StarDetector*) cveStarDetectorCreate(int maxSize, int responseThreshold, int lineThresholdProjected, int lineThresholdBinarized, int suppressNonmaxSize, cv::Feature2D** feature2D, cv::Ptr<cv::xfeatures2d::StarDetector>** sharedPtr);

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
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveStarDetectorCreate", "int", $maxSize, "int", $responseThreshold, "int", $lineThresholdProjected, "int", $lineThresholdBinarized, "int", $suppressNonmaxSize, $bFeature2DDllType, $feature2D, $bSharedPtrDllType, $sharedPtr), "cveStarDetectorCreate", @error)
EndFunc   ;==>_cveStarDetectorCreate

Func _cveStarDetectorRelease($sharedPtr)
    ; CVAPI(void) cveStarDetectorRelease(cv::Ptr<cv::xfeatures2d::StarDetector>** sharedPtr);

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveStarDetectorRelease", $bSharedPtrDllType, $sharedPtr), "cveStarDetectorRelease", @error)
EndFunc   ;==>_cveStarDetectorRelease

Func _cveFreakCreate($orientationNormalized, $scaleNormalized, $patternScale, $nOctaves, $descriptorExtractor, $sharedPtr)
    ; CVAPI(cv::xfeatures2d::FREAK*) cveFreakCreate(bool orientationNormalized, bool scaleNormalized, float patternScale, int nOctaves, cv::Feature2D** descriptorExtractor, cv::Ptr<cv::xfeatures2d::FREAK>** sharedPtr);

    Local $bDescriptorExtractorDllType
    If VarGetType($descriptorExtractor) == "DLLStruct" Then
        $bDescriptorExtractorDllType = "struct*"
    Else
        $bDescriptorExtractorDllType = "ptr*"
    EndIf

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveFreakCreate", "boolean", $orientationNormalized, "boolean", $scaleNormalized, "float", $patternScale, "int", $nOctaves, $bDescriptorExtractorDllType, $descriptorExtractor, $bSharedPtrDllType, $sharedPtr), "cveFreakCreate", @error)
EndFunc   ;==>_cveFreakCreate

Func _cveFreakRelease($sharedPtr)
    ; CVAPI(void) cveFreakRelease(cv::Ptr<cv::xfeatures2d::FREAK>** sharedPtr);

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFreakRelease", $bSharedPtrDllType, $sharedPtr), "cveFreakRelease", @error)
EndFunc   ;==>_cveFreakRelease

Func _cveBriefDescriptorExtractorCreate($descriptorSize, $feature2D, $sharedPtr)
    ; CVAPI(cv::xfeatures2d::BriefDescriptorExtractor*) cveBriefDescriptorExtractorCreate(int descriptorSize, cv::Feature2D** feature2D, cv::Ptr<cv::xfeatures2d::BriefDescriptorExtractor>** sharedPtr);

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
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveBriefDescriptorExtractorCreate", "int", $descriptorSize, $bFeature2DDllType, $feature2D, $bSharedPtrDllType, $sharedPtr), "cveBriefDescriptorExtractorCreate", @error)
EndFunc   ;==>_cveBriefDescriptorExtractorCreate

Func _cveBriefDescriptorExtractorRelease($sharedPtr)
    ; CVAPI(void) cveBriefDescriptorExtractorRelease(cv::Ptr<cv::xfeatures2d::BriefDescriptorExtractor>** sharedPtr);

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBriefDescriptorExtractorRelease", $bSharedPtrDllType, $sharedPtr), "cveBriefDescriptorExtractorRelease", @error)
EndFunc   ;==>_cveBriefDescriptorExtractorRelease

Func _cveLUCIDCreate($lucidKernel, $blurKernel, $feature2D, $sharedPtr)
    ; CVAPI(cv::xfeatures2d::LUCID*) cveLUCIDCreate(int lucidKernel, int blurKernel, cv::Feature2D** feature2D, cv::Ptr<cv::xfeatures2d::LUCID>** sharedPtr);

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
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveLUCIDCreate", "int", $lucidKernel, "int", $blurKernel, $bFeature2DDllType, $feature2D, $bSharedPtrDllType, $sharedPtr), "cveLUCIDCreate", @error)
EndFunc   ;==>_cveLUCIDCreate

Func _cveLUCIDRelease($sharedPtr)
    ; CVAPI(void) cveLUCIDRelease(cv::Ptr<cv::xfeatures2d::LUCID>** sharedPtr);

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveLUCIDRelease", $bSharedPtrDllType, $sharedPtr), "cveLUCIDRelease", @error)
EndFunc   ;==>_cveLUCIDRelease

Func _cveLATCHCreate($bytes, $rotationInvariance, $halfSsdSize, $extractor, $sharedPtr)
    ; CVAPI(cv::xfeatures2d::LATCH*) cveLATCHCreate(int bytes, bool rotationInvariance, int halfSsdSize, cv::Feature2D** extractor, cv::Ptr<cv::xfeatures2d::LATCH>** sharedPtr);

    Local $bExtractorDllType
    If VarGetType($extractor) == "DLLStruct" Then
        $bExtractorDllType = "struct*"
    Else
        $bExtractorDllType = "ptr*"
    EndIf

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveLATCHCreate", "int", $bytes, "boolean", $rotationInvariance, "int", $halfSsdSize, $bExtractorDllType, $extractor, $bSharedPtrDllType, $sharedPtr), "cveLATCHCreate", @error)
EndFunc   ;==>_cveLATCHCreate

Func _cveLATCHRelease($sharedPtr)
    ; CVAPI(void) cveLATCHRelease(cv::Ptr<cv::xfeatures2d::LATCH>** sharedPtr);

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveLATCHRelease", $bSharedPtrDllType, $sharedPtr), "cveLATCHRelease", @error)
EndFunc   ;==>_cveLATCHRelease

Func _cveDAISYCreate($radius, $qRadius, $qTheta, $qHist, $norm, $H, $interpolation, $useOrientation, $extractor, $sharedPtr)
    ; CVAPI(cv::xfeatures2d::DAISY*) cveDAISYCreate(float radius, int qRadius, int qTheta, int qHist, int norm, cv::_InputArray* H, bool interpolation, bool useOrientation, cv::Feature2D** extractor, cv::Ptr<cv::xfeatures2d::DAISY>** sharedPtr);

    Local $bHDllType
    If VarGetType($H) == "DLLStruct" Then
        $bHDllType = "struct*"
    Else
        $bHDllType = "ptr"
    EndIf

    Local $bExtractorDllType
    If VarGetType($extractor) == "DLLStruct" Then
        $bExtractorDllType = "struct*"
    Else
        $bExtractorDllType = "ptr*"
    EndIf

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveDAISYCreate", "float", $radius, "int", $qRadius, "int", $qTheta, "int", $qHist, "int", $norm, $bHDllType, $H, "boolean", $interpolation, "boolean", $useOrientation, $bExtractorDllType, $extractor, $bSharedPtrDllType, $sharedPtr), "cveDAISYCreate", @error)
EndFunc   ;==>_cveDAISYCreate

Func _cveDAISYCreateMat($radius, $qRadius, $qTheta, $qHist, $norm, $matH, $interpolation, $useOrientation, $extractor, $sharedPtr)
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

Func _cveDAISYRelease($sharedPtr)
    ; CVAPI(void) cveDAISYRelease(cv::Ptr<cv::xfeatures2d::DAISY>** sharedPtr);

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDAISYRelease", $bSharedPtrDllType, $sharedPtr), "cveDAISYRelease", @error)
EndFunc   ;==>_cveDAISYRelease

Func _cveBoostDescCreate($desc, $useScaleOrientation, $scalefactor, $feature2D, $sharedPtr)
    ; CVAPI(cv::xfeatures2d::BoostDesc*) cveBoostDescCreate(int desc, bool useScaleOrientation, float scalefactor, cv::Feature2D** feature2D, cv::Ptr<cv::xfeatures2d::BoostDesc>** sharedPtr);

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
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveBoostDescCreate", "int", $desc, "boolean", $useScaleOrientation, "float", $scalefactor, $bFeature2DDllType, $feature2D, $bSharedPtrDllType, $sharedPtr), "cveBoostDescCreate", @error)
EndFunc   ;==>_cveBoostDescCreate

Func _cveBoostDescRelease($sharedPtr)
    ; CVAPI(void) cveBoostDescRelease(cv::Ptr<cv::xfeatures2d::BoostDesc>** sharedPtr);

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBoostDescRelease", $bSharedPtrDllType, $sharedPtr), "cveBoostDescRelease", @error)
EndFunc   ;==>_cveBoostDescRelease

Func _cveMSDDetectorCreate($m_patch_radius, $m_search_area_radius, $m_nms_radius, $m_nms_scale_radius, $m_th_saliency, $m_kNN, $m_scale_factor, $m_n_scales, $m_compute_orientation, $feature2D, $sharedPtr)
    ; CVAPI(cv::xfeatures2d::MSDDetector*) cveMSDDetectorCreate(int m_patch_radius, int m_search_area_radius, int m_nms_radius, int m_nms_scale_radius, float m_th_saliency, int m_kNN, float m_scale_factor, int m_n_scales, bool m_compute_orientation, cv::Feature2D** feature2D, cv::Ptr<cv::xfeatures2d::MSDDetector>** sharedPtr);

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
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveMSDDetectorCreate", "int", $m_patch_radius, "int", $m_search_area_radius, "int", $m_nms_radius, "int", $m_nms_scale_radius, "float", $m_th_saliency, "int", $m_kNN, "float", $m_scale_factor, "int", $m_n_scales, "boolean", $m_compute_orientation, $bFeature2DDllType, $feature2D, $bSharedPtrDllType, $sharedPtr), "cveMSDDetectorCreate", @error)
EndFunc   ;==>_cveMSDDetectorCreate

Func _cveMSDDetectorRelease($sharedPtr)
    ; CVAPI(void) cveMSDDetectorRelease(cv::Ptr<cv::xfeatures2d::MSDDetector>** sharedPtr);

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMSDDetectorRelease", $bSharedPtrDllType, $sharedPtr), "cveMSDDetectorRelease", @error)
EndFunc   ;==>_cveMSDDetectorRelease

Func _cveVGGCreate($desc, $isigma, $imgNormalize, $useScaleOrientation, $scaleFactor, $dscNormalize, $feature2D, $sharedPtr)
    ; CVAPI(cv::xfeatures2d::VGG*) cveVGGCreate(int desc, float isigma, bool imgNormalize, bool useScaleOrientation, float scaleFactor, bool dscNormalize, cv::Feature2D** feature2D, cv::Ptr<cv::xfeatures2d::VGG>** sharedPtr);

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
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveVGGCreate", "int", $desc, "float", $isigma, "boolean", $imgNormalize, "boolean", $useScaleOrientation, "float", $scaleFactor, "boolean", $dscNormalize, $bFeature2DDllType, $feature2D, $bSharedPtrDllType, $sharedPtr), "cveVGGCreate", @error)
EndFunc   ;==>_cveVGGCreate

Func _cveVGGRelease($sharedPtr)
    ; CVAPI(void) cveVGGRelease(cv::Ptr<cv::xfeatures2d::VGG>** sharedPtr);

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveVGGRelease", $bSharedPtrDllType, $sharedPtr), "cveVGGRelease", @error)
EndFunc   ;==>_cveVGGRelease

Func _cvePCTSignaturesCreate($initSampleCount, $initSeedCount, $pointDistribution, $sharedPtr)
    ; CVAPI(cv::xfeatures2d::PCTSignatures*) cvePCTSignaturesCreate(int initSampleCount, int initSeedCount, int pointDistribution, cv::Ptr<cv::xfeatures2d::PCTSignatures>** sharedPtr);

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cvePCTSignaturesCreate", "int", $initSampleCount, "int", $initSeedCount, "int", $pointDistribution, $bSharedPtrDllType, $sharedPtr), "cvePCTSignaturesCreate", @error)
EndFunc   ;==>_cvePCTSignaturesCreate

Func _cvePCTSignaturesCreate2($initSamplingPoints, $initSeedCount, $sharedPtr)
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

    Local $bInitSamplingPointsDllType
    If VarGetType($initSamplingPoints) == "DLLStruct" Then
        $bInitSamplingPointsDllType = "struct*"
    Else
        $bInitSamplingPointsDllType = "ptr"
    EndIf

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cvePCTSignaturesCreate2", $bInitSamplingPointsDllType, $vecInitSamplingPoints, "int", $initSeedCount, $bSharedPtrDllType, $sharedPtr), "cvePCTSignaturesCreate2", @error)

    If $bInitSamplingPointsIsArray Then
        _VectorOfPointFRelease($vecInitSamplingPoints)
    EndIf

    Return $retval
EndFunc   ;==>_cvePCTSignaturesCreate2

Func _cvePCTSignaturesCreate3($initSamplingPoints, $initClusterSeedIndexes, $sharedPtr)
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

    Local $bInitSamplingPointsDllType
    If VarGetType($initSamplingPoints) == "DLLStruct" Then
        $bInitSamplingPointsDllType = "struct*"
    Else
        $bInitSamplingPointsDllType = "ptr"
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

    Local $bInitClusterSeedIndexesDllType
    If VarGetType($initClusterSeedIndexes) == "DLLStruct" Then
        $bInitClusterSeedIndexesDllType = "struct*"
    Else
        $bInitClusterSeedIndexesDllType = "ptr"
    EndIf

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cvePCTSignaturesCreate3", $bInitSamplingPointsDllType, $vecInitSamplingPoints, $bInitClusterSeedIndexesDllType, $vecInitClusterSeedIndexes, $bSharedPtrDllType, $sharedPtr), "cvePCTSignaturesCreate3", @error)

    If $bInitClusterSeedIndexesIsArray Then
        _VectorOfIntRelease($vecInitClusterSeedIndexes)
    EndIf

    If $bInitSamplingPointsIsArray Then
        _VectorOfPointFRelease($vecInitSamplingPoints)
    EndIf

    Return $retval
EndFunc   ;==>_cvePCTSignaturesCreate3

Func _cvePCTSignaturesRelease($sharedPtr)
    ; CVAPI(void) cvePCTSignaturesRelease(cv::Ptr<cv::xfeatures2d::PCTSignatures>** sharedPtr);

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cvePCTSignaturesRelease", $bSharedPtrDllType, $sharedPtr), "cvePCTSignaturesRelease", @error)
EndFunc   ;==>_cvePCTSignaturesRelease

Func _cvePCTSignaturesComputeSignature($pct, $image, $signature)
    ; CVAPI(void) cvePCTSignaturesComputeSignature(cv::xfeatures2d::PCTSignatures* pct, cv::_InputArray* image, cv::_OutputArray* signature);

    Local $bPctDllType
    If VarGetType($pct) == "DLLStruct" Then
        $bPctDllType = "struct*"
    Else
        $bPctDllType = "ptr"
    EndIf

    Local $bImageDllType
    If VarGetType($image) == "DLLStruct" Then
        $bImageDllType = "struct*"
    Else
        $bImageDllType = "ptr"
    EndIf

    Local $bSignatureDllType
    If VarGetType($signature) == "DLLStruct" Then
        $bSignatureDllType = "struct*"
    Else
        $bSignatureDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cvePCTSignaturesComputeSignature", $bPctDllType, $pct, $bImageDllType, $image, $bSignatureDllType, $signature), "cvePCTSignaturesComputeSignature", @error)
EndFunc   ;==>_cvePCTSignaturesComputeSignature

Func _cvePCTSignaturesComputeSignatureMat($pct, $matImage, $matSignature)
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

Func _cvePCTSignaturesDrawSignature($source, $signature, $result, $radiusToShorterSideRatio, $borderThickness)
    ; CVAPI(void) cvePCTSignaturesDrawSignature(cv::_InputArray* source, cv::_InputArray* signature, cv::_OutputArray* result, float radiusToShorterSideRatio, int borderThickness);

    Local $bSourceDllType
    If VarGetType($source) == "DLLStruct" Then
        $bSourceDllType = "struct*"
    Else
        $bSourceDllType = "ptr"
    EndIf

    Local $bSignatureDllType
    If VarGetType($signature) == "DLLStruct" Then
        $bSignatureDllType = "struct*"
    Else
        $bSignatureDllType = "ptr"
    EndIf

    Local $bResultDllType
    If VarGetType($result) == "DLLStruct" Then
        $bResultDllType = "struct*"
    Else
        $bResultDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cvePCTSignaturesDrawSignature", $bSourceDllType, $source, $bSignatureDllType, $signature, $bResultDllType, $result, "float", $radiusToShorterSideRatio, "int", $borderThickness), "cvePCTSignaturesDrawSignature", @error)
EndFunc   ;==>_cvePCTSignaturesDrawSignature

Func _cvePCTSignaturesDrawSignatureMat($matSource, $matSignature, $matResult, $radiusToShorterSideRatio, $borderThickness)
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

Func _cvePCTSignaturesSQFDCreate($distanceFunction, $similarityFunction, $similarityParameter, $sharedPtr)
    ; CVAPI(cv::xfeatures2d::PCTSignaturesSQFD*) cvePCTSignaturesSQFDCreate(int distanceFunction, int similarityFunction, float similarityParameter, cv::Ptr<cv::xfeatures2d::PCTSignaturesSQFD>** sharedPtr);

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cvePCTSignaturesSQFDCreate", "int", $distanceFunction, "int", $similarityFunction, "float", $similarityParameter, $bSharedPtrDllType, $sharedPtr), "cvePCTSignaturesSQFDCreate", @error)
EndFunc   ;==>_cvePCTSignaturesSQFDCreate

Func _cvePCTSignaturesSQFDComputeQuadraticFormDistance($sqfd, $signature0, $signature1)
    ; CVAPI(float) cvePCTSignaturesSQFDComputeQuadraticFormDistance(cv::xfeatures2d::PCTSignaturesSQFD* sqfd, cv::_InputArray* signature0, cv::_InputArray* signature1);

    Local $bSqfdDllType
    If VarGetType($sqfd) == "DLLStruct" Then
        $bSqfdDllType = "struct*"
    Else
        $bSqfdDllType = "ptr"
    EndIf

    Local $bSignature0DllType
    If VarGetType($signature0) == "DLLStruct" Then
        $bSignature0DllType = "struct*"
    Else
        $bSignature0DllType = "ptr"
    EndIf

    Local $bSignature1DllType
    If VarGetType($signature1) == "DLLStruct" Then
        $bSignature1DllType = "struct*"
    Else
        $bSignature1DllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cvePCTSignaturesSQFDComputeQuadraticFormDistance", $bSqfdDllType, $sqfd, $bSignature0DllType, $signature0, $bSignature1DllType, $signature1), "cvePCTSignaturesSQFDComputeQuadraticFormDistance", @error)
EndFunc   ;==>_cvePCTSignaturesSQFDComputeQuadraticFormDistance

Func _cvePCTSignaturesSQFDComputeQuadraticFormDistanceMat($sqfd, $matSignature0, $matSignature1)
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

Func _cvePCTSignaturesSQFDComputeQuadraticFormDistances($sqfd, $sourceSignature, $imageSignatures, $distances)
    ; CVAPI(void) cvePCTSignaturesSQFDComputeQuadraticFormDistances(cv::xfeatures2d::PCTSignaturesSQFD* sqfd, cv::Mat* sourceSignature, std::vector<cv::Mat>* imageSignatures, std::vector<float>* distances);

    Local $bSqfdDllType
    If VarGetType($sqfd) == "DLLStruct" Then
        $bSqfdDllType = "struct*"
    Else
        $bSqfdDllType = "ptr"
    EndIf

    Local $bSourceSignatureDllType
    If VarGetType($sourceSignature) == "DLLStruct" Then
        $bSourceSignatureDllType = "struct*"
    Else
        $bSourceSignatureDllType = "ptr"
    EndIf

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

    Local $bImageSignaturesDllType
    If VarGetType($imageSignatures) == "DLLStruct" Then
        $bImageSignaturesDllType = "struct*"
    Else
        $bImageSignaturesDllType = "ptr"
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

    Local $bDistancesDllType
    If VarGetType($distances) == "DLLStruct" Then
        $bDistancesDllType = "struct*"
    Else
        $bDistancesDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cvePCTSignaturesSQFDComputeQuadraticFormDistances", $bSqfdDllType, $sqfd, $bSourceSignatureDllType, $sourceSignature, $bImageSignaturesDllType, $vecImageSignatures, $bDistancesDllType, $vecDistances), "cvePCTSignaturesSQFDComputeQuadraticFormDistances", @error)

    If $bDistancesIsArray Then
        _VectorOfFloatRelease($vecDistances)
    EndIf

    If $bImageSignaturesIsArray Then
        _VectorOfMatRelease($vecImageSignatures)
    EndIf
EndFunc   ;==>_cvePCTSignaturesSQFDComputeQuadraticFormDistances

Func _cvePCTSignaturesSQFDRelease($sharedPtr)
    ; CVAPI(void) cvePCTSignaturesSQFDRelease(cv::Ptr<cv::xfeatures2d::PCTSignaturesSQFD>** sharedPtr);

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cvePCTSignaturesSQFDRelease", $bSharedPtrDllType, $sharedPtr), "cvePCTSignaturesSQFDRelease", @error)
EndFunc   ;==>_cvePCTSignaturesSQFDRelease

Func _cveHarrisLaplaceFeatureDetectorCreate($numOctaves, $corn_thresh, $DOG_thresh, $maxCorners, $num_layers, $sharedPtr)
    ; CVAPI(cv::xfeatures2d::HarrisLaplaceFeatureDetector*) cveHarrisLaplaceFeatureDetectorCreate(int numOctaves, float corn_thresh, float DOG_thresh, int maxCorners, int num_layers, cv::Ptr<cv::xfeatures2d::HarrisLaplaceFeatureDetector>** sharedPtr);

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveHarrisLaplaceFeatureDetectorCreate", "int", $numOctaves, "float", $corn_thresh, "float", $DOG_thresh, "int", $maxCorners, "int", $num_layers, $bSharedPtrDllType, $sharedPtr), "cveHarrisLaplaceFeatureDetectorCreate", @error)
EndFunc   ;==>_cveHarrisLaplaceFeatureDetectorCreate

Func _cveHarrisLaplaceFeatureDetectorRelease($sharedPtr)
    ; CVAPI(void) cveHarrisLaplaceFeatureDetectorRelease(cv::Ptr<cv::xfeatures2d::HarrisLaplaceFeatureDetector>** sharedPtr);

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveHarrisLaplaceFeatureDetectorRelease", $bSharedPtrDllType, $sharedPtr), "cveHarrisLaplaceFeatureDetectorRelease", @error)
EndFunc   ;==>_cveHarrisLaplaceFeatureDetectorRelease

Func _cveMatchGMS($size1, $size2, $keypoints1, $keypoints2, $matches1to2, $matchesGMS, $withRotation = false, $withScale = false, $thresholdFactor = 6.0)
    ; CVAPI(void) cveMatchGMS(CvSize* size1, CvSize* size2, std::vector<cv::KeyPoint>* keypoints1, std::vector<cv::KeyPoint>* keypoints2, std::vector<cv::DMatch>* matches1to2, std::vector<cv::DMatch>* matchesGMS, bool withRotation, bool withScale, double thresholdFactor);

    Local $bSize1DllType
    If VarGetType($size1) == "DLLStruct" Then
        $bSize1DllType = "struct*"
    Else
        $bSize1DllType = "ptr"
    EndIf

    Local $bSize2DllType
    If VarGetType($size2) == "DLLStruct" Then
        $bSize2DllType = "struct*"
    Else
        $bSize2DllType = "ptr"
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

    Local $bMatches1to2DllType
    If VarGetType($matches1to2) == "DLLStruct" Then
        $bMatches1to2DllType = "struct*"
    Else
        $bMatches1to2DllType = "ptr"
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

    Local $bMatchesGMSDllType
    If VarGetType($matchesGMS) == "DLLStruct" Then
        $bMatchesGMSDllType = "struct*"
    Else
        $bMatchesGMSDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMatchGMS", $bSize1DllType, $size1, $bSize2DllType, $size2, $bKeypoints1DllType, $vecKeypoints1, $bKeypoints2DllType, $vecKeypoints2, $bMatches1to2DllType, $vecMatches1to2, $bMatchesGMSDllType, $vecMatchesGMS, "boolean", $withRotation, "boolean", $withScale, "double", $thresholdFactor), "cveMatchGMS", @error)

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

Func _cveMatchLOGOS($keypoints1, $keypoints2, $nn1, $nn2, $matches1to2)
    ; CVAPI(void) cveMatchLOGOS(std::vector<cv::KeyPoint>* keypoints1, std::vector<cv::KeyPoint>* keypoints2, std::vector<int>* nn1, std::vector<int>* nn2, std::vector<cv::DMatch>* matches1to2);

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

    Local $bNn1DllType
    If VarGetType($nn1) == "DLLStruct" Then
        $bNn1DllType = "struct*"
    Else
        $bNn1DllType = "ptr"
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

    Local $bNn2DllType
    If VarGetType($nn2) == "DLLStruct" Then
        $bNn2DllType = "struct*"
    Else
        $bNn2DllType = "ptr"
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

    Local $bMatches1to2DllType
    If VarGetType($matches1to2) == "DLLStruct" Then
        $bMatches1to2DllType = "struct*"
    Else
        $bMatches1to2DllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMatchLOGOS", $bKeypoints1DllType, $vecKeypoints1, $bKeypoints2DllType, $vecKeypoints2, $bNn1DllType, $vecNn1, $bNn2DllType, $vecNn2, $bMatches1to2DllType, $vecMatches1to2), "cveMatchLOGOS", @error)

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