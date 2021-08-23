#include-once
#include "..\..\CVEUtils.au3"

Func _cveBEBLIDCreate($scaleFactor, $nBits, $feature2D, $sharedPtr)
    ; CVAPI(cv::xfeatures2d::BEBLID*) cveBEBLIDCreate(float scaleFactor, int nBits, cv::Feature2D** feature2D, cv::Ptr<cv::xfeatures2d::BEBLID>** sharedPtr);

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
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveBEBLIDCreate", "float", $scaleFactor, "int", $nBits, $sFeature2DDllType, $feature2D, $sSharedPtrDllType, $sharedPtr), "cveBEBLIDCreate", @error)
EndFunc   ;==>_cveBEBLIDCreate

Func _cveBEBLIDRelease($sharedPtr)
    ; CVAPI(void) cveBEBLIDRelease(cv::Ptr<cv::xfeatures2d::BEBLID>** sharedPtr);

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBEBLIDRelease", $sSharedPtrDllType, $sharedPtr), "cveBEBLIDRelease", @error)
EndFunc   ;==>_cveBEBLIDRelease

Func _cveTBMRCreate($minArea, $maxAreaRelative, $scaleFactor, $nScales, $feature2D, $sharedPtr)
    ; CVAPI(cv::xfeatures2d::TBMR*) cveTBMRCreate(int minArea, float maxAreaRelative, float scaleFactor, int nScales, cv::Feature2D** feature2D, cv::Ptr<cv::xfeatures2d::TBMR>** sharedPtr);

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
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveTBMRCreate", "int", $minArea, "float", $maxAreaRelative, "float", $scaleFactor, "int", $nScales, $sFeature2DDllType, $feature2D, $sSharedPtrDllType, $sharedPtr), "cveTBMRCreate", @error)
EndFunc   ;==>_cveTBMRCreate

Func _cveTBMRRelease($sharedPtr)
    ; CVAPI(void) cveTBMRRelease(cv::Ptr<cv::xfeatures2d::TBMR>** sharedPtr);

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveTBMRRelease", $sSharedPtrDllType, $sharedPtr), "cveTBMRRelease", @error)
EndFunc   ;==>_cveTBMRRelease

Func _cveStarDetectorCreate($maxSize, $responseThreshold, $lineThresholdProjected, $lineThresholdBinarized, $suppressNonmaxSize, $feature2D, $sharedPtr)
    ; CVAPI(cv::xfeatures2d::StarDetector*) cveStarDetectorCreate(int maxSize, int responseThreshold, int lineThresholdProjected, int lineThresholdBinarized, int suppressNonmaxSize, cv::Feature2D** feature2D, cv::Ptr<cv::xfeatures2d::StarDetector>** sharedPtr);

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
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveStarDetectorCreate", "int", $maxSize, "int", $responseThreshold, "int", $lineThresholdProjected, "int", $lineThresholdBinarized, "int", $suppressNonmaxSize, $sFeature2DDllType, $feature2D, $sSharedPtrDllType, $sharedPtr), "cveStarDetectorCreate", @error)
EndFunc   ;==>_cveStarDetectorCreate

Func _cveStarDetectorRelease($sharedPtr)
    ; CVAPI(void) cveStarDetectorRelease(cv::Ptr<cv::xfeatures2d::StarDetector>** sharedPtr);

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveStarDetectorRelease", $sSharedPtrDllType, $sharedPtr), "cveStarDetectorRelease", @error)
EndFunc   ;==>_cveStarDetectorRelease

Func _cveFreakCreate($orientationNormalized, $scaleNormalized, $patternScale, $nOctaves, $descriptorExtractor, $sharedPtr)
    ; CVAPI(cv::xfeatures2d::FREAK*) cveFreakCreate(bool orientationNormalized, bool scaleNormalized, float patternScale, int nOctaves, cv::Feature2D** descriptorExtractor, cv::Ptr<cv::xfeatures2d::FREAK>** sharedPtr);

    Local $sDescriptorExtractorDllType
    If IsDllStruct($descriptorExtractor) Then
        $sDescriptorExtractorDllType = "struct*"
    ElseIf $descriptorExtractor == Null Then
        $sDescriptorExtractorDllType = "ptr"
    Else
        $sDescriptorExtractorDllType = "ptr*"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveFreakCreate", "boolean", $orientationNormalized, "boolean", $scaleNormalized, "float", $patternScale, "int", $nOctaves, $sDescriptorExtractorDllType, $descriptorExtractor, $sSharedPtrDllType, $sharedPtr), "cveFreakCreate", @error)
EndFunc   ;==>_cveFreakCreate

Func _cveFreakRelease($sharedPtr)
    ; CVAPI(void) cveFreakRelease(cv::Ptr<cv::xfeatures2d::FREAK>** sharedPtr);

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFreakRelease", $sSharedPtrDllType, $sharedPtr), "cveFreakRelease", @error)
EndFunc   ;==>_cveFreakRelease

Func _cveBriefDescriptorExtractorCreate($descriptorSize, $feature2D, $sharedPtr)
    ; CVAPI(cv::xfeatures2d::BriefDescriptorExtractor*) cveBriefDescriptorExtractorCreate(int descriptorSize, cv::Feature2D** feature2D, cv::Ptr<cv::xfeatures2d::BriefDescriptorExtractor>** sharedPtr);

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
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveBriefDescriptorExtractorCreate", "int", $descriptorSize, $sFeature2DDllType, $feature2D, $sSharedPtrDllType, $sharedPtr), "cveBriefDescriptorExtractorCreate", @error)
EndFunc   ;==>_cveBriefDescriptorExtractorCreate

Func _cveBriefDescriptorExtractorRelease($sharedPtr)
    ; CVAPI(void) cveBriefDescriptorExtractorRelease(cv::Ptr<cv::xfeatures2d::BriefDescriptorExtractor>** sharedPtr);

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBriefDescriptorExtractorRelease", $sSharedPtrDllType, $sharedPtr), "cveBriefDescriptorExtractorRelease", @error)
EndFunc   ;==>_cveBriefDescriptorExtractorRelease

Func _cveLUCIDCreate($lucidKernel, $blurKernel, $feature2D, $sharedPtr)
    ; CVAPI(cv::xfeatures2d::LUCID*) cveLUCIDCreate(int lucidKernel, int blurKernel, cv::Feature2D** feature2D, cv::Ptr<cv::xfeatures2d::LUCID>** sharedPtr);

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
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveLUCIDCreate", "int", $lucidKernel, "int", $blurKernel, $sFeature2DDllType, $feature2D, $sSharedPtrDllType, $sharedPtr), "cveLUCIDCreate", @error)
EndFunc   ;==>_cveLUCIDCreate

Func _cveLUCIDRelease($sharedPtr)
    ; CVAPI(void) cveLUCIDRelease(cv::Ptr<cv::xfeatures2d::LUCID>** sharedPtr);

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveLUCIDRelease", $sSharedPtrDllType, $sharedPtr), "cveLUCIDRelease", @error)
EndFunc   ;==>_cveLUCIDRelease

Func _cveLATCHCreate($bytes, $rotationInvariance, $halfSsdSize, $extractor, $sharedPtr)
    ; CVAPI(cv::xfeatures2d::LATCH*) cveLATCHCreate(int bytes, bool rotationInvariance, int halfSsdSize, cv::Feature2D** extractor, cv::Ptr<cv::xfeatures2d::LATCH>** sharedPtr);

    Local $sExtractorDllType
    If IsDllStruct($extractor) Then
        $sExtractorDllType = "struct*"
    ElseIf $extractor == Null Then
        $sExtractorDllType = "ptr"
    Else
        $sExtractorDllType = "ptr*"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveLATCHCreate", "int", $bytes, "boolean", $rotationInvariance, "int", $halfSsdSize, $sExtractorDllType, $extractor, $sSharedPtrDllType, $sharedPtr), "cveLATCHCreate", @error)
EndFunc   ;==>_cveLATCHCreate

Func _cveLATCHRelease($sharedPtr)
    ; CVAPI(void) cveLATCHRelease(cv::Ptr<cv::xfeatures2d::LATCH>** sharedPtr);

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveLATCHRelease", $sSharedPtrDllType, $sharedPtr), "cveLATCHRelease", @error)
EndFunc   ;==>_cveLATCHRelease

Func _cveDAISYCreate($radius, $qRadius, $qTheta, $qHist, $norm, $H, $interpolation, $useOrientation, $extractor, $sharedPtr)
    ; CVAPI(cv::xfeatures2d::DAISY*) cveDAISYCreate(float radius, int qRadius, int qTheta, int qHist, int norm, cv::_InputArray* H, bool interpolation, bool useOrientation, cv::Feature2D** extractor, cv::Ptr<cv::xfeatures2d::DAISY>** sharedPtr);

    Local $sHDllType
    If IsDllStruct($H) Then
        $sHDllType = "struct*"
    Else
        $sHDllType = "ptr"
    EndIf

    Local $sExtractorDllType
    If IsDllStruct($extractor) Then
        $sExtractorDllType = "struct*"
    ElseIf $extractor == Null Then
        $sExtractorDllType = "ptr"
    Else
        $sExtractorDllType = "ptr*"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveDAISYCreate", "float", $radius, "int", $qRadius, "int", $qTheta, "int", $qHist, "int", $norm, $sHDllType, $H, "boolean", $interpolation, "boolean", $useOrientation, $sExtractorDllType, $extractor, $sSharedPtrDllType, $sharedPtr), "cveDAISYCreate", @error)
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

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDAISYRelease", $sSharedPtrDllType, $sharedPtr), "cveDAISYRelease", @error)
EndFunc   ;==>_cveDAISYRelease

Func _cveBoostDescCreate($desc, $useScaleOrientation, $scalefactor, $feature2D, $sharedPtr)
    ; CVAPI(cv::xfeatures2d::BoostDesc*) cveBoostDescCreate(int desc, bool useScaleOrientation, float scalefactor, cv::Feature2D** feature2D, cv::Ptr<cv::xfeatures2d::BoostDesc>** sharedPtr);

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
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveBoostDescCreate", "int", $desc, "boolean", $useScaleOrientation, "float", $scalefactor, $sFeature2DDllType, $feature2D, $sSharedPtrDllType, $sharedPtr), "cveBoostDescCreate", @error)
EndFunc   ;==>_cveBoostDescCreate

Func _cveBoostDescRelease($sharedPtr)
    ; CVAPI(void) cveBoostDescRelease(cv::Ptr<cv::xfeatures2d::BoostDesc>** sharedPtr);

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBoostDescRelease", $sSharedPtrDllType, $sharedPtr), "cveBoostDescRelease", @error)
EndFunc   ;==>_cveBoostDescRelease

Func _cveMSDDetectorCreate($m_patch_radius, $m_search_area_radius, $m_nms_radius, $m_nms_scale_radius, $m_th_saliency, $m_kNN, $m_scale_factor, $m_n_scales, $m_compute_orientation, $feature2D, $sharedPtr)
    ; CVAPI(cv::xfeatures2d::MSDDetector*) cveMSDDetectorCreate(int m_patch_radius, int m_search_area_radius, int m_nms_radius, int m_nms_scale_radius, float m_th_saliency, int m_kNN, float m_scale_factor, int m_n_scales, bool m_compute_orientation, cv::Feature2D** feature2D, cv::Ptr<cv::xfeatures2d::MSDDetector>** sharedPtr);

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
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveMSDDetectorCreate", "int", $m_patch_radius, "int", $m_search_area_radius, "int", $m_nms_radius, "int", $m_nms_scale_radius, "float", $m_th_saliency, "int", $m_kNN, "float", $m_scale_factor, "int", $m_n_scales, "boolean", $m_compute_orientation, $sFeature2DDllType, $feature2D, $sSharedPtrDllType, $sharedPtr), "cveMSDDetectorCreate", @error)
EndFunc   ;==>_cveMSDDetectorCreate

Func _cveMSDDetectorRelease($sharedPtr)
    ; CVAPI(void) cveMSDDetectorRelease(cv::Ptr<cv::xfeatures2d::MSDDetector>** sharedPtr);

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMSDDetectorRelease", $sSharedPtrDllType, $sharedPtr), "cveMSDDetectorRelease", @error)
EndFunc   ;==>_cveMSDDetectorRelease

Func _cveVGGCreate($desc, $isigma, $imgNormalize, $useScaleOrientation, $scaleFactor, $dscNormalize, $feature2D, $sharedPtr)
    ; CVAPI(cv::xfeatures2d::VGG*) cveVGGCreate(int desc, float isigma, bool imgNormalize, bool useScaleOrientation, float scaleFactor, bool dscNormalize, cv::Feature2D** feature2D, cv::Ptr<cv::xfeatures2d::VGG>** sharedPtr);

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
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveVGGCreate", "int", $desc, "float", $isigma, "boolean", $imgNormalize, "boolean", $useScaleOrientation, "float", $scaleFactor, "boolean", $dscNormalize, $sFeature2DDllType, $feature2D, $sSharedPtrDllType, $sharedPtr), "cveVGGCreate", @error)
EndFunc   ;==>_cveVGGCreate

Func _cveVGGRelease($sharedPtr)
    ; CVAPI(void) cveVGGRelease(cv::Ptr<cv::xfeatures2d::VGG>** sharedPtr);

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveVGGRelease", $sSharedPtrDllType, $sharedPtr), "cveVGGRelease", @error)
EndFunc   ;==>_cveVGGRelease

Func _cvePCTSignaturesCreate($initSampleCount, $initSeedCount, $pointDistribution, $sharedPtr)
    ; CVAPI(cv::xfeatures2d::PCTSignatures*) cvePCTSignaturesCreate(int initSampleCount, int initSeedCount, int pointDistribution, cv::Ptr<cv::xfeatures2d::PCTSignatures>** sharedPtr);

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cvePCTSignaturesCreate", "int", $initSampleCount, "int", $initSeedCount, "int", $pointDistribution, $sSharedPtrDllType, $sharedPtr), "cvePCTSignaturesCreate", @error)
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

    Local $sInitSamplingPointsDllType
    If IsDllStruct($initSamplingPoints) Then
        $sInitSamplingPointsDllType = "struct*"
    Else
        $sInitSamplingPointsDllType = "ptr"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cvePCTSignaturesCreate2", $sInitSamplingPointsDllType, $vecInitSamplingPoints, "int", $initSeedCount, $sSharedPtrDllType, $sharedPtr), "cvePCTSignaturesCreate2", @error)

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

    Local $sInitSamplingPointsDllType
    If IsDllStruct($initSamplingPoints) Then
        $sInitSamplingPointsDllType = "struct*"
    Else
        $sInitSamplingPointsDllType = "ptr"
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

    Local $sInitClusterSeedIndexesDllType
    If IsDllStruct($initClusterSeedIndexes) Then
        $sInitClusterSeedIndexesDllType = "struct*"
    Else
        $sInitClusterSeedIndexesDllType = "ptr"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cvePCTSignaturesCreate3", $sInitSamplingPointsDllType, $vecInitSamplingPoints, $sInitClusterSeedIndexesDllType, $vecInitClusterSeedIndexes, $sSharedPtrDllType, $sharedPtr), "cvePCTSignaturesCreate3", @error)

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

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cvePCTSignaturesRelease", $sSharedPtrDllType, $sharedPtr), "cvePCTSignaturesRelease", @error)
EndFunc   ;==>_cvePCTSignaturesRelease

Func _cvePCTSignaturesComputeSignature($pct, $image, $signature)
    ; CVAPI(void) cvePCTSignaturesComputeSignature(cv::xfeatures2d::PCTSignatures* pct, cv::_InputArray* image, cv::_OutputArray* signature);

    Local $sPctDllType
    If IsDllStruct($pct) Then
        $sPctDllType = "struct*"
    Else
        $sPctDllType = "ptr"
    EndIf

    Local $sImageDllType
    If IsDllStruct($image) Then
        $sImageDllType = "struct*"
    Else
        $sImageDllType = "ptr"
    EndIf

    Local $sSignatureDllType
    If IsDllStruct($signature) Then
        $sSignatureDllType = "struct*"
    Else
        $sSignatureDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cvePCTSignaturesComputeSignature", $sPctDllType, $pct, $sImageDllType, $image, $sSignatureDllType, $signature), "cvePCTSignaturesComputeSignature", @error)
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

    Local $sSourceDllType
    If IsDllStruct($source) Then
        $sSourceDllType = "struct*"
    Else
        $sSourceDllType = "ptr"
    EndIf

    Local $sSignatureDllType
    If IsDllStruct($signature) Then
        $sSignatureDllType = "struct*"
    Else
        $sSignatureDllType = "ptr"
    EndIf

    Local $sResultDllType
    If IsDllStruct($result) Then
        $sResultDllType = "struct*"
    Else
        $sResultDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cvePCTSignaturesDrawSignature", $sSourceDllType, $source, $sSignatureDllType, $signature, $sResultDllType, $result, "float", $radiusToShorterSideRatio, "int", $borderThickness), "cvePCTSignaturesDrawSignature", @error)
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

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cvePCTSignaturesSQFDCreate", "int", $distanceFunction, "int", $similarityFunction, "float", $similarityParameter, $sSharedPtrDllType, $sharedPtr), "cvePCTSignaturesSQFDCreate", @error)
EndFunc   ;==>_cvePCTSignaturesSQFDCreate

Func _cvePCTSignaturesSQFDComputeQuadraticFormDistance($sqfd, $signature0, $signature1)
    ; CVAPI(float) cvePCTSignaturesSQFDComputeQuadraticFormDistance(cv::xfeatures2d::PCTSignaturesSQFD* sqfd, cv::_InputArray* signature0, cv::_InputArray* signature1);

    Local $sSqfdDllType
    If IsDllStruct($sqfd) Then
        $sSqfdDllType = "struct*"
    Else
        $sSqfdDllType = "ptr"
    EndIf

    Local $sSignature0DllType
    If IsDllStruct($signature0) Then
        $sSignature0DllType = "struct*"
    Else
        $sSignature0DllType = "ptr"
    EndIf

    Local $sSignature1DllType
    If IsDllStruct($signature1) Then
        $sSignature1DllType = "struct*"
    Else
        $sSignature1DllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cvePCTSignaturesSQFDComputeQuadraticFormDistance", $sSqfdDllType, $sqfd, $sSignature0DllType, $signature0, $sSignature1DllType, $signature1), "cvePCTSignaturesSQFDComputeQuadraticFormDistance", @error)
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

    Local $sSqfdDllType
    If IsDllStruct($sqfd) Then
        $sSqfdDllType = "struct*"
    Else
        $sSqfdDllType = "ptr"
    EndIf

    Local $sSourceSignatureDllType
    If IsDllStruct($sourceSignature) Then
        $sSourceSignatureDllType = "struct*"
    Else
        $sSourceSignatureDllType = "ptr"
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

    Local $sImageSignaturesDllType
    If IsDllStruct($imageSignatures) Then
        $sImageSignaturesDllType = "struct*"
    Else
        $sImageSignaturesDllType = "ptr"
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

    Local $sDistancesDllType
    If IsDllStruct($distances) Then
        $sDistancesDllType = "struct*"
    Else
        $sDistancesDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cvePCTSignaturesSQFDComputeQuadraticFormDistances", $sSqfdDllType, $sqfd, $sSourceSignatureDllType, $sourceSignature, $sImageSignaturesDllType, $vecImageSignatures, $sDistancesDllType, $vecDistances), "cvePCTSignaturesSQFDComputeQuadraticFormDistances", @error)

    If $bDistancesIsArray Then
        _VectorOfFloatRelease($vecDistances)
    EndIf

    If $bImageSignaturesIsArray Then
        _VectorOfMatRelease($vecImageSignatures)
    EndIf
EndFunc   ;==>_cvePCTSignaturesSQFDComputeQuadraticFormDistances

Func _cvePCTSignaturesSQFDRelease($sharedPtr)
    ; CVAPI(void) cvePCTSignaturesSQFDRelease(cv::Ptr<cv::xfeatures2d::PCTSignaturesSQFD>** sharedPtr);

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cvePCTSignaturesSQFDRelease", $sSharedPtrDllType, $sharedPtr), "cvePCTSignaturesSQFDRelease", @error)
EndFunc   ;==>_cvePCTSignaturesSQFDRelease

Func _cveHarrisLaplaceFeatureDetectorCreate($numOctaves, $corn_thresh, $DOG_thresh, $maxCorners, $num_layers, $sharedPtr)
    ; CVAPI(cv::xfeatures2d::HarrisLaplaceFeatureDetector*) cveHarrisLaplaceFeatureDetectorCreate(int numOctaves, float corn_thresh, float DOG_thresh, int maxCorners, int num_layers, cv::Ptr<cv::xfeatures2d::HarrisLaplaceFeatureDetector>** sharedPtr);

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveHarrisLaplaceFeatureDetectorCreate", "int", $numOctaves, "float", $corn_thresh, "float", $DOG_thresh, "int", $maxCorners, "int", $num_layers, $sSharedPtrDllType, $sharedPtr), "cveHarrisLaplaceFeatureDetectorCreate", @error)
EndFunc   ;==>_cveHarrisLaplaceFeatureDetectorCreate

Func _cveHarrisLaplaceFeatureDetectorRelease($sharedPtr)
    ; CVAPI(void) cveHarrisLaplaceFeatureDetectorRelease(cv::Ptr<cv::xfeatures2d::HarrisLaplaceFeatureDetector>** sharedPtr);

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveHarrisLaplaceFeatureDetectorRelease", $sSharedPtrDllType, $sharedPtr), "cveHarrisLaplaceFeatureDetectorRelease", @error)
EndFunc   ;==>_cveHarrisLaplaceFeatureDetectorRelease

Func _cveMatchGMS($size1, $size2, $keypoints1, $keypoints2, $matches1to2, $matchesGMS, $withRotation = false, $withScale = false, $thresholdFactor = 6.0)
    ; CVAPI(void) cveMatchGMS(CvSize* size1, CvSize* size2, std::vector<cv::KeyPoint>* keypoints1, std::vector<cv::KeyPoint>* keypoints2, std::vector<cv::DMatch>* matches1to2, std::vector<cv::DMatch>* matchesGMS, bool withRotation, bool withScale, double thresholdFactor);

    Local $sSize1DllType
    If IsDllStruct($size1) Then
        $sSize1DllType = "struct*"
    Else
        $sSize1DllType = "ptr"
    EndIf

    Local $sSize2DllType
    If IsDllStruct($size2) Then
        $sSize2DllType = "struct*"
    Else
        $sSize2DllType = "ptr"
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

    Local $sKeypoints1DllType
    If IsDllStruct($keypoints1) Then
        $sKeypoints1DllType = "struct*"
    Else
        $sKeypoints1DllType = "ptr"
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

    Local $sKeypoints2DllType
    If IsDllStruct($keypoints2) Then
        $sKeypoints2DllType = "struct*"
    Else
        $sKeypoints2DllType = "ptr"
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

    Local $sMatches1to2DllType
    If IsDllStruct($matches1to2) Then
        $sMatches1to2DllType = "struct*"
    Else
        $sMatches1to2DllType = "ptr"
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

    Local $sMatchesGMSDllType
    If IsDllStruct($matchesGMS) Then
        $sMatchesGMSDllType = "struct*"
    Else
        $sMatchesGMSDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMatchGMS", $sSize1DllType, $size1, $sSize2DllType, $size2, $sKeypoints1DllType, $vecKeypoints1, $sKeypoints2DllType, $vecKeypoints2, $sMatches1to2DllType, $vecMatches1to2, $sMatchesGMSDllType, $vecMatchesGMS, "boolean", $withRotation, "boolean", $withScale, "double", $thresholdFactor), "cveMatchGMS", @error)

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

    Local $sKeypoints1DllType
    If IsDllStruct($keypoints1) Then
        $sKeypoints1DllType = "struct*"
    Else
        $sKeypoints1DllType = "ptr"
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

    Local $sKeypoints2DllType
    If IsDllStruct($keypoints2) Then
        $sKeypoints2DllType = "struct*"
    Else
        $sKeypoints2DllType = "ptr"
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

    Local $sNn1DllType
    If IsDllStruct($nn1) Then
        $sNn1DllType = "struct*"
    Else
        $sNn1DllType = "ptr"
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

    Local $sNn2DllType
    If IsDllStruct($nn2) Then
        $sNn2DllType = "struct*"
    Else
        $sNn2DllType = "ptr"
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

    Local $sMatches1to2DllType
    If IsDllStruct($matches1to2) Then
        $sMatches1to2DllType = "struct*"
    Else
        $sMatches1to2DllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMatchLOGOS", $sKeypoints1DllType, $vecKeypoints1, $sKeypoints2DllType, $vecKeypoints2, $sNn1DllType, $vecNn1, $sNn2DllType, $vecNn2, $sMatches1to2DllType, $vecMatches1to2), "cveMatchLOGOS", @error)

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