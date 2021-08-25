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

Func _cveDAISYCreateTyped($radius, $qRadius, $qTheta, $qHist, $norm, $typeOfH, $H, $interpolation, $useOrientation, $extractor, $sharedPtr)

    Local $iArrH, $vectorH, $iArrHSize
    Local $bHIsArray = IsArray($H)
    Local $bHCreate = IsDllStruct($H) And $typeOfH == "Scalar"

    If $typeOfH == Default Then
        $iArrH = $H
    ElseIf $bHIsArray Then
        $vectorH = Call("_VectorOf" & $typeOfH & "Create")

        $iArrHSize = UBound($H)
        For $i = 0 To $iArrHSize - 1
            Call("_VectorOf" & $typeOfH & "Push", $vectorH, $H[$i])
        Next

        $iArrH = Call("_cveInputArrayFromVectorOf" & $typeOfH, $vectorH)
    Else
        If $bHCreate Then
            $H = Call("_cve" & $typeOfH & "Create", $H)
        EndIf
        $iArrH = Call("_cveInputArrayFrom" & $typeOfH, $H)
    EndIf

    Local $retval = _cveDAISYCreate($radius, $qRadius, $qTheta, $qHist, $norm, $iArrH, $interpolation, $useOrientation, $extractor, $sharedPtr)

    If $bHIsArray Then
        Call("_VectorOf" & $typeOfH & "Release", $vectorH)
    EndIf

    If $typeOfH <> Default Then
        _cveInputArrayRelease($iArrH)
        If $bHCreate Then
            Call("_cve" & $typeOfH & "Release", $H)
        EndIf
    EndIf

    Return $retval
EndFunc   ;==>_cveDAISYCreateTyped

Func _cveDAISYCreateMat($radius, $qRadius, $qTheta, $qHist, $norm, $H, $interpolation, $useOrientation, $extractor, $sharedPtr)
    ; cveDAISYCreate using cv::Mat instead of _*Array
    Local $retval = _cveDAISYCreateTyped($radius, $qRadius, $qTheta, $qHist, $norm, "Mat", $H, $interpolation, $useOrientation, $extractor, $sharedPtr)

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
    Local $bInitSamplingPointsIsArray = IsArray($initSamplingPoints)

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
    Local $bInitSamplingPointsIsArray = IsArray($initSamplingPoints)

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
    Local $bInitClusterSeedIndexesIsArray = IsArray($initClusterSeedIndexes)

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

Func _cvePCTSignaturesComputeSignatureTyped($pct, $typeOfImage, $image, $typeOfSignature, $signature)

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

    Local $oArrSignature, $vectorSignature, $iArrSignatureSize
    Local $bSignatureIsArray = IsArray($signature)
    Local $bSignatureCreate = IsDllStruct($signature) And $typeOfSignature == "Scalar"

    If $typeOfSignature == Default Then
        $oArrSignature = $signature
    ElseIf $bSignatureIsArray Then
        $vectorSignature = Call("_VectorOf" & $typeOfSignature & "Create")

        $iArrSignatureSize = UBound($signature)
        For $i = 0 To $iArrSignatureSize - 1
            Call("_VectorOf" & $typeOfSignature & "Push", $vectorSignature, $signature[$i])
        Next

        $oArrSignature = Call("_cveOutputArrayFromVectorOf" & $typeOfSignature, $vectorSignature)
    Else
        If $bSignatureCreate Then
            $signature = Call("_cve" & $typeOfSignature & "Create", $signature)
        EndIf
        $oArrSignature = Call("_cveOutputArrayFrom" & $typeOfSignature, $signature)
    EndIf

    _cvePCTSignaturesComputeSignature($pct, $iArrImage, $oArrSignature)

    If $bSignatureIsArray Then
        Call("_VectorOf" & $typeOfSignature & "Release", $vectorSignature)
    EndIf

    If $typeOfSignature <> Default Then
        _cveOutputArrayRelease($oArrSignature)
        If $bSignatureCreate Then
            Call("_cve" & $typeOfSignature & "Release", $signature)
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
EndFunc   ;==>_cvePCTSignaturesComputeSignatureTyped

Func _cvePCTSignaturesComputeSignatureMat($pct, $image, $signature)
    ; cvePCTSignaturesComputeSignature using cv::Mat instead of _*Array
    _cvePCTSignaturesComputeSignatureTyped($pct, "Mat", $image, "Mat", $signature)
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

Func _cvePCTSignaturesDrawSignatureTyped($typeOfSource, $source, $typeOfSignature, $signature, $typeOfResult, $result, $radiusToShorterSideRatio, $borderThickness)

    Local $iArrSource, $vectorSource, $iArrSourceSize
    Local $bSourceIsArray = IsArray($source)
    Local $bSourceCreate = IsDllStruct($source) And $typeOfSource == "Scalar"

    If $typeOfSource == Default Then
        $iArrSource = $source
    ElseIf $bSourceIsArray Then
        $vectorSource = Call("_VectorOf" & $typeOfSource & "Create")

        $iArrSourceSize = UBound($source)
        For $i = 0 To $iArrSourceSize - 1
            Call("_VectorOf" & $typeOfSource & "Push", $vectorSource, $source[$i])
        Next

        $iArrSource = Call("_cveInputArrayFromVectorOf" & $typeOfSource, $vectorSource)
    Else
        If $bSourceCreate Then
            $source = Call("_cve" & $typeOfSource & "Create", $source)
        EndIf
        $iArrSource = Call("_cveInputArrayFrom" & $typeOfSource, $source)
    EndIf

    Local $iArrSignature, $vectorSignature, $iArrSignatureSize
    Local $bSignatureIsArray = IsArray($signature)
    Local $bSignatureCreate = IsDllStruct($signature) And $typeOfSignature == "Scalar"

    If $typeOfSignature == Default Then
        $iArrSignature = $signature
    ElseIf $bSignatureIsArray Then
        $vectorSignature = Call("_VectorOf" & $typeOfSignature & "Create")

        $iArrSignatureSize = UBound($signature)
        For $i = 0 To $iArrSignatureSize - 1
            Call("_VectorOf" & $typeOfSignature & "Push", $vectorSignature, $signature[$i])
        Next

        $iArrSignature = Call("_cveInputArrayFromVectorOf" & $typeOfSignature, $vectorSignature)
    Else
        If $bSignatureCreate Then
            $signature = Call("_cve" & $typeOfSignature & "Create", $signature)
        EndIf
        $iArrSignature = Call("_cveInputArrayFrom" & $typeOfSignature, $signature)
    EndIf

    Local $oArrResult, $vectorResult, $iArrResultSize
    Local $bResultIsArray = IsArray($result)
    Local $bResultCreate = IsDllStruct($result) And $typeOfResult == "Scalar"

    If $typeOfResult == Default Then
        $oArrResult = $result
    ElseIf $bResultIsArray Then
        $vectorResult = Call("_VectorOf" & $typeOfResult & "Create")

        $iArrResultSize = UBound($result)
        For $i = 0 To $iArrResultSize - 1
            Call("_VectorOf" & $typeOfResult & "Push", $vectorResult, $result[$i])
        Next

        $oArrResult = Call("_cveOutputArrayFromVectorOf" & $typeOfResult, $vectorResult)
    Else
        If $bResultCreate Then
            $result = Call("_cve" & $typeOfResult & "Create", $result)
        EndIf
        $oArrResult = Call("_cveOutputArrayFrom" & $typeOfResult, $result)
    EndIf

    _cvePCTSignaturesDrawSignature($iArrSource, $iArrSignature, $oArrResult, $radiusToShorterSideRatio, $borderThickness)

    If $bResultIsArray Then
        Call("_VectorOf" & $typeOfResult & "Release", $vectorResult)
    EndIf

    If $typeOfResult <> Default Then
        _cveOutputArrayRelease($oArrResult)
        If $bResultCreate Then
            Call("_cve" & $typeOfResult & "Release", $result)
        EndIf
    EndIf

    If $bSignatureIsArray Then
        Call("_VectorOf" & $typeOfSignature & "Release", $vectorSignature)
    EndIf

    If $typeOfSignature <> Default Then
        _cveInputArrayRelease($iArrSignature)
        If $bSignatureCreate Then
            Call("_cve" & $typeOfSignature & "Release", $signature)
        EndIf
    EndIf

    If $bSourceIsArray Then
        Call("_VectorOf" & $typeOfSource & "Release", $vectorSource)
    EndIf

    If $typeOfSource <> Default Then
        _cveInputArrayRelease($iArrSource)
        If $bSourceCreate Then
            Call("_cve" & $typeOfSource & "Release", $source)
        EndIf
    EndIf
EndFunc   ;==>_cvePCTSignaturesDrawSignatureTyped

Func _cvePCTSignaturesDrawSignatureMat($source, $signature, $result, $radiusToShorterSideRatio, $borderThickness)
    ; cvePCTSignaturesDrawSignature using cv::Mat instead of _*Array
    _cvePCTSignaturesDrawSignatureTyped("Mat", $source, "Mat", $signature, "Mat", $result, $radiusToShorterSideRatio, $borderThickness)
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

Func _cvePCTSignaturesSQFDComputeQuadraticFormDistanceTyped($sqfd, $typeOfSignature0, $signature0, $typeOfSignature1, $signature1)

    Local $iArrSignature0, $vectorSignature0, $iArrSignature0Size
    Local $bSignature0IsArray = IsArray($signature0)
    Local $bSignature0Create = IsDllStruct($signature0) And $typeOfSignature0 == "Scalar"

    If $typeOfSignature0 == Default Then
        $iArrSignature0 = $signature0
    ElseIf $bSignature0IsArray Then
        $vectorSignature0 = Call("_VectorOf" & $typeOfSignature0 & "Create")

        $iArrSignature0Size = UBound($signature0)
        For $i = 0 To $iArrSignature0Size - 1
            Call("_VectorOf" & $typeOfSignature0 & "Push", $vectorSignature0, $signature0[$i])
        Next

        $iArrSignature0 = Call("_cveInputArrayFromVectorOf" & $typeOfSignature0, $vectorSignature0)
    Else
        If $bSignature0Create Then
            $signature0 = Call("_cve" & $typeOfSignature0 & "Create", $signature0)
        EndIf
        $iArrSignature0 = Call("_cveInputArrayFrom" & $typeOfSignature0, $signature0)
    EndIf

    Local $iArrSignature1, $vectorSignature1, $iArrSignature1Size
    Local $bSignature1IsArray = IsArray($signature1)
    Local $bSignature1Create = IsDllStruct($signature1) And $typeOfSignature1 == "Scalar"

    If $typeOfSignature1 == Default Then
        $iArrSignature1 = $signature1
    ElseIf $bSignature1IsArray Then
        $vectorSignature1 = Call("_VectorOf" & $typeOfSignature1 & "Create")

        $iArrSignature1Size = UBound($signature1)
        For $i = 0 To $iArrSignature1Size - 1
            Call("_VectorOf" & $typeOfSignature1 & "Push", $vectorSignature1, $signature1[$i])
        Next

        $iArrSignature1 = Call("_cveInputArrayFromVectorOf" & $typeOfSignature1, $vectorSignature1)
    Else
        If $bSignature1Create Then
            $signature1 = Call("_cve" & $typeOfSignature1 & "Create", $signature1)
        EndIf
        $iArrSignature1 = Call("_cveInputArrayFrom" & $typeOfSignature1, $signature1)
    EndIf

    Local $retval = _cvePCTSignaturesSQFDComputeQuadraticFormDistance($sqfd, $iArrSignature0, $iArrSignature1)

    If $bSignature1IsArray Then
        Call("_VectorOf" & $typeOfSignature1 & "Release", $vectorSignature1)
    EndIf

    If $typeOfSignature1 <> Default Then
        _cveInputArrayRelease($iArrSignature1)
        If $bSignature1Create Then
            Call("_cve" & $typeOfSignature1 & "Release", $signature1)
        EndIf
    EndIf

    If $bSignature0IsArray Then
        Call("_VectorOf" & $typeOfSignature0 & "Release", $vectorSignature0)
    EndIf

    If $typeOfSignature0 <> Default Then
        _cveInputArrayRelease($iArrSignature0)
        If $bSignature0Create Then
            Call("_cve" & $typeOfSignature0 & "Release", $signature0)
        EndIf
    EndIf

    Return $retval
EndFunc   ;==>_cvePCTSignaturesSQFDComputeQuadraticFormDistanceTyped

Func _cvePCTSignaturesSQFDComputeQuadraticFormDistanceMat($sqfd, $signature0, $signature1)
    ; cvePCTSignaturesSQFDComputeQuadraticFormDistance using cv::Mat instead of _*Array
    Local $retval = _cvePCTSignaturesSQFDComputeQuadraticFormDistanceTyped($sqfd, "Mat", $signature0, "Mat", $signature1)

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
    Local $bImageSignaturesIsArray = IsArray($imageSignatures)

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
    Local $bDistancesIsArray = IsArray($distances)

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

    Local $vecMatches1to2, $iArrMatches1to2Size
    Local $bMatches1to2IsArray = IsArray($matches1to2)

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
    Local $bMatchesGMSIsArray = IsArray($matchesGMS)

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

    Local $vecNn1, $iArrNn1Size
    Local $bNn1IsArray = IsArray($nn1)

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
    Local $bNn2IsArray = IsArray($nn2)

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
    Local $bMatches1to2IsArray = IsArray($matches1to2)

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