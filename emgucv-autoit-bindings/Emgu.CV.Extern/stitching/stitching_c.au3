#include-once
#include "..\..\CVEUtils.au3"

Func _cveStitcherCreate($mode, $sharedPtr)
    ; CVAPI(cv::Stitcher*) cveStitcherCreate(int mode, cv::Ptr<cv::Stitcher>** sharedPtr);

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveStitcherCreate", "int", $mode, $sSharedPtrDllType, $sharedPtr), "cveStitcherCreate", @error)
EndFunc   ;==>_cveStitcherCreate

Func _cveStitcherRelease($sharedPtr)
    ; CVAPI(void) cveStitcherRelease(cv::Ptr<cv::Stitcher>** sharedPtr);

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveStitcherRelease", $sSharedPtrDllType, $sharedPtr), "cveStitcherRelease", @error)
EndFunc   ;==>_cveStitcherRelease

Func _cveStitcherSetFeaturesFinder($stitcher, $finder)
    ; CVAPI(void) cveStitcherSetFeaturesFinder(cv::Stitcher* stitcher, cv::Feature2D* finder);

    Local $sStitcherDllType
    If IsDllStruct($stitcher) Then
        $sStitcherDllType = "struct*"
    Else
        $sStitcherDllType = "ptr"
    EndIf

    Local $sFinderDllType
    If IsDllStruct($finder) Then
        $sFinderDllType = "struct*"
    Else
        $sFinderDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveStitcherSetFeaturesFinder", $sStitcherDllType, $stitcher, $sFinderDllType, $finder), "cveStitcherSetFeaturesFinder", @error)
EndFunc   ;==>_cveStitcherSetFeaturesFinder

Func _cveStitcherSetWarper($stitcher, $creator)
    ; CVAPI(void) cveStitcherSetWarper(cv::Stitcher* stitcher, cv::WarperCreator* creator);

    Local $sStitcherDllType
    If IsDllStruct($stitcher) Then
        $sStitcherDllType = "struct*"
    Else
        $sStitcherDllType = "ptr"
    EndIf

    Local $sCreatorDllType
    If IsDllStruct($creator) Then
        $sCreatorDllType = "struct*"
    Else
        $sCreatorDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveStitcherSetWarper", $sStitcherDllType, $stitcher, $sCreatorDllType, $creator), "cveStitcherSetWarper", @error)
EndFunc   ;==>_cveStitcherSetWarper

Func _cveStitcherSetBlender($stitcher, $b)
    ; CVAPI(void) cveStitcherSetBlender(cv::Stitcher* stitcher, cv::detail::Blender* b);

    Local $sStitcherDllType
    If IsDllStruct($stitcher) Then
        $sStitcherDllType = "struct*"
    Else
        $sStitcherDllType = "ptr"
    EndIf

    Local $sBDllType
    If IsDllStruct($b) Then
        $sBDllType = "struct*"
    Else
        $sBDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveStitcherSetBlender", $sStitcherDllType, $stitcher, $sBDllType, $b), "cveStitcherSetBlender", @error)
EndFunc   ;==>_cveStitcherSetBlender

Func _cveStitcherSetExposureCompensator($stitcher, $exposureComp)
    ; CVAPI(void) cveStitcherSetExposureCompensator(cv::Stitcher* stitcher, cv::detail::ExposureCompensator* exposureComp);

    Local $sStitcherDllType
    If IsDllStruct($stitcher) Then
        $sStitcherDllType = "struct*"
    Else
        $sStitcherDllType = "ptr"
    EndIf

    Local $sExposureCompDllType
    If IsDllStruct($exposureComp) Then
        $sExposureCompDllType = "struct*"
    Else
        $sExposureCompDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveStitcherSetExposureCompensator", $sStitcherDllType, $stitcher, $sExposureCompDllType, $exposureComp), "cveStitcherSetExposureCompensator", @error)
EndFunc   ;==>_cveStitcherSetExposureCompensator

Func _cveStitcherSetBundleAdjuster($stitcher, $bundleAdjuster)
    ; CVAPI(void) cveStitcherSetBundleAdjuster(cv::Stitcher* stitcher, cv::detail::BundleAdjusterBase* bundleAdjuster);

    Local $sStitcherDllType
    If IsDllStruct($stitcher) Then
        $sStitcherDllType = "struct*"
    Else
        $sStitcherDllType = "ptr"
    EndIf

    Local $sBundleAdjusterDllType
    If IsDllStruct($bundleAdjuster) Then
        $sBundleAdjusterDllType = "struct*"
    Else
        $sBundleAdjusterDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveStitcherSetBundleAdjuster", $sStitcherDllType, $stitcher, $sBundleAdjusterDllType, $bundleAdjuster), "cveStitcherSetBundleAdjuster", @error)
EndFunc   ;==>_cveStitcherSetBundleAdjuster

Func _cveStitcherSetSeamFinder($stitcher, $seamFinder)
    ; CVAPI(void) cveStitcherSetSeamFinder(cv::Stitcher* stitcher, cv::detail::SeamFinder* seamFinder);

    Local $sStitcherDllType
    If IsDllStruct($stitcher) Then
        $sStitcherDllType = "struct*"
    Else
        $sStitcherDllType = "ptr"
    EndIf

    Local $sSeamFinderDllType
    If IsDllStruct($seamFinder) Then
        $sSeamFinderDllType = "struct*"
    Else
        $sSeamFinderDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveStitcherSetSeamFinder", $sStitcherDllType, $stitcher, $sSeamFinderDllType, $seamFinder), "cveStitcherSetSeamFinder", @error)
EndFunc   ;==>_cveStitcherSetSeamFinder

Func _cveStitcherSetEstimator($stitcher, $estimator)
    ; CVAPI(void) cveStitcherSetEstimator(cv::Stitcher* stitcher, cv::detail::Estimator* estimator);

    Local $sStitcherDllType
    If IsDllStruct($stitcher) Then
        $sStitcherDllType = "struct*"
    Else
        $sStitcherDllType = "ptr"
    EndIf

    Local $sEstimatorDllType
    If IsDllStruct($estimator) Then
        $sEstimatorDllType = "struct*"
    Else
        $sEstimatorDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveStitcherSetEstimator", $sStitcherDllType, $stitcher, $sEstimatorDllType, $estimator), "cveStitcherSetEstimator", @error)
EndFunc   ;==>_cveStitcherSetEstimator

Func _cveStitcherSetFeaturesMatcher($stitcher, $featuresMatcher)
    ; CVAPI(void) cveStitcherSetFeaturesMatcher(cv::Stitcher* stitcher, cv::detail::FeaturesMatcher* featuresMatcher);

    Local $sStitcherDllType
    If IsDllStruct($stitcher) Then
        $sStitcherDllType = "struct*"
    Else
        $sStitcherDllType = "ptr"
    EndIf

    Local $sFeaturesMatcherDllType
    If IsDllStruct($featuresMatcher) Then
        $sFeaturesMatcherDllType = "struct*"
    Else
        $sFeaturesMatcherDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveStitcherSetFeaturesMatcher", $sStitcherDllType, $stitcher, $sFeaturesMatcherDllType, $featuresMatcher), "cveStitcherSetFeaturesMatcher", @error)
EndFunc   ;==>_cveStitcherSetFeaturesMatcher

Func _cveStitcherSetWaveCorrection($stitcher, $flag)
    ; CVAPI(void) cveStitcherSetWaveCorrection(cv::Stitcher* stitcher, bool flag);

    Local $sStitcherDllType
    If IsDllStruct($stitcher) Then
        $sStitcherDllType = "struct*"
    Else
        $sStitcherDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveStitcherSetWaveCorrection", $sStitcherDllType, $stitcher, "boolean", $flag), "cveStitcherSetWaveCorrection", @error)
EndFunc   ;==>_cveStitcherSetWaveCorrection

Func _cveStitcherGetWaveCorrection($stitcher)
    ; CVAPI(bool) cveStitcherGetWaveCorrection(cv::Stitcher* stitcher);

    Local $sStitcherDllType
    If IsDllStruct($stitcher) Then
        $sStitcherDllType = "struct*"
    Else
        $sStitcherDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveStitcherGetWaveCorrection", $sStitcherDllType, $stitcher), "cveStitcherGetWaveCorrection", @error)
EndFunc   ;==>_cveStitcherGetWaveCorrection

Func _cveStitcherSetWaveCorrectionKind($stitcher, $kind)
    ; CVAPI(void) cveStitcherSetWaveCorrectionKind(cv::Stitcher* stitcher, int kind);

    Local $sStitcherDllType
    If IsDllStruct($stitcher) Then
        $sStitcherDllType = "struct*"
    Else
        $sStitcherDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveStitcherSetWaveCorrectionKind", $sStitcherDllType, $stitcher, "int", $kind), "cveStitcherSetWaveCorrectionKind", @error)
EndFunc   ;==>_cveStitcherSetWaveCorrectionKind

Func _cveStitcherGetWaveCorrectionKind($stitcher)
    ; CVAPI(int) cveStitcherGetWaveCorrectionKind(cv::Stitcher* stitcher);

    Local $sStitcherDllType
    If IsDllStruct($stitcher) Then
        $sStitcherDllType = "struct*"
    Else
        $sStitcherDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveStitcherGetWaveCorrectionKind", $sStitcherDllType, $stitcher), "cveStitcherGetWaveCorrectionKind", @error)
EndFunc   ;==>_cveStitcherGetWaveCorrectionKind

Func _cveStitcherSetPanoConfidenceThresh($stitcher, $confThresh)
    ; CVAPI(void) cveStitcherSetPanoConfidenceThresh(cv::Stitcher* stitcher, double confThresh);

    Local $sStitcherDllType
    If IsDllStruct($stitcher) Then
        $sStitcherDllType = "struct*"
    Else
        $sStitcherDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveStitcherSetPanoConfidenceThresh", $sStitcherDllType, $stitcher, "double", $confThresh), "cveStitcherSetPanoConfidenceThresh", @error)
EndFunc   ;==>_cveStitcherSetPanoConfidenceThresh

Func _cveStitcherGetPanoConfidenceThresh($stitcher)
    ; CVAPI(double) cveStitcherGetPanoConfidenceThresh(cv::Stitcher* stitcher);

    Local $sStitcherDllType
    If IsDllStruct($stitcher) Then
        $sStitcherDllType = "struct*"
    Else
        $sStitcherDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveStitcherGetPanoConfidenceThresh", $sStitcherDllType, $stitcher), "cveStitcherGetPanoConfidenceThresh", @error)
EndFunc   ;==>_cveStitcherGetPanoConfidenceThresh

Func _cveStitcherSetCompositingResol($stitcher, $resolMpx)
    ; CVAPI(void) cveStitcherSetCompositingResol(cv::Stitcher* stitcher, double resolMpx);

    Local $sStitcherDllType
    If IsDllStruct($stitcher) Then
        $sStitcherDllType = "struct*"
    Else
        $sStitcherDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveStitcherSetCompositingResol", $sStitcherDllType, $stitcher, "double", $resolMpx), "cveStitcherSetCompositingResol", @error)
EndFunc   ;==>_cveStitcherSetCompositingResol

Func _cveStitcherGetCompositingResol($stitcher)
    ; CVAPI(double) cveStitcherGetCompositingResol(cv::Stitcher* stitcher);

    Local $sStitcherDllType
    If IsDllStruct($stitcher) Then
        $sStitcherDllType = "struct*"
    Else
        $sStitcherDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveStitcherGetCompositingResol", $sStitcherDllType, $stitcher), "cveStitcherGetCompositingResol", @error)
EndFunc   ;==>_cveStitcherGetCompositingResol

Func _cveStitcherSetSeamEstimationResol($stitcher, $resolMpx)
    ; CVAPI(void) cveStitcherSetSeamEstimationResol(cv::Stitcher* stitcher, double resolMpx);

    Local $sStitcherDllType
    If IsDllStruct($stitcher) Then
        $sStitcherDllType = "struct*"
    Else
        $sStitcherDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveStitcherSetSeamEstimationResol", $sStitcherDllType, $stitcher, "double", $resolMpx), "cveStitcherSetSeamEstimationResol", @error)
EndFunc   ;==>_cveStitcherSetSeamEstimationResol

Func _cveStitcherGetSeamEstimationResol($stitcher)
    ; CVAPI(double) cveStitcherGetSeamEstimationResol(cv::Stitcher* stitcher);

    Local $sStitcherDllType
    If IsDllStruct($stitcher) Then
        $sStitcherDllType = "struct*"
    Else
        $sStitcherDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveStitcherGetSeamEstimationResol", $sStitcherDllType, $stitcher), "cveStitcherGetSeamEstimationResol", @error)
EndFunc   ;==>_cveStitcherGetSeamEstimationResol

Func _cveStitcherSetRegistrationResol($stitcher, $resolMpx)
    ; CVAPI(void) cveStitcherSetRegistrationResol(cv::Stitcher* stitcher, double resolMpx);

    Local $sStitcherDllType
    If IsDllStruct($stitcher) Then
        $sStitcherDllType = "struct*"
    Else
        $sStitcherDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveStitcherSetRegistrationResol", $sStitcherDllType, $stitcher, "double", $resolMpx), "cveStitcherSetRegistrationResol", @error)
EndFunc   ;==>_cveStitcherSetRegistrationResol

Func _cveStitcherGetRegistrationResol($stitcher)
    ; CVAPI(double) cveStitcherGetRegistrationResol(cv::Stitcher* stitcher);

    Local $sStitcherDllType
    If IsDllStruct($stitcher) Then
        $sStitcherDllType = "struct*"
    Else
        $sStitcherDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveStitcherGetRegistrationResol", $sStitcherDllType, $stitcher), "cveStitcherGetRegistrationResol", @error)
EndFunc   ;==>_cveStitcherGetRegistrationResol

Func _cveStitcherGetInterpolationFlags($stitcher)
    ; CVAPI(int) cveStitcherGetInterpolationFlags(cv::Stitcher* stitcher);

    Local $sStitcherDllType
    If IsDllStruct($stitcher) Then
        $sStitcherDllType = "struct*"
    Else
        $sStitcherDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveStitcherGetInterpolationFlags", $sStitcherDllType, $stitcher), "cveStitcherGetInterpolationFlags", @error)
EndFunc   ;==>_cveStitcherGetInterpolationFlags

Func _cveStitcherSetInterpolationFlags($stitcher, $interpFlags)
    ; CVAPI(void) cveStitcherSetInterpolationFlags(cv::Stitcher* stitcher, int interpFlags);

    Local $sStitcherDllType
    If IsDllStruct($stitcher) Then
        $sStitcherDllType = "struct*"
    Else
        $sStitcherDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveStitcherSetInterpolationFlags", $sStitcherDllType, $stitcher, "int", $interpFlags), "cveStitcherSetInterpolationFlags", @error)
EndFunc   ;==>_cveStitcherSetInterpolationFlags

Func _cveStitcherStitch($stitcher, $images, $pano)
    ; CVAPI(int) cveStitcherStitch(cv::Stitcher* stitcher, cv::_InputArray* images, cv::_OutputArray* pano);

    Local $sStitcherDllType
    If IsDllStruct($stitcher) Then
        $sStitcherDllType = "struct*"
    Else
        $sStitcherDllType = "ptr"
    EndIf

    Local $sImagesDllType
    If IsDllStruct($images) Then
        $sImagesDllType = "struct*"
    Else
        $sImagesDllType = "ptr"
    EndIf

    Local $sPanoDllType
    If IsDllStruct($pano) Then
        $sPanoDllType = "struct*"
    Else
        $sPanoDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveStitcherStitch", $sStitcherDllType, $stitcher, $sImagesDllType, $images, $sPanoDllType, $pano), "cveStitcherStitch", @error)
EndFunc   ;==>_cveStitcherStitch

Func _cveStitcherStitchMat($stitcher, $matImages, $matPano)
    ; cveStitcherStitch using cv::Mat instead of _*Array

    Local $iArrImages, $vectorOfMatImages, $iArrImagesSize
    Local $bImagesIsArray = VarGetType($matImages) == "Array"

    If $bImagesIsArray Then
        $vectorOfMatImages = _VectorOfMatCreate()

        $iArrImagesSize = UBound($matImages)
        For $i = 0 To $iArrImagesSize - 1
            _VectorOfMatPush($vectorOfMatImages, $matImages[$i])
        Next

        $iArrImages = _cveInputArrayFromVectorOfMat($vectorOfMatImages)
    Else
        $iArrImages = _cveInputArrayFromMat($matImages)
    EndIf

    Local $oArrPano, $vectorOfMatPano, $iArrPanoSize
    Local $bPanoIsArray = VarGetType($matPano) == "Array"

    If $bPanoIsArray Then
        $vectorOfMatPano = _VectorOfMatCreate()

        $iArrPanoSize = UBound($matPano)
        For $i = 0 To $iArrPanoSize - 1
            _VectorOfMatPush($vectorOfMatPano, $matPano[$i])
        Next

        $oArrPano = _cveOutputArrayFromVectorOfMat($vectorOfMatPano)
    Else
        $oArrPano = _cveOutputArrayFromMat($matPano)
    EndIf

    Local $retval = _cveStitcherStitch($stitcher, $iArrImages, $oArrPano)

    If $bPanoIsArray Then
        _VectorOfMatRelease($vectorOfMatPano)
    EndIf

    _cveOutputArrayRelease($oArrPano)

    If $bImagesIsArray Then
        _VectorOfMatRelease($vectorOfMatImages)
    EndIf

    _cveInputArrayRelease($iArrImages)

    Return $retval
EndFunc   ;==>_cveStitcherStitchMat

Func _cveStitcherEstimateTransform($stitcher, $images, $masks)
    ; CVAPI(int) cveStitcherEstimateTransform(cv::Stitcher* stitcher, cv::_InputArray* images, cv::_InputArray* masks);

    Local $sStitcherDllType
    If IsDllStruct($stitcher) Then
        $sStitcherDllType = "struct*"
    Else
        $sStitcherDllType = "ptr"
    EndIf

    Local $sImagesDllType
    If IsDllStruct($images) Then
        $sImagesDllType = "struct*"
    Else
        $sImagesDllType = "ptr"
    EndIf

    Local $sMasksDllType
    If IsDllStruct($masks) Then
        $sMasksDllType = "struct*"
    Else
        $sMasksDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveStitcherEstimateTransform", $sStitcherDllType, $stitcher, $sImagesDllType, $images, $sMasksDllType, $masks), "cveStitcherEstimateTransform", @error)
EndFunc   ;==>_cveStitcherEstimateTransform

Func _cveStitcherEstimateTransformMat($stitcher, $matImages, $matMasks)
    ; cveStitcherEstimateTransform using cv::Mat instead of _*Array

    Local $iArrImages, $vectorOfMatImages, $iArrImagesSize
    Local $bImagesIsArray = VarGetType($matImages) == "Array"

    If $bImagesIsArray Then
        $vectorOfMatImages = _VectorOfMatCreate()

        $iArrImagesSize = UBound($matImages)
        For $i = 0 To $iArrImagesSize - 1
            _VectorOfMatPush($vectorOfMatImages, $matImages[$i])
        Next

        $iArrImages = _cveInputArrayFromVectorOfMat($vectorOfMatImages)
    Else
        $iArrImages = _cveInputArrayFromMat($matImages)
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

    Local $retval = _cveStitcherEstimateTransform($stitcher, $iArrImages, $iArrMasks)

    If $bMasksIsArray Then
        _VectorOfMatRelease($vectorOfMatMasks)
    EndIf

    _cveInputArrayRelease($iArrMasks)

    If $bImagesIsArray Then
        _VectorOfMatRelease($vectorOfMatImages)
    EndIf

    _cveInputArrayRelease($iArrImages)

    Return $retval
EndFunc   ;==>_cveStitcherEstimateTransformMat

Func _cveStitcherComposePanorama1($stitcher, $pano)
    ; CVAPI(int) cveStitcherComposePanorama1(cv::Stitcher* stitcher, cv::_OutputArray* pano);

    Local $sStitcherDllType
    If IsDllStruct($stitcher) Then
        $sStitcherDllType = "struct*"
    Else
        $sStitcherDllType = "ptr"
    EndIf

    Local $sPanoDllType
    If IsDllStruct($pano) Then
        $sPanoDllType = "struct*"
    Else
        $sPanoDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveStitcherComposePanorama1", $sStitcherDllType, $stitcher, $sPanoDllType, $pano), "cveStitcherComposePanorama1", @error)
EndFunc   ;==>_cveStitcherComposePanorama1

Func _cveStitcherComposePanorama1Mat($stitcher, $matPano)
    ; cveStitcherComposePanorama1 using cv::Mat instead of _*Array

    Local $oArrPano, $vectorOfMatPano, $iArrPanoSize
    Local $bPanoIsArray = VarGetType($matPano) == "Array"

    If $bPanoIsArray Then
        $vectorOfMatPano = _VectorOfMatCreate()

        $iArrPanoSize = UBound($matPano)
        For $i = 0 To $iArrPanoSize - 1
            _VectorOfMatPush($vectorOfMatPano, $matPano[$i])
        Next

        $oArrPano = _cveOutputArrayFromVectorOfMat($vectorOfMatPano)
    Else
        $oArrPano = _cveOutputArrayFromMat($matPano)
    EndIf

    Local $retval = _cveStitcherComposePanorama1($stitcher, $oArrPano)

    If $bPanoIsArray Then
        _VectorOfMatRelease($vectorOfMatPano)
    EndIf

    _cveOutputArrayRelease($oArrPano)

    Return $retval
EndFunc   ;==>_cveStitcherComposePanorama1Mat

Func _cveStitcherComposePanorama2($stitcher, $images, $pano)
    ; CVAPI(int) cveStitcherComposePanorama2(cv::Stitcher* stitcher, cv::_InputArray* images, cv::_OutputArray* pano);

    Local $sStitcherDllType
    If IsDllStruct($stitcher) Then
        $sStitcherDllType = "struct*"
    Else
        $sStitcherDllType = "ptr"
    EndIf

    Local $sImagesDllType
    If IsDllStruct($images) Then
        $sImagesDllType = "struct*"
    Else
        $sImagesDllType = "ptr"
    EndIf

    Local $sPanoDllType
    If IsDllStruct($pano) Then
        $sPanoDllType = "struct*"
    Else
        $sPanoDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveStitcherComposePanorama2", $sStitcherDllType, $stitcher, $sImagesDllType, $images, $sPanoDllType, $pano), "cveStitcherComposePanorama2", @error)
EndFunc   ;==>_cveStitcherComposePanorama2

Func _cveStitcherComposePanorama2Mat($stitcher, $matImages, $matPano)
    ; cveStitcherComposePanorama2 using cv::Mat instead of _*Array

    Local $iArrImages, $vectorOfMatImages, $iArrImagesSize
    Local $bImagesIsArray = VarGetType($matImages) == "Array"

    If $bImagesIsArray Then
        $vectorOfMatImages = _VectorOfMatCreate()

        $iArrImagesSize = UBound($matImages)
        For $i = 0 To $iArrImagesSize - 1
            _VectorOfMatPush($vectorOfMatImages, $matImages[$i])
        Next

        $iArrImages = _cveInputArrayFromVectorOfMat($vectorOfMatImages)
    Else
        $iArrImages = _cveInputArrayFromMat($matImages)
    EndIf

    Local $oArrPano, $vectorOfMatPano, $iArrPanoSize
    Local $bPanoIsArray = VarGetType($matPano) == "Array"

    If $bPanoIsArray Then
        $vectorOfMatPano = _VectorOfMatCreate()

        $iArrPanoSize = UBound($matPano)
        For $i = 0 To $iArrPanoSize - 1
            _VectorOfMatPush($vectorOfMatPano, $matPano[$i])
        Next

        $oArrPano = _cveOutputArrayFromVectorOfMat($vectorOfMatPano)
    Else
        $oArrPano = _cveOutputArrayFromMat($matPano)
    EndIf

    Local $retval = _cveStitcherComposePanorama2($stitcher, $iArrImages, $oArrPano)

    If $bPanoIsArray Then
        _VectorOfMatRelease($vectorOfMatPano)
    EndIf

    _cveOutputArrayRelease($oArrPano)

    If $bImagesIsArray Then
        _VectorOfMatRelease($vectorOfMatImages)
    EndIf

    _cveInputArrayRelease($iArrImages)

    Return $retval
EndFunc   ;==>_cveStitcherComposePanorama2Mat

Func _cveRotationWarperBuildMaps($warper, $srcSize, $K, $R, $xmap, $ymap, $boundingBox)
    ; CVAPI(void) cveRotationWarperBuildMaps(cv::detail::RotationWarper* warper, CvSize* srcSize, cv::_InputArray* K, cv::_InputArray* R, cv::_OutputArray* xmap, cv::_OutputArray* ymap, CvRect* boundingBox);

    Local $sWarperDllType
    If IsDllStruct($warper) Then
        $sWarperDllType = "struct*"
    Else
        $sWarperDllType = "ptr"
    EndIf

    Local $sSrcSizeDllType
    If IsDllStruct($srcSize) Then
        $sSrcSizeDllType = "struct*"
    Else
        $sSrcSizeDllType = "ptr"
    EndIf

    Local $sKDllType
    If IsDllStruct($K) Then
        $sKDllType = "struct*"
    Else
        $sKDllType = "ptr"
    EndIf

    Local $sRDllType
    If IsDllStruct($R) Then
        $sRDllType = "struct*"
    Else
        $sRDllType = "ptr"
    EndIf

    Local $sXmapDllType
    If IsDllStruct($xmap) Then
        $sXmapDllType = "struct*"
    Else
        $sXmapDllType = "ptr"
    EndIf

    Local $sYmapDllType
    If IsDllStruct($ymap) Then
        $sYmapDllType = "struct*"
    Else
        $sYmapDllType = "ptr"
    EndIf

    Local $sBoundingBoxDllType
    If IsDllStruct($boundingBox) Then
        $sBoundingBoxDllType = "struct*"
    Else
        $sBoundingBoxDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveRotationWarperBuildMaps", $sWarperDllType, $warper, $sSrcSizeDllType, $srcSize, $sKDllType, $K, $sRDllType, $R, $sXmapDllType, $xmap, $sYmapDllType, $ymap, $sBoundingBoxDllType, $boundingBox), "cveRotationWarperBuildMaps", @error)
EndFunc   ;==>_cveRotationWarperBuildMaps

Func _cveRotationWarperBuildMapsMat($warper, $srcSize, $matK, $matR, $matXmap, $matYmap, $boundingBox)
    ; cveRotationWarperBuildMaps using cv::Mat instead of _*Array

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

    Local $oArrXmap, $vectorOfMatXmap, $iArrXmapSize
    Local $bXmapIsArray = VarGetType($matXmap) == "Array"

    If $bXmapIsArray Then
        $vectorOfMatXmap = _VectorOfMatCreate()

        $iArrXmapSize = UBound($matXmap)
        For $i = 0 To $iArrXmapSize - 1
            _VectorOfMatPush($vectorOfMatXmap, $matXmap[$i])
        Next

        $oArrXmap = _cveOutputArrayFromVectorOfMat($vectorOfMatXmap)
    Else
        $oArrXmap = _cveOutputArrayFromMat($matXmap)
    EndIf

    Local $oArrYmap, $vectorOfMatYmap, $iArrYmapSize
    Local $bYmapIsArray = VarGetType($matYmap) == "Array"

    If $bYmapIsArray Then
        $vectorOfMatYmap = _VectorOfMatCreate()

        $iArrYmapSize = UBound($matYmap)
        For $i = 0 To $iArrYmapSize - 1
            _VectorOfMatPush($vectorOfMatYmap, $matYmap[$i])
        Next

        $oArrYmap = _cveOutputArrayFromVectorOfMat($vectorOfMatYmap)
    Else
        $oArrYmap = _cveOutputArrayFromMat($matYmap)
    EndIf

    _cveRotationWarperBuildMaps($warper, $srcSize, $iArrK, $iArrR, $oArrXmap, $oArrYmap, $boundingBox)

    If $bYmapIsArray Then
        _VectorOfMatRelease($vectorOfMatYmap)
    EndIf

    _cveOutputArrayRelease($oArrYmap)

    If $bXmapIsArray Then
        _VectorOfMatRelease($vectorOfMatXmap)
    EndIf

    _cveOutputArrayRelease($oArrXmap)

    If $bRIsArray Then
        _VectorOfMatRelease($vectorOfMatR)
    EndIf

    _cveInputArrayRelease($iArrR)

    If $bKIsArray Then
        _VectorOfMatRelease($vectorOfMatK)
    EndIf

    _cveInputArrayRelease($iArrK)
EndFunc   ;==>_cveRotationWarperBuildMapsMat

Func _cveRotationWarperWarp($warper, $src, $K, $R, $interpMode, $borderMode, $dst, $corner)
    ; CVAPI(void) cveRotationWarperWarp(cv::detail::RotationWarper* warper, cv::_InputArray* src, cv::_InputArray* K, cv::_InputArray* R, int interpMode, int borderMode, cv::_OutputArray* dst, CvPoint* corner);

    Local $sWarperDllType
    If IsDllStruct($warper) Then
        $sWarperDllType = "struct*"
    Else
        $sWarperDllType = "ptr"
    EndIf

    Local $sSrcDllType
    If IsDllStruct($src) Then
        $sSrcDllType = "struct*"
    Else
        $sSrcDllType = "ptr"
    EndIf

    Local $sKDllType
    If IsDllStruct($K) Then
        $sKDllType = "struct*"
    Else
        $sKDllType = "ptr"
    EndIf

    Local $sRDllType
    If IsDllStruct($R) Then
        $sRDllType = "struct*"
    Else
        $sRDllType = "ptr"
    EndIf

    Local $sDstDllType
    If IsDllStruct($dst) Then
        $sDstDllType = "struct*"
    Else
        $sDstDllType = "ptr"
    EndIf

    Local $sCornerDllType
    If IsDllStruct($corner) Then
        $sCornerDllType = "struct*"
    Else
        $sCornerDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveRotationWarperWarp", $sWarperDllType, $warper, $sSrcDllType, $src, $sKDllType, $K, $sRDllType, $R, "int", $interpMode, "int", $borderMode, $sDstDllType, $dst, $sCornerDllType, $corner), "cveRotationWarperWarp", @error)
EndFunc   ;==>_cveRotationWarperWarp

Func _cveRotationWarperWarpMat($warper, $matSrc, $matK, $matR, $interpMode, $borderMode, $matDst, $corner)
    ; cveRotationWarperWarp using cv::Mat instead of _*Array

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

    _cveRotationWarperWarp($warper, $iArrSrc, $iArrK, $iArrR, $interpMode, $borderMode, $oArrDst, $corner)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveOutputArrayRelease($oArrDst)

    If $bRIsArray Then
        _VectorOfMatRelease($vectorOfMatR)
    EndIf

    _cveInputArrayRelease($iArrR)

    If $bKIsArray Then
        _VectorOfMatRelease($vectorOfMatK)
    EndIf

    _cveInputArrayRelease($iArrK)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)
EndFunc   ;==>_cveRotationWarperWarpMat

Func _cveDetailPlaneWarperCreate($scale, $rotationWarper)
    ; CVAPI(cv::detail::PlaneWarper*) cveDetailPlaneWarperCreate(float scale, cv::detail::RotationWarper** rotationWarper);

    Local $sRotationWarperDllType
    If IsDllStruct($rotationWarper) Then
        $sRotationWarperDllType = "struct*"
    ElseIf $rotationWarper == Null Then
        $sRotationWarperDllType = "ptr"
    Else
        $sRotationWarperDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveDetailPlaneWarperCreate", "float", $scale, $sRotationWarperDllType, $rotationWarper), "cveDetailPlaneWarperCreate", @error)
EndFunc   ;==>_cveDetailPlaneWarperCreate

Func _cveDetailPlaneWarperRelease($warper)
    ; CVAPI(void) cveDetailPlaneWarperRelease(cv::detail::PlaneWarper** warper);

    Local $sWarperDllType
    If IsDllStruct($warper) Then
        $sWarperDllType = "struct*"
    ElseIf $warper == Null Then
        $sWarperDllType = "ptr"
    Else
        $sWarperDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDetailPlaneWarperRelease", $sWarperDllType, $warper), "cveDetailPlaneWarperRelease", @error)
EndFunc   ;==>_cveDetailPlaneWarperRelease

Func _cvePlaneWarperCreate($warperCreator)
    ; CVAPI(cv::PlaneWarper*) cvePlaneWarperCreate(cv::WarperCreator** warperCreator);

    Local $sWarperCreatorDllType
    If IsDllStruct($warperCreator) Then
        $sWarperCreatorDllType = "struct*"
    ElseIf $warperCreator == Null Then
        $sWarperCreatorDllType = "ptr"
    Else
        $sWarperCreatorDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cvePlaneWarperCreate", $sWarperCreatorDllType, $warperCreator), "cvePlaneWarperCreate", @error)
EndFunc   ;==>_cvePlaneWarperCreate

Func _cvePlaneWarperRelease($warper)
    ; CVAPI(void) cvePlaneWarperRelease(cv::PlaneWarper** warper);

    Local $sWarperDllType
    If IsDllStruct($warper) Then
        $sWarperDllType = "struct*"
    ElseIf $warper == Null Then
        $sWarperDllType = "ptr"
    Else
        $sWarperDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cvePlaneWarperRelease", $sWarperDllType, $warper), "cvePlaneWarperRelease", @error)
EndFunc   ;==>_cvePlaneWarperRelease

Func _cveDetailCylindricalWarperCreate($scale, $rotationWarper)
    ; CVAPI(cv::detail::CylindricalWarper*) cveDetailCylindricalWarperCreate(float scale, cv::detail::RotationWarper** rotationWarper);

    Local $sRotationWarperDllType
    If IsDllStruct($rotationWarper) Then
        $sRotationWarperDllType = "struct*"
    ElseIf $rotationWarper == Null Then
        $sRotationWarperDllType = "ptr"
    Else
        $sRotationWarperDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveDetailCylindricalWarperCreate", "float", $scale, $sRotationWarperDllType, $rotationWarper), "cveDetailCylindricalWarperCreate", @error)
EndFunc   ;==>_cveDetailCylindricalWarperCreate

Func _cveDetailCylindricalWarperRelease($warper)
    ; CVAPI(void) cveDetailCylindricalWarperRelease(cv::detail::CylindricalWarper** warper);

    Local $sWarperDllType
    If IsDllStruct($warper) Then
        $sWarperDllType = "struct*"
    ElseIf $warper == Null Then
        $sWarperDllType = "ptr"
    Else
        $sWarperDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDetailCylindricalWarperRelease", $sWarperDllType, $warper), "cveDetailCylindricalWarperRelease", @error)
EndFunc   ;==>_cveDetailCylindricalWarperRelease

Func _cveCylindricalWarperCreate($warperCreator)
    ; CVAPI(cv::CylindricalWarper*) cveCylindricalWarperCreate(cv::WarperCreator** warperCreator);

    Local $sWarperCreatorDllType
    If IsDllStruct($warperCreator) Then
        $sWarperCreatorDllType = "struct*"
    ElseIf $warperCreator == Null Then
        $sWarperCreatorDllType = "ptr"
    Else
        $sWarperCreatorDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveCylindricalWarperCreate", $sWarperCreatorDllType, $warperCreator), "cveCylindricalWarperCreate", @error)
EndFunc   ;==>_cveCylindricalWarperCreate

Func _cveCylindricalWarperRelease($warper)
    ; CVAPI(void) cveCylindricalWarperRelease(cv::CylindricalWarper** warper);

    Local $sWarperDllType
    If IsDllStruct($warper) Then
        $sWarperDllType = "struct*"
    ElseIf $warper == Null Then
        $sWarperDllType = "ptr"
    Else
        $sWarperDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCylindricalWarperRelease", $sWarperDllType, $warper), "cveCylindricalWarperRelease", @error)
EndFunc   ;==>_cveCylindricalWarperRelease

Func _cveDetailSphericalWarperCreate($scale, $rotationWarper)
    ; CVAPI(cv::detail::SphericalWarper*) cveDetailSphericalWarperCreate(float scale, cv::detail::RotationWarper** rotationWarper);

    Local $sRotationWarperDllType
    If IsDllStruct($rotationWarper) Then
        $sRotationWarperDllType = "struct*"
    ElseIf $rotationWarper == Null Then
        $sRotationWarperDllType = "ptr"
    Else
        $sRotationWarperDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveDetailSphericalWarperCreate", "float", $scale, $sRotationWarperDllType, $rotationWarper), "cveDetailSphericalWarperCreate", @error)
EndFunc   ;==>_cveDetailSphericalWarperCreate

Func _cveDetailSphericalWarperRelease($warper)
    ; CVAPI(void) cveDetailSphericalWarperRelease(cv::detail::SphericalWarper** warper);

    Local $sWarperDllType
    If IsDllStruct($warper) Then
        $sWarperDllType = "struct*"
    ElseIf $warper == Null Then
        $sWarperDllType = "ptr"
    Else
        $sWarperDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDetailSphericalWarperRelease", $sWarperDllType, $warper), "cveDetailSphericalWarperRelease", @error)
EndFunc   ;==>_cveDetailSphericalWarperRelease

Func _cveSphericalWarperCreate($warperCreator)
    ; CVAPI(cv::SphericalWarper*) cveSphericalWarperCreate(cv::WarperCreator** warperCreator);

    Local $sWarperCreatorDllType
    If IsDllStruct($warperCreator) Then
        $sWarperCreatorDllType = "struct*"
    ElseIf $warperCreator == Null Then
        $sWarperCreatorDllType = "ptr"
    Else
        $sWarperCreatorDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveSphericalWarperCreate", $sWarperCreatorDllType, $warperCreator), "cveSphericalWarperCreate", @error)
EndFunc   ;==>_cveSphericalWarperCreate

Func _cveSphericalWarperRelease($warperCreator)
    ; CVAPI(void) cveSphericalWarperRelease(cv::SphericalWarper** warperCreator);

    Local $sWarperCreatorDllType
    If IsDllStruct($warperCreator) Then
        $sWarperCreatorDllType = "struct*"
    ElseIf $warperCreator == Null Then
        $sWarperCreatorDllType = "ptr"
    Else
        $sWarperCreatorDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSphericalWarperRelease", $sWarperCreatorDllType, $warperCreator), "cveSphericalWarperRelease", @error)
EndFunc   ;==>_cveSphericalWarperRelease

Func _cveDetailFisheyeWarperCreate($scale, $rotationWarper)
    ; CVAPI(cv::detail::FisheyeWarper*) cveDetailFisheyeWarperCreate(float scale, cv::detail::RotationWarper** rotationWarper);

    Local $sRotationWarperDllType
    If IsDllStruct($rotationWarper) Then
        $sRotationWarperDllType = "struct*"
    ElseIf $rotationWarper == Null Then
        $sRotationWarperDllType = "ptr"
    Else
        $sRotationWarperDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveDetailFisheyeWarperCreate", "float", $scale, $sRotationWarperDllType, $rotationWarper), "cveDetailFisheyeWarperCreate", @error)
EndFunc   ;==>_cveDetailFisheyeWarperCreate

Func _cveDetailFisheyeWarperRelease($warper)
    ; CVAPI(void) cveDetailFisheyeWarperRelease(cv::detail::FisheyeWarper** warper);

    Local $sWarperDllType
    If IsDllStruct($warper) Then
        $sWarperDllType = "struct*"
    ElseIf $warper == Null Then
        $sWarperDllType = "ptr"
    Else
        $sWarperDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDetailFisheyeWarperRelease", $sWarperDllType, $warper), "cveDetailFisheyeWarperRelease", @error)
EndFunc   ;==>_cveDetailFisheyeWarperRelease

Func _cveFisheyeWarperCreate($warperCreator)
    ; CVAPI(cv::FisheyeWarper*) cveFisheyeWarperCreate(cv::WarperCreator** warperCreator);

    Local $sWarperCreatorDllType
    If IsDllStruct($warperCreator) Then
        $sWarperCreatorDllType = "struct*"
    ElseIf $warperCreator == Null Then
        $sWarperCreatorDllType = "ptr"
    Else
        $sWarperCreatorDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveFisheyeWarperCreate", $sWarperCreatorDllType, $warperCreator), "cveFisheyeWarperCreate", @error)
EndFunc   ;==>_cveFisheyeWarperCreate

Func _cveFisheyeWarperRelease($warperCreator)
    ; CVAPI(void) cveFisheyeWarperRelease(cv::FisheyeWarper** warperCreator);

    Local $sWarperCreatorDllType
    If IsDllStruct($warperCreator) Then
        $sWarperCreatorDllType = "struct*"
    ElseIf $warperCreator == Null Then
        $sWarperCreatorDllType = "ptr"
    Else
        $sWarperCreatorDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFisheyeWarperRelease", $sWarperCreatorDllType, $warperCreator), "cveFisheyeWarperRelease", @error)
EndFunc   ;==>_cveFisheyeWarperRelease

Func _cveDetailStereographicWarperCreate($scale, $rotationWarper)
    ; CVAPI(cv::detail::StereographicWarper*) cveDetailStereographicWarperCreate(float scale, cv::detail::RotationWarper** rotationWarper);

    Local $sRotationWarperDllType
    If IsDllStruct($rotationWarper) Then
        $sRotationWarperDllType = "struct*"
    ElseIf $rotationWarper == Null Then
        $sRotationWarperDllType = "ptr"
    Else
        $sRotationWarperDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveDetailStereographicWarperCreate", "float", $scale, $sRotationWarperDllType, $rotationWarper), "cveDetailStereographicWarperCreate", @error)
EndFunc   ;==>_cveDetailStereographicWarperCreate

Func _cveDetailStereographicWarperRelease($warper)
    ; CVAPI(void) cveDetailStereographicWarperRelease(cv::detail::StereographicWarper** warper);

    Local $sWarperDllType
    If IsDllStruct($warper) Then
        $sWarperDllType = "struct*"
    ElseIf $warper == Null Then
        $sWarperDllType = "ptr"
    Else
        $sWarperDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDetailStereographicWarperRelease", $sWarperDllType, $warper), "cveDetailStereographicWarperRelease", @error)
EndFunc   ;==>_cveDetailStereographicWarperRelease

Func _cveStereographicWarperCreate($warperCreator)
    ; CVAPI(cv::StereographicWarper*) cveStereographicWarperCreate(cv::WarperCreator** warperCreator);

    Local $sWarperCreatorDllType
    If IsDllStruct($warperCreator) Then
        $sWarperCreatorDllType = "struct*"
    ElseIf $warperCreator == Null Then
        $sWarperCreatorDllType = "ptr"
    Else
        $sWarperCreatorDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveStereographicWarperCreate", $sWarperCreatorDllType, $warperCreator), "cveStereographicWarperCreate", @error)
EndFunc   ;==>_cveStereographicWarperCreate

Func _cveStereographicWarperRelease($warperCreator)
    ; CVAPI(void) cveStereographicWarperRelease(cv::StereographicWarper** warperCreator);

    Local $sWarperCreatorDllType
    If IsDllStruct($warperCreator) Then
        $sWarperCreatorDllType = "struct*"
    ElseIf $warperCreator == Null Then
        $sWarperCreatorDllType = "ptr"
    Else
        $sWarperCreatorDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveStereographicWarperRelease", $sWarperCreatorDllType, $warperCreator), "cveStereographicWarperRelease", @error)
EndFunc   ;==>_cveStereographicWarperRelease

Func _cveDetailCompressedRectilinearWarperCreate($scale, $rotationWarper)
    ; CVAPI(cv::detail::CompressedRectilinearWarper*) cveDetailCompressedRectilinearWarperCreate(float scale, cv::detail::RotationWarper** rotationWarper);

    Local $sRotationWarperDllType
    If IsDllStruct($rotationWarper) Then
        $sRotationWarperDllType = "struct*"
    ElseIf $rotationWarper == Null Then
        $sRotationWarperDllType = "ptr"
    Else
        $sRotationWarperDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveDetailCompressedRectilinearWarperCreate", "float", $scale, $sRotationWarperDllType, $rotationWarper), "cveDetailCompressedRectilinearWarperCreate", @error)
EndFunc   ;==>_cveDetailCompressedRectilinearWarperCreate

Func _cveDetailCompressedRectilinearWarperRelease($warper)
    ; CVAPI(void) cveDetailCompressedRectilinearWarperRelease(cv::detail::CompressedRectilinearWarper** warper);

    Local $sWarperDllType
    If IsDllStruct($warper) Then
        $sWarperDllType = "struct*"
    ElseIf $warper == Null Then
        $sWarperDllType = "ptr"
    Else
        $sWarperDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDetailCompressedRectilinearWarperRelease", $sWarperDllType, $warper), "cveDetailCompressedRectilinearWarperRelease", @error)
EndFunc   ;==>_cveDetailCompressedRectilinearWarperRelease

Func _cveCompressedRectilinearWarperCreate($warperCreator)
    ; CVAPI(cv::CompressedRectilinearWarper*) cveCompressedRectilinearWarperCreate(cv::WarperCreator** warperCreator);

    Local $sWarperCreatorDllType
    If IsDllStruct($warperCreator) Then
        $sWarperCreatorDllType = "struct*"
    ElseIf $warperCreator == Null Then
        $sWarperCreatorDllType = "ptr"
    Else
        $sWarperCreatorDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveCompressedRectilinearWarperCreate", $sWarperCreatorDllType, $warperCreator), "cveCompressedRectilinearWarperCreate", @error)
EndFunc   ;==>_cveCompressedRectilinearWarperCreate

Func _cveCompressedRectilinearWarperRelease($warperCreator)
    ; CVAPI(void) cveCompressedRectilinearWarperRelease(cv::CompressedRectilinearWarper** warperCreator);

    Local $sWarperCreatorDllType
    If IsDllStruct($warperCreator) Then
        $sWarperCreatorDllType = "struct*"
    ElseIf $warperCreator == Null Then
        $sWarperCreatorDllType = "ptr"
    Else
        $sWarperCreatorDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCompressedRectilinearWarperRelease", $sWarperCreatorDllType, $warperCreator), "cveCompressedRectilinearWarperRelease", @error)
EndFunc   ;==>_cveCompressedRectilinearWarperRelease

Func _cveDetailPaniniWarperCreate($scale, $rotationWarper)
    ; CVAPI(cv::detail::PaniniWarper*) cveDetailPaniniWarperCreate(float scale, cv::detail::RotationWarper** rotationWarper);

    Local $sRotationWarperDllType
    If IsDllStruct($rotationWarper) Then
        $sRotationWarperDllType = "struct*"
    ElseIf $rotationWarper == Null Then
        $sRotationWarperDllType = "ptr"
    Else
        $sRotationWarperDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveDetailPaniniWarperCreate", "float", $scale, $sRotationWarperDllType, $rotationWarper), "cveDetailPaniniWarperCreate", @error)
EndFunc   ;==>_cveDetailPaniniWarperCreate

Func _cveDetailPaniniWarperRelease($warper)
    ; CVAPI(void) cveDetailPaniniWarperRelease(cv::detail::PaniniWarper** warper);

    Local $sWarperDllType
    If IsDllStruct($warper) Then
        $sWarperDllType = "struct*"
    ElseIf $warper == Null Then
        $sWarperDllType = "ptr"
    Else
        $sWarperDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDetailPaniniWarperRelease", $sWarperDllType, $warper), "cveDetailPaniniWarperRelease", @error)
EndFunc   ;==>_cveDetailPaniniWarperRelease

Func _cvePaniniWarperCreate($warperCreator)
    ; CVAPI(cv::PaniniWarper*) cvePaniniWarperCreate(cv::WarperCreator** warperCreator);

    Local $sWarperCreatorDllType
    If IsDllStruct($warperCreator) Then
        $sWarperCreatorDllType = "struct*"
    ElseIf $warperCreator == Null Then
        $sWarperCreatorDllType = "ptr"
    Else
        $sWarperCreatorDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cvePaniniWarperCreate", $sWarperCreatorDllType, $warperCreator), "cvePaniniWarperCreate", @error)
EndFunc   ;==>_cvePaniniWarperCreate

Func _cvePaniniWarperRelease($warperCreator)
    ; CVAPI(void) cvePaniniWarperRelease(cv::PaniniWarper** warperCreator);

    Local $sWarperCreatorDllType
    If IsDllStruct($warperCreator) Then
        $sWarperCreatorDllType = "struct*"
    ElseIf $warperCreator == Null Then
        $sWarperCreatorDllType = "ptr"
    Else
        $sWarperCreatorDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cvePaniniWarperRelease", $sWarperCreatorDllType, $warperCreator), "cvePaniniWarperRelease", @error)
EndFunc   ;==>_cvePaniniWarperRelease

Func _cveDetailPaniniPortraitWarperCreate($scale, $rotationWarper)
    ; CVAPI(cv::detail::PaniniPortraitWarper*) cveDetailPaniniPortraitWarperCreate(float scale, cv::detail::RotationWarper** rotationWarper);

    Local $sRotationWarperDllType
    If IsDllStruct($rotationWarper) Then
        $sRotationWarperDllType = "struct*"
    ElseIf $rotationWarper == Null Then
        $sRotationWarperDllType = "ptr"
    Else
        $sRotationWarperDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveDetailPaniniPortraitWarperCreate", "float", $scale, $sRotationWarperDllType, $rotationWarper), "cveDetailPaniniPortraitWarperCreate", @error)
EndFunc   ;==>_cveDetailPaniniPortraitWarperCreate

Func _cveDetailPaniniPortraitWarperRelease($warper)
    ; CVAPI(void) cveDetailPaniniPortraitWarperRelease(cv::detail::PaniniPortraitWarper** warper);

    Local $sWarperDllType
    If IsDllStruct($warper) Then
        $sWarperDllType = "struct*"
    ElseIf $warper == Null Then
        $sWarperDllType = "ptr"
    Else
        $sWarperDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDetailPaniniPortraitWarperRelease", $sWarperDllType, $warper), "cveDetailPaniniPortraitWarperRelease", @error)
EndFunc   ;==>_cveDetailPaniniPortraitWarperRelease

Func _cvePaniniPortraitWarperCreate($warperCreator)
    ; CVAPI(cv::PaniniPortraitWarper*) cvePaniniPortraitWarperCreate(cv::WarperCreator** warperCreator);

    Local $sWarperCreatorDllType
    If IsDllStruct($warperCreator) Then
        $sWarperCreatorDllType = "struct*"
    ElseIf $warperCreator == Null Then
        $sWarperCreatorDllType = "ptr"
    Else
        $sWarperCreatorDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cvePaniniPortraitWarperCreate", $sWarperCreatorDllType, $warperCreator), "cvePaniniPortraitWarperCreate", @error)
EndFunc   ;==>_cvePaniniPortraitWarperCreate

Func _cvePaniniPortraitWarperRelease($warperCreator)
    ; CVAPI(void) cvePaniniPortraitWarperRelease(cv::PaniniPortraitWarper** warperCreator);

    Local $sWarperCreatorDllType
    If IsDllStruct($warperCreator) Then
        $sWarperCreatorDllType = "struct*"
    ElseIf $warperCreator == Null Then
        $sWarperCreatorDllType = "ptr"
    Else
        $sWarperCreatorDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cvePaniniPortraitWarperRelease", $sWarperCreatorDllType, $warperCreator), "cvePaniniPortraitWarperRelease", @error)
EndFunc   ;==>_cvePaniniPortraitWarperRelease

Func _cveDetailMercatorWarperCreate($scale, $rotationWarper)
    ; CVAPI(cv::detail::MercatorWarper*) cveDetailMercatorWarperCreate(float scale, cv::detail::RotationWarper** rotationWarper);

    Local $sRotationWarperDllType
    If IsDllStruct($rotationWarper) Then
        $sRotationWarperDllType = "struct*"
    ElseIf $rotationWarper == Null Then
        $sRotationWarperDllType = "ptr"
    Else
        $sRotationWarperDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveDetailMercatorWarperCreate", "float", $scale, $sRotationWarperDllType, $rotationWarper), "cveDetailMercatorWarperCreate", @error)
EndFunc   ;==>_cveDetailMercatorWarperCreate

Func _cveDetailMercatorWarperRelease($warper)
    ; CVAPI(void) cveDetailMercatorWarperRelease(cv::detail::MercatorWarper** warper);

    Local $sWarperDllType
    If IsDllStruct($warper) Then
        $sWarperDllType = "struct*"
    ElseIf $warper == Null Then
        $sWarperDllType = "ptr"
    Else
        $sWarperDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDetailMercatorWarperRelease", $sWarperDllType, $warper), "cveDetailMercatorWarperRelease", @error)
EndFunc   ;==>_cveDetailMercatorWarperRelease

Func _cveMercatorWarperCreate($warperCreator)
    ; CVAPI(cv::MercatorWarper*) cveMercatorWarperCreate(cv::WarperCreator** warperCreator);

    Local $sWarperCreatorDllType
    If IsDllStruct($warperCreator) Then
        $sWarperCreatorDllType = "struct*"
    ElseIf $warperCreator == Null Then
        $sWarperCreatorDllType = "ptr"
    Else
        $sWarperCreatorDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveMercatorWarperCreate", $sWarperCreatorDllType, $warperCreator), "cveMercatorWarperCreate", @error)
EndFunc   ;==>_cveMercatorWarperCreate

Func _cveMercatorWarperRelease($warperCreator)
    ; CVAPI(void) cveMercatorWarperRelease(cv::MercatorWarper** warperCreator);

    Local $sWarperCreatorDllType
    If IsDllStruct($warperCreator) Then
        $sWarperCreatorDllType = "struct*"
    ElseIf $warperCreator == Null Then
        $sWarperCreatorDllType = "ptr"
    Else
        $sWarperCreatorDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMercatorWarperRelease", $sWarperCreatorDllType, $warperCreator), "cveMercatorWarperRelease", @error)
EndFunc   ;==>_cveMercatorWarperRelease

Func _cveDetailTransverseMercatorWarperCreate($scale, $rotationWarper)
    ; CVAPI(cv::detail::TransverseMercatorWarper*) cveDetailTransverseMercatorWarperCreate(float scale, cv::detail::RotationWarper** rotationWarper);

    Local $sRotationWarperDllType
    If IsDllStruct($rotationWarper) Then
        $sRotationWarperDllType = "struct*"
    ElseIf $rotationWarper == Null Then
        $sRotationWarperDllType = "ptr"
    Else
        $sRotationWarperDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveDetailTransverseMercatorWarperCreate", "float", $scale, $sRotationWarperDllType, $rotationWarper), "cveDetailTransverseMercatorWarperCreate", @error)
EndFunc   ;==>_cveDetailTransverseMercatorWarperCreate

Func _cveDetailTransverseMercatorWarperRelease($warper)
    ; CVAPI(void) cveDetailTransverseMercatorWarperRelease(cv::detail::TransverseMercatorWarper** warper);

    Local $sWarperDllType
    If IsDllStruct($warper) Then
        $sWarperDllType = "struct*"
    ElseIf $warper == Null Then
        $sWarperDllType = "ptr"
    Else
        $sWarperDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDetailTransverseMercatorWarperRelease", $sWarperDllType, $warper), "cveDetailTransverseMercatorWarperRelease", @error)
EndFunc   ;==>_cveDetailTransverseMercatorWarperRelease

Func _cveTransverseMercatorWarperCreate($warperCreator)
    ; CVAPI(cv::TransverseMercatorWarper*) cveTransverseMercatorWarperCreate(cv::WarperCreator** warperCreator);

    Local $sWarperCreatorDllType
    If IsDllStruct($warperCreator) Then
        $sWarperCreatorDllType = "struct*"
    ElseIf $warperCreator == Null Then
        $sWarperCreatorDllType = "ptr"
    Else
        $sWarperCreatorDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveTransverseMercatorWarperCreate", $sWarperCreatorDllType, $warperCreator), "cveTransverseMercatorWarperCreate", @error)
EndFunc   ;==>_cveTransverseMercatorWarperCreate

Func _cveTransverseMercatorWarperRelease($warperCreator)
    ; CVAPI(void) cveTransverseMercatorWarperRelease(cv::TransverseMercatorWarper** warperCreator);

    Local $sWarperCreatorDllType
    If IsDllStruct($warperCreator) Then
        $sWarperCreatorDllType = "struct*"
    ElseIf $warperCreator == Null Then
        $sWarperCreatorDllType = "ptr"
    Else
        $sWarperCreatorDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveTransverseMercatorWarperRelease", $sWarperCreatorDllType, $warperCreator), "cveTransverseMercatorWarperRelease", @error)
EndFunc   ;==>_cveTransverseMercatorWarperRelease

Func _cveFeatherBlenderCreate($sharpness, $blender)
    ; CVAPI(cv::detail::FeatherBlender*) cveFeatherBlenderCreate(float sharpness, cv::detail::Blender** blender);

    Local $sBlenderDllType
    If IsDllStruct($blender) Then
        $sBlenderDllType = "struct*"
    ElseIf $blender == Null Then
        $sBlenderDllType = "ptr"
    Else
        $sBlenderDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveFeatherBlenderCreate", "float", $sharpness, $sBlenderDllType, $blender), "cveFeatherBlenderCreate", @error)
EndFunc   ;==>_cveFeatherBlenderCreate

Func _cveFeatherBlenderRelease($blender)
    ; CVAPI(void) cveFeatherBlenderRelease(cv::detail::FeatherBlender** blender);

    Local $sBlenderDllType
    If IsDllStruct($blender) Then
        $sBlenderDllType = "struct*"
    ElseIf $blender == Null Then
        $sBlenderDllType = "ptr"
    Else
        $sBlenderDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFeatherBlenderRelease", $sBlenderDllType, $blender), "cveFeatherBlenderRelease", @error)
EndFunc   ;==>_cveFeatherBlenderRelease

Func _cveMultiBandBlenderCreate($tryGpu, $numBands, $weightType, $blender)
    ; CVAPI(cv::detail::MultiBandBlender*) cveMultiBandBlenderCreate(int tryGpu, int numBands, int weightType, cv::detail::Blender** blender);

    Local $sBlenderDllType
    If IsDllStruct($blender) Then
        $sBlenderDllType = "struct*"
    ElseIf $blender == Null Then
        $sBlenderDllType = "ptr"
    Else
        $sBlenderDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveMultiBandBlenderCreate", "int", $tryGpu, "int", $numBands, "int", $weightType, $sBlenderDllType, $blender), "cveMultiBandBlenderCreate", @error)
EndFunc   ;==>_cveMultiBandBlenderCreate

Func _cveMultiBandBlenderRelease($blender)
    ; CVAPI(void) cveMultiBandBlenderRelease(cv::detail::MultiBandBlender** blender);

    Local $sBlenderDllType
    If IsDllStruct($blender) Then
        $sBlenderDllType = "struct*"
    ElseIf $blender == Null Then
        $sBlenderDllType = "ptr"
    Else
        $sBlenderDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMultiBandBlenderRelease", $sBlenderDllType, $blender), "cveMultiBandBlenderRelease", @error)
EndFunc   ;==>_cveMultiBandBlenderRelease

Func _cveNoExposureCompensatorCreate($exposureCompensatorPtr)
    ; CVAPI(cv::detail::NoExposureCompensator*) cveNoExposureCompensatorCreate(cv::detail::ExposureCompensator** exposureCompensatorPtr);

    Local $sExposureCompensatorPtrDllType
    If IsDllStruct($exposureCompensatorPtr) Then
        $sExposureCompensatorPtrDllType = "struct*"
    ElseIf $exposureCompensatorPtr == Null Then
        $sExposureCompensatorPtrDllType = "ptr"
    Else
        $sExposureCompensatorPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveNoExposureCompensatorCreate", $sExposureCompensatorPtrDllType, $exposureCompensatorPtr), "cveNoExposureCompensatorCreate", @error)
EndFunc   ;==>_cveNoExposureCompensatorCreate

Func _cveNoExposureCompensatorRelease($compensator)
    ; CVAPI(void) cveNoExposureCompensatorRelease(cv::detail::NoExposureCompensator** compensator);

    Local $sCompensatorDllType
    If IsDllStruct($compensator) Then
        $sCompensatorDllType = "struct*"
    ElseIf $compensator == Null Then
        $sCompensatorDllType = "ptr"
    Else
        $sCompensatorDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveNoExposureCompensatorRelease", $sCompensatorDllType, $compensator), "cveNoExposureCompensatorRelease", @error)
EndFunc   ;==>_cveNoExposureCompensatorRelease

Func _cveGainCompensatorCreate($nrFeeds, $exposureCompensatorPtr)
    ; CVAPI(cv::detail::GainCompensator*) cveGainCompensatorCreate(int nrFeeds, cv::detail::ExposureCompensator** exposureCompensatorPtr);

    Local $sExposureCompensatorPtrDllType
    If IsDllStruct($exposureCompensatorPtr) Then
        $sExposureCompensatorPtrDllType = "struct*"
    ElseIf $exposureCompensatorPtr == Null Then
        $sExposureCompensatorPtrDllType = "ptr"
    Else
        $sExposureCompensatorPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGainCompensatorCreate", "int", $nrFeeds, $sExposureCompensatorPtrDllType, $exposureCompensatorPtr), "cveGainCompensatorCreate", @error)
EndFunc   ;==>_cveGainCompensatorCreate

Func _cveGainCompensatorRelease($compensator)
    ; CVAPI(void) cveGainCompensatorRelease(cv::detail::GainCompensator** compensator);

    Local $sCompensatorDllType
    If IsDllStruct($compensator) Then
        $sCompensatorDllType = "struct*"
    ElseIf $compensator == Null Then
        $sCompensatorDllType = "ptr"
    Else
        $sCompensatorDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveGainCompensatorRelease", $sCompensatorDllType, $compensator), "cveGainCompensatorRelease", @error)
EndFunc   ;==>_cveGainCompensatorRelease

Func _cveChannelsCompensatorCreate($nrFeeds, $exposureCompensatorPtr)
    ; CVAPI(cv::detail::ChannelsCompensator*) cveChannelsCompensatorCreate(int nrFeeds, cv::detail::ExposureCompensator** exposureCompensatorPtr);

    Local $sExposureCompensatorPtrDllType
    If IsDllStruct($exposureCompensatorPtr) Then
        $sExposureCompensatorPtrDllType = "struct*"
    ElseIf $exposureCompensatorPtr == Null Then
        $sExposureCompensatorPtrDllType = "ptr"
    Else
        $sExposureCompensatorPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveChannelsCompensatorCreate", "int", $nrFeeds, $sExposureCompensatorPtrDllType, $exposureCompensatorPtr), "cveChannelsCompensatorCreate", @error)
EndFunc   ;==>_cveChannelsCompensatorCreate

Func _cveChannelsCompensatorRelease($compensator)
    ; CVAPI(void) cveChannelsCompensatorRelease(cv::detail::ChannelsCompensator** compensator);

    Local $sCompensatorDllType
    If IsDllStruct($compensator) Then
        $sCompensatorDllType = "struct*"
    ElseIf $compensator == Null Then
        $sCompensatorDllType = "ptr"
    Else
        $sCompensatorDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveChannelsCompensatorRelease", $sCompensatorDllType, $compensator), "cveChannelsCompensatorRelease", @error)
EndFunc   ;==>_cveChannelsCompensatorRelease

Func _cveBlocksGainCompensatorCreate($blWidth, $blHeight, $nrFeeds, $exposureCompensatorPtr)
    ; CVAPI(cv::detail::BlocksGainCompensator*) cveBlocksGainCompensatorCreate(int blWidth, int blHeight, int nrFeeds, cv::detail::ExposureCompensator** exposureCompensatorPtr);

    Local $sExposureCompensatorPtrDllType
    If IsDllStruct($exposureCompensatorPtr) Then
        $sExposureCompensatorPtrDllType = "struct*"
    ElseIf $exposureCompensatorPtr == Null Then
        $sExposureCompensatorPtrDllType = "ptr"
    Else
        $sExposureCompensatorPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveBlocksGainCompensatorCreate", "int", $blWidth, "int", $blHeight, "int", $nrFeeds, $sExposureCompensatorPtrDllType, $exposureCompensatorPtr), "cveBlocksGainCompensatorCreate", @error)
EndFunc   ;==>_cveBlocksGainCompensatorCreate

Func _cveBlocksGainCompensatorRelease($compensator)
    ; CVAPI(void) cveBlocksGainCompensatorRelease(cv::detail::BlocksGainCompensator** compensator);

    Local $sCompensatorDllType
    If IsDllStruct($compensator) Then
        $sCompensatorDllType = "struct*"
    ElseIf $compensator == Null Then
        $sCompensatorDllType = "ptr"
    Else
        $sCompensatorDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBlocksGainCompensatorRelease", $sCompensatorDllType, $compensator), "cveBlocksGainCompensatorRelease", @error)
EndFunc   ;==>_cveBlocksGainCompensatorRelease

Func _cveBlocksChannelsCompensatorCreate($blWidth, $blHeight, $nrFeeds, $exposureCompensatorPtr)
    ; CVAPI(cv::detail::BlocksChannelsCompensator*) cveBlocksChannelsCompensatorCreate(int blWidth, int blHeight, int nrFeeds, cv::detail::ExposureCompensator** exposureCompensatorPtr);

    Local $sExposureCompensatorPtrDllType
    If IsDllStruct($exposureCompensatorPtr) Then
        $sExposureCompensatorPtrDllType = "struct*"
    ElseIf $exposureCompensatorPtr == Null Then
        $sExposureCompensatorPtrDllType = "ptr"
    Else
        $sExposureCompensatorPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveBlocksChannelsCompensatorCreate", "int", $blWidth, "int", $blHeight, "int", $nrFeeds, $sExposureCompensatorPtrDllType, $exposureCompensatorPtr), "cveBlocksChannelsCompensatorCreate", @error)
EndFunc   ;==>_cveBlocksChannelsCompensatorCreate

Func _cveBlocksChannelsCompensatorRelease($compensator)
    ; CVAPI(void) cveBlocksChannelsCompensatorRelease(cv::detail::BlocksChannelsCompensator** compensator);

    Local $sCompensatorDllType
    If IsDllStruct($compensator) Then
        $sCompensatorDllType = "struct*"
    ElseIf $compensator == Null Then
        $sCompensatorDllType = "ptr"
    Else
        $sCompensatorDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBlocksChannelsCompensatorRelease", $sCompensatorDllType, $compensator), "cveBlocksChannelsCompensatorRelease", @error)
EndFunc   ;==>_cveBlocksChannelsCompensatorRelease

Func _cveNoBundleAdjusterCreate($bundleAdjusterBasePtr)
    ; CVAPI(cv::detail::NoBundleAdjuster*) cveNoBundleAdjusterCreate(cv::detail::BundleAdjusterBase** bundleAdjusterBasePtr);

    Local $sBundleAdjusterBasePtrDllType
    If IsDllStruct($bundleAdjusterBasePtr) Then
        $sBundleAdjusterBasePtrDllType = "struct*"
    ElseIf $bundleAdjusterBasePtr == Null Then
        $sBundleAdjusterBasePtrDllType = "ptr"
    Else
        $sBundleAdjusterBasePtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveNoBundleAdjusterCreate", $sBundleAdjusterBasePtrDllType, $bundleAdjusterBasePtr), "cveNoBundleAdjusterCreate", @error)
EndFunc   ;==>_cveNoBundleAdjusterCreate

Func _cveNoBundleAdjusterRelease($bundleAdjuster)
    ; CVAPI(void) cveNoBundleAdjusterRelease(cv::detail::NoBundleAdjuster** bundleAdjuster);

    Local $sBundleAdjusterDllType
    If IsDllStruct($bundleAdjuster) Then
        $sBundleAdjusterDllType = "struct*"
    ElseIf $bundleAdjuster == Null Then
        $sBundleAdjusterDllType = "ptr"
    Else
        $sBundleAdjusterDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveNoBundleAdjusterRelease", $sBundleAdjusterDllType, $bundleAdjuster), "cveNoBundleAdjusterRelease", @error)
EndFunc   ;==>_cveNoBundleAdjusterRelease

Func _cveBundleAdjusterReprojCreate($bundleAdjusterBasePtr)
    ; CVAPI(cv::detail::BundleAdjusterReproj*) cveBundleAdjusterReprojCreate(cv::detail::BundleAdjusterBase** bundleAdjusterBasePtr);

    Local $sBundleAdjusterBasePtrDllType
    If IsDllStruct($bundleAdjusterBasePtr) Then
        $sBundleAdjusterBasePtrDllType = "struct*"
    ElseIf $bundleAdjusterBasePtr == Null Then
        $sBundleAdjusterBasePtrDllType = "ptr"
    Else
        $sBundleAdjusterBasePtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveBundleAdjusterReprojCreate", $sBundleAdjusterBasePtrDllType, $bundleAdjusterBasePtr), "cveBundleAdjusterReprojCreate", @error)
EndFunc   ;==>_cveBundleAdjusterReprojCreate

Func _cveBundleAdjusterReprojRelease($bundleAdjuster)
    ; CVAPI(void) cveBundleAdjusterReprojRelease(cv::detail::BundleAdjusterReproj** bundleAdjuster);

    Local $sBundleAdjusterDllType
    If IsDllStruct($bundleAdjuster) Then
        $sBundleAdjusterDllType = "struct*"
    ElseIf $bundleAdjuster == Null Then
        $sBundleAdjusterDllType = "ptr"
    Else
        $sBundleAdjusterDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBundleAdjusterReprojRelease", $sBundleAdjusterDllType, $bundleAdjuster), "cveBundleAdjusterReprojRelease", @error)
EndFunc   ;==>_cveBundleAdjusterReprojRelease

Func _cveBundleAdjusterRayCreate($bundleAdjusterBasePtr)
    ; CVAPI(cv::detail::BundleAdjusterRay*) cveBundleAdjusterRayCreate(cv::detail::BundleAdjusterBase** bundleAdjusterBasePtr);

    Local $sBundleAdjusterBasePtrDllType
    If IsDllStruct($bundleAdjusterBasePtr) Then
        $sBundleAdjusterBasePtrDllType = "struct*"
    ElseIf $bundleAdjusterBasePtr == Null Then
        $sBundleAdjusterBasePtrDllType = "ptr"
    Else
        $sBundleAdjusterBasePtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveBundleAdjusterRayCreate", $sBundleAdjusterBasePtrDllType, $bundleAdjusterBasePtr), "cveBundleAdjusterRayCreate", @error)
EndFunc   ;==>_cveBundleAdjusterRayCreate

Func _cveBundleAdjusterRayRelease($bundleAdjuster)
    ; CVAPI(void) cveBundleAdjusterRayRelease(cv::detail::BundleAdjusterRay** bundleAdjuster);

    Local $sBundleAdjusterDllType
    If IsDllStruct($bundleAdjuster) Then
        $sBundleAdjusterDllType = "struct*"
    ElseIf $bundleAdjuster == Null Then
        $sBundleAdjusterDllType = "ptr"
    Else
        $sBundleAdjusterDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBundleAdjusterRayRelease", $sBundleAdjusterDllType, $bundleAdjuster), "cveBundleAdjusterRayRelease", @error)
EndFunc   ;==>_cveBundleAdjusterRayRelease

Func _cveBundleAdjusterAffineCreate($bundleAdjusterBasePtr)
    ; CVAPI(cv::detail::BundleAdjusterAffine*) cveBundleAdjusterAffineCreate(cv::detail::BundleAdjusterBase** bundleAdjusterBasePtr);

    Local $sBundleAdjusterBasePtrDllType
    If IsDllStruct($bundleAdjusterBasePtr) Then
        $sBundleAdjusterBasePtrDllType = "struct*"
    ElseIf $bundleAdjusterBasePtr == Null Then
        $sBundleAdjusterBasePtrDllType = "ptr"
    Else
        $sBundleAdjusterBasePtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveBundleAdjusterAffineCreate", $sBundleAdjusterBasePtrDllType, $bundleAdjusterBasePtr), "cveBundleAdjusterAffineCreate", @error)
EndFunc   ;==>_cveBundleAdjusterAffineCreate

Func _cveBundleAdjusterAffineRelease($bundleAdjuster)
    ; CVAPI(void) cveBundleAdjusterAffineRelease(cv::detail::BundleAdjusterAffine** bundleAdjuster);

    Local $sBundleAdjusterDllType
    If IsDllStruct($bundleAdjuster) Then
        $sBundleAdjusterDllType = "struct*"
    ElseIf $bundleAdjuster == Null Then
        $sBundleAdjusterDllType = "ptr"
    Else
        $sBundleAdjusterDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBundleAdjusterAffineRelease", $sBundleAdjusterDllType, $bundleAdjuster), "cveBundleAdjusterAffineRelease", @error)
EndFunc   ;==>_cveBundleAdjusterAffineRelease

Func _cveBundleAdjusterAffinePartialCreate($bundleAdjusterBasePtr)
    ; CVAPI(cv::detail::BundleAdjusterAffinePartial*) cveBundleAdjusterAffinePartialCreate(cv::detail::BundleAdjusterBase** bundleAdjusterBasePtr);

    Local $sBundleAdjusterBasePtrDllType
    If IsDllStruct($bundleAdjusterBasePtr) Then
        $sBundleAdjusterBasePtrDllType = "struct*"
    ElseIf $bundleAdjusterBasePtr == Null Then
        $sBundleAdjusterBasePtrDllType = "ptr"
    Else
        $sBundleAdjusterBasePtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveBundleAdjusterAffinePartialCreate", $sBundleAdjusterBasePtrDllType, $bundleAdjusterBasePtr), "cveBundleAdjusterAffinePartialCreate", @error)
EndFunc   ;==>_cveBundleAdjusterAffinePartialCreate

Func _cveBundleAdjusterAffinePartialRelease($bundleAdjuster)
    ; CVAPI(void) cveBundleAdjusterAffinePartialRelease(cv::detail::BundleAdjusterAffinePartial** bundleAdjuster);

    Local $sBundleAdjusterDllType
    If IsDllStruct($bundleAdjuster) Then
        $sBundleAdjusterDllType = "struct*"
    ElseIf $bundleAdjuster == Null Then
        $sBundleAdjusterDllType = "ptr"
    Else
        $sBundleAdjusterDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBundleAdjusterAffinePartialRelease", $sBundleAdjusterDllType, $bundleAdjuster), "cveBundleAdjusterAffinePartialRelease", @error)
EndFunc   ;==>_cveBundleAdjusterAffinePartialRelease

Func _cveNoSeamFinderCreate($seamFinderPtr)
    ; CVAPI(cv::detail::NoSeamFinder*) cveNoSeamFinderCreate(cv::detail::SeamFinder** seamFinderPtr);

    Local $sSeamFinderPtrDllType
    If IsDllStruct($seamFinderPtr) Then
        $sSeamFinderPtrDllType = "struct*"
    ElseIf $seamFinderPtr == Null Then
        $sSeamFinderPtrDllType = "ptr"
    Else
        $sSeamFinderPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveNoSeamFinderCreate", $sSeamFinderPtrDllType, $seamFinderPtr), "cveNoSeamFinderCreate", @error)
EndFunc   ;==>_cveNoSeamFinderCreate

Func _cveNoSeamFinderRelease($seamFinder)
    ; CVAPI(void) cveNoSeamFinderRelease(cv::detail::NoSeamFinder** seamFinder);

    Local $sSeamFinderDllType
    If IsDllStruct($seamFinder) Then
        $sSeamFinderDllType = "struct*"
    ElseIf $seamFinder == Null Then
        $sSeamFinderDllType = "ptr"
    Else
        $sSeamFinderDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveNoSeamFinderRelease", $sSeamFinderDllType, $seamFinder), "cveNoSeamFinderRelease", @error)
EndFunc   ;==>_cveNoSeamFinderRelease

Func _cveVoronoiSeamFinderCreate($seamFinderPtr)
    ; CVAPI(cv::detail::VoronoiSeamFinder*) cveVoronoiSeamFinderCreate(cv::detail::SeamFinder** seamFinderPtr);

    Local $sSeamFinderPtrDllType
    If IsDllStruct($seamFinderPtr) Then
        $sSeamFinderPtrDllType = "struct*"
    ElseIf $seamFinderPtr == Null Then
        $sSeamFinderPtrDllType = "ptr"
    Else
        $sSeamFinderPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveVoronoiSeamFinderCreate", $sSeamFinderPtrDllType, $seamFinderPtr), "cveVoronoiSeamFinderCreate", @error)
EndFunc   ;==>_cveVoronoiSeamFinderCreate

Func _cveVoronoiSeamFinderRelease($seamFinder)
    ; CVAPI(void) cveVoronoiSeamFinderRelease(cv::detail::VoronoiSeamFinder** seamFinder);

    Local $sSeamFinderDllType
    If IsDllStruct($seamFinder) Then
        $sSeamFinderDllType = "struct*"
    ElseIf $seamFinder == Null Then
        $sSeamFinderDllType = "ptr"
    Else
        $sSeamFinderDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveVoronoiSeamFinderRelease", $sSeamFinderDllType, $seamFinder), "cveVoronoiSeamFinderRelease", @error)
EndFunc   ;==>_cveVoronoiSeamFinderRelease

Func _cveDpSeamFinderCreate($costFunc, $seamFinderPtr)
    ; CVAPI(cv::detail::DpSeamFinder*) cveDpSeamFinderCreate(int costFunc, cv::detail::SeamFinder** seamFinderPtr);

    Local $sSeamFinderPtrDllType
    If IsDllStruct($seamFinderPtr) Then
        $sSeamFinderPtrDllType = "struct*"
    ElseIf $seamFinderPtr == Null Then
        $sSeamFinderPtrDllType = "ptr"
    Else
        $sSeamFinderPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveDpSeamFinderCreate", "int", $costFunc, $sSeamFinderPtrDllType, $seamFinderPtr), "cveDpSeamFinderCreate", @error)
EndFunc   ;==>_cveDpSeamFinderCreate

Func _cveDpSeamFinderRelease($seamFinder)
    ; CVAPI(void) cveDpSeamFinderRelease(cv::detail::DpSeamFinder** seamFinder);

    Local $sSeamFinderDllType
    If IsDllStruct($seamFinder) Then
        $sSeamFinderDllType = "struct*"
    ElseIf $seamFinder == Null Then
        $sSeamFinderDllType = "ptr"
    Else
        $sSeamFinderDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDpSeamFinderRelease", $sSeamFinderDllType, $seamFinder), "cveDpSeamFinderRelease", @error)
EndFunc   ;==>_cveDpSeamFinderRelease

Func _cveGraphCutSeamFinderCreate($costType, $terminalCost, $badRegionPenalty, $seamFinderPtr)
    ; CVAPI(cv::detail::GraphCutSeamFinder*) cveGraphCutSeamFinderCreate(int costType, float terminalCost, float badRegionPenalty, cv::detail::SeamFinder** seamFinderPtr);

    Local $sSeamFinderPtrDllType
    If IsDllStruct($seamFinderPtr) Then
        $sSeamFinderPtrDllType = "struct*"
    ElseIf $seamFinderPtr == Null Then
        $sSeamFinderPtrDllType = "ptr"
    Else
        $sSeamFinderPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGraphCutSeamFinderCreate", "int", $costType, "float", $terminalCost, "float", $badRegionPenalty, $sSeamFinderPtrDllType, $seamFinderPtr), "cveGraphCutSeamFinderCreate", @error)
EndFunc   ;==>_cveGraphCutSeamFinderCreate

Func _cveGraphCutSeamFinderRelease($seamFinder)
    ; CVAPI(void) cveGraphCutSeamFinderRelease(cv::detail::GraphCutSeamFinder** seamFinder);

    Local $sSeamFinderDllType
    If IsDllStruct($seamFinder) Then
        $sSeamFinderDllType = "struct*"
    ElseIf $seamFinder == Null Then
        $sSeamFinderDllType = "ptr"
    Else
        $sSeamFinderDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveGraphCutSeamFinderRelease", $sSeamFinderDllType, $seamFinder), "cveGraphCutSeamFinderRelease", @error)
EndFunc   ;==>_cveGraphCutSeamFinderRelease

Func _cveHomographyBasedEstimatorCreate($isFocalsEstimated, $estimatorPtr)
    ; CVAPI(cv::detail::HomographyBasedEstimator*) cveHomographyBasedEstimatorCreate(bool isFocalsEstimated, cv::detail::Estimator** estimatorPtr);

    Local $sEstimatorPtrDllType
    If IsDllStruct($estimatorPtr) Then
        $sEstimatorPtrDllType = "struct*"
    ElseIf $estimatorPtr == Null Then
        $sEstimatorPtrDllType = "ptr"
    Else
        $sEstimatorPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveHomographyBasedEstimatorCreate", "boolean", $isFocalsEstimated, $sEstimatorPtrDllType, $estimatorPtr), "cveHomographyBasedEstimatorCreate", @error)
EndFunc   ;==>_cveHomographyBasedEstimatorCreate

Func _cveHomographyBasedEstimatorRelease($estimator)
    ; CVAPI(void) cveHomographyBasedEstimatorRelease(cv::detail::HomographyBasedEstimator** estimator);

    Local $sEstimatorDllType
    If IsDllStruct($estimator) Then
        $sEstimatorDllType = "struct*"
    ElseIf $estimator == Null Then
        $sEstimatorDllType = "ptr"
    Else
        $sEstimatorDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveHomographyBasedEstimatorRelease", $sEstimatorDllType, $estimator), "cveHomographyBasedEstimatorRelease", @error)
EndFunc   ;==>_cveHomographyBasedEstimatorRelease

Func _cveAffineBasedEstimatorCreate($estimatorPtr)
    ; CVAPI(cv::detail::AffineBasedEstimator*) cveAffineBasedEstimatorCreate(cv::detail::Estimator** estimatorPtr);

    Local $sEstimatorPtrDllType
    If IsDllStruct($estimatorPtr) Then
        $sEstimatorPtrDllType = "struct*"
    ElseIf $estimatorPtr == Null Then
        $sEstimatorPtrDllType = "ptr"
    Else
        $sEstimatorPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveAffineBasedEstimatorCreate", $sEstimatorPtrDllType, $estimatorPtr), "cveAffineBasedEstimatorCreate", @error)
EndFunc   ;==>_cveAffineBasedEstimatorCreate

Func _cveAffineBasedEstimatorRelease($estimator)
    ; CVAPI(void) cveAffineBasedEstimatorRelease(cv::detail::AffineBasedEstimator** estimator);

    Local $sEstimatorDllType
    If IsDllStruct($estimator) Then
        $sEstimatorDllType = "struct*"
    ElseIf $estimator == Null Then
        $sEstimatorDllType = "ptr"
    Else
        $sEstimatorDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveAffineBasedEstimatorRelease", $sEstimatorDllType, $estimator), "cveAffineBasedEstimatorRelease", @error)
EndFunc   ;==>_cveAffineBasedEstimatorRelease

Func _cveBestOf2NearestMatcherCreate($tryUseGpu, $matchConf, $numMatchesThresh1, $numMatchesThresh2, $featuresMatcher)
    ; CVAPI(cv::detail::BestOf2NearestMatcher*) cveBestOf2NearestMatcherCreate(bool tryUseGpu, float matchConf, int numMatchesThresh1, int numMatchesThresh2, cv::detail::FeaturesMatcher** featuresMatcher);

    Local $sFeaturesMatcherDllType
    If IsDllStruct($featuresMatcher) Then
        $sFeaturesMatcherDllType = "struct*"
    ElseIf $featuresMatcher == Null Then
        $sFeaturesMatcherDllType = "ptr"
    Else
        $sFeaturesMatcherDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveBestOf2NearestMatcherCreate", "boolean", $tryUseGpu, "float", $matchConf, "int", $numMatchesThresh1, "int", $numMatchesThresh2, $sFeaturesMatcherDllType, $featuresMatcher), "cveBestOf2NearestMatcherCreate", @error)
EndFunc   ;==>_cveBestOf2NearestMatcherCreate

Func _cveBestOf2NearestMatcherRelease($featuresMatcher)
    ; CVAPI(void) cveBestOf2NearestMatcherRelease(cv::detail::BestOf2NearestMatcher** featuresMatcher);

    Local $sFeaturesMatcherDllType
    If IsDllStruct($featuresMatcher) Then
        $sFeaturesMatcherDllType = "struct*"
    ElseIf $featuresMatcher == Null Then
        $sFeaturesMatcherDllType = "ptr"
    Else
        $sFeaturesMatcherDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBestOf2NearestMatcherRelease", $sFeaturesMatcherDllType, $featuresMatcher), "cveBestOf2NearestMatcherRelease", @error)
EndFunc   ;==>_cveBestOf2NearestMatcherRelease

Func _cveBestOf2NearestRangeMatcherCreate($rangeWidth, $tryUseGpu, $matchConf, $numMatchesThresh1, $numMatchesThresh2, $featuresMatcher)
    ; CVAPI(cv::detail::BestOf2NearestRangeMatcher*) cveBestOf2NearestRangeMatcherCreate(int rangeWidth, bool tryUseGpu, float matchConf, int numMatchesThresh1, int numMatchesThresh2, cv::detail::FeaturesMatcher** featuresMatcher);

    Local $sFeaturesMatcherDllType
    If IsDllStruct($featuresMatcher) Then
        $sFeaturesMatcherDllType = "struct*"
    ElseIf $featuresMatcher == Null Then
        $sFeaturesMatcherDllType = "ptr"
    Else
        $sFeaturesMatcherDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveBestOf2NearestRangeMatcherCreate", "int", $rangeWidth, "boolean", $tryUseGpu, "float", $matchConf, "int", $numMatchesThresh1, "int", $numMatchesThresh2, $sFeaturesMatcherDllType, $featuresMatcher), "cveBestOf2NearestRangeMatcherCreate", @error)
EndFunc   ;==>_cveBestOf2NearestRangeMatcherCreate

Func _cveBestOf2NearestRangeMatcherRelease($featuresMatcher)
    ; CVAPI(void) cveBestOf2NearestRangeMatcherRelease(cv::detail::BestOf2NearestRangeMatcher** featuresMatcher);

    Local $sFeaturesMatcherDllType
    If IsDllStruct($featuresMatcher) Then
        $sFeaturesMatcherDllType = "struct*"
    ElseIf $featuresMatcher == Null Then
        $sFeaturesMatcherDllType = "ptr"
    Else
        $sFeaturesMatcherDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBestOf2NearestRangeMatcherRelease", $sFeaturesMatcherDllType, $featuresMatcher), "cveBestOf2NearestRangeMatcherRelease", @error)
EndFunc   ;==>_cveBestOf2NearestRangeMatcherRelease

Func _cveAffineBestOf2NearestMatcherCreate($fullAffine, $tryUseGpu, $matchConf, $numMatchesThresh1, $featuresMatcher)
    ; CVAPI(cv::detail::AffineBestOf2NearestMatcher*) cveAffineBestOf2NearestMatcherCreate(bool fullAffine, bool tryUseGpu, float matchConf, int numMatchesThresh1, cv::detail::FeaturesMatcher** featuresMatcher);

    Local $sFeaturesMatcherDllType
    If IsDllStruct($featuresMatcher) Then
        $sFeaturesMatcherDllType = "struct*"
    ElseIf $featuresMatcher == Null Then
        $sFeaturesMatcherDllType = "ptr"
    Else
        $sFeaturesMatcherDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveAffineBestOf2NearestMatcherCreate", "boolean", $fullAffine, "boolean", $tryUseGpu, "float", $matchConf, "int", $numMatchesThresh1, $sFeaturesMatcherDllType, $featuresMatcher), "cveAffineBestOf2NearestMatcherCreate", @error)
EndFunc   ;==>_cveAffineBestOf2NearestMatcherCreate

Func _cveAffineBestOf2NearestMatcherRelease($featuresMatcher)
    ; CVAPI(void) cveAffineBestOf2NearestMatcherRelease(cv::detail::AffineBestOf2NearestMatcher** featuresMatcher);

    Local $sFeaturesMatcherDllType
    If IsDllStruct($featuresMatcher) Then
        $sFeaturesMatcherDllType = "struct*"
    ElseIf $featuresMatcher == Null Then
        $sFeaturesMatcherDllType = "ptr"
    Else
        $sFeaturesMatcherDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveAffineBestOf2NearestMatcherRelease", $sFeaturesMatcherDllType, $featuresMatcher), "cveAffineBestOf2NearestMatcherRelease", @error)
EndFunc   ;==>_cveAffineBestOf2NearestMatcherRelease

Func _cveDetailPlaneWarperGpuCreate($scale, $rotationWarper)
    ; CVAPI(cv::detail::PlaneWarperGpu*) cveDetailPlaneWarperGpuCreate(float scale, cv::detail::RotationWarper** rotationWarper);

    Local $sRotationWarperDllType
    If IsDllStruct($rotationWarper) Then
        $sRotationWarperDllType = "struct*"
    ElseIf $rotationWarper == Null Then
        $sRotationWarperDllType = "ptr"
    Else
        $sRotationWarperDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveDetailPlaneWarperGpuCreate", "float", $scale, $sRotationWarperDllType, $rotationWarper), "cveDetailPlaneWarperGpuCreate", @error)
EndFunc   ;==>_cveDetailPlaneWarperGpuCreate

Func _cveDetailPlaneWarperGpuRelease($warper)
    ; CVAPI(void) cveDetailPlaneWarperGpuRelease(cv::detail::PlaneWarperGpu** warper);

    Local $sWarperDllType
    If IsDllStruct($warper) Then
        $sWarperDllType = "struct*"
    ElseIf $warper == Null Then
        $sWarperDllType = "ptr"
    Else
        $sWarperDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDetailPlaneWarperGpuRelease", $sWarperDllType, $warper), "cveDetailPlaneWarperGpuRelease", @error)
EndFunc   ;==>_cveDetailPlaneWarperGpuRelease

Func _cvePlaneWarperGpuCreate($warperCreator)
    ; CVAPI(cv::PlaneWarperGpu*) cvePlaneWarperGpuCreate(cv::WarperCreator** warperCreator);

    Local $sWarperCreatorDllType
    If IsDllStruct($warperCreator) Then
        $sWarperCreatorDllType = "struct*"
    ElseIf $warperCreator == Null Then
        $sWarperCreatorDllType = "ptr"
    Else
        $sWarperCreatorDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cvePlaneWarperGpuCreate", $sWarperCreatorDllType, $warperCreator), "cvePlaneWarperGpuCreate", @error)
EndFunc   ;==>_cvePlaneWarperGpuCreate

Func _cvePlaneWarperGpuRelease($warperCreator)
    ; CVAPI(void) cvePlaneWarperGpuRelease(cv::PlaneWarperGpu** warperCreator);

    Local $sWarperCreatorDllType
    If IsDllStruct($warperCreator) Then
        $sWarperCreatorDllType = "struct*"
    ElseIf $warperCreator == Null Then
        $sWarperCreatorDllType = "ptr"
    Else
        $sWarperCreatorDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cvePlaneWarperGpuRelease", $sWarperCreatorDllType, $warperCreator), "cvePlaneWarperGpuRelease", @error)
EndFunc   ;==>_cvePlaneWarperGpuRelease

Func _cveDetailCylindricalWarperGpuCreate($scale, $rotationWarper)
    ; CVAPI(cv::detail::CylindricalWarperGpu*) cveDetailCylindricalWarperGpuCreate(float scale, cv::detail::RotationWarper** rotationWarper);

    Local $sRotationWarperDllType
    If IsDllStruct($rotationWarper) Then
        $sRotationWarperDllType = "struct*"
    ElseIf $rotationWarper == Null Then
        $sRotationWarperDllType = "ptr"
    Else
        $sRotationWarperDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveDetailCylindricalWarperGpuCreate", "float", $scale, $sRotationWarperDllType, $rotationWarper), "cveDetailCylindricalWarperGpuCreate", @error)
EndFunc   ;==>_cveDetailCylindricalWarperGpuCreate

Func _cveDetailCylindricalWarperGpuRelease($warper)
    ; CVAPI(void) cveDetailCylindricalWarperGpuRelease(cv::detail::CylindricalWarperGpu** warper);

    Local $sWarperDllType
    If IsDllStruct($warper) Then
        $sWarperDllType = "struct*"
    ElseIf $warper == Null Then
        $sWarperDllType = "ptr"
    Else
        $sWarperDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDetailCylindricalWarperGpuRelease", $sWarperDllType, $warper), "cveDetailCylindricalWarperGpuRelease", @error)
EndFunc   ;==>_cveDetailCylindricalWarperGpuRelease

Func _cveCylindricalWarperGpuCreate($warperCreator)
    ; CVAPI(cv::CylindricalWarperGpu*) cveCylindricalWarperGpuCreate(cv::WarperCreator** warperCreator);

    Local $sWarperCreatorDllType
    If IsDllStruct($warperCreator) Then
        $sWarperCreatorDllType = "struct*"
    ElseIf $warperCreator == Null Then
        $sWarperCreatorDllType = "ptr"
    Else
        $sWarperCreatorDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveCylindricalWarperGpuCreate", $sWarperCreatorDllType, $warperCreator), "cveCylindricalWarperGpuCreate", @error)
EndFunc   ;==>_cveCylindricalWarperGpuCreate

Func _cveCylindricalWarperGpuRelease($warperCreator)
    ; CVAPI(void) cveCylindricalWarperGpuRelease(cv::CylindricalWarperGpu** warperCreator);

    Local $sWarperCreatorDllType
    If IsDllStruct($warperCreator) Then
        $sWarperCreatorDllType = "struct*"
    ElseIf $warperCreator == Null Then
        $sWarperCreatorDllType = "ptr"
    Else
        $sWarperCreatorDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCylindricalWarperGpuRelease", $sWarperCreatorDllType, $warperCreator), "cveCylindricalWarperGpuRelease", @error)
EndFunc   ;==>_cveCylindricalWarperGpuRelease

Func _cveDetailSphericalWarperGpuCreate($scale, $rotationWarper)
    ; CVAPI(cv::detail::SphericalWarperGpu*) cveDetailSphericalWarperGpuCreate(float scale, cv::detail::RotationWarper** rotationWarper);

    Local $sRotationWarperDllType
    If IsDllStruct($rotationWarper) Then
        $sRotationWarperDllType = "struct*"
    ElseIf $rotationWarper == Null Then
        $sRotationWarperDllType = "ptr"
    Else
        $sRotationWarperDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveDetailSphericalWarperGpuCreate", "float", $scale, $sRotationWarperDllType, $rotationWarper), "cveDetailSphericalWarperGpuCreate", @error)
EndFunc   ;==>_cveDetailSphericalWarperGpuCreate

Func _cveDetailSphericalWarperGpuRelease($warper)
    ; CVAPI(void) cveDetailSphericalWarperGpuRelease(cv::detail::SphericalWarperGpu** warper);

    Local $sWarperDllType
    If IsDllStruct($warper) Then
        $sWarperDllType = "struct*"
    ElseIf $warper == Null Then
        $sWarperDllType = "ptr"
    Else
        $sWarperDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDetailSphericalWarperGpuRelease", $sWarperDllType, $warper), "cveDetailSphericalWarperGpuRelease", @error)
EndFunc   ;==>_cveDetailSphericalWarperGpuRelease

Func _cveSphericalWarperGpuCreate($warperCreator)
    ; CVAPI(cv::SphericalWarperGpu*) cveSphericalWarperGpuCreate(cv::WarperCreator** warperCreator);

    Local $sWarperCreatorDllType
    If IsDllStruct($warperCreator) Then
        $sWarperCreatorDllType = "struct*"
    ElseIf $warperCreator == Null Then
        $sWarperCreatorDllType = "ptr"
    Else
        $sWarperCreatorDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveSphericalWarperGpuCreate", $sWarperCreatorDllType, $warperCreator), "cveSphericalWarperGpuCreate", @error)
EndFunc   ;==>_cveSphericalWarperGpuCreate

Func _cveSphericalWarperGpuRelease($warper)
    ; CVAPI(void) cveSphericalWarperGpuRelease(cv::SphericalWarperGpu** warper);

    Local $sWarperDllType
    If IsDllStruct($warper) Then
        $sWarperDllType = "struct*"
    ElseIf $warper == Null Then
        $sWarperDllType = "ptr"
    Else
        $sWarperDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSphericalWarperGpuRelease", $sWarperDllType, $warper), "cveSphericalWarperGpuRelease", @error)
EndFunc   ;==>_cveSphericalWarperGpuRelease