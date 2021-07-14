#include-once
#include <..\..\CVEUtils.au3>

Func _cveStitcherCreate($mode, ByRef $sharedPtr)
    ; CVAPI(cv::Stitcher*) cveStitcherCreate(int mode, cv::Ptr<cv::Stitcher>** sharedPtr);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveStitcherCreate", "int", $mode, "ptr*", $sharedPtr), "cveStitcherCreate", @error)
EndFunc   ;==>_cveStitcherCreate

Func _cveStitcherRelease(ByRef $sharedPtr)
    ; CVAPI(void) cveStitcherRelease(cv::Ptr<cv::Stitcher>** sharedPtr);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveStitcherRelease", "ptr*", $sharedPtr), "cveStitcherRelease", @error)
EndFunc   ;==>_cveStitcherRelease

Func _cveStitcherSetFeaturesFinder(ByRef $stitcher, ByRef $finder)
    ; CVAPI(void) cveStitcherSetFeaturesFinder(cv::Stitcher* stitcher, cv::Feature2D* finder);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveStitcherSetFeaturesFinder", "ptr", $stitcher, "ptr", $finder), "cveStitcherSetFeaturesFinder", @error)
EndFunc   ;==>_cveStitcherSetFeaturesFinder

Func _cveStitcherSetWarper(ByRef $stitcher, ByRef $creator)
    ; CVAPI(void) cveStitcherSetWarper(cv::Stitcher* stitcher, cv::WarperCreator* creator);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveStitcherSetWarper", "ptr", $stitcher, "ptr", $creator), "cveStitcherSetWarper", @error)
EndFunc   ;==>_cveStitcherSetWarper

Func _cveStitcherSetBlender(ByRef $stitcher, ByRef $b)
    ; CVAPI(void) cveStitcherSetBlender(cv::Stitcher* stitcher, cv::detail::Blender* b);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveStitcherSetBlender", "ptr", $stitcher, "ptr", $b), "cveStitcherSetBlender", @error)
EndFunc   ;==>_cveStitcherSetBlender

Func _cveStitcherSetExposureCompensator(ByRef $stitcher, ByRef $exposureComp)
    ; CVAPI(void) cveStitcherSetExposureCompensator(cv::Stitcher* stitcher, cv::detail::ExposureCompensator* exposureComp);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveStitcherSetExposureCompensator", "ptr", $stitcher, "ptr", $exposureComp), "cveStitcherSetExposureCompensator", @error)
EndFunc   ;==>_cveStitcherSetExposureCompensator

Func _cveStitcherSetBundleAdjuster(ByRef $stitcher, ByRef $bundleAdjuster)
    ; CVAPI(void) cveStitcherSetBundleAdjuster(cv::Stitcher* stitcher, cv::detail::BundleAdjusterBase* bundleAdjuster);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveStitcherSetBundleAdjuster", "ptr", $stitcher, "ptr", $bundleAdjuster), "cveStitcherSetBundleAdjuster", @error)
EndFunc   ;==>_cveStitcherSetBundleAdjuster

Func _cveStitcherSetSeamFinder(ByRef $stitcher, ByRef $seamFinder)
    ; CVAPI(void) cveStitcherSetSeamFinder(cv::Stitcher* stitcher, cv::detail::SeamFinder* seamFinder);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveStitcherSetSeamFinder", "ptr", $stitcher, "ptr", $seamFinder), "cveStitcherSetSeamFinder", @error)
EndFunc   ;==>_cveStitcherSetSeamFinder

Func _cveStitcherSetEstimator(ByRef $stitcher, ByRef $estimator)
    ; CVAPI(void) cveStitcherSetEstimator(cv::Stitcher* stitcher, cv::detail::Estimator* estimator);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveStitcherSetEstimator", "ptr", $stitcher, "ptr", $estimator), "cveStitcherSetEstimator", @error)
EndFunc   ;==>_cveStitcherSetEstimator

Func _cveStitcherSetFeaturesMatcher(ByRef $stitcher, ByRef $featuresMatcher)
    ; CVAPI(void) cveStitcherSetFeaturesMatcher(cv::Stitcher* stitcher, cv::detail::FeaturesMatcher* featuresMatcher);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveStitcherSetFeaturesMatcher", "ptr", $stitcher, "ptr", $featuresMatcher), "cveStitcherSetFeaturesMatcher", @error)
EndFunc   ;==>_cveStitcherSetFeaturesMatcher

Func _cveStitcherSetWaveCorrection(ByRef $stitcher, $flag)
    ; CVAPI(void) cveStitcherSetWaveCorrection(cv::Stitcher* stitcher, bool flag);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveStitcherSetWaveCorrection", "ptr", $stitcher, "boolean", $flag), "cveStitcherSetWaveCorrection", @error)
EndFunc   ;==>_cveStitcherSetWaveCorrection

Func _cveStitcherGetWaveCorrection(ByRef $stitcher)
    ; CVAPI(bool) cveStitcherGetWaveCorrection(cv::Stitcher* stitcher);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveStitcherGetWaveCorrection", "ptr", $stitcher), "cveStitcherGetWaveCorrection", @error)
EndFunc   ;==>_cveStitcherGetWaveCorrection

Func _cveStitcherSetWaveCorrectionKind(ByRef $stitcher, $kind)
    ; CVAPI(void) cveStitcherSetWaveCorrectionKind(cv::Stitcher* stitcher, int kind);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveStitcherSetWaveCorrectionKind", "ptr", $stitcher, "int", $kind), "cveStitcherSetWaveCorrectionKind", @error)
EndFunc   ;==>_cveStitcherSetWaveCorrectionKind

Func _cveStitcherGetWaveCorrectionKind(ByRef $stitcher)
    ; CVAPI(int) cveStitcherGetWaveCorrectionKind(cv::Stitcher* stitcher);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveStitcherGetWaveCorrectionKind", "ptr", $stitcher), "cveStitcherGetWaveCorrectionKind", @error)
EndFunc   ;==>_cveStitcherGetWaveCorrectionKind

Func _cveStitcherSetPanoConfidenceThresh(ByRef $stitcher, $confThresh)
    ; CVAPI(void) cveStitcherSetPanoConfidenceThresh(cv::Stitcher* stitcher, double confThresh);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveStitcherSetPanoConfidenceThresh", "ptr", $stitcher, "double", $confThresh), "cveStitcherSetPanoConfidenceThresh", @error)
EndFunc   ;==>_cveStitcherSetPanoConfidenceThresh

Func _cveStitcherGetPanoConfidenceThresh(ByRef $stitcher)
    ; CVAPI(double) cveStitcherGetPanoConfidenceThresh(cv::Stitcher* stitcher);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveStitcherGetPanoConfidenceThresh", "ptr", $stitcher), "cveStitcherGetPanoConfidenceThresh", @error)
EndFunc   ;==>_cveStitcherGetPanoConfidenceThresh

Func _cveStitcherSetCompositingResol(ByRef $stitcher, $resolMpx)
    ; CVAPI(void) cveStitcherSetCompositingResol(cv::Stitcher* stitcher, double resolMpx);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveStitcherSetCompositingResol", "ptr", $stitcher, "double", $resolMpx), "cveStitcherSetCompositingResol", @error)
EndFunc   ;==>_cveStitcherSetCompositingResol

Func _cveStitcherGetCompositingResol(ByRef $stitcher)
    ; CVAPI(double) cveStitcherGetCompositingResol(cv::Stitcher* stitcher);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveStitcherGetCompositingResol", "ptr", $stitcher), "cveStitcherGetCompositingResol", @error)
EndFunc   ;==>_cveStitcherGetCompositingResol

Func _cveStitcherSetSeamEstimationResol(ByRef $stitcher, $resolMpx)
    ; CVAPI(void) cveStitcherSetSeamEstimationResol(cv::Stitcher* stitcher, double resolMpx);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveStitcherSetSeamEstimationResol", "ptr", $stitcher, "double", $resolMpx), "cveStitcherSetSeamEstimationResol", @error)
EndFunc   ;==>_cveStitcherSetSeamEstimationResol

Func _cveStitcherGetSeamEstimationResol(ByRef $stitcher)
    ; CVAPI(double) cveStitcherGetSeamEstimationResol(cv::Stitcher* stitcher);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveStitcherGetSeamEstimationResol", "ptr", $stitcher), "cveStitcherGetSeamEstimationResol", @error)
EndFunc   ;==>_cveStitcherGetSeamEstimationResol

Func _cveStitcherSetRegistrationResol(ByRef $stitcher, $resolMpx)
    ; CVAPI(void) cveStitcherSetRegistrationResol(cv::Stitcher* stitcher, double resolMpx);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveStitcherSetRegistrationResol", "ptr", $stitcher, "double", $resolMpx), "cveStitcherSetRegistrationResol", @error)
EndFunc   ;==>_cveStitcherSetRegistrationResol

Func _cveStitcherGetRegistrationResol(ByRef $stitcher)
    ; CVAPI(double) cveStitcherGetRegistrationResol(cv::Stitcher* stitcher);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveStitcherGetRegistrationResol", "ptr", $stitcher), "cveStitcherGetRegistrationResol", @error)
EndFunc   ;==>_cveStitcherGetRegistrationResol

Func _cveStitcherGetInterpolationFlags(ByRef $stitcher)
    ; CVAPI(int) cveStitcherGetInterpolationFlags(cv::Stitcher* stitcher);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveStitcherGetInterpolationFlags", "ptr", $stitcher), "cveStitcherGetInterpolationFlags", @error)
EndFunc   ;==>_cveStitcherGetInterpolationFlags

Func _cveStitcherSetInterpolationFlags(ByRef $stitcher, $interpFlags)
    ; CVAPI(void) cveStitcherSetInterpolationFlags(cv::Stitcher* stitcher, int interpFlags);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveStitcherSetInterpolationFlags", "ptr", $stitcher, "int", $interpFlags), "cveStitcherSetInterpolationFlags", @error)
EndFunc   ;==>_cveStitcherSetInterpolationFlags

Func _cveStitcherStitch(ByRef $stitcher, ByRef $images, ByRef $pano)
    ; CVAPI(int) cveStitcherStitch(cv::Stitcher* stitcher, cv::_InputArray* images, cv::_OutputArray* pano);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveStitcherStitch", "ptr", $stitcher, "ptr", $images, "ptr", $pano), "cveStitcherStitch", @error)
EndFunc   ;==>_cveStitcherStitch

Func _cveStitcherStitchMat(ByRef $stitcher, ByRef $matImages, ByRef $matPano)
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

Func _cveStitcherEstimateTransform(ByRef $stitcher, ByRef $images, ByRef $masks)
    ; CVAPI(int) cveStitcherEstimateTransform(cv::Stitcher* stitcher, cv::_InputArray* images, cv::_InputArray* masks);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveStitcherEstimateTransform", "ptr", $stitcher, "ptr", $images, "ptr", $masks), "cveStitcherEstimateTransform", @error)
EndFunc   ;==>_cveStitcherEstimateTransform

Func _cveStitcherEstimateTransformMat(ByRef $stitcher, ByRef $matImages, ByRef $matMasks)
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

Func _cveStitcherComposePanorama1(ByRef $stitcher, ByRef $pano)
    ; CVAPI(int) cveStitcherComposePanorama1(cv::Stitcher* stitcher, cv::_OutputArray* pano);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveStitcherComposePanorama1", "ptr", $stitcher, "ptr", $pano), "cveStitcherComposePanorama1", @error)
EndFunc   ;==>_cveStitcherComposePanorama1

Func _cveStitcherComposePanorama1Mat(ByRef $stitcher, ByRef $matPano)
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

Func _cveStitcherComposePanorama2(ByRef $stitcher, ByRef $images, ByRef $pano)
    ; CVAPI(int) cveStitcherComposePanorama2(cv::Stitcher* stitcher, cv::_InputArray* images, cv::_OutputArray* pano);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveStitcherComposePanorama2", "ptr", $stitcher, "ptr", $images, "ptr", $pano), "cveStitcherComposePanorama2", @error)
EndFunc   ;==>_cveStitcherComposePanorama2

Func _cveStitcherComposePanorama2Mat(ByRef $stitcher, ByRef $matImages, ByRef $matPano)
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

Func _cveRotationWarperBuildMaps(ByRef $warper, ByRef $srcSize, ByRef $K, ByRef $R, ByRef $xmap, ByRef $ymap, ByRef $boundingBox)
    ; CVAPI(void) cveRotationWarperBuildMaps(cv::detail::RotationWarper* warper, CvSize* srcSize, cv::_InputArray* K, cv::_InputArray* R, cv::_OutputArray* xmap, cv::_OutputArray* ymap, CvRect* boundingBox);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveRotationWarperBuildMaps", "ptr", $warper, "struct*", $srcSize, "ptr", $K, "ptr", $R, "ptr", $xmap, "ptr", $ymap, "struct*", $boundingBox), "cveRotationWarperBuildMaps", @error)
EndFunc   ;==>_cveRotationWarperBuildMaps

Func _cveRotationWarperBuildMapsMat(ByRef $warper, ByRef $srcSize, ByRef $matK, ByRef $matR, ByRef $matXmap, ByRef $matYmap, ByRef $boundingBox)
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

Func _cveRotationWarperWarp(ByRef $warper, ByRef $src, ByRef $K, ByRef $R, $interpMode, $borderMode, ByRef $dst, ByRef $corner)
    ; CVAPI(void) cveRotationWarperWarp(cv::detail::RotationWarper* warper, cv::_InputArray* src, cv::_InputArray* K, cv::_InputArray* R, int interpMode, int borderMode, cv::_OutputArray* dst, CvPoint* corner);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveRotationWarperWarp", "ptr", $warper, "ptr", $src, "ptr", $K, "ptr", $R, "int", $interpMode, "int", $borderMode, "ptr", $dst, "struct*", $corner), "cveRotationWarperWarp", @error)
EndFunc   ;==>_cveRotationWarperWarp

Func _cveRotationWarperWarpMat(ByRef $warper, ByRef $matSrc, ByRef $matK, ByRef $matR, $interpMode, $borderMode, ByRef $matDst, ByRef $corner)
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

Func _cveDetailPlaneWarperCreate($scale, ByRef $rotationWarper)
    ; CVAPI(cv::detail::PlaneWarper*) cveDetailPlaneWarperCreate(float scale, cv::detail::RotationWarper** rotationWarper);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveDetailPlaneWarperCreate", "float", $scale, "ptr*", $rotationWarper), "cveDetailPlaneWarperCreate", @error)
EndFunc   ;==>_cveDetailPlaneWarperCreate

Func _cveDetailPlaneWarperRelease(ByRef $warper)
    ; CVAPI(void) cveDetailPlaneWarperRelease(cv::detail::PlaneWarper** warper);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDetailPlaneWarperRelease", "ptr*", $warper), "cveDetailPlaneWarperRelease", @error)
EndFunc   ;==>_cveDetailPlaneWarperRelease

Func _cvePlaneWarperCreate(ByRef $warperCreator)
    ; CVAPI(cv::PlaneWarper*) cvePlaneWarperCreate(cv::WarperCreator** warperCreator);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cvePlaneWarperCreate", "ptr*", $warperCreator), "cvePlaneWarperCreate", @error)
EndFunc   ;==>_cvePlaneWarperCreate

Func _cvePlaneWarperRelease(ByRef $warper)
    ; CVAPI(void) cvePlaneWarperRelease(cv::PlaneWarper** warper);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cvePlaneWarperRelease", "ptr*", $warper), "cvePlaneWarperRelease", @error)
EndFunc   ;==>_cvePlaneWarperRelease

Func _cveDetailCylindricalWarperCreate($scale, ByRef $rotationWarper)
    ; CVAPI(cv::detail::CylindricalWarper*) cveDetailCylindricalWarperCreate(float scale, cv::detail::RotationWarper** rotationWarper);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveDetailCylindricalWarperCreate", "float", $scale, "ptr*", $rotationWarper), "cveDetailCylindricalWarperCreate", @error)
EndFunc   ;==>_cveDetailCylindricalWarperCreate

Func _cveDetailCylindricalWarperRelease(ByRef $warper)
    ; CVAPI(void) cveDetailCylindricalWarperRelease(cv::detail::CylindricalWarper** warper);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDetailCylindricalWarperRelease", "ptr*", $warper), "cveDetailCylindricalWarperRelease", @error)
EndFunc   ;==>_cveDetailCylindricalWarperRelease

Func _cveCylindricalWarperCreate(ByRef $warperCreator)
    ; CVAPI(cv::CylindricalWarper*) cveCylindricalWarperCreate(cv::WarperCreator** warperCreator);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveCylindricalWarperCreate", "ptr*", $warperCreator), "cveCylindricalWarperCreate", @error)
EndFunc   ;==>_cveCylindricalWarperCreate

Func _cveCylindricalWarperRelease(ByRef $warper)
    ; CVAPI(void) cveCylindricalWarperRelease(cv::CylindricalWarper** warper);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCylindricalWarperRelease", "ptr*", $warper), "cveCylindricalWarperRelease", @error)
EndFunc   ;==>_cveCylindricalWarperRelease

Func _cveDetailSphericalWarperCreate($scale, ByRef $rotationWarper)
    ; CVAPI(cv::detail::SphericalWarper*) cveDetailSphericalWarperCreate(float scale, cv::detail::RotationWarper** rotationWarper);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveDetailSphericalWarperCreate", "float", $scale, "ptr*", $rotationWarper), "cveDetailSphericalWarperCreate", @error)
EndFunc   ;==>_cveDetailSphericalWarperCreate

Func _cveDetailSphericalWarperRelease(ByRef $warper)
    ; CVAPI(void) cveDetailSphericalWarperRelease(cv::detail::SphericalWarper** warper);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDetailSphericalWarperRelease", "ptr*", $warper), "cveDetailSphericalWarperRelease", @error)
EndFunc   ;==>_cveDetailSphericalWarperRelease

Func _cveSphericalWarperCreate(ByRef $warperCreator)
    ; CVAPI(cv::SphericalWarper*) cveSphericalWarperCreate(cv::WarperCreator** warperCreator);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveSphericalWarperCreate", "ptr*", $warperCreator), "cveSphericalWarperCreate", @error)
EndFunc   ;==>_cveSphericalWarperCreate

Func _cveSphericalWarperRelease(ByRef $warperCreator)
    ; CVAPI(void) cveSphericalWarperRelease(cv::SphericalWarper** warperCreator);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSphericalWarperRelease", "ptr*", $warperCreator), "cveSphericalWarperRelease", @error)
EndFunc   ;==>_cveSphericalWarperRelease

Func _cveDetailFisheyeWarperCreate($scale, ByRef $rotationWarper)
    ; CVAPI(cv::detail::FisheyeWarper*) cveDetailFisheyeWarperCreate(float scale, cv::detail::RotationWarper** rotationWarper);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveDetailFisheyeWarperCreate", "float", $scale, "ptr*", $rotationWarper), "cveDetailFisheyeWarperCreate", @error)
EndFunc   ;==>_cveDetailFisheyeWarperCreate

Func _cveDetailFisheyeWarperRelease(ByRef $warper)
    ; CVAPI(void) cveDetailFisheyeWarperRelease(cv::detail::FisheyeWarper** warper);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDetailFisheyeWarperRelease", "ptr*", $warper), "cveDetailFisheyeWarperRelease", @error)
EndFunc   ;==>_cveDetailFisheyeWarperRelease

Func _cveFisheyeWarperCreate(ByRef $warperCreator)
    ; CVAPI(cv::FisheyeWarper*) cveFisheyeWarperCreate(cv::WarperCreator** warperCreator);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveFisheyeWarperCreate", "ptr*", $warperCreator), "cveFisheyeWarperCreate", @error)
EndFunc   ;==>_cveFisheyeWarperCreate

Func _cveFisheyeWarperRelease(ByRef $warperCreator)
    ; CVAPI(void) cveFisheyeWarperRelease(cv::FisheyeWarper** warperCreator);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFisheyeWarperRelease", "ptr*", $warperCreator), "cveFisheyeWarperRelease", @error)
EndFunc   ;==>_cveFisheyeWarperRelease

Func _cveDetailStereographicWarperCreate($scale, ByRef $rotationWarper)
    ; CVAPI(cv::detail::StereographicWarper*) cveDetailStereographicWarperCreate(float scale, cv::detail::RotationWarper** rotationWarper);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveDetailStereographicWarperCreate", "float", $scale, "ptr*", $rotationWarper), "cveDetailStereographicWarperCreate", @error)
EndFunc   ;==>_cveDetailStereographicWarperCreate

Func _cveDetailStereographicWarperRelease(ByRef $warper)
    ; CVAPI(void) cveDetailStereographicWarperRelease(cv::detail::StereographicWarper** warper);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDetailStereographicWarperRelease", "ptr*", $warper), "cveDetailStereographicWarperRelease", @error)
EndFunc   ;==>_cveDetailStereographicWarperRelease

Func _cveStereographicWarperCreate(ByRef $warperCreator)
    ; CVAPI(cv::StereographicWarper*) cveStereographicWarperCreate(cv::WarperCreator** warperCreator);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveStereographicWarperCreate", "ptr*", $warperCreator), "cveStereographicWarperCreate", @error)
EndFunc   ;==>_cveStereographicWarperCreate

Func _cveStereographicWarperRelease(ByRef $warperCreator)
    ; CVAPI(void) cveStereographicWarperRelease(cv::StereographicWarper** warperCreator);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveStereographicWarperRelease", "ptr*", $warperCreator), "cveStereographicWarperRelease", @error)
EndFunc   ;==>_cveStereographicWarperRelease

Func _cveDetailCompressedRectilinearWarperCreate($scale, ByRef $rotationWarper)
    ; CVAPI(cv::detail::CompressedRectilinearWarper*) cveDetailCompressedRectilinearWarperCreate(float scale, cv::detail::RotationWarper** rotationWarper);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveDetailCompressedRectilinearWarperCreate", "float", $scale, "ptr*", $rotationWarper), "cveDetailCompressedRectilinearWarperCreate", @error)
EndFunc   ;==>_cveDetailCompressedRectilinearWarperCreate

Func _cveDetailCompressedRectilinearWarperRelease(ByRef $warper)
    ; CVAPI(void) cveDetailCompressedRectilinearWarperRelease(cv::detail::CompressedRectilinearWarper** warper);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDetailCompressedRectilinearWarperRelease", "ptr*", $warper), "cveDetailCompressedRectilinearWarperRelease", @error)
EndFunc   ;==>_cveDetailCompressedRectilinearWarperRelease

Func _cveCompressedRectilinearWarperCreate(ByRef $warperCreator)
    ; CVAPI(cv::CompressedRectilinearWarper*) cveCompressedRectilinearWarperCreate(cv::WarperCreator** warperCreator);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveCompressedRectilinearWarperCreate", "ptr*", $warperCreator), "cveCompressedRectilinearWarperCreate", @error)
EndFunc   ;==>_cveCompressedRectilinearWarperCreate

Func _cveCompressedRectilinearWarperRelease(ByRef $warperCreator)
    ; CVAPI(void) cveCompressedRectilinearWarperRelease(cv::CompressedRectilinearWarper** warperCreator);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCompressedRectilinearWarperRelease", "ptr*", $warperCreator), "cveCompressedRectilinearWarperRelease", @error)
EndFunc   ;==>_cveCompressedRectilinearWarperRelease

Func _cveDetailPaniniWarperCreate($scale, ByRef $rotationWarper)
    ; CVAPI(cv::detail::PaniniWarper*) cveDetailPaniniWarperCreate(float scale, cv::detail::RotationWarper** rotationWarper);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveDetailPaniniWarperCreate", "float", $scale, "ptr*", $rotationWarper), "cveDetailPaniniWarperCreate", @error)
EndFunc   ;==>_cveDetailPaniniWarperCreate

Func _cveDetailPaniniWarperRelease(ByRef $warper)
    ; CVAPI(void) cveDetailPaniniWarperRelease(cv::detail::PaniniWarper** warper);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDetailPaniniWarperRelease", "ptr*", $warper), "cveDetailPaniniWarperRelease", @error)
EndFunc   ;==>_cveDetailPaniniWarperRelease

Func _cvePaniniWarperCreate(ByRef $warperCreator)
    ; CVAPI(cv::PaniniWarper*) cvePaniniWarperCreate(cv::WarperCreator** warperCreator);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cvePaniniWarperCreate", "ptr*", $warperCreator), "cvePaniniWarperCreate", @error)
EndFunc   ;==>_cvePaniniWarperCreate

Func _cvePaniniWarperRelease(ByRef $warperCreator)
    ; CVAPI(void) cvePaniniWarperRelease(cv::PaniniWarper** warperCreator);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cvePaniniWarperRelease", "ptr*", $warperCreator), "cvePaniniWarperRelease", @error)
EndFunc   ;==>_cvePaniniWarperRelease

Func _cveDetailPaniniPortraitWarperCreate($scale, ByRef $rotationWarper)
    ; CVAPI(cv::detail::PaniniPortraitWarper*) cveDetailPaniniPortraitWarperCreate(float scale, cv::detail::RotationWarper** rotationWarper);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveDetailPaniniPortraitWarperCreate", "float", $scale, "ptr*", $rotationWarper), "cveDetailPaniniPortraitWarperCreate", @error)
EndFunc   ;==>_cveDetailPaniniPortraitWarperCreate

Func _cveDetailPaniniPortraitWarperRelease(ByRef $warper)
    ; CVAPI(void) cveDetailPaniniPortraitWarperRelease(cv::detail::PaniniPortraitWarper** warper);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDetailPaniniPortraitWarperRelease", "ptr*", $warper), "cveDetailPaniniPortraitWarperRelease", @error)
EndFunc   ;==>_cveDetailPaniniPortraitWarperRelease

Func _cvePaniniPortraitWarperCreate(ByRef $warperCreator)
    ; CVAPI(cv::PaniniPortraitWarper*) cvePaniniPortraitWarperCreate(cv::WarperCreator** warperCreator);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cvePaniniPortraitWarperCreate", "ptr*", $warperCreator), "cvePaniniPortraitWarperCreate", @error)
EndFunc   ;==>_cvePaniniPortraitWarperCreate

Func _cvePaniniPortraitWarperRelease(ByRef $warperCreator)
    ; CVAPI(void) cvePaniniPortraitWarperRelease(cv::PaniniPortraitWarper** warperCreator);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cvePaniniPortraitWarperRelease", "ptr*", $warperCreator), "cvePaniniPortraitWarperRelease", @error)
EndFunc   ;==>_cvePaniniPortraitWarperRelease

Func _cveDetailMercatorWarperCreate($scale, ByRef $rotationWarper)
    ; CVAPI(cv::detail::MercatorWarper*) cveDetailMercatorWarperCreate(float scale, cv::detail::RotationWarper** rotationWarper);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveDetailMercatorWarperCreate", "float", $scale, "ptr*", $rotationWarper), "cveDetailMercatorWarperCreate", @error)
EndFunc   ;==>_cveDetailMercatorWarperCreate

Func _cveDetailMercatorWarperRelease(ByRef $warper)
    ; CVAPI(void) cveDetailMercatorWarperRelease(cv::detail::MercatorWarper** warper);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDetailMercatorWarperRelease", "ptr*", $warper), "cveDetailMercatorWarperRelease", @error)
EndFunc   ;==>_cveDetailMercatorWarperRelease

Func _cveMercatorWarperCreate(ByRef $warperCreator)
    ; CVAPI(cv::MercatorWarper*) cveMercatorWarperCreate(cv::WarperCreator** warperCreator);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveMercatorWarperCreate", "ptr*", $warperCreator), "cveMercatorWarperCreate", @error)
EndFunc   ;==>_cveMercatorWarperCreate

Func _cveMercatorWarperRelease(ByRef $warperCreator)
    ; CVAPI(void) cveMercatorWarperRelease(cv::MercatorWarper** warperCreator);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMercatorWarperRelease", "ptr*", $warperCreator), "cveMercatorWarperRelease", @error)
EndFunc   ;==>_cveMercatorWarperRelease

Func _cveDetailTransverseMercatorWarperCreate($scale, ByRef $rotationWarper)
    ; CVAPI(cv::detail::TransverseMercatorWarper*) cveDetailTransverseMercatorWarperCreate(float scale, cv::detail::RotationWarper** rotationWarper);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveDetailTransverseMercatorWarperCreate", "float", $scale, "ptr*", $rotationWarper), "cveDetailTransverseMercatorWarperCreate", @error)
EndFunc   ;==>_cveDetailTransverseMercatorWarperCreate

Func _cveDetailTransverseMercatorWarperRelease(ByRef $warper)
    ; CVAPI(void) cveDetailTransverseMercatorWarperRelease(cv::detail::TransverseMercatorWarper** warper);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDetailTransverseMercatorWarperRelease", "ptr*", $warper), "cveDetailTransverseMercatorWarperRelease", @error)
EndFunc   ;==>_cveDetailTransverseMercatorWarperRelease

Func _cveTransverseMercatorWarperCreate(ByRef $warperCreator)
    ; CVAPI(cv::TransverseMercatorWarper*) cveTransverseMercatorWarperCreate(cv::WarperCreator** warperCreator);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveTransverseMercatorWarperCreate", "ptr*", $warperCreator), "cveTransverseMercatorWarperCreate", @error)
EndFunc   ;==>_cveTransverseMercatorWarperCreate

Func _cveTransverseMercatorWarperRelease(ByRef $warperCreator)
    ; CVAPI(void) cveTransverseMercatorWarperRelease(cv::TransverseMercatorWarper** warperCreator);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveTransverseMercatorWarperRelease", "ptr*", $warperCreator), "cveTransverseMercatorWarperRelease", @error)
EndFunc   ;==>_cveTransverseMercatorWarperRelease

Func _cveFeatherBlenderCreate($sharpness, ByRef $blender)
    ; CVAPI(cv::detail::FeatherBlender*) cveFeatherBlenderCreate(float sharpness, cv::detail::Blender** blender);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveFeatherBlenderCreate", "float", $sharpness, "ptr*", $blender), "cveFeatherBlenderCreate", @error)
EndFunc   ;==>_cveFeatherBlenderCreate

Func _cveFeatherBlenderRelease(ByRef $blender)
    ; CVAPI(void) cveFeatherBlenderRelease(cv::detail::FeatherBlender** blender);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFeatherBlenderRelease", "ptr*", $blender), "cveFeatherBlenderRelease", @error)
EndFunc   ;==>_cveFeatherBlenderRelease

Func _cveMultiBandBlenderCreate($tryGpu, $numBands, $weightType, ByRef $blender)
    ; CVAPI(cv::detail::MultiBandBlender*) cveMultiBandBlenderCreate(int tryGpu, int numBands, int weightType, cv::detail::Blender** blender);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveMultiBandBlenderCreate", "int", $tryGpu, "int", $numBands, "int", $weightType, "ptr*", $blender), "cveMultiBandBlenderCreate", @error)
EndFunc   ;==>_cveMultiBandBlenderCreate

Func _cveMultiBandBlenderRelease(ByRef $blender)
    ; CVAPI(void) cveMultiBandBlenderRelease(cv::detail::MultiBandBlender** blender);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMultiBandBlenderRelease", "ptr*", $blender), "cveMultiBandBlenderRelease", @error)
EndFunc   ;==>_cveMultiBandBlenderRelease

Func _cveNoExposureCompensatorCreate(ByRef $exposureCompensatorPtr)
    ; CVAPI(cv::detail::NoExposureCompensator*) cveNoExposureCompensatorCreate(cv::detail::ExposureCompensator** exposureCompensatorPtr);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveNoExposureCompensatorCreate", "ptr*", $exposureCompensatorPtr), "cveNoExposureCompensatorCreate", @error)
EndFunc   ;==>_cveNoExposureCompensatorCreate

Func _cveNoExposureCompensatorRelease(ByRef $compensator)
    ; CVAPI(void) cveNoExposureCompensatorRelease(cv::detail::NoExposureCompensator** compensator);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveNoExposureCompensatorRelease", "ptr*", $compensator), "cveNoExposureCompensatorRelease", @error)
EndFunc   ;==>_cveNoExposureCompensatorRelease

Func _cveGainCompensatorCreate($nrFeeds, ByRef $exposureCompensatorPtr)
    ; CVAPI(cv::detail::GainCompensator*) cveGainCompensatorCreate(int nrFeeds, cv::detail::ExposureCompensator** exposureCompensatorPtr);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGainCompensatorCreate", "int", $nrFeeds, "ptr*", $exposureCompensatorPtr), "cveGainCompensatorCreate", @error)
EndFunc   ;==>_cveGainCompensatorCreate

Func _cveGainCompensatorRelease(ByRef $compensator)
    ; CVAPI(void) cveGainCompensatorRelease(cv::detail::GainCompensator** compensator);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveGainCompensatorRelease", "ptr*", $compensator), "cveGainCompensatorRelease", @error)
EndFunc   ;==>_cveGainCompensatorRelease

Func _cveChannelsCompensatorCreate($nrFeeds, ByRef $exposureCompensatorPtr)
    ; CVAPI(cv::detail::ChannelsCompensator*) cveChannelsCompensatorCreate(int nrFeeds, cv::detail::ExposureCompensator** exposureCompensatorPtr);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveChannelsCompensatorCreate", "int", $nrFeeds, "ptr*", $exposureCompensatorPtr), "cveChannelsCompensatorCreate", @error)
EndFunc   ;==>_cveChannelsCompensatorCreate

Func _cveChannelsCompensatorRelease(ByRef $compensator)
    ; CVAPI(void) cveChannelsCompensatorRelease(cv::detail::ChannelsCompensator** compensator);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveChannelsCompensatorRelease", "ptr*", $compensator), "cveChannelsCompensatorRelease", @error)
EndFunc   ;==>_cveChannelsCompensatorRelease

Func _cveBlocksGainCompensatorCreate($blWidth, $blHeight, $nrFeeds, ByRef $exposureCompensatorPtr)
    ; CVAPI(cv::detail::BlocksGainCompensator*) cveBlocksGainCompensatorCreate(int blWidth, int blHeight, int nrFeeds, cv::detail::ExposureCompensator** exposureCompensatorPtr);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveBlocksGainCompensatorCreate", "int", $blWidth, "int", $blHeight, "int", $nrFeeds, "ptr*", $exposureCompensatorPtr), "cveBlocksGainCompensatorCreate", @error)
EndFunc   ;==>_cveBlocksGainCompensatorCreate

Func _cveBlocksGainCompensatorRelease(ByRef $compensator)
    ; CVAPI(void) cveBlocksGainCompensatorRelease(cv::detail::BlocksGainCompensator** compensator);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBlocksGainCompensatorRelease", "ptr*", $compensator), "cveBlocksGainCompensatorRelease", @error)
EndFunc   ;==>_cveBlocksGainCompensatorRelease

Func _cveBlocksChannelsCompensatorCreate($blWidth, $blHeight, $nrFeeds, ByRef $exposureCompensatorPtr)
    ; CVAPI(cv::detail::BlocksChannelsCompensator*) cveBlocksChannelsCompensatorCreate(int blWidth, int blHeight, int nrFeeds, cv::detail::ExposureCompensator** exposureCompensatorPtr);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveBlocksChannelsCompensatorCreate", "int", $blWidth, "int", $blHeight, "int", $nrFeeds, "ptr*", $exposureCompensatorPtr), "cveBlocksChannelsCompensatorCreate", @error)
EndFunc   ;==>_cveBlocksChannelsCompensatorCreate

Func _cveBlocksChannelsCompensatorRelease(ByRef $compensator)
    ; CVAPI(void) cveBlocksChannelsCompensatorRelease(cv::detail::BlocksChannelsCompensator** compensator);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBlocksChannelsCompensatorRelease", "ptr*", $compensator), "cveBlocksChannelsCompensatorRelease", @error)
EndFunc   ;==>_cveBlocksChannelsCompensatorRelease

Func _cveNoBundleAdjusterCreate(ByRef $bundleAdjusterBasePtr)
    ; CVAPI(cv::detail::NoBundleAdjuster*) cveNoBundleAdjusterCreate(cv::detail::BundleAdjusterBase** bundleAdjusterBasePtr);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveNoBundleAdjusterCreate", "ptr*", $bundleAdjusterBasePtr), "cveNoBundleAdjusterCreate", @error)
EndFunc   ;==>_cveNoBundleAdjusterCreate

Func _cveNoBundleAdjusterRelease(ByRef $bundleAdjuster)
    ; CVAPI(void) cveNoBundleAdjusterRelease(cv::detail::NoBundleAdjuster** bundleAdjuster);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveNoBundleAdjusterRelease", "ptr*", $bundleAdjuster), "cveNoBundleAdjusterRelease", @error)
EndFunc   ;==>_cveNoBundleAdjusterRelease

Func _cveBundleAdjusterReprojCreate(ByRef $bundleAdjusterBasePtr)
    ; CVAPI(cv::detail::BundleAdjusterReproj*) cveBundleAdjusterReprojCreate(cv::detail::BundleAdjusterBase** bundleAdjusterBasePtr);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveBundleAdjusterReprojCreate", "ptr*", $bundleAdjusterBasePtr), "cveBundleAdjusterReprojCreate", @error)
EndFunc   ;==>_cveBundleAdjusterReprojCreate

Func _cveBundleAdjusterReprojRelease(ByRef $bundleAdjuster)
    ; CVAPI(void) cveBundleAdjusterReprojRelease(cv::detail::BundleAdjusterReproj** bundleAdjuster);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBundleAdjusterReprojRelease", "ptr*", $bundleAdjuster), "cveBundleAdjusterReprojRelease", @error)
EndFunc   ;==>_cveBundleAdjusterReprojRelease

Func _cveBundleAdjusterRayCreate(ByRef $bundleAdjusterBasePtr)
    ; CVAPI(cv::detail::BundleAdjusterRay*) cveBundleAdjusterRayCreate(cv::detail::BundleAdjusterBase** bundleAdjusterBasePtr);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveBundleAdjusterRayCreate", "ptr*", $bundleAdjusterBasePtr), "cveBundleAdjusterRayCreate", @error)
EndFunc   ;==>_cveBundleAdjusterRayCreate

Func _cveBundleAdjusterRayRelease(ByRef $bundleAdjuster)
    ; CVAPI(void) cveBundleAdjusterRayRelease(cv::detail::BundleAdjusterRay** bundleAdjuster);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBundleAdjusterRayRelease", "ptr*", $bundleAdjuster), "cveBundleAdjusterRayRelease", @error)
EndFunc   ;==>_cveBundleAdjusterRayRelease

Func _cveBundleAdjusterAffineCreate(ByRef $bundleAdjusterBasePtr)
    ; CVAPI(cv::detail::BundleAdjusterAffine*) cveBundleAdjusterAffineCreate(cv::detail::BundleAdjusterBase** bundleAdjusterBasePtr);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveBundleAdjusterAffineCreate", "ptr*", $bundleAdjusterBasePtr), "cveBundleAdjusterAffineCreate", @error)
EndFunc   ;==>_cveBundleAdjusterAffineCreate

Func _cveBundleAdjusterAffineRelease(ByRef $bundleAdjuster)
    ; CVAPI(void) cveBundleAdjusterAffineRelease(cv::detail::BundleAdjusterAffine** bundleAdjuster);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBundleAdjusterAffineRelease", "ptr*", $bundleAdjuster), "cveBundleAdjusterAffineRelease", @error)
EndFunc   ;==>_cveBundleAdjusterAffineRelease

Func _cveBundleAdjusterAffinePartialCreate(ByRef $bundleAdjusterBasePtr)
    ; CVAPI(cv::detail::BundleAdjusterAffinePartial*) cveBundleAdjusterAffinePartialCreate(cv::detail::BundleAdjusterBase** bundleAdjusterBasePtr);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveBundleAdjusterAffinePartialCreate", "ptr*", $bundleAdjusterBasePtr), "cveBundleAdjusterAffinePartialCreate", @error)
EndFunc   ;==>_cveBundleAdjusterAffinePartialCreate

Func _cveBundleAdjusterAffinePartialRelease(ByRef $bundleAdjuster)
    ; CVAPI(void) cveBundleAdjusterAffinePartialRelease(cv::detail::BundleAdjusterAffinePartial** bundleAdjuster);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBundleAdjusterAffinePartialRelease", "ptr*", $bundleAdjuster), "cveBundleAdjusterAffinePartialRelease", @error)
EndFunc   ;==>_cveBundleAdjusterAffinePartialRelease

Func _cveNoSeamFinderCreate(ByRef $seamFinderPtr)
    ; CVAPI(cv::detail::NoSeamFinder*) cveNoSeamFinderCreate(cv::detail::SeamFinder** seamFinderPtr);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveNoSeamFinderCreate", "ptr*", $seamFinderPtr), "cveNoSeamFinderCreate", @error)
EndFunc   ;==>_cveNoSeamFinderCreate

Func _cveNoSeamFinderRelease(ByRef $seamFinder)
    ; CVAPI(void) cveNoSeamFinderRelease(cv::detail::NoSeamFinder** seamFinder);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveNoSeamFinderRelease", "ptr*", $seamFinder), "cveNoSeamFinderRelease", @error)
EndFunc   ;==>_cveNoSeamFinderRelease

Func _cveVoronoiSeamFinderCreate(ByRef $seamFinderPtr)
    ; CVAPI(cv::detail::VoronoiSeamFinder*) cveVoronoiSeamFinderCreate(cv::detail::SeamFinder** seamFinderPtr);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveVoronoiSeamFinderCreate", "ptr*", $seamFinderPtr), "cveVoronoiSeamFinderCreate", @error)
EndFunc   ;==>_cveVoronoiSeamFinderCreate

Func _cveVoronoiSeamFinderRelease(ByRef $seamFinder)
    ; CVAPI(void) cveVoronoiSeamFinderRelease(cv::detail::VoronoiSeamFinder** seamFinder);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveVoronoiSeamFinderRelease", "ptr*", $seamFinder), "cveVoronoiSeamFinderRelease", @error)
EndFunc   ;==>_cveVoronoiSeamFinderRelease

Func _cveDpSeamFinderCreate($costFunc, ByRef $seamFinderPtr)
    ; CVAPI(cv::detail::DpSeamFinder*) cveDpSeamFinderCreate(int costFunc, cv::detail::SeamFinder** seamFinderPtr);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveDpSeamFinderCreate", "int", $costFunc, "ptr*", $seamFinderPtr), "cveDpSeamFinderCreate", @error)
EndFunc   ;==>_cveDpSeamFinderCreate

Func _cveDpSeamFinderRelease(ByRef $seamFinder)
    ; CVAPI(void) cveDpSeamFinderRelease(cv::detail::DpSeamFinder** seamFinder);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDpSeamFinderRelease", "ptr*", $seamFinder), "cveDpSeamFinderRelease", @error)
EndFunc   ;==>_cveDpSeamFinderRelease

Func _cveGraphCutSeamFinderCreate($costType, $terminalCost, $badRegionPenalty, ByRef $seamFinderPtr)
    ; CVAPI(cv::detail::GraphCutSeamFinder*) cveGraphCutSeamFinderCreate(int costType, float terminalCost, float badRegionPenalty, cv::detail::SeamFinder** seamFinderPtr);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGraphCutSeamFinderCreate", "int", $costType, "float", $terminalCost, "float", $badRegionPenalty, "ptr*", $seamFinderPtr), "cveGraphCutSeamFinderCreate", @error)
EndFunc   ;==>_cveGraphCutSeamFinderCreate

Func _cveGraphCutSeamFinderRelease(ByRef $seamFinder)
    ; CVAPI(void) cveGraphCutSeamFinderRelease(cv::detail::GraphCutSeamFinder** seamFinder);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveGraphCutSeamFinderRelease", "ptr*", $seamFinder), "cveGraphCutSeamFinderRelease", @error)
EndFunc   ;==>_cveGraphCutSeamFinderRelease

Func _cveHomographyBasedEstimatorCreate($isFocalsEstimated, ByRef $estimatorPtr)
    ; CVAPI(cv::detail::HomographyBasedEstimator*) cveHomographyBasedEstimatorCreate(bool isFocalsEstimated, cv::detail::Estimator** estimatorPtr);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveHomographyBasedEstimatorCreate", "boolean", $isFocalsEstimated, "ptr*", $estimatorPtr), "cveHomographyBasedEstimatorCreate", @error)
EndFunc   ;==>_cveHomographyBasedEstimatorCreate

Func _cveHomographyBasedEstimatorRelease(ByRef $estimator)
    ; CVAPI(void) cveHomographyBasedEstimatorRelease(cv::detail::HomographyBasedEstimator** estimator);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveHomographyBasedEstimatorRelease", "ptr*", $estimator), "cveHomographyBasedEstimatorRelease", @error)
EndFunc   ;==>_cveHomographyBasedEstimatorRelease

Func _cveAffineBasedEstimatorCreate(ByRef $estimatorPtr)
    ; CVAPI(cv::detail::AffineBasedEstimator*) cveAffineBasedEstimatorCreate(cv::detail::Estimator** estimatorPtr);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveAffineBasedEstimatorCreate", "ptr*", $estimatorPtr), "cveAffineBasedEstimatorCreate", @error)
EndFunc   ;==>_cveAffineBasedEstimatorCreate

Func _cveAffineBasedEstimatorRelease(ByRef $estimator)
    ; CVAPI(void) cveAffineBasedEstimatorRelease(cv::detail::AffineBasedEstimator** estimator);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveAffineBasedEstimatorRelease", "ptr*", $estimator), "cveAffineBasedEstimatorRelease", @error)
EndFunc   ;==>_cveAffineBasedEstimatorRelease

Func _cveBestOf2NearestMatcherCreate($tryUseGpu, $matchConf, $numMatchesThresh1, $numMatchesThresh2, ByRef $featuresMatcher)
    ; CVAPI(cv::detail::BestOf2NearestMatcher*) cveBestOf2NearestMatcherCreate(bool tryUseGpu, float matchConf, int numMatchesThresh1, int numMatchesThresh2, cv::detail::FeaturesMatcher** featuresMatcher);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveBestOf2NearestMatcherCreate", "boolean", $tryUseGpu, "float", $matchConf, "int", $numMatchesThresh1, "int", $numMatchesThresh2, "ptr*", $featuresMatcher), "cveBestOf2NearestMatcherCreate", @error)
EndFunc   ;==>_cveBestOf2NearestMatcherCreate

Func _cveBestOf2NearestMatcherRelease(ByRef $featuresMatcher)
    ; CVAPI(void) cveBestOf2NearestMatcherRelease(cv::detail::BestOf2NearestMatcher** featuresMatcher);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBestOf2NearestMatcherRelease", "ptr*", $featuresMatcher), "cveBestOf2NearestMatcherRelease", @error)
EndFunc   ;==>_cveBestOf2NearestMatcherRelease

Func _cveBestOf2NearestRangeMatcherCreate($rangeWidth, $tryUseGpu, $matchConf, $numMatchesThresh1, $numMatchesThresh2, ByRef $featuresMatcher)
    ; CVAPI(cv::detail::BestOf2NearestRangeMatcher*) cveBestOf2NearestRangeMatcherCreate(int rangeWidth, bool tryUseGpu, float matchConf, int numMatchesThresh1, int numMatchesThresh2, cv::detail::FeaturesMatcher** featuresMatcher);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveBestOf2NearestRangeMatcherCreate", "int", $rangeWidth, "boolean", $tryUseGpu, "float", $matchConf, "int", $numMatchesThresh1, "int", $numMatchesThresh2, "ptr*", $featuresMatcher), "cveBestOf2NearestRangeMatcherCreate", @error)
EndFunc   ;==>_cveBestOf2NearestRangeMatcherCreate

Func _cveBestOf2NearestRangeMatcherRelease(ByRef $featuresMatcher)
    ; CVAPI(void) cveBestOf2NearestRangeMatcherRelease(cv::detail::BestOf2NearestRangeMatcher** featuresMatcher);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBestOf2NearestRangeMatcherRelease", "ptr*", $featuresMatcher), "cveBestOf2NearestRangeMatcherRelease", @error)
EndFunc   ;==>_cveBestOf2NearestRangeMatcherRelease

Func _cveAffineBestOf2NearestMatcherCreate($fullAffine, $tryUseGpu, $matchConf, $numMatchesThresh1, ByRef $featuresMatcher)
    ; CVAPI(cv::detail::AffineBestOf2NearestMatcher*) cveAffineBestOf2NearestMatcherCreate(bool fullAffine, bool tryUseGpu, float matchConf, int numMatchesThresh1, cv::detail::FeaturesMatcher** featuresMatcher);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveAffineBestOf2NearestMatcherCreate", "boolean", $fullAffine, "boolean", $tryUseGpu, "float", $matchConf, "int", $numMatchesThresh1, "ptr*", $featuresMatcher), "cveAffineBestOf2NearestMatcherCreate", @error)
EndFunc   ;==>_cveAffineBestOf2NearestMatcherCreate

Func _cveAffineBestOf2NearestMatcherRelease(ByRef $featuresMatcher)
    ; CVAPI(void) cveAffineBestOf2NearestMatcherRelease(cv::detail::AffineBestOf2NearestMatcher** featuresMatcher);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveAffineBestOf2NearestMatcherRelease", "ptr*", $featuresMatcher), "cveAffineBestOf2NearestMatcherRelease", @error)
EndFunc   ;==>_cveAffineBestOf2NearestMatcherRelease

Func _cveDetailPlaneWarperGpuCreate($scale, ByRef $rotationWarper)
    ; CVAPI(cv::detail::PlaneWarperGpu*) cveDetailPlaneWarperGpuCreate(float scale, cv::detail::RotationWarper** rotationWarper);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveDetailPlaneWarperGpuCreate", "float", $scale, "ptr*", $rotationWarper), "cveDetailPlaneWarperGpuCreate", @error)
EndFunc   ;==>_cveDetailPlaneWarperGpuCreate

Func _cveDetailPlaneWarperGpuRelease(ByRef $warper)
    ; CVAPI(void) cveDetailPlaneWarperGpuRelease(cv::detail::PlaneWarperGpu** warper);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDetailPlaneWarperGpuRelease", "ptr*", $warper), "cveDetailPlaneWarperGpuRelease", @error)
EndFunc   ;==>_cveDetailPlaneWarperGpuRelease

Func _cvePlaneWarperGpuCreate(ByRef $warperCreator)
    ; CVAPI(cv::PlaneWarperGpu*) cvePlaneWarperGpuCreate(cv::WarperCreator** warperCreator);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cvePlaneWarperGpuCreate", "ptr*", $warperCreator), "cvePlaneWarperGpuCreate", @error)
EndFunc   ;==>_cvePlaneWarperGpuCreate

Func _cvePlaneWarperGpuRelease(ByRef $warperCreator)
    ; CVAPI(void) cvePlaneWarperGpuRelease(cv::PlaneWarperGpu** warperCreator);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cvePlaneWarperGpuRelease", "ptr*", $warperCreator), "cvePlaneWarperGpuRelease", @error)
EndFunc   ;==>_cvePlaneWarperGpuRelease

Func _cveDetailCylindricalWarperGpuCreate($scale, ByRef $rotationWarper)
    ; CVAPI(cv::detail::CylindricalWarperGpu*) cveDetailCylindricalWarperGpuCreate(float scale, cv::detail::RotationWarper** rotationWarper);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveDetailCylindricalWarperGpuCreate", "float", $scale, "ptr*", $rotationWarper), "cveDetailCylindricalWarperGpuCreate", @error)
EndFunc   ;==>_cveDetailCylindricalWarperGpuCreate

Func _cveDetailCylindricalWarperGpuRelease(ByRef $warper)
    ; CVAPI(void) cveDetailCylindricalWarperGpuRelease(cv::detail::CylindricalWarperGpu** warper);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDetailCylindricalWarperGpuRelease", "ptr*", $warper), "cveDetailCylindricalWarperGpuRelease", @error)
EndFunc   ;==>_cveDetailCylindricalWarperGpuRelease

Func _cveCylindricalWarperGpuCreate(ByRef $warperCreator)
    ; CVAPI(cv::CylindricalWarperGpu*) cveCylindricalWarperGpuCreate(cv::WarperCreator** warperCreator);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveCylindricalWarperGpuCreate", "ptr*", $warperCreator), "cveCylindricalWarperGpuCreate", @error)
EndFunc   ;==>_cveCylindricalWarperGpuCreate

Func _cveCylindricalWarperGpuRelease(ByRef $warperCreator)
    ; CVAPI(void) cveCylindricalWarperGpuRelease(cv::CylindricalWarperGpu** warperCreator);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCylindricalWarperGpuRelease", "ptr*", $warperCreator), "cveCylindricalWarperGpuRelease", @error)
EndFunc   ;==>_cveCylindricalWarperGpuRelease

Func _cveDetailSphericalWarperGpuCreate($scale, ByRef $rotationWarper)
    ; CVAPI(cv::detail::SphericalWarperGpu*) cveDetailSphericalWarperGpuCreate(float scale, cv::detail::RotationWarper** rotationWarper);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveDetailSphericalWarperGpuCreate", "float", $scale, "ptr*", $rotationWarper), "cveDetailSphericalWarperGpuCreate", @error)
EndFunc   ;==>_cveDetailSphericalWarperGpuCreate

Func _cveDetailSphericalWarperGpuRelease(ByRef $warper)
    ; CVAPI(void) cveDetailSphericalWarperGpuRelease(cv::detail::SphericalWarperGpu** warper);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDetailSphericalWarperGpuRelease", "ptr*", $warper), "cveDetailSphericalWarperGpuRelease", @error)
EndFunc   ;==>_cveDetailSphericalWarperGpuRelease

Func _cveSphericalWarperGpuCreate(ByRef $warperCreator)
    ; CVAPI(cv::SphericalWarperGpu*) cveSphericalWarperGpuCreate(cv::WarperCreator** warperCreator);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveSphericalWarperGpuCreate", "ptr*", $warperCreator), "cveSphericalWarperGpuCreate", @error)
EndFunc   ;==>_cveSphericalWarperGpuCreate

Func _cveSphericalWarperGpuRelease(ByRef $warper)
    ; CVAPI(void) cveSphericalWarperGpuRelease(cv::SphericalWarperGpu** warper);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSphericalWarperGpuRelease", "ptr*", $warper), "cveSphericalWarperGpuRelease", @error)
EndFunc   ;==>_cveSphericalWarperGpuRelease