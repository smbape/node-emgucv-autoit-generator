#include-once
#include "..\..\CVEUtils.au3"

Func _cveERFilterNM1Create($classifier, $thresholdDelta, $minArea, $maxArea, $minProbability, $nonMaxSuppression, $minProbabilityDiff, ByRef $sharedPtr)
    ; CVAPI(cv::text::ERFilter*) cveERFilterNM1Create(cv::String* classifier, int thresholdDelta, float minArea, float maxArea, float minProbability, bool nonMaxSuppression, float minProbabilityDiff, cv::Ptr<cv::text::ERFilter>** sharedPtr);

    Local $bClassifierIsString = VarGetType($classifier) == "String"
    If $bClassifierIsString Then
        $classifier = _cveStringCreateFromStr($classifier)
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveERFilterNM1Create", "ptr", $classifier, "int", $thresholdDelta, "float", $minArea, "float", $maxArea, "float", $minProbability, "boolean", $nonMaxSuppression, "float", $minProbabilityDiff, "ptr*", $sharedPtr), "cveERFilterNM1Create", @error)

    If $bClassifierIsString Then
        _cveStringRelease($classifier)
    EndIf

    Return $retval
EndFunc   ;==>_cveERFilterNM1Create

Func _cveERFilterNM2Create($classifier, $minProbability, ByRef $sharedPtr)
    ; CVAPI(cv::text::ERFilter*) cveERFilterNM2Create(cv::String* classifier, float minProbability, cv::Ptr<cv::text::ERFilter>** sharedPtr);

    Local $bClassifierIsString = VarGetType($classifier) == "String"
    If $bClassifierIsString Then
        $classifier = _cveStringCreateFromStr($classifier)
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveERFilterNM2Create", "ptr", $classifier, "float", $minProbability, "ptr*", $sharedPtr), "cveERFilterNM2Create", @error)

    If $bClassifierIsString Then
        _cveStringRelease($classifier)
    EndIf

    Return $retval
EndFunc   ;==>_cveERFilterNM2Create

Func _cveERFilterRelease(ByRef $sharedPtr)
    ; CVAPI(void) cveERFilterRelease(cv::Ptr<cv::text::ERFilter>** sharedPtr);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveERFilterRelease", "ptr*", $sharedPtr), "cveERFilterRelease", @error)
EndFunc   ;==>_cveERFilterRelease

Func _cveERFilterRun(ByRef $filter, ByRef $image, ByRef $regions)
    ; CVAPI(void) cveERFilterRun(cv::text::ERFilter* filter, cv::_InputArray* image, std::vector<cv::text::ERStat>* regions);

    Local $vecRegions, $iArrRegionsSize
    Local $bRegionsIsArray = VarGetType($regions) == "Array"

    If $bRegionsIsArray Then
        $vecRegions = _VectorOfERStatCreate()

        $iArrRegionsSize = UBound($regions)
        For $i = 0 To $iArrRegionsSize - 1
            _VectorOfERStatPush($vecRegions, $regions[$i])
        Next
    Else
        $vecRegions = $regions
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveERFilterRun", "ptr", $filter, "ptr", $image, "ptr", $vecRegions), "cveERFilterRun", @error)

    If $bRegionsIsArray Then
        _VectorOfERStatRelease($vecRegions)
    EndIf
EndFunc   ;==>_cveERFilterRun

Func _cveERFilterRunMat(ByRef $filter, ByRef $matImage, ByRef $regions)
    ; cveERFilterRun using cv::Mat instead of _*Array

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

    _cveERFilterRun($filter, $iArrImage, $regions)

    If $bImageIsArray Then
        _VectorOfMatRelease($vectorOfMatImage)
    EndIf

    _cveInputArrayRelease($iArrImage)
EndFunc   ;==>_cveERFilterRunMat

Func _cveERGrouping(ByRef $image, ByRef $channels, ByRef $regions, $count, ByRef $groups, ByRef $group_rects, $method, $fileName, $minProbability)
    ; CVAPI(void) cveERGrouping(cv::_InputArray* image, cv::_InputArray* channels, std::vector<cv::text::ERStat>** regions, int count, std::vector< std::vector<cv::Vec2i> >* groups, std::vector<cv::Rect>* group_rects, int method, cv::String* fileName, float minProbability);

    Local $vecRegions, $iArrRegionsSize
    Local $bRegionsIsArray = VarGetType($regions) == "Array"

    If $bRegionsIsArray Then
        $vecRegions = _VectorOfERStatCreate()

        $iArrRegionsSize = UBound($regions)
        For $i = 0 To $iArrRegionsSize - 1
            _VectorOfERStatPush($vecRegions, $regions[$i])
        Next
    Else
        $vecRegions = $regions
    EndIf

    Local $vecGroup_rects, $iArrGroup_rectsSize
    Local $bGroup_rectsIsArray = VarGetType($group_rects) == "Array"

    If $bGroup_rectsIsArray Then
        $vecGroup_rects = _VectorOfRectCreate()

        $iArrGroup_rectsSize = UBound($group_rects)
        For $i = 0 To $iArrGroup_rectsSize - 1
            _VectorOfRectPush($vecGroup_rects, $group_rects[$i])
        Next
    Else
        $vecGroup_rects = $group_rects
    EndIf

    Local $bFileNameIsString = VarGetType($fileName) == "String"
    If $bFileNameIsString Then
        $fileName = _cveStringCreateFromStr($fileName)
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveERGrouping", "ptr", $image, "ptr", $channels, "ptr*", $vecRegions, "int", $count, "ptr", $groups, "ptr", $vecGroup_rects, "int", $method, "ptr", $fileName, "float", $minProbability), "cveERGrouping", @error)

    If $bFileNameIsString Then
        _cveStringRelease($fileName)
    EndIf

    If $bGroup_rectsIsArray Then
        _VectorOfRectRelease($vecGroup_rects)
    EndIf

    If $bRegionsIsArray Then
        _VectorOfERStatRelease($vecRegions)
    EndIf
EndFunc   ;==>_cveERGrouping

Func _cveERGroupingMat(ByRef $matImage, ByRef $matChannels, ByRef $regions, $count, ByRef $groups, ByRef $group_rects, $method, $fileName, $minProbability)
    ; cveERGrouping using cv::Mat instead of _*Array

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

    Local $iArrChannels, $vectorOfMatChannels, $iArrChannelsSize
    Local $bChannelsIsArray = VarGetType($matChannels) == "Array"

    If $bChannelsIsArray Then
        $vectorOfMatChannels = _VectorOfMatCreate()

        $iArrChannelsSize = UBound($matChannels)
        For $i = 0 To $iArrChannelsSize - 1
            _VectorOfMatPush($vectorOfMatChannels, $matChannels[$i])
        Next

        $iArrChannels = _cveInputArrayFromVectorOfMat($vectorOfMatChannels)
    Else
        $iArrChannels = _cveInputArrayFromMat($matChannels)
    EndIf

    _cveERGrouping($iArrImage, $iArrChannels, $regions, $count, $groups, $group_rects, $method, $fileName, $minProbability)

    If $bChannelsIsArray Then
        _VectorOfMatRelease($vectorOfMatChannels)
    EndIf

    _cveInputArrayRelease($iArrChannels)

    If $bImageIsArray Then
        _VectorOfMatRelease($vectorOfMatImage)
    EndIf

    _cveInputArrayRelease($iArrImage)
EndFunc   ;==>_cveERGroupingMat

Func _cveMSERsToERStats(ByRef $image, ByRef $contours, ByRef $regions)
    ; CVAPI(void) cveMSERsToERStats(cv::_InputArray* image, std::vector< std::vector< cv::Point > >* contours, std::vector< std::vector< cv::text::ERStat> >* regions);

    Local $vecContours, $iArrContoursSize
    Local $bContoursIsArray = VarGetType($contours) == "Array"

    If $bContoursIsArray Then
        $vecContours = _VectorOfVectorOfPointCreate()

        $iArrContoursSize = UBound($contours)
        For $i = 0 To $iArrContoursSize - 1
            _VectorOfVectorOfPointPush($vecContours, $contours[$i])
        Next
    Else
        $vecContours = $contours
    EndIf

    Local $vecRegions, $iArrRegionsSize
    Local $bRegionsIsArray = VarGetType($regions) == "Array"

    If $bRegionsIsArray Then
        $vecRegions = _VectorOfVectorOfERStatCreate()

        $iArrRegionsSize = UBound($regions)
        For $i = 0 To $iArrRegionsSize - 1
            _VectorOfVectorOfERStatPush($vecRegions, $regions[$i])
        Next
    Else
        $vecRegions = $regions
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMSERsToERStats", "ptr", $image, "ptr", $vecContours, "ptr", $vecRegions), "cveMSERsToERStats", @error)

    If $bRegionsIsArray Then
        _VectorOfVectorOfERStatRelease($vecRegions)
    EndIf

    If $bContoursIsArray Then
        _VectorOfVectorOfPointRelease($vecContours)
    EndIf
EndFunc   ;==>_cveMSERsToERStats

Func _cveMSERsToERStatsMat(ByRef $matImage, ByRef $contours, ByRef $regions)
    ; cveMSERsToERStats using cv::Mat instead of _*Array

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

    _cveMSERsToERStats($iArrImage, $contours, $regions)

    If $bImageIsArray Then
        _VectorOfMatRelease($vectorOfMatImage)
    EndIf

    _cveInputArrayRelease($iArrImage)
EndFunc   ;==>_cveMSERsToERStatsMat

Func _cveComputeNMChannels(ByRef $src, ByRef $channels, $mode)
    ; CVAPI(void) cveComputeNMChannels(cv::_InputArray* src, cv::_OutputArray* channels, int mode);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveComputeNMChannels", "ptr", $src, "ptr", $channels, "int", $mode), "cveComputeNMChannels", @error)
EndFunc   ;==>_cveComputeNMChannels

Func _cveComputeNMChannelsMat(ByRef $matSrc, ByRef $matChannels, $mode)
    ; cveComputeNMChannels using cv::Mat instead of _*Array

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

    Local $oArrChannels, $vectorOfMatChannels, $iArrChannelsSize
    Local $bChannelsIsArray = VarGetType($matChannels) == "Array"

    If $bChannelsIsArray Then
        $vectorOfMatChannels = _VectorOfMatCreate()

        $iArrChannelsSize = UBound($matChannels)
        For $i = 0 To $iArrChannelsSize - 1
            _VectorOfMatPush($vectorOfMatChannels, $matChannels[$i])
        Next

        $oArrChannels = _cveOutputArrayFromVectorOfMat($vectorOfMatChannels)
    Else
        $oArrChannels = _cveOutputArrayFromMat($matChannels)
    EndIf

    _cveComputeNMChannels($iArrSrc, $oArrChannels, $mode)

    If $bChannelsIsArray Then
        _VectorOfMatRelease($vectorOfMatChannels)
    EndIf

    _cveOutputArrayRelease($oArrChannels)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)
EndFunc   ;==>_cveComputeNMChannelsMat

Func _cveTextDetectorCNNCreate($modelArchFilename, $modelWeightsFilename, ByRef $sharedPtr)
    ; CVAPI(cv::text::TextDetectorCNN*) cveTextDetectorCNNCreate(cv::String* modelArchFilename, cv::String* modelWeightsFilename, cv::Ptr<cv::text::TextDetectorCNN>** sharedPtr);

    Local $bModelArchFilenameIsString = VarGetType($modelArchFilename) == "String"
    If $bModelArchFilenameIsString Then
        $modelArchFilename = _cveStringCreateFromStr($modelArchFilename)
    EndIf

    Local $bModelWeightsFilenameIsString = VarGetType($modelWeightsFilename) == "String"
    If $bModelWeightsFilenameIsString Then
        $modelWeightsFilename = _cveStringCreateFromStr($modelWeightsFilename)
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveTextDetectorCNNCreate", "ptr", $modelArchFilename, "ptr", $modelWeightsFilename, "ptr*", $sharedPtr), "cveTextDetectorCNNCreate", @error)

    If $bModelWeightsFilenameIsString Then
        _cveStringRelease($modelWeightsFilename)
    EndIf

    If $bModelArchFilenameIsString Then
        _cveStringRelease($modelArchFilename)
    EndIf

    Return $retval
EndFunc   ;==>_cveTextDetectorCNNCreate

Func _cveTextDetectorCNNCreate2($modelArchFilename, $modelWeightsFilename, ByRef $detectionSizes, ByRef $sharedPtr)
    ; CVAPI(cv::text::TextDetectorCNN*) cveTextDetectorCNNCreate2(cv::String* modelArchFilename, cv::String* modelWeightsFilename, std::vector<cv::Size>* detectionSizes, cv::Ptr<cv::text::TextDetectorCNN>** sharedPtr);

    Local $bModelArchFilenameIsString = VarGetType($modelArchFilename) == "String"
    If $bModelArchFilenameIsString Then
        $modelArchFilename = _cveStringCreateFromStr($modelArchFilename)
    EndIf

    Local $bModelWeightsFilenameIsString = VarGetType($modelWeightsFilename) == "String"
    If $bModelWeightsFilenameIsString Then
        $modelWeightsFilename = _cveStringCreateFromStr($modelWeightsFilename)
    EndIf

    Local $vecDetectionSizes, $iArrDetectionSizesSize
    Local $bDetectionSizesIsArray = VarGetType($detectionSizes) == "Array"

    If $bDetectionSizesIsArray Then
        $vecDetectionSizes = _VectorOfSizeCreate()

        $iArrDetectionSizesSize = UBound($detectionSizes)
        For $i = 0 To $iArrDetectionSizesSize - 1
            _VectorOfSizePush($vecDetectionSizes, $detectionSizes[$i])
        Next
    Else
        $vecDetectionSizes = $detectionSizes
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveTextDetectorCNNCreate2", "ptr", $modelArchFilename, "ptr", $modelWeightsFilename, "ptr", $vecDetectionSizes, "ptr*", $sharedPtr), "cveTextDetectorCNNCreate2", @error)

    If $bDetectionSizesIsArray Then
        _VectorOfSizeRelease($vecDetectionSizes)
    EndIf

    If $bModelWeightsFilenameIsString Then
        _cveStringRelease($modelWeightsFilename)
    EndIf

    If $bModelArchFilenameIsString Then
        _cveStringRelease($modelArchFilename)
    EndIf

    Return $retval
EndFunc   ;==>_cveTextDetectorCNNCreate2

Func _cveTextDetectorCNNDetect(ByRef $detector, ByRef $inputImage, ByRef $bbox, ByRef $confidence)
    ; CVAPI(void) cveTextDetectorCNNDetect(cv::text::TextDetectorCNN* detector, cv::_InputArray* inputImage, std::vector<cv::Rect>* bbox, std::vector<float>* confidence);

    Local $vecBbox, $iArrBboxSize
    Local $bBboxIsArray = VarGetType($bbox) == "Array"

    If $bBboxIsArray Then
        $vecBbox = _VectorOfRectCreate()

        $iArrBboxSize = UBound($bbox)
        For $i = 0 To $iArrBboxSize - 1
            _VectorOfRectPush($vecBbox, $bbox[$i])
        Next
    Else
        $vecBbox = $bbox
    EndIf

    Local $vecConfidence, $iArrConfidenceSize
    Local $bConfidenceIsArray = VarGetType($confidence) == "Array"

    If $bConfidenceIsArray Then
        $vecConfidence = _VectorOfFloatCreate()

        $iArrConfidenceSize = UBound($confidence)
        For $i = 0 To $iArrConfidenceSize - 1
            _VectorOfFloatPush($vecConfidence, $confidence[$i])
        Next
    Else
        $vecConfidence = $confidence
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveTextDetectorCNNDetect", "ptr", $detector, "ptr", $inputImage, "ptr", $vecBbox, "ptr", $vecConfidence), "cveTextDetectorCNNDetect", @error)

    If $bConfidenceIsArray Then
        _VectorOfFloatRelease($vecConfidence)
    EndIf

    If $bBboxIsArray Then
        _VectorOfRectRelease($vecBbox)
    EndIf
EndFunc   ;==>_cveTextDetectorCNNDetect

Func _cveTextDetectorCNNDetectMat(ByRef $detector, ByRef $matInputImage, ByRef $bbox, ByRef $confidence)
    ; cveTextDetectorCNNDetect using cv::Mat instead of _*Array

    Local $iArrInputImage, $vectorOfMatInputImage, $iArrInputImageSize
    Local $bInputImageIsArray = VarGetType($matInputImage) == "Array"

    If $bInputImageIsArray Then
        $vectorOfMatInputImage = _VectorOfMatCreate()

        $iArrInputImageSize = UBound($matInputImage)
        For $i = 0 To $iArrInputImageSize - 1
            _VectorOfMatPush($vectorOfMatInputImage, $matInputImage[$i])
        Next

        $iArrInputImage = _cveInputArrayFromVectorOfMat($vectorOfMatInputImage)
    Else
        $iArrInputImage = _cveInputArrayFromMat($matInputImage)
    EndIf

    _cveTextDetectorCNNDetect($detector, $iArrInputImage, $bbox, $confidence)

    If $bInputImageIsArray Then
        _VectorOfMatRelease($vectorOfMatInputImage)
    EndIf

    _cveInputArrayRelease($iArrInputImage)
EndFunc   ;==>_cveTextDetectorCNNDetectMat

Func _cveTextDetectorCNNRelease(ByRef $sharedPtr)
    ; CVAPI(void) cveTextDetectorCNNRelease(cv::Ptr<cv::text::TextDetectorCNN>** sharedPtr);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveTextDetectorCNNRelease", "ptr*", $sharedPtr), "cveTextDetectorCNNRelease", @error)
EndFunc   ;==>_cveTextDetectorCNNRelease