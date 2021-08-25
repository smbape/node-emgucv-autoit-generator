#include-once
#include "..\..\CVEUtils.au3"

Func _cveERFilterNM1Create($classifier, $thresholdDelta, $minArea, $maxArea, $minProbability, $nonMaxSuppression, $minProbabilityDiff, $sharedPtr)
    ; CVAPI(cv::text::ERFilter*) cveERFilterNM1Create(cv::String* classifier, int thresholdDelta, float minArea, float maxArea, float minProbability, bool nonMaxSuppression, float minProbabilityDiff, cv::Ptr<cv::text::ERFilter>** sharedPtr);

    Local $bClassifierIsString = IsString($classifier)
    If $bClassifierIsString Then
        $classifier = _cveStringCreateFromStr($classifier)
    EndIf

    Local $sClassifierDllType
    If IsDllStruct($classifier) Then
        $sClassifierDllType = "struct*"
    Else
        $sClassifierDllType = "ptr"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveERFilterNM1Create", $sClassifierDllType, $classifier, "int", $thresholdDelta, "float", $minArea, "float", $maxArea, "float", $minProbability, "boolean", $nonMaxSuppression, "float", $minProbabilityDiff, $sSharedPtrDllType, $sharedPtr), "cveERFilterNM1Create", @error)

    If $bClassifierIsString Then
        _cveStringRelease($classifier)
    EndIf

    Return $retval
EndFunc   ;==>_cveERFilterNM1Create

Func _cveERFilterNM2Create($classifier, $minProbability, $sharedPtr)
    ; CVAPI(cv::text::ERFilter*) cveERFilterNM2Create(cv::String* classifier, float minProbability, cv::Ptr<cv::text::ERFilter>** sharedPtr);

    Local $bClassifierIsString = IsString($classifier)
    If $bClassifierIsString Then
        $classifier = _cveStringCreateFromStr($classifier)
    EndIf

    Local $sClassifierDllType
    If IsDllStruct($classifier) Then
        $sClassifierDllType = "struct*"
    Else
        $sClassifierDllType = "ptr"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveERFilterNM2Create", $sClassifierDllType, $classifier, "float", $minProbability, $sSharedPtrDllType, $sharedPtr), "cveERFilterNM2Create", @error)

    If $bClassifierIsString Then
        _cveStringRelease($classifier)
    EndIf

    Return $retval
EndFunc   ;==>_cveERFilterNM2Create

Func _cveERFilterRelease($sharedPtr)
    ; CVAPI(void) cveERFilterRelease(cv::Ptr<cv::text::ERFilter>** sharedPtr);

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveERFilterRelease", $sSharedPtrDllType, $sharedPtr), "cveERFilterRelease", @error)
EndFunc   ;==>_cveERFilterRelease

Func _cveERFilterRun($filter, $image, $regions)
    ; CVAPI(void) cveERFilterRun(cv::text::ERFilter* filter, cv::_InputArray* image, std::vector<cv::text::ERStat>* regions);

    Local $sFilterDllType
    If IsDllStruct($filter) Then
        $sFilterDllType = "struct*"
    Else
        $sFilterDllType = "ptr"
    EndIf

    Local $sImageDllType
    If IsDllStruct($image) Then
        $sImageDllType = "struct*"
    Else
        $sImageDllType = "ptr"
    EndIf

    Local $vecRegions, $iArrRegionsSize
    Local $bRegionsIsArray = IsArray($regions)

    If $bRegionsIsArray Then
        $vecRegions = _VectorOfERStatCreate()

        $iArrRegionsSize = UBound($regions)
        For $i = 0 To $iArrRegionsSize - 1
            _VectorOfERStatPush($vecRegions, $regions[$i])
        Next
    Else
        $vecRegions = $regions
    EndIf

    Local $sRegionsDllType
    If IsDllStruct($regions) Then
        $sRegionsDllType = "struct*"
    Else
        $sRegionsDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveERFilterRun", $sFilterDllType, $filter, $sImageDllType, $image, $sRegionsDllType, $vecRegions), "cveERFilterRun", @error)

    If $bRegionsIsArray Then
        _VectorOfERStatRelease($vecRegions)
    EndIf
EndFunc   ;==>_cveERFilterRun

Func _cveERFilterRunTyped($filter, $typeOfImage, $image, $regions)

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

    _cveERFilterRun($filter, $iArrImage, $regions)

    If $bImageIsArray Then
        Call("_VectorOf" & $typeOfImage & "Release", $vectorImage)
    EndIf

    If $typeOfImage <> Default Then
        _cveInputArrayRelease($iArrImage)
        If $bImageCreate Then
            Call("_cve" & $typeOfImage & "Release", $image)
        EndIf
    EndIf
EndFunc   ;==>_cveERFilterRunTyped

Func _cveERFilterRunMat($filter, $image, $regions)
    ; cveERFilterRun using cv::Mat instead of _*Array
    _cveERFilterRunTyped($filter, "Mat", $image, $regions)
EndFunc   ;==>_cveERFilterRunMat

Func _cveERGrouping($image, $channels, $regions, $count, $groups, $group_rects, $method, $fileName, $minProbability)
    ; CVAPI(void) cveERGrouping(cv::_InputArray* image, cv::_InputArray* channels, std::vector<cv::text::ERStat>** regions, int count, std::vector<std::vector<cv::Vec2i>>* groups, std::vector<cv::Rect>* group_rects, int method, cv::String* fileName, float minProbability);

    Local $sImageDllType
    If IsDllStruct($image) Then
        $sImageDllType = "struct*"
    Else
        $sImageDllType = "ptr"
    EndIf

    Local $sChannelsDllType
    If IsDllStruct($channels) Then
        $sChannelsDllType = "struct*"
    Else
        $sChannelsDllType = "ptr"
    EndIf

    Local $vecRegions, $iArrRegionsSize
    Local $bRegionsIsArray = IsArray($regions)

    If $bRegionsIsArray Then
        $vecRegions = _VectorOfERStatCreate()

        $iArrRegionsSize = UBound($regions)
        For $i = 0 To $iArrRegionsSize - 1
            _VectorOfERStatPush($vecRegions, $regions[$i])
        Next
    Else
        $vecRegions = $regions
    EndIf

    Local $sRegionsDllType
    If IsDllStruct($regions) Then
        $sRegionsDllType = "struct*"
    ElseIf $regions == Null Then
        $sRegionsDllType = "ptr"
    Else
        $sRegionsDllType = "ptr*"
    EndIf

    Local $sGroupsDllType
    If IsDllStruct($groups) Then
        $sGroupsDllType = "struct*"
    Else
        $sGroupsDllType = "ptr"
    EndIf

    Local $vecGroup_rects, $iArrGroup_rectsSize
    Local $bGroup_rectsIsArray = IsArray($group_rects)

    If $bGroup_rectsIsArray Then
        $vecGroup_rects = _VectorOfRectCreate()

        $iArrGroup_rectsSize = UBound($group_rects)
        For $i = 0 To $iArrGroup_rectsSize - 1
            _VectorOfRectPush($vecGroup_rects, $group_rects[$i])
        Next
    Else
        $vecGroup_rects = $group_rects
    EndIf

    Local $sGroup_rectsDllType
    If IsDllStruct($group_rects) Then
        $sGroup_rectsDllType = "struct*"
    Else
        $sGroup_rectsDllType = "ptr"
    EndIf

    Local $bFileNameIsString = IsString($fileName)
    If $bFileNameIsString Then
        $fileName = _cveStringCreateFromStr($fileName)
    EndIf

    Local $sFileNameDllType
    If IsDllStruct($fileName) Then
        $sFileNameDllType = "struct*"
    Else
        $sFileNameDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveERGrouping", $sImageDllType, $image, $sChannelsDllType, $channels, $sRegionsDllType, $vecRegions, "int", $count, $sGroupsDllType, $groups, $sGroup_rectsDllType, $vecGroup_rects, "int", $method, $sFileNameDllType, $fileName, "float", $minProbability), "cveERGrouping", @error)

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

Func _cveERGroupingTyped($typeOfImage, $image, $typeOfChannels, $channels, $regions, $count, $groups, $group_rects, $method, $fileName, $minProbability)

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

    Local $iArrChannels, $vectorChannels, $iArrChannelsSize
    Local $bChannelsIsArray = IsArray($channels)
    Local $bChannelsCreate = IsDllStruct($channels) And $typeOfChannels == "Scalar"

    If $typeOfChannels == Default Then
        $iArrChannels = $channels
    ElseIf $bChannelsIsArray Then
        $vectorChannels = Call("_VectorOf" & $typeOfChannels & "Create")

        $iArrChannelsSize = UBound($channels)
        For $i = 0 To $iArrChannelsSize - 1
            Call("_VectorOf" & $typeOfChannels & "Push", $vectorChannels, $channels[$i])
        Next

        $iArrChannels = Call("_cveInputArrayFromVectorOf" & $typeOfChannels, $vectorChannels)
    Else
        If $bChannelsCreate Then
            $channels = Call("_cve" & $typeOfChannels & "Create", $channels)
        EndIf
        $iArrChannels = Call("_cveInputArrayFrom" & $typeOfChannels, $channels)
    EndIf

    _cveERGrouping($iArrImage, $iArrChannels, $regions, $count, $groups, $group_rects, $method, $fileName, $minProbability)

    If $bChannelsIsArray Then
        Call("_VectorOf" & $typeOfChannels & "Release", $vectorChannels)
    EndIf

    If $typeOfChannels <> Default Then
        _cveInputArrayRelease($iArrChannels)
        If $bChannelsCreate Then
            Call("_cve" & $typeOfChannels & "Release", $channels)
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
EndFunc   ;==>_cveERGroupingTyped

Func _cveERGroupingMat($image, $channels, $regions, $count, $groups, $group_rects, $method, $fileName, $minProbability)
    ; cveERGrouping using cv::Mat instead of _*Array
    _cveERGroupingTyped("Mat", $image, "Mat", $channels, $regions, $count, $groups, $group_rects, $method, $fileName, $minProbability)
EndFunc   ;==>_cveERGroupingMat

Func _cveMSERsToERStats($image, $contours, $regions)
    ; CVAPI(void) cveMSERsToERStats(cv::_InputArray* image, std::vector<std::vector<cv::Point>>* contours, std::vector<std::vector<cv::text::ERStat>>* regions);

    Local $sImageDllType
    If IsDllStruct($image) Then
        $sImageDllType = "struct*"
    Else
        $sImageDllType = "ptr"
    EndIf

    Local $vecContours, $iArrContoursSize
    Local $bContoursIsArray = IsArray($contours)

    If $bContoursIsArray Then
        $vecContours = _VectorOfVectorOfPointCreate()

        $iArrContoursSize = UBound($contours)
        For $i = 0 To $iArrContoursSize - 1
            _VectorOfVectorOfPointPush($vecContours, $contours[$i])
        Next
    Else
        $vecContours = $contours
    EndIf

    Local $sContoursDllType
    If IsDllStruct($contours) Then
        $sContoursDllType = "struct*"
    Else
        $sContoursDllType = "ptr"
    EndIf

    Local $vecRegions, $iArrRegionsSize
    Local $bRegionsIsArray = IsArray($regions)

    If $bRegionsIsArray Then
        $vecRegions = _VectorOfVectorOfERStatCreate()

        $iArrRegionsSize = UBound($regions)
        For $i = 0 To $iArrRegionsSize - 1
            _VectorOfVectorOfERStatPush($vecRegions, $regions[$i])
        Next
    Else
        $vecRegions = $regions
    EndIf

    Local $sRegionsDllType
    If IsDllStruct($regions) Then
        $sRegionsDllType = "struct*"
    Else
        $sRegionsDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMSERsToERStats", $sImageDllType, $image, $sContoursDllType, $vecContours, $sRegionsDllType, $vecRegions), "cveMSERsToERStats", @error)

    If $bRegionsIsArray Then
        _VectorOfVectorOfERStatRelease($vecRegions)
    EndIf

    If $bContoursIsArray Then
        _VectorOfVectorOfPointRelease($vecContours)
    EndIf
EndFunc   ;==>_cveMSERsToERStats

Func _cveMSERsToERStatsTyped($typeOfImage, $image, $contours, $regions)

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

    _cveMSERsToERStats($iArrImage, $contours, $regions)

    If $bImageIsArray Then
        Call("_VectorOf" & $typeOfImage & "Release", $vectorImage)
    EndIf

    If $typeOfImage <> Default Then
        _cveInputArrayRelease($iArrImage)
        If $bImageCreate Then
            Call("_cve" & $typeOfImage & "Release", $image)
        EndIf
    EndIf
EndFunc   ;==>_cveMSERsToERStatsTyped

Func _cveMSERsToERStatsMat($image, $contours, $regions)
    ; cveMSERsToERStats using cv::Mat instead of _*Array
    _cveMSERsToERStatsTyped("Mat", $image, $contours, $regions)
EndFunc   ;==>_cveMSERsToERStatsMat

Func _cveComputeNMChannels($src, $channels, $mode)
    ; CVAPI(void) cveComputeNMChannels(cv::_InputArray* src, cv::_OutputArray* channels, int mode);

    Local $sSrcDllType
    If IsDllStruct($src) Then
        $sSrcDllType = "struct*"
    Else
        $sSrcDllType = "ptr"
    EndIf

    Local $sChannelsDllType
    If IsDllStruct($channels) Then
        $sChannelsDllType = "struct*"
    Else
        $sChannelsDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveComputeNMChannels", $sSrcDllType, $src, $sChannelsDllType, $channels, "int", $mode), "cveComputeNMChannels", @error)
EndFunc   ;==>_cveComputeNMChannels

Func _cveComputeNMChannelsTyped($typeOfSrc, $src, $typeOfChannels, $channels, $mode)

    Local $iArrSrc, $vectorSrc, $iArrSrcSize
    Local $bSrcIsArray = IsArray($src)
    Local $bSrcCreate = IsDllStruct($src) And $typeOfSrc == "Scalar"

    If $typeOfSrc == Default Then
        $iArrSrc = $src
    ElseIf $bSrcIsArray Then
        $vectorSrc = Call("_VectorOf" & $typeOfSrc & "Create")

        $iArrSrcSize = UBound($src)
        For $i = 0 To $iArrSrcSize - 1
            Call("_VectorOf" & $typeOfSrc & "Push", $vectorSrc, $src[$i])
        Next

        $iArrSrc = Call("_cveInputArrayFromVectorOf" & $typeOfSrc, $vectorSrc)
    Else
        If $bSrcCreate Then
            $src = Call("_cve" & $typeOfSrc & "Create", $src)
        EndIf
        $iArrSrc = Call("_cveInputArrayFrom" & $typeOfSrc, $src)
    EndIf

    Local $oArrChannels, $vectorChannels, $iArrChannelsSize
    Local $bChannelsIsArray = IsArray($channels)
    Local $bChannelsCreate = IsDllStruct($channels) And $typeOfChannels == "Scalar"

    If $typeOfChannels == Default Then
        $oArrChannels = $channels
    ElseIf $bChannelsIsArray Then
        $vectorChannels = Call("_VectorOf" & $typeOfChannels & "Create")

        $iArrChannelsSize = UBound($channels)
        For $i = 0 To $iArrChannelsSize - 1
            Call("_VectorOf" & $typeOfChannels & "Push", $vectorChannels, $channels[$i])
        Next

        $oArrChannels = Call("_cveOutputArrayFromVectorOf" & $typeOfChannels, $vectorChannels)
    Else
        If $bChannelsCreate Then
            $channels = Call("_cve" & $typeOfChannels & "Create", $channels)
        EndIf
        $oArrChannels = Call("_cveOutputArrayFrom" & $typeOfChannels, $channels)
    EndIf

    _cveComputeNMChannels($iArrSrc, $oArrChannels, $mode)

    If $bChannelsIsArray Then
        Call("_VectorOf" & $typeOfChannels & "Release", $vectorChannels)
    EndIf

    If $typeOfChannels <> Default Then
        _cveOutputArrayRelease($oArrChannels)
        If $bChannelsCreate Then
            Call("_cve" & $typeOfChannels & "Release", $channels)
        EndIf
    EndIf

    If $bSrcIsArray Then
        Call("_VectorOf" & $typeOfSrc & "Release", $vectorSrc)
    EndIf

    If $typeOfSrc <> Default Then
        _cveInputArrayRelease($iArrSrc)
        If $bSrcCreate Then
            Call("_cve" & $typeOfSrc & "Release", $src)
        EndIf
    EndIf
EndFunc   ;==>_cveComputeNMChannelsTyped

Func _cveComputeNMChannelsMat($src, $channels, $mode)
    ; cveComputeNMChannels using cv::Mat instead of _*Array
    _cveComputeNMChannelsTyped("Mat", $src, "Mat", $channels, $mode)
EndFunc   ;==>_cveComputeNMChannelsMat

Func _cveTextDetectorCNNCreate($modelArchFilename, $modelWeightsFilename, $sharedPtr)
    ; CVAPI(cv::text::TextDetectorCNN*) cveTextDetectorCNNCreate(cv::String* modelArchFilename, cv::String* modelWeightsFilename, cv::Ptr<cv::text::TextDetectorCNN>** sharedPtr);

    Local $bModelArchFilenameIsString = IsString($modelArchFilename)
    If $bModelArchFilenameIsString Then
        $modelArchFilename = _cveStringCreateFromStr($modelArchFilename)
    EndIf

    Local $sModelArchFilenameDllType
    If IsDllStruct($modelArchFilename) Then
        $sModelArchFilenameDllType = "struct*"
    Else
        $sModelArchFilenameDllType = "ptr"
    EndIf

    Local $bModelWeightsFilenameIsString = IsString($modelWeightsFilename)
    If $bModelWeightsFilenameIsString Then
        $modelWeightsFilename = _cveStringCreateFromStr($modelWeightsFilename)
    EndIf

    Local $sModelWeightsFilenameDllType
    If IsDllStruct($modelWeightsFilename) Then
        $sModelWeightsFilenameDllType = "struct*"
    Else
        $sModelWeightsFilenameDllType = "ptr"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveTextDetectorCNNCreate", $sModelArchFilenameDllType, $modelArchFilename, $sModelWeightsFilenameDllType, $modelWeightsFilename, $sSharedPtrDllType, $sharedPtr), "cveTextDetectorCNNCreate", @error)

    If $bModelWeightsFilenameIsString Then
        _cveStringRelease($modelWeightsFilename)
    EndIf

    If $bModelArchFilenameIsString Then
        _cveStringRelease($modelArchFilename)
    EndIf

    Return $retval
EndFunc   ;==>_cveTextDetectorCNNCreate

Func _cveTextDetectorCNNCreate2($modelArchFilename, $modelWeightsFilename, $detectionSizes, $sharedPtr)
    ; CVAPI(cv::text::TextDetectorCNN*) cveTextDetectorCNNCreate2(cv::String* modelArchFilename, cv::String* modelWeightsFilename, std::vector<cv::Size>* detectionSizes, cv::Ptr<cv::text::TextDetectorCNN>** sharedPtr);

    Local $bModelArchFilenameIsString = IsString($modelArchFilename)
    If $bModelArchFilenameIsString Then
        $modelArchFilename = _cveStringCreateFromStr($modelArchFilename)
    EndIf

    Local $sModelArchFilenameDllType
    If IsDllStruct($modelArchFilename) Then
        $sModelArchFilenameDllType = "struct*"
    Else
        $sModelArchFilenameDllType = "ptr"
    EndIf

    Local $bModelWeightsFilenameIsString = IsString($modelWeightsFilename)
    If $bModelWeightsFilenameIsString Then
        $modelWeightsFilename = _cveStringCreateFromStr($modelWeightsFilename)
    EndIf

    Local $sModelWeightsFilenameDllType
    If IsDllStruct($modelWeightsFilename) Then
        $sModelWeightsFilenameDllType = "struct*"
    Else
        $sModelWeightsFilenameDllType = "ptr"
    EndIf

    Local $vecDetectionSizes, $iArrDetectionSizesSize
    Local $bDetectionSizesIsArray = IsArray($detectionSizes)

    If $bDetectionSizesIsArray Then
        $vecDetectionSizes = _VectorOfSizeCreate()

        $iArrDetectionSizesSize = UBound($detectionSizes)
        For $i = 0 To $iArrDetectionSizesSize - 1
            _VectorOfSizePush($vecDetectionSizes, $detectionSizes[$i])
        Next
    Else
        $vecDetectionSizes = $detectionSizes
    EndIf

    Local $sDetectionSizesDllType
    If IsDllStruct($detectionSizes) Then
        $sDetectionSizesDllType = "struct*"
    Else
        $sDetectionSizesDllType = "ptr"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveTextDetectorCNNCreate2", $sModelArchFilenameDllType, $modelArchFilename, $sModelWeightsFilenameDllType, $modelWeightsFilename, $sDetectionSizesDllType, $vecDetectionSizes, $sSharedPtrDllType, $sharedPtr), "cveTextDetectorCNNCreate2", @error)

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

Func _cveTextDetectorCNNDetect($detector, $inputImage, $bbox, $confidence)
    ; CVAPI(void) cveTextDetectorCNNDetect(cv::text::TextDetectorCNN* detector, cv::_InputArray* inputImage, std::vector<cv::Rect>* bbox, std::vector<float>* confidence);

    Local $sDetectorDllType
    If IsDllStruct($detector) Then
        $sDetectorDllType = "struct*"
    Else
        $sDetectorDllType = "ptr"
    EndIf

    Local $sInputImageDllType
    If IsDllStruct($inputImage) Then
        $sInputImageDllType = "struct*"
    Else
        $sInputImageDllType = "ptr"
    EndIf

    Local $vecBbox, $iArrBboxSize
    Local $bBboxIsArray = IsArray($bbox)

    If $bBboxIsArray Then
        $vecBbox = _VectorOfRectCreate()

        $iArrBboxSize = UBound($bbox)
        For $i = 0 To $iArrBboxSize - 1
            _VectorOfRectPush($vecBbox, $bbox[$i])
        Next
    Else
        $vecBbox = $bbox
    EndIf

    Local $sBboxDllType
    If IsDllStruct($bbox) Then
        $sBboxDllType = "struct*"
    Else
        $sBboxDllType = "ptr"
    EndIf

    Local $vecConfidence, $iArrConfidenceSize
    Local $bConfidenceIsArray = IsArray($confidence)

    If $bConfidenceIsArray Then
        $vecConfidence = _VectorOfFloatCreate()

        $iArrConfidenceSize = UBound($confidence)
        For $i = 0 To $iArrConfidenceSize - 1
            _VectorOfFloatPush($vecConfidence, $confidence[$i])
        Next
    Else
        $vecConfidence = $confidence
    EndIf

    Local $sConfidenceDllType
    If IsDllStruct($confidence) Then
        $sConfidenceDllType = "struct*"
    Else
        $sConfidenceDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveTextDetectorCNNDetect", $sDetectorDllType, $detector, $sInputImageDllType, $inputImage, $sBboxDllType, $vecBbox, $sConfidenceDllType, $vecConfidence), "cveTextDetectorCNNDetect", @error)

    If $bConfidenceIsArray Then
        _VectorOfFloatRelease($vecConfidence)
    EndIf

    If $bBboxIsArray Then
        _VectorOfRectRelease($vecBbox)
    EndIf
EndFunc   ;==>_cveTextDetectorCNNDetect

Func _cveTextDetectorCNNDetectTyped($detector, $typeOfInputImage, $inputImage, $bbox, $confidence)

    Local $iArrInputImage, $vectorInputImage, $iArrInputImageSize
    Local $bInputImageIsArray = IsArray($inputImage)
    Local $bInputImageCreate = IsDllStruct($inputImage) And $typeOfInputImage == "Scalar"

    If $typeOfInputImage == Default Then
        $iArrInputImage = $inputImage
    ElseIf $bInputImageIsArray Then
        $vectorInputImage = Call("_VectorOf" & $typeOfInputImage & "Create")

        $iArrInputImageSize = UBound($inputImage)
        For $i = 0 To $iArrInputImageSize - 1
            Call("_VectorOf" & $typeOfInputImage & "Push", $vectorInputImage, $inputImage[$i])
        Next

        $iArrInputImage = Call("_cveInputArrayFromVectorOf" & $typeOfInputImage, $vectorInputImage)
    Else
        If $bInputImageCreate Then
            $inputImage = Call("_cve" & $typeOfInputImage & "Create", $inputImage)
        EndIf
        $iArrInputImage = Call("_cveInputArrayFrom" & $typeOfInputImage, $inputImage)
    EndIf

    _cveTextDetectorCNNDetect($detector, $iArrInputImage, $bbox, $confidence)

    If $bInputImageIsArray Then
        Call("_VectorOf" & $typeOfInputImage & "Release", $vectorInputImage)
    EndIf

    If $typeOfInputImage <> Default Then
        _cveInputArrayRelease($iArrInputImage)
        If $bInputImageCreate Then
            Call("_cve" & $typeOfInputImage & "Release", $inputImage)
        EndIf
    EndIf
EndFunc   ;==>_cveTextDetectorCNNDetectTyped

Func _cveTextDetectorCNNDetectMat($detector, $inputImage, $bbox, $confidence)
    ; cveTextDetectorCNNDetect using cv::Mat instead of _*Array
    _cveTextDetectorCNNDetectTyped($detector, "Mat", $inputImage, $bbox, $confidence)
EndFunc   ;==>_cveTextDetectorCNNDetectMat

Func _cveTextDetectorCNNRelease($sharedPtr)
    ; CVAPI(void) cveTextDetectorCNNRelease(cv::Ptr<cv::text::TextDetectorCNN>** sharedPtr);

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveTextDetectorCNNRelease", $sSharedPtrDllType, $sharedPtr), "cveTextDetectorCNNRelease", @error)
EndFunc   ;==>_cveTextDetectorCNNRelease