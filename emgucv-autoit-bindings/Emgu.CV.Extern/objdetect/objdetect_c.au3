#include-once
#include "..\..\CVEUtils.au3"

Func _cveHOGDescriptorPeopleDetectorCreate($seq)
    ; CVAPI(void) cveHOGDescriptorPeopleDetectorCreate(std::vector<float>* seq);

    Local $vecSeq, $iArrSeqSize
    Local $bSeqIsArray = VarGetType($seq) == "Array"

    If $bSeqIsArray Then
        $vecSeq = _VectorOfFloatCreate()

        $iArrSeqSize = UBound($seq)
        For $i = 0 To $iArrSeqSize - 1
            _VectorOfFloatPush($vecSeq, $seq[$i])
        Next
    Else
        $vecSeq = $seq
    EndIf

    Local $sSeqDllType
    If IsDllStruct($seq) Then
        $sSeqDllType = "struct*"
    Else
        $sSeqDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveHOGDescriptorPeopleDetectorCreate", $sSeqDllType, $vecSeq), "cveHOGDescriptorPeopleDetectorCreate", @error)

    If $bSeqIsArray Then
        _VectorOfFloatRelease($vecSeq)
    EndIf
EndFunc   ;==>_cveHOGDescriptorPeopleDetectorCreate

Func _cveHOGDescriptorCreateDefault()
    ; CVAPI(cv::HOGDescriptor*) cveHOGDescriptorCreateDefault();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveHOGDescriptorCreateDefault"), "cveHOGDescriptorCreateDefault", @error)
EndFunc   ;==>_cveHOGDescriptorCreateDefault

Func _cveHOGDescriptorCreate($_winSize, $_blockSize, $_blockStride, $_cellSize, $_nbins, $_derivAperture, $_winSigma, $_histogramNormType, $_L2HysThreshold, $_gammaCorrection)
    ; CVAPI(cv::HOGDescriptor*) cveHOGDescriptorCreate(CvSize* _winSize, CvSize* _blockSize, CvSize* _blockStride, CvSize* _cellSize, int _nbins, int _derivAperture, double _winSigma, int _histogramNormType, double _L2HysThreshold, bool _gammaCorrection);

    Local $s_winSizeDllType
    If IsDllStruct($_winSize) Then
        $s_winSizeDllType = "struct*"
    Else
        $s_winSizeDllType = "ptr"
    EndIf

    Local $s_blockSizeDllType
    If IsDllStruct($_blockSize) Then
        $s_blockSizeDllType = "struct*"
    Else
        $s_blockSizeDllType = "ptr"
    EndIf

    Local $s_blockStrideDllType
    If IsDllStruct($_blockStride) Then
        $s_blockStrideDllType = "struct*"
    Else
        $s_blockStrideDllType = "ptr"
    EndIf

    Local $s_cellSizeDllType
    If IsDllStruct($_cellSize) Then
        $s_cellSizeDllType = "struct*"
    Else
        $s_cellSizeDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveHOGDescriptorCreate", $s_winSizeDllType, $_winSize, $s_blockSizeDllType, $_blockSize, $s_blockStrideDllType, $_blockStride, $s_cellSizeDllType, $_cellSize, "int", $_nbins, "int", $_derivAperture, "double", $_winSigma, "int", $_histogramNormType, "double", $_L2HysThreshold, "boolean", $_gammaCorrection), "cveHOGDescriptorCreate", @error)
EndFunc   ;==>_cveHOGDescriptorCreate

Func _cveHOGSetSVMDetector($descriptor, $vector)
    ; CVAPI(void) cveHOGSetSVMDetector(cv::HOGDescriptor* descriptor, std::vector<float>* vector);

    Local $sDescriptorDllType
    If IsDllStruct($descriptor) Then
        $sDescriptorDllType = "struct*"
    Else
        $sDescriptorDllType = "ptr"
    EndIf

    Local $vecVector, $iArrVectorSize
    Local $bVectorIsArray = VarGetType($vector) == "Array"

    If $bVectorIsArray Then
        $vecVector = _VectorOfFloatCreate()

        $iArrVectorSize = UBound($vector)
        For $i = 0 To $iArrVectorSize - 1
            _VectorOfFloatPush($vecVector, $vector[$i])
        Next
    Else
        $vecVector = $vector
    EndIf

    Local $sVectorDllType
    If IsDllStruct($vector) Then
        $sVectorDllType = "struct*"
    Else
        $sVectorDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveHOGSetSVMDetector", $sDescriptorDllType, $descriptor, $sVectorDllType, $vecVector), "cveHOGSetSVMDetector", @error)

    If $bVectorIsArray Then
        _VectorOfFloatRelease($vecVector)
    EndIf
EndFunc   ;==>_cveHOGSetSVMDetector

Func _cveHOGDescriptorRelease($descriptor)
    ; CVAPI(void) cveHOGDescriptorRelease(cv::HOGDescriptor** descriptor);

    Local $sDescriptorDllType
    If IsDllStruct($descriptor) Then
        $sDescriptorDllType = "struct*"
    ElseIf $descriptor == Null Then
        $sDescriptorDllType = "ptr"
    Else
        $sDescriptorDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveHOGDescriptorRelease", $sDescriptorDllType, $descriptor), "cveHOGDescriptorRelease", @error)
EndFunc   ;==>_cveHOGDescriptorRelease

Func _cveHOGDescriptorDetectMultiScale($descriptor, $img, $foundLocations, $weights, $hitThreshold, $winStride, $padding, $scale, $finalThreshold, $useMeanshiftGrouping)
    ; CVAPI(void) cveHOGDescriptorDetectMultiScale(cv::HOGDescriptor* descriptor, cv::_InputArray* img, std::vector<cv::Rect>* foundLocations, std::vector<double>* weights, double hitThreshold, CvSize* winStride, CvSize* padding, double scale, double finalThreshold, bool useMeanshiftGrouping);

    Local $sDescriptorDllType
    If IsDllStruct($descriptor) Then
        $sDescriptorDllType = "struct*"
    Else
        $sDescriptorDllType = "ptr"
    EndIf

    Local $sImgDllType
    If IsDllStruct($img) Then
        $sImgDllType = "struct*"
    Else
        $sImgDllType = "ptr"
    EndIf

    Local $vecFoundLocations, $iArrFoundLocationsSize
    Local $bFoundLocationsIsArray = VarGetType($foundLocations) == "Array"

    If $bFoundLocationsIsArray Then
        $vecFoundLocations = _VectorOfRectCreate()

        $iArrFoundLocationsSize = UBound($foundLocations)
        For $i = 0 To $iArrFoundLocationsSize - 1
            _VectorOfRectPush($vecFoundLocations, $foundLocations[$i])
        Next
    Else
        $vecFoundLocations = $foundLocations
    EndIf

    Local $sFoundLocationsDllType
    If IsDllStruct($foundLocations) Then
        $sFoundLocationsDllType = "struct*"
    Else
        $sFoundLocationsDllType = "ptr"
    EndIf

    Local $vecWeights, $iArrWeightsSize
    Local $bWeightsIsArray = VarGetType($weights) == "Array"

    If $bWeightsIsArray Then
        $vecWeights = _VectorOfDoubleCreate()

        $iArrWeightsSize = UBound($weights)
        For $i = 0 To $iArrWeightsSize - 1
            _VectorOfDoublePush($vecWeights, $weights[$i])
        Next
    Else
        $vecWeights = $weights
    EndIf

    Local $sWeightsDllType
    If IsDllStruct($weights) Then
        $sWeightsDllType = "struct*"
    Else
        $sWeightsDllType = "ptr"
    EndIf

    Local $sWinStrideDllType
    If IsDllStruct($winStride) Then
        $sWinStrideDllType = "struct*"
    Else
        $sWinStrideDllType = "ptr"
    EndIf

    Local $sPaddingDllType
    If IsDllStruct($padding) Then
        $sPaddingDllType = "struct*"
    Else
        $sPaddingDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveHOGDescriptorDetectMultiScale", $sDescriptorDllType, $descriptor, $sImgDllType, $img, $sFoundLocationsDllType, $vecFoundLocations, $sWeightsDllType, $vecWeights, "double", $hitThreshold, $sWinStrideDllType, $winStride, $sPaddingDllType, $padding, "double", $scale, "double", $finalThreshold, "boolean", $useMeanshiftGrouping), "cveHOGDescriptorDetectMultiScale", @error)

    If $bWeightsIsArray Then
        _VectorOfDoubleRelease($vecWeights)
    EndIf

    If $bFoundLocationsIsArray Then
        _VectorOfRectRelease($vecFoundLocations)
    EndIf
EndFunc   ;==>_cveHOGDescriptorDetectMultiScale

Func _cveHOGDescriptorDetectMultiScaleMat($descriptor, $matImg, $foundLocations, $weights, $hitThreshold, $winStride, $padding, $scale, $finalThreshold, $useMeanshiftGrouping)
    ; cveHOGDescriptorDetectMultiScale using cv::Mat instead of _*Array

    Local $iArrImg, $vectorOfMatImg, $iArrImgSize
    Local $bImgIsArray = VarGetType($matImg) == "Array"

    If $bImgIsArray Then
        $vectorOfMatImg = _VectorOfMatCreate()

        $iArrImgSize = UBound($matImg)
        For $i = 0 To $iArrImgSize - 1
            _VectorOfMatPush($vectorOfMatImg, $matImg[$i])
        Next

        $iArrImg = _cveInputArrayFromVectorOfMat($vectorOfMatImg)
    Else
        $iArrImg = _cveInputArrayFromMat($matImg)
    EndIf

    _cveHOGDescriptorDetectMultiScale($descriptor, $iArrImg, $foundLocations, $weights, $hitThreshold, $winStride, $padding, $scale, $finalThreshold, $useMeanshiftGrouping)

    If $bImgIsArray Then
        _VectorOfMatRelease($vectorOfMatImg)
    EndIf

    _cveInputArrayRelease($iArrImg)
EndFunc   ;==>_cveHOGDescriptorDetectMultiScaleMat

Func _cveHOGDescriptorCompute($descriptor, $img, $descriptors, $winStride, $padding, $locations)
    ; CVAPI(void) cveHOGDescriptorCompute(cv::HOGDescriptor* descriptor, cv::_InputArray* img, std::vector<float>* descriptors, CvSize* winStride, CvSize* padding, std::vector<cv::Point>* locations);

    Local $sDescriptorDllType
    If IsDllStruct($descriptor) Then
        $sDescriptorDllType = "struct*"
    Else
        $sDescriptorDllType = "ptr"
    EndIf

    Local $sImgDllType
    If IsDllStruct($img) Then
        $sImgDllType = "struct*"
    Else
        $sImgDllType = "ptr"
    EndIf

    Local $vecDescriptors, $iArrDescriptorsSize
    Local $bDescriptorsIsArray = VarGetType($descriptors) == "Array"

    If $bDescriptorsIsArray Then
        $vecDescriptors = _VectorOfFloatCreate()

        $iArrDescriptorsSize = UBound($descriptors)
        For $i = 0 To $iArrDescriptorsSize - 1
            _VectorOfFloatPush($vecDescriptors, $descriptors[$i])
        Next
    Else
        $vecDescriptors = $descriptors
    EndIf

    Local $sDescriptorsDllType
    If IsDllStruct($descriptors) Then
        $sDescriptorsDllType = "struct*"
    Else
        $sDescriptorsDllType = "ptr"
    EndIf

    Local $sWinStrideDllType
    If IsDllStruct($winStride) Then
        $sWinStrideDllType = "struct*"
    Else
        $sWinStrideDllType = "ptr"
    EndIf

    Local $sPaddingDllType
    If IsDllStruct($padding) Then
        $sPaddingDllType = "struct*"
    Else
        $sPaddingDllType = "ptr"
    EndIf

    Local $vecLocations, $iArrLocationsSize
    Local $bLocationsIsArray = VarGetType($locations) == "Array"

    If $bLocationsIsArray Then
        $vecLocations = _VectorOfPointCreate()

        $iArrLocationsSize = UBound($locations)
        For $i = 0 To $iArrLocationsSize - 1
            _VectorOfPointPush($vecLocations, $locations[$i])
        Next
    Else
        $vecLocations = $locations
    EndIf

    Local $sLocationsDllType
    If IsDllStruct($locations) Then
        $sLocationsDllType = "struct*"
    Else
        $sLocationsDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveHOGDescriptorCompute", $sDescriptorDllType, $descriptor, $sImgDllType, $img, $sDescriptorsDllType, $vecDescriptors, $sWinStrideDllType, $winStride, $sPaddingDllType, $padding, $sLocationsDllType, $vecLocations), "cveHOGDescriptorCompute", @error)

    If $bLocationsIsArray Then
        _VectorOfPointRelease($vecLocations)
    EndIf

    If $bDescriptorsIsArray Then
        _VectorOfFloatRelease($vecDescriptors)
    EndIf
EndFunc   ;==>_cveHOGDescriptorCompute

Func _cveHOGDescriptorComputeMat($descriptor, $matImg, $descriptors, $winStride, $padding, $locations)
    ; cveHOGDescriptorCompute using cv::Mat instead of _*Array

    Local $iArrImg, $vectorOfMatImg, $iArrImgSize
    Local $bImgIsArray = VarGetType($matImg) == "Array"

    If $bImgIsArray Then
        $vectorOfMatImg = _VectorOfMatCreate()

        $iArrImgSize = UBound($matImg)
        For $i = 0 To $iArrImgSize - 1
            _VectorOfMatPush($vectorOfMatImg, $matImg[$i])
        Next

        $iArrImg = _cveInputArrayFromVectorOfMat($vectorOfMatImg)
    Else
        $iArrImg = _cveInputArrayFromMat($matImg)
    EndIf

    _cveHOGDescriptorCompute($descriptor, $iArrImg, $descriptors, $winStride, $padding, $locations)

    If $bImgIsArray Then
        _VectorOfMatRelease($vectorOfMatImg)
    EndIf

    _cveInputArrayRelease($iArrImg)
EndFunc   ;==>_cveHOGDescriptorComputeMat

Func _cveHOGDescriptorGetDescriptorSize($descriptor)
    ; CVAPI(unsigned int) cveHOGDescriptorGetDescriptorSize(cv::HOGDescriptor* descriptor);

    Local $sDescriptorDllType
    If IsDllStruct($descriptor) Then
        $sDescriptorDllType = "struct*"
    Else
        $sDescriptorDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "uint:cdecl", "cveHOGDescriptorGetDescriptorSize", $sDescriptorDllType, $descriptor), "cveHOGDescriptorGetDescriptorSize", @error)
EndFunc   ;==>_cveHOGDescriptorGetDescriptorSize

Func _cveCascadeClassifierCreate()
    ; CVAPI(cv::CascadeClassifier*) cveCascadeClassifierCreate();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveCascadeClassifierCreate"), "cveCascadeClassifierCreate", @error)
EndFunc   ;==>_cveCascadeClassifierCreate

Func _cveCascadeClassifierCreateFromFile($fileName)
    ; CVAPI(cv::CascadeClassifier*) cveCascadeClassifierCreateFromFile(cv::String* fileName);

    Local $bFileNameIsString = VarGetType($fileName) == "String"
    If $bFileNameIsString Then
        $fileName = _cveStringCreateFromStr($fileName)
    EndIf

    Local $sFileNameDllType
    If IsDllStruct($fileName) Then
        $sFileNameDllType = "struct*"
    Else
        $sFileNameDllType = "ptr"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveCascadeClassifierCreateFromFile", $sFileNameDllType, $fileName), "cveCascadeClassifierCreateFromFile", @error)

    If $bFileNameIsString Then
        _cveStringRelease($fileName)
    EndIf

    Return $retval
EndFunc   ;==>_cveCascadeClassifierCreateFromFile

Func _cveCascadeClassifierRead($classifier, $node)
    ; CVAPI(bool) cveCascadeClassifierRead(cv::CascadeClassifier* classifier, cv::FileNode* node);

    Local $sClassifierDllType
    If IsDllStruct($classifier) Then
        $sClassifierDllType = "struct*"
    Else
        $sClassifierDllType = "ptr"
    EndIf

    Local $sNodeDllType
    If IsDllStruct($node) Then
        $sNodeDllType = "struct*"
    Else
        $sNodeDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveCascadeClassifierRead", $sClassifierDllType, $classifier, $sNodeDllType, $node), "cveCascadeClassifierRead", @error)
EndFunc   ;==>_cveCascadeClassifierRead

Func _cveCascadeClassifierRelease($classifier)
    ; CVAPI(void) cveCascadeClassifierRelease(cv::CascadeClassifier** classifier);

    Local $sClassifierDllType
    If IsDllStruct($classifier) Then
        $sClassifierDllType = "struct*"
    ElseIf $classifier == Null Then
        $sClassifierDllType = "ptr"
    Else
        $sClassifierDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCascadeClassifierRelease", $sClassifierDllType, $classifier), "cveCascadeClassifierRelease", @error)
EndFunc   ;==>_cveCascadeClassifierRelease

Func _cveCascadeClassifierDetectMultiScale($classifier, $image, $objects, $scaleFactor, $minNeighbors, $flags, $minSize, $maxSize)
    ; CVAPI(void) cveCascadeClassifierDetectMultiScale(cv::CascadeClassifier* classifier, cv::_InputArray* image, std::vector<cv::Rect>* objects, double scaleFactor, int minNeighbors, int flags, CvSize* minSize, CvSize* maxSize);

    Local $sClassifierDllType
    If IsDllStruct($classifier) Then
        $sClassifierDllType = "struct*"
    Else
        $sClassifierDllType = "ptr"
    EndIf

    Local $sImageDllType
    If IsDllStruct($image) Then
        $sImageDllType = "struct*"
    Else
        $sImageDllType = "ptr"
    EndIf

    Local $vecObjects, $iArrObjectsSize
    Local $bObjectsIsArray = VarGetType($objects) == "Array"

    If $bObjectsIsArray Then
        $vecObjects = _VectorOfRectCreate()

        $iArrObjectsSize = UBound($objects)
        For $i = 0 To $iArrObjectsSize - 1
            _VectorOfRectPush($vecObjects, $objects[$i])
        Next
    Else
        $vecObjects = $objects
    EndIf

    Local $sObjectsDllType
    If IsDllStruct($objects) Then
        $sObjectsDllType = "struct*"
    Else
        $sObjectsDllType = "ptr"
    EndIf

    Local $sMinSizeDllType
    If IsDllStruct($minSize) Then
        $sMinSizeDllType = "struct*"
    Else
        $sMinSizeDllType = "ptr"
    EndIf

    Local $sMaxSizeDllType
    If IsDllStruct($maxSize) Then
        $sMaxSizeDllType = "struct*"
    Else
        $sMaxSizeDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCascadeClassifierDetectMultiScale", $sClassifierDllType, $classifier, $sImageDllType, $image, $sObjectsDllType, $vecObjects, "double", $scaleFactor, "int", $minNeighbors, "int", $flags, $sMinSizeDllType, $minSize, $sMaxSizeDllType, $maxSize), "cveCascadeClassifierDetectMultiScale", @error)

    If $bObjectsIsArray Then
        _VectorOfRectRelease($vecObjects)
    EndIf
EndFunc   ;==>_cveCascadeClassifierDetectMultiScale

Func _cveCascadeClassifierDetectMultiScaleMat($classifier, $matImage, $objects, $scaleFactor, $minNeighbors, $flags, $minSize, $maxSize)
    ; cveCascadeClassifierDetectMultiScale using cv::Mat instead of _*Array

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

    _cveCascadeClassifierDetectMultiScale($classifier, $iArrImage, $objects, $scaleFactor, $minNeighbors, $flags, $minSize, $maxSize)

    If $bImageIsArray Then
        _VectorOfMatRelease($vectorOfMatImage)
    EndIf

    _cveInputArrayRelease($iArrImage)
EndFunc   ;==>_cveCascadeClassifierDetectMultiScaleMat

Func _cveCascadeClassifierIsOldFormatCascade($classifier)
    ; CVAPI(bool) cveCascadeClassifierIsOldFormatCascade(cv::CascadeClassifier* classifier);

    Local $sClassifierDllType
    If IsDllStruct($classifier) Then
        $sClassifierDllType = "struct*"
    Else
        $sClassifierDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveCascadeClassifierIsOldFormatCascade", $sClassifierDllType, $classifier), "cveCascadeClassifierIsOldFormatCascade", @error)
EndFunc   ;==>_cveCascadeClassifierIsOldFormatCascade

Func _cveCascadeClassifierGetOriginalWindowSize($classifier, $size)
    ; CVAPI(void) cveCascadeClassifierGetOriginalWindowSize(cv::CascadeClassifier* classifier, CvSize* size);

    Local $sClassifierDllType
    If IsDllStruct($classifier) Then
        $sClassifierDllType = "struct*"
    Else
        $sClassifierDllType = "ptr"
    EndIf

    Local $sSizeDllType
    If IsDllStruct($size) Then
        $sSizeDllType = "struct*"
    Else
        $sSizeDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCascadeClassifierGetOriginalWindowSize", $sClassifierDllType, $classifier, $sSizeDllType, $size), "cveCascadeClassifierGetOriginalWindowSize", @error)
EndFunc   ;==>_cveCascadeClassifierGetOriginalWindowSize

Func _cveGroupRectangles1($rectList, $groupThreshold, $eps)
    ; CVAPI(void) cveGroupRectangles1(std::vector<cv::Rect>* rectList, int groupThreshold, double eps);

    Local $vecRectList, $iArrRectListSize
    Local $bRectListIsArray = VarGetType($rectList) == "Array"

    If $bRectListIsArray Then
        $vecRectList = _VectorOfRectCreate()

        $iArrRectListSize = UBound($rectList)
        For $i = 0 To $iArrRectListSize - 1
            _VectorOfRectPush($vecRectList, $rectList[$i])
        Next
    Else
        $vecRectList = $rectList
    EndIf

    Local $sRectListDllType
    If IsDllStruct($rectList) Then
        $sRectListDllType = "struct*"
    Else
        $sRectListDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveGroupRectangles1", $sRectListDllType, $vecRectList, "int", $groupThreshold, "double", $eps), "cveGroupRectangles1", @error)

    If $bRectListIsArray Then
        _VectorOfRectRelease($vecRectList)
    EndIf
EndFunc   ;==>_cveGroupRectangles1

Func _cveGroupRectangles2($rectList, $weights, $groupThreshold, $eps)
    ; CVAPI(void) cveGroupRectangles2(std::vector<cv::Rect>* rectList, std::vector<int>* weights, int groupThreshold, double eps);

    Local $vecRectList, $iArrRectListSize
    Local $bRectListIsArray = VarGetType($rectList) == "Array"

    If $bRectListIsArray Then
        $vecRectList = _VectorOfRectCreate()

        $iArrRectListSize = UBound($rectList)
        For $i = 0 To $iArrRectListSize - 1
            _VectorOfRectPush($vecRectList, $rectList[$i])
        Next
    Else
        $vecRectList = $rectList
    EndIf

    Local $sRectListDllType
    If IsDllStruct($rectList) Then
        $sRectListDllType = "struct*"
    Else
        $sRectListDllType = "ptr"
    EndIf

    Local $vecWeights, $iArrWeightsSize
    Local $bWeightsIsArray = VarGetType($weights) == "Array"

    If $bWeightsIsArray Then
        $vecWeights = _VectorOfIntCreate()

        $iArrWeightsSize = UBound($weights)
        For $i = 0 To $iArrWeightsSize - 1
            _VectorOfIntPush($vecWeights, $weights[$i])
        Next
    Else
        $vecWeights = $weights
    EndIf

    Local $sWeightsDllType
    If IsDllStruct($weights) Then
        $sWeightsDllType = "struct*"
    Else
        $sWeightsDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveGroupRectangles2", $sRectListDllType, $vecRectList, $sWeightsDllType, $vecWeights, "int", $groupThreshold, "double", $eps), "cveGroupRectangles2", @error)

    If $bWeightsIsArray Then
        _VectorOfIntRelease($vecWeights)
    EndIf

    If $bRectListIsArray Then
        _VectorOfRectRelease($vecRectList)
    EndIf
EndFunc   ;==>_cveGroupRectangles2

Func _cveGroupRectangles3($rectList, $groupThreshold, $eps, $weights, $levelWeights)
    ; CVAPI(void) cveGroupRectangles3(std::vector<cv::Rect>* rectList, int groupThreshold, double eps, std::vector<int>* weights, std::vector<double>* levelWeights);

    Local $vecRectList, $iArrRectListSize
    Local $bRectListIsArray = VarGetType($rectList) == "Array"

    If $bRectListIsArray Then
        $vecRectList = _VectorOfRectCreate()

        $iArrRectListSize = UBound($rectList)
        For $i = 0 To $iArrRectListSize - 1
            _VectorOfRectPush($vecRectList, $rectList[$i])
        Next
    Else
        $vecRectList = $rectList
    EndIf

    Local $sRectListDllType
    If IsDllStruct($rectList) Then
        $sRectListDllType = "struct*"
    Else
        $sRectListDllType = "ptr"
    EndIf

    Local $vecWeights, $iArrWeightsSize
    Local $bWeightsIsArray = VarGetType($weights) == "Array"

    If $bWeightsIsArray Then
        $vecWeights = _VectorOfIntCreate()

        $iArrWeightsSize = UBound($weights)
        For $i = 0 To $iArrWeightsSize - 1
            _VectorOfIntPush($vecWeights, $weights[$i])
        Next
    Else
        $vecWeights = $weights
    EndIf

    Local $sWeightsDllType
    If IsDllStruct($weights) Then
        $sWeightsDllType = "struct*"
    Else
        $sWeightsDllType = "ptr"
    EndIf

    Local $vecLevelWeights, $iArrLevelWeightsSize
    Local $bLevelWeightsIsArray = VarGetType($levelWeights) == "Array"

    If $bLevelWeightsIsArray Then
        $vecLevelWeights = _VectorOfDoubleCreate()

        $iArrLevelWeightsSize = UBound($levelWeights)
        For $i = 0 To $iArrLevelWeightsSize - 1
            _VectorOfDoublePush($vecLevelWeights, $levelWeights[$i])
        Next
    Else
        $vecLevelWeights = $levelWeights
    EndIf

    Local $sLevelWeightsDllType
    If IsDllStruct($levelWeights) Then
        $sLevelWeightsDllType = "struct*"
    Else
        $sLevelWeightsDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveGroupRectangles3", $sRectListDllType, $vecRectList, "int", $groupThreshold, "double", $eps, $sWeightsDllType, $vecWeights, $sLevelWeightsDllType, $vecLevelWeights), "cveGroupRectangles3", @error)

    If $bLevelWeightsIsArray Then
        _VectorOfDoubleRelease($vecLevelWeights)
    EndIf

    If $bWeightsIsArray Then
        _VectorOfIntRelease($vecWeights)
    EndIf

    If $bRectListIsArray Then
        _VectorOfRectRelease($vecRectList)
    EndIf
EndFunc   ;==>_cveGroupRectangles3

Func _cveGroupRectangles4($rectList, $rejectLevels, $levelWeights, $groupThreshold, $eps)
    ; CVAPI(void) cveGroupRectangles4(std::vector<cv::Rect>* rectList, std::vector<int>* rejectLevels, std::vector<double>* levelWeights, int groupThreshold, double eps);

    Local $vecRectList, $iArrRectListSize
    Local $bRectListIsArray = VarGetType($rectList) == "Array"

    If $bRectListIsArray Then
        $vecRectList = _VectorOfRectCreate()

        $iArrRectListSize = UBound($rectList)
        For $i = 0 To $iArrRectListSize - 1
            _VectorOfRectPush($vecRectList, $rectList[$i])
        Next
    Else
        $vecRectList = $rectList
    EndIf

    Local $sRectListDllType
    If IsDllStruct($rectList) Then
        $sRectListDllType = "struct*"
    Else
        $sRectListDllType = "ptr"
    EndIf

    Local $vecRejectLevels, $iArrRejectLevelsSize
    Local $bRejectLevelsIsArray = VarGetType($rejectLevels) == "Array"

    If $bRejectLevelsIsArray Then
        $vecRejectLevels = _VectorOfIntCreate()

        $iArrRejectLevelsSize = UBound($rejectLevels)
        For $i = 0 To $iArrRejectLevelsSize - 1
            _VectorOfIntPush($vecRejectLevels, $rejectLevels[$i])
        Next
    Else
        $vecRejectLevels = $rejectLevels
    EndIf

    Local $sRejectLevelsDllType
    If IsDllStruct($rejectLevels) Then
        $sRejectLevelsDllType = "struct*"
    Else
        $sRejectLevelsDllType = "ptr"
    EndIf

    Local $vecLevelWeights, $iArrLevelWeightsSize
    Local $bLevelWeightsIsArray = VarGetType($levelWeights) == "Array"

    If $bLevelWeightsIsArray Then
        $vecLevelWeights = _VectorOfDoubleCreate()

        $iArrLevelWeightsSize = UBound($levelWeights)
        For $i = 0 To $iArrLevelWeightsSize - 1
            _VectorOfDoublePush($vecLevelWeights, $levelWeights[$i])
        Next
    Else
        $vecLevelWeights = $levelWeights
    EndIf

    Local $sLevelWeightsDllType
    If IsDllStruct($levelWeights) Then
        $sLevelWeightsDllType = "struct*"
    Else
        $sLevelWeightsDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveGroupRectangles4", $sRectListDllType, $vecRectList, $sRejectLevelsDllType, $vecRejectLevels, $sLevelWeightsDllType, $vecLevelWeights, "int", $groupThreshold, "double", $eps), "cveGroupRectangles4", @error)

    If $bLevelWeightsIsArray Then
        _VectorOfDoubleRelease($vecLevelWeights)
    EndIf

    If $bRejectLevelsIsArray Then
        _VectorOfIntRelease($vecRejectLevels)
    EndIf

    If $bRectListIsArray Then
        _VectorOfRectRelease($vecRectList)
    EndIf
EndFunc   ;==>_cveGroupRectangles4

Func _cveGroupRectanglesMeanshift($rectList, $foundWeights, $foundScales, $detectThreshold, $winDetSize)
    ; CVAPI(void) cveGroupRectanglesMeanshift(std::vector<cv::Rect>* rectList, std::vector<double>* foundWeights, std::vector<double>* foundScales, double detectThreshold, CvSize* winDetSize);

    Local $vecRectList, $iArrRectListSize
    Local $bRectListIsArray = VarGetType($rectList) == "Array"

    If $bRectListIsArray Then
        $vecRectList = _VectorOfRectCreate()

        $iArrRectListSize = UBound($rectList)
        For $i = 0 To $iArrRectListSize - 1
            _VectorOfRectPush($vecRectList, $rectList[$i])
        Next
    Else
        $vecRectList = $rectList
    EndIf

    Local $sRectListDllType
    If IsDllStruct($rectList) Then
        $sRectListDllType = "struct*"
    Else
        $sRectListDllType = "ptr"
    EndIf

    Local $vecFoundWeights, $iArrFoundWeightsSize
    Local $bFoundWeightsIsArray = VarGetType($foundWeights) == "Array"

    If $bFoundWeightsIsArray Then
        $vecFoundWeights = _VectorOfDoubleCreate()

        $iArrFoundWeightsSize = UBound($foundWeights)
        For $i = 0 To $iArrFoundWeightsSize - 1
            _VectorOfDoublePush($vecFoundWeights, $foundWeights[$i])
        Next
    Else
        $vecFoundWeights = $foundWeights
    EndIf

    Local $sFoundWeightsDllType
    If IsDllStruct($foundWeights) Then
        $sFoundWeightsDllType = "struct*"
    Else
        $sFoundWeightsDllType = "ptr"
    EndIf

    Local $vecFoundScales, $iArrFoundScalesSize
    Local $bFoundScalesIsArray = VarGetType($foundScales) == "Array"

    If $bFoundScalesIsArray Then
        $vecFoundScales = _VectorOfDoubleCreate()

        $iArrFoundScalesSize = UBound($foundScales)
        For $i = 0 To $iArrFoundScalesSize - 1
            _VectorOfDoublePush($vecFoundScales, $foundScales[$i])
        Next
    Else
        $vecFoundScales = $foundScales
    EndIf

    Local $sFoundScalesDllType
    If IsDllStruct($foundScales) Then
        $sFoundScalesDllType = "struct*"
    Else
        $sFoundScalesDllType = "ptr"
    EndIf

    Local $sWinDetSizeDllType
    If IsDllStruct($winDetSize) Then
        $sWinDetSizeDllType = "struct*"
    Else
        $sWinDetSizeDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveGroupRectanglesMeanshift", $sRectListDllType, $vecRectList, $sFoundWeightsDllType, $vecFoundWeights, $sFoundScalesDllType, $vecFoundScales, "double", $detectThreshold, $sWinDetSizeDllType, $winDetSize), "cveGroupRectanglesMeanshift", @error)

    If $bFoundScalesIsArray Then
        _VectorOfDoubleRelease($vecFoundScales)
    EndIf

    If $bFoundWeightsIsArray Then
        _VectorOfDoubleRelease($vecFoundWeights)
    EndIf

    If $bRectListIsArray Then
        _VectorOfRectRelease($vecRectList)
    EndIf
EndFunc   ;==>_cveGroupRectanglesMeanshift

Func _cveQRCodeDetectorCreate()
    ; CVAPI(cv::QRCodeDetector*) cveQRCodeDetectorCreate();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveQRCodeDetectorCreate"), "cveQRCodeDetectorCreate", @error)
EndFunc   ;==>_cveQRCodeDetectorCreate

Func _cveQRCodeDetectorRelease($detector)
    ; CVAPI(void) cveQRCodeDetectorRelease(cv::QRCodeDetector** detector);

    Local $sDetectorDllType
    If IsDllStruct($detector) Then
        $sDetectorDllType = "struct*"
    ElseIf $detector == Null Then
        $sDetectorDllType = "ptr"
    Else
        $sDetectorDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveQRCodeDetectorRelease", $sDetectorDllType, $detector), "cveQRCodeDetectorRelease", @error)
EndFunc   ;==>_cveQRCodeDetectorRelease

Func _cveQRCodeDetectorDetect($detector, $img, $points)
    ; CVAPI(bool) cveQRCodeDetectorDetect(cv::QRCodeDetector* detector, cv::_InputArray* img, cv::_OutputArray* points);

    Local $sDetectorDllType
    If IsDllStruct($detector) Then
        $sDetectorDllType = "struct*"
    Else
        $sDetectorDllType = "ptr"
    EndIf

    Local $sImgDllType
    If IsDllStruct($img) Then
        $sImgDllType = "struct*"
    Else
        $sImgDllType = "ptr"
    EndIf

    Local $sPointsDllType
    If IsDllStruct($points) Then
        $sPointsDllType = "struct*"
    Else
        $sPointsDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveQRCodeDetectorDetect", $sDetectorDllType, $detector, $sImgDllType, $img, $sPointsDllType, $points), "cveQRCodeDetectorDetect", @error)
EndFunc   ;==>_cveQRCodeDetectorDetect

Func _cveQRCodeDetectorDetectMat($detector, $matImg, $matPoints)
    ; cveQRCodeDetectorDetect using cv::Mat instead of _*Array

    Local $iArrImg, $vectorOfMatImg, $iArrImgSize
    Local $bImgIsArray = VarGetType($matImg) == "Array"

    If $bImgIsArray Then
        $vectorOfMatImg = _VectorOfMatCreate()

        $iArrImgSize = UBound($matImg)
        For $i = 0 To $iArrImgSize - 1
            _VectorOfMatPush($vectorOfMatImg, $matImg[$i])
        Next

        $iArrImg = _cveInputArrayFromVectorOfMat($vectorOfMatImg)
    Else
        $iArrImg = _cveInputArrayFromMat($matImg)
    EndIf

    Local $oArrPoints, $vectorOfMatPoints, $iArrPointsSize
    Local $bPointsIsArray = VarGetType($matPoints) == "Array"

    If $bPointsIsArray Then
        $vectorOfMatPoints = _VectorOfMatCreate()

        $iArrPointsSize = UBound($matPoints)
        For $i = 0 To $iArrPointsSize - 1
            _VectorOfMatPush($vectorOfMatPoints, $matPoints[$i])
        Next

        $oArrPoints = _cveOutputArrayFromVectorOfMat($vectorOfMatPoints)
    Else
        $oArrPoints = _cveOutputArrayFromMat($matPoints)
    EndIf

    Local $retval = _cveQRCodeDetectorDetect($detector, $iArrImg, $oArrPoints)

    If $bPointsIsArray Then
        _VectorOfMatRelease($vectorOfMatPoints)
    EndIf

    _cveOutputArrayRelease($oArrPoints)

    If $bImgIsArray Then
        _VectorOfMatRelease($vectorOfMatImg)
    EndIf

    _cveInputArrayRelease($iArrImg)

    Return $retval
EndFunc   ;==>_cveQRCodeDetectorDetectMat

Func _cveQRCodeDetectorDetectMulti($detector, $img, $points)
    ; CVAPI(bool) cveQRCodeDetectorDetectMulti(cv::QRCodeDetector* detector, cv::_InputArray* img, cv::_OutputArray* points);

    Local $sDetectorDllType
    If IsDllStruct($detector) Then
        $sDetectorDllType = "struct*"
    Else
        $sDetectorDllType = "ptr"
    EndIf

    Local $sImgDllType
    If IsDllStruct($img) Then
        $sImgDllType = "struct*"
    Else
        $sImgDllType = "ptr"
    EndIf

    Local $sPointsDllType
    If IsDllStruct($points) Then
        $sPointsDllType = "struct*"
    Else
        $sPointsDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveQRCodeDetectorDetectMulti", $sDetectorDllType, $detector, $sImgDllType, $img, $sPointsDllType, $points), "cveQRCodeDetectorDetectMulti", @error)
EndFunc   ;==>_cveQRCodeDetectorDetectMulti

Func _cveQRCodeDetectorDetectMultiMat($detector, $matImg, $matPoints)
    ; cveQRCodeDetectorDetectMulti using cv::Mat instead of _*Array

    Local $iArrImg, $vectorOfMatImg, $iArrImgSize
    Local $bImgIsArray = VarGetType($matImg) == "Array"

    If $bImgIsArray Then
        $vectorOfMatImg = _VectorOfMatCreate()

        $iArrImgSize = UBound($matImg)
        For $i = 0 To $iArrImgSize - 1
            _VectorOfMatPush($vectorOfMatImg, $matImg[$i])
        Next

        $iArrImg = _cveInputArrayFromVectorOfMat($vectorOfMatImg)
    Else
        $iArrImg = _cveInputArrayFromMat($matImg)
    EndIf

    Local $oArrPoints, $vectorOfMatPoints, $iArrPointsSize
    Local $bPointsIsArray = VarGetType($matPoints) == "Array"

    If $bPointsIsArray Then
        $vectorOfMatPoints = _VectorOfMatCreate()

        $iArrPointsSize = UBound($matPoints)
        For $i = 0 To $iArrPointsSize - 1
            _VectorOfMatPush($vectorOfMatPoints, $matPoints[$i])
        Next

        $oArrPoints = _cveOutputArrayFromVectorOfMat($vectorOfMatPoints)
    Else
        $oArrPoints = _cveOutputArrayFromMat($matPoints)
    EndIf

    Local $retval = _cveQRCodeDetectorDetectMulti($detector, $iArrImg, $oArrPoints)

    If $bPointsIsArray Then
        _VectorOfMatRelease($vectorOfMatPoints)
    EndIf

    _cveOutputArrayRelease($oArrPoints)

    If $bImgIsArray Then
        _VectorOfMatRelease($vectorOfMatImg)
    EndIf

    _cveInputArrayRelease($iArrImg)

    Return $retval
EndFunc   ;==>_cveQRCodeDetectorDetectMultiMat

Func _cveQRCodeDetectorDecode($detector, $img, $points, $decodedInfo, $straightQrcode)
    ; CVAPI(void) cveQRCodeDetectorDecode(cv::QRCodeDetector* detector, cv::_InputArray* img, cv::_InputArray* points, cv::String* decodedInfo, cv::_OutputArray* straightQrcode);

    Local $sDetectorDllType
    If IsDllStruct($detector) Then
        $sDetectorDllType = "struct*"
    Else
        $sDetectorDllType = "ptr"
    EndIf

    Local $sImgDllType
    If IsDllStruct($img) Then
        $sImgDllType = "struct*"
    Else
        $sImgDllType = "ptr"
    EndIf

    Local $sPointsDllType
    If IsDllStruct($points) Then
        $sPointsDllType = "struct*"
    Else
        $sPointsDllType = "ptr"
    EndIf

    Local $bDecodedInfoIsString = VarGetType($decodedInfo) == "String"
    If $bDecodedInfoIsString Then
        $decodedInfo = _cveStringCreateFromStr($decodedInfo)
    EndIf

    Local $sDecodedInfoDllType
    If IsDllStruct($decodedInfo) Then
        $sDecodedInfoDllType = "struct*"
    Else
        $sDecodedInfoDllType = "ptr"
    EndIf

    Local $sStraightQrcodeDllType
    If IsDllStruct($straightQrcode) Then
        $sStraightQrcodeDllType = "struct*"
    Else
        $sStraightQrcodeDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveQRCodeDetectorDecode", $sDetectorDllType, $detector, $sImgDllType, $img, $sPointsDllType, $points, $sDecodedInfoDllType, $decodedInfo, $sStraightQrcodeDllType, $straightQrcode), "cveQRCodeDetectorDecode", @error)

    If $bDecodedInfoIsString Then
        _cveStringRelease($decodedInfo)
    EndIf
EndFunc   ;==>_cveQRCodeDetectorDecode

Func _cveQRCodeDetectorDecodeMat($detector, $matImg, $matPoints, $decodedInfo, $matStraightQrcode)
    ; cveQRCodeDetectorDecode using cv::Mat instead of _*Array

    Local $iArrImg, $vectorOfMatImg, $iArrImgSize
    Local $bImgIsArray = VarGetType($matImg) == "Array"

    If $bImgIsArray Then
        $vectorOfMatImg = _VectorOfMatCreate()

        $iArrImgSize = UBound($matImg)
        For $i = 0 To $iArrImgSize - 1
            _VectorOfMatPush($vectorOfMatImg, $matImg[$i])
        Next

        $iArrImg = _cveInputArrayFromVectorOfMat($vectorOfMatImg)
    Else
        $iArrImg = _cveInputArrayFromMat($matImg)
    EndIf

    Local $iArrPoints, $vectorOfMatPoints, $iArrPointsSize
    Local $bPointsIsArray = VarGetType($matPoints) == "Array"

    If $bPointsIsArray Then
        $vectorOfMatPoints = _VectorOfMatCreate()

        $iArrPointsSize = UBound($matPoints)
        For $i = 0 To $iArrPointsSize - 1
            _VectorOfMatPush($vectorOfMatPoints, $matPoints[$i])
        Next

        $iArrPoints = _cveInputArrayFromVectorOfMat($vectorOfMatPoints)
    Else
        $iArrPoints = _cveInputArrayFromMat($matPoints)
    EndIf

    Local $oArrStraightQrcode, $vectorOfMatStraightQrcode, $iArrStraightQrcodeSize
    Local $bStraightQrcodeIsArray = VarGetType($matStraightQrcode) == "Array"

    If $bStraightQrcodeIsArray Then
        $vectorOfMatStraightQrcode = _VectorOfMatCreate()

        $iArrStraightQrcodeSize = UBound($matStraightQrcode)
        For $i = 0 To $iArrStraightQrcodeSize - 1
            _VectorOfMatPush($vectorOfMatStraightQrcode, $matStraightQrcode[$i])
        Next

        $oArrStraightQrcode = _cveOutputArrayFromVectorOfMat($vectorOfMatStraightQrcode)
    Else
        $oArrStraightQrcode = _cveOutputArrayFromMat($matStraightQrcode)
    EndIf

    _cveQRCodeDetectorDecode($detector, $iArrImg, $iArrPoints, $decodedInfo, $oArrStraightQrcode)

    If $bStraightQrcodeIsArray Then
        _VectorOfMatRelease($vectorOfMatStraightQrcode)
    EndIf

    _cveOutputArrayRelease($oArrStraightQrcode)

    If $bPointsIsArray Then
        _VectorOfMatRelease($vectorOfMatPoints)
    EndIf

    _cveInputArrayRelease($iArrPoints)

    If $bImgIsArray Then
        _VectorOfMatRelease($vectorOfMatImg)
    EndIf

    _cveInputArrayRelease($iArrImg)
EndFunc   ;==>_cveQRCodeDetectorDecodeMat

Func _cveQRCodeDetectorDecodeCurved($detector, $img, $points, $decodedInfo, $straightQrcode)
    ; CVAPI(void) cveQRCodeDetectorDecodeCurved(cv::QRCodeDetector* detector, cv::_InputArray* img, cv::_InputArray* points, cv::String* decodedInfo, cv::_OutputArray* straightQrcode);

    Local $sDetectorDllType
    If IsDllStruct($detector) Then
        $sDetectorDllType = "struct*"
    Else
        $sDetectorDllType = "ptr"
    EndIf

    Local $sImgDllType
    If IsDllStruct($img) Then
        $sImgDllType = "struct*"
    Else
        $sImgDllType = "ptr"
    EndIf

    Local $sPointsDllType
    If IsDllStruct($points) Then
        $sPointsDllType = "struct*"
    Else
        $sPointsDllType = "ptr"
    EndIf

    Local $bDecodedInfoIsString = VarGetType($decodedInfo) == "String"
    If $bDecodedInfoIsString Then
        $decodedInfo = _cveStringCreateFromStr($decodedInfo)
    EndIf

    Local $sDecodedInfoDllType
    If IsDllStruct($decodedInfo) Then
        $sDecodedInfoDllType = "struct*"
    Else
        $sDecodedInfoDllType = "ptr"
    EndIf

    Local $sStraightQrcodeDllType
    If IsDllStruct($straightQrcode) Then
        $sStraightQrcodeDllType = "struct*"
    Else
        $sStraightQrcodeDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveQRCodeDetectorDecodeCurved", $sDetectorDllType, $detector, $sImgDllType, $img, $sPointsDllType, $points, $sDecodedInfoDllType, $decodedInfo, $sStraightQrcodeDllType, $straightQrcode), "cveQRCodeDetectorDecodeCurved", @error)

    If $bDecodedInfoIsString Then
        _cveStringRelease($decodedInfo)
    EndIf
EndFunc   ;==>_cveQRCodeDetectorDecodeCurved

Func _cveQRCodeDetectorDecodeCurvedMat($detector, $matImg, $matPoints, $decodedInfo, $matStraightQrcode)
    ; cveQRCodeDetectorDecodeCurved using cv::Mat instead of _*Array

    Local $iArrImg, $vectorOfMatImg, $iArrImgSize
    Local $bImgIsArray = VarGetType($matImg) == "Array"

    If $bImgIsArray Then
        $vectorOfMatImg = _VectorOfMatCreate()

        $iArrImgSize = UBound($matImg)
        For $i = 0 To $iArrImgSize - 1
            _VectorOfMatPush($vectorOfMatImg, $matImg[$i])
        Next

        $iArrImg = _cveInputArrayFromVectorOfMat($vectorOfMatImg)
    Else
        $iArrImg = _cveInputArrayFromMat($matImg)
    EndIf

    Local $iArrPoints, $vectorOfMatPoints, $iArrPointsSize
    Local $bPointsIsArray = VarGetType($matPoints) == "Array"

    If $bPointsIsArray Then
        $vectorOfMatPoints = _VectorOfMatCreate()

        $iArrPointsSize = UBound($matPoints)
        For $i = 0 To $iArrPointsSize - 1
            _VectorOfMatPush($vectorOfMatPoints, $matPoints[$i])
        Next

        $iArrPoints = _cveInputArrayFromVectorOfMat($vectorOfMatPoints)
    Else
        $iArrPoints = _cveInputArrayFromMat($matPoints)
    EndIf

    Local $oArrStraightQrcode, $vectorOfMatStraightQrcode, $iArrStraightQrcodeSize
    Local $bStraightQrcodeIsArray = VarGetType($matStraightQrcode) == "Array"

    If $bStraightQrcodeIsArray Then
        $vectorOfMatStraightQrcode = _VectorOfMatCreate()

        $iArrStraightQrcodeSize = UBound($matStraightQrcode)
        For $i = 0 To $iArrStraightQrcodeSize - 1
            _VectorOfMatPush($vectorOfMatStraightQrcode, $matStraightQrcode[$i])
        Next

        $oArrStraightQrcode = _cveOutputArrayFromVectorOfMat($vectorOfMatStraightQrcode)
    Else
        $oArrStraightQrcode = _cveOutputArrayFromMat($matStraightQrcode)
    EndIf

    _cveQRCodeDetectorDecodeCurved($detector, $iArrImg, $iArrPoints, $decodedInfo, $oArrStraightQrcode)

    If $bStraightQrcodeIsArray Then
        _VectorOfMatRelease($vectorOfMatStraightQrcode)
    EndIf

    _cveOutputArrayRelease($oArrStraightQrcode)

    If $bPointsIsArray Then
        _VectorOfMatRelease($vectorOfMatPoints)
    EndIf

    _cveInputArrayRelease($iArrPoints)

    If $bImgIsArray Then
        _VectorOfMatRelease($vectorOfMatImg)
    EndIf

    _cveInputArrayRelease($iArrImg)
EndFunc   ;==>_cveQRCodeDetectorDecodeCurvedMat

Func _cveQRCodeDetectorDecodeMulti($detector, $img, $points, $decodedInfo, $straightQrcode)
    ; CVAPI(bool) cveQRCodeDetectorDecodeMulti(cv::QRCodeDetector* detector, cv::_InputArray* img, cv::_InputArray* points, std::vector<std::string>* decodedInfo, cv::_OutputArray* straightQrcode);

    Local $sDetectorDllType
    If IsDllStruct($detector) Then
        $sDetectorDllType = "struct*"
    Else
        $sDetectorDllType = "ptr"
    EndIf

    Local $sImgDllType
    If IsDllStruct($img) Then
        $sImgDllType = "struct*"
    Else
        $sImgDllType = "ptr"
    EndIf

    Local $sPointsDllType
    If IsDllStruct($points) Then
        $sPointsDllType = "struct*"
    Else
        $sPointsDllType = "ptr"
    EndIf

    Local $sDecodedInfoDllType
    If IsDllStruct($decodedInfo) Then
        $sDecodedInfoDllType = "struct*"
    Else
        $sDecodedInfoDllType = "ptr"
    EndIf

    Local $sStraightQrcodeDllType
    If IsDllStruct($straightQrcode) Then
        $sStraightQrcodeDllType = "struct*"
    Else
        $sStraightQrcodeDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveQRCodeDetectorDecodeMulti", $sDetectorDllType, $detector, $sImgDllType, $img, $sPointsDllType, $points, $sDecodedInfoDllType, $decodedInfo, $sStraightQrcodeDllType, $straightQrcode), "cveQRCodeDetectorDecodeMulti", @error)
EndFunc   ;==>_cveQRCodeDetectorDecodeMulti

Func _cveQRCodeDetectorDecodeMultiMat($detector, $matImg, $matPoints, $decodedInfo, $matStraightQrcode)
    ; cveQRCodeDetectorDecodeMulti using cv::Mat instead of _*Array

    Local $iArrImg, $vectorOfMatImg, $iArrImgSize
    Local $bImgIsArray = VarGetType($matImg) == "Array"

    If $bImgIsArray Then
        $vectorOfMatImg = _VectorOfMatCreate()

        $iArrImgSize = UBound($matImg)
        For $i = 0 To $iArrImgSize - 1
            _VectorOfMatPush($vectorOfMatImg, $matImg[$i])
        Next

        $iArrImg = _cveInputArrayFromVectorOfMat($vectorOfMatImg)
    Else
        $iArrImg = _cveInputArrayFromMat($matImg)
    EndIf

    Local $iArrPoints, $vectorOfMatPoints, $iArrPointsSize
    Local $bPointsIsArray = VarGetType($matPoints) == "Array"

    If $bPointsIsArray Then
        $vectorOfMatPoints = _VectorOfMatCreate()

        $iArrPointsSize = UBound($matPoints)
        For $i = 0 To $iArrPointsSize - 1
            _VectorOfMatPush($vectorOfMatPoints, $matPoints[$i])
        Next

        $iArrPoints = _cveInputArrayFromVectorOfMat($vectorOfMatPoints)
    Else
        $iArrPoints = _cveInputArrayFromMat($matPoints)
    EndIf

    Local $oArrStraightQrcode, $vectorOfMatStraightQrcode, $iArrStraightQrcodeSize
    Local $bStraightQrcodeIsArray = VarGetType($matStraightQrcode) == "Array"

    If $bStraightQrcodeIsArray Then
        $vectorOfMatStraightQrcode = _VectorOfMatCreate()

        $iArrStraightQrcodeSize = UBound($matStraightQrcode)
        For $i = 0 To $iArrStraightQrcodeSize - 1
            _VectorOfMatPush($vectorOfMatStraightQrcode, $matStraightQrcode[$i])
        Next

        $oArrStraightQrcode = _cveOutputArrayFromVectorOfMat($vectorOfMatStraightQrcode)
    Else
        $oArrStraightQrcode = _cveOutputArrayFromMat($matStraightQrcode)
    EndIf

    Local $retval = _cveQRCodeDetectorDecodeMulti($detector, $iArrImg, $iArrPoints, $decodedInfo, $oArrStraightQrcode)

    If $bStraightQrcodeIsArray Then
        _VectorOfMatRelease($vectorOfMatStraightQrcode)
    EndIf

    _cveOutputArrayRelease($oArrStraightQrcode)

    If $bPointsIsArray Then
        _VectorOfMatRelease($vectorOfMatPoints)
    EndIf

    _cveInputArrayRelease($iArrPoints)

    If $bImgIsArray Then
        _VectorOfMatRelease($vectorOfMatImg)
    EndIf

    _cveInputArrayRelease($iArrImg)

    Return $retval
EndFunc   ;==>_cveQRCodeDetectorDecodeMultiMat