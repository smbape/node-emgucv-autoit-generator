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

    Local $bSeqDllType
    If VarGetType($seq) == "DLLStruct" Then
        $bSeqDllType = "struct*"
    Else
        $bSeqDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveHOGDescriptorPeopleDetectorCreate", $bSeqDllType, $vecSeq), "cveHOGDescriptorPeopleDetectorCreate", @error)

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

    Local $b_winSizeDllType
    If VarGetType($_winSize) == "DLLStruct" Then
        $b_winSizeDllType = "struct*"
    Else
        $b_winSizeDllType = "ptr"
    EndIf

    Local $b_blockSizeDllType
    If VarGetType($_blockSize) == "DLLStruct" Then
        $b_blockSizeDllType = "struct*"
    Else
        $b_blockSizeDllType = "ptr"
    EndIf

    Local $b_blockStrideDllType
    If VarGetType($_blockStride) == "DLLStruct" Then
        $b_blockStrideDllType = "struct*"
    Else
        $b_blockStrideDllType = "ptr"
    EndIf

    Local $b_cellSizeDllType
    If VarGetType($_cellSize) == "DLLStruct" Then
        $b_cellSizeDllType = "struct*"
    Else
        $b_cellSizeDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveHOGDescriptorCreate", $b_winSizeDllType, $_winSize, $b_blockSizeDllType, $_blockSize, $b_blockStrideDllType, $_blockStride, $b_cellSizeDllType, $_cellSize, "int", $_nbins, "int", $_derivAperture, "double", $_winSigma, "int", $_histogramNormType, "double", $_L2HysThreshold, "boolean", $_gammaCorrection), "cveHOGDescriptorCreate", @error)
EndFunc   ;==>_cveHOGDescriptorCreate

Func _cveHOGSetSVMDetector($descriptor, $vector)
    ; CVAPI(void) cveHOGSetSVMDetector(cv::HOGDescriptor* descriptor, std::vector<float>* vector);

    Local $bDescriptorDllType
    If VarGetType($descriptor) == "DLLStruct" Then
        $bDescriptorDllType = "struct*"
    Else
        $bDescriptorDllType = "ptr"
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

    Local $bVectorDllType
    If VarGetType($vector) == "DLLStruct" Then
        $bVectorDllType = "struct*"
    Else
        $bVectorDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveHOGSetSVMDetector", $bDescriptorDllType, $descriptor, $bVectorDllType, $vecVector), "cveHOGSetSVMDetector", @error)

    If $bVectorIsArray Then
        _VectorOfFloatRelease($vecVector)
    EndIf
EndFunc   ;==>_cveHOGSetSVMDetector

Func _cveHOGDescriptorRelease($descriptor)
    ; CVAPI(void) cveHOGDescriptorRelease(cv::HOGDescriptor** descriptor);

    Local $bDescriptorDllType
    If VarGetType($descriptor) == "DLLStruct" Then
        $bDescriptorDllType = "struct*"
    Else
        $bDescriptorDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveHOGDescriptorRelease", $bDescriptorDllType, $descriptor), "cveHOGDescriptorRelease", @error)
EndFunc   ;==>_cveHOGDescriptorRelease

Func _cveHOGDescriptorDetectMultiScale($descriptor, $img, $foundLocations, $weights, $hitThreshold, $winStride, $padding, $scale, $finalThreshold, $useMeanshiftGrouping)
    ; CVAPI(void) cveHOGDescriptorDetectMultiScale(cv::HOGDescriptor* descriptor, cv::_InputArray* img, std::vector<cv::Rect>* foundLocations, std::vector<double>* weights, double hitThreshold, CvSize* winStride, CvSize* padding, double scale, double finalThreshold, bool useMeanshiftGrouping);

    Local $bDescriptorDllType
    If VarGetType($descriptor) == "DLLStruct" Then
        $bDescriptorDllType = "struct*"
    Else
        $bDescriptorDllType = "ptr"
    EndIf

    Local $bImgDllType
    If VarGetType($img) == "DLLStruct" Then
        $bImgDllType = "struct*"
    Else
        $bImgDllType = "ptr"
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

    Local $bFoundLocationsDllType
    If VarGetType($foundLocations) == "DLLStruct" Then
        $bFoundLocationsDllType = "struct*"
    Else
        $bFoundLocationsDllType = "ptr"
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

    Local $bWeightsDllType
    If VarGetType($weights) == "DLLStruct" Then
        $bWeightsDllType = "struct*"
    Else
        $bWeightsDllType = "ptr"
    EndIf

    Local $bWinStrideDllType
    If VarGetType($winStride) == "DLLStruct" Then
        $bWinStrideDllType = "struct*"
    Else
        $bWinStrideDllType = "ptr"
    EndIf

    Local $bPaddingDllType
    If VarGetType($padding) == "DLLStruct" Then
        $bPaddingDllType = "struct*"
    Else
        $bPaddingDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveHOGDescriptorDetectMultiScale", $bDescriptorDllType, $descriptor, $bImgDllType, $img, $bFoundLocationsDllType, $vecFoundLocations, $bWeightsDllType, $vecWeights, "double", $hitThreshold, $bWinStrideDllType, $winStride, $bPaddingDllType, $padding, "double", $scale, "double", $finalThreshold, "boolean", $useMeanshiftGrouping), "cveHOGDescriptorDetectMultiScale", @error)

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
    ; CVAPI(void) cveHOGDescriptorCompute(cv::HOGDescriptor * descriptor, cv::_InputArray* img, std::vector<float> * descriptors, CvSize* winStride, CvSize* padding, std::vector< cv::Point >* locations);

    Local $bDescriptorDllType
    If VarGetType($descriptor) == "DLLStruct" Then
        $bDescriptorDllType = "struct*"
    Else
        $bDescriptorDllType = "ptr"
    EndIf

    Local $bImgDllType
    If VarGetType($img) == "DLLStruct" Then
        $bImgDllType = "struct*"
    Else
        $bImgDllType = "ptr"
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

    Local $bDescriptorsDllType
    If VarGetType($descriptors) == "DLLStruct" Then
        $bDescriptorsDllType = "struct*"
    Else
        $bDescriptorsDllType = "ptr"
    EndIf

    Local $bWinStrideDllType
    If VarGetType($winStride) == "DLLStruct" Then
        $bWinStrideDllType = "struct*"
    Else
        $bWinStrideDllType = "ptr"
    EndIf

    Local $bPaddingDllType
    If VarGetType($padding) == "DLLStruct" Then
        $bPaddingDllType = "struct*"
    Else
        $bPaddingDllType = "ptr"
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

    Local $bLocationsDllType
    If VarGetType($locations) == "DLLStruct" Then
        $bLocationsDllType = "struct*"
    Else
        $bLocationsDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveHOGDescriptorCompute", $bDescriptorDllType, $descriptor, $bImgDllType, $img, $bDescriptorsDllType, $vecDescriptors, $bWinStrideDllType, $winStride, $bPaddingDllType, $padding, $bLocationsDllType, $vecLocations), "cveHOGDescriptorCompute", @error)

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
    ; CVAPI(unsigned) cveHOGDescriptorGetDescriptorSize(cv::HOGDescriptor* descriptor);

    Local $bDescriptorDllType
    If VarGetType($descriptor) == "DLLStruct" Then
        $bDescriptorDllType = "struct*"
    Else
        $bDescriptorDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "uint:cdecl", "cveHOGDescriptorGetDescriptorSize", $bDescriptorDllType, $descriptor), "cveHOGDescriptorGetDescriptorSize", @error)
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

    Local $bFileNameDllType
    If VarGetType($fileName) == "DLLStruct" Then
        $bFileNameDllType = "struct*"
    Else
        $bFileNameDllType = "ptr"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveCascadeClassifierCreateFromFile", $bFileNameDllType, $fileName), "cveCascadeClassifierCreateFromFile", @error)

    If $bFileNameIsString Then
        _cveStringRelease($fileName)
    EndIf

    Return $retval
EndFunc   ;==>_cveCascadeClassifierCreateFromFile

Func _cveCascadeClassifierRead($classifier, $node)
    ; CVAPI(bool) cveCascadeClassifierRead(cv::CascadeClassifier* classifier, cv::FileNode* node);

    Local $bClassifierDllType
    If VarGetType($classifier) == "DLLStruct" Then
        $bClassifierDllType = "struct*"
    Else
        $bClassifierDllType = "ptr"
    EndIf

    Local $bNodeDllType
    If VarGetType($node) == "DLLStruct" Then
        $bNodeDllType = "struct*"
    Else
        $bNodeDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveCascadeClassifierRead", $bClassifierDllType, $classifier, $bNodeDllType, $node), "cveCascadeClassifierRead", @error)
EndFunc   ;==>_cveCascadeClassifierRead

Func _cveCascadeClassifierRelease($classifier)
    ; CVAPI(void) cveCascadeClassifierRelease(cv::CascadeClassifier** classifier);

    Local $bClassifierDllType
    If VarGetType($classifier) == "DLLStruct" Then
        $bClassifierDllType = "struct*"
    Else
        $bClassifierDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCascadeClassifierRelease", $bClassifierDllType, $classifier), "cveCascadeClassifierRelease", @error)
EndFunc   ;==>_cveCascadeClassifierRelease

Func _cveCascadeClassifierDetectMultiScale($classifier, $image, $objects, $scaleFactor, $minNeighbors, $flags, $minSize, $maxSize)
    ; CVAPI(void) cveCascadeClassifierDetectMultiScale(cv::CascadeClassifier* classifier, cv::_InputArray* image, std::vector<cv::Rect>* objects, double scaleFactor, int minNeighbors, int flags, CvSize* minSize, CvSize* maxSize);

    Local $bClassifierDllType
    If VarGetType($classifier) == "DLLStruct" Then
        $bClassifierDllType = "struct*"
    Else
        $bClassifierDllType = "ptr"
    EndIf

    Local $bImageDllType
    If VarGetType($image) == "DLLStruct" Then
        $bImageDllType = "struct*"
    Else
        $bImageDllType = "ptr"
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

    Local $bObjectsDllType
    If VarGetType($objects) == "DLLStruct" Then
        $bObjectsDllType = "struct*"
    Else
        $bObjectsDllType = "ptr"
    EndIf

    Local $bMinSizeDllType
    If VarGetType($minSize) == "DLLStruct" Then
        $bMinSizeDllType = "struct*"
    Else
        $bMinSizeDllType = "ptr"
    EndIf

    Local $bMaxSizeDllType
    If VarGetType($maxSize) == "DLLStruct" Then
        $bMaxSizeDllType = "struct*"
    Else
        $bMaxSizeDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCascadeClassifierDetectMultiScale", $bClassifierDllType, $classifier, $bImageDllType, $image, $bObjectsDllType, $vecObjects, "double", $scaleFactor, "int", $minNeighbors, "int", $flags, $bMinSizeDllType, $minSize, $bMaxSizeDllType, $maxSize), "cveCascadeClassifierDetectMultiScale", @error)

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

    Local $bClassifierDllType
    If VarGetType($classifier) == "DLLStruct" Then
        $bClassifierDllType = "struct*"
    Else
        $bClassifierDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveCascadeClassifierIsOldFormatCascade", $bClassifierDllType, $classifier), "cveCascadeClassifierIsOldFormatCascade", @error)
EndFunc   ;==>_cveCascadeClassifierIsOldFormatCascade

Func _cveCascadeClassifierGetOriginalWindowSize($classifier, $size)
    ; CVAPI(void) cveCascadeClassifierGetOriginalWindowSize(cv::CascadeClassifier* classifier, CvSize* size);

    Local $bClassifierDllType
    If VarGetType($classifier) == "DLLStruct" Then
        $bClassifierDllType = "struct*"
    Else
        $bClassifierDllType = "ptr"
    EndIf

    Local $bSizeDllType
    If VarGetType($size) == "DLLStruct" Then
        $bSizeDllType = "struct*"
    Else
        $bSizeDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCascadeClassifierGetOriginalWindowSize", $bClassifierDllType, $classifier, $bSizeDllType, $size), "cveCascadeClassifierGetOriginalWindowSize", @error)
EndFunc   ;==>_cveCascadeClassifierGetOriginalWindowSize

Func _cveGroupRectangles1($rectList, $groupThreshold, $eps)
    ; CVAPI(void) cveGroupRectangles1(std::vector< cv::Rect >* rectList, int groupThreshold, double eps);

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

    Local $bRectListDllType
    If VarGetType($rectList) == "DLLStruct" Then
        $bRectListDllType = "struct*"
    Else
        $bRectListDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveGroupRectangles1", $bRectListDllType, $vecRectList, "int", $groupThreshold, "double", $eps), "cveGroupRectangles1", @error)

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

    Local $bRectListDllType
    If VarGetType($rectList) == "DLLStruct" Then
        $bRectListDllType = "struct*"
    Else
        $bRectListDllType = "ptr"
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

    Local $bWeightsDllType
    If VarGetType($weights) == "DLLStruct" Then
        $bWeightsDllType = "struct*"
    Else
        $bWeightsDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveGroupRectangles2", $bRectListDllType, $vecRectList, $bWeightsDllType, $vecWeights, "int", $groupThreshold, "double", $eps), "cveGroupRectangles2", @error)

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

    Local $bRectListDllType
    If VarGetType($rectList) == "DLLStruct" Then
        $bRectListDllType = "struct*"
    Else
        $bRectListDllType = "ptr"
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

    Local $bWeightsDllType
    If VarGetType($weights) == "DLLStruct" Then
        $bWeightsDllType = "struct*"
    Else
        $bWeightsDllType = "ptr"
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

    Local $bLevelWeightsDllType
    If VarGetType($levelWeights) == "DLLStruct" Then
        $bLevelWeightsDllType = "struct*"
    Else
        $bLevelWeightsDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveGroupRectangles3", $bRectListDllType, $vecRectList, "int", $groupThreshold, "double", $eps, $bWeightsDllType, $vecWeights, $bLevelWeightsDllType, $vecLevelWeights), "cveGroupRectangles3", @error)

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

    Local $bRectListDllType
    If VarGetType($rectList) == "DLLStruct" Then
        $bRectListDllType = "struct*"
    Else
        $bRectListDllType = "ptr"
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

    Local $bRejectLevelsDllType
    If VarGetType($rejectLevels) == "DLLStruct" Then
        $bRejectLevelsDllType = "struct*"
    Else
        $bRejectLevelsDllType = "ptr"
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

    Local $bLevelWeightsDllType
    If VarGetType($levelWeights) == "DLLStruct" Then
        $bLevelWeightsDllType = "struct*"
    Else
        $bLevelWeightsDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveGroupRectangles4", $bRectListDllType, $vecRectList, $bRejectLevelsDllType, $vecRejectLevels, $bLevelWeightsDllType, $vecLevelWeights, "int", $groupThreshold, "double", $eps), "cveGroupRectangles4", @error)

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

    Local $bRectListDllType
    If VarGetType($rectList) == "DLLStruct" Then
        $bRectListDllType = "struct*"
    Else
        $bRectListDllType = "ptr"
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

    Local $bFoundWeightsDllType
    If VarGetType($foundWeights) == "DLLStruct" Then
        $bFoundWeightsDllType = "struct*"
    Else
        $bFoundWeightsDllType = "ptr"
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

    Local $bFoundScalesDllType
    If VarGetType($foundScales) == "DLLStruct" Then
        $bFoundScalesDllType = "struct*"
    Else
        $bFoundScalesDllType = "ptr"
    EndIf

    Local $bWinDetSizeDllType
    If VarGetType($winDetSize) == "DLLStruct" Then
        $bWinDetSizeDllType = "struct*"
    Else
        $bWinDetSizeDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveGroupRectanglesMeanshift", $bRectListDllType, $vecRectList, $bFoundWeightsDllType, $vecFoundWeights, $bFoundScalesDllType, $vecFoundScales, "double", $detectThreshold, $bWinDetSizeDllType, $winDetSize), "cveGroupRectanglesMeanshift", @error)

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

    Local $bDetectorDllType
    If VarGetType($detector) == "DLLStruct" Then
        $bDetectorDllType = "struct*"
    Else
        $bDetectorDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveQRCodeDetectorRelease", $bDetectorDllType, $detector), "cveQRCodeDetectorRelease", @error)
EndFunc   ;==>_cveQRCodeDetectorRelease

Func _cveQRCodeDetectorDetect($detector, $img, $points)
    ; CVAPI(bool) cveQRCodeDetectorDetect(cv::QRCodeDetector* detector, cv::_InputArray* img, cv::_OutputArray* points);

    Local $bDetectorDllType
    If VarGetType($detector) == "DLLStruct" Then
        $bDetectorDllType = "struct*"
    Else
        $bDetectorDllType = "ptr"
    EndIf

    Local $bImgDllType
    If VarGetType($img) == "DLLStruct" Then
        $bImgDllType = "struct*"
    Else
        $bImgDllType = "ptr"
    EndIf

    Local $bPointsDllType
    If VarGetType($points) == "DLLStruct" Then
        $bPointsDllType = "struct*"
    Else
        $bPointsDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveQRCodeDetectorDetect", $bDetectorDllType, $detector, $bImgDllType, $img, $bPointsDllType, $points), "cveQRCodeDetectorDetect", @error)
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

    Local $bDetectorDllType
    If VarGetType($detector) == "DLLStruct" Then
        $bDetectorDllType = "struct*"
    Else
        $bDetectorDllType = "ptr"
    EndIf

    Local $bImgDllType
    If VarGetType($img) == "DLLStruct" Then
        $bImgDllType = "struct*"
    Else
        $bImgDllType = "ptr"
    EndIf

    Local $bPointsDllType
    If VarGetType($points) == "DLLStruct" Then
        $bPointsDllType = "struct*"
    Else
        $bPointsDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveQRCodeDetectorDetectMulti", $bDetectorDllType, $detector, $bImgDllType, $img, $bPointsDllType, $points), "cveQRCodeDetectorDetectMulti", @error)
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

    Local $bDetectorDllType
    If VarGetType($detector) == "DLLStruct" Then
        $bDetectorDllType = "struct*"
    Else
        $bDetectorDllType = "ptr"
    EndIf

    Local $bImgDllType
    If VarGetType($img) == "DLLStruct" Then
        $bImgDllType = "struct*"
    Else
        $bImgDllType = "ptr"
    EndIf

    Local $bPointsDllType
    If VarGetType($points) == "DLLStruct" Then
        $bPointsDllType = "struct*"
    Else
        $bPointsDllType = "ptr"
    EndIf

    Local $bDecodedInfoIsString = VarGetType($decodedInfo) == "String"
    If $bDecodedInfoIsString Then
        $decodedInfo = _cveStringCreateFromStr($decodedInfo)
    EndIf

    Local $bDecodedInfoDllType
    If VarGetType($decodedInfo) == "DLLStruct" Then
        $bDecodedInfoDllType = "struct*"
    Else
        $bDecodedInfoDllType = "ptr"
    EndIf

    Local $bStraightQrcodeDllType
    If VarGetType($straightQrcode) == "DLLStruct" Then
        $bStraightQrcodeDllType = "struct*"
    Else
        $bStraightQrcodeDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveQRCodeDetectorDecode", $bDetectorDllType, $detector, $bImgDllType, $img, $bPointsDllType, $points, $bDecodedInfoDllType, $decodedInfo, $bStraightQrcodeDllType, $straightQrcode), "cveQRCodeDetectorDecode", @error)

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

    Local $bDetectorDllType
    If VarGetType($detector) == "DLLStruct" Then
        $bDetectorDllType = "struct*"
    Else
        $bDetectorDllType = "ptr"
    EndIf

    Local $bImgDllType
    If VarGetType($img) == "DLLStruct" Then
        $bImgDllType = "struct*"
    Else
        $bImgDllType = "ptr"
    EndIf

    Local $bPointsDllType
    If VarGetType($points) == "DLLStruct" Then
        $bPointsDllType = "struct*"
    Else
        $bPointsDllType = "ptr"
    EndIf

    Local $bDecodedInfoIsString = VarGetType($decodedInfo) == "String"
    If $bDecodedInfoIsString Then
        $decodedInfo = _cveStringCreateFromStr($decodedInfo)
    EndIf

    Local $bDecodedInfoDllType
    If VarGetType($decodedInfo) == "DLLStruct" Then
        $bDecodedInfoDllType = "struct*"
    Else
        $bDecodedInfoDllType = "ptr"
    EndIf

    Local $bStraightQrcodeDllType
    If VarGetType($straightQrcode) == "DLLStruct" Then
        $bStraightQrcodeDllType = "struct*"
    Else
        $bStraightQrcodeDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveQRCodeDetectorDecodeCurved", $bDetectorDllType, $detector, $bImgDllType, $img, $bPointsDllType, $points, $bDecodedInfoDllType, $decodedInfo, $bStraightQrcodeDllType, $straightQrcode), "cveQRCodeDetectorDecodeCurved", @error)

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
    ; CVAPI(bool) cveQRCodeDetectorDecodeMulti(cv::QRCodeDetector* detector, cv::_InputArray* img, cv::_InputArray* points, std::vector< std::string >* decodedInfo, cv::_OutputArray* straightQrcode);

    Local $bDetectorDllType
    If VarGetType($detector) == "DLLStruct" Then
        $bDetectorDllType = "struct*"
    Else
        $bDetectorDllType = "ptr"
    EndIf

    Local $bImgDllType
    If VarGetType($img) == "DLLStruct" Then
        $bImgDllType = "struct*"
    Else
        $bImgDllType = "ptr"
    EndIf

    Local $bPointsDllType
    If VarGetType($points) == "DLLStruct" Then
        $bPointsDllType = "struct*"
    Else
        $bPointsDllType = "ptr"
    EndIf

    Local $bDecodedInfoDllType
    If VarGetType($decodedInfo) == "DLLStruct" Then
        $bDecodedInfoDllType = "struct*"
    Else
        $bDecodedInfoDllType = "ptr"
    EndIf

    Local $bStraightQrcodeDllType
    If VarGetType($straightQrcode) == "DLLStruct" Then
        $bStraightQrcodeDllType = "struct*"
    Else
        $bStraightQrcodeDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveQRCodeDetectorDecodeMulti", $bDetectorDllType, $detector, $bImgDllType, $img, $bPointsDllType, $points, $bDecodedInfoDllType, $decodedInfo, $bStraightQrcodeDllType, $straightQrcode), "cveQRCodeDetectorDecodeMulti", @error)
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