#include-once
#include <..\..\CVEUtils.au3>

Func _cveHOGDescriptorPeopleDetectorCreate(ByRef $seq)
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveHOGDescriptorPeopleDetectorCreate", "ptr", $vecSeq), "cveHOGDescriptorPeopleDetectorCreate", @error)

    If $bSeqIsArray Then
        _VectorOfFloatRelease($vecSeq)
    EndIf
EndFunc   ;==>_cveHOGDescriptorPeopleDetectorCreate

Func _cveHOGDescriptorCreateDefault()
    ; CVAPI(cv::HOGDescriptor*) cveHOGDescriptorCreateDefault();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveHOGDescriptorCreateDefault"), "cveHOGDescriptorCreateDefault", @error)
EndFunc   ;==>_cveHOGDescriptorCreateDefault

Func _cveHOGDescriptorCreate(ByRef $_winSize, ByRef $_blockSize, ByRef $_blockStride, ByRef $_cellSize, $_nbins, $_derivAperture, $_winSigma, $_histogramNormType, $_L2HysThreshold, $_gammaCorrection)
    ; CVAPI(cv::HOGDescriptor*) cveHOGDescriptorCreate(CvSize* _winSize, CvSize* _blockSize, CvSize* _blockStride, CvSize* _cellSize, int _nbins, int _derivAperture, double _winSigma, int _histogramNormType, double _L2HysThreshold, bool _gammaCorrection);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveHOGDescriptorCreate", "struct*", $_winSize, "struct*", $_blockSize, "struct*", $_blockStride, "struct*", $_cellSize, "int", $_nbins, "int", $_derivAperture, "double", $_winSigma, "int", $_histogramNormType, "double", $_L2HysThreshold, "boolean", $_gammaCorrection), "cveHOGDescriptorCreate", @error)
EndFunc   ;==>_cveHOGDescriptorCreate

Func _cveHOGSetSVMDetector(ByRef $descriptor, ByRef $vector)
    ; CVAPI(void) cveHOGSetSVMDetector(cv::HOGDescriptor* descriptor, std::vector<float>* vector);

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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveHOGSetSVMDetector", "ptr", $descriptor, "ptr", $vecVector), "cveHOGSetSVMDetector", @error)

    If $bVectorIsArray Then
        _VectorOfFloatRelease($vecVector)
    EndIf
EndFunc   ;==>_cveHOGSetSVMDetector

Func _cveHOGDescriptorRelease(ByRef $descriptor)
    ; CVAPI(void) cveHOGDescriptorRelease(cv::HOGDescriptor** descriptor);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveHOGDescriptorRelease", "ptr*", $descriptor), "cveHOGDescriptorRelease", @error)
EndFunc   ;==>_cveHOGDescriptorRelease

Func _cveHOGDescriptorDetectMultiScale(ByRef $descriptor, ByRef $img, ByRef $foundLocations, ByRef $weights, $hitThreshold, ByRef $winStride, ByRef $padding, $scale, $finalThreshold, $useMeanshiftGrouping)
    ; CVAPI(void) cveHOGDescriptorDetectMultiScale(cv::HOGDescriptor* descriptor, cv::_InputArray* img, std::vector<cv::Rect>* foundLocations, std::vector<double>* weights, double hitThreshold, CvSize* winStride, CvSize* padding, double scale, double finalThreshold, bool useMeanshiftGrouping);

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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveHOGDescriptorDetectMultiScale", "ptr", $descriptor, "ptr", $img, "ptr", $vecFoundLocations, "ptr", $vecWeights, "double", $hitThreshold, "struct*", $winStride, "struct*", $padding, "double", $scale, "double", $finalThreshold, "boolean", $useMeanshiftGrouping), "cveHOGDescriptorDetectMultiScale", @error)

    If $bWeightsIsArray Then
        _VectorOfDoubleRelease($vecWeights)
    EndIf

    If $bFoundLocationsIsArray Then
        _VectorOfRectRelease($vecFoundLocations)
    EndIf
EndFunc   ;==>_cveHOGDescriptorDetectMultiScale

Func _cveHOGDescriptorDetectMultiScaleMat(ByRef $descriptor, ByRef $matImg, ByRef $foundLocations, ByRef $weights, $hitThreshold, ByRef $winStride, ByRef $padding, $scale, $finalThreshold, $useMeanshiftGrouping)
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

Func _cveHOGDescriptorCompute(ByRef $descriptor, ByRef $img, ByRef $descriptors, ByRef $winStride, ByRef $padding, ByRef $locations)
    ; CVAPI(void) cveHOGDescriptorCompute(cv::HOGDescriptor * descriptor, cv::_InputArray* img, std::vector<float> * descriptors, CvSize* winStride, CvSize* padding, std::vector< cv::Point >* locations);

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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveHOGDescriptorCompute", "ptr", $descriptor, "ptr", $img, "ptr", $vecDescriptors, "struct*", $winStride, "struct*", $padding, "ptr", $vecLocations), "cveHOGDescriptorCompute", @error)

    If $bLocationsIsArray Then
        _VectorOfPointRelease($vecLocations)
    EndIf

    If $bDescriptorsIsArray Then
        _VectorOfFloatRelease($vecDescriptors)
    EndIf
EndFunc   ;==>_cveHOGDescriptorCompute

Func _cveHOGDescriptorComputeMat(ByRef $descriptor, ByRef $matImg, ByRef $descriptors, ByRef $winStride, ByRef $padding, ByRef $locations)
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

Func _cveHOGDescriptorGetDescriptorSize(ByRef $descriptor)
    ; CVAPI(unsigned) cveHOGDescriptorGetDescriptorSize(cv::HOGDescriptor* descriptor);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "unsigned:cdecl", "cveHOGDescriptorGetDescriptorSize", "ptr", $descriptor), "cveHOGDescriptorGetDescriptorSize", @error)
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveCascadeClassifierCreateFromFile", "ptr", $fileName), "cveCascadeClassifierCreateFromFile", @error)

    If $bFileNameIsString Then
        _cveStringRelease($fileName)
    EndIf

    Return $retval
EndFunc   ;==>_cveCascadeClassifierCreateFromFile

Func _cveCascadeClassifierRead(ByRef $classifier, ByRef $node)
    ; CVAPI(bool) cveCascadeClassifierRead(cv::CascadeClassifier* classifier, cv::FileNode* node);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveCascadeClassifierRead", "ptr", $classifier, "ptr", $node), "cveCascadeClassifierRead", @error)
EndFunc   ;==>_cveCascadeClassifierRead

Func _cveCascadeClassifierRelease(ByRef $classifier)
    ; CVAPI(void) cveCascadeClassifierRelease(cv::CascadeClassifier** classifier);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCascadeClassifierRelease", "ptr*", $classifier), "cveCascadeClassifierRelease", @error)
EndFunc   ;==>_cveCascadeClassifierRelease

Func _cveCascadeClassifierDetectMultiScale(ByRef $classifier, ByRef $image, ByRef $objects, $scaleFactor, $minNeighbors, $flags, ByRef $minSize, ByRef $maxSize)
    ; CVAPI(void) cveCascadeClassifierDetectMultiScale(cv::CascadeClassifier* classifier, cv::_InputArray* image, std::vector<cv::Rect>* objects, double scaleFactor, int minNeighbors, int flags, CvSize* minSize, CvSize* maxSize);

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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCascadeClassifierDetectMultiScale", "ptr", $classifier, "ptr", $image, "ptr", $vecObjects, "double", $scaleFactor, "int", $minNeighbors, "int", $flags, "struct*", $minSize, "struct*", $maxSize), "cveCascadeClassifierDetectMultiScale", @error)

    If $bObjectsIsArray Then
        _VectorOfRectRelease($vecObjects)
    EndIf
EndFunc   ;==>_cveCascadeClassifierDetectMultiScale

Func _cveCascadeClassifierDetectMultiScaleMat(ByRef $classifier, ByRef $matImage, ByRef $objects, $scaleFactor, $minNeighbors, $flags, ByRef $minSize, ByRef $maxSize)
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

Func _cveCascadeClassifierIsOldFormatCascade(ByRef $classifier)
    ; CVAPI(bool) cveCascadeClassifierIsOldFormatCascade(cv::CascadeClassifier* classifier);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveCascadeClassifierIsOldFormatCascade", "ptr", $classifier), "cveCascadeClassifierIsOldFormatCascade", @error)
EndFunc   ;==>_cveCascadeClassifierIsOldFormatCascade

Func _cveCascadeClassifierGetOriginalWindowSize(ByRef $classifier, ByRef $size)
    ; CVAPI(void) cveCascadeClassifierGetOriginalWindowSize(cv::CascadeClassifier* classifier, CvSize* size);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCascadeClassifierGetOriginalWindowSize", "ptr", $classifier, "struct*", $size), "cveCascadeClassifierGetOriginalWindowSize", @error)
EndFunc   ;==>_cveCascadeClassifierGetOriginalWindowSize

Func _cveGroupRectangles1(ByRef $rectList, $groupThreshold, $eps)
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveGroupRectangles1", "ptr", $vecRectList, "int", $groupThreshold, "double", $eps), "cveGroupRectangles1", @error)

    If $bRectListIsArray Then
        _VectorOfRectRelease($vecRectList)
    EndIf
EndFunc   ;==>_cveGroupRectangles1

Func _cveGroupRectangles2(ByRef $rectList, ByRef $weights, $groupThreshold, $eps)
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveGroupRectangles2", "ptr", $vecRectList, "ptr", $vecWeights, "int", $groupThreshold, "double", $eps), "cveGroupRectangles2", @error)

    If $bWeightsIsArray Then
        _VectorOfIntRelease($vecWeights)
    EndIf

    If $bRectListIsArray Then
        _VectorOfRectRelease($vecRectList)
    EndIf
EndFunc   ;==>_cveGroupRectangles2

Func _cveGroupRectangles3(ByRef $rectList, $groupThreshold, $eps, ByRef $weights, ByRef $levelWeights)
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveGroupRectangles3", "ptr", $vecRectList, "int", $groupThreshold, "double", $eps, "ptr", $vecWeights, "ptr", $vecLevelWeights), "cveGroupRectangles3", @error)

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

Func _cveGroupRectangles4(ByRef $rectList, ByRef $rejectLevels, ByRef $levelWeights, $groupThreshold, $eps)
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveGroupRectangles4", "ptr", $vecRectList, "ptr", $vecRejectLevels, "ptr", $vecLevelWeights, "int", $groupThreshold, "double", $eps), "cveGroupRectangles4", @error)

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

Func _cveGroupRectanglesMeanshift(ByRef $rectList, ByRef $foundWeights, ByRef $foundScales, $detectThreshold, ByRef $winDetSize)
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveGroupRectanglesMeanshift", "ptr", $vecRectList, "ptr", $vecFoundWeights, "ptr", $vecFoundScales, "double", $detectThreshold, "struct*", $winDetSize), "cveGroupRectanglesMeanshift", @error)

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

Func _cveQRCodeDetectorRelease(ByRef $detector)
    ; CVAPI(void) cveQRCodeDetectorRelease(cv::QRCodeDetector** detector);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveQRCodeDetectorRelease", "ptr*", $detector), "cveQRCodeDetectorRelease", @error)
EndFunc   ;==>_cveQRCodeDetectorRelease

Func _cveQRCodeDetectorDetect(ByRef $detector, ByRef $img, ByRef $points)
    ; CVAPI(bool) cveQRCodeDetectorDetect(cv::QRCodeDetector* detector, cv::_InputArray* img, cv::_OutputArray* points);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveQRCodeDetectorDetect", "ptr", $detector, "ptr", $img, "ptr", $points), "cveQRCodeDetectorDetect", @error)
EndFunc   ;==>_cveQRCodeDetectorDetect

Func _cveQRCodeDetectorDetectMat(ByRef $detector, ByRef $matImg, ByRef $matPoints)
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

Func _cveQRCodeDetectorDetectMulti(ByRef $detector, ByRef $img, ByRef $points)
    ; CVAPI(bool) cveQRCodeDetectorDetectMulti(cv::QRCodeDetector* detector, cv::_InputArray* img, cv::_OutputArray* points);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveQRCodeDetectorDetectMulti", "ptr", $detector, "ptr", $img, "ptr", $points), "cveQRCodeDetectorDetectMulti", @error)
EndFunc   ;==>_cveQRCodeDetectorDetectMulti

Func _cveQRCodeDetectorDetectMultiMat(ByRef $detector, ByRef $matImg, ByRef $matPoints)
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

Func _cveQRCodeDetectorDecode(ByRef $detector, ByRef $img, ByRef $points, $decodedInfo, ByRef $straightQrcode)
    ; CVAPI(void) cveQRCodeDetectorDecode(cv::QRCodeDetector* detector, cv::_InputArray* img, cv::_InputArray* points, cv::String* decodedInfo, cv::_OutputArray* straightQrcode);

    Local $bDecodedInfoIsString = VarGetType($decodedInfo) == "String"
    If $bDecodedInfoIsString Then
        $decodedInfo = _cveStringCreateFromStr($decodedInfo)
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveQRCodeDetectorDecode", "ptr", $detector, "ptr", $img, "ptr", $points, "ptr", $decodedInfo, "ptr", $straightQrcode), "cveQRCodeDetectorDecode", @error)

    If $bDecodedInfoIsString Then
        _cveStringRelease($decodedInfo)
    EndIf
EndFunc   ;==>_cveQRCodeDetectorDecode

Func _cveQRCodeDetectorDecodeMat(ByRef $detector, ByRef $matImg, ByRef $matPoints, $decodedInfo, ByRef $matStraightQrcode)
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

Func _cveQRCodeDetectorDecodeCurved(ByRef $detector, ByRef $img, ByRef $points, $decodedInfo, ByRef $straightQrcode)
    ; CVAPI(void) cveQRCodeDetectorDecodeCurved(cv::QRCodeDetector* detector, cv::_InputArray* img, cv::_InputArray* points, cv::String* decodedInfo, cv::_OutputArray* straightQrcode);

    Local $bDecodedInfoIsString = VarGetType($decodedInfo) == "String"
    If $bDecodedInfoIsString Then
        $decodedInfo = _cveStringCreateFromStr($decodedInfo)
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveQRCodeDetectorDecodeCurved", "ptr", $detector, "ptr", $img, "ptr", $points, "ptr", $decodedInfo, "ptr", $straightQrcode), "cveQRCodeDetectorDecodeCurved", @error)

    If $bDecodedInfoIsString Then
        _cveStringRelease($decodedInfo)
    EndIf
EndFunc   ;==>_cveQRCodeDetectorDecodeCurved

Func _cveQRCodeDetectorDecodeCurvedMat(ByRef $detector, ByRef $matImg, ByRef $matPoints, $decodedInfo, ByRef $matStraightQrcode)
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

Func _cveQRCodeDetectorDecodeMulti(ByRef $detector, ByRef $img, ByRef $points, ByRef $decodedInfo, ByRef $straightQrcode)
    ; CVAPI(bool) cveQRCodeDetectorDecodeMulti(cv::QRCodeDetector* detector, cv::_InputArray* img, cv::_InputArray* points, std::vector< std::string >* decodedInfo, cv::_OutputArray* straightQrcode);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveQRCodeDetectorDecodeMulti", "ptr", $detector, "ptr", $img, "ptr", $points, "ptr", $decodedInfo, "ptr", $straightQrcode), "cveQRCodeDetectorDecodeMulti", @error)
EndFunc   ;==>_cveQRCodeDetectorDecodeMulti

Func _cveQRCodeDetectorDecodeMultiMat(ByRef $detector, ByRef $matImg, ByRef $matPoints, ByRef $decodedInfo, ByRef $matStraightQrcode)
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