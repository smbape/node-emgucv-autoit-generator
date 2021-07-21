#include-once
#include "..\..\CVEUtils.au3"

Func _cudaCascadeClassifierCreate($filename, $sharedPtr)
    ; CVAPI(cv::cuda::CascadeClassifier*) cudaCascadeClassifierCreate(cv::String* filename, cv::Ptr<cv::cuda::CascadeClassifier>** sharedPtr);

    Local $bFilenameIsString = VarGetType($filename) == "String"
    If $bFilenameIsString Then
        $filename = _cveStringCreateFromStr($filename)
    EndIf

    Local $bFilenameDllType
    If VarGetType($filename) == "DLLStruct" Then
        $bFilenameDllType = "struct*"
    Else
        $bFilenameDllType = "ptr"
    EndIf

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cudaCascadeClassifierCreate", $bFilenameDllType, $filename, $bSharedPtrDllType, $sharedPtr), "cudaCascadeClassifierCreate", @error)

    If $bFilenameIsString Then
        _cveStringRelease($filename)
    EndIf

    Return $retval
EndFunc   ;==>_cudaCascadeClassifierCreate

Func _cudaCascadeClassifierCreateFromFileStorage($filestorage, $sharedPtr)
    ; CVAPI(cv::cuda::CascadeClassifier*) cudaCascadeClassifierCreateFromFileStorage(cv::FileStorage* filestorage, cv::Ptr<cv::cuda::CascadeClassifier>** sharedPtr);

    Local $bFilestorageDllType
    If VarGetType($filestorage) == "DLLStruct" Then
        $bFilestorageDllType = "struct*"
    Else
        $bFilestorageDllType = "ptr"
    EndIf

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cudaCascadeClassifierCreateFromFileStorage", $bFilestorageDllType, $filestorage, $bSharedPtrDllType, $sharedPtr), "cudaCascadeClassifierCreateFromFileStorage", @error)
EndFunc   ;==>_cudaCascadeClassifierCreateFromFileStorage

Func _cudaCascadeClassifierRelease($classifier)
    ; CVAPI(void) cudaCascadeClassifierRelease(cv::Ptr<cv::cuda::CascadeClassifier>** classifier);

    Local $bClassifierDllType
    If VarGetType($classifier) == "DLLStruct" Then
        $bClassifierDllType = "struct*"
    Else
        $bClassifierDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaCascadeClassifierRelease", $bClassifierDllType, $classifier), "cudaCascadeClassifierRelease", @error)
EndFunc   ;==>_cudaCascadeClassifierRelease

Func _cudaCascadeClassifierDetectMultiScale($classifier, $image, $objects, $stream)
    ; CVAPI(void) cudaCascadeClassifierDetectMultiScale(cv::cuda::CascadeClassifier* classifier, cv::_InputArray* image, cv::_OutputArray* objects, cv::cuda::Stream* stream);

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

    Local $bObjectsDllType
    If VarGetType($objects) == "DLLStruct" Then
        $bObjectsDllType = "struct*"
    Else
        $bObjectsDllType = "ptr"
    EndIf

    Local $bStreamDllType
    If VarGetType($stream) == "DLLStruct" Then
        $bStreamDllType = "struct*"
    Else
        $bStreamDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaCascadeClassifierDetectMultiScale", $bClassifierDllType, $classifier, $bImageDllType, $image, $bObjectsDllType, $objects, $bStreamDllType, $stream), "cudaCascadeClassifierDetectMultiScale", @error)
EndFunc   ;==>_cudaCascadeClassifierDetectMultiScale

Func _cudaCascadeClassifierDetectMultiScaleMat($classifier, $matImage, $matObjects, $stream)
    ; cudaCascadeClassifierDetectMultiScale using cv::Mat instead of _*Array

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

    Local $oArrObjects, $vectorOfMatObjects, $iArrObjectsSize
    Local $bObjectsIsArray = VarGetType($matObjects) == "Array"

    If $bObjectsIsArray Then
        $vectorOfMatObjects = _VectorOfMatCreate()

        $iArrObjectsSize = UBound($matObjects)
        For $i = 0 To $iArrObjectsSize - 1
            _VectorOfMatPush($vectorOfMatObjects, $matObjects[$i])
        Next

        $oArrObjects = _cveOutputArrayFromVectorOfMat($vectorOfMatObjects)
    Else
        $oArrObjects = _cveOutputArrayFromMat($matObjects)
    EndIf

    _cudaCascadeClassifierDetectMultiScale($classifier, $iArrImage, $oArrObjects, $stream)

    If $bObjectsIsArray Then
        _VectorOfMatRelease($vectorOfMatObjects)
    EndIf

    _cveOutputArrayRelease($oArrObjects)

    If $bImageIsArray Then
        _VectorOfMatRelease($vectorOfMatImage)
    EndIf

    _cveInputArrayRelease($iArrImage)
EndFunc   ;==>_cudaCascadeClassifierDetectMultiScaleMat

Func _cudaCascadeClassifierConvert($classifier, $gpuObjects, $objects)
    ; CVAPI(void) cudaCascadeClassifierConvert(cv::cuda::CascadeClassifier* classifier, cv::_OutputArray* gpuObjects, std::vector<cv::Rect>* objects);

    Local $bClassifierDllType
    If VarGetType($classifier) == "DLLStruct" Then
        $bClassifierDllType = "struct*"
    Else
        $bClassifierDllType = "ptr"
    EndIf

    Local $bGpuObjectsDllType
    If VarGetType($gpuObjects) == "DLLStruct" Then
        $bGpuObjectsDllType = "struct*"
    Else
        $bGpuObjectsDllType = "ptr"
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaCascadeClassifierConvert", $bClassifierDllType, $classifier, $bGpuObjectsDllType, $gpuObjects, $bObjectsDllType, $vecObjects), "cudaCascadeClassifierConvert", @error)

    If $bObjectsIsArray Then
        _VectorOfRectRelease($vecObjects)
    EndIf
EndFunc   ;==>_cudaCascadeClassifierConvert

Func _cudaCascadeClassifierConvertMat($classifier, $matGpuObjects, $objects)
    ; cudaCascadeClassifierConvert using cv::Mat instead of _*Array

    Local $oArrGpuObjects, $vectorOfMatGpuObjects, $iArrGpuObjectsSize
    Local $bGpuObjectsIsArray = VarGetType($matGpuObjects) == "Array"

    If $bGpuObjectsIsArray Then
        $vectorOfMatGpuObjects = _VectorOfMatCreate()

        $iArrGpuObjectsSize = UBound($matGpuObjects)
        For $i = 0 To $iArrGpuObjectsSize - 1
            _VectorOfMatPush($vectorOfMatGpuObjects, $matGpuObjects[$i])
        Next

        $oArrGpuObjects = _cveOutputArrayFromVectorOfMat($vectorOfMatGpuObjects)
    Else
        $oArrGpuObjects = _cveOutputArrayFromMat($matGpuObjects)
    EndIf

    _cudaCascadeClassifierConvert($classifier, $oArrGpuObjects, $objects)

    If $bGpuObjectsIsArray Then
        _VectorOfMatRelease($vectorOfMatGpuObjects)
    EndIf

    _cveOutputArrayRelease($oArrGpuObjects)
EndFunc   ;==>_cudaCascadeClassifierConvertMat

Func _cudaCascadeClassifierGetMinObjectSize($classifier, $minObjectSize)
    ; CVAPI(void) cudaCascadeClassifierGetMinObjectSize(cv::cuda::CascadeClassifier* classifier, CvSize* minObjectSize);

    Local $bClassifierDllType
    If VarGetType($classifier) == "DLLStruct" Then
        $bClassifierDllType = "struct*"
    Else
        $bClassifierDllType = "ptr"
    EndIf

    Local $bMinObjectSizeDllType
    If VarGetType($minObjectSize) == "DLLStruct" Then
        $bMinObjectSizeDllType = "struct*"
    Else
        $bMinObjectSizeDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaCascadeClassifierGetMinObjectSize", $bClassifierDllType, $classifier, $bMinObjectSizeDllType, $minObjectSize), "cudaCascadeClassifierGetMinObjectSize", @error)
EndFunc   ;==>_cudaCascadeClassifierGetMinObjectSize

Func _cudaCascadeClassifierSetMinObjectSize($classifier, $minObjectSize)
    ; CVAPI(void) cudaCascadeClassifierSetMinObjectSize(cv::cuda::CascadeClassifier* classifier, CvSize* minObjectSize);

    Local $bClassifierDllType
    If VarGetType($classifier) == "DLLStruct" Then
        $bClassifierDllType = "struct*"
    Else
        $bClassifierDllType = "ptr"
    EndIf

    Local $bMinObjectSizeDllType
    If VarGetType($minObjectSize) == "DLLStruct" Then
        $bMinObjectSizeDllType = "struct*"
    Else
        $bMinObjectSizeDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaCascadeClassifierSetMinObjectSize", $bClassifierDllType, $classifier, $bMinObjectSizeDllType, $minObjectSize), "cudaCascadeClassifierSetMinObjectSize", @error)
EndFunc   ;==>_cudaCascadeClassifierSetMinObjectSize

Func _cudaHOGGetDefaultPeopleDetector($descriptor, $detector)
    ; CVAPI(void) cudaHOGGetDefaultPeopleDetector(cv::cuda::HOG* descriptor, cv::Mat* detector);

    Local $bDescriptorDllType
    If VarGetType($descriptor) == "DLLStruct" Then
        $bDescriptorDllType = "struct*"
    Else
        $bDescriptorDllType = "ptr"
    EndIf

    Local $bDetectorDllType
    If VarGetType($detector) == "DLLStruct" Then
        $bDetectorDllType = "struct*"
    Else
        $bDetectorDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaHOGGetDefaultPeopleDetector", $bDescriptorDllType, $descriptor, $bDetectorDllType, $detector), "cudaHOGGetDefaultPeopleDetector", @error)
EndFunc   ;==>_cudaHOGGetDefaultPeopleDetector

Func _cudaHOGCreate($winSize, $blockSize, $blockStride, $cellSize, $nbins, $sharedPtr)
    ; CVAPI(cv::cuda::HOG*) cudaHOGCreate(CvSize* winSize, CvSize* blockSize, CvSize* blockStride, CvSize* cellSize, int nbins, cv::Ptr<cv::cuda::HOG>** sharedPtr);

    Local $bWinSizeDllType
    If VarGetType($winSize) == "DLLStruct" Then
        $bWinSizeDllType = "struct*"
    Else
        $bWinSizeDllType = "ptr"
    EndIf

    Local $bBlockSizeDllType
    If VarGetType($blockSize) == "DLLStruct" Then
        $bBlockSizeDllType = "struct*"
    Else
        $bBlockSizeDllType = "ptr"
    EndIf

    Local $bBlockStrideDllType
    If VarGetType($blockStride) == "DLLStruct" Then
        $bBlockStrideDllType = "struct*"
    Else
        $bBlockStrideDllType = "ptr"
    EndIf

    Local $bCellSizeDllType
    If VarGetType($cellSize) == "DLLStruct" Then
        $bCellSizeDllType = "struct*"
    Else
        $bCellSizeDllType = "ptr"
    EndIf

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cudaHOGCreate", $bWinSizeDllType, $winSize, $bBlockSizeDllType, $blockSize, $bBlockStrideDllType, $blockStride, $bCellSizeDllType, $cellSize, "int", $nbins, $bSharedPtrDllType, $sharedPtr), "cudaHOGCreate", @error)
EndFunc   ;==>_cudaHOGCreate

Func _cudaHOGSetSVMDetector($descriptor, $detector)
    ; CVAPI(void) cudaHOGSetSVMDetector(cv::cuda::HOG* descriptor, cv::_InputArray* detector);

    Local $bDescriptorDllType
    If VarGetType($descriptor) == "DLLStruct" Then
        $bDescriptorDllType = "struct*"
    Else
        $bDescriptorDllType = "ptr"
    EndIf

    Local $bDetectorDllType
    If VarGetType($detector) == "DLLStruct" Then
        $bDetectorDllType = "struct*"
    Else
        $bDetectorDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaHOGSetSVMDetector", $bDescriptorDllType, $descriptor, $bDetectorDllType, $detector), "cudaHOGSetSVMDetector", @error)
EndFunc   ;==>_cudaHOGSetSVMDetector

Func _cudaHOGSetSVMDetectorMat($descriptor, $matDetector)
    ; cudaHOGSetSVMDetector using cv::Mat instead of _*Array

    Local $iArrDetector, $vectorOfMatDetector, $iArrDetectorSize
    Local $bDetectorIsArray = VarGetType($matDetector) == "Array"

    If $bDetectorIsArray Then
        $vectorOfMatDetector = _VectorOfMatCreate()

        $iArrDetectorSize = UBound($matDetector)
        For $i = 0 To $iArrDetectorSize - 1
            _VectorOfMatPush($vectorOfMatDetector, $matDetector[$i])
        Next

        $iArrDetector = _cveInputArrayFromVectorOfMat($vectorOfMatDetector)
    Else
        $iArrDetector = _cveInputArrayFromMat($matDetector)
    EndIf

    _cudaHOGSetSVMDetector($descriptor, $iArrDetector)

    If $bDetectorIsArray Then
        _VectorOfMatRelease($vectorOfMatDetector)
    EndIf

    _cveInputArrayRelease($iArrDetector)
EndFunc   ;==>_cudaHOGSetSVMDetectorMat

Func _cudaHOGRelease($descriptor)
    ; CVAPI(void) cudaHOGRelease(cv::Ptr<cv::cuda::HOG>** descriptor);

    Local $bDescriptorDllType
    If VarGetType($descriptor) == "DLLStruct" Then
        $bDescriptorDllType = "struct*"
    Else
        $bDescriptorDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaHOGRelease", $bDescriptorDllType, $descriptor), "cudaHOGRelease", @error)
EndFunc   ;==>_cudaHOGRelease

Func _cudaHOGDetectMultiScale($descriptor, $img, $foundLocations, $confidents)
    ; CVAPI(void) cudaHOGDetectMultiScale(cv::cuda::HOG* descriptor, cv::_InputArray* img, std::vector<cv::Rect>* foundLocations, std::vector<double>* confidents);

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

    Local $vecConfidents, $iArrConfidentsSize
    Local $bConfidentsIsArray = VarGetType($confidents) == "Array"

    If $bConfidentsIsArray Then
        $vecConfidents = _VectorOfDoubleCreate()

        $iArrConfidentsSize = UBound($confidents)
        For $i = 0 To $iArrConfidentsSize - 1
            _VectorOfDoublePush($vecConfidents, $confidents[$i])
        Next
    Else
        $vecConfidents = $confidents
    EndIf

    Local $bConfidentsDllType
    If VarGetType($confidents) == "DLLStruct" Then
        $bConfidentsDllType = "struct*"
    Else
        $bConfidentsDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaHOGDetectMultiScale", $bDescriptorDllType, $descriptor, $bImgDllType, $img, $bFoundLocationsDllType, $vecFoundLocations, $bConfidentsDllType, $vecConfidents), "cudaHOGDetectMultiScale", @error)

    If $bConfidentsIsArray Then
        _VectorOfDoubleRelease($vecConfidents)
    EndIf

    If $bFoundLocationsIsArray Then
        _VectorOfRectRelease($vecFoundLocations)
    EndIf
EndFunc   ;==>_cudaHOGDetectMultiScale

Func _cudaHOGDetectMultiScaleMat($descriptor, $matImg, $foundLocations, $confidents)
    ; cudaHOGDetectMultiScale using cv::Mat instead of _*Array

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

    _cudaHOGDetectMultiScale($descriptor, $iArrImg, $foundLocations, $confidents)

    If $bImgIsArray Then
        _VectorOfMatRelease($vectorOfMatImg)
    EndIf

    _cveInputArrayRelease($iArrImg)
EndFunc   ;==>_cudaHOGDetectMultiScaleMat