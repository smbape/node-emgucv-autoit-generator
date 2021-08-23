#include-once
#include "..\..\CVEUtils.au3"

Func _cudaCascadeClassifierCreate($filename, $sharedPtr)
    ; CVAPI(cv::cuda::CascadeClassifier*) cudaCascadeClassifierCreate(cv::String* filename, cv::Ptr<cv::cuda::CascadeClassifier>** sharedPtr);

    Local $bFilenameIsString = VarGetType($filename) == "String"
    If $bFilenameIsString Then
        $filename = _cveStringCreateFromStr($filename)
    EndIf

    Local $sFilenameDllType
    If IsDllStruct($filename) Then
        $sFilenameDllType = "struct*"
    Else
        $sFilenameDllType = "ptr"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cudaCascadeClassifierCreate", $sFilenameDllType, $filename, $sSharedPtrDllType, $sharedPtr), "cudaCascadeClassifierCreate", @error)

    If $bFilenameIsString Then
        _cveStringRelease($filename)
    EndIf

    Return $retval
EndFunc   ;==>_cudaCascadeClassifierCreate

Func _cudaCascadeClassifierCreateFromFileStorage($filestorage, $sharedPtr)
    ; CVAPI(cv::cuda::CascadeClassifier*) cudaCascadeClassifierCreateFromFileStorage(cv::FileStorage* filestorage, cv::Ptr<cv::cuda::CascadeClassifier>** sharedPtr);

    Local $sFilestorageDllType
    If IsDllStruct($filestorage) Then
        $sFilestorageDllType = "struct*"
    Else
        $sFilestorageDllType = "ptr"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cudaCascadeClassifierCreateFromFileStorage", $sFilestorageDllType, $filestorage, $sSharedPtrDllType, $sharedPtr), "cudaCascadeClassifierCreateFromFileStorage", @error)
EndFunc   ;==>_cudaCascadeClassifierCreateFromFileStorage

Func _cudaCascadeClassifierRelease($classifier)
    ; CVAPI(void) cudaCascadeClassifierRelease(cv::Ptr<cv::cuda::CascadeClassifier>** classifier);

    Local $sClassifierDllType
    If IsDllStruct($classifier) Then
        $sClassifierDllType = "struct*"
    ElseIf $classifier == Null Then
        $sClassifierDllType = "ptr"
    Else
        $sClassifierDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaCascadeClassifierRelease", $sClassifierDllType, $classifier), "cudaCascadeClassifierRelease", @error)
EndFunc   ;==>_cudaCascadeClassifierRelease

Func _cudaCascadeClassifierDetectMultiScale($classifier, $image, $objects, $stream)
    ; CVAPI(void) cudaCascadeClassifierDetectMultiScale(cv::cuda::CascadeClassifier* classifier, cv::_InputArray* image, cv::_OutputArray* objects, cv::cuda::Stream* stream);

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

    Local $sObjectsDllType
    If IsDllStruct($objects) Then
        $sObjectsDllType = "struct*"
    Else
        $sObjectsDllType = "ptr"
    EndIf

    Local $sStreamDllType
    If IsDllStruct($stream) Then
        $sStreamDllType = "struct*"
    Else
        $sStreamDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaCascadeClassifierDetectMultiScale", $sClassifierDllType, $classifier, $sImageDllType, $image, $sObjectsDllType, $objects, $sStreamDllType, $stream), "cudaCascadeClassifierDetectMultiScale", @error)
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

    Local $sClassifierDllType
    If IsDllStruct($classifier) Then
        $sClassifierDllType = "struct*"
    Else
        $sClassifierDllType = "ptr"
    EndIf

    Local $sGpuObjectsDllType
    If IsDllStruct($gpuObjects) Then
        $sGpuObjectsDllType = "struct*"
    Else
        $sGpuObjectsDllType = "ptr"
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaCascadeClassifierConvert", $sClassifierDllType, $classifier, $sGpuObjectsDllType, $gpuObjects, $sObjectsDllType, $vecObjects), "cudaCascadeClassifierConvert", @error)

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

    Local $sClassifierDllType
    If IsDllStruct($classifier) Then
        $sClassifierDllType = "struct*"
    Else
        $sClassifierDllType = "ptr"
    EndIf

    Local $sMinObjectSizeDllType
    If IsDllStruct($minObjectSize) Then
        $sMinObjectSizeDllType = "struct*"
    Else
        $sMinObjectSizeDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaCascadeClassifierGetMinObjectSize", $sClassifierDllType, $classifier, $sMinObjectSizeDllType, $minObjectSize), "cudaCascadeClassifierGetMinObjectSize", @error)
EndFunc   ;==>_cudaCascadeClassifierGetMinObjectSize

Func _cudaCascadeClassifierSetMinObjectSize($classifier, $minObjectSize)
    ; CVAPI(void) cudaCascadeClassifierSetMinObjectSize(cv::cuda::CascadeClassifier* classifier, CvSize* minObjectSize);

    Local $sClassifierDllType
    If IsDllStruct($classifier) Then
        $sClassifierDllType = "struct*"
    Else
        $sClassifierDllType = "ptr"
    EndIf

    Local $sMinObjectSizeDllType
    If IsDllStruct($minObjectSize) Then
        $sMinObjectSizeDllType = "struct*"
    Else
        $sMinObjectSizeDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaCascadeClassifierSetMinObjectSize", $sClassifierDllType, $classifier, $sMinObjectSizeDllType, $minObjectSize), "cudaCascadeClassifierSetMinObjectSize", @error)
EndFunc   ;==>_cudaCascadeClassifierSetMinObjectSize

Func _cudaHOGGetDefaultPeopleDetector($descriptor, $detector)
    ; CVAPI(void) cudaHOGGetDefaultPeopleDetector(cv::cuda::HOG* descriptor, cv::Mat* detector);

    Local $sDescriptorDllType
    If IsDllStruct($descriptor) Then
        $sDescriptorDllType = "struct*"
    Else
        $sDescriptorDllType = "ptr"
    EndIf

    Local $sDetectorDllType
    If IsDllStruct($detector) Then
        $sDetectorDllType = "struct*"
    Else
        $sDetectorDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaHOGGetDefaultPeopleDetector", $sDescriptorDllType, $descriptor, $sDetectorDllType, $detector), "cudaHOGGetDefaultPeopleDetector", @error)
EndFunc   ;==>_cudaHOGGetDefaultPeopleDetector

Func _cudaHOGCreate($winSize, $blockSize, $blockStride, $cellSize, $nbins, $sharedPtr)
    ; CVAPI(cv::cuda::HOG*) cudaHOGCreate(CvSize* winSize, CvSize* blockSize, CvSize* blockStride, CvSize* cellSize, int nbins, cv::Ptr<cv::cuda::HOG>** sharedPtr);

    Local $sWinSizeDllType
    If IsDllStruct($winSize) Then
        $sWinSizeDllType = "struct*"
    Else
        $sWinSizeDllType = "ptr"
    EndIf

    Local $sBlockSizeDllType
    If IsDllStruct($blockSize) Then
        $sBlockSizeDllType = "struct*"
    Else
        $sBlockSizeDllType = "ptr"
    EndIf

    Local $sBlockStrideDllType
    If IsDllStruct($blockStride) Then
        $sBlockStrideDllType = "struct*"
    Else
        $sBlockStrideDllType = "ptr"
    EndIf

    Local $sCellSizeDllType
    If IsDllStruct($cellSize) Then
        $sCellSizeDllType = "struct*"
    Else
        $sCellSizeDllType = "ptr"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cudaHOGCreate", $sWinSizeDllType, $winSize, $sBlockSizeDllType, $blockSize, $sBlockStrideDllType, $blockStride, $sCellSizeDllType, $cellSize, "int", $nbins, $sSharedPtrDllType, $sharedPtr), "cudaHOGCreate", @error)
EndFunc   ;==>_cudaHOGCreate

Func _cudaHOGSetSVMDetector($descriptor, $detector)
    ; CVAPI(void) cudaHOGSetSVMDetector(cv::cuda::HOG* descriptor, cv::_InputArray* detector);

    Local $sDescriptorDllType
    If IsDllStruct($descriptor) Then
        $sDescriptorDllType = "struct*"
    Else
        $sDescriptorDllType = "ptr"
    EndIf

    Local $sDetectorDllType
    If IsDllStruct($detector) Then
        $sDetectorDllType = "struct*"
    Else
        $sDetectorDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaHOGSetSVMDetector", $sDescriptorDllType, $descriptor, $sDetectorDllType, $detector), "cudaHOGSetSVMDetector", @error)
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

    Local $sDescriptorDllType
    If IsDllStruct($descriptor) Then
        $sDescriptorDllType = "struct*"
    ElseIf $descriptor == Null Then
        $sDescriptorDllType = "ptr"
    Else
        $sDescriptorDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaHOGRelease", $sDescriptorDllType, $descriptor), "cudaHOGRelease", @error)
EndFunc   ;==>_cudaHOGRelease

Func _cudaHOGDetectMultiScale($descriptor, $img, $foundLocations, $confidents)
    ; CVAPI(void) cudaHOGDetectMultiScale(cv::cuda::HOG* descriptor, cv::_InputArray* img, std::vector<cv::Rect>* foundLocations, std::vector<double>* confidents);

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

    Local $sConfidentsDllType
    If IsDllStruct($confidents) Then
        $sConfidentsDllType = "struct*"
    Else
        $sConfidentsDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaHOGDetectMultiScale", $sDescriptorDllType, $descriptor, $sImgDllType, $img, $sFoundLocationsDllType, $vecFoundLocations, $sConfidentsDllType, $vecConfidents), "cudaHOGDetectMultiScale", @error)

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