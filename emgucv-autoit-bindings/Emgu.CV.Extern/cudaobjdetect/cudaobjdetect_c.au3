#include-once
#include "..\..\CVEUtils.au3"

Func _cudaCascadeClassifierCreate($filename, $sharedPtr)
    ; CVAPI(cv::cuda::CascadeClassifier*) cudaCascadeClassifierCreate(cv::String* filename, cv::Ptr<cv::cuda::CascadeClassifier>** sharedPtr);

    Local $bFilenameIsString = IsString($filename)
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

Func _cudaCascadeClassifierDetectMultiScaleTyped($classifier, $typeOfImage, $image, $typeOfObjects, $objects, $stream)

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

    Local $oArrObjects, $vectorObjects, $iArrObjectsSize
    Local $bObjectsIsArray = IsArray($objects)
    Local $bObjectsCreate = IsDllStruct($objects) And $typeOfObjects == "Scalar"

    If $typeOfObjects == Default Then
        $oArrObjects = $objects
    ElseIf $bObjectsIsArray Then
        $vectorObjects = Call("_VectorOf" & $typeOfObjects & "Create")

        $iArrObjectsSize = UBound($objects)
        For $i = 0 To $iArrObjectsSize - 1
            Call("_VectorOf" & $typeOfObjects & "Push", $vectorObjects, $objects[$i])
        Next

        $oArrObjects = Call("_cveOutputArrayFromVectorOf" & $typeOfObjects, $vectorObjects)
    Else
        If $bObjectsCreate Then
            $objects = Call("_cve" & $typeOfObjects & "Create", $objects)
        EndIf
        $oArrObjects = Call("_cveOutputArrayFrom" & $typeOfObjects, $objects)
    EndIf

    _cudaCascadeClassifierDetectMultiScale($classifier, $iArrImage, $oArrObjects, $stream)

    If $bObjectsIsArray Then
        Call("_VectorOf" & $typeOfObjects & "Release", $vectorObjects)
    EndIf

    If $typeOfObjects <> Default Then
        _cveOutputArrayRelease($oArrObjects)
        If $bObjectsCreate Then
            Call("_cve" & $typeOfObjects & "Release", $objects)
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
EndFunc   ;==>_cudaCascadeClassifierDetectMultiScaleTyped

Func _cudaCascadeClassifierDetectMultiScaleMat($classifier, $image, $objects, $stream)
    ; cudaCascadeClassifierDetectMultiScale using cv::Mat instead of _*Array
    _cudaCascadeClassifierDetectMultiScaleTyped($classifier, "Mat", $image, "Mat", $objects, $stream)
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
    Local $bObjectsIsArray = IsArray($objects)

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

Func _cudaCascadeClassifierConvertTyped($classifier, $typeOfGpuObjects, $gpuObjects, $objects)

    Local $oArrGpuObjects, $vectorGpuObjects, $iArrGpuObjectsSize
    Local $bGpuObjectsIsArray = IsArray($gpuObjects)
    Local $bGpuObjectsCreate = IsDllStruct($gpuObjects) And $typeOfGpuObjects == "Scalar"

    If $typeOfGpuObjects == Default Then
        $oArrGpuObjects = $gpuObjects
    ElseIf $bGpuObjectsIsArray Then
        $vectorGpuObjects = Call("_VectorOf" & $typeOfGpuObjects & "Create")

        $iArrGpuObjectsSize = UBound($gpuObjects)
        For $i = 0 To $iArrGpuObjectsSize - 1
            Call("_VectorOf" & $typeOfGpuObjects & "Push", $vectorGpuObjects, $gpuObjects[$i])
        Next

        $oArrGpuObjects = Call("_cveOutputArrayFromVectorOf" & $typeOfGpuObjects, $vectorGpuObjects)
    Else
        If $bGpuObjectsCreate Then
            $gpuObjects = Call("_cve" & $typeOfGpuObjects & "Create", $gpuObjects)
        EndIf
        $oArrGpuObjects = Call("_cveOutputArrayFrom" & $typeOfGpuObjects, $gpuObjects)
    EndIf

    _cudaCascadeClassifierConvert($classifier, $oArrGpuObjects, $objects)

    If $bGpuObjectsIsArray Then
        Call("_VectorOf" & $typeOfGpuObjects & "Release", $vectorGpuObjects)
    EndIf

    If $typeOfGpuObjects <> Default Then
        _cveOutputArrayRelease($oArrGpuObjects)
        If $bGpuObjectsCreate Then
            Call("_cve" & $typeOfGpuObjects & "Release", $gpuObjects)
        EndIf
    EndIf
EndFunc   ;==>_cudaCascadeClassifierConvertTyped

Func _cudaCascadeClassifierConvertMat($classifier, $gpuObjects, $objects)
    ; cudaCascadeClassifierConvert using cv::Mat instead of _*Array
    _cudaCascadeClassifierConvertTyped($classifier, "Mat", $gpuObjects, $objects)
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

Func _cudaHOGSetSVMDetectorTyped($descriptor, $typeOfDetector, $detector)

    Local $iArrDetector, $vectorDetector, $iArrDetectorSize
    Local $bDetectorIsArray = IsArray($detector)
    Local $bDetectorCreate = IsDllStruct($detector) And $typeOfDetector == "Scalar"

    If $typeOfDetector == Default Then
        $iArrDetector = $detector
    ElseIf $bDetectorIsArray Then
        $vectorDetector = Call("_VectorOf" & $typeOfDetector & "Create")

        $iArrDetectorSize = UBound($detector)
        For $i = 0 To $iArrDetectorSize - 1
            Call("_VectorOf" & $typeOfDetector & "Push", $vectorDetector, $detector[$i])
        Next

        $iArrDetector = Call("_cveInputArrayFromVectorOf" & $typeOfDetector, $vectorDetector)
    Else
        If $bDetectorCreate Then
            $detector = Call("_cve" & $typeOfDetector & "Create", $detector)
        EndIf
        $iArrDetector = Call("_cveInputArrayFrom" & $typeOfDetector, $detector)
    EndIf

    _cudaHOGSetSVMDetector($descriptor, $iArrDetector)

    If $bDetectorIsArray Then
        Call("_VectorOf" & $typeOfDetector & "Release", $vectorDetector)
    EndIf

    If $typeOfDetector <> Default Then
        _cveInputArrayRelease($iArrDetector)
        If $bDetectorCreate Then
            Call("_cve" & $typeOfDetector & "Release", $detector)
        EndIf
    EndIf
EndFunc   ;==>_cudaHOGSetSVMDetectorTyped

Func _cudaHOGSetSVMDetectorMat($descriptor, $detector)
    ; cudaHOGSetSVMDetector using cv::Mat instead of _*Array
    _cudaHOGSetSVMDetectorTyped($descriptor, "Mat", $detector)
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
    Local $bFoundLocationsIsArray = IsArray($foundLocations)

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
    Local $bConfidentsIsArray = IsArray($confidents)

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

Func _cudaHOGDetectMultiScaleTyped($descriptor, $typeOfImg, $img, $foundLocations, $confidents)

    Local $iArrImg, $vectorImg, $iArrImgSize
    Local $bImgIsArray = IsArray($img)
    Local $bImgCreate = IsDllStruct($img) And $typeOfImg == "Scalar"

    If $typeOfImg == Default Then
        $iArrImg = $img
    ElseIf $bImgIsArray Then
        $vectorImg = Call("_VectorOf" & $typeOfImg & "Create")

        $iArrImgSize = UBound($img)
        For $i = 0 To $iArrImgSize - 1
            Call("_VectorOf" & $typeOfImg & "Push", $vectorImg, $img[$i])
        Next

        $iArrImg = Call("_cveInputArrayFromVectorOf" & $typeOfImg, $vectorImg)
    Else
        If $bImgCreate Then
            $img = Call("_cve" & $typeOfImg & "Create", $img)
        EndIf
        $iArrImg = Call("_cveInputArrayFrom" & $typeOfImg, $img)
    EndIf

    _cudaHOGDetectMultiScale($descriptor, $iArrImg, $foundLocations, $confidents)

    If $bImgIsArray Then
        Call("_VectorOf" & $typeOfImg & "Release", $vectorImg)
    EndIf

    If $typeOfImg <> Default Then
        _cveInputArrayRelease($iArrImg)
        If $bImgCreate Then
            Call("_cve" & $typeOfImg & "Release", $img)
        EndIf
    EndIf
EndFunc   ;==>_cudaHOGDetectMultiScaleTyped

Func _cudaHOGDetectMultiScaleMat($descriptor, $img, $foundLocations, $confidents)
    ; cudaHOGDetectMultiScale using cv::Mat instead of _*Array
    _cudaHOGDetectMultiScaleTyped($descriptor, "Mat", $img, $foundLocations, $confidents)
EndFunc   ;==>_cudaHOGDetectMultiScaleMat