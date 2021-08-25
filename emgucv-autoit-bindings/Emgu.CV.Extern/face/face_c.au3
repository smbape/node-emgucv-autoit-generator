#include-once
#include "..\..\CVEUtils.au3"

Func _cveEigenFaceRecognizerCreate($numComponents, $threshold, $faceRecognizerPtr, $basicFaceRecognizerPtr, $sharedPtr)
    ; CVAPI(cv::face::EigenFaceRecognizer*) cveEigenFaceRecognizerCreate(int numComponents, double threshold, cv::face::FaceRecognizer** faceRecognizerPtr, cv::face::BasicFaceRecognizer** basicFaceRecognizerPtr, cv::Ptr<cv::face::EigenFaceRecognizer>** sharedPtr);

    Local $sFaceRecognizerPtrDllType
    If IsDllStruct($faceRecognizerPtr) Then
        $sFaceRecognizerPtrDllType = "struct*"
    ElseIf $faceRecognizerPtr == Null Then
        $sFaceRecognizerPtrDllType = "ptr"
    Else
        $sFaceRecognizerPtrDllType = "ptr*"
    EndIf

    Local $sBasicFaceRecognizerPtrDllType
    If IsDllStruct($basicFaceRecognizerPtr) Then
        $sBasicFaceRecognizerPtrDllType = "struct*"
    ElseIf $basicFaceRecognizerPtr == Null Then
        $sBasicFaceRecognizerPtrDllType = "ptr"
    Else
        $sBasicFaceRecognizerPtrDllType = "ptr*"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveEigenFaceRecognizerCreate", "int", $numComponents, "double", $threshold, $sFaceRecognizerPtrDllType, $faceRecognizerPtr, $sBasicFaceRecognizerPtrDllType, $basicFaceRecognizerPtr, $sSharedPtrDllType, $sharedPtr), "cveEigenFaceRecognizerCreate", @error)
EndFunc   ;==>_cveEigenFaceRecognizerCreate

Func _cveEigenFaceRecognizerRelease($sharedPtr)
    ; CVAPI(void) cveEigenFaceRecognizerRelease(cv::Ptr<cv::face::EigenFaceRecognizer>** sharedPtr);

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveEigenFaceRecognizerRelease", $sSharedPtrDllType, $sharedPtr), "cveEigenFaceRecognizerRelease", @error)
EndFunc   ;==>_cveEigenFaceRecognizerRelease

Func _cveFisherFaceRecognizerCreate($numComponents, $threshold, $faceRecognizerPtr, $basicFaceRecognizerPtr, $sharedPtr)
    ; CVAPI(cv::face::FisherFaceRecognizer*) cveFisherFaceRecognizerCreate(int numComponents, double threshold, cv::face::FaceRecognizer** faceRecognizerPtr, cv::face::FaceRecognizer** basicFaceRecognizerPtr, cv::Ptr<cv::face::FisherFaceRecognizer>** sharedPtr);

    Local $sFaceRecognizerPtrDllType
    If IsDllStruct($faceRecognizerPtr) Then
        $sFaceRecognizerPtrDllType = "struct*"
    ElseIf $faceRecognizerPtr == Null Then
        $sFaceRecognizerPtrDllType = "ptr"
    Else
        $sFaceRecognizerPtrDllType = "ptr*"
    EndIf

    Local $sBasicFaceRecognizerPtrDllType
    If IsDllStruct($basicFaceRecognizerPtr) Then
        $sBasicFaceRecognizerPtrDllType = "struct*"
    ElseIf $basicFaceRecognizerPtr == Null Then
        $sBasicFaceRecognizerPtrDllType = "ptr"
    Else
        $sBasicFaceRecognizerPtrDllType = "ptr*"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveFisherFaceRecognizerCreate", "int", $numComponents, "double", $threshold, $sFaceRecognizerPtrDllType, $faceRecognizerPtr, $sBasicFaceRecognizerPtrDllType, $basicFaceRecognizerPtr, $sSharedPtrDllType, $sharedPtr), "cveFisherFaceRecognizerCreate", @error)
EndFunc   ;==>_cveFisherFaceRecognizerCreate

Func _cveFisherFaceRecognizerRelease($sharedPtr)
    ; CVAPI(void) cveFisherFaceRecognizerRelease(cv::Ptr<cv::face::FisherFaceRecognizer>** sharedPtr);

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFisherFaceRecognizerRelease", $sSharedPtrDllType, $sharedPtr), "cveFisherFaceRecognizerRelease", @error)
EndFunc   ;==>_cveFisherFaceRecognizerRelease

Func _cveLBPHFaceRecognizerCreate($radius, $neighbors, $gridX, $gridY, $threshold, $faceRecognizerPtr, $sharedPtr)
    ; CVAPI(cv::face::LBPHFaceRecognizer*) cveLBPHFaceRecognizerCreate(int radius, int neighbors, int gridX, int gridY, double threshold, cv::face::FaceRecognizer** faceRecognizerPtr, cv::Ptr<cv::face::LBPHFaceRecognizer>** sharedPtr);

    Local $sFaceRecognizerPtrDllType
    If IsDllStruct($faceRecognizerPtr) Then
        $sFaceRecognizerPtrDllType = "struct*"
    ElseIf $faceRecognizerPtr == Null Then
        $sFaceRecognizerPtrDllType = "ptr"
    Else
        $sFaceRecognizerPtrDllType = "ptr*"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveLBPHFaceRecognizerCreate", "int", $radius, "int", $neighbors, "int", $gridX, "int", $gridY, "double", $threshold, $sFaceRecognizerPtrDllType, $faceRecognizerPtr, $sSharedPtrDllType, $sharedPtr), "cveLBPHFaceRecognizerCreate", @error)
EndFunc   ;==>_cveLBPHFaceRecognizerCreate

Func _cveLBPHFaceRecognizerRelease($sharedPtr)
    ; CVAPI(void) cveLBPHFaceRecognizerRelease(cv::Ptr<cv::face::LBPHFaceRecognizer>** sharedPtr);

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveLBPHFaceRecognizerRelease", $sSharedPtrDllType, $sharedPtr), "cveLBPHFaceRecognizerRelease", @error)
EndFunc   ;==>_cveLBPHFaceRecognizerRelease

Func _cveLBPHFaceRecognizerGetHistograms($recognizer, $histograms)
    ; CVAPI(void) cveLBPHFaceRecognizerGetHistograms(cv::face::LBPHFaceRecognizer* recognizer, std::vector<cv::Mat>* histograms);

    Local $sRecognizerDllType
    If IsDllStruct($recognizer) Then
        $sRecognizerDllType = "struct*"
    Else
        $sRecognizerDllType = "ptr"
    EndIf

    Local $vecHistograms, $iArrHistogramsSize
    Local $bHistogramsIsArray = IsArray($histograms)

    If $bHistogramsIsArray Then
        $vecHistograms = _VectorOfMatCreate()

        $iArrHistogramsSize = UBound($histograms)
        For $i = 0 To $iArrHistogramsSize - 1
            _VectorOfMatPush($vecHistograms, $histograms[$i])
        Next
    Else
        $vecHistograms = $histograms
    EndIf

    Local $sHistogramsDllType
    If IsDllStruct($histograms) Then
        $sHistogramsDllType = "struct*"
    Else
        $sHistogramsDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveLBPHFaceRecognizerGetHistograms", $sRecognizerDllType, $recognizer, $sHistogramsDllType, $vecHistograms), "cveLBPHFaceRecognizerGetHistograms", @error)

    If $bHistogramsIsArray Then
        _VectorOfMatRelease($vecHistograms)
    EndIf
EndFunc   ;==>_cveLBPHFaceRecognizerGetHistograms

Func _cveFaceRecognizerTrain($recognizer, $images, $labels)
    ; CVAPI(void) cveFaceRecognizerTrain(cv::face::FaceRecognizer* recognizer, cv::_InputArray* images, cv::_InputArray* labels);

    Local $sRecognizerDllType
    If IsDllStruct($recognizer) Then
        $sRecognizerDllType = "struct*"
    Else
        $sRecognizerDllType = "ptr"
    EndIf

    Local $sImagesDllType
    If IsDllStruct($images) Then
        $sImagesDllType = "struct*"
    Else
        $sImagesDllType = "ptr"
    EndIf

    Local $sLabelsDllType
    If IsDllStruct($labels) Then
        $sLabelsDllType = "struct*"
    Else
        $sLabelsDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFaceRecognizerTrain", $sRecognizerDllType, $recognizer, $sImagesDllType, $images, $sLabelsDllType, $labels), "cveFaceRecognizerTrain", @error)
EndFunc   ;==>_cveFaceRecognizerTrain

Func _cveFaceRecognizerTrainTyped($recognizer, $typeOfImages, $images, $typeOfLabels, $labels)

    Local $iArrImages, $vectorImages, $iArrImagesSize
    Local $bImagesIsArray = IsArray($images)
    Local $bImagesCreate = IsDllStruct($images) And $typeOfImages == "Scalar"

    If $typeOfImages == Default Then
        $iArrImages = $images
    ElseIf $bImagesIsArray Then
        $vectorImages = Call("_VectorOf" & $typeOfImages & "Create")

        $iArrImagesSize = UBound($images)
        For $i = 0 To $iArrImagesSize - 1
            Call("_VectorOf" & $typeOfImages & "Push", $vectorImages, $images[$i])
        Next

        $iArrImages = Call("_cveInputArrayFromVectorOf" & $typeOfImages, $vectorImages)
    Else
        If $bImagesCreate Then
            $images = Call("_cve" & $typeOfImages & "Create", $images)
        EndIf
        $iArrImages = Call("_cveInputArrayFrom" & $typeOfImages, $images)
    EndIf

    Local $iArrLabels, $vectorLabels, $iArrLabelsSize
    Local $bLabelsIsArray = IsArray($labels)
    Local $bLabelsCreate = IsDllStruct($labels) And $typeOfLabels == "Scalar"

    If $typeOfLabels == Default Then
        $iArrLabels = $labels
    ElseIf $bLabelsIsArray Then
        $vectorLabels = Call("_VectorOf" & $typeOfLabels & "Create")

        $iArrLabelsSize = UBound($labels)
        For $i = 0 To $iArrLabelsSize - 1
            Call("_VectorOf" & $typeOfLabels & "Push", $vectorLabels, $labels[$i])
        Next

        $iArrLabels = Call("_cveInputArrayFromVectorOf" & $typeOfLabels, $vectorLabels)
    Else
        If $bLabelsCreate Then
            $labels = Call("_cve" & $typeOfLabels & "Create", $labels)
        EndIf
        $iArrLabels = Call("_cveInputArrayFrom" & $typeOfLabels, $labels)
    EndIf

    _cveFaceRecognizerTrain($recognizer, $iArrImages, $iArrLabels)

    If $bLabelsIsArray Then
        Call("_VectorOf" & $typeOfLabels & "Release", $vectorLabels)
    EndIf

    If $typeOfLabels <> Default Then
        _cveInputArrayRelease($iArrLabels)
        If $bLabelsCreate Then
            Call("_cve" & $typeOfLabels & "Release", $labels)
        EndIf
    EndIf

    If $bImagesIsArray Then
        Call("_VectorOf" & $typeOfImages & "Release", $vectorImages)
    EndIf

    If $typeOfImages <> Default Then
        _cveInputArrayRelease($iArrImages)
        If $bImagesCreate Then
            Call("_cve" & $typeOfImages & "Release", $images)
        EndIf
    EndIf
EndFunc   ;==>_cveFaceRecognizerTrainTyped

Func _cveFaceRecognizerTrainMat($recognizer, $images, $labels)
    ; cveFaceRecognizerTrain using cv::Mat instead of _*Array
    _cveFaceRecognizerTrainTyped($recognizer, "Mat", $images, "Mat", $labels)
EndFunc   ;==>_cveFaceRecognizerTrainMat

Func _cveFaceRecognizerUpdate($recognizer, $images, $labels)
    ; CVAPI(void) cveFaceRecognizerUpdate(cv::face::FaceRecognizer* recognizer, cv::_InputArray* images, cv::_InputArray* labels);

    Local $sRecognizerDllType
    If IsDllStruct($recognizer) Then
        $sRecognizerDllType = "struct*"
    Else
        $sRecognizerDllType = "ptr"
    EndIf

    Local $sImagesDllType
    If IsDllStruct($images) Then
        $sImagesDllType = "struct*"
    Else
        $sImagesDllType = "ptr"
    EndIf

    Local $sLabelsDllType
    If IsDllStruct($labels) Then
        $sLabelsDllType = "struct*"
    Else
        $sLabelsDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFaceRecognizerUpdate", $sRecognizerDllType, $recognizer, $sImagesDllType, $images, $sLabelsDllType, $labels), "cveFaceRecognizerUpdate", @error)
EndFunc   ;==>_cveFaceRecognizerUpdate

Func _cveFaceRecognizerUpdateTyped($recognizer, $typeOfImages, $images, $typeOfLabels, $labels)

    Local $iArrImages, $vectorImages, $iArrImagesSize
    Local $bImagesIsArray = IsArray($images)
    Local $bImagesCreate = IsDllStruct($images) And $typeOfImages == "Scalar"

    If $typeOfImages == Default Then
        $iArrImages = $images
    ElseIf $bImagesIsArray Then
        $vectorImages = Call("_VectorOf" & $typeOfImages & "Create")

        $iArrImagesSize = UBound($images)
        For $i = 0 To $iArrImagesSize - 1
            Call("_VectorOf" & $typeOfImages & "Push", $vectorImages, $images[$i])
        Next

        $iArrImages = Call("_cveInputArrayFromVectorOf" & $typeOfImages, $vectorImages)
    Else
        If $bImagesCreate Then
            $images = Call("_cve" & $typeOfImages & "Create", $images)
        EndIf
        $iArrImages = Call("_cveInputArrayFrom" & $typeOfImages, $images)
    EndIf

    Local $iArrLabels, $vectorLabels, $iArrLabelsSize
    Local $bLabelsIsArray = IsArray($labels)
    Local $bLabelsCreate = IsDllStruct($labels) And $typeOfLabels == "Scalar"

    If $typeOfLabels == Default Then
        $iArrLabels = $labels
    ElseIf $bLabelsIsArray Then
        $vectorLabels = Call("_VectorOf" & $typeOfLabels & "Create")

        $iArrLabelsSize = UBound($labels)
        For $i = 0 To $iArrLabelsSize - 1
            Call("_VectorOf" & $typeOfLabels & "Push", $vectorLabels, $labels[$i])
        Next

        $iArrLabels = Call("_cveInputArrayFromVectorOf" & $typeOfLabels, $vectorLabels)
    Else
        If $bLabelsCreate Then
            $labels = Call("_cve" & $typeOfLabels & "Create", $labels)
        EndIf
        $iArrLabels = Call("_cveInputArrayFrom" & $typeOfLabels, $labels)
    EndIf

    _cveFaceRecognizerUpdate($recognizer, $iArrImages, $iArrLabels)

    If $bLabelsIsArray Then
        Call("_VectorOf" & $typeOfLabels & "Release", $vectorLabels)
    EndIf

    If $typeOfLabels <> Default Then
        _cveInputArrayRelease($iArrLabels)
        If $bLabelsCreate Then
            Call("_cve" & $typeOfLabels & "Release", $labels)
        EndIf
    EndIf

    If $bImagesIsArray Then
        Call("_VectorOf" & $typeOfImages & "Release", $vectorImages)
    EndIf

    If $typeOfImages <> Default Then
        _cveInputArrayRelease($iArrImages)
        If $bImagesCreate Then
            Call("_cve" & $typeOfImages & "Release", $images)
        EndIf
    EndIf
EndFunc   ;==>_cveFaceRecognizerUpdateTyped

Func _cveFaceRecognizerUpdateMat($recognizer, $images, $labels)
    ; cveFaceRecognizerUpdate using cv::Mat instead of _*Array
    _cveFaceRecognizerUpdateTyped($recognizer, "Mat", $images, "Mat", $labels)
EndFunc   ;==>_cveFaceRecognizerUpdateMat

Func _cveFaceRecognizerPredict($recognizer, $image, $label, $distance)
    ; CVAPI(void) cveFaceRecognizerPredict(cv::face::FaceRecognizer* recognizer, cv::_InputArray* image, int* label, double* distance);

    Local $sRecognizerDllType
    If IsDllStruct($recognizer) Then
        $sRecognizerDllType = "struct*"
    Else
        $sRecognizerDllType = "ptr"
    EndIf

    Local $sImageDllType
    If IsDllStruct($image) Then
        $sImageDllType = "struct*"
    Else
        $sImageDllType = "ptr"
    EndIf

    Local $sLabelDllType
    If IsDllStruct($label) Then
        $sLabelDllType = "struct*"
    Else
        $sLabelDllType = "int*"
    EndIf

    Local $sDistanceDllType
    If IsDllStruct($distance) Then
        $sDistanceDllType = "struct*"
    Else
        $sDistanceDllType = "double*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFaceRecognizerPredict", $sRecognizerDllType, $recognizer, $sImageDllType, $image, $sLabelDllType, $label, $sDistanceDllType, $distance), "cveFaceRecognizerPredict", @error)
EndFunc   ;==>_cveFaceRecognizerPredict

Func _cveFaceRecognizerPredictTyped($recognizer, $typeOfImage, $image, $label, $distance)

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

    _cveFaceRecognizerPredict($recognizer, $iArrImage, $label, $distance)

    If $bImageIsArray Then
        Call("_VectorOf" & $typeOfImage & "Release", $vectorImage)
    EndIf

    If $typeOfImage <> Default Then
        _cveInputArrayRelease($iArrImage)
        If $bImageCreate Then
            Call("_cve" & $typeOfImage & "Release", $image)
        EndIf
    EndIf
EndFunc   ;==>_cveFaceRecognizerPredictTyped

Func _cveFaceRecognizerPredictMat($recognizer, $image, $label, $distance)
    ; cveFaceRecognizerPredict using cv::Mat instead of _*Array
    _cveFaceRecognizerPredictTyped($recognizer, "Mat", $image, $label, $distance)
EndFunc   ;==>_cveFaceRecognizerPredictMat

Func _cveFaceRecognizerWrite($recognizer, $fileName)
    ; CVAPI(void) cveFaceRecognizerWrite(cv::face::FaceRecognizer* recognizer, cv::String* fileName);

    Local $sRecognizerDllType
    If IsDllStruct($recognizer) Then
        $sRecognizerDllType = "struct*"
    Else
        $sRecognizerDllType = "ptr"
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFaceRecognizerWrite", $sRecognizerDllType, $recognizer, $sFileNameDllType, $fileName), "cveFaceRecognizerWrite", @error)

    If $bFileNameIsString Then
        _cveStringRelease($fileName)
    EndIf
EndFunc   ;==>_cveFaceRecognizerWrite

Func _cveFaceRecognizerRead($recognizer, $fileName)
    ; CVAPI(void) cveFaceRecognizerRead(cv::face::FaceRecognizer* recognizer, cv::String* fileName);

    Local $sRecognizerDllType
    If IsDllStruct($recognizer) Then
        $sRecognizerDllType = "struct*"
    Else
        $sRecognizerDllType = "ptr"
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFaceRecognizerRead", $sRecognizerDllType, $recognizer, $sFileNameDllType, $fileName), "cveFaceRecognizerRead", @error)

    If $bFileNameIsString Then
        _cveStringRelease($fileName)
    EndIf
EndFunc   ;==>_cveFaceRecognizerRead

Func _cveBIFCreate($numBands, $numRotations, $sharedPtr)
    ; CVAPI(cv::face::BIF*) cveBIFCreate(int numBands, int numRotations, cv::Ptr<cv::face::BIF>** sharedPtr);

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveBIFCreate", "int", $numBands, "int", $numRotations, $sSharedPtrDllType, $sharedPtr), "cveBIFCreate", @error)
EndFunc   ;==>_cveBIFCreate

Func _cveBIFCompute($bif, $image, $features)
    ; CVAPI(void) cveBIFCompute(cv::face::BIF* bif, cv::_InputArray* image, cv::_OutputArray* features);

    Local $sBifDllType
    If IsDllStruct($bif) Then
        $sBifDllType = "struct*"
    Else
        $sBifDllType = "ptr"
    EndIf

    Local $sImageDllType
    If IsDllStruct($image) Then
        $sImageDllType = "struct*"
    Else
        $sImageDllType = "ptr"
    EndIf

    Local $sFeaturesDllType
    If IsDllStruct($features) Then
        $sFeaturesDllType = "struct*"
    Else
        $sFeaturesDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBIFCompute", $sBifDllType, $bif, $sImageDllType, $image, $sFeaturesDllType, $features), "cveBIFCompute", @error)
EndFunc   ;==>_cveBIFCompute

Func _cveBIFComputeTyped($bif, $typeOfImage, $image, $typeOfFeatures, $features)

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

    Local $oArrFeatures, $vectorFeatures, $iArrFeaturesSize
    Local $bFeaturesIsArray = IsArray($features)
    Local $bFeaturesCreate = IsDllStruct($features) And $typeOfFeatures == "Scalar"

    If $typeOfFeatures == Default Then
        $oArrFeatures = $features
    ElseIf $bFeaturesIsArray Then
        $vectorFeatures = Call("_VectorOf" & $typeOfFeatures & "Create")

        $iArrFeaturesSize = UBound($features)
        For $i = 0 To $iArrFeaturesSize - 1
            Call("_VectorOf" & $typeOfFeatures & "Push", $vectorFeatures, $features[$i])
        Next

        $oArrFeatures = Call("_cveOutputArrayFromVectorOf" & $typeOfFeatures, $vectorFeatures)
    Else
        If $bFeaturesCreate Then
            $features = Call("_cve" & $typeOfFeatures & "Create", $features)
        EndIf
        $oArrFeatures = Call("_cveOutputArrayFrom" & $typeOfFeatures, $features)
    EndIf

    _cveBIFCompute($bif, $iArrImage, $oArrFeatures)

    If $bFeaturesIsArray Then
        Call("_VectorOf" & $typeOfFeatures & "Release", $vectorFeatures)
    EndIf

    If $typeOfFeatures <> Default Then
        _cveOutputArrayRelease($oArrFeatures)
        If $bFeaturesCreate Then
            Call("_cve" & $typeOfFeatures & "Release", $features)
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
EndFunc   ;==>_cveBIFComputeTyped

Func _cveBIFComputeMat($bif, $image, $features)
    ; cveBIFCompute using cv::Mat instead of _*Array
    _cveBIFComputeTyped($bif, "Mat", $image, "Mat", $features)
EndFunc   ;==>_cveBIFComputeMat

Func _cveBIFRelease($sharedPtr)
    ; CVAPI(void) cveBIFRelease(cv::Ptr<cv::face::BIF>** sharedPtr);

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBIFRelease", $sSharedPtrDllType, $sharedPtr), "cveBIFRelease", @error)
EndFunc   ;==>_cveBIFRelease

Func _cveFacemarkAAMParamsCreate()
    ; CVAPI(cv::face::FacemarkAAM::Params*) cveFacemarkAAMParamsCreate();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveFacemarkAAMParamsCreate"), "cveFacemarkAAMParamsCreate", @error)
EndFunc   ;==>_cveFacemarkAAMParamsCreate

Func _cveFacemarkAAMParamsRelease($params)
    ; CVAPI(void) cveFacemarkAAMParamsRelease(cv::face::FacemarkAAM::Params** params);

    Local $sParamsDllType
    If IsDllStruct($params) Then
        $sParamsDllType = "struct*"
    ElseIf $params == Null Then
        $sParamsDllType = "ptr"
    Else
        $sParamsDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFacemarkAAMParamsRelease", $sParamsDllType, $params), "cveFacemarkAAMParamsRelease", @error)
EndFunc   ;==>_cveFacemarkAAMParamsRelease

Func _cveFacemarkAAMCreate($parameters, $facemark, $algorithm, $sharedPtr)
    ; CVAPI(cv::face::FacemarkAAM*) cveFacemarkAAMCreate(cv::face::FacemarkAAM::Params* parameters, cv::face::Facemark** facemark, cv::Algorithm** algorithm, cv::Ptr<cv::face::FacemarkAAM>** sharedPtr);

    Local $sParametersDllType
    If IsDllStruct($parameters) Then
        $sParametersDllType = "struct*"
    Else
        $sParametersDllType = "ptr"
    EndIf

    Local $sFacemarkDllType
    If IsDllStruct($facemark) Then
        $sFacemarkDllType = "struct*"
    ElseIf $facemark == Null Then
        $sFacemarkDllType = "ptr"
    Else
        $sFacemarkDllType = "ptr*"
    EndIf

    Local $sAlgorithmDllType
    If IsDllStruct($algorithm) Then
        $sAlgorithmDllType = "struct*"
    ElseIf $algorithm == Null Then
        $sAlgorithmDllType = "ptr"
    Else
        $sAlgorithmDllType = "ptr*"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveFacemarkAAMCreate", $sParametersDllType, $parameters, $sFacemarkDllType, $facemark, $sAlgorithmDllType, $algorithm, $sSharedPtrDllType, $sharedPtr), "cveFacemarkAAMCreate", @error)
EndFunc   ;==>_cveFacemarkAAMCreate

Func _cveFacemarkAAMRelease($facemark, $sharedPtr)
    ; CVAPI(void) cveFacemarkAAMRelease(cv::face::FacemarkAAM** facemark, cv::Ptr<cv::face::FacemarkAAM>** sharedPtr);

    Local $sFacemarkDllType
    If IsDllStruct($facemark) Then
        $sFacemarkDllType = "struct*"
    ElseIf $facemark == Null Then
        $sFacemarkDllType = "ptr"
    Else
        $sFacemarkDllType = "ptr*"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFacemarkAAMRelease", $sFacemarkDllType, $facemark, $sSharedPtrDllType, $sharedPtr), "cveFacemarkAAMRelease", @error)
EndFunc   ;==>_cveFacemarkAAMRelease

Func _cveFacemarkLBFParamsCreate()
    ; CVAPI(cv::face::FacemarkLBF::Params*) cveFacemarkLBFParamsCreate();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveFacemarkLBFParamsCreate"), "cveFacemarkLBFParamsCreate", @error)
EndFunc   ;==>_cveFacemarkLBFParamsCreate

Func _cveFacemarkLBFParamsRelease($params)
    ; CVAPI(void) cveFacemarkLBFParamsRelease(cv::face::FacemarkLBF::Params** params);

    Local $sParamsDllType
    If IsDllStruct($params) Then
        $sParamsDllType = "struct*"
    ElseIf $params == Null Then
        $sParamsDllType = "ptr"
    Else
        $sParamsDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFacemarkLBFParamsRelease", $sParamsDllType, $params), "cveFacemarkLBFParamsRelease", @error)
EndFunc   ;==>_cveFacemarkLBFParamsRelease

Func _cveFacemarkLBFCreate($parameters, $facemark, $algorithm, $sharedPtr)
    ; CVAPI(cv::face::FacemarkLBF*) cveFacemarkLBFCreate(cv::face::FacemarkLBF::Params* parameters, cv::face::Facemark** facemark, cv::Algorithm** algorithm, cv::Ptr<cv::face::FacemarkLBF>** sharedPtr);

    Local $sParametersDllType
    If IsDllStruct($parameters) Then
        $sParametersDllType = "struct*"
    Else
        $sParametersDllType = "ptr"
    EndIf

    Local $sFacemarkDllType
    If IsDllStruct($facemark) Then
        $sFacemarkDllType = "struct*"
    ElseIf $facemark == Null Then
        $sFacemarkDllType = "ptr"
    Else
        $sFacemarkDllType = "ptr*"
    EndIf

    Local $sAlgorithmDllType
    If IsDllStruct($algorithm) Then
        $sAlgorithmDllType = "struct*"
    ElseIf $algorithm == Null Then
        $sAlgorithmDllType = "ptr"
    Else
        $sAlgorithmDllType = "ptr*"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveFacemarkLBFCreate", $sParametersDllType, $parameters, $sFacemarkDllType, $facemark, $sAlgorithmDllType, $algorithm, $sSharedPtrDllType, $sharedPtr), "cveFacemarkLBFCreate", @error)
EndFunc   ;==>_cveFacemarkLBFCreate

Func _cveFacemarkLBFRelease($facemark, $sharedPtr)
    ; CVAPI(void) cveFacemarkLBFRelease(cv::face::FacemarkLBF** facemark, cv::Ptr<cv::face::FacemarkLBF>** sharedPtr);

    Local $sFacemarkDllType
    If IsDllStruct($facemark) Then
        $sFacemarkDllType = "struct*"
    ElseIf $facemark == Null Then
        $sFacemarkDllType = "ptr"
    Else
        $sFacemarkDllType = "ptr*"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFacemarkLBFRelease", $sFacemarkDllType, $facemark, $sSharedPtrDllType, $sharedPtr), "cveFacemarkLBFRelease", @error)
EndFunc   ;==>_cveFacemarkLBFRelease

Func _cveFacemarkLoadModel($facemark, $model)
    ; CVAPI(void) cveFacemarkLoadModel(cv::face::Facemark* facemark, cv::String* model);

    Local $sFacemarkDllType
    If IsDllStruct($facemark) Then
        $sFacemarkDllType = "struct*"
    Else
        $sFacemarkDllType = "ptr"
    EndIf

    Local $bModelIsString = IsString($model)
    If $bModelIsString Then
        $model = _cveStringCreateFromStr($model)
    EndIf

    Local $sModelDllType
    If IsDllStruct($model) Then
        $sModelDllType = "struct*"
    Else
        $sModelDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFacemarkLoadModel", $sFacemarkDllType, $facemark, $sModelDllType, $model), "cveFacemarkLoadModel", @error)

    If $bModelIsString Then
        _cveStringRelease($model)
    EndIf
EndFunc   ;==>_cveFacemarkLoadModel

Func _cveFacemarkFit($facemark, $image, $faces, $landmarks)
    ; CVAPI(bool) cveFacemarkFit(cv::face::Facemark* facemark, cv::_InputArray* image, cv::_InputArray* faces, cv::_InputOutputArray* landmarks);

    Local $sFacemarkDllType
    If IsDllStruct($facemark) Then
        $sFacemarkDllType = "struct*"
    Else
        $sFacemarkDllType = "ptr"
    EndIf

    Local $sImageDllType
    If IsDllStruct($image) Then
        $sImageDllType = "struct*"
    Else
        $sImageDllType = "ptr"
    EndIf

    Local $sFacesDllType
    If IsDllStruct($faces) Then
        $sFacesDllType = "struct*"
    Else
        $sFacesDllType = "ptr"
    EndIf

    Local $sLandmarksDllType
    If IsDllStruct($landmarks) Then
        $sLandmarksDllType = "struct*"
    Else
        $sLandmarksDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveFacemarkFit", $sFacemarkDllType, $facemark, $sImageDllType, $image, $sFacesDllType, $faces, $sLandmarksDllType, $landmarks), "cveFacemarkFit", @error)
EndFunc   ;==>_cveFacemarkFit

Func _cveFacemarkFitTyped($facemark, $typeOfImage, $image, $typeOfFaces, $faces, $typeOfLandmarks, $landmarks)

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

    Local $iArrFaces, $vectorFaces, $iArrFacesSize
    Local $bFacesIsArray = IsArray($faces)
    Local $bFacesCreate = IsDllStruct($faces) And $typeOfFaces == "Scalar"

    If $typeOfFaces == Default Then
        $iArrFaces = $faces
    ElseIf $bFacesIsArray Then
        $vectorFaces = Call("_VectorOf" & $typeOfFaces & "Create")

        $iArrFacesSize = UBound($faces)
        For $i = 0 To $iArrFacesSize - 1
            Call("_VectorOf" & $typeOfFaces & "Push", $vectorFaces, $faces[$i])
        Next

        $iArrFaces = Call("_cveInputArrayFromVectorOf" & $typeOfFaces, $vectorFaces)
    Else
        If $bFacesCreate Then
            $faces = Call("_cve" & $typeOfFaces & "Create", $faces)
        EndIf
        $iArrFaces = Call("_cveInputArrayFrom" & $typeOfFaces, $faces)
    EndIf

    Local $ioArrLandmarks, $vectorLandmarks, $iArrLandmarksSize
    Local $bLandmarksIsArray = IsArray($landmarks)
    Local $bLandmarksCreate = IsDllStruct($landmarks) And $typeOfLandmarks == "Scalar"

    If $typeOfLandmarks == Default Then
        $ioArrLandmarks = $landmarks
    ElseIf $bLandmarksIsArray Then
        $vectorLandmarks = Call("_VectorOf" & $typeOfLandmarks & "Create")

        $iArrLandmarksSize = UBound($landmarks)
        For $i = 0 To $iArrLandmarksSize - 1
            Call("_VectorOf" & $typeOfLandmarks & "Push", $vectorLandmarks, $landmarks[$i])
        Next

        $ioArrLandmarks = Call("_cveInputOutputArrayFromVectorOf" & $typeOfLandmarks, $vectorLandmarks)
    Else
        If $bLandmarksCreate Then
            $landmarks = Call("_cve" & $typeOfLandmarks & "Create", $landmarks)
        EndIf
        $ioArrLandmarks = Call("_cveInputOutputArrayFrom" & $typeOfLandmarks, $landmarks)
    EndIf

    Local $retval = _cveFacemarkFit($facemark, $iArrImage, $iArrFaces, $ioArrLandmarks)

    If $bLandmarksIsArray Then
        Call("_VectorOf" & $typeOfLandmarks & "Release", $vectorLandmarks)
    EndIf

    If $typeOfLandmarks <> Default Then
        _cveInputOutputArrayRelease($ioArrLandmarks)
        If $bLandmarksCreate Then
            Call("_cve" & $typeOfLandmarks & "Release", $landmarks)
        EndIf
    EndIf

    If $bFacesIsArray Then
        Call("_VectorOf" & $typeOfFaces & "Release", $vectorFaces)
    EndIf

    If $typeOfFaces <> Default Then
        _cveInputArrayRelease($iArrFaces)
        If $bFacesCreate Then
            Call("_cve" & $typeOfFaces & "Release", $faces)
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

    Return $retval
EndFunc   ;==>_cveFacemarkFitTyped

Func _cveFacemarkFitMat($facemark, $image, $faces, $landmarks)
    ; cveFacemarkFit using cv::Mat instead of _*Array
    Local $retval = _cveFacemarkFitTyped($facemark, "Mat", $image, "Mat", $faces, "Mat", $landmarks)

    Return $retval
EndFunc   ;==>_cveFacemarkFitMat

Func _cveDrawFacemarks($image, $points, $color = _cvScalar(255,0,0))
    ; CVAPI(void) cveDrawFacemarks(cv::_InputOutputArray* image, cv::_InputArray* points, CvScalar* color);

    Local $sImageDllType
    If IsDllStruct($image) Then
        $sImageDllType = "struct*"
    Else
        $sImageDllType = "ptr"
    EndIf

    Local $sPointsDllType
    If IsDllStruct($points) Then
        $sPointsDllType = "struct*"
    Else
        $sPointsDllType = "ptr"
    EndIf

    Local $sColorDllType
    If IsDllStruct($color) Then
        $sColorDllType = "struct*"
    Else
        $sColorDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDrawFacemarks", $sImageDllType, $image, $sPointsDllType, $points, $sColorDllType, $color), "cveDrawFacemarks", @error)
EndFunc   ;==>_cveDrawFacemarks

Func _cveDrawFacemarksTyped($typeOfImage, $image, $typeOfPoints, $points, $color = _cvScalar(255,0,0))

    Local $ioArrImage, $vectorImage, $iArrImageSize
    Local $bImageIsArray = IsArray($image)
    Local $bImageCreate = IsDllStruct($image) And $typeOfImage == "Scalar"

    If $typeOfImage == Default Then
        $ioArrImage = $image
    ElseIf $bImageIsArray Then
        $vectorImage = Call("_VectorOf" & $typeOfImage & "Create")

        $iArrImageSize = UBound($image)
        For $i = 0 To $iArrImageSize - 1
            Call("_VectorOf" & $typeOfImage & "Push", $vectorImage, $image[$i])
        Next

        $ioArrImage = Call("_cveInputOutputArrayFromVectorOf" & $typeOfImage, $vectorImage)
    Else
        If $bImageCreate Then
            $image = Call("_cve" & $typeOfImage & "Create", $image)
        EndIf
        $ioArrImage = Call("_cveInputOutputArrayFrom" & $typeOfImage, $image)
    EndIf

    Local $iArrPoints, $vectorPoints, $iArrPointsSize
    Local $bPointsIsArray = IsArray($points)
    Local $bPointsCreate = IsDllStruct($points) And $typeOfPoints == "Scalar"

    If $typeOfPoints == Default Then
        $iArrPoints = $points
    ElseIf $bPointsIsArray Then
        $vectorPoints = Call("_VectorOf" & $typeOfPoints & "Create")

        $iArrPointsSize = UBound($points)
        For $i = 0 To $iArrPointsSize - 1
            Call("_VectorOf" & $typeOfPoints & "Push", $vectorPoints, $points[$i])
        Next

        $iArrPoints = Call("_cveInputArrayFromVectorOf" & $typeOfPoints, $vectorPoints)
    Else
        If $bPointsCreate Then
            $points = Call("_cve" & $typeOfPoints & "Create", $points)
        EndIf
        $iArrPoints = Call("_cveInputArrayFrom" & $typeOfPoints, $points)
    EndIf

    _cveDrawFacemarks($ioArrImage, $iArrPoints, $color)

    If $bPointsIsArray Then
        Call("_VectorOf" & $typeOfPoints & "Release", $vectorPoints)
    EndIf

    If $typeOfPoints <> Default Then
        _cveInputArrayRelease($iArrPoints)
        If $bPointsCreate Then
            Call("_cve" & $typeOfPoints & "Release", $points)
        EndIf
    EndIf

    If $bImageIsArray Then
        Call("_VectorOf" & $typeOfImage & "Release", $vectorImage)
    EndIf

    If $typeOfImage <> Default Then
        _cveInputOutputArrayRelease($ioArrImage)
        If $bImageCreate Then
            Call("_cve" & $typeOfImage & "Release", $image)
        EndIf
    EndIf
EndFunc   ;==>_cveDrawFacemarksTyped

Func _cveDrawFacemarksMat($image, $points, $color = _cvScalar(255,0,0))
    ; cveDrawFacemarks using cv::Mat instead of _*Array
    _cveDrawFacemarksTyped("Mat", $image, "Mat", $points, $color)
EndFunc   ;==>_cveDrawFacemarksMat

Func _cveMaceCreate($imgSize, $sharedPtr)
    ; CVAPI(cv::face::MACE*) cveMaceCreate(int imgSize, cv::Ptr<cv::face::MACE>** sharedPtr);

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveMaceCreate", "int", $imgSize, $sSharedPtrDllType, $sharedPtr), "cveMaceCreate", @error)
EndFunc   ;==>_cveMaceCreate

Func _cveMaceSalt($mace, $passphrase)
    ; CVAPI(void) cveMaceSalt(cv::face::MACE* mace, cv::String* passphrase);

    Local $sMaceDllType
    If IsDllStruct($mace) Then
        $sMaceDllType = "struct*"
    Else
        $sMaceDllType = "ptr"
    EndIf

    Local $bPassphraseIsString = IsString($passphrase)
    If $bPassphraseIsString Then
        $passphrase = _cveStringCreateFromStr($passphrase)
    EndIf

    Local $sPassphraseDllType
    If IsDllStruct($passphrase) Then
        $sPassphraseDllType = "struct*"
    Else
        $sPassphraseDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMaceSalt", $sMaceDllType, $mace, $sPassphraseDllType, $passphrase), "cveMaceSalt", @error)

    If $bPassphraseIsString Then
        _cveStringRelease($passphrase)
    EndIf
EndFunc   ;==>_cveMaceSalt

Func _cveMaceTrain($mace, $images)
    ; CVAPI(void) cveMaceTrain(cv::face::MACE* mace, cv::_InputArray* images);

    Local $sMaceDllType
    If IsDllStruct($mace) Then
        $sMaceDllType = "struct*"
    Else
        $sMaceDllType = "ptr"
    EndIf

    Local $sImagesDllType
    If IsDllStruct($images) Then
        $sImagesDllType = "struct*"
    Else
        $sImagesDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMaceTrain", $sMaceDllType, $mace, $sImagesDllType, $images), "cveMaceTrain", @error)
EndFunc   ;==>_cveMaceTrain

Func _cveMaceTrainTyped($mace, $typeOfImages, $images)

    Local $iArrImages, $vectorImages, $iArrImagesSize
    Local $bImagesIsArray = IsArray($images)
    Local $bImagesCreate = IsDllStruct($images) And $typeOfImages == "Scalar"

    If $typeOfImages == Default Then
        $iArrImages = $images
    ElseIf $bImagesIsArray Then
        $vectorImages = Call("_VectorOf" & $typeOfImages & "Create")

        $iArrImagesSize = UBound($images)
        For $i = 0 To $iArrImagesSize - 1
            Call("_VectorOf" & $typeOfImages & "Push", $vectorImages, $images[$i])
        Next

        $iArrImages = Call("_cveInputArrayFromVectorOf" & $typeOfImages, $vectorImages)
    Else
        If $bImagesCreate Then
            $images = Call("_cve" & $typeOfImages & "Create", $images)
        EndIf
        $iArrImages = Call("_cveInputArrayFrom" & $typeOfImages, $images)
    EndIf

    _cveMaceTrain($mace, $iArrImages)

    If $bImagesIsArray Then
        Call("_VectorOf" & $typeOfImages & "Release", $vectorImages)
    EndIf

    If $typeOfImages <> Default Then
        _cveInputArrayRelease($iArrImages)
        If $bImagesCreate Then
            Call("_cve" & $typeOfImages & "Release", $images)
        EndIf
    EndIf
EndFunc   ;==>_cveMaceTrainTyped

Func _cveMaceTrainMat($mace, $images)
    ; cveMaceTrain using cv::Mat instead of _*Array
    _cveMaceTrainTyped($mace, "Mat", $images)
EndFunc   ;==>_cveMaceTrainMat

Func _cveMaceSame($mace, $query)
    ; CVAPI(bool) cveMaceSame(cv::face::MACE* mace, cv::_InputArray* query);

    Local $sMaceDllType
    If IsDllStruct($mace) Then
        $sMaceDllType = "struct*"
    Else
        $sMaceDllType = "ptr"
    EndIf

    Local $sQueryDllType
    If IsDllStruct($query) Then
        $sQueryDllType = "struct*"
    Else
        $sQueryDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveMaceSame", $sMaceDllType, $mace, $sQueryDllType, $query), "cveMaceSame", @error)
EndFunc   ;==>_cveMaceSame

Func _cveMaceSameTyped($mace, $typeOfQuery, $query)

    Local $iArrQuery, $vectorQuery, $iArrQuerySize
    Local $bQueryIsArray = IsArray($query)
    Local $bQueryCreate = IsDllStruct($query) And $typeOfQuery == "Scalar"

    If $typeOfQuery == Default Then
        $iArrQuery = $query
    ElseIf $bQueryIsArray Then
        $vectorQuery = Call("_VectorOf" & $typeOfQuery & "Create")

        $iArrQuerySize = UBound($query)
        For $i = 0 To $iArrQuerySize - 1
            Call("_VectorOf" & $typeOfQuery & "Push", $vectorQuery, $query[$i])
        Next

        $iArrQuery = Call("_cveInputArrayFromVectorOf" & $typeOfQuery, $vectorQuery)
    Else
        If $bQueryCreate Then
            $query = Call("_cve" & $typeOfQuery & "Create", $query)
        EndIf
        $iArrQuery = Call("_cveInputArrayFrom" & $typeOfQuery, $query)
    EndIf

    Local $retval = _cveMaceSame($mace, $iArrQuery)

    If $bQueryIsArray Then
        Call("_VectorOf" & $typeOfQuery & "Release", $vectorQuery)
    EndIf

    If $typeOfQuery <> Default Then
        _cveInputArrayRelease($iArrQuery)
        If $bQueryCreate Then
            Call("_cve" & $typeOfQuery & "Release", $query)
        EndIf
    EndIf

    Return $retval
EndFunc   ;==>_cveMaceSameTyped

Func _cveMaceSameMat($mace, $query)
    ; cveMaceSame using cv::Mat instead of _*Array
    Local $retval = _cveMaceSameTyped($mace, "Mat", $query)

    Return $retval
EndFunc   ;==>_cveMaceSameMat

Func _cveMaceRelease($sharedPtr)
    ; CVAPI(void) cveMaceRelease(cv::Ptr<cv::face::MACE>** sharedPtr);

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMaceRelease", $sSharedPtrDllType, $sharedPtr), "cveMaceRelease", @error)
EndFunc   ;==>_cveMaceRelease