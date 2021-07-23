#include-once
#include "..\..\CVEUtils.au3"

Func _cveEigenFaceRecognizerCreate($numComponents, $threshold, $faceRecognizerPtr, $basicFaceRecognizerPtr, $sharedPtr)
    ; CVAPI(cv::face::EigenFaceRecognizer*) cveEigenFaceRecognizerCreate(int numComponents, double threshold, cv::face::FaceRecognizer** faceRecognizerPtr, cv::face::BasicFaceRecognizer** basicFaceRecognizerPtr, cv::Ptr<cv::face::EigenFaceRecognizer>** sharedPtr);

    Local $bFaceRecognizerPtrDllType
    If VarGetType($faceRecognizerPtr) == "DLLStruct" Then
        $bFaceRecognizerPtrDllType = "struct*"
    Else
        $bFaceRecognizerPtrDllType = "ptr*"
    EndIf

    Local $bBasicFaceRecognizerPtrDllType
    If VarGetType($basicFaceRecognizerPtr) == "DLLStruct" Then
        $bBasicFaceRecognizerPtrDllType = "struct*"
    Else
        $bBasicFaceRecognizerPtrDllType = "ptr*"
    EndIf

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveEigenFaceRecognizerCreate", "int", $numComponents, "double", $threshold, $bFaceRecognizerPtrDllType, $faceRecognizerPtr, $bBasicFaceRecognizerPtrDllType, $basicFaceRecognizerPtr, $bSharedPtrDllType, $sharedPtr), "cveEigenFaceRecognizerCreate", @error)
EndFunc   ;==>_cveEigenFaceRecognizerCreate

Func _cveEigenFaceRecognizerRelease($sharedPtr)
    ; CVAPI(void) cveEigenFaceRecognizerRelease(cv::Ptr<cv::face::EigenFaceRecognizer>** sharedPtr);

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveEigenFaceRecognizerRelease", $bSharedPtrDllType, $sharedPtr), "cveEigenFaceRecognizerRelease", @error)
EndFunc   ;==>_cveEigenFaceRecognizerRelease

Func _cveFisherFaceRecognizerCreate($numComponents, $threshold, $faceRecognizerPtr, $basicFaceRecognizerPtr, $sharedPtr)
    ; CVAPI(cv::face::FisherFaceRecognizer*) cveFisherFaceRecognizerCreate(int numComponents, double threshold, cv::face::FaceRecognizer** faceRecognizerPtr, cv::face::FaceRecognizer** basicFaceRecognizerPtr, cv::Ptr<cv::face::FisherFaceRecognizer>** sharedPtr);

    Local $bFaceRecognizerPtrDllType
    If VarGetType($faceRecognizerPtr) == "DLLStruct" Then
        $bFaceRecognizerPtrDllType = "struct*"
    Else
        $bFaceRecognizerPtrDllType = "ptr*"
    EndIf

    Local $bBasicFaceRecognizerPtrDllType
    If VarGetType($basicFaceRecognizerPtr) == "DLLStruct" Then
        $bBasicFaceRecognizerPtrDllType = "struct*"
    Else
        $bBasicFaceRecognizerPtrDllType = "ptr*"
    EndIf

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveFisherFaceRecognizerCreate", "int", $numComponents, "double", $threshold, $bFaceRecognizerPtrDllType, $faceRecognizerPtr, $bBasicFaceRecognizerPtrDllType, $basicFaceRecognizerPtr, $bSharedPtrDllType, $sharedPtr), "cveFisherFaceRecognizerCreate", @error)
EndFunc   ;==>_cveFisherFaceRecognizerCreate

Func _cveFisherFaceRecognizerRelease($sharedPtr)
    ; CVAPI(void) cveFisherFaceRecognizerRelease(cv::Ptr<cv::face::FisherFaceRecognizer>** sharedPtr);

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFisherFaceRecognizerRelease", $bSharedPtrDllType, $sharedPtr), "cveFisherFaceRecognizerRelease", @error)
EndFunc   ;==>_cveFisherFaceRecognizerRelease

Func _cveLBPHFaceRecognizerCreate($radius, $neighbors, $gridX, $gridY, $threshold, $faceRecognizerPtr, $sharedPtr)
    ; CVAPI(cv::face::LBPHFaceRecognizer*) cveLBPHFaceRecognizerCreate(int radius, int neighbors, int gridX, int gridY, double threshold, cv::face::FaceRecognizer** faceRecognizerPtr, cv::Ptr<cv::face::LBPHFaceRecognizer>** sharedPtr);

    Local $bFaceRecognizerPtrDllType
    If VarGetType($faceRecognizerPtr) == "DLLStruct" Then
        $bFaceRecognizerPtrDllType = "struct*"
    Else
        $bFaceRecognizerPtrDllType = "ptr*"
    EndIf

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveLBPHFaceRecognizerCreate", "int", $radius, "int", $neighbors, "int", $gridX, "int", $gridY, "double", $threshold, $bFaceRecognizerPtrDllType, $faceRecognizerPtr, $bSharedPtrDllType, $sharedPtr), "cveLBPHFaceRecognizerCreate", @error)
EndFunc   ;==>_cveLBPHFaceRecognizerCreate

Func _cveLBPHFaceRecognizerRelease($sharedPtr)
    ; CVAPI(void) cveLBPHFaceRecognizerRelease(cv::Ptr<cv::face::LBPHFaceRecognizer>** sharedPtr);

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveLBPHFaceRecognizerRelease", $bSharedPtrDllType, $sharedPtr), "cveLBPHFaceRecognizerRelease", @error)
EndFunc   ;==>_cveLBPHFaceRecognizerRelease

Func _cveLBPHFaceRecognizerGetHistograms($recognizer, $histograms)
    ; CVAPI(void) cveLBPHFaceRecognizerGetHistograms(cv::face::LBPHFaceRecognizer* recognizer, std::vector<cv::Mat>* histograms);

    Local $bRecognizerDllType
    If VarGetType($recognizer) == "DLLStruct" Then
        $bRecognizerDllType = "struct*"
    Else
        $bRecognizerDllType = "ptr"
    EndIf

    Local $vecHistograms, $iArrHistogramsSize
    Local $bHistogramsIsArray = VarGetType($histograms) == "Array"

    If $bHistogramsIsArray Then
        $vecHistograms = _VectorOfMatCreate()

        $iArrHistogramsSize = UBound($histograms)
        For $i = 0 To $iArrHistogramsSize - 1
            _VectorOfMatPush($vecHistograms, $histograms[$i])
        Next
    Else
        $vecHistograms = $histograms
    EndIf

    Local $bHistogramsDllType
    If VarGetType($histograms) == "DLLStruct" Then
        $bHistogramsDllType = "struct*"
    Else
        $bHistogramsDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveLBPHFaceRecognizerGetHistograms", $bRecognizerDllType, $recognizer, $bHistogramsDllType, $vecHistograms), "cveLBPHFaceRecognizerGetHistograms", @error)

    If $bHistogramsIsArray Then
        _VectorOfMatRelease($vecHistograms)
    EndIf
EndFunc   ;==>_cveLBPHFaceRecognizerGetHistograms

Func _cveFaceRecognizerTrain($recognizer, $images, $labels)
    ; CVAPI(void) cveFaceRecognizerTrain(cv::face::FaceRecognizer* recognizer, cv::_InputArray* images, cv::_InputArray* labels);

    Local $bRecognizerDllType
    If VarGetType($recognizer) == "DLLStruct" Then
        $bRecognizerDllType = "struct*"
    Else
        $bRecognizerDllType = "ptr"
    EndIf

    Local $bImagesDllType
    If VarGetType($images) == "DLLStruct" Then
        $bImagesDllType = "struct*"
    Else
        $bImagesDllType = "ptr"
    EndIf

    Local $bLabelsDllType
    If VarGetType($labels) == "DLLStruct" Then
        $bLabelsDllType = "struct*"
    Else
        $bLabelsDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFaceRecognizerTrain", $bRecognizerDllType, $recognizer, $bImagesDllType, $images, $bLabelsDllType, $labels), "cveFaceRecognizerTrain", @error)
EndFunc   ;==>_cveFaceRecognizerTrain

Func _cveFaceRecognizerTrainMat($recognizer, $matImages, $matLabels)
    ; cveFaceRecognizerTrain using cv::Mat instead of _*Array

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

    Local $iArrLabels, $vectorOfMatLabels, $iArrLabelsSize
    Local $bLabelsIsArray = VarGetType($matLabels) == "Array"

    If $bLabelsIsArray Then
        $vectorOfMatLabels = _VectorOfMatCreate()

        $iArrLabelsSize = UBound($matLabels)
        For $i = 0 To $iArrLabelsSize - 1
            _VectorOfMatPush($vectorOfMatLabels, $matLabels[$i])
        Next

        $iArrLabels = _cveInputArrayFromVectorOfMat($vectorOfMatLabels)
    Else
        $iArrLabels = _cveInputArrayFromMat($matLabels)
    EndIf

    _cveFaceRecognizerTrain($recognizer, $iArrImages, $iArrLabels)

    If $bLabelsIsArray Then
        _VectorOfMatRelease($vectorOfMatLabels)
    EndIf

    _cveInputArrayRelease($iArrLabels)

    If $bImagesIsArray Then
        _VectorOfMatRelease($vectorOfMatImages)
    EndIf

    _cveInputArrayRelease($iArrImages)
EndFunc   ;==>_cveFaceRecognizerTrainMat

Func _cveFaceRecognizerUpdate($recognizer, $images, $labels)
    ; CVAPI(void) cveFaceRecognizerUpdate(cv::face::FaceRecognizer* recognizer, cv::_InputArray* images, cv::_InputArray* labels);

    Local $bRecognizerDllType
    If VarGetType($recognizer) == "DLLStruct" Then
        $bRecognizerDllType = "struct*"
    Else
        $bRecognizerDllType = "ptr"
    EndIf

    Local $bImagesDllType
    If VarGetType($images) == "DLLStruct" Then
        $bImagesDllType = "struct*"
    Else
        $bImagesDllType = "ptr"
    EndIf

    Local $bLabelsDllType
    If VarGetType($labels) == "DLLStruct" Then
        $bLabelsDllType = "struct*"
    Else
        $bLabelsDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFaceRecognizerUpdate", $bRecognizerDllType, $recognizer, $bImagesDllType, $images, $bLabelsDllType, $labels), "cveFaceRecognizerUpdate", @error)
EndFunc   ;==>_cveFaceRecognizerUpdate

Func _cveFaceRecognizerUpdateMat($recognizer, $matImages, $matLabels)
    ; cveFaceRecognizerUpdate using cv::Mat instead of _*Array

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

    Local $iArrLabels, $vectorOfMatLabels, $iArrLabelsSize
    Local $bLabelsIsArray = VarGetType($matLabels) == "Array"

    If $bLabelsIsArray Then
        $vectorOfMatLabels = _VectorOfMatCreate()

        $iArrLabelsSize = UBound($matLabels)
        For $i = 0 To $iArrLabelsSize - 1
            _VectorOfMatPush($vectorOfMatLabels, $matLabels[$i])
        Next

        $iArrLabels = _cveInputArrayFromVectorOfMat($vectorOfMatLabels)
    Else
        $iArrLabels = _cveInputArrayFromMat($matLabels)
    EndIf

    _cveFaceRecognizerUpdate($recognizer, $iArrImages, $iArrLabels)

    If $bLabelsIsArray Then
        _VectorOfMatRelease($vectorOfMatLabels)
    EndIf

    _cveInputArrayRelease($iArrLabels)

    If $bImagesIsArray Then
        _VectorOfMatRelease($vectorOfMatImages)
    EndIf

    _cveInputArrayRelease($iArrImages)
EndFunc   ;==>_cveFaceRecognizerUpdateMat

Func _cveFaceRecognizerPredict($recognizer, $image, $label, $distance)
    ; CVAPI(void) cveFaceRecognizerPredict(cv::face::FaceRecognizer* recognizer, cv::_InputArray* image, int* label, double* distance);

    Local $bRecognizerDllType
    If VarGetType($recognizer) == "DLLStruct" Then
        $bRecognizerDllType = "struct*"
    Else
        $bRecognizerDllType = "ptr"
    EndIf

    Local $bImageDllType
    If VarGetType($image) == "DLLStruct" Then
        $bImageDllType = "struct*"
    Else
        $bImageDllType = "ptr"
    EndIf

    Local $bLabelDllType
    If VarGetType($label) == "DLLStruct" Then
        $bLabelDllType = "struct*"
    Else
        $bLabelDllType = "int*"
    EndIf

    Local $bDistanceDllType
    If VarGetType($distance) == "DLLStruct" Then
        $bDistanceDllType = "struct*"
    Else
        $bDistanceDllType = "double*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFaceRecognizerPredict", $bRecognizerDllType, $recognizer, $bImageDllType, $image, $bLabelDllType, $label, $bDistanceDllType, $distance), "cveFaceRecognizerPredict", @error)
EndFunc   ;==>_cveFaceRecognizerPredict

Func _cveFaceRecognizerPredictMat($recognizer, $matImage, $label, $distance)
    ; cveFaceRecognizerPredict using cv::Mat instead of _*Array

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

    _cveFaceRecognizerPredict($recognizer, $iArrImage, $label, $distance)

    If $bImageIsArray Then
        _VectorOfMatRelease($vectorOfMatImage)
    EndIf

    _cveInputArrayRelease($iArrImage)
EndFunc   ;==>_cveFaceRecognizerPredictMat

Func _cveFaceRecognizerWrite($recognizer, $fileName)
    ; CVAPI(void) cveFaceRecognizerWrite(cv::face::FaceRecognizer* recognizer, cv::String* fileName);

    Local $bRecognizerDllType
    If VarGetType($recognizer) == "DLLStruct" Then
        $bRecognizerDllType = "struct*"
    Else
        $bRecognizerDllType = "ptr"
    EndIf

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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFaceRecognizerWrite", $bRecognizerDllType, $recognizer, $bFileNameDllType, $fileName), "cveFaceRecognizerWrite", @error)

    If $bFileNameIsString Then
        _cveStringRelease($fileName)
    EndIf
EndFunc   ;==>_cveFaceRecognizerWrite

Func _cveFaceRecognizerRead($recognizer, $fileName)
    ; CVAPI(void) cveFaceRecognizerRead(cv::face::FaceRecognizer* recognizer, cv::String* fileName);

    Local $bRecognizerDllType
    If VarGetType($recognizer) == "DLLStruct" Then
        $bRecognizerDllType = "struct*"
    Else
        $bRecognizerDllType = "ptr"
    EndIf

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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFaceRecognizerRead", $bRecognizerDllType, $recognizer, $bFileNameDllType, $fileName), "cveFaceRecognizerRead", @error)

    If $bFileNameIsString Then
        _cveStringRelease($fileName)
    EndIf
EndFunc   ;==>_cveFaceRecognizerRead

Func _cveBIFCreate($numBands, $numRotations, $sharedPtr)
    ; CVAPI(cv::face::BIF*) cveBIFCreate(int numBands, int numRotations, cv::Ptr<cv::face::BIF>** sharedPtr);

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveBIFCreate", "int", $numBands, "int", $numRotations, $bSharedPtrDllType, $sharedPtr), "cveBIFCreate", @error)
EndFunc   ;==>_cveBIFCreate

Func _cveBIFCompute($bif, $image, $features)
    ; CVAPI(void) cveBIFCompute(cv::face::BIF* bif, cv::_InputArray* image, cv::_OutputArray* features);

    Local $bBifDllType
    If VarGetType($bif) == "DLLStruct" Then
        $bBifDllType = "struct*"
    Else
        $bBifDllType = "ptr"
    EndIf

    Local $bImageDllType
    If VarGetType($image) == "DLLStruct" Then
        $bImageDllType = "struct*"
    Else
        $bImageDllType = "ptr"
    EndIf

    Local $bFeaturesDllType
    If VarGetType($features) == "DLLStruct" Then
        $bFeaturesDllType = "struct*"
    Else
        $bFeaturesDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBIFCompute", $bBifDllType, $bif, $bImageDllType, $image, $bFeaturesDllType, $features), "cveBIFCompute", @error)
EndFunc   ;==>_cveBIFCompute

Func _cveBIFComputeMat($bif, $matImage, $matFeatures)
    ; cveBIFCompute using cv::Mat instead of _*Array

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

    Local $oArrFeatures, $vectorOfMatFeatures, $iArrFeaturesSize
    Local $bFeaturesIsArray = VarGetType($matFeatures) == "Array"

    If $bFeaturesIsArray Then
        $vectorOfMatFeatures = _VectorOfMatCreate()

        $iArrFeaturesSize = UBound($matFeatures)
        For $i = 0 To $iArrFeaturesSize - 1
            _VectorOfMatPush($vectorOfMatFeatures, $matFeatures[$i])
        Next

        $oArrFeatures = _cveOutputArrayFromVectorOfMat($vectorOfMatFeatures)
    Else
        $oArrFeatures = _cveOutputArrayFromMat($matFeatures)
    EndIf

    _cveBIFCompute($bif, $iArrImage, $oArrFeatures)

    If $bFeaturesIsArray Then
        _VectorOfMatRelease($vectorOfMatFeatures)
    EndIf

    _cveOutputArrayRelease($oArrFeatures)

    If $bImageIsArray Then
        _VectorOfMatRelease($vectorOfMatImage)
    EndIf

    _cveInputArrayRelease($iArrImage)
EndFunc   ;==>_cveBIFComputeMat

Func _cveBIFRelease($sharedPtr)
    ; CVAPI(void) cveBIFRelease(cv::Ptr<cv::face::BIF>** sharedPtr);

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBIFRelease", $bSharedPtrDllType, $sharedPtr), "cveBIFRelease", @error)
EndFunc   ;==>_cveBIFRelease

Func _cveFacemarkAAMParamsCreate()
    ; CVAPI(cv::face::FacemarkAAM::Params*) cveFacemarkAAMParamsCreate();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveFacemarkAAMParamsCreate"), "cveFacemarkAAMParamsCreate", @error)
EndFunc   ;==>_cveFacemarkAAMParamsCreate

Func _cveFacemarkAAMParamsRelease($params)
    ; CVAPI(void) cveFacemarkAAMParamsRelease(cv::face::FacemarkAAM::Params** params);

    Local $bParamsDllType
    If VarGetType($params) == "DLLStruct" Then
        $bParamsDllType = "struct*"
    Else
        $bParamsDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFacemarkAAMParamsRelease", $bParamsDllType, $params), "cveFacemarkAAMParamsRelease", @error)
EndFunc   ;==>_cveFacemarkAAMParamsRelease

Func _cveFacemarkAAMCreate($parameters, $facemark, $algorithm, $sharedPtr)
    ; CVAPI(cv::face::FacemarkAAM*) cveFacemarkAAMCreate(cv::face::FacemarkAAM::Params* parameters, cv::face::Facemark** facemark, cv::Algorithm** algorithm, cv::Ptr<cv::face::FacemarkAAM>** sharedPtr);

    Local $bParametersDllType
    If VarGetType($parameters) == "DLLStruct" Then
        $bParametersDllType = "struct*"
    Else
        $bParametersDllType = "ptr"
    EndIf

    Local $bFacemarkDllType
    If VarGetType($facemark) == "DLLStruct" Then
        $bFacemarkDllType = "struct*"
    Else
        $bFacemarkDllType = "ptr*"
    EndIf

    Local $bAlgorithmDllType
    If VarGetType($algorithm) == "DLLStruct" Then
        $bAlgorithmDllType = "struct*"
    Else
        $bAlgorithmDllType = "ptr*"
    EndIf

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveFacemarkAAMCreate", $bParametersDllType, $parameters, $bFacemarkDllType, $facemark, $bAlgorithmDllType, $algorithm, $bSharedPtrDllType, $sharedPtr), "cveFacemarkAAMCreate", @error)
EndFunc   ;==>_cveFacemarkAAMCreate

Func _cveFacemarkAAMRelease($facemark, $sharedPtr)
    ; CVAPI(void) cveFacemarkAAMRelease(cv::face::FacemarkAAM** facemark, cv::Ptr<cv::face::FacemarkAAM>** sharedPtr);

    Local $bFacemarkDllType
    If VarGetType($facemark) == "DLLStruct" Then
        $bFacemarkDllType = "struct*"
    Else
        $bFacemarkDllType = "ptr*"
    EndIf

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFacemarkAAMRelease", $bFacemarkDllType, $facemark, $bSharedPtrDllType, $sharedPtr), "cveFacemarkAAMRelease", @error)
EndFunc   ;==>_cveFacemarkAAMRelease

Func _cveFacemarkLBFParamsCreate()
    ; CVAPI(cv::face::FacemarkLBF::Params*) cveFacemarkLBFParamsCreate();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveFacemarkLBFParamsCreate"), "cveFacemarkLBFParamsCreate", @error)
EndFunc   ;==>_cveFacemarkLBFParamsCreate

Func _cveFacemarkLBFParamsRelease($params)
    ; CVAPI(void) cveFacemarkLBFParamsRelease(cv::face::FacemarkLBF::Params** params);

    Local $bParamsDllType
    If VarGetType($params) == "DLLStruct" Then
        $bParamsDllType = "struct*"
    Else
        $bParamsDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFacemarkLBFParamsRelease", $bParamsDllType, $params), "cveFacemarkLBFParamsRelease", @error)
EndFunc   ;==>_cveFacemarkLBFParamsRelease

Func _cveFacemarkLBFCreate($parameters, $facemark, $algorithm, $sharedPtr)
    ; CVAPI(cv::face::FacemarkLBF*) cveFacemarkLBFCreate(cv::face::FacemarkLBF::Params* parameters, cv::face::Facemark** facemark, cv::Algorithm** algorithm, cv::Ptr<cv::face::FacemarkLBF>** sharedPtr);

    Local $bParametersDllType
    If VarGetType($parameters) == "DLLStruct" Then
        $bParametersDllType = "struct*"
    Else
        $bParametersDllType = "ptr"
    EndIf

    Local $bFacemarkDllType
    If VarGetType($facemark) == "DLLStruct" Then
        $bFacemarkDllType = "struct*"
    Else
        $bFacemarkDllType = "ptr*"
    EndIf

    Local $bAlgorithmDllType
    If VarGetType($algorithm) == "DLLStruct" Then
        $bAlgorithmDllType = "struct*"
    Else
        $bAlgorithmDllType = "ptr*"
    EndIf

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveFacemarkLBFCreate", $bParametersDllType, $parameters, $bFacemarkDllType, $facemark, $bAlgorithmDllType, $algorithm, $bSharedPtrDllType, $sharedPtr), "cveFacemarkLBFCreate", @error)
EndFunc   ;==>_cveFacemarkLBFCreate

Func _cveFacemarkLBFRelease($facemark, $sharedPtr)
    ; CVAPI(void) cveFacemarkLBFRelease(cv::face::FacemarkLBF** facemark, cv::Ptr<cv::face::FacemarkLBF>** sharedPtr);

    Local $bFacemarkDllType
    If VarGetType($facemark) == "DLLStruct" Then
        $bFacemarkDllType = "struct*"
    Else
        $bFacemarkDllType = "ptr*"
    EndIf

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFacemarkLBFRelease", $bFacemarkDllType, $facemark, $bSharedPtrDllType, $sharedPtr), "cveFacemarkLBFRelease", @error)
EndFunc   ;==>_cveFacemarkLBFRelease

Func _cveFacemarkLoadModel($facemark, $model)
    ; CVAPI(void) cveFacemarkLoadModel(cv::face::Facemark* facemark, cv::String* model);

    Local $bFacemarkDllType
    If VarGetType($facemark) == "DLLStruct" Then
        $bFacemarkDllType = "struct*"
    Else
        $bFacemarkDllType = "ptr"
    EndIf

    Local $bModelIsString = VarGetType($model) == "String"
    If $bModelIsString Then
        $model = _cveStringCreateFromStr($model)
    EndIf

    Local $bModelDllType
    If VarGetType($model) == "DLLStruct" Then
        $bModelDllType = "struct*"
    Else
        $bModelDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFacemarkLoadModel", $bFacemarkDllType, $facemark, $bModelDllType, $model), "cveFacemarkLoadModel", @error)

    If $bModelIsString Then
        _cveStringRelease($model)
    EndIf
EndFunc   ;==>_cveFacemarkLoadModel

Func _cveFacemarkFit($facemark, $image, $faces, $landmarks)
    ; CVAPI(bool) cveFacemarkFit(cv::face::Facemark* facemark, cv::_InputArray* image, cv::_InputArray* faces, cv::_InputOutputArray* landmarks);

    Local $bFacemarkDllType
    If VarGetType($facemark) == "DLLStruct" Then
        $bFacemarkDllType = "struct*"
    Else
        $bFacemarkDllType = "ptr"
    EndIf

    Local $bImageDllType
    If VarGetType($image) == "DLLStruct" Then
        $bImageDllType = "struct*"
    Else
        $bImageDllType = "ptr"
    EndIf

    Local $bFacesDllType
    If VarGetType($faces) == "DLLStruct" Then
        $bFacesDllType = "struct*"
    Else
        $bFacesDllType = "ptr"
    EndIf

    Local $bLandmarksDllType
    If VarGetType($landmarks) == "DLLStruct" Then
        $bLandmarksDllType = "struct*"
    Else
        $bLandmarksDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveFacemarkFit", $bFacemarkDllType, $facemark, $bImageDllType, $image, $bFacesDllType, $faces, $bLandmarksDllType, $landmarks), "cveFacemarkFit", @error)
EndFunc   ;==>_cveFacemarkFit

Func _cveFacemarkFitMat($facemark, $matImage, $matFaces, $matLandmarks)
    ; cveFacemarkFit using cv::Mat instead of _*Array

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

    Local $iArrFaces, $vectorOfMatFaces, $iArrFacesSize
    Local $bFacesIsArray = VarGetType($matFaces) == "Array"

    If $bFacesIsArray Then
        $vectorOfMatFaces = _VectorOfMatCreate()

        $iArrFacesSize = UBound($matFaces)
        For $i = 0 To $iArrFacesSize - 1
            _VectorOfMatPush($vectorOfMatFaces, $matFaces[$i])
        Next

        $iArrFaces = _cveInputArrayFromVectorOfMat($vectorOfMatFaces)
    Else
        $iArrFaces = _cveInputArrayFromMat($matFaces)
    EndIf

    Local $ioArrLandmarks, $vectorOfMatLandmarks, $iArrLandmarksSize
    Local $bLandmarksIsArray = VarGetType($matLandmarks) == "Array"

    If $bLandmarksIsArray Then
        $vectorOfMatLandmarks = _VectorOfMatCreate()

        $iArrLandmarksSize = UBound($matLandmarks)
        For $i = 0 To $iArrLandmarksSize - 1
            _VectorOfMatPush($vectorOfMatLandmarks, $matLandmarks[$i])
        Next

        $ioArrLandmarks = _cveInputOutputArrayFromVectorOfMat($vectorOfMatLandmarks)
    Else
        $ioArrLandmarks = _cveInputOutputArrayFromMat($matLandmarks)
    EndIf

    Local $retval = _cveFacemarkFit($facemark, $iArrImage, $iArrFaces, $ioArrLandmarks)

    If $bLandmarksIsArray Then
        _VectorOfMatRelease($vectorOfMatLandmarks)
    EndIf

    _cveInputOutputArrayRelease($ioArrLandmarks)

    If $bFacesIsArray Then
        _VectorOfMatRelease($vectorOfMatFaces)
    EndIf

    _cveInputArrayRelease($iArrFaces)

    If $bImageIsArray Then
        _VectorOfMatRelease($vectorOfMatImage)
    EndIf

    _cveInputArrayRelease($iArrImage)

    Return $retval
EndFunc   ;==>_cveFacemarkFitMat

Func _cveDrawFacemarks($image, $points, $color = _cvScalar(255,0,0))
    ; CVAPI(void) cveDrawFacemarks(cv::_InputOutputArray* image, cv::_InputArray* points, CvScalar* color);

    Local $bImageDllType
    If VarGetType($image) == "DLLStruct" Then
        $bImageDllType = "struct*"
    Else
        $bImageDllType = "ptr"
    EndIf

    Local $bPointsDllType
    If VarGetType($points) == "DLLStruct" Then
        $bPointsDllType = "struct*"
    Else
        $bPointsDllType = "ptr"
    EndIf

    Local $bColorDllType
    If VarGetType($color) == "DLLStruct" Then
        $bColorDllType = "struct*"
    Else
        $bColorDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDrawFacemarks", $bImageDllType, $image, $bPointsDllType, $points, $bColorDllType, $color), "cveDrawFacemarks", @error)
EndFunc   ;==>_cveDrawFacemarks

Func _cveDrawFacemarksMat($matImage, $matPoints, $color = _cvScalar(255,0,0))
    ; cveDrawFacemarks using cv::Mat instead of _*Array

    Local $ioArrImage, $vectorOfMatImage, $iArrImageSize
    Local $bImageIsArray = VarGetType($matImage) == "Array"

    If $bImageIsArray Then
        $vectorOfMatImage = _VectorOfMatCreate()

        $iArrImageSize = UBound($matImage)
        For $i = 0 To $iArrImageSize - 1
            _VectorOfMatPush($vectorOfMatImage, $matImage[$i])
        Next

        $ioArrImage = _cveInputOutputArrayFromVectorOfMat($vectorOfMatImage)
    Else
        $ioArrImage = _cveInputOutputArrayFromMat($matImage)
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

    _cveDrawFacemarks($ioArrImage, $iArrPoints, $color)

    If $bPointsIsArray Then
        _VectorOfMatRelease($vectorOfMatPoints)
    EndIf

    _cveInputArrayRelease($iArrPoints)

    If $bImageIsArray Then
        _VectorOfMatRelease($vectorOfMatImage)
    EndIf

    _cveInputOutputArrayRelease($ioArrImage)
EndFunc   ;==>_cveDrawFacemarksMat

Func _cveMaceCreate($imgSize, $sharedPtr)
    ; CVAPI(cv::face::MACE*) cveMaceCreate(int imgSize, cv::Ptr<cv::face::MACE>** sharedPtr);

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveMaceCreate", "int", $imgSize, $bSharedPtrDllType, $sharedPtr), "cveMaceCreate", @error)
EndFunc   ;==>_cveMaceCreate

Func _cveMaceSalt($mace, $passphrase)
    ; CVAPI(void) cveMaceSalt(cv::face::MACE* mace, cv::String* passphrase);

    Local $bMaceDllType
    If VarGetType($mace) == "DLLStruct" Then
        $bMaceDllType = "struct*"
    Else
        $bMaceDllType = "ptr"
    EndIf

    Local $bPassphraseIsString = VarGetType($passphrase) == "String"
    If $bPassphraseIsString Then
        $passphrase = _cveStringCreateFromStr($passphrase)
    EndIf

    Local $bPassphraseDllType
    If VarGetType($passphrase) == "DLLStruct" Then
        $bPassphraseDllType = "struct*"
    Else
        $bPassphraseDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMaceSalt", $bMaceDllType, $mace, $bPassphraseDllType, $passphrase), "cveMaceSalt", @error)

    If $bPassphraseIsString Then
        _cveStringRelease($passphrase)
    EndIf
EndFunc   ;==>_cveMaceSalt

Func _cveMaceTrain($mace, $images)
    ; CVAPI(void) cveMaceTrain(cv::face::MACE* mace, cv::_InputArray* images);

    Local $bMaceDllType
    If VarGetType($mace) == "DLLStruct" Then
        $bMaceDllType = "struct*"
    Else
        $bMaceDllType = "ptr"
    EndIf

    Local $bImagesDllType
    If VarGetType($images) == "DLLStruct" Then
        $bImagesDllType = "struct*"
    Else
        $bImagesDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMaceTrain", $bMaceDllType, $mace, $bImagesDllType, $images), "cveMaceTrain", @error)
EndFunc   ;==>_cveMaceTrain

Func _cveMaceTrainMat($mace, $matImages)
    ; cveMaceTrain using cv::Mat instead of _*Array

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

    _cveMaceTrain($mace, $iArrImages)

    If $bImagesIsArray Then
        _VectorOfMatRelease($vectorOfMatImages)
    EndIf

    _cveInputArrayRelease($iArrImages)
EndFunc   ;==>_cveMaceTrainMat

Func _cveMaceSame($mace, $query)
    ; CVAPI(bool) cveMaceSame(cv::face::MACE* mace, cv::_InputArray* query);

    Local $bMaceDllType
    If VarGetType($mace) == "DLLStruct" Then
        $bMaceDllType = "struct*"
    Else
        $bMaceDllType = "ptr"
    EndIf

    Local $bQueryDllType
    If VarGetType($query) == "DLLStruct" Then
        $bQueryDllType = "struct*"
    Else
        $bQueryDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveMaceSame", $bMaceDllType, $mace, $bQueryDllType, $query), "cveMaceSame", @error)
EndFunc   ;==>_cveMaceSame

Func _cveMaceSameMat($mace, $matQuery)
    ; cveMaceSame using cv::Mat instead of _*Array

    Local $iArrQuery, $vectorOfMatQuery, $iArrQuerySize
    Local $bQueryIsArray = VarGetType($matQuery) == "Array"

    If $bQueryIsArray Then
        $vectorOfMatQuery = _VectorOfMatCreate()

        $iArrQuerySize = UBound($matQuery)
        For $i = 0 To $iArrQuerySize - 1
            _VectorOfMatPush($vectorOfMatQuery, $matQuery[$i])
        Next

        $iArrQuery = _cveInputArrayFromVectorOfMat($vectorOfMatQuery)
    Else
        $iArrQuery = _cveInputArrayFromMat($matQuery)
    EndIf

    Local $retval = _cveMaceSame($mace, $iArrQuery)

    If $bQueryIsArray Then
        _VectorOfMatRelease($vectorOfMatQuery)
    EndIf

    _cveInputArrayRelease($iArrQuery)

    Return $retval
EndFunc   ;==>_cveMaceSameMat

Func _cveMaceRelease($sharedPtr)
    ; CVAPI(void) cveMaceRelease(cv::Ptr<cv::face::MACE>** sharedPtr);

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMaceRelease", $bSharedPtrDllType, $sharedPtr), "cveMaceRelease", @error)
EndFunc   ;==>_cveMaceRelease