#include-once
#include <..\..\CVEUtils.au3>

Func _cveEigenFaceRecognizerCreate($numComponents, $threshold, ByRef $faceRecognizerPtr, ByRef $basicFaceRecognizerPtr, ByRef $sharedPtr)
    ; CVAPI(cv::face::EigenFaceRecognizer*) cveEigenFaceRecognizerCreate(int numComponents, double threshold, cv::face::FaceRecognizer** faceRecognizerPtr, cv::face::BasicFaceRecognizer** basicFaceRecognizerPtr, cv::Ptr<cv::face::EigenFaceRecognizer>** sharedPtr);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveEigenFaceRecognizerCreate", "int", $numComponents, "double", $threshold, "ptr*", $faceRecognizerPtr, "ptr*", $basicFaceRecognizerPtr, "ptr*", $sharedPtr), "cveEigenFaceRecognizerCreate", @error)
EndFunc   ;==>_cveEigenFaceRecognizerCreate

Func _cveEigenFaceRecognizerRelease(ByRef $sharedPtr)
    ; CVAPI(void) cveEigenFaceRecognizerRelease(cv::Ptr<cv::face::EigenFaceRecognizer>** sharedPtr);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveEigenFaceRecognizerRelease", "ptr*", $sharedPtr), "cveEigenFaceRecognizerRelease", @error)
EndFunc   ;==>_cveEigenFaceRecognizerRelease

Func _cveFisherFaceRecognizerCreate($numComponents, $threshold, ByRef $faceRecognizerPtr, ByRef $basicFaceRecognizerPtr, ByRef $sharedPtr)
    ; CVAPI(cv::face::FisherFaceRecognizer*) cveFisherFaceRecognizerCreate(int numComponents, double threshold, cv::face::FaceRecognizer** faceRecognizerPtr, cv::face::FaceRecognizer** basicFaceRecognizerPtr, cv::Ptr<cv::face::FisherFaceRecognizer>** sharedPtr);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveFisherFaceRecognizerCreate", "int", $numComponents, "double", $threshold, "ptr*", $faceRecognizerPtr, "ptr*", $basicFaceRecognizerPtr, "ptr*", $sharedPtr), "cveFisherFaceRecognizerCreate", @error)
EndFunc   ;==>_cveFisherFaceRecognizerCreate

Func _cveFisherFaceRecognizerRelease(ByRef $sharedPtr)
    ; CVAPI(void) cveFisherFaceRecognizerRelease(cv::Ptr<cv::face::FisherFaceRecognizer>** sharedPtr);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFisherFaceRecognizerRelease", "ptr*", $sharedPtr), "cveFisherFaceRecognizerRelease", @error)
EndFunc   ;==>_cveFisherFaceRecognizerRelease

Func _cveLBPHFaceRecognizerCreate($radius, $neighbors, $gridX, $gridY, $threshold, ByRef $faceRecognizerPtr, ByRef $sharedPtr)
    ; CVAPI(cv::face::LBPHFaceRecognizer*) cveLBPHFaceRecognizerCreate(int radius, int neighbors, int gridX, int gridY, double threshold, cv::face::FaceRecognizer** faceRecognizerPtr, cv::Ptr<cv::face::LBPHFaceRecognizer>** sharedPtr);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveLBPHFaceRecognizerCreate", "int", $radius, "int", $neighbors, "int", $gridX, "int", $gridY, "double", $threshold, "ptr*", $faceRecognizerPtr, "ptr*", $sharedPtr), "cveLBPHFaceRecognizerCreate", @error)
EndFunc   ;==>_cveLBPHFaceRecognizerCreate

Func _cveLBPHFaceRecognizerRelease(ByRef $sharedPtr)
    ; CVAPI(void) cveLBPHFaceRecognizerRelease(cv::Ptr<cv::face::LBPHFaceRecognizer>** sharedPtr);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveLBPHFaceRecognizerRelease", "ptr*", $sharedPtr), "cveLBPHFaceRecognizerRelease", @error)
EndFunc   ;==>_cveLBPHFaceRecognizerRelease

Func _cveLBPHFaceRecognizerGetHistograms(ByRef $recognizer, ByRef $histograms)
    ; CVAPI(void) cveLBPHFaceRecognizerGetHistograms(cv::face::LBPHFaceRecognizer* recognizer, std::vector<cv::Mat>* histograms);

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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveLBPHFaceRecognizerGetHistograms", "ptr", $recognizer, "ptr", $vecHistograms), "cveLBPHFaceRecognizerGetHistograms", @error)

    If $bHistogramsIsArray Then
        _VectorOfMatRelease($vecHistograms)
    EndIf
EndFunc   ;==>_cveLBPHFaceRecognizerGetHistograms

Func _cveFaceRecognizerTrain(ByRef $recognizer, ByRef $images, ByRef $labels)
    ; CVAPI(void) cveFaceRecognizerTrain(cv::face::FaceRecognizer* recognizer, cv::_InputArray* images, cv::_InputArray* labels);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFaceRecognizerTrain", "ptr", $recognizer, "ptr", $images, "ptr", $labels), "cveFaceRecognizerTrain", @error)
EndFunc   ;==>_cveFaceRecognizerTrain

Func _cveFaceRecognizerTrainMat(ByRef $recognizer, ByRef $matImages, ByRef $matLabels)
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

Func _cveFaceRecognizerUpdate(ByRef $recognizer, ByRef $images, ByRef $labels)
    ; CVAPI(void) cveFaceRecognizerUpdate(cv::face::FaceRecognizer* recognizer, cv::_InputArray* images, cv::_InputArray* labels);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFaceRecognizerUpdate", "ptr", $recognizer, "ptr", $images, "ptr", $labels), "cveFaceRecognizerUpdate", @error)
EndFunc   ;==>_cveFaceRecognizerUpdate

Func _cveFaceRecognizerUpdateMat(ByRef $recognizer, ByRef $matImages, ByRef $matLabels)
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

Func _cveFaceRecognizerPredict(ByRef $recognizer, ByRef $image, ByRef $label, ByRef $distance)
    ; CVAPI(void) cveFaceRecognizerPredict(cv::face::FaceRecognizer* recognizer, cv::_InputArray* image, int* label, double* distance);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFaceRecognizerPredict", "ptr", $recognizer, "ptr", $image, "struct*", $label, "struct*", $distance), "cveFaceRecognizerPredict", @error)
EndFunc   ;==>_cveFaceRecognizerPredict

Func _cveFaceRecognizerPredictMat(ByRef $recognizer, ByRef $matImage, ByRef $label, ByRef $distance)
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

Func _cveFaceRecognizerWrite(ByRef $recognizer, $fileName)
    ; CVAPI(void) cveFaceRecognizerWrite(cv::face::FaceRecognizer* recognizer, cv::String* fileName);

    Local $bFileNameIsString = VarGetType($fileName) == "String"
    If $bFileNameIsString Then
        $fileName = _cveStringCreateFromStr($fileName)
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFaceRecognizerWrite", "ptr", $recognizer, "ptr", $fileName), "cveFaceRecognizerWrite", @error)

    If $bFileNameIsString Then
        _cveStringRelease($fileName)
    EndIf
EndFunc   ;==>_cveFaceRecognizerWrite

Func _cveFaceRecognizerRead(ByRef $recognizer, $fileName)
    ; CVAPI(void) cveFaceRecognizerRead(cv::face::FaceRecognizer* recognizer, cv::String* fileName);

    Local $bFileNameIsString = VarGetType($fileName) == "String"
    If $bFileNameIsString Then
        $fileName = _cveStringCreateFromStr($fileName)
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFaceRecognizerRead", "ptr", $recognizer, "ptr", $fileName), "cveFaceRecognizerRead", @error)

    If $bFileNameIsString Then
        _cveStringRelease($fileName)
    EndIf
EndFunc   ;==>_cveFaceRecognizerRead

Func _cveBIFCreate($numBands, $numRotations, ByRef $sharedPtr)
    ; CVAPI(cv::face::BIF*) cveBIFCreate(int numBands, int numRotations, cv::Ptr<cv::face::BIF>** sharedPtr);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveBIFCreate", "int", $numBands, "int", $numRotations, "ptr*", $sharedPtr), "cveBIFCreate", @error)
EndFunc   ;==>_cveBIFCreate

Func _cveBIFCompute(ByRef $bif, ByRef $image, ByRef $features)
    ; CVAPI(void) cveBIFCompute(cv::face::BIF* bif, cv::_InputArray* image, cv::_OutputArray* features);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBIFCompute", "ptr", $bif, "ptr", $image, "ptr", $features), "cveBIFCompute", @error)
EndFunc   ;==>_cveBIFCompute

Func _cveBIFComputeMat(ByRef $bif, ByRef $matImage, ByRef $matFeatures)
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

Func _cveBIFRelease(ByRef $sharedPtr)
    ; CVAPI(void) cveBIFRelease(cv::Ptr<cv::face::BIF>** sharedPtr);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBIFRelease", "ptr*", $sharedPtr), "cveBIFRelease", @error)
EndFunc   ;==>_cveBIFRelease

Func _cveFacemarkAAMParamsCreate()
    ; CVAPI(cv::face::FacemarkAAM::Params*) cveFacemarkAAMParamsCreate();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveFacemarkAAMParamsCreate"), "cveFacemarkAAMParamsCreate", @error)
EndFunc   ;==>_cveFacemarkAAMParamsCreate

Func _cveFacemarkAAMParamsRelease(ByRef $params)
    ; CVAPI(void) cveFacemarkAAMParamsRelease(cv::face::FacemarkAAM::Params** params);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFacemarkAAMParamsRelease", "ptr*", $params), "cveFacemarkAAMParamsRelease", @error)
EndFunc   ;==>_cveFacemarkAAMParamsRelease

Func _cveFacemarkAAMCreate(ByRef $parameters, ByRef $facemark, ByRef $algorithm, ByRef $sharedPtr)
    ; CVAPI(cv::face::FacemarkAAM*) cveFacemarkAAMCreate(cv::face::FacemarkAAM::Params* parameters, cv::face::Facemark** facemark, cv::Algorithm** algorithm, cv::Ptr<cv::face::FacemarkAAM>** sharedPtr);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveFacemarkAAMCreate", "ptr", $parameters, "ptr*", $facemark, "ptr*", $algorithm, "ptr*", $sharedPtr), "cveFacemarkAAMCreate", @error)
EndFunc   ;==>_cveFacemarkAAMCreate

Func _cveFacemarkAAMRelease(ByRef $facemark, ByRef $sharedPtr)
    ; CVAPI(void) cveFacemarkAAMRelease(cv::face::FacemarkAAM** facemark, cv::Ptr<cv::face::FacemarkAAM>** sharedPtr);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFacemarkAAMRelease", "ptr*", $facemark, "ptr*", $sharedPtr), "cveFacemarkAAMRelease", @error)
EndFunc   ;==>_cveFacemarkAAMRelease

Func _cveFacemarkLBFParamsCreate()
    ; CVAPI(cv::face::FacemarkLBF::Params*) cveFacemarkLBFParamsCreate();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveFacemarkLBFParamsCreate"), "cveFacemarkLBFParamsCreate", @error)
EndFunc   ;==>_cveFacemarkLBFParamsCreate

Func _cveFacemarkLBFParamsRelease(ByRef $params)
    ; CVAPI(void) cveFacemarkLBFParamsRelease(cv::face::FacemarkLBF::Params** params);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFacemarkLBFParamsRelease", "ptr*", $params), "cveFacemarkLBFParamsRelease", @error)
EndFunc   ;==>_cveFacemarkLBFParamsRelease

Func _cveFacemarkLBFCreate(ByRef $parameters, ByRef $facemark, ByRef $algorithm, ByRef $sharedPtr)
    ; CVAPI(cv::face::FacemarkLBF*) cveFacemarkLBFCreate(cv::face::FacemarkLBF::Params* parameters, cv::face::Facemark** facemark, cv::Algorithm** algorithm, cv::Ptr<cv::face::FacemarkLBF>** sharedPtr);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveFacemarkLBFCreate", "ptr", $parameters, "ptr*", $facemark, "ptr*", $algorithm, "ptr*", $sharedPtr), "cveFacemarkLBFCreate", @error)
EndFunc   ;==>_cveFacemarkLBFCreate

Func _cveFacemarkLBFRelease(ByRef $facemark, ByRef $sharedPtr)
    ; CVAPI(void) cveFacemarkLBFRelease(cv::face::FacemarkLBF** facemark, cv::Ptr<cv::face::FacemarkLBF>** sharedPtr);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFacemarkLBFRelease", "ptr*", $facemark, "ptr*", $sharedPtr), "cveFacemarkLBFRelease", @error)
EndFunc   ;==>_cveFacemarkLBFRelease

Func _cveFacemarkLoadModel(ByRef $facemark, $model)
    ; CVAPI(void) cveFacemarkLoadModel(cv::face::Facemark* facemark, cv::String* model);

    Local $bModelIsString = VarGetType($model) == "String"
    If $bModelIsString Then
        $model = _cveStringCreateFromStr($model)
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFacemarkLoadModel", "ptr", $facemark, "ptr", $model), "cveFacemarkLoadModel", @error)

    If $bModelIsString Then
        _cveStringRelease($model)
    EndIf
EndFunc   ;==>_cveFacemarkLoadModel

Func _cveFacemarkFit(ByRef $facemark, ByRef $image, ByRef $faces, ByRef $landmarks)
    ; CVAPI(bool) cveFacemarkFit(cv::face::Facemark* facemark, cv::_InputArray* image, cv::_InputArray* faces, cv::_InputOutputArray* landmarks);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveFacemarkFit", "ptr", $facemark, "ptr", $image, "ptr", $faces, "ptr", $landmarks), "cveFacemarkFit", @error)
EndFunc   ;==>_cveFacemarkFit

Func _cveFacemarkFitMat(ByRef $facemark, ByRef $matImage, ByRef $matFaces, ByRef $matLandmarks)
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

Func _cveDrawFacemarks(ByRef $image, ByRef $points, ByRef $color)
    ; CVAPI(void) cveDrawFacemarks(cv::_InputOutputArray* image, cv::_InputArray* points, CvScalar* color);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDrawFacemarks", "ptr", $image, "ptr", $points, "struct*", $color), "cveDrawFacemarks", @error)
EndFunc   ;==>_cveDrawFacemarks

Func _cveDrawFacemarksMat(ByRef $matImage, ByRef $matPoints, ByRef $color)
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

Func _cveMaceCreate($imgSize, ByRef $sharedPtr)
    ; CVAPI(cv::face::MACE*) cveMaceCreate(int imgSize, cv::Ptr<cv::face::MACE>** sharedPtr);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveMaceCreate", "int", $imgSize, "ptr*", $sharedPtr), "cveMaceCreate", @error)
EndFunc   ;==>_cveMaceCreate

Func _cveMaceSalt(ByRef $mace, $passphrase)
    ; CVAPI(void) cveMaceSalt(cv::face::MACE* mace, cv::String* passphrase);

    Local $bPassphraseIsString = VarGetType($passphrase) == "String"
    If $bPassphraseIsString Then
        $passphrase = _cveStringCreateFromStr($passphrase)
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMaceSalt", "ptr", $mace, "ptr", $passphrase), "cveMaceSalt", @error)

    If $bPassphraseIsString Then
        _cveStringRelease($passphrase)
    EndIf
EndFunc   ;==>_cveMaceSalt

Func _cveMaceTrain(ByRef $mace, ByRef $images)
    ; CVAPI(void) cveMaceTrain(cv::face::MACE* mace, cv::_InputArray* images);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMaceTrain", "ptr", $mace, "ptr", $images), "cveMaceTrain", @error)
EndFunc   ;==>_cveMaceTrain

Func _cveMaceTrainMat(ByRef $mace, ByRef $matImages)
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

Func _cveMaceSame(ByRef $mace, ByRef $query)
    ; CVAPI(bool) cveMaceSame(cv::face::MACE* mace, cv::_InputArray* query);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveMaceSame", "ptr", $mace, "ptr", $query), "cveMaceSame", @error)
EndFunc   ;==>_cveMaceSame

Func _cveMaceSameMat(ByRef $mace, ByRef $matQuery)
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

Func _cveMaceRelease(ByRef $sharedPtr)
    ; CVAPI(void) cveMaceRelease(cv::Ptr<cv::face::MACE>** sharedPtr);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMaceRelease", "ptr*", $sharedPtr), "cveMaceRelease", @error)
EndFunc   ;==>_cveMaceRelease