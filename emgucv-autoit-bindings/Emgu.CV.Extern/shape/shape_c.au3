#include-once
#include "..\..\CVEUtils.au3"

Func _cveNormHistogramCostExtractorCreate($flag, $nDummies, $defaultCost, $sharedPtr)
    ; CVAPI(cv::HistogramCostExtractor*) cveNormHistogramCostExtractorCreate(int flag, int nDummies, float defaultCost, cv::Ptr<cv::HistogramCostExtractor>** sharedPtr);

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveNormHistogramCostExtractorCreate", "int", $flag, "int", $nDummies, "float", $defaultCost, $bSharedPtrDllType, $sharedPtr), "cveNormHistogramCostExtractorCreate", @error)
EndFunc   ;==>_cveNormHistogramCostExtractorCreate

Func _cveEMDHistogramCostExtractorCreate($flag, $nDummies, $defaultCost, $sharedPtr)
    ; CVAPI(cv::HistogramCostExtractor*) cveEMDHistogramCostExtractorCreate(int flag, int nDummies, float defaultCost, cv::Ptr<cv::HistogramCostExtractor>** sharedPtr);

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveEMDHistogramCostExtractorCreate", "int", $flag, "int", $nDummies, "float", $defaultCost, $bSharedPtrDllType, $sharedPtr), "cveEMDHistogramCostExtractorCreate", @error)
EndFunc   ;==>_cveEMDHistogramCostExtractorCreate

Func _cveChiHistogramCostExtractorCreate($nDummies, $defaultCost, $sharedPtr)
    ; CVAPI(cv::HistogramCostExtractor*) cveChiHistogramCostExtractorCreate(int nDummies, float defaultCost, cv::Ptr<cv::HistogramCostExtractor>** sharedPtr);

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveChiHistogramCostExtractorCreate", "int", $nDummies, "float", $defaultCost, $bSharedPtrDllType, $sharedPtr), "cveChiHistogramCostExtractorCreate", @error)
EndFunc   ;==>_cveChiHistogramCostExtractorCreate

Func _cveEMDL1HistogramCostExtractorCreate($nDummies, $defaultCost, $sharedPtr)
    ; CVAPI(cv::HistogramCostExtractor*) cveEMDL1HistogramCostExtractorCreate(int nDummies, float defaultCost, cv::Ptr<cv::HistogramCostExtractor>** sharedPtr);

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveEMDL1HistogramCostExtractorCreate", "int", $nDummies, "float", $defaultCost, $bSharedPtrDllType, $sharedPtr), "cveEMDL1HistogramCostExtractorCreate", @error)
EndFunc   ;==>_cveEMDL1HistogramCostExtractorCreate

Func _cveHistogramCostExtractorRelease($sharedPtr)
    ; CVAPI(void) cveHistogramCostExtractorRelease(cv::Ptr<cv::HistogramCostExtractor>** sharedPtr);

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveHistogramCostExtractorRelease", $bSharedPtrDllType, $sharedPtr), "cveHistogramCostExtractorRelease", @error)
EndFunc   ;==>_cveHistogramCostExtractorRelease

Func _cveThinPlateSplineShapeTransformerCreate($regularizationParameter, $shapeTransformer, $sharedPtr)
    ; CVAPI(cv::ThinPlateSplineShapeTransformer*) cveThinPlateSplineShapeTransformerCreate(double regularizationParameter, cv::ShapeTransformer** shapeTransformer, cv::Ptr<cv::ThinPlateSplineShapeTransformer>** sharedPtr);

    Local $bShapeTransformerDllType
    If VarGetType($shapeTransformer) == "DLLStruct" Then
        $bShapeTransformerDllType = "struct*"
    Else
        $bShapeTransformerDllType = "ptr*"
    EndIf

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveThinPlateSplineShapeTransformerCreate", "double", $regularizationParameter, $bShapeTransformerDllType, $shapeTransformer, $bSharedPtrDllType, $sharedPtr), "cveThinPlateSplineShapeTransformerCreate", @error)
EndFunc   ;==>_cveThinPlateSplineShapeTransformerCreate

Func _cveThinPlateSplineShapeTransformerRelease($sharedPtr)
    ; CVAPI(void) cveThinPlateSplineShapeTransformerRelease(cv::Ptr<cv::ThinPlateSplineShapeTransformer>** sharedPtr);

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveThinPlateSplineShapeTransformerRelease", $bSharedPtrDllType, $sharedPtr), "cveThinPlateSplineShapeTransformerRelease", @error)
EndFunc   ;==>_cveThinPlateSplineShapeTransformerRelease

Func _cveAffineTransformerCreate($fullAffine, $transformer, $sharedPtr)
    ; CVAPI(cv::AffineTransformer*) cveAffineTransformerCreate(bool fullAffine, cv::ShapeTransformer** transformer, cv::Ptr<cv::AffineTransformer>** sharedPtr);

    Local $bTransformerDllType
    If VarGetType($transformer) == "DLLStruct" Then
        $bTransformerDllType = "struct*"
    Else
        $bTransformerDllType = "ptr*"
    EndIf

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveAffineTransformerCreate", "boolean", $fullAffine, $bTransformerDllType, $transformer, $bSharedPtrDllType, $sharedPtr), "cveAffineTransformerCreate", @error)
EndFunc   ;==>_cveAffineTransformerCreate

Func _cveAffineTransformerRelease($sharedPtr)
    ; CVAPI(void) cveAffineTransformerRelease(cv::Ptr<cv::AffineTransformer>** sharedPtr);

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveAffineTransformerRelease", $bSharedPtrDllType, $sharedPtr), "cveAffineTransformerRelease", @error)
EndFunc   ;==>_cveAffineTransformerRelease

Func _cveShapeTransformerEstimateTransformation($transformer, $transformingShape, $targetShape, $matches)
    ; CVAPI(void) cveShapeTransformerEstimateTransformation(cv::ShapeTransformer* transformer, cv::_InputArray* transformingShape, cv::_InputArray* targetShape, std::vector<cv::DMatch>* matches);

    Local $vecMatches, $iArrMatchesSize
    Local $bMatchesIsArray = VarGetType($matches) == "Array"

    If $bMatchesIsArray Then
        $vecMatches = _VectorOfDMatchCreate()

        $iArrMatchesSize = UBound($matches)
        For $i = 0 To $iArrMatchesSize - 1
            _VectorOfDMatchPush($vecMatches, $matches[$i])
        Next
    Else
        $vecMatches = $matches
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveShapeTransformerEstimateTransformation", "ptr", $transformer, "ptr", $transformingShape, "ptr", $targetShape, "ptr", $vecMatches), "cveShapeTransformerEstimateTransformation", @error)

    If $bMatchesIsArray Then
        _VectorOfDMatchRelease($vecMatches)
    EndIf
EndFunc   ;==>_cveShapeTransformerEstimateTransformation

Func _cveShapeTransformerEstimateTransformationMat($transformer, $matTransformingShape, $matTargetShape, $matches)
    ; cveShapeTransformerEstimateTransformation using cv::Mat instead of _*Array

    Local $iArrTransformingShape, $vectorOfMatTransformingShape, $iArrTransformingShapeSize
    Local $bTransformingShapeIsArray = VarGetType($matTransformingShape) == "Array"

    If $bTransformingShapeIsArray Then
        $vectorOfMatTransformingShape = _VectorOfMatCreate()

        $iArrTransformingShapeSize = UBound($matTransformingShape)
        For $i = 0 To $iArrTransformingShapeSize - 1
            _VectorOfMatPush($vectorOfMatTransformingShape, $matTransformingShape[$i])
        Next

        $iArrTransformingShape = _cveInputArrayFromVectorOfMat($vectorOfMatTransformingShape)
    Else
        $iArrTransformingShape = _cveInputArrayFromMat($matTransformingShape)
    EndIf

    Local $iArrTargetShape, $vectorOfMatTargetShape, $iArrTargetShapeSize
    Local $bTargetShapeIsArray = VarGetType($matTargetShape) == "Array"

    If $bTargetShapeIsArray Then
        $vectorOfMatTargetShape = _VectorOfMatCreate()

        $iArrTargetShapeSize = UBound($matTargetShape)
        For $i = 0 To $iArrTargetShapeSize - 1
            _VectorOfMatPush($vectorOfMatTargetShape, $matTargetShape[$i])
        Next

        $iArrTargetShape = _cveInputArrayFromVectorOfMat($vectorOfMatTargetShape)
    Else
        $iArrTargetShape = _cveInputArrayFromMat($matTargetShape)
    EndIf

    _cveShapeTransformerEstimateTransformation($transformer, $iArrTransformingShape, $iArrTargetShape, $matches)

    If $bTargetShapeIsArray Then
        _VectorOfMatRelease($vectorOfMatTargetShape)
    EndIf

    _cveInputArrayRelease($iArrTargetShape)

    If $bTransformingShapeIsArray Then
        _VectorOfMatRelease($vectorOfMatTransformingShape)
    EndIf

    _cveInputArrayRelease($iArrTransformingShape)
EndFunc   ;==>_cveShapeTransformerEstimateTransformationMat

Func _cveShapeTransformerApplyTransformation($transformer, $input, $output)
    ; CVAPI(float) cveShapeTransformerApplyTransformation(cv::ShapeTransformer* transformer, cv::_InputArray* input, cv::_OutputArray* output);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cveShapeTransformerApplyTransformation", "ptr", $transformer, "ptr", $input, "ptr", $output), "cveShapeTransformerApplyTransformation", @error)
EndFunc   ;==>_cveShapeTransformerApplyTransformation

Func _cveShapeTransformerApplyTransformationMat($transformer, $matInput, $matOutput)
    ; cveShapeTransformerApplyTransformation using cv::Mat instead of _*Array

    Local $iArrInput, $vectorOfMatInput, $iArrInputSize
    Local $bInputIsArray = VarGetType($matInput) == "Array"

    If $bInputIsArray Then
        $vectorOfMatInput = _VectorOfMatCreate()

        $iArrInputSize = UBound($matInput)
        For $i = 0 To $iArrInputSize - 1
            _VectorOfMatPush($vectorOfMatInput, $matInput[$i])
        Next

        $iArrInput = _cveInputArrayFromVectorOfMat($vectorOfMatInput)
    Else
        $iArrInput = _cveInputArrayFromMat($matInput)
    EndIf

    Local $oArrOutput, $vectorOfMatOutput, $iArrOutputSize
    Local $bOutputIsArray = VarGetType($matOutput) == "Array"

    If $bOutputIsArray Then
        $vectorOfMatOutput = _VectorOfMatCreate()

        $iArrOutputSize = UBound($matOutput)
        For $i = 0 To $iArrOutputSize - 1
            _VectorOfMatPush($vectorOfMatOutput, $matOutput[$i])
        Next

        $oArrOutput = _cveOutputArrayFromVectorOfMat($vectorOfMatOutput)
    Else
        $oArrOutput = _cveOutputArrayFromMat($matOutput)
    EndIf

    Local $retval = _cveShapeTransformerApplyTransformation($transformer, $iArrInput, $oArrOutput)

    If $bOutputIsArray Then
        _VectorOfMatRelease($vectorOfMatOutput)
    EndIf

    _cveOutputArrayRelease($oArrOutput)

    If $bInputIsArray Then
        _VectorOfMatRelease($vectorOfMatInput)
    EndIf

    _cveInputArrayRelease($iArrInput)

    Return $retval
EndFunc   ;==>_cveShapeTransformerApplyTransformationMat

Func _cveShapeTransformerWarpImage($transformer, $transformingImage, $output, $flags, $borderMode, $borderValue)
    ; CVAPI(void) cveShapeTransformerWarpImage(cv::ShapeTransformer* transformer, cv::_InputArray* transformingImage, cv::_OutputArray* output, int flags, int borderMode, CvScalar* borderValue);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveShapeTransformerWarpImage", "ptr", $transformer, "ptr", $transformingImage, "ptr", $output, "int", $flags, "int", $borderMode, "struct*", $borderValue), "cveShapeTransformerWarpImage", @error)
EndFunc   ;==>_cveShapeTransformerWarpImage

Func _cveShapeTransformerWarpImageMat($transformer, $matTransformingImage, $matOutput, $flags, $borderMode, $borderValue)
    ; cveShapeTransformerWarpImage using cv::Mat instead of _*Array

    Local $iArrTransformingImage, $vectorOfMatTransformingImage, $iArrTransformingImageSize
    Local $bTransformingImageIsArray = VarGetType($matTransformingImage) == "Array"

    If $bTransformingImageIsArray Then
        $vectorOfMatTransformingImage = _VectorOfMatCreate()

        $iArrTransformingImageSize = UBound($matTransformingImage)
        For $i = 0 To $iArrTransformingImageSize - 1
            _VectorOfMatPush($vectorOfMatTransformingImage, $matTransformingImage[$i])
        Next

        $iArrTransformingImage = _cveInputArrayFromVectorOfMat($vectorOfMatTransformingImage)
    Else
        $iArrTransformingImage = _cveInputArrayFromMat($matTransformingImage)
    EndIf

    Local $oArrOutput, $vectorOfMatOutput, $iArrOutputSize
    Local $bOutputIsArray = VarGetType($matOutput) == "Array"

    If $bOutputIsArray Then
        $vectorOfMatOutput = _VectorOfMatCreate()

        $iArrOutputSize = UBound($matOutput)
        For $i = 0 To $iArrOutputSize - 1
            _VectorOfMatPush($vectorOfMatOutput, $matOutput[$i])
        Next

        $oArrOutput = _cveOutputArrayFromVectorOfMat($vectorOfMatOutput)
    Else
        $oArrOutput = _cveOutputArrayFromMat($matOutput)
    EndIf

    _cveShapeTransformerWarpImage($transformer, $iArrTransformingImage, $oArrOutput, $flags, $borderMode, $borderValue)

    If $bOutputIsArray Then
        _VectorOfMatRelease($vectorOfMatOutput)
    EndIf

    _cveOutputArrayRelease($oArrOutput)

    If $bTransformingImageIsArray Then
        _VectorOfMatRelease($vectorOfMatTransformingImage)
    EndIf

    _cveInputArrayRelease($iArrTransformingImage)
EndFunc   ;==>_cveShapeTransformerWarpImageMat

Func _cveShapeDistanceExtractorComputeDistance($extractor, $contour1, $contour2)
    ; CVAPI(float) cveShapeDistanceExtractorComputeDistance(cv::ShapeDistanceExtractor* extractor, cv::_InputArray* contour1, cv::_InputArray* contour2);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cveShapeDistanceExtractorComputeDistance", "ptr", $extractor, "ptr", $contour1, "ptr", $contour2), "cveShapeDistanceExtractorComputeDistance", @error)
EndFunc   ;==>_cveShapeDistanceExtractorComputeDistance

Func _cveShapeDistanceExtractorComputeDistanceMat($extractor, $matContour1, $matContour2)
    ; cveShapeDistanceExtractorComputeDistance using cv::Mat instead of _*Array

    Local $iArrContour1, $vectorOfMatContour1, $iArrContour1Size
    Local $bContour1IsArray = VarGetType($matContour1) == "Array"

    If $bContour1IsArray Then
        $vectorOfMatContour1 = _VectorOfMatCreate()

        $iArrContour1Size = UBound($matContour1)
        For $i = 0 To $iArrContour1Size - 1
            _VectorOfMatPush($vectorOfMatContour1, $matContour1[$i])
        Next

        $iArrContour1 = _cveInputArrayFromVectorOfMat($vectorOfMatContour1)
    Else
        $iArrContour1 = _cveInputArrayFromMat($matContour1)
    EndIf

    Local $iArrContour2, $vectorOfMatContour2, $iArrContour2Size
    Local $bContour2IsArray = VarGetType($matContour2) == "Array"

    If $bContour2IsArray Then
        $vectorOfMatContour2 = _VectorOfMatCreate()

        $iArrContour2Size = UBound($matContour2)
        For $i = 0 To $iArrContour2Size - 1
            _VectorOfMatPush($vectorOfMatContour2, $matContour2[$i])
        Next

        $iArrContour2 = _cveInputArrayFromVectorOfMat($vectorOfMatContour2)
    Else
        $iArrContour2 = _cveInputArrayFromMat($matContour2)
    EndIf

    Local $retval = _cveShapeDistanceExtractorComputeDistance($extractor, $iArrContour1, $iArrContour2)

    If $bContour2IsArray Then
        _VectorOfMatRelease($vectorOfMatContour2)
    EndIf

    _cveInputArrayRelease($iArrContour2)

    If $bContour1IsArray Then
        _VectorOfMatRelease($vectorOfMatContour1)
    EndIf

    _cveInputArrayRelease($iArrContour1)

    Return $retval
EndFunc   ;==>_cveShapeDistanceExtractorComputeDistanceMat

Func _cveShapeContextDistanceExtractorCreate($nAngularBins, $nRadialBins, $innerRadius, $outerRadius, $iterations, $comparer, $transformer, $e, $sharedPtr)
    ; CVAPI(cv::ShapeContextDistanceExtractor*) cveShapeContextDistanceExtractorCreate(int nAngularBins, int nRadialBins, float innerRadius, float outerRadius, int iterations, cv::HistogramCostExtractor* comparer, cv::ShapeTransformer* transformer, cv::ShapeDistanceExtractor** e, cv::Ptr<cv::ShapeContextDistanceExtractor>** sharedPtr);

    Local $bEDllType
    If VarGetType($e) == "DLLStruct" Then
        $bEDllType = "struct*"
    Else
        $bEDllType = "ptr*"
    EndIf

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveShapeContextDistanceExtractorCreate", "int", $nAngularBins, "int", $nRadialBins, "float", $innerRadius, "float", $outerRadius, "int", $iterations, "ptr", $comparer, "ptr", $transformer, $bEDllType, $e, $bSharedPtrDllType, $sharedPtr), "cveShapeContextDistanceExtractorCreate", @error)
EndFunc   ;==>_cveShapeContextDistanceExtractorCreate

Func _cveShapeContextDistanceExtractorRelease($sharedPtr)
    ; CVAPI(void) cveShapeContextDistanceExtractorRelease(cv::Ptr<cv::ShapeContextDistanceExtractor>** sharedPtr);

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveShapeContextDistanceExtractorRelease", $bSharedPtrDllType, $sharedPtr), "cveShapeContextDistanceExtractorRelease", @error)
EndFunc   ;==>_cveShapeContextDistanceExtractorRelease

Func _cveHausdorffDistanceExtractorCreate($distanceFlag, $rankProp, $e, $sharedPtr)
    ; CVAPI(cv::HausdorffDistanceExtractor*) cveHausdorffDistanceExtractorCreate(int distanceFlag, float rankProp, cv::ShapeDistanceExtractor** e, cv::Ptr<cv::HausdorffDistanceExtractor>** sharedPtr);

    Local $bEDllType
    If VarGetType($e) == "DLLStruct" Then
        $bEDllType = "struct*"
    Else
        $bEDllType = "ptr*"
    EndIf

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveHausdorffDistanceExtractorCreate", "int", $distanceFlag, "float", $rankProp, $bEDllType, $e, $bSharedPtrDllType, $sharedPtr), "cveHausdorffDistanceExtractorCreate", @error)
EndFunc   ;==>_cveHausdorffDistanceExtractorCreate

Func _cveHausdorffDistanceExtractorRelease($sharedPtr)
    ; CVAPI(void) cveHausdorffDistanceExtractorRelease(cv::Ptr<cv::HausdorffDistanceExtractor>** sharedPtr);

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveHausdorffDistanceExtractorRelease", $bSharedPtrDllType, $sharedPtr), "cveHausdorffDistanceExtractorRelease", @error)
EndFunc   ;==>_cveHausdorffDistanceExtractorRelease