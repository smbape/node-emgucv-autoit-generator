#include-once
#include "..\..\CVEUtils.au3"

Func _cveNormHistogramCostExtractorCreate($flag, $nDummies, $defaultCost, $sharedPtr)
    ; CVAPI(cv::HistogramCostExtractor*) cveNormHistogramCostExtractorCreate(int flag, int nDummies, float defaultCost, cv::Ptr<cv::HistogramCostExtractor>** sharedPtr);

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveNormHistogramCostExtractorCreate", "int", $flag, "int", $nDummies, "float", $defaultCost, $sSharedPtrDllType, $sharedPtr), "cveNormHistogramCostExtractorCreate", @error)
EndFunc   ;==>_cveNormHistogramCostExtractorCreate

Func _cveEMDHistogramCostExtractorCreate($flag, $nDummies, $defaultCost, $sharedPtr)
    ; CVAPI(cv::HistogramCostExtractor*) cveEMDHistogramCostExtractorCreate(int flag, int nDummies, float defaultCost, cv::Ptr<cv::HistogramCostExtractor>** sharedPtr);

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveEMDHistogramCostExtractorCreate", "int", $flag, "int", $nDummies, "float", $defaultCost, $sSharedPtrDllType, $sharedPtr), "cveEMDHistogramCostExtractorCreate", @error)
EndFunc   ;==>_cveEMDHistogramCostExtractorCreate

Func _cveChiHistogramCostExtractorCreate($nDummies, $defaultCost, $sharedPtr)
    ; CVAPI(cv::HistogramCostExtractor*) cveChiHistogramCostExtractorCreate(int nDummies, float defaultCost, cv::Ptr<cv::HistogramCostExtractor>** sharedPtr);

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveChiHistogramCostExtractorCreate", "int", $nDummies, "float", $defaultCost, $sSharedPtrDllType, $sharedPtr), "cveChiHistogramCostExtractorCreate", @error)
EndFunc   ;==>_cveChiHistogramCostExtractorCreate

Func _cveEMDL1HistogramCostExtractorCreate($nDummies, $defaultCost, $sharedPtr)
    ; CVAPI(cv::HistogramCostExtractor*) cveEMDL1HistogramCostExtractorCreate(int nDummies, float defaultCost, cv::Ptr<cv::HistogramCostExtractor>** sharedPtr);

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveEMDL1HistogramCostExtractorCreate", "int", $nDummies, "float", $defaultCost, $sSharedPtrDllType, $sharedPtr), "cveEMDL1HistogramCostExtractorCreate", @error)
EndFunc   ;==>_cveEMDL1HistogramCostExtractorCreate

Func _cveHistogramCostExtractorRelease($sharedPtr)
    ; CVAPI(void) cveHistogramCostExtractorRelease(cv::Ptr<cv::HistogramCostExtractor>** sharedPtr);

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveHistogramCostExtractorRelease", $sSharedPtrDllType, $sharedPtr), "cveHistogramCostExtractorRelease", @error)
EndFunc   ;==>_cveHistogramCostExtractorRelease

Func _cveThinPlateSplineShapeTransformerCreate($regularizationParameter, $shapeTransformer, $sharedPtr)
    ; CVAPI(cv::ThinPlateSplineShapeTransformer*) cveThinPlateSplineShapeTransformerCreate(double regularizationParameter, cv::ShapeTransformer** shapeTransformer, cv::Ptr<cv::ThinPlateSplineShapeTransformer>** sharedPtr);

    Local $sShapeTransformerDllType
    If IsDllStruct($shapeTransformer) Then
        $sShapeTransformerDllType = "struct*"
    ElseIf $shapeTransformer == Null Then
        $sShapeTransformerDllType = "ptr"
    Else
        $sShapeTransformerDllType = "ptr*"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveThinPlateSplineShapeTransformerCreate", "double", $regularizationParameter, $sShapeTransformerDllType, $shapeTransformer, $sSharedPtrDllType, $sharedPtr), "cveThinPlateSplineShapeTransformerCreate", @error)
EndFunc   ;==>_cveThinPlateSplineShapeTransformerCreate

Func _cveThinPlateSplineShapeTransformerRelease($sharedPtr)
    ; CVAPI(void) cveThinPlateSplineShapeTransformerRelease(cv::Ptr<cv::ThinPlateSplineShapeTransformer>** sharedPtr);

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveThinPlateSplineShapeTransformerRelease", $sSharedPtrDllType, $sharedPtr), "cveThinPlateSplineShapeTransformerRelease", @error)
EndFunc   ;==>_cveThinPlateSplineShapeTransformerRelease

Func _cveAffineTransformerCreate($fullAffine, $transformer, $sharedPtr)
    ; CVAPI(cv::AffineTransformer*) cveAffineTransformerCreate(bool fullAffine, cv::ShapeTransformer** transformer, cv::Ptr<cv::AffineTransformer>** sharedPtr);

    Local $sTransformerDllType
    If IsDllStruct($transformer) Then
        $sTransformerDllType = "struct*"
    ElseIf $transformer == Null Then
        $sTransformerDllType = "ptr"
    Else
        $sTransformerDllType = "ptr*"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveAffineTransformerCreate", "boolean", $fullAffine, $sTransformerDllType, $transformer, $sSharedPtrDllType, $sharedPtr), "cveAffineTransformerCreate", @error)
EndFunc   ;==>_cveAffineTransformerCreate

Func _cveAffineTransformerRelease($sharedPtr)
    ; CVAPI(void) cveAffineTransformerRelease(cv::Ptr<cv::AffineTransformer>** sharedPtr);

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveAffineTransformerRelease", $sSharedPtrDllType, $sharedPtr), "cveAffineTransformerRelease", @error)
EndFunc   ;==>_cveAffineTransformerRelease

Func _cveShapeTransformerEstimateTransformation($transformer, $transformingShape, $targetShape, $matches)
    ; CVAPI(void) cveShapeTransformerEstimateTransformation(cv::ShapeTransformer* transformer, cv::_InputArray* transformingShape, cv::_InputArray* targetShape, std::vector<cv::DMatch>* matches);

    Local $sTransformerDllType
    If IsDllStruct($transformer) Then
        $sTransformerDllType = "struct*"
    Else
        $sTransformerDllType = "ptr"
    EndIf

    Local $sTransformingShapeDllType
    If IsDllStruct($transformingShape) Then
        $sTransformingShapeDllType = "struct*"
    Else
        $sTransformingShapeDllType = "ptr"
    EndIf

    Local $sTargetShapeDllType
    If IsDllStruct($targetShape) Then
        $sTargetShapeDllType = "struct*"
    Else
        $sTargetShapeDllType = "ptr"
    EndIf

    Local $vecMatches, $iArrMatchesSize
    Local $bMatchesIsArray = IsArray($matches)

    If $bMatchesIsArray Then
        $vecMatches = _VectorOfDMatchCreate()

        $iArrMatchesSize = UBound($matches)
        For $i = 0 To $iArrMatchesSize - 1
            _VectorOfDMatchPush($vecMatches, $matches[$i])
        Next
    Else
        $vecMatches = $matches
    EndIf

    Local $sMatchesDllType
    If IsDllStruct($matches) Then
        $sMatchesDllType = "struct*"
    Else
        $sMatchesDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveShapeTransformerEstimateTransformation", $sTransformerDllType, $transformer, $sTransformingShapeDllType, $transformingShape, $sTargetShapeDllType, $targetShape, $sMatchesDllType, $vecMatches), "cveShapeTransformerEstimateTransformation", @error)

    If $bMatchesIsArray Then
        _VectorOfDMatchRelease($vecMatches)
    EndIf
EndFunc   ;==>_cveShapeTransformerEstimateTransformation

Func _cveShapeTransformerEstimateTransformationTyped($transformer, $typeOfTransformingShape, $transformingShape, $typeOfTargetShape, $targetShape, $matches)

    Local $iArrTransformingShape, $vectorTransformingShape, $iArrTransformingShapeSize
    Local $bTransformingShapeIsArray = IsArray($transformingShape)
    Local $bTransformingShapeCreate = IsDllStruct($transformingShape) And $typeOfTransformingShape == "Scalar"

    If $typeOfTransformingShape == Default Then
        $iArrTransformingShape = $transformingShape
    ElseIf $bTransformingShapeIsArray Then
        $vectorTransformingShape = Call("_VectorOf" & $typeOfTransformingShape & "Create")

        $iArrTransformingShapeSize = UBound($transformingShape)
        For $i = 0 To $iArrTransformingShapeSize - 1
            Call("_VectorOf" & $typeOfTransformingShape & "Push", $vectorTransformingShape, $transformingShape[$i])
        Next

        $iArrTransformingShape = Call("_cveInputArrayFromVectorOf" & $typeOfTransformingShape, $vectorTransformingShape)
    Else
        If $bTransformingShapeCreate Then
            $transformingShape = Call("_cve" & $typeOfTransformingShape & "Create", $transformingShape)
        EndIf
        $iArrTransformingShape = Call("_cveInputArrayFrom" & $typeOfTransformingShape, $transformingShape)
    EndIf

    Local $iArrTargetShape, $vectorTargetShape, $iArrTargetShapeSize
    Local $bTargetShapeIsArray = IsArray($targetShape)
    Local $bTargetShapeCreate = IsDllStruct($targetShape) And $typeOfTargetShape == "Scalar"

    If $typeOfTargetShape == Default Then
        $iArrTargetShape = $targetShape
    ElseIf $bTargetShapeIsArray Then
        $vectorTargetShape = Call("_VectorOf" & $typeOfTargetShape & "Create")

        $iArrTargetShapeSize = UBound($targetShape)
        For $i = 0 To $iArrTargetShapeSize - 1
            Call("_VectorOf" & $typeOfTargetShape & "Push", $vectorTargetShape, $targetShape[$i])
        Next

        $iArrTargetShape = Call("_cveInputArrayFromVectorOf" & $typeOfTargetShape, $vectorTargetShape)
    Else
        If $bTargetShapeCreate Then
            $targetShape = Call("_cve" & $typeOfTargetShape & "Create", $targetShape)
        EndIf
        $iArrTargetShape = Call("_cveInputArrayFrom" & $typeOfTargetShape, $targetShape)
    EndIf

    _cveShapeTransformerEstimateTransformation($transformer, $iArrTransformingShape, $iArrTargetShape, $matches)

    If $bTargetShapeIsArray Then
        Call("_VectorOf" & $typeOfTargetShape & "Release", $vectorTargetShape)
    EndIf

    If $typeOfTargetShape <> Default Then
        _cveInputArrayRelease($iArrTargetShape)
        If $bTargetShapeCreate Then
            Call("_cve" & $typeOfTargetShape & "Release", $targetShape)
        EndIf
    EndIf

    If $bTransformingShapeIsArray Then
        Call("_VectorOf" & $typeOfTransformingShape & "Release", $vectorTransformingShape)
    EndIf

    If $typeOfTransformingShape <> Default Then
        _cveInputArrayRelease($iArrTransformingShape)
        If $bTransformingShapeCreate Then
            Call("_cve" & $typeOfTransformingShape & "Release", $transformingShape)
        EndIf
    EndIf
EndFunc   ;==>_cveShapeTransformerEstimateTransformationTyped

Func _cveShapeTransformerEstimateTransformationMat($transformer, $transformingShape, $targetShape, $matches)
    ; cveShapeTransformerEstimateTransformation using cv::Mat instead of _*Array
    _cveShapeTransformerEstimateTransformationTyped($transformer, "Mat", $transformingShape, "Mat", $targetShape, $matches)
EndFunc   ;==>_cveShapeTransformerEstimateTransformationMat

Func _cveShapeTransformerApplyTransformation($transformer, $input, $output)
    ; CVAPI(float) cveShapeTransformerApplyTransformation(cv::ShapeTransformer* transformer, cv::_InputArray* input, cv::_OutputArray* output);

    Local $sTransformerDllType
    If IsDllStruct($transformer) Then
        $sTransformerDllType = "struct*"
    Else
        $sTransformerDllType = "ptr"
    EndIf

    Local $sInputDllType
    If IsDllStruct($input) Then
        $sInputDllType = "struct*"
    Else
        $sInputDllType = "ptr"
    EndIf

    Local $sOutputDllType
    If IsDllStruct($output) Then
        $sOutputDllType = "struct*"
    Else
        $sOutputDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cveShapeTransformerApplyTransformation", $sTransformerDllType, $transformer, $sInputDllType, $input, $sOutputDllType, $output), "cveShapeTransformerApplyTransformation", @error)
EndFunc   ;==>_cveShapeTransformerApplyTransformation

Func _cveShapeTransformerApplyTransformationTyped($transformer, $typeOfInput, $input, $typeOfOutput, $output)

    Local $iArrInput, $vectorInput, $iArrInputSize
    Local $bInputIsArray = IsArray($input)
    Local $bInputCreate = IsDllStruct($input) And $typeOfInput == "Scalar"

    If $typeOfInput == Default Then
        $iArrInput = $input
    ElseIf $bInputIsArray Then
        $vectorInput = Call("_VectorOf" & $typeOfInput & "Create")

        $iArrInputSize = UBound($input)
        For $i = 0 To $iArrInputSize - 1
            Call("_VectorOf" & $typeOfInput & "Push", $vectorInput, $input[$i])
        Next

        $iArrInput = Call("_cveInputArrayFromVectorOf" & $typeOfInput, $vectorInput)
    Else
        If $bInputCreate Then
            $input = Call("_cve" & $typeOfInput & "Create", $input)
        EndIf
        $iArrInput = Call("_cveInputArrayFrom" & $typeOfInput, $input)
    EndIf

    Local $oArrOutput, $vectorOutput, $iArrOutputSize
    Local $bOutputIsArray = IsArray($output)
    Local $bOutputCreate = IsDllStruct($output) And $typeOfOutput == "Scalar"

    If $typeOfOutput == Default Then
        $oArrOutput = $output
    ElseIf $bOutputIsArray Then
        $vectorOutput = Call("_VectorOf" & $typeOfOutput & "Create")

        $iArrOutputSize = UBound($output)
        For $i = 0 To $iArrOutputSize - 1
            Call("_VectorOf" & $typeOfOutput & "Push", $vectorOutput, $output[$i])
        Next

        $oArrOutput = Call("_cveOutputArrayFromVectorOf" & $typeOfOutput, $vectorOutput)
    Else
        If $bOutputCreate Then
            $output = Call("_cve" & $typeOfOutput & "Create", $output)
        EndIf
        $oArrOutput = Call("_cveOutputArrayFrom" & $typeOfOutput, $output)
    EndIf

    Local $retval = _cveShapeTransformerApplyTransformation($transformer, $iArrInput, $oArrOutput)

    If $bOutputIsArray Then
        Call("_VectorOf" & $typeOfOutput & "Release", $vectorOutput)
    EndIf

    If $typeOfOutput <> Default Then
        _cveOutputArrayRelease($oArrOutput)
        If $bOutputCreate Then
            Call("_cve" & $typeOfOutput & "Release", $output)
        EndIf
    EndIf

    If $bInputIsArray Then
        Call("_VectorOf" & $typeOfInput & "Release", $vectorInput)
    EndIf

    If $typeOfInput <> Default Then
        _cveInputArrayRelease($iArrInput)
        If $bInputCreate Then
            Call("_cve" & $typeOfInput & "Release", $input)
        EndIf
    EndIf

    Return $retval
EndFunc   ;==>_cveShapeTransformerApplyTransformationTyped

Func _cveShapeTransformerApplyTransformationMat($transformer, $input, $output)
    ; cveShapeTransformerApplyTransformation using cv::Mat instead of _*Array
    Local $retval = _cveShapeTransformerApplyTransformationTyped($transformer, "Mat", $input, "Mat", $output)

    Return $retval
EndFunc   ;==>_cveShapeTransformerApplyTransformationMat

Func _cveShapeTransformerWarpImage($transformer, $transformingImage, $output, $flags, $borderMode, $borderValue)
    ; CVAPI(void) cveShapeTransformerWarpImage(cv::ShapeTransformer* transformer, cv::_InputArray* transformingImage, cv::_OutputArray* output, int flags, int borderMode, CvScalar* borderValue);

    Local $sTransformerDllType
    If IsDllStruct($transformer) Then
        $sTransformerDllType = "struct*"
    Else
        $sTransformerDllType = "ptr"
    EndIf

    Local $sTransformingImageDllType
    If IsDllStruct($transformingImage) Then
        $sTransformingImageDllType = "struct*"
    Else
        $sTransformingImageDllType = "ptr"
    EndIf

    Local $sOutputDllType
    If IsDllStruct($output) Then
        $sOutputDllType = "struct*"
    Else
        $sOutputDllType = "ptr"
    EndIf

    Local $sBorderValueDllType
    If IsDllStruct($borderValue) Then
        $sBorderValueDllType = "struct*"
    Else
        $sBorderValueDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveShapeTransformerWarpImage", $sTransformerDllType, $transformer, $sTransformingImageDllType, $transformingImage, $sOutputDllType, $output, "int", $flags, "int", $borderMode, $sBorderValueDllType, $borderValue), "cveShapeTransformerWarpImage", @error)
EndFunc   ;==>_cveShapeTransformerWarpImage

Func _cveShapeTransformerWarpImageTyped($transformer, $typeOfTransformingImage, $transformingImage, $typeOfOutput, $output, $flags, $borderMode, $borderValue)

    Local $iArrTransformingImage, $vectorTransformingImage, $iArrTransformingImageSize
    Local $bTransformingImageIsArray = IsArray($transformingImage)
    Local $bTransformingImageCreate = IsDllStruct($transformingImage) And $typeOfTransformingImage == "Scalar"

    If $typeOfTransformingImage == Default Then
        $iArrTransformingImage = $transformingImage
    ElseIf $bTransformingImageIsArray Then
        $vectorTransformingImage = Call("_VectorOf" & $typeOfTransformingImage & "Create")

        $iArrTransformingImageSize = UBound($transformingImage)
        For $i = 0 To $iArrTransformingImageSize - 1
            Call("_VectorOf" & $typeOfTransformingImage & "Push", $vectorTransformingImage, $transformingImage[$i])
        Next

        $iArrTransformingImage = Call("_cveInputArrayFromVectorOf" & $typeOfTransformingImage, $vectorTransformingImage)
    Else
        If $bTransformingImageCreate Then
            $transformingImage = Call("_cve" & $typeOfTransformingImage & "Create", $transformingImage)
        EndIf
        $iArrTransformingImage = Call("_cveInputArrayFrom" & $typeOfTransformingImage, $transformingImage)
    EndIf

    Local $oArrOutput, $vectorOutput, $iArrOutputSize
    Local $bOutputIsArray = IsArray($output)
    Local $bOutputCreate = IsDllStruct($output) And $typeOfOutput == "Scalar"

    If $typeOfOutput == Default Then
        $oArrOutput = $output
    ElseIf $bOutputIsArray Then
        $vectorOutput = Call("_VectorOf" & $typeOfOutput & "Create")

        $iArrOutputSize = UBound($output)
        For $i = 0 To $iArrOutputSize - 1
            Call("_VectorOf" & $typeOfOutput & "Push", $vectorOutput, $output[$i])
        Next

        $oArrOutput = Call("_cveOutputArrayFromVectorOf" & $typeOfOutput, $vectorOutput)
    Else
        If $bOutputCreate Then
            $output = Call("_cve" & $typeOfOutput & "Create", $output)
        EndIf
        $oArrOutput = Call("_cveOutputArrayFrom" & $typeOfOutput, $output)
    EndIf

    _cveShapeTransformerWarpImage($transformer, $iArrTransformingImage, $oArrOutput, $flags, $borderMode, $borderValue)

    If $bOutputIsArray Then
        Call("_VectorOf" & $typeOfOutput & "Release", $vectorOutput)
    EndIf

    If $typeOfOutput <> Default Then
        _cveOutputArrayRelease($oArrOutput)
        If $bOutputCreate Then
            Call("_cve" & $typeOfOutput & "Release", $output)
        EndIf
    EndIf

    If $bTransformingImageIsArray Then
        Call("_VectorOf" & $typeOfTransformingImage & "Release", $vectorTransformingImage)
    EndIf

    If $typeOfTransformingImage <> Default Then
        _cveInputArrayRelease($iArrTransformingImage)
        If $bTransformingImageCreate Then
            Call("_cve" & $typeOfTransformingImage & "Release", $transformingImage)
        EndIf
    EndIf
EndFunc   ;==>_cveShapeTransformerWarpImageTyped

Func _cveShapeTransformerWarpImageMat($transformer, $transformingImage, $output, $flags, $borderMode, $borderValue)
    ; cveShapeTransformerWarpImage using cv::Mat instead of _*Array
    _cveShapeTransformerWarpImageTyped($transformer, "Mat", $transformingImage, "Mat", $output, $flags, $borderMode, $borderValue)
EndFunc   ;==>_cveShapeTransformerWarpImageMat

Func _cveShapeDistanceExtractorComputeDistance($extractor, $contour1, $contour2)
    ; CVAPI(float) cveShapeDistanceExtractorComputeDistance(cv::ShapeDistanceExtractor* extractor, cv::_InputArray* contour1, cv::_InputArray* contour2);

    Local $sExtractorDllType
    If IsDllStruct($extractor) Then
        $sExtractorDllType = "struct*"
    Else
        $sExtractorDllType = "ptr"
    EndIf

    Local $sContour1DllType
    If IsDllStruct($contour1) Then
        $sContour1DllType = "struct*"
    Else
        $sContour1DllType = "ptr"
    EndIf

    Local $sContour2DllType
    If IsDllStruct($contour2) Then
        $sContour2DllType = "struct*"
    Else
        $sContour2DllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cveShapeDistanceExtractorComputeDistance", $sExtractorDllType, $extractor, $sContour1DllType, $contour1, $sContour2DllType, $contour2), "cveShapeDistanceExtractorComputeDistance", @error)
EndFunc   ;==>_cveShapeDistanceExtractorComputeDistance

Func _cveShapeDistanceExtractorComputeDistanceTyped($extractor, $typeOfContour1, $contour1, $typeOfContour2, $contour2)

    Local $iArrContour1, $vectorContour1, $iArrContour1Size
    Local $bContour1IsArray = IsArray($contour1)
    Local $bContour1Create = IsDllStruct($contour1) And $typeOfContour1 == "Scalar"

    If $typeOfContour1 == Default Then
        $iArrContour1 = $contour1
    ElseIf $bContour1IsArray Then
        $vectorContour1 = Call("_VectorOf" & $typeOfContour1 & "Create")

        $iArrContour1Size = UBound($contour1)
        For $i = 0 To $iArrContour1Size - 1
            Call("_VectorOf" & $typeOfContour1 & "Push", $vectorContour1, $contour1[$i])
        Next

        $iArrContour1 = Call("_cveInputArrayFromVectorOf" & $typeOfContour1, $vectorContour1)
    Else
        If $bContour1Create Then
            $contour1 = Call("_cve" & $typeOfContour1 & "Create", $contour1)
        EndIf
        $iArrContour1 = Call("_cveInputArrayFrom" & $typeOfContour1, $contour1)
    EndIf

    Local $iArrContour2, $vectorContour2, $iArrContour2Size
    Local $bContour2IsArray = IsArray($contour2)
    Local $bContour2Create = IsDllStruct($contour2) And $typeOfContour2 == "Scalar"

    If $typeOfContour2 == Default Then
        $iArrContour2 = $contour2
    ElseIf $bContour2IsArray Then
        $vectorContour2 = Call("_VectorOf" & $typeOfContour2 & "Create")

        $iArrContour2Size = UBound($contour2)
        For $i = 0 To $iArrContour2Size - 1
            Call("_VectorOf" & $typeOfContour2 & "Push", $vectorContour2, $contour2[$i])
        Next

        $iArrContour2 = Call("_cveInputArrayFromVectorOf" & $typeOfContour2, $vectorContour2)
    Else
        If $bContour2Create Then
            $contour2 = Call("_cve" & $typeOfContour2 & "Create", $contour2)
        EndIf
        $iArrContour2 = Call("_cveInputArrayFrom" & $typeOfContour2, $contour2)
    EndIf

    Local $retval = _cveShapeDistanceExtractorComputeDistance($extractor, $iArrContour1, $iArrContour2)

    If $bContour2IsArray Then
        Call("_VectorOf" & $typeOfContour2 & "Release", $vectorContour2)
    EndIf

    If $typeOfContour2 <> Default Then
        _cveInputArrayRelease($iArrContour2)
        If $bContour2Create Then
            Call("_cve" & $typeOfContour2 & "Release", $contour2)
        EndIf
    EndIf

    If $bContour1IsArray Then
        Call("_VectorOf" & $typeOfContour1 & "Release", $vectorContour1)
    EndIf

    If $typeOfContour1 <> Default Then
        _cveInputArrayRelease($iArrContour1)
        If $bContour1Create Then
            Call("_cve" & $typeOfContour1 & "Release", $contour1)
        EndIf
    EndIf

    Return $retval
EndFunc   ;==>_cveShapeDistanceExtractorComputeDistanceTyped

Func _cveShapeDistanceExtractorComputeDistanceMat($extractor, $contour1, $contour2)
    ; cveShapeDistanceExtractorComputeDistance using cv::Mat instead of _*Array
    Local $retval = _cveShapeDistanceExtractorComputeDistanceTyped($extractor, "Mat", $contour1, "Mat", $contour2)

    Return $retval
EndFunc   ;==>_cveShapeDistanceExtractorComputeDistanceMat

Func _cveShapeContextDistanceExtractorCreate($nAngularBins, $nRadialBins, $innerRadius, $outerRadius, $iterations, $comparer, $transformer, $e, $sharedPtr)
    ; CVAPI(cv::ShapeContextDistanceExtractor*) cveShapeContextDistanceExtractorCreate(int nAngularBins, int nRadialBins, float innerRadius, float outerRadius, int iterations, cv::HistogramCostExtractor* comparer, cv::ShapeTransformer* transformer, cv::ShapeDistanceExtractor** e, cv::Ptr<cv::ShapeContextDistanceExtractor>** sharedPtr);

    Local $sComparerDllType
    If IsDllStruct($comparer) Then
        $sComparerDllType = "struct*"
    Else
        $sComparerDllType = "ptr"
    EndIf

    Local $sTransformerDllType
    If IsDllStruct($transformer) Then
        $sTransformerDllType = "struct*"
    Else
        $sTransformerDllType = "ptr"
    EndIf

    Local $sEDllType
    If IsDllStruct($e) Then
        $sEDllType = "struct*"
    ElseIf $e == Null Then
        $sEDllType = "ptr"
    Else
        $sEDllType = "ptr*"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveShapeContextDistanceExtractorCreate", "int", $nAngularBins, "int", $nRadialBins, "float", $innerRadius, "float", $outerRadius, "int", $iterations, $sComparerDllType, $comparer, $sTransformerDllType, $transformer, $sEDllType, $e, $sSharedPtrDllType, $sharedPtr), "cveShapeContextDistanceExtractorCreate", @error)
EndFunc   ;==>_cveShapeContextDistanceExtractorCreate

Func _cveShapeContextDistanceExtractorRelease($sharedPtr)
    ; CVAPI(void) cveShapeContextDistanceExtractorRelease(cv::Ptr<cv::ShapeContextDistanceExtractor>** sharedPtr);

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveShapeContextDistanceExtractorRelease", $sSharedPtrDllType, $sharedPtr), "cveShapeContextDistanceExtractorRelease", @error)
EndFunc   ;==>_cveShapeContextDistanceExtractorRelease

Func _cveHausdorffDistanceExtractorCreate($distanceFlag, $rankProp, $e, $sharedPtr)
    ; CVAPI(cv::HausdorffDistanceExtractor*) cveHausdorffDistanceExtractorCreate(int distanceFlag, float rankProp, cv::ShapeDistanceExtractor** e, cv::Ptr<cv::HausdorffDistanceExtractor>** sharedPtr);

    Local $sEDllType
    If IsDllStruct($e) Then
        $sEDllType = "struct*"
    ElseIf $e == Null Then
        $sEDllType = "ptr"
    Else
        $sEDllType = "ptr*"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveHausdorffDistanceExtractorCreate", "int", $distanceFlag, "float", $rankProp, $sEDllType, $e, $sSharedPtrDllType, $sharedPtr), "cveHausdorffDistanceExtractorCreate", @error)
EndFunc   ;==>_cveHausdorffDistanceExtractorCreate

Func _cveHausdorffDistanceExtractorRelease($sharedPtr)
    ; CVAPI(void) cveHausdorffDistanceExtractorRelease(cv::Ptr<cv::HausdorffDistanceExtractor>** sharedPtr);

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveHausdorffDistanceExtractorRelease", $sSharedPtrDllType, $sharedPtr), "cveHausdorffDistanceExtractorRelease", @error)
EndFunc   ;==>_cveHausdorffDistanceExtractorRelease