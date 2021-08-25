#include-once
#include "..\..\CVEUtils.au3"

Func _StatModelTrain($model, $samples, $layout, $responses)
    ; CVAPI(bool) StatModelTrain(cv::ml::StatModel* model, cv::_InputArray* samples, int layout, cv::_InputArray* responses);

    Local $sModelDllType
    If IsDllStruct($model) Then
        $sModelDllType = "struct*"
    Else
        $sModelDllType = "ptr"
    EndIf

    Local $sSamplesDllType
    If IsDllStruct($samples) Then
        $sSamplesDllType = "struct*"
    Else
        $sSamplesDllType = "ptr"
    EndIf

    Local $sResponsesDllType
    If IsDllStruct($responses) Then
        $sResponsesDllType = "struct*"
    Else
        $sResponsesDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "StatModelTrain", $sModelDllType, $model, $sSamplesDllType, $samples, "int", $layout, $sResponsesDllType, $responses), "StatModelTrain", @error)
EndFunc   ;==>_StatModelTrain

Func _StatModelTrainTyped($model, $typeOfSamples, $samples, $layout, $typeOfResponses, $responses)

    Local $iArrSamples, $vectorSamples, $iArrSamplesSize
    Local $bSamplesIsArray = IsArray($samples)
    Local $bSamplesCreate = IsDllStruct($samples) And $typeOfSamples == "Scalar"

    If $typeOfSamples == Default Then
        $iArrSamples = $samples
    ElseIf $bSamplesIsArray Then
        $vectorSamples = Call("_VectorOf" & $typeOfSamples & "Create")

        $iArrSamplesSize = UBound($samples)
        For $i = 0 To $iArrSamplesSize - 1
            Call("_VectorOf" & $typeOfSamples & "Push", $vectorSamples, $samples[$i])
        Next

        $iArrSamples = Call("_cveInputArrayFromVectorOf" & $typeOfSamples, $vectorSamples)
    Else
        If $bSamplesCreate Then
            $samples = Call("_cve" & $typeOfSamples & "Create", $samples)
        EndIf
        $iArrSamples = Call("_cveInputArrayFrom" & $typeOfSamples, $samples)
    EndIf

    Local $iArrResponses, $vectorResponses, $iArrResponsesSize
    Local $bResponsesIsArray = IsArray($responses)
    Local $bResponsesCreate = IsDllStruct($responses) And $typeOfResponses == "Scalar"

    If $typeOfResponses == Default Then
        $iArrResponses = $responses
    ElseIf $bResponsesIsArray Then
        $vectorResponses = Call("_VectorOf" & $typeOfResponses & "Create")

        $iArrResponsesSize = UBound($responses)
        For $i = 0 To $iArrResponsesSize - 1
            Call("_VectorOf" & $typeOfResponses & "Push", $vectorResponses, $responses[$i])
        Next

        $iArrResponses = Call("_cveInputArrayFromVectorOf" & $typeOfResponses, $vectorResponses)
    Else
        If $bResponsesCreate Then
            $responses = Call("_cve" & $typeOfResponses & "Create", $responses)
        EndIf
        $iArrResponses = Call("_cveInputArrayFrom" & $typeOfResponses, $responses)
    EndIf

    Local $retval = _StatModelTrain($model, $iArrSamples, $layout, $iArrResponses)

    If $bResponsesIsArray Then
        Call("_VectorOf" & $typeOfResponses & "Release", $vectorResponses)
    EndIf

    If $typeOfResponses <> Default Then
        _cveInputArrayRelease($iArrResponses)
        If $bResponsesCreate Then
            Call("_cve" & $typeOfResponses & "Release", $responses)
        EndIf
    EndIf

    If $bSamplesIsArray Then
        Call("_VectorOf" & $typeOfSamples & "Release", $vectorSamples)
    EndIf

    If $typeOfSamples <> Default Then
        _cveInputArrayRelease($iArrSamples)
        If $bSamplesCreate Then
            Call("_cve" & $typeOfSamples & "Release", $samples)
        EndIf
    EndIf

    Return $retval
EndFunc   ;==>_StatModelTrainTyped

Func _StatModelTrainMat($model, $samples, $layout, $responses)
    ; StatModelTrain using cv::Mat instead of _*Array
    Local $retval = _StatModelTrainTyped($model, "Mat", $samples, $layout, "Mat", $responses)

    Return $retval
EndFunc   ;==>_StatModelTrainMat

Func _StatModelTrainWithData($model, $data, $flags)
    ; CVAPI(bool) StatModelTrainWithData(cv::ml::StatModel* model, cv::ml::TrainData* data, int flags);

    Local $sModelDllType
    If IsDllStruct($model) Then
        $sModelDllType = "struct*"
    Else
        $sModelDllType = "ptr"
    EndIf

    Local $sDataDllType
    If IsDllStruct($data) Then
        $sDataDllType = "struct*"
    Else
        $sDataDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "StatModelTrainWithData", $sModelDllType, $model, $sDataDllType, $data, "int", $flags), "StatModelTrainWithData", @error)
EndFunc   ;==>_StatModelTrainWithData

Func _StatModelPredict($model, $samples, $results, $flags)
    ; CVAPI(float) StatModelPredict(cv::ml::StatModel* model, cv::_InputArray* samples, cv::_OutputArray* results, int flags);

    Local $sModelDllType
    If IsDllStruct($model) Then
        $sModelDllType = "struct*"
    Else
        $sModelDllType = "ptr"
    EndIf

    Local $sSamplesDllType
    If IsDllStruct($samples) Then
        $sSamplesDllType = "struct*"
    Else
        $sSamplesDllType = "ptr"
    EndIf

    Local $sResultsDllType
    If IsDllStruct($results) Then
        $sResultsDllType = "struct*"
    Else
        $sResultsDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "StatModelPredict", $sModelDllType, $model, $sSamplesDllType, $samples, $sResultsDllType, $results, "int", $flags), "StatModelPredict", @error)
EndFunc   ;==>_StatModelPredict

Func _StatModelPredictTyped($model, $typeOfSamples, $samples, $typeOfResults, $results, $flags)

    Local $iArrSamples, $vectorSamples, $iArrSamplesSize
    Local $bSamplesIsArray = IsArray($samples)
    Local $bSamplesCreate = IsDllStruct($samples) And $typeOfSamples == "Scalar"

    If $typeOfSamples == Default Then
        $iArrSamples = $samples
    ElseIf $bSamplesIsArray Then
        $vectorSamples = Call("_VectorOf" & $typeOfSamples & "Create")

        $iArrSamplesSize = UBound($samples)
        For $i = 0 To $iArrSamplesSize - 1
            Call("_VectorOf" & $typeOfSamples & "Push", $vectorSamples, $samples[$i])
        Next

        $iArrSamples = Call("_cveInputArrayFromVectorOf" & $typeOfSamples, $vectorSamples)
    Else
        If $bSamplesCreate Then
            $samples = Call("_cve" & $typeOfSamples & "Create", $samples)
        EndIf
        $iArrSamples = Call("_cveInputArrayFrom" & $typeOfSamples, $samples)
    EndIf

    Local $oArrResults, $vectorResults, $iArrResultsSize
    Local $bResultsIsArray = IsArray($results)
    Local $bResultsCreate = IsDllStruct($results) And $typeOfResults == "Scalar"

    If $typeOfResults == Default Then
        $oArrResults = $results
    ElseIf $bResultsIsArray Then
        $vectorResults = Call("_VectorOf" & $typeOfResults & "Create")

        $iArrResultsSize = UBound($results)
        For $i = 0 To $iArrResultsSize - 1
            Call("_VectorOf" & $typeOfResults & "Push", $vectorResults, $results[$i])
        Next

        $oArrResults = Call("_cveOutputArrayFromVectorOf" & $typeOfResults, $vectorResults)
    Else
        If $bResultsCreate Then
            $results = Call("_cve" & $typeOfResults & "Create", $results)
        EndIf
        $oArrResults = Call("_cveOutputArrayFrom" & $typeOfResults, $results)
    EndIf

    Local $retval = _StatModelPredict($model, $iArrSamples, $oArrResults, $flags)

    If $bResultsIsArray Then
        Call("_VectorOf" & $typeOfResults & "Release", $vectorResults)
    EndIf

    If $typeOfResults <> Default Then
        _cveOutputArrayRelease($oArrResults)
        If $bResultsCreate Then
            Call("_cve" & $typeOfResults & "Release", $results)
        EndIf
    EndIf

    If $bSamplesIsArray Then
        Call("_VectorOf" & $typeOfSamples & "Release", $vectorSamples)
    EndIf

    If $typeOfSamples <> Default Then
        _cveInputArrayRelease($iArrSamples)
        If $bSamplesCreate Then
            Call("_cve" & $typeOfSamples & "Release", $samples)
        EndIf
    EndIf

    Return $retval
EndFunc   ;==>_StatModelPredictTyped

Func _StatModelPredictMat($model, $samples, $results, $flags)
    ; StatModelPredict using cv::Mat instead of _*Array
    Local $retval = _StatModelPredictTyped($model, "Mat", $samples, "Mat", $results, $flags)

    Return $retval
EndFunc   ;==>_StatModelPredictMat

Func _cveTrainDataCreate($samples, $layout, $responses, $varIdx, $sampleIdx, $sampleWeights, $varType, $sharedPtr)
    ; CVAPI(cv::ml::TrainData*) cveTrainDataCreate(cv::_InputArray* samples, int layout, cv::_InputArray* responses, cv::_InputArray* varIdx, cv::_InputArray* sampleIdx, cv::_InputArray* sampleWeights, cv::_InputArray* varType, cv::Ptr<cv::ml::TrainData>** sharedPtr);

    Local $sSamplesDllType
    If IsDllStruct($samples) Then
        $sSamplesDllType = "struct*"
    Else
        $sSamplesDllType = "ptr"
    EndIf

    Local $sResponsesDllType
    If IsDllStruct($responses) Then
        $sResponsesDllType = "struct*"
    Else
        $sResponsesDllType = "ptr"
    EndIf

    Local $sVarIdxDllType
    If IsDllStruct($varIdx) Then
        $sVarIdxDllType = "struct*"
    Else
        $sVarIdxDllType = "ptr"
    EndIf

    Local $sSampleIdxDllType
    If IsDllStruct($sampleIdx) Then
        $sSampleIdxDllType = "struct*"
    Else
        $sSampleIdxDllType = "ptr"
    EndIf

    Local $sSampleWeightsDllType
    If IsDllStruct($sampleWeights) Then
        $sSampleWeightsDllType = "struct*"
    Else
        $sSampleWeightsDllType = "ptr"
    EndIf

    Local $sVarTypeDllType
    If IsDllStruct($varType) Then
        $sVarTypeDllType = "struct*"
    Else
        $sVarTypeDllType = "ptr"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveTrainDataCreate", $sSamplesDllType, $samples, "int", $layout, $sResponsesDllType, $responses, $sVarIdxDllType, $varIdx, $sSampleIdxDllType, $sampleIdx, $sSampleWeightsDllType, $sampleWeights, $sVarTypeDllType, $varType, $sSharedPtrDllType, $sharedPtr), "cveTrainDataCreate", @error)
EndFunc   ;==>_cveTrainDataCreate

Func _cveTrainDataCreateTyped($typeOfSamples, $samples, $layout, $typeOfResponses, $responses, $typeOfVarIdx, $varIdx, $typeOfSampleIdx, $sampleIdx, $typeOfSampleWeights, $sampleWeights, $typeOfVarType, $varType, $sharedPtr)

    Local $iArrSamples, $vectorSamples, $iArrSamplesSize
    Local $bSamplesIsArray = IsArray($samples)
    Local $bSamplesCreate = IsDllStruct($samples) And $typeOfSamples == "Scalar"

    If $typeOfSamples == Default Then
        $iArrSamples = $samples
    ElseIf $bSamplesIsArray Then
        $vectorSamples = Call("_VectorOf" & $typeOfSamples & "Create")

        $iArrSamplesSize = UBound($samples)
        For $i = 0 To $iArrSamplesSize - 1
            Call("_VectorOf" & $typeOfSamples & "Push", $vectorSamples, $samples[$i])
        Next

        $iArrSamples = Call("_cveInputArrayFromVectorOf" & $typeOfSamples, $vectorSamples)
    Else
        If $bSamplesCreate Then
            $samples = Call("_cve" & $typeOfSamples & "Create", $samples)
        EndIf
        $iArrSamples = Call("_cveInputArrayFrom" & $typeOfSamples, $samples)
    EndIf

    Local $iArrResponses, $vectorResponses, $iArrResponsesSize
    Local $bResponsesIsArray = IsArray($responses)
    Local $bResponsesCreate = IsDllStruct($responses) And $typeOfResponses == "Scalar"

    If $typeOfResponses == Default Then
        $iArrResponses = $responses
    ElseIf $bResponsesIsArray Then
        $vectorResponses = Call("_VectorOf" & $typeOfResponses & "Create")

        $iArrResponsesSize = UBound($responses)
        For $i = 0 To $iArrResponsesSize - 1
            Call("_VectorOf" & $typeOfResponses & "Push", $vectorResponses, $responses[$i])
        Next

        $iArrResponses = Call("_cveInputArrayFromVectorOf" & $typeOfResponses, $vectorResponses)
    Else
        If $bResponsesCreate Then
            $responses = Call("_cve" & $typeOfResponses & "Create", $responses)
        EndIf
        $iArrResponses = Call("_cveInputArrayFrom" & $typeOfResponses, $responses)
    EndIf

    Local $iArrVarIdx, $vectorVarIdx, $iArrVarIdxSize
    Local $bVarIdxIsArray = IsArray($varIdx)
    Local $bVarIdxCreate = IsDllStruct($varIdx) And $typeOfVarIdx == "Scalar"

    If $typeOfVarIdx == Default Then
        $iArrVarIdx = $varIdx
    ElseIf $bVarIdxIsArray Then
        $vectorVarIdx = Call("_VectorOf" & $typeOfVarIdx & "Create")

        $iArrVarIdxSize = UBound($varIdx)
        For $i = 0 To $iArrVarIdxSize - 1
            Call("_VectorOf" & $typeOfVarIdx & "Push", $vectorVarIdx, $varIdx[$i])
        Next

        $iArrVarIdx = Call("_cveInputArrayFromVectorOf" & $typeOfVarIdx, $vectorVarIdx)
    Else
        If $bVarIdxCreate Then
            $varIdx = Call("_cve" & $typeOfVarIdx & "Create", $varIdx)
        EndIf
        $iArrVarIdx = Call("_cveInputArrayFrom" & $typeOfVarIdx, $varIdx)
    EndIf

    Local $iArrSampleIdx, $vectorSampleIdx, $iArrSampleIdxSize
    Local $bSampleIdxIsArray = IsArray($sampleIdx)
    Local $bSampleIdxCreate = IsDllStruct($sampleIdx) And $typeOfSampleIdx == "Scalar"

    If $typeOfSampleIdx == Default Then
        $iArrSampleIdx = $sampleIdx
    ElseIf $bSampleIdxIsArray Then
        $vectorSampleIdx = Call("_VectorOf" & $typeOfSampleIdx & "Create")

        $iArrSampleIdxSize = UBound($sampleIdx)
        For $i = 0 To $iArrSampleIdxSize - 1
            Call("_VectorOf" & $typeOfSampleIdx & "Push", $vectorSampleIdx, $sampleIdx[$i])
        Next

        $iArrSampleIdx = Call("_cveInputArrayFromVectorOf" & $typeOfSampleIdx, $vectorSampleIdx)
    Else
        If $bSampleIdxCreate Then
            $sampleIdx = Call("_cve" & $typeOfSampleIdx & "Create", $sampleIdx)
        EndIf
        $iArrSampleIdx = Call("_cveInputArrayFrom" & $typeOfSampleIdx, $sampleIdx)
    EndIf

    Local $iArrSampleWeights, $vectorSampleWeights, $iArrSampleWeightsSize
    Local $bSampleWeightsIsArray = IsArray($sampleWeights)
    Local $bSampleWeightsCreate = IsDllStruct($sampleWeights) And $typeOfSampleWeights == "Scalar"

    If $typeOfSampleWeights == Default Then
        $iArrSampleWeights = $sampleWeights
    ElseIf $bSampleWeightsIsArray Then
        $vectorSampleWeights = Call("_VectorOf" & $typeOfSampleWeights & "Create")

        $iArrSampleWeightsSize = UBound($sampleWeights)
        For $i = 0 To $iArrSampleWeightsSize - 1
            Call("_VectorOf" & $typeOfSampleWeights & "Push", $vectorSampleWeights, $sampleWeights[$i])
        Next

        $iArrSampleWeights = Call("_cveInputArrayFromVectorOf" & $typeOfSampleWeights, $vectorSampleWeights)
    Else
        If $bSampleWeightsCreate Then
            $sampleWeights = Call("_cve" & $typeOfSampleWeights & "Create", $sampleWeights)
        EndIf
        $iArrSampleWeights = Call("_cveInputArrayFrom" & $typeOfSampleWeights, $sampleWeights)
    EndIf

    Local $iArrVarType, $vectorVarType, $iArrVarTypeSize
    Local $bVarTypeIsArray = IsArray($varType)
    Local $bVarTypeCreate = IsDllStruct($varType) And $typeOfVarType == "Scalar"

    If $typeOfVarType == Default Then
        $iArrVarType = $varType
    ElseIf $bVarTypeIsArray Then
        $vectorVarType = Call("_VectorOf" & $typeOfVarType & "Create")

        $iArrVarTypeSize = UBound($varType)
        For $i = 0 To $iArrVarTypeSize - 1
            Call("_VectorOf" & $typeOfVarType & "Push", $vectorVarType, $varType[$i])
        Next

        $iArrVarType = Call("_cveInputArrayFromVectorOf" & $typeOfVarType, $vectorVarType)
    Else
        If $bVarTypeCreate Then
            $varType = Call("_cve" & $typeOfVarType & "Create", $varType)
        EndIf
        $iArrVarType = Call("_cveInputArrayFrom" & $typeOfVarType, $varType)
    EndIf

    Local $retval = _cveTrainDataCreate($iArrSamples, $layout, $iArrResponses, $iArrVarIdx, $iArrSampleIdx, $iArrSampleWeights, $iArrVarType, $sharedPtr)

    If $bVarTypeIsArray Then
        Call("_VectorOf" & $typeOfVarType & "Release", $vectorVarType)
    EndIf

    If $typeOfVarType <> Default Then
        _cveInputArrayRelease($iArrVarType)
        If $bVarTypeCreate Then
            Call("_cve" & $typeOfVarType & "Release", $varType)
        EndIf
    EndIf

    If $bSampleWeightsIsArray Then
        Call("_VectorOf" & $typeOfSampleWeights & "Release", $vectorSampleWeights)
    EndIf

    If $typeOfSampleWeights <> Default Then
        _cveInputArrayRelease($iArrSampleWeights)
        If $bSampleWeightsCreate Then
            Call("_cve" & $typeOfSampleWeights & "Release", $sampleWeights)
        EndIf
    EndIf

    If $bSampleIdxIsArray Then
        Call("_VectorOf" & $typeOfSampleIdx & "Release", $vectorSampleIdx)
    EndIf

    If $typeOfSampleIdx <> Default Then
        _cveInputArrayRelease($iArrSampleIdx)
        If $bSampleIdxCreate Then
            Call("_cve" & $typeOfSampleIdx & "Release", $sampleIdx)
        EndIf
    EndIf

    If $bVarIdxIsArray Then
        Call("_VectorOf" & $typeOfVarIdx & "Release", $vectorVarIdx)
    EndIf

    If $typeOfVarIdx <> Default Then
        _cveInputArrayRelease($iArrVarIdx)
        If $bVarIdxCreate Then
            Call("_cve" & $typeOfVarIdx & "Release", $varIdx)
        EndIf
    EndIf

    If $bResponsesIsArray Then
        Call("_VectorOf" & $typeOfResponses & "Release", $vectorResponses)
    EndIf

    If $typeOfResponses <> Default Then
        _cveInputArrayRelease($iArrResponses)
        If $bResponsesCreate Then
            Call("_cve" & $typeOfResponses & "Release", $responses)
        EndIf
    EndIf

    If $bSamplesIsArray Then
        Call("_VectorOf" & $typeOfSamples & "Release", $vectorSamples)
    EndIf

    If $typeOfSamples <> Default Then
        _cveInputArrayRelease($iArrSamples)
        If $bSamplesCreate Then
            Call("_cve" & $typeOfSamples & "Release", $samples)
        EndIf
    EndIf

    Return $retval
EndFunc   ;==>_cveTrainDataCreateTyped

Func _cveTrainDataCreateMat($samples, $layout, $responses, $varIdx, $sampleIdx, $sampleWeights, $varType, $sharedPtr)
    ; cveTrainDataCreate using cv::Mat instead of _*Array
    Local $retval = _cveTrainDataCreateTyped("Mat", $samples, $layout, "Mat", $responses, "Mat", $varIdx, "Mat", $sampleIdx, "Mat", $sampleWeights, "Mat", $varType, $sharedPtr)

    Return $retval
EndFunc   ;==>_cveTrainDataCreateMat

Func _cveTrainDataRelease($sharedPtr)
    ; CVAPI(void) cveTrainDataRelease(cv::Ptr<cv::ml::TrainData>** sharedPtr);

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveTrainDataRelease", $sSharedPtrDllType, $sharedPtr), "cveTrainDataRelease", @error)
EndFunc   ;==>_cveTrainDataRelease

Func _cveNormalBayesClassifierDefaultCreate($statModel, $algorithm, $sharedPtr)
    ; CVAPI(cv::ml::NormalBayesClassifier*) cveNormalBayesClassifierDefaultCreate(cv::ml::StatModel** statModel, cv::Algorithm** algorithm, cv::Ptr<cv::ml::NormalBayesClassifier>** sharedPtr);

    Local $sStatModelDllType
    If IsDllStruct($statModel) Then
        $sStatModelDllType = "struct*"
    ElseIf $statModel == Null Then
        $sStatModelDllType = "ptr"
    Else
        $sStatModelDllType = "ptr*"
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
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveNormalBayesClassifierDefaultCreate", $sStatModelDllType, $statModel, $sAlgorithmDllType, $algorithm, $sSharedPtrDllType, $sharedPtr), "cveNormalBayesClassifierDefaultCreate", @error)
EndFunc   ;==>_cveNormalBayesClassifierDefaultCreate

Func _cveNormalBayesClassifierRelease($classifier, $sharedPtr)
    ; CVAPI(void) cveNormalBayesClassifierRelease(cv::ml::NormalBayesClassifier** classifier, cv::Ptr<cv::ml::NormalBayesClassifier>** sharedPtr);

    Local $sClassifierDllType
    If IsDllStruct($classifier) Then
        $sClassifierDllType = "struct*"
    ElseIf $classifier == Null Then
        $sClassifierDllType = "ptr"
    Else
        $sClassifierDllType = "ptr*"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveNormalBayesClassifierRelease", $sClassifierDllType, $classifier, $sSharedPtrDllType, $sharedPtr), "cveNormalBayesClassifierRelease", @error)
EndFunc   ;==>_cveNormalBayesClassifierRelease

Func _cveKNearestCreate($statModel, $algorithm, $sharedPtr)
    ; CVAPI(cv::ml::KNearest*) cveKNearestCreate(cv::ml::StatModel** statModel, cv::Algorithm** algorithm, cv::Ptr<cv::ml::KNearest>** sharedPtr);

    Local $sStatModelDllType
    If IsDllStruct($statModel) Then
        $sStatModelDllType = "struct*"
    ElseIf $statModel == Null Then
        $sStatModelDllType = "ptr"
    Else
        $sStatModelDllType = "ptr*"
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
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveKNearestCreate", $sStatModelDllType, $statModel, $sAlgorithmDllType, $algorithm, $sSharedPtrDllType, $sharedPtr), "cveKNearestCreate", @error)
EndFunc   ;==>_cveKNearestCreate

Func _cveKNearestRelease($sharedPtr)
    ; CVAPI(void) cveKNearestRelease(cv::Ptr<cv::ml::KNearest>** sharedPtr);

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveKNearestRelease", $sSharedPtrDllType, $sharedPtr), "cveKNearestRelease", @error)
EndFunc   ;==>_cveKNearestRelease

Func _cveKNearestFindNearest($classifier, $samples, $k, $results, $neighborResponses, $dist)
    ; CVAPI(float) cveKNearestFindNearest(cv::ml::KNearest* classifier, cv::_InputArray* samples, int k, cv::_OutputArray* results, cv::_OutputArray* neighborResponses, cv::_OutputArray* dist);

    Local $sClassifierDllType
    If IsDllStruct($classifier) Then
        $sClassifierDllType = "struct*"
    Else
        $sClassifierDllType = "ptr"
    EndIf

    Local $sSamplesDllType
    If IsDllStruct($samples) Then
        $sSamplesDllType = "struct*"
    Else
        $sSamplesDllType = "ptr"
    EndIf

    Local $sResultsDllType
    If IsDllStruct($results) Then
        $sResultsDllType = "struct*"
    Else
        $sResultsDllType = "ptr"
    EndIf

    Local $sNeighborResponsesDllType
    If IsDllStruct($neighborResponses) Then
        $sNeighborResponsesDllType = "struct*"
    Else
        $sNeighborResponsesDllType = "ptr"
    EndIf

    Local $sDistDllType
    If IsDllStruct($dist) Then
        $sDistDllType = "struct*"
    Else
        $sDistDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cveKNearestFindNearest", $sClassifierDllType, $classifier, $sSamplesDllType, $samples, "int", $k, $sResultsDllType, $results, $sNeighborResponsesDllType, $neighborResponses, $sDistDllType, $dist), "cveKNearestFindNearest", @error)
EndFunc   ;==>_cveKNearestFindNearest

Func _cveKNearestFindNearestTyped($classifier, $typeOfSamples, $samples, $k, $typeOfResults, $results, $typeOfNeighborResponses, $neighborResponses, $typeOfDist, $dist)

    Local $iArrSamples, $vectorSamples, $iArrSamplesSize
    Local $bSamplesIsArray = IsArray($samples)
    Local $bSamplesCreate = IsDllStruct($samples) And $typeOfSamples == "Scalar"

    If $typeOfSamples == Default Then
        $iArrSamples = $samples
    ElseIf $bSamplesIsArray Then
        $vectorSamples = Call("_VectorOf" & $typeOfSamples & "Create")

        $iArrSamplesSize = UBound($samples)
        For $i = 0 To $iArrSamplesSize - 1
            Call("_VectorOf" & $typeOfSamples & "Push", $vectorSamples, $samples[$i])
        Next

        $iArrSamples = Call("_cveInputArrayFromVectorOf" & $typeOfSamples, $vectorSamples)
    Else
        If $bSamplesCreate Then
            $samples = Call("_cve" & $typeOfSamples & "Create", $samples)
        EndIf
        $iArrSamples = Call("_cveInputArrayFrom" & $typeOfSamples, $samples)
    EndIf

    Local $oArrResults, $vectorResults, $iArrResultsSize
    Local $bResultsIsArray = IsArray($results)
    Local $bResultsCreate = IsDllStruct($results) And $typeOfResults == "Scalar"

    If $typeOfResults == Default Then
        $oArrResults = $results
    ElseIf $bResultsIsArray Then
        $vectorResults = Call("_VectorOf" & $typeOfResults & "Create")

        $iArrResultsSize = UBound($results)
        For $i = 0 To $iArrResultsSize - 1
            Call("_VectorOf" & $typeOfResults & "Push", $vectorResults, $results[$i])
        Next

        $oArrResults = Call("_cveOutputArrayFromVectorOf" & $typeOfResults, $vectorResults)
    Else
        If $bResultsCreate Then
            $results = Call("_cve" & $typeOfResults & "Create", $results)
        EndIf
        $oArrResults = Call("_cveOutputArrayFrom" & $typeOfResults, $results)
    EndIf

    Local $oArrNeighborResponses, $vectorNeighborResponses, $iArrNeighborResponsesSize
    Local $bNeighborResponsesIsArray = IsArray($neighborResponses)
    Local $bNeighborResponsesCreate = IsDllStruct($neighborResponses) And $typeOfNeighborResponses == "Scalar"

    If $typeOfNeighborResponses == Default Then
        $oArrNeighborResponses = $neighborResponses
    ElseIf $bNeighborResponsesIsArray Then
        $vectorNeighborResponses = Call("_VectorOf" & $typeOfNeighborResponses & "Create")

        $iArrNeighborResponsesSize = UBound($neighborResponses)
        For $i = 0 To $iArrNeighborResponsesSize - 1
            Call("_VectorOf" & $typeOfNeighborResponses & "Push", $vectorNeighborResponses, $neighborResponses[$i])
        Next

        $oArrNeighborResponses = Call("_cveOutputArrayFromVectorOf" & $typeOfNeighborResponses, $vectorNeighborResponses)
    Else
        If $bNeighborResponsesCreate Then
            $neighborResponses = Call("_cve" & $typeOfNeighborResponses & "Create", $neighborResponses)
        EndIf
        $oArrNeighborResponses = Call("_cveOutputArrayFrom" & $typeOfNeighborResponses, $neighborResponses)
    EndIf

    Local $oArrDist, $vectorDist, $iArrDistSize
    Local $bDistIsArray = IsArray($dist)
    Local $bDistCreate = IsDllStruct($dist) And $typeOfDist == "Scalar"

    If $typeOfDist == Default Then
        $oArrDist = $dist
    ElseIf $bDistIsArray Then
        $vectorDist = Call("_VectorOf" & $typeOfDist & "Create")

        $iArrDistSize = UBound($dist)
        For $i = 0 To $iArrDistSize - 1
            Call("_VectorOf" & $typeOfDist & "Push", $vectorDist, $dist[$i])
        Next

        $oArrDist = Call("_cveOutputArrayFromVectorOf" & $typeOfDist, $vectorDist)
    Else
        If $bDistCreate Then
            $dist = Call("_cve" & $typeOfDist & "Create", $dist)
        EndIf
        $oArrDist = Call("_cveOutputArrayFrom" & $typeOfDist, $dist)
    EndIf

    Local $retval = _cveKNearestFindNearest($classifier, $iArrSamples, $k, $oArrResults, $oArrNeighborResponses, $oArrDist)

    If $bDistIsArray Then
        Call("_VectorOf" & $typeOfDist & "Release", $vectorDist)
    EndIf

    If $typeOfDist <> Default Then
        _cveOutputArrayRelease($oArrDist)
        If $bDistCreate Then
            Call("_cve" & $typeOfDist & "Release", $dist)
        EndIf
    EndIf

    If $bNeighborResponsesIsArray Then
        Call("_VectorOf" & $typeOfNeighborResponses & "Release", $vectorNeighborResponses)
    EndIf

    If $typeOfNeighborResponses <> Default Then
        _cveOutputArrayRelease($oArrNeighborResponses)
        If $bNeighborResponsesCreate Then
            Call("_cve" & $typeOfNeighborResponses & "Release", $neighborResponses)
        EndIf
    EndIf

    If $bResultsIsArray Then
        Call("_VectorOf" & $typeOfResults & "Release", $vectorResults)
    EndIf

    If $typeOfResults <> Default Then
        _cveOutputArrayRelease($oArrResults)
        If $bResultsCreate Then
            Call("_cve" & $typeOfResults & "Release", $results)
        EndIf
    EndIf

    If $bSamplesIsArray Then
        Call("_VectorOf" & $typeOfSamples & "Release", $vectorSamples)
    EndIf

    If $typeOfSamples <> Default Then
        _cveInputArrayRelease($iArrSamples)
        If $bSamplesCreate Then
            Call("_cve" & $typeOfSamples & "Release", $samples)
        EndIf
    EndIf

    Return $retval
EndFunc   ;==>_cveKNearestFindNearestTyped

Func _cveKNearestFindNearestMat($classifier, $samples, $k, $results, $neighborResponses, $dist)
    ; cveKNearestFindNearest using cv::Mat instead of _*Array
    Local $retval = _cveKNearestFindNearestTyped($classifier, "Mat", $samples, $k, "Mat", $results, "Mat", $neighborResponses, "Mat", $dist)

    Return $retval
EndFunc   ;==>_cveKNearestFindNearestMat

Func _cveEMDefaultCreate($statModel, $algorithm, $sharedPtr)
    ; CVAPI(cv::ml::EM*) cveEMDefaultCreate(cv::ml::StatModel** statModel, cv::Algorithm** algorithm, cv::Ptr<cv::ml::EM>** sharedPtr);

    Local $sStatModelDllType
    If IsDllStruct($statModel) Then
        $sStatModelDllType = "struct*"
    ElseIf $statModel == Null Then
        $sStatModelDllType = "ptr"
    Else
        $sStatModelDllType = "ptr*"
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
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveEMDefaultCreate", $sStatModelDllType, $statModel, $sAlgorithmDllType, $algorithm, $sSharedPtrDllType, $sharedPtr), "cveEMDefaultCreate", @error)
EndFunc   ;==>_cveEMDefaultCreate

Func _cveEMTrainE($model, $samples, $means0, $covs0, $weights0, $logLikelihoods, $labels, $probs, $statModel, $algorithm)
    ; CVAPI(void) cveEMTrainE(cv::ml::EM* model, cv::_InputArray* samples, cv::_InputArray* means0, cv::_InputArray* covs0, cv::_InputArray* weights0, cv::_OutputArray* logLikelihoods, cv::_OutputArray* labels, cv::_OutputArray* probs, cv::ml::StatModel** statModel, cv::Algorithm** algorithm);

    Local $sModelDllType
    If IsDllStruct($model) Then
        $sModelDllType = "struct*"
    Else
        $sModelDllType = "ptr"
    EndIf

    Local $sSamplesDllType
    If IsDllStruct($samples) Then
        $sSamplesDllType = "struct*"
    Else
        $sSamplesDllType = "ptr"
    EndIf

    Local $sMeans0DllType
    If IsDllStruct($means0) Then
        $sMeans0DllType = "struct*"
    Else
        $sMeans0DllType = "ptr"
    EndIf

    Local $sCovs0DllType
    If IsDllStruct($covs0) Then
        $sCovs0DllType = "struct*"
    Else
        $sCovs0DllType = "ptr"
    EndIf

    Local $sWeights0DllType
    If IsDllStruct($weights0) Then
        $sWeights0DllType = "struct*"
    Else
        $sWeights0DllType = "ptr"
    EndIf

    Local $sLogLikelihoodsDllType
    If IsDllStruct($logLikelihoods) Then
        $sLogLikelihoodsDllType = "struct*"
    Else
        $sLogLikelihoodsDllType = "ptr"
    EndIf

    Local $sLabelsDllType
    If IsDllStruct($labels) Then
        $sLabelsDllType = "struct*"
    Else
        $sLabelsDllType = "ptr"
    EndIf

    Local $sProbsDllType
    If IsDllStruct($probs) Then
        $sProbsDllType = "struct*"
    Else
        $sProbsDllType = "ptr"
    EndIf

    Local $sStatModelDllType
    If IsDllStruct($statModel) Then
        $sStatModelDllType = "struct*"
    ElseIf $statModel == Null Then
        $sStatModelDllType = "ptr"
    Else
        $sStatModelDllType = "ptr*"
    EndIf

    Local $sAlgorithmDllType
    If IsDllStruct($algorithm) Then
        $sAlgorithmDllType = "struct*"
    ElseIf $algorithm == Null Then
        $sAlgorithmDllType = "ptr"
    Else
        $sAlgorithmDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveEMTrainE", $sModelDllType, $model, $sSamplesDllType, $samples, $sMeans0DllType, $means0, $sCovs0DllType, $covs0, $sWeights0DllType, $weights0, $sLogLikelihoodsDllType, $logLikelihoods, $sLabelsDllType, $labels, $sProbsDllType, $probs, $sStatModelDllType, $statModel, $sAlgorithmDllType, $algorithm), "cveEMTrainE", @error)
EndFunc   ;==>_cveEMTrainE

Func _cveEMTrainETyped($model, $typeOfSamples, $samples, $typeOfMeans0, $means0, $typeOfCovs0, $covs0, $typeOfWeights0, $weights0, $typeOfLogLikelihoods, $logLikelihoods, $typeOfLabels, $labels, $typeOfProbs, $probs, $statModel, $algorithm)

    Local $iArrSamples, $vectorSamples, $iArrSamplesSize
    Local $bSamplesIsArray = IsArray($samples)
    Local $bSamplesCreate = IsDllStruct($samples) And $typeOfSamples == "Scalar"

    If $typeOfSamples == Default Then
        $iArrSamples = $samples
    ElseIf $bSamplesIsArray Then
        $vectorSamples = Call("_VectorOf" & $typeOfSamples & "Create")

        $iArrSamplesSize = UBound($samples)
        For $i = 0 To $iArrSamplesSize - 1
            Call("_VectorOf" & $typeOfSamples & "Push", $vectorSamples, $samples[$i])
        Next

        $iArrSamples = Call("_cveInputArrayFromVectorOf" & $typeOfSamples, $vectorSamples)
    Else
        If $bSamplesCreate Then
            $samples = Call("_cve" & $typeOfSamples & "Create", $samples)
        EndIf
        $iArrSamples = Call("_cveInputArrayFrom" & $typeOfSamples, $samples)
    EndIf

    Local $iArrMeans0, $vectorMeans0, $iArrMeans0Size
    Local $bMeans0IsArray = IsArray($means0)
    Local $bMeans0Create = IsDllStruct($means0) And $typeOfMeans0 == "Scalar"

    If $typeOfMeans0 == Default Then
        $iArrMeans0 = $means0
    ElseIf $bMeans0IsArray Then
        $vectorMeans0 = Call("_VectorOf" & $typeOfMeans0 & "Create")

        $iArrMeans0Size = UBound($means0)
        For $i = 0 To $iArrMeans0Size - 1
            Call("_VectorOf" & $typeOfMeans0 & "Push", $vectorMeans0, $means0[$i])
        Next

        $iArrMeans0 = Call("_cveInputArrayFromVectorOf" & $typeOfMeans0, $vectorMeans0)
    Else
        If $bMeans0Create Then
            $means0 = Call("_cve" & $typeOfMeans0 & "Create", $means0)
        EndIf
        $iArrMeans0 = Call("_cveInputArrayFrom" & $typeOfMeans0, $means0)
    EndIf

    Local $iArrCovs0, $vectorCovs0, $iArrCovs0Size
    Local $bCovs0IsArray = IsArray($covs0)
    Local $bCovs0Create = IsDllStruct($covs0) And $typeOfCovs0 == "Scalar"

    If $typeOfCovs0 == Default Then
        $iArrCovs0 = $covs0
    ElseIf $bCovs0IsArray Then
        $vectorCovs0 = Call("_VectorOf" & $typeOfCovs0 & "Create")

        $iArrCovs0Size = UBound($covs0)
        For $i = 0 To $iArrCovs0Size - 1
            Call("_VectorOf" & $typeOfCovs0 & "Push", $vectorCovs0, $covs0[$i])
        Next

        $iArrCovs0 = Call("_cveInputArrayFromVectorOf" & $typeOfCovs0, $vectorCovs0)
    Else
        If $bCovs0Create Then
            $covs0 = Call("_cve" & $typeOfCovs0 & "Create", $covs0)
        EndIf
        $iArrCovs0 = Call("_cveInputArrayFrom" & $typeOfCovs0, $covs0)
    EndIf

    Local $iArrWeights0, $vectorWeights0, $iArrWeights0Size
    Local $bWeights0IsArray = IsArray($weights0)
    Local $bWeights0Create = IsDllStruct($weights0) And $typeOfWeights0 == "Scalar"

    If $typeOfWeights0 == Default Then
        $iArrWeights0 = $weights0
    ElseIf $bWeights0IsArray Then
        $vectorWeights0 = Call("_VectorOf" & $typeOfWeights0 & "Create")

        $iArrWeights0Size = UBound($weights0)
        For $i = 0 To $iArrWeights0Size - 1
            Call("_VectorOf" & $typeOfWeights0 & "Push", $vectorWeights0, $weights0[$i])
        Next

        $iArrWeights0 = Call("_cveInputArrayFromVectorOf" & $typeOfWeights0, $vectorWeights0)
    Else
        If $bWeights0Create Then
            $weights0 = Call("_cve" & $typeOfWeights0 & "Create", $weights0)
        EndIf
        $iArrWeights0 = Call("_cveInputArrayFrom" & $typeOfWeights0, $weights0)
    EndIf

    Local $oArrLogLikelihoods, $vectorLogLikelihoods, $iArrLogLikelihoodsSize
    Local $bLogLikelihoodsIsArray = IsArray($logLikelihoods)
    Local $bLogLikelihoodsCreate = IsDllStruct($logLikelihoods) And $typeOfLogLikelihoods == "Scalar"

    If $typeOfLogLikelihoods == Default Then
        $oArrLogLikelihoods = $logLikelihoods
    ElseIf $bLogLikelihoodsIsArray Then
        $vectorLogLikelihoods = Call("_VectorOf" & $typeOfLogLikelihoods & "Create")

        $iArrLogLikelihoodsSize = UBound($logLikelihoods)
        For $i = 0 To $iArrLogLikelihoodsSize - 1
            Call("_VectorOf" & $typeOfLogLikelihoods & "Push", $vectorLogLikelihoods, $logLikelihoods[$i])
        Next

        $oArrLogLikelihoods = Call("_cveOutputArrayFromVectorOf" & $typeOfLogLikelihoods, $vectorLogLikelihoods)
    Else
        If $bLogLikelihoodsCreate Then
            $logLikelihoods = Call("_cve" & $typeOfLogLikelihoods & "Create", $logLikelihoods)
        EndIf
        $oArrLogLikelihoods = Call("_cveOutputArrayFrom" & $typeOfLogLikelihoods, $logLikelihoods)
    EndIf

    Local $oArrLabels, $vectorLabels, $iArrLabelsSize
    Local $bLabelsIsArray = IsArray($labels)
    Local $bLabelsCreate = IsDllStruct($labels) And $typeOfLabels == "Scalar"

    If $typeOfLabels == Default Then
        $oArrLabels = $labels
    ElseIf $bLabelsIsArray Then
        $vectorLabels = Call("_VectorOf" & $typeOfLabels & "Create")

        $iArrLabelsSize = UBound($labels)
        For $i = 0 To $iArrLabelsSize - 1
            Call("_VectorOf" & $typeOfLabels & "Push", $vectorLabels, $labels[$i])
        Next

        $oArrLabels = Call("_cveOutputArrayFromVectorOf" & $typeOfLabels, $vectorLabels)
    Else
        If $bLabelsCreate Then
            $labels = Call("_cve" & $typeOfLabels & "Create", $labels)
        EndIf
        $oArrLabels = Call("_cveOutputArrayFrom" & $typeOfLabels, $labels)
    EndIf

    Local $oArrProbs, $vectorProbs, $iArrProbsSize
    Local $bProbsIsArray = IsArray($probs)
    Local $bProbsCreate = IsDllStruct($probs) And $typeOfProbs == "Scalar"

    If $typeOfProbs == Default Then
        $oArrProbs = $probs
    ElseIf $bProbsIsArray Then
        $vectorProbs = Call("_VectorOf" & $typeOfProbs & "Create")

        $iArrProbsSize = UBound($probs)
        For $i = 0 To $iArrProbsSize - 1
            Call("_VectorOf" & $typeOfProbs & "Push", $vectorProbs, $probs[$i])
        Next

        $oArrProbs = Call("_cveOutputArrayFromVectorOf" & $typeOfProbs, $vectorProbs)
    Else
        If $bProbsCreate Then
            $probs = Call("_cve" & $typeOfProbs & "Create", $probs)
        EndIf
        $oArrProbs = Call("_cveOutputArrayFrom" & $typeOfProbs, $probs)
    EndIf

    _cveEMTrainE($model, $iArrSamples, $iArrMeans0, $iArrCovs0, $iArrWeights0, $oArrLogLikelihoods, $oArrLabels, $oArrProbs, $statModel, $algorithm)

    If $bProbsIsArray Then
        Call("_VectorOf" & $typeOfProbs & "Release", $vectorProbs)
    EndIf

    If $typeOfProbs <> Default Then
        _cveOutputArrayRelease($oArrProbs)
        If $bProbsCreate Then
            Call("_cve" & $typeOfProbs & "Release", $probs)
        EndIf
    EndIf

    If $bLabelsIsArray Then
        Call("_VectorOf" & $typeOfLabels & "Release", $vectorLabels)
    EndIf

    If $typeOfLabels <> Default Then
        _cveOutputArrayRelease($oArrLabels)
        If $bLabelsCreate Then
            Call("_cve" & $typeOfLabels & "Release", $labels)
        EndIf
    EndIf

    If $bLogLikelihoodsIsArray Then
        Call("_VectorOf" & $typeOfLogLikelihoods & "Release", $vectorLogLikelihoods)
    EndIf

    If $typeOfLogLikelihoods <> Default Then
        _cveOutputArrayRelease($oArrLogLikelihoods)
        If $bLogLikelihoodsCreate Then
            Call("_cve" & $typeOfLogLikelihoods & "Release", $logLikelihoods)
        EndIf
    EndIf

    If $bWeights0IsArray Then
        Call("_VectorOf" & $typeOfWeights0 & "Release", $vectorWeights0)
    EndIf

    If $typeOfWeights0 <> Default Then
        _cveInputArrayRelease($iArrWeights0)
        If $bWeights0Create Then
            Call("_cve" & $typeOfWeights0 & "Release", $weights0)
        EndIf
    EndIf

    If $bCovs0IsArray Then
        Call("_VectorOf" & $typeOfCovs0 & "Release", $vectorCovs0)
    EndIf

    If $typeOfCovs0 <> Default Then
        _cveInputArrayRelease($iArrCovs0)
        If $bCovs0Create Then
            Call("_cve" & $typeOfCovs0 & "Release", $covs0)
        EndIf
    EndIf

    If $bMeans0IsArray Then
        Call("_VectorOf" & $typeOfMeans0 & "Release", $vectorMeans0)
    EndIf

    If $typeOfMeans0 <> Default Then
        _cveInputArrayRelease($iArrMeans0)
        If $bMeans0Create Then
            Call("_cve" & $typeOfMeans0 & "Release", $means0)
        EndIf
    EndIf

    If $bSamplesIsArray Then
        Call("_VectorOf" & $typeOfSamples & "Release", $vectorSamples)
    EndIf

    If $typeOfSamples <> Default Then
        _cveInputArrayRelease($iArrSamples)
        If $bSamplesCreate Then
            Call("_cve" & $typeOfSamples & "Release", $samples)
        EndIf
    EndIf
EndFunc   ;==>_cveEMTrainETyped

Func _cveEMTrainEMat($model, $samples, $means0, $covs0, $weights0, $logLikelihoods, $labels, $probs, $statModel, $algorithm)
    ; cveEMTrainE using cv::Mat instead of _*Array
    _cveEMTrainETyped($model, "Mat", $samples, "Mat", $means0, "Mat", $covs0, "Mat", $weights0, "Mat", $logLikelihoods, "Mat", $labels, "Mat", $probs, $statModel, $algorithm)
EndFunc   ;==>_cveEMTrainEMat

Func _cveEMTrainM($model, $samples, $probs0, $logLikelihoods, $labels, $probs, $statModel, $algorithm)
    ; CVAPI(void) cveEMTrainM(cv::ml::EM* model, cv::_InputArray* samples, cv::_InputArray* probs0, cv::_OutputArray* logLikelihoods, cv::_OutputArray* labels, cv::_OutputArray* probs, cv::ml::StatModel** statModel, cv::Algorithm** algorithm);

    Local $sModelDllType
    If IsDllStruct($model) Then
        $sModelDllType = "struct*"
    Else
        $sModelDllType = "ptr"
    EndIf

    Local $sSamplesDllType
    If IsDllStruct($samples) Then
        $sSamplesDllType = "struct*"
    Else
        $sSamplesDllType = "ptr"
    EndIf

    Local $sProbs0DllType
    If IsDllStruct($probs0) Then
        $sProbs0DllType = "struct*"
    Else
        $sProbs0DllType = "ptr"
    EndIf

    Local $sLogLikelihoodsDllType
    If IsDllStruct($logLikelihoods) Then
        $sLogLikelihoodsDllType = "struct*"
    Else
        $sLogLikelihoodsDllType = "ptr"
    EndIf

    Local $sLabelsDllType
    If IsDllStruct($labels) Then
        $sLabelsDllType = "struct*"
    Else
        $sLabelsDllType = "ptr"
    EndIf

    Local $sProbsDllType
    If IsDllStruct($probs) Then
        $sProbsDllType = "struct*"
    Else
        $sProbsDllType = "ptr"
    EndIf

    Local $sStatModelDllType
    If IsDllStruct($statModel) Then
        $sStatModelDllType = "struct*"
    ElseIf $statModel == Null Then
        $sStatModelDllType = "ptr"
    Else
        $sStatModelDllType = "ptr*"
    EndIf

    Local $sAlgorithmDllType
    If IsDllStruct($algorithm) Then
        $sAlgorithmDllType = "struct*"
    ElseIf $algorithm == Null Then
        $sAlgorithmDllType = "ptr"
    Else
        $sAlgorithmDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveEMTrainM", $sModelDllType, $model, $sSamplesDllType, $samples, $sProbs0DllType, $probs0, $sLogLikelihoodsDllType, $logLikelihoods, $sLabelsDllType, $labels, $sProbsDllType, $probs, $sStatModelDllType, $statModel, $sAlgorithmDllType, $algorithm), "cveEMTrainM", @error)
EndFunc   ;==>_cveEMTrainM

Func _cveEMTrainMTyped($model, $typeOfSamples, $samples, $typeOfProbs0, $probs0, $typeOfLogLikelihoods, $logLikelihoods, $typeOfLabels, $labels, $typeOfProbs, $probs, $statModel, $algorithm)

    Local $iArrSamples, $vectorSamples, $iArrSamplesSize
    Local $bSamplesIsArray = IsArray($samples)
    Local $bSamplesCreate = IsDllStruct($samples) And $typeOfSamples == "Scalar"

    If $typeOfSamples == Default Then
        $iArrSamples = $samples
    ElseIf $bSamplesIsArray Then
        $vectorSamples = Call("_VectorOf" & $typeOfSamples & "Create")

        $iArrSamplesSize = UBound($samples)
        For $i = 0 To $iArrSamplesSize - 1
            Call("_VectorOf" & $typeOfSamples & "Push", $vectorSamples, $samples[$i])
        Next

        $iArrSamples = Call("_cveInputArrayFromVectorOf" & $typeOfSamples, $vectorSamples)
    Else
        If $bSamplesCreate Then
            $samples = Call("_cve" & $typeOfSamples & "Create", $samples)
        EndIf
        $iArrSamples = Call("_cveInputArrayFrom" & $typeOfSamples, $samples)
    EndIf

    Local $iArrProbs0, $vectorProbs0, $iArrProbs0Size
    Local $bProbs0IsArray = IsArray($probs0)
    Local $bProbs0Create = IsDllStruct($probs0) And $typeOfProbs0 == "Scalar"

    If $typeOfProbs0 == Default Then
        $iArrProbs0 = $probs0
    ElseIf $bProbs0IsArray Then
        $vectorProbs0 = Call("_VectorOf" & $typeOfProbs0 & "Create")

        $iArrProbs0Size = UBound($probs0)
        For $i = 0 To $iArrProbs0Size - 1
            Call("_VectorOf" & $typeOfProbs0 & "Push", $vectorProbs0, $probs0[$i])
        Next

        $iArrProbs0 = Call("_cveInputArrayFromVectorOf" & $typeOfProbs0, $vectorProbs0)
    Else
        If $bProbs0Create Then
            $probs0 = Call("_cve" & $typeOfProbs0 & "Create", $probs0)
        EndIf
        $iArrProbs0 = Call("_cveInputArrayFrom" & $typeOfProbs0, $probs0)
    EndIf

    Local $oArrLogLikelihoods, $vectorLogLikelihoods, $iArrLogLikelihoodsSize
    Local $bLogLikelihoodsIsArray = IsArray($logLikelihoods)
    Local $bLogLikelihoodsCreate = IsDllStruct($logLikelihoods) And $typeOfLogLikelihoods == "Scalar"

    If $typeOfLogLikelihoods == Default Then
        $oArrLogLikelihoods = $logLikelihoods
    ElseIf $bLogLikelihoodsIsArray Then
        $vectorLogLikelihoods = Call("_VectorOf" & $typeOfLogLikelihoods & "Create")

        $iArrLogLikelihoodsSize = UBound($logLikelihoods)
        For $i = 0 To $iArrLogLikelihoodsSize - 1
            Call("_VectorOf" & $typeOfLogLikelihoods & "Push", $vectorLogLikelihoods, $logLikelihoods[$i])
        Next

        $oArrLogLikelihoods = Call("_cveOutputArrayFromVectorOf" & $typeOfLogLikelihoods, $vectorLogLikelihoods)
    Else
        If $bLogLikelihoodsCreate Then
            $logLikelihoods = Call("_cve" & $typeOfLogLikelihoods & "Create", $logLikelihoods)
        EndIf
        $oArrLogLikelihoods = Call("_cveOutputArrayFrom" & $typeOfLogLikelihoods, $logLikelihoods)
    EndIf

    Local $oArrLabels, $vectorLabels, $iArrLabelsSize
    Local $bLabelsIsArray = IsArray($labels)
    Local $bLabelsCreate = IsDllStruct($labels) And $typeOfLabels == "Scalar"

    If $typeOfLabels == Default Then
        $oArrLabels = $labels
    ElseIf $bLabelsIsArray Then
        $vectorLabels = Call("_VectorOf" & $typeOfLabels & "Create")

        $iArrLabelsSize = UBound($labels)
        For $i = 0 To $iArrLabelsSize - 1
            Call("_VectorOf" & $typeOfLabels & "Push", $vectorLabels, $labels[$i])
        Next

        $oArrLabels = Call("_cveOutputArrayFromVectorOf" & $typeOfLabels, $vectorLabels)
    Else
        If $bLabelsCreate Then
            $labels = Call("_cve" & $typeOfLabels & "Create", $labels)
        EndIf
        $oArrLabels = Call("_cveOutputArrayFrom" & $typeOfLabels, $labels)
    EndIf

    Local $oArrProbs, $vectorProbs, $iArrProbsSize
    Local $bProbsIsArray = IsArray($probs)
    Local $bProbsCreate = IsDllStruct($probs) And $typeOfProbs == "Scalar"

    If $typeOfProbs == Default Then
        $oArrProbs = $probs
    ElseIf $bProbsIsArray Then
        $vectorProbs = Call("_VectorOf" & $typeOfProbs & "Create")

        $iArrProbsSize = UBound($probs)
        For $i = 0 To $iArrProbsSize - 1
            Call("_VectorOf" & $typeOfProbs & "Push", $vectorProbs, $probs[$i])
        Next

        $oArrProbs = Call("_cveOutputArrayFromVectorOf" & $typeOfProbs, $vectorProbs)
    Else
        If $bProbsCreate Then
            $probs = Call("_cve" & $typeOfProbs & "Create", $probs)
        EndIf
        $oArrProbs = Call("_cveOutputArrayFrom" & $typeOfProbs, $probs)
    EndIf

    _cveEMTrainM($model, $iArrSamples, $iArrProbs0, $oArrLogLikelihoods, $oArrLabels, $oArrProbs, $statModel, $algorithm)

    If $bProbsIsArray Then
        Call("_VectorOf" & $typeOfProbs & "Release", $vectorProbs)
    EndIf

    If $typeOfProbs <> Default Then
        _cveOutputArrayRelease($oArrProbs)
        If $bProbsCreate Then
            Call("_cve" & $typeOfProbs & "Release", $probs)
        EndIf
    EndIf

    If $bLabelsIsArray Then
        Call("_VectorOf" & $typeOfLabels & "Release", $vectorLabels)
    EndIf

    If $typeOfLabels <> Default Then
        _cveOutputArrayRelease($oArrLabels)
        If $bLabelsCreate Then
            Call("_cve" & $typeOfLabels & "Release", $labels)
        EndIf
    EndIf

    If $bLogLikelihoodsIsArray Then
        Call("_VectorOf" & $typeOfLogLikelihoods & "Release", $vectorLogLikelihoods)
    EndIf

    If $typeOfLogLikelihoods <> Default Then
        _cveOutputArrayRelease($oArrLogLikelihoods)
        If $bLogLikelihoodsCreate Then
            Call("_cve" & $typeOfLogLikelihoods & "Release", $logLikelihoods)
        EndIf
    EndIf

    If $bProbs0IsArray Then
        Call("_VectorOf" & $typeOfProbs0 & "Release", $vectorProbs0)
    EndIf

    If $typeOfProbs0 <> Default Then
        _cveInputArrayRelease($iArrProbs0)
        If $bProbs0Create Then
            Call("_cve" & $typeOfProbs0 & "Release", $probs0)
        EndIf
    EndIf

    If $bSamplesIsArray Then
        Call("_VectorOf" & $typeOfSamples & "Release", $vectorSamples)
    EndIf

    If $typeOfSamples <> Default Then
        _cveInputArrayRelease($iArrSamples)
        If $bSamplesCreate Then
            Call("_cve" & $typeOfSamples & "Release", $samples)
        EndIf
    EndIf
EndFunc   ;==>_cveEMTrainMTyped

Func _cveEMTrainMMat($model, $samples, $probs0, $logLikelihoods, $labels, $probs, $statModel, $algorithm)
    ; cveEMTrainM using cv::Mat instead of _*Array
    _cveEMTrainMTyped($model, "Mat", $samples, "Mat", $probs0, "Mat", $logLikelihoods, "Mat", $labels, "Mat", $probs, $statModel, $algorithm)
EndFunc   ;==>_cveEMTrainMMat

Func _cveEMPredict($model, $sample, $result, $probs)
    ; CVAPI(void) cveEMPredict(cv::ml::EM* model, cv::_InputArray* sample, CvPoint2D64f* result, cv::_OutputArray* probs);

    Local $sModelDllType
    If IsDllStruct($model) Then
        $sModelDllType = "struct*"
    Else
        $sModelDllType = "ptr"
    EndIf

    Local $sSampleDllType
    If IsDllStruct($sample) Then
        $sSampleDllType = "struct*"
    Else
        $sSampleDllType = "ptr"
    EndIf

    Local $sResultDllType
    If IsDllStruct($result) Then
        $sResultDllType = "struct*"
    Else
        $sResultDllType = "ptr"
    EndIf

    Local $sProbsDllType
    If IsDllStruct($probs) Then
        $sProbsDllType = "struct*"
    Else
        $sProbsDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveEMPredict", $sModelDllType, $model, $sSampleDllType, $sample, $sResultDllType, $result, $sProbsDllType, $probs), "cveEMPredict", @error)
EndFunc   ;==>_cveEMPredict

Func _cveEMPredictTyped($model, $typeOfSample, $sample, $result, $typeOfProbs, $probs)

    Local $iArrSample, $vectorSample, $iArrSampleSize
    Local $bSampleIsArray = IsArray($sample)
    Local $bSampleCreate = IsDllStruct($sample) And $typeOfSample == "Scalar"

    If $typeOfSample == Default Then
        $iArrSample = $sample
    ElseIf $bSampleIsArray Then
        $vectorSample = Call("_VectorOf" & $typeOfSample & "Create")

        $iArrSampleSize = UBound($sample)
        For $i = 0 To $iArrSampleSize - 1
            Call("_VectorOf" & $typeOfSample & "Push", $vectorSample, $sample[$i])
        Next

        $iArrSample = Call("_cveInputArrayFromVectorOf" & $typeOfSample, $vectorSample)
    Else
        If $bSampleCreate Then
            $sample = Call("_cve" & $typeOfSample & "Create", $sample)
        EndIf
        $iArrSample = Call("_cveInputArrayFrom" & $typeOfSample, $sample)
    EndIf

    Local $oArrProbs, $vectorProbs, $iArrProbsSize
    Local $bProbsIsArray = IsArray($probs)
    Local $bProbsCreate = IsDllStruct($probs) And $typeOfProbs == "Scalar"

    If $typeOfProbs == Default Then
        $oArrProbs = $probs
    ElseIf $bProbsIsArray Then
        $vectorProbs = Call("_VectorOf" & $typeOfProbs & "Create")

        $iArrProbsSize = UBound($probs)
        For $i = 0 To $iArrProbsSize - 1
            Call("_VectorOf" & $typeOfProbs & "Push", $vectorProbs, $probs[$i])
        Next

        $oArrProbs = Call("_cveOutputArrayFromVectorOf" & $typeOfProbs, $vectorProbs)
    Else
        If $bProbsCreate Then
            $probs = Call("_cve" & $typeOfProbs & "Create", $probs)
        EndIf
        $oArrProbs = Call("_cveOutputArrayFrom" & $typeOfProbs, $probs)
    EndIf

    _cveEMPredict($model, $iArrSample, $result, $oArrProbs)

    If $bProbsIsArray Then
        Call("_VectorOf" & $typeOfProbs & "Release", $vectorProbs)
    EndIf

    If $typeOfProbs <> Default Then
        _cveOutputArrayRelease($oArrProbs)
        If $bProbsCreate Then
            Call("_cve" & $typeOfProbs & "Release", $probs)
        EndIf
    EndIf

    If $bSampleIsArray Then
        Call("_VectorOf" & $typeOfSample & "Release", $vectorSample)
    EndIf

    If $typeOfSample <> Default Then
        _cveInputArrayRelease($iArrSample)
        If $bSampleCreate Then
            Call("_cve" & $typeOfSample & "Release", $sample)
        EndIf
    EndIf
EndFunc   ;==>_cveEMPredictTyped

Func _cveEMPredictMat($model, $sample, $result, $probs)
    ; cveEMPredict using cv::Mat instead of _*Array
    _cveEMPredictTyped($model, "Mat", $sample, $result, "Mat", $probs)
EndFunc   ;==>_cveEMPredictMat

Func _cveEMRelease($model, $sharedPtr)
    ; CVAPI(void) cveEMRelease(cv::ml::EM** model, cv::Ptr<cv::ml::EM>** sharedPtr);

    Local $sModelDllType
    If IsDllStruct($model) Then
        $sModelDllType = "struct*"
    ElseIf $model == Null Then
        $sModelDllType = "ptr"
    Else
        $sModelDllType = "ptr*"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveEMRelease", $sModelDllType, $model, $sSharedPtrDllType, $sharedPtr), "cveEMRelease", @error)
EndFunc   ;==>_cveEMRelease

Func _cveSVMDefaultCreate($model, $algorithm, $sharedPtr)
    ; CVAPI(cv::ml::SVM*) cveSVMDefaultCreate(cv::ml::StatModel** model, cv::Algorithm** algorithm, cv::Ptr<cv::ml::SVM>** sharedPtr);

    Local $sModelDllType
    If IsDllStruct($model) Then
        $sModelDllType = "struct*"
    ElseIf $model == Null Then
        $sModelDllType = "ptr"
    Else
        $sModelDllType = "ptr*"
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
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveSVMDefaultCreate", $sModelDllType, $model, $sAlgorithmDllType, $algorithm, $sSharedPtrDllType, $sharedPtr), "cveSVMDefaultCreate", @error)
EndFunc   ;==>_cveSVMDefaultCreate

Func _cveSVMTrainAuto($model, $trainData, $kFold, $CGrid, $gammaGrid, $pGrid, $nuGrid, $coefGrid, $degreeGrid, $balanced)
    ; CVAPI(bool) cveSVMTrainAuto(cv::ml::SVM* model, cv::ml::TrainData* trainData, int kFold, cv::ml::ParamGrid* CGrid, cv::ml::ParamGrid* gammaGrid, cv::ml::ParamGrid* pGrid, cv::ml::ParamGrid* nuGrid, cv::ml::ParamGrid* coefGrid, cv::ml::ParamGrid* degreeGrid, bool balanced);

    Local $sModelDllType
    If IsDllStruct($model) Then
        $sModelDllType = "struct*"
    Else
        $sModelDllType = "ptr"
    EndIf

    Local $sTrainDataDllType
    If IsDllStruct($trainData) Then
        $sTrainDataDllType = "struct*"
    Else
        $sTrainDataDllType = "ptr"
    EndIf

    Local $sCGridDllType
    If IsDllStruct($CGrid) Then
        $sCGridDllType = "struct*"
    Else
        $sCGridDllType = "ptr"
    EndIf

    Local $sGammaGridDllType
    If IsDllStruct($gammaGrid) Then
        $sGammaGridDllType = "struct*"
    Else
        $sGammaGridDllType = "ptr"
    EndIf

    Local $sPGridDllType
    If IsDllStruct($pGrid) Then
        $sPGridDllType = "struct*"
    Else
        $sPGridDllType = "ptr"
    EndIf

    Local $sNuGridDllType
    If IsDllStruct($nuGrid) Then
        $sNuGridDllType = "struct*"
    Else
        $sNuGridDllType = "ptr"
    EndIf

    Local $sCoefGridDllType
    If IsDllStruct($coefGrid) Then
        $sCoefGridDllType = "struct*"
    Else
        $sCoefGridDllType = "ptr"
    EndIf

    Local $sDegreeGridDllType
    If IsDllStruct($degreeGrid) Then
        $sDegreeGridDllType = "struct*"
    Else
        $sDegreeGridDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveSVMTrainAuto", $sModelDllType, $model, $sTrainDataDllType, $trainData, "int", $kFold, $sCGridDllType, $CGrid, $sGammaGridDllType, $gammaGrid, $sPGridDllType, $pGrid, $sNuGridDllType, $nuGrid, $sCoefGridDllType, $coefGrid, $sDegreeGridDllType, $degreeGrid, "boolean", $balanced), "cveSVMTrainAuto", @error)
EndFunc   ;==>_cveSVMTrainAuto

Func _cveSVMGetDefaultGrid($gridType, $grid)
    ; CVAPI(void) cveSVMGetDefaultGrid(int gridType, cv::ml::ParamGrid* grid);

    Local $sGridDllType
    If IsDllStruct($grid) Then
        $sGridDllType = "struct*"
    Else
        $sGridDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSVMGetDefaultGrid", "int", $gridType, $sGridDllType, $grid), "cveSVMGetDefaultGrid", @error)
EndFunc   ;==>_cveSVMGetDefaultGrid

Func _cveSVMRelease($model, $sharedPtr)
    ; CVAPI(void) cveSVMRelease(cv::ml::SVM** model, cv::Ptr<cv::ml::SVM>** sharedPtr);

    Local $sModelDllType
    If IsDllStruct($model) Then
        $sModelDllType = "struct*"
    ElseIf $model == Null Then
        $sModelDllType = "ptr"
    Else
        $sModelDllType = "ptr*"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSVMRelease", $sModelDllType, $model, $sSharedPtrDllType, $sharedPtr), "cveSVMRelease", @error)
EndFunc   ;==>_cveSVMRelease

Func _cveSVMGetSupportVectors($model, $supportVectors)
    ; CVAPI(void) cveSVMGetSupportVectors(cv::ml::SVM* model, cv::Mat* supportVectors);

    Local $sModelDllType
    If IsDllStruct($model) Then
        $sModelDllType = "struct*"
    Else
        $sModelDllType = "ptr"
    EndIf

    Local $sSupportVectorsDllType
    If IsDllStruct($supportVectors) Then
        $sSupportVectorsDllType = "struct*"
    Else
        $sSupportVectorsDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSVMGetSupportVectors", $sModelDllType, $model, $sSupportVectorsDllType, $supportVectors), "cveSVMGetSupportVectors", @error)
EndFunc   ;==>_cveSVMGetSupportVectors

Func _cveANN_MLPCreate($model, $algorithm, $sharedPtr)
    ; CVAPI(cv::ml::ANN_MLP*) cveANN_MLPCreate(cv::ml::StatModel** model, cv::Algorithm** algorithm, cv::Ptr<cv::ml::ANN_MLP>** sharedPtr);

    Local $sModelDllType
    If IsDllStruct($model) Then
        $sModelDllType = "struct*"
    ElseIf $model == Null Then
        $sModelDllType = "ptr"
    Else
        $sModelDllType = "ptr*"
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
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveANN_MLPCreate", $sModelDllType, $model, $sAlgorithmDllType, $algorithm, $sSharedPtrDllType, $sharedPtr), "cveANN_MLPCreate", @error)
EndFunc   ;==>_cveANN_MLPCreate

Func _cveANN_MLPSetLayerSizes($model, $layerSizes)
    ; CVAPI(void) cveANN_MLPSetLayerSizes(cv::ml::ANN_MLP* model, cv::_InputArray* layerSizes);

    Local $sModelDllType
    If IsDllStruct($model) Then
        $sModelDllType = "struct*"
    Else
        $sModelDllType = "ptr"
    EndIf

    Local $sLayerSizesDllType
    If IsDllStruct($layerSizes) Then
        $sLayerSizesDllType = "struct*"
    Else
        $sLayerSizesDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveANN_MLPSetLayerSizes", $sModelDllType, $model, $sLayerSizesDllType, $layerSizes), "cveANN_MLPSetLayerSizes", @error)
EndFunc   ;==>_cveANN_MLPSetLayerSizes

Func _cveANN_MLPSetLayerSizesTyped($model, $typeOfLayerSizes, $layerSizes)

    Local $iArrLayerSizes, $vectorLayerSizes, $iArrLayerSizesSize
    Local $bLayerSizesIsArray = IsArray($layerSizes)
    Local $bLayerSizesCreate = IsDllStruct($layerSizes) And $typeOfLayerSizes == "Scalar"

    If $typeOfLayerSizes == Default Then
        $iArrLayerSizes = $layerSizes
    ElseIf $bLayerSizesIsArray Then
        $vectorLayerSizes = Call("_VectorOf" & $typeOfLayerSizes & "Create")

        $iArrLayerSizesSize = UBound($layerSizes)
        For $i = 0 To $iArrLayerSizesSize - 1
            Call("_VectorOf" & $typeOfLayerSizes & "Push", $vectorLayerSizes, $layerSizes[$i])
        Next

        $iArrLayerSizes = Call("_cveInputArrayFromVectorOf" & $typeOfLayerSizes, $vectorLayerSizes)
    Else
        If $bLayerSizesCreate Then
            $layerSizes = Call("_cve" & $typeOfLayerSizes & "Create", $layerSizes)
        EndIf
        $iArrLayerSizes = Call("_cveInputArrayFrom" & $typeOfLayerSizes, $layerSizes)
    EndIf

    _cveANN_MLPSetLayerSizes($model, $iArrLayerSizes)

    If $bLayerSizesIsArray Then
        Call("_VectorOf" & $typeOfLayerSizes & "Release", $vectorLayerSizes)
    EndIf

    If $typeOfLayerSizes <> Default Then
        _cveInputArrayRelease($iArrLayerSizes)
        If $bLayerSizesCreate Then
            Call("_cve" & $typeOfLayerSizes & "Release", $layerSizes)
        EndIf
    EndIf
EndFunc   ;==>_cveANN_MLPSetLayerSizesTyped

Func _cveANN_MLPSetLayerSizesMat($model, $layerSizes)
    ; cveANN_MLPSetLayerSizes using cv::Mat instead of _*Array
    _cveANN_MLPSetLayerSizesTyped($model, "Mat", $layerSizes)
EndFunc   ;==>_cveANN_MLPSetLayerSizesMat

Func _cveANN_MLPSetActivationFunction($model, $type, $param1, $param2)
    ; CVAPI(void) cveANN_MLPSetActivationFunction(cv::ml::ANN_MLP* model, int type, double param1, double param2);

    Local $sModelDllType
    If IsDllStruct($model) Then
        $sModelDllType = "struct*"
    Else
        $sModelDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveANN_MLPSetActivationFunction", $sModelDllType, $model, "int", $type, "double", $param1, "double", $param2), "cveANN_MLPSetActivationFunction", @error)
EndFunc   ;==>_cveANN_MLPSetActivationFunction

Func _cveANN_MLPSetTrainMethod($model, $method, $param1, $param2)
    ; CVAPI(void) cveANN_MLPSetTrainMethod(cv::ml::ANN_MLP* model, int method, double param1, double param2);

    Local $sModelDllType
    If IsDllStruct($model) Then
        $sModelDllType = "struct*"
    Else
        $sModelDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveANN_MLPSetTrainMethod", $sModelDllType, $model, "int", $method, "double", $param1, "double", $param2), "cveANN_MLPSetTrainMethod", @error)
EndFunc   ;==>_cveANN_MLPSetTrainMethod

Func _cveANN_MLPRelease($model, $sharedPtr)
    ; CVAPI(void) cveANN_MLPRelease(cv::ml::ANN_MLP** model, cv::Ptr<cv::ml::ANN_MLP>** sharedPtr);

    Local $sModelDllType
    If IsDllStruct($model) Then
        $sModelDllType = "struct*"
    ElseIf $model == Null Then
        $sModelDllType = "ptr"
    Else
        $sModelDllType = "ptr*"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveANN_MLPRelease", $sModelDllType, $model, $sSharedPtrDllType, $sharedPtr), "cveANN_MLPRelease", @error)
EndFunc   ;==>_cveANN_MLPRelease

Func _cveDTreesCreate($statModel, $algorithm, $sharedPtr)
    ; CVAPI(cv::ml::DTrees*) cveDTreesCreate(cv::ml::StatModel** statModel, cv::Algorithm** algorithm, cv::Ptr<cv::ml::DTrees>** sharedPtr);

    Local $sStatModelDllType
    If IsDllStruct($statModel) Then
        $sStatModelDllType = "struct*"
    ElseIf $statModel == Null Then
        $sStatModelDllType = "ptr"
    Else
        $sStatModelDllType = "ptr*"
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
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveDTreesCreate", $sStatModelDllType, $statModel, $sAlgorithmDllType, $algorithm, $sSharedPtrDllType, $sharedPtr), "cveDTreesCreate", @error)
EndFunc   ;==>_cveDTreesCreate

Func _cveDTreesRelease($model, $sharedPtr)
    ; CVAPI(void) cveDTreesRelease(cv::ml::DTrees** model, cv::Ptr<cv::ml::DTrees>** sharedPtr);

    Local $sModelDllType
    If IsDllStruct($model) Then
        $sModelDllType = "struct*"
    ElseIf $model == Null Then
        $sModelDllType = "ptr"
    Else
        $sModelDllType = "ptr*"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDTreesRelease", $sModelDllType, $model, $sSharedPtrDllType, $sharedPtr), "cveDTreesRelease", @error)
EndFunc   ;==>_cveDTreesRelease

Func _cveRTreesCreate($statModel, $algorithm, $sharedPtr)
    ; CVAPI(cv::ml::RTrees*) cveRTreesCreate(cv::ml::StatModel** statModel, cv::Algorithm** algorithm, cv::Ptr<cv::ml::RTrees>** sharedPtr);

    Local $sStatModelDllType
    If IsDllStruct($statModel) Then
        $sStatModelDllType = "struct*"
    ElseIf $statModel == Null Then
        $sStatModelDllType = "ptr"
    Else
        $sStatModelDllType = "ptr*"
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
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveRTreesCreate", $sStatModelDllType, $statModel, $sAlgorithmDllType, $algorithm, $sSharedPtrDllType, $sharedPtr), "cveRTreesCreate", @error)
EndFunc   ;==>_cveRTreesCreate

Func _cveRTreesGetVotes($model, $samples, $results, $flags)
    ; CVAPI(void) cveRTreesGetVotes(cv::ml::RTrees* model, cv::_InputArray* samples, cv::_OutputArray* results, int flags);

    Local $sModelDllType
    If IsDllStruct($model) Then
        $sModelDllType = "struct*"
    Else
        $sModelDllType = "ptr"
    EndIf

    Local $sSamplesDllType
    If IsDllStruct($samples) Then
        $sSamplesDllType = "struct*"
    Else
        $sSamplesDllType = "ptr"
    EndIf

    Local $sResultsDllType
    If IsDllStruct($results) Then
        $sResultsDllType = "struct*"
    Else
        $sResultsDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveRTreesGetVotes", $sModelDllType, $model, $sSamplesDllType, $samples, $sResultsDllType, $results, "int", $flags), "cveRTreesGetVotes", @error)
EndFunc   ;==>_cveRTreesGetVotes

Func _cveRTreesGetVotesTyped($model, $typeOfSamples, $samples, $typeOfResults, $results, $flags)

    Local $iArrSamples, $vectorSamples, $iArrSamplesSize
    Local $bSamplesIsArray = IsArray($samples)
    Local $bSamplesCreate = IsDllStruct($samples) And $typeOfSamples == "Scalar"

    If $typeOfSamples == Default Then
        $iArrSamples = $samples
    ElseIf $bSamplesIsArray Then
        $vectorSamples = Call("_VectorOf" & $typeOfSamples & "Create")

        $iArrSamplesSize = UBound($samples)
        For $i = 0 To $iArrSamplesSize - 1
            Call("_VectorOf" & $typeOfSamples & "Push", $vectorSamples, $samples[$i])
        Next

        $iArrSamples = Call("_cveInputArrayFromVectorOf" & $typeOfSamples, $vectorSamples)
    Else
        If $bSamplesCreate Then
            $samples = Call("_cve" & $typeOfSamples & "Create", $samples)
        EndIf
        $iArrSamples = Call("_cveInputArrayFrom" & $typeOfSamples, $samples)
    EndIf

    Local $oArrResults, $vectorResults, $iArrResultsSize
    Local $bResultsIsArray = IsArray($results)
    Local $bResultsCreate = IsDllStruct($results) And $typeOfResults == "Scalar"

    If $typeOfResults == Default Then
        $oArrResults = $results
    ElseIf $bResultsIsArray Then
        $vectorResults = Call("_VectorOf" & $typeOfResults & "Create")

        $iArrResultsSize = UBound($results)
        For $i = 0 To $iArrResultsSize - 1
            Call("_VectorOf" & $typeOfResults & "Push", $vectorResults, $results[$i])
        Next

        $oArrResults = Call("_cveOutputArrayFromVectorOf" & $typeOfResults, $vectorResults)
    Else
        If $bResultsCreate Then
            $results = Call("_cve" & $typeOfResults & "Create", $results)
        EndIf
        $oArrResults = Call("_cveOutputArrayFrom" & $typeOfResults, $results)
    EndIf

    _cveRTreesGetVotes($model, $iArrSamples, $oArrResults, $flags)

    If $bResultsIsArray Then
        Call("_VectorOf" & $typeOfResults & "Release", $vectorResults)
    EndIf

    If $typeOfResults <> Default Then
        _cveOutputArrayRelease($oArrResults)
        If $bResultsCreate Then
            Call("_cve" & $typeOfResults & "Release", $results)
        EndIf
    EndIf

    If $bSamplesIsArray Then
        Call("_VectorOf" & $typeOfSamples & "Release", $vectorSamples)
    EndIf

    If $typeOfSamples <> Default Then
        _cveInputArrayRelease($iArrSamples)
        If $bSamplesCreate Then
            Call("_cve" & $typeOfSamples & "Release", $samples)
        EndIf
    EndIf
EndFunc   ;==>_cveRTreesGetVotesTyped

Func _cveRTreesGetVotesMat($model, $samples, $results, $flags)
    ; cveRTreesGetVotes using cv::Mat instead of _*Array
    _cveRTreesGetVotesTyped($model, "Mat", $samples, "Mat", $results, $flags)
EndFunc   ;==>_cveRTreesGetVotesMat

Func _cveRTreesRelease($model, $sharedPtr)
    ; CVAPI(void) cveRTreesRelease(cv::ml::RTrees** model, cv::Ptr<cv::ml::RTrees>** sharedPtr);

    Local $sModelDllType
    If IsDllStruct($model) Then
        $sModelDllType = "struct*"
    ElseIf $model == Null Then
        $sModelDllType = "ptr"
    Else
        $sModelDllType = "ptr*"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveRTreesRelease", $sModelDllType, $model, $sSharedPtrDllType, $sharedPtr), "cveRTreesRelease", @error)
EndFunc   ;==>_cveRTreesRelease

Func _cveBoostCreate($statModel, $algorithm, $sharedPtr)
    ; CVAPI(cv::ml::Boost*) cveBoostCreate(cv::ml::StatModel** statModel, cv::Algorithm** algorithm, cv::Ptr<cv::ml::Boost>** sharedPtr);

    Local $sStatModelDllType
    If IsDllStruct($statModel) Then
        $sStatModelDllType = "struct*"
    ElseIf $statModel == Null Then
        $sStatModelDllType = "ptr"
    Else
        $sStatModelDllType = "ptr*"
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
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveBoostCreate", $sStatModelDllType, $statModel, $sAlgorithmDllType, $algorithm, $sSharedPtrDllType, $sharedPtr), "cveBoostCreate", @error)
EndFunc   ;==>_cveBoostCreate

Func _cveBoostRelease($model, $sharedPtr)
    ; CVAPI(void) cveBoostRelease(cv::ml::Boost** model, cv::Ptr<cv::ml::Boost>** sharedPtr);

    Local $sModelDllType
    If IsDllStruct($model) Then
        $sModelDllType = "struct*"
    ElseIf $model == Null Then
        $sModelDllType = "ptr"
    Else
        $sModelDllType = "ptr*"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBoostRelease", $sModelDllType, $model, $sSharedPtrDllType, $sharedPtr), "cveBoostRelease", @error)
EndFunc   ;==>_cveBoostRelease

Func _cveLogisticRegressionCreate($statModel, $algorithm, $sharedPtr)
    ; CVAPI(cv::ml::LogisticRegression*) cveLogisticRegressionCreate(cv::ml::StatModel** statModel, cv::Algorithm** algorithm, cv::Ptr<cv::ml::LogisticRegression>** sharedPtr);

    Local $sStatModelDllType
    If IsDllStruct($statModel) Then
        $sStatModelDllType = "struct*"
    ElseIf $statModel == Null Then
        $sStatModelDllType = "ptr"
    Else
        $sStatModelDllType = "ptr*"
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
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveLogisticRegressionCreate", $sStatModelDllType, $statModel, $sAlgorithmDllType, $algorithm, $sSharedPtrDllType, $sharedPtr), "cveLogisticRegressionCreate", @error)
EndFunc   ;==>_cveLogisticRegressionCreate

Func _cveLogisticRegressionRelease($model, $sharedPtr)
    ; CVAPI(void) cveLogisticRegressionRelease(cv::ml::LogisticRegression** model, cv::Ptr<cv::ml::LogisticRegression>** sharedPtr);

    Local $sModelDllType
    If IsDllStruct($model) Then
        $sModelDllType = "struct*"
    ElseIf $model == Null Then
        $sModelDllType = "ptr"
    Else
        $sModelDllType = "ptr*"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveLogisticRegressionRelease", $sModelDllType, $model, $sSharedPtrDllType, $sharedPtr), "cveLogisticRegressionRelease", @error)
EndFunc   ;==>_cveLogisticRegressionRelease

Func _cveSVMSGDDefaultCreate($model, $algorithm, $sharedPtr)
    ; CVAPI(cv::ml::SVMSGD*) cveSVMSGDDefaultCreate(cv::ml::StatModel** model, cv::Algorithm** algorithm, cv::Ptr<cv::ml::SVMSGD>** sharedPtr);

    Local $sModelDllType
    If IsDllStruct($model) Then
        $sModelDllType = "struct*"
    ElseIf $model == Null Then
        $sModelDllType = "ptr"
    Else
        $sModelDllType = "ptr*"
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
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveSVMSGDDefaultCreate", $sModelDllType, $model, $sAlgorithmDllType, $algorithm, $sSharedPtrDllType, $sharedPtr), "cveSVMSGDDefaultCreate", @error)
EndFunc   ;==>_cveSVMSGDDefaultCreate

Func _cveSVMSGDRelease($model, $sharedPtr)
    ; CVAPI(void) cveSVMSGDRelease(cv::ml::SVMSGD** model, cv::Ptr<cv::ml::SVMSGD>** sharedPtr);

    Local $sModelDllType
    If IsDllStruct($model) Then
        $sModelDllType = "struct*"
    ElseIf $model == Null Then
        $sModelDllType = "ptr"
    Else
        $sModelDllType = "ptr*"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSVMSGDRelease", $sModelDllType, $model, $sSharedPtrDllType, $sharedPtr), "cveSVMSGDRelease", @error)
EndFunc   ;==>_cveSVMSGDRelease

Func _cveSVMSGDSetOptimalParameters($model, $svmsgdType, $marginType)
    ; CVAPI(void) cveSVMSGDSetOptimalParameters(cv::ml::SVMSGD* model, int svmsgdType, int marginType);

    Local $sModelDllType
    If IsDllStruct($model) Then
        $sModelDllType = "struct*"
    Else
        $sModelDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSVMSGDSetOptimalParameters", $sModelDllType, $model, "int", $svmsgdType, "int", $marginType), "cveSVMSGDSetOptimalParameters", @error)
EndFunc   ;==>_cveSVMSGDSetOptimalParameters