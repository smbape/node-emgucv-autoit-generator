#include-once
#include "..\..\CVEUtils.au3"

Func _StatModelTrain($model, $samples, $layout, $responses)
    ; CVAPI(bool) StatModelTrain(cv::ml::StatModel* model, cv::_InputArray* samples, int layout, cv::_InputArray* responses);

    Local $bModelDllType
    If VarGetType($model) == "DLLStruct" Then
        $bModelDllType = "struct*"
    Else
        $bModelDllType = "ptr"
    EndIf

    Local $bSamplesDllType
    If VarGetType($samples) == "DLLStruct" Then
        $bSamplesDllType = "struct*"
    Else
        $bSamplesDllType = "ptr"
    EndIf

    Local $bResponsesDllType
    If VarGetType($responses) == "DLLStruct" Then
        $bResponsesDllType = "struct*"
    Else
        $bResponsesDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "StatModelTrain", $bModelDllType, $model, $bSamplesDllType, $samples, "int", $layout, $bResponsesDllType, $responses), "StatModelTrain", @error)
EndFunc   ;==>_StatModelTrain

Func _StatModelTrainMat($model, $matSamples, $layout, $matResponses)
    ; StatModelTrain using cv::Mat instead of _*Array

    Local $iArrSamples, $vectorOfMatSamples, $iArrSamplesSize
    Local $bSamplesIsArray = VarGetType($matSamples) == "Array"

    If $bSamplesIsArray Then
        $vectorOfMatSamples = _VectorOfMatCreate()

        $iArrSamplesSize = UBound($matSamples)
        For $i = 0 To $iArrSamplesSize - 1
            _VectorOfMatPush($vectorOfMatSamples, $matSamples[$i])
        Next

        $iArrSamples = _cveInputArrayFromVectorOfMat($vectorOfMatSamples)
    Else
        $iArrSamples = _cveInputArrayFromMat($matSamples)
    EndIf

    Local $iArrResponses, $vectorOfMatResponses, $iArrResponsesSize
    Local $bResponsesIsArray = VarGetType($matResponses) == "Array"

    If $bResponsesIsArray Then
        $vectorOfMatResponses = _VectorOfMatCreate()

        $iArrResponsesSize = UBound($matResponses)
        For $i = 0 To $iArrResponsesSize - 1
            _VectorOfMatPush($vectorOfMatResponses, $matResponses[$i])
        Next

        $iArrResponses = _cveInputArrayFromVectorOfMat($vectorOfMatResponses)
    Else
        $iArrResponses = _cveInputArrayFromMat($matResponses)
    EndIf

    Local $retval = _StatModelTrain($model, $iArrSamples, $layout, $iArrResponses)

    If $bResponsesIsArray Then
        _VectorOfMatRelease($vectorOfMatResponses)
    EndIf

    _cveInputArrayRelease($iArrResponses)

    If $bSamplesIsArray Then
        _VectorOfMatRelease($vectorOfMatSamples)
    EndIf

    _cveInputArrayRelease($iArrSamples)

    Return $retval
EndFunc   ;==>_StatModelTrainMat

Func _StatModelTrainWithData($model, $data, $flags)
    ; CVAPI(bool) StatModelTrainWithData(cv::ml::StatModel* model, cv::ml::TrainData* data, int flags);

    Local $bModelDllType
    If VarGetType($model) == "DLLStruct" Then
        $bModelDllType = "struct*"
    Else
        $bModelDllType = "ptr"
    EndIf

    Local $bDataDllType
    If VarGetType($data) == "DLLStruct" Then
        $bDataDllType = "struct*"
    Else
        $bDataDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "StatModelTrainWithData", $bModelDllType, $model, $bDataDllType, $data, "int", $flags), "StatModelTrainWithData", @error)
EndFunc   ;==>_StatModelTrainWithData

Func _StatModelPredict($model, $samples, $results, $flags)
    ; CVAPI(float) StatModelPredict(cv::ml::StatModel* model, cv::_InputArray* samples, cv::_OutputArray* results, int flags);

    Local $bModelDllType
    If VarGetType($model) == "DLLStruct" Then
        $bModelDllType = "struct*"
    Else
        $bModelDllType = "ptr"
    EndIf

    Local $bSamplesDllType
    If VarGetType($samples) == "DLLStruct" Then
        $bSamplesDllType = "struct*"
    Else
        $bSamplesDllType = "ptr"
    EndIf

    Local $bResultsDllType
    If VarGetType($results) == "DLLStruct" Then
        $bResultsDllType = "struct*"
    Else
        $bResultsDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "StatModelPredict", $bModelDllType, $model, $bSamplesDllType, $samples, $bResultsDllType, $results, "int", $flags), "StatModelPredict", @error)
EndFunc   ;==>_StatModelPredict

Func _StatModelPredictMat($model, $matSamples, $matResults, $flags)
    ; StatModelPredict using cv::Mat instead of _*Array

    Local $iArrSamples, $vectorOfMatSamples, $iArrSamplesSize
    Local $bSamplesIsArray = VarGetType($matSamples) == "Array"

    If $bSamplesIsArray Then
        $vectorOfMatSamples = _VectorOfMatCreate()

        $iArrSamplesSize = UBound($matSamples)
        For $i = 0 To $iArrSamplesSize - 1
            _VectorOfMatPush($vectorOfMatSamples, $matSamples[$i])
        Next

        $iArrSamples = _cveInputArrayFromVectorOfMat($vectorOfMatSamples)
    Else
        $iArrSamples = _cveInputArrayFromMat($matSamples)
    EndIf

    Local $oArrResults, $vectorOfMatResults, $iArrResultsSize
    Local $bResultsIsArray = VarGetType($matResults) == "Array"

    If $bResultsIsArray Then
        $vectorOfMatResults = _VectorOfMatCreate()

        $iArrResultsSize = UBound($matResults)
        For $i = 0 To $iArrResultsSize - 1
            _VectorOfMatPush($vectorOfMatResults, $matResults[$i])
        Next

        $oArrResults = _cveOutputArrayFromVectorOfMat($vectorOfMatResults)
    Else
        $oArrResults = _cveOutputArrayFromMat($matResults)
    EndIf

    Local $retval = _StatModelPredict($model, $iArrSamples, $oArrResults, $flags)

    If $bResultsIsArray Then
        _VectorOfMatRelease($vectorOfMatResults)
    EndIf

    _cveOutputArrayRelease($oArrResults)

    If $bSamplesIsArray Then
        _VectorOfMatRelease($vectorOfMatSamples)
    EndIf

    _cveInputArrayRelease($iArrSamples)

    Return $retval
EndFunc   ;==>_StatModelPredictMat

Func _cveTrainDataCreate($samples, $layout, $responses, $varIdx, $sampleIdx, $sampleWeights, $varType, $sharedPtr)
    ; CVAPI(cv::ml::TrainData*) cveTrainDataCreate(cv::_InputArray* samples, int layout, cv::_InputArray* responses, cv::_InputArray* varIdx, cv::_InputArray* sampleIdx, cv::_InputArray* sampleWeights, cv::_InputArray* varType, cv::Ptr<cv::ml::TrainData>** sharedPtr);

    Local $bSamplesDllType
    If VarGetType($samples) == "DLLStruct" Then
        $bSamplesDllType = "struct*"
    Else
        $bSamplesDllType = "ptr"
    EndIf

    Local $bResponsesDllType
    If VarGetType($responses) == "DLLStruct" Then
        $bResponsesDllType = "struct*"
    Else
        $bResponsesDllType = "ptr"
    EndIf

    Local $bVarIdxDllType
    If VarGetType($varIdx) == "DLLStruct" Then
        $bVarIdxDllType = "struct*"
    Else
        $bVarIdxDllType = "ptr"
    EndIf

    Local $bSampleIdxDllType
    If VarGetType($sampleIdx) == "DLLStruct" Then
        $bSampleIdxDllType = "struct*"
    Else
        $bSampleIdxDllType = "ptr"
    EndIf

    Local $bSampleWeightsDllType
    If VarGetType($sampleWeights) == "DLLStruct" Then
        $bSampleWeightsDllType = "struct*"
    Else
        $bSampleWeightsDllType = "ptr"
    EndIf

    Local $bVarTypeDllType
    If VarGetType($varType) == "DLLStruct" Then
        $bVarTypeDllType = "struct*"
    Else
        $bVarTypeDllType = "ptr"
    EndIf

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveTrainDataCreate", $bSamplesDllType, $samples, "int", $layout, $bResponsesDllType, $responses, $bVarIdxDllType, $varIdx, $bSampleIdxDllType, $sampleIdx, $bSampleWeightsDllType, $sampleWeights, $bVarTypeDllType, $varType, $bSharedPtrDllType, $sharedPtr), "cveTrainDataCreate", @error)
EndFunc   ;==>_cveTrainDataCreate

Func _cveTrainDataCreateMat($matSamples, $layout, $matResponses, $matVarIdx, $matSampleIdx, $matSampleWeights, $matVarType, $sharedPtr)
    ; cveTrainDataCreate using cv::Mat instead of _*Array

    Local $iArrSamples, $vectorOfMatSamples, $iArrSamplesSize
    Local $bSamplesIsArray = VarGetType($matSamples) == "Array"

    If $bSamplesIsArray Then
        $vectorOfMatSamples = _VectorOfMatCreate()

        $iArrSamplesSize = UBound($matSamples)
        For $i = 0 To $iArrSamplesSize - 1
            _VectorOfMatPush($vectorOfMatSamples, $matSamples[$i])
        Next

        $iArrSamples = _cveInputArrayFromVectorOfMat($vectorOfMatSamples)
    Else
        $iArrSamples = _cveInputArrayFromMat($matSamples)
    EndIf

    Local $iArrResponses, $vectorOfMatResponses, $iArrResponsesSize
    Local $bResponsesIsArray = VarGetType($matResponses) == "Array"

    If $bResponsesIsArray Then
        $vectorOfMatResponses = _VectorOfMatCreate()

        $iArrResponsesSize = UBound($matResponses)
        For $i = 0 To $iArrResponsesSize - 1
            _VectorOfMatPush($vectorOfMatResponses, $matResponses[$i])
        Next

        $iArrResponses = _cveInputArrayFromVectorOfMat($vectorOfMatResponses)
    Else
        $iArrResponses = _cveInputArrayFromMat($matResponses)
    EndIf

    Local $iArrVarIdx, $vectorOfMatVarIdx, $iArrVarIdxSize
    Local $bVarIdxIsArray = VarGetType($matVarIdx) == "Array"

    If $bVarIdxIsArray Then
        $vectorOfMatVarIdx = _VectorOfMatCreate()

        $iArrVarIdxSize = UBound($matVarIdx)
        For $i = 0 To $iArrVarIdxSize - 1
            _VectorOfMatPush($vectorOfMatVarIdx, $matVarIdx[$i])
        Next

        $iArrVarIdx = _cveInputArrayFromVectorOfMat($vectorOfMatVarIdx)
    Else
        $iArrVarIdx = _cveInputArrayFromMat($matVarIdx)
    EndIf

    Local $iArrSampleIdx, $vectorOfMatSampleIdx, $iArrSampleIdxSize
    Local $bSampleIdxIsArray = VarGetType($matSampleIdx) == "Array"

    If $bSampleIdxIsArray Then
        $vectorOfMatSampleIdx = _VectorOfMatCreate()

        $iArrSampleIdxSize = UBound($matSampleIdx)
        For $i = 0 To $iArrSampleIdxSize - 1
            _VectorOfMatPush($vectorOfMatSampleIdx, $matSampleIdx[$i])
        Next

        $iArrSampleIdx = _cveInputArrayFromVectorOfMat($vectorOfMatSampleIdx)
    Else
        $iArrSampleIdx = _cveInputArrayFromMat($matSampleIdx)
    EndIf

    Local $iArrSampleWeights, $vectorOfMatSampleWeights, $iArrSampleWeightsSize
    Local $bSampleWeightsIsArray = VarGetType($matSampleWeights) == "Array"

    If $bSampleWeightsIsArray Then
        $vectorOfMatSampleWeights = _VectorOfMatCreate()

        $iArrSampleWeightsSize = UBound($matSampleWeights)
        For $i = 0 To $iArrSampleWeightsSize - 1
            _VectorOfMatPush($vectorOfMatSampleWeights, $matSampleWeights[$i])
        Next

        $iArrSampleWeights = _cveInputArrayFromVectorOfMat($vectorOfMatSampleWeights)
    Else
        $iArrSampleWeights = _cveInputArrayFromMat($matSampleWeights)
    EndIf

    Local $iArrVarType, $vectorOfMatVarType, $iArrVarTypeSize
    Local $bVarTypeIsArray = VarGetType($matVarType) == "Array"

    If $bVarTypeIsArray Then
        $vectorOfMatVarType = _VectorOfMatCreate()

        $iArrVarTypeSize = UBound($matVarType)
        For $i = 0 To $iArrVarTypeSize - 1
            _VectorOfMatPush($vectorOfMatVarType, $matVarType[$i])
        Next

        $iArrVarType = _cveInputArrayFromVectorOfMat($vectorOfMatVarType)
    Else
        $iArrVarType = _cveInputArrayFromMat($matVarType)
    EndIf

    Local $retval = _cveTrainDataCreate($iArrSamples, $layout, $iArrResponses, $iArrVarIdx, $iArrSampleIdx, $iArrSampleWeights, $iArrVarType, $sharedPtr)

    If $bVarTypeIsArray Then
        _VectorOfMatRelease($vectorOfMatVarType)
    EndIf

    _cveInputArrayRelease($iArrVarType)

    If $bSampleWeightsIsArray Then
        _VectorOfMatRelease($vectorOfMatSampleWeights)
    EndIf

    _cveInputArrayRelease($iArrSampleWeights)

    If $bSampleIdxIsArray Then
        _VectorOfMatRelease($vectorOfMatSampleIdx)
    EndIf

    _cveInputArrayRelease($iArrSampleIdx)

    If $bVarIdxIsArray Then
        _VectorOfMatRelease($vectorOfMatVarIdx)
    EndIf

    _cveInputArrayRelease($iArrVarIdx)

    If $bResponsesIsArray Then
        _VectorOfMatRelease($vectorOfMatResponses)
    EndIf

    _cveInputArrayRelease($iArrResponses)

    If $bSamplesIsArray Then
        _VectorOfMatRelease($vectorOfMatSamples)
    EndIf

    _cveInputArrayRelease($iArrSamples)

    Return $retval
EndFunc   ;==>_cveTrainDataCreateMat

Func _cveTrainDataRelease($sharedPtr)
    ; CVAPI(void) cveTrainDataRelease(cv::Ptr<cv::ml::TrainData>** sharedPtr);

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveTrainDataRelease", $bSharedPtrDllType, $sharedPtr), "cveTrainDataRelease", @error)
EndFunc   ;==>_cveTrainDataRelease

Func _cveNormalBayesClassifierDefaultCreate($statModel, $algorithm, $sharedPtr)
    ; CVAPI(cv::ml::NormalBayesClassifier*) cveNormalBayesClassifierDefaultCreate(cv::ml::StatModel** statModel, cv::Algorithm** algorithm, cv::Ptr<cv::ml::NormalBayesClassifier>** sharedPtr);

    Local $bStatModelDllType
    If VarGetType($statModel) == "DLLStruct" Then
        $bStatModelDllType = "struct*"
    Else
        $bStatModelDllType = "ptr*"
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
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveNormalBayesClassifierDefaultCreate", $bStatModelDllType, $statModel, $bAlgorithmDllType, $algorithm, $bSharedPtrDllType, $sharedPtr), "cveNormalBayesClassifierDefaultCreate", @error)
EndFunc   ;==>_cveNormalBayesClassifierDefaultCreate

Func _cveNormalBayesClassifierRelease($classifier, $sharedPtr)
    ; CVAPI(void) cveNormalBayesClassifierRelease(cv::ml::NormalBayesClassifier** classifier, cv::Ptr<cv::ml::NormalBayesClassifier>** sharedPtr);

    Local $bClassifierDllType
    If VarGetType($classifier) == "DLLStruct" Then
        $bClassifierDllType = "struct*"
    Else
        $bClassifierDllType = "ptr*"
    EndIf

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveNormalBayesClassifierRelease", $bClassifierDllType, $classifier, $bSharedPtrDllType, $sharedPtr), "cveNormalBayesClassifierRelease", @error)
EndFunc   ;==>_cveNormalBayesClassifierRelease

Func _cveKNearestCreate($statModel, $algorithm, $sharedPtr)
    ; CVAPI(cv::ml::KNearest*) cveKNearestCreate(cv::ml::StatModel** statModel, cv::Algorithm** algorithm, cv::Ptr<cv::ml::KNearest>** sharedPtr);

    Local $bStatModelDllType
    If VarGetType($statModel) == "DLLStruct" Then
        $bStatModelDllType = "struct*"
    Else
        $bStatModelDllType = "ptr*"
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
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveKNearestCreate", $bStatModelDllType, $statModel, $bAlgorithmDllType, $algorithm, $bSharedPtrDllType, $sharedPtr), "cveKNearestCreate", @error)
EndFunc   ;==>_cveKNearestCreate

Func _cveKNearestRelease($sharedPtr)
    ; CVAPI(void) cveKNearestRelease(cv::Ptr<cv::ml::KNearest>** sharedPtr);

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveKNearestRelease", $bSharedPtrDllType, $sharedPtr), "cveKNearestRelease", @error)
EndFunc   ;==>_cveKNearestRelease

Func _cveKNearestFindNearest($classifier, $samples, $k, $results, $neighborResponses, $dist)
    ; CVAPI(float) cveKNearestFindNearest(cv::ml::KNearest* classifier, cv::_InputArray* samples, int k, cv::_OutputArray* results, cv::_OutputArray* neighborResponses, cv::_OutputArray* dist);

    Local $bClassifierDllType
    If VarGetType($classifier) == "DLLStruct" Then
        $bClassifierDllType = "struct*"
    Else
        $bClassifierDllType = "ptr"
    EndIf

    Local $bSamplesDllType
    If VarGetType($samples) == "DLLStruct" Then
        $bSamplesDllType = "struct*"
    Else
        $bSamplesDllType = "ptr"
    EndIf

    Local $bResultsDllType
    If VarGetType($results) == "DLLStruct" Then
        $bResultsDllType = "struct*"
    Else
        $bResultsDllType = "ptr"
    EndIf

    Local $bNeighborResponsesDllType
    If VarGetType($neighborResponses) == "DLLStruct" Then
        $bNeighborResponsesDllType = "struct*"
    Else
        $bNeighborResponsesDllType = "ptr"
    EndIf

    Local $bDistDllType
    If VarGetType($dist) == "DLLStruct" Then
        $bDistDllType = "struct*"
    Else
        $bDistDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cveKNearestFindNearest", $bClassifierDllType, $classifier, $bSamplesDllType, $samples, "int", $k, $bResultsDllType, $results, $bNeighborResponsesDllType, $neighborResponses, $bDistDllType, $dist), "cveKNearestFindNearest", @error)
EndFunc   ;==>_cveKNearestFindNearest

Func _cveKNearestFindNearestMat($classifier, $matSamples, $k, $matResults, $matNeighborResponses, $matDist)
    ; cveKNearestFindNearest using cv::Mat instead of _*Array

    Local $iArrSamples, $vectorOfMatSamples, $iArrSamplesSize
    Local $bSamplesIsArray = VarGetType($matSamples) == "Array"

    If $bSamplesIsArray Then
        $vectorOfMatSamples = _VectorOfMatCreate()

        $iArrSamplesSize = UBound($matSamples)
        For $i = 0 To $iArrSamplesSize - 1
            _VectorOfMatPush($vectorOfMatSamples, $matSamples[$i])
        Next

        $iArrSamples = _cveInputArrayFromVectorOfMat($vectorOfMatSamples)
    Else
        $iArrSamples = _cveInputArrayFromMat($matSamples)
    EndIf

    Local $oArrResults, $vectorOfMatResults, $iArrResultsSize
    Local $bResultsIsArray = VarGetType($matResults) == "Array"

    If $bResultsIsArray Then
        $vectorOfMatResults = _VectorOfMatCreate()

        $iArrResultsSize = UBound($matResults)
        For $i = 0 To $iArrResultsSize - 1
            _VectorOfMatPush($vectorOfMatResults, $matResults[$i])
        Next

        $oArrResults = _cveOutputArrayFromVectorOfMat($vectorOfMatResults)
    Else
        $oArrResults = _cveOutputArrayFromMat($matResults)
    EndIf

    Local $oArrNeighborResponses, $vectorOfMatNeighborResponses, $iArrNeighborResponsesSize
    Local $bNeighborResponsesIsArray = VarGetType($matNeighborResponses) == "Array"

    If $bNeighborResponsesIsArray Then
        $vectorOfMatNeighborResponses = _VectorOfMatCreate()

        $iArrNeighborResponsesSize = UBound($matNeighborResponses)
        For $i = 0 To $iArrNeighborResponsesSize - 1
            _VectorOfMatPush($vectorOfMatNeighborResponses, $matNeighborResponses[$i])
        Next

        $oArrNeighborResponses = _cveOutputArrayFromVectorOfMat($vectorOfMatNeighborResponses)
    Else
        $oArrNeighborResponses = _cveOutputArrayFromMat($matNeighborResponses)
    EndIf

    Local $oArrDist, $vectorOfMatDist, $iArrDistSize
    Local $bDistIsArray = VarGetType($matDist) == "Array"

    If $bDistIsArray Then
        $vectorOfMatDist = _VectorOfMatCreate()

        $iArrDistSize = UBound($matDist)
        For $i = 0 To $iArrDistSize - 1
            _VectorOfMatPush($vectorOfMatDist, $matDist[$i])
        Next

        $oArrDist = _cveOutputArrayFromVectorOfMat($vectorOfMatDist)
    Else
        $oArrDist = _cveOutputArrayFromMat($matDist)
    EndIf

    Local $retval = _cveKNearestFindNearest($classifier, $iArrSamples, $k, $oArrResults, $oArrNeighborResponses, $oArrDist)

    If $bDistIsArray Then
        _VectorOfMatRelease($vectorOfMatDist)
    EndIf

    _cveOutputArrayRelease($oArrDist)

    If $bNeighborResponsesIsArray Then
        _VectorOfMatRelease($vectorOfMatNeighborResponses)
    EndIf

    _cveOutputArrayRelease($oArrNeighborResponses)

    If $bResultsIsArray Then
        _VectorOfMatRelease($vectorOfMatResults)
    EndIf

    _cveOutputArrayRelease($oArrResults)

    If $bSamplesIsArray Then
        _VectorOfMatRelease($vectorOfMatSamples)
    EndIf

    _cveInputArrayRelease($iArrSamples)

    Return $retval
EndFunc   ;==>_cveKNearestFindNearestMat

Func _cveEMDefaultCreate($statModel, $algorithm, $sharedPtr)
    ; CVAPI(cv::ml::EM*) cveEMDefaultCreate(cv::ml::StatModel** statModel, cv::Algorithm** algorithm, cv::Ptr<cv::ml::EM>** sharedPtr);

    Local $bStatModelDllType
    If VarGetType($statModel) == "DLLStruct" Then
        $bStatModelDllType = "struct*"
    Else
        $bStatModelDllType = "ptr*"
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
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveEMDefaultCreate", $bStatModelDllType, $statModel, $bAlgorithmDllType, $algorithm, $bSharedPtrDllType, $sharedPtr), "cveEMDefaultCreate", @error)
EndFunc   ;==>_cveEMDefaultCreate

Func _cveEMTrainE($model, $samples, $means0, $covs0, $weights0, $logLikelihoods, $labels, $probs, $statModel, $algorithm)
    ; CVAPI(void) cveEMTrainE(cv::ml::EM* model, cv::_InputArray* samples, cv::_InputArray* means0, cv::_InputArray* covs0, cv::_InputArray* weights0, cv::_OutputArray* logLikelihoods, cv::_OutputArray* labels, cv::_OutputArray* probs, cv::ml::StatModel** statModel, cv::Algorithm** algorithm);

    Local $bModelDllType
    If VarGetType($model) == "DLLStruct" Then
        $bModelDllType = "struct*"
    Else
        $bModelDllType = "ptr"
    EndIf

    Local $bSamplesDllType
    If VarGetType($samples) == "DLLStruct" Then
        $bSamplesDllType = "struct*"
    Else
        $bSamplesDllType = "ptr"
    EndIf

    Local $bMeans0DllType
    If VarGetType($means0) == "DLLStruct" Then
        $bMeans0DllType = "struct*"
    Else
        $bMeans0DllType = "ptr"
    EndIf

    Local $bCovs0DllType
    If VarGetType($covs0) == "DLLStruct" Then
        $bCovs0DllType = "struct*"
    Else
        $bCovs0DllType = "ptr"
    EndIf

    Local $bWeights0DllType
    If VarGetType($weights0) == "DLLStruct" Then
        $bWeights0DllType = "struct*"
    Else
        $bWeights0DllType = "ptr"
    EndIf

    Local $bLogLikelihoodsDllType
    If VarGetType($logLikelihoods) == "DLLStruct" Then
        $bLogLikelihoodsDllType = "struct*"
    Else
        $bLogLikelihoodsDllType = "ptr"
    EndIf

    Local $bLabelsDllType
    If VarGetType($labels) == "DLLStruct" Then
        $bLabelsDllType = "struct*"
    Else
        $bLabelsDllType = "ptr"
    EndIf

    Local $bProbsDllType
    If VarGetType($probs) == "DLLStruct" Then
        $bProbsDllType = "struct*"
    Else
        $bProbsDllType = "ptr"
    EndIf

    Local $bStatModelDllType
    If VarGetType($statModel) == "DLLStruct" Then
        $bStatModelDllType = "struct*"
    Else
        $bStatModelDllType = "ptr*"
    EndIf

    Local $bAlgorithmDllType
    If VarGetType($algorithm) == "DLLStruct" Then
        $bAlgorithmDllType = "struct*"
    Else
        $bAlgorithmDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveEMTrainE", $bModelDllType, $model, $bSamplesDllType, $samples, $bMeans0DllType, $means0, $bCovs0DllType, $covs0, $bWeights0DllType, $weights0, $bLogLikelihoodsDllType, $logLikelihoods, $bLabelsDllType, $labels, $bProbsDllType, $probs, $bStatModelDllType, $statModel, $bAlgorithmDllType, $algorithm), "cveEMTrainE", @error)
EndFunc   ;==>_cveEMTrainE

Func _cveEMTrainEMat($model, $matSamples, $matMeans0, $matCovs0, $matWeights0, $matLogLikelihoods, $matLabels, $matProbs, $statModel, $algorithm)
    ; cveEMTrainE using cv::Mat instead of _*Array

    Local $iArrSamples, $vectorOfMatSamples, $iArrSamplesSize
    Local $bSamplesIsArray = VarGetType($matSamples) == "Array"

    If $bSamplesIsArray Then
        $vectorOfMatSamples = _VectorOfMatCreate()

        $iArrSamplesSize = UBound($matSamples)
        For $i = 0 To $iArrSamplesSize - 1
            _VectorOfMatPush($vectorOfMatSamples, $matSamples[$i])
        Next

        $iArrSamples = _cveInputArrayFromVectorOfMat($vectorOfMatSamples)
    Else
        $iArrSamples = _cveInputArrayFromMat($matSamples)
    EndIf

    Local $iArrMeans0, $vectorOfMatMeans0, $iArrMeans0Size
    Local $bMeans0IsArray = VarGetType($matMeans0) == "Array"

    If $bMeans0IsArray Then
        $vectorOfMatMeans0 = _VectorOfMatCreate()

        $iArrMeans0Size = UBound($matMeans0)
        For $i = 0 To $iArrMeans0Size - 1
            _VectorOfMatPush($vectorOfMatMeans0, $matMeans0[$i])
        Next

        $iArrMeans0 = _cveInputArrayFromVectorOfMat($vectorOfMatMeans0)
    Else
        $iArrMeans0 = _cveInputArrayFromMat($matMeans0)
    EndIf

    Local $iArrCovs0, $vectorOfMatCovs0, $iArrCovs0Size
    Local $bCovs0IsArray = VarGetType($matCovs0) == "Array"

    If $bCovs0IsArray Then
        $vectorOfMatCovs0 = _VectorOfMatCreate()

        $iArrCovs0Size = UBound($matCovs0)
        For $i = 0 To $iArrCovs0Size - 1
            _VectorOfMatPush($vectorOfMatCovs0, $matCovs0[$i])
        Next

        $iArrCovs0 = _cveInputArrayFromVectorOfMat($vectorOfMatCovs0)
    Else
        $iArrCovs0 = _cveInputArrayFromMat($matCovs0)
    EndIf

    Local $iArrWeights0, $vectorOfMatWeights0, $iArrWeights0Size
    Local $bWeights0IsArray = VarGetType($matWeights0) == "Array"

    If $bWeights0IsArray Then
        $vectorOfMatWeights0 = _VectorOfMatCreate()

        $iArrWeights0Size = UBound($matWeights0)
        For $i = 0 To $iArrWeights0Size - 1
            _VectorOfMatPush($vectorOfMatWeights0, $matWeights0[$i])
        Next

        $iArrWeights0 = _cveInputArrayFromVectorOfMat($vectorOfMatWeights0)
    Else
        $iArrWeights0 = _cveInputArrayFromMat($matWeights0)
    EndIf

    Local $oArrLogLikelihoods, $vectorOfMatLogLikelihoods, $iArrLogLikelihoodsSize
    Local $bLogLikelihoodsIsArray = VarGetType($matLogLikelihoods) == "Array"

    If $bLogLikelihoodsIsArray Then
        $vectorOfMatLogLikelihoods = _VectorOfMatCreate()

        $iArrLogLikelihoodsSize = UBound($matLogLikelihoods)
        For $i = 0 To $iArrLogLikelihoodsSize - 1
            _VectorOfMatPush($vectorOfMatLogLikelihoods, $matLogLikelihoods[$i])
        Next

        $oArrLogLikelihoods = _cveOutputArrayFromVectorOfMat($vectorOfMatLogLikelihoods)
    Else
        $oArrLogLikelihoods = _cveOutputArrayFromMat($matLogLikelihoods)
    EndIf

    Local $oArrLabels, $vectorOfMatLabels, $iArrLabelsSize
    Local $bLabelsIsArray = VarGetType($matLabels) == "Array"

    If $bLabelsIsArray Then
        $vectorOfMatLabels = _VectorOfMatCreate()

        $iArrLabelsSize = UBound($matLabels)
        For $i = 0 To $iArrLabelsSize - 1
            _VectorOfMatPush($vectorOfMatLabels, $matLabels[$i])
        Next

        $oArrLabels = _cveOutputArrayFromVectorOfMat($vectorOfMatLabels)
    Else
        $oArrLabels = _cveOutputArrayFromMat($matLabels)
    EndIf

    Local $oArrProbs, $vectorOfMatProbs, $iArrProbsSize
    Local $bProbsIsArray = VarGetType($matProbs) == "Array"

    If $bProbsIsArray Then
        $vectorOfMatProbs = _VectorOfMatCreate()

        $iArrProbsSize = UBound($matProbs)
        For $i = 0 To $iArrProbsSize - 1
            _VectorOfMatPush($vectorOfMatProbs, $matProbs[$i])
        Next

        $oArrProbs = _cveOutputArrayFromVectorOfMat($vectorOfMatProbs)
    Else
        $oArrProbs = _cveOutputArrayFromMat($matProbs)
    EndIf

    _cveEMTrainE($model, $iArrSamples, $iArrMeans0, $iArrCovs0, $iArrWeights0, $oArrLogLikelihoods, $oArrLabels, $oArrProbs, $statModel, $algorithm)

    If $bProbsIsArray Then
        _VectorOfMatRelease($vectorOfMatProbs)
    EndIf

    _cveOutputArrayRelease($oArrProbs)

    If $bLabelsIsArray Then
        _VectorOfMatRelease($vectorOfMatLabels)
    EndIf

    _cveOutputArrayRelease($oArrLabels)

    If $bLogLikelihoodsIsArray Then
        _VectorOfMatRelease($vectorOfMatLogLikelihoods)
    EndIf

    _cveOutputArrayRelease($oArrLogLikelihoods)

    If $bWeights0IsArray Then
        _VectorOfMatRelease($vectorOfMatWeights0)
    EndIf

    _cveInputArrayRelease($iArrWeights0)

    If $bCovs0IsArray Then
        _VectorOfMatRelease($vectorOfMatCovs0)
    EndIf

    _cveInputArrayRelease($iArrCovs0)

    If $bMeans0IsArray Then
        _VectorOfMatRelease($vectorOfMatMeans0)
    EndIf

    _cveInputArrayRelease($iArrMeans0)

    If $bSamplesIsArray Then
        _VectorOfMatRelease($vectorOfMatSamples)
    EndIf

    _cveInputArrayRelease($iArrSamples)
EndFunc   ;==>_cveEMTrainEMat

Func _cveEMTrainM($model, $samples, $probs0, $logLikelihoods, $labels, $probs, $statModel, $algorithm)
    ; CVAPI(void) cveEMTrainM(cv::ml::EM* model, cv::_InputArray* samples, cv::_InputArray* probs0, cv::_OutputArray* logLikelihoods, cv::_OutputArray* labels, cv::_OutputArray* probs, cv::ml::StatModel** statModel, cv::Algorithm** algorithm);

    Local $bModelDllType
    If VarGetType($model) == "DLLStruct" Then
        $bModelDllType = "struct*"
    Else
        $bModelDllType = "ptr"
    EndIf

    Local $bSamplesDllType
    If VarGetType($samples) == "DLLStruct" Then
        $bSamplesDllType = "struct*"
    Else
        $bSamplesDllType = "ptr"
    EndIf

    Local $bProbs0DllType
    If VarGetType($probs0) == "DLLStruct" Then
        $bProbs0DllType = "struct*"
    Else
        $bProbs0DllType = "ptr"
    EndIf

    Local $bLogLikelihoodsDllType
    If VarGetType($logLikelihoods) == "DLLStruct" Then
        $bLogLikelihoodsDllType = "struct*"
    Else
        $bLogLikelihoodsDllType = "ptr"
    EndIf

    Local $bLabelsDllType
    If VarGetType($labels) == "DLLStruct" Then
        $bLabelsDllType = "struct*"
    Else
        $bLabelsDllType = "ptr"
    EndIf

    Local $bProbsDllType
    If VarGetType($probs) == "DLLStruct" Then
        $bProbsDllType = "struct*"
    Else
        $bProbsDllType = "ptr"
    EndIf

    Local $bStatModelDllType
    If VarGetType($statModel) == "DLLStruct" Then
        $bStatModelDllType = "struct*"
    Else
        $bStatModelDllType = "ptr*"
    EndIf

    Local $bAlgorithmDllType
    If VarGetType($algorithm) == "DLLStruct" Then
        $bAlgorithmDllType = "struct*"
    Else
        $bAlgorithmDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveEMTrainM", $bModelDllType, $model, $bSamplesDllType, $samples, $bProbs0DllType, $probs0, $bLogLikelihoodsDllType, $logLikelihoods, $bLabelsDllType, $labels, $bProbsDllType, $probs, $bStatModelDllType, $statModel, $bAlgorithmDllType, $algorithm), "cveEMTrainM", @error)
EndFunc   ;==>_cveEMTrainM

Func _cveEMTrainMMat($model, $matSamples, $matProbs0, $matLogLikelihoods, $matLabels, $matProbs, $statModel, $algorithm)
    ; cveEMTrainM using cv::Mat instead of _*Array

    Local $iArrSamples, $vectorOfMatSamples, $iArrSamplesSize
    Local $bSamplesIsArray = VarGetType($matSamples) == "Array"

    If $bSamplesIsArray Then
        $vectorOfMatSamples = _VectorOfMatCreate()

        $iArrSamplesSize = UBound($matSamples)
        For $i = 0 To $iArrSamplesSize - 1
            _VectorOfMatPush($vectorOfMatSamples, $matSamples[$i])
        Next

        $iArrSamples = _cveInputArrayFromVectorOfMat($vectorOfMatSamples)
    Else
        $iArrSamples = _cveInputArrayFromMat($matSamples)
    EndIf

    Local $iArrProbs0, $vectorOfMatProbs0, $iArrProbs0Size
    Local $bProbs0IsArray = VarGetType($matProbs0) == "Array"

    If $bProbs0IsArray Then
        $vectorOfMatProbs0 = _VectorOfMatCreate()

        $iArrProbs0Size = UBound($matProbs0)
        For $i = 0 To $iArrProbs0Size - 1
            _VectorOfMatPush($vectorOfMatProbs0, $matProbs0[$i])
        Next

        $iArrProbs0 = _cveInputArrayFromVectorOfMat($vectorOfMatProbs0)
    Else
        $iArrProbs0 = _cveInputArrayFromMat($matProbs0)
    EndIf

    Local $oArrLogLikelihoods, $vectorOfMatLogLikelihoods, $iArrLogLikelihoodsSize
    Local $bLogLikelihoodsIsArray = VarGetType($matLogLikelihoods) == "Array"

    If $bLogLikelihoodsIsArray Then
        $vectorOfMatLogLikelihoods = _VectorOfMatCreate()

        $iArrLogLikelihoodsSize = UBound($matLogLikelihoods)
        For $i = 0 To $iArrLogLikelihoodsSize - 1
            _VectorOfMatPush($vectorOfMatLogLikelihoods, $matLogLikelihoods[$i])
        Next

        $oArrLogLikelihoods = _cveOutputArrayFromVectorOfMat($vectorOfMatLogLikelihoods)
    Else
        $oArrLogLikelihoods = _cveOutputArrayFromMat($matLogLikelihoods)
    EndIf

    Local $oArrLabels, $vectorOfMatLabels, $iArrLabelsSize
    Local $bLabelsIsArray = VarGetType($matLabels) == "Array"

    If $bLabelsIsArray Then
        $vectorOfMatLabels = _VectorOfMatCreate()

        $iArrLabelsSize = UBound($matLabels)
        For $i = 0 To $iArrLabelsSize - 1
            _VectorOfMatPush($vectorOfMatLabels, $matLabels[$i])
        Next

        $oArrLabels = _cveOutputArrayFromVectorOfMat($vectorOfMatLabels)
    Else
        $oArrLabels = _cveOutputArrayFromMat($matLabels)
    EndIf

    Local $oArrProbs, $vectorOfMatProbs, $iArrProbsSize
    Local $bProbsIsArray = VarGetType($matProbs) == "Array"

    If $bProbsIsArray Then
        $vectorOfMatProbs = _VectorOfMatCreate()

        $iArrProbsSize = UBound($matProbs)
        For $i = 0 To $iArrProbsSize - 1
            _VectorOfMatPush($vectorOfMatProbs, $matProbs[$i])
        Next

        $oArrProbs = _cveOutputArrayFromVectorOfMat($vectorOfMatProbs)
    Else
        $oArrProbs = _cveOutputArrayFromMat($matProbs)
    EndIf

    _cveEMTrainM($model, $iArrSamples, $iArrProbs0, $oArrLogLikelihoods, $oArrLabels, $oArrProbs, $statModel, $algorithm)

    If $bProbsIsArray Then
        _VectorOfMatRelease($vectorOfMatProbs)
    EndIf

    _cveOutputArrayRelease($oArrProbs)

    If $bLabelsIsArray Then
        _VectorOfMatRelease($vectorOfMatLabels)
    EndIf

    _cveOutputArrayRelease($oArrLabels)

    If $bLogLikelihoodsIsArray Then
        _VectorOfMatRelease($vectorOfMatLogLikelihoods)
    EndIf

    _cveOutputArrayRelease($oArrLogLikelihoods)

    If $bProbs0IsArray Then
        _VectorOfMatRelease($vectorOfMatProbs0)
    EndIf

    _cveInputArrayRelease($iArrProbs0)

    If $bSamplesIsArray Then
        _VectorOfMatRelease($vectorOfMatSamples)
    EndIf

    _cveInputArrayRelease($iArrSamples)
EndFunc   ;==>_cveEMTrainMMat

Func _cveEMPredict($model, $sample, $result, $probs)
    ; CVAPI(void) cveEMPredict(cv::ml::EM* model, cv::_InputArray* sample, CvPoint2D64f* result, cv::_OutputArray* probs);

    Local $bModelDllType
    If VarGetType($model) == "DLLStruct" Then
        $bModelDllType = "struct*"
    Else
        $bModelDllType = "ptr"
    EndIf

    Local $bSampleDllType
    If VarGetType($sample) == "DLLStruct" Then
        $bSampleDllType = "struct*"
    Else
        $bSampleDllType = "ptr"
    EndIf

    Local $bResultDllType
    If VarGetType($result) == "DLLStruct" Then
        $bResultDllType = "struct*"
    Else
        $bResultDllType = "ptr"
    EndIf

    Local $bProbsDllType
    If VarGetType($probs) == "DLLStruct" Then
        $bProbsDllType = "struct*"
    Else
        $bProbsDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveEMPredict", $bModelDllType, $model, $bSampleDllType, $sample, $bResultDllType, $result, $bProbsDllType, $probs), "cveEMPredict", @error)
EndFunc   ;==>_cveEMPredict

Func _cveEMPredictMat($model, $matSample, $result, $matProbs)
    ; cveEMPredict using cv::Mat instead of _*Array

    Local $iArrSample, $vectorOfMatSample, $iArrSampleSize
    Local $bSampleIsArray = VarGetType($matSample) == "Array"

    If $bSampleIsArray Then
        $vectorOfMatSample = _VectorOfMatCreate()

        $iArrSampleSize = UBound($matSample)
        For $i = 0 To $iArrSampleSize - 1
            _VectorOfMatPush($vectorOfMatSample, $matSample[$i])
        Next

        $iArrSample = _cveInputArrayFromVectorOfMat($vectorOfMatSample)
    Else
        $iArrSample = _cveInputArrayFromMat($matSample)
    EndIf

    Local $oArrProbs, $vectorOfMatProbs, $iArrProbsSize
    Local $bProbsIsArray = VarGetType($matProbs) == "Array"

    If $bProbsIsArray Then
        $vectorOfMatProbs = _VectorOfMatCreate()

        $iArrProbsSize = UBound($matProbs)
        For $i = 0 To $iArrProbsSize - 1
            _VectorOfMatPush($vectorOfMatProbs, $matProbs[$i])
        Next

        $oArrProbs = _cveOutputArrayFromVectorOfMat($vectorOfMatProbs)
    Else
        $oArrProbs = _cveOutputArrayFromMat($matProbs)
    EndIf

    _cveEMPredict($model, $iArrSample, $result, $oArrProbs)

    If $bProbsIsArray Then
        _VectorOfMatRelease($vectorOfMatProbs)
    EndIf

    _cveOutputArrayRelease($oArrProbs)

    If $bSampleIsArray Then
        _VectorOfMatRelease($vectorOfMatSample)
    EndIf

    _cveInputArrayRelease($iArrSample)
EndFunc   ;==>_cveEMPredictMat

Func _cveEMRelease($model, $sharedPtr)
    ; CVAPI(void) cveEMRelease(cv::ml::EM** model, cv::Ptr<cv::ml::EM>** sharedPtr);

    Local $bModelDllType
    If VarGetType($model) == "DLLStruct" Then
        $bModelDllType = "struct*"
    Else
        $bModelDllType = "ptr*"
    EndIf

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveEMRelease", $bModelDllType, $model, $bSharedPtrDllType, $sharedPtr), "cveEMRelease", @error)
EndFunc   ;==>_cveEMRelease

Func _cveSVMDefaultCreate($model, $algorithm, $sharedPtr)
    ; CVAPI(cv::ml::SVM*) cveSVMDefaultCreate(cv::ml::StatModel** model, cv::Algorithm** algorithm, cv::Ptr<cv::ml::SVM>** sharedPtr);

    Local $bModelDllType
    If VarGetType($model) == "DLLStruct" Then
        $bModelDllType = "struct*"
    Else
        $bModelDllType = "ptr*"
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
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveSVMDefaultCreate", $bModelDllType, $model, $bAlgorithmDllType, $algorithm, $bSharedPtrDllType, $sharedPtr), "cveSVMDefaultCreate", @error)
EndFunc   ;==>_cveSVMDefaultCreate

Func _cveSVMTrainAuto($model, $trainData, $kFold, $CGrid, $gammaGrid, $pGrid, $nuGrid, $coefGrid, $degreeGrid, $balanced)
    ; CVAPI(bool) cveSVMTrainAuto(cv::ml::SVM* model, cv::ml::TrainData* trainData, int kFold, cv::ml::ParamGrid* CGrid, cv::ml::ParamGrid* gammaGrid, cv::ml::ParamGrid* pGrid, cv::ml::ParamGrid* nuGrid, cv::ml::ParamGrid* coefGrid, cv::ml::ParamGrid* degreeGrid, bool balanced);

    Local $bModelDllType
    If VarGetType($model) == "DLLStruct" Then
        $bModelDllType = "struct*"
    Else
        $bModelDllType = "ptr"
    EndIf

    Local $bTrainDataDllType
    If VarGetType($trainData) == "DLLStruct" Then
        $bTrainDataDllType = "struct*"
    Else
        $bTrainDataDllType = "ptr"
    EndIf

    Local $bCGridDllType
    If VarGetType($CGrid) == "DLLStruct" Then
        $bCGridDllType = "struct*"
    Else
        $bCGridDllType = "ptr"
    EndIf

    Local $bGammaGridDllType
    If VarGetType($gammaGrid) == "DLLStruct" Then
        $bGammaGridDllType = "struct*"
    Else
        $bGammaGridDllType = "ptr"
    EndIf

    Local $bPGridDllType
    If VarGetType($pGrid) == "DLLStruct" Then
        $bPGridDllType = "struct*"
    Else
        $bPGridDllType = "ptr"
    EndIf

    Local $bNuGridDllType
    If VarGetType($nuGrid) == "DLLStruct" Then
        $bNuGridDllType = "struct*"
    Else
        $bNuGridDllType = "ptr"
    EndIf

    Local $bCoefGridDllType
    If VarGetType($coefGrid) == "DLLStruct" Then
        $bCoefGridDllType = "struct*"
    Else
        $bCoefGridDllType = "ptr"
    EndIf

    Local $bDegreeGridDllType
    If VarGetType($degreeGrid) == "DLLStruct" Then
        $bDegreeGridDllType = "struct*"
    Else
        $bDegreeGridDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveSVMTrainAuto", $bModelDllType, $model, $bTrainDataDllType, $trainData, "int", $kFold, $bCGridDllType, $CGrid, $bGammaGridDllType, $gammaGrid, $bPGridDllType, $pGrid, $bNuGridDllType, $nuGrid, $bCoefGridDllType, $coefGrid, $bDegreeGridDllType, $degreeGrid, "boolean", $balanced), "cveSVMTrainAuto", @error)
EndFunc   ;==>_cveSVMTrainAuto

Func _cveSVMGetDefaultGrid($gridType, $grid)
    ; CVAPI(void) cveSVMGetDefaultGrid(int gridType, cv::ml::ParamGrid* grid);

    Local $bGridDllType
    If VarGetType($grid) == "DLLStruct" Then
        $bGridDllType = "struct*"
    Else
        $bGridDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSVMGetDefaultGrid", "int", $gridType, $bGridDllType, $grid), "cveSVMGetDefaultGrid", @error)
EndFunc   ;==>_cveSVMGetDefaultGrid

Func _cveSVMRelease($model, $sharedPtr)
    ; CVAPI(void) cveSVMRelease(cv::ml::SVM** model, cv::Ptr<cv::ml::SVM>** sharedPtr);

    Local $bModelDllType
    If VarGetType($model) == "DLLStruct" Then
        $bModelDllType = "struct*"
    Else
        $bModelDllType = "ptr*"
    EndIf

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSVMRelease", $bModelDllType, $model, $bSharedPtrDllType, $sharedPtr), "cveSVMRelease", @error)
EndFunc   ;==>_cveSVMRelease

Func _cveSVMGetSupportVectors($model, $supportVectors)
    ; CVAPI(void) cveSVMGetSupportVectors(cv::ml::SVM* model, cv::Mat* supportVectors);

    Local $bModelDllType
    If VarGetType($model) == "DLLStruct" Then
        $bModelDllType = "struct*"
    Else
        $bModelDllType = "ptr"
    EndIf

    Local $bSupportVectorsDllType
    If VarGetType($supportVectors) == "DLLStruct" Then
        $bSupportVectorsDllType = "struct*"
    Else
        $bSupportVectorsDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSVMGetSupportVectors", $bModelDllType, $model, $bSupportVectorsDllType, $supportVectors), "cveSVMGetSupportVectors", @error)
EndFunc   ;==>_cveSVMGetSupportVectors

Func _cveANN_MLPCreate($model, $algorithm, $sharedPtr)
    ; CVAPI(cv::ml::ANN_MLP*) cveANN_MLPCreate(cv::ml::StatModel** model, cv::Algorithm** algorithm, cv::Ptr<cv::ml::ANN_MLP>** sharedPtr);

    Local $bModelDllType
    If VarGetType($model) == "DLLStruct" Then
        $bModelDllType = "struct*"
    Else
        $bModelDllType = "ptr*"
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
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveANN_MLPCreate", $bModelDllType, $model, $bAlgorithmDllType, $algorithm, $bSharedPtrDllType, $sharedPtr), "cveANN_MLPCreate", @error)
EndFunc   ;==>_cveANN_MLPCreate

Func _cveANN_MLPSetLayerSizes($model, $layerSizes)
    ; CVAPI(void) cveANN_MLPSetLayerSizes(cv::ml::ANN_MLP* model, cv::_InputArray* layerSizes);

    Local $bModelDllType
    If VarGetType($model) == "DLLStruct" Then
        $bModelDllType = "struct*"
    Else
        $bModelDllType = "ptr"
    EndIf

    Local $bLayerSizesDllType
    If VarGetType($layerSizes) == "DLLStruct" Then
        $bLayerSizesDllType = "struct*"
    Else
        $bLayerSizesDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveANN_MLPSetLayerSizes", $bModelDllType, $model, $bLayerSizesDllType, $layerSizes), "cveANN_MLPSetLayerSizes", @error)
EndFunc   ;==>_cveANN_MLPSetLayerSizes

Func _cveANN_MLPSetLayerSizesMat($model, $matLayerSizes)
    ; cveANN_MLPSetLayerSizes using cv::Mat instead of _*Array

    Local $iArrLayerSizes, $vectorOfMatLayerSizes, $iArrLayerSizesSize
    Local $bLayerSizesIsArray = VarGetType($matLayerSizes) == "Array"

    If $bLayerSizesIsArray Then
        $vectorOfMatLayerSizes = _VectorOfMatCreate()

        $iArrLayerSizesSize = UBound($matLayerSizes)
        For $i = 0 To $iArrLayerSizesSize - 1
            _VectorOfMatPush($vectorOfMatLayerSizes, $matLayerSizes[$i])
        Next

        $iArrLayerSizes = _cveInputArrayFromVectorOfMat($vectorOfMatLayerSizes)
    Else
        $iArrLayerSizes = _cveInputArrayFromMat($matLayerSizes)
    EndIf

    _cveANN_MLPSetLayerSizes($model, $iArrLayerSizes)

    If $bLayerSizesIsArray Then
        _VectorOfMatRelease($vectorOfMatLayerSizes)
    EndIf

    _cveInputArrayRelease($iArrLayerSizes)
EndFunc   ;==>_cveANN_MLPSetLayerSizesMat

Func _cveANN_MLPSetActivationFunction($model, $type, $param1, $param2)
    ; CVAPI(void) cveANN_MLPSetActivationFunction(cv::ml::ANN_MLP* model, int type, double param1, double param2);

    Local $bModelDllType
    If VarGetType($model) == "DLLStruct" Then
        $bModelDllType = "struct*"
    Else
        $bModelDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveANN_MLPSetActivationFunction", $bModelDllType, $model, "int", $type, "double", $param1, "double", $param2), "cveANN_MLPSetActivationFunction", @error)
EndFunc   ;==>_cveANN_MLPSetActivationFunction

Func _cveANN_MLPSetTrainMethod($model, $method, $param1, $param2)
    ; CVAPI(void) cveANN_MLPSetTrainMethod(cv::ml::ANN_MLP* model, int method, double param1, double param2);

    Local $bModelDllType
    If VarGetType($model) == "DLLStruct" Then
        $bModelDllType = "struct*"
    Else
        $bModelDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveANN_MLPSetTrainMethod", $bModelDllType, $model, "int", $method, "double", $param1, "double", $param2), "cveANN_MLPSetTrainMethod", @error)
EndFunc   ;==>_cveANN_MLPSetTrainMethod

Func _cveANN_MLPRelease($model, $sharedPtr)
    ; CVAPI(void) cveANN_MLPRelease(cv::ml::ANN_MLP** model, cv::Ptr<cv::ml::ANN_MLP>** sharedPtr);

    Local $bModelDllType
    If VarGetType($model) == "DLLStruct" Then
        $bModelDllType = "struct*"
    Else
        $bModelDllType = "ptr*"
    EndIf

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveANN_MLPRelease", $bModelDllType, $model, $bSharedPtrDllType, $sharedPtr), "cveANN_MLPRelease", @error)
EndFunc   ;==>_cveANN_MLPRelease

Func _cveDTreesCreate($statModel, $algorithm, $sharedPtr)
    ; CVAPI(cv::ml::DTrees*) cveDTreesCreate(cv::ml::StatModel** statModel, cv::Algorithm** algorithm, cv::Ptr<cv::ml::DTrees>** sharedPtr);

    Local $bStatModelDllType
    If VarGetType($statModel) == "DLLStruct" Then
        $bStatModelDllType = "struct*"
    Else
        $bStatModelDllType = "ptr*"
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
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveDTreesCreate", $bStatModelDllType, $statModel, $bAlgorithmDllType, $algorithm, $bSharedPtrDllType, $sharedPtr), "cveDTreesCreate", @error)
EndFunc   ;==>_cveDTreesCreate

Func _cveDTreesRelease($model, $sharedPtr)
    ; CVAPI(void) cveDTreesRelease(cv::ml::DTrees** model, cv::Ptr<cv::ml::DTrees>** sharedPtr);

    Local $bModelDllType
    If VarGetType($model) == "DLLStruct" Then
        $bModelDllType = "struct*"
    Else
        $bModelDllType = "ptr*"
    EndIf

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDTreesRelease", $bModelDllType, $model, $bSharedPtrDllType, $sharedPtr), "cveDTreesRelease", @error)
EndFunc   ;==>_cveDTreesRelease

Func _cveRTreesCreate($statModel, $algorithm, $sharedPtr)
    ; CVAPI(cv::ml::RTrees*) cveRTreesCreate(cv::ml::StatModel** statModel, cv::Algorithm** algorithm, cv::Ptr<cv::ml::RTrees>** sharedPtr);

    Local $bStatModelDllType
    If VarGetType($statModel) == "DLLStruct" Then
        $bStatModelDllType = "struct*"
    Else
        $bStatModelDllType = "ptr*"
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
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveRTreesCreate", $bStatModelDllType, $statModel, $bAlgorithmDllType, $algorithm, $bSharedPtrDllType, $sharedPtr), "cveRTreesCreate", @error)
EndFunc   ;==>_cveRTreesCreate

Func _cveRTreesGetVotes($model, $samples, $results, $flags)
    ; CVAPI(void) cveRTreesGetVotes(cv::ml::RTrees* model, cv::_InputArray* samples, cv::_OutputArray* results, int flags);

    Local $bModelDllType
    If VarGetType($model) == "DLLStruct" Then
        $bModelDllType = "struct*"
    Else
        $bModelDllType = "ptr"
    EndIf

    Local $bSamplesDllType
    If VarGetType($samples) == "DLLStruct" Then
        $bSamplesDllType = "struct*"
    Else
        $bSamplesDllType = "ptr"
    EndIf

    Local $bResultsDllType
    If VarGetType($results) == "DLLStruct" Then
        $bResultsDllType = "struct*"
    Else
        $bResultsDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveRTreesGetVotes", $bModelDllType, $model, $bSamplesDllType, $samples, $bResultsDllType, $results, "int", $flags), "cveRTreesGetVotes", @error)
EndFunc   ;==>_cveRTreesGetVotes

Func _cveRTreesGetVotesMat($model, $matSamples, $matResults, $flags)
    ; cveRTreesGetVotes using cv::Mat instead of _*Array

    Local $iArrSamples, $vectorOfMatSamples, $iArrSamplesSize
    Local $bSamplesIsArray = VarGetType($matSamples) == "Array"

    If $bSamplesIsArray Then
        $vectorOfMatSamples = _VectorOfMatCreate()

        $iArrSamplesSize = UBound($matSamples)
        For $i = 0 To $iArrSamplesSize - 1
            _VectorOfMatPush($vectorOfMatSamples, $matSamples[$i])
        Next

        $iArrSamples = _cveInputArrayFromVectorOfMat($vectorOfMatSamples)
    Else
        $iArrSamples = _cveInputArrayFromMat($matSamples)
    EndIf

    Local $oArrResults, $vectorOfMatResults, $iArrResultsSize
    Local $bResultsIsArray = VarGetType($matResults) == "Array"

    If $bResultsIsArray Then
        $vectorOfMatResults = _VectorOfMatCreate()

        $iArrResultsSize = UBound($matResults)
        For $i = 0 To $iArrResultsSize - 1
            _VectorOfMatPush($vectorOfMatResults, $matResults[$i])
        Next

        $oArrResults = _cveOutputArrayFromVectorOfMat($vectorOfMatResults)
    Else
        $oArrResults = _cveOutputArrayFromMat($matResults)
    EndIf

    _cveRTreesGetVotes($model, $iArrSamples, $oArrResults, $flags)

    If $bResultsIsArray Then
        _VectorOfMatRelease($vectorOfMatResults)
    EndIf

    _cveOutputArrayRelease($oArrResults)

    If $bSamplesIsArray Then
        _VectorOfMatRelease($vectorOfMatSamples)
    EndIf

    _cveInputArrayRelease($iArrSamples)
EndFunc   ;==>_cveRTreesGetVotesMat

Func _cveRTreesRelease($model, $sharedPtr)
    ; CVAPI(void) cveRTreesRelease(cv::ml::RTrees** model, cv::Ptr<cv::ml::RTrees>** sharedPtr);

    Local $bModelDllType
    If VarGetType($model) == "DLLStruct" Then
        $bModelDllType = "struct*"
    Else
        $bModelDllType = "ptr*"
    EndIf

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveRTreesRelease", $bModelDllType, $model, $bSharedPtrDllType, $sharedPtr), "cveRTreesRelease", @error)
EndFunc   ;==>_cveRTreesRelease

Func _cveBoostCreate($statModel, $algorithm, $sharedPtr)
    ; CVAPI(cv::ml::Boost*) cveBoostCreate(cv::ml::StatModel** statModel, cv::Algorithm** algorithm, cv::Ptr<cv::ml::Boost>** sharedPtr);

    Local $bStatModelDllType
    If VarGetType($statModel) == "DLLStruct" Then
        $bStatModelDllType = "struct*"
    Else
        $bStatModelDllType = "ptr*"
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
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveBoostCreate", $bStatModelDllType, $statModel, $bAlgorithmDllType, $algorithm, $bSharedPtrDllType, $sharedPtr), "cveBoostCreate", @error)
EndFunc   ;==>_cveBoostCreate

Func _cveBoostRelease($model, $sharedPtr)
    ; CVAPI(void) cveBoostRelease(cv::ml::Boost** model, cv::Ptr<cv::ml::Boost>** sharedPtr);

    Local $bModelDllType
    If VarGetType($model) == "DLLStruct" Then
        $bModelDllType = "struct*"
    Else
        $bModelDllType = "ptr*"
    EndIf

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBoostRelease", $bModelDllType, $model, $bSharedPtrDllType, $sharedPtr), "cveBoostRelease", @error)
EndFunc   ;==>_cveBoostRelease

Func _cveLogisticRegressionCreate($statModel, $algorithm, $sharedPtr)
    ; CVAPI(cv::ml::LogisticRegression*) cveLogisticRegressionCreate(cv::ml::StatModel** statModel, cv::Algorithm** algorithm, cv::Ptr<cv::ml::LogisticRegression>** sharedPtr);

    Local $bStatModelDllType
    If VarGetType($statModel) == "DLLStruct" Then
        $bStatModelDllType = "struct*"
    Else
        $bStatModelDllType = "ptr*"
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
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveLogisticRegressionCreate", $bStatModelDllType, $statModel, $bAlgorithmDllType, $algorithm, $bSharedPtrDllType, $sharedPtr), "cveLogisticRegressionCreate", @error)
EndFunc   ;==>_cveLogisticRegressionCreate

Func _cveLogisticRegressionRelease($model, $sharedPtr)
    ; CVAPI(void) cveLogisticRegressionRelease(cv::ml::LogisticRegression** model, cv::Ptr<cv::ml::LogisticRegression>** sharedPtr);

    Local $bModelDllType
    If VarGetType($model) == "DLLStruct" Then
        $bModelDllType = "struct*"
    Else
        $bModelDllType = "ptr*"
    EndIf

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveLogisticRegressionRelease", $bModelDllType, $model, $bSharedPtrDllType, $sharedPtr), "cveLogisticRegressionRelease", @error)
EndFunc   ;==>_cveLogisticRegressionRelease

Func _cveSVMSGDDefaultCreate($model, $algorithm, $sharedPtr)
    ; CVAPI(cv::ml::SVMSGD*) cveSVMSGDDefaultCreate(cv::ml::StatModel** model, cv::Algorithm** algorithm, cv::Ptr<cv::ml::SVMSGD>** sharedPtr);

    Local $bModelDllType
    If VarGetType($model) == "DLLStruct" Then
        $bModelDllType = "struct*"
    Else
        $bModelDllType = "ptr*"
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
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveSVMSGDDefaultCreate", $bModelDllType, $model, $bAlgorithmDllType, $algorithm, $bSharedPtrDllType, $sharedPtr), "cveSVMSGDDefaultCreate", @error)
EndFunc   ;==>_cveSVMSGDDefaultCreate

Func _cveSVMSGDRelease($model, $sharedPtr)
    ; CVAPI(void) cveSVMSGDRelease(cv::ml::SVMSGD** model, cv::Ptr<cv::ml::SVMSGD>** sharedPtr);

    Local $bModelDllType
    If VarGetType($model) == "DLLStruct" Then
        $bModelDllType = "struct*"
    Else
        $bModelDllType = "ptr*"
    EndIf

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSVMSGDRelease", $bModelDllType, $model, $bSharedPtrDllType, $sharedPtr), "cveSVMSGDRelease", @error)
EndFunc   ;==>_cveSVMSGDRelease

Func _cveSVMSGDSetOptimalParameters($model, $svmsgdType, $marginType)
    ; CVAPI(void) cveSVMSGDSetOptimalParameters(cv::ml::SVMSGD* model, int svmsgdType, int marginType);

    Local $bModelDllType
    If VarGetType($model) == "DLLStruct" Then
        $bModelDllType = "struct*"
    Else
        $bModelDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSVMSGDSetOptimalParameters", $bModelDllType, $model, "int", $svmsgdType, "int", $marginType), "cveSVMSGDSetOptimalParameters", @error)
EndFunc   ;==>_cveSVMSGDSetOptimalParameters