#include-once
#include "..\..\CVEUtils.au3"

Func _cveReadNetFromDarknet($cfgFile, $darknetModel)
    ; CVAPI(cv::dnn::Net*) cveReadNetFromDarknet(cv::String* cfgFile, cv::String* darknetModel);

    Local $bCfgFileIsString = VarGetType($cfgFile) == "String"
    If $bCfgFileIsString Then
        $cfgFile = _cveStringCreateFromStr($cfgFile)
    EndIf

    Local $bCfgFileDllType
    If VarGetType($cfgFile) == "DLLStruct" Then
        $bCfgFileDllType = "struct*"
    Else
        $bCfgFileDllType = "ptr"
    EndIf

    Local $bDarknetModelIsString = VarGetType($darknetModel) == "String"
    If $bDarknetModelIsString Then
        $darknetModel = _cveStringCreateFromStr($darknetModel)
    EndIf

    Local $bDarknetModelDllType
    If VarGetType($darknetModel) == "DLLStruct" Then
        $bDarknetModelDllType = "struct*"
    Else
        $bDarknetModelDllType = "ptr"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveReadNetFromDarknet", $bCfgFileDllType, $cfgFile, $bDarknetModelDllType, $darknetModel), "cveReadNetFromDarknet", @error)

    If $bDarknetModelIsString Then
        _cveStringRelease($darknetModel)
    EndIf

    If $bCfgFileIsString Then
        _cveStringRelease($cfgFile)
    EndIf

    Return $retval
EndFunc   ;==>_cveReadNetFromDarknet

Func _cveReadNetFromDarknet2($bufferCfg, $lenCfg, $bufferModel, $lenModel)
    ; CVAPI(cv::dnn::Net*) cveReadNetFromDarknet2(const char* bufferCfg, int lenCfg, const char* bufferModel, int lenModel);

    Local $bBufferCfgDllType
    If VarGetType($bufferCfg) == "DLLStruct" Then
        $bBufferCfgDllType = "struct*"
    Else
        $bBufferCfgDllType = "str"
    EndIf

    Local $bBufferModelDllType
    If VarGetType($bufferModel) == "DLLStruct" Then
        $bBufferModelDllType = "struct*"
    Else
        $bBufferModelDllType = "str"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveReadNetFromDarknet2", $bBufferCfgDllType, $bufferCfg, "int", $lenCfg, $bBufferModelDllType, $bufferModel, "int", $lenModel), "cveReadNetFromDarknet2", @error)
EndFunc   ;==>_cveReadNetFromDarknet2

Func _cveReadNetFromCaffe($prototxt, $caffeModel)
    ; CVAPI(cv::dnn::Net*) cveReadNetFromCaffe(cv::String* prototxt, cv::String* caffeModel);

    Local $bPrototxtIsString = VarGetType($prototxt) == "String"
    If $bPrototxtIsString Then
        $prototxt = _cveStringCreateFromStr($prototxt)
    EndIf

    Local $bPrototxtDllType
    If VarGetType($prototxt) == "DLLStruct" Then
        $bPrototxtDllType = "struct*"
    Else
        $bPrototxtDllType = "ptr"
    EndIf

    Local $bCaffeModelIsString = VarGetType($caffeModel) == "String"
    If $bCaffeModelIsString Then
        $caffeModel = _cveStringCreateFromStr($caffeModel)
    EndIf

    Local $bCaffeModelDllType
    If VarGetType($caffeModel) == "DLLStruct" Then
        $bCaffeModelDllType = "struct*"
    Else
        $bCaffeModelDllType = "ptr"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveReadNetFromCaffe", $bPrototxtDllType, $prototxt, $bCaffeModelDllType, $caffeModel), "cveReadNetFromCaffe", @error)

    If $bCaffeModelIsString Then
        _cveStringRelease($caffeModel)
    EndIf

    If $bPrototxtIsString Then
        _cveStringRelease($prototxt)
    EndIf

    Return $retval
EndFunc   ;==>_cveReadNetFromCaffe

Func _cveReadNetFromCaffe2($bufferProto, $lenProto, $bufferModel, $lenModel)
    ; CVAPI(cv::dnn::Net*) cveReadNetFromCaffe2(const char* bufferProto, int lenProto, const char* bufferModel, int lenModel);

    Local $bBufferProtoDllType
    If VarGetType($bufferProto) == "DLLStruct" Then
        $bBufferProtoDllType = "struct*"
    Else
        $bBufferProtoDllType = "str"
    EndIf

    Local $bBufferModelDllType
    If VarGetType($bufferModel) == "DLLStruct" Then
        $bBufferModelDllType = "struct*"
    Else
        $bBufferModelDllType = "str"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveReadNetFromCaffe2", $bBufferProtoDllType, $bufferProto, "int", $lenProto, $bBufferModelDllType, $bufferModel, "int", $lenModel), "cveReadNetFromCaffe2", @error)
EndFunc   ;==>_cveReadNetFromCaffe2

Func _cveReadNetFromTensorflow($model, $config)
    ; CVAPI(cv::dnn::Net*) cveReadNetFromTensorflow(cv::String* model, cv::String* config);

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

    Local $bConfigIsString = VarGetType($config) == "String"
    If $bConfigIsString Then
        $config = _cveStringCreateFromStr($config)
    EndIf

    Local $bConfigDllType
    If VarGetType($config) == "DLLStruct" Then
        $bConfigDllType = "struct*"
    Else
        $bConfigDllType = "ptr"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveReadNetFromTensorflow", $bModelDllType, $model, $bConfigDllType, $config), "cveReadNetFromTensorflow", @error)

    If $bConfigIsString Then
        _cveStringRelease($config)
    EndIf

    If $bModelIsString Then
        _cveStringRelease($model)
    EndIf

    Return $retval
EndFunc   ;==>_cveReadNetFromTensorflow

Func _cveReadNetFromTensorflow2($bufferModel, $lenModel, $bufferConfig, $lenConfig)
    ; CVAPI(cv::dnn::Net*) cveReadNetFromTensorflow2(const char* bufferModel, int lenModel, const char* bufferConfig, int lenConfig);

    Local $bBufferModelDllType
    If VarGetType($bufferModel) == "DLLStruct" Then
        $bBufferModelDllType = "struct*"
    Else
        $bBufferModelDllType = "str"
    EndIf

    Local $bBufferConfigDllType
    If VarGetType($bufferConfig) == "DLLStruct" Then
        $bBufferConfigDllType = "struct*"
    Else
        $bBufferConfigDllType = "str"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveReadNetFromTensorflow2", $bBufferModelDllType, $bufferModel, "int", $lenModel, $bBufferConfigDllType, $bufferConfig, "int", $lenConfig), "cveReadNetFromTensorflow2", @error)
EndFunc   ;==>_cveReadNetFromTensorflow2

Func _cveReadNetFromONNX($onnxFile)
    ; CVAPI(cv::dnn::Net*) cveReadNetFromONNX(cv::String* onnxFile);

    Local $bOnnxFileIsString = VarGetType($onnxFile) == "String"
    If $bOnnxFileIsString Then
        $onnxFile = _cveStringCreateFromStr($onnxFile)
    EndIf

    Local $bOnnxFileDllType
    If VarGetType($onnxFile) == "DLLStruct" Then
        $bOnnxFileDllType = "struct*"
    Else
        $bOnnxFileDllType = "ptr"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveReadNetFromONNX", $bOnnxFileDllType, $onnxFile), "cveReadNetFromONNX", @error)

    If $bOnnxFileIsString Then
        _cveStringRelease($onnxFile)
    EndIf

    Return $retval
EndFunc   ;==>_cveReadNetFromONNX

Func _cveReadTensorFromONNX($path, $tensor)
    ; CVAPI(void) cveReadTensorFromONNX(cv::String* path, cv::Mat* tensor);

    Local $bPathIsString = VarGetType($path) == "String"
    If $bPathIsString Then
        $path = _cveStringCreateFromStr($path)
    EndIf

    Local $bPathDllType
    If VarGetType($path) == "DLLStruct" Then
        $bPathDllType = "struct*"
    Else
        $bPathDllType = "ptr"
    EndIf

    Local $bTensorDllType
    If VarGetType($tensor) == "DLLStruct" Then
        $bTensorDllType = "struct*"
    Else
        $bTensorDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveReadTensorFromONNX", $bPathDllType, $path, $bTensorDllType, $tensor), "cveReadTensorFromONNX", @error)

    If $bPathIsString Then
        _cveStringRelease($path)
    EndIf
EndFunc   ;==>_cveReadTensorFromONNX

Func _cveReadNet($model, $config, $framework)
    ; CVAPI(cv::dnn::Net*) cveReadNet(cv::String* model, cv::String* config, cv::String* framework);

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

    Local $bConfigIsString = VarGetType($config) == "String"
    If $bConfigIsString Then
        $config = _cveStringCreateFromStr($config)
    EndIf

    Local $bConfigDllType
    If VarGetType($config) == "DLLStruct" Then
        $bConfigDllType = "struct*"
    Else
        $bConfigDllType = "ptr"
    EndIf

    Local $bFrameworkIsString = VarGetType($framework) == "String"
    If $bFrameworkIsString Then
        $framework = _cveStringCreateFromStr($framework)
    EndIf

    Local $bFrameworkDllType
    If VarGetType($framework) == "DLLStruct" Then
        $bFrameworkDllType = "struct*"
    Else
        $bFrameworkDllType = "ptr"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveReadNet", $bModelDllType, $model, $bConfigDllType, $config, $bFrameworkDllType, $framework), "cveReadNet", @error)

    If $bFrameworkIsString Then
        _cveStringRelease($framework)
    EndIf

    If $bConfigIsString Then
        _cveStringRelease($config)
    EndIf

    If $bModelIsString Then
        _cveStringRelease($model)
    EndIf

    Return $retval
EndFunc   ;==>_cveReadNet

Func _cveReadNetFromModelOptimizer($xml, $bin)
    ; CVAPI(cv::dnn::Net*) cveReadNetFromModelOptimizer(cv::String* xml, cv::String* bin);

    Local $bXmlIsString = VarGetType($xml) == "String"
    If $bXmlIsString Then
        $xml = _cveStringCreateFromStr($xml)
    EndIf

    Local $bXmlDllType
    If VarGetType($xml) == "DLLStruct" Then
        $bXmlDllType = "struct*"
    Else
        $bXmlDllType = "ptr"
    EndIf

    Local $bBinIsString = VarGetType($bin) == "String"
    If $bBinIsString Then
        $bin = _cveStringCreateFromStr($bin)
    EndIf

    Local $bBinDllType
    If VarGetType($bin) == "DLLStruct" Then
        $bBinDllType = "struct*"
    Else
        $bBinDllType = "ptr"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveReadNetFromModelOptimizer", $bXmlDllType, $xml, $bBinDllType, $bin), "cveReadNetFromModelOptimizer", @error)

    If $bBinIsString Then
        _cveStringRelease($bin)
    EndIf

    If $bXmlIsString Then
        _cveStringRelease($xml)
    EndIf

    Return $retval
EndFunc   ;==>_cveReadNetFromModelOptimizer

Func _cveDnnNetCreate()
    ; CVAPI(cv::dnn::Net*) cveDnnNetCreate();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveDnnNetCreate"), "cveDnnNetCreate", @error)
EndFunc   ;==>_cveDnnNetCreate

Func _cveDnnNetSetInput($net, $blob, $name, $scalefactor, $mean)
    ; CVAPI(void) cveDnnNetSetInput(cv::dnn::Net* net, cv::_InputArray* blob, cv::String* name, double scalefactor, CvScalar* mean);

    Local $bNetDllType
    If VarGetType($net) == "DLLStruct" Then
        $bNetDllType = "struct*"
    Else
        $bNetDllType = "ptr"
    EndIf

    Local $bBlobDllType
    If VarGetType($blob) == "DLLStruct" Then
        $bBlobDllType = "struct*"
    Else
        $bBlobDllType = "ptr"
    EndIf

    Local $bNameIsString = VarGetType($name) == "String"
    If $bNameIsString Then
        $name = _cveStringCreateFromStr($name)
    EndIf

    Local $bNameDllType
    If VarGetType($name) == "DLLStruct" Then
        $bNameDllType = "struct*"
    Else
        $bNameDllType = "ptr"
    EndIf

    Local $bMeanDllType
    If VarGetType($mean) == "DLLStruct" Then
        $bMeanDllType = "struct*"
    Else
        $bMeanDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDnnNetSetInput", $bNetDllType, $net, $bBlobDllType, $blob, $bNameDllType, $name, "double", $scalefactor, $bMeanDllType, $mean), "cveDnnNetSetInput", @error)

    If $bNameIsString Then
        _cveStringRelease($name)
    EndIf
EndFunc   ;==>_cveDnnNetSetInput

Func _cveDnnNetSetInputMat($net, $matBlob, $name, $scalefactor, $mean)
    ; cveDnnNetSetInput using cv::Mat instead of _*Array

    Local $iArrBlob, $vectorOfMatBlob, $iArrBlobSize
    Local $bBlobIsArray = VarGetType($matBlob) == "Array"

    If $bBlobIsArray Then
        $vectorOfMatBlob = _VectorOfMatCreate()

        $iArrBlobSize = UBound($matBlob)
        For $i = 0 To $iArrBlobSize - 1
            _VectorOfMatPush($vectorOfMatBlob, $matBlob[$i])
        Next

        $iArrBlob = _cveInputArrayFromVectorOfMat($vectorOfMatBlob)
    Else
        $iArrBlob = _cveInputArrayFromMat($matBlob)
    EndIf

    _cveDnnNetSetInput($net, $iArrBlob, $name, $scalefactor, $mean)

    If $bBlobIsArray Then
        _VectorOfMatRelease($vectorOfMatBlob)
    EndIf

    _cveInputArrayRelease($iArrBlob)
EndFunc   ;==>_cveDnnNetSetInputMat

Func _cveDnnNetForward($net, $outputName, $output)
    ; CVAPI(void) cveDnnNetForward(cv::dnn::Net* net, cv::String* outputName, cv::Mat* output);

    Local $bNetDllType
    If VarGetType($net) == "DLLStruct" Then
        $bNetDllType = "struct*"
    Else
        $bNetDllType = "ptr"
    EndIf

    Local $bOutputNameIsString = VarGetType($outputName) == "String"
    If $bOutputNameIsString Then
        $outputName = _cveStringCreateFromStr($outputName)
    EndIf

    Local $bOutputNameDllType
    If VarGetType($outputName) == "DLLStruct" Then
        $bOutputNameDllType = "struct*"
    Else
        $bOutputNameDllType = "ptr"
    EndIf

    Local $bOutputDllType
    If VarGetType($output) == "DLLStruct" Then
        $bOutputDllType = "struct*"
    Else
        $bOutputDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDnnNetForward", $bNetDllType, $net, $bOutputNameDllType, $outputName, $bOutputDllType, $output), "cveDnnNetForward", @error)

    If $bOutputNameIsString Then
        _cveStringRelease($outputName)
    EndIf
EndFunc   ;==>_cveDnnNetForward

Func _cveDnnNetForward2($net, $outputBlobs, $outputName)
    ; CVAPI(void) cveDnnNetForward2(cv::dnn::Net* net, cv::_OutputArray* outputBlobs, cv::String* outputName);

    Local $bNetDllType
    If VarGetType($net) == "DLLStruct" Then
        $bNetDllType = "struct*"
    Else
        $bNetDllType = "ptr"
    EndIf

    Local $bOutputBlobsDllType
    If VarGetType($outputBlobs) == "DLLStruct" Then
        $bOutputBlobsDllType = "struct*"
    Else
        $bOutputBlobsDllType = "ptr"
    EndIf

    Local $bOutputNameIsString = VarGetType($outputName) == "String"
    If $bOutputNameIsString Then
        $outputName = _cveStringCreateFromStr($outputName)
    EndIf

    Local $bOutputNameDllType
    If VarGetType($outputName) == "DLLStruct" Then
        $bOutputNameDllType = "struct*"
    Else
        $bOutputNameDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDnnNetForward2", $bNetDllType, $net, $bOutputBlobsDllType, $outputBlobs, $bOutputNameDllType, $outputName), "cveDnnNetForward2", @error)

    If $bOutputNameIsString Then
        _cveStringRelease($outputName)
    EndIf
EndFunc   ;==>_cveDnnNetForward2

Func _cveDnnNetForward2Mat($net, $matOutputBlobs, $outputName)
    ; cveDnnNetForward2 using cv::Mat instead of _*Array

    Local $oArrOutputBlobs, $vectorOfMatOutputBlobs, $iArrOutputBlobsSize
    Local $bOutputBlobsIsArray = VarGetType($matOutputBlobs) == "Array"

    If $bOutputBlobsIsArray Then
        $vectorOfMatOutputBlobs = _VectorOfMatCreate()

        $iArrOutputBlobsSize = UBound($matOutputBlobs)
        For $i = 0 To $iArrOutputBlobsSize - 1
            _VectorOfMatPush($vectorOfMatOutputBlobs, $matOutputBlobs[$i])
        Next

        $oArrOutputBlobs = _cveOutputArrayFromVectorOfMat($vectorOfMatOutputBlobs)
    Else
        $oArrOutputBlobs = _cveOutputArrayFromMat($matOutputBlobs)
    EndIf

    _cveDnnNetForward2($net, $oArrOutputBlobs, $outputName)

    If $bOutputBlobsIsArray Then
        _VectorOfMatRelease($vectorOfMatOutputBlobs)
    EndIf

    _cveOutputArrayRelease($oArrOutputBlobs)
EndFunc   ;==>_cveDnnNetForward2Mat

Func _cveDnnNetForward3($net, $outputBlobs, $outBlobNames)
    ; CVAPI(void) cveDnnNetForward3(cv::dnn::Net* net, cv::_OutputArray* outputBlobs, std::vector<cv::String>* outBlobNames);

    Local $bNetDllType
    If VarGetType($net) == "DLLStruct" Then
        $bNetDllType = "struct*"
    Else
        $bNetDllType = "ptr"
    EndIf

    Local $bOutputBlobsDllType
    If VarGetType($outputBlobs) == "DLLStruct" Then
        $bOutputBlobsDllType = "struct*"
    Else
        $bOutputBlobsDllType = "ptr"
    EndIf

    Local $vecOutBlobNames, $iArrOutBlobNamesSize
    Local $bOutBlobNamesIsArray = VarGetType($outBlobNames) == "Array"

    If $bOutBlobNamesIsArray Then
        $vecOutBlobNames = _VectorOfCvStringCreate()

        $iArrOutBlobNamesSize = UBound($outBlobNames)
        For $i = 0 To $iArrOutBlobNamesSize - 1
            _VectorOfCvStringPush($vecOutBlobNames, $outBlobNames[$i])
        Next
    Else
        $vecOutBlobNames = $outBlobNames
    EndIf

    Local $bOutBlobNamesDllType
    If VarGetType($outBlobNames) == "DLLStruct" Then
        $bOutBlobNamesDllType = "struct*"
    Else
        $bOutBlobNamesDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDnnNetForward3", $bNetDllType, $net, $bOutputBlobsDllType, $outputBlobs, $bOutBlobNamesDllType, $vecOutBlobNames), "cveDnnNetForward3", @error)

    If $bOutBlobNamesIsArray Then
        _VectorOfCvStringRelease($vecOutBlobNames)
    EndIf
EndFunc   ;==>_cveDnnNetForward3

Func _cveDnnNetForward3Mat($net, $matOutputBlobs, $outBlobNames)
    ; cveDnnNetForward3 using cv::Mat instead of _*Array

    Local $oArrOutputBlobs, $vectorOfMatOutputBlobs, $iArrOutputBlobsSize
    Local $bOutputBlobsIsArray = VarGetType($matOutputBlobs) == "Array"

    If $bOutputBlobsIsArray Then
        $vectorOfMatOutputBlobs = _VectorOfMatCreate()

        $iArrOutputBlobsSize = UBound($matOutputBlobs)
        For $i = 0 To $iArrOutputBlobsSize - 1
            _VectorOfMatPush($vectorOfMatOutputBlobs, $matOutputBlobs[$i])
        Next

        $oArrOutputBlobs = _cveOutputArrayFromVectorOfMat($vectorOfMatOutputBlobs)
    Else
        $oArrOutputBlobs = _cveOutputArrayFromMat($matOutputBlobs)
    EndIf

    _cveDnnNetForward3($net, $oArrOutputBlobs, $outBlobNames)

    If $bOutputBlobsIsArray Then
        _VectorOfMatRelease($vectorOfMatOutputBlobs)
    EndIf

    _cveOutputArrayRelease($oArrOutputBlobs)
EndFunc   ;==>_cveDnnNetForward3Mat

Func _cveDnnNetRelease($net)
    ; CVAPI(void) cveDnnNetRelease(cv::dnn::Net** net);

    Local $bNetDllType
    If VarGetType($net) == "DLLStruct" Then
        $bNetDllType = "struct*"
    Else
        $bNetDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDnnNetRelease", $bNetDllType, $net), "cveDnnNetRelease", @error)
EndFunc   ;==>_cveDnnNetRelease

Func _cveDnnNetGetUnconnectedOutLayers($net, $layerIds)
    ; CVAPI(void) cveDnnNetGetUnconnectedOutLayers(cv::dnn::Net* net, std::vector<int>* layerIds);

    Local $bNetDllType
    If VarGetType($net) == "DLLStruct" Then
        $bNetDllType = "struct*"
    Else
        $bNetDllType = "ptr"
    EndIf

    Local $vecLayerIds, $iArrLayerIdsSize
    Local $bLayerIdsIsArray = VarGetType($layerIds) == "Array"

    If $bLayerIdsIsArray Then
        $vecLayerIds = _VectorOfIntCreate()

        $iArrLayerIdsSize = UBound($layerIds)
        For $i = 0 To $iArrLayerIdsSize - 1
            _VectorOfIntPush($vecLayerIds, $layerIds[$i])
        Next
    Else
        $vecLayerIds = $layerIds
    EndIf

    Local $bLayerIdsDllType
    If VarGetType($layerIds) == "DLLStruct" Then
        $bLayerIdsDllType = "struct*"
    Else
        $bLayerIdsDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDnnNetGetUnconnectedOutLayers", $bNetDllType, $net, $bLayerIdsDllType, $vecLayerIds), "cveDnnNetGetUnconnectedOutLayers", @error)

    If $bLayerIdsIsArray Then
        _VectorOfIntRelease($vecLayerIds)
    EndIf
EndFunc   ;==>_cveDnnNetGetUnconnectedOutLayers

Func _cveDnnNetGetUnconnectedOutLayersNames($net, $layerNames)
    ; CVAPI(void) cveDnnNetGetUnconnectedOutLayersNames(cv::dnn::Net* net, std::vector<cv::String>* layerNames);

    Local $bNetDllType
    If VarGetType($net) == "DLLStruct" Then
        $bNetDllType = "struct*"
    Else
        $bNetDllType = "ptr"
    EndIf

    Local $vecLayerNames, $iArrLayerNamesSize
    Local $bLayerNamesIsArray = VarGetType($layerNames) == "Array"

    If $bLayerNamesIsArray Then
        $vecLayerNames = _VectorOfCvStringCreate()

        $iArrLayerNamesSize = UBound($layerNames)
        For $i = 0 To $iArrLayerNamesSize - 1
            _VectorOfCvStringPush($vecLayerNames, $layerNames[$i])
        Next
    Else
        $vecLayerNames = $layerNames
    EndIf

    Local $bLayerNamesDllType
    If VarGetType($layerNames) == "DLLStruct" Then
        $bLayerNamesDllType = "struct*"
    Else
        $bLayerNamesDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDnnNetGetUnconnectedOutLayersNames", $bNetDllType, $net, $bLayerNamesDllType, $vecLayerNames), "cveDnnNetGetUnconnectedOutLayersNames", @error)

    If $bLayerNamesIsArray Then
        _VectorOfCvStringRelease($vecLayerNames)
    EndIf
EndFunc   ;==>_cveDnnNetGetUnconnectedOutLayersNames

Func _cveDnnNetGetPerfProfile($net, $timings)
    ; CVAPI(int64) cveDnnNetGetPerfProfile(cv::dnn::Net* net, std::vector<double>* timings);

    Local $bNetDllType
    If VarGetType($net) == "DLLStruct" Then
        $bNetDllType = "struct*"
    Else
        $bNetDllType = "ptr"
    EndIf

    Local $vecTimings, $iArrTimingsSize
    Local $bTimingsIsArray = VarGetType($timings) == "Array"

    If $bTimingsIsArray Then
        $vecTimings = _VectorOfDoubleCreate()

        $iArrTimingsSize = UBound($timings)
        For $i = 0 To $iArrTimingsSize - 1
            _VectorOfDoublePush($vecTimings, $timings[$i])
        Next
    Else
        $vecTimings = $timings
    EndIf

    Local $bTimingsDllType
    If VarGetType($timings) == "DLLStruct" Then
        $bTimingsDllType = "struct*"
    Else
        $bTimingsDllType = "ptr"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "int64:cdecl", "cveDnnNetGetPerfProfile", $bNetDllType, $net, $bTimingsDllType, $vecTimings), "cveDnnNetGetPerfProfile", @error)

    If $bTimingsIsArray Then
        _VectorOfDoubleRelease($vecTimings)
    EndIf

    Return $retval
EndFunc   ;==>_cveDnnNetGetPerfProfile

Func _cveDnnNetDump($net, $string)
    ; CVAPI(void) cveDnnNetDump(cv::dnn::Net* net, cv::String* string);

    Local $bNetDllType
    If VarGetType($net) == "DLLStruct" Then
        $bNetDllType = "struct*"
    Else
        $bNetDllType = "ptr"
    EndIf

    Local $bStringIsString = VarGetType($string) == "String"
    If $bStringIsString Then
        $string = _cveStringCreateFromStr($string)
    EndIf

    Local $bStringDllType
    If VarGetType($string) == "DLLStruct" Then
        $bStringDllType = "struct*"
    Else
        $bStringDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDnnNetDump", $bNetDllType, $net, $bStringDllType, $string), "cveDnnNetDump", @error)

    If $bStringIsString Then
        _cveStringRelease($string)
    EndIf
EndFunc   ;==>_cveDnnNetDump

Func _cveDnnNetDumpToFile($net, $path)
    ; CVAPI(void) cveDnnNetDumpToFile(cv::dnn::Net* net, cv::String* path);

    Local $bNetDllType
    If VarGetType($net) == "DLLStruct" Then
        $bNetDllType = "struct*"
    Else
        $bNetDllType = "ptr"
    EndIf

    Local $bPathIsString = VarGetType($path) == "String"
    If $bPathIsString Then
        $path = _cveStringCreateFromStr($path)
    EndIf

    Local $bPathDllType
    If VarGetType($path) == "DLLStruct" Then
        $bPathDllType = "struct*"
    Else
        $bPathDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDnnNetDumpToFile", $bNetDllType, $net, $bPathDllType, $path), "cveDnnNetDumpToFile", @error)

    If $bPathIsString Then
        _cveStringRelease($path)
    EndIf
EndFunc   ;==>_cveDnnNetDumpToFile

Func _cveDnnNetGetLayerNames($net)
    ; CVAPI(std::vector<cv::String>*) cveDnnNetGetLayerNames(cv::dnn::Net* net);

    Local $bNetDllType
    If VarGetType($net) == "DLLStruct" Then
        $bNetDllType = "struct*"
    Else
        $bNetDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveDnnNetGetLayerNames", $bNetDllType, $net), "cveDnnNetGetLayerNames", @error)
EndFunc   ;==>_cveDnnNetGetLayerNames

Func _cveDnnGetLayerId($net, $layer)
    ; CVAPI(int) cveDnnGetLayerId(cv::dnn::Net* net, cv::String* layer);

    Local $bNetDllType
    If VarGetType($net) == "DLLStruct" Then
        $bNetDllType = "struct*"
    Else
        $bNetDllType = "ptr"
    EndIf

    Local $bLayerIsString = VarGetType($layer) == "String"
    If $bLayerIsString Then
        $layer = _cveStringCreateFromStr($layer)
    EndIf

    Local $bLayerDllType
    If VarGetType($layer) == "DLLStruct" Then
        $bLayerDllType = "struct*"
    Else
        $bLayerDllType = "ptr"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveDnnGetLayerId", $bNetDllType, $net, $bLayerDllType, $layer), "cveDnnGetLayerId", @error)

    If $bLayerIsString Then
        _cveStringRelease($layer)
    EndIf

    Return $retval
EndFunc   ;==>_cveDnnGetLayerId

Func _cveDnnGetLayerByName($net, $layerName, $sharedPtr)
    ; CVAPI(cv::dnn::Layer*) cveDnnGetLayerByName(cv::dnn::Net* net, cv::String* layerName, cv::Ptr<cv::dnn::Layer>** sharedPtr);

    Local $bNetDllType
    If VarGetType($net) == "DLLStruct" Then
        $bNetDllType = "struct*"
    Else
        $bNetDllType = "ptr"
    EndIf

    Local $bLayerNameIsString = VarGetType($layerName) == "String"
    If $bLayerNameIsString Then
        $layerName = _cveStringCreateFromStr($layerName)
    EndIf

    Local $bLayerNameDllType
    If VarGetType($layerName) == "DLLStruct" Then
        $bLayerNameDllType = "struct*"
    Else
        $bLayerNameDllType = "ptr"
    EndIf

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveDnnGetLayerByName", $bNetDllType, $net, $bLayerNameDllType, $layerName, $bSharedPtrDllType, $sharedPtr), "cveDnnGetLayerByName", @error)

    If $bLayerNameIsString Then
        _cveStringRelease($layerName)
    EndIf

    Return $retval
EndFunc   ;==>_cveDnnGetLayerByName

Func _cveDnnGetLayerById($net, $layerId, $sharedPtr)
    ; CVAPI(cv::dnn::Layer*) cveDnnGetLayerById(cv::dnn::Net* net, int layerId, cv::Ptr<cv::dnn::Layer>** sharedPtr);

    Local $bNetDllType
    If VarGetType($net) == "DLLStruct" Then
        $bNetDllType = "struct*"
    Else
        $bNetDllType = "ptr"
    EndIf

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveDnnGetLayerById", $bNetDllType, $net, "int", $layerId, $bSharedPtrDllType, $sharedPtr), "cveDnnGetLayerById", @error)
EndFunc   ;==>_cveDnnGetLayerById

Func _cveDnnLayerRelease($layer)
    ; CVAPI(void) cveDnnLayerRelease(cv::Ptr<cv::dnn::Layer>** layer);

    Local $bLayerDllType
    If VarGetType($layer) == "DLLStruct" Then
        $bLayerDllType = "struct*"
    Else
        $bLayerDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDnnLayerRelease", $bLayerDllType, $layer), "cveDnnLayerRelease", @error)
EndFunc   ;==>_cveDnnLayerRelease

Func _cveDnnLayerGetBlobs($layer)
    ; CVAPI(std::vector<cv::Mat>*) cveDnnLayerGetBlobs(cv::dnn::Layer* layer);

    Local $bLayerDllType
    If VarGetType($layer) == "DLLStruct" Then
        $bLayerDllType = "struct*"
    Else
        $bLayerDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveDnnLayerGetBlobs", $bLayerDllType, $layer), "cveDnnLayerGetBlobs", @error)
EndFunc   ;==>_cveDnnLayerGetBlobs

Func _cveDnnBlobFromImage($image, $blob, $scalefactor, $size, $mean, $swapRB, $crop, $ddepth)
    ; CVAPI(void) cveDnnBlobFromImage(cv::_InputArray* image, cv::_OutputArray* blob, double scalefactor, CvSize* size, CvScalar* mean, bool swapRB, bool crop, int ddepth);

    Local $bImageDllType
    If VarGetType($image) == "DLLStruct" Then
        $bImageDllType = "struct*"
    Else
        $bImageDllType = "ptr"
    EndIf

    Local $bBlobDllType
    If VarGetType($blob) == "DLLStruct" Then
        $bBlobDllType = "struct*"
    Else
        $bBlobDllType = "ptr"
    EndIf

    Local $bSizeDllType
    If VarGetType($size) == "DLLStruct" Then
        $bSizeDllType = "struct*"
    Else
        $bSizeDllType = "ptr"
    EndIf

    Local $bMeanDllType
    If VarGetType($mean) == "DLLStruct" Then
        $bMeanDllType = "struct*"
    Else
        $bMeanDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDnnBlobFromImage", $bImageDllType, $image, $bBlobDllType, $blob, "double", $scalefactor, $bSizeDllType, $size, $bMeanDllType, $mean, "boolean", $swapRB, "boolean", $crop, "int", $ddepth), "cveDnnBlobFromImage", @error)
EndFunc   ;==>_cveDnnBlobFromImage

Func _cveDnnBlobFromImageMat($matImage, $matBlob, $scalefactor, $size, $mean, $swapRB, $crop, $ddepth)
    ; cveDnnBlobFromImage using cv::Mat instead of _*Array

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

    Local $oArrBlob, $vectorOfMatBlob, $iArrBlobSize
    Local $bBlobIsArray = VarGetType($matBlob) == "Array"

    If $bBlobIsArray Then
        $vectorOfMatBlob = _VectorOfMatCreate()

        $iArrBlobSize = UBound($matBlob)
        For $i = 0 To $iArrBlobSize - 1
            _VectorOfMatPush($vectorOfMatBlob, $matBlob[$i])
        Next

        $oArrBlob = _cveOutputArrayFromVectorOfMat($vectorOfMatBlob)
    Else
        $oArrBlob = _cveOutputArrayFromMat($matBlob)
    EndIf

    _cveDnnBlobFromImage($iArrImage, $oArrBlob, $scalefactor, $size, $mean, $swapRB, $crop, $ddepth)

    If $bBlobIsArray Then
        _VectorOfMatRelease($vectorOfMatBlob)
    EndIf

    _cveOutputArrayRelease($oArrBlob)

    If $bImageIsArray Then
        _VectorOfMatRelease($vectorOfMatImage)
    EndIf

    _cveInputArrayRelease($iArrImage)
EndFunc   ;==>_cveDnnBlobFromImageMat

Func _cveDnnBlobFromImages($images, $blob, $scalefactor, $size, $mean, $swapRB, $crop, $ddepth)
    ; CVAPI(void) cveDnnBlobFromImages(cv::_InputArray* images, cv::_OutputArray* blob, double scalefactor, CvSize* size, CvScalar* mean, bool swapRB, bool crop, int ddepth);

    Local $bImagesDllType
    If VarGetType($images) == "DLLStruct" Then
        $bImagesDllType = "struct*"
    Else
        $bImagesDllType = "ptr"
    EndIf

    Local $bBlobDllType
    If VarGetType($blob) == "DLLStruct" Then
        $bBlobDllType = "struct*"
    Else
        $bBlobDllType = "ptr"
    EndIf

    Local $bSizeDllType
    If VarGetType($size) == "DLLStruct" Then
        $bSizeDllType = "struct*"
    Else
        $bSizeDllType = "ptr"
    EndIf

    Local $bMeanDllType
    If VarGetType($mean) == "DLLStruct" Then
        $bMeanDllType = "struct*"
    Else
        $bMeanDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDnnBlobFromImages", $bImagesDllType, $images, $bBlobDllType, $blob, "double", $scalefactor, $bSizeDllType, $size, $bMeanDllType, $mean, "boolean", $swapRB, "boolean", $crop, "int", $ddepth), "cveDnnBlobFromImages", @error)
EndFunc   ;==>_cveDnnBlobFromImages

Func _cveDnnBlobFromImagesMat($matImages, $matBlob, $scalefactor, $size, $mean, $swapRB, $crop, $ddepth)
    ; cveDnnBlobFromImages using cv::Mat instead of _*Array

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

    Local $oArrBlob, $vectorOfMatBlob, $iArrBlobSize
    Local $bBlobIsArray = VarGetType($matBlob) == "Array"

    If $bBlobIsArray Then
        $vectorOfMatBlob = _VectorOfMatCreate()

        $iArrBlobSize = UBound($matBlob)
        For $i = 0 To $iArrBlobSize - 1
            _VectorOfMatPush($vectorOfMatBlob, $matBlob[$i])
        Next

        $oArrBlob = _cveOutputArrayFromVectorOfMat($vectorOfMatBlob)
    Else
        $oArrBlob = _cveOutputArrayFromMat($matBlob)
    EndIf

    _cveDnnBlobFromImages($iArrImages, $oArrBlob, $scalefactor, $size, $mean, $swapRB, $crop, $ddepth)

    If $bBlobIsArray Then
        _VectorOfMatRelease($vectorOfMatBlob)
    EndIf

    _cveOutputArrayRelease($oArrBlob)

    If $bImagesIsArray Then
        _VectorOfMatRelease($vectorOfMatImages)
    EndIf

    _cveInputArrayRelease($iArrImages)
EndFunc   ;==>_cveDnnBlobFromImagesMat

Func _cveDnnImagesFromBlob($blob, $images)
    ; CVAPI(void) cveDnnImagesFromBlob(cv::Mat* blob, cv::_OutputArray* images);

    Local $bBlobDllType
    If VarGetType($blob) == "DLLStruct" Then
        $bBlobDllType = "struct*"
    Else
        $bBlobDllType = "ptr"
    EndIf

    Local $bImagesDllType
    If VarGetType($images) == "DLLStruct" Then
        $bImagesDllType = "struct*"
    Else
        $bImagesDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDnnImagesFromBlob", $bBlobDllType, $blob, $bImagesDllType, $images), "cveDnnImagesFromBlob", @error)
EndFunc   ;==>_cveDnnImagesFromBlob

Func _cveDnnImagesFromBlobMat($blob, $matImages)
    ; cveDnnImagesFromBlob using cv::Mat instead of _*Array

    Local $oArrImages, $vectorOfMatImages, $iArrImagesSize
    Local $bImagesIsArray = VarGetType($matImages) == "Array"

    If $bImagesIsArray Then
        $vectorOfMatImages = _VectorOfMatCreate()

        $iArrImagesSize = UBound($matImages)
        For $i = 0 To $iArrImagesSize - 1
            _VectorOfMatPush($vectorOfMatImages, $matImages[$i])
        Next

        $oArrImages = _cveOutputArrayFromVectorOfMat($vectorOfMatImages)
    Else
        $oArrImages = _cveOutputArrayFromMat($matImages)
    EndIf

    _cveDnnImagesFromBlob($blob, $oArrImages)

    If $bImagesIsArray Then
        _VectorOfMatRelease($vectorOfMatImages)
    EndIf

    _cveOutputArrayRelease($oArrImages)
EndFunc   ;==>_cveDnnImagesFromBlobMat

Func _cveDnnShrinkCaffeModel($src, $dst)
    ; CVAPI(void) cveDnnShrinkCaffeModel(cv::String* src, cv::String* dst);

    Local $bSrcIsString = VarGetType($src) == "String"
    If $bSrcIsString Then
        $src = _cveStringCreateFromStr($src)
    EndIf

    Local $bSrcDllType
    If VarGetType($src) == "DLLStruct" Then
        $bSrcDllType = "struct*"
    Else
        $bSrcDllType = "ptr"
    EndIf

    Local $bDstIsString = VarGetType($dst) == "String"
    If $bDstIsString Then
        $dst = _cveStringCreateFromStr($dst)
    EndIf

    Local $bDstDllType
    If VarGetType($dst) == "DLLStruct" Then
        $bDstDllType = "struct*"
    Else
        $bDstDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDnnShrinkCaffeModel", $bSrcDllType, $src, $bDstDllType, $dst), "cveDnnShrinkCaffeModel", @error)

    If $bDstIsString Then
        _cveStringRelease($dst)
    EndIf

    If $bSrcIsString Then
        _cveStringRelease($src)
    EndIf
EndFunc   ;==>_cveDnnShrinkCaffeModel

Func _cveDnnWriteTextGraph($model, $output)
    ; CVAPI(void) cveDnnWriteTextGraph(cv::String* model, cv::String* output);

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

    Local $bOutputIsString = VarGetType($output) == "String"
    If $bOutputIsString Then
        $output = _cveStringCreateFromStr($output)
    EndIf

    Local $bOutputDllType
    If VarGetType($output) == "DLLStruct" Then
        $bOutputDllType = "struct*"
    Else
        $bOutputDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDnnWriteTextGraph", $bModelDllType, $model, $bOutputDllType, $output), "cveDnnWriteTextGraph", @error)

    If $bOutputIsString Then
        _cveStringRelease($output)
    EndIf

    If $bModelIsString Then
        _cveStringRelease($model)
    EndIf
EndFunc   ;==>_cveDnnWriteTextGraph

Func _cveDnnNMSBoxes($bboxes, $scores, $scoreThreshold, $nmsThreshold, $indices, $eta, $topK)
    ; CVAPI(void) cveDnnNMSBoxes(std::vector<cv::Rect>* bboxes, std::vector<float>* scores, float scoreThreshold, float nmsThreshold, std::vector<int>* indices, float eta, int topK);

    Local $vecBboxes, $iArrBboxesSize
    Local $bBboxesIsArray = VarGetType($bboxes) == "Array"

    If $bBboxesIsArray Then
        $vecBboxes = _VectorOfRectCreate()

        $iArrBboxesSize = UBound($bboxes)
        For $i = 0 To $iArrBboxesSize - 1
            _VectorOfRectPush($vecBboxes, $bboxes[$i])
        Next
    Else
        $vecBboxes = $bboxes
    EndIf

    Local $bBboxesDllType
    If VarGetType($bboxes) == "DLLStruct" Then
        $bBboxesDllType = "struct*"
    Else
        $bBboxesDllType = "ptr"
    EndIf

    Local $vecScores, $iArrScoresSize
    Local $bScoresIsArray = VarGetType($scores) == "Array"

    If $bScoresIsArray Then
        $vecScores = _VectorOfFloatCreate()

        $iArrScoresSize = UBound($scores)
        For $i = 0 To $iArrScoresSize - 1
            _VectorOfFloatPush($vecScores, $scores[$i])
        Next
    Else
        $vecScores = $scores
    EndIf

    Local $bScoresDllType
    If VarGetType($scores) == "DLLStruct" Then
        $bScoresDllType = "struct*"
    Else
        $bScoresDllType = "ptr"
    EndIf

    Local $vecIndices, $iArrIndicesSize
    Local $bIndicesIsArray = VarGetType($indices) == "Array"

    If $bIndicesIsArray Then
        $vecIndices = _VectorOfIntCreate()

        $iArrIndicesSize = UBound($indices)
        For $i = 0 To $iArrIndicesSize - 1
            _VectorOfIntPush($vecIndices, $indices[$i])
        Next
    Else
        $vecIndices = $indices
    EndIf

    Local $bIndicesDllType
    If VarGetType($indices) == "DLLStruct" Then
        $bIndicesDllType = "struct*"
    Else
        $bIndicesDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDnnNMSBoxes", $bBboxesDllType, $vecBboxes, $bScoresDllType, $vecScores, "float", $scoreThreshold, "float", $nmsThreshold, $bIndicesDllType, $vecIndices, "float", $eta, "int", $topK), "cveDnnNMSBoxes", @error)

    If $bIndicesIsArray Then
        _VectorOfIntRelease($vecIndices)
    EndIf

    If $bScoresIsArray Then
        _VectorOfFloatRelease($vecScores)
    EndIf

    If $bBboxesIsArray Then
        _VectorOfRectRelease($vecBboxes)
    EndIf
EndFunc   ;==>_cveDnnNMSBoxes

Func _cveDnnNMSBoxes2($bboxes, $scores, $scoreThreshold, $nmsThreshold, $indices, $eta, $topK)
    ; CVAPI(void) cveDnnNMSBoxes2(std::vector<cv::RotatedRect>* bboxes, std::vector<float>* scores, float scoreThreshold, float nmsThreshold, std::vector<int>* indices, float eta, int topK);

    Local $vecBboxes, $iArrBboxesSize
    Local $bBboxesIsArray = VarGetType($bboxes) == "Array"

    If $bBboxesIsArray Then
        $vecBboxes = _VectorOfRotatedRectCreate()

        $iArrBboxesSize = UBound($bboxes)
        For $i = 0 To $iArrBboxesSize - 1
            _VectorOfRotatedRectPush($vecBboxes, $bboxes[$i])
        Next
    Else
        $vecBboxes = $bboxes
    EndIf

    Local $bBboxesDllType
    If VarGetType($bboxes) == "DLLStruct" Then
        $bBboxesDllType = "struct*"
    Else
        $bBboxesDllType = "ptr"
    EndIf

    Local $vecScores, $iArrScoresSize
    Local $bScoresIsArray = VarGetType($scores) == "Array"

    If $bScoresIsArray Then
        $vecScores = _VectorOfFloatCreate()

        $iArrScoresSize = UBound($scores)
        For $i = 0 To $iArrScoresSize - 1
            _VectorOfFloatPush($vecScores, $scores[$i])
        Next
    Else
        $vecScores = $scores
    EndIf

    Local $bScoresDllType
    If VarGetType($scores) == "DLLStruct" Then
        $bScoresDllType = "struct*"
    Else
        $bScoresDllType = "ptr"
    EndIf

    Local $vecIndices, $iArrIndicesSize
    Local $bIndicesIsArray = VarGetType($indices) == "Array"

    If $bIndicesIsArray Then
        $vecIndices = _VectorOfIntCreate()

        $iArrIndicesSize = UBound($indices)
        For $i = 0 To $iArrIndicesSize - 1
            _VectorOfIntPush($vecIndices, $indices[$i])
        Next
    Else
        $vecIndices = $indices
    EndIf

    Local $bIndicesDllType
    If VarGetType($indices) == "DLLStruct" Then
        $bIndicesDllType = "struct*"
    Else
        $bIndicesDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDnnNMSBoxes2", $bBboxesDllType, $vecBboxes, $bScoresDllType, $vecScores, "float", $scoreThreshold, "float", $nmsThreshold, $bIndicesDllType, $vecIndices, "float", $eta, "int", $topK), "cveDnnNMSBoxes2", @error)

    If $bIndicesIsArray Then
        _VectorOfIntRelease($vecIndices)
    EndIf

    If $bScoresIsArray Then
        _VectorOfFloatRelease($vecScores)
    EndIf

    If $bBboxesIsArray Then
        _VectorOfRotatedRectRelease($vecBboxes)
    EndIf
EndFunc   ;==>_cveDnnNMSBoxes2

Func _cveDNNGetAvailableBackends($backends, $targets)
    ; CVAPI(void) cveDNNGetAvailableBackends(std::vector<int>* backends, std::vector<int>* targets);

    Local $vecBackends, $iArrBackendsSize
    Local $bBackendsIsArray = VarGetType($backends) == "Array"

    If $bBackendsIsArray Then
        $vecBackends = _VectorOfIntCreate()

        $iArrBackendsSize = UBound($backends)
        For $i = 0 To $iArrBackendsSize - 1
            _VectorOfIntPush($vecBackends, $backends[$i])
        Next
    Else
        $vecBackends = $backends
    EndIf

    Local $bBackendsDllType
    If VarGetType($backends) == "DLLStruct" Then
        $bBackendsDllType = "struct*"
    Else
        $bBackendsDllType = "ptr"
    EndIf

    Local $vecTargets, $iArrTargetsSize
    Local $bTargetsIsArray = VarGetType($targets) == "Array"

    If $bTargetsIsArray Then
        $vecTargets = _VectorOfIntCreate()

        $iArrTargetsSize = UBound($targets)
        For $i = 0 To $iArrTargetsSize - 1
            _VectorOfIntPush($vecTargets, $targets[$i])
        Next
    Else
        $vecTargets = $targets
    EndIf

    Local $bTargetsDllType
    If VarGetType($targets) == "DLLStruct" Then
        $bTargetsDllType = "struct*"
    Else
        $bTargetsDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDNNGetAvailableBackends", $bBackendsDllType, $vecBackends, $bTargetsDllType, $vecTargets), "cveDNNGetAvailableBackends", @error)

    If $bTargetsIsArray Then
        _VectorOfIntRelease($vecTargets)
    EndIf

    If $bBackendsIsArray Then
        _VectorOfIntRelease($vecBackends)
    EndIf
EndFunc   ;==>_cveDNNGetAvailableBackends

Func _cveDnnTextDetectionModelDbCreate1($model, $config, $textDetectionModel, $baseModel)
    ; CVAPI(cv::dnn::TextDetectionModel_DB*) cveDnnTextDetectionModelDbCreate1(cv::String* model, cv::String* config, cv::dnn::TextDetectionModel** textDetectionModel, cv::dnn::Model** baseModel);

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

    Local $bConfigIsString = VarGetType($config) == "String"
    If $bConfigIsString Then
        $config = _cveStringCreateFromStr($config)
    EndIf

    Local $bConfigDllType
    If VarGetType($config) == "DLLStruct" Then
        $bConfigDllType = "struct*"
    Else
        $bConfigDllType = "ptr"
    EndIf

    Local $bTextDetectionModelDllType
    If VarGetType($textDetectionModel) == "DLLStruct" Then
        $bTextDetectionModelDllType = "struct*"
    Else
        $bTextDetectionModelDllType = "ptr*"
    EndIf

    Local $bBaseModelDllType
    If VarGetType($baseModel) == "DLLStruct" Then
        $bBaseModelDllType = "struct*"
    Else
        $bBaseModelDllType = "ptr*"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveDnnTextDetectionModelDbCreate1", $bModelDllType, $model, $bConfigDllType, $config, $bTextDetectionModelDllType, $textDetectionModel, $bBaseModelDllType, $baseModel), "cveDnnTextDetectionModelDbCreate1", @error)

    If $bConfigIsString Then
        _cveStringRelease($config)
    EndIf

    If $bModelIsString Then
        _cveStringRelease($model)
    EndIf

    Return $retval
EndFunc   ;==>_cveDnnTextDetectionModelDbCreate1

Func _cveDnnTextDetectionModelDbCreate2($network, $textDetectionModel, $baseModel)
    ; CVAPI(cv::dnn::TextDetectionModel_DB*) cveDnnTextDetectionModelDbCreate2(cv::dnn::Net* network, cv::dnn::TextDetectionModel** textDetectionModel, cv::dnn::Model** baseModel);

    Local $bNetworkDllType
    If VarGetType($network) == "DLLStruct" Then
        $bNetworkDllType = "struct*"
    Else
        $bNetworkDllType = "ptr"
    EndIf

    Local $bTextDetectionModelDllType
    If VarGetType($textDetectionModel) == "DLLStruct" Then
        $bTextDetectionModelDllType = "struct*"
    Else
        $bTextDetectionModelDllType = "ptr*"
    EndIf

    Local $bBaseModelDllType
    If VarGetType($baseModel) == "DLLStruct" Then
        $bBaseModelDllType = "struct*"
    Else
        $bBaseModelDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveDnnTextDetectionModelDbCreate2", $bNetworkDllType, $network, $bTextDetectionModelDllType, $textDetectionModel, $bBaseModelDllType, $baseModel), "cveDnnTextDetectionModelDbCreate2", @error)
EndFunc   ;==>_cveDnnTextDetectionModelDbCreate2

Func _cveDnnTextDetectionModelDbRelease($textDetectionModel)
    ; CVAPI(void) cveDnnTextDetectionModelDbRelease(cv::dnn::TextDetectionModel_DB** textDetectionModel);

    Local $bTextDetectionModelDllType
    If VarGetType($textDetectionModel) == "DLLStruct" Then
        $bTextDetectionModelDllType = "struct*"
    Else
        $bTextDetectionModelDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDnnTextDetectionModelDbRelease", $bTextDetectionModelDllType, $textDetectionModel), "cveDnnTextDetectionModelDbRelease", @error)
EndFunc   ;==>_cveDnnTextDetectionModelDbRelease

Func _cveDnnTextDetectionModelEastCreate1($model, $config, $textDetectionModel, $baseModel)
    ; CVAPI(cv::dnn::TextDetectionModel_EAST*) cveDnnTextDetectionModelEastCreate1(cv::String* model, cv::String* config, cv::dnn::TextDetectionModel** textDetectionModel, cv::dnn::Model** baseModel);

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

    Local $bConfigIsString = VarGetType($config) == "String"
    If $bConfigIsString Then
        $config = _cveStringCreateFromStr($config)
    EndIf

    Local $bConfigDllType
    If VarGetType($config) == "DLLStruct" Then
        $bConfigDllType = "struct*"
    Else
        $bConfigDllType = "ptr"
    EndIf

    Local $bTextDetectionModelDllType
    If VarGetType($textDetectionModel) == "DLLStruct" Then
        $bTextDetectionModelDllType = "struct*"
    Else
        $bTextDetectionModelDllType = "ptr*"
    EndIf

    Local $bBaseModelDllType
    If VarGetType($baseModel) == "DLLStruct" Then
        $bBaseModelDllType = "struct*"
    Else
        $bBaseModelDllType = "ptr*"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveDnnTextDetectionModelEastCreate1", $bModelDllType, $model, $bConfigDllType, $config, $bTextDetectionModelDllType, $textDetectionModel, $bBaseModelDllType, $baseModel), "cveDnnTextDetectionModelEastCreate1", @error)

    If $bConfigIsString Then
        _cveStringRelease($config)
    EndIf

    If $bModelIsString Then
        _cveStringRelease($model)
    EndIf

    Return $retval
EndFunc   ;==>_cveDnnTextDetectionModelEastCreate1

Func _cveDnnTextDetectionModelEastCreate2($network, $textDetectionModel, $baseModel)
    ; CVAPI(cv::dnn::TextDetectionModel_EAST*) cveDnnTextDetectionModelEastCreate2(cv::dnn::Net* network, cv::dnn::TextDetectionModel** textDetectionModel, cv::dnn::Model** baseModel);

    Local $bNetworkDllType
    If VarGetType($network) == "DLLStruct" Then
        $bNetworkDllType = "struct*"
    Else
        $bNetworkDllType = "ptr"
    EndIf

    Local $bTextDetectionModelDllType
    If VarGetType($textDetectionModel) == "DLLStruct" Then
        $bTextDetectionModelDllType = "struct*"
    Else
        $bTextDetectionModelDllType = "ptr*"
    EndIf

    Local $bBaseModelDllType
    If VarGetType($baseModel) == "DLLStruct" Then
        $bBaseModelDllType = "struct*"
    Else
        $bBaseModelDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveDnnTextDetectionModelEastCreate2", $bNetworkDllType, $network, $bTextDetectionModelDllType, $textDetectionModel, $bBaseModelDllType, $baseModel), "cveDnnTextDetectionModelEastCreate2", @error)
EndFunc   ;==>_cveDnnTextDetectionModelEastCreate2

Func _cveDnnTextDetectionModelEastRelease($textDetectionModel)
    ; CVAPI(void) cveDnnTextDetectionModelEastRelease(cv::dnn::TextDetectionModel_EAST** textDetectionModel);

    Local $bTextDetectionModelDllType
    If VarGetType($textDetectionModel) == "DLLStruct" Then
        $bTextDetectionModelDllType = "struct*"
    Else
        $bTextDetectionModelDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDnnTextDetectionModelEastRelease", $bTextDetectionModelDllType, $textDetectionModel), "cveDnnTextDetectionModelEastRelease", @error)
EndFunc   ;==>_cveDnnTextDetectionModelEastRelease

Func _cveDnnTextDetectionModelDetect($textDetectionModel, $frame, $detections, $confidences)
    ; CVAPI(void) cveDnnTextDetectionModelDetect(cv::dnn::TextDetectionModel* textDetectionModel, cv::_InputArray* frame, std::vector<std::vector<cv::Point>>* detections, std::vector<float>* confidences);

    Local $bTextDetectionModelDllType
    If VarGetType($textDetectionModel) == "DLLStruct" Then
        $bTextDetectionModelDllType = "struct*"
    Else
        $bTextDetectionModelDllType = "ptr"
    EndIf

    Local $bFrameDllType
    If VarGetType($frame) == "DLLStruct" Then
        $bFrameDllType = "struct*"
    Else
        $bFrameDllType = "ptr"
    EndIf

    Local $vecDetections, $iArrDetectionsSize
    Local $bDetectionsIsArray = VarGetType($detections) == "Array"

    If $bDetectionsIsArray Then
        $vecDetections = _VectorOfVectorOfPointCreate()

        $iArrDetectionsSize = UBound($detections)
        For $i = 0 To $iArrDetectionsSize - 1
            _VectorOfVectorOfPointPush($vecDetections, $detections[$i])
        Next
    Else
        $vecDetections = $detections
    EndIf

    Local $bDetectionsDllType
    If VarGetType($detections) == "DLLStruct" Then
        $bDetectionsDllType = "struct*"
    Else
        $bDetectionsDllType = "ptr"
    EndIf

    Local $vecConfidences, $iArrConfidencesSize
    Local $bConfidencesIsArray = VarGetType($confidences) == "Array"

    If $bConfidencesIsArray Then
        $vecConfidences = _VectorOfFloatCreate()

        $iArrConfidencesSize = UBound($confidences)
        For $i = 0 To $iArrConfidencesSize - 1
            _VectorOfFloatPush($vecConfidences, $confidences[$i])
        Next
    Else
        $vecConfidences = $confidences
    EndIf

    Local $bConfidencesDllType
    If VarGetType($confidences) == "DLLStruct" Then
        $bConfidencesDllType = "struct*"
    Else
        $bConfidencesDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDnnTextDetectionModelDetect", $bTextDetectionModelDllType, $textDetectionModel, $bFrameDllType, $frame, $bDetectionsDllType, $vecDetections, $bConfidencesDllType, $vecConfidences), "cveDnnTextDetectionModelDetect", @error)

    If $bConfidencesIsArray Then
        _VectorOfFloatRelease($vecConfidences)
    EndIf

    If $bDetectionsIsArray Then
        _VectorOfVectorOfPointRelease($vecDetections)
    EndIf
EndFunc   ;==>_cveDnnTextDetectionModelDetect

Func _cveDnnTextDetectionModelDetectMat($textDetectionModel, $matFrame, $detections, $confidences)
    ; cveDnnTextDetectionModelDetect using cv::Mat instead of _*Array

    Local $iArrFrame, $vectorOfMatFrame, $iArrFrameSize
    Local $bFrameIsArray = VarGetType($matFrame) == "Array"

    If $bFrameIsArray Then
        $vectorOfMatFrame = _VectorOfMatCreate()

        $iArrFrameSize = UBound($matFrame)
        For $i = 0 To $iArrFrameSize - 1
            _VectorOfMatPush($vectorOfMatFrame, $matFrame[$i])
        Next

        $iArrFrame = _cveInputArrayFromVectorOfMat($vectorOfMatFrame)
    Else
        $iArrFrame = _cveInputArrayFromMat($matFrame)
    EndIf

    _cveDnnTextDetectionModelDetect($textDetectionModel, $iArrFrame, $detections, $confidences)

    If $bFrameIsArray Then
        _VectorOfMatRelease($vectorOfMatFrame)
    EndIf

    _cveInputArrayRelease($iArrFrame)
EndFunc   ;==>_cveDnnTextDetectionModelDetectMat

Func _cveDnnTextDetectionModelDetectTextRectangles($textDetectionModel, $frame, $detections, $confidences)
    ; CVAPI(void) cveDnnTextDetectionModelDetectTextRectangles(cv::dnn::TextDetectionModel* textDetectionModel, cv::_InputArray* frame, std::vector<cv::RotatedRect>* detections, std::vector<float>* confidences);

    Local $bTextDetectionModelDllType
    If VarGetType($textDetectionModel) == "DLLStruct" Then
        $bTextDetectionModelDllType = "struct*"
    Else
        $bTextDetectionModelDllType = "ptr"
    EndIf

    Local $bFrameDllType
    If VarGetType($frame) == "DLLStruct" Then
        $bFrameDllType = "struct*"
    Else
        $bFrameDllType = "ptr"
    EndIf

    Local $vecDetections, $iArrDetectionsSize
    Local $bDetectionsIsArray = VarGetType($detections) == "Array"

    If $bDetectionsIsArray Then
        $vecDetections = _VectorOfRotatedRectCreate()

        $iArrDetectionsSize = UBound($detections)
        For $i = 0 To $iArrDetectionsSize - 1
            _VectorOfRotatedRectPush($vecDetections, $detections[$i])
        Next
    Else
        $vecDetections = $detections
    EndIf

    Local $bDetectionsDllType
    If VarGetType($detections) == "DLLStruct" Then
        $bDetectionsDllType = "struct*"
    Else
        $bDetectionsDllType = "ptr"
    EndIf

    Local $vecConfidences, $iArrConfidencesSize
    Local $bConfidencesIsArray = VarGetType($confidences) == "Array"

    If $bConfidencesIsArray Then
        $vecConfidences = _VectorOfFloatCreate()

        $iArrConfidencesSize = UBound($confidences)
        For $i = 0 To $iArrConfidencesSize - 1
            _VectorOfFloatPush($vecConfidences, $confidences[$i])
        Next
    Else
        $vecConfidences = $confidences
    EndIf

    Local $bConfidencesDllType
    If VarGetType($confidences) == "DLLStruct" Then
        $bConfidencesDllType = "struct*"
    Else
        $bConfidencesDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDnnTextDetectionModelDetectTextRectangles", $bTextDetectionModelDllType, $textDetectionModel, $bFrameDllType, $frame, $bDetectionsDllType, $vecDetections, $bConfidencesDllType, $vecConfidences), "cveDnnTextDetectionModelDetectTextRectangles", @error)

    If $bConfidencesIsArray Then
        _VectorOfFloatRelease($vecConfidences)
    EndIf

    If $bDetectionsIsArray Then
        _VectorOfRotatedRectRelease($vecDetections)
    EndIf
EndFunc   ;==>_cveDnnTextDetectionModelDetectTextRectangles

Func _cveDnnTextDetectionModelDetectTextRectanglesMat($textDetectionModel, $matFrame, $detections, $confidences)
    ; cveDnnTextDetectionModelDetectTextRectangles using cv::Mat instead of _*Array

    Local $iArrFrame, $vectorOfMatFrame, $iArrFrameSize
    Local $bFrameIsArray = VarGetType($matFrame) == "Array"

    If $bFrameIsArray Then
        $vectorOfMatFrame = _VectorOfMatCreate()

        $iArrFrameSize = UBound($matFrame)
        For $i = 0 To $iArrFrameSize - 1
            _VectorOfMatPush($vectorOfMatFrame, $matFrame[$i])
        Next

        $iArrFrame = _cveInputArrayFromVectorOfMat($vectorOfMatFrame)
    Else
        $iArrFrame = _cveInputArrayFromMat($matFrame)
    EndIf

    _cveDnnTextDetectionModelDetectTextRectangles($textDetectionModel, $iArrFrame, $detections, $confidences)

    If $bFrameIsArray Then
        _VectorOfMatRelease($vectorOfMatFrame)
    EndIf

    _cveInputArrayRelease($iArrFrame)
EndFunc   ;==>_cveDnnTextDetectionModelDetectTextRectanglesMat

Func _cveDnnTextRecognitionModelCreate1($model, $config, $baseModel)
    ; CVAPI(cv::dnn::TextRecognitionModel*) cveDnnTextRecognitionModelCreate1(cv::String* model, cv::String* config, cv::dnn::Model** baseModel);

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

    Local $bConfigIsString = VarGetType($config) == "String"
    If $bConfigIsString Then
        $config = _cveStringCreateFromStr($config)
    EndIf

    Local $bConfigDllType
    If VarGetType($config) == "DLLStruct" Then
        $bConfigDllType = "struct*"
    Else
        $bConfigDllType = "ptr"
    EndIf

    Local $bBaseModelDllType
    If VarGetType($baseModel) == "DLLStruct" Then
        $bBaseModelDllType = "struct*"
    Else
        $bBaseModelDllType = "ptr*"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveDnnTextRecognitionModelCreate1", $bModelDllType, $model, $bConfigDllType, $config, $bBaseModelDllType, $baseModel), "cveDnnTextRecognitionModelCreate1", @error)

    If $bConfigIsString Then
        _cveStringRelease($config)
    EndIf

    If $bModelIsString Then
        _cveStringRelease($model)
    EndIf

    Return $retval
EndFunc   ;==>_cveDnnTextRecognitionModelCreate1

Func _cveDnnTextRecognitionModelCreate2($network, $baseModel)
    ; CVAPI(cv::dnn::TextRecognitionModel*) cveDnnTextRecognitionModelCreate2(cv::dnn::Net* network, cv::dnn::Model** baseModel);

    Local $bNetworkDllType
    If VarGetType($network) == "DLLStruct" Then
        $bNetworkDllType = "struct*"
    Else
        $bNetworkDllType = "ptr"
    EndIf

    Local $bBaseModelDllType
    If VarGetType($baseModel) == "DLLStruct" Then
        $bBaseModelDllType = "struct*"
    Else
        $bBaseModelDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveDnnTextRecognitionModelCreate2", $bNetworkDllType, $network, $bBaseModelDllType, $baseModel), "cveDnnTextRecognitionModelCreate2", @error)
EndFunc   ;==>_cveDnnTextRecognitionModelCreate2

Func _cveDnnTextRecognitionModelRelease($textRecognitionModel)
    ; CVAPI(void) cveDnnTextRecognitionModelRelease(cv::dnn::TextRecognitionModel** textRecognitionModel);

    Local $bTextRecognitionModelDllType
    If VarGetType($textRecognitionModel) == "DLLStruct" Then
        $bTextRecognitionModelDllType = "struct*"
    Else
        $bTextRecognitionModelDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDnnTextRecognitionModelRelease", $bTextRecognitionModelDllType, $textRecognitionModel), "cveDnnTextRecognitionModelRelease", @error)
EndFunc   ;==>_cveDnnTextRecognitionModelRelease

Func _cveDnnTextRecognitionModelSetVocabulary($textRecognitionModel, $vocabulary)
    ; CVAPI(void) cveDnnTextRecognitionModelSetVocabulary(cv::dnn::TextRecognitionModel* textRecognitionModel, std::vector<std::string>* vocabulary);

    Local $bTextRecognitionModelDllType
    If VarGetType($textRecognitionModel) == "DLLStruct" Then
        $bTextRecognitionModelDllType = "struct*"
    Else
        $bTextRecognitionModelDllType = "ptr"
    EndIf

    Local $bVocabularyDllType
    If VarGetType($vocabulary) == "DLLStruct" Then
        $bVocabularyDllType = "struct*"
    Else
        $bVocabularyDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDnnTextRecognitionModelSetVocabulary", $bTextRecognitionModelDllType, $textRecognitionModel, $bVocabularyDllType, $vocabulary), "cveDnnTextRecognitionModelSetVocabulary", @error)
EndFunc   ;==>_cveDnnTextRecognitionModelSetVocabulary

Func _cveDnnTextRecognitionModelGetVocabulary($textRecognitionModel, $vocabulary)
    ; CVAPI(void) cveDnnTextRecognitionModelGetVocabulary(cv::dnn::TextRecognitionModel* textRecognitionModel, std::vector<std::string>* vocabulary);

    Local $bTextRecognitionModelDllType
    If VarGetType($textRecognitionModel) == "DLLStruct" Then
        $bTextRecognitionModelDllType = "struct*"
    Else
        $bTextRecognitionModelDllType = "ptr"
    EndIf

    Local $bVocabularyDllType
    If VarGetType($vocabulary) == "DLLStruct" Then
        $bVocabularyDllType = "struct*"
    Else
        $bVocabularyDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDnnTextRecognitionModelGetVocabulary", $bTextRecognitionModelDllType, $textRecognitionModel, $bVocabularyDllType, $vocabulary), "cveDnnTextRecognitionModelGetVocabulary", @error)
EndFunc   ;==>_cveDnnTextRecognitionModelGetVocabulary

Func _cveDnnTextRecognitionModelRecognize1($textRecognitionModel, $frame, $text)
    ; CVAPI(void) cveDnnTextRecognitionModelRecognize1(cv::dnn::TextRecognitionModel* textRecognitionModel, cv::_InputArray* frame, cv::String* text);

    Local $bTextRecognitionModelDllType
    If VarGetType($textRecognitionModel) == "DLLStruct" Then
        $bTextRecognitionModelDllType = "struct*"
    Else
        $bTextRecognitionModelDllType = "ptr"
    EndIf

    Local $bFrameDllType
    If VarGetType($frame) == "DLLStruct" Then
        $bFrameDllType = "struct*"
    Else
        $bFrameDllType = "ptr"
    EndIf

    Local $bTextIsString = VarGetType($text) == "String"
    If $bTextIsString Then
        $text = _cveStringCreateFromStr($text)
    EndIf

    Local $bTextDllType
    If VarGetType($text) == "DLLStruct" Then
        $bTextDllType = "struct*"
    Else
        $bTextDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDnnTextRecognitionModelRecognize1", $bTextRecognitionModelDllType, $textRecognitionModel, $bFrameDllType, $frame, $bTextDllType, $text), "cveDnnTextRecognitionModelRecognize1", @error)

    If $bTextIsString Then
        _cveStringRelease($text)
    EndIf
EndFunc   ;==>_cveDnnTextRecognitionModelRecognize1

Func _cveDnnTextRecognitionModelRecognize1Mat($textRecognitionModel, $matFrame, $text)
    ; cveDnnTextRecognitionModelRecognize1 using cv::Mat instead of _*Array

    Local $iArrFrame, $vectorOfMatFrame, $iArrFrameSize
    Local $bFrameIsArray = VarGetType($matFrame) == "Array"

    If $bFrameIsArray Then
        $vectorOfMatFrame = _VectorOfMatCreate()

        $iArrFrameSize = UBound($matFrame)
        For $i = 0 To $iArrFrameSize - 1
            _VectorOfMatPush($vectorOfMatFrame, $matFrame[$i])
        Next

        $iArrFrame = _cveInputArrayFromVectorOfMat($vectorOfMatFrame)
    Else
        $iArrFrame = _cveInputArrayFromMat($matFrame)
    EndIf

    _cveDnnTextRecognitionModelRecognize1($textRecognitionModel, $iArrFrame, $text)

    If $bFrameIsArray Then
        _VectorOfMatRelease($vectorOfMatFrame)
    EndIf

    _cveInputArrayRelease($iArrFrame)
EndFunc   ;==>_cveDnnTextRecognitionModelRecognize1Mat

Func _cveDnnTextRecognitionModelRecognize2($textRecognitionModel, $frame, $roiRects, $results)
    ; CVAPI(void) cveDnnTextRecognitionModelRecognize2(cv::dnn::TextRecognitionModel* textRecognitionModel, cv::_InputArray* frame, cv::_InputArray* roiRects, std::vector<std::string>* results);

    Local $bTextRecognitionModelDllType
    If VarGetType($textRecognitionModel) == "DLLStruct" Then
        $bTextRecognitionModelDllType = "struct*"
    Else
        $bTextRecognitionModelDllType = "ptr"
    EndIf

    Local $bFrameDllType
    If VarGetType($frame) == "DLLStruct" Then
        $bFrameDllType = "struct*"
    Else
        $bFrameDllType = "ptr"
    EndIf

    Local $bRoiRectsDllType
    If VarGetType($roiRects) == "DLLStruct" Then
        $bRoiRectsDllType = "struct*"
    Else
        $bRoiRectsDllType = "ptr"
    EndIf

    Local $bResultsDllType
    If VarGetType($results) == "DLLStruct" Then
        $bResultsDllType = "struct*"
    Else
        $bResultsDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDnnTextRecognitionModelRecognize2", $bTextRecognitionModelDllType, $textRecognitionModel, $bFrameDllType, $frame, $bRoiRectsDllType, $roiRects, $bResultsDllType, $results), "cveDnnTextRecognitionModelRecognize2", @error)
EndFunc   ;==>_cveDnnTextRecognitionModelRecognize2

Func _cveDnnTextRecognitionModelRecognize2Mat($textRecognitionModel, $matFrame, $matRoiRects, $results)
    ; cveDnnTextRecognitionModelRecognize2 using cv::Mat instead of _*Array

    Local $iArrFrame, $vectorOfMatFrame, $iArrFrameSize
    Local $bFrameIsArray = VarGetType($matFrame) == "Array"

    If $bFrameIsArray Then
        $vectorOfMatFrame = _VectorOfMatCreate()

        $iArrFrameSize = UBound($matFrame)
        For $i = 0 To $iArrFrameSize - 1
            _VectorOfMatPush($vectorOfMatFrame, $matFrame[$i])
        Next

        $iArrFrame = _cveInputArrayFromVectorOfMat($vectorOfMatFrame)
    Else
        $iArrFrame = _cveInputArrayFromMat($matFrame)
    EndIf

    Local $iArrRoiRects, $vectorOfMatRoiRects, $iArrRoiRectsSize
    Local $bRoiRectsIsArray = VarGetType($matRoiRects) == "Array"

    If $bRoiRectsIsArray Then
        $vectorOfMatRoiRects = _VectorOfMatCreate()

        $iArrRoiRectsSize = UBound($matRoiRects)
        For $i = 0 To $iArrRoiRectsSize - 1
            _VectorOfMatPush($vectorOfMatRoiRects, $matRoiRects[$i])
        Next

        $iArrRoiRects = _cveInputArrayFromVectorOfMat($vectorOfMatRoiRects)
    Else
        $iArrRoiRects = _cveInputArrayFromMat($matRoiRects)
    EndIf

    _cveDnnTextRecognitionModelRecognize2($textRecognitionModel, $iArrFrame, $iArrRoiRects, $results)

    If $bRoiRectsIsArray Then
        _VectorOfMatRelease($vectorOfMatRoiRects)
    EndIf

    _cveInputArrayRelease($iArrRoiRects)

    If $bFrameIsArray Then
        _VectorOfMatRelease($vectorOfMatFrame)
    EndIf

    _cveInputArrayRelease($iArrFrame)
EndFunc   ;==>_cveDnnTextRecognitionModelRecognize2Mat

Func _cveModelCreate($model, $config)
    ; CVAPI(cv::dnn::Model*) cveModelCreate(cv::String* model, cv::String* config);

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

    Local $bConfigIsString = VarGetType($config) == "String"
    If $bConfigIsString Then
        $config = _cveStringCreateFromStr($config)
    EndIf

    Local $bConfigDllType
    If VarGetType($config) == "DLLStruct" Then
        $bConfigDllType = "struct*"
    Else
        $bConfigDllType = "ptr"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveModelCreate", $bModelDllType, $model, $bConfigDllType, $config), "cveModelCreate", @error)

    If $bConfigIsString Then
        _cveStringRelease($config)
    EndIf

    If $bModelIsString Then
        _cveStringRelease($model)
    EndIf

    Return $retval
EndFunc   ;==>_cveModelCreate

Func _cveModelCreateFromNet($network)
    ; CVAPI(cv::dnn::Model*) cveModelCreateFromNet(cv::dnn::Net* network);

    Local $bNetworkDllType
    If VarGetType($network) == "DLLStruct" Then
        $bNetworkDllType = "struct*"
    Else
        $bNetworkDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveModelCreateFromNet", $bNetworkDllType, $network), "cveModelCreateFromNet", @error)
EndFunc   ;==>_cveModelCreateFromNet

Func _cveModelRelease($model)
    ; CVAPI(void) cveModelRelease(cv::dnn::Model** model);

    Local $bModelDllType
    If VarGetType($model) == "DLLStruct" Then
        $bModelDllType = "struct*"
    Else
        $bModelDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveModelRelease", $bModelDllType, $model), "cveModelRelease", @error)
EndFunc   ;==>_cveModelRelease

Func _cveModelPredict($model, $frame, $outs)
    ; CVAPI(void) cveModelPredict(cv::dnn::Model* model, cv::_InputArray* frame, cv::_OutputArray* outs);

    Local $bModelDllType
    If VarGetType($model) == "DLLStruct" Then
        $bModelDllType = "struct*"
    Else
        $bModelDllType = "ptr"
    EndIf

    Local $bFrameDllType
    If VarGetType($frame) == "DLLStruct" Then
        $bFrameDllType = "struct*"
    Else
        $bFrameDllType = "ptr"
    EndIf

    Local $bOutsDllType
    If VarGetType($outs) == "DLLStruct" Then
        $bOutsDllType = "struct*"
    Else
        $bOutsDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveModelPredict", $bModelDllType, $model, $bFrameDllType, $frame, $bOutsDllType, $outs), "cveModelPredict", @error)
EndFunc   ;==>_cveModelPredict

Func _cveModelPredictMat($model, $matFrame, $matOuts)
    ; cveModelPredict using cv::Mat instead of _*Array

    Local $iArrFrame, $vectorOfMatFrame, $iArrFrameSize
    Local $bFrameIsArray = VarGetType($matFrame) == "Array"

    If $bFrameIsArray Then
        $vectorOfMatFrame = _VectorOfMatCreate()

        $iArrFrameSize = UBound($matFrame)
        For $i = 0 To $iArrFrameSize - 1
            _VectorOfMatPush($vectorOfMatFrame, $matFrame[$i])
        Next

        $iArrFrame = _cveInputArrayFromVectorOfMat($vectorOfMatFrame)
    Else
        $iArrFrame = _cveInputArrayFromMat($matFrame)
    EndIf

    Local $oArrOuts, $vectorOfMatOuts, $iArrOutsSize
    Local $bOutsIsArray = VarGetType($matOuts) == "Array"

    If $bOutsIsArray Then
        $vectorOfMatOuts = _VectorOfMatCreate()

        $iArrOutsSize = UBound($matOuts)
        For $i = 0 To $iArrOutsSize - 1
            _VectorOfMatPush($vectorOfMatOuts, $matOuts[$i])
        Next

        $oArrOuts = _cveOutputArrayFromVectorOfMat($vectorOfMatOuts)
    Else
        $oArrOuts = _cveOutputArrayFromMat($matOuts)
    EndIf

    _cveModelPredict($model, $iArrFrame, $oArrOuts)

    If $bOutsIsArray Then
        _VectorOfMatRelease($vectorOfMatOuts)
    EndIf

    _cveOutputArrayRelease($oArrOuts)

    If $bFrameIsArray Then
        _VectorOfMatRelease($vectorOfMatFrame)
    EndIf

    _cveInputArrayRelease($iArrFrame)
EndFunc   ;==>_cveModelPredictMat

Func _cveModelSetInputMean($model, $mean)
    ; CVAPI(void) cveModelSetInputMean(cv::dnn::Model* model, CvScalar* mean);

    Local $bModelDllType
    If VarGetType($model) == "DLLStruct" Then
        $bModelDllType = "struct*"
    Else
        $bModelDllType = "ptr"
    EndIf

    Local $bMeanDllType
    If VarGetType($mean) == "DLLStruct" Then
        $bMeanDllType = "struct*"
    Else
        $bMeanDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveModelSetInputMean", $bModelDllType, $model, $bMeanDllType, $mean), "cveModelSetInputMean", @error)
EndFunc   ;==>_cveModelSetInputMean

Func _cveModelSetInputScale($model, $value)
    ; CVAPI(void) cveModelSetInputScale(cv::dnn::Model* model, double value);

    Local $bModelDllType
    If VarGetType($model) == "DLLStruct" Then
        $bModelDllType = "struct*"
    Else
        $bModelDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveModelSetInputScale", $bModelDllType, $model, "double", $value), "cveModelSetInputScale", @error)
EndFunc   ;==>_cveModelSetInputScale

Func _cveModelSetInputSize($model, $size)
    ; CVAPI(void) cveModelSetInputSize(cv::dnn::Model* model, CvSize* size);

    Local $bModelDllType
    If VarGetType($model) == "DLLStruct" Then
        $bModelDllType = "struct*"
    Else
        $bModelDllType = "ptr"
    EndIf

    Local $bSizeDllType
    If VarGetType($size) == "DLLStruct" Then
        $bSizeDllType = "struct*"
    Else
        $bSizeDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveModelSetInputSize", $bModelDllType, $model, $bSizeDllType, $size), "cveModelSetInputSize", @error)
EndFunc   ;==>_cveModelSetInputSize

Func _cveModelSetInputCrop($model, $crop)
    ; CVAPI(void) cveModelSetInputCrop(cv::dnn::Model* model, bool crop);

    Local $bModelDllType
    If VarGetType($model) == "DLLStruct" Then
        $bModelDllType = "struct*"
    Else
        $bModelDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveModelSetInputCrop", $bModelDllType, $model, "boolean", $crop), "cveModelSetInputCrop", @error)
EndFunc   ;==>_cveModelSetInputCrop

Func _cveModelSetInputSwapRB($model, $swapRB)
    ; CVAPI(void) cveModelSetInputSwapRB(cv::dnn::Model* model, bool swapRB);

    Local $bModelDllType
    If VarGetType($model) == "DLLStruct" Then
        $bModelDllType = "struct*"
    Else
        $bModelDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveModelSetInputSwapRB", $bModelDllType, $model, "boolean", $swapRB), "cveModelSetInputSwapRB", @error)
EndFunc   ;==>_cveModelSetInputSwapRB

Func _cveModelSetPreferableBackend($model, $backendId)
    ; CVAPI(void) cveModelSetPreferableBackend(cv::dnn::Model* model, int backendId);

    Local $bModelDllType
    If VarGetType($model) == "DLLStruct" Then
        $bModelDllType = "struct*"
    Else
        $bModelDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveModelSetPreferableBackend", $bModelDllType, $model, "int", $backendId), "cveModelSetPreferableBackend", @error)
EndFunc   ;==>_cveModelSetPreferableBackend

Func _cveModelSetPreferableTarget($model, $targetId)
    ; CVAPI(void) cveModelSetPreferableTarget(cv::dnn::Model* model, int targetId);

    Local $bModelDllType
    If VarGetType($model) == "DLLStruct" Then
        $bModelDllType = "struct*"
    Else
        $bModelDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveModelSetPreferableTarget", $bModelDllType, $model, "int", $targetId), "cveModelSetPreferableTarget", @error)
EndFunc   ;==>_cveModelSetPreferableTarget

Func _cveDnnDetectionModelCreate1($model, $config, $baseModel)
    ; CVAPI(cv::dnn::DetectionModel*) cveDnnDetectionModelCreate1(cv::String* model, cv::String* config, cv::dnn::Model** baseModel);

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

    Local $bConfigIsString = VarGetType($config) == "String"
    If $bConfigIsString Then
        $config = _cveStringCreateFromStr($config)
    EndIf

    Local $bConfigDllType
    If VarGetType($config) == "DLLStruct" Then
        $bConfigDllType = "struct*"
    Else
        $bConfigDllType = "ptr"
    EndIf

    Local $bBaseModelDllType
    If VarGetType($baseModel) == "DLLStruct" Then
        $bBaseModelDllType = "struct*"
    Else
        $bBaseModelDllType = "ptr*"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveDnnDetectionModelCreate1", $bModelDllType, $model, $bConfigDllType, $config, $bBaseModelDllType, $baseModel), "cveDnnDetectionModelCreate1", @error)

    If $bConfigIsString Then
        _cveStringRelease($config)
    EndIf

    If $bModelIsString Then
        _cveStringRelease($model)
    EndIf

    Return $retval
EndFunc   ;==>_cveDnnDetectionModelCreate1

Func _cveDnnDetectionModelCreate2($network, $baseModel)
    ; CVAPI(cv::dnn::DetectionModel*) cveDnnDetectionModelCreate2(cv::dnn::Net* network, cv::dnn::Model** baseModel);

    Local $bNetworkDllType
    If VarGetType($network) == "DLLStruct" Then
        $bNetworkDllType = "struct*"
    Else
        $bNetworkDllType = "ptr"
    EndIf

    Local $bBaseModelDllType
    If VarGetType($baseModel) == "DLLStruct" Then
        $bBaseModelDllType = "struct*"
    Else
        $bBaseModelDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveDnnDetectionModelCreate2", $bNetworkDllType, $network, $bBaseModelDllType, $baseModel), "cveDnnDetectionModelCreate2", @error)
EndFunc   ;==>_cveDnnDetectionModelCreate2

Func _cveDnnDetectionModelRelease($detectionModel)
    ; CVAPI(void) cveDnnDetectionModelRelease(cv::dnn::DetectionModel** detectionModel);

    Local $bDetectionModelDllType
    If VarGetType($detectionModel) == "DLLStruct" Then
        $bDetectionModelDllType = "struct*"
    Else
        $bDetectionModelDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDnnDetectionModelRelease", $bDetectionModelDllType, $detectionModel), "cveDnnDetectionModelRelease", @error)
EndFunc   ;==>_cveDnnDetectionModelRelease

Func _cveDnnDetectionModelDetect($detectionModel, $frame, $classIds, $confidences, $boxes, $confThreshold, $nmsThreshold)
    ; CVAPI(void) cveDnnDetectionModelDetect(cv::dnn::DetectionModel* detectionModel, cv::_InputArray* frame, std::vector<int>* classIds, std::vector<float>* confidences, std::vector<cv::Rect>* boxes, float confThreshold, float nmsThreshold);

    Local $bDetectionModelDllType
    If VarGetType($detectionModel) == "DLLStruct" Then
        $bDetectionModelDllType = "struct*"
    Else
        $bDetectionModelDllType = "ptr"
    EndIf

    Local $bFrameDllType
    If VarGetType($frame) == "DLLStruct" Then
        $bFrameDllType = "struct*"
    Else
        $bFrameDllType = "ptr"
    EndIf

    Local $vecClassIds, $iArrClassIdsSize
    Local $bClassIdsIsArray = VarGetType($classIds) == "Array"

    If $bClassIdsIsArray Then
        $vecClassIds = _VectorOfIntCreate()

        $iArrClassIdsSize = UBound($classIds)
        For $i = 0 To $iArrClassIdsSize - 1
            _VectorOfIntPush($vecClassIds, $classIds[$i])
        Next
    Else
        $vecClassIds = $classIds
    EndIf

    Local $bClassIdsDllType
    If VarGetType($classIds) == "DLLStruct" Then
        $bClassIdsDllType = "struct*"
    Else
        $bClassIdsDllType = "ptr"
    EndIf

    Local $vecConfidences, $iArrConfidencesSize
    Local $bConfidencesIsArray = VarGetType($confidences) == "Array"

    If $bConfidencesIsArray Then
        $vecConfidences = _VectorOfFloatCreate()

        $iArrConfidencesSize = UBound($confidences)
        For $i = 0 To $iArrConfidencesSize - 1
            _VectorOfFloatPush($vecConfidences, $confidences[$i])
        Next
    Else
        $vecConfidences = $confidences
    EndIf

    Local $bConfidencesDllType
    If VarGetType($confidences) == "DLLStruct" Then
        $bConfidencesDllType = "struct*"
    Else
        $bConfidencesDllType = "ptr"
    EndIf

    Local $vecBoxes, $iArrBoxesSize
    Local $bBoxesIsArray = VarGetType($boxes) == "Array"

    If $bBoxesIsArray Then
        $vecBoxes = _VectorOfRectCreate()

        $iArrBoxesSize = UBound($boxes)
        For $i = 0 To $iArrBoxesSize - 1
            _VectorOfRectPush($vecBoxes, $boxes[$i])
        Next
    Else
        $vecBoxes = $boxes
    EndIf

    Local $bBoxesDllType
    If VarGetType($boxes) == "DLLStruct" Then
        $bBoxesDllType = "struct*"
    Else
        $bBoxesDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDnnDetectionModelDetect", $bDetectionModelDllType, $detectionModel, $bFrameDllType, $frame, $bClassIdsDllType, $vecClassIds, $bConfidencesDllType, $vecConfidences, $bBoxesDllType, $vecBoxes, "float", $confThreshold, "float", $nmsThreshold), "cveDnnDetectionModelDetect", @error)

    If $bBoxesIsArray Then
        _VectorOfRectRelease($vecBoxes)
    EndIf

    If $bConfidencesIsArray Then
        _VectorOfFloatRelease($vecConfidences)
    EndIf

    If $bClassIdsIsArray Then
        _VectorOfIntRelease($vecClassIds)
    EndIf
EndFunc   ;==>_cveDnnDetectionModelDetect

Func _cveDnnDetectionModelDetectMat($detectionModel, $matFrame, $classIds, $confidences, $boxes, $confThreshold, $nmsThreshold)
    ; cveDnnDetectionModelDetect using cv::Mat instead of _*Array

    Local $iArrFrame, $vectorOfMatFrame, $iArrFrameSize
    Local $bFrameIsArray = VarGetType($matFrame) == "Array"

    If $bFrameIsArray Then
        $vectorOfMatFrame = _VectorOfMatCreate()

        $iArrFrameSize = UBound($matFrame)
        For $i = 0 To $iArrFrameSize - 1
            _VectorOfMatPush($vectorOfMatFrame, $matFrame[$i])
        Next

        $iArrFrame = _cveInputArrayFromVectorOfMat($vectorOfMatFrame)
    Else
        $iArrFrame = _cveInputArrayFromMat($matFrame)
    EndIf

    _cveDnnDetectionModelDetect($detectionModel, $iArrFrame, $classIds, $confidences, $boxes, $confThreshold, $nmsThreshold)

    If $bFrameIsArray Then
        _VectorOfMatRelease($vectorOfMatFrame)
    EndIf

    _cveInputArrayRelease($iArrFrame)
EndFunc   ;==>_cveDnnDetectionModelDetectMat

Func _cveDnnClassificationModelCreate1($model, $config, $baseModel)
    ; CVAPI(cv::dnn::ClassificationModel*) cveDnnClassificationModelCreate1(cv::String* model, cv::String* config, cv::dnn::Model** baseModel);

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

    Local $bConfigIsString = VarGetType($config) == "String"
    If $bConfigIsString Then
        $config = _cveStringCreateFromStr($config)
    EndIf

    Local $bConfigDllType
    If VarGetType($config) == "DLLStruct" Then
        $bConfigDllType = "struct*"
    Else
        $bConfigDllType = "ptr"
    EndIf

    Local $bBaseModelDllType
    If VarGetType($baseModel) == "DLLStruct" Then
        $bBaseModelDllType = "struct*"
    Else
        $bBaseModelDllType = "ptr*"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveDnnClassificationModelCreate1", $bModelDllType, $model, $bConfigDllType, $config, $bBaseModelDllType, $baseModel), "cveDnnClassificationModelCreate1", @error)

    If $bConfigIsString Then
        _cveStringRelease($config)
    EndIf

    If $bModelIsString Then
        _cveStringRelease($model)
    EndIf

    Return $retval
EndFunc   ;==>_cveDnnClassificationModelCreate1

Func _cveDnnClassificationModelCreate2($network, $baseModel)
    ; CVAPI(cv::dnn::ClassificationModel*) cveDnnClassificationModelCreate2(cv::dnn::Net* network, cv::dnn::Model** baseModel);

    Local $bNetworkDllType
    If VarGetType($network) == "DLLStruct" Then
        $bNetworkDllType = "struct*"
    Else
        $bNetworkDllType = "ptr"
    EndIf

    Local $bBaseModelDllType
    If VarGetType($baseModel) == "DLLStruct" Then
        $bBaseModelDllType = "struct*"
    Else
        $bBaseModelDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveDnnClassificationModelCreate2", $bNetworkDllType, $network, $bBaseModelDllType, $baseModel), "cveDnnClassificationModelCreate2", @error)
EndFunc   ;==>_cveDnnClassificationModelCreate2

Func _cveDnnClassificationModelRelease($classificationModel)
    ; CVAPI(void) cveDnnClassificationModelRelease(cv::dnn::ClassificationModel** classificationModel);

    Local $bClassificationModelDllType
    If VarGetType($classificationModel) == "DLLStruct" Then
        $bClassificationModelDllType = "struct*"
    Else
        $bClassificationModelDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDnnClassificationModelRelease", $bClassificationModelDllType, $classificationModel), "cveDnnClassificationModelRelease", @error)
EndFunc   ;==>_cveDnnClassificationModelRelease

Func _cveDnnClassificationModelClassify($classificationModel, $frame, $classId, $conf)
    ; CVAPI(void) cveDnnClassificationModelClassify(cv::dnn::ClassificationModel* classificationModel, cv::_InputArray* frame, int* classId, float* conf);

    Local $bClassificationModelDllType
    If VarGetType($classificationModel) == "DLLStruct" Then
        $bClassificationModelDllType = "struct*"
    Else
        $bClassificationModelDllType = "ptr"
    EndIf

    Local $bFrameDllType
    If VarGetType($frame) == "DLLStruct" Then
        $bFrameDllType = "struct*"
    Else
        $bFrameDllType = "ptr"
    EndIf

    Local $bClassIdDllType
    If VarGetType($classId) == "DLLStruct" Then
        $bClassIdDllType = "struct*"
    Else
        $bClassIdDllType = "int*"
    EndIf

    Local $bConfDllType
    If VarGetType($conf) == "DLLStruct" Then
        $bConfDllType = "struct*"
    Else
        $bConfDllType = "float*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDnnClassificationModelClassify", $bClassificationModelDllType, $classificationModel, $bFrameDllType, $frame, $bClassIdDllType, $classId, $bConfDllType, $conf), "cveDnnClassificationModelClassify", @error)
EndFunc   ;==>_cveDnnClassificationModelClassify

Func _cveDnnClassificationModelClassifyMat($classificationModel, $matFrame, $classId, $conf)
    ; cveDnnClassificationModelClassify using cv::Mat instead of _*Array

    Local $iArrFrame, $vectorOfMatFrame, $iArrFrameSize
    Local $bFrameIsArray = VarGetType($matFrame) == "Array"

    If $bFrameIsArray Then
        $vectorOfMatFrame = _VectorOfMatCreate()

        $iArrFrameSize = UBound($matFrame)
        For $i = 0 To $iArrFrameSize - 1
            _VectorOfMatPush($vectorOfMatFrame, $matFrame[$i])
        Next

        $iArrFrame = _cveInputArrayFromVectorOfMat($vectorOfMatFrame)
    Else
        $iArrFrame = _cveInputArrayFromMat($matFrame)
    EndIf

    _cveDnnClassificationModelClassify($classificationModel, $iArrFrame, $classId, $conf)

    If $bFrameIsArray Then
        _VectorOfMatRelease($vectorOfMatFrame)
    EndIf

    _cveInputArrayRelease($iArrFrame)
EndFunc   ;==>_cveDnnClassificationModelClassifyMat

Func _cveDnnKeypointsModelCreate1($model, $config, $baseModel)
    ; CVAPI(cv::dnn::KeypointsModel*) cveDnnKeypointsModelCreate1(cv::String* model, cv::String* config, cv::dnn::Model** baseModel);

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

    Local $bConfigIsString = VarGetType($config) == "String"
    If $bConfigIsString Then
        $config = _cveStringCreateFromStr($config)
    EndIf

    Local $bConfigDllType
    If VarGetType($config) == "DLLStruct" Then
        $bConfigDllType = "struct*"
    Else
        $bConfigDllType = "ptr"
    EndIf

    Local $bBaseModelDllType
    If VarGetType($baseModel) == "DLLStruct" Then
        $bBaseModelDllType = "struct*"
    Else
        $bBaseModelDllType = "ptr*"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveDnnKeypointsModelCreate1", $bModelDllType, $model, $bConfigDllType, $config, $bBaseModelDllType, $baseModel), "cveDnnKeypointsModelCreate1", @error)

    If $bConfigIsString Then
        _cveStringRelease($config)
    EndIf

    If $bModelIsString Then
        _cveStringRelease($model)
    EndIf

    Return $retval
EndFunc   ;==>_cveDnnKeypointsModelCreate1

Func _cveDnnKeypointsModelCreate2($network, $baseModel)
    ; CVAPI(cv::dnn::KeypointsModel*) cveDnnKeypointsModelCreate2(cv::dnn::Net* network, cv::dnn::Model** baseModel);

    Local $bNetworkDllType
    If VarGetType($network) == "DLLStruct" Then
        $bNetworkDllType = "struct*"
    Else
        $bNetworkDllType = "ptr"
    EndIf

    Local $bBaseModelDllType
    If VarGetType($baseModel) == "DLLStruct" Then
        $bBaseModelDllType = "struct*"
    Else
        $bBaseModelDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveDnnKeypointsModelCreate2", $bNetworkDllType, $network, $bBaseModelDllType, $baseModel), "cveDnnKeypointsModelCreate2", @error)
EndFunc   ;==>_cveDnnKeypointsModelCreate2

Func _cveDnnKeypointsModelRelease($keypointsModel)
    ; CVAPI(void) cveDnnKeypointsModelRelease(cv::dnn::KeypointsModel** keypointsModel);

    Local $bKeypointsModelDllType
    If VarGetType($keypointsModel) == "DLLStruct" Then
        $bKeypointsModelDllType = "struct*"
    Else
        $bKeypointsModelDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDnnKeypointsModelRelease", $bKeypointsModelDllType, $keypointsModel), "cveDnnKeypointsModelRelease", @error)
EndFunc   ;==>_cveDnnKeypointsModelRelease

Func _cveDnnKeypointsModelEstimate($keypointsModel, $frame, $keypoints, $thresh)
    ; CVAPI(void) cveDnnKeypointsModelEstimate(cv::dnn::KeypointsModel* keypointsModel, cv::_InputArray* frame, std::vector<cv::Point2f>* keypoints, float thresh);

    Local $bKeypointsModelDllType
    If VarGetType($keypointsModel) == "DLLStruct" Then
        $bKeypointsModelDllType = "struct*"
    Else
        $bKeypointsModelDllType = "ptr"
    EndIf

    Local $bFrameDllType
    If VarGetType($frame) == "DLLStruct" Then
        $bFrameDllType = "struct*"
    Else
        $bFrameDllType = "ptr"
    EndIf

    Local $vecKeypoints, $iArrKeypointsSize
    Local $bKeypointsIsArray = VarGetType($keypoints) == "Array"

    If $bKeypointsIsArray Then
        $vecKeypoints = _VectorOfPointFCreate()

        $iArrKeypointsSize = UBound($keypoints)
        For $i = 0 To $iArrKeypointsSize - 1
            _VectorOfPointFPush($vecKeypoints, $keypoints[$i])
        Next
    Else
        $vecKeypoints = $keypoints
    EndIf

    Local $bKeypointsDllType
    If VarGetType($keypoints) == "DLLStruct" Then
        $bKeypointsDllType = "struct*"
    Else
        $bKeypointsDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDnnKeypointsModelEstimate", $bKeypointsModelDllType, $keypointsModel, $bFrameDllType, $frame, $bKeypointsDllType, $vecKeypoints, "float", $thresh), "cveDnnKeypointsModelEstimate", @error)

    If $bKeypointsIsArray Then
        _VectorOfPointFRelease($vecKeypoints)
    EndIf
EndFunc   ;==>_cveDnnKeypointsModelEstimate

Func _cveDnnKeypointsModelEstimateMat($keypointsModel, $matFrame, $keypoints, $thresh)
    ; cveDnnKeypointsModelEstimate using cv::Mat instead of _*Array

    Local $iArrFrame, $vectorOfMatFrame, $iArrFrameSize
    Local $bFrameIsArray = VarGetType($matFrame) == "Array"

    If $bFrameIsArray Then
        $vectorOfMatFrame = _VectorOfMatCreate()

        $iArrFrameSize = UBound($matFrame)
        For $i = 0 To $iArrFrameSize - 1
            _VectorOfMatPush($vectorOfMatFrame, $matFrame[$i])
        Next

        $iArrFrame = _cveInputArrayFromVectorOfMat($vectorOfMatFrame)
    Else
        $iArrFrame = _cveInputArrayFromMat($matFrame)
    EndIf

    _cveDnnKeypointsModelEstimate($keypointsModel, $iArrFrame, $keypoints, $thresh)

    If $bFrameIsArray Then
        _VectorOfMatRelease($vectorOfMatFrame)
    EndIf

    _cveInputArrayRelease($iArrFrame)
EndFunc   ;==>_cveDnnKeypointsModelEstimateMat

Func _cveDnnSegmentationModelCreate1($model, $config, $baseModel)
    ; CVAPI(cv::dnn::SegmentationModel*) cveDnnSegmentationModelCreate1(cv::String* model, cv::String* config, cv::dnn::Model** baseModel);

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

    Local $bConfigIsString = VarGetType($config) == "String"
    If $bConfigIsString Then
        $config = _cveStringCreateFromStr($config)
    EndIf

    Local $bConfigDllType
    If VarGetType($config) == "DLLStruct" Then
        $bConfigDllType = "struct*"
    Else
        $bConfigDllType = "ptr"
    EndIf

    Local $bBaseModelDllType
    If VarGetType($baseModel) == "DLLStruct" Then
        $bBaseModelDllType = "struct*"
    Else
        $bBaseModelDllType = "ptr*"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveDnnSegmentationModelCreate1", $bModelDllType, $model, $bConfigDllType, $config, $bBaseModelDllType, $baseModel), "cveDnnSegmentationModelCreate1", @error)

    If $bConfigIsString Then
        _cveStringRelease($config)
    EndIf

    If $bModelIsString Then
        _cveStringRelease($model)
    EndIf

    Return $retval
EndFunc   ;==>_cveDnnSegmentationModelCreate1

Func _cveDnnSegmentationModelCreate2($network, $baseModel)
    ; CVAPI(cv::dnn::SegmentationModel*) cveDnnSegmentationModelCreate2(cv::dnn::Net* network, cv::dnn::Model** baseModel);

    Local $bNetworkDllType
    If VarGetType($network) == "DLLStruct" Then
        $bNetworkDllType = "struct*"
    Else
        $bNetworkDllType = "ptr"
    EndIf

    Local $bBaseModelDllType
    If VarGetType($baseModel) == "DLLStruct" Then
        $bBaseModelDllType = "struct*"
    Else
        $bBaseModelDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveDnnSegmentationModelCreate2", $bNetworkDllType, $network, $bBaseModelDllType, $baseModel), "cveDnnSegmentationModelCreate2", @error)
EndFunc   ;==>_cveDnnSegmentationModelCreate2

Func _cveDnnSegmentationModelRelease($segmentationModel)
    ; CVAPI(void) cveDnnSegmentationModelRelease(cv::dnn::SegmentationModel** segmentationModel);

    Local $bSegmentationModelDllType
    If VarGetType($segmentationModel) == "DLLStruct" Then
        $bSegmentationModelDllType = "struct*"
    Else
        $bSegmentationModelDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDnnSegmentationModelRelease", $bSegmentationModelDllType, $segmentationModel), "cveDnnSegmentationModelRelease", @error)
EndFunc   ;==>_cveDnnSegmentationModelRelease

Func _cveDnnSegmentationModelSegment($segmentationModel, $frame, $mask)
    ; CVAPI(void) cveDnnSegmentationModelSegment(cv::dnn::SegmentationModel* segmentationModel, cv::_InputArray* frame, cv::_OutputArray* mask);

    Local $bSegmentationModelDllType
    If VarGetType($segmentationModel) == "DLLStruct" Then
        $bSegmentationModelDllType = "struct*"
    Else
        $bSegmentationModelDllType = "ptr"
    EndIf

    Local $bFrameDllType
    If VarGetType($frame) == "DLLStruct" Then
        $bFrameDllType = "struct*"
    Else
        $bFrameDllType = "ptr"
    EndIf

    Local $bMaskDllType
    If VarGetType($mask) == "DLLStruct" Then
        $bMaskDllType = "struct*"
    Else
        $bMaskDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDnnSegmentationModelSegment", $bSegmentationModelDllType, $segmentationModel, $bFrameDllType, $frame, $bMaskDllType, $mask), "cveDnnSegmentationModelSegment", @error)
EndFunc   ;==>_cveDnnSegmentationModelSegment

Func _cveDnnSegmentationModelSegmentMat($segmentationModel, $matFrame, $matMask)
    ; cveDnnSegmentationModelSegment using cv::Mat instead of _*Array

    Local $iArrFrame, $vectorOfMatFrame, $iArrFrameSize
    Local $bFrameIsArray = VarGetType($matFrame) == "Array"

    If $bFrameIsArray Then
        $vectorOfMatFrame = _VectorOfMatCreate()

        $iArrFrameSize = UBound($matFrame)
        For $i = 0 To $iArrFrameSize - 1
            _VectorOfMatPush($vectorOfMatFrame, $matFrame[$i])
        Next

        $iArrFrame = _cveInputArrayFromVectorOfMat($vectorOfMatFrame)
    Else
        $iArrFrame = _cveInputArrayFromMat($matFrame)
    EndIf

    Local $oArrMask, $vectorOfMatMask, $iArrMaskSize
    Local $bMaskIsArray = VarGetType($matMask) == "Array"

    If $bMaskIsArray Then
        $vectorOfMatMask = _VectorOfMatCreate()

        $iArrMaskSize = UBound($matMask)
        For $i = 0 To $iArrMaskSize - 1
            _VectorOfMatPush($vectorOfMatMask, $matMask[$i])
        Next

        $oArrMask = _cveOutputArrayFromVectorOfMat($vectorOfMatMask)
    Else
        $oArrMask = _cveOutputArrayFromMat($matMask)
    EndIf

    _cveDnnSegmentationModelSegment($segmentationModel, $iArrFrame, $oArrMask)

    If $bMaskIsArray Then
        _VectorOfMatRelease($vectorOfMatMask)
    EndIf

    _cveOutputArrayRelease($oArrMask)

    If $bFrameIsArray Then
        _VectorOfMatRelease($vectorOfMatFrame)
    EndIf

    _cveInputArrayRelease($iArrFrame)
EndFunc   ;==>_cveDnnSegmentationModelSegmentMat