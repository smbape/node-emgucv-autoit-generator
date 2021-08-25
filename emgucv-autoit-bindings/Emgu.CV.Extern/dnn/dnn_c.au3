#include-once
#include "..\..\CVEUtils.au3"

Func _cveReadNetFromDarknet($cfgFile, $darknetModel)
    ; CVAPI(cv::dnn::Net*) cveReadNetFromDarknet(cv::String* cfgFile, cv::String* darknetModel);

    Local $bCfgFileIsString = IsString($cfgFile)
    If $bCfgFileIsString Then
        $cfgFile = _cveStringCreateFromStr($cfgFile)
    EndIf

    Local $sCfgFileDllType
    If IsDllStruct($cfgFile) Then
        $sCfgFileDllType = "struct*"
    Else
        $sCfgFileDllType = "ptr"
    EndIf

    Local $bDarknetModelIsString = IsString($darknetModel)
    If $bDarknetModelIsString Then
        $darknetModel = _cveStringCreateFromStr($darknetModel)
    EndIf

    Local $sDarknetModelDllType
    If IsDllStruct($darknetModel) Then
        $sDarknetModelDllType = "struct*"
    Else
        $sDarknetModelDllType = "ptr"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveReadNetFromDarknet", $sCfgFileDllType, $cfgFile, $sDarknetModelDllType, $darknetModel), "cveReadNetFromDarknet", @error)

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

    Local $sBufferCfgDllType
    If IsDllStruct($bufferCfg) Then
        $sBufferCfgDllType = "struct*"
    ElseIf IsPtr($bufferCfg) Then
        $sBufferCfgDllType = "ptr"
    Else
        $sBufferCfgDllType = "str"
    EndIf

    Local $sBufferModelDllType
    If IsDllStruct($bufferModel) Then
        $sBufferModelDllType = "struct*"
    ElseIf IsPtr($bufferModel) Then
        $sBufferModelDllType = "ptr"
    Else
        $sBufferModelDllType = "str"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveReadNetFromDarknet2", $sBufferCfgDllType, $bufferCfg, "int", $lenCfg, $sBufferModelDllType, $bufferModel, "int", $lenModel), "cveReadNetFromDarknet2", @error)
EndFunc   ;==>_cveReadNetFromDarknet2

Func _cveReadNetFromCaffe($prototxt, $caffeModel)
    ; CVAPI(cv::dnn::Net*) cveReadNetFromCaffe(cv::String* prototxt, cv::String* caffeModel);

    Local $bPrototxtIsString = IsString($prototxt)
    If $bPrototxtIsString Then
        $prototxt = _cveStringCreateFromStr($prototxt)
    EndIf

    Local $sPrototxtDllType
    If IsDllStruct($prototxt) Then
        $sPrototxtDllType = "struct*"
    Else
        $sPrototxtDllType = "ptr"
    EndIf

    Local $bCaffeModelIsString = IsString($caffeModel)
    If $bCaffeModelIsString Then
        $caffeModel = _cveStringCreateFromStr($caffeModel)
    EndIf

    Local $sCaffeModelDllType
    If IsDllStruct($caffeModel) Then
        $sCaffeModelDllType = "struct*"
    Else
        $sCaffeModelDllType = "ptr"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveReadNetFromCaffe", $sPrototxtDllType, $prototxt, $sCaffeModelDllType, $caffeModel), "cveReadNetFromCaffe", @error)

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

    Local $sBufferProtoDllType
    If IsDllStruct($bufferProto) Then
        $sBufferProtoDllType = "struct*"
    ElseIf IsPtr($bufferProto) Then
        $sBufferProtoDllType = "ptr"
    Else
        $sBufferProtoDllType = "str"
    EndIf

    Local $sBufferModelDllType
    If IsDllStruct($bufferModel) Then
        $sBufferModelDllType = "struct*"
    ElseIf IsPtr($bufferModel) Then
        $sBufferModelDllType = "ptr"
    Else
        $sBufferModelDllType = "str"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveReadNetFromCaffe2", $sBufferProtoDllType, $bufferProto, "int", $lenProto, $sBufferModelDllType, $bufferModel, "int", $lenModel), "cveReadNetFromCaffe2", @error)
EndFunc   ;==>_cveReadNetFromCaffe2

Func _cveReadNetFromTensorflow($model, $config)
    ; CVAPI(cv::dnn::Net*) cveReadNetFromTensorflow(cv::String* model, cv::String* config);

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

    Local $bConfigIsString = IsString($config)
    If $bConfigIsString Then
        $config = _cveStringCreateFromStr($config)
    EndIf

    Local $sConfigDllType
    If IsDllStruct($config) Then
        $sConfigDllType = "struct*"
    Else
        $sConfigDllType = "ptr"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveReadNetFromTensorflow", $sModelDllType, $model, $sConfigDllType, $config), "cveReadNetFromTensorflow", @error)

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

    Local $sBufferModelDllType
    If IsDllStruct($bufferModel) Then
        $sBufferModelDllType = "struct*"
    ElseIf IsPtr($bufferModel) Then
        $sBufferModelDllType = "ptr"
    Else
        $sBufferModelDllType = "str"
    EndIf

    Local $sBufferConfigDllType
    If IsDllStruct($bufferConfig) Then
        $sBufferConfigDllType = "struct*"
    ElseIf IsPtr($bufferConfig) Then
        $sBufferConfigDllType = "ptr"
    Else
        $sBufferConfigDllType = "str"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveReadNetFromTensorflow2", $sBufferModelDllType, $bufferModel, "int", $lenModel, $sBufferConfigDllType, $bufferConfig, "int", $lenConfig), "cveReadNetFromTensorflow2", @error)
EndFunc   ;==>_cveReadNetFromTensorflow2

Func _cveReadNetFromONNX($onnxFile)
    ; CVAPI(cv::dnn::Net*) cveReadNetFromONNX(cv::String* onnxFile);

    Local $bOnnxFileIsString = IsString($onnxFile)
    If $bOnnxFileIsString Then
        $onnxFile = _cveStringCreateFromStr($onnxFile)
    EndIf

    Local $sOnnxFileDllType
    If IsDllStruct($onnxFile) Then
        $sOnnxFileDllType = "struct*"
    Else
        $sOnnxFileDllType = "ptr"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveReadNetFromONNX", $sOnnxFileDllType, $onnxFile), "cveReadNetFromONNX", @error)

    If $bOnnxFileIsString Then
        _cveStringRelease($onnxFile)
    EndIf

    Return $retval
EndFunc   ;==>_cveReadNetFromONNX

Func _cveReadTensorFromONNX($path, $tensor)
    ; CVAPI(void) cveReadTensorFromONNX(cv::String* path, cv::Mat* tensor);

    Local $bPathIsString = IsString($path)
    If $bPathIsString Then
        $path = _cveStringCreateFromStr($path)
    EndIf

    Local $sPathDllType
    If IsDllStruct($path) Then
        $sPathDllType = "struct*"
    Else
        $sPathDllType = "ptr"
    EndIf

    Local $sTensorDllType
    If IsDllStruct($tensor) Then
        $sTensorDllType = "struct*"
    Else
        $sTensorDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveReadTensorFromONNX", $sPathDllType, $path, $sTensorDllType, $tensor), "cveReadTensorFromONNX", @error)

    If $bPathIsString Then
        _cveStringRelease($path)
    EndIf
EndFunc   ;==>_cveReadTensorFromONNX

Func _cveReadNet($model, $config, $framework)
    ; CVAPI(cv::dnn::Net*) cveReadNet(cv::String* model, cv::String* config, cv::String* framework);

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

    Local $bConfigIsString = IsString($config)
    If $bConfigIsString Then
        $config = _cveStringCreateFromStr($config)
    EndIf

    Local $sConfigDllType
    If IsDllStruct($config) Then
        $sConfigDllType = "struct*"
    Else
        $sConfigDllType = "ptr"
    EndIf

    Local $bFrameworkIsString = IsString($framework)
    If $bFrameworkIsString Then
        $framework = _cveStringCreateFromStr($framework)
    EndIf

    Local $sFrameworkDllType
    If IsDllStruct($framework) Then
        $sFrameworkDllType = "struct*"
    Else
        $sFrameworkDllType = "ptr"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveReadNet", $sModelDllType, $model, $sConfigDllType, $config, $sFrameworkDllType, $framework), "cveReadNet", @error)

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

    Local $bXmlIsString = IsString($xml)
    If $bXmlIsString Then
        $xml = _cveStringCreateFromStr($xml)
    EndIf

    Local $sXmlDllType
    If IsDllStruct($xml) Then
        $sXmlDllType = "struct*"
    Else
        $sXmlDllType = "ptr"
    EndIf

    Local $bBinIsString = IsString($bin)
    If $bBinIsString Then
        $bin = _cveStringCreateFromStr($bin)
    EndIf

    Local $sBinDllType
    If IsDllStruct($bin) Then
        $sBinDllType = "struct*"
    Else
        $sBinDllType = "ptr"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveReadNetFromModelOptimizer", $sXmlDllType, $xml, $sBinDllType, $bin), "cveReadNetFromModelOptimizer", @error)

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

    Local $sNetDllType
    If IsDllStruct($net) Then
        $sNetDllType = "struct*"
    Else
        $sNetDllType = "ptr"
    EndIf

    Local $sBlobDllType
    If IsDllStruct($blob) Then
        $sBlobDllType = "struct*"
    Else
        $sBlobDllType = "ptr"
    EndIf

    Local $bNameIsString = IsString($name)
    If $bNameIsString Then
        $name = _cveStringCreateFromStr($name)
    EndIf

    Local $sNameDllType
    If IsDllStruct($name) Then
        $sNameDllType = "struct*"
    Else
        $sNameDllType = "ptr"
    EndIf

    Local $sMeanDllType
    If IsDllStruct($mean) Then
        $sMeanDllType = "struct*"
    Else
        $sMeanDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDnnNetSetInput", $sNetDllType, $net, $sBlobDllType, $blob, $sNameDllType, $name, "double", $scalefactor, $sMeanDllType, $mean), "cveDnnNetSetInput", @error)

    If $bNameIsString Then
        _cveStringRelease($name)
    EndIf
EndFunc   ;==>_cveDnnNetSetInput

Func _cveDnnNetSetInputTyped($net, $typeOfBlob, $blob, $name, $scalefactor, $mean)

    Local $iArrBlob, $vectorBlob, $iArrBlobSize
    Local $bBlobIsArray = IsArray($blob)
    Local $bBlobCreate = IsDllStruct($blob) And $typeOfBlob == "Scalar"

    If $typeOfBlob == Default Then
        $iArrBlob = $blob
    ElseIf $bBlobIsArray Then
        $vectorBlob = Call("_VectorOf" & $typeOfBlob & "Create")

        $iArrBlobSize = UBound($blob)
        For $i = 0 To $iArrBlobSize - 1
            Call("_VectorOf" & $typeOfBlob & "Push", $vectorBlob, $blob[$i])
        Next

        $iArrBlob = Call("_cveInputArrayFromVectorOf" & $typeOfBlob, $vectorBlob)
    Else
        If $bBlobCreate Then
            $blob = Call("_cve" & $typeOfBlob & "Create", $blob)
        EndIf
        $iArrBlob = Call("_cveInputArrayFrom" & $typeOfBlob, $blob)
    EndIf

    _cveDnnNetSetInput($net, $iArrBlob, $name, $scalefactor, $mean)

    If $bBlobIsArray Then
        Call("_VectorOf" & $typeOfBlob & "Release", $vectorBlob)
    EndIf

    If $typeOfBlob <> Default Then
        _cveInputArrayRelease($iArrBlob)
        If $bBlobCreate Then
            Call("_cve" & $typeOfBlob & "Release", $blob)
        EndIf
    EndIf
EndFunc   ;==>_cveDnnNetSetInputTyped

Func _cveDnnNetSetInputMat($net, $blob, $name, $scalefactor, $mean)
    ; cveDnnNetSetInput using cv::Mat instead of _*Array
    _cveDnnNetSetInputTyped($net, "Mat", $blob, $name, $scalefactor, $mean)
EndFunc   ;==>_cveDnnNetSetInputMat

Func _cveDnnNetForward($net, $outputName, $output)
    ; CVAPI(void) cveDnnNetForward(cv::dnn::Net* net, cv::String* outputName, cv::Mat* output);

    Local $sNetDllType
    If IsDllStruct($net) Then
        $sNetDllType = "struct*"
    Else
        $sNetDllType = "ptr"
    EndIf

    Local $bOutputNameIsString = IsString($outputName)
    If $bOutputNameIsString Then
        $outputName = _cveStringCreateFromStr($outputName)
    EndIf

    Local $sOutputNameDllType
    If IsDllStruct($outputName) Then
        $sOutputNameDllType = "struct*"
    Else
        $sOutputNameDllType = "ptr"
    EndIf

    Local $sOutputDllType
    If IsDllStruct($output) Then
        $sOutputDllType = "struct*"
    Else
        $sOutputDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDnnNetForward", $sNetDllType, $net, $sOutputNameDllType, $outputName, $sOutputDllType, $output), "cveDnnNetForward", @error)

    If $bOutputNameIsString Then
        _cveStringRelease($outputName)
    EndIf
EndFunc   ;==>_cveDnnNetForward

Func _cveDnnNetForward2($net, $outputBlobs, $outputName)
    ; CVAPI(void) cveDnnNetForward2(cv::dnn::Net* net, cv::_OutputArray* outputBlobs, cv::String* outputName);

    Local $sNetDllType
    If IsDllStruct($net) Then
        $sNetDllType = "struct*"
    Else
        $sNetDllType = "ptr"
    EndIf

    Local $sOutputBlobsDllType
    If IsDllStruct($outputBlobs) Then
        $sOutputBlobsDllType = "struct*"
    Else
        $sOutputBlobsDllType = "ptr"
    EndIf

    Local $bOutputNameIsString = IsString($outputName)
    If $bOutputNameIsString Then
        $outputName = _cveStringCreateFromStr($outputName)
    EndIf

    Local $sOutputNameDllType
    If IsDllStruct($outputName) Then
        $sOutputNameDllType = "struct*"
    Else
        $sOutputNameDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDnnNetForward2", $sNetDllType, $net, $sOutputBlobsDllType, $outputBlobs, $sOutputNameDllType, $outputName), "cveDnnNetForward2", @error)

    If $bOutputNameIsString Then
        _cveStringRelease($outputName)
    EndIf
EndFunc   ;==>_cveDnnNetForward2

Func _cveDnnNetForward2Typed($net, $typeOfOutputBlobs, $outputBlobs, $outputName)

    Local $oArrOutputBlobs, $vectorOutputBlobs, $iArrOutputBlobsSize
    Local $bOutputBlobsIsArray = IsArray($outputBlobs)
    Local $bOutputBlobsCreate = IsDllStruct($outputBlobs) And $typeOfOutputBlobs == "Scalar"

    If $typeOfOutputBlobs == Default Then
        $oArrOutputBlobs = $outputBlobs
    ElseIf $bOutputBlobsIsArray Then
        $vectorOutputBlobs = Call("_VectorOf" & $typeOfOutputBlobs & "Create")

        $iArrOutputBlobsSize = UBound($outputBlobs)
        For $i = 0 To $iArrOutputBlobsSize - 1
            Call("_VectorOf" & $typeOfOutputBlobs & "Push", $vectorOutputBlobs, $outputBlobs[$i])
        Next

        $oArrOutputBlobs = Call("_cveOutputArrayFromVectorOf" & $typeOfOutputBlobs, $vectorOutputBlobs)
    Else
        If $bOutputBlobsCreate Then
            $outputBlobs = Call("_cve" & $typeOfOutputBlobs & "Create", $outputBlobs)
        EndIf
        $oArrOutputBlobs = Call("_cveOutputArrayFrom" & $typeOfOutputBlobs, $outputBlobs)
    EndIf

    _cveDnnNetForward2($net, $oArrOutputBlobs, $outputName)

    If $bOutputBlobsIsArray Then
        Call("_VectorOf" & $typeOfOutputBlobs & "Release", $vectorOutputBlobs)
    EndIf

    If $typeOfOutputBlobs <> Default Then
        _cveOutputArrayRelease($oArrOutputBlobs)
        If $bOutputBlobsCreate Then
            Call("_cve" & $typeOfOutputBlobs & "Release", $outputBlobs)
        EndIf
    EndIf
EndFunc   ;==>_cveDnnNetForward2Typed

Func _cveDnnNetForward2Mat($net, $outputBlobs, $outputName)
    ; cveDnnNetForward2 using cv::Mat instead of _*Array
    _cveDnnNetForward2Typed($net, "Mat", $outputBlobs, $outputName)
EndFunc   ;==>_cveDnnNetForward2Mat

Func _cveDnnNetForward3($net, $outputBlobs, $outBlobNames)
    ; CVAPI(void) cveDnnNetForward3(cv::dnn::Net* net, cv::_OutputArray* outputBlobs, std::vector<cv::String>* outBlobNames);

    Local $sNetDllType
    If IsDllStruct($net) Then
        $sNetDllType = "struct*"
    Else
        $sNetDllType = "ptr"
    EndIf

    Local $sOutputBlobsDllType
    If IsDllStruct($outputBlobs) Then
        $sOutputBlobsDllType = "struct*"
    Else
        $sOutputBlobsDllType = "ptr"
    EndIf

    Local $vecOutBlobNames, $iArrOutBlobNamesSize
    Local $bOutBlobNamesIsArray = IsArray($outBlobNames)

    If $bOutBlobNamesIsArray Then
        $vecOutBlobNames = _VectorOfCvStringCreate()

        $iArrOutBlobNamesSize = UBound($outBlobNames)
        For $i = 0 To $iArrOutBlobNamesSize - 1
            _VectorOfCvStringPush($vecOutBlobNames, $outBlobNames[$i])
        Next
    Else
        $vecOutBlobNames = $outBlobNames
    EndIf

    Local $sOutBlobNamesDllType
    If IsDllStruct($outBlobNames) Then
        $sOutBlobNamesDllType = "struct*"
    Else
        $sOutBlobNamesDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDnnNetForward3", $sNetDllType, $net, $sOutputBlobsDllType, $outputBlobs, $sOutBlobNamesDllType, $vecOutBlobNames), "cveDnnNetForward3", @error)

    If $bOutBlobNamesIsArray Then
        _VectorOfCvStringRelease($vecOutBlobNames)
    EndIf
EndFunc   ;==>_cveDnnNetForward3

Func _cveDnnNetForward3Typed($net, $typeOfOutputBlobs, $outputBlobs, $outBlobNames)

    Local $oArrOutputBlobs, $vectorOutputBlobs, $iArrOutputBlobsSize
    Local $bOutputBlobsIsArray = IsArray($outputBlobs)
    Local $bOutputBlobsCreate = IsDllStruct($outputBlobs) And $typeOfOutputBlobs == "Scalar"

    If $typeOfOutputBlobs == Default Then
        $oArrOutputBlobs = $outputBlobs
    ElseIf $bOutputBlobsIsArray Then
        $vectorOutputBlobs = Call("_VectorOf" & $typeOfOutputBlobs & "Create")

        $iArrOutputBlobsSize = UBound($outputBlobs)
        For $i = 0 To $iArrOutputBlobsSize - 1
            Call("_VectorOf" & $typeOfOutputBlobs & "Push", $vectorOutputBlobs, $outputBlobs[$i])
        Next

        $oArrOutputBlobs = Call("_cveOutputArrayFromVectorOf" & $typeOfOutputBlobs, $vectorOutputBlobs)
    Else
        If $bOutputBlobsCreate Then
            $outputBlobs = Call("_cve" & $typeOfOutputBlobs & "Create", $outputBlobs)
        EndIf
        $oArrOutputBlobs = Call("_cveOutputArrayFrom" & $typeOfOutputBlobs, $outputBlobs)
    EndIf

    _cveDnnNetForward3($net, $oArrOutputBlobs, $outBlobNames)

    If $bOutputBlobsIsArray Then
        Call("_VectorOf" & $typeOfOutputBlobs & "Release", $vectorOutputBlobs)
    EndIf

    If $typeOfOutputBlobs <> Default Then
        _cveOutputArrayRelease($oArrOutputBlobs)
        If $bOutputBlobsCreate Then
            Call("_cve" & $typeOfOutputBlobs & "Release", $outputBlobs)
        EndIf
    EndIf
EndFunc   ;==>_cveDnnNetForward3Typed

Func _cveDnnNetForward3Mat($net, $outputBlobs, $outBlobNames)
    ; cveDnnNetForward3 using cv::Mat instead of _*Array
    _cveDnnNetForward3Typed($net, "Mat", $outputBlobs, $outBlobNames)
EndFunc   ;==>_cveDnnNetForward3Mat

Func _cveDnnNetRelease($net)
    ; CVAPI(void) cveDnnNetRelease(cv::dnn::Net** net);

    Local $sNetDllType
    If IsDllStruct($net) Then
        $sNetDllType = "struct*"
    ElseIf $net == Null Then
        $sNetDllType = "ptr"
    Else
        $sNetDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDnnNetRelease", $sNetDllType, $net), "cveDnnNetRelease", @error)
EndFunc   ;==>_cveDnnNetRelease

Func _cveDnnNetGetUnconnectedOutLayers($net, $layerIds)
    ; CVAPI(void) cveDnnNetGetUnconnectedOutLayers(cv::dnn::Net* net, std::vector<int>* layerIds);

    Local $sNetDllType
    If IsDllStruct($net) Then
        $sNetDllType = "struct*"
    Else
        $sNetDllType = "ptr"
    EndIf

    Local $vecLayerIds, $iArrLayerIdsSize
    Local $bLayerIdsIsArray = IsArray($layerIds)

    If $bLayerIdsIsArray Then
        $vecLayerIds = _VectorOfIntCreate()

        $iArrLayerIdsSize = UBound($layerIds)
        For $i = 0 To $iArrLayerIdsSize - 1
            _VectorOfIntPush($vecLayerIds, $layerIds[$i])
        Next
    Else
        $vecLayerIds = $layerIds
    EndIf

    Local $sLayerIdsDllType
    If IsDllStruct($layerIds) Then
        $sLayerIdsDllType = "struct*"
    Else
        $sLayerIdsDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDnnNetGetUnconnectedOutLayers", $sNetDllType, $net, $sLayerIdsDllType, $vecLayerIds), "cveDnnNetGetUnconnectedOutLayers", @error)

    If $bLayerIdsIsArray Then
        _VectorOfIntRelease($vecLayerIds)
    EndIf
EndFunc   ;==>_cveDnnNetGetUnconnectedOutLayers

Func _cveDnnNetGetUnconnectedOutLayersNames($net, $layerNames)
    ; CVAPI(void) cveDnnNetGetUnconnectedOutLayersNames(cv::dnn::Net* net, std::vector<cv::String>* layerNames);

    Local $sNetDllType
    If IsDllStruct($net) Then
        $sNetDllType = "struct*"
    Else
        $sNetDllType = "ptr"
    EndIf

    Local $vecLayerNames, $iArrLayerNamesSize
    Local $bLayerNamesIsArray = IsArray($layerNames)

    If $bLayerNamesIsArray Then
        $vecLayerNames = _VectorOfCvStringCreate()

        $iArrLayerNamesSize = UBound($layerNames)
        For $i = 0 To $iArrLayerNamesSize - 1
            _VectorOfCvStringPush($vecLayerNames, $layerNames[$i])
        Next
    Else
        $vecLayerNames = $layerNames
    EndIf

    Local $sLayerNamesDllType
    If IsDllStruct($layerNames) Then
        $sLayerNamesDllType = "struct*"
    Else
        $sLayerNamesDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDnnNetGetUnconnectedOutLayersNames", $sNetDllType, $net, $sLayerNamesDllType, $vecLayerNames), "cveDnnNetGetUnconnectedOutLayersNames", @error)

    If $bLayerNamesIsArray Then
        _VectorOfCvStringRelease($vecLayerNames)
    EndIf
EndFunc   ;==>_cveDnnNetGetUnconnectedOutLayersNames

Func _cveDnnNetGetPerfProfile($net, $timings)
    ; CVAPI(int64) cveDnnNetGetPerfProfile(cv::dnn::Net* net, std::vector<double>* timings);

    Local $sNetDllType
    If IsDllStruct($net) Then
        $sNetDllType = "struct*"
    Else
        $sNetDllType = "ptr"
    EndIf

    Local $vecTimings, $iArrTimingsSize
    Local $bTimingsIsArray = IsArray($timings)

    If $bTimingsIsArray Then
        $vecTimings = _VectorOfDoubleCreate()

        $iArrTimingsSize = UBound($timings)
        For $i = 0 To $iArrTimingsSize - 1
            _VectorOfDoublePush($vecTimings, $timings[$i])
        Next
    Else
        $vecTimings = $timings
    EndIf

    Local $sTimingsDllType
    If IsDllStruct($timings) Then
        $sTimingsDllType = "struct*"
    Else
        $sTimingsDllType = "ptr"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "int64:cdecl", "cveDnnNetGetPerfProfile", $sNetDllType, $net, $sTimingsDllType, $vecTimings), "cveDnnNetGetPerfProfile", @error)

    If $bTimingsIsArray Then
        _VectorOfDoubleRelease($vecTimings)
    EndIf

    Return $retval
EndFunc   ;==>_cveDnnNetGetPerfProfile

Func _cveDnnNetDump($net, $string)
    ; CVAPI(void) cveDnnNetDump(cv::dnn::Net* net, cv::String* string);

    Local $sNetDllType
    If IsDllStruct($net) Then
        $sNetDllType = "struct*"
    Else
        $sNetDllType = "ptr"
    EndIf

    Local $bStringIsString = IsString($string)
    If $bStringIsString Then
        $string = _cveStringCreateFromStr($string)
    EndIf

    Local $sStringDllType
    If IsDllStruct($string) Then
        $sStringDllType = "struct*"
    Else
        $sStringDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDnnNetDump", $sNetDllType, $net, $sStringDllType, $string), "cveDnnNetDump", @error)

    If $bStringIsString Then
        _cveStringRelease($string)
    EndIf
EndFunc   ;==>_cveDnnNetDump

Func _cveDnnNetDumpToFile($net, $path)
    ; CVAPI(void) cveDnnNetDumpToFile(cv::dnn::Net* net, cv::String* path);

    Local $sNetDllType
    If IsDllStruct($net) Then
        $sNetDllType = "struct*"
    Else
        $sNetDllType = "ptr"
    EndIf

    Local $bPathIsString = IsString($path)
    If $bPathIsString Then
        $path = _cveStringCreateFromStr($path)
    EndIf

    Local $sPathDllType
    If IsDllStruct($path) Then
        $sPathDllType = "struct*"
    Else
        $sPathDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDnnNetDumpToFile", $sNetDllType, $net, $sPathDllType, $path), "cveDnnNetDumpToFile", @error)

    If $bPathIsString Then
        _cveStringRelease($path)
    EndIf
EndFunc   ;==>_cveDnnNetDumpToFile

Func _cveDnnNetGetLayerNames($net)
    ; CVAPI(std::vector<cv::String>*) cveDnnNetGetLayerNames(cv::dnn::Net* net);

    Local $sNetDllType
    If IsDllStruct($net) Then
        $sNetDllType = "struct*"
    Else
        $sNetDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveDnnNetGetLayerNames", $sNetDllType, $net), "cveDnnNetGetLayerNames", @error)
EndFunc   ;==>_cveDnnNetGetLayerNames

Func _cveDnnGetLayerId($net, $layer)
    ; CVAPI(int) cveDnnGetLayerId(cv::dnn::Net* net, cv::String* layer);

    Local $sNetDllType
    If IsDllStruct($net) Then
        $sNetDllType = "struct*"
    Else
        $sNetDllType = "ptr"
    EndIf

    Local $bLayerIsString = IsString($layer)
    If $bLayerIsString Then
        $layer = _cveStringCreateFromStr($layer)
    EndIf

    Local $sLayerDllType
    If IsDllStruct($layer) Then
        $sLayerDllType = "struct*"
    Else
        $sLayerDllType = "ptr"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveDnnGetLayerId", $sNetDllType, $net, $sLayerDllType, $layer), "cveDnnGetLayerId", @error)

    If $bLayerIsString Then
        _cveStringRelease($layer)
    EndIf

    Return $retval
EndFunc   ;==>_cveDnnGetLayerId

Func _cveDnnGetLayerByName($net, $layerName, $sharedPtr)
    ; CVAPI(cv::dnn::Layer*) cveDnnGetLayerByName(cv::dnn::Net* net, cv::String* layerName, cv::Ptr<cv::dnn::Layer>** sharedPtr);

    Local $sNetDllType
    If IsDllStruct($net) Then
        $sNetDllType = "struct*"
    Else
        $sNetDllType = "ptr"
    EndIf

    Local $bLayerNameIsString = IsString($layerName)
    If $bLayerNameIsString Then
        $layerName = _cveStringCreateFromStr($layerName)
    EndIf

    Local $sLayerNameDllType
    If IsDllStruct($layerName) Then
        $sLayerNameDllType = "struct*"
    Else
        $sLayerNameDllType = "ptr"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveDnnGetLayerByName", $sNetDllType, $net, $sLayerNameDllType, $layerName, $sSharedPtrDllType, $sharedPtr), "cveDnnGetLayerByName", @error)

    If $bLayerNameIsString Then
        _cveStringRelease($layerName)
    EndIf

    Return $retval
EndFunc   ;==>_cveDnnGetLayerByName

Func _cveDnnGetLayerById($net, $layerId, $sharedPtr)
    ; CVAPI(cv::dnn::Layer*) cveDnnGetLayerById(cv::dnn::Net* net, int layerId, cv::Ptr<cv::dnn::Layer>** sharedPtr);

    Local $sNetDllType
    If IsDllStruct($net) Then
        $sNetDllType = "struct*"
    Else
        $sNetDllType = "ptr"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveDnnGetLayerById", $sNetDllType, $net, "int", $layerId, $sSharedPtrDllType, $sharedPtr), "cveDnnGetLayerById", @error)
EndFunc   ;==>_cveDnnGetLayerById

Func _cveDnnLayerRelease($layer)
    ; CVAPI(void) cveDnnLayerRelease(cv::Ptr<cv::dnn::Layer>** layer);

    Local $sLayerDllType
    If IsDllStruct($layer) Then
        $sLayerDllType = "struct*"
    ElseIf $layer == Null Then
        $sLayerDllType = "ptr"
    Else
        $sLayerDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDnnLayerRelease", $sLayerDllType, $layer), "cveDnnLayerRelease", @error)
EndFunc   ;==>_cveDnnLayerRelease

Func _cveDnnLayerGetBlobs($layer)
    ; CVAPI(std::vector<cv::Mat>*) cveDnnLayerGetBlobs(cv::dnn::Layer* layer);

    Local $sLayerDllType
    If IsDllStruct($layer) Then
        $sLayerDllType = "struct*"
    Else
        $sLayerDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveDnnLayerGetBlobs", $sLayerDllType, $layer), "cveDnnLayerGetBlobs", @error)
EndFunc   ;==>_cveDnnLayerGetBlobs

Func _cveDnnBlobFromImage($image, $blob, $scalefactor, $size, $mean, $swapRB, $crop, $ddepth)
    ; CVAPI(void) cveDnnBlobFromImage(cv::_InputArray* image, cv::_OutputArray* blob, double scalefactor, CvSize* size, CvScalar* mean, bool swapRB, bool crop, int ddepth);

    Local $sImageDllType
    If IsDllStruct($image) Then
        $sImageDllType = "struct*"
    Else
        $sImageDllType = "ptr"
    EndIf

    Local $sBlobDllType
    If IsDllStruct($blob) Then
        $sBlobDllType = "struct*"
    Else
        $sBlobDllType = "ptr"
    EndIf

    Local $sSizeDllType
    If IsDllStruct($size) Then
        $sSizeDllType = "struct*"
    Else
        $sSizeDllType = "ptr"
    EndIf

    Local $sMeanDllType
    If IsDllStruct($mean) Then
        $sMeanDllType = "struct*"
    Else
        $sMeanDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDnnBlobFromImage", $sImageDllType, $image, $sBlobDllType, $blob, "double", $scalefactor, $sSizeDllType, $size, $sMeanDllType, $mean, "boolean", $swapRB, "boolean", $crop, "int", $ddepth), "cveDnnBlobFromImage", @error)
EndFunc   ;==>_cveDnnBlobFromImage

Func _cveDnnBlobFromImageTyped($typeOfImage, $image, $typeOfBlob, $blob, $scalefactor, $size, $mean, $swapRB, $crop, $ddepth)

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

    Local $oArrBlob, $vectorBlob, $iArrBlobSize
    Local $bBlobIsArray = IsArray($blob)
    Local $bBlobCreate = IsDllStruct($blob) And $typeOfBlob == "Scalar"

    If $typeOfBlob == Default Then
        $oArrBlob = $blob
    ElseIf $bBlobIsArray Then
        $vectorBlob = Call("_VectorOf" & $typeOfBlob & "Create")

        $iArrBlobSize = UBound($blob)
        For $i = 0 To $iArrBlobSize - 1
            Call("_VectorOf" & $typeOfBlob & "Push", $vectorBlob, $blob[$i])
        Next

        $oArrBlob = Call("_cveOutputArrayFromVectorOf" & $typeOfBlob, $vectorBlob)
    Else
        If $bBlobCreate Then
            $blob = Call("_cve" & $typeOfBlob & "Create", $blob)
        EndIf
        $oArrBlob = Call("_cveOutputArrayFrom" & $typeOfBlob, $blob)
    EndIf

    _cveDnnBlobFromImage($iArrImage, $oArrBlob, $scalefactor, $size, $mean, $swapRB, $crop, $ddepth)

    If $bBlobIsArray Then
        Call("_VectorOf" & $typeOfBlob & "Release", $vectorBlob)
    EndIf

    If $typeOfBlob <> Default Then
        _cveOutputArrayRelease($oArrBlob)
        If $bBlobCreate Then
            Call("_cve" & $typeOfBlob & "Release", $blob)
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
EndFunc   ;==>_cveDnnBlobFromImageTyped

Func _cveDnnBlobFromImageMat($image, $blob, $scalefactor, $size, $mean, $swapRB, $crop, $ddepth)
    ; cveDnnBlobFromImage using cv::Mat instead of _*Array
    _cveDnnBlobFromImageTyped("Mat", $image, "Mat", $blob, $scalefactor, $size, $mean, $swapRB, $crop, $ddepth)
EndFunc   ;==>_cveDnnBlobFromImageMat

Func _cveDnnBlobFromImages($images, $blob, $scalefactor, $size, $mean, $swapRB, $crop, $ddepth)
    ; CVAPI(void) cveDnnBlobFromImages(cv::_InputArray* images, cv::_OutputArray* blob, double scalefactor, CvSize* size, CvScalar* mean, bool swapRB, bool crop, int ddepth);

    Local $sImagesDllType
    If IsDllStruct($images) Then
        $sImagesDllType = "struct*"
    Else
        $sImagesDllType = "ptr"
    EndIf

    Local $sBlobDllType
    If IsDllStruct($blob) Then
        $sBlobDllType = "struct*"
    Else
        $sBlobDllType = "ptr"
    EndIf

    Local $sSizeDllType
    If IsDllStruct($size) Then
        $sSizeDllType = "struct*"
    Else
        $sSizeDllType = "ptr"
    EndIf

    Local $sMeanDllType
    If IsDllStruct($mean) Then
        $sMeanDllType = "struct*"
    Else
        $sMeanDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDnnBlobFromImages", $sImagesDllType, $images, $sBlobDllType, $blob, "double", $scalefactor, $sSizeDllType, $size, $sMeanDllType, $mean, "boolean", $swapRB, "boolean", $crop, "int", $ddepth), "cveDnnBlobFromImages", @error)
EndFunc   ;==>_cveDnnBlobFromImages

Func _cveDnnBlobFromImagesTyped($typeOfImages, $images, $typeOfBlob, $blob, $scalefactor, $size, $mean, $swapRB, $crop, $ddepth)

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

    Local $oArrBlob, $vectorBlob, $iArrBlobSize
    Local $bBlobIsArray = IsArray($blob)
    Local $bBlobCreate = IsDllStruct($blob) And $typeOfBlob == "Scalar"

    If $typeOfBlob == Default Then
        $oArrBlob = $blob
    ElseIf $bBlobIsArray Then
        $vectorBlob = Call("_VectorOf" & $typeOfBlob & "Create")

        $iArrBlobSize = UBound($blob)
        For $i = 0 To $iArrBlobSize - 1
            Call("_VectorOf" & $typeOfBlob & "Push", $vectorBlob, $blob[$i])
        Next

        $oArrBlob = Call("_cveOutputArrayFromVectorOf" & $typeOfBlob, $vectorBlob)
    Else
        If $bBlobCreate Then
            $blob = Call("_cve" & $typeOfBlob & "Create", $blob)
        EndIf
        $oArrBlob = Call("_cveOutputArrayFrom" & $typeOfBlob, $blob)
    EndIf

    _cveDnnBlobFromImages($iArrImages, $oArrBlob, $scalefactor, $size, $mean, $swapRB, $crop, $ddepth)

    If $bBlobIsArray Then
        Call("_VectorOf" & $typeOfBlob & "Release", $vectorBlob)
    EndIf

    If $typeOfBlob <> Default Then
        _cveOutputArrayRelease($oArrBlob)
        If $bBlobCreate Then
            Call("_cve" & $typeOfBlob & "Release", $blob)
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
EndFunc   ;==>_cveDnnBlobFromImagesTyped

Func _cveDnnBlobFromImagesMat($images, $blob, $scalefactor, $size, $mean, $swapRB, $crop, $ddepth)
    ; cveDnnBlobFromImages using cv::Mat instead of _*Array
    _cveDnnBlobFromImagesTyped("Mat", $images, "Mat", $blob, $scalefactor, $size, $mean, $swapRB, $crop, $ddepth)
EndFunc   ;==>_cveDnnBlobFromImagesMat

Func _cveDnnImagesFromBlob($blob, $images)
    ; CVAPI(void) cveDnnImagesFromBlob(cv::Mat* blob, cv::_OutputArray* images);

    Local $sBlobDllType
    If IsDllStruct($blob) Then
        $sBlobDllType = "struct*"
    Else
        $sBlobDllType = "ptr"
    EndIf

    Local $sImagesDllType
    If IsDllStruct($images) Then
        $sImagesDllType = "struct*"
    Else
        $sImagesDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDnnImagesFromBlob", $sBlobDllType, $blob, $sImagesDllType, $images), "cveDnnImagesFromBlob", @error)
EndFunc   ;==>_cveDnnImagesFromBlob

Func _cveDnnImagesFromBlobTyped($blob, $typeOfImages, $images)

    Local $oArrImages, $vectorImages, $iArrImagesSize
    Local $bImagesIsArray = IsArray($images)
    Local $bImagesCreate = IsDllStruct($images) And $typeOfImages == "Scalar"

    If $typeOfImages == Default Then
        $oArrImages = $images
    ElseIf $bImagesIsArray Then
        $vectorImages = Call("_VectorOf" & $typeOfImages & "Create")

        $iArrImagesSize = UBound($images)
        For $i = 0 To $iArrImagesSize - 1
            Call("_VectorOf" & $typeOfImages & "Push", $vectorImages, $images[$i])
        Next

        $oArrImages = Call("_cveOutputArrayFromVectorOf" & $typeOfImages, $vectorImages)
    Else
        If $bImagesCreate Then
            $images = Call("_cve" & $typeOfImages & "Create", $images)
        EndIf
        $oArrImages = Call("_cveOutputArrayFrom" & $typeOfImages, $images)
    EndIf

    _cveDnnImagesFromBlob($blob, $oArrImages)

    If $bImagesIsArray Then
        Call("_VectorOf" & $typeOfImages & "Release", $vectorImages)
    EndIf

    If $typeOfImages <> Default Then
        _cveOutputArrayRelease($oArrImages)
        If $bImagesCreate Then
            Call("_cve" & $typeOfImages & "Release", $images)
        EndIf
    EndIf
EndFunc   ;==>_cveDnnImagesFromBlobTyped

Func _cveDnnImagesFromBlobMat($blob, $images)
    ; cveDnnImagesFromBlob using cv::Mat instead of _*Array
    _cveDnnImagesFromBlobTyped($blob, "Mat", $images)
EndFunc   ;==>_cveDnnImagesFromBlobMat

Func _cveDnnShrinkCaffeModel($src, $dst)
    ; CVAPI(void) cveDnnShrinkCaffeModel(cv::String* src, cv::String* dst);

    Local $bSrcIsString = IsString($src)
    If $bSrcIsString Then
        $src = _cveStringCreateFromStr($src)
    EndIf

    Local $sSrcDllType
    If IsDllStruct($src) Then
        $sSrcDllType = "struct*"
    Else
        $sSrcDllType = "ptr"
    EndIf

    Local $bDstIsString = IsString($dst)
    If $bDstIsString Then
        $dst = _cveStringCreateFromStr($dst)
    EndIf

    Local $sDstDllType
    If IsDllStruct($dst) Then
        $sDstDllType = "struct*"
    Else
        $sDstDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDnnShrinkCaffeModel", $sSrcDllType, $src, $sDstDllType, $dst), "cveDnnShrinkCaffeModel", @error)

    If $bDstIsString Then
        _cveStringRelease($dst)
    EndIf

    If $bSrcIsString Then
        _cveStringRelease($src)
    EndIf
EndFunc   ;==>_cveDnnShrinkCaffeModel

Func _cveDnnWriteTextGraph($model, $output)
    ; CVAPI(void) cveDnnWriteTextGraph(cv::String* model, cv::String* output);

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

    Local $bOutputIsString = IsString($output)
    If $bOutputIsString Then
        $output = _cveStringCreateFromStr($output)
    EndIf

    Local $sOutputDllType
    If IsDllStruct($output) Then
        $sOutputDllType = "struct*"
    Else
        $sOutputDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDnnWriteTextGraph", $sModelDllType, $model, $sOutputDllType, $output), "cveDnnWriteTextGraph", @error)

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
    Local $bBboxesIsArray = IsArray($bboxes)

    If $bBboxesIsArray Then
        $vecBboxes = _VectorOfRectCreate()

        $iArrBboxesSize = UBound($bboxes)
        For $i = 0 To $iArrBboxesSize - 1
            _VectorOfRectPush($vecBboxes, $bboxes[$i])
        Next
    Else
        $vecBboxes = $bboxes
    EndIf

    Local $sBboxesDllType
    If IsDllStruct($bboxes) Then
        $sBboxesDllType = "struct*"
    Else
        $sBboxesDllType = "ptr"
    EndIf

    Local $vecScores, $iArrScoresSize
    Local $bScoresIsArray = IsArray($scores)

    If $bScoresIsArray Then
        $vecScores = _VectorOfFloatCreate()

        $iArrScoresSize = UBound($scores)
        For $i = 0 To $iArrScoresSize - 1
            _VectorOfFloatPush($vecScores, $scores[$i])
        Next
    Else
        $vecScores = $scores
    EndIf

    Local $sScoresDllType
    If IsDllStruct($scores) Then
        $sScoresDllType = "struct*"
    Else
        $sScoresDllType = "ptr"
    EndIf

    Local $vecIndices, $iArrIndicesSize
    Local $bIndicesIsArray = IsArray($indices)

    If $bIndicesIsArray Then
        $vecIndices = _VectorOfIntCreate()

        $iArrIndicesSize = UBound($indices)
        For $i = 0 To $iArrIndicesSize - 1
            _VectorOfIntPush($vecIndices, $indices[$i])
        Next
    Else
        $vecIndices = $indices
    EndIf

    Local $sIndicesDllType
    If IsDllStruct($indices) Then
        $sIndicesDllType = "struct*"
    Else
        $sIndicesDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDnnNMSBoxes", $sBboxesDllType, $vecBboxes, $sScoresDllType, $vecScores, "float", $scoreThreshold, "float", $nmsThreshold, $sIndicesDllType, $vecIndices, "float", $eta, "int", $topK), "cveDnnNMSBoxes", @error)

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
    Local $bBboxesIsArray = IsArray($bboxes)

    If $bBboxesIsArray Then
        $vecBboxes = _VectorOfRotatedRectCreate()

        $iArrBboxesSize = UBound($bboxes)
        For $i = 0 To $iArrBboxesSize - 1
            _VectorOfRotatedRectPush($vecBboxes, $bboxes[$i])
        Next
    Else
        $vecBboxes = $bboxes
    EndIf

    Local $sBboxesDllType
    If IsDllStruct($bboxes) Then
        $sBboxesDllType = "struct*"
    Else
        $sBboxesDllType = "ptr"
    EndIf

    Local $vecScores, $iArrScoresSize
    Local $bScoresIsArray = IsArray($scores)

    If $bScoresIsArray Then
        $vecScores = _VectorOfFloatCreate()

        $iArrScoresSize = UBound($scores)
        For $i = 0 To $iArrScoresSize - 1
            _VectorOfFloatPush($vecScores, $scores[$i])
        Next
    Else
        $vecScores = $scores
    EndIf

    Local $sScoresDllType
    If IsDllStruct($scores) Then
        $sScoresDllType = "struct*"
    Else
        $sScoresDllType = "ptr"
    EndIf

    Local $vecIndices, $iArrIndicesSize
    Local $bIndicesIsArray = IsArray($indices)

    If $bIndicesIsArray Then
        $vecIndices = _VectorOfIntCreate()

        $iArrIndicesSize = UBound($indices)
        For $i = 0 To $iArrIndicesSize - 1
            _VectorOfIntPush($vecIndices, $indices[$i])
        Next
    Else
        $vecIndices = $indices
    EndIf

    Local $sIndicesDllType
    If IsDllStruct($indices) Then
        $sIndicesDllType = "struct*"
    Else
        $sIndicesDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDnnNMSBoxes2", $sBboxesDllType, $vecBboxes, $sScoresDllType, $vecScores, "float", $scoreThreshold, "float", $nmsThreshold, $sIndicesDllType, $vecIndices, "float", $eta, "int", $topK), "cveDnnNMSBoxes2", @error)

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
    Local $bBackendsIsArray = IsArray($backends)

    If $bBackendsIsArray Then
        $vecBackends = _VectorOfIntCreate()

        $iArrBackendsSize = UBound($backends)
        For $i = 0 To $iArrBackendsSize - 1
            _VectorOfIntPush($vecBackends, $backends[$i])
        Next
    Else
        $vecBackends = $backends
    EndIf

    Local $sBackendsDllType
    If IsDllStruct($backends) Then
        $sBackendsDllType = "struct*"
    Else
        $sBackendsDllType = "ptr"
    EndIf

    Local $vecTargets, $iArrTargetsSize
    Local $bTargetsIsArray = IsArray($targets)

    If $bTargetsIsArray Then
        $vecTargets = _VectorOfIntCreate()

        $iArrTargetsSize = UBound($targets)
        For $i = 0 To $iArrTargetsSize - 1
            _VectorOfIntPush($vecTargets, $targets[$i])
        Next
    Else
        $vecTargets = $targets
    EndIf

    Local $sTargetsDllType
    If IsDllStruct($targets) Then
        $sTargetsDllType = "struct*"
    Else
        $sTargetsDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDNNGetAvailableBackends", $sBackendsDllType, $vecBackends, $sTargetsDllType, $vecTargets), "cveDNNGetAvailableBackends", @error)

    If $bTargetsIsArray Then
        _VectorOfIntRelease($vecTargets)
    EndIf

    If $bBackendsIsArray Then
        _VectorOfIntRelease($vecBackends)
    EndIf
EndFunc   ;==>_cveDNNGetAvailableBackends

Func _cveDnnTextDetectionModelDbCreate1($model, $config, $textDetectionModel, $baseModel)
    ; CVAPI(cv::dnn::TextDetectionModel_DB*) cveDnnTextDetectionModelDbCreate1(cv::String* model, cv::String* config, cv::dnn::TextDetectionModel** textDetectionModel, cv::dnn::Model** baseModel);

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

    Local $bConfigIsString = IsString($config)
    If $bConfigIsString Then
        $config = _cveStringCreateFromStr($config)
    EndIf

    Local $sConfigDllType
    If IsDllStruct($config) Then
        $sConfigDllType = "struct*"
    Else
        $sConfigDllType = "ptr"
    EndIf

    Local $sTextDetectionModelDllType
    If IsDllStruct($textDetectionModel) Then
        $sTextDetectionModelDllType = "struct*"
    ElseIf $textDetectionModel == Null Then
        $sTextDetectionModelDllType = "ptr"
    Else
        $sTextDetectionModelDllType = "ptr*"
    EndIf

    Local $sBaseModelDllType
    If IsDllStruct($baseModel) Then
        $sBaseModelDllType = "struct*"
    ElseIf $baseModel == Null Then
        $sBaseModelDllType = "ptr"
    Else
        $sBaseModelDllType = "ptr*"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveDnnTextDetectionModelDbCreate1", $sModelDllType, $model, $sConfigDllType, $config, $sTextDetectionModelDllType, $textDetectionModel, $sBaseModelDllType, $baseModel), "cveDnnTextDetectionModelDbCreate1", @error)

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

    Local $sNetworkDllType
    If IsDllStruct($network) Then
        $sNetworkDllType = "struct*"
    Else
        $sNetworkDllType = "ptr"
    EndIf

    Local $sTextDetectionModelDllType
    If IsDllStruct($textDetectionModel) Then
        $sTextDetectionModelDllType = "struct*"
    ElseIf $textDetectionModel == Null Then
        $sTextDetectionModelDllType = "ptr"
    Else
        $sTextDetectionModelDllType = "ptr*"
    EndIf

    Local $sBaseModelDllType
    If IsDllStruct($baseModel) Then
        $sBaseModelDllType = "struct*"
    ElseIf $baseModel == Null Then
        $sBaseModelDllType = "ptr"
    Else
        $sBaseModelDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveDnnTextDetectionModelDbCreate2", $sNetworkDllType, $network, $sTextDetectionModelDllType, $textDetectionModel, $sBaseModelDllType, $baseModel), "cveDnnTextDetectionModelDbCreate2", @error)
EndFunc   ;==>_cveDnnTextDetectionModelDbCreate2

Func _cveDnnTextDetectionModelDbRelease($textDetectionModel)
    ; CVAPI(void) cveDnnTextDetectionModelDbRelease(cv::dnn::TextDetectionModel_DB** textDetectionModel);

    Local $sTextDetectionModelDllType
    If IsDllStruct($textDetectionModel) Then
        $sTextDetectionModelDllType = "struct*"
    ElseIf $textDetectionModel == Null Then
        $sTextDetectionModelDllType = "ptr"
    Else
        $sTextDetectionModelDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDnnTextDetectionModelDbRelease", $sTextDetectionModelDllType, $textDetectionModel), "cveDnnTextDetectionModelDbRelease", @error)
EndFunc   ;==>_cveDnnTextDetectionModelDbRelease

Func _cveDnnTextDetectionModelEastCreate1($model, $config, $textDetectionModel, $baseModel)
    ; CVAPI(cv::dnn::TextDetectionModel_EAST*) cveDnnTextDetectionModelEastCreate1(cv::String* model, cv::String* config, cv::dnn::TextDetectionModel** textDetectionModel, cv::dnn::Model** baseModel);

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

    Local $bConfigIsString = IsString($config)
    If $bConfigIsString Then
        $config = _cveStringCreateFromStr($config)
    EndIf

    Local $sConfigDllType
    If IsDllStruct($config) Then
        $sConfigDllType = "struct*"
    Else
        $sConfigDllType = "ptr"
    EndIf

    Local $sTextDetectionModelDllType
    If IsDllStruct($textDetectionModel) Then
        $sTextDetectionModelDllType = "struct*"
    ElseIf $textDetectionModel == Null Then
        $sTextDetectionModelDllType = "ptr"
    Else
        $sTextDetectionModelDllType = "ptr*"
    EndIf

    Local $sBaseModelDllType
    If IsDllStruct($baseModel) Then
        $sBaseModelDllType = "struct*"
    ElseIf $baseModel == Null Then
        $sBaseModelDllType = "ptr"
    Else
        $sBaseModelDllType = "ptr*"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveDnnTextDetectionModelEastCreate1", $sModelDllType, $model, $sConfigDllType, $config, $sTextDetectionModelDllType, $textDetectionModel, $sBaseModelDllType, $baseModel), "cveDnnTextDetectionModelEastCreate1", @error)

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

    Local $sNetworkDllType
    If IsDllStruct($network) Then
        $sNetworkDllType = "struct*"
    Else
        $sNetworkDllType = "ptr"
    EndIf

    Local $sTextDetectionModelDllType
    If IsDllStruct($textDetectionModel) Then
        $sTextDetectionModelDllType = "struct*"
    ElseIf $textDetectionModel == Null Then
        $sTextDetectionModelDllType = "ptr"
    Else
        $sTextDetectionModelDllType = "ptr*"
    EndIf

    Local $sBaseModelDllType
    If IsDllStruct($baseModel) Then
        $sBaseModelDllType = "struct*"
    ElseIf $baseModel == Null Then
        $sBaseModelDllType = "ptr"
    Else
        $sBaseModelDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveDnnTextDetectionModelEastCreate2", $sNetworkDllType, $network, $sTextDetectionModelDllType, $textDetectionModel, $sBaseModelDllType, $baseModel), "cveDnnTextDetectionModelEastCreate2", @error)
EndFunc   ;==>_cveDnnTextDetectionModelEastCreate2

Func _cveDnnTextDetectionModelEastRelease($textDetectionModel)
    ; CVAPI(void) cveDnnTextDetectionModelEastRelease(cv::dnn::TextDetectionModel_EAST** textDetectionModel);

    Local $sTextDetectionModelDllType
    If IsDllStruct($textDetectionModel) Then
        $sTextDetectionModelDllType = "struct*"
    ElseIf $textDetectionModel == Null Then
        $sTextDetectionModelDllType = "ptr"
    Else
        $sTextDetectionModelDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDnnTextDetectionModelEastRelease", $sTextDetectionModelDllType, $textDetectionModel), "cveDnnTextDetectionModelEastRelease", @error)
EndFunc   ;==>_cveDnnTextDetectionModelEastRelease

Func _cveDnnTextDetectionModelDetect($textDetectionModel, $frame, $detections, $confidences)
    ; CVAPI(void) cveDnnTextDetectionModelDetect(cv::dnn::TextDetectionModel* textDetectionModel, cv::_InputArray* frame, std::vector<std::vector<cv::Point>>* detections, std::vector<float>* confidences);

    Local $sTextDetectionModelDllType
    If IsDllStruct($textDetectionModel) Then
        $sTextDetectionModelDllType = "struct*"
    Else
        $sTextDetectionModelDllType = "ptr"
    EndIf

    Local $sFrameDllType
    If IsDllStruct($frame) Then
        $sFrameDllType = "struct*"
    Else
        $sFrameDllType = "ptr"
    EndIf

    Local $vecDetections, $iArrDetectionsSize
    Local $bDetectionsIsArray = IsArray($detections)

    If $bDetectionsIsArray Then
        $vecDetections = _VectorOfVectorOfPointCreate()

        $iArrDetectionsSize = UBound($detections)
        For $i = 0 To $iArrDetectionsSize - 1
            _VectorOfVectorOfPointPush($vecDetections, $detections[$i])
        Next
    Else
        $vecDetections = $detections
    EndIf

    Local $sDetectionsDllType
    If IsDllStruct($detections) Then
        $sDetectionsDllType = "struct*"
    Else
        $sDetectionsDllType = "ptr"
    EndIf

    Local $vecConfidences, $iArrConfidencesSize
    Local $bConfidencesIsArray = IsArray($confidences)

    If $bConfidencesIsArray Then
        $vecConfidences = _VectorOfFloatCreate()

        $iArrConfidencesSize = UBound($confidences)
        For $i = 0 To $iArrConfidencesSize - 1
            _VectorOfFloatPush($vecConfidences, $confidences[$i])
        Next
    Else
        $vecConfidences = $confidences
    EndIf

    Local $sConfidencesDllType
    If IsDllStruct($confidences) Then
        $sConfidencesDllType = "struct*"
    Else
        $sConfidencesDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDnnTextDetectionModelDetect", $sTextDetectionModelDllType, $textDetectionModel, $sFrameDllType, $frame, $sDetectionsDllType, $vecDetections, $sConfidencesDllType, $vecConfidences), "cveDnnTextDetectionModelDetect", @error)

    If $bConfidencesIsArray Then
        _VectorOfFloatRelease($vecConfidences)
    EndIf

    If $bDetectionsIsArray Then
        _VectorOfVectorOfPointRelease($vecDetections)
    EndIf
EndFunc   ;==>_cveDnnTextDetectionModelDetect

Func _cveDnnTextDetectionModelDetectTyped($textDetectionModel, $typeOfFrame, $frame, $detections, $confidences)

    Local $iArrFrame, $vectorFrame, $iArrFrameSize
    Local $bFrameIsArray = IsArray($frame)
    Local $bFrameCreate = IsDllStruct($frame) And $typeOfFrame == "Scalar"

    If $typeOfFrame == Default Then
        $iArrFrame = $frame
    ElseIf $bFrameIsArray Then
        $vectorFrame = Call("_VectorOf" & $typeOfFrame & "Create")

        $iArrFrameSize = UBound($frame)
        For $i = 0 To $iArrFrameSize - 1
            Call("_VectorOf" & $typeOfFrame & "Push", $vectorFrame, $frame[$i])
        Next

        $iArrFrame = Call("_cveInputArrayFromVectorOf" & $typeOfFrame, $vectorFrame)
    Else
        If $bFrameCreate Then
            $frame = Call("_cve" & $typeOfFrame & "Create", $frame)
        EndIf
        $iArrFrame = Call("_cveInputArrayFrom" & $typeOfFrame, $frame)
    EndIf

    _cveDnnTextDetectionModelDetect($textDetectionModel, $iArrFrame, $detections, $confidences)

    If $bFrameIsArray Then
        Call("_VectorOf" & $typeOfFrame & "Release", $vectorFrame)
    EndIf

    If $typeOfFrame <> Default Then
        _cveInputArrayRelease($iArrFrame)
        If $bFrameCreate Then
            Call("_cve" & $typeOfFrame & "Release", $frame)
        EndIf
    EndIf
EndFunc   ;==>_cveDnnTextDetectionModelDetectTyped

Func _cveDnnTextDetectionModelDetectMat($textDetectionModel, $frame, $detections, $confidences)
    ; cveDnnTextDetectionModelDetect using cv::Mat instead of _*Array
    _cveDnnTextDetectionModelDetectTyped($textDetectionModel, "Mat", $frame, $detections, $confidences)
EndFunc   ;==>_cveDnnTextDetectionModelDetectMat

Func _cveDnnTextDetectionModelDetectTextRectangles($textDetectionModel, $frame, $detections, $confidences)
    ; CVAPI(void) cveDnnTextDetectionModelDetectTextRectangles(cv::dnn::TextDetectionModel* textDetectionModel, cv::_InputArray* frame, std::vector<cv::RotatedRect>* detections, std::vector<float>* confidences);

    Local $sTextDetectionModelDllType
    If IsDllStruct($textDetectionModel) Then
        $sTextDetectionModelDllType = "struct*"
    Else
        $sTextDetectionModelDllType = "ptr"
    EndIf

    Local $sFrameDllType
    If IsDllStruct($frame) Then
        $sFrameDllType = "struct*"
    Else
        $sFrameDllType = "ptr"
    EndIf

    Local $vecDetections, $iArrDetectionsSize
    Local $bDetectionsIsArray = IsArray($detections)

    If $bDetectionsIsArray Then
        $vecDetections = _VectorOfRotatedRectCreate()

        $iArrDetectionsSize = UBound($detections)
        For $i = 0 To $iArrDetectionsSize - 1
            _VectorOfRotatedRectPush($vecDetections, $detections[$i])
        Next
    Else
        $vecDetections = $detections
    EndIf

    Local $sDetectionsDllType
    If IsDllStruct($detections) Then
        $sDetectionsDllType = "struct*"
    Else
        $sDetectionsDllType = "ptr"
    EndIf

    Local $vecConfidences, $iArrConfidencesSize
    Local $bConfidencesIsArray = IsArray($confidences)

    If $bConfidencesIsArray Then
        $vecConfidences = _VectorOfFloatCreate()

        $iArrConfidencesSize = UBound($confidences)
        For $i = 0 To $iArrConfidencesSize - 1
            _VectorOfFloatPush($vecConfidences, $confidences[$i])
        Next
    Else
        $vecConfidences = $confidences
    EndIf

    Local $sConfidencesDllType
    If IsDllStruct($confidences) Then
        $sConfidencesDllType = "struct*"
    Else
        $sConfidencesDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDnnTextDetectionModelDetectTextRectangles", $sTextDetectionModelDllType, $textDetectionModel, $sFrameDllType, $frame, $sDetectionsDllType, $vecDetections, $sConfidencesDllType, $vecConfidences), "cveDnnTextDetectionModelDetectTextRectangles", @error)

    If $bConfidencesIsArray Then
        _VectorOfFloatRelease($vecConfidences)
    EndIf

    If $bDetectionsIsArray Then
        _VectorOfRotatedRectRelease($vecDetections)
    EndIf
EndFunc   ;==>_cveDnnTextDetectionModelDetectTextRectangles

Func _cveDnnTextDetectionModelDetectTextRectanglesTyped($textDetectionModel, $typeOfFrame, $frame, $detections, $confidences)

    Local $iArrFrame, $vectorFrame, $iArrFrameSize
    Local $bFrameIsArray = IsArray($frame)
    Local $bFrameCreate = IsDllStruct($frame) And $typeOfFrame == "Scalar"

    If $typeOfFrame == Default Then
        $iArrFrame = $frame
    ElseIf $bFrameIsArray Then
        $vectorFrame = Call("_VectorOf" & $typeOfFrame & "Create")

        $iArrFrameSize = UBound($frame)
        For $i = 0 To $iArrFrameSize - 1
            Call("_VectorOf" & $typeOfFrame & "Push", $vectorFrame, $frame[$i])
        Next

        $iArrFrame = Call("_cveInputArrayFromVectorOf" & $typeOfFrame, $vectorFrame)
    Else
        If $bFrameCreate Then
            $frame = Call("_cve" & $typeOfFrame & "Create", $frame)
        EndIf
        $iArrFrame = Call("_cveInputArrayFrom" & $typeOfFrame, $frame)
    EndIf

    _cveDnnTextDetectionModelDetectTextRectangles($textDetectionModel, $iArrFrame, $detections, $confidences)

    If $bFrameIsArray Then
        Call("_VectorOf" & $typeOfFrame & "Release", $vectorFrame)
    EndIf

    If $typeOfFrame <> Default Then
        _cveInputArrayRelease($iArrFrame)
        If $bFrameCreate Then
            Call("_cve" & $typeOfFrame & "Release", $frame)
        EndIf
    EndIf
EndFunc   ;==>_cveDnnTextDetectionModelDetectTextRectanglesTyped

Func _cveDnnTextDetectionModelDetectTextRectanglesMat($textDetectionModel, $frame, $detections, $confidences)
    ; cveDnnTextDetectionModelDetectTextRectangles using cv::Mat instead of _*Array
    _cveDnnTextDetectionModelDetectTextRectanglesTyped($textDetectionModel, "Mat", $frame, $detections, $confidences)
EndFunc   ;==>_cveDnnTextDetectionModelDetectTextRectanglesMat

Func _cveDnnTextRecognitionModelCreate1($model, $config, $baseModel)
    ; CVAPI(cv::dnn::TextRecognitionModel*) cveDnnTextRecognitionModelCreate1(cv::String* model, cv::String* config, cv::dnn::Model** baseModel);

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

    Local $bConfigIsString = IsString($config)
    If $bConfigIsString Then
        $config = _cveStringCreateFromStr($config)
    EndIf

    Local $sConfigDllType
    If IsDllStruct($config) Then
        $sConfigDllType = "struct*"
    Else
        $sConfigDllType = "ptr"
    EndIf

    Local $sBaseModelDllType
    If IsDllStruct($baseModel) Then
        $sBaseModelDllType = "struct*"
    ElseIf $baseModel == Null Then
        $sBaseModelDllType = "ptr"
    Else
        $sBaseModelDllType = "ptr*"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveDnnTextRecognitionModelCreate1", $sModelDllType, $model, $sConfigDllType, $config, $sBaseModelDllType, $baseModel), "cveDnnTextRecognitionModelCreate1", @error)

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

    Local $sNetworkDllType
    If IsDllStruct($network) Then
        $sNetworkDllType = "struct*"
    Else
        $sNetworkDllType = "ptr"
    EndIf

    Local $sBaseModelDllType
    If IsDllStruct($baseModel) Then
        $sBaseModelDllType = "struct*"
    ElseIf $baseModel == Null Then
        $sBaseModelDllType = "ptr"
    Else
        $sBaseModelDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveDnnTextRecognitionModelCreate2", $sNetworkDllType, $network, $sBaseModelDllType, $baseModel), "cveDnnTextRecognitionModelCreate2", @error)
EndFunc   ;==>_cveDnnTextRecognitionModelCreate2

Func _cveDnnTextRecognitionModelRelease($textRecognitionModel)
    ; CVAPI(void) cveDnnTextRecognitionModelRelease(cv::dnn::TextRecognitionModel** textRecognitionModel);

    Local $sTextRecognitionModelDllType
    If IsDllStruct($textRecognitionModel) Then
        $sTextRecognitionModelDllType = "struct*"
    ElseIf $textRecognitionModel == Null Then
        $sTextRecognitionModelDllType = "ptr"
    Else
        $sTextRecognitionModelDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDnnTextRecognitionModelRelease", $sTextRecognitionModelDllType, $textRecognitionModel), "cveDnnTextRecognitionModelRelease", @error)
EndFunc   ;==>_cveDnnTextRecognitionModelRelease

Func _cveDnnTextRecognitionModelSetVocabulary($textRecognitionModel, $vocabulary)
    ; CVAPI(void) cveDnnTextRecognitionModelSetVocabulary(cv::dnn::TextRecognitionModel* textRecognitionModel, std::vector<std::string>* vocabulary);

    Local $sTextRecognitionModelDllType
    If IsDllStruct($textRecognitionModel) Then
        $sTextRecognitionModelDllType = "struct*"
    Else
        $sTextRecognitionModelDllType = "ptr"
    EndIf

    Local $sVocabularyDllType
    If IsDllStruct($vocabulary) Then
        $sVocabularyDllType = "struct*"
    Else
        $sVocabularyDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDnnTextRecognitionModelSetVocabulary", $sTextRecognitionModelDllType, $textRecognitionModel, $sVocabularyDllType, $vocabulary), "cveDnnTextRecognitionModelSetVocabulary", @error)
EndFunc   ;==>_cveDnnTextRecognitionModelSetVocabulary

Func _cveDnnTextRecognitionModelGetVocabulary($textRecognitionModel, $vocabulary)
    ; CVAPI(void) cveDnnTextRecognitionModelGetVocabulary(cv::dnn::TextRecognitionModel* textRecognitionModel, std::vector<std::string>* vocabulary);

    Local $sTextRecognitionModelDllType
    If IsDllStruct($textRecognitionModel) Then
        $sTextRecognitionModelDllType = "struct*"
    Else
        $sTextRecognitionModelDllType = "ptr"
    EndIf

    Local $sVocabularyDllType
    If IsDllStruct($vocabulary) Then
        $sVocabularyDllType = "struct*"
    Else
        $sVocabularyDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDnnTextRecognitionModelGetVocabulary", $sTextRecognitionModelDllType, $textRecognitionModel, $sVocabularyDllType, $vocabulary), "cveDnnTextRecognitionModelGetVocabulary", @error)
EndFunc   ;==>_cveDnnTextRecognitionModelGetVocabulary

Func _cveDnnTextRecognitionModelRecognize1($textRecognitionModel, $frame, $text)
    ; CVAPI(void) cveDnnTextRecognitionModelRecognize1(cv::dnn::TextRecognitionModel* textRecognitionModel, cv::_InputArray* frame, cv::String* text);

    Local $sTextRecognitionModelDllType
    If IsDllStruct($textRecognitionModel) Then
        $sTextRecognitionModelDllType = "struct*"
    Else
        $sTextRecognitionModelDllType = "ptr"
    EndIf

    Local $sFrameDllType
    If IsDllStruct($frame) Then
        $sFrameDllType = "struct*"
    Else
        $sFrameDllType = "ptr"
    EndIf

    Local $bTextIsString = IsString($text)
    If $bTextIsString Then
        $text = _cveStringCreateFromStr($text)
    EndIf

    Local $sTextDllType
    If IsDllStruct($text) Then
        $sTextDllType = "struct*"
    Else
        $sTextDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDnnTextRecognitionModelRecognize1", $sTextRecognitionModelDllType, $textRecognitionModel, $sFrameDllType, $frame, $sTextDllType, $text), "cveDnnTextRecognitionModelRecognize1", @error)

    If $bTextIsString Then
        _cveStringRelease($text)
    EndIf
EndFunc   ;==>_cveDnnTextRecognitionModelRecognize1

Func _cveDnnTextRecognitionModelRecognize1Typed($textRecognitionModel, $typeOfFrame, $frame, $text)

    Local $iArrFrame, $vectorFrame, $iArrFrameSize
    Local $bFrameIsArray = IsArray($frame)
    Local $bFrameCreate = IsDllStruct($frame) And $typeOfFrame == "Scalar"

    If $typeOfFrame == Default Then
        $iArrFrame = $frame
    ElseIf $bFrameIsArray Then
        $vectorFrame = Call("_VectorOf" & $typeOfFrame & "Create")

        $iArrFrameSize = UBound($frame)
        For $i = 0 To $iArrFrameSize - 1
            Call("_VectorOf" & $typeOfFrame & "Push", $vectorFrame, $frame[$i])
        Next

        $iArrFrame = Call("_cveInputArrayFromVectorOf" & $typeOfFrame, $vectorFrame)
    Else
        If $bFrameCreate Then
            $frame = Call("_cve" & $typeOfFrame & "Create", $frame)
        EndIf
        $iArrFrame = Call("_cveInputArrayFrom" & $typeOfFrame, $frame)
    EndIf

    _cveDnnTextRecognitionModelRecognize1($textRecognitionModel, $iArrFrame, $text)

    If $bFrameIsArray Then
        Call("_VectorOf" & $typeOfFrame & "Release", $vectorFrame)
    EndIf

    If $typeOfFrame <> Default Then
        _cveInputArrayRelease($iArrFrame)
        If $bFrameCreate Then
            Call("_cve" & $typeOfFrame & "Release", $frame)
        EndIf
    EndIf
EndFunc   ;==>_cveDnnTextRecognitionModelRecognize1Typed

Func _cveDnnTextRecognitionModelRecognize1Mat($textRecognitionModel, $frame, $text)
    ; cveDnnTextRecognitionModelRecognize1 using cv::Mat instead of _*Array
    _cveDnnTextRecognitionModelRecognize1Typed($textRecognitionModel, "Mat", $frame, $text)
EndFunc   ;==>_cveDnnTextRecognitionModelRecognize1Mat

Func _cveDnnTextRecognitionModelRecognize2($textRecognitionModel, $frame, $roiRects, $results)
    ; CVAPI(void) cveDnnTextRecognitionModelRecognize2(cv::dnn::TextRecognitionModel* textRecognitionModel, cv::_InputArray* frame, cv::_InputArray* roiRects, std::vector<std::string>* results);

    Local $sTextRecognitionModelDllType
    If IsDllStruct($textRecognitionModel) Then
        $sTextRecognitionModelDllType = "struct*"
    Else
        $sTextRecognitionModelDllType = "ptr"
    EndIf

    Local $sFrameDllType
    If IsDllStruct($frame) Then
        $sFrameDllType = "struct*"
    Else
        $sFrameDllType = "ptr"
    EndIf

    Local $sRoiRectsDllType
    If IsDllStruct($roiRects) Then
        $sRoiRectsDllType = "struct*"
    Else
        $sRoiRectsDllType = "ptr"
    EndIf

    Local $sResultsDllType
    If IsDllStruct($results) Then
        $sResultsDllType = "struct*"
    Else
        $sResultsDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDnnTextRecognitionModelRecognize2", $sTextRecognitionModelDllType, $textRecognitionModel, $sFrameDllType, $frame, $sRoiRectsDllType, $roiRects, $sResultsDllType, $results), "cveDnnTextRecognitionModelRecognize2", @error)
EndFunc   ;==>_cveDnnTextRecognitionModelRecognize2

Func _cveDnnTextRecognitionModelRecognize2Typed($textRecognitionModel, $typeOfFrame, $frame, $typeOfRoiRects, $roiRects, $results)

    Local $iArrFrame, $vectorFrame, $iArrFrameSize
    Local $bFrameIsArray = IsArray($frame)
    Local $bFrameCreate = IsDllStruct($frame) And $typeOfFrame == "Scalar"

    If $typeOfFrame == Default Then
        $iArrFrame = $frame
    ElseIf $bFrameIsArray Then
        $vectorFrame = Call("_VectorOf" & $typeOfFrame & "Create")

        $iArrFrameSize = UBound($frame)
        For $i = 0 To $iArrFrameSize - 1
            Call("_VectorOf" & $typeOfFrame & "Push", $vectorFrame, $frame[$i])
        Next

        $iArrFrame = Call("_cveInputArrayFromVectorOf" & $typeOfFrame, $vectorFrame)
    Else
        If $bFrameCreate Then
            $frame = Call("_cve" & $typeOfFrame & "Create", $frame)
        EndIf
        $iArrFrame = Call("_cveInputArrayFrom" & $typeOfFrame, $frame)
    EndIf

    Local $iArrRoiRects, $vectorRoiRects, $iArrRoiRectsSize
    Local $bRoiRectsIsArray = IsArray($roiRects)
    Local $bRoiRectsCreate = IsDllStruct($roiRects) And $typeOfRoiRects == "Scalar"

    If $typeOfRoiRects == Default Then
        $iArrRoiRects = $roiRects
    ElseIf $bRoiRectsIsArray Then
        $vectorRoiRects = Call("_VectorOf" & $typeOfRoiRects & "Create")

        $iArrRoiRectsSize = UBound($roiRects)
        For $i = 0 To $iArrRoiRectsSize - 1
            Call("_VectorOf" & $typeOfRoiRects & "Push", $vectorRoiRects, $roiRects[$i])
        Next

        $iArrRoiRects = Call("_cveInputArrayFromVectorOf" & $typeOfRoiRects, $vectorRoiRects)
    Else
        If $bRoiRectsCreate Then
            $roiRects = Call("_cve" & $typeOfRoiRects & "Create", $roiRects)
        EndIf
        $iArrRoiRects = Call("_cveInputArrayFrom" & $typeOfRoiRects, $roiRects)
    EndIf

    _cveDnnTextRecognitionModelRecognize2($textRecognitionModel, $iArrFrame, $iArrRoiRects, $results)

    If $bRoiRectsIsArray Then
        Call("_VectorOf" & $typeOfRoiRects & "Release", $vectorRoiRects)
    EndIf

    If $typeOfRoiRects <> Default Then
        _cveInputArrayRelease($iArrRoiRects)
        If $bRoiRectsCreate Then
            Call("_cve" & $typeOfRoiRects & "Release", $roiRects)
        EndIf
    EndIf

    If $bFrameIsArray Then
        Call("_VectorOf" & $typeOfFrame & "Release", $vectorFrame)
    EndIf

    If $typeOfFrame <> Default Then
        _cveInputArrayRelease($iArrFrame)
        If $bFrameCreate Then
            Call("_cve" & $typeOfFrame & "Release", $frame)
        EndIf
    EndIf
EndFunc   ;==>_cveDnnTextRecognitionModelRecognize2Typed

Func _cveDnnTextRecognitionModelRecognize2Mat($textRecognitionModel, $frame, $roiRects, $results)
    ; cveDnnTextRecognitionModelRecognize2 using cv::Mat instead of _*Array
    _cveDnnTextRecognitionModelRecognize2Typed($textRecognitionModel, "Mat", $frame, "Mat", $roiRects, $results)
EndFunc   ;==>_cveDnnTextRecognitionModelRecognize2Mat

Func _cveModelCreate($model, $config)
    ; CVAPI(cv::dnn::Model*) cveModelCreate(cv::String* model, cv::String* config);

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

    Local $bConfigIsString = IsString($config)
    If $bConfigIsString Then
        $config = _cveStringCreateFromStr($config)
    EndIf

    Local $sConfigDllType
    If IsDllStruct($config) Then
        $sConfigDllType = "struct*"
    Else
        $sConfigDllType = "ptr"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveModelCreate", $sModelDllType, $model, $sConfigDllType, $config), "cveModelCreate", @error)

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

    Local $sNetworkDllType
    If IsDllStruct($network) Then
        $sNetworkDllType = "struct*"
    Else
        $sNetworkDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveModelCreateFromNet", $sNetworkDllType, $network), "cveModelCreateFromNet", @error)
EndFunc   ;==>_cveModelCreateFromNet

Func _cveModelRelease($model)
    ; CVAPI(void) cveModelRelease(cv::dnn::Model** model);

    Local $sModelDllType
    If IsDllStruct($model) Then
        $sModelDllType = "struct*"
    ElseIf $model == Null Then
        $sModelDllType = "ptr"
    Else
        $sModelDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveModelRelease", $sModelDllType, $model), "cveModelRelease", @error)
EndFunc   ;==>_cveModelRelease

Func _cveModelPredict($model, $frame, $outs)
    ; CVAPI(void) cveModelPredict(cv::dnn::Model* model, cv::_InputArray* frame, cv::_OutputArray* outs);

    Local $sModelDllType
    If IsDllStruct($model) Then
        $sModelDllType = "struct*"
    Else
        $sModelDllType = "ptr"
    EndIf

    Local $sFrameDllType
    If IsDllStruct($frame) Then
        $sFrameDllType = "struct*"
    Else
        $sFrameDllType = "ptr"
    EndIf

    Local $sOutsDllType
    If IsDllStruct($outs) Then
        $sOutsDllType = "struct*"
    Else
        $sOutsDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveModelPredict", $sModelDllType, $model, $sFrameDllType, $frame, $sOutsDllType, $outs), "cveModelPredict", @error)
EndFunc   ;==>_cveModelPredict

Func _cveModelPredictTyped($model, $typeOfFrame, $frame, $typeOfOuts, $outs)

    Local $iArrFrame, $vectorFrame, $iArrFrameSize
    Local $bFrameIsArray = IsArray($frame)
    Local $bFrameCreate = IsDllStruct($frame) And $typeOfFrame == "Scalar"

    If $typeOfFrame == Default Then
        $iArrFrame = $frame
    ElseIf $bFrameIsArray Then
        $vectorFrame = Call("_VectorOf" & $typeOfFrame & "Create")

        $iArrFrameSize = UBound($frame)
        For $i = 0 To $iArrFrameSize - 1
            Call("_VectorOf" & $typeOfFrame & "Push", $vectorFrame, $frame[$i])
        Next

        $iArrFrame = Call("_cveInputArrayFromVectorOf" & $typeOfFrame, $vectorFrame)
    Else
        If $bFrameCreate Then
            $frame = Call("_cve" & $typeOfFrame & "Create", $frame)
        EndIf
        $iArrFrame = Call("_cveInputArrayFrom" & $typeOfFrame, $frame)
    EndIf

    Local $oArrOuts, $vectorOuts, $iArrOutsSize
    Local $bOutsIsArray = IsArray($outs)
    Local $bOutsCreate = IsDllStruct($outs) And $typeOfOuts == "Scalar"

    If $typeOfOuts == Default Then
        $oArrOuts = $outs
    ElseIf $bOutsIsArray Then
        $vectorOuts = Call("_VectorOf" & $typeOfOuts & "Create")

        $iArrOutsSize = UBound($outs)
        For $i = 0 To $iArrOutsSize - 1
            Call("_VectorOf" & $typeOfOuts & "Push", $vectorOuts, $outs[$i])
        Next

        $oArrOuts = Call("_cveOutputArrayFromVectorOf" & $typeOfOuts, $vectorOuts)
    Else
        If $bOutsCreate Then
            $outs = Call("_cve" & $typeOfOuts & "Create", $outs)
        EndIf
        $oArrOuts = Call("_cveOutputArrayFrom" & $typeOfOuts, $outs)
    EndIf

    _cveModelPredict($model, $iArrFrame, $oArrOuts)

    If $bOutsIsArray Then
        Call("_VectorOf" & $typeOfOuts & "Release", $vectorOuts)
    EndIf

    If $typeOfOuts <> Default Then
        _cveOutputArrayRelease($oArrOuts)
        If $bOutsCreate Then
            Call("_cve" & $typeOfOuts & "Release", $outs)
        EndIf
    EndIf

    If $bFrameIsArray Then
        Call("_VectorOf" & $typeOfFrame & "Release", $vectorFrame)
    EndIf

    If $typeOfFrame <> Default Then
        _cveInputArrayRelease($iArrFrame)
        If $bFrameCreate Then
            Call("_cve" & $typeOfFrame & "Release", $frame)
        EndIf
    EndIf
EndFunc   ;==>_cveModelPredictTyped

Func _cveModelPredictMat($model, $frame, $outs)
    ; cveModelPredict using cv::Mat instead of _*Array
    _cveModelPredictTyped($model, "Mat", $frame, "Mat", $outs)
EndFunc   ;==>_cveModelPredictMat

Func _cveModelSetInputMean($model, $mean)
    ; CVAPI(void) cveModelSetInputMean(cv::dnn::Model* model, CvScalar* mean);

    Local $sModelDllType
    If IsDllStruct($model) Then
        $sModelDllType = "struct*"
    Else
        $sModelDllType = "ptr"
    EndIf

    Local $sMeanDllType
    If IsDllStruct($mean) Then
        $sMeanDllType = "struct*"
    Else
        $sMeanDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveModelSetInputMean", $sModelDllType, $model, $sMeanDllType, $mean), "cveModelSetInputMean", @error)
EndFunc   ;==>_cveModelSetInputMean

Func _cveModelSetInputScale($model, $value)
    ; CVAPI(void) cveModelSetInputScale(cv::dnn::Model* model, double value);

    Local $sModelDllType
    If IsDllStruct($model) Then
        $sModelDllType = "struct*"
    Else
        $sModelDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveModelSetInputScale", $sModelDllType, $model, "double", $value), "cveModelSetInputScale", @error)
EndFunc   ;==>_cveModelSetInputScale

Func _cveModelSetInputSize($model, $size)
    ; CVAPI(void) cveModelSetInputSize(cv::dnn::Model* model, CvSize* size);

    Local $sModelDllType
    If IsDllStruct($model) Then
        $sModelDllType = "struct*"
    Else
        $sModelDllType = "ptr"
    EndIf

    Local $sSizeDllType
    If IsDllStruct($size) Then
        $sSizeDllType = "struct*"
    Else
        $sSizeDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveModelSetInputSize", $sModelDllType, $model, $sSizeDllType, $size), "cveModelSetInputSize", @error)
EndFunc   ;==>_cveModelSetInputSize

Func _cveModelSetInputCrop($model, $crop)
    ; CVAPI(void) cveModelSetInputCrop(cv::dnn::Model* model, bool crop);

    Local $sModelDllType
    If IsDllStruct($model) Then
        $sModelDllType = "struct*"
    Else
        $sModelDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveModelSetInputCrop", $sModelDllType, $model, "boolean", $crop), "cveModelSetInputCrop", @error)
EndFunc   ;==>_cveModelSetInputCrop

Func _cveModelSetInputSwapRB($model, $swapRB)
    ; CVAPI(void) cveModelSetInputSwapRB(cv::dnn::Model* model, bool swapRB);

    Local $sModelDllType
    If IsDllStruct($model) Then
        $sModelDllType = "struct*"
    Else
        $sModelDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveModelSetInputSwapRB", $sModelDllType, $model, "boolean", $swapRB), "cveModelSetInputSwapRB", @error)
EndFunc   ;==>_cveModelSetInputSwapRB

Func _cveModelSetPreferableBackend($model, $backendId)
    ; CVAPI(void) cveModelSetPreferableBackend(cv::dnn::Model* model, int backendId);

    Local $sModelDllType
    If IsDllStruct($model) Then
        $sModelDllType = "struct*"
    Else
        $sModelDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveModelSetPreferableBackend", $sModelDllType, $model, "int", $backendId), "cveModelSetPreferableBackend", @error)
EndFunc   ;==>_cveModelSetPreferableBackend

Func _cveModelSetPreferableTarget($model, $targetId)
    ; CVAPI(void) cveModelSetPreferableTarget(cv::dnn::Model* model, int targetId);

    Local $sModelDllType
    If IsDllStruct($model) Then
        $sModelDllType = "struct*"
    Else
        $sModelDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveModelSetPreferableTarget", $sModelDllType, $model, "int", $targetId), "cveModelSetPreferableTarget", @error)
EndFunc   ;==>_cveModelSetPreferableTarget

Func _cveDnnDetectionModelCreate1($model, $config, $baseModel)
    ; CVAPI(cv::dnn::DetectionModel*) cveDnnDetectionModelCreate1(cv::String* model, cv::String* config, cv::dnn::Model** baseModel);

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

    Local $bConfigIsString = IsString($config)
    If $bConfigIsString Then
        $config = _cveStringCreateFromStr($config)
    EndIf

    Local $sConfigDllType
    If IsDllStruct($config) Then
        $sConfigDllType = "struct*"
    Else
        $sConfigDllType = "ptr"
    EndIf

    Local $sBaseModelDllType
    If IsDllStruct($baseModel) Then
        $sBaseModelDllType = "struct*"
    ElseIf $baseModel == Null Then
        $sBaseModelDllType = "ptr"
    Else
        $sBaseModelDllType = "ptr*"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveDnnDetectionModelCreate1", $sModelDllType, $model, $sConfigDllType, $config, $sBaseModelDllType, $baseModel), "cveDnnDetectionModelCreate1", @error)

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

    Local $sNetworkDllType
    If IsDllStruct($network) Then
        $sNetworkDllType = "struct*"
    Else
        $sNetworkDllType = "ptr"
    EndIf

    Local $sBaseModelDllType
    If IsDllStruct($baseModel) Then
        $sBaseModelDllType = "struct*"
    ElseIf $baseModel == Null Then
        $sBaseModelDllType = "ptr"
    Else
        $sBaseModelDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveDnnDetectionModelCreate2", $sNetworkDllType, $network, $sBaseModelDllType, $baseModel), "cveDnnDetectionModelCreate2", @error)
EndFunc   ;==>_cveDnnDetectionModelCreate2

Func _cveDnnDetectionModelRelease($detectionModel)
    ; CVAPI(void) cveDnnDetectionModelRelease(cv::dnn::DetectionModel** detectionModel);

    Local $sDetectionModelDllType
    If IsDllStruct($detectionModel) Then
        $sDetectionModelDllType = "struct*"
    ElseIf $detectionModel == Null Then
        $sDetectionModelDllType = "ptr"
    Else
        $sDetectionModelDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDnnDetectionModelRelease", $sDetectionModelDllType, $detectionModel), "cveDnnDetectionModelRelease", @error)
EndFunc   ;==>_cveDnnDetectionModelRelease

Func _cveDnnDetectionModelDetect($detectionModel, $frame, $classIds, $confidences, $boxes, $confThreshold, $nmsThreshold)
    ; CVAPI(void) cveDnnDetectionModelDetect(cv::dnn::DetectionModel* detectionModel, cv::_InputArray* frame, std::vector<int>* classIds, std::vector<float>* confidences, std::vector<cv::Rect>* boxes, float confThreshold, float nmsThreshold);

    Local $sDetectionModelDllType
    If IsDllStruct($detectionModel) Then
        $sDetectionModelDllType = "struct*"
    Else
        $sDetectionModelDllType = "ptr"
    EndIf

    Local $sFrameDllType
    If IsDllStruct($frame) Then
        $sFrameDllType = "struct*"
    Else
        $sFrameDllType = "ptr"
    EndIf

    Local $vecClassIds, $iArrClassIdsSize
    Local $bClassIdsIsArray = IsArray($classIds)

    If $bClassIdsIsArray Then
        $vecClassIds = _VectorOfIntCreate()

        $iArrClassIdsSize = UBound($classIds)
        For $i = 0 To $iArrClassIdsSize - 1
            _VectorOfIntPush($vecClassIds, $classIds[$i])
        Next
    Else
        $vecClassIds = $classIds
    EndIf

    Local $sClassIdsDllType
    If IsDllStruct($classIds) Then
        $sClassIdsDllType = "struct*"
    Else
        $sClassIdsDllType = "ptr"
    EndIf

    Local $vecConfidences, $iArrConfidencesSize
    Local $bConfidencesIsArray = IsArray($confidences)

    If $bConfidencesIsArray Then
        $vecConfidences = _VectorOfFloatCreate()

        $iArrConfidencesSize = UBound($confidences)
        For $i = 0 To $iArrConfidencesSize - 1
            _VectorOfFloatPush($vecConfidences, $confidences[$i])
        Next
    Else
        $vecConfidences = $confidences
    EndIf

    Local $sConfidencesDllType
    If IsDllStruct($confidences) Then
        $sConfidencesDllType = "struct*"
    Else
        $sConfidencesDllType = "ptr"
    EndIf

    Local $vecBoxes, $iArrBoxesSize
    Local $bBoxesIsArray = IsArray($boxes)

    If $bBoxesIsArray Then
        $vecBoxes = _VectorOfRectCreate()

        $iArrBoxesSize = UBound($boxes)
        For $i = 0 To $iArrBoxesSize - 1
            _VectorOfRectPush($vecBoxes, $boxes[$i])
        Next
    Else
        $vecBoxes = $boxes
    EndIf

    Local $sBoxesDllType
    If IsDllStruct($boxes) Then
        $sBoxesDllType = "struct*"
    Else
        $sBoxesDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDnnDetectionModelDetect", $sDetectionModelDllType, $detectionModel, $sFrameDllType, $frame, $sClassIdsDllType, $vecClassIds, $sConfidencesDllType, $vecConfidences, $sBoxesDllType, $vecBoxes, "float", $confThreshold, "float", $nmsThreshold), "cveDnnDetectionModelDetect", @error)

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

Func _cveDnnDetectionModelDetectTyped($detectionModel, $typeOfFrame, $frame, $classIds, $confidences, $boxes, $confThreshold, $nmsThreshold)

    Local $iArrFrame, $vectorFrame, $iArrFrameSize
    Local $bFrameIsArray = IsArray($frame)
    Local $bFrameCreate = IsDllStruct($frame) And $typeOfFrame == "Scalar"

    If $typeOfFrame == Default Then
        $iArrFrame = $frame
    ElseIf $bFrameIsArray Then
        $vectorFrame = Call("_VectorOf" & $typeOfFrame & "Create")

        $iArrFrameSize = UBound($frame)
        For $i = 0 To $iArrFrameSize - 1
            Call("_VectorOf" & $typeOfFrame & "Push", $vectorFrame, $frame[$i])
        Next

        $iArrFrame = Call("_cveInputArrayFromVectorOf" & $typeOfFrame, $vectorFrame)
    Else
        If $bFrameCreate Then
            $frame = Call("_cve" & $typeOfFrame & "Create", $frame)
        EndIf
        $iArrFrame = Call("_cveInputArrayFrom" & $typeOfFrame, $frame)
    EndIf

    _cveDnnDetectionModelDetect($detectionModel, $iArrFrame, $classIds, $confidences, $boxes, $confThreshold, $nmsThreshold)

    If $bFrameIsArray Then
        Call("_VectorOf" & $typeOfFrame & "Release", $vectorFrame)
    EndIf

    If $typeOfFrame <> Default Then
        _cveInputArrayRelease($iArrFrame)
        If $bFrameCreate Then
            Call("_cve" & $typeOfFrame & "Release", $frame)
        EndIf
    EndIf
EndFunc   ;==>_cveDnnDetectionModelDetectTyped

Func _cveDnnDetectionModelDetectMat($detectionModel, $frame, $classIds, $confidences, $boxes, $confThreshold, $nmsThreshold)
    ; cveDnnDetectionModelDetect using cv::Mat instead of _*Array
    _cveDnnDetectionModelDetectTyped($detectionModel, "Mat", $frame, $classIds, $confidences, $boxes, $confThreshold, $nmsThreshold)
EndFunc   ;==>_cveDnnDetectionModelDetectMat

Func _cveDnnClassificationModelCreate1($model, $config, $baseModel)
    ; CVAPI(cv::dnn::ClassificationModel*) cveDnnClassificationModelCreate1(cv::String* model, cv::String* config, cv::dnn::Model** baseModel);

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

    Local $bConfigIsString = IsString($config)
    If $bConfigIsString Then
        $config = _cveStringCreateFromStr($config)
    EndIf

    Local $sConfigDllType
    If IsDllStruct($config) Then
        $sConfigDllType = "struct*"
    Else
        $sConfigDllType = "ptr"
    EndIf

    Local $sBaseModelDllType
    If IsDllStruct($baseModel) Then
        $sBaseModelDllType = "struct*"
    ElseIf $baseModel == Null Then
        $sBaseModelDllType = "ptr"
    Else
        $sBaseModelDllType = "ptr*"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveDnnClassificationModelCreate1", $sModelDllType, $model, $sConfigDllType, $config, $sBaseModelDllType, $baseModel), "cveDnnClassificationModelCreate1", @error)

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

    Local $sNetworkDllType
    If IsDllStruct($network) Then
        $sNetworkDllType = "struct*"
    Else
        $sNetworkDllType = "ptr"
    EndIf

    Local $sBaseModelDllType
    If IsDllStruct($baseModel) Then
        $sBaseModelDllType = "struct*"
    ElseIf $baseModel == Null Then
        $sBaseModelDllType = "ptr"
    Else
        $sBaseModelDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveDnnClassificationModelCreate2", $sNetworkDllType, $network, $sBaseModelDllType, $baseModel), "cveDnnClassificationModelCreate2", @error)
EndFunc   ;==>_cveDnnClassificationModelCreate2

Func _cveDnnClassificationModelRelease($classificationModel)
    ; CVAPI(void) cveDnnClassificationModelRelease(cv::dnn::ClassificationModel** classificationModel);

    Local $sClassificationModelDllType
    If IsDllStruct($classificationModel) Then
        $sClassificationModelDllType = "struct*"
    ElseIf $classificationModel == Null Then
        $sClassificationModelDllType = "ptr"
    Else
        $sClassificationModelDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDnnClassificationModelRelease", $sClassificationModelDllType, $classificationModel), "cveDnnClassificationModelRelease", @error)
EndFunc   ;==>_cveDnnClassificationModelRelease

Func _cveDnnClassificationModelClassify($classificationModel, $frame, $classId, $conf)
    ; CVAPI(void) cveDnnClassificationModelClassify(cv::dnn::ClassificationModel* classificationModel, cv::_InputArray* frame, int* classId, float* conf);

    Local $sClassificationModelDllType
    If IsDllStruct($classificationModel) Then
        $sClassificationModelDllType = "struct*"
    Else
        $sClassificationModelDllType = "ptr"
    EndIf

    Local $sFrameDllType
    If IsDllStruct($frame) Then
        $sFrameDllType = "struct*"
    Else
        $sFrameDllType = "ptr"
    EndIf

    Local $sClassIdDllType
    If IsDllStruct($classId) Then
        $sClassIdDllType = "struct*"
    Else
        $sClassIdDllType = "int*"
    EndIf

    Local $sConfDllType
    If IsDllStruct($conf) Then
        $sConfDllType = "struct*"
    Else
        $sConfDllType = "float*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDnnClassificationModelClassify", $sClassificationModelDllType, $classificationModel, $sFrameDllType, $frame, $sClassIdDllType, $classId, $sConfDllType, $conf), "cveDnnClassificationModelClassify", @error)
EndFunc   ;==>_cveDnnClassificationModelClassify

Func _cveDnnClassificationModelClassifyTyped($classificationModel, $typeOfFrame, $frame, $classId, $conf)

    Local $iArrFrame, $vectorFrame, $iArrFrameSize
    Local $bFrameIsArray = IsArray($frame)
    Local $bFrameCreate = IsDllStruct($frame) And $typeOfFrame == "Scalar"

    If $typeOfFrame == Default Then
        $iArrFrame = $frame
    ElseIf $bFrameIsArray Then
        $vectorFrame = Call("_VectorOf" & $typeOfFrame & "Create")

        $iArrFrameSize = UBound($frame)
        For $i = 0 To $iArrFrameSize - 1
            Call("_VectorOf" & $typeOfFrame & "Push", $vectorFrame, $frame[$i])
        Next

        $iArrFrame = Call("_cveInputArrayFromVectorOf" & $typeOfFrame, $vectorFrame)
    Else
        If $bFrameCreate Then
            $frame = Call("_cve" & $typeOfFrame & "Create", $frame)
        EndIf
        $iArrFrame = Call("_cveInputArrayFrom" & $typeOfFrame, $frame)
    EndIf

    _cveDnnClassificationModelClassify($classificationModel, $iArrFrame, $classId, $conf)

    If $bFrameIsArray Then
        Call("_VectorOf" & $typeOfFrame & "Release", $vectorFrame)
    EndIf

    If $typeOfFrame <> Default Then
        _cveInputArrayRelease($iArrFrame)
        If $bFrameCreate Then
            Call("_cve" & $typeOfFrame & "Release", $frame)
        EndIf
    EndIf
EndFunc   ;==>_cveDnnClassificationModelClassifyTyped

Func _cveDnnClassificationModelClassifyMat($classificationModel, $frame, $classId, $conf)
    ; cveDnnClassificationModelClassify using cv::Mat instead of _*Array
    _cveDnnClassificationModelClassifyTyped($classificationModel, "Mat", $frame, $classId, $conf)
EndFunc   ;==>_cveDnnClassificationModelClassifyMat

Func _cveDnnKeypointsModelCreate1($model, $config, $baseModel)
    ; CVAPI(cv::dnn::KeypointsModel*) cveDnnKeypointsModelCreate1(cv::String* model, cv::String* config, cv::dnn::Model** baseModel);

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

    Local $bConfigIsString = IsString($config)
    If $bConfigIsString Then
        $config = _cveStringCreateFromStr($config)
    EndIf

    Local $sConfigDllType
    If IsDllStruct($config) Then
        $sConfigDllType = "struct*"
    Else
        $sConfigDllType = "ptr"
    EndIf

    Local $sBaseModelDllType
    If IsDllStruct($baseModel) Then
        $sBaseModelDllType = "struct*"
    ElseIf $baseModel == Null Then
        $sBaseModelDllType = "ptr"
    Else
        $sBaseModelDllType = "ptr*"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveDnnKeypointsModelCreate1", $sModelDllType, $model, $sConfigDllType, $config, $sBaseModelDllType, $baseModel), "cveDnnKeypointsModelCreate1", @error)

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

    Local $sNetworkDllType
    If IsDllStruct($network) Then
        $sNetworkDllType = "struct*"
    Else
        $sNetworkDllType = "ptr"
    EndIf

    Local $sBaseModelDllType
    If IsDllStruct($baseModel) Then
        $sBaseModelDllType = "struct*"
    ElseIf $baseModel == Null Then
        $sBaseModelDllType = "ptr"
    Else
        $sBaseModelDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveDnnKeypointsModelCreate2", $sNetworkDllType, $network, $sBaseModelDllType, $baseModel), "cveDnnKeypointsModelCreate2", @error)
EndFunc   ;==>_cveDnnKeypointsModelCreate2

Func _cveDnnKeypointsModelRelease($keypointsModel)
    ; CVAPI(void) cveDnnKeypointsModelRelease(cv::dnn::KeypointsModel** keypointsModel);

    Local $sKeypointsModelDllType
    If IsDllStruct($keypointsModel) Then
        $sKeypointsModelDllType = "struct*"
    ElseIf $keypointsModel == Null Then
        $sKeypointsModelDllType = "ptr"
    Else
        $sKeypointsModelDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDnnKeypointsModelRelease", $sKeypointsModelDllType, $keypointsModel), "cveDnnKeypointsModelRelease", @error)
EndFunc   ;==>_cveDnnKeypointsModelRelease

Func _cveDnnKeypointsModelEstimate($keypointsModel, $frame, $keypoints, $thresh)
    ; CVAPI(void) cveDnnKeypointsModelEstimate(cv::dnn::KeypointsModel* keypointsModel, cv::_InputArray* frame, std::vector<cv::Point2f>* keypoints, float thresh);

    Local $sKeypointsModelDllType
    If IsDllStruct($keypointsModel) Then
        $sKeypointsModelDllType = "struct*"
    Else
        $sKeypointsModelDllType = "ptr"
    EndIf

    Local $sFrameDllType
    If IsDllStruct($frame) Then
        $sFrameDllType = "struct*"
    Else
        $sFrameDllType = "ptr"
    EndIf

    Local $vecKeypoints, $iArrKeypointsSize
    Local $bKeypointsIsArray = IsArray($keypoints)

    If $bKeypointsIsArray Then
        $vecKeypoints = _VectorOfPointFCreate()

        $iArrKeypointsSize = UBound($keypoints)
        For $i = 0 To $iArrKeypointsSize - 1
            _VectorOfPointFPush($vecKeypoints, $keypoints[$i])
        Next
    Else
        $vecKeypoints = $keypoints
    EndIf

    Local $sKeypointsDllType
    If IsDllStruct($keypoints) Then
        $sKeypointsDllType = "struct*"
    Else
        $sKeypointsDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDnnKeypointsModelEstimate", $sKeypointsModelDllType, $keypointsModel, $sFrameDllType, $frame, $sKeypointsDllType, $vecKeypoints, "float", $thresh), "cveDnnKeypointsModelEstimate", @error)

    If $bKeypointsIsArray Then
        _VectorOfPointFRelease($vecKeypoints)
    EndIf
EndFunc   ;==>_cveDnnKeypointsModelEstimate

Func _cveDnnKeypointsModelEstimateTyped($keypointsModel, $typeOfFrame, $frame, $keypoints, $thresh)

    Local $iArrFrame, $vectorFrame, $iArrFrameSize
    Local $bFrameIsArray = IsArray($frame)
    Local $bFrameCreate = IsDllStruct($frame) And $typeOfFrame == "Scalar"

    If $typeOfFrame == Default Then
        $iArrFrame = $frame
    ElseIf $bFrameIsArray Then
        $vectorFrame = Call("_VectorOf" & $typeOfFrame & "Create")

        $iArrFrameSize = UBound($frame)
        For $i = 0 To $iArrFrameSize - 1
            Call("_VectorOf" & $typeOfFrame & "Push", $vectorFrame, $frame[$i])
        Next

        $iArrFrame = Call("_cveInputArrayFromVectorOf" & $typeOfFrame, $vectorFrame)
    Else
        If $bFrameCreate Then
            $frame = Call("_cve" & $typeOfFrame & "Create", $frame)
        EndIf
        $iArrFrame = Call("_cveInputArrayFrom" & $typeOfFrame, $frame)
    EndIf

    _cveDnnKeypointsModelEstimate($keypointsModel, $iArrFrame, $keypoints, $thresh)

    If $bFrameIsArray Then
        Call("_VectorOf" & $typeOfFrame & "Release", $vectorFrame)
    EndIf

    If $typeOfFrame <> Default Then
        _cveInputArrayRelease($iArrFrame)
        If $bFrameCreate Then
            Call("_cve" & $typeOfFrame & "Release", $frame)
        EndIf
    EndIf
EndFunc   ;==>_cveDnnKeypointsModelEstimateTyped

Func _cveDnnKeypointsModelEstimateMat($keypointsModel, $frame, $keypoints, $thresh)
    ; cveDnnKeypointsModelEstimate using cv::Mat instead of _*Array
    _cveDnnKeypointsModelEstimateTyped($keypointsModel, "Mat", $frame, $keypoints, $thresh)
EndFunc   ;==>_cveDnnKeypointsModelEstimateMat

Func _cveDnnSegmentationModelCreate1($model, $config, $baseModel)
    ; CVAPI(cv::dnn::SegmentationModel*) cveDnnSegmentationModelCreate1(cv::String* model, cv::String* config, cv::dnn::Model** baseModel);

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

    Local $bConfigIsString = IsString($config)
    If $bConfigIsString Then
        $config = _cveStringCreateFromStr($config)
    EndIf

    Local $sConfigDllType
    If IsDllStruct($config) Then
        $sConfigDllType = "struct*"
    Else
        $sConfigDllType = "ptr"
    EndIf

    Local $sBaseModelDllType
    If IsDllStruct($baseModel) Then
        $sBaseModelDllType = "struct*"
    ElseIf $baseModel == Null Then
        $sBaseModelDllType = "ptr"
    Else
        $sBaseModelDllType = "ptr*"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveDnnSegmentationModelCreate1", $sModelDllType, $model, $sConfigDllType, $config, $sBaseModelDllType, $baseModel), "cveDnnSegmentationModelCreate1", @error)

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

    Local $sNetworkDllType
    If IsDllStruct($network) Then
        $sNetworkDllType = "struct*"
    Else
        $sNetworkDllType = "ptr"
    EndIf

    Local $sBaseModelDllType
    If IsDllStruct($baseModel) Then
        $sBaseModelDllType = "struct*"
    ElseIf $baseModel == Null Then
        $sBaseModelDllType = "ptr"
    Else
        $sBaseModelDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveDnnSegmentationModelCreate2", $sNetworkDllType, $network, $sBaseModelDllType, $baseModel), "cveDnnSegmentationModelCreate2", @error)
EndFunc   ;==>_cveDnnSegmentationModelCreate2

Func _cveDnnSegmentationModelRelease($segmentationModel)
    ; CVAPI(void) cveDnnSegmentationModelRelease(cv::dnn::SegmentationModel** segmentationModel);

    Local $sSegmentationModelDllType
    If IsDllStruct($segmentationModel) Then
        $sSegmentationModelDllType = "struct*"
    ElseIf $segmentationModel == Null Then
        $sSegmentationModelDllType = "ptr"
    Else
        $sSegmentationModelDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDnnSegmentationModelRelease", $sSegmentationModelDllType, $segmentationModel), "cveDnnSegmentationModelRelease", @error)
EndFunc   ;==>_cveDnnSegmentationModelRelease

Func _cveDnnSegmentationModelSegment($segmentationModel, $frame, $mask)
    ; CVAPI(void) cveDnnSegmentationModelSegment(cv::dnn::SegmentationModel* segmentationModel, cv::_InputArray* frame, cv::_OutputArray* mask);

    Local $sSegmentationModelDllType
    If IsDllStruct($segmentationModel) Then
        $sSegmentationModelDllType = "struct*"
    Else
        $sSegmentationModelDllType = "ptr"
    EndIf

    Local $sFrameDllType
    If IsDllStruct($frame) Then
        $sFrameDllType = "struct*"
    Else
        $sFrameDllType = "ptr"
    EndIf

    Local $sMaskDllType
    If IsDllStruct($mask) Then
        $sMaskDllType = "struct*"
    Else
        $sMaskDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDnnSegmentationModelSegment", $sSegmentationModelDllType, $segmentationModel, $sFrameDllType, $frame, $sMaskDllType, $mask), "cveDnnSegmentationModelSegment", @error)
EndFunc   ;==>_cveDnnSegmentationModelSegment

Func _cveDnnSegmentationModelSegmentTyped($segmentationModel, $typeOfFrame, $frame, $typeOfMask, $mask)

    Local $iArrFrame, $vectorFrame, $iArrFrameSize
    Local $bFrameIsArray = IsArray($frame)
    Local $bFrameCreate = IsDllStruct($frame) And $typeOfFrame == "Scalar"

    If $typeOfFrame == Default Then
        $iArrFrame = $frame
    ElseIf $bFrameIsArray Then
        $vectorFrame = Call("_VectorOf" & $typeOfFrame & "Create")

        $iArrFrameSize = UBound($frame)
        For $i = 0 To $iArrFrameSize - 1
            Call("_VectorOf" & $typeOfFrame & "Push", $vectorFrame, $frame[$i])
        Next

        $iArrFrame = Call("_cveInputArrayFromVectorOf" & $typeOfFrame, $vectorFrame)
    Else
        If $bFrameCreate Then
            $frame = Call("_cve" & $typeOfFrame & "Create", $frame)
        EndIf
        $iArrFrame = Call("_cveInputArrayFrom" & $typeOfFrame, $frame)
    EndIf

    Local $oArrMask, $vectorMask, $iArrMaskSize
    Local $bMaskIsArray = IsArray($mask)
    Local $bMaskCreate = IsDllStruct($mask) And $typeOfMask == "Scalar"

    If $typeOfMask == Default Then
        $oArrMask = $mask
    ElseIf $bMaskIsArray Then
        $vectorMask = Call("_VectorOf" & $typeOfMask & "Create")

        $iArrMaskSize = UBound($mask)
        For $i = 0 To $iArrMaskSize - 1
            Call("_VectorOf" & $typeOfMask & "Push", $vectorMask, $mask[$i])
        Next

        $oArrMask = Call("_cveOutputArrayFromVectorOf" & $typeOfMask, $vectorMask)
    Else
        If $bMaskCreate Then
            $mask = Call("_cve" & $typeOfMask & "Create", $mask)
        EndIf
        $oArrMask = Call("_cveOutputArrayFrom" & $typeOfMask, $mask)
    EndIf

    _cveDnnSegmentationModelSegment($segmentationModel, $iArrFrame, $oArrMask)

    If $bMaskIsArray Then
        Call("_VectorOf" & $typeOfMask & "Release", $vectorMask)
    EndIf

    If $typeOfMask <> Default Then
        _cveOutputArrayRelease($oArrMask)
        If $bMaskCreate Then
            Call("_cve" & $typeOfMask & "Release", $mask)
        EndIf
    EndIf

    If $bFrameIsArray Then
        Call("_VectorOf" & $typeOfFrame & "Release", $vectorFrame)
    EndIf

    If $typeOfFrame <> Default Then
        _cveInputArrayRelease($iArrFrame)
        If $bFrameCreate Then
            Call("_cve" & $typeOfFrame & "Release", $frame)
        EndIf
    EndIf
EndFunc   ;==>_cveDnnSegmentationModelSegmentTyped

Func _cveDnnSegmentationModelSegmentMat($segmentationModel, $frame, $mask)
    ; cveDnnSegmentationModelSegment using cv::Mat instead of _*Array
    _cveDnnSegmentationModelSegmentTyped($segmentationModel, "Mat", $frame, "Mat", $mask)
EndFunc   ;==>_cveDnnSegmentationModelSegmentMat