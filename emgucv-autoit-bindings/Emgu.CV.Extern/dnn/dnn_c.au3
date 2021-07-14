#include-once
#include <..\..\CVEUtils.au3>

Func _cveReadNetFromDarknet($cfgFile, $darknetModel)
    ; CVAPI(cv::dnn::Net*) cveReadNetFromDarknet(cv::String* cfgFile, cv::String* darknetModel);

    Local $bCfgFileIsString = VarGetType($cfgFile) == "String"
    If $bCfgFileIsString Then
        $cfgFile = _cveStringCreateFromStr($cfgFile)
    EndIf

    Local $bDarknetModelIsString = VarGetType($darknetModel) == "String"
    If $bDarknetModelIsString Then
        $darknetModel = _cveStringCreateFromStr($darknetModel)
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveReadNetFromDarknet", "ptr", $cfgFile, "ptr", $darknetModel), "cveReadNetFromDarknet", @error)

    If $bDarknetModelIsString Then
        _cveStringRelease($darknetModel)
    EndIf

    If $bCfgFileIsString Then
        _cveStringRelease($cfgFile)
    EndIf

    Return $retval
EndFunc   ;==>_cveReadNetFromDarknet

Func _cveReadNetFromDarknet2($bufferCfg, $lenCfg, $bufferModel, $lenModel)
    ; CVAPI(cv::dnn::Net*) cveReadNetFromDarknet2(const char * bufferCfg, int lenCfg, const char * bufferModel, int lenModel);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveReadNetFromDarknet2", "ptr", $bufferCfg, "int", $lenCfg, "ptr", $bufferModel, "int", $lenModel), "cveReadNetFromDarknet2", @error)
EndFunc   ;==>_cveReadNetFromDarknet2

Func _cveReadNetFromCaffe($prototxt, $caffeModel)
    ; CVAPI(cv::dnn::Net*) cveReadNetFromCaffe(cv::String* prototxt, cv::String* caffeModel);

    Local $bPrototxtIsString = VarGetType($prototxt) == "String"
    If $bPrototxtIsString Then
        $prototxt = _cveStringCreateFromStr($prototxt)
    EndIf

    Local $bCaffeModelIsString = VarGetType($caffeModel) == "String"
    If $bCaffeModelIsString Then
        $caffeModel = _cveStringCreateFromStr($caffeModel)
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveReadNetFromCaffe", "ptr", $prototxt, "ptr", $caffeModel), "cveReadNetFromCaffe", @error)

    If $bCaffeModelIsString Then
        _cveStringRelease($caffeModel)
    EndIf

    If $bPrototxtIsString Then
        _cveStringRelease($prototxt)
    EndIf

    Return $retval
EndFunc   ;==>_cveReadNetFromCaffe

Func _cveReadNetFromCaffe2($bufferProto, $lenProto, $bufferModel, $lenModel)
    ; CVAPI(cv::dnn::Net*) cveReadNetFromCaffe2(const char * bufferProto, int lenProto, const char * bufferModel, int lenModel);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveReadNetFromCaffe2", "ptr", $bufferProto, "int", $lenProto, "ptr", $bufferModel, "int", $lenModel), "cveReadNetFromCaffe2", @error)
EndFunc   ;==>_cveReadNetFromCaffe2

Func _cveReadNetFromTensorflow($model, $config)
    ; CVAPI(cv::dnn::Net*) cveReadNetFromTensorflow(cv::String* model, cv::String* config);

    Local $bModelIsString = VarGetType($model) == "String"
    If $bModelIsString Then
        $model = _cveStringCreateFromStr($model)
    EndIf

    Local $bConfigIsString = VarGetType($config) == "String"
    If $bConfigIsString Then
        $config = _cveStringCreateFromStr($config)
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveReadNetFromTensorflow", "ptr", $model, "ptr", $config), "cveReadNetFromTensorflow", @error)

    If $bConfigIsString Then
        _cveStringRelease($config)
    EndIf

    If $bModelIsString Then
        _cveStringRelease($model)
    EndIf

    Return $retval
EndFunc   ;==>_cveReadNetFromTensorflow

Func _cveReadNetFromTensorflow2($bufferModel, $lenModel, $bufferConfig, $lenConfig)
    ; CVAPI(cv::dnn::Net*) cveReadNetFromTensorflow2(const char * bufferModel, int lenModel, const char * bufferConfig, int lenConfig);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveReadNetFromTensorflow2", "ptr", $bufferModel, "int", $lenModel, "ptr", $bufferConfig, "int", $lenConfig), "cveReadNetFromTensorflow2", @error)
EndFunc   ;==>_cveReadNetFromTensorflow2

Func _cveReadNetFromONNX($onnxFile)
    ; CVAPI(cv::dnn::Net*) cveReadNetFromONNX(cv::String* onnxFile);

    Local $bOnnxFileIsString = VarGetType($onnxFile) == "String"
    If $bOnnxFileIsString Then
        $onnxFile = _cveStringCreateFromStr($onnxFile)
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveReadNetFromONNX", "ptr", $onnxFile), "cveReadNetFromONNX", @error)

    If $bOnnxFileIsString Then
        _cveStringRelease($onnxFile)
    EndIf

    Return $retval
EndFunc   ;==>_cveReadNetFromONNX

Func _cveReadTensorFromONNX($path, ByRef $tensor)
    ; CVAPI(void) cveReadTensorFromONNX(cv::String* path, cv::Mat* tensor);

    Local $bPathIsString = VarGetType($path) == "String"
    If $bPathIsString Then
        $path = _cveStringCreateFromStr($path)
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveReadTensorFromONNX", "ptr", $path, "ptr", $tensor), "cveReadTensorFromONNX", @error)

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

    Local $bConfigIsString = VarGetType($config) == "String"
    If $bConfigIsString Then
        $config = _cveStringCreateFromStr($config)
    EndIf

    Local $bFrameworkIsString = VarGetType($framework) == "String"
    If $bFrameworkIsString Then
        $framework = _cveStringCreateFromStr($framework)
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveReadNet", "ptr", $model, "ptr", $config, "ptr", $framework), "cveReadNet", @error)

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

    Local $bBinIsString = VarGetType($bin) == "String"
    If $bBinIsString Then
        $bin = _cveStringCreateFromStr($bin)
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveReadNetFromModelOptimizer", "ptr", $xml, "ptr", $bin), "cveReadNetFromModelOptimizer", @error)

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

Func _cveDnnNetSetInput(ByRef $net, ByRef $blob, $name, $scalefactor, ByRef $mean)
    ; CVAPI(void) cveDnnNetSetInput(cv::dnn::Net* net, cv::_InputArray* blob, cv::String* name, double scalefactor, CvScalar* mean);

    Local $bNameIsString = VarGetType($name) == "String"
    If $bNameIsString Then
        $name = _cveStringCreateFromStr($name)
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDnnNetSetInput", "ptr", $net, "ptr", $blob, "ptr", $name, "double", $scalefactor, "struct*", $mean), "cveDnnNetSetInput", @error)

    If $bNameIsString Then
        _cveStringRelease($name)
    EndIf
EndFunc   ;==>_cveDnnNetSetInput

Func _cveDnnNetSetInputMat(ByRef $net, ByRef $matBlob, $name, $scalefactor, ByRef $mean)
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

Func _cveDnnNetForward(ByRef $net, $outputName, ByRef $output)
    ; CVAPI(void) cveDnnNetForward(cv::dnn::Net* net, cv::String* outputName, cv::Mat* output);

    Local $bOutputNameIsString = VarGetType($outputName) == "String"
    If $bOutputNameIsString Then
        $outputName = _cveStringCreateFromStr($outputName)
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDnnNetForward", "ptr", $net, "ptr", $outputName, "ptr", $output), "cveDnnNetForward", @error)

    If $bOutputNameIsString Then
        _cveStringRelease($outputName)
    EndIf
EndFunc   ;==>_cveDnnNetForward

Func _cveDnnNetForward2(ByRef $net, ByRef $outputBlobs, $outputName)
    ; CVAPI(void) cveDnnNetForward2(cv::dnn::Net* net, cv::_OutputArray* outputBlobs, cv::String* outputName);

    Local $bOutputNameIsString = VarGetType($outputName) == "String"
    If $bOutputNameIsString Then
        $outputName = _cveStringCreateFromStr($outputName)
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDnnNetForward2", "ptr", $net, "ptr", $outputBlobs, "ptr", $outputName), "cveDnnNetForward2", @error)

    If $bOutputNameIsString Then
        _cveStringRelease($outputName)
    EndIf
EndFunc   ;==>_cveDnnNetForward2

Func _cveDnnNetForward2Mat(ByRef $net, ByRef $matOutputBlobs, $outputName)
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

Func _cveDnnNetForward3(ByRef $net, ByRef $outputBlobs, ByRef $outBlobNames)
    ; CVAPI(void) cveDnnNetForward3(cv::dnn::Net* net, cv::_OutputArray* outputBlobs, std::vector<cv::String>* outBlobNames);

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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDnnNetForward3", "ptr", $net, "ptr", $outputBlobs, "ptr", $vecOutBlobNames), "cveDnnNetForward3", @error)

    If $bOutBlobNamesIsArray Then
        _VectorOfCvStringRelease($vecOutBlobNames)
    EndIf
EndFunc   ;==>_cveDnnNetForward3

Func _cveDnnNetForward3Mat(ByRef $net, ByRef $matOutputBlobs, ByRef $outBlobNames)
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

Func _cveDnnNetRelease(ByRef $net)
    ; CVAPI(void) cveDnnNetRelease(cv::dnn::Net** net);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDnnNetRelease", "ptr*", $net), "cveDnnNetRelease", @error)
EndFunc   ;==>_cveDnnNetRelease

Func _cveDnnNetGetUnconnectedOutLayers(ByRef $net, ByRef $layerIds)
    ; CVAPI(void) cveDnnNetGetUnconnectedOutLayers(cv::dnn::Net* net, std::vector<int>* layerIds);

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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDnnNetGetUnconnectedOutLayers", "ptr", $net, "ptr", $vecLayerIds), "cveDnnNetGetUnconnectedOutLayers", @error)

    If $bLayerIdsIsArray Then
        _VectorOfIntRelease($vecLayerIds)
    EndIf
EndFunc   ;==>_cveDnnNetGetUnconnectedOutLayers

Func _cveDnnNetGetUnconnectedOutLayersNames(ByRef $net, ByRef $layerNames)
    ; CVAPI(void) cveDnnNetGetUnconnectedOutLayersNames(cv::dnn::Net* net, std::vector<cv::String>* layerNames);

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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDnnNetGetUnconnectedOutLayersNames", "ptr", $net, "ptr", $vecLayerNames), "cveDnnNetGetUnconnectedOutLayersNames", @error)

    If $bLayerNamesIsArray Then
        _VectorOfCvStringRelease($vecLayerNames)
    EndIf
EndFunc   ;==>_cveDnnNetGetUnconnectedOutLayersNames

Func _cveDnnNetGetPerfProfile(ByRef $net, ByRef $timings)
    ; CVAPI(int64) cveDnnNetGetPerfProfile(cv::dnn::Net* net, std::vector<double>* timings);

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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "int64:cdecl", "cveDnnNetGetPerfProfile", "ptr", $net, "ptr", $vecTimings), "cveDnnNetGetPerfProfile", @error)

    If $bTimingsIsArray Then
        _VectorOfDoubleRelease($vecTimings)
    EndIf

    Return $retval
EndFunc   ;==>_cveDnnNetGetPerfProfile

Func _cveDnnNetDump(ByRef $net, $string)
    ; CVAPI(void) cveDnnNetDump(cv::dnn::Net* net, cv::String* string);

    Local $bStringIsString = VarGetType($string) == "String"
    If $bStringIsString Then
        $string = _cveStringCreateFromStr($string)
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDnnNetDump", "ptr", $net, "ptr", $string), "cveDnnNetDump", @error)

    If $bStringIsString Then
        _cveStringRelease($string)
    EndIf
EndFunc   ;==>_cveDnnNetDump

Func _cveDnnNetDumpToFile(ByRef $net, $path)
    ; CVAPI(void) cveDnnNetDumpToFile(cv::dnn::Net* net, cv::String* path);

    Local $bPathIsString = VarGetType($path) == "String"
    If $bPathIsString Then
        $path = _cveStringCreateFromStr($path)
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDnnNetDumpToFile", "ptr", $net, "ptr", $path), "cveDnnNetDumpToFile", @error)

    If $bPathIsString Then
        _cveStringRelease($path)
    EndIf
EndFunc   ;==>_cveDnnNetDumpToFile

Func _cveDnnNetGetLayerNames(ByRef $net)
    ; CVAPI(std::vector<cv::String>*) cveDnnNetGetLayerNames(cv::dnn::Net* net);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveDnnNetGetLayerNames", "ptr", $net), "cveDnnNetGetLayerNames", @error)
EndFunc   ;==>_cveDnnNetGetLayerNames

Func _cveDnnGetLayerId(ByRef $net, $layer)
    ; CVAPI(int) cveDnnGetLayerId(cv::dnn::Net* net, cv::String* layer);

    Local $bLayerIsString = VarGetType($layer) == "String"
    If $bLayerIsString Then
        $layer = _cveStringCreateFromStr($layer)
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveDnnGetLayerId", "ptr", $net, "ptr", $layer), "cveDnnGetLayerId", @error)

    If $bLayerIsString Then
        _cveStringRelease($layer)
    EndIf

    Return $retval
EndFunc   ;==>_cveDnnGetLayerId

Func _cveDnnGetLayerByName(ByRef $net, $layerName, ByRef $sharedPtr)
    ; CVAPI(cv::dnn::Layer*) cveDnnGetLayerByName(cv::dnn::Net* net, cv::String* layerName, cv::Ptr<cv::dnn::Layer>** sharedPtr);

    Local $bLayerNameIsString = VarGetType($layerName) == "String"
    If $bLayerNameIsString Then
        $layerName = _cveStringCreateFromStr($layerName)
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveDnnGetLayerByName", "ptr", $net, "ptr", $layerName, "ptr*", $sharedPtr), "cveDnnGetLayerByName", @error)

    If $bLayerNameIsString Then
        _cveStringRelease($layerName)
    EndIf

    Return $retval
EndFunc   ;==>_cveDnnGetLayerByName

Func _cveDnnGetLayerById(ByRef $net, $layerId, ByRef $sharedPtr)
    ; CVAPI(cv::dnn::Layer*) cveDnnGetLayerById(cv::dnn::Net* net, int layerId, cv::Ptr<cv::dnn::Layer>** sharedPtr);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveDnnGetLayerById", "ptr", $net, "int", $layerId, "ptr*", $sharedPtr), "cveDnnGetLayerById", @error)
EndFunc   ;==>_cveDnnGetLayerById

Func _cveDnnLayerRelease(ByRef $layer)
    ; CVAPI(void) cveDnnLayerRelease(cv::Ptr<cv::dnn::Layer>** layer);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDnnLayerRelease", "ptr*", $layer), "cveDnnLayerRelease", @error)
EndFunc   ;==>_cveDnnLayerRelease

Func _cveDnnLayerGetBlobs(ByRef $layer)
    ; CVAPI(std::vector<cv::Mat>*) cveDnnLayerGetBlobs(cv::dnn::Layer* layer);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveDnnLayerGetBlobs", "ptr", $layer), "cveDnnLayerGetBlobs", @error)
EndFunc   ;==>_cveDnnLayerGetBlobs

Func _cveDnnBlobFromImage(ByRef $image, ByRef $blob, $scalefactor, ByRef $size, ByRef $mean, $swapRB, $crop, $ddepth)
    ; CVAPI(void) cveDnnBlobFromImage(cv::_InputArray* image, cv::_OutputArray* blob, double scalefactor, CvSize* size, CvScalar* mean, bool swapRB, bool crop, int ddepth);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDnnBlobFromImage", "ptr", $image, "ptr", $blob, "double", $scalefactor, "struct*", $size, "struct*", $mean, "boolean", $swapRB, "boolean", $crop, "int", $ddepth), "cveDnnBlobFromImage", @error)
EndFunc   ;==>_cveDnnBlobFromImage

Func _cveDnnBlobFromImageMat(ByRef $matImage, ByRef $matBlob, $scalefactor, ByRef $size, ByRef $mean, $swapRB, $crop, $ddepth)
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

Func _cveDnnBlobFromImages(ByRef $images, ByRef $blob, $scalefactor, ByRef $size, ByRef $mean, $swapRB, $crop, $ddepth)
    ; CVAPI(void) cveDnnBlobFromImages(cv::_InputArray* images, cv::_OutputArray* blob, double scalefactor, CvSize* size, CvScalar* mean, bool swapRB, bool crop, int ddepth);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDnnBlobFromImages", "ptr", $images, "ptr", $blob, "double", $scalefactor, "struct*", $size, "struct*", $mean, "boolean", $swapRB, "boolean", $crop, "int", $ddepth), "cveDnnBlobFromImages", @error)
EndFunc   ;==>_cveDnnBlobFromImages

Func _cveDnnBlobFromImagesMat(ByRef $matImages, ByRef $matBlob, $scalefactor, ByRef $size, ByRef $mean, $swapRB, $crop, $ddepth)
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

Func _cveDnnImagesFromBlob(ByRef $blob, ByRef $images)
    ; CVAPI(void) cveDnnImagesFromBlob(cv::Mat* blob, cv::_OutputArray* images);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDnnImagesFromBlob", "ptr", $blob, "ptr", $images), "cveDnnImagesFromBlob", @error)
EndFunc   ;==>_cveDnnImagesFromBlob

Func _cveDnnImagesFromBlobMat(ByRef $blob, ByRef $matImages)
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

    Local $bDstIsString = VarGetType($dst) == "String"
    If $bDstIsString Then
        $dst = _cveStringCreateFromStr($dst)
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDnnShrinkCaffeModel", "ptr", $src, "ptr", $dst), "cveDnnShrinkCaffeModel", @error)

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

    Local $bOutputIsString = VarGetType($output) == "String"
    If $bOutputIsString Then
        $output = _cveStringCreateFromStr($output)
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDnnWriteTextGraph", "ptr", $model, "ptr", $output), "cveDnnWriteTextGraph", @error)

    If $bOutputIsString Then
        _cveStringRelease($output)
    EndIf

    If $bModelIsString Then
        _cveStringRelease($model)
    EndIf
EndFunc   ;==>_cveDnnWriteTextGraph

Func _cveDnnNMSBoxes(ByRef $bboxes, ByRef $scores, $scoreThreshold, $nmsThreshold, ByRef $indices, $eta, $topK)
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDnnNMSBoxes", "ptr", $vecBboxes, "ptr", $vecScores, "float", $scoreThreshold, "float", $nmsThreshold, "ptr", $vecIndices, "float", $eta, "int", $topK), "cveDnnNMSBoxes", @error)

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

Func _cveDnnNMSBoxes2(ByRef $bboxes, ByRef $scores, $scoreThreshold, $nmsThreshold, ByRef $indices, $eta, $topK)
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDnnNMSBoxes2", "ptr", $vecBboxes, "ptr", $vecScores, "float", $scoreThreshold, "float", $nmsThreshold, "ptr", $vecIndices, "float", $eta, "int", $topK), "cveDnnNMSBoxes2", @error)

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

Func _cveDNNGetAvailableBackends(ByRef $backends, ByRef $targets)
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDNNGetAvailableBackends", "ptr", $vecBackends, "ptr", $vecTargets), "cveDNNGetAvailableBackends", @error)

    If $bTargetsIsArray Then
        _VectorOfIntRelease($vecTargets)
    EndIf

    If $bBackendsIsArray Then
        _VectorOfIntRelease($vecBackends)
    EndIf
EndFunc   ;==>_cveDNNGetAvailableBackends

Func _cveDnnTextDetectionModelDbCreate1($model, $config, ByRef $textDetectionModel, ByRef $baseModel)
    ; CVAPI(cv::dnn::TextDetectionModel_DB*) cveDnnTextDetectionModelDbCreate1(cv::String* model, cv::String* config, cv::dnn::TextDetectionModel** textDetectionModel, cv::dnn::Model** baseModel);

    Local $bModelIsString = VarGetType($model) == "String"
    If $bModelIsString Then
        $model = _cveStringCreateFromStr($model)
    EndIf

    Local $bConfigIsString = VarGetType($config) == "String"
    If $bConfigIsString Then
        $config = _cveStringCreateFromStr($config)
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveDnnTextDetectionModelDbCreate1", "ptr", $model, "ptr", $config, "ptr*", $textDetectionModel, "ptr*", $baseModel), "cveDnnTextDetectionModelDbCreate1", @error)

    If $bConfigIsString Then
        _cveStringRelease($config)
    EndIf

    If $bModelIsString Then
        _cveStringRelease($model)
    EndIf

    Return $retval
EndFunc   ;==>_cveDnnTextDetectionModelDbCreate1

Func _cveDnnTextDetectionModelDbCreate2(ByRef $network, ByRef $textDetectionModel, ByRef $baseModel)
    ; CVAPI(cv::dnn::TextDetectionModel_DB*) cveDnnTextDetectionModelDbCreate2(cv::dnn::Net* network, cv::dnn::TextDetectionModel** textDetectionModel, cv::dnn::Model** baseModel);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveDnnTextDetectionModelDbCreate2", "ptr", $network, "ptr*", $textDetectionModel, "ptr*", $baseModel), "cveDnnTextDetectionModelDbCreate2", @error)
EndFunc   ;==>_cveDnnTextDetectionModelDbCreate2

Func _cveDnnTextDetectionModelDbRelease(ByRef $textDetectionModel)
    ; CVAPI(void) cveDnnTextDetectionModelDbRelease(cv::dnn::TextDetectionModel_DB** textDetectionModel);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDnnTextDetectionModelDbRelease", "ptr*", $textDetectionModel), "cveDnnTextDetectionModelDbRelease", @error)
EndFunc   ;==>_cveDnnTextDetectionModelDbRelease

Func _cveDnnTextDetectionModelEastCreate1($model, $config, ByRef $textDetectionModel, ByRef $baseModel)
    ; CVAPI(cv::dnn::TextDetectionModel_EAST*) cveDnnTextDetectionModelEastCreate1(cv::String* model, cv::String* config, cv::dnn::TextDetectionModel** textDetectionModel, cv::dnn::Model** baseModel);

    Local $bModelIsString = VarGetType($model) == "String"
    If $bModelIsString Then
        $model = _cveStringCreateFromStr($model)
    EndIf

    Local $bConfigIsString = VarGetType($config) == "String"
    If $bConfigIsString Then
        $config = _cveStringCreateFromStr($config)
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveDnnTextDetectionModelEastCreate1", "ptr", $model, "ptr", $config, "ptr*", $textDetectionModel, "ptr*", $baseModel), "cveDnnTextDetectionModelEastCreate1", @error)

    If $bConfigIsString Then
        _cveStringRelease($config)
    EndIf

    If $bModelIsString Then
        _cveStringRelease($model)
    EndIf

    Return $retval
EndFunc   ;==>_cveDnnTextDetectionModelEastCreate1

Func _cveDnnTextDetectionModelEastCreate2(ByRef $network, ByRef $textDetectionModel, ByRef $baseModel)
    ; CVAPI(cv::dnn::TextDetectionModel_EAST*) cveDnnTextDetectionModelEastCreate2(cv::dnn::Net* network, cv::dnn::TextDetectionModel** textDetectionModel, cv::dnn::Model** baseModel);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveDnnTextDetectionModelEastCreate2", "ptr", $network, "ptr*", $textDetectionModel, "ptr*", $baseModel), "cveDnnTextDetectionModelEastCreate2", @error)
EndFunc   ;==>_cveDnnTextDetectionModelEastCreate2

Func _cveDnnTextDetectionModelEastRelease(ByRef $textDetectionModel)
    ; CVAPI(void) cveDnnTextDetectionModelEastRelease(cv::dnn::TextDetectionModel_EAST** textDetectionModel);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDnnTextDetectionModelEastRelease", "ptr*", $textDetectionModel), "cveDnnTextDetectionModelEastRelease", @error)
EndFunc   ;==>_cveDnnTextDetectionModelEastRelease

Func _cveDnnTextDetectionModelDetect(ByRef $textDetectionModel, ByRef $frame, ByRef $detections, ByRef $confidences)
    ; CVAPI(void) cveDnnTextDetectionModelDetect(cv::dnn::TextDetectionModel* textDetectionModel, cv::_InputArray* frame, std::vector< std::vector< cv::Point > >* detections, std::vector<float>* confidences);

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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDnnTextDetectionModelDetect", "ptr", $textDetectionModel, "ptr", $frame, "ptr", $vecDetections, "ptr", $vecConfidences), "cveDnnTextDetectionModelDetect", @error)

    If $bConfidencesIsArray Then
        _VectorOfFloatRelease($vecConfidences)
    EndIf

    If $bDetectionsIsArray Then
        _VectorOfVectorOfPointRelease($vecDetections)
    EndIf
EndFunc   ;==>_cveDnnTextDetectionModelDetect

Func _cveDnnTextDetectionModelDetectMat(ByRef $textDetectionModel, ByRef $matFrame, ByRef $detections, ByRef $confidences)
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

Func _cveDnnTextDetectionModelDetectTextRectangles(ByRef $textDetectionModel, ByRef $frame, ByRef $detections, ByRef $confidences)
    ; CVAPI(void) cveDnnTextDetectionModelDetectTextRectangles(cv::dnn::TextDetectionModel* textDetectionModel, cv::_InputArray* frame, std::vector< cv::RotatedRect >* detections, std::vector< float >* confidences);

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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDnnTextDetectionModelDetectTextRectangles", "ptr", $textDetectionModel, "ptr", $frame, "ptr", $vecDetections, "ptr", $vecConfidences), "cveDnnTextDetectionModelDetectTextRectangles", @error)

    If $bConfidencesIsArray Then
        _VectorOfFloatRelease($vecConfidences)
    EndIf

    If $bDetectionsIsArray Then
        _VectorOfRotatedRectRelease($vecDetections)
    EndIf
EndFunc   ;==>_cveDnnTextDetectionModelDetectTextRectangles

Func _cveDnnTextDetectionModelDetectTextRectanglesMat(ByRef $textDetectionModel, ByRef $matFrame, ByRef $detections, ByRef $confidences)
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

Func _cveDnnTextRecognitionModelCreate1($model, $config, ByRef $baseModel)
    ; CVAPI(cv::dnn::TextRecognitionModel*) cveDnnTextRecognitionModelCreate1(cv::String* model, cv::String* config, cv::dnn::Model** baseModel);

    Local $bModelIsString = VarGetType($model) == "String"
    If $bModelIsString Then
        $model = _cveStringCreateFromStr($model)
    EndIf

    Local $bConfigIsString = VarGetType($config) == "String"
    If $bConfigIsString Then
        $config = _cveStringCreateFromStr($config)
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveDnnTextRecognitionModelCreate1", "ptr", $model, "ptr", $config, "ptr*", $baseModel), "cveDnnTextRecognitionModelCreate1", @error)

    If $bConfigIsString Then
        _cveStringRelease($config)
    EndIf

    If $bModelIsString Then
        _cveStringRelease($model)
    EndIf

    Return $retval
EndFunc   ;==>_cveDnnTextRecognitionModelCreate1

Func _cveDnnTextRecognitionModelCreate2(ByRef $network, ByRef $baseModel)
    ; CVAPI(cv::dnn::TextRecognitionModel*) cveDnnTextRecognitionModelCreate2(cv::dnn::Net* network, cv::dnn::Model** baseModel);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveDnnTextRecognitionModelCreate2", "ptr", $network, "ptr*", $baseModel), "cveDnnTextRecognitionModelCreate2", @error)
EndFunc   ;==>_cveDnnTextRecognitionModelCreate2

Func _cveDnnTextRecognitionModelRelease(ByRef $textRecognitionModel)
    ; CVAPI(void) cveDnnTextRecognitionModelRelease(cv::dnn::TextRecognitionModel** textRecognitionModel);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDnnTextRecognitionModelRelease", "ptr*", $textRecognitionModel), "cveDnnTextRecognitionModelRelease", @error)
EndFunc   ;==>_cveDnnTextRecognitionModelRelease

Func _cveDnnTextRecognitionModelSetVocabulary(ByRef $textRecognitionModel, ByRef $vocabulary)
    ; CVAPI(void) cveDnnTextRecognitionModelSetVocabulary(cv::dnn::TextRecognitionModel* textRecognitionModel, std::vector< std::string >* vocabulary);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDnnTextRecognitionModelSetVocabulary", "ptr", $textRecognitionModel, "ptr", $vocabulary), "cveDnnTextRecognitionModelSetVocabulary", @error)
EndFunc   ;==>_cveDnnTextRecognitionModelSetVocabulary

Func _cveDnnTextRecognitionModelGetVocabulary(ByRef $textRecognitionModel, ByRef $vocabulary)
    ; CVAPI(void) cveDnnTextRecognitionModelGetVocabulary(cv::dnn::TextRecognitionModel* textRecognitionModel, std::vector< std::string >* vocabulary);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDnnTextRecognitionModelGetVocabulary", "ptr", $textRecognitionModel, "ptr", $vocabulary), "cveDnnTextRecognitionModelGetVocabulary", @error)
EndFunc   ;==>_cveDnnTextRecognitionModelGetVocabulary

Func _cveDnnTextRecognitionModelRecognize1(ByRef $textRecognitionModel, ByRef $frame, $text)
    ; CVAPI(void) cveDnnTextRecognitionModelRecognize1(cv::dnn::TextRecognitionModel* textRecognitionModel, cv::_InputArray* frame, cv::String* text);

    Local $bTextIsString = VarGetType($text) == "String"
    If $bTextIsString Then
        $text = _cveStringCreateFromStr($text)
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDnnTextRecognitionModelRecognize1", "ptr", $textRecognitionModel, "ptr", $frame, "ptr", $text), "cveDnnTextRecognitionModelRecognize1", @error)

    If $bTextIsString Then
        _cveStringRelease($text)
    EndIf
EndFunc   ;==>_cveDnnTextRecognitionModelRecognize1

Func _cveDnnTextRecognitionModelRecognize1Mat(ByRef $textRecognitionModel, ByRef $matFrame, $text)
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

Func _cveDnnTextRecognitionModelRecognize2(ByRef $textRecognitionModel, ByRef $frame, ByRef $roiRects, ByRef $results)
    ; CVAPI(void) cveDnnTextRecognitionModelRecognize2(cv::dnn::TextRecognitionModel* textRecognitionModel, cv::_InputArray* frame, cv::_InputArray* roiRects, std::vector< std::string >* results);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDnnTextRecognitionModelRecognize2", "ptr", $textRecognitionModel, "ptr", $frame, "ptr", $roiRects, "ptr", $results), "cveDnnTextRecognitionModelRecognize2", @error)
EndFunc   ;==>_cveDnnTextRecognitionModelRecognize2

Func _cveDnnTextRecognitionModelRecognize2Mat(ByRef $textRecognitionModel, ByRef $matFrame, ByRef $matRoiRects, ByRef $results)
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

    Local $bConfigIsString = VarGetType($config) == "String"
    If $bConfigIsString Then
        $config = _cveStringCreateFromStr($config)
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveModelCreate", "ptr", $model, "ptr", $config), "cveModelCreate", @error)

    If $bConfigIsString Then
        _cveStringRelease($config)
    EndIf

    If $bModelIsString Then
        _cveStringRelease($model)
    EndIf

    Return $retval
EndFunc   ;==>_cveModelCreate

Func _cveModelCreateFromNet(ByRef $network)
    ; CVAPI(cv::dnn::Model*) cveModelCreateFromNet(cv::dnn::Net* network);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveModelCreateFromNet", "ptr", $network), "cveModelCreateFromNet", @error)
EndFunc   ;==>_cveModelCreateFromNet

Func _cveModelRelease(ByRef $model)
    ; CVAPI(void) cveModelRelease(cv::dnn::Model** model);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveModelRelease", "ptr*", $model), "cveModelRelease", @error)
EndFunc   ;==>_cveModelRelease

Func _cveModelPredict(ByRef $model, ByRef $frame, ByRef $outs)
    ; CVAPI(void) cveModelPredict(cv::dnn::Model* model, cv::_InputArray* frame, cv::_OutputArray* outs);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveModelPredict", "ptr", $model, "ptr", $frame, "ptr", $outs), "cveModelPredict", @error)
EndFunc   ;==>_cveModelPredict

Func _cveModelPredictMat(ByRef $model, ByRef $matFrame, ByRef $matOuts)
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

Func _cveModelSetInputMean(ByRef $model, ByRef $mean)
    ; CVAPI(void) cveModelSetInputMean(cv::dnn::Model* model, CvScalar* mean);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveModelSetInputMean", "ptr", $model, "struct*", $mean), "cveModelSetInputMean", @error)
EndFunc   ;==>_cveModelSetInputMean

Func _cveModelSetInputScale(ByRef $model, $value)
    ; CVAPI(void) cveModelSetInputScale(cv::dnn::Model* model, double value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveModelSetInputScale", "ptr", $model, "double", $value), "cveModelSetInputScale", @error)
EndFunc   ;==>_cveModelSetInputScale

Func _cveModelSetInputSize(ByRef $model, ByRef $size)
    ; CVAPI(void) cveModelSetInputSize(cv::dnn::Model* model, CvSize* size);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveModelSetInputSize", "ptr", $model, "struct*", $size), "cveModelSetInputSize", @error)
EndFunc   ;==>_cveModelSetInputSize

Func _cveModelSetInputCrop(ByRef $model, $crop)
    ; CVAPI(void) cveModelSetInputCrop(cv::dnn::Model* model, bool crop);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveModelSetInputCrop", "ptr", $model, "boolean", $crop), "cveModelSetInputCrop", @error)
EndFunc   ;==>_cveModelSetInputCrop

Func _cveModelSetInputSwapRB(ByRef $model, $swapRB)
    ; CVAPI(void) cveModelSetInputSwapRB(cv::dnn::Model* model, bool swapRB);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveModelSetInputSwapRB", "ptr", $model, "boolean", $swapRB), "cveModelSetInputSwapRB", @error)
EndFunc   ;==>_cveModelSetInputSwapRB

Func _cveModelSetPreferableBackend(ByRef $model, $backendId)
    ; CVAPI(void) cveModelSetPreferableBackend(cv::dnn::Model* model, int backendId);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveModelSetPreferableBackend", "ptr", $model, "int", $backendId), "cveModelSetPreferableBackend", @error)
EndFunc   ;==>_cveModelSetPreferableBackend

Func _cveModelSetPreferableTarget(ByRef $model, $targetId)
    ; CVAPI(void) cveModelSetPreferableTarget(cv::dnn::Model* model, int targetId);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveModelSetPreferableTarget", "ptr", $model, "int", $targetId), "cveModelSetPreferableTarget", @error)
EndFunc   ;==>_cveModelSetPreferableTarget

Func _cveDnnDetectionModelCreate1($model, $config, ByRef $baseModel)
    ; CVAPI(cv::dnn::DetectionModel*) cveDnnDetectionModelCreate1(cv::String* model, cv::String* config, cv::dnn::Model** baseModel);

    Local $bModelIsString = VarGetType($model) == "String"
    If $bModelIsString Then
        $model = _cveStringCreateFromStr($model)
    EndIf

    Local $bConfigIsString = VarGetType($config) == "String"
    If $bConfigIsString Then
        $config = _cveStringCreateFromStr($config)
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveDnnDetectionModelCreate1", "ptr", $model, "ptr", $config, "ptr*", $baseModel), "cveDnnDetectionModelCreate1", @error)

    If $bConfigIsString Then
        _cveStringRelease($config)
    EndIf

    If $bModelIsString Then
        _cveStringRelease($model)
    EndIf

    Return $retval
EndFunc   ;==>_cveDnnDetectionModelCreate1

Func _cveDnnDetectionModelCreate2(ByRef $network, ByRef $baseModel)
    ; CVAPI(cv::dnn::DetectionModel*) cveDnnDetectionModelCreate2(cv::dnn::Net* network, cv::dnn::Model** baseModel);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveDnnDetectionModelCreate2", "ptr", $network, "ptr*", $baseModel), "cveDnnDetectionModelCreate2", @error)
EndFunc   ;==>_cveDnnDetectionModelCreate2

Func _cveDnnDetectionModelRelease(ByRef $detectionModel)
    ; CVAPI(void) cveDnnDetectionModelRelease(cv::dnn::DetectionModel** detectionModel);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDnnDetectionModelRelease", "ptr*", $detectionModel), "cveDnnDetectionModelRelease", @error)
EndFunc   ;==>_cveDnnDetectionModelRelease

Func _cveDnnDetectionModelDetect(ByRef $detectionModel, ByRef $frame, ByRef $classIds, ByRef $confidences, ByRef $boxes, $confThreshold, $nmsThreshold)
    ; CVAPI(void) cveDnnDetectionModelDetect(cv::dnn::DetectionModel* detectionModel, cv::_InputArray* frame, std::vector< int >* classIds, std::vector< float >* confidences, std::vector< cv::Rect >* boxes, float confThreshold, float nmsThreshold);

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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDnnDetectionModelDetect", "ptr", $detectionModel, "ptr", $frame, "ptr", $vecClassIds, "ptr", $vecConfidences, "ptr", $vecBoxes, "float", $confThreshold, "float", $nmsThreshold), "cveDnnDetectionModelDetect", @error)

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

Func _cveDnnDetectionModelDetectMat(ByRef $detectionModel, ByRef $matFrame, ByRef $classIds, ByRef $confidences, ByRef $boxes, $confThreshold, $nmsThreshold)
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

Func _cveDnnClassificationModelCreate1($model, $config, ByRef $baseModel)
    ; CVAPI(cv::dnn::ClassificationModel*) cveDnnClassificationModelCreate1(cv::String* model, cv::String* config, cv::dnn::Model** baseModel);

    Local $bModelIsString = VarGetType($model) == "String"
    If $bModelIsString Then
        $model = _cveStringCreateFromStr($model)
    EndIf

    Local $bConfigIsString = VarGetType($config) == "String"
    If $bConfigIsString Then
        $config = _cveStringCreateFromStr($config)
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveDnnClassificationModelCreate1", "ptr", $model, "ptr", $config, "ptr*", $baseModel), "cveDnnClassificationModelCreate1", @error)

    If $bConfigIsString Then
        _cveStringRelease($config)
    EndIf

    If $bModelIsString Then
        _cveStringRelease($model)
    EndIf

    Return $retval
EndFunc   ;==>_cveDnnClassificationModelCreate1

Func _cveDnnClassificationModelCreate2(ByRef $network, ByRef $baseModel)
    ; CVAPI(cv::dnn::ClassificationModel*) cveDnnClassificationModelCreate2(cv::dnn::Net* network, cv::dnn::Model** baseModel);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveDnnClassificationModelCreate2", "ptr", $network, "ptr*", $baseModel), "cveDnnClassificationModelCreate2", @error)
EndFunc   ;==>_cveDnnClassificationModelCreate2

Func _cveDnnClassificationModelRelease(ByRef $classificationModel)
    ; CVAPI(void) cveDnnClassificationModelRelease(cv::dnn::ClassificationModel** classificationModel);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDnnClassificationModelRelease", "ptr*", $classificationModel), "cveDnnClassificationModelRelease", @error)
EndFunc   ;==>_cveDnnClassificationModelRelease

Func _cveDnnClassificationModelClassify(ByRef $classificationModel, ByRef $frame, ByRef $classId, ByRef $conf)
    ; CVAPI(void) cveDnnClassificationModelClassify(cv::dnn::ClassificationModel* classificationModel, cv::_InputArray* frame, int* classId, float* conf);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDnnClassificationModelClassify", "ptr", $classificationModel, "ptr", $frame, "struct*", $classId, "struct*", $conf), "cveDnnClassificationModelClassify", @error)
EndFunc   ;==>_cveDnnClassificationModelClassify

Func _cveDnnClassificationModelClassifyMat(ByRef $classificationModel, ByRef $matFrame, ByRef $classId, ByRef $conf)
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

Func _cveDnnKeypointsModelCreate1($model, $config, ByRef $baseModel)
    ; CVAPI(cv::dnn::KeypointsModel*) cveDnnKeypointsModelCreate1(cv::String* model, cv::String* config, cv::dnn::Model** baseModel);

    Local $bModelIsString = VarGetType($model) == "String"
    If $bModelIsString Then
        $model = _cveStringCreateFromStr($model)
    EndIf

    Local $bConfigIsString = VarGetType($config) == "String"
    If $bConfigIsString Then
        $config = _cveStringCreateFromStr($config)
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveDnnKeypointsModelCreate1", "ptr", $model, "ptr", $config, "ptr*", $baseModel), "cveDnnKeypointsModelCreate1", @error)

    If $bConfigIsString Then
        _cveStringRelease($config)
    EndIf

    If $bModelIsString Then
        _cveStringRelease($model)
    EndIf

    Return $retval
EndFunc   ;==>_cveDnnKeypointsModelCreate1

Func _cveDnnKeypointsModelCreate2(ByRef $network, ByRef $baseModel)
    ; CVAPI(cv::dnn::KeypointsModel*) cveDnnKeypointsModelCreate2(cv::dnn::Net* network, cv::dnn::Model** baseModel);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveDnnKeypointsModelCreate2", "ptr", $network, "ptr*", $baseModel), "cveDnnKeypointsModelCreate2", @error)
EndFunc   ;==>_cveDnnKeypointsModelCreate2

Func _cveDnnKeypointsModelRelease(ByRef $keypointsModel)
    ; CVAPI(void) cveDnnKeypointsModelRelease(cv::dnn::KeypointsModel** keypointsModel);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDnnKeypointsModelRelease", "ptr*", $keypointsModel), "cveDnnKeypointsModelRelease", @error)
EndFunc   ;==>_cveDnnKeypointsModelRelease

Func _cveDnnKeypointsModelEstimate(ByRef $keypointsModel, ByRef $frame, ByRef $keypoints, $thresh)
    ; CVAPI(void) cveDnnKeypointsModelEstimate(cv::dnn::KeypointsModel* keypointsModel, cv::_InputArray* frame, std::vector< cv::Point2f >* keypoints, float thresh);

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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDnnKeypointsModelEstimate", "ptr", $keypointsModel, "ptr", $frame, "ptr", $vecKeypoints, "float", $thresh), "cveDnnKeypointsModelEstimate", @error)

    If $bKeypointsIsArray Then
        _VectorOfPointFRelease($vecKeypoints)
    EndIf
EndFunc   ;==>_cveDnnKeypointsModelEstimate

Func _cveDnnKeypointsModelEstimateMat(ByRef $keypointsModel, ByRef $matFrame, ByRef $keypoints, $thresh)
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

Func _cveDnnSegmentationModelCreate1($model, $config, ByRef $baseModel)
    ; CVAPI(cv::dnn::SegmentationModel*) cveDnnSegmentationModelCreate1(cv::String* model, cv::String* config, cv::dnn::Model** baseModel);

    Local $bModelIsString = VarGetType($model) == "String"
    If $bModelIsString Then
        $model = _cveStringCreateFromStr($model)
    EndIf

    Local $bConfigIsString = VarGetType($config) == "String"
    If $bConfigIsString Then
        $config = _cveStringCreateFromStr($config)
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveDnnSegmentationModelCreate1", "ptr", $model, "ptr", $config, "ptr*", $baseModel), "cveDnnSegmentationModelCreate1", @error)

    If $bConfigIsString Then
        _cveStringRelease($config)
    EndIf

    If $bModelIsString Then
        _cveStringRelease($model)
    EndIf

    Return $retval
EndFunc   ;==>_cveDnnSegmentationModelCreate1

Func _cveDnnSegmentationModelCreate2(ByRef $network, ByRef $baseModel)
    ; CVAPI(cv::dnn::SegmentationModel*) cveDnnSegmentationModelCreate2(cv::dnn::Net* network, cv::dnn::Model** baseModel);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveDnnSegmentationModelCreate2", "ptr", $network, "ptr*", $baseModel), "cveDnnSegmentationModelCreate2", @error)
EndFunc   ;==>_cveDnnSegmentationModelCreate2

Func _cveDnnSegmentationModelRelease(ByRef $segmentationModel)
    ; CVAPI(void) cveDnnSegmentationModelRelease(cv::dnn::SegmentationModel** segmentationModel);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDnnSegmentationModelRelease", "ptr*", $segmentationModel), "cveDnnSegmentationModelRelease", @error)
EndFunc   ;==>_cveDnnSegmentationModelRelease

Func _cveDnnSegmentationModelSegment(ByRef $segmentationModel, ByRef $frame, ByRef $mask)
    ; CVAPI(void) cveDnnSegmentationModelSegment(cv::dnn::SegmentationModel* segmentationModel, cv::_InputArray* frame, cv::_OutputArray* mask);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDnnSegmentationModelSegment", "ptr", $segmentationModel, "ptr", $frame, "ptr", $mask), "cveDnnSegmentationModelSegment", @error)
EndFunc   ;==>_cveDnnSegmentationModelSegment

Func _cveDnnSegmentationModelSegmentMat(ByRef $segmentationModel, ByRef $matFrame, ByRef $matMask)
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