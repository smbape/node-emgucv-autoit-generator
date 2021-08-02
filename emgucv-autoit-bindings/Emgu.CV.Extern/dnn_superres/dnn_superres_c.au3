#include-once
#include "..\..\CVEUtils.au3"

Func _cveDnnSuperResImplCreate()
    ; CVAPI(cv::dnn_superres::DnnSuperResImpl*) cveDnnSuperResImplCreate();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveDnnSuperResImplCreate"), "cveDnnSuperResImplCreate", @error)
EndFunc   ;==>_cveDnnSuperResImplCreate

Func _cveDnnSuperResImplSetModel($dnnSuperRes, $algo, $scale)
    ; CVAPI(void) cveDnnSuperResImplSetModel(cv::dnn_superres::DnnSuperResImpl* dnnSuperRes, const cv::String* algo, int scale);

    Local $bDnnSuperResDllType
    If VarGetType($dnnSuperRes) == "DLLStruct" Then
        $bDnnSuperResDllType = "struct*"
    Else
        $bDnnSuperResDllType = "ptr"
    EndIf

    Local $bAlgoIsString = VarGetType($algo) == "String"
    If $bAlgoIsString Then
        $algo = _cveStringCreateFromStr($algo)
    EndIf

    Local $bAlgoDllType
    If VarGetType($algo) == "DLLStruct" Then
        $bAlgoDllType = "struct*"
    Else
        $bAlgoDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDnnSuperResImplSetModel", $bDnnSuperResDllType, $dnnSuperRes, $bAlgoDllType, $algo, "int", $scale), "cveDnnSuperResImplSetModel", @error)

    If $bAlgoIsString Then
        _cveStringRelease($algo)
    EndIf
EndFunc   ;==>_cveDnnSuperResImplSetModel

Func _cveDnnSuperResImplReadModel1($dnnSuperRes, $path)
    ; CVAPI(void) cveDnnSuperResImplReadModel1(cv::dnn_superres::DnnSuperResImpl* dnnSuperRes, const cv::String* path);

    Local $bDnnSuperResDllType
    If VarGetType($dnnSuperRes) == "DLLStruct" Then
        $bDnnSuperResDllType = "struct*"
    Else
        $bDnnSuperResDllType = "ptr"
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDnnSuperResImplReadModel1", $bDnnSuperResDllType, $dnnSuperRes, $bPathDllType, $path), "cveDnnSuperResImplReadModel1", @error)

    If $bPathIsString Then
        _cveStringRelease($path)
    EndIf
EndFunc   ;==>_cveDnnSuperResImplReadModel1

Func _cveDnnSuperResImplReadModel2($dnnSuperRes, $weights, $definition)
    ; CVAPI(void) cveDnnSuperResImplReadModel2(cv::dnn_superres::DnnSuperResImpl* dnnSuperRes, const cv::String* weights, cv::String* definition);

    Local $bDnnSuperResDllType
    If VarGetType($dnnSuperRes) == "DLLStruct" Then
        $bDnnSuperResDllType = "struct*"
    Else
        $bDnnSuperResDllType = "ptr"
    EndIf

    Local $bWeightsIsString = VarGetType($weights) == "String"
    If $bWeightsIsString Then
        $weights = _cveStringCreateFromStr($weights)
    EndIf

    Local $bWeightsDllType
    If VarGetType($weights) == "DLLStruct" Then
        $bWeightsDllType = "struct*"
    Else
        $bWeightsDllType = "ptr"
    EndIf

    Local $bDefinitionIsString = VarGetType($definition) == "String"
    If $bDefinitionIsString Then
        $definition = _cveStringCreateFromStr($definition)
    EndIf

    Local $bDefinitionDllType
    If VarGetType($definition) == "DLLStruct" Then
        $bDefinitionDllType = "struct*"
    Else
        $bDefinitionDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDnnSuperResImplReadModel2", $bDnnSuperResDllType, $dnnSuperRes, $bWeightsDllType, $weights, $bDefinitionDllType, $definition), "cveDnnSuperResImplReadModel2", @error)

    If $bDefinitionIsString Then
        _cveStringRelease($definition)
    EndIf

    If $bWeightsIsString Then
        _cveStringRelease($weights)
    EndIf
EndFunc   ;==>_cveDnnSuperResImplReadModel2

Func _cveDnnSuperResImplUpsample($dnnSuperRes, $img, $result)
    ; CVAPI(void) cveDnnSuperResImplUpsample(cv::dnn_superres::DnnSuperResImpl* dnnSuperRes, cv::_InputArray* img, cv::_OutputArray* result);

    Local $bDnnSuperResDllType
    If VarGetType($dnnSuperRes) == "DLLStruct" Then
        $bDnnSuperResDllType = "struct*"
    Else
        $bDnnSuperResDllType = "ptr"
    EndIf

    Local $bImgDllType
    If VarGetType($img) == "DLLStruct" Then
        $bImgDllType = "struct*"
    Else
        $bImgDllType = "ptr"
    EndIf

    Local $bResultDllType
    If VarGetType($result) == "DLLStruct" Then
        $bResultDllType = "struct*"
    Else
        $bResultDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDnnSuperResImplUpsample", $bDnnSuperResDllType, $dnnSuperRes, $bImgDllType, $img, $bResultDllType, $result), "cveDnnSuperResImplUpsample", @error)
EndFunc   ;==>_cveDnnSuperResImplUpsample

Func _cveDnnSuperResImplUpsampleMat($dnnSuperRes, $matImg, $matResult)
    ; cveDnnSuperResImplUpsample using cv::Mat instead of _*Array

    Local $iArrImg, $vectorOfMatImg, $iArrImgSize
    Local $bImgIsArray = VarGetType($matImg) == "Array"

    If $bImgIsArray Then
        $vectorOfMatImg = _VectorOfMatCreate()

        $iArrImgSize = UBound($matImg)
        For $i = 0 To $iArrImgSize - 1
            _VectorOfMatPush($vectorOfMatImg, $matImg[$i])
        Next

        $iArrImg = _cveInputArrayFromVectorOfMat($vectorOfMatImg)
    Else
        $iArrImg = _cveInputArrayFromMat($matImg)
    EndIf

    Local $oArrResult, $vectorOfMatResult, $iArrResultSize
    Local $bResultIsArray = VarGetType($matResult) == "Array"

    If $bResultIsArray Then
        $vectorOfMatResult = _VectorOfMatCreate()

        $iArrResultSize = UBound($matResult)
        For $i = 0 To $iArrResultSize - 1
            _VectorOfMatPush($vectorOfMatResult, $matResult[$i])
        Next

        $oArrResult = _cveOutputArrayFromVectorOfMat($vectorOfMatResult)
    Else
        $oArrResult = _cveOutputArrayFromMat($matResult)
    EndIf

    _cveDnnSuperResImplUpsample($dnnSuperRes, $iArrImg, $oArrResult)

    If $bResultIsArray Then
        _VectorOfMatRelease($vectorOfMatResult)
    EndIf

    _cveOutputArrayRelease($oArrResult)

    If $bImgIsArray Then
        _VectorOfMatRelease($vectorOfMatImg)
    EndIf

    _cveInputArrayRelease($iArrImg)
EndFunc   ;==>_cveDnnSuperResImplUpsampleMat

Func _cveDnnSuperResImplGetScale($dnnSuperRes)
    ; CVAPI(int) cveDnnSuperResImplGetScale(cv::dnn_superres::DnnSuperResImpl* dnnSuperRes);

    Local $bDnnSuperResDllType
    If VarGetType($dnnSuperRes) == "DLLStruct" Then
        $bDnnSuperResDllType = "struct*"
    Else
        $bDnnSuperResDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveDnnSuperResImplGetScale", $bDnnSuperResDllType, $dnnSuperRes), "cveDnnSuperResImplGetScale", @error)
EndFunc   ;==>_cveDnnSuperResImplGetScale

Func _cveDnnSuperResImplGetAlgorithm($dnnSuperRes, $algorithm)
    ; CVAPI(void) cveDnnSuperResImplGetAlgorithm(cv::dnn_superres::DnnSuperResImpl* dnnSuperRes, cv::String* algorithm);

    Local $bDnnSuperResDllType
    If VarGetType($dnnSuperRes) == "DLLStruct" Then
        $bDnnSuperResDllType = "struct*"
    Else
        $bDnnSuperResDllType = "ptr"
    EndIf

    Local $bAlgorithmIsString = VarGetType($algorithm) == "String"
    If $bAlgorithmIsString Then
        $algorithm = _cveStringCreateFromStr($algorithm)
    EndIf

    Local $bAlgorithmDllType
    If VarGetType($algorithm) == "DLLStruct" Then
        $bAlgorithmDllType = "struct*"
    Else
        $bAlgorithmDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDnnSuperResImplGetAlgorithm", $bDnnSuperResDllType, $dnnSuperRes, $bAlgorithmDllType, $algorithm), "cveDnnSuperResImplGetAlgorithm", @error)

    If $bAlgorithmIsString Then
        _cveStringRelease($algorithm)
    EndIf
EndFunc   ;==>_cveDnnSuperResImplGetAlgorithm

Func _cveDnnSuperResImplRelease($dnnSuperRes)
    ; CVAPI(void) cveDnnSuperResImplRelease(cv::dnn_superres::DnnSuperResImpl** dnnSuperRes);

    Local $bDnnSuperResDllType
    If VarGetType($dnnSuperRes) == "DLLStruct" Then
        $bDnnSuperResDllType = "struct*"
    Else
        $bDnnSuperResDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDnnSuperResImplRelease", $bDnnSuperResDllType, $dnnSuperRes), "cveDnnSuperResImplRelease", @error)
EndFunc   ;==>_cveDnnSuperResImplRelease