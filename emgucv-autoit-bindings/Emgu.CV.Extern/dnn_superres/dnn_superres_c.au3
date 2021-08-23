#include-once
#include "..\..\CVEUtils.au3"

Func _cveDnnSuperResImplCreate()
    ; CVAPI(cv::dnn_superres::DnnSuperResImpl*) cveDnnSuperResImplCreate();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveDnnSuperResImplCreate"), "cveDnnSuperResImplCreate", @error)
EndFunc   ;==>_cveDnnSuperResImplCreate

Func _cveDnnSuperResImplSetModel($dnnSuperRes, $algo, $scale)
    ; CVAPI(void) cveDnnSuperResImplSetModel(cv::dnn_superres::DnnSuperResImpl* dnnSuperRes, const cv::String* algo, int scale);

    Local $sDnnSuperResDllType
    If IsDllStruct($dnnSuperRes) Then
        $sDnnSuperResDllType = "struct*"
    Else
        $sDnnSuperResDllType = "ptr"
    EndIf

    Local $bAlgoIsString = VarGetType($algo) == "String"
    If $bAlgoIsString Then
        $algo = _cveStringCreateFromStr($algo)
    EndIf

    Local $sAlgoDllType
    If IsDllStruct($algo) Then
        $sAlgoDllType = "struct*"
    Else
        $sAlgoDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDnnSuperResImplSetModel", $sDnnSuperResDllType, $dnnSuperRes, $sAlgoDllType, $algo, "int", $scale), "cveDnnSuperResImplSetModel", @error)

    If $bAlgoIsString Then
        _cveStringRelease($algo)
    EndIf
EndFunc   ;==>_cveDnnSuperResImplSetModel

Func _cveDnnSuperResImplReadModel1($dnnSuperRes, $path)
    ; CVAPI(void) cveDnnSuperResImplReadModel1(cv::dnn_superres::DnnSuperResImpl* dnnSuperRes, const cv::String* path);

    Local $sDnnSuperResDllType
    If IsDllStruct($dnnSuperRes) Then
        $sDnnSuperResDllType = "struct*"
    Else
        $sDnnSuperResDllType = "ptr"
    EndIf

    Local $bPathIsString = VarGetType($path) == "String"
    If $bPathIsString Then
        $path = _cveStringCreateFromStr($path)
    EndIf

    Local $sPathDllType
    If IsDllStruct($path) Then
        $sPathDllType = "struct*"
    Else
        $sPathDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDnnSuperResImplReadModel1", $sDnnSuperResDllType, $dnnSuperRes, $sPathDllType, $path), "cveDnnSuperResImplReadModel1", @error)

    If $bPathIsString Then
        _cveStringRelease($path)
    EndIf
EndFunc   ;==>_cveDnnSuperResImplReadModel1

Func _cveDnnSuperResImplReadModel2($dnnSuperRes, $weights, $definition)
    ; CVAPI(void) cveDnnSuperResImplReadModel2(cv::dnn_superres::DnnSuperResImpl* dnnSuperRes, const cv::String* weights, cv::String* definition);

    Local $sDnnSuperResDllType
    If IsDllStruct($dnnSuperRes) Then
        $sDnnSuperResDllType = "struct*"
    Else
        $sDnnSuperResDllType = "ptr"
    EndIf

    Local $bWeightsIsString = VarGetType($weights) == "String"
    If $bWeightsIsString Then
        $weights = _cveStringCreateFromStr($weights)
    EndIf

    Local $sWeightsDllType
    If IsDllStruct($weights) Then
        $sWeightsDllType = "struct*"
    Else
        $sWeightsDllType = "ptr"
    EndIf

    Local $bDefinitionIsString = VarGetType($definition) == "String"
    If $bDefinitionIsString Then
        $definition = _cveStringCreateFromStr($definition)
    EndIf

    Local $sDefinitionDllType
    If IsDllStruct($definition) Then
        $sDefinitionDllType = "struct*"
    Else
        $sDefinitionDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDnnSuperResImplReadModel2", $sDnnSuperResDllType, $dnnSuperRes, $sWeightsDllType, $weights, $sDefinitionDllType, $definition), "cveDnnSuperResImplReadModel2", @error)

    If $bDefinitionIsString Then
        _cveStringRelease($definition)
    EndIf

    If $bWeightsIsString Then
        _cveStringRelease($weights)
    EndIf
EndFunc   ;==>_cveDnnSuperResImplReadModel2

Func _cveDnnSuperResImplUpsample($dnnSuperRes, $img, $result)
    ; CVAPI(void) cveDnnSuperResImplUpsample(cv::dnn_superres::DnnSuperResImpl* dnnSuperRes, cv::_InputArray* img, cv::_OutputArray* result);

    Local $sDnnSuperResDllType
    If IsDllStruct($dnnSuperRes) Then
        $sDnnSuperResDllType = "struct*"
    Else
        $sDnnSuperResDllType = "ptr"
    EndIf

    Local $sImgDllType
    If IsDllStruct($img) Then
        $sImgDllType = "struct*"
    Else
        $sImgDllType = "ptr"
    EndIf

    Local $sResultDllType
    If IsDllStruct($result) Then
        $sResultDllType = "struct*"
    Else
        $sResultDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDnnSuperResImplUpsample", $sDnnSuperResDllType, $dnnSuperRes, $sImgDllType, $img, $sResultDllType, $result), "cveDnnSuperResImplUpsample", @error)
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

    Local $sDnnSuperResDllType
    If IsDllStruct($dnnSuperRes) Then
        $sDnnSuperResDllType = "struct*"
    Else
        $sDnnSuperResDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveDnnSuperResImplGetScale", $sDnnSuperResDllType, $dnnSuperRes), "cveDnnSuperResImplGetScale", @error)
EndFunc   ;==>_cveDnnSuperResImplGetScale

Func _cveDnnSuperResImplGetAlgorithm($dnnSuperRes, $algorithm)
    ; CVAPI(void) cveDnnSuperResImplGetAlgorithm(cv::dnn_superres::DnnSuperResImpl* dnnSuperRes, cv::String* algorithm);

    Local $sDnnSuperResDllType
    If IsDllStruct($dnnSuperRes) Then
        $sDnnSuperResDllType = "struct*"
    Else
        $sDnnSuperResDllType = "ptr"
    EndIf

    Local $bAlgorithmIsString = VarGetType($algorithm) == "String"
    If $bAlgorithmIsString Then
        $algorithm = _cveStringCreateFromStr($algorithm)
    EndIf

    Local $sAlgorithmDllType
    If IsDllStruct($algorithm) Then
        $sAlgorithmDllType = "struct*"
    Else
        $sAlgorithmDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDnnSuperResImplGetAlgorithm", $sDnnSuperResDllType, $dnnSuperRes, $sAlgorithmDllType, $algorithm), "cveDnnSuperResImplGetAlgorithm", @error)

    If $bAlgorithmIsString Then
        _cveStringRelease($algorithm)
    EndIf
EndFunc   ;==>_cveDnnSuperResImplGetAlgorithm

Func _cveDnnSuperResImplRelease($dnnSuperRes)
    ; CVAPI(void) cveDnnSuperResImplRelease(cv::dnn_superres::DnnSuperResImpl** dnnSuperRes);

    Local $sDnnSuperResDllType
    If IsDllStruct($dnnSuperRes) Then
        $sDnnSuperResDllType = "struct*"
    ElseIf $dnnSuperRes == Null Then
        $sDnnSuperResDllType = "ptr"
    Else
        $sDnnSuperResDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDnnSuperResImplRelease", $sDnnSuperResDllType, $dnnSuperRes), "cveDnnSuperResImplRelease", @error)
EndFunc   ;==>_cveDnnSuperResImplRelease