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

    Local $bAlgoIsString = IsString($algo)
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

    Local $bWeightsIsString = IsString($weights)
    If $bWeightsIsString Then
        $weights = _cveStringCreateFromStr($weights)
    EndIf

    Local $sWeightsDllType
    If IsDllStruct($weights) Then
        $sWeightsDllType = "struct*"
    Else
        $sWeightsDllType = "ptr"
    EndIf

    Local $bDefinitionIsString = IsString($definition)
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

Func _cveDnnSuperResImplUpsampleTyped($dnnSuperRes, $typeOfImg, $img, $typeOfResult, $result)

    Local $iArrImg, $vectorImg, $iArrImgSize
    Local $bImgIsArray = IsArray($img)
    Local $bImgCreate = IsDllStruct($img) And $typeOfImg == "Scalar"

    If $typeOfImg == Default Then
        $iArrImg = $img
    ElseIf $bImgIsArray Then
        $vectorImg = Call("_VectorOf" & $typeOfImg & "Create")

        $iArrImgSize = UBound($img)
        For $i = 0 To $iArrImgSize - 1
            Call("_VectorOf" & $typeOfImg & "Push", $vectorImg, $img[$i])
        Next

        $iArrImg = Call("_cveInputArrayFromVectorOf" & $typeOfImg, $vectorImg)
    Else
        If $bImgCreate Then
            $img = Call("_cve" & $typeOfImg & "Create", $img)
        EndIf
        $iArrImg = Call("_cveInputArrayFrom" & $typeOfImg, $img)
    EndIf

    Local $oArrResult, $vectorResult, $iArrResultSize
    Local $bResultIsArray = IsArray($result)
    Local $bResultCreate = IsDllStruct($result) And $typeOfResult == "Scalar"

    If $typeOfResult == Default Then
        $oArrResult = $result
    ElseIf $bResultIsArray Then
        $vectorResult = Call("_VectorOf" & $typeOfResult & "Create")

        $iArrResultSize = UBound($result)
        For $i = 0 To $iArrResultSize - 1
            Call("_VectorOf" & $typeOfResult & "Push", $vectorResult, $result[$i])
        Next

        $oArrResult = Call("_cveOutputArrayFromVectorOf" & $typeOfResult, $vectorResult)
    Else
        If $bResultCreate Then
            $result = Call("_cve" & $typeOfResult & "Create", $result)
        EndIf
        $oArrResult = Call("_cveOutputArrayFrom" & $typeOfResult, $result)
    EndIf

    _cveDnnSuperResImplUpsample($dnnSuperRes, $iArrImg, $oArrResult)

    If $bResultIsArray Then
        Call("_VectorOf" & $typeOfResult & "Release", $vectorResult)
    EndIf

    If $typeOfResult <> Default Then
        _cveOutputArrayRelease($oArrResult)
        If $bResultCreate Then
            Call("_cve" & $typeOfResult & "Release", $result)
        EndIf
    EndIf

    If $bImgIsArray Then
        Call("_VectorOf" & $typeOfImg & "Release", $vectorImg)
    EndIf

    If $typeOfImg <> Default Then
        _cveInputArrayRelease($iArrImg)
        If $bImgCreate Then
            Call("_cve" & $typeOfImg & "Release", $img)
        EndIf
    EndIf
EndFunc   ;==>_cveDnnSuperResImplUpsampleTyped

Func _cveDnnSuperResImplUpsampleMat($dnnSuperRes, $img, $result)
    ; cveDnnSuperResImplUpsample using cv::Mat instead of _*Array
    _cveDnnSuperResImplUpsampleTyped($dnnSuperRes, "Mat", $img, "Mat", $result)
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

    Local $bAlgorithmIsString = IsString($algorithm)
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