#include-once
#include "..\..\CVEUtils.au3"

Func _cveDnnSuperResImplCreate()
    ; CVAPI(cv::dnn_superres::DnnSuperResImpl*) cveDnnSuperResImplCreate();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveDnnSuperResImplCreate"), "cveDnnSuperResImplCreate", @error)
EndFunc   ;==>_cveDnnSuperResImplCreate

Func _cveDnnSuperResImplSetModel(ByRef $dnnSuperRes, $algo, $scale)
    ; CVAPI(void) cveDnnSuperResImplSetModel(cv::dnn_superres::DnnSuperResImpl* dnnSuperRes, const cv::String* algo, int scale);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDnnSuperResImplSetModel", "ptr", $dnnSuperRes, "ptr", $algo, "int", $scale), "cveDnnSuperResImplSetModel", @error)
EndFunc   ;==>_cveDnnSuperResImplSetModel

Func _cveDnnSuperResImplReadModel1(ByRef $dnnSuperRes, $path)
    ; CVAPI(void) cveDnnSuperResImplReadModel1(cv::dnn_superres::DnnSuperResImpl* dnnSuperRes, const cv::String* path);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDnnSuperResImplReadModel1", "ptr", $dnnSuperRes, "ptr", $path), "cveDnnSuperResImplReadModel1", @error)
EndFunc   ;==>_cveDnnSuperResImplReadModel1

Func _cveDnnSuperResImplReadModel2(ByRef $dnnSuperRes, $weights, $definition)
    ; CVAPI(void) cveDnnSuperResImplReadModel2(cv::dnn_superres::DnnSuperResImpl* dnnSuperRes, const cv::String* weights, cv::String* definition);

    Local $bDefinitionIsString = VarGetType($definition) == "String"
    If $bDefinitionIsString Then
        $definition = _cveStringCreateFromStr($definition)
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDnnSuperResImplReadModel2", "ptr", $dnnSuperRes, "ptr", $weights, "ptr", $definition), "cveDnnSuperResImplReadModel2", @error)

    If $bDefinitionIsString Then
        _cveStringRelease($definition)
    EndIf
EndFunc   ;==>_cveDnnSuperResImplReadModel2

Func _cveDnnSuperResImplUpsample(ByRef $dnnSuperRes, ByRef $img, ByRef $result)
    ; CVAPI(void) cveDnnSuperResImplUpsample(cv::dnn_superres::DnnSuperResImpl* dnnSuperRes, cv::_InputArray* img, cv::_OutputArray* result);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDnnSuperResImplUpsample", "ptr", $dnnSuperRes, "ptr", $img, "ptr", $result), "cveDnnSuperResImplUpsample", @error)
EndFunc   ;==>_cveDnnSuperResImplUpsample

Func _cveDnnSuperResImplUpsampleMat(ByRef $dnnSuperRes, ByRef $matImg, ByRef $matResult)
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

Func _cveDnnSuperResImplGetScale(ByRef $dnnSuperRes)
    ; CVAPI(int) cveDnnSuperResImplGetScale(cv::dnn_superres::DnnSuperResImpl* dnnSuperRes);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveDnnSuperResImplGetScale", "ptr", $dnnSuperRes), "cveDnnSuperResImplGetScale", @error)
EndFunc   ;==>_cveDnnSuperResImplGetScale

Func _cveDnnSuperResImplGetAlgorithm(ByRef $dnnSuperRes, $algorithm)
    ; CVAPI(void) cveDnnSuperResImplGetAlgorithm(cv::dnn_superres::DnnSuperResImpl* dnnSuperRes, cv::String* algorithm);

    Local $bAlgorithmIsString = VarGetType($algorithm) == "String"
    If $bAlgorithmIsString Then
        $algorithm = _cveStringCreateFromStr($algorithm)
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDnnSuperResImplGetAlgorithm", "ptr", $dnnSuperRes, "ptr", $algorithm), "cveDnnSuperResImplGetAlgorithm", @error)

    If $bAlgorithmIsString Then
        _cveStringRelease($algorithm)
    EndIf
EndFunc   ;==>_cveDnnSuperResImplGetAlgorithm

Func _cveDnnSuperResImplRelease(ByRef $dnnSuperRes)
    ; CVAPI(void) cveDnnSuperResImplRelease(cv::dnn_superres::DnnSuperResImpl** dnnSuperRes);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDnnSuperResImplRelease", "ptr*", $dnnSuperRes), "cveDnnSuperResImplRelease", @error)
EndFunc   ;==>_cveDnnSuperResImplRelease