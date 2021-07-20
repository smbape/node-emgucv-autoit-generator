#include-once
#include "..\..\CVEUtils.au3"

Func _cveStaticSaliencySpectralResidualCreate($static_saliency, $saliency, $algorithm, $sharedPtr)
    ; CVAPI(cv::saliency::StaticSaliencySpectralResidual*) cveStaticSaliencySpectralResidualCreate(cv::saliency::StaticSaliency** static_saliency, cv::saliency::Saliency** saliency, cv::Algorithm** algorithm, cv::Ptr<cv::saliency::StaticSaliencySpectralResidual>** sharedPtr);

    Local $bStatic_saliencyDllType
    If VarGetType($static_saliency) == "DLLStruct" Then
        $bStatic_saliencyDllType = "struct*"
    Else
        $bStatic_saliencyDllType = "ptr*"
    EndIf

    Local $bSaliencyDllType
    If VarGetType($saliency) == "DLLStruct" Then
        $bSaliencyDllType = "struct*"
    Else
        $bSaliencyDllType = "ptr*"
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
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveStaticSaliencySpectralResidualCreate", $bStatic_saliencyDllType, $static_saliency, $bSaliencyDllType, $saliency, $bAlgorithmDllType, $algorithm, $bSharedPtrDllType, $sharedPtr), "cveStaticSaliencySpectralResidualCreate", @error)
EndFunc   ;==>_cveStaticSaliencySpectralResidualCreate

Func _cveStaticSaliencySpectralResidualRelease($saliency, $sharedPtr)
    ; CVAPI(void) cveStaticSaliencySpectralResidualRelease(cv::saliency::StaticSaliencySpectralResidual** saliency, cv::Ptr<cv::saliency::StaticSaliencySpectralResidual>** sharedPtr);

    Local $bSaliencyDllType
    If VarGetType($saliency) == "DLLStruct" Then
        $bSaliencyDllType = "struct*"
    Else
        $bSaliencyDllType = "ptr*"
    EndIf

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveStaticSaliencySpectralResidualRelease", $bSaliencyDllType, $saliency, $bSharedPtrDllType, $sharedPtr), "cveStaticSaliencySpectralResidualRelease", @error)
EndFunc   ;==>_cveStaticSaliencySpectralResidualRelease

Func _cveStaticSaliencyFineGrainedCreate($static_saliency, $saliency, $algorithm, $sharedPtr)
    ; CVAPI(cv::saliency::StaticSaliencyFineGrained*) cveStaticSaliencyFineGrainedCreate(cv::saliency::StaticSaliency** static_saliency, cv::saliency::Saliency** saliency, cv::Algorithm** algorithm, cv::Ptr<cv::saliency::StaticSaliencyFineGrained>** sharedPtr);

    Local $bStatic_saliencyDllType
    If VarGetType($static_saliency) == "DLLStruct" Then
        $bStatic_saliencyDllType = "struct*"
    Else
        $bStatic_saliencyDllType = "ptr*"
    EndIf

    Local $bSaliencyDllType
    If VarGetType($saliency) == "DLLStruct" Then
        $bSaliencyDllType = "struct*"
    Else
        $bSaliencyDllType = "ptr*"
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
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveStaticSaliencyFineGrainedCreate", $bStatic_saliencyDllType, $static_saliency, $bSaliencyDllType, $saliency, $bAlgorithmDllType, $algorithm, $bSharedPtrDllType, $sharedPtr), "cveStaticSaliencyFineGrainedCreate", @error)
EndFunc   ;==>_cveStaticSaliencyFineGrainedCreate

Func _cveStaticSaliencyFineGrainedRelease($saliency, $sharedPtr)
    ; CVAPI(void) cveStaticSaliencyFineGrainedRelease(cv::saliency::StaticSaliencyFineGrained** saliency, cv::Ptr<cv::saliency::StaticSaliencyFineGrained>** sharedPtr);

    Local $bSaliencyDllType
    If VarGetType($saliency) == "DLLStruct" Then
        $bSaliencyDllType = "struct*"
    Else
        $bSaliencyDllType = "ptr*"
    EndIf

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveStaticSaliencyFineGrainedRelease", $bSaliencyDllType, $saliency, $bSharedPtrDllType, $sharedPtr), "cveStaticSaliencyFineGrainedRelease", @error)
EndFunc   ;==>_cveStaticSaliencyFineGrainedRelease

Func _cveMotionSaliencyBinWangApr2014Create($motion_saliency, $saliency, $algorithm, $sharedPtr)
    ; CVAPI(cv::saliency::MotionSaliencyBinWangApr2014*) cveMotionSaliencyBinWangApr2014Create(cv::saliency::MotionSaliency** motion_saliency, cv::saliency::Saliency** saliency, cv::Algorithm** algorithm, cv::Ptr<cv::saliency::MotionSaliencyBinWangApr2014>** sharedPtr);

    Local $bMotion_saliencyDllType
    If VarGetType($motion_saliency) == "DLLStruct" Then
        $bMotion_saliencyDllType = "struct*"
    Else
        $bMotion_saliencyDllType = "ptr*"
    EndIf

    Local $bSaliencyDllType
    If VarGetType($saliency) == "DLLStruct" Then
        $bSaliencyDllType = "struct*"
    Else
        $bSaliencyDllType = "ptr*"
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
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveMotionSaliencyBinWangApr2014Create", $bMotion_saliencyDllType, $motion_saliency, $bSaliencyDllType, $saliency, $bAlgorithmDllType, $algorithm, $bSharedPtrDllType, $sharedPtr), "cveMotionSaliencyBinWangApr2014Create", @error)
EndFunc   ;==>_cveMotionSaliencyBinWangApr2014Create

Func _cveMotionSaliencyBinWangApr2014Release($saliency, $sharedPtr)
    ; CVAPI(void) cveMotionSaliencyBinWangApr2014Release(cv::saliency::MotionSaliencyBinWangApr2014** saliency, cv::Ptr<cv::saliency::MotionSaliencyBinWangApr2014>** sharedPtr);

    Local $bSaliencyDllType
    If VarGetType($saliency) == "DLLStruct" Then
        $bSaliencyDllType = "struct*"
    Else
        $bSaliencyDllType = "ptr*"
    EndIf

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMotionSaliencyBinWangApr2014Release", $bSaliencyDllType, $saliency, $bSharedPtrDllType, $sharedPtr), "cveMotionSaliencyBinWangApr2014Release", @error)
EndFunc   ;==>_cveMotionSaliencyBinWangApr2014Release

Func _cveObjectnessBINGCreate($objectness_saliency, $saliency, $algorithm, $sharedPtr)
    ; CVAPI(cv::saliency::ObjectnessBING*) cveObjectnessBINGCreate(cv::saliency::Objectness** objectness_saliency, cv::saliency::Saliency** saliency, cv::Algorithm** algorithm, cv::Ptr<cv::saliency::ObjectnessBING>** sharedPtr);

    Local $bObjectness_saliencyDllType
    If VarGetType($objectness_saliency) == "DLLStruct" Then
        $bObjectness_saliencyDllType = "struct*"
    Else
        $bObjectness_saliencyDllType = "ptr*"
    EndIf

    Local $bSaliencyDllType
    If VarGetType($saliency) == "DLLStruct" Then
        $bSaliencyDllType = "struct*"
    Else
        $bSaliencyDllType = "ptr*"
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
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveObjectnessBINGCreate", $bObjectness_saliencyDllType, $objectness_saliency, $bSaliencyDllType, $saliency, $bAlgorithmDllType, $algorithm, $bSharedPtrDllType, $sharedPtr), "cveObjectnessBINGCreate", @error)
EndFunc   ;==>_cveObjectnessBINGCreate

Func _cveObjectnessBINGRelease($saliency, $sharedPtr)
    ; CVAPI(void) cveObjectnessBINGRelease(cv::saliency::ObjectnessBING** saliency, cv::Ptr<cv::saliency::ObjectnessBING>** sharedPtr);

    Local $bSaliencyDllType
    If VarGetType($saliency) == "DLLStruct" Then
        $bSaliencyDllType = "struct*"
    Else
        $bSaliencyDllType = "ptr*"
    EndIf

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveObjectnessBINGRelease", $bSaliencyDllType, $saliency, $bSharedPtrDllType, $sharedPtr), "cveObjectnessBINGRelease", @error)
EndFunc   ;==>_cveObjectnessBINGRelease

Func _cveSaliencyComputeSaliency($saliency, $image, $saliencyMap)
    ; CVAPI(bool) cveSaliencyComputeSaliency(cv::saliency::Saliency* saliency, cv::_InputArray* image, cv::_OutputArray* saliencyMap);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveSaliencyComputeSaliency", "ptr", $saliency, "ptr", $image, "ptr", $saliencyMap), "cveSaliencyComputeSaliency", @error)
EndFunc   ;==>_cveSaliencyComputeSaliency

Func _cveSaliencyComputeSaliencyMat($saliency, $matImage, $matSaliencyMap)
    ; cveSaliencyComputeSaliency using cv::Mat instead of _*Array

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

    Local $oArrSaliencyMap, $vectorOfMatSaliencyMap, $iArrSaliencyMapSize
    Local $bSaliencyMapIsArray = VarGetType($matSaliencyMap) == "Array"

    If $bSaliencyMapIsArray Then
        $vectorOfMatSaliencyMap = _VectorOfMatCreate()

        $iArrSaliencyMapSize = UBound($matSaliencyMap)
        For $i = 0 To $iArrSaliencyMapSize - 1
            _VectorOfMatPush($vectorOfMatSaliencyMap, $matSaliencyMap[$i])
        Next

        $oArrSaliencyMap = _cveOutputArrayFromVectorOfMat($vectorOfMatSaliencyMap)
    Else
        $oArrSaliencyMap = _cveOutputArrayFromMat($matSaliencyMap)
    EndIf

    Local $retval = _cveSaliencyComputeSaliency($saliency, $iArrImage, $oArrSaliencyMap)

    If $bSaliencyMapIsArray Then
        _VectorOfMatRelease($vectorOfMatSaliencyMap)
    EndIf

    _cveOutputArrayRelease($oArrSaliencyMap)

    If $bImageIsArray Then
        _VectorOfMatRelease($vectorOfMatImage)
    EndIf

    _cveInputArrayRelease($iArrImage)

    Return $retval
EndFunc   ;==>_cveSaliencyComputeSaliencyMat

Func _cveStaticSaliencyComputeBinaryMap($saliency, $saliencyMap, $binaryMap)
    ; CVAPI(bool) cveStaticSaliencyComputeBinaryMap(cv::saliency::StaticSaliency* saliency, cv::_InputArray* saliencyMap, cv::_OutputArray* binaryMap);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveStaticSaliencyComputeBinaryMap", "ptr", $saliency, "ptr", $saliencyMap, "ptr", $binaryMap), "cveStaticSaliencyComputeBinaryMap", @error)
EndFunc   ;==>_cveStaticSaliencyComputeBinaryMap

Func _cveStaticSaliencyComputeBinaryMapMat($saliency, $matSaliencyMap, $matBinaryMap)
    ; cveStaticSaliencyComputeBinaryMap using cv::Mat instead of _*Array

    Local $iArrSaliencyMap, $vectorOfMatSaliencyMap, $iArrSaliencyMapSize
    Local $bSaliencyMapIsArray = VarGetType($matSaliencyMap) == "Array"

    If $bSaliencyMapIsArray Then
        $vectorOfMatSaliencyMap = _VectorOfMatCreate()

        $iArrSaliencyMapSize = UBound($matSaliencyMap)
        For $i = 0 To $iArrSaliencyMapSize - 1
            _VectorOfMatPush($vectorOfMatSaliencyMap, $matSaliencyMap[$i])
        Next

        $iArrSaliencyMap = _cveInputArrayFromVectorOfMat($vectorOfMatSaliencyMap)
    Else
        $iArrSaliencyMap = _cveInputArrayFromMat($matSaliencyMap)
    EndIf

    Local $oArrBinaryMap, $vectorOfMatBinaryMap, $iArrBinaryMapSize
    Local $bBinaryMapIsArray = VarGetType($matBinaryMap) == "Array"

    If $bBinaryMapIsArray Then
        $vectorOfMatBinaryMap = _VectorOfMatCreate()

        $iArrBinaryMapSize = UBound($matBinaryMap)
        For $i = 0 To $iArrBinaryMapSize - 1
            _VectorOfMatPush($vectorOfMatBinaryMap, $matBinaryMap[$i])
        Next

        $oArrBinaryMap = _cveOutputArrayFromVectorOfMat($vectorOfMatBinaryMap)
    Else
        $oArrBinaryMap = _cveOutputArrayFromMat($matBinaryMap)
    EndIf

    Local $retval = _cveStaticSaliencyComputeBinaryMap($saliency, $iArrSaliencyMap, $oArrBinaryMap)

    If $bBinaryMapIsArray Then
        _VectorOfMatRelease($vectorOfMatBinaryMap)
    EndIf

    _cveOutputArrayRelease($oArrBinaryMap)

    If $bSaliencyMapIsArray Then
        _VectorOfMatRelease($vectorOfMatSaliencyMap)
    EndIf

    _cveInputArrayRelease($iArrSaliencyMap)

    Return $retval
EndFunc   ;==>_cveStaticSaliencyComputeBinaryMapMat

Func _cveSaliencyMotionInit($saliency)
    ; CVAPI(bool) cveSaliencyMotionInit(cv::saliency::Saliency* saliency);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveSaliencyMotionInit", "ptr", $saliency), "cveSaliencyMotionInit", @error)
EndFunc   ;==>_cveSaliencyMotionInit

Func _cveSaliencyMotionSetImageSize($saliency, $width, $height)
    ; CVAPI(void) cveSaliencyMotionSetImageSize(cv::saliency::Saliency* saliency, int width, int height);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSaliencyMotionSetImageSize", "ptr", $saliency, "int", $width, "int", $height), "cveSaliencyMotionSetImageSize", @error)
EndFunc   ;==>_cveSaliencyMotionSetImageSize

Func _cveObjectnessBINGSetTrainingPath($saliency, $trainingPath)
    ; CVAPI(void) cveObjectnessBINGSetTrainingPath(cv::saliency::ObjectnessBING* saliency, cv::String* trainingPath);

    Local $bTrainingPathIsString = VarGetType($trainingPath) == "String"
    If $bTrainingPathIsString Then
        $trainingPath = _cveStringCreateFromStr($trainingPath)
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveObjectnessBINGSetTrainingPath", "ptr", $saliency, "ptr", $trainingPath), "cveObjectnessBINGSetTrainingPath", @error)

    If $bTrainingPathIsString Then
        _cveStringRelease($trainingPath)
    EndIf
EndFunc   ;==>_cveObjectnessBINGSetTrainingPath

Func _cveObjectnessBINGGetObjectnessValues($saliency, $values)
    ; CVAPI(void) cveObjectnessBINGGetObjectnessValues(cv::saliency::ObjectnessBING* saliency, std::vector<float>* values);

    Local $vecValues, $iArrValuesSize
    Local $bValuesIsArray = VarGetType($values) == "Array"

    If $bValuesIsArray Then
        $vecValues = _VectorOfFloatCreate()

        $iArrValuesSize = UBound($values)
        For $i = 0 To $iArrValuesSize - 1
            _VectorOfFloatPush($vecValues, $values[$i])
        Next
    Else
        $vecValues = $values
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveObjectnessBINGGetObjectnessValues", "ptr", $saliency, "ptr", $vecValues), "cveObjectnessBINGGetObjectnessValues", @error)

    If $bValuesIsArray Then
        _VectorOfFloatRelease($vecValues)
    EndIf
EndFunc   ;==>_cveObjectnessBINGGetObjectnessValues