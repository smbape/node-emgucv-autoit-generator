#include-once
#include "..\..\CVEUtils.au3"

Func _cveStaticSaliencySpectralResidualCreate($static_saliency, $saliency, $algorithm, $sharedPtr)
    ; CVAPI(cv::saliency::StaticSaliencySpectralResidual*) cveStaticSaliencySpectralResidualCreate(cv::saliency::StaticSaliency** static_saliency, cv::saliency::Saliency** saliency, cv::Algorithm** algorithm, cv::Ptr<cv::saliency::StaticSaliencySpectralResidual>** sharedPtr);

    Local $sStatic_saliencyDllType
    If IsDllStruct($static_saliency) Then
        $sStatic_saliencyDllType = "struct*"
    ElseIf $static_saliency == Null Then
        $sStatic_saliencyDllType = "ptr"
    Else
        $sStatic_saliencyDllType = "ptr*"
    EndIf

    Local $sSaliencyDllType
    If IsDllStruct($saliency) Then
        $sSaliencyDllType = "struct*"
    ElseIf $saliency == Null Then
        $sSaliencyDllType = "ptr"
    Else
        $sSaliencyDllType = "ptr*"
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
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveStaticSaliencySpectralResidualCreate", $sStatic_saliencyDllType, $static_saliency, $sSaliencyDllType, $saliency, $sAlgorithmDllType, $algorithm, $sSharedPtrDllType, $sharedPtr), "cveStaticSaliencySpectralResidualCreate", @error)
EndFunc   ;==>_cveStaticSaliencySpectralResidualCreate

Func _cveStaticSaliencySpectralResidualRelease($saliency, $sharedPtr)
    ; CVAPI(void) cveStaticSaliencySpectralResidualRelease(cv::saliency::StaticSaliencySpectralResidual** saliency, cv::Ptr<cv::saliency::StaticSaliencySpectralResidual>** sharedPtr);

    Local $sSaliencyDllType
    If IsDllStruct($saliency) Then
        $sSaliencyDllType = "struct*"
    ElseIf $saliency == Null Then
        $sSaliencyDllType = "ptr"
    Else
        $sSaliencyDllType = "ptr*"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveStaticSaliencySpectralResidualRelease", $sSaliencyDllType, $saliency, $sSharedPtrDllType, $sharedPtr), "cveStaticSaliencySpectralResidualRelease", @error)
EndFunc   ;==>_cveStaticSaliencySpectralResidualRelease

Func _cveStaticSaliencyFineGrainedCreate($static_saliency, $saliency, $algorithm, $sharedPtr)
    ; CVAPI(cv::saliency::StaticSaliencyFineGrained*) cveStaticSaliencyFineGrainedCreate(cv::saliency::StaticSaliency** static_saliency, cv::saliency::Saliency** saliency, cv::Algorithm** algorithm, cv::Ptr<cv::saliency::StaticSaliencyFineGrained>** sharedPtr);

    Local $sStatic_saliencyDllType
    If IsDllStruct($static_saliency) Then
        $sStatic_saliencyDllType = "struct*"
    ElseIf $static_saliency == Null Then
        $sStatic_saliencyDllType = "ptr"
    Else
        $sStatic_saliencyDllType = "ptr*"
    EndIf

    Local $sSaliencyDllType
    If IsDllStruct($saliency) Then
        $sSaliencyDllType = "struct*"
    ElseIf $saliency == Null Then
        $sSaliencyDllType = "ptr"
    Else
        $sSaliencyDllType = "ptr*"
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
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveStaticSaliencyFineGrainedCreate", $sStatic_saliencyDllType, $static_saliency, $sSaliencyDllType, $saliency, $sAlgorithmDllType, $algorithm, $sSharedPtrDllType, $sharedPtr), "cveStaticSaliencyFineGrainedCreate", @error)
EndFunc   ;==>_cveStaticSaliencyFineGrainedCreate

Func _cveStaticSaliencyFineGrainedRelease($saliency, $sharedPtr)
    ; CVAPI(void) cveStaticSaliencyFineGrainedRelease(cv::saliency::StaticSaliencyFineGrained** saliency, cv::Ptr<cv::saliency::StaticSaliencyFineGrained>** sharedPtr);

    Local $sSaliencyDllType
    If IsDllStruct($saliency) Then
        $sSaliencyDllType = "struct*"
    ElseIf $saliency == Null Then
        $sSaliencyDllType = "ptr"
    Else
        $sSaliencyDllType = "ptr*"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveStaticSaliencyFineGrainedRelease", $sSaliencyDllType, $saliency, $sSharedPtrDllType, $sharedPtr), "cveStaticSaliencyFineGrainedRelease", @error)
EndFunc   ;==>_cveStaticSaliencyFineGrainedRelease

Func _cveMotionSaliencyBinWangApr2014Create($motion_saliency, $saliency, $algorithm, $sharedPtr)
    ; CVAPI(cv::saliency::MotionSaliencyBinWangApr2014*) cveMotionSaliencyBinWangApr2014Create(cv::saliency::MotionSaliency** motion_saliency, cv::saliency::Saliency** saliency, cv::Algorithm** algorithm, cv::Ptr<cv::saliency::MotionSaliencyBinWangApr2014>** sharedPtr);

    Local $sMotion_saliencyDllType
    If IsDllStruct($motion_saliency) Then
        $sMotion_saliencyDllType = "struct*"
    ElseIf $motion_saliency == Null Then
        $sMotion_saliencyDllType = "ptr"
    Else
        $sMotion_saliencyDllType = "ptr*"
    EndIf

    Local $sSaliencyDllType
    If IsDllStruct($saliency) Then
        $sSaliencyDllType = "struct*"
    ElseIf $saliency == Null Then
        $sSaliencyDllType = "ptr"
    Else
        $sSaliencyDllType = "ptr*"
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
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveMotionSaliencyBinWangApr2014Create", $sMotion_saliencyDllType, $motion_saliency, $sSaliencyDllType, $saliency, $sAlgorithmDllType, $algorithm, $sSharedPtrDllType, $sharedPtr), "cveMotionSaliencyBinWangApr2014Create", @error)
EndFunc   ;==>_cveMotionSaliencyBinWangApr2014Create

Func _cveMotionSaliencyBinWangApr2014Release($saliency, $sharedPtr)
    ; CVAPI(void) cveMotionSaliencyBinWangApr2014Release(cv::saliency::MotionSaliencyBinWangApr2014** saliency, cv::Ptr<cv::saliency::MotionSaliencyBinWangApr2014>** sharedPtr);

    Local $sSaliencyDllType
    If IsDllStruct($saliency) Then
        $sSaliencyDllType = "struct*"
    ElseIf $saliency == Null Then
        $sSaliencyDllType = "ptr"
    Else
        $sSaliencyDllType = "ptr*"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMotionSaliencyBinWangApr2014Release", $sSaliencyDllType, $saliency, $sSharedPtrDllType, $sharedPtr), "cveMotionSaliencyBinWangApr2014Release", @error)
EndFunc   ;==>_cveMotionSaliencyBinWangApr2014Release

Func _cveObjectnessBINGCreate($objectness_saliency, $saliency, $algorithm, $sharedPtr)
    ; CVAPI(cv::saliency::ObjectnessBING*) cveObjectnessBINGCreate(cv::saliency::Objectness** objectness_saliency, cv::saliency::Saliency** saliency, cv::Algorithm** algorithm, cv::Ptr<cv::saliency::ObjectnessBING>** sharedPtr);

    Local $sObjectness_saliencyDllType
    If IsDllStruct($objectness_saliency) Then
        $sObjectness_saliencyDllType = "struct*"
    ElseIf $objectness_saliency == Null Then
        $sObjectness_saliencyDllType = "ptr"
    Else
        $sObjectness_saliencyDllType = "ptr*"
    EndIf

    Local $sSaliencyDllType
    If IsDllStruct($saliency) Then
        $sSaliencyDllType = "struct*"
    ElseIf $saliency == Null Then
        $sSaliencyDllType = "ptr"
    Else
        $sSaliencyDllType = "ptr*"
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
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveObjectnessBINGCreate", $sObjectness_saliencyDllType, $objectness_saliency, $sSaliencyDllType, $saliency, $sAlgorithmDllType, $algorithm, $sSharedPtrDllType, $sharedPtr), "cveObjectnessBINGCreate", @error)
EndFunc   ;==>_cveObjectnessBINGCreate

Func _cveObjectnessBINGRelease($saliency, $sharedPtr)
    ; CVAPI(void) cveObjectnessBINGRelease(cv::saliency::ObjectnessBING** saliency, cv::Ptr<cv::saliency::ObjectnessBING>** sharedPtr);

    Local $sSaliencyDllType
    If IsDllStruct($saliency) Then
        $sSaliencyDllType = "struct*"
    ElseIf $saliency == Null Then
        $sSaliencyDllType = "ptr"
    Else
        $sSaliencyDllType = "ptr*"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveObjectnessBINGRelease", $sSaliencyDllType, $saliency, $sSharedPtrDllType, $sharedPtr), "cveObjectnessBINGRelease", @error)
EndFunc   ;==>_cveObjectnessBINGRelease

Func _cveSaliencyComputeSaliency($saliency, $image, $saliencyMap)
    ; CVAPI(bool) cveSaliencyComputeSaliency(cv::saliency::Saliency* saliency, cv::_InputArray* image, cv::_OutputArray* saliencyMap);

    Local $sSaliencyDllType
    If IsDllStruct($saliency) Then
        $sSaliencyDllType = "struct*"
    Else
        $sSaliencyDllType = "ptr"
    EndIf

    Local $sImageDllType
    If IsDllStruct($image) Then
        $sImageDllType = "struct*"
    Else
        $sImageDllType = "ptr"
    EndIf

    Local $sSaliencyMapDllType
    If IsDllStruct($saliencyMap) Then
        $sSaliencyMapDllType = "struct*"
    Else
        $sSaliencyMapDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveSaliencyComputeSaliency", $sSaliencyDllType, $saliency, $sImageDllType, $image, $sSaliencyMapDllType, $saliencyMap), "cveSaliencyComputeSaliency", @error)
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

    Local $sSaliencyDllType
    If IsDllStruct($saliency) Then
        $sSaliencyDllType = "struct*"
    Else
        $sSaliencyDllType = "ptr"
    EndIf

    Local $sSaliencyMapDllType
    If IsDllStruct($saliencyMap) Then
        $sSaliencyMapDllType = "struct*"
    Else
        $sSaliencyMapDllType = "ptr"
    EndIf

    Local $sBinaryMapDllType
    If IsDllStruct($binaryMap) Then
        $sBinaryMapDllType = "struct*"
    Else
        $sBinaryMapDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveStaticSaliencyComputeBinaryMap", $sSaliencyDllType, $saliency, $sSaliencyMapDllType, $saliencyMap, $sBinaryMapDllType, $binaryMap), "cveStaticSaliencyComputeBinaryMap", @error)
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

    Local $sSaliencyDllType
    If IsDllStruct($saliency) Then
        $sSaliencyDllType = "struct*"
    Else
        $sSaliencyDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveSaliencyMotionInit", $sSaliencyDllType, $saliency), "cveSaliencyMotionInit", @error)
EndFunc   ;==>_cveSaliencyMotionInit

Func _cveSaliencyMotionSetImageSize($saliency, $width, $height)
    ; CVAPI(void) cveSaliencyMotionSetImageSize(cv::saliency::Saliency* saliency, int width, int height);

    Local $sSaliencyDllType
    If IsDllStruct($saliency) Then
        $sSaliencyDllType = "struct*"
    Else
        $sSaliencyDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSaliencyMotionSetImageSize", $sSaliencyDllType, $saliency, "int", $width, "int", $height), "cveSaliencyMotionSetImageSize", @error)
EndFunc   ;==>_cveSaliencyMotionSetImageSize

Func _cveObjectnessBINGSetTrainingPath($saliency, $trainingPath)
    ; CVAPI(void) cveObjectnessBINGSetTrainingPath(cv::saliency::ObjectnessBING* saliency, cv::String* trainingPath);

    Local $sSaliencyDllType
    If IsDllStruct($saliency) Then
        $sSaliencyDllType = "struct*"
    Else
        $sSaliencyDllType = "ptr"
    EndIf

    Local $bTrainingPathIsString = VarGetType($trainingPath) == "String"
    If $bTrainingPathIsString Then
        $trainingPath = _cveStringCreateFromStr($trainingPath)
    EndIf

    Local $sTrainingPathDllType
    If IsDllStruct($trainingPath) Then
        $sTrainingPathDllType = "struct*"
    Else
        $sTrainingPathDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveObjectnessBINGSetTrainingPath", $sSaliencyDllType, $saliency, $sTrainingPathDllType, $trainingPath), "cveObjectnessBINGSetTrainingPath", @error)

    If $bTrainingPathIsString Then
        _cveStringRelease($trainingPath)
    EndIf
EndFunc   ;==>_cveObjectnessBINGSetTrainingPath

Func _cveObjectnessBINGGetObjectnessValues($saliency, $values)
    ; CVAPI(void) cveObjectnessBINGGetObjectnessValues(cv::saliency::ObjectnessBING* saliency, std::vector<float>* values);

    Local $sSaliencyDllType
    If IsDllStruct($saliency) Then
        $sSaliencyDllType = "struct*"
    Else
        $sSaliencyDllType = "ptr"
    EndIf

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

    Local $sValuesDllType
    If IsDllStruct($values) Then
        $sValuesDllType = "struct*"
    Else
        $sValuesDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveObjectnessBINGGetObjectnessValues", $sSaliencyDllType, $saliency, $sValuesDllType, $vecValues), "cveObjectnessBINGGetObjectnessValues", @error)

    If $bValuesIsArray Then
        _VectorOfFloatRelease($vecValues)
    EndIf
EndFunc   ;==>_cveObjectnessBINGGetObjectnessValues