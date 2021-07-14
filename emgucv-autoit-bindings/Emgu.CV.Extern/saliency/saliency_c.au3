#include-once
#include "..\..\CVEUtils.au3"

Func _cveStaticSaliencySpectralResidualCreate(ByRef $static_saliency, ByRef $saliency, ByRef $algorithm, ByRef $sharedPtr)
    ; CVAPI(cv::saliency::StaticSaliencySpectralResidual*) cveStaticSaliencySpectralResidualCreate(cv::saliency::StaticSaliency** static_saliency, cv::saliency::Saliency** saliency, cv::Algorithm** algorithm, cv::Ptr<cv::saliency::StaticSaliencySpectralResidual>** sharedPtr);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveStaticSaliencySpectralResidualCreate", "ptr*", $static_saliency, "ptr*", $saliency, "ptr*", $algorithm, "ptr*", $sharedPtr), "cveStaticSaliencySpectralResidualCreate", @error)
EndFunc   ;==>_cveStaticSaliencySpectralResidualCreate

Func _cveStaticSaliencySpectralResidualRelease(ByRef $saliency, ByRef $sharedPtr)
    ; CVAPI(void) cveStaticSaliencySpectralResidualRelease(cv::saliency::StaticSaliencySpectralResidual** saliency, cv::Ptr<cv::saliency::StaticSaliencySpectralResidual>** sharedPtr);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveStaticSaliencySpectralResidualRelease", "ptr*", $saliency, "ptr*", $sharedPtr), "cveStaticSaliencySpectralResidualRelease", @error)
EndFunc   ;==>_cveStaticSaliencySpectralResidualRelease

Func _cveStaticSaliencyFineGrainedCreate(ByRef $static_saliency, ByRef $saliency, ByRef $algorithm, ByRef $sharedPtr)
    ; CVAPI(cv::saliency::StaticSaliencyFineGrained*) cveStaticSaliencyFineGrainedCreate(cv::saliency::StaticSaliency** static_saliency, cv::saliency::Saliency** saliency, cv::Algorithm** algorithm, cv::Ptr<cv::saliency::StaticSaliencyFineGrained>** sharedPtr);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveStaticSaliencyFineGrainedCreate", "ptr*", $static_saliency, "ptr*", $saliency, "ptr*", $algorithm, "ptr*", $sharedPtr), "cveStaticSaliencyFineGrainedCreate", @error)
EndFunc   ;==>_cveStaticSaliencyFineGrainedCreate

Func _cveStaticSaliencyFineGrainedRelease(ByRef $saliency, ByRef $sharedPtr)
    ; CVAPI(void) cveStaticSaliencyFineGrainedRelease(cv::saliency::StaticSaliencyFineGrained** saliency, cv::Ptr<cv::saliency::StaticSaliencyFineGrained>** sharedPtr);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveStaticSaliencyFineGrainedRelease", "ptr*", $saliency, "ptr*", $sharedPtr), "cveStaticSaliencyFineGrainedRelease", @error)
EndFunc   ;==>_cveStaticSaliencyFineGrainedRelease

Func _cveMotionSaliencyBinWangApr2014Create(ByRef $motion_saliency, ByRef $saliency, ByRef $algorithm, ByRef $sharedPtr)
    ; CVAPI(cv::saliency::MotionSaliencyBinWangApr2014*) cveMotionSaliencyBinWangApr2014Create(cv::saliency::MotionSaliency** motion_saliency, cv::saliency::Saliency** saliency, cv::Algorithm** algorithm, cv::Ptr<cv::saliency::MotionSaliencyBinWangApr2014>** sharedPtr);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveMotionSaliencyBinWangApr2014Create", "ptr*", $motion_saliency, "ptr*", $saliency, "ptr*", $algorithm, "ptr*", $sharedPtr), "cveMotionSaliencyBinWangApr2014Create", @error)
EndFunc   ;==>_cveMotionSaliencyBinWangApr2014Create

Func _cveMotionSaliencyBinWangApr2014Release(ByRef $saliency, ByRef $sharedPtr)
    ; CVAPI(void) cveMotionSaliencyBinWangApr2014Release(cv::saliency::MotionSaliencyBinWangApr2014** saliency, cv::Ptr<cv::saliency::MotionSaliencyBinWangApr2014>** sharedPtr);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMotionSaliencyBinWangApr2014Release", "ptr*", $saliency, "ptr*", $sharedPtr), "cveMotionSaliencyBinWangApr2014Release", @error)
EndFunc   ;==>_cveMotionSaliencyBinWangApr2014Release

Func _cveObjectnessBINGCreate(ByRef $objectness_saliency, ByRef $saliency, ByRef $algorithm, ByRef $sharedPtr)
    ; CVAPI(cv::saliency::ObjectnessBING*) cveObjectnessBINGCreate(cv::saliency::Objectness** objectness_saliency, cv::saliency::Saliency** saliency, cv::Algorithm** algorithm, cv::Ptr<cv::saliency::ObjectnessBING>** sharedPtr);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveObjectnessBINGCreate", "ptr*", $objectness_saliency, "ptr*", $saliency, "ptr*", $algorithm, "ptr*", $sharedPtr), "cveObjectnessBINGCreate", @error)
EndFunc   ;==>_cveObjectnessBINGCreate

Func _cveObjectnessBINGRelease(ByRef $saliency, ByRef $sharedPtr)
    ; CVAPI(void) cveObjectnessBINGRelease(cv::saliency::ObjectnessBING** saliency, cv::Ptr<cv::saliency::ObjectnessBING>** sharedPtr);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveObjectnessBINGRelease", "ptr*", $saliency, "ptr*", $sharedPtr), "cveObjectnessBINGRelease", @error)
EndFunc   ;==>_cveObjectnessBINGRelease

Func _cveSaliencyComputeSaliency(ByRef $saliency, ByRef $image, ByRef $saliencyMap)
    ; CVAPI(bool) cveSaliencyComputeSaliency(cv::saliency::Saliency* saliency, cv::_InputArray* image, cv::_OutputArray* saliencyMap);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveSaliencyComputeSaliency", "ptr", $saliency, "ptr", $image, "ptr", $saliencyMap), "cveSaliencyComputeSaliency", @error)
EndFunc   ;==>_cveSaliencyComputeSaliency

Func _cveSaliencyComputeSaliencyMat(ByRef $saliency, ByRef $matImage, ByRef $matSaliencyMap)
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

Func _cveStaticSaliencyComputeBinaryMap(ByRef $saliency, ByRef $saliencyMap, ByRef $binaryMap)
    ; CVAPI(bool) cveStaticSaliencyComputeBinaryMap(cv::saliency::StaticSaliency* saliency, cv::_InputArray* saliencyMap, cv::_OutputArray* binaryMap);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveStaticSaliencyComputeBinaryMap", "ptr", $saliency, "ptr", $saliencyMap, "ptr", $binaryMap), "cveStaticSaliencyComputeBinaryMap", @error)
EndFunc   ;==>_cveStaticSaliencyComputeBinaryMap

Func _cveStaticSaliencyComputeBinaryMapMat(ByRef $saliency, ByRef $matSaliencyMap, ByRef $matBinaryMap)
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

Func _cveSaliencyMotionInit(ByRef $saliency)
    ; CVAPI(bool) cveSaliencyMotionInit(cv::saliency::Saliency* saliency);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveSaliencyMotionInit", "ptr", $saliency), "cveSaliencyMotionInit", @error)
EndFunc   ;==>_cveSaliencyMotionInit

Func _cveSaliencyMotionSetImageSize(ByRef $saliency, $width, $height)
    ; CVAPI(void) cveSaliencyMotionSetImageSize(cv::saliency::Saliency* saliency, int width, int height);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSaliencyMotionSetImageSize", "ptr", $saliency, "int", $width, "int", $height), "cveSaliencyMotionSetImageSize", @error)
EndFunc   ;==>_cveSaliencyMotionSetImageSize

Func _cveObjectnessBINGSetTrainingPath(ByRef $saliency, $trainingPath)
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

Func _cveObjectnessBINGGetObjectnessValues(ByRef $saliency, ByRef $values)
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