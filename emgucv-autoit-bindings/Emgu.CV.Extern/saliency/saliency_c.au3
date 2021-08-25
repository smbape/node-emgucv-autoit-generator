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

Func _cveSaliencyComputeSaliencyTyped($saliency, $typeOfImage, $image, $typeOfSaliencyMap, $saliencyMap)

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

    Local $oArrSaliencyMap, $vectorSaliencyMap, $iArrSaliencyMapSize
    Local $bSaliencyMapIsArray = IsArray($saliencyMap)
    Local $bSaliencyMapCreate = IsDllStruct($saliencyMap) And $typeOfSaliencyMap == "Scalar"

    If $typeOfSaliencyMap == Default Then
        $oArrSaliencyMap = $saliencyMap
    ElseIf $bSaliencyMapIsArray Then
        $vectorSaliencyMap = Call("_VectorOf" & $typeOfSaliencyMap & "Create")

        $iArrSaliencyMapSize = UBound($saliencyMap)
        For $i = 0 To $iArrSaliencyMapSize - 1
            Call("_VectorOf" & $typeOfSaliencyMap & "Push", $vectorSaliencyMap, $saliencyMap[$i])
        Next

        $oArrSaliencyMap = Call("_cveOutputArrayFromVectorOf" & $typeOfSaliencyMap, $vectorSaliencyMap)
    Else
        If $bSaliencyMapCreate Then
            $saliencyMap = Call("_cve" & $typeOfSaliencyMap & "Create", $saliencyMap)
        EndIf
        $oArrSaliencyMap = Call("_cveOutputArrayFrom" & $typeOfSaliencyMap, $saliencyMap)
    EndIf

    Local $retval = _cveSaliencyComputeSaliency($saliency, $iArrImage, $oArrSaliencyMap)

    If $bSaliencyMapIsArray Then
        Call("_VectorOf" & $typeOfSaliencyMap & "Release", $vectorSaliencyMap)
    EndIf

    If $typeOfSaliencyMap <> Default Then
        _cveOutputArrayRelease($oArrSaliencyMap)
        If $bSaliencyMapCreate Then
            Call("_cve" & $typeOfSaliencyMap & "Release", $saliencyMap)
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

    Return $retval
EndFunc   ;==>_cveSaliencyComputeSaliencyTyped

Func _cveSaliencyComputeSaliencyMat($saliency, $image, $saliencyMap)
    ; cveSaliencyComputeSaliency using cv::Mat instead of _*Array
    Local $retval = _cveSaliencyComputeSaliencyTyped($saliency, "Mat", $image, "Mat", $saliencyMap)

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

Func _cveStaticSaliencyComputeBinaryMapTyped($saliency, $typeOfSaliencyMap, $saliencyMap, $typeOfBinaryMap, $binaryMap)

    Local $iArrSaliencyMap, $vectorSaliencyMap, $iArrSaliencyMapSize
    Local $bSaliencyMapIsArray = IsArray($saliencyMap)
    Local $bSaliencyMapCreate = IsDllStruct($saliencyMap) And $typeOfSaliencyMap == "Scalar"

    If $typeOfSaliencyMap == Default Then
        $iArrSaliencyMap = $saliencyMap
    ElseIf $bSaliencyMapIsArray Then
        $vectorSaliencyMap = Call("_VectorOf" & $typeOfSaliencyMap & "Create")

        $iArrSaliencyMapSize = UBound($saliencyMap)
        For $i = 0 To $iArrSaliencyMapSize - 1
            Call("_VectorOf" & $typeOfSaliencyMap & "Push", $vectorSaliencyMap, $saliencyMap[$i])
        Next

        $iArrSaliencyMap = Call("_cveInputArrayFromVectorOf" & $typeOfSaliencyMap, $vectorSaliencyMap)
    Else
        If $bSaliencyMapCreate Then
            $saliencyMap = Call("_cve" & $typeOfSaliencyMap & "Create", $saliencyMap)
        EndIf
        $iArrSaliencyMap = Call("_cveInputArrayFrom" & $typeOfSaliencyMap, $saliencyMap)
    EndIf

    Local $oArrBinaryMap, $vectorBinaryMap, $iArrBinaryMapSize
    Local $bBinaryMapIsArray = IsArray($binaryMap)
    Local $bBinaryMapCreate = IsDllStruct($binaryMap) And $typeOfBinaryMap == "Scalar"

    If $typeOfBinaryMap == Default Then
        $oArrBinaryMap = $binaryMap
    ElseIf $bBinaryMapIsArray Then
        $vectorBinaryMap = Call("_VectorOf" & $typeOfBinaryMap & "Create")

        $iArrBinaryMapSize = UBound($binaryMap)
        For $i = 0 To $iArrBinaryMapSize - 1
            Call("_VectorOf" & $typeOfBinaryMap & "Push", $vectorBinaryMap, $binaryMap[$i])
        Next

        $oArrBinaryMap = Call("_cveOutputArrayFromVectorOf" & $typeOfBinaryMap, $vectorBinaryMap)
    Else
        If $bBinaryMapCreate Then
            $binaryMap = Call("_cve" & $typeOfBinaryMap & "Create", $binaryMap)
        EndIf
        $oArrBinaryMap = Call("_cveOutputArrayFrom" & $typeOfBinaryMap, $binaryMap)
    EndIf

    Local $retval = _cveStaticSaliencyComputeBinaryMap($saliency, $iArrSaliencyMap, $oArrBinaryMap)

    If $bBinaryMapIsArray Then
        Call("_VectorOf" & $typeOfBinaryMap & "Release", $vectorBinaryMap)
    EndIf

    If $typeOfBinaryMap <> Default Then
        _cveOutputArrayRelease($oArrBinaryMap)
        If $bBinaryMapCreate Then
            Call("_cve" & $typeOfBinaryMap & "Release", $binaryMap)
        EndIf
    EndIf

    If $bSaliencyMapIsArray Then
        Call("_VectorOf" & $typeOfSaliencyMap & "Release", $vectorSaliencyMap)
    EndIf

    If $typeOfSaliencyMap <> Default Then
        _cveInputArrayRelease($iArrSaliencyMap)
        If $bSaliencyMapCreate Then
            Call("_cve" & $typeOfSaliencyMap & "Release", $saliencyMap)
        EndIf
    EndIf

    Return $retval
EndFunc   ;==>_cveStaticSaliencyComputeBinaryMapTyped

Func _cveStaticSaliencyComputeBinaryMapMat($saliency, $saliencyMap, $binaryMap)
    ; cveStaticSaliencyComputeBinaryMap using cv::Mat instead of _*Array
    Local $retval = _cveStaticSaliencyComputeBinaryMapTyped($saliency, "Mat", $saliencyMap, "Mat", $binaryMap)

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

    Local $bTrainingPathIsString = IsString($trainingPath)
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
    Local $bValuesIsArray = IsArray($values)

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