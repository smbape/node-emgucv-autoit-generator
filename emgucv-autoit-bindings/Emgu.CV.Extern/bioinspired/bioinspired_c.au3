#include-once
#include "..\..\CVEUtils.au3"

Func _cveRetinaCreate($inputSize, $colorMode, $colorSamplingMethod, $useRetinaLogSampling, $reductionFactor, $samplingStrength, $sharedPtr)
    ; CVAPI(cv::bioinspired::Retina*) cveRetinaCreate(CvSize* inputSize, const bool colorMode, int colorSamplingMethod, const bool useRetinaLogSampling, const double reductionFactor, const double samplingStrength, cv::Ptr<cv::bioinspired::Retina>** sharedPtr);

    Local $sInputSizeDllType
    If IsDllStruct($inputSize) Then
        $sInputSizeDllType = "struct*"
    Else
        $sInputSizeDllType = "ptr"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveRetinaCreate", $sInputSizeDllType, $inputSize, "bool", $colorMode, "int", $colorSamplingMethod, "bool", $useRetinaLogSampling, "double", $reductionFactor, "double", $samplingStrength, $sSharedPtrDllType, $sharedPtr), "cveRetinaCreate", @error)
EndFunc   ;==>_cveRetinaCreate

Func _cveRetinaRelease($sharedPtr)
    ; CVAPI(void) cveRetinaRelease(cv::Ptr<cv::bioinspired::Retina>** sharedPtr);

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveRetinaRelease", $sSharedPtrDllType, $sharedPtr), "cveRetinaRelease", @error)
EndFunc   ;==>_cveRetinaRelease

Func _cveRetinaRun($retina, $image)
    ; CVAPI(void) cveRetinaRun(cv::bioinspired::Retina* retina, cv::_InputArray* image);

    Local $sRetinaDllType
    If IsDllStruct($retina) Then
        $sRetinaDllType = "struct*"
    Else
        $sRetinaDllType = "ptr"
    EndIf

    Local $sImageDllType
    If IsDllStruct($image) Then
        $sImageDllType = "struct*"
    Else
        $sImageDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveRetinaRun", $sRetinaDllType, $retina, $sImageDllType, $image), "cveRetinaRun", @error)
EndFunc   ;==>_cveRetinaRun

Func _cveRetinaRunTyped($retina, $typeOfImage, $image)

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

    _cveRetinaRun($retina, $iArrImage)

    If $bImageIsArray Then
        Call("_VectorOf" & $typeOfImage & "Release", $vectorImage)
    EndIf

    If $typeOfImage <> Default Then
        _cveInputArrayRelease($iArrImage)
        If $bImageCreate Then
            Call("_cve" & $typeOfImage & "Release", $image)
        EndIf
    EndIf
EndFunc   ;==>_cveRetinaRunTyped

Func _cveRetinaRunMat($retina, $image)
    ; cveRetinaRun using cv::Mat instead of _*Array
    _cveRetinaRunTyped($retina, "Mat", $image)
EndFunc   ;==>_cveRetinaRunMat

Func _cveRetinaGetParvo($retina, $parvo)
    ; CVAPI(void) cveRetinaGetParvo(cv::bioinspired::Retina* retina, cv::_OutputArray* parvo);

    Local $sRetinaDllType
    If IsDllStruct($retina) Then
        $sRetinaDllType = "struct*"
    Else
        $sRetinaDllType = "ptr"
    EndIf

    Local $sParvoDllType
    If IsDllStruct($parvo) Then
        $sParvoDllType = "struct*"
    Else
        $sParvoDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveRetinaGetParvo", $sRetinaDllType, $retina, $sParvoDllType, $parvo), "cveRetinaGetParvo", @error)
EndFunc   ;==>_cveRetinaGetParvo

Func _cveRetinaGetParvoTyped($retina, $typeOfParvo, $parvo)

    Local $oArrParvo, $vectorParvo, $iArrParvoSize
    Local $bParvoIsArray = IsArray($parvo)
    Local $bParvoCreate = IsDllStruct($parvo) And $typeOfParvo == "Scalar"

    If $typeOfParvo == Default Then
        $oArrParvo = $parvo
    ElseIf $bParvoIsArray Then
        $vectorParvo = Call("_VectorOf" & $typeOfParvo & "Create")

        $iArrParvoSize = UBound($parvo)
        For $i = 0 To $iArrParvoSize - 1
            Call("_VectorOf" & $typeOfParvo & "Push", $vectorParvo, $parvo[$i])
        Next

        $oArrParvo = Call("_cveOutputArrayFromVectorOf" & $typeOfParvo, $vectorParvo)
    Else
        If $bParvoCreate Then
            $parvo = Call("_cve" & $typeOfParvo & "Create", $parvo)
        EndIf
        $oArrParvo = Call("_cveOutputArrayFrom" & $typeOfParvo, $parvo)
    EndIf

    _cveRetinaGetParvo($retina, $oArrParvo)

    If $bParvoIsArray Then
        Call("_VectorOf" & $typeOfParvo & "Release", $vectorParvo)
    EndIf

    If $typeOfParvo <> Default Then
        _cveOutputArrayRelease($oArrParvo)
        If $bParvoCreate Then
            Call("_cve" & $typeOfParvo & "Release", $parvo)
        EndIf
    EndIf
EndFunc   ;==>_cveRetinaGetParvoTyped

Func _cveRetinaGetParvoMat($retina, $parvo)
    ; cveRetinaGetParvo using cv::Mat instead of _*Array
    _cveRetinaGetParvoTyped($retina, "Mat", $parvo)
EndFunc   ;==>_cveRetinaGetParvoMat

Func _cveRetinaGetMagno($retina, $magno)
    ; CVAPI(void) cveRetinaGetMagno(cv::bioinspired::Retina* retina, cv::_OutputArray* magno);

    Local $sRetinaDllType
    If IsDllStruct($retina) Then
        $sRetinaDllType = "struct*"
    Else
        $sRetinaDllType = "ptr"
    EndIf

    Local $sMagnoDllType
    If IsDllStruct($magno) Then
        $sMagnoDllType = "struct*"
    Else
        $sMagnoDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveRetinaGetMagno", $sRetinaDllType, $retina, $sMagnoDllType, $magno), "cveRetinaGetMagno", @error)
EndFunc   ;==>_cveRetinaGetMagno

Func _cveRetinaGetMagnoTyped($retina, $typeOfMagno, $magno)

    Local $oArrMagno, $vectorMagno, $iArrMagnoSize
    Local $bMagnoIsArray = IsArray($magno)
    Local $bMagnoCreate = IsDllStruct($magno) And $typeOfMagno == "Scalar"

    If $typeOfMagno == Default Then
        $oArrMagno = $magno
    ElseIf $bMagnoIsArray Then
        $vectorMagno = Call("_VectorOf" & $typeOfMagno & "Create")

        $iArrMagnoSize = UBound($magno)
        For $i = 0 To $iArrMagnoSize - 1
            Call("_VectorOf" & $typeOfMagno & "Push", $vectorMagno, $magno[$i])
        Next

        $oArrMagno = Call("_cveOutputArrayFromVectorOf" & $typeOfMagno, $vectorMagno)
    Else
        If $bMagnoCreate Then
            $magno = Call("_cve" & $typeOfMagno & "Create", $magno)
        EndIf
        $oArrMagno = Call("_cveOutputArrayFrom" & $typeOfMagno, $magno)
    EndIf

    _cveRetinaGetMagno($retina, $oArrMagno)

    If $bMagnoIsArray Then
        Call("_VectorOf" & $typeOfMagno & "Release", $vectorMagno)
    EndIf

    If $typeOfMagno <> Default Then
        _cveOutputArrayRelease($oArrMagno)
        If $bMagnoCreate Then
            Call("_cve" & $typeOfMagno & "Release", $magno)
        EndIf
    EndIf
EndFunc   ;==>_cveRetinaGetMagnoTyped

Func _cveRetinaGetMagnoMat($retina, $magno)
    ; cveRetinaGetMagno using cv::Mat instead of _*Array
    _cveRetinaGetMagnoTyped($retina, "Mat", $magno)
EndFunc   ;==>_cveRetinaGetMagnoMat

Func _cveRetinaClearBuffers($retina)
    ; CVAPI(void) cveRetinaClearBuffers(cv::bioinspired::Retina* retina);

    Local $sRetinaDllType
    If IsDllStruct($retina) Then
        $sRetinaDllType = "struct*"
    Else
        $sRetinaDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveRetinaClearBuffers", $sRetinaDllType, $retina), "cveRetinaClearBuffers", @error)
EndFunc   ;==>_cveRetinaClearBuffers

Func _cveRetinaGetParameters($retina, $p)
    ; CVAPI(void) cveRetinaGetParameters(cv::bioinspired::Retina* retina, cv::bioinspired::RetinaParameters* p);

    Local $sRetinaDllType
    If IsDllStruct($retina) Then
        $sRetinaDllType = "struct*"
    Else
        $sRetinaDllType = "ptr"
    EndIf

    Local $sPDllType
    If IsDllStruct($p) Then
        $sPDllType = "struct*"
    Else
        $sPDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveRetinaGetParameters", $sRetinaDllType, $retina, $sPDllType, $p), "cveRetinaGetParameters", @error)
EndFunc   ;==>_cveRetinaGetParameters

Func _cveRetinaSetParameters($retina, $p)
    ; CVAPI(void) cveRetinaSetParameters(cv::bioinspired::Retina* retina, cv::bioinspired::RetinaParameters* p);

    Local $sRetinaDllType
    If IsDllStruct($retina) Then
        $sRetinaDllType = "struct*"
    Else
        $sRetinaDllType = "ptr"
    EndIf

    Local $sPDllType
    If IsDllStruct($p) Then
        $sPDllType = "struct*"
    Else
        $sPDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveRetinaSetParameters", $sRetinaDllType, $retina, $sPDllType, $p), "cveRetinaSetParameters", @error)
EndFunc   ;==>_cveRetinaSetParameters

Func _cveRetinaFastToneMappingCreate($inputSize, $sharedPtr)
    ; CVAPI(cv::bioinspired::RetinaFastToneMapping*) cveRetinaFastToneMappingCreate(CvSize* inputSize, cv::Ptr<cv::bioinspired::RetinaFastToneMapping>** sharedPtr);

    Local $sInputSizeDllType
    If IsDllStruct($inputSize) Then
        $sInputSizeDllType = "struct*"
    Else
        $sInputSizeDllType = "ptr"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveRetinaFastToneMappingCreate", $sInputSizeDllType, $inputSize, $sSharedPtrDllType, $sharedPtr), "cveRetinaFastToneMappingCreate", @error)
EndFunc   ;==>_cveRetinaFastToneMappingCreate

Func _cveRetinaFastToneMappingSetup($toneMapping, $photoreceptorsNeighborhoodRadius, $ganglioncellsNeighborhoodRadius, $meanLuminanceModulatorK)
    ; CVAPI(void) cveRetinaFastToneMappingSetup(cv::bioinspired::RetinaFastToneMapping* toneMapping, float photoreceptorsNeighborhoodRadius, float ganglioncellsNeighborhoodRadius, float meanLuminanceModulatorK);

    Local $sToneMappingDllType
    If IsDllStruct($toneMapping) Then
        $sToneMappingDllType = "struct*"
    Else
        $sToneMappingDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveRetinaFastToneMappingSetup", $sToneMappingDllType, $toneMapping, "float", $photoreceptorsNeighborhoodRadius, "float", $ganglioncellsNeighborhoodRadius, "float", $meanLuminanceModulatorK), "cveRetinaFastToneMappingSetup", @error)
EndFunc   ;==>_cveRetinaFastToneMappingSetup

Func _cveRetinaFastToneMappingApplyFastToneMapping($toneMapping, $inputImage, $outputToneMappedImage)
    ; CVAPI(void) cveRetinaFastToneMappingApplyFastToneMapping(cv::bioinspired::RetinaFastToneMapping* toneMapping, cv::_InputArray* inputImage, cv::_OutputArray* outputToneMappedImage);

    Local $sToneMappingDllType
    If IsDllStruct($toneMapping) Then
        $sToneMappingDllType = "struct*"
    Else
        $sToneMappingDllType = "ptr"
    EndIf

    Local $sInputImageDllType
    If IsDllStruct($inputImage) Then
        $sInputImageDllType = "struct*"
    Else
        $sInputImageDllType = "ptr"
    EndIf

    Local $sOutputToneMappedImageDllType
    If IsDllStruct($outputToneMappedImage) Then
        $sOutputToneMappedImageDllType = "struct*"
    Else
        $sOutputToneMappedImageDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveRetinaFastToneMappingApplyFastToneMapping", $sToneMappingDllType, $toneMapping, $sInputImageDllType, $inputImage, $sOutputToneMappedImageDllType, $outputToneMappedImage), "cveRetinaFastToneMappingApplyFastToneMapping", @error)
EndFunc   ;==>_cveRetinaFastToneMappingApplyFastToneMapping

Func _cveRetinaFastToneMappingApplyFastToneMappingTyped($toneMapping, $typeOfInputImage, $inputImage, $typeOfOutputToneMappedImage, $outputToneMappedImage)

    Local $iArrInputImage, $vectorInputImage, $iArrInputImageSize
    Local $bInputImageIsArray = IsArray($inputImage)
    Local $bInputImageCreate = IsDllStruct($inputImage) And $typeOfInputImage == "Scalar"

    If $typeOfInputImage == Default Then
        $iArrInputImage = $inputImage
    ElseIf $bInputImageIsArray Then
        $vectorInputImage = Call("_VectorOf" & $typeOfInputImage & "Create")

        $iArrInputImageSize = UBound($inputImage)
        For $i = 0 To $iArrInputImageSize - 1
            Call("_VectorOf" & $typeOfInputImage & "Push", $vectorInputImage, $inputImage[$i])
        Next

        $iArrInputImage = Call("_cveInputArrayFromVectorOf" & $typeOfInputImage, $vectorInputImage)
    Else
        If $bInputImageCreate Then
            $inputImage = Call("_cve" & $typeOfInputImage & "Create", $inputImage)
        EndIf
        $iArrInputImage = Call("_cveInputArrayFrom" & $typeOfInputImage, $inputImage)
    EndIf

    Local $oArrOutputToneMappedImage, $vectorOutputToneMappedImage, $iArrOutputToneMappedImageSize
    Local $bOutputToneMappedImageIsArray = IsArray($outputToneMappedImage)
    Local $bOutputToneMappedImageCreate = IsDllStruct($outputToneMappedImage) And $typeOfOutputToneMappedImage == "Scalar"

    If $typeOfOutputToneMappedImage == Default Then
        $oArrOutputToneMappedImage = $outputToneMappedImage
    ElseIf $bOutputToneMappedImageIsArray Then
        $vectorOutputToneMappedImage = Call("_VectorOf" & $typeOfOutputToneMappedImage & "Create")

        $iArrOutputToneMappedImageSize = UBound($outputToneMappedImage)
        For $i = 0 To $iArrOutputToneMappedImageSize - 1
            Call("_VectorOf" & $typeOfOutputToneMappedImage & "Push", $vectorOutputToneMappedImage, $outputToneMappedImage[$i])
        Next

        $oArrOutputToneMappedImage = Call("_cveOutputArrayFromVectorOf" & $typeOfOutputToneMappedImage, $vectorOutputToneMappedImage)
    Else
        If $bOutputToneMappedImageCreate Then
            $outputToneMappedImage = Call("_cve" & $typeOfOutputToneMappedImage & "Create", $outputToneMappedImage)
        EndIf
        $oArrOutputToneMappedImage = Call("_cveOutputArrayFrom" & $typeOfOutputToneMappedImage, $outputToneMappedImage)
    EndIf

    _cveRetinaFastToneMappingApplyFastToneMapping($toneMapping, $iArrInputImage, $oArrOutputToneMappedImage)

    If $bOutputToneMappedImageIsArray Then
        Call("_VectorOf" & $typeOfOutputToneMappedImage & "Release", $vectorOutputToneMappedImage)
    EndIf

    If $typeOfOutputToneMappedImage <> Default Then
        _cveOutputArrayRelease($oArrOutputToneMappedImage)
        If $bOutputToneMappedImageCreate Then
            Call("_cve" & $typeOfOutputToneMappedImage & "Release", $outputToneMappedImage)
        EndIf
    EndIf

    If $bInputImageIsArray Then
        Call("_VectorOf" & $typeOfInputImage & "Release", $vectorInputImage)
    EndIf

    If $typeOfInputImage <> Default Then
        _cveInputArrayRelease($iArrInputImage)
        If $bInputImageCreate Then
            Call("_cve" & $typeOfInputImage & "Release", $inputImage)
        EndIf
    EndIf
EndFunc   ;==>_cveRetinaFastToneMappingApplyFastToneMappingTyped

Func _cveRetinaFastToneMappingApplyFastToneMappingMat($toneMapping, $inputImage, $outputToneMappedImage)
    ; cveRetinaFastToneMappingApplyFastToneMapping using cv::Mat instead of _*Array
    _cveRetinaFastToneMappingApplyFastToneMappingTyped($toneMapping, "Mat", $inputImage, "Mat", $outputToneMappedImage)
EndFunc   ;==>_cveRetinaFastToneMappingApplyFastToneMappingMat

Func _cveRetinaFastToneMappingRelease($sharedPtr)
    ; CVAPI(void) cveRetinaFastToneMappingRelease(cv::Ptr<cv::bioinspired::RetinaFastToneMapping>** sharedPtr);

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveRetinaFastToneMappingRelease", $sSharedPtrDllType, $sharedPtr), "cveRetinaFastToneMappingRelease", @error)
EndFunc   ;==>_cveRetinaFastToneMappingRelease