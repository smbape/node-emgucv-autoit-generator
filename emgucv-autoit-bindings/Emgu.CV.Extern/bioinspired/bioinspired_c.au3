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

Func _cveRetinaRunMat($retina, $matImage)
    ; cveRetinaRun using cv::Mat instead of _*Array

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

    _cveRetinaRun($retina, $iArrImage)

    If $bImageIsArray Then
        _VectorOfMatRelease($vectorOfMatImage)
    EndIf

    _cveInputArrayRelease($iArrImage)
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

Func _cveRetinaGetParvoMat($retina, $matParvo)
    ; cveRetinaGetParvo using cv::Mat instead of _*Array

    Local $oArrParvo, $vectorOfMatParvo, $iArrParvoSize
    Local $bParvoIsArray = VarGetType($matParvo) == "Array"

    If $bParvoIsArray Then
        $vectorOfMatParvo = _VectorOfMatCreate()

        $iArrParvoSize = UBound($matParvo)
        For $i = 0 To $iArrParvoSize - 1
            _VectorOfMatPush($vectorOfMatParvo, $matParvo[$i])
        Next

        $oArrParvo = _cveOutputArrayFromVectorOfMat($vectorOfMatParvo)
    Else
        $oArrParvo = _cveOutputArrayFromMat($matParvo)
    EndIf

    _cveRetinaGetParvo($retina, $oArrParvo)

    If $bParvoIsArray Then
        _VectorOfMatRelease($vectorOfMatParvo)
    EndIf

    _cveOutputArrayRelease($oArrParvo)
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

Func _cveRetinaGetMagnoMat($retina, $matMagno)
    ; cveRetinaGetMagno using cv::Mat instead of _*Array

    Local $oArrMagno, $vectorOfMatMagno, $iArrMagnoSize
    Local $bMagnoIsArray = VarGetType($matMagno) == "Array"

    If $bMagnoIsArray Then
        $vectorOfMatMagno = _VectorOfMatCreate()

        $iArrMagnoSize = UBound($matMagno)
        For $i = 0 To $iArrMagnoSize - 1
            _VectorOfMatPush($vectorOfMatMagno, $matMagno[$i])
        Next

        $oArrMagno = _cveOutputArrayFromVectorOfMat($vectorOfMatMagno)
    Else
        $oArrMagno = _cveOutputArrayFromMat($matMagno)
    EndIf

    _cveRetinaGetMagno($retina, $oArrMagno)

    If $bMagnoIsArray Then
        _VectorOfMatRelease($vectorOfMatMagno)
    EndIf

    _cveOutputArrayRelease($oArrMagno)
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

Func _cveRetinaFastToneMappingApplyFastToneMappingMat($toneMapping, $matInputImage, $matOutputToneMappedImage)
    ; cveRetinaFastToneMappingApplyFastToneMapping using cv::Mat instead of _*Array

    Local $iArrInputImage, $vectorOfMatInputImage, $iArrInputImageSize
    Local $bInputImageIsArray = VarGetType($matInputImage) == "Array"

    If $bInputImageIsArray Then
        $vectorOfMatInputImage = _VectorOfMatCreate()

        $iArrInputImageSize = UBound($matInputImage)
        For $i = 0 To $iArrInputImageSize - 1
            _VectorOfMatPush($vectorOfMatInputImage, $matInputImage[$i])
        Next

        $iArrInputImage = _cveInputArrayFromVectorOfMat($vectorOfMatInputImage)
    Else
        $iArrInputImage = _cveInputArrayFromMat($matInputImage)
    EndIf

    Local $oArrOutputToneMappedImage, $vectorOfMatOutputToneMappedImage, $iArrOutputToneMappedImageSize
    Local $bOutputToneMappedImageIsArray = VarGetType($matOutputToneMappedImage) == "Array"

    If $bOutputToneMappedImageIsArray Then
        $vectorOfMatOutputToneMappedImage = _VectorOfMatCreate()

        $iArrOutputToneMappedImageSize = UBound($matOutputToneMappedImage)
        For $i = 0 To $iArrOutputToneMappedImageSize - 1
            _VectorOfMatPush($vectorOfMatOutputToneMappedImage, $matOutputToneMappedImage[$i])
        Next

        $oArrOutputToneMappedImage = _cveOutputArrayFromVectorOfMat($vectorOfMatOutputToneMappedImage)
    Else
        $oArrOutputToneMappedImage = _cveOutputArrayFromMat($matOutputToneMappedImage)
    EndIf

    _cveRetinaFastToneMappingApplyFastToneMapping($toneMapping, $iArrInputImage, $oArrOutputToneMappedImage)

    If $bOutputToneMappedImageIsArray Then
        _VectorOfMatRelease($vectorOfMatOutputToneMappedImage)
    EndIf

    _cveOutputArrayRelease($oArrOutputToneMappedImage)

    If $bInputImageIsArray Then
        _VectorOfMatRelease($vectorOfMatInputImage)
    EndIf

    _cveInputArrayRelease($iArrInputImage)
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