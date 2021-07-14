#include-once
#include "..\..\CVEUtils.au3"

Func _cveRetinaCreate(ByRef $inputSize, $colorMode, $colorSamplingMethod, $useRetinaLogSampling, $reductionFactor, $samplingStrength, ByRef $sharedPtr)
    ; CVAPI(cv::bioinspired::Retina*) cveRetinaCreate(CvSize* inputSize, const bool colorMode, int colorSamplingMethod, const bool useRetinaLogSampling, const double reductionFactor, const double samplingStrength, cv::Ptr<cv::bioinspired::Retina>** sharedPtr);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveRetinaCreate", "struct*", $inputSize, "const bool", $colorMode, "int", $colorSamplingMethod, "const bool", $useRetinaLogSampling, "const double", $reductionFactor, "const double", $samplingStrength, "ptr*", $sharedPtr), "cveRetinaCreate", @error)
EndFunc   ;==>_cveRetinaCreate

Func _cveRetinaRelease(ByRef $sharedPtr)
    ; CVAPI(void) cveRetinaRelease(cv::Ptr<cv::bioinspired::Retina>** sharedPtr);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveRetinaRelease", "ptr*", $sharedPtr), "cveRetinaRelease", @error)
EndFunc   ;==>_cveRetinaRelease

Func _cveRetinaRun(ByRef $retina, ByRef $image)
    ; CVAPI(void) cveRetinaRun(cv::bioinspired::Retina* retina, cv::_InputArray* image);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveRetinaRun", "ptr", $retina, "ptr", $image), "cveRetinaRun", @error)
EndFunc   ;==>_cveRetinaRun

Func _cveRetinaRunMat(ByRef $retina, ByRef $matImage)
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

Func _cveRetinaGetParvo(ByRef $retina, ByRef $parvo)
    ; CVAPI(void) cveRetinaGetParvo(cv::bioinspired::Retina* retina, cv::_OutputArray* parvo);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveRetinaGetParvo", "ptr", $retina, "ptr", $parvo), "cveRetinaGetParvo", @error)
EndFunc   ;==>_cveRetinaGetParvo

Func _cveRetinaGetParvoMat(ByRef $retina, ByRef $matParvo)
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

Func _cveRetinaGetMagno(ByRef $retina, ByRef $magno)
    ; CVAPI(void) cveRetinaGetMagno(cv::bioinspired::Retina* retina, cv::_OutputArray* magno);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveRetinaGetMagno", "ptr", $retina, "ptr", $magno), "cveRetinaGetMagno", @error)
EndFunc   ;==>_cveRetinaGetMagno

Func _cveRetinaGetMagnoMat(ByRef $retina, ByRef $matMagno)
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

Func _cveRetinaClearBuffers(ByRef $retina)
    ; CVAPI(void) cveRetinaClearBuffers(cv::bioinspired::Retina* retina);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveRetinaClearBuffers", "ptr", $retina), "cveRetinaClearBuffers", @error)
EndFunc   ;==>_cveRetinaClearBuffers

Func _cveRetinaGetParameters(ByRef $retina, ByRef $p)
    ; CVAPI(void) cveRetinaGetParameters(cv::bioinspired::Retina* retina, cv::bioinspired::RetinaParameters* p);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveRetinaGetParameters", "ptr", $retina, "ptr", $p), "cveRetinaGetParameters", @error)
EndFunc   ;==>_cveRetinaGetParameters

Func _cveRetinaSetParameters(ByRef $retina, ByRef $p)
    ; CVAPI(void) cveRetinaSetParameters(cv::bioinspired::Retina* retina, cv::bioinspired::RetinaParameters* p);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveRetinaSetParameters", "ptr", $retina, "ptr", $p), "cveRetinaSetParameters", @error)
EndFunc   ;==>_cveRetinaSetParameters

Func _cveRetinaFastToneMappingCreate(ByRef $inputSize, ByRef $sharedPtr)
    ; CVAPI(cv::bioinspired::RetinaFastToneMapping*) cveRetinaFastToneMappingCreate(CvSize* inputSize, cv::Ptr<cv::bioinspired::RetinaFastToneMapping>** sharedPtr);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveRetinaFastToneMappingCreate", "struct*", $inputSize, "ptr*", $sharedPtr), "cveRetinaFastToneMappingCreate", @error)
EndFunc   ;==>_cveRetinaFastToneMappingCreate

Func _cveRetinaFastToneMappingSetup(ByRef $toneMapping, $photoreceptorsNeighborhoodRadius, $ganglioncellsNeighborhoodRadius, $meanLuminanceModulatorK)
    ; CVAPI(void) cveRetinaFastToneMappingSetup(cv::bioinspired::RetinaFastToneMapping* toneMapping, float photoreceptorsNeighborhoodRadius, float ganglioncellsNeighborhoodRadius, float meanLuminanceModulatorK);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveRetinaFastToneMappingSetup", "ptr", $toneMapping, "float", $photoreceptorsNeighborhoodRadius, "float", $ganglioncellsNeighborhoodRadius, "float", $meanLuminanceModulatorK), "cveRetinaFastToneMappingSetup", @error)
EndFunc   ;==>_cveRetinaFastToneMappingSetup

Func _cveRetinaFastToneMappingApplyFastToneMapping(ByRef $toneMapping, ByRef $inputImage, ByRef $outputToneMappedImage)
    ; CVAPI(void) cveRetinaFastToneMappingApplyFastToneMapping(cv::bioinspired::RetinaFastToneMapping* toneMapping, cv::_InputArray* inputImage, cv::_OutputArray* outputToneMappedImage);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveRetinaFastToneMappingApplyFastToneMapping", "ptr", $toneMapping, "ptr", $inputImage, "ptr", $outputToneMappedImage), "cveRetinaFastToneMappingApplyFastToneMapping", @error)
EndFunc   ;==>_cveRetinaFastToneMappingApplyFastToneMapping

Func _cveRetinaFastToneMappingApplyFastToneMappingMat(ByRef $toneMapping, ByRef $matInputImage, ByRef $matOutputToneMappedImage)
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

Func _cveRetinaFastToneMappingRelease(ByRef $sharedPtr)
    ; CVAPI(void) cveRetinaFastToneMappingRelease(cv::Ptr<cv::bioinspired::RetinaFastToneMapping>** sharedPtr);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveRetinaFastToneMappingRelease", "ptr*", $sharedPtr), "cveRetinaFastToneMappingRelease", @error)
EndFunc   ;==>_cveRetinaFastToneMappingRelease