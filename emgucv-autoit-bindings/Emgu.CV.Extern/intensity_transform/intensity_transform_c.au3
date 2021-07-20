#include-once
#include "..\..\CVEUtils.au3"

Func _cveLogTransform($input, $output)
    ; CVAPI(void) cveLogTransform(cv::Mat* input, cv::Mat* output);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveLogTransform", "ptr", $input, "ptr", $output), "cveLogTransform", @error)
EndFunc   ;==>_cveLogTransform

Func _cveGammaCorrection($input, $output, $gamma)
    ; CVAPI(void) cveGammaCorrection(cv::Mat* input, cv::Mat* output, float gamma);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveGammaCorrection", "ptr", $input, "ptr", $output, "float", $gamma), "cveGammaCorrection", @error)
EndFunc   ;==>_cveGammaCorrection

Func _cveAutoscaling($input, $output)
    ; CVAPI(void) cveAutoscaling(cv::Mat* input, cv::Mat* output);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveAutoscaling", "ptr", $input, "ptr", $output), "cveAutoscaling", @error)
EndFunc   ;==>_cveAutoscaling

Func _cveContrastStretching($input, $output, $r1, $s1, $r2, $s2)
    ; CVAPI(void) cveContrastStretching(cv::Mat* input, cv::Mat* output, int r1, int s1, int r2, int s2);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveContrastStretching", "ptr", $input, "ptr", $output, "int", $r1, "int", $s1, "int", $r2, "int", $s2), "cveContrastStretching", @error)
EndFunc   ;==>_cveContrastStretching

Func _cveBIMEF($input, $output, $mu, $a, $b)
    ; CVAPI(void) cveBIMEF(cv::_InputArray* input, cv::_OutputArray* output, float mu, float a, float b);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBIMEF", "ptr", $input, "ptr", $output, "float", $mu, "float", $a, "float", $b), "cveBIMEF", @error)
EndFunc   ;==>_cveBIMEF

Func _cveBIMEFMat($matInput, $matOutput, $mu, $a, $b)
    ; cveBIMEF using cv::Mat instead of _*Array

    Local $iArrInput, $vectorOfMatInput, $iArrInputSize
    Local $bInputIsArray = VarGetType($matInput) == "Array"

    If $bInputIsArray Then
        $vectorOfMatInput = _VectorOfMatCreate()

        $iArrInputSize = UBound($matInput)
        For $i = 0 To $iArrInputSize - 1
            _VectorOfMatPush($vectorOfMatInput, $matInput[$i])
        Next

        $iArrInput = _cveInputArrayFromVectorOfMat($vectorOfMatInput)
    Else
        $iArrInput = _cveInputArrayFromMat($matInput)
    EndIf

    Local $oArrOutput, $vectorOfMatOutput, $iArrOutputSize
    Local $bOutputIsArray = VarGetType($matOutput) == "Array"

    If $bOutputIsArray Then
        $vectorOfMatOutput = _VectorOfMatCreate()

        $iArrOutputSize = UBound($matOutput)
        For $i = 0 To $iArrOutputSize - 1
            _VectorOfMatPush($vectorOfMatOutput, $matOutput[$i])
        Next

        $oArrOutput = _cveOutputArrayFromVectorOfMat($vectorOfMatOutput)
    Else
        $oArrOutput = _cveOutputArrayFromMat($matOutput)
    EndIf

    _cveBIMEF($iArrInput, $oArrOutput, $mu, $a, $b)

    If $bOutputIsArray Then
        _VectorOfMatRelease($vectorOfMatOutput)
    EndIf

    _cveOutputArrayRelease($oArrOutput)

    If $bInputIsArray Then
        _VectorOfMatRelease($vectorOfMatInput)
    EndIf

    _cveInputArrayRelease($iArrInput)
EndFunc   ;==>_cveBIMEFMat

Func _cveBIMEF2($input, $output, $k, $mu, $a, $b)
    ; CVAPI(void) cveBIMEF2(cv::_InputArray* input, cv::_OutputArray* output, float k, float mu, float a, float b);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBIMEF2", "ptr", $input, "ptr", $output, "float", $k, "float", $mu, "float", $a, "float", $b), "cveBIMEF2", @error)
EndFunc   ;==>_cveBIMEF2

Func _cveBIMEF2Mat($matInput, $matOutput, $k, $mu, $a, $b)
    ; cveBIMEF2 using cv::Mat instead of _*Array

    Local $iArrInput, $vectorOfMatInput, $iArrInputSize
    Local $bInputIsArray = VarGetType($matInput) == "Array"

    If $bInputIsArray Then
        $vectorOfMatInput = _VectorOfMatCreate()

        $iArrInputSize = UBound($matInput)
        For $i = 0 To $iArrInputSize - 1
            _VectorOfMatPush($vectorOfMatInput, $matInput[$i])
        Next

        $iArrInput = _cveInputArrayFromVectorOfMat($vectorOfMatInput)
    Else
        $iArrInput = _cveInputArrayFromMat($matInput)
    EndIf

    Local $oArrOutput, $vectorOfMatOutput, $iArrOutputSize
    Local $bOutputIsArray = VarGetType($matOutput) == "Array"

    If $bOutputIsArray Then
        $vectorOfMatOutput = _VectorOfMatCreate()

        $iArrOutputSize = UBound($matOutput)
        For $i = 0 To $iArrOutputSize - 1
            _VectorOfMatPush($vectorOfMatOutput, $matOutput[$i])
        Next

        $oArrOutput = _cveOutputArrayFromVectorOfMat($vectorOfMatOutput)
    Else
        $oArrOutput = _cveOutputArrayFromMat($matOutput)
    EndIf

    _cveBIMEF2($iArrInput, $oArrOutput, $k, $mu, $a, $b)

    If $bOutputIsArray Then
        _VectorOfMatRelease($vectorOfMatOutput)
    EndIf

    _cveOutputArrayRelease($oArrOutput)

    If $bInputIsArray Then
        _VectorOfMatRelease($vectorOfMatInput)
    EndIf

    _cveInputArrayRelease($iArrInput)
EndFunc   ;==>_cveBIMEF2Mat