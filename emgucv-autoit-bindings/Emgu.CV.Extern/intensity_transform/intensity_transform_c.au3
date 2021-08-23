#include-once
#include "..\..\CVEUtils.au3"

Func _cveLogTransform($input, $output)
    ; CVAPI(void) cveLogTransform(cv::Mat* input, cv::Mat* output);

    Local $sInputDllType
    If IsDllStruct($input) Then
        $sInputDllType = "struct*"
    Else
        $sInputDllType = "ptr"
    EndIf

    Local $sOutputDllType
    If IsDllStruct($output) Then
        $sOutputDllType = "struct*"
    Else
        $sOutputDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveLogTransform", $sInputDllType, $input, $sOutputDllType, $output), "cveLogTransform", @error)
EndFunc   ;==>_cveLogTransform

Func _cveGammaCorrection($input, $output, $gamma)
    ; CVAPI(void) cveGammaCorrection(cv::Mat* input, cv::Mat* output, float gamma);

    Local $sInputDllType
    If IsDllStruct($input) Then
        $sInputDllType = "struct*"
    Else
        $sInputDllType = "ptr"
    EndIf

    Local $sOutputDllType
    If IsDllStruct($output) Then
        $sOutputDllType = "struct*"
    Else
        $sOutputDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveGammaCorrection", $sInputDllType, $input, $sOutputDllType, $output, "float", $gamma), "cveGammaCorrection", @error)
EndFunc   ;==>_cveGammaCorrection

Func _cveAutoscaling($input, $output)
    ; CVAPI(void) cveAutoscaling(cv::Mat* input, cv::Mat* output);

    Local $sInputDllType
    If IsDllStruct($input) Then
        $sInputDllType = "struct*"
    Else
        $sInputDllType = "ptr"
    EndIf

    Local $sOutputDllType
    If IsDllStruct($output) Then
        $sOutputDllType = "struct*"
    Else
        $sOutputDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveAutoscaling", $sInputDllType, $input, $sOutputDllType, $output), "cveAutoscaling", @error)
EndFunc   ;==>_cveAutoscaling

Func _cveContrastStretching($input, $output, $r1, $s1, $r2, $s2)
    ; CVAPI(void) cveContrastStretching(cv::Mat* input, cv::Mat* output, int r1, int s1, int r2, int s2);

    Local $sInputDllType
    If IsDllStruct($input) Then
        $sInputDllType = "struct*"
    Else
        $sInputDllType = "ptr"
    EndIf

    Local $sOutputDllType
    If IsDllStruct($output) Then
        $sOutputDllType = "struct*"
    Else
        $sOutputDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveContrastStretching", $sInputDllType, $input, $sOutputDllType, $output, "int", $r1, "int", $s1, "int", $r2, "int", $s2), "cveContrastStretching", @error)
EndFunc   ;==>_cveContrastStretching

Func _cveBIMEF($input, $output, $mu = 0.5, $a = -0.3293, $b = 1.1258)
    ; CVAPI(void) cveBIMEF(cv::_InputArray* input, cv::_OutputArray* output, float mu, float a, float b);

    Local $sInputDllType
    If IsDllStruct($input) Then
        $sInputDllType = "struct*"
    Else
        $sInputDllType = "ptr"
    EndIf

    Local $sOutputDllType
    If IsDllStruct($output) Then
        $sOutputDllType = "struct*"
    Else
        $sOutputDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBIMEF", $sInputDllType, $input, $sOutputDllType, $output, "float", $mu, "float", $a, "float", $b), "cveBIMEF", @error)
EndFunc   ;==>_cveBIMEF

Func _cveBIMEFMat($matInput, $matOutput, $mu = 0.5, $a = -0.3293, $b = 1.1258)
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

    Local $sInputDllType
    If IsDllStruct($input) Then
        $sInputDllType = "struct*"
    Else
        $sInputDllType = "ptr"
    EndIf

    Local $sOutputDllType
    If IsDllStruct($output) Then
        $sOutputDllType = "struct*"
    Else
        $sOutputDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBIMEF2", $sInputDllType, $input, $sOutputDllType, $output, "float", $k, "float", $mu, "float", $a, "float", $b), "cveBIMEF2", @error)
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