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

Func _cveBIMEFTyped($typeOfInput, $input, $typeOfOutput, $output, $mu = 0.5, $a = -0.3293, $b = 1.1258)

    Local $iArrInput, $vectorInput, $iArrInputSize
    Local $bInputIsArray = IsArray($input)
    Local $bInputCreate = IsDllStruct($input) And $typeOfInput == "Scalar"

    If $typeOfInput == Default Then
        $iArrInput = $input
    ElseIf $bInputIsArray Then
        $vectorInput = Call("_VectorOf" & $typeOfInput & "Create")

        $iArrInputSize = UBound($input)
        For $i = 0 To $iArrInputSize - 1
            Call("_VectorOf" & $typeOfInput & "Push", $vectorInput, $input[$i])
        Next

        $iArrInput = Call("_cveInputArrayFromVectorOf" & $typeOfInput, $vectorInput)
    Else
        If $bInputCreate Then
            $input = Call("_cve" & $typeOfInput & "Create", $input)
        EndIf
        $iArrInput = Call("_cveInputArrayFrom" & $typeOfInput, $input)
    EndIf

    Local $oArrOutput, $vectorOutput, $iArrOutputSize
    Local $bOutputIsArray = IsArray($output)
    Local $bOutputCreate = IsDllStruct($output) And $typeOfOutput == "Scalar"

    If $typeOfOutput == Default Then
        $oArrOutput = $output
    ElseIf $bOutputIsArray Then
        $vectorOutput = Call("_VectorOf" & $typeOfOutput & "Create")

        $iArrOutputSize = UBound($output)
        For $i = 0 To $iArrOutputSize - 1
            Call("_VectorOf" & $typeOfOutput & "Push", $vectorOutput, $output[$i])
        Next

        $oArrOutput = Call("_cveOutputArrayFromVectorOf" & $typeOfOutput, $vectorOutput)
    Else
        If $bOutputCreate Then
            $output = Call("_cve" & $typeOfOutput & "Create", $output)
        EndIf
        $oArrOutput = Call("_cveOutputArrayFrom" & $typeOfOutput, $output)
    EndIf

    _cveBIMEF($iArrInput, $oArrOutput, $mu, $a, $b)

    If $bOutputIsArray Then
        Call("_VectorOf" & $typeOfOutput & "Release", $vectorOutput)
    EndIf

    If $typeOfOutput <> Default Then
        _cveOutputArrayRelease($oArrOutput)
        If $bOutputCreate Then
            Call("_cve" & $typeOfOutput & "Release", $output)
        EndIf
    EndIf

    If $bInputIsArray Then
        Call("_VectorOf" & $typeOfInput & "Release", $vectorInput)
    EndIf

    If $typeOfInput <> Default Then
        _cveInputArrayRelease($iArrInput)
        If $bInputCreate Then
            Call("_cve" & $typeOfInput & "Release", $input)
        EndIf
    EndIf
EndFunc   ;==>_cveBIMEFTyped

Func _cveBIMEFMat($input, $output, $mu = 0.5, $a = -0.3293, $b = 1.1258)
    ; cveBIMEF using cv::Mat instead of _*Array
    _cveBIMEFTyped("Mat", $input, "Mat", $output, $mu, $a, $b)
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

Func _cveBIMEF2Typed($typeOfInput, $input, $typeOfOutput, $output, $k, $mu, $a, $b)

    Local $iArrInput, $vectorInput, $iArrInputSize
    Local $bInputIsArray = IsArray($input)
    Local $bInputCreate = IsDllStruct($input) And $typeOfInput == "Scalar"

    If $typeOfInput == Default Then
        $iArrInput = $input
    ElseIf $bInputIsArray Then
        $vectorInput = Call("_VectorOf" & $typeOfInput & "Create")

        $iArrInputSize = UBound($input)
        For $i = 0 To $iArrInputSize - 1
            Call("_VectorOf" & $typeOfInput & "Push", $vectorInput, $input[$i])
        Next

        $iArrInput = Call("_cveInputArrayFromVectorOf" & $typeOfInput, $vectorInput)
    Else
        If $bInputCreate Then
            $input = Call("_cve" & $typeOfInput & "Create", $input)
        EndIf
        $iArrInput = Call("_cveInputArrayFrom" & $typeOfInput, $input)
    EndIf

    Local $oArrOutput, $vectorOutput, $iArrOutputSize
    Local $bOutputIsArray = IsArray($output)
    Local $bOutputCreate = IsDllStruct($output) And $typeOfOutput == "Scalar"

    If $typeOfOutput == Default Then
        $oArrOutput = $output
    ElseIf $bOutputIsArray Then
        $vectorOutput = Call("_VectorOf" & $typeOfOutput & "Create")

        $iArrOutputSize = UBound($output)
        For $i = 0 To $iArrOutputSize - 1
            Call("_VectorOf" & $typeOfOutput & "Push", $vectorOutput, $output[$i])
        Next

        $oArrOutput = Call("_cveOutputArrayFromVectorOf" & $typeOfOutput, $vectorOutput)
    Else
        If $bOutputCreate Then
            $output = Call("_cve" & $typeOfOutput & "Create", $output)
        EndIf
        $oArrOutput = Call("_cveOutputArrayFrom" & $typeOfOutput, $output)
    EndIf

    _cveBIMEF2($iArrInput, $oArrOutput, $k, $mu, $a, $b)

    If $bOutputIsArray Then
        Call("_VectorOf" & $typeOfOutput & "Release", $vectorOutput)
    EndIf

    If $typeOfOutput <> Default Then
        _cveOutputArrayRelease($oArrOutput)
        If $bOutputCreate Then
            Call("_cve" & $typeOfOutput & "Release", $output)
        EndIf
    EndIf

    If $bInputIsArray Then
        Call("_VectorOf" & $typeOfInput & "Release", $vectorInput)
    EndIf

    If $typeOfInput <> Default Then
        _cveInputArrayRelease($iArrInput)
        If $bInputCreate Then
            Call("_cve" & $typeOfInput & "Release", $input)
        EndIf
    EndIf
EndFunc   ;==>_cveBIMEF2Typed

Func _cveBIMEF2Mat($input, $output, $k, $mu, $a, $b)
    ; cveBIMEF2 using cv::Mat instead of _*Array
    _cveBIMEF2Typed("Mat", $input, "Mat", $output, $k, $mu, $a, $b)
EndFunc   ;==>_cveBIMEF2Mat