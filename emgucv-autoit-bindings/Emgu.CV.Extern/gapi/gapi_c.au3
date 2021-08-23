#include-once
#include "..\..\CVEUtils.au3"

Func _cveGMatCreate()
    ; CVAPI(cv::GMat*) cveGMatCreate();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGMatCreate"), "cveGMatCreate", @error)
EndFunc   ;==>_cveGMatCreate

Func _cveGMatRelease($gmat)
    ; CVAPI(void) cveGMatRelease(cv::GMat** gmat);

    Local $sGmatDllType
    If IsDllStruct($gmat) Then
        $sGmatDllType = "struct*"
    ElseIf $gmat == Null Then
        $sGmatDllType = "ptr"
    Else
        $sGmatDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveGMatRelease", $sGmatDllType, $gmat), "cveGMatRelease", @error)
EndFunc   ;==>_cveGMatRelease

Func _cveGapiAdd($src1, $src2, $ddepth)
    ; CVAPI(cv::GMat*) cveGapiAdd(cv::GMat* src1, cv::GMat* src2, int ddepth);

    Local $sSrc1DllType
    If IsDllStruct($src1) Then
        $sSrc1DllType = "struct*"
    Else
        $sSrc1DllType = "ptr"
    EndIf

    Local $sSrc2DllType
    If IsDllStruct($src2) Then
        $sSrc2DllType = "struct*"
    Else
        $sSrc2DllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiAdd", $sSrc1DllType, $src1, $sSrc2DllType, $src2, "int", $ddepth), "cveGapiAdd", @error)
EndFunc   ;==>_cveGapiAdd

Func _cveGapiAddC($src1, $c, $ddepth)
    ; CVAPI(cv::GMat*) cveGapiAddC(cv::GMat* src1, cv::GScalar* c, int ddepth);

    Local $sSrc1DllType
    If IsDllStruct($src1) Then
        $sSrc1DllType = "struct*"
    Else
        $sSrc1DllType = "ptr"
    EndIf

    Local $sCDllType
    If IsDllStruct($c) Then
        $sCDllType = "struct*"
    Else
        $sCDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiAddC", $sSrc1DllType, $src1, $sCDllType, $c, "int", $ddepth), "cveGapiAddC", @error)
EndFunc   ;==>_cveGapiAddC

Func _cveGapiSub($src1, $src2, $ddepth)
    ; CVAPI(cv::GMat*) cveGapiSub(cv::GMat* src1, cv::GMat* src2, int ddepth);

    Local $sSrc1DllType
    If IsDllStruct($src1) Then
        $sSrc1DllType = "struct*"
    Else
        $sSrc1DllType = "ptr"
    EndIf

    Local $sSrc2DllType
    If IsDllStruct($src2) Then
        $sSrc2DllType = "struct*"
    Else
        $sSrc2DllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiSub", $sSrc1DllType, $src1, $sSrc2DllType, $src2, "int", $ddepth), "cveGapiSub", @error)
EndFunc   ;==>_cveGapiSub

Func _cveGapiSubC($src1, $c, $ddepth)
    ; CVAPI(cv::GMat*) cveGapiSubC(cv::GMat* src1, cv::GScalar* c, int ddepth);

    Local $sSrc1DllType
    If IsDllStruct($src1) Then
        $sSrc1DllType = "struct*"
    Else
        $sSrc1DllType = "ptr"
    EndIf

    Local $sCDllType
    If IsDllStruct($c) Then
        $sCDllType = "struct*"
    Else
        $sCDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiSubC", $sSrc1DllType, $src1, $sCDllType, $c, "int", $ddepth), "cveGapiSubC", @error)
EndFunc   ;==>_cveGapiSubC

Func _cveGapiSubRC($c, $src1, $ddepth)
    ; CVAPI(cv::GMat*) cveGapiSubRC(cv::GScalar* c, cv::GMat* src1, int ddepth);

    Local $sCDllType
    If IsDllStruct($c) Then
        $sCDllType = "struct*"
    Else
        $sCDllType = "ptr"
    EndIf

    Local $sSrc1DllType
    If IsDllStruct($src1) Then
        $sSrc1DllType = "struct*"
    Else
        $sSrc1DllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiSubRC", $sCDllType, $c, $sSrc1DllType, $src1, "int", $ddepth), "cveGapiSubRC", @error)
EndFunc   ;==>_cveGapiSubRC

Func _cveGapiMul($src1, $src2, $scale, $ddepth)
    ; CVAPI(cv::GMat*) cveGapiMul(cv::GMat* src1, cv::GMat* src2, double scale, int ddepth);

    Local $sSrc1DllType
    If IsDllStruct($src1) Then
        $sSrc1DllType = "struct*"
    Else
        $sSrc1DllType = "ptr"
    EndIf

    Local $sSrc2DllType
    If IsDllStruct($src2) Then
        $sSrc2DllType = "struct*"
    Else
        $sSrc2DllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiMul", $sSrc1DllType, $src1, $sSrc2DllType, $src2, "double", $scale, "int", $ddepth), "cveGapiMul", @error)
EndFunc   ;==>_cveGapiMul

Func _cveGapiMulC($src, $scale, $ddepth)
    ; CVAPI(cv::GMat*) cveGapiMulC(cv::GMat* src, cv::GScalar* scale, int ddepth);

    Local $sSrcDllType
    If IsDllStruct($src) Then
        $sSrcDllType = "struct*"
    Else
        $sSrcDllType = "ptr"
    EndIf

    Local $sScaleDllType
    If IsDllStruct($scale) Then
        $sScaleDllType = "struct*"
    Else
        $sScaleDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiMulC", $sSrcDllType, $src, $sScaleDllType, $scale, "int", $ddepth), "cveGapiMulC", @error)
EndFunc   ;==>_cveGapiMulC

Func _cveGapiDiv($src1, $src2, $scale, $ddepth)
    ; CVAPI(cv::GMat*) cveGapiDiv(cv::GMat* src1, cv::GMat* src2, double scale, int ddepth);

    Local $sSrc1DllType
    If IsDllStruct($src1) Then
        $sSrc1DllType = "struct*"
    Else
        $sSrc1DllType = "ptr"
    EndIf

    Local $sSrc2DllType
    If IsDllStruct($src2) Then
        $sSrc2DllType = "struct*"
    Else
        $sSrc2DllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiDiv", $sSrc1DllType, $src1, $sSrc2DllType, $src2, "double", $scale, "int", $ddepth), "cveGapiDiv", @error)
EndFunc   ;==>_cveGapiDiv

Func _cveGapiDivC($src, $divisor, $scale, $ddepth)
    ; CVAPI(cv::GMat*) cveGapiDivC(cv::GMat* src, cv::GScalar* divisor, double scale, int ddepth);

    Local $sSrcDllType
    If IsDllStruct($src) Then
        $sSrcDllType = "struct*"
    Else
        $sSrcDllType = "ptr"
    EndIf

    Local $sDivisorDllType
    If IsDllStruct($divisor) Then
        $sDivisorDllType = "struct*"
    Else
        $sDivisorDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiDivC", $sSrcDllType, $src, $sDivisorDllType, $divisor, "double", $scale, "int", $ddepth), "cveGapiDivC", @error)
EndFunc   ;==>_cveGapiDivC

Func _cveGapiDivRC($divident, $src, $scale, $ddepth)
    ; CVAPI(cv::GMat*) cveGapiDivRC(cv::GScalar* divident, cv::GMat* src, double scale, int ddepth);

    Local $sDividentDllType
    If IsDllStruct($divident) Then
        $sDividentDllType = "struct*"
    Else
        $sDividentDllType = "ptr"
    EndIf

    Local $sSrcDllType
    If IsDllStruct($src) Then
        $sSrcDllType = "struct*"
    Else
        $sSrcDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiDivRC", $sDividentDllType, $divident, $sSrcDllType, $src, "double", $scale, "int", $ddepth), "cveGapiDivRC", @error)
EndFunc   ;==>_cveGapiDivRC

Func _cveGapiMean($src)
    ; CVAPI(cv::GScalar*) cveGapiMean(cv::GMat* src);

    Local $sSrcDllType
    If IsDllStruct($src) Then
        $sSrcDllType = "struct*"
    Else
        $sSrcDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiMean", $sSrcDllType, $src), "cveGapiMean", @error)
EndFunc   ;==>_cveGapiMean

Func _cveGapiPolarToCart($magnitude, $angle, $angleInDegrees, $outX, $outY)
    ; CVAPI(void) cveGapiPolarToCart(cv::GMat* magnitude, cv::GMat* angle, bool angleInDegrees, cv::GMat* outX, cv::GMat* outY);

    Local $sMagnitudeDllType
    If IsDllStruct($magnitude) Then
        $sMagnitudeDllType = "struct*"
    Else
        $sMagnitudeDllType = "ptr"
    EndIf

    Local $sAngleDllType
    If IsDllStruct($angle) Then
        $sAngleDllType = "struct*"
    Else
        $sAngleDllType = "ptr"
    EndIf

    Local $sOutXDllType
    If IsDllStruct($outX) Then
        $sOutXDllType = "struct*"
    Else
        $sOutXDllType = "ptr"
    EndIf

    Local $sOutYDllType
    If IsDllStruct($outY) Then
        $sOutYDllType = "struct*"
    Else
        $sOutYDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveGapiPolarToCart", $sMagnitudeDllType, $magnitude, $sAngleDllType, $angle, "boolean", $angleInDegrees, $sOutXDllType, $outX, $sOutYDllType, $outY), "cveGapiPolarToCart", @error)
EndFunc   ;==>_cveGapiPolarToCart

Func _cveGapiCartToPolar($x, $y, $angleInDegrees, $outMagnitude, $outAngle)
    ; CVAPI(void) cveGapiCartToPolar(cv::GMat* x, cv::GMat* y, bool angleInDegrees, cv::GMat* outMagnitude, cv::GMat* outAngle);

    Local $sXDllType
    If IsDllStruct($x) Then
        $sXDllType = "struct*"
    Else
        $sXDllType = "ptr"
    EndIf

    Local $sYDllType
    If IsDllStruct($y) Then
        $sYDllType = "struct*"
    Else
        $sYDllType = "ptr"
    EndIf

    Local $sOutMagnitudeDllType
    If IsDllStruct($outMagnitude) Then
        $sOutMagnitudeDllType = "struct*"
    Else
        $sOutMagnitudeDllType = "ptr"
    EndIf

    Local $sOutAngleDllType
    If IsDllStruct($outAngle) Then
        $sOutAngleDllType = "struct*"
    Else
        $sOutAngleDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveGapiCartToPolar", $sXDllType, $x, $sYDllType, $y, "boolean", $angleInDegrees, $sOutMagnitudeDllType, $outMagnitude, $sOutAngleDllType, $outAngle), "cveGapiCartToPolar", @error)
EndFunc   ;==>_cveGapiCartToPolar

Func _cveGapiPhase($x, $y, $angleInDegrees)
    ; CVAPI(cv::GMat*) cveGapiPhase(cv::GMat* x, cv::GMat* y, bool angleInDegrees);

    Local $sXDllType
    If IsDllStruct($x) Then
        $sXDllType = "struct*"
    Else
        $sXDllType = "ptr"
    EndIf

    Local $sYDllType
    If IsDllStruct($y) Then
        $sYDllType = "struct*"
    Else
        $sYDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiPhase", $sXDllType, $x, $sYDllType, $y, "boolean", $angleInDegrees), "cveGapiPhase", @error)
EndFunc   ;==>_cveGapiPhase

Func _cveGapiSqrt($src)
    ; CVAPI(cv::GMat*) cveGapiSqrt(cv::GMat* src);

    Local $sSrcDllType
    If IsDllStruct($src) Then
        $sSrcDllType = "struct*"
    Else
        $sSrcDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiSqrt", $sSrcDllType, $src), "cveGapiSqrt", @error)
EndFunc   ;==>_cveGapiSqrt

Func _cveGapiCmpGT($src1, $src2)
    ; CVAPI(cv::GMat*) cveGapiCmpGT(cv::GMat* src1, cv::GMat* src2);

    Local $sSrc1DllType
    If IsDllStruct($src1) Then
        $sSrc1DllType = "struct*"
    Else
        $sSrc1DllType = "ptr"
    EndIf

    Local $sSrc2DllType
    If IsDllStruct($src2) Then
        $sSrc2DllType = "struct*"
    Else
        $sSrc2DllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiCmpGT", $sSrc1DllType, $src1, $sSrc2DllType, $src2), "cveGapiCmpGT", @error)
EndFunc   ;==>_cveGapiCmpGT

Func _cveGapiCmpGTS($src1, $src2)
    ; CVAPI(cv::GMat*) cveGapiCmpGTS(cv::GMat* src1, cv::GMat* src2);

    Local $sSrc1DllType
    If IsDllStruct($src1) Then
        $sSrc1DllType = "struct*"
    Else
        $sSrc1DllType = "ptr"
    EndIf

    Local $sSrc2DllType
    If IsDllStruct($src2) Then
        $sSrc2DllType = "struct*"
    Else
        $sSrc2DllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiCmpGTS", $sSrc1DllType, $src1, $sSrc2DllType, $src2), "cveGapiCmpGTS", @error)
EndFunc   ;==>_cveGapiCmpGTS

Func _cveGapiCmpLT($src1, $src2)
    ; CVAPI(cv::GMat*) cveGapiCmpLT(cv::GMat* src1, cv::GMat* src2);

    Local $sSrc1DllType
    If IsDllStruct($src1) Then
        $sSrc1DllType = "struct*"
    Else
        $sSrc1DllType = "ptr"
    EndIf

    Local $sSrc2DllType
    If IsDllStruct($src2) Then
        $sSrc2DllType = "struct*"
    Else
        $sSrc2DllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiCmpLT", $sSrc1DllType, $src1, $sSrc2DllType, $src2), "cveGapiCmpLT", @error)
EndFunc   ;==>_cveGapiCmpLT

Func _cveGapiCmpLTS($src1, $src2)
    ; CVAPI(cv::GMat*) cveGapiCmpLTS(cv::GMat* src1, cv::GScalar* src2);

    Local $sSrc1DllType
    If IsDllStruct($src1) Then
        $sSrc1DllType = "struct*"
    Else
        $sSrc1DllType = "ptr"
    EndIf

    Local $sSrc2DllType
    If IsDllStruct($src2) Then
        $sSrc2DllType = "struct*"
    Else
        $sSrc2DllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiCmpLTS", $sSrc1DllType, $src1, $sSrc2DllType, $src2), "cveGapiCmpLTS", @error)
EndFunc   ;==>_cveGapiCmpLTS

Func _cveGapiCmpGE($src1, $src2)
    ; CVAPI(cv::GMat*) cveGapiCmpGE(cv::GMat* src1, cv::GMat* src2);

    Local $sSrc1DllType
    If IsDllStruct($src1) Then
        $sSrc1DllType = "struct*"
    Else
        $sSrc1DllType = "ptr"
    EndIf

    Local $sSrc2DllType
    If IsDllStruct($src2) Then
        $sSrc2DllType = "struct*"
    Else
        $sSrc2DllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiCmpGE", $sSrc1DllType, $src1, $sSrc2DllType, $src2), "cveGapiCmpGE", @error)
EndFunc   ;==>_cveGapiCmpGE

Func _cveGapiCmpGES($src1, $src2)
    ; CVAPI(cv::GMat*) cveGapiCmpGES(cv::GMat* src1, cv::GScalar* src2);

    Local $sSrc1DllType
    If IsDllStruct($src1) Then
        $sSrc1DllType = "struct*"
    Else
        $sSrc1DllType = "ptr"
    EndIf

    Local $sSrc2DllType
    If IsDllStruct($src2) Then
        $sSrc2DllType = "struct*"
    Else
        $sSrc2DllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiCmpGES", $sSrc1DllType, $src1, $sSrc2DllType, $src2), "cveGapiCmpGES", @error)
EndFunc   ;==>_cveGapiCmpGES

Func _cveGapiCmpLE($src1, $src2)
    ; CVAPI(cv::GMat*) cveGapiCmpLE(cv::GMat* src1, cv::GMat* src2);

    Local $sSrc1DllType
    If IsDllStruct($src1) Then
        $sSrc1DllType = "struct*"
    Else
        $sSrc1DllType = "ptr"
    EndIf

    Local $sSrc2DllType
    If IsDllStruct($src2) Then
        $sSrc2DllType = "struct*"
    Else
        $sSrc2DllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiCmpLE", $sSrc1DllType, $src1, $sSrc2DllType, $src2), "cveGapiCmpLE", @error)
EndFunc   ;==>_cveGapiCmpLE

Func _cveGapiCmpLES($src1, $src2)
    ; CVAPI(cv::GMat*) cveGapiCmpLES(cv::GMat* src1, cv::GScalar* src2);

    Local $sSrc1DllType
    If IsDllStruct($src1) Then
        $sSrc1DllType = "struct*"
    Else
        $sSrc1DllType = "ptr"
    EndIf

    Local $sSrc2DllType
    If IsDllStruct($src2) Then
        $sSrc2DllType = "struct*"
    Else
        $sSrc2DllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiCmpLES", $sSrc1DllType, $src1, $sSrc2DllType, $src2), "cveGapiCmpLES", @error)
EndFunc   ;==>_cveGapiCmpLES

Func _cveGapiCmpEQ($src1, $src2)
    ; CVAPI(cv::GMat*) cveGapiCmpEQ(cv::GMat* src1, cv::GMat* src2);

    Local $sSrc1DllType
    If IsDllStruct($src1) Then
        $sSrc1DllType = "struct*"
    Else
        $sSrc1DllType = "ptr"
    EndIf

    Local $sSrc2DllType
    If IsDllStruct($src2) Then
        $sSrc2DllType = "struct*"
    Else
        $sSrc2DllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiCmpEQ", $sSrc1DllType, $src1, $sSrc2DllType, $src2), "cveGapiCmpEQ", @error)
EndFunc   ;==>_cveGapiCmpEQ

Func _cveGapiCmpEQS($src1, $src2)
    ; CVAPI(cv::GMat*) cveGapiCmpEQS(cv::GMat* src1, cv::GScalar* src2);

    Local $sSrc1DllType
    If IsDllStruct($src1) Then
        $sSrc1DllType = "struct*"
    Else
        $sSrc1DllType = "ptr"
    EndIf

    Local $sSrc2DllType
    If IsDllStruct($src2) Then
        $sSrc2DllType = "struct*"
    Else
        $sSrc2DllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiCmpEQS", $sSrc1DllType, $src1, $sSrc2DllType, $src2), "cveGapiCmpEQS", @error)
EndFunc   ;==>_cveGapiCmpEQS

Func _cveGapiCmpNE($src1, $src2)
    ; CVAPI(cv::GMat*) cveGapiCmpNE(cv::GMat* src1, cv::GMat* src2);

    Local $sSrc1DllType
    If IsDllStruct($src1) Then
        $sSrc1DllType = "struct*"
    Else
        $sSrc1DllType = "ptr"
    EndIf

    Local $sSrc2DllType
    If IsDllStruct($src2) Then
        $sSrc2DllType = "struct*"
    Else
        $sSrc2DllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiCmpNE", $sSrc1DllType, $src1, $sSrc2DllType, $src2), "cveGapiCmpNE", @error)
EndFunc   ;==>_cveGapiCmpNE

Func _cveGapiCmpNES($src1, $src2)
    ; CVAPI(cv::GMat*) cveGapiCmpNES(cv::GMat* src1, cv::GScalar* src2);

    Local $sSrc1DllType
    If IsDllStruct($src1) Then
        $sSrc1DllType = "struct*"
    Else
        $sSrc1DllType = "ptr"
    EndIf

    Local $sSrc2DllType
    If IsDllStruct($src2) Then
        $sSrc2DllType = "struct*"
    Else
        $sSrc2DllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiCmpNES", $sSrc1DllType, $src1, $sSrc2DllType, $src2), "cveGapiCmpNES", @error)
EndFunc   ;==>_cveGapiCmpNES

Func _cveGapiBitwiseAnd($src1, $src2)
    ; CVAPI(cv::GMat*) cveGapiBitwiseAnd(cv::GMat* src1, cv::GMat* src2);

    Local $sSrc1DllType
    If IsDllStruct($src1) Then
        $sSrc1DllType = "struct*"
    Else
        $sSrc1DllType = "ptr"
    EndIf

    Local $sSrc2DllType
    If IsDllStruct($src2) Then
        $sSrc2DllType = "struct*"
    Else
        $sSrc2DllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiBitwiseAnd", $sSrc1DllType, $src1, $sSrc2DllType, $src2), "cveGapiBitwiseAnd", @error)
EndFunc   ;==>_cveGapiBitwiseAnd

Func _cveGapiBitwiseAndS($src1, $src2)
    ; CVAPI(cv::GMat*) cveGapiBitwiseAndS(cv::GMat* src1, cv::GScalar* src2);

    Local $sSrc1DllType
    If IsDllStruct($src1) Then
        $sSrc1DllType = "struct*"
    Else
        $sSrc1DllType = "ptr"
    EndIf

    Local $sSrc2DllType
    If IsDllStruct($src2) Then
        $sSrc2DllType = "struct*"
    Else
        $sSrc2DllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiBitwiseAndS", $sSrc1DllType, $src1, $sSrc2DllType, $src2), "cveGapiBitwiseAndS", @error)
EndFunc   ;==>_cveGapiBitwiseAndS

Func _cveGapiBitwiseOr($src1, $src2)
    ; CVAPI(cv::GMat*) cveGapiBitwiseOr(cv::GMat* src1, cv::GMat* src2);

    Local $sSrc1DllType
    If IsDllStruct($src1) Then
        $sSrc1DllType = "struct*"
    Else
        $sSrc1DllType = "ptr"
    EndIf

    Local $sSrc2DllType
    If IsDllStruct($src2) Then
        $sSrc2DllType = "struct*"
    Else
        $sSrc2DllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiBitwiseOr", $sSrc1DllType, $src1, $sSrc2DllType, $src2), "cveGapiBitwiseOr", @error)
EndFunc   ;==>_cveGapiBitwiseOr

Func _cveGapiBitwiseOrS($src1, $src2)
    ; CVAPI(cv::GMat*) cveGapiBitwiseOrS(cv::GMat* src1, cv::GScalar* src2);

    Local $sSrc1DllType
    If IsDllStruct($src1) Then
        $sSrc1DllType = "struct*"
    Else
        $sSrc1DllType = "ptr"
    EndIf

    Local $sSrc2DllType
    If IsDllStruct($src2) Then
        $sSrc2DllType = "struct*"
    Else
        $sSrc2DllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiBitwiseOrS", $sSrc1DllType, $src1, $sSrc2DllType, $src2), "cveGapiBitwiseOrS", @error)
EndFunc   ;==>_cveGapiBitwiseOrS

Func _cveGapiBitwiseXor($src1, $src2)
    ; CVAPI(cv::GMat*) cveGapiBitwiseXor(cv::GMat* src1, cv::GMat* src2);

    Local $sSrc1DllType
    If IsDllStruct($src1) Then
        $sSrc1DllType = "struct*"
    Else
        $sSrc1DllType = "ptr"
    EndIf

    Local $sSrc2DllType
    If IsDllStruct($src2) Then
        $sSrc2DllType = "struct*"
    Else
        $sSrc2DllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiBitwiseXor", $sSrc1DllType, $src1, $sSrc2DllType, $src2), "cveGapiBitwiseXor", @error)
EndFunc   ;==>_cveGapiBitwiseXor

Func _cveGapiBitwiseXorS($src1, $src2)
    ; CVAPI(cv::GMat*) cveGapiBitwiseXorS(cv::GMat* src1, cv::GScalar* src2);

    Local $sSrc1DllType
    If IsDllStruct($src1) Then
        $sSrc1DllType = "struct*"
    Else
        $sSrc1DllType = "ptr"
    EndIf

    Local $sSrc2DllType
    If IsDllStruct($src2) Then
        $sSrc2DllType = "struct*"
    Else
        $sSrc2DllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiBitwiseXorS", $sSrc1DllType, $src1, $sSrc2DllType, $src2), "cveGapiBitwiseXorS", @error)
EndFunc   ;==>_cveGapiBitwiseXorS

Func _cveGapiMask($src, $mask)
    ; CVAPI(cv::GMat*) cveGapiMask(cv::GMat* src, cv::GMat* mask);

    Local $sSrcDllType
    If IsDllStruct($src) Then
        $sSrcDllType = "struct*"
    Else
        $sSrcDllType = "ptr"
    EndIf

    Local $sMaskDllType
    If IsDllStruct($mask) Then
        $sMaskDllType = "struct*"
    Else
        $sMaskDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiMask", $sSrcDllType, $src, $sMaskDllType, $mask), "cveGapiMask", @error)
EndFunc   ;==>_cveGapiMask

Func _cveGapiResize($src, $dsize, $fx, $fy, $interpolation)
    ; CVAPI(cv::GMat*) cveGapiResize(cv::GMat* src, cv::Size* dsize, double fx, double fy, int interpolation);

    Local $sSrcDllType
    If IsDllStruct($src) Then
        $sSrcDllType = "struct*"
    Else
        $sSrcDllType = "ptr"
    EndIf

    Local $sDsizeDllType
    If IsDllStruct($dsize) Then
        $sDsizeDllType = "struct*"
    Else
        $sDsizeDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiResize", $sSrcDllType, $src, $sDsizeDllType, $dsize, "double", $fx, "double", $fy, "int", $interpolation), "cveGapiResize", @error)
EndFunc   ;==>_cveGapiResize

Func _cveGapiBitwiseNot($src)
    ; CVAPI(cv::GMat*) cveGapiBitwiseNot(cv::GMat* src);

    Local $sSrcDllType
    If IsDllStruct($src) Then
        $sSrcDllType = "struct*"
    Else
        $sSrcDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiBitwiseNot", $sSrcDllType, $src), "cveGapiBitwiseNot", @error)
EndFunc   ;==>_cveGapiBitwiseNot

Func _cveGapiSelect($src1, $src2, $mask)
    ; CVAPI(cv::GMat*) cveGapiSelect(cv::GMat* src1, cv::GMat* src2, cv::GMat* mask);

    Local $sSrc1DllType
    If IsDllStruct($src1) Then
        $sSrc1DllType = "struct*"
    Else
        $sSrc1DllType = "ptr"
    EndIf

    Local $sSrc2DllType
    If IsDllStruct($src2) Then
        $sSrc2DllType = "struct*"
    Else
        $sSrc2DllType = "ptr"
    EndIf

    Local $sMaskDllType
    If IsDllStruct($mask) Then
        $sMaskDllType = "struct*"
    Else
        $sMaskDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiSelect", $sSrc1DllType, $src1, $sSrc2DllType, $src2, $sMaskDllType, $mask), "cveGapiSelect", @error)
EndFunc   ;==>_cveGapiSelect

Func _cveGapiMin($src1, $src2)
    ; CVAPI(cv::GMat*) cveGapiMin(cv::GMat* src1, cv::GMat* src2);

    Local $sSrc1DllType
    If IsDllStruct($src1) Then
        $sSrc1DllType = "struct*"
    Else
        $sSrc1DllType = "ptr"
    EndIf

    Local $sSrc2DllType
    If IsDllStruct($src2) Then
        $sSrc2DllType = "struct*"
    Else
        $sSrc2DllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiMin", $sSrc1DllType, $src1, $sSrc2DllType, $src2), "cveGapiMin", @error)
EndFunc   ;==>_cveGapiMin

Func _cveGapiMax($src1, $src2)
    ; CVAPI(cv::GMat*) cveGapiMax(cv::GMat* src1, cv::GMat* src2);

    Local $sSrc1DllType
    If IsDllStruct($src1) Then
        $sSrc1DllType = "struct*"
    Else
        $sSrc1DllType = "ptr"
    EndIf

    Local $sSrc2DllType
    If IsDllStruct($src2) Then
        $sSrc2DllType = "struct*"
    Else
        $sSrc2DllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiMax", $sSrc1DllType, $src1, $sSrc2DllType, $src2), "cveGapiMax", @error)
EndFunc   ;==>_cveGapiMax

Func _cveGapiAbsDiff($src1, $src2)
    ; CVAPI(cv::GMat*) cveGapiAbsDiff(cv::GMat* src1, cv::GMat* src2);

    Local $sSrc1DllType
    If IsDllStruct($src1) Then
        $sSrc1DllType = "struct*"
    Else
        $sSrc1DllType = "ptr"
    EndIf

    Local $sSrc2DllType
    If IsDllStruct($src2) Then
        $sSrc2DllType = "struct*"
    Else
        $sSrc2DllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiAbsDiff", $sSrc1DllType, $src1, $sSrc2DllType, $src2), "cveGapiAbsDiff", @error)
EndFunc   ;==>_cveGapiAbsDiff

Func _cveGapiAbsDiffC($src, $c)
    ; CVAPI(cv::GMat*) cveGapiAbsDiffC(cv::GMat* src, cv::GScalar* c);

    Local $sSrcDllType
    If IsDllStruct($src) Then
        $sSrcDllType = "struct*"
    Else
        $sSrcDllType = "ptr"
    EndIf

    Local $sCDllType
    If IsDllStruct($c) Then
        $sCDllType = "struct*"
    Else
        $sCDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiAbsDiffC", $sSrcDllType, $src, $sCDllType, $c), "cveGapiAbsDiffC", @error)
EndFunc   ;==>_cveGapiAbsDiffC

Func _cveGapiSum($src)
    ; CVAPI(cv::GScalar*) cveGapiSum(cv::GMat* src);

    Local $sSrcDllType
    If IsDllStruct($src) Then
        $sSrcDllType = "struct*"
    Else
        $sSrcDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiSum", $sSrcDllType, $src), "cveGapiSum", @error)
EndFunc   ;==>_cveGapiSum

Func _cveGapiAddWeighted($src1, $alpha, $src2, $beta, $gamma, $ddepth)
    ; CVAPI(cv::GMat*) cveGapiAddWeighted(cv::GMat* src1, double alpha, cv::GMat* src2, double beta, double gamma, int ddepth);

    Local $sSrc1DllType
    If IsDllStruct($src1) Then
        $sSrc1DllType = "struct*"
    Else
        $sSrc1DllType = "ptr"
    EndIf

    Local $sSrc2DllType
    If IsDllStruct($src2) Then
        $sSrc2DllType = "struct*"
    Else
        $sSrc2DllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiAddWeighted", $sSrc1DllType, $src1, "double", $alpha, $sSrc2DllType, $src2, "double", $beta, "double", $gamma, "int", $ddepth), "cveGapiAddWeighted", @error)
EndFunc   ;==>_cveGapiAddWeighted

Func _cveGapiNormL1($src)
    ; CVAPI(cv::GScalar*) cveGapiNormL1(cv::GMat* src);

    Local $sSrcDllType
    If IsDllStruct($src) Then
        $sSrcDllType = "struct*"
    Else
        $sSrcDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiNormL1", $sSrcDllType, $src), "cveGapiNormL1", @error)
EndFunc   ;==>_cveGapiNormL1

Func _cveGapiNormL2($src)
    ; CVAPI(cv::GScalar*) cveGapiNormL2(cv::GMat* src);

    Local $sSrcDllType
    If IsDllStruct($src) Then
        $sSrcDllType = "struct*"
    Else
        $sSrcDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiNormL2", $sSrcDllType, $src), "cveGapiNormL2", @error)
EndFunc   ;==>_cveGapiNormL2

Func _cveGapiNormInf($src)
    ; CVAPI(cv::GScalar*) cveGapiNormInf(cv::GMat* src);

    Local $sSrcDllType
    If IsDllStruct($src) Then
        $sSrcDllType = "struct*"
    Else
        $sSrcDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiNormInf", $sSrcDllType, $src), "cveGapiNormInf", @error)
EndFunc   ;==>_cveGapiNormInf

Func _cveGapiIntegral($src, $sdepth, $sqdepth, $dst1, $dst2)
    ; CVAPI(void) cveGapiIntegral(cv::GMat* src, int sdepth, int sqdepth, cv::GMat* dst1, cv::GMat* dst2);

    Local $sSrcDllType
    If IsDllStruct($src) Then
        $sSrcDllType = "struct*"
    Else
        $sSrcDllType = "ptr"
    EndIf

    Local $sDst1DllType
    If IsDllStruct($dst1) Then
        $sDst1DllType = "struct*"
    Else
        $sDst1DllType = "ptr"
    EndIf

    Local $sDst2DllType
    If IsDllStruct($dst2) Then
        $sDst2DllType = "struct*"
    Else
        $sDst2DllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveGapiIntegral", $sSrcDllType, $src, "int", $sdepth, "int", $sqdepth, $sDst1DllType, $dst1, $sDst2DllType, $dst2), "cveGapiIntegral", @error)
EndFunc   ;==>_cveGapiIntegral

Func _cveGapiThreshold($src, $thresh, $maxval, $type)
    ; CVAPI(cv::GMat*) cveGapiThreshold(cv::GMat* src, cv::GScalar* thresh, cv::GScalar* maxval, int type);

    Local $sSrcDllType
    If IsDllStruct($src) Then
        $sSrcDllType = "struct*"
    Else
        $sSrcDllType = "ptr"
    EndIf

    Local $sThreshDllType
    If IsDllStruct($thresh) Then
        $sThreshDllType = "struct*"
    Else
        $sThreshDllType = "ptr"
    EndIf

    Local $sMaxvalDllType
    If IsDllStruct($maxval) Then
        $sMaxvalDllType = "struct*"
    Else
        $sMaxvalDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiThreshold", $sSrcDllType, $src, $sThreshDllType, $thresh, $sMaxvalDllType, $maxval, "int", $type), "cveGapiThreshold", @error)
EndFunc   ;==>_cveGapiThreshold

Func _cveGapiInRange($src, $threshLow, $threshUp)
    ; CVAPI(cv::GMat*) cveGapiInRange(cv::GMat* src, cv::GScalar* threshLow, cv::GScalar* threshUp);

    Local $sSrcDllType
    If IsDllStruct($src) Then
        $sSrcDllType = "struct*"
    Else
        $sSrcDllType = "ptr"
    EndIf

    Local $sThreshLowDllType
    If IsDllStruct($threshLow) Then
        $sThreshLowDllType = "struct*"
    Else
        $sThreshLowDllType = "ptr"
    EndIf

    Local $sThreshUpDllType
    If IsDllStruct($threshUp) Then
        $sThreshUpDllType = "struct*"
    Else
        $sThreshUpDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiInRange", $sSrcDllType, $src, $sThreshLowDllType, $threshLow, $sThreshUpDllType, $threshUp), "cveGapiInRange", @error)
EndFunc   ;==>_cveGapiInRange

Func _cveGapiMerge4($src1, $src2, $src3, $src4)
    ; CVAPI(cv::GMat*) cveGapiMerge4(cv::GMat* src1, cv::GMat* src2, cv::GMat* src3, cv::GMat* src4);

    Local $sSrc1DllType
    If IsDllStruct($src1) Then
        $sSrc1DllType = "struct*"
    Else
        $sSrc1DllType = "ptr"
    EndIf

    Local $sSrc2DllType
    If IsDllStruct($src2) Then
        $sSrc2DllType = "struct*"
    Else
        $sSrc2DllType = "ptr"
    EndIf

    Local $sSrc3DllType
    If IsDllStruct($src3) Then
        $sSrc3DllType = "struct*"
    Else
        $sSrc3DllType = "ptr"
    EndIf

    Local $sSrc4DllType
    If IsDllStruct($src4) Then
        $sSrc4DllType = "struct*"
    Else
        $sSrc4DllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiMerge4", $sSrc1DllType, $src1, $sSrc2DllType, $src2, $sSrc3DllType, $src3, $sSrc4DllType, $src4), "cveGapiMerge4", @error)
EndFunc   ;==>_cveGapiMerge4

Func _cveGapiMerge3($src1, $src2, $src3)
    ; CVAPI(cv::GMat*) cveGapiMerge3(cv::GMat* src1, cv::GMat* src2, cv::GMat* src3);

    Local $sSrc1DllType
    If IsDllStruct($src1) Then
        $sSrc1DllType = "struct*"
    Else
        $sSrc1DllType = "ptr"
    EndIf

    Local $sSrc2DllType
    If IsDllStruct($src2) Then
        $sSrc2DllType = "struct*"
    Else
        $sSrc2DllType = "ptr"
    EndIf

    Local $sSrc3DllType
    If IsDllStruct($src3) Then
        $sSrc3DllType = "struct*"
    Else
        $sSrc3DllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiMerge3", $sSrc1DllType, $src1, $sSrc2DllType, $src2, $sSrc3DllType, $src3), "cveGapiMerge3", @error)
EndFunc   ;==>_cveGapiMerge3

Func _cveGapiSplit4($src, $dst1, $dst2, $dst3, $dst4)
    ; CVAPI(void) cveGapiSplit4(cv::GMat* src, cv::GMat* dst1, cv::GMat* dst2, cv::GMat* dst3, cv::GMat* dst4);

    Local $sSrcDllType
    If IsDllStruct($src) Then
        $sSrcDllType = "struct*"
    Else
        $sSrcDllType = "ptr"
    EndIf

    Local $sDst1DllType
    If IsDllStruct($dst1) Then
        $sDst1DllType = "struct*"
    Else
        $sDst1DllType = "ptr"
    EndIf

    Local $sDst2DllType
    If IsDllStruct($dst2) Then
        $sDst2DllType = "struct*"
    Else
        $sDst2DllType = "ptr"
    EndIf

    Local $sDst3DllType
    If IsDllStruct($dst3) Then
        $sDst3DllType = "struct*"
    Else
        $sDst3DllType = "ptr"
    EndIf

    Local $sDst4DllType
    If IsDllStruct($dst4) Then
        $sDst4DllType = "struct*"
    Else
        $sDst4DllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveGapiSplit4", $sSrcDllType, $src, $sDst1DllType, $dst1, $sDst2DllType, $dst2, $sDst3DllType, $dst3, $sDst4DllType, $dst4), "cveGapiSplit4", @error)
EndFunc   ;==>_cveGapiSplit4

Func _cveGapiSplit3($src, $dst1, $dst2, $dst3)
    ; CVAPI(void) cveGapiSplit3(cv::GMat* src, cv::GMat* dst1, cv::GMat* dst2, cv::GMat* dst3);

    Local $sSrcDllType
    If IsDllStruct($src) Then
        $sSrcDllType = "struct*"
    Else
        $sSrcDllType = "ptr"
    EndIf

    Local $sDst1DllType
    If IsDllStruct($dst1) Then
        $sDst1DllType = "struct*"
    Else
        $sDst1DllType = "ptr"
    EndIf

    Local $sDst2DllType
    If IsDllStruct($dst2) Then
        $sDst2DllType = "struct*"
    Else
        $sDst2DllType = "ptr"
    EndIf

    Local $sDst3DllType
    If IsDllStruct($dst3) Then
        $sDst3DllType = "struct*"
    Else
        $sDst3DllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveGapiSplit3", $sSrcDllType, $src, $sDst1DllType, $dst1, $sDst2DllType, $dst2, $sDst3DllType, $dst3), "cveGapiSplit3", @error)
EndFunc   ;==>_cveGapiSplit3

Func _cveGapiRemap($src, $map1, $map2, $interpolation, $borderMode, $borderValue)
    ; CVAPI(cv::GMat*) cveGapiRemap(cv::GMat* src, cv::Mat* map1, cv::Mat* map2, int interpolation, int borderMode, CvScalar* borderValue);

    Local $sSrcDllType
    If IsDllStruct($src) Then
        $sSrcDllType = "struct*"
    Else
        $sSrcDllType = "ptr"
    EndIf

    Local $sMap1DllType
    If IsDllStruct($map1) Then
        $sMap1DllType = "struct*"
    Else
        $sMap1DllType = "ptr"
    EndIf

    Local $sMap2DllType
    If IsDllStruct($map2) Then
        $sMap2DllType = "struct*"
    Else
        $sMap2DllType = "ptr"
    EndIf

    Local $sBorderValueDllType
    If IsDllStruct($borderValue) Then
        $sBorderValueDllType = "struct*"
    Else
        $sBorderValueDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiRemap", $sSrcDllType, $src, $sMap1DllType, $map1, $sMap2DllType, $map2, "int", $interpolation, "int", $borderMode, $sBorderValueDllType, $borderValue), "cveGapiRemap", @error)
EndFunc   ;==>_cveGapiRemap

Func _cveGapiFlip($src, $flipCode)
    ; CVAPI(cv::GMat*) cveGapiFlip(cv::GMat* src, int flipCode);

    Local $sSrcDllType
    If IsDllStruct($src) Then
        $sSrcDllType = "struct*"
    Else
        $sSrcDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiFlip", $sSrcDllType, $src, "int", $flipCode), "cveGapiFlip", @error)
EndFunc   ;==>_cveGapiFlip

Func _cveGapiCrop($src, $rect)
    ; CVAPI(cv::GMat*) cveGapiCrop(cv::GMat* src, CvRect* rect);

    Local $sSrcDllType
    If IsDllStruct($src) Then
        $sSrcDllType = "struct*"
    Else
        $sSrcDllType = "ptr"
    EndIf

    Local $sRectDllType
    If IsDllStruct($rect) Then
        $sRectDllType = "struct*"
    Else
        $sRectDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiCrop", $sSrcDllType, $src, $sRectDllType, $rect), "cveGapiCrop", @error)
EndFunc   ;==>_cveGapiCrop

Func _cveGapiConcatHor($src1, $src2)
    ; CVAPI(cv::GMat*) cveGapiConcatHor(cv::GMat* src1, cv::GMat* src2);

    Local $sSrc1DllType
    If IsDllStruct($src1) Then
        $sSrc1DllType = "struct*"
    Else
        $sSrc1DllType = "ptr"
    EndIf

    Local $sSrc2DllType
    If IsDllStruct($src2) Then
        $sSrc2DllType = "struct*"
    Else
        $sSrc2DllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiConcatHor", $sSrc1DllType, $src1, $sSrc2DllType, $src2), "cveGapiConcatHor", @error)
EndFunc   ;==>_cveGapiConcatHor

Func _cveGapiConcatHorV($v)
    ; CVAPI(cv::GMat*) cveGapiConcatHorV(std::vector<cv::GMat>* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfGMatCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfGMatPush($vecV, $v[$i])
        Next
    Else
        $vecV = $v
    EndIf

    Local $sVDllType
    If IsDllStruct($v) Then
        $sVDllType = "struct*"
    Else
        $sVDllType = "ptr"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiConcatHorV", $sVDllType, $vecV), "cveGapiConcatHorV", @error)

    If $bVIsArray Then
        _VectorOfGMatRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_cveGapiConcatHorV

Func _cveGapiConcatVert($src1, $src2)
    ; CVAPI(cv::GMat*) cveGapiConcatVert(cv::GMat* src1, cv::GMat* src2);

    Local $sSrc1DllType
    If IsDllStruct($src1) Then
        $sSrc1DllType = "struct*"
    Else
        $sSrc1DllType = "ptr"
    EndIf

    Local $sSrc2DllType
    If IsDllStruct($src2) Then
        $sSrc2DllType = "struct*"
    Else
        $sSrc2DllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiConcatVert", $sSrc1DllType, $src1, $sSrc2DllType, $src2), "cveGapiConcatVert", @error)
EndFunc   ;==>_cveGapiConcatVert

Func _cveGapiConcatVertV($v)
    ; CVAPI(cv::GMat*) cveGapiConcatVertV(std::vector<cv::GMat>* v);

    Local $vecV, $iArrVSize
    Local $bVIsArray = VarGetType($v) == "Array"

    If $bVIsArray Then
        $vecV = _VectorOfGMatCreate()

        $iArrVSize = UBound($v)
        For $i = 0 To $iArrVSize - 1
            _VectorOfGMatPush($vecV, $v[$i])
        Next
    Else
        $vecV = $v
    EndIf

    Local $sVDllType
    If IsDllStruct($v) Then
        $sVDllType = "struct*"
    Else
        $sVDllType = "ptr"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiConcatVertV", $sVDllType, $vecV), "cveGapiConcatVertV", @error)

    If $bVIsArray Then
        _VectorOfGMatRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_cveGapiConcatVertV

Func _cveGapiLUT($src, $lut)
    ; CVAPI(cv::GMat*) cveGapiLUT(cv::GMat* src, cv::Mat* lut);

    Local $sSrcDllType
    If IsDllStruct($src) Then
        $sSrcDllType = "struct*"
    Else
        $sSrcDllType = "ptr"
    EndIf

    Local $sLutDllType
    If IsDllStruct($lut) Then
        $sLutDllType = "struct*"
    Else
        $sLutDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiLUT", $sSrcDllType, $src, $sLutDllType, $lut), "cveGapiLUT", @error)
EndFunc   ;==>_cveGapiLUT

Func _cveGapiConvertTo($src, $rdepth, $alpha, $beta)
    ; CVAPI(cv::GMat*) cveGapiConvertTo(cv::GMat* src, int rdepth, double alpha, double beta);

    Local $sSrcDllType
    If IsDllStruct($src) Then
        $sSrcDllType = "struct*"
    Else
        $sSrcDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiConvertTo", $sSrcDllType, $src, "int", $rdepth, "double", $alpha, "double", $beta), "cveGapiConvertTo", @error)
EndFunc   ;==>_cveGapiConvertTo

Func _cveGapiNormalize($src, $alpha, $beta, $normType, $ddepth)
    ; CVAPI(cv::GMat*) cveGapiNormalize(cv::GMat* src, double alpha, double beta, int normType, int ddepth);

    Local $sSrcDllType
    If IsDllStruct($src) Then
        $sSrcDllType = "struct*"
    Else
        $sSrcDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiNormalize", $sSrcDllType, $src, "double", $alpha, "double", $beta, "int", $normType, "int", $ddepth), "cveGapiNormalize", @error)
EndFunc   ;==>_cveGapiNormalize

Func _cveGapiWarpPerspective($src, $M, $dsize, $flags, $borderMode, $borderValue)
    ; CVAPI(cv::GMat*) cveGapiWarpPerspective(cv::GMat* src, cv::Mat* M, CvSize* dsize, int flags, int borderMode, CvScalar* borderValue);

    Local $sSrcDllType
    If IsDllStruct($src) Then
        $sSrcDllType = "struct*"
    Else
        $sSrcDllType = "ptr"
    EndIf

    Local $sMDllType
    If IsDllStruct($M) Then
        $sMDllType = "struct*"
    Else
        $sMDllType = "ptr"
    EndIf

    Local $sDsizeDllType
    If IsDllStruct($dsize) Then
        $sDsizeDllType = "struct*"
    Else
        $sDsizeDllType = "ptr"
    EndIf

    Local $sBorderValueDllType
    If IsDllStruct($borderValue) Then
        $sBorderValueDllType = "struct*"
    Else
        $sBorderValueDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiWarpPerspective", $sSrcDllType, $src, $sMDllType, $M, $sDsizeDllType, $dsize, "int", $flags, "int", $borderMode, $sBorderValueDllType, $borderValue), "cveGapiWarpPerspective", @error)
EndFunc   ;==>_cveGapiWarpPerspective

Func _cveGapiWarpAffine($src, $M, $dsize, $flags, $borderMode, $borderValue)
    ; CVAPI(cv::GMat*) cveGapiWarpAffine(cv::GMat* src, cv::Mat* M, CvSize* dsize, int flags, int borderMode, CvScalar* borderValue);

    Local $sSrcDllType
    If IsDllStruct($src) Then
        $sSrcDllType = "struct*"
    Else
        $sSrcDllType = "ptr"
    EndIf

    Local $sMDllType
    If IsDllStruct($M) Then
        $sMDllType = "struct*"
    Else
        $sMDllType = "ptr"
    EndIf

    Local $sDsizeDllType
    If IsDllStruct($dsize) Then
        $sDsizeDllType = "struct*"
    Else
        $sDsizeDllType = "ptr"
    EndIf

    Local $sBorderValueDllType
    If IsDllStruct($borderValue) Then
        $sBorderValueDllType = "struct*"
    Else
        $sBorderValueDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiWarpAffine", $sSrcDllType, $src, $sMDllType, $M, $sDsizeDllType, $dsize, "int", $flags, "int", $borderMode, $sBorderValueDllType, $borderValue), "cveGapiWarpAffine", @error)
EndFunc   ;==>_cveGapiWarpAffine

Func _cveGapiTranspose($src)
    ; CVAPI(cv::GMat*) cveGapiTranspose(cv::GMat* src);

    Local $sSrcDllType
    If IsDllStruct($src) Then
        $sSrcDllType = "struct*"
    Else
        $sSrcDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiTranspose", $sSrcDllType, $src), "cveGapiTranspose", @error)
EndFunc   ;==>_cveGapiTranspose

Func _cveGComputationCreate1($input, $output)
    ; CVAPI(cv::GComputation*) cveGComputationCreate1(cv::GMat* input, cv::GMat* output);

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
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGComputationCreate1", $sInputDllType, $input, $sOutputDllType, $output), "cveGComputationCreate1", @error)
EndFunc   ;==>_cveGComputationCreate1

Func _cveGComputationCreate2($input, $output)
    ; CVAPI(cv::GComputation*) cveGComputationCreate2(cv::GMat* input, cv::GScalar* output);

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
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGComputationCreate2", $sInputDllType, $input, $sOutputDllType, $output), "cveGComputationCreate2", @error)
EndFunc   ;==>_cveGComputationCreate2

Func _cveGComputationCreate3($input1, $input2, $output)
    ; CVAPI(cv::GComputation*) cveGComputationCreate3(cv::GMat* input1, cv::GMat* input2, cv::GMat* output);

    Local $sInput1DllType
    If IsDllStruct($input1) Then
        $sInput1DllType = "struct*"
    Else
        $sInput1DllType = "ptr"
    EndIf

    Local $sInput2DllType
    If IsDllStruct($input2) Then
        $sInput2DllType = "struct*"
    Else
        $sInput2DllType = "ptr"
    EndIf

    Local $sOutputDllType
    If IsDllStruct($output) Then
        $sOutputDllType = "struct*"
    Else
        $sOutputDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGComputationCreate3", $sInput1DllType, $input1, $sInput2DllType, $input2, $sOutputDllType, $output), "cveGComputationCreate3", @error)
EndFunc   ;==>_cveGComputationCreate3

Func _cveGComputationCreate4($input1, $input2, $output)
    ; CVAPI(cv::GComputation*) cveGComputationCreate4(cv::GMat* input1, cv::GMat* input2, cv::GScalar* output);

    Local $sInput1DllType
    If IsDllStruct($input1) Then
        $sInput1DllType = "struct*"
    Else
        $sInput1DllType = "ptr"
    EndIf

    Local $sInput2DllType
    If IsDllStruct($input2) Then
        $sInput2DllType = "struct*"
    Else
        $sInput2DllType = "ptr"
    EndIf

    Local $sOutputDllType
    If IsDllStruct($output) Then
        $sOutputDllType = "struct*"
    Else
        $sOutputDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGComputationCreate4", $sInput1DllType, $input1, $sInput2DllType, $input2, $sOutputDllType, $output), "cveGComputationCreate4", @error)
EndFunc   ;==>_cveGComputationCreate4

Func _cveGComputationCreate5($ins, $outs)
    ; CVAPI(cv::GComputation*) cveGComputationCreate5(std::vector<cv::GMat>* ins, std::vector<cv::GMat>* outs);

    Local $vecIns, $iArrInsSize
    Local $bInsIsArray = VarGetType($ins) == "Array"

    If $bInsIsArray Then
        $vecIns = _VectorOfGMatCreate()

        $iArrInsSize = UBound($ins)
        For $i = 0 To $iArrInsSize - 1
            _VectorOfGMatPush($vecIns, $ins[$i])
        Next
    Else
        $vecIns = $ins
    EndIf

    Local $sInsDllType
    If IsDllStruct($ins) Then
        $sInsDllType = "struct*"
    Else
        $sInsDllType = "ptr"
    EndIf

    Local $vecOuts, $iArrOutsSize
    Local $bOutsIsArray = VarGetType($outs) == "Array"

    If $bOutsIsArray Then
        $vecOuts = _VectorOfGMatCreate()

        $iArrOutsSize = UBound($outs)
        For $i = 0 To $iArrOutsSize - 1
            _VectorOfGMatPush($vecOuts, $outs[$i])
        Next
    Else
        $vecOuts = $outs
    EndIf

    Local $sOutsDllType
    If IsDllStruct($outs) Then
        $sOutsDllType = "struct*"
    Else
        $sOutsDllType = "ptr"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGComputationCreate5", $sInsDllType, $vecIns, $sOutsDllType, $vecOuts), "cveGComputationCreate5", @error)

    If $bOutsIsArray Then
        _VectorOfGMatRelease($vecOuts)
    EndIf

    If $bInsIsArray Then
        _VectorOfGMatRelease($vecIns)
    EndIf

    Return $retval
EndFunc   ;==>_cveGComputationCreate5

Func _cveGComputationRelease($computation)
    ; CVAPI(void) cveGComputationRelease(cv::GComputation** computation);

    Local $sComputationDllType
    If IsDllStruct($computation) Then
        $sComputationDllType = "struct*"
    ElseIf $computation == Null Then
        $sComputationDllType = "ptr"
    Else
        $sComputationDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveGComputationRelease", $sComputationDllType, $computation), "cveGComputationRelease", @error)
EndFunc   ;==>_cveGComputationRelease

Func _cveGComputationApply1($computation, $input, $output)
    ; CVAPI(void) cveGComputationApply1(cv::GComputation* computation, cv::Mat* input, cv::Mat* output);

    Local $sComputationDllType
    If IsDllStruct($computation) Then
        $sComputationDllType = "struct*"
    Else
        $sComputationDllType = "ptr"
    EndIf

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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveGComputationApply1", $sComputationDllType, $computation, $sInputDllType, $input, $sOutputDllType, $output), "cveGComputationApply1", @error)
EndFunc   ;==>_cveGComputationApply1

Func _cveGComputationApply2($computation, $input, $output)
    ; CVAPI(void) cveGComputationApply2(cv::GComputation* computation, cv::Mat* input, CvScalar* output);

    Local $sComputationDllType
    If IsDllStruct($computation) Then
        $sComputationDllType = "struct*"
    Else
        $sComputationDllType = "ptr"
    EndIf

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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveGComputationApply2", $sComputationDllType, $computation, $sInputDllType, $input, $sOutputDllType, $output), "cveGComputationApply2", @error)
EndFunc   ;==>_cveGComputationApply2

Func _cveGComputationApply3($computation, $input1, $input2, $output)
    ; CVAPI(void) cveGComputationApply3(cv::GComputation* computation, cv::Mat* input1, cv::Mat* input2, cv::Mat* output);

    Local $sComputationDllType
    If IsDllStruct($computation) Then
        $sComputationDllType = "struct*"
    Else
        $sComputationDllType = "ptr"
    EndIf

    Local $sInput1DllType
    If IsDllStruct($input1) Then
        $sInput1DllType = "struct*"
    Else
        $sInput1DllType = "ptr"
    EndIf

    Local $sInput2DllType
    If IsDllStruct($input2) Then
        $sInput2DllType = "struct*"
    Else
        $sInput2DllType = "ptr"
    EndIf

    Local $sOutputDllType
    If IsDllStruct($output) Then
        $sOutputDllType = "struct*"
    Else
        $sOutputDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveGComputationApply3", $sComputationDllType, $computation, $sInput1DllType, $input1, $sInput2DllType, $input2, $sOutputDllType, $output), "cveGComputationApply3", @error)
EndFunc   ;==>_cveGComputationApply3

Func _cveGComputationApply4($computation, $input1, $input2, $output)
    ; CVAPI(void) cveGComputationApply4(cv::GComputation* computation, cv::Mat* input1, cv::Mat* input2, CvScalar* output);

    Local $sComputationDllType
    If IsDllStruct($computation) Then
        $sComputationDllType = "struct*"
    Else
        $sComputationDllType = "ptr"
    EndIf

    Local $sInput1DllType
    If IsDllStruct($input1) Then
        $sInput1DllType = "struct*"
    Else
        $sInput1DllType = "ptr"
    EndIf

    Local $sInput2DllType
    If IsDllStruct($input2) Then
        $sInput2DllType = "struct*"
    Else
        $sInput2DllType = "ptr"
    EndIf

    Local $sOutputDllType
    If IsDllStruct($output) Then
        $sOutputDllType = "struct*"
    Else
        $sOutputDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveGComputationApply4", $sComputationDllType, $computation, $sInput1DllType, $input1, $sInput2DllType, $input2, $sOutputDllType, $output), "cveGComputationApply4", @error)
EndFunc   ;==>_cveGComputationApply4

Func _cveGComputationApply5($computation, $inputs, $outputs)
    ; CVAPI(void) cveGComputationApply5(cv::GComputation* computation, std::vector<cv::Mat>* inputs, std::vector<cv::Mat>* outputs);

    Local $sComputationDllType
    If IsDllStruct($computation) Then
        $sComputationDllType = "struct*"
    Else
        $sComputationDllType = "ptr"
    EndIf

    Local $vecInputs, $iArrInputsSize
    Local $bInputsIsArray = VarGetType($inputs) == "Array"

    If $bInputsIsArray Then
        $vecInputs = _VectorOfMatCreate()

        $iArrInputsSize = UBound($inputs)
        For $i = 0 To $iArrInputsSize - 1
            _VectorOfMatPush($vecInputs, $inputs[$i])
        Next
    Else
        $vecInputs = $inputs
    EndIf

    Local $sInputsDllType
    If IsDllStruct($inputs) Then
        $sInputsDllType = "struct*"
    Else
        $sInputsDllType = "ptr"
    EndIf

    Local $vecOutputs, $iArrOutputsSize
    Local $bOutputsIsArray = VarGetType($outputs) == "Array"

    If $bOutputsIsArray Then
        $vecOutputs = _VectorOfMatCreate()

        $iArrOutputsSize = UBound($outputs)
        For $i = 0 To $iArrOutputsSize - 1
            _VectorOfMatPush($vecOutputs, $outputs[$i])
        Next
    Else
        $vecOutputs = $outputs
    EndIf

    Local $sOutputsDllType
    If IsDllStruct($outputs) Then
        $sOutputsDllType = "struct*"
    Else
        $sOutputsDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveGComputationApply5", $sComputationDllType, $computation, $sInputsDllType, $vecInputs, $sOutputsDllType, $vecOutputs), "cveGComputationApply5", @error)

    If $bOutputsIsArray Then
        _VectorOfMatRelease($vecOutputs)
    EndIf

    If $bInputsIsArray Then
        _VectorOfMatRelease($vecInputs)
    EndIf
EndFunc   ;==>_cveGComputationApply5

Func _cveGScalarCreate($value)
    ; CVAPI(cv::GScalar*) cveGScalarCreate(CvScalar* value);

    Local $sValueDllType
    If IsDllStruct($value) Then
        $sValueDllType = "struct*"
    Else
        $sValueDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGScalarCreate", $sValueDllType, $value), "cveGScalarCreate", @error)
EndFunc   ;==>_cveGScalarCreate

Func _cveGScalarRelease($gscalar)
    ; CVAPI(void) cveGScalarRelease(cv::GScalar** gscalar);

    Local $sGscalarDllType
    If IsDllStruct($gscalar) Then
        $sGscalarDllType = "struct*"
    ElseIf $gscalar == Null Then
        $sGscalarDllType = "ptr"
    Else
        $sGscalarDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveGScalarRelease", $sGscalarDllType, $gscalar), "cveGScalarRelease", @error)
EndFunc   ;==>_cveGScalarRelease

Func _cveGapiSepFilter($src, $ddepth, $kernelX, $kernelY, $anchor, $delta, $borderType, $borderValue)
    ; CVAPI(cv::GMat*) cveGapiSepFilter(cv::GMat* src, int ddepth, cv::Mat* kernelX, cv::Mat* kernelY, CvPoint* anchor, CvScalar* delta, int borderType, CvScalar* borderValue);

    Local $sSrcDllType
    If IsDllStruct($src) Then
        $sSrcDllType = "struct*"
    Else
        $sSrcDllType = "ptr"
    EndIf

    Local $sKernelXDllType
    If IsDllStruct($kernelX) Then
        $sKernelXDllType = "struct*"
    Else
        $sKernelXDllType = "ptr"
    EndIf

    Local $sKernelYDllType
    If IsDllStruct($kernelY) Then
        $sKernelYDllType = "struct*"
    Else
        $sKernelYDllType = "ptr"
    EndIf

    Local $sAnchorDllType
    If IsDllStruct($anchor) Then
        $sAnchorDllType = "struct*"
    Else
        $sAnchorDllType = "ptr"
    EndIf

    Local $sDeltaDllType
    If IsDllStruct($delta) Then
        $sDeltaDllType = "struct*"
    Else
        $sDeltaDllType = "ptr"
    EndIf

    Local $sBorderValueDllType
    If IsDllStruct($borderValue) Then
        $sBorderValueDllType = "struct*"
    Else
        $sBorderValueDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiSepFilter", $sSrcDllType, $src, "int", $ddepth, $sKernelXDllType, $kernelX, $sKernelYDllType, $kernelY, $sAnchorDllType, $anchor, $sDeltaDllType, $delta, "int", $borderType, $sBorderValueDllType, $borderValue), "cveGapiSepFilter", @error)
EndFunc   ;==>_cveGapiSepFilter

Func _cveGapiFilter2D($src, $ddepth, $kernel, $anchor, $delta, $borderType, $borderValue)
    ; CVAPI(cv::GMat*) cveGapiFilter2D(cv::GMat* src, int ddepth, cv::Mat* kernel, CvPoint* anchor, CvScalar* delta, int borderType, CvScalar* borderValue);

    Local $sSrcDllType
    If IsDllStruct($src) Then
        $sSrcDllType = "struct*"
    Else
        $sSrcDllType = "ptr"
    EndIf

    Local $sKernelDllType
    If IsDllStruct($kernel) Then
        $sKernelDllType = "struct*"
    Else
        $sKernelDllType = "ptr"
    EndIf

    Local $sAnchorDllType
    If IsDllStruct($anchor) Then
        $sAnchorDllType = "struct*"
    Else
        $sAnchorDllType = "ptr"
    EndIf

    Local $sDeltaDllType
    If IsDllStruct($delta) Then
        $sDeltaDllType = "struct*"
    Else
        $sDeltaDllType = "ptr"
    EndIf

    Local $sBorderValueDllType
    If IsDllStruct($borderValue) Then
        $sBorderValueDllType = "struct*"
    Else
        $sBorderValueDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiFilter2D", $sSrcDllType, $src, "int", $ddepth, $sKernelDllType, $kernel, $sAnchorDllType, $anchor, $sDeltaDllType, $delta, "int", $borderType, $sBorderValueDllType, $borderValue), "cveGapiFilter2D", @error)
EndFunc   ;==>_cveGapiFilter2D

Func _cveGapiBoxFilter($src, $dtype, $ksize, $anchor, $normalize, $borderType, $borderValue)
    ; CVAPI(cv::GMat*) cveGapiBoxFilter(cv::GMat* src, int dtype, CvSize* ksize, CvPoint* anchor, bool normalize, int borderType, CvScalar* borderValue);

    Local $sSrcDllType
    If IsDllStruct($src) Then
        $sSrcDllType = "struct*"
    Else
        $sSrcDllType = "ptr"
    EndIf

    Local $sKsizeDllType
    If IsDllStruct($ksize) Then
        $sKsizeDllType = "struct*"
    Else
        $sKsizeDllType = "ptr"
    EndIf

    Local $sAnchorDllType
    If IsDllStruct($anchor) Then
        $sAnchorDllType = "struct*"
    Else
        $sAnchorDllType = "ptr"
    EndIf

    Local $sBorderValueDllType
    If IsDllStruct($borderValue) Then
        $sBorderValueDllType = "struct*"
    Else
        $sBorderValueDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiBoxFilter", $sSrcDllType, $src, "int", $dtype, $sKsizeDllType, $ksize, $sAnchorDllType, $anchor, "boolean", $normalize, "int", $borderType, $sBorderValueDllType, $borderValue), "cveGapiBoxFilter", @error)
EndFunc   ;==>_cveGapiBoxFilter

Func _cveGapiBlur($src, $ksize, $anchor, $borderType, $borderValue)
    ; CVAPI(cv::GMat*) cveGapiBlur(cv::GMat* src, CvSize* ksize, CvPoint* anchor, int borderType, CvScalar* borderValue);

    Local $sSrcDllType
    If IsDllStruct($src) Then
        $sSrcDllType = "struct*"
    Else
        $sSrcDllType = "ptr"
    EndIf

    Local $sKsizeDllType
    If IsDllStruct($ksize) Then
        $sKsizeDllType = "struct*"
    Else
        $sKsizeDllType = "ptr"
    EndIf

    Local $sAnchorDllType
    If IsDllStruct($anchor) Then
        $sAnchorDllType = "struct*"
    Else
        $sAnchorDllType = "ptr"
    EndIf

    Local $sBorderValueDllType
    If IsDllStruct($borderValue) Then
        $sBorderValueDllType = "struct*"
    Else
        $sBorderValueDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiBlur", $sSrcDllType, $src, $sKsizeDllType, $ksize, $sAnchorDllType, $anchor, "int", $borderType, $sBorderValueDllType, $borderValue), "cveGapiBlur", @error)
EndFunc   ;==>_cveGapiBlur

Func _cveGapiGaussianBlur($src, $ksize, $sigmaX, $sigmaY, $borderType, $borderValue)
    ; CVAPI(cv::GMat*) cveGapiGaussianBlur(cv::GMat* src, CvSize* ksize, double sigmaX, double sigmaY, int borderType, CvScalar* borderValue);

    Local $sSrcDllType
    If IsDllStruct($src) Then
        $sSrcDllType = "struct*"
    Else
        $sSrcDllType = "ptr"
    EndIf

    Local $sKsizeDllType
    If IsDllStruct($ksize) Then
        $sKsizeDllType = "struct*"
    Else
        $sKsizeDllType = "ptr"
    EndIf

    Local $sBorderValueDllType
    If IsDllStruct($borderValue) Then
        $sBorderValueDllType = "struct*"
    Else
        $sBorderValueDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiGaussianBlur", $sSrcDllType, $src, $sKsizeDllType, $ksize, "double", $sigmaX, "double", $sigmaY, "int", $borderType, $sBorderValueDllType, $borderValue), "cveGapiGaussianBlur", @error)
EndFunc   ;==>_cveGapiGaussianBlur

Func _cveGapiMedianBlur($src, $ksize)
    ; CVAPI(cv::GMat*) cveGapiMedianBlur(cv::GMat* src, int ksize);

    Local $sSrcDllType
    If IsDllStruct($src) Then
        $sSrcDllType = "struct*"
    Else
        $sSrcDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiMedianBlur", $sSrcDllType, $src, "int", $ksize), "cveGapiMedianBlur", @error)
EndFunc   ;==>_cveGapiMedianBlur

Func _cveGapiErode($src, $kernel, $anchor, $iterations, $borderType, $borderValue)
    ; CVAPI(cv::GMat*) cveGapiErode(cv::GMat* src, cv::Mat* kernel, CvPoint* anchor, int iterations, int borderType, CvScalar* borderValue);

    Local $sSrcDllType
    If IsDllStruct($src) Then
        $sSrcDllType = "struct*"
    Else
        $sSrcDllType = "ptr"
    EndIf

    Local $sKernelDllType
    If IsDllStruct($kernel) Then
        $sKernelDllType = "struct*"
    Else
        $sKernelDllType = "ptr"
    EndIf

    Local $sAnchorDllType
    If IsDllStruct($anchor) Then
        $sAnchorDllType = "struct*"
    Else
        $sAnchorDllType = "ptr"
    EndIf

    Local $sBorderValueDllType
    If IsDllStruct($borderValue) Then
        $sBorderValueDllType = "struct*"
    Else
        $sBorderValueDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiErode", $sSrcDllType, $src, $sKernelDllType, $kernel, $sAnchorDllType, $anchor, "int", $iterations, "int", $borderType, $sBorderValueDllType, $borderValue), "cveGapiErode", @error)
EndFunc   ;==>_cveGapiErode

Func _cveGapiErode3x3($src, $iterations, $borderType, $borderValue)
    ; CVAPI(cv::GMat*) cveGapiErode3x3(cv::GMat* src, int iterations, int borderType, CvScalar* borderValue);

    Local $sSrcDllType
    If IsDllStruct($src) Then
        $sSrcDllType = "struct*"
    Else
        $sSrcDllType = "ptr"
    EndIf

    Local $sBorderValueDllType
    If IsDllStruct($borderValue) Then
        $sBorderValueDllType = "struct*"
    Else
        $sBorderValueDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiErode3x3", $sSrcDllType, $src, "int", $iterations, "int", $borderType, $sBorderValueDllType, $borderValue), "cveGapiErode3x3", @error)
EndFunc   ;==>_cveGapiErode3x3

Func _cveGapiDilate($src, $kernel, $anchor, $iterations, $borderType, $borderValue)
    ; CVAPI(cv::GMat*) cveGapiDilate(cv::GMat* src, cv::Mat* kernel, CvPoint* anchor, int iterations, int borderType, CvScalar* borderValue);

    Local $sSrcDllType
    If IsDllStruct($src) Then
        $sSrcDllType = "struct*"
    Else
        $sSrcDllType = "ptr"
    EndIf

    Local $sKernelDllType
    If IsDllStruct($kernel) Then
        $sKernelDllType = "struct*"
    Else
        $sKernelDllType = "ptr"
    EndIf

    Local $sAnchorDllType
    If IsDllStruct($anchor) Then
        $sAnchorDllType = "struct*"
    Else
        $sAnchorDllType = "ptr"
    EndIf

    Local $sBorderValueDllType
    If IsDllStruct($borderValue) Then
        $sBorderValueDllType = "struct*"
    Else
        $sBorderValueDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiDilate", $sSrcDllType, $src, $sKernelDllType, $kernel, $sAnchorDllType, $anchor, "int", $iterations, "int", $borderType, $sBorderValueDllType, $borderValue), "cveGapiDilate", @error)
EndFunc   ;==>_cveGapiDilate

Func _cveGapiDilate3x3($src, $iterations, $borderType, $borderValue)
    ; CVAPI(cv::GMat*) cveGapiDilate3x3(cv::GMat* src, int iterations, int borderType, CvScalar* borderValue);

    Local $sSrcDllType
    If IsDllStruct($src) Then
        $sSrcDllType = "struct*"
    Else
        $sSrcDllType = "ptr"
    EndIf

    Local $sBorderValueDllType
    If IsDllStruct($borderValue) Then
        $sBorderValueDllType = "struct*"
    Else
        $sBorderValueDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiDilate3x3", $sSrcDllType, $src, "int", $iterations, "int", $borderType, $sBorderValueDllType, $borderValue), "cveGapiDilate3x3", @error)
EndFunc   ;==>_cveGapiDilate3x3

Func _cveGapiMorphologyEx($src, $op, $kernel, $anchor, $iterations, $borderType, $borderValue)
    ; CVAPI(cv::GMat*) cveGapiMorphologyEx(cv::GMat* src, int op, cv::Mat* kernel, CvPoint* anchor, int iterations, int borderType, CvScalar* borderValue);

    Local $sSrcDllType
    If IsDllStruct($src) Then
        $sSrcDllType = "struct*"
    Else
        $sSrcDllType = "ptr"
    EndIf

    Local $sKernelDllType
    If IsDllStruct($kernel) Then
        $sKernelDllType = "struct*"
    Else
        $sKernelDllType = "ptr"
    EndIf

    Local $sAnchorDllType
    If IsDllStruct($anchor) Then
        $sAnchorDllType = "struct*"
    Else
        $sAnchorDllType = "ptr"
    EndIf

    Local $sBorderValueDllType
    If IsDllStruct($borderValue) Then
        $sBorderValueDllType = "struct*"
    Else
        $sBorderValueDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiMorphologyEx", $sSrcDllType, $src, "int", $op, $sKernelDllType, $kernel, $sAnchorDllType, $anchor, "int", $iterations, "int", $borderType, $sBorderValueDllType, $borderValue), "cveGapiMorphologyEx", @error)
EndFunc   ;==>_cveGapiMorphologyEx

Func _cveGapiSobel($src, $ddepth, $dx, $dy, $ksize, $scale, $delta, $borderType, $borderValue)
    ; CVAPI(cv::GMat*) cveGapiSobel(cv::GMat* src, int ddepth, int dx, int dy, int ksize, double scale, double delta, int borderType, CvScalar* borderValue);

    Local $sSrcDllType
    If IsDllStruct($src) Then
        $sSrcDllType = "struct*"
    Else
        $sSrcDllType = "ptr"
    EndIf

    Local $sBorderValueDllType
    If IsDllStruct($borderValue) Then
        $sBorderValueDllType = "struct*"
    Else
        $sBorderValueDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiSobel", $sSrcDllType, $src, "int", $ddepth, "int", $dx, "int", $dy, "int", $ksize, "double", $scale, "double", $delta, "int", $borderType, $sBorderValueDllType, $borderValue), "cveGapiSobel", @error)
EndFunc   ;==>_cveGapiSobel

Func _cveGapiSobelXY($src, $ddepth, $order, $ksize, $scale, $delta, $borderType, $borderValue, $sobelX, $sobelY)
    ; CVAPI(void) cveGapiSobelXY(cv::GMat* src, int ddepth, int order, int ksize, double scale, double delta, int borderType, CvScalar* borderValue, cv::GMat* sobelX, cv::GMat* sobelY);

    Local $sSrcDllType
    If IsDllStruct($src) Then
        $sSrcDllType = "struct*"
    Else
        $sSrcDllType = "ptr"
    EndIf

    Local $sBorderValueDllType
    If IsDllStruct($borderValue) Then
        $sBorderValueDllType = "struct*"
    Else
        $sBorderValueDllType = "ptr"
    EndIf

    Local $sSobelXDllType
    If IsDllStruct($sobelX) Then
        $sSobelXDllType = "struct*"
    Else
        $sSobelXDllType = "ptr"
    EndIf

    Local $sSobelYDllType
    If IsDllStruct($sobelY) Then
        $sSobelYDllType = "struct*"
    Else
        $sSobelYDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveGapiSobelXY", $sSrcDllType, $src, "int", $ddepth, "int", $order, "int", $ksize, "double", $scale, "double", $delta, "int", $borderType, $sBorderValueDllType, $borderValue, $sSobelXDllType, $sobelX, $sSobelYDllType, $sobelY), "cveGapiSobelXY", @error)
EndFunc   ;==>_cveGapiSobelXY

Func _cveGapiLaplacian($src, $ddepth, $ksize, $scale, $delta, $borderType)
    ; CVAPI(cv::GMat*) cveGapiLaplacian(cv::GMat* src, int ddepth, int ksize, double scale, double delta, int borderType);

    Local $sSrcDllType
    If IsDllStruct($src) Then
        $sSrcDllType = "struct*"
    Else
        $sSrcDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiLaplacian", $sSrcDllType, $src, "int", $ddepth, "int", $ksize, "double", $scale, "double", $delta, "int", $borderType), "cveGapiLaplacian", @error)
EndFunc   ;==>_cveGapiLaplacian

Func _cveGapiBilateralFilter($src, $d, $sigmaColor, $sigmaSpace, $borderType)
    ; CVAPI(cv::GMat*) cveGapiBilateralFilter(cv::GMat* src, int d, double sigmaColor, double sigmaSpace, int borderType);

    Local $sSrcDllType
    If IsDllStruct($src) Then
        $sSrcDllType = "struct*"
    Else
        $sSrcDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiBilateralFilter", $sSrcDllType, $src, "int", $d, "double", $sigmaColor, "double", $sigmaSpace, "int", $borderType), "cveGapiBilateralFilter", @error)
EndFunc   ;==>_cveGapiBilateralFilter

Func _cveGapiCanny($image, $threshold1, $threshold2, $apertureSize, $L2gradient)
    ; CVAPI(cv::GMat*) cveGapiCanny(cv::GMat* image, double threshold1, double threshold2, int apertureSize, bool L2gradient);

    Local $sImageDllType
    If IsDllStruct($image) Then
        $sImageDllType = "struct*"
    Else
        $sImageDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiCanny", $sImageDllType, $image, "double", $threshold1, "double", $threshold2, "int", $apertureSize, "boolean", $L2gradient), "cveGapiCanny", @error)
EndFunc   ;==>_cveGapiCanny

Func _cveGapiEqualizeHist($src)
    ; CVAPI(cv::GMat*) cveGapiEqualizeHist(cv::GMat* src);

    Local $sSrcDllType
    If IsDllStruct($src) Then
        $sSrcDllType = "struct*"
    Else
        $sSrcDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiEqualizeHist", $sSrcDllType, $src), "cveGapiEqualizeHist", @error)
EndFunc   ;==>_cveGapiEqualizeHist

Func _cveGapiBGR2RGB($src)
    ; CVAPI(cv::GMat*) cveGapiBGR2RGB(cv::GMat* src);

    Local $sSrcDllType
    If IsDllStruct($src) Then
        $sSrcDllType = "struct*"
    Else
        $sSrcDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiBGR2RGB", $sSrcDllType, $src), "cveGapiBGR2RGB", @error)
EndFunc   ;==>_cveGapiBGR2RGB

Func _cveGapiRGB2Gray1($src)
    ; CVAPI(cv::GMat*) cveGapiRGB2Gray1(cv::GMat* src);

    Local $sSrcDllType
    If IsDllStruct($src) Then
        $sSrcDllType = "struct*"
    Else
        $sSrcDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiRGB2Gray1", $sSrcDllType, $src), "cveGapiRGB2Gray1", @error)
EndFunc   ;==>_cveGapiRGB2Gray1

Func _cveGapiRGB2Gray2($src, $rY, $gY, $bY)
    ; CVAPI(cv::GMat*) cveGapiRGB2Gray2(cv::GMat* src, float rY, float gY, float bY);

    Local $sSrcDllType
    If IsDllStruct($src) Then
        $sSrcDllType = "struct*"
    Else
        $sSrcDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiRGB2Gray2", $sSrcDllType, $src, "float", $rY, "float", $gY, "float", $bY), "cveGapiRGB2Gray2", @error)
EndFunc   ;==>_cveGapiRGB2Gray2

Func _cveGapiBGR2Gray($src)
    ; CVAPI(cv::GMat*) cveGapiBGR2Gray(cv::GMat* src);

    Local $sSrcDllType
    If IsDllStruct($src) Then
        $sSrcDllType = "struct*"
    Else
        $sSrcDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiBGR2Gray", $sSrcDllType, $src), "cveGapiBGR2Gray", @error)
EndFunc   ;==>_cveGapiBGR2Gray

Func _cveGapiRGB2YUV($src)
    ; CVAPI(cv::GMat*) cveGapiRGB2YUV(cv::GMat* src);

    Local $sSrcDllType
    If IsDllStruct($src) Then
        $sSrcDllType = "struct*"
    Else
        $sSrcDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiRGB2YUV", $sSrcDllType, $src), "cveGapiRGB2YUV", @error)
EndFunc   ;==>_cveGapiRGB2YUV

Func _cveGapiBGR2I420($src)
    ; CVAPI(cv::GMat*) cveGapiBGR2I420(cv::GMat* src);

    Local $sSrcDllType
    If IsDllStruct($src) Then
        $sSrcDllType = "struct*"
    Else
        $sSrcDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiBGR2I420", $sSrcDllType, $src), "cveGapiBGR2I420", @error)
EndFunc   ;==>_cveGapiBGR2I420

Func _cveGapiRGB2I420($src)
    ; CVAPI(cv::GMat*) cveGapiRGB2I420(cv::GMat* src);

    Local $sSrcDllType
    If IsDllStruct($src) Then
        $sSrcDllType = "struct*"
    Else
        $sSrcDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiRGB2I420", $sSrcDllType, $src), "cveGapiRGB2I420", @error)
EndFunc   ;==>_cveGapiRGB2I420

Func _cveGapiI4202BGR($src)
    ; CVAPI(cv::GMat*) cveGapiI4202BGR(cv::GMat* src);

    Local $sSrcDllType
    If IsDllStruct($src) Then
        $sSrcDllType = "struct*"
    Else
        $sSrcDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiI4202BGR", $sSrcDllType, $src), "cveGapiI4202BGR", @error)
EndFunc   ;==>_cveGapiI4202BGR

Func _cveGapiI4202RGB($src)
    ; CVAPI(cv::GMat*) cveGapiI4202RGB(cv::GMat* src);

    Local $sSrcDllType
    If IsDllStruct($src) Then
        $sSrcDllType = "struct*"
    Else
        $sSrcDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiI4202RGB", $sSrcDllType, $src), "cveGapiI4202RGB", @error)
EndFunc   ;==>_cveGapiI4202RGB

Func _cveGapiBGR2LUV($src)
    ; CVAPI(cv::GMat*) cveGapiBGR2LUV(cv::GMat* src);

    Local $sSrcDllType
    If IsDllStruct($src) Then
        $sSrcDllType = "struct*"
    Else
        $sSrcDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiBGR2LUV", $sSrcDllType, $src), "cveGapiBGR2LUV", @error)
EndFunc   ;==>_cveGapiBGR2LUV

Func _cveGapiLUV2BGR($src)
    ; CVAPI(cv::GMat*) cveGapiLUV2BGR(cv::GMat* src);

    Local $sSrcDllType
    If IsDllStruct($src) Then
        $sSrcDllType = "struct*"
    Else
        $sSrcDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiLUV2BGR", $sSrcDllType, $src), "cveGapiLUV2BGR", @error)
EndFunc   ;==>_cveGapiLUV2BGR

Func _cveGapiYUV2BGR($src)
    ; CVAPI(cv::GMat*) cveGapiYUV2BGR(cv::GMat* src);

    Local $sSrcDllType
    If IsDllStruct($src) Then
        $sSrcDllType = "struct*"
    Else
        $sSrcDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiYUV2BGR", $sSrcDllType, $src), "cveGapiYUV2BGR", @error)
EndFunc   ;==>_cveGapiYUV2BGR

Func _cveGapiBGR2YUV($src)
    ; CVAPI(cv::GMat*) cveGapiBGR2YUV(cv::GMat* src);

    Local $sSrcDllType
    If IsDllStruct($src) Then
        $sSrcDllType = "struct*"
    Else
        $sSrcDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiBGR2YUV", $sSrcDllType, $src), "cveGapiBGR2YUV", @error)
EndFunc   ;==>_cveGapiBGR2YUV

Func _cveGapiRGB2Lab($src)
    ; CVAPI(cv::GMat*) cveGapiRGB2Lab(cv::GMat* src);

    Local $sSrcDllType
    If IsDllStruct($src) Then
        $sSrcDllType = "struct*"
    Else
        $sSrcDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiRGB2Lab", $sSrcDllType, $src), "cveGapiRGB2Lab", @error)
EndFunc   ;==>_cveGapiRGB2Lab

Func _cveGapiYUV2RGB($src)
    ; CVAPI(cv::GMat*) cveGapiYUV2RGB(cv::GMat* src);

    Local $sSrcDllType
    If IsDllStruct($src) Then
        $sSrcDllType = "struct*"
    Else
        $sSrcDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiYUV2RGB", $sSrcDllType, $src), "cveGapiYUV2RGB", @error)
EndFunc   ;==>_cveGapiYUV2RGB

Func _cveGapiNV12toRGB($srcY, $srcUV)
    ; CVAPI(cv::GMat*) cveGapiNV12toRGB(cv::GMat* srcY, cv::GMat* srcUV);

    Local $sSrcYDllType
    If IsDllStruct($srcY) Then
        $sSrcYDllType = "struct*"
    Else
        $sSrcYDllType = "ptr"
    EndIf

    Local $sSrcUVDllType
    If IsDllStruct($srcUV) Then
        $sSrcUVDllType = "struct*"
    Else
        $sSrcUVDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiNV12toRGB", $sSrcYDllType, $srcY, $sSrcUVDllType, $srcUV), "cveGapiNV12toRGB", @error)
EndFunc   ;==>_cveGapiNV12toRGB

Func _cveGapiNV12toGray($srcY, $srcUV)
    ; CVAPI(cv::GMat*) cveGapiNV12toGray(cv::GMat* srcY, cv::GMat* srcUV);

    Local $sSrcYDllType
    If IsDllStruct($srcY) Then
        $sSrcYDllType = "struct*"
    Else
        $sSrcYDllType = "ptr"
    EndIf

    Local $sSrcUVDllType
    If IsDllStruct($srcUV) Then
        $sSrcUVDllType = "struct*"
    Else
        $sSrcUVDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiNV12toGray", $sSrcYDllType, $srcY, $sSrcUVDllType, $srcUV), "cveGapiNV12toGray", @error)
EndFunc   ;==>_cveGapiNV12toGray

Func _cveGapiNV12toBGR($srcY, $srcUV)
    ; CVAPI(cv::GMat*) cveGapiNV12toBGR(cv::GMat* srcY, cv::GMat* srcUV);

    Local $sSrcYDllType
    If IsDllStruct($srcY) Then
        $sSrcYDllType = "struct*"
    Else
        $sSrcYDllType = "ptr"
    EndIf

    Local $sSrcUVDllType
    If IsDllStruct($srcUV) Then
        $sSrcUVDllType = "struct*"
    Else
        $sSrcUVDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiNV12toBGR", $sSrcYDllType, $srcY, $sSrcUVDllType, $srcUV), "cveGapiNV12toBGR", @error)
EndFunc   ;==>_cveGapiNV12toBGR

Func _cveGapiBayerGR2RGB($srcGR)
    ; CVAPI(cv::GMat*) cveGapiBayerGR2RGB(cv::GMat* srcGR);

    Local $sSrcGRDllType
    If IsDllStruct($srcGR) Then
        $sSrcGRDllType = "struct*"
    Else
        $sSrcGRDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiBayerGR2RGB", $sSrcGRDllType, $srcGR), "cveGapiBayerGR2RGB", @error)
EndFunc   ;==>_cveGapiBayerGR2RGB

Func _cveGapiRGB2HSV($src)
    ; CVAPI(cv::GMat*) cveGapiRGB2HSV(cv::GMat* src);

    Local $sSrcDllType
    If IsDllStruct($src) Then
        $sSrcDllType = "struct*"
    Else
        $sSrcDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiRGB2HSV", $sSrcDllType, $src), "cveGapiRGB2HSV", @error)
EndFunc   ;==>_cveGapiRGB2HSV

Func _cveGapiRGB2YUV422($src)
    ; CVAPI(cv::GMat*) cveGapiRGB2YUV422(cv::GMat* src);

    Local $sSrcDllType
    If IsDllStruct($src) Then
        $sSrcDllType = "struct*"
    Else
        $sSrcDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiRGB2YUV422", $sSrcDllType, $src), "cveGapiRGB2YUV422", @error)
EndFunc   ;==>_cveGapiRGB2YUV422

Func _cveGapiStereo($left, $right, $of)
    ; CVAPI(cv::GMat*) cveGapiStereo(cv::GMat* left, cv::GMat* right, int of);

    Local $sLeftDllType
    If IsDllStruct($left) Then
        $sLeftDllType = "struct*"
    Else
        $sLeftDllType = "ptr"
    EndIf

    Local $sRightDllType
    If IsDllStruct($right) Then
        $sRightDllType = "struct*"
    Else
        $sRightDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiStereo", $sLeftDllType, $left, $sRightDllType, $right, "int", $of), "cveGapiStereo", @error)
EndFunc   ;==>_cveGapiStereo