#include-once
#include "..\..\CVEUtils.au3"

Func _cveGMatCreate()
    ; CVAPI(cv::GMat*) cveGMatCreate();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGMatCreate"), "cveGMatCreate", @error)
EndFunc   ;==>_cveGMatCreate

Func _cveGMatRelease($gmat)
    ; CVAPI(void) cveGMatRelease(cv::GMat** gmat);

    Local $bGmatDllType
    If VarGetType($gmat) == "DLLStruct" Then
        $bGmatDllType = "struct*"
    Else
        $bGmatDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveGMatRelease", $bGmatDllType, $gmat), "cveGMatRelease", @error)
EndFunc   ;==>_cveGMatRelease

Func _cveGapiAdd($src1, $src2, $ddepth)
    ; CVAPI(cv::GMat*) cveGapiAdd(cv::GMat* src1, cv::GMat* src2, int ddepth);

    Local $bSrc1DllType
    If VarGetType($src1) == "DLLStruct" Then
        $bSrc1DllType = "struct*"
    Else
        $bSrc1DllType = "ptr"
    EndIf

    Local $bSrc2DllType
    If VarGetType($src2) == "DLLStruct" Then
        $bSrc2DllType = "struct*"
    Else
        $bSrc2DllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiAdd", $bSrc1DllType, $src1, $bSrc2DllType, $src2, "int", $ddepth), "cveGapiAdd", @error)
EndFunc   ;==>_cveGapiAdd

Func _cveGapiAddC($src1, $c, $ddepth)
    ; CVAPI(cv::GMat*) cveGapiAddC(cv::GMat* src1, cv::GScalar* c, int ddepth);

    Local $bSrc1DllType
    If VarGetType($src1) == "DLLStruct" Then
        $bSrc1DllType = "struct*"
    Else
        $bSrc1DllType = "ptr"
    EndIf

    Local $bCDllType
    If VarGetType($c) == "DLLStruct" Then
        $bCDllType = "struct*"
    Else
        $bCDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiAddC", $bSrc1DllType, $src1, $bCDllType, $c, "int", $ddepth), "cveGapiAddC", @error)
EndFunc   ;==>_cveGapiAddC

Func _cveGapiSub($src1, $src2, $ddepth)
    ; CVAPI(cv::GMat*) cveGapiSub(cv::GMat* src1, cv::GMat* src2, int ddepth);

    Local $bSrc1DllType
    If VarGetType($src1) == "DLLStruct" Then
        $bSrc1DllType = "struct*"
    Else
        $bSrc1DllType = "ptr"
    EndIf

    Local $bSrc2DllType
    If VarGetType($src2) == "DLLStruct" Then
        $bSrc2DllType = "struct*"
    Else
        $bSrc2DllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiSub", $bSrc1DllType, $src1, $bSrc2DllType, $src2, "int", $ddepth), "cveGapiSub", @error)
EndFunc   ;==>_cveGapiSub

Func _cveGapiSubC($src1, $c, $ddepth)
    ; CVAPI(cv::GMat*) cveGapiSubC(cv::GMat* src1, cv::GScalar* c, int ddepth);

    Local $bSrc1DllType
    If VarGetType($src1) == "DLLStruct" Then
        $bSrc1DllType = "struct*"
    Else
        $bSrc1DllType = "ptr"
    EndIf

    Local $bCDllType
    If VarGetType($c) == "DLLStruct" Then
        $bCDllType = "struct*"
    Else
        $bCDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiSubC", $bSrc1DllType, $src1, $bCDllType, $c, "int", $ddepth), "cveGapiSubC", @error)
EndFunc   ;==>_cveGapiSubC

Func _cveGapiSubRC($c, $src1, $ddepth)
    ; CVAPI(cv::GMat*) cveGapiSubRC(cv::GScalar* c, cv::GMat* src1, int ddepth);

    Local $bCDllType
    If VarGetType($c) == "DLLStruct" Then
        $bCDllType = "struct*"
    Else
        $bCDllType = "ptr"
    EndIf

    Local $bSrc1DllType
    If VarGetType($src1) == "DLLStruct" Then
        $bSrc1DllType = "struct*"
    Else
        $bSrc1DllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiSubRC", $bCDllType, $c, $bSrc1DllType, $src1, "int", $ddepth), "cveGapiSubRC", @error)
EndFunc   ;==>_cveGapiSubRC

Func _cveGapiMul($src1, $src2, $scale, $ddepth)
    ; CVAPI(cv::GMat*) cveGapiMul(cv::GMat* src1, cv::GMat* src2, double scale, int ddepth);

    Local $bSrc1DllType
    If VarGetType($src1) == "DLLStruct" Then
        $bSrc1DllType = "struct*"
    Else
        $bSrc1DllType = "ptr"
    EndIf

    Local $bSrc2DllType
    If VarGetType($src2) == "DLLStruct" Then
        $bSrc2DllType = "struct*"
    Else
        $bSrc2DllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiMul", $bSrc1DllType, $src1, $bSrc2DllType, $src2, "double", $scale, "int", $ddepth), "cveGapiMul", @error)
EndFunc   ;==>_cveGapiMul

Func _cveGapiMulC($src, $scale, $ddepth)
    ; CVAPI(cv::GMat*) cveGapiMulC(cv::GMat* src, cv::GScalar* scale, int ddepth);

    Local $bSrcDllType
    If VarGetType($src) == "DLLStruct" Then
        $bSrcDllType = "struct*"
    Else
        $bSrcDllType = "ptr"
    EndIf

    Local $bScaleDllType
    If VarGetType($scale) == "DLLStruct" Then
        $bScaleDllType = "struct*"
    Else
        $bScaleDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiMulC", $bSrcDllType, $src, $bScaleDllType, $scale, "int", $ddepth), "cveGapiMulC", @error)
EndFunc   ;==>_cveGapiMulC

Func _cveGapiDiv($src1, $src2, $scale, $ddepth)
    ; CVAPI(cv::GMat*) cveGapiDiv(cv::GMat* src1, cv::GMat* src2, double scale, int ddepth);

    Local $bSrc1DllType
    If VarGetType($src1) == "DLLStruct" Then
        $bSrc1DllType = "struct*"
    Else
        $bSrc1DllType = "ptr"
    EndIf

    Local $bSrc2DllType
    If VarGetType($src2) == "DLLStruct" Then
        $bSrc2DllType = "struct*"
    Else
        $bSrc2DllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiDiv", $bSrc1DllType, $src1, $bSrc2DllType, $src2, "double", $scale, "int", $ddepth), "cveGapiDiv", @error)
EndFunc   ;==>_cveGapiDiv

Func _cveGapiDivC($src, $divisor, $scale, $ddepth)
    ; CVAPI(cv::GMat*) cveGapiDivC(cv::GMat* src, cv::GScalar* divisor, double scale, int ddepth);

    Local $bSrcDllType
    If VarGetType($src) == "DLLStruct" Then
        $bSrcDllType = "struct*"
    Else
        $bSrcDllType = "ptr"
    EndIf

    Local $bDivisorDllType
    If VarGetType($divisor) == "DLLStruct" Then
        $bDivisorDllType = "struct*"
    Else
        $bDivisorDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiDivC", $bSrcDllType, $src, $bDivisorDllType, $divisor, "double", $scale, "int", $ddepth), "cveGapiDivC", @error)
EndFunc   ;==>_cveGapiDivC

Func _cveGapiDivRC($divident, $src, $scale, $ddepth)
    ; CVAPI(cv::GMat*) cveGapiDivRC(cv::GScalar* divident, cv::GMat* src, double scale, int ddepth);

    Local $bDividentDllType
    If VarGetType($divident) == "DLLStruct" Then
        $bDividentDllType = "struct*"
    Else
        $bDividentDllType = "ptr"
    EndIf

    Local $bSrcDllType
    If VarGetType($src) == "DLLStruct" Then
        $bSrcDllType = "struct*"
    Else
        $bSrcDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiDivRC", $bDividentDllType, $divident, $bSrcDllType, $src, "double", $scale, "int", $ddepth), "cveGapiDivRC", @error)
EndFunc   ;==>_cveGapiDivRC

Func _cveGapiMean($src)
    ; CVAPI(cv::GScalar*) cveGapiMean(cv::GMat* src);

    Local $bSrcDllType
    If VarGetType($src) == "DLLStruct" Then
        $bSrcDllType = "struct*"
    Else
        $bSrcDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiMean", $bSrcDllType, $src), "cveGapiMean", @error)
EndFunc   ;==>_cveGapiMean

Func _cveGapiPolarToCart($magnitude, $angle, $angleInDegrees, $outX, $outY)
    ; CVAPI(void) cveGapiPolarToCart(cv::GMat* magnitude, cv::GMat* angle, bool angleInDegrees, cv::GMat* outX, cv::GMat* outY);

    Local $bMagnitudeDllType
    If VarGetType($magnitude) == "DLLStruct" Then
        $bMagnitudeDllType = "struct*"
    Else
        $bMagnitudeDllType = "ptr"
    EndIf

    Local $bAngleDllType
    If VarGetType($angle) == "DLLStruct" Then
        $bAngleDllType = "struct*"
    Else
        $bAngleDllType = "ptr"
    EndIf

    Local $bOutXDllType
    If VarGetType($outX) == "DLLStruct" Then
        $bOutXDllType = "struct*"
    Else
        $bOutXDllType = "ptr"
    EndIf

    Local $bOutYDllType
    If VarGetType($outY) == "DLLStruct" Then
        $bOutYDllType = "struct*"
    Else
        $bOutYDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveGapiPolarToCart", $bMagnitudeDllType, $magnitude, $bAngleDllType, $angle, "boolean", $angleInDegrees, $bOutXDllType, $outX, $bOutYDllType, $outY), "cveGapiPolarToCart", @error)
EndFunc   ;==>_cveGapiPolarToCart

Func _cveGapiCartToPolar($x, $y, $angleInDegrees, $outMagnitude, $outAngle)
    ; CVAPI(void) cveGapiCartToPolar(cv::GMat* x, cv::GMat* y, bool angleInDegrees, cv::GMat* outMagnitude, cv::GMat* outAngle);

    Local $bXDllType
    If VarGetType($x) == "DLLStruct" Then
        $bXDllType = "struct*"
    Else
        $bXDllType = "ptr"
    EndIf

    Local $bYDllType
    If VarGetType($y) == "DLLStruct" Then
        $bYDllType = "struct*"
    Else
        $bYDllType = "ptr"
    EndIf

    Local $bOutMagnitudeDllType
    If VarGetType($outMagnitude) == "DLLStruct" Then
        $bOutMagnitudeDllType = "struct*"
    Else
        $bOutMagnitudeDllType = "ptr"
    EndIf

    Local $bOutAngleDllType
    If VarGetType($outAngle) == "DLLStruct" Then
        $bOutAngleDllType = "struct*"
    Else
        $bOutAngleDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveGapiCartToPolar", $bXDllType, $x, $bYDllType, $y, "boolean", $angleInDegrees, $bOutMagnitudeDllType, $outMagnitude, $bOutAngleDllType, $outAngle), "cveGapiCartToPolar", @error)
EndFunc   ;==>_cveGapiCartToPolar

Func _cveGapiPhase($x, $y, $angleInDegrees)
    ; CVAPI(cv::GMat*) cveGapiPhase(cv::GMat* x, cv::GMat* y, bool angleInDegrees);

    Local $bXDllType
    If VarGetType($x) == "DLLStruct" Then
        $bXDllType = "struct*"
    Else
        $bXDllType = "ptr"
    EndIf

    Local $bYDllType
    If VarGetType($y) == "DLLStruct" Then
        $bYDllType = "struct*"
    Else
        $bYDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiPhase", $bXDllType, $x, $bYDllType, $y, "boolean", $angleInDegrees), "cveGapiPhase", @error)
EndFunc   ;==>_cveGapiPhase

Func _cveGapiSqrt($src)
    ; CVAPI(cv::GMat*) cveGapiSqrt(cv::GMat* src);

    Local $bSrcDllType
    If VarGetType($src) == "DLLStruct" Then
        $bSrcDllType = "struct*"
    Else
        $bSrcDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiSqrt", $bSrcDllType, $src), "cveGapiSqrt", @error)
EndFunc   ;==>_cveGapiSqrt

Func _cveGapiCmpGT($src1, $src2)
    ; CVAPI(cv::GMat*) cveGapiCmpGT(cv::GMat* src1, cv::GMat* src2);

    Local $bSrc1DllType
    If VarGetType($src1) == "DLLStruct" Then
        $bSrc1DllType = "struct*"
    Else
        $bSrc1DllType = "ptr"
    EndIf

    Local $bSrc2DllType
    If VarGetType($src2) == "DLLStruct" Then
        $bSrc2DllType = "struct*"
    Else
        $bSrc2DllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiCmpGT", $bSrc1DllType, $src1, $bSrc2DllType, $src2), "cveGapiCmpGT", @error)
EndFunc   ;==>_cveGapiCmpGT

Func _cveGapiCmpGTS($src1, $src2)
    ; CVAPI(cv::GMat*) cveGapiCmpGTS(cv::GMat* src1, cv::GMat* src2);

    Local $bSrc1DllType
    If VarGetType($src1) == "DLLStruct" Then
        $bSrc1DllType = "struct*"
    Else
        $bSrc1DllType = "ptr"
    EndIf

    Local $bSrc2DllType
    If VarGetType($src2) == "DLLStruct" Then
        $bSrc2DllType = "struct*"
    Else
        $bSrc2DllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiCmpGTS", $bSrc1DllType, $src1, $bSrc2DllType, $src2), "cveGapiCmpGTS", @error)
EndFunc   ;==>_cveGapiCmpGTS

Func _cveGapiCmpLT($src1, $src2)
    ; CVAPI(cv::GMat*) cveGapiCmpLT(cv::GMat* src1, cv::GMat* src2);

    Local $bSrc1DllType
    If VarGetType($src1) == "DLLStruct" Then
        $bSrc1DllType = "struct*"
    Else
        $bSrc1DllType = "ptr"
    EndIf

    Local $bSrc2DllType
    If VarGetType($src2) == "DLLStruct" Then
        $bSrc2DllType = "struct*"
    Else
        $bSrc2DllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiCmpLT", $bSrc1DllType, $src1, $bSrc2DllType, $src2), "cveGapiCmpLT", @error)
EndFunc   ;==>_cveGapiCmpLT

Func _cveGapiCmpLTS($src1, $src2)
    ; CVAPI(cv::GMat*) cveGapiCmpLTS(cv::GMat* src1, cv::GScalar* src2);

    Local $bSrc1DllType
    If VarGetType($src1) == "DLLStruct" Then
        $bSrc1DllType = "struct*"
    Else
        $bSrc1DllType = "ptr"
    EndIf

    Local $bSrc2DllType
    If VarGetType($src2) == "DLLStruct" Then
        $bSrc2DllType = "struct*"
    Else
        $bSrc2DllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiCmpLTS", $bSrc1DllType, $src1, $bSrc2DllType, $src2), "cveGapiCmpLTS", @error)
EndFunc   ;==>_cveGapiCmpLTS

Func _cveGapiCmpGE($src1, $src2)
    ; CVAPI(cv::GMat*) cveGapiCmpGE(cv::GMat* src1, cv::GMat* src2);

    Local $bSrc1DllType
    If VarGetType($src1) == "DLLStruct" Then
        $bSrc1DllType = "struct*"
    Else
        $bSrc1DllType = "ptr"
    EndIf

    Local $bSrc2DllType
    If VarGetType($src2) == "DLLStruct" Then
        $bSrc2DllType = "struct*"
    Else
        $bSrc2DllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiCmpGE", $bSrc1DllType, $src1, $bSrc2DllType, $src2), "cveGapiCmpGE", @error)
EndFunc   ;==>_cveGapiCmpGE

Func _cveGapiCmpGES($src1, $src2)
    ; CVAPI(cv::GMat*) cveGapiCmpGES(cv::GMat* src1, cv::GScalar* src2);

    Local $bSrc1DllType
    If VarGetType($src1) == "DLLStruct" Then
        $bSrc1DllType = "struct*"
    Else
        $bSrc1DllType = "ptr"
    EndIf

    Local $bSrc2DllType
    If VarGetType($src2) == "DLLStruct" Then
        $bSrc2DllType = "struct*"
    Else
        $bSrc2DllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiCmpGES", $bSrc1DllType, $src1, $bSrc2DllType, $src2), "cveGapiCmpGES", @error)
EndFunc   ;==>_cveGapiCmpGES

Func _cveGapiCmpLE($src1, $src2)
    ; CVAPI(cv::GMat*) cveGapiCmpLE(cv::GMat* src1, cv::GMat* src2);

    Local $bSrc1DllType
    If VarGetType($src1) == "DLLStruct" Then
        $bSrc1DllType = "struct*"
    Else
        $bSrc1DllType = "ptr"
    EndIf

    Local $bSrc2DllType
    If VarGetType($src2) == "DLLStruct" Then
        $bSrc2DllType = "struct*"
    Else
        $bSrc2DllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiCmpLE", $bSrc1DllType, $src1, $bSrc2DllType, $src2), "cveGapiCmpLE", @error)
EndFunc   ;==>_cveGapiCmpLE

Func _cveGapiCmpLES($src1, $src2)
    ; CVAPI(cv::GMat*) cveGapiCmpLES(cv::GMat* src1, cv::GScalar* src2);

    Local $bSrc1DllType
    If VarGetType($src1) == "DLLStruct" Then
        $bSrc1DllType = "struct*"
    Else
        $bSrc1DllType = "ptr"
    EndIf

    Local $bSrc2DllType
    If VarGetType($src2) == "DLLStruct" Then
        $bSrc2DllType = "struct*"
    Else
        $bSrc2DllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiCmpLES", $bSrc1DllType, $src1, $bSrc2DllType, $src2), "cveGapiCmpLES", @error)
EndFunc   ;==>_cveGapiCmpLES

Func _cveGapiCmpEQ($src1, $src2)
    ; CVAPI(cv::GMat*) cveGapiCmpEQ(cv::GMat* src1, cv::GMat* src2);

    Local $bSrc1DllType
    If VarGetType($src1) == "DLLStruct" Then
        $bSrc1DllType = "struct*"
    Else
        $bSrc1DllType = "ptr"
    EndIf

    Local $bSrc2DllType
    If VarGetType($src2) == "DLLStruct" Then
        $bSrc2DllType = "struct*"
    Else
        $bSrc2DllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiCmpEQ", $bSrc1DllType, $src1, $bSrc2DllType, $src2), "cveGapiCmpEQ", @error)
EndFunc   ;==>_cveGapiCmpEQ

Func _cveGapiCmpEQS($src1, $src2)
    ; CVAPI(cv::GMat*) cveGapiCmpEQS(cv::GMat* src1, cv::GScalar* src2);

    Local $bSrc1DllType
    If VarGetType($src1) == "DLLStruct" Then
        $bSrc1DllType = "struct*"
    Else
        $bSrc1DllType = "ptr"
    EndIf

    Local $bSrc2DllType
    If VarGetType($src2) == "DLLStruct" Then
        $bSrc2DllType = "struct*"
    Else
        $bSrc2DllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiCmpEQS", $bSrc1DllType, $src1, $bSrc2DllType, $src2), "cveGapiCmpEQS", @error)
EndFunc   ;==>_cveGapiCmpEQS

Func _cveGapiCmpNE($src1, $src2)
    ; CVAPI(cv::GMat*) cveGapiCmpNE(cv::GMat* src1, cv::GMat* src2);

    Local $bSrc1DllType
    If VarGetType($src1) == "DLLStruct" Then
        $bSrc1DllType = "struct*"
    Else
        $bSrc1DllType = "ptr"
    EndIf

    Local $bSrc2DllType
    If VarGetType($src2) == "DLLStruct" Then
        $bSrc2DllType = "struct*"
    Else
        $bSrc2DllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiCmpNE", $bSrc1DllType, $src1, $bSrc2DllType, $src2), "cveGapiCmpNE", @error)
EndFunc   ;==>_cveGapiCmpNE

Func _cveGapiCmpNES($src1, $src2)
    ; CVAPI(cv::GMat*) cveGapiCmpNES(cv::GMat* src1, cv::GScalar* src2);

    Local $bSrc1DllType
    If VarGetType($src1) == "DLLStruct" Then
        $bSrc1DllType = "struct*"
    Else
        $bSrc1DllType = "ptr"
    EndIf

    Local $bSrc2DllType
    If VarGetType($src2) == "DLLStruct" Then
        $bSrc2DllType = "struct*"
    Else
        $bSrc2DllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiCmpNES", $bSrc1DllType, $src1, $bSrc2DllType, $src2), "cveGapiCmpNES", @error)
EndFunc   ;==>_cveGapiCmpNES

Func _cveGapiBitwiseAnd($src1, $src2)
    ; CVAPI(cv::GMat*) cveGapiBitwiseAnd(cv::GMat* src1, cv::GMat* src2);

    Local $bSrc1DllType
    If VarGetType($src1) == "DLLStruct" Then
        $bSrc1DllType = "struct*"
    Else
        $bSrc1DllType = "ptr"
    EndIf

    Local $bSrc2DllType
    If VarGetType($src2) == "DLLStruct" Then
        $bSrc2DllType = "struct*"
    Else
        $bSrc2DllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiBitwiseAnd", $bSrc1DllType, $src1, $bSrc2DllType, $src2), "cveGapiBitwiseAnd", @error)
EndFunc   ;==>_cveGapiBitwiseAnd

Func _cveGapiBitwiseAndS($src1, $src2)
    ; CVAPI(cv::GMat*) cveGapiBitwiseAndS(cv::GMat* src1, cv::GScalar* src2);

    Local $bSrc1DllType
    If VarGetType($src1) == "DLLStruct" Then
        $bSrc1DllType = "struct*"
    Else
        $bSrc1DllType = "ptr"
    EndIf

    Local $bSrc2DllType
    If VarGetType($src2) == "DLLStruct" Then
        $bSrc2DllType = "struct*"
    Else
        $bSrc2DllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiBitwiseAndS", $bSrc1DllType, $src1, $bSrc2DllType, $src2), "cveGapiBitwiseAndS", @error)
EndFunc   ;==>_cveGapiBitwiseAndS

Func _cveGapiBitwiseOr($src1, $src2)
    ; CVAPI(cv::GMat*) cveGapiBitwiseOr(cv::GMat* src1, cv::GMat* src2);

    Local $bSrc1DllType
    If VarGetType($src1) == "DLLStruct" Then
        $bSrc1DllType = "struct*"
    Else
        $bSrc1DllType = "ptr"
    EndIf

    Local $bSrc2DllType
    If VarGetType($src2) == "DLLStruct" Then
        $bSrc2DllType = "struct*"
    Else
        $bSrc2DllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiBitwiseOr", $bSrc1DllType, $src1, $bSrc2DllType, $src2), "cveGapiBitwiseOr", @error)
EndFunc   ;==>_cveGapiBitwiseOr

Func _cveGapiBitwiseOrS($src1, $src2)
    ; CVAPI(cv::GMat*) cveGapiBitwiseOrS(cv::GMat* src1, cv::GScalar* src2);

    Local $bSrc1DllType
    If VarGetType($src1) == "DLLStruct" Then
        $bSrc1DllType = "struct*"
    Else
        $bSrc1DllType = "ptr"
    EndIf

    Local $bSrc2DllType
    If VarGetType($src2) == "DLLStruct" Then
        $bSrc2DllType = "struct*"
    Else
        $bSrc2DllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiBitwiseOrS", $bSrc1DllType, $src1, $bSrc2DllType, $src2), "cveGapiBitwiseOrS", @error)
EndFunc   ;==>_cveGapiBitwiseOrS

Func _cveGapiBitwiseXor($src1, $src2)
    ; CVAPI(cv::GMat*) cveGapiBitwiseXor(cv::GMat* src1, cv::GMat* src2);

    Local $bSrc1DllType
    If VarGetType($src1) == "DLLStruct" Then
        $bSrc1DllType = "struct*"
    Else
        $bSrc1DllType = "ptr"
    EndIf

    Local $bSrc2DllType
    If VarGetType($src2) == "DLLStruct" Then
        $bSrc2DllType = "struct*"
    Else
        $bSrc2DllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiBitwiseXor", $bSrc1DllType, $src1, $bSrc2DllType, $src2), "cveGapiBitwiseXor", @error)
EndFunc   ;==>_cveGapiBitwiseXor

Func _cveGapiBitwiseXorS($src1, $src2)
    ; CVAPI(cv::GMat*) cveGapiBitwiseXorS(cv::GMat* src1, cv::GScalar* src2);

    Local $bSrc1DllType
    If VarGetType($src1) == "DLLStruct" Then
        $bSrc1DllType = "struct*"
    Else
        $bSrc1DllType = "ptr"
    EndIf

    Local $bSrc2DllType
    If VarGetType($src2) == "DLLStruct" Then
        $bSrc2DllType = "struct*"
    Else
        $bSrc2DllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiBitwiseXorS", $bSrc1DllType, $src1, $bSrc2DllType, $src2), "cveGapiBitwiseXorS", @error)
EndFunc   ;==>_cveGapiBitwiseXorS

Func _cveGapiMask($src, $mask)
    ; CVAPI(cv::GMat*) cveGapiMask(cv::GMat* src, cv::GMat* mask);

    Local $bSrcDllType
    If VarGetType($src) == "DLLStruct" Then
        $bSrcDllType = "struct*"
    Else
        $bSrcDllType = "ptr"
    EndIf

    Local $bMaskDllType
    If VarGetType($mask) == "DLLStruct" Then
        $bMaskDllType = "struct*"
    Else
        $bMaskDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiMask", $bSrcDllType, $src, $bMaskDllType, $mask), "cveGapiMask", @error)
EndFunc   ;==>_cveGapiMask

Func _cveGapiResize($src, $dsize, $fx, $fy, $interpolation)
    ; CVAPI(cv::GMat*) cveGapiResize(cv::GMat* src, cv::Size* dsize, double fx, double fy, int interpolation);

    Local $bSrcDllType
    If VarGetType($src) == "DLLStruct" Then
        $bSrcDllType = "struct*"
    Else
        $bSrcDllType = "ptr"
    EndIf

    Local $bDsizeDllType
    If VarGetType($dsize) == "DLLStruct" Then
        $bDsizeDllType = "struct*"
    Else
        $bDsizeDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiResize", $bSrcDllType, $src, $bDsizeDllType, $dsize, "double", $fx, "double", $fy, "int", $interpolation), "cveGapiResize", @error)
EndFunc   ;==>_cveGapiResize

Func _cveGapiBitwiseNot($src)
    ; CVAPI(cv::GMat*) cveGapiBitwiseNot(cv::GMat* src);

    Local $bSrcDllType
    If VarGetType($src) == "DLLStruct" Then
        $bSrcDllType = "struct*"
    Else
        $bSrcDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiBitwiseNot", $bSrcDllType, $src), "cveGapiBitwiseNot", @error)
EndFunc   ;==>_cveGapiBitwiseNot

Func _cveGapiSelect($src1, $src2, $mask)
    ; CVAPI(cv::GMat*) cveGapiSelect(cv::GMat* src1, cv::GMat* src2, cv::GMat* mask);

    Local $bSrc1DllType
    If VarGetType($src1) == "DLLStruct" Then
        $bSrc1DllType = "struct*"
    Else
        $bSrc1DllType = "ptr"
    EndIf

    Local $bSrc2DllType
    If VarGetType($src2) == "DLLStruct" Then
        $bSrc2DllType = "struct*"
    Else
        $bSrc2DllType = "ptr"
    EndIf

    Local $bMaskDllType
    If VarGetType($mask) == "DLLStruct" Then
        $bMaskDllType = "struct*"
    Else
        $bMaskDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiSelect", $bSrc1DllType, $src1, $bSrc2DllType, $src2, $bMaskDllType, $mask), "cveGapiSelect", @error)
EndFunc   ;==>_cveGapiSelect

Func _cveGapiMin($src1, $src2)
    ; CVAPI(cv::GMat*) cveGapiMin(cv::GMat* src1, cv::GMat* src2);

    Local $bSrc1DllType
    If VarGetType($src1) == "DLLStruct" Then
        $bSrc1DllType = "struct*"
    Else
        $bSrc1DllType = "ptr"
    EndIf

    Local $bSrc2DllType
    If VarGetType($src2) == "DLLStruct" Then
        $bSrc2DllType = "struct*"
    Else
        $bSrc2DllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiMin", $bSrc1DllType, $src1, $bSrc2DllType, $src2), "cveGapiMin", @error)
EndFunc   ;==>_cveGapiMin

Func _cveGapiMax($src1, $src2)
    ; CVAPI(cv::GMat*) cveGapiMax(cv::GMat* src1, cv::GMat* src2);

    Local $bSrc1DllType
    If VarGetType($src1) == "DLLStruct" Then
        $bSrc1DllType = "struct*"
    Else
        $bSrc1DllType = "ptr"
    EndIf

    Local $bSrc2DllType
    If VarGetType($src2) == "DLLStruct" Then
        $bSrc2DllType = "struct*"
    Else
        $bSrc2DllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiMax", $bSrc1DllType, $src1, $bSrc2DllType, $src2), "cveGapiMax", @error)
EndFunc   ;==>_cveGapiMax

Func _cveGapiAbsDiff($src1, $src2)
    ; CVAPI(cv::GMat*) cveGapiAbsDiff(cv::GMat* src1, cv::GMat* src2);

    Local $bSrc1DllType
    If VarGetType($src1) == "DLLStruct" Then
        $bSrc1DllType = "struct*"
    Else
        $bSrc1DllType = "ptr"
    EndIf

    Local $bSrc2DllType
    If VarGetType($src2) == "DLLStruct" Then
        $bSrc2DllType = "struct*"
    Else
        $bSrc2DllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiAbsDiff", $bSrc1DllType, $src1, $bSrc2DllType, $src2), "cveGapiAbsDiff", @error)
EndFunc   ;==>_cveGapiAbsDiff

Func _cveGapiAbsDiffC($src, $c)
    ; CVAPI(cv::GMat*) cveGapiAbsDiffC(cv::GMat* src, cv::GScalar* c);

    Local $bSrcDllType
    If VarGetType($src) == "DLLStruct" Then
        $bSrcDllType = "struct*"
    Else
        $bSrcDllType = "ptr"
    EndIf

    Local $bCDllType
    If VarGetType($c) == "DLLStruct" Then
        $bCDllType = "struct*"
    Else
        $bCDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiAbsDiffC", $bSrcDllType, $src, $bCDllType, $c), "cveGapiAbsDiffC", @error)
EndFunc   ;==>_cveGapiAbsDiffC

Func _cveGapiSum($src)
    ; CVAPI(cv::GScalar*) cveGapiSum(cv::GMat* src);

    Local $bSrcDllType
    If VarGetType($src) == "DLLStruct" Then
        $bSrcDllType = "struct*"
    Else
        $bSrcDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiSum", $bSrcDllType, $src), "cveGapiSum", @error)
EndFunc   ;==>_cveGapiSum

Func _cveGapiAddWeighted($src1, $alpha, $src2, $beta, $gamma, $ddepth)
    ; CVAPI(cv::GMat*) cveGapiAddWeighted(cv::GMat* src1, double alpha, cv::GMat* src2, double beta, double gamma, int ddepth);

    Local $bSrc1DllType
    If VarGetType($src1) == "DLLStruct" Then
        $bSrc1DllType = "struct*"
    Else
        $bSrc1DllType = "ptr"
    EndIf

    Local $bSrc2DllType
    If VarGetType($src2) == "DLLStruct" Then
        $bSrc2DllType = "struct*"
    Else
        $bSrc2DllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiAddWeighted", $bSrc1DllType, $src1, "double", $alpha, $bSrc2DllType, $src2, "double", $beta, "double", $gamma, "int", $ddepth), "cveGapiAddWeighted", @error)
EndFunc   ;==>_cveGapiAddWeighted

Func _cveGapiNormL1($src)
    ; CVAPI(cv::GScalar*) cveGapiNormL1(cv::GMat* src);

    Local $bSrcDllType
    If VarGetType($src) == "DLLStruct" Then
        $bSrcDllType = "struct*"
    Else
        $bSrcDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiNormL1", $bSrcDllType, $src), "cveGapiNormL1", @error)
EndFunc   ;==>_cveGapiNormL1

Func _cveGapiNormL2($src)
    ; CVAPI(cv::GScalar*) cveGapiNormL2(cv::GMat* src);

    Local $bSrcDllType
    If VarGetType($src) == "DLLStruct" Then
        $bSrcDllType = "struct*"
    Else
        $bSrcDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiNormL2", $bSrcDllType, $src), "cveGapiNormL2", @error)
EndFunc   ;==>_cveGapiNormL2

Func _cveGapiNormInf($src)
    ; CVAPI(cv::GScalar*) cveGapiNormInf(cv::GMat* src);

    Local $bSrcDllType
    If VarGetType($src) == "DLLStruct" Then
        $bSrcDllType = "struct*"
    Else
        $bSrcDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiNormInf", $bSrcDllType, $src), "cveGapiNormInf", @error)
EndFunc   ;==>_cveGapiNormInf

Func _cveGapiIntegral($src, $sdepth, $sqdepth, $dst1, $dst2)
    ; CVAPI(void) cveGapiIntegral(cv::GMat* src, int sdepth, int sqdepth, cv::GMat* dst1, cv::GMat* dst2);

    Local $bSrcDllType
    If VarGetType($src) == "DLLStruct" Then
        $bSrcDllType = "struct*"
    Else
        $bSrcDllType = "ptr"
    EndIf

    Local $bDst1DllType
    If VarGetType($dst1) == "DLLStruct" Then
        $bDst1DllType = "struct*"
    Else
        $bDst1DllType = "ptr"
    EndIf

    Local $bDst2DllType
    If VarGetType($dst2) == "DLLStruct" Then
        $bDst2DllType = "struct*"
    Else
        $bDst2DllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveGapiIntegral", $bSrcDllType, $src, "int", $sdepth, "int", $sqdepth, $bDst1DllType, $dst1, $bDst2DllType, $dst2), "cveGapiIntegral", @error)
EndFunc   ;==>_cveGapiIntegral

Func _cveGapiThreshold($src, $thresh, $maxval, $type)
    ; CVAPI(cv::GMat*) cveGapiThreshold(cv::GMat* src, cv::GScalar* thresh, cv::GScalar* maxval, int type);

    Local $bSrcDllType
    If VarGetType($src) == "DLLStruct" Then
        $bSrcDllType = "struct*"
    Else
        $bSrcDllType = "ptr"
    EndIf

    Local $bThreshDllType
    If VarGetType($thresh) == "DLLStruct" Then
        $bThreshDllType = "struct*"
    Else
        $bThreshDllType = "ptr"
    EndIf

    Local $bMaxvalDllType
    If VarGetType($maxval) == "DLLStruct" Then
        $bMaxvalDllType = "struct*"
    Else
        $bMaxvalDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiThreshold", $bSrcDllType, $src, $bThreshDllType, $thresh, $bMaxvalDllType, $maxval, "int", $type), "cveGapiThreshold", @error)
EndFunc   ;==>_cveGapiThreshold

Func _cveGapiInRange($src, $threshLow, $threshUp)
    ; CVAPI(cv::GMat*) cveGapiInRange(cv::GMat* src, cv::GScalar* threshLow, cv::GScalar* threshUp);

    Local $bSrcDllType
    If VarGetType($src) == "DLLStruct" Then
        $bSrcDllType = "struct*"
    Else
        $bSrcDllType = "ptr"
    EndIf

    Local $bThreshLowDllType
    If VarGetType($threshLow) == "DLLStruct" Then
        $bThreshLowDllType = "struct*"
    Else
        $bThreshLowDllType = "ptr"
    EndIf

    Local $bThreshUpDllType
    If VarGetType($threshUp) == "DLLStruct" Then
        $bThreshUpDllType = "struct*"
    Else
        $bThreshUpDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiInRange", $bSrcDllType, $src, $bThreshLowDllType, $threshLow, $bThreshUpDllType, $threshUp), "cveGapiInRange", @error)
EndFunc   ;==>_cveGapiInRange

Func _cveGapiMerge4($src1, $src2, $src3, $src4)
    ; CVAPI(cv::GMat*) cveGapiMerge4(cv::GMat* src1, cv::GMat* src2, cv::GMat* src3, cv::GMat* src4);

    Local $bSrc1DllType
    If VarGetType($src1) == "DLLStruct" Then
        $bSrc1DllType = "struct*"
    Else
        $bSrc1DllType = "ptr"
    EndIf

    Local $bSrc2DllType
    If VarGetType($src2) == "DLLStruct" Then
        $bSrc2DllType = "struct*"
    Else
        $bSrc2DllType = "ptr"
    EndIf

    Local $bSrc3DllType
    If VarGetType($src3) == "DLLStruct" Then
        $bSrc3DllType = "struct*"
    Else
        $bSrc3DllType = "ptr"
    EndIf

    Local $bSrc4DllType
    If VarGetType($src4) == "DLLStruct" Then
        $bSrc4DllType = "struct*"
    Else
        $bSrc4DllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiMerge4", $bSrc1DllType, $src1, $bSrc2DllType, $src2, $bSrc3DllType, $src3, $bSrc4DllType, $src4), "cveGapiMerge4", @error)
EndFunc   ;==>_cveGapiMerge4

Func _cveGapiMerge3($src1, $src2, $src3)
    ; CVAPI(cv::GMat*) cveGapiMerge3(cv::GMat* src1, cv::GMat* src2, cv::GMat* src3);

    Local $bSrc1DllType
    If VarGetType($src1) == "DLLStruct" Then
        $bSrc1DllType = "struct*"
    Else
        $bSrc1DllType = "ptr"
    EndIf

    Local $bSrc2DllType
    If VarGetType($src2) == "DLLStruct" Then
        $bSrc2DllType = "struct*"
    Else
        $bSrc2DllType = "ptr"
    EndIf

    Local $bSrc3DllType
    If VarGetType($src3) == "DLLStruct" Then
        $bSrc3DllType = "struct*"
    Else
        $bSrc3DllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiMerge3", $bSrc1DllType, $src1, $bSrc2DllType, $src2, $bSrc3DllType, $src3), "cveGapiMerge3", @error)
EndFunc   ;==>_cveGapiMerge3

Func _cveGapiSplit4($src, $dst1, $dst2, $dst3, $dst4)
    ; CVAPI(void) cveGapiSplit4(cv::GMat* src, cv::GMat* dst1, cv::GMat* dst2, cv::GMat* dst3, cv::GMat* dst4);

    Local $bSrcDllType
    If VarGetType($src) == "DLLStruct" Then
        $bSrcDllType = "struct*"
    Else
        $bSrcDllType = "ptr"
    EndIf

    Local $bDst1DllType
    If VarGetType($dst1) == "DLLStruct" Then
        $bDst1DllType = "struct*"
    Else
        $bDst1DllType = "ptr"
    EndIf

    Local $bDst2DllType
    If VarGetType($dst2) == "DLLStruct" Then
        $bDst2DllType = "struct*"
    Else
        $bDst2DllType = "ptr"
    EndIf

    Local $bDst3DllType
    If VarGetType($dst3) == "DLLStruct" Then
        $bDst3DllType = "struct*"
    Else
        $bDst3DllType = "ptr"
    EndIf

    Local $bDst4DllType
    If VarGetType($dst4) == "DLLStruct" Then
        $bDst4DllType = "struct*"
    Else
        $bDst4DllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveGapiSplit4", $bSrcDllType, $src, $bDst1DllType, $dst1, $bDst2DllType, $dst2, $bDst3DllType, $dst3, $bDst4DllType, $dst4), "cveGapiSplit4", @error)
EndFunc   ;==>_cveGapiSplit4

Func _cveGapiSplit3($src, $dst1, $dst2, $dst3)
    ; CVAPI(void) cveGapiSplit3(cv::GMat* src, cv::GMat* dst1, cv::GMat* dst2, cv::GMat* dst3);

    Local $bSrcDllType
    If VarGetType($src) == "DLLStruct" Then
        $bSrcDllType = "struct*"
    Else
        $bSrcDllType = "ptr"
    EndIf

    Local $bDst1DllType
    If VarGetType($dst1) == "DLLStruct" Then
        $bDst1DllType = "struct*"
    Else
        $bDst1DllType = "ptr"
    EndIf

    Local $bDst2DllType
    If VarGetType($dst2) == "DLLStruct" Then
        $bDst2DllType = "struct*"
    Else
        $bDst2DllType = "ptr"
    EndIf

    Local $bDst3DllType
    If VarGetType($dst3) == "DLLStruct" Then
        $bDst3DllType = "struct*"
    Else
        $bDst3DllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveGapiSplit3", $bSrcDllType, $src, $bDst1DllType, $dst1, $bDst2DllType, $dst2, $bDst3DllType, $dst3), "cveGapiSplit3", @error)
EndFunc   ;==>_cveGapiSplit3

Func _cveGapiRemap($src, $map1, $map2, $interpolation, $borderMode, $borderValue)
    ; CVAPI(cv::GMat*) cveGapiRemap(cv::GMat* src, cv::Mat* map1, cv::Mat* map2, int interpolation, int borderMode, CvScalar* borderValue);

    Local $bSrcDllType
    If VarGetType($src) == "DLLStruct" Then
        $bSrcDllType = "struct*"
    Else
        $bSrcDllType = "ptr"
    EndIf

    Local $bMap1DllType
    If VarGetType($map1) == "DLLStruct" Then
        $bMap1DllType = "struct*"
    Else
        $bMap1DllType = "ptr"
    EndIf

    Local $bMap2DllType
    If VarGetType($map2) == "DLLStruct" Then
        $bMap2DllType = "struct*"
    Else
        $bMap2DllType = "ptr"
    EndIf

    Local $bBorderValueDllType
    If VarGetType($borderValue) == "DLLStruct" Then
        $bBorderValueDllType = "struct*"
    Else
        $bBorderValueDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiRemap", $bSrcDllType, $src, $bMap1DllType, $map1, $bMap2DllType, $map2, "int", $interpolation, "int", $borderMode, $bBorderValueDllType, $borderValue), "cveGapiRemap", @error)
EndFunc   ;==>_cveGapiRemap

Func _cveGapiFlip($src, $flipCode)
    ; CVAPI(cv::GMat*) cveGapiFlip(cv::GMat* src, int flipCode);

    Local $bSrcDllType
    If VarGetType($src) == "DLLStruct" Then
        $bSrcDllType = "struct*"
    Else
        $bSrcDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiFlip", $bSrcDllType, $src, "int", $flipCode), "cveGapiFlip", @error)
EndFunc   ;==>_cveGapiFlip

Func _cveGapiCrop($src, $rect)
    ; CVAPI(cv::GMat*) cveGapiCrop(cv::GMat* src, CvRect* rect);

    Local $bSrcDllType
    If VarGetType($src) == "DLLStruct" Then
        $bSrcDllType = "struct*"
    Else
        $bSrcDllType = "ptr"
    EndIf

    Local $bRectDllType
    If VarGetType($rect) == "DLLStruct" Then
        $bRectDllType = "struct*"
    Else
        $bRectDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiCrop", $bSrcDllType, $src, $bRectDllType, $rect), "cveGapiCrop", @error)
EndFunc   ;==>_cveGapiCrop

Func _cveGapiConcatHor($src1, $src2)
    ; CVAPI(cv::GMat*) cveGapiConcatHor(cv::GMat* src1, cv::GMat* src2);

    Local $bSrc1DllType
    If VarGetType($src1) == "DLLStruct" Then
        $bSrc1DllType = "struct*"
    Else
        $bSrc1DllType = "ptr"
    EndIf

    Local $bSrc2DllType
    If VarGetType($src2) == "DLLStruct" Then
        $bSrc2DllType = "struct*"
    Else
        $bSrc2DllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiConcatHor", $bSrc1DllType, $src1, $bSrc2DllType, $src2), "cveGapiConcatHor", @error)
EndFunc   ;==>_cveGapiConcatHor

Func _cveGapiConcatHorV($v)
    ; CVAPI(cv::GMat*) cveGapiConcatHorV(std::vector< cv::GMat >* v);

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

    Local $bVDllType
    If VarGetType($v) == "DLLStruct" Then
        $bVDllType = "struct*"
    Else
        $bVDllType = "ptr"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiConcatHorV", $bVDllType, $vecV), "cveGapiConcatHorV", @error)

    If $bVIsArray Then
        _VectorOfGMatRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_cveGapiConcatHorV

Func _cveGapiConcatVert($src1, $src2)
    ; CVAPI(cv::GMat*) cveGapiConcatVert(cv::GMat* src1, cv::GMat* src2);

    Local $bSrc1DllType
    If VarGetType($src1) == "DLLStruct" Then
        $bSrc1DllType = "struct*"
    Else
        $bSrc1DllType = "ptr"
    EndIf

    Local $bSrc2DllType
    If VarGetType($src2) == "DLLStruct" Then
        $bSrc2DllType = "struct*"
    Else
        $bSrc2DllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiConcatVert", $bSrc1DllType, $src1, $bSrc2DllType, $src2), "cveGapiConcatVert", @error)
EndFunc   ;==>_cveGapiConcatVert

Func _cveGapiConcatVertV($v)
    ; CVAPI(cv::GMat*) cveGapiConcatVertV(std::vector< cv::GMat >* v);

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

    Local $bVDllType
    If VarGetType($v) == "DLLStruct" Then
        $bVDllType = "struct*"
    Else
        $bVDllType = "ptr"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiConcatVertV", $bVDllType, $vecV), "cveGapiConcatVertV", @error)

    If $bVIsArray Then
        _VectorOfGMatRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_cveGapiConcatVertV

Func _cveGapiLUT($src, $lut)
    ; CVAPI(cv::GMat*) cveGapiLUT(cv::GMat* src, cv::Mat* lut);

    Local $bSrcDllType
    If VarGetType($src) == "DLLStruct" Then
        $bSrcDllType = "struct*"
    Else
        $bSrcDllType = "ptr"
    EndIf

    Local $bLutDllType
    If VarGetType($lut) == "DLLStruct" Then
        $bLutDllType = "struct*"
    Else
        $bLutDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiLUT", $bSrcDllType, $src, $bLutDllType, $lut), "cveGapiLUT", @error)
EndFunc   ;==>_cveGapiLUT

Func _cveGapiConvertTo($src, $rdepth, $alpha, $beta)
    ; CVAPI(cv::GMat*) cveGapiConvertTo(cv::GMat* src, int rdepth, double alpha, double beta);

    Local $bSrcDllType
    If VarGetType($src) == "DLLStruct" Then
        $bSrcDllType = "struct*"
    Else
        $bSrcDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiConvertTo", $bSrcDllType, $src, "int", $rdepth, "double", $alpha, "double", $beta), "cveGapiConvertTo", @error)
EndFunc   ;==>_cveGapiConvertTo

Func _cveGapiNormalize($src, $alpha, $beta, $normType, $ddepth)
    ; CVAPI(cv::GMat*) cveGapiNormalize(cv::GMat* src, double alpha, double beta, int normType, int ddepth);

    Local $bSrcDllType
    If VarGetType($src) == "DLLStruct" Then
        $bSrcDllType = "struct*"
    Else
        $bSrcDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiNormalize", $bSrcDllType, $src, "double", $alpha, "double", $beta, "int", $normType, "int", $ddepth), "cveGapiNormalize", @error)
EndFunc   ;==>_cveGapiNormalize

Func _cveGapiWarpPerspective($src, $M, $dsize, $flags, $borderMode, $borderValue)
    ; CVAPI(cv::GMat*) cveGapiWarpPerspective(cv::GMat* src, cv::Mat* M, CvSize* dsize, int flags, int borderMode, CvScalar* borderValue);

    Local $bSrcDllType
    If VarGetType($src) == "DLLStruct" Then
        $bSrcDllType = "struct*"
    Else
        $bSrcDllType = "ptr"
    EndIf

    Local $bMDllType
    If VarGetType($M) == "DLLStruct" Then
        $bMDllType = "struct*"
    Else
        $bMDllType = "ptr"
    EndIf

    Local $bDsizeDllType
    If VarGetType($dsize) == "DLLStruct" Then
        $bDsizeDllType = "struct*"
    Else
        $bDsizeDllType = "ptr"
    EndIf

    Local $bBorderValueDllType
    If VarGetType($borderValue) == "DLLStruct" Then
        $bBorderValueDllType = "struct*"
    Else
        $bBorderValueDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiWarpPerspective", $bSrcDllType, $src, $bMDllType, $M, $bDsizeDllType, $dsize, "int", $flags, "int", $borderMode, $bBorderValueDllType, $borderValue), "cveGapiWarpPerspective", @error)
EndFunc   ;==>_cveGapiWarpPerspective

Func _cveGapiWarpAffine($src, $M, $dsize, $flags, $borderMode, $borderValue)
    ; CVAPI(cv::GMat*) cveGapiWarpAffine(cv::GMat* src, cv::Mat* M, CvSize* dsize, int flags, int borderMode, CvScalar* borderValue);

    Local $bSrcDllType
    If VarGetType($src) == "DLLStruct" Then
        $bSrcDllType = "struct*"
    Else
        $bSrcDllType = "ptr"
    EndIf

    Local $bMDllType
    If VarGetType($M) == "DLLStruct" Then
        $bMDllType = "struct*"
    Else
        $bMDllType = "ptr"
    EndIf

    Local $bDsizeDllType
    If VarGetType($dsize) == "DLLStruct" Then
        $bDsizeDllType = "struct*"
    Else
        $bDsizeDllType = "ptr"
    EndIf

    Local $bBorderValueDllType
    If VarGetType($borderValue) == "DLLStruct" Then
        $bBorderValueDllType = "struct*"
    Else
        $bBorderValueDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiWarpAffine", $bSrcDllType, $src, $bMDllType, $M, $bDsizeDllType, $dsize, "int", $flags, "int", $borderMode, $bBorderValueDllType, $borderValue), "cveGapiWarpAffine", @error)
EndFunc   ;==>_cveGapiWarpAffine

Func _cveGComputationCreate1($input, $output)
    ; CVAPI(cv::GComputation*) cveGComputationCreate1(cv::GMat* input, cv::GMat* output);

    Local $bInputDllType
    If VarGetType($input) == "DLLStruct" Then
        $bInputDllType = "struct*"
    Else
        $bInputDllType = "ptr"
    EndIf

    Local $bOutputDllType
    If VarGetType($output) == "DLLStruct" Then
        $bOutputDllType = "struct*"
    Else
        $bOutputDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGComputationCreate1", $bInputDllType, $input, $bOutputDllType, $output), "cveGComputationCreate1", @error)
EndFunc   ;==>_cveGComputationCreate1

Func _cveGComputationCreate2($input, $output)
    ; CVAPI(cv::GComputation*) cveGComputationCreate2(cv::GMat* input, cv::GScalar* output);

    Local $bInputDllType
    If VarGetType($input) == "DLLStruct" Then
        $bInputDllType = "struct*"
    Else
        $bInputDllType = "ptr"
    EndIf

    Local $bOutputDllType
    If VarGetType($output) == "DLLStruct" Then
        $bOutputDllType = "struct*"
    Else
        $bOutputDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGComputationCreate2", $bInputDllType, $input, $bOutputDllType, $output), "cveGComputationCreate2", @error)
EndFunc   ;==>_cveGComputationCreate2

Func _cveGComputationCreate3($input1, $input2, $output)
    ; CVAPI(cv::GComputation*) cveGComputationCreate3(cv::GMat* input1, cv::GMat* input2, cv::GMat* output);

    Local $bInput1DllType
    If VarGetType($input1) == "DLLStruct" Then
        $bInput1DllType = "struct*"
    Else
        $bInput1DllType = "ptr"
    EndIf

    Local $bInput2DllType
    If VarGetType($input2) == "DLLStruct" Then
        $bInput2DllType = "struct*"
    Else
        $bInput2DllType = "ptr"
    EndIf

    Local $bOutputDllType
    If VarGetType($output) == "DLLStruct" Then
        $bOutputDllType = "struct*"
    Else
        $bOutputDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGComputationCreate3", $bInput1DllType, $input1, $bInput2DllType, $input2, $bOutputDllType, $output), "cveGComputationCreate3", @error)
EndFunc   ;==>_cveGComputationCreate3

Func _cveGComputationCreate4($input1, $input2, $output)
    ; CVAPI(cv::GComputation*) cveGComputationCreate4(cv::GMat* input1, cv::GMat* input2, cv::GScalar* output);

    Local $bInput1DllType
    If VarGetType($input1) == "DLLStruct" Then
        $bInput1DllType = "struct*"
    Else
        $bInput1DllType = "ptr"
    EndIf

    Local $bInput2DllType
    If VarGetType($input2) == "DLLStruct" Then
        $bInput2DllType = "struct*"
    Else
        $bInput2DllType = "ptr"
    EndIf

    Local $bOutputDllType
    If VarGetType($output) == "DLLStruct" Then
        $bOutputDllType = "struct*"
    Else
        $bOutputDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGComputationCreate4", $bInput1DllType, $input1, $bInput2DllType, $input2, $bOutputDllType, $output), "cveGComputationCreate4", @error)
EndFunc   ;==>_cveGComputationCreate4

Func _cveGComputationCreate5($ins, $outs)
    ; CVAPI(cv::GComputation*) cveGComputationCreate5(std::vector< cv::GMat >* ins, std::vector< cv::GMat >* outs);

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

    Local $bInsDllType
    If VarGetType($ins) == "DLLStruct" Then
        $bInsDllType = "struct*"
    Else
        $bInsDllType = "ptr"
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

    Local $bOutsDllType
    If VarGetType($outs) == "DLLStruct" Then
        $bOutsDllType = "struct*"
    Else
        $bOutsDllType = "ptr"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGComputationCreate5", $bInsDllType, $vecIns, $bOutsDllType, $vecOuts), "cveGComputationCreate5", @error)

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

    Local $bComputationDllType
    If VarGetType($computation) == "DLLStruct" Then
        $bComputationDllType = "struct*"
    Else
        $bComputationDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveGComputationRelease", $bComputationDllType, $computation), "cveGComputationRelease", @error)
EndFunc   ;==>_cveGComputationRelease

Func _cveGComputationApply1($computation, $input, $output)
    ; CVAPI(void) cveGComputationApply1(cv::GComputation* computation, cv::Mat* input, cv::Mat* output);

    Local $bComputationDllType
    If VarGetType($computation) == "DLLStruct" Then
        $bComputationDllType = "struct*"
    Else
        $bComputationDllType = "ptr"
    EndIf

    Local $bInputDllType
    If VarGetType($input) == "DLLStruct" Then
        $bInputDllType = "struct*"
    Else
        $bInputDllType = "ptr"
    EndIf

    Local $bOutputDllType
    If VarGetType($output) == "DLLStruct" Then
        $bOutputDllType = "struct*"
    Else
        $bOutputDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveGComputationApply1", $bComputationDllType, $computation, $bInputDllType, $input, $bOutputDllType, $output), "cveGComputationApply1", @error)
EndFunc   ;==>_cveGComputationApply1

Func _cveGComputationApply2($computation, $input, $output)
    ; CVAPI(void) cveGComputationApply2(cv::GComputation* computation, cv::Mat* input, CvScalar* output);

    Local $bComputationDllType
    If VarGetType($computation) == "DLLStruct" Then
        $bComputationDllType = "struct*"
    Else
        $bComputationDllType = "ptr"
    EndIf

    Local $bInputDllType
    If VarGetType($input) == "DLLStruct" Then
        $bInputDllType = "struct*"
    Else
        $bInputDllType = "ptr"
    EndIf

    Local $bOutputDllType
    If VarGetType($output) == "DLLStruct" Then
        $bOutputDllType = "struct*"
    Else
        $bOutputDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveGComputationApply2", $bComputationDllType, $computation, $bInputDllType, $input, $bOutputDllType, $output), "cveGComputationApply2", @error)
EndFunc   ;==>_cveGComputationApply2

Func _cveGComputationApply3($computation, $input1, $input2, $output)
    ; CVAPI(void) cveGComputationApply3(cv::GComputation* computation, cv::Mat* input1, cv::Mat* input2, cv::Mat* output);

    Local $bComputationDllType
    If VarGetType($computation) == "DLLStruct" Then
        $bComputationDllType = "struct*"
    Else
        $bComputationDllType = "ptr"
    EndIf

    Local $bInput1DllType
    If VarGetType($input1) == "DLLStruct" Then
        $bInput1DllType = "struct*"
    Else
        $bInput1DllType = "ptr"
    EndIf

    Local $bInput2DllType
    If VarGetType($input2) == "DLLStruct" Then
        $bInput2DllType = "struct*"
    Else
        $bInput2DllType = "ptr"
    EndIf

    Local $bOutputDllType
    If VarGetType($output) == "DLLStruct" Then
        $bOutputDllType = "struct*"
    Else
        $bOutputDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveGComputationApply3", $bComputationDllType, $computation, $bInput1DllType, $input1, $bInput2DllType, $input2, $bOutputDllType, $output), "cveGComputationApply3", @error)
EndFunc   ;==>_cveGComputationApply3

Func _cveGComputationApply4($computation, $input1, $input2, $output)
    ; CVAPI(void) cveGComputationApply4(cv::GComputation* computation, cv::Mat* input1, cv::Mat* input2, CvScalar* output);

    Local $bComputationDllType
    If VarGetType($computation) == "DLLStruct" Then
        $bComputationDllType = "struct*"
    Else
        $bComputationDllType = "ptr"
    EndIf

    Local $bInput1DllType
    If VarGetType($input1) == "DLLStruct" Then
        $bInput1DllType = "struct*"
    Else
        $bInput1DllType = "ptr"
    EndIf

    Local $bInput2DllType
    If VarGetType($input2) == "DLLStruct" Then
        $bInput2DllType = "struct*"
    Else
        $bInput2DllType = "ptr"
    EndIf

    Local $bOutputDllType
    If VarGetType($output) == "DLLStruct" Then
        $bOutputDllType = "struct*"
    Else
        $bOutputDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveGComputationApply4", $bComputationDllType, $computation, $bInput1DllType, $input1, $bInput2DllType, $input2, $bOutputDllType, $output), "cveGComputationApply4", @error)
EndFunc   ;==>_cveGComputationApply4

Func _cveGComputationApply5($computation, $inputs, $outputs)
    ; CVAPI(void) cveGComputationApply5(cv::GComputation* computation, std::vector< cv::Mat >* inputs, std::vector< cv::Mat >* outputs);

    Local $bComputationDllType
    If VarGetType($computation) == "DLLStruct" Then
        $bComputationDllType = "struct*"
    Else
        $bComputationDllType = "ptr"
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

    Local $bInputsDllType
    If VarGetType($inputs) == "DLLStruct" Then
        $bInputsDllType = "struct*"
    Else
        $bInputsDllType = "ptr"
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

    Local $bOutputsDllType
    If VarGetType($outputs) == "DLLStruct" Then
        $bOutputsDllType = "struct*"
    Else
        $bOutputsDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveGComputationApply5", $bComputationDllType, $computation, $bInputsDllType, $vecInputs, $bOutputsDllType, $vecOutputs), "cveGComputationApply5", @error)

    If $bOutputsIsArray Then
        _VectorOfMatRelease($vecOutputs)
    EndIf

    If $bInputsIsArray Then
        _VectorOfMatRelease($vecInputs)
    EndIf
EndFunc   ;==>_cveGComputationApply5

Func _cveGScalarCreate($value)
    ; CVAPI(cv::GScalar*) cveGScalarCreate(CvScalar* value);

    Local $bValueDllType
    If VarGetType($value) == "DLLStruct" Then
        $bValueDllType = "struct*"
    Else
        $bValueDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGScalarCreate", $bValueDllType, $value), "cveGScalarCreate", @error)
EndFunc   ;==>_cveGScalarCreate

Func _cveGScalarRelease($gscalar)
    ; CVAPI(void) cveGScalarRelease(cv::GScalar** gscalar);

    Local $bGscalarDllType
    If VarGetType($gscalar) == "DLLStruct" Then
        $bGscalarDllType = "struct*"
    Else
        $bGscalarDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveGScalarRelease", $bGscalarDllType, $gscalar), "cveGScalarRelease", @error)
EndFunc   ;==>_cveGScalarRelease

Func _cveGapiSepFilter($src, $ddepth, $kernelX, $kernelY, $anchor, $delta, $borderType, $borderValue)
    ; CVAPI(cv::GMat*) cveGapiSepFilter(cv::GMat* src, int ddepth, cv::Mat* kernelX, cv::Mat* kernelY, CvPoint* anchor, CvScalar* delta, int borderType, CvScalar* borderValue);

    Local $bSrcDllType
    If VarGetType($src) == "DLLStruct" Then
        $bSrcDllType = "struct*"
    Else
        $bSrcDllType = "ptr"
    EndIf

    Local $bKernelXDllType
    If VarGetType($kernelX) == "DLLStruct" Then
        $bKernelXDllType = "struct*"
    Else
        $bKernelXDllType = "ptr"
    EndIf

    Local $bKernelYDllType
    If VarGetType($kernelY) == "DLLStruct" Then
        $bKernelYDllType = "struct*"
    Else
        $bKernelYDllType = "ptr"
    EndIf

    Local $bAnchorDllType
    If VarGetType($anchor) == "DLLStruct" Then
        $bAnchorDllType = "struct*"
    Else
        $bAnchorDllType = "ptr"
    EndIf

    Local $bDeltaDllType
    If VarGetType($delta) == "DLLStruct" Then
        $bDeltaDllType = "struct*"
    Else
        $bDeltaDllType = "ptr"
    EndIf

    Local $bBorderValueDllType
    If VarGetType($borderValue) == "DLLStruct" Then
        $bBorderValueDllType = "struct*"
    Else
        $bBorderValueDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiSepFilter", $bSrcDllType, $src, "int", $ddepth, $bKernelXDllType, $kernelX, $bKernelYDllType, $kernelY, $bAnchorDllType, $anchor, $bDeltaDllType, $delta, "int", $borderType, $bBorderValueDllType, $borderValue), "cveGapiSepFilter", @error)
EndFunc   ;==>_cveGapiSepFilter

Func _cveGapiFilter2D($src, $ddepth, $kernel, $anchor, $delta, $borderType, $borderValue)
    ; CVAPI(cv::GMat*) cveGapiFilter2D(cv::GMat* src, int ddepth, cv::Mat* kernel, CvPoint* anchor, CvScalar* delta, int borderType, CvScalar* borderValue);

    Local $bSrcDllType
    If VarGetType($src) == "DLLStruct" Then
        $bSrcDllType = "struct*"
    Else
        $bSrcDllType = "ptr"
    EndIf

    Local $bKernelDllType
    If VarGetType($kernel) == "DLLStruct" Then
        $bKernelDllType = "struct*"
    Else
        $bKernelDllType = "ptr"
    EndIf

    Local $bAnchorDllType
    If VarGetType($anchor) == "DLLStruct" Then
        $bAnchorDllType = "struct*"
    Else
        $bAnchorDllType = "ptr"
    EndIf

    Local $bDeltaDllType
    If VarGetType($delta) == "DLLStruct" Then
        $bDeltaDllType = "struct*"
    Else
        $bDeltaDllType = "ptr"
    EndIf

    Local $bBorderValueDllType
    If VarGetType($borderValue) == "DLLStruct" Then
        $bBorderValueDllType = "struct*"
    Else
        $bBorderValueDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiFilter2D", $bSrcDllType, $src, "int", $ddepth, $bKernelDllType, $kernel, $bAnchorDllType, $anchor, $bDeltaDllType, $delta, "int", $borderType, $bBorderValueDllType, $borderValue), "cveGapiFilter2D", @error)
EndFunc   ;==>_cveGapiFilter2D

Func _cveGapiBoxFilter($src, $dtype, $ksize, $anchor, $normalize, $borderType, $borderValue)
    ; CVAPI(cv::GMat*) cveGapiBoxFilter(cv::GMat* src, int dtype, CvSize* ksize, CvPoint* anchor, bool normalize, int borderType, CvScalar* borderValue);

    Local $bSrcDllType
    If VarGetType($src) == "DLLStruct" Then
        $bSrcDllType = "struct*"
    Else
        $bSrcDllType = "ptr"
    EndIf

    Local $bKsizeDllType
    If VarGetType($ksize) == "DLLStruct" Then
        $bKsizeDllType = "struct*"
    Else
        $bKsizeDllType = "ptr"
    EndIf

    Local $bAnchorDllType
    If VarGetType($anchor) == "DLLStruct" Then
        $bAnchorDllType = "struct*"
    Else
        $bAnchorDllType = "ptr"
    EndIf

    Local $bBorderValueDllType
    If VarGetType($borderValue) == "DLLStruct" Then
        $bBorderValueDllType = "struct*"
    Else
        $bBorderValueDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiBoxFilter", $bSrcDllType, $src, "int", $dtype, $bKsizeDllType, $ksize, $bAnchorDllType, $anchor, "boolean", $normalize, "int", $borderType, $bBorderValueDllType, $borderValue), "cveGapiBoxFilter", @error)
EndFunc   ;==>_cveGapiBoxFilter

Func _cveGapiBlur($src, $ksize, $anchor, $borderType, $borderValue)
    ; CVAPI(cv::GMat*) cveGapiBlur(cv::GMat* src, CvSize* ksize, CvPoint* anchor, int borderType, CvScalar* borderValue);

    Local $bSrcDllType
    If VarGetType($src) == "DLLStruct" Then
        $bSrcDllType = "struct*"
    Else
        $bSrcDllType = "ptr"
    EndIf

    Local $bKsizeDllType
    If VarGetType($ksize) == "DLLStruct" Then
        $bKsizeDllType = "struct*"
    Else
        $bKsizeDllType = "ptr"
    EndIf

    Local $bAnchorDllType
    If VarGetType($anchor) == "DLLStruct" Then
        $bAnchorDllType = "struct*"
    Else
        $bAnchorDllType = "ptr"
    EndIf

    Local $bBorderValueDllType
    If VarGetType($borderValue) == "DLLStruct" Then
        $bBorderValueDllType = "struct*"
    Else
        $bBorderValueDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiBlur", $bSrcDllType, $src, $bKsizeDllType, $ksize, $bAnchorDllType, $anchor, "int", $borderType, $bBorderValueDllType, $borderValue), "cveGapiBlur", @error)
EndFunc   ;==>_cveGapiBlur

Func _cveGapiGaussianBlur($src, $ksize, $sigmaX, $sigmaY, $borderType, $borderValue)
    ; CVAPI(cv::GMat*) cveGapiGaussianBlur(cv::GMat* src, CvSize* ksize, double sigmaX, double sigmaY, int borderType, CvScalar* borderValue);

    Local $bSrcDllType
    If VarGetType($src) == "DLLStruct" Then
        $bSrcDllType = "struct*"
    Else
        $bSrcDllType = "ptr"
    EndIf

    Local $bKsizeDllType
    If VarGetType($ksize) == "DLLStruct" Then
        $bKsizeDllType = "struct*"
    Else
        $bKsizeDllType = "ptr"
    EndIf

    Local $bBorderValueDllType
    If VarGetType($borderValue) == "DLLStruct" Then
        $bBorderValueDllType = "struct*"
    Else
        $bBorderValueDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiGaussianBlur", $bSrcDllType, $src, $bKsizeDllType, $ksize, "double", $sigmaX, "double", $sigmaY, "int", $borderType, $bBorderValueDllType, $borderValue), "cveGapiGaussianBlur", @error)
EndFunc   ;==>_cveGapiGaussianBlur

Func _cveGapiMedianBlur($src, $ksize)
    ; CVAPI(cv::GMat*) cveGapiMedianBlur(cv::GMat* src, int ksize);

    Local $bSrcDllType
    If VarGetType($src) == "DLLStruct" Then
        $bSrcDllType = "struct*"
    Else
        $bSrcDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiMedianBlur", $bSrcDllType, $src, "int", $ksize), "cveGapiMedianBlur", @error)
EndFunc   ;==>_cveGapiMedianBlur

Func _cveGapiErode($src, $kernel, $anchor, $iterations, $borderType, $borderValue)
    ; CVAPI(cv::GMat*) cveGapiErode(cv::GMat* src, cv::Mat* kernel, CvPoint* anchor, int iterations, int borderType, CvScalar* borderValue);

    Local $bSrcDllType
    If VarGetType($src) == "DLLStruct" Then
        $bSrcDllType = "struct*"
    Else
        $bSrcDllType = "ptr"
    EndIf

    Local $bKernelDllType
    If VarGetType($kernel) == "DLLStruct" Then
        $bKernelDllType = "struct*"
    Else
        $bKernelDllType = "ptr"
    EndIf

    Local $bAnchorDllType
    If VarGetType($anchor) == "DLLStruct" Then
        $bAnchorDllType = "struct*"
    Else
        $bAnchorDllType = "ptr"
    EndIf

    Local $bBorderValueDllType
    If VarGetType($borderValue) == "DLLStruct" Then
        $bBorderValueDllType = "struct*"
    Else
        $bBorderValueDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiErode", $bSrcDllType, $src, $bKernelDllType, $kernel, $bAnchorDllType, $anchor, "int", $iterations, "int", $borderType, $bBorderValueDllType, $borderValue), "cveGapiErode", @error)
EndFunc   ;==>_cveGapiErode

Func _cveGapiErode3x3($src, $iterations, $borderType, $borderValue)
    ; CVAPI(cv::GMat*) cveGapiErode3x3(cv::GMat* src, int iterations, int borderType, CvScalar* borderValue);

    Local $bSrcDllType
    If VarGetType($src) == "DLLStruct" Then
        $bSrcDllType = "struct*"
    Else
        $bSrcDllType = "ptr"
    EndIf

    Local $bBorderValueDllType
    If VarGetType($borderValue) == "DLLStruct" Then
        $bBorderValueDllType = "struct*"
    Else
        $bBorderValueDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiErode3x3", $bSrcDllType, $src, "int", $iterations, "int", $borderType, $bBorderValueDllType, $borderValue), "cveGapiErode3x3", @error)
EndFunc   ;==>_cveGapiErode3x3

Func _cveGapiDilate($src, $kernel, $anchor, $iterations, $borderType, $borderValue)
    ; CVAPI(cv::GMat*) cveGapiDilate(cv::GMat* src, cv::Mat* kernel, CvPoint* anchor, int iterations, int borderType, CvScalar* borderValue);

    Local $bSrcDllType
    If VarGetType($src) == "DLLStruct" Then
        $bSrcDllType = "struct*"
    Else
        $bSrcDllType = "ptr"
    EndIf

    Local $bKernelDllType
    If VarGetType($kernel) == "DLLStruct" Then
        $bKernelDllType = "struct*"
    Else
        $bKernelDllType = "ptr"
    EndIf

    Local $bAnchorDllType
    If VarGetType($anchor) == "DLLStruct" Then
        $bAnchorDllType = "struct*"
    Else
        $bAnchorDllType = "ptr"
    EndIf

    Local $bBorderValueDllType
    If VarGetType($borderValue) == "DLLStruct" Then
        $bBorderValueDllType = "struct*"
    Else
        $bBorderValueDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiDilate", $bSrcDllType, $src, $bKernelDllType, $kernel, $bAnchorDllType, $anchor, "int", $iterations, "int", $borderType, $bBorderValueDllType, $borderValue), "cveGapiDilate", @error)
EndFunc   ;==>_cveGapiDilate

Func _cveGapiDilate3x3($src, $iterations, $borderType, $borderValue)
    ; CVAPI(cv::GMat*) cveGapiDilate3x3(cv::GMat* src, int iterations, int borderType, CvScalar* borderValue);

    Local $bSrcDllType
    If VarGetType($src) == "DLLStruct" Then
        $bSrcDllType = "struct*"
    Else
        $bSrcDllType = "ptr"
    EndIf

    Local $bBorderValueDllType
    If VarGetType($borderValue) == "DLLStruct" Then
        $bBorderValueDllType = "struct*"
    Else
        $bBorderValueDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiDilate3x3", $bSrcDllType, $src, "int", $iterations, "int", $borderType, $bBorderValueDllType, $borderValue), "cveGapiDilate3x3", @error)
EndFunc   ;==>_cveGapiDilate3x3

Func _cveGapiMorphologyEx($src, $op, $kernel, $anchor, $iterations, $borderType, $borderValue)
    ; CVAPI(cv::GMat*) cveGapiMorphologyEx(cv::GMat* src, int op, cv::Mat* kernel, CvPoint* anchor, int iterations, int borderType, CvScalar* borderValue);

    Local $bSrcDllType
    If VarGetType($src) == "DLLStruct" Then
        $bSrcDllType = "struct*"
    Else
        $bSrcDllType = "ptr"
    EndIf

    Local $bKernelDllType
    If VarGetType($kernel) == "DLLStruct" Then
        $bKernelDllType = "struct*"
    Else
        $bKernelDllType = "ptr"
    EndIf

    Local $bAnchorDllType
    If VarGetType($anchor) == "DLLStruct" Then
        $bAnchorDllType = "struct*"
    Else
        $bAnchorDllType = "ptr"
    EndIf

    Local $bBorderValueDllType
    If VarGetType($borderValue) == "DLLStruct" Then
        $bBorderValueDllType = "struct*"
    Else
        $bBorderValueDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiMorphologyEx", $bSrcDllType, $src, "int", $op, $bKernelDllType, $kernel, $bAnchorDllType, $anchor, "int", $iterations, "int", $borderType, $bBorderValueDllType, $borderValue), "cveGapiMorphologyEx", @error)
EndFunc   ;==>_cveGapiMorphologyEx

Func _cveGapiSobel($src, $ddepth, $dx, $dy, $ksize, $scale, $delta, $borderType, $borderValue)
    ; CVAPI(cv::GMat*) cveGapiSobel(cv::GMat* src, int ddepth, int dx, int dy, int ksize, double scale, double delta, int borderType, CvScalar* borderValue);

    Local $bSrcDllType
    If VarGetType($src) == "DLLStruct" Then
        $bSrcDllType = "struct*"
    Else
        $bSrcDllType = "ptr"
    EndIf

    Local $bBorderValueDllType
    If VarGetType($borderValue) == "DLLStruct" Then
        $bBorderValueDllType = "struct*"
    Else
        $bBorderValueDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiSobel", $bSrcDllType, $src, "int", $ddepth, "int", $dx, "int", $dy, "int", $ksize, "double", $scale, "double", $delta, "int", $borderType, $bBorderValueDllType, $borderValue), "cveGapiSobel", @error)
EndFunc   ;==>_cveGapiSobel

Func _cveGapiSobelXY($src, $ddepth, $order, $ksize, $scale, $delta, $borderType, $borderValue, $sobelX, $sobelY)
    ; CVAPI(void) cveGapiSobelXY(cv::GMat* src, int ddepth, int order, int ksize, double scale, double delta, int borderType, CvScalar* borderValue, cv::GMat* sobelX, cv::GMat* sobelY);

    Local $bSrcDllType
    If VarGetType($src) == "DLLStruct" Then
        $bSrcDllType = "struct*"
    Else
        $bSrcDllType = "ptr"
    EndIf

    Local $bBorderValueDllType
    If VarGetType($borderValue) == "DLLStruct" Then
        $bBorderValueDllType = "struct*"
    Else
        $bBorderValueDllType = "ptr"
    EndIf

    Local $bSobelXDllType
    If VarGetType($sobelX) == "DLLStruct" Then
        $bSobelXDllType = "struct*"
    Else
        $bSobelXDllType = "ptr"
    EndIf

    Local $bSobelYDllType
    If VarGetType($sobelY) == "DLLStruct" Then
        $bSobelYDllType = "struct*"
    Else
        $bSobelYDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveGapiSobelXY", $bSrcDllType, $src, "int", $ddepth, "int", $order, "int", $ksize, "double", $scale, "double", $delta, "int", $borderType, $bBorderValueDllType, $borderValue, $bSobelXDllType, $sobelX, $bSobelYDllType, $sobelY), "cveGapiSobelXY", @error)
EndFunc   ;==>_cveGapiSobelXY

Func _cveGapiLaplacian($src, $ddepth, $ksize, $scale, $delta, $borderType)
    ; CVAPI(cv::GMat*) cveGapiLaplacian(cv::GMat* src, int ddepth, int ksize, double scale, double delta, int borderType);

    Local $bSrcDllType
    If VarGetType($src) == "DLLStruct" Then
        $bSrcDllType = "struct*"
    Else
        $bSrcDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiLaplacian", $bSrcDllType, $src, "int", $ddepth, "int", $ksize, "double", $scale, "double", $delta, "int", $borderType), "cveGapiLaplacian", @error)
EndFunc   ;==>_cveGapiLaplacian

Func _cveGapiBilateralFilter($src, $d, $sigmaColor, $sigmaSpace, $borderType)
    ; CVAPI(cv::GMat*) cveGapiBilateralFilter(cv::GMat* src, int d, double sigmaColor, double sigmaSpace, int borderType);

    Local $bSrcDllType
    If VarGetType($src) == "DLLStruct" Then
        $bSrcDllType = "struct*"
    Else
        $bSrcDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiBilateralFilter", $bSrcDllType, $src, "int", $d, "double", $sigmaColor, "double", $sigmaSpace, "int", $borderType), "cveGapiBilateralFilter", @error)
EndFunc   ;==>_cveGapiBilateralFilter

Func _cveGapiCanny($image, $threshold1, $threshold2, $apertureSize, $L2gradient)
    ; CVAPI(cv::GMat*) cveGapiCanny(cv::GMat* image, double threshold1, double threshold2, int apertureSize, bool L2gradient);

    Local $bImageDllType
    If VarGetType($image) == "DLLStruct" Then
        $bImageDllType = "struct*"
    Else
        $bImageDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiCanny", $bImageDllType, $image, "double", $threshold1, "double", $threshold2, "int", $apertureSize, "boolean", $L2gradient), "cveGapiCanny", @error)
EndFunc   ;==>_cveGapiCanny

Func _cveGapiEqualizeHist($src)
    ; CVAPI(cv::GMat*) cveGapiEqualizeHist(cv::GMat* src);

    Local $bSrcDllType
    If VarGetType($src) == "DLLStruct" Then
        $bSrcDllType = "struct*"
    Else
        $bSrcDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiEqualizeHist", $bSrcDllType, $src), "cveGapiEqualizeHist", @error)
EndFunc   ;==>_cveGapiEqualizeHist

Func _cveGapiBGR2RGB($src)
    ; CVAPI(cv::GMat*) cveGapiBGR2RGB(cv::GMat* src);

    Local $bSrcDllType
    If VarGetType($src) == "DLLStruct" Then
        $bSrcDllType = "struct*"
    Else
        $bSrcDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiBGR2RGB", $bSrcDllType, $src), "cveGapiBGR2RGB", @error)
EndFunc   ;==>_cveGapiBGR2RGB

Func _cveGapiRGB2Gray1($src)
    ; CVAPI(cv::GMat*) cveGapiRGB2Gray1(cv::GMat* src);

    Local $bSrcDllType
    If VarGetType($src) == "DLLStruct" Then
        $bSrcDllType = "struct*"
    Else
        $bSrcDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiRGB2Gray1", $bSrcDllType, $src), "cveGapiRGB2Gray1", @error)
EndFunc   ;==>_cveGapiRGB2Gray1

Func _cveGapiRGB2Gray2($src, $rY, $gY, $bY)
    ; CVAPI(cv::GMat*) cveGapiRGB2Gray2(cv::GMat* src, float rY, float gY, float bY);

    Local $bSrcDllType
    If VarGetType($src) == "DLLStruct" Then
        $bSrcDllType = "struct*"
    Else
        $bSrcDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiRGB2Gray2", $bSrcDllType, $src, "float", $rY, "float", $gY, "float", $bY), "cveGapiRGB2Gray2", @error)
EndFunc   ;==>_cveGapiRGB2Gray2

Func _cveGapiBGR2Gray($src)
    ; CVAPI(cv::GMat*) cveGapiBGR2Gray(cv::GMat* src);

    Local $bSrcDllType
    If VarGetType($src) == "DLLStruct" Then
        $bSrcDllType = "struct*"
    Else
        $bSrcDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiBGR2Gray", $bSrcDllType, $src), "cveGapiBGR2Gray", @error)
EndFunc   ;==>_cveGapiBGR2Gray

Func _cveGapiRGB2YUV($src)
    ; CVAPI(cv::GMat*) cveGapiRGB2YUV(cv::GMat* src);

    Local $bSrcDllType
    If VarGetType($src) == "DLLStruct" Then
        $bSrcDllType = "struct*"
    Else
        $bSrcDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiRGB2YUV", $bSrcDllType, $src), "cveGapiRGB2YUV", @error)
EndFunc   ;==>_cveGapiRGB2YUV

Func _cveGapiBGR2I420($src)
    ; CVAPI(cv::GMat*) cveGapiBGR2I420(cv::GMat* src);

    Local $bSrcDllType
    If VarGetType($src) == "DLLStruct" Then
        $bSrcDllType = "struct*"
    Else
        $bSrcDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiBGR2I420", $bSrcDllType, $src), "cveGapiBGR2I420", @error)
EndFunc   ;==>_cveGapiBGR2I420

Func _cveGapiRGB2I420($src)
    ; CVAPI(cv::GMat*) cveGapiRGB2I420(cv::GMat* src);

    Local $bSrcDllType
    If VarGetType($src) == "DLLStruct" Then
        $bSrcDllType = "struct*"
    Else
        $bSrcDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiRGB2I420", $bSrcDllType, $src), "cveGapiRGB2I420", @error)
EndFunc   ;==>_cveGapiRGB2I420

Func _cveGapiI4202BGR($src)
    ; CVAPI(cv::GMat*) cveGapiI4202BGR(cv::GMat* src);

    Local $bSrcDllType
    If VarGetType($src) == "DLLStruct" Then
        $bSrcDllType = "struct*"
    Else
        $bSrcDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiI4202BGR", $bSrcDllType, $src), "cveGapiI4202BGR", @error)
EndFunc   ;==>_cveGapiI4202BGR

Func _cveGapiI4202RGB($src)
    ; CVAPI(cv::GMat*) cveGapiI4202RGB(cv::GMat* src);

    Local $bSrcDllType
    If VarGetType($src) == "DLLStruct" Then
        $bSrcDllType = "struct*"
    Else
        $bSrcDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiI4202RGB", $bSrcDllType, $src), "cveGapiI4202RGB", @error)
EndFunc   ;==>_cveGapiI4202RGB

Func _cveGapiBGR2LUV($src)
    ; CVAPI(cv::GMat*) cveGapiBGR2LUV(cv::GMat* src);

    Local $bSrcDllType
    If VarGetType($src) == "DLLStruct" Then
        $bSrcDllType = "struct*"
    Else
        $bSrcDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiBGR2LUV", $bSrcDllType, $src), "cveGapiBGR2LUV", @error)
EndFunc   ;==>_cveGapiBGR2LUV

Func _cveGapiLUV2BGR($src)
    ; CVAPI(cv::GMat*) cveGapiLUV2BGR(cv::GMat* src);

    Local $bSrcDllType
    If VarGetType($src) == "DLLStruct" Then
        $bSrcDllType = "struct*"
    Else
        $bSrcDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiLUV2BGR", $bSrcDllType, $src), "cveGapiLUV2BGR", @error)
EndFunc   ;==>_cveGapiLUV2BGR

Func _cveGapiYUV2BGR($src)
    ; CVAPI(cv::GMat*) cveGapiYUV2BGR(cv::GMat* src);

    Local $bSrcDllType
    If VarGetType($src) == "DLLStruct" Then
        $bSrcDllType = "struct*"
    Else
        $bSrcDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiYUV2BGR", $bSrcDllType, $src), "cveGapiYUV2BGR", @error)
EndFunc   ;==>_cveGapiYUV2BGR

Func _cveGapiBGR2YUV($src)
    ; CVAPI(cv::GMat*) cveGapiBGR2YUV(cv::GMat* src);

    Local $bSrcDllType
    If VarGetType($src) == "DLLStruct" Then
        $bSrcDllType = "struct*"
    Else
        $bSrcDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiBGR2YUV", $bSrcDllType, $src), "cveGapiBGR2YUV", @error)
EndFunc   ;==>_cveGapiBGR2YUV

Func _cveGapiRGB2Lab($src)
    ; CVAPI(cv::GMat*) cveGapiRGB2Lab(cv::GMat* src);

    Local $bSrcDllType
    If VarGetType($src) == "DLLStruct" Then
        $bSrcDllType = "struct*"
    Else
        $bSrcDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiRGB2Lab", $bSrcDllType, $src), "cveGapiRGB2Lab", @error)
EndFunc   ;==>_cveGapiRGB2Lab

Func _cveGapiYUV2RGB($src)
    ; CVAPI(cv::GMat*) cveGapiYUV2RGB(cv::GMat* src);

    Local $bSrcDllType
    If VarGetType($src) == "DLLStruct" Then
        $bSrcDllType = "struct*"
    Else
        $bSrcDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiYUV2RGB", $bSrcDllType, $src), "cveGapiYUV2RGB", @error)
EndFunc   ;==>_cveGapiYUV2RGB

Func _cveGapiNV12toRGB($srcY, $srcUV)
    ; CVAPI(cv::GMat*) cveGapiNV12toRGB(cv::GMat* srcY, cv::GMat* srcUV);

    Local $bSrcYDllType
    If VarGetType($srcY) == "DLLStruct" Then
        $bSrcYDllType = "struct*"
    Else
        $bSrcYDllType = "ptr"
    EndIf

    Local $bSrcUVDllType
    If VarGetType($srcUV) == "DLLStruct" Then
        $bSrcUVDllType = "struct*"
    Else
        $bSrcUVDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiNV12toRGB", $bSrcYDllType, $srcY, $bSrcUVDllType, $srcUV), "cveGapiNV12toRGB", @error)
EndFunc   ;==>_cveGapiNV12toRGB

Func _cveGapiNV12toGray($srcY, $srcUV)
    ; CVAPI(cv::GMat*) cveGapiNV12toGray(cv::GMat* srcY, cv::GMat* srcUV);

    Local $bSrcYDllType
    If VarGetType($srcY) == "DLLStruct" Then
        $bSrcYDllType = "struct*"
    Else
        $bSrcYDllType = "ptr"
    EndIf

    Local $bSrcUVDllType
    If VarGetType($srcUV) == "DLLStruct" Then
        $bSrcUVDllType = "struct*"
    Else
        $bSrcUVDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiNV12toGray", $bSrcYDllType, $srcY, $bSrcUVDllType, $srcUV), "cveGapiNV12toGray", @error)
EndFunc   ;==>_cveGapiNV12toGray

Func _cveGapiNV12toBGR($srcY, $srcUV)
    ; CVAPI(cv::GMat*) cveGapiNV12toBGR(cv::GMat* srcY, cv::GMat* srcUV);

    Local $bSrcYDllType
    If VarGetType($srcY) == "DLLStruct" Then
        $bSrcYDllType = "struct*"
    Else
        $bSrcYDllType = "ptr"
    EndIf

    Local $bSrcUVDllType
    If VarGetType($srcUV) == "DLLStruct" Then
        $bSrcUVDllType = "struct*"
    Else
        $bSrcUVDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiNV12toBGR", $bSrcYDllType, $srcY, $bSrcUVDllType, $srcUV), "cveGapiNV12toBGR", @error)
EndFunc   ;==>_cveGapiNV12toBGR

Func _cveGapiBayerGR2RGB($srcGR)
    ; CVAPI(cv::GMat*) cveGapiBayerGR2RGB(cv::GMat* srcGR);

    Local $bSrcGRDllType
    If VarGetType($srcGR) == "DLLStruct" Then
        $bSrcGRDllType = "struct*"
    Else
        $bSrcGRDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiBayerGR2RGB", $bSrcGRDllType, $srcGR), "cveGapiBayerGR2RGB", @error)
EndFunc   ;==>_cveGapiBayerGR2RGB

Func _cveGapiRGB2HSV($src)
    ; CVAPI(cv::GMat*) cveGapiRGB2HSV(cv::GMat* src);

    Local $bSrcDllType
    If VarGetType($src) == "DLLStruct" Then
        $bSrcDllType = "struct*"
    Else
        $bSrcDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiRGB2HSV", $bSrcDllType, $src), "cveGapiRGB2HSV", @error)
EndFunc   ;==>_cveGapiRGB2HSV

Func _cveGapiRGB2YUV422($src)
    ; CVAPI(cv::GMat*) cveGapiRGB2YUV422(cv::GMat* src);

    Local $bSrcDllType
    If VarGetType($src) == "DLLStruct" Then
        $bSrcDllType = "struct*"
    Else
        $bSrcDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiRGB2YUV422", $bSrcDllType, $src), "cveGapiRGB2YUV422", @error)
EndFunc   ;==>_cveGapiRGB2YUV422