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
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiAdd", "ptr", $src1, "ptr", $src2, "int", $ddepth), "cveGapiAdd", @error)
EndFunc   ;==>_cveGapiAdd

Func _cveGapiAddC($src1, $c, $ddepth)
    ; CVAPI(cv::GMat*) cveGapiAddC(cv::GMat* src1, cv::GScalar* c, int ddepth);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiAddC", "ptr", $src1, "ptr", $c, "int", $ddepth), "cveGapiAddC", @error)
EndFunc   ;==>_cveGapiAddC

Func _cveGapiSub($src1, $src2, $ddepth)
    ; CVAPI(cv::GMat*) cveGapiSub(cv::GMat* src1, cv::GMat* src2, int ddepth);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiSub", "ptr", $src1, "ptr", $src2, "int", $ddepth), "cveGapiSub", @error)
EndFunc   ;==>_cveGapiSub

Func _cveGapiSubC($src1, $c, $ddepth)
    ; CVAPI(cv::GMat*) cveGapiSubC(cv::GMat* src1, cv::GScalar* c, int ddepth);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiSubC", "ptr", $src1, "ptr", $c, "int", $ddepth), "cveGapiSubC", @error)
EndFunc   ;==>_cveGapiSubC

Func _cveGapiSubRC($c, $src1, $ddepth)
    ; CVAPI(cv::GMat*) cveGapiSubRC(cv::GScalar* c, cv::GMat* src1, int ddepth);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiSubRC", "ptr", $c, "ptr", $src1, "int", $ddepth), "cveGapiSubRC", @error)
EndFunc   ;==>_cveGapiSubRC

Func _cveGapiMul($src1, $src2, $scale, $ddepth)
    ; CVAPI(cv::GMat*) cveGapiMul(cv::GMat* src1, cv::GMat* src2, double scale, int ddepth);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiMul", "ptr", $src1, "ptr", $src2, "double", $scale, "int", $ddepth), "cveGapiMul", @error)
EndFunc   ;==>_cveGapiMul

Func _cveGapiMulC($src, $scale, $ddepth)
    ; CVAPI(cv::GMat*) cveGapiMulC(cv::GMat* src, cv::GScalar* scale, int ddepth);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiMulC", "ptr", $src, "ptr", $scale, "int", $ddepth), "cveGapiMulC", @error)
EndFunc   ;==>_cveGapiMulC

Func _cveGapiDiv($src1, $src2, $scale, $ddepth)
    ; CVAPI(cv::GMat*) cveGapiDiv(cv::GMat* src1, cv::GMat* src2, double scale, int ddepth);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiDiv", "ptr", $src1, "ptr", $src2, "double", $scale, "int", $ddepth), "cveGapiDiv", @error)
EndFunc   ;==>_cveGapiDiv

Func _cveGapiDivC($src, $divisor, $scale, $ddepth)
    ; CVAPI(cv::GMat*) cveGapiDivC(cv::GMat* src, cv::GScalar* divisor, double scale, int ddepth);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiDivC", "ptr", $src, "ptr", $divisor, "double", $scale, "int", $ddepth), "cveGapiDivC", @error)
EndFunc   ;==>_cveGapiDivC

Func _cveGapiDivRC($divident, $src, $scale, $ddepth)
    ; CVAPI(cv::GMat*) cveGapiDivRC(cv::GScalar* divident, cv::GMat* src, double scale, int ddepth);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiDivRC", "ptr", $divident, "ptr", $src, "double", $scale, "int", $ddepth), "cveGapiDivRC", @error)
EndFunc   ;==>_cveGapiDivRC

Func _cveGapiMean($src)
    ; CVAPI(cv::GScalar*) cveGapiMean(cv::GMat* src);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiMean", "ptr", $src), "cveGapiMean", @error)
EndFunc   ;==>_cveGapiMean

Func _cveGapiPolarToCart($magnitude, $angle, $angleInDegrees, $outX, $outY)
    ; CVAPI(void) cveGapiPolarToCart(cv::GMat* magnitude, cv::GMat* angle, bool angleInDegrees, cv::GMat* outX, cv::GMat* outY);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveGapiPolarToCart", "ptr", $magnitude, "ptr", $angle, "boolean", $angleInDegrees, "ptr", $outX, "ptr", $outY), "cveGapiPolarToCart", @error)
EndFunc   ;==>_cveGapiPolarToCart

Func _cveGapiCartToPolar($x, $y, $angleInDegrees, $outMagnitude, $outAngle)
    ; CVAPI(void) cveGapiCartToPolar(cv::GMat* x, cv::GMat* y, bool angleInDegrees, cv::GMat* outMagnitude, cv::GMat* outAngle);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveGapiCartToPolar", "ptr", $x, "ptr", $y, "boolean", $angleInDegrees, "ptr", $outMagnitude, "ptr", $outAngle), "cveGapiCartToPolar", @error)
EndFunc   ;==>_cveGapiCartToPolar

Func _cveGapiPhase($x, $y, $angleInDegrees)
    ; CVAPI(cv::GMat*) cveGapiPhase(cv::GMat* x, cv::GMat* y, bool angleInDegrees);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiPhase", "ptr", $x, "ptr", $y, "boolean", $angleInDegrees), "cveGapiPhase", @error)
EndFunc   ;==>_cveGapiPhase

Func _cveGapiSqrt($src)
    ; CVAPI(cv::GMat*) cveGapiSqrt(cv::GMat* src);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiSqrt", "ptr", $src), "cveGapiSqrt", @error)
EndFunc   ;==>_cveGapiSqrt

Func _cveGapiCmpGT($src1, $src2)
    ; CVAPI(cv::GMat*) cveGapiCmpGT(cv::GMat* src1, cv::GMat* src2);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiCmpGT", "ptr", $src1, "ptr", $src2), "cveGapiCmpGT", @error)
EndFunc   ;==>_cveGapiCmpGT

Func _cveGapiCmpGTS($src1, $src2)
    ; CVAPI(cv::GMat*) cveGapiCmpGTS(cv::GMat* src1, cv::GMat* src2);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiCmpGTS", "ptr", $src1, "ptr", $src2), "cveGapiCmpGTS", @error)
EndFunc   ;==>_cveGapiCmpGTS

Func _cveGapiCmpLT($src1, $src2)
    ; CVAPI(cv::GMat*) cveGapiCmpLT(cv::GMat* src1, cv::GMat* src2);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiCmpLT", "ptr", $src1, "ptr", $src2), "cveGapiCmpLT", @error)
EndFunc   ;==>_cveGapiCmpLT

Func _cveGapiCmpLTS($src1, $src2)
    ; CVAPI(cv::GMat*) cveGapiCmpLTS(cv::GMat* src1, cv::GScalar* src2);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiCmpLTS", "ptr", $src1, "ptr", $src2), "cveGapiCmpLTS", @error)
EndFunc   ;==>_cveGapiCmpLTS

Func _cveGapiCmpGE($src1, $src2)
    ; CVAPI(cv::GMat*) cveGapiCmpGE(cv::GMat* src1, cv::GMat* src2);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiCmpGE", "ptr", $src1, "ptr", $src2), "cveGapiCmpGE", @error)
EndFunc   ;==>_cveGapiCmpGE

Func _cveGapiCmpGES($src1, $src2)
    ; CVAPI(cv::GMat*) cveGapiCmpGES(cv::GMat* src1, cv::GScalar* src2);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiCmpGES", "ptr", $src1, "ptr", $src2), "cveGapiCmpGES", @error)
EndFunc   ;==>_cveGapiCmpGES

Func _cveGapiCmpLE($src1, $src2)
    ; CVAPI(cv::GMat*) cveGapiCmpLE(cv::GMat* src1, cv::GMat* src2);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiCmpLE", "ptr", $src1, "ptr", $src2), "cveGapiCmpLE", @error)
EndFunc   ;==>_cveGapiCmpLE

Func _cveGapiCmpLES($src1, $src2)
    ; CVAPI(cv::GMat*) cveGapiCmpLES(cv::GMat* src1, cv::GScalar* src2);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiCmpLES", "ptr", $src1, "ptr", $src2), "cveGapiCmpLES", @error)
EndFunc   ;==>_cveGapiCmpLES

Func _cveGapiCmpEQ($src1, $src2)
    ; CVAPI(cv::GMat*) cveGapiCmpEQ(cv::GMat* src1, cv::GMat* src2);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiCmpEQ", "ptr", $src1, "ptr", $src2), "cveGapiCmpEQ", @error)
EndFunc   ;==>_cveGapiCmpEQ

Func _cveGapiCmpEQS($src1, $src2)
    ; CVAPI(cv::GMat*) cveGapiCmpEQS(cv::GMat* src1, cv::GScalar* src2);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiCmpEQS", "ptr", $src1, "ptr", $src2), "cveGapiCmpEQS", @error)
EndFunc   ;==>_cveGapiCmpEQS

Func _cveGapiCmpNE($src1, $src2)
    ; CVAPI(cv::GMat*) cveGapiCmpNE(cv::GMat* src1, cv::GMat* src2);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiCmpNE", "ptr", $src1, "ptr", $src2), "cveGapiCmpNE", @error)
EndFunc   ;==>_cveGapiCmpNE

Func _cveGapiCmpNES($src1, $src2)
    ; CVAPI(cv::GMat*) cveGapiCmpNES(cv::GMat* src1, cv::GScalar* src2);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiCmpNES", "ptr", $src1, "ptr", $src2), "cveGapiCmpNES", @error)
EndFunc   ;==>_cveGapiCmpNES

Func _cveGapiBitwiseAnd($src1, $src2)
    ; CVAPI(cv::GMat*) cveGapiBitwiseAnd(cv::GMat* src1, cv::GMat* src2);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiBitwiseAnd", "ptr", $src1, "ptr", $src2), "cveGapiBitwiseAnd", @error)
EndFunc   ;==>_cveGapiBitwiseAnd

Func _cveGapiBitwiseAndS($src1, $src2)
    ; CVAPI(cv::GMat*) cveGapiBitwiseAndS(cv::GMat* src1, cv::GScalar* src2);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiBitwiseAndS", "ptr", $src1, "ptr", $src2), "cveGapiBitwiseAndS", @error)
EndFunc   ;==>_cveGapiBitwiseAndS

Func _cveGapiBitwiseOr($src1, $src2)
    ; CVAPI(cv::GMat*) cveGapiBitwiseOr(cv::GMat* src1, cv::GMat* src2);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiBitwiseOr", "ptr", $src1, "ptr", $src2), "cveGapiBitwiseOr", @error)
EndFunc   ;==>_cveGapiBitwiseOr

Func _cveGapiBitwiseOrS($src1, $src2)
    ; CVAPI(cv::GMat*) cveGapiBitwiseOrS(cv::GMat* src1, cv::GScalar* src2);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiBitwiseOrS", "ptr", $src1, "ptr", $src2), "cveGapiBitwiseOrS", @error)
EndFunc   ;==>_cveGapiBitwiseOrS

Func _cveGapiBitwiseXor($src1, $src2)
    ; CVAPI(cv::GMat*) cveGapiBitwiseXor(cv::GMat* src1, cv::GMat* src2);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiBitwiseXor", "ptr", $src1, "ptr", $src2), "cveGapiBitwiseXor", @error)
EndFunc   ;==>_cveGapiBitwiseXor

Func _cveGapiBitwiseXorS($src1, $src2)
    ; CVAPI(cv::GMat*) cveGapiBitwiseXorS(cv::GMat* src1, cv::GScalar* src2);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiBitwiseXorS", "ptr", $src1, "ptr", $src2), "cveGapiBitwiseXorS", @error)
EndFunc   ;==>_cveGapiBitwiseXorS

Func _cveGapiMask($src, $mask)
    ; CVAPI(cv::GMat*) cveGapiMask(cv::GMat* src, cv::GMat* mask);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiMask", "ptr", $src, "ptr", $mask), "cveGapiMask", @error)
EndFunc   ;==>_cveGapiMask

Func _cveGapiResize($src, $dsize, $fx, $fy, $interpolation)
    ; CVAPI(cv::GMat*) cveGapiResize(cv::GMat* src, cv::Size* dsize, double fx, double fy, int interpolation);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiResize", "ptr", $src, "ptr", $dsize, "double", $fx, "double", $fy, "int", $interpolation), "cveGapiResize", @error)
EndFunc   ;==>_cveGapiResize

Func _cveGapiBitwiseNot($src)
    ; CVAPI(cv::GMat*) cveGapiBitwiseNot(cv::GMat* src);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiBitwiseNot", "ptr", $src), "cveGapiBitwiseNot", @error)
EndFunc   ;==>_cveGapiBitwiseNot

Func _cveGapiSelect($src1, $src2, $mask)
    ; CVAPI(cv::GMat*) cveGapiSelect(cv::GMat* src1, cv::GMat* src2, cv::GMat* mask);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiSelect", "ptr", $src1, "ptr", $src2, "ptr", $mask), "cveGapiSelect", @error)
EndFunc   ;==>_cveGapiSelect

Func _cveGapiMin($src1, $src2)
    ; CVAPI(cv::GMat*) cveGapiMin(cv::GMat* src1, cv::GMat* src2);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiMin", "ptr", $src1, "ptr", $src2), "cveGapiMin", @error)
EndFunc   ;==>_cveGapiMin

Func _cveGapiMax($src1, $src2)
    ; CVAPI(cv::GMat*) cveGapiMax(cv::GMat* src1, cv::GMat* src2);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiMax", "ptr", $src1, "ptr", $src2), "cveGapiMax", @error)
EndFunc   ;==>_cveGapiMax

Func _cveGapiAbsDiff($src1, $src2)
    ; CVAPI(cv::GMat*) cveGapiAbsDiff(cv::GMat* src1, cv::GMat* src2);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiAbsDiff", "ptr", $src1, "ptr", $src2), "cveGapiAbsDiff", @error)
EndFunc   ;==>_cveGapiAbsDiff

Func _cveGapiAbsDiffC($src, $c)
    ; CVAPI(cv::GMat*) cveGapiAbsDiffC(cv::GMat* src, cv::GScalar* c);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiAbsDiffC", "ptr", $src, "ptr", $c), "cveGapiAbsDiffC", @error)
EndFunc   ;==>_cveGapiAbsDiffC

Func _cveGapiSum($src)
    ; CVAPI(cv::GScalar*) cveGapiSum(cv::GMat* src);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiSum", "ptr", $src), "cveGapiSum", @error)
EndFunc   ;==>_cveGapiSum

Func _cveGapiAddWeighted($src1, $alpha, $src2, $beta, $gamma, $ddepth)
    ; CVAPI(cv::GMat*) cveGapiAddWeighted(cv::GMat* src1, double alpha, cv::GMat* src2, double beta, double gamma, int ddepth);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiAddWeighted", "ptr", $src1, "double", $alpha, "ptr", $src2, "double", $beta, "double", $gamma, "int", $ddepth), "cveGapiAddWeighted", @error)
EndFunc   ;==>_cveGapiAddWeighted

Func _cveGapiNormL1($src)
    ; CVAPI(cv::GScalar*) cveGapiNormL1(cv::GMat* src);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiNormL1", "ptr", $src), "cveGapiNormL1", @error)
EndFunc   ;==>_cveGapiNormL1

Func _cveGapiNormL2($src)
    ; CVAPI(cv::GScalar*) cveGapiNormL2(cv::GMat* src);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiNormL2", "ptr", $src), "cveGapiNormL2", @error)
EndFunc   ;==>_cveGapiNormL2

Func _cveGapiNormInf($src)
    ; CVAPI(cv::GScalar*) cveGapiNormInf(cv::GMat* src);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiNormInf", "ptr", $src), "cveGapiNormInf", @error)
EndFunc   ;==>_cveGapiNormInf

Func _cveGapiIntegral($src, $sdepth, $sqdepth, $dst1, $dst2)
    ; CVAPI(void) cveGapiIntegral(cv::GMat* src, int sdepth, int sqdepth, cv::GMat* dst1, cv::GMat* dst2);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveGapiIntegral", "ptr", $src, "int", $sdepth, "int", $sqdepth, "ptr", $dst1, "ptr", $dst2), "cveGapiIntegral", @error)
EndFunc   ;==>_cveGapiIntegral

Func _cveGapiThreshold($src, $thresh, $maxval, $type)
    ; CVAPI(cv::GMat*) cveGapiThreshold(cv::GMat* src, cv::GScalar* thresh, cv::GScalar* maxval, int type);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiThreshold", "ptr", $src, "ptr", $thresh, "ptr", $maxval, "int", $type), "cveGapiThreshold", @error)
EndFunc   ;==>_cveGapiThreshold

Func _cveGapiInRange($src, $threshLow, $threshUp)
    ; CVAPI(cv::GMat*) cveGapiInRange(cv::GMat* src, cv::GScalar* threshLow, cv::GScalar* threshUp);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiInRange", "ptr", $src, "ptr", $threshLow, "ptr", $threshUp), "cveGapiInRange", @error)
EndFunc   ;==>_cveGapiInRange

Func _cveGapiMerge4($src1, $src2, $src3, $src4)
    ; CVAPI(cv::GMat*) cveGapiMerge4(cv::GMat* src1, cv::GMat* src2, cv::GMat* src3, cv::GMat* src4);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiMerge4", "ptr", $src1, "ptr", $src2, "ptr", $src3, "ptr", $src4), "cveGapiMerge4", @error)
EndFunc   ;==>_cveGapiMerge4

Func _cveGapiMerge3($src1, $src2, $src3)
    ; CVAPI(cv::GMat*) cveGapiMerge3(cv::GMat* src1, cv::GMat* src2, cv::GMat* src3);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiMerge3", "ptr", $src1, "ptr", $src2, "ptr", $src3), "cveGapiMerge3", @error)
EndFunc   ;==>_cveGapiMerge3

Func _cveGapiSplit4($src, $dst1, $dst2, $dst3, $dst4)
    ; CVAPI(void) cveGapiSplit4(cv::GMat* src, cv::GMat* dst1, cv::GMat* dst2, cv::GMat* dst3, cv::GMat* dst4);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveGapiSplit4", "ptr", $src, "ptr", $dst1, "ptr", $dst2, "ptr", $dst3, "ptr", $dst4), "cveGapiSplit4", @error)
EndFunc   ;==>_cveGapiSplit4

Func _cveGapiSplit3($src, $dst1, $dst2, $dst3)
    ; CVAPI(void) cveGapiSplit3(cv::GMat* src, cv::GMat* dst1, cv::GMat* dst2, cv::GMat* dst3);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveGapiSplit3", "ptr", $src, "ptr", $dst1, "ptr", $dst2, "ptr", $dst3), "cveGapiSplit3", @error)
EndFunc   ;==>_cveGapiSplit3

Func _cveGapiRemap($src, $map1, $map2, $interpolation, $borderMode, $borderValue)
    ; CVAPI(cv::GMat*) cveGapiRemap(cv::GMat* src, cv::Mat* map1, cv::Mat* map2, int interpolation, int borderMode, CvScalar* borderValue);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiRemap", "ptr", $src, "ptr", $map1, "ptr", $map2, "int", $interpolation, "int", $borderMode, "struct*", $borderValue), "cveGapiRemap", @error)
EndFunc   ;==>_cveGapiRemap

Func _cveGapiFlip($src, $flipCode)
    ; CVAPI(cv::GMat*) cveGapiFlip(cv::GMat* src, int flipCode);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiFlip", "ptr", $src, "int", $flipCode), "cveGapiFlip", @error)
EndFunc   ;==>_cveGapiFlip

Func _cveGapiCrop($src, $rect)
    ; CVAPI(cv::GMat*) cveGapiCrop(cv::GMat* src, CvRect* rect);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiCrop", "ptr", $src, "struct*", $rect), "cveGapiCrop", @error)
EndFunc   ;==>_cveGapiCrop

Func _cveGapiConcatHor($src1, $src2)
    ; CVAPI(cv::GMat*) cveGapiConcatHor(cv::GMat* src1, cv::GMat* src2);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiConcatHor", "ptr", $src1, "ptr", $src2), "cveGapiConcatHor", @error)
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiConcatHorV", "ptr", $vecV), "cveGapiConcatHorV", @error)

    If $bVIsArray Then
        _VectorOfGMatRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_cveGapiConcatHorV

Func _cveGapiConcatVert($src1, $src2)
    ; CVAPI(cv::GMat*) cveGapiConcatVert(cv::GMat* src1, cv::GMat* src2);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiConcatVert", "ptr", $src1, "ptr", $src2), "cveGapiConcatVert", @error)
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiConcatVertV", "ptr", $vecV), "cveGapiConcatVertV", @error)

    If $bVIsArray Then
        _VectorOfGMatRelease($vecV)
    EndIf

    Return $retval
EndFunc   ;==>_cveGapiConcatVertV

Func _cveGapiLUT($src, $lut)
    ; CVAPI(cv::GMat*) cveGapiLUT(cv::GMat* src, cv::Mat* lut);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiLUT", "ptr", $src, "ptr", $lut), "cveGapiLUT", @error)
EndFunc   ;==>_cveGapiLUT

Func _cveGapiConvertTo($src, $rdepth, $alpha, $beta)
    ; CVAPI(cv::GMat*) cveGapiConvertTo(cv::GMat* src, int rdepth, double alpha, double beta);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiConvertTo", "ptr", $src, "int", $rdepth, "double", $alpha, "double", $beta), "cveGapiConvertTo", @error)
EndFunc   ;==>_cveGapiConvertTo

Func _cveGapiNormalize($src, $alpha, $beta, $normType, $ddepth)
    ; CVAPI(cv::GMat*) cveGapiNormalize(cv::GMat* src, double alpha, double beta, int normType, int ddepth);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiNormalize", "ptr", $src, "double", $alpha, "double", $beta, "int", $normType, "int", $ddepth), "cveGapiNormalize", @error)
EndFunc   ;==>_cveGapiNormalize

Func _cveGapiWarpPerspective($src, $M, $dsize, $flags, $borderMode, $borderValue)
    ; CVAPI(cv::GMat*) cveGapiWarpPerspective(cv::GMat* src, cv::Mat* M, CvSize* dsize, int flags, int borderMode, CvScalar* borderValue);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiWarpPerspective", "ptr", $src, "ptr", $M, "struct*", $dsize, "int", $flags, "int", $borderMode, "struct*", $borderValue), "cveGapiWarpPerspective", @error)
EndFunc   ;==>_cveGapiWarpPerspective

Func _cveGapiWarpAffine($src, $M, $dsize, $flags, $borderMode, $borderValue)
    ; CVAPI(cv::GMat*) cveGapiWarpAffine(cv::GMat* src, cv::Mat* M, CvSize* dsize, int flags, int borderMode, CvScalar* borderValue);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiWarpAffine", "ptr", $src, "ptr", $M, "struct*", $dsize, "int", $flags, "int", $borderMode, "struct*", $borderValue), "cveGapiWarpAffine", @error)
EndFunc   ;==>_cveGapiWarpAffine

Func _cveGComputationCreate1($input, $output)
    ; CVAPI(cv::GComputation*) cveGComputationCreate1(cv::GMat* input, cv::GMat* output);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGComputationCreate1", "ptr", $input, "ptr", $output), "cveGComputationCreate1", @error)
EndFunc   ;==>_cveGComputationCreate1

Func _cveGComputationCreate2($input, $output)
    ; CVAPI(cv::GComputation*) cveGComputationCreate2(cv::GMat* input, cv::GScalar* output);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGComputationCreate2", "ptr", $input, "ptr", $output), "cveGComputationCreate2", @error)
EndFunc   ;==>_cveGComputationCreate2

Func _cveGComputationCreate3($input1, $input2, $output)
    ; CVAPI(cv::GComputation*) cveGComputationCreate3(cv::GMat* input1, cv::GMat* input2, cv::GMat* output);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGComputationCreate3", "ptr", $input1, "ptr", $input2, "ptr", $output), "cveGComputationCreate3", @error)
EndFunc   ;==>_cveGComputationCreate3

Func _cveGComputationCreate4($input1, $input2, $output)
    ; CVAPI(cv::GComputation*) cveGComputationCreate4(cv::GMat* input1, cv::GMat* input2, cv::GScalar* output);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGComputationCreate4", "ptr", $input1, "ptr", $input2, "ptr", $output), "cveGComputationCreate4", @error)
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

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGComputationCreate5", "ptr", $vecIns, "ptr", $vecOuts), "cveGComputationCreate5", @error)

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
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveGComputationApply1", "ptr", $computation, "ptr", $input, "ptr", $output), "cveGComputationApply1", @error)
EndFunc   ;==>_cveGComputationApply1

Func _cveGComputationApply2($computation, $input, $output)
    ; CVAPI(void) cveGComputationApply2(cv::GComputation* computation, cv::Mat* input, CvScalar* output);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveGComputationApply2", "ptr", $computation, "ptr", $input, "struct*", $output), "cveGComputationApply2", @error)
EndFunc   ;==>_cveGComputationApply2

Func _cveGComputationApply3($computation, $input1, $input2, $output)
    ; CVAPI(void) cveGComputationApply3(cv::GComputation* computation, cv::Mat* input1, cv::Mat* input2, cv::Mat* output);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveGComputationApply3", "ptr", $computation, "ptr", $input1, "ptr", $input2, "ptr", $output), "cveGComputationApply3", @error)
EndFunc   ;==>_cveGComputationApply3

Func _cveGComputationApply4($computation, $input1, $input2, $output)
    ; CVAPI(void) cveGComputationApply4(cv::GComputation* computation, cv::Mat* input1, cv::Mat* input2, CvScalar* output);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveGComputationApply4", "ptr", $computation, "ptr", $input1, "ptr", $input2, "struct*", $output), "cveGComputationApply4", @error)
EndFunc   ;==>_cveGComputationApply4

Func _cveGComputationApply5($computation, $inputs, $outputs)
    ; CVAPI(void) cveGComputationApply5(cv::GComputation* computation, std::vector< cv::Mat >* inputs, std::vector< cv::Mat >* outputs);

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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveGComputationApply5", "ptr", $computation, "ptr", $vecInputs, "ptr", $vecOutputs), "cveGComputationApply5", @error)

    If $bOutputsIsArray Then
        _VectorOfMatRelease($vecOutputs)
    EndIf

    If $bInputsIsArray Then
        _VectorOfMatRelease($vecInputs)
    EndIf
EndFunc   ;==>_cveGComputationApply5

Func _cveGScalarCreate($value)
    ; CVAPI(cv::GScalar*) cveGScalarCreate(CvScalar* value);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGScalarCreate", "struct*", $value), "cveGScalarCreate", @error)
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
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiSepFilter", "ptr", $src, "int", $ddepth, "ptr", $kernelX, "ptr", $kernelY, "struct*", $anchor, "struct*", $delta, "int", $borderType, "struct*", $borderValue), "cveGapiSepFilter", @error)
EndFunc   ;==>_cveGapiSepFilter

Func _cveGapiFilter2D($src, $ddepth, $kernel, $anchor, $delta, $borderType, $borderValue)
    ; CVAPI(cv::GMat*) cveGapiFilter2D(cv::GMat* src, int ddepth, cv::Mat* kernel, CvPoint* anchor, CvScalar* delta, int borderType, CvScalar* borderValue);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiFilter2D", "ptr", $src, "int", $ddepth, "ptr", $kernel, "struct*", $anchor, "struct*", $delta, "int", $borderType, "struct*", $borderValue), "cveGapiFilter2D", @error)
EndFunc   ;==>_cveGapiFilter2D

Func _cveGapiBoxFilter($src, $dtype, $ksize, $anchor, $normalize, $borderType, $borderValue)
    ; CVAPI(cv::GMat*) cveGapiBoxFilter(cv::GMat* src, int dtype, CvSize* ksize, CvPoint* anchor, bool normalize, int borderType, CvScalar* borderValue);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiBoxFilter", "ptr", $src, "int", $dtype, "struct*", $ksize, "struct*", $anchor, "boolean", $normalize, "int", $borderType, "struct*", $borderValue), "cveGapiBoxFilter", @error)
EndFunc   ;==>_cveGapiBoxFilter

Func _cveGapiBlur($src, $ksize, $anchor, $borderType, $borderValue)
    ; CVAPI(cv::GMat*) cveGapiBlur(cv::GMat* src, CvSize* ksize, CvPoint* anchor, int borderType, CvScalar* borderValue);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiBlur", "ptr", $src, "struct*", $ksize, "struct*", $anchor, "int", $borderType, "struct*", $borderValue), "cveGapiBlur", @error)
EndFunc   ;==>_cveGapiBlur

Func _cveGapiGaussianBlur($src, $ksize, $sigmaX, $sigmaY, $borderType, $borderValue)
    ; CVAPI(cv::GMat*) cveGapiGaussianBlur(cv::GMat* src, CvSize* ksize, double sigmaX, double sigmaY, int borderType, CvScalar* borderValue);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiGaussianBlur", "ptr", $src, "struct*", $ksize, "double", $sigmaX, "double", $sigmaY, "int", $borderType, "struct*", $borderValue), "cveGapiGaussianBlur", @error)
EndFunc   ;==>_cveGapiGaussianBlur

Func _cveGapiMedianBlur($src, $ksize)
    ; CVAPI(cv::GMat*) cveGapiMedianBlur(cv::GMat* src, int ksize);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiMedianBlur", "ptr", $src, "int", $ksize), "cveGapiMedianBlur", @error)
EndFunc   ;==>_cveGapiMedianBlur

Func _cveGapiErode($src, $kernel, $anchor, $iterations, $borderType, $borderValue)
    ; CVAPI(cv::GMat*) cveGapiErode(cv::GMat* src, cv::Mat* kernel, CvPoint* anchor, int iterations, int borderType, CvScalar* borderValue);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiErode", "ptr", $src, "ptr", $kernel, "struct*", $anchor, "int", $iterations, "int", $borderType, "struct*", $borderValue), "cveGapiErode", @error)
EndFunc   ;==>_cveGapiErode

Func _cveGapiErode3x3($src, $iterations, $borderType, $borderValue)
    ; CVAPI(cv::GMat*) cveGapiErode3x3(cv::GMat* src, int iterations, int borderType, CvScalar* borderValue);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiErode3x3", "ptr", $src, "int", $iterations, "int", $borderType, "struct*", $borderValue), "cveGapiErode3x3", @error)
EndFunc   ;==>_cveGapiErode3x3

Func _cveGapiDilate($src, $kernel, $anchor, $iterations, $borderType, $borderValue)
    ; CVAPI(cv::GMat*) cveGapiDilate(cv::GMat* src, cv::Mat* kernel, CvPoint* anchor, int iterations, int borderType, CvScalar* borderValue);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiDilate", "ptr", $src, "ptr", $kernel, "struct*", $anchor, "int", $iterations, "int", $borderType, "struct*", $borderValue), "cveGapiDilate", @error)
EndFunc   ;==>_cveGapiDilate

Func _cveGapiDilate3x3($src, $iterations, $borderType, $borderValue)
    ; CVAPI(cv::GMat*) cveGapiDilate3x3(cv::GMat* src, int iterations, int borderType, CvScalar* borderValue);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiDilate3x3", "ptr", $src, "int", $iterations, "int", $borderType, "struct*", $borderValue), "cveGapiDilate3x3", @error)
EndFunc   ;==>_cveGapiDilate3x3

Func _cveGapiMorphologyEx($src, $op, $kernel, $anchor, $iterations, $borderType, $borderValue)
    ; CVAPI(cv::GMat*) cveGapiMorphologyEx(cv::GMat* src, int op, cv::Mat* kernel, CvPoint* anchor, int iterations, int borderType, CvScalar* borderValue);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiMorphologyEx", "ptr", $src, "int", $op, "ptr", $kernel, "struct*", $anchor, "int", $iterations, "int", $borderType, "struct*", $borderValue), "cveGapiMorphologyEx", @error)
EndFunc   ;==>_cveGapiMorphologyEx

Func _cveGapiSobel($src, $ddepth, $dx, $dy, $ksize, $scale, $delta, $borderType, $borderValue)
    ; CVAPI(cv::GMat*) cveGapiSobel(cv::GMat* src, int ddepth, int dx, int dy, int ksize, double scale, double delta, int borderType, CvScalar* borderValue);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiSobel", "ptr", $src, "int", $ddepth, "int", $dx, "int", $dy, "int", $ksize, "double", $scale, "double", $delta, "int", $borderType, "struct*", $borderValue), "cveGapiSobel", @error)
EndFunc   ;==>_cveGapiSobel

Func _cveGapiSobelXY($src, $ddepth, $order, $ksize, $scale, $delta, $borderType, $borderValue, $sobelX, $sobelY)
    ; CVAPI(void) cveGapiSobelXY(cv::GMat* src, int ddepth, int order, int ksize, double scale, double delta, int borderType, CvScalar* borderValue, cv::GMat* sobelX, cv::GMat* sobelY);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveGapiSobelXY", "ptr", $src, "int", $ddepth, "int", $order, "int", $ksize, "double", $scale, "double", $delta, "int", $borderType, "struct*", $borderValue, "ptr", $sobelX, "ptr", $sobelY), "cveGapiSobelXY", @error)
EndFunc   ;==>_cveGapiSobelXY

Func _cveGapiLaplacian($src, $ddepth, $ksize, $scale, $delta, $borderType)
    ; CVAPI(cv::GMat*) cveGapiLaplacian(cv::GMat* src, int ddepth, int ksize, double scale, double delta, int borderType);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiLaplacian", "ptr", $src, "int", $ddepth, "int", $ksize, "double", $scale, "double", $delta, "int", $borderType), "cveGapiLaplacian", @error)
EndFunc   ;==>_cveGapiLaplacian

Func _cveGapiBilateralFilter($src, $d, $sigmaColor, $sigmaSpace, $borderType)
    ; CVAPI(cv::GMat*) cveGapiBilateralFilter(cv::GMat* src, int d, double sigmaColor, double sigmaSpace, int borderType);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiBilateralFilter", "ptr", $src, "int", $d, "double", $sigmaColor, "double", $sigmaSpace, "int", $borderType), "cveGapiBilateralFilter", @error)
EndFunc   ;==>_cveGapiBilateralFilter

Func _cveGapiCanny($image, $threshold1, $threshold2, $apertureSize, $L2gradient)
    ; CVAPI(cv::GMat*) cveGapiCanny(cv::GMat* image, double threshold1, double threshold2, int apertureSize, bool L2gradient);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiCanny", "ptr", $image, "double", $threshold1, "double", $threshold2, "int", $apertureSize, "boolean", $L2gradient), "cveGapiCanny", @error)
EndFunc   ;==>_cveGapiCanny

Func _cveGapiEqualizeHist($src)
    ; CVAPI(cv::GMat*) cveGapiEqualizeHist(cv::GMat* src);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiEqualizeHist", "ptr", $src), "cveGapiEqualizeHist", @error)
EndFunc   ;==>_cveGapiEqualizeHist

Func _cveGapiBGR2RGB($src)
    ; CVAPI(cv::GMat*) cveGapiBGR2RGB(cv::GMat* src);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiBGR2RGB", "ptr", $src), "cveGapiBGR2RGB", @error)
EndFunc   ;==>_cveGapiBGR2RGB

Func _cveGapiRGB2Gray1($src)
    ; CVAPI(cv::GMat*) cveGapiRGB2Gray1(cv::GMat* src);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiRGB2Gray1", "ptr", $src), "cveGapiRGB2Gray1", @error)
EndFunc   ;==>_cveGapiRGB2Gray1

Func _cveGapiRGB2Gray2($src, $rY, $gY, $bY)
    ; CVAPI(cv::GMat*) cveGapiRGB2Gray2(cv::GMat* src, float rY, float gY, float bY);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiRGB2Gray2", "ptr", $src, "float", $rY, "float", $gY, "float", $bY), "cveGapiRGB2Gray2", @error)
EndFunc   ;==>_cveGapiRGB2Gray2

Func _cveGapiBGR2Gray($src)
    ; CVAPI(cv::GMat*) cveGapiBGR2Gray(cv::GMat* src);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiBGR2Gray", "ptr", $src), "cveGapiBGR2Gray", @error)
EndFunc   ;==>_cveGapiBGR2Gray

Func _cveGapiRGB2YUV($src)
    ; CVAPI(cv::GMat*) cveGapiRGB2YUV(cv::GMat* src);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiRGB2YUV", "ptr", $src), "cveGapiRGB2YUV", @error)
EndFunc   ;==>_cveGapiRGB2YUV

Func _cveGapiBGR2I420($src)
    ; CVAPI(cv::GMat*) cveGapiBGR2I420(cv::GMat* src);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiBGR2I420", "ptr", $src), "cveGapiBGR2I420", @error)
EndFunc   ;==>_cveGapiBGR2I420

Func _cveGapiRGB2I420($src)
    ; CVAPI(cv::GMat*) cveGapiRGB2I420(cv::GMat* src);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiRGB2I420", "ptr", $src), "cveGapiRGB2I420", @error)
EndFunc   ;==>_cveGapiRGB2I420

Func _cveGapiI4202BGR($src)
    ; CVAPI(cv::GMat*) cveGapiI4202BGR(cv::GMat* src);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiI4202BGR", "ptr", $src), "cveGapiI4202BGR", @error)
EndFunc   ;==>_cveGapiI4202BGR

Func _cveGapiI4202RGB($src)
    ; CVAPI(cv::GMat*) cveGapiI4202RGB(cv::GMat* src);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiI4202RGB", "ptr", $src), "cveGapiI4202RGB", @error)
EndFunc   ;==>_cveGapiI4202RGB

Func _cveGapiBGR2LUV($src)
    ; CVAPI(cv::GMat*) cveGapiBGR2LUV(cv::GMat* src);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiBGR2LUV", "ptr", $src), "cveGapiBGR2LUV", @error)
EndFunc   ;==>_cveGapiBGR2LUV

Func _cveGapiLUV2BGR($src)
    ; CVAPI(cv::GMat*) cveGapiLUV2BGR(cv::GMat* src);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiLUV2BGR", "ptr", $src), "cveGapiLUV2BGR", @error)
EndFunc   ;==>_cveGapiLUV2BGR

Func _cveGapiYUV2BGR($src)
    ; CVAPI(cv::GMat*) cveGapiYUV2BGR(cv::GMat* src);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiYUV2BGR", "ptr", $src), "cveGapiYUV2BGR", @error)
EndFunc   ;==>_cveGapiYUV2BGR

Func _cveGapiBGR2YUV($src)
    ; CVAPI(cv::GMat*) cveGapiBGR2YUV(cv::GMat* src);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiBGR2YUV", "ptr", $src), "cveGapiBGR2YUV", @error)
EndFunc   ;==>_cveGapiBGR2YUV

Func _cveGapiRGB2Lab($src)
    ; CVAPI(cv::GMat*) cveGapiRGB2Lab(cv::GMat* src);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiRGB2Lab", "ptr", $src), "cveGapiRGB2Lab", @error)
EndFunc   ;==>_cveGapiRGB2Lab

Func _cveGapiYUV2RGB($src)
    ; CVAPI(cv::GMat*) cveGapiYUV2RGB(cv::GMat* src);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiYUV2RGB", "ptr", $src), "cveGapiYUV2RGB", @error)
EndFunc   ;==>_cveGapiYUV2RGB

Func _cveGapiNV12toRGB($srcY, $srcUV)
    ; CVAPI(cv::GMat*) cveGapiNV12toRGB(cv::GMat* srcY, cv::GMat* srcUV);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiNV12toRGB", "ptr", $srcY, "ptr", $srcUV), "cveGapiNV12toRGB", @error)
EndFunc   ;==>_cveGapiNV12toRGB

Func _cveGapiNV12toGray($srcY, $srcUV)
    ; CVAPI(cv::GMat*) cveGapiNV12toGray(cv::GMat* srcY, cv::GMat* srcUV);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiNV12toGray", "ptr", $srcY, "ptr", $srcUV), "cveGapiNV12toGray", @error)
EndFunc   ;==>_cveGapiNV12toGray

Func _cveGapiNV12toBGR($srcY, $srcUV)
    ; CVAPI(cv::GMat*) cveGapiNV12toBGR(cv::GMat* srcY, cv::GMat* srcUV);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiNV12toBGR", "ptr", $srcY, "ptr", $srcUV), "cveGapiNV12toBGR", @error)
EndFunc   ;==>_cveGapiNV12toBGR

Func _cveGapiBayerGR2RGB($srcGR)
    ; CVAPI(cv::GMat*) cveGapiBayerGR2RGB(cv::GMat* srcGR);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiBayerGR2RGB", "ptr", $srcGR), "cveGapiBayerGR2RGB", @error)
EndFunc   ;==>_cveGapiBayerGR2RGB

Func _cveGapiRGB2HSV($src)
    ; CVAPI(cv::GMat*) cveGapiRGB2HSV(cv::GMat* src);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiRGB2HSV", "ptr", $src), "cveGapiRGB2HSV", @error)
EndFunc   ;==>_cveGapiRGB2HSV

Func _cveGapiRGB2YUV422($src)
    ; CVAPI(cv::GMat*) cveGapiRGB2YUV422(cv::GMat* src);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGapiRGB2YUV422", "ptr", $src), "cveGapiRGB2YUV422", @error)
EndFunc   ;==>_cveGapiRGB2YUV422