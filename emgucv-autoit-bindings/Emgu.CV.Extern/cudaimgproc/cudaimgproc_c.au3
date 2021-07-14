#include-once
#include "..\..\CVEUtils.au3"

Func _cudaBlendLinear(ByRef $img1, ByRef $img2, ByRef $weights1, ByRef $weights2, ByRef $result, ByRef $stream)
    ; CVAPI(void) cudaBlendLinear(cv::_InputArray* img1, cv::_InputArray* img2, cv::_InputArray* weights1, cv::_InputArray* weights2, cv::_OutputArray* result, cv::cuda::Stream* stream);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaBlendLinear", "ptr", $img1, "ptr", $img2, "ptr", $weights1, "ptr", $weights2, "ptr", $result, "ptr", $stream), "cudaBlendLinear", @error)
EndFunc   ;==>_cudaBlendLinear

Func _cudaBlendLinearMat(ByRef $matImg1, ByRef $matImg2, ByRef $matWeights1, ByRef $matWeights2, ByRef $matResult, ByRef $stream)
    ; cudaBlendLinear using cv::Mat instead of _*Array

    Local $iArrImg1, $vectorOfMatImg1, $iArrImg1Size
    Local $bImg1IsArray = VarGetType($matImg1) == "Array"

    If $bImg1IsArray Then
        $vectorOfMatImg1 = _VectorOfMatCreate()

        $iArrImg1Size = UBound($matImg1)
        For $i = 0 To $iArrImg1Size - 1
            _VectorOfMatPush($vectorOfMatImg1, $matImg1[$i])
        Next

        $iArrImg1 = _cveInputArrayFromVectorOfMat($vectorOfMatImg1)
    Else
        $iArrImg1 = _cveInputArrayFromMat($matImg1)
    EndIf

    Local $iArrImg2, $vectorOfMatImg2, $iArrImg2Size
    Local $bImg2IsArray = VarGetType($matImg2) == "Array"

    If $bImg2IsArray Then
        $vectorOfMatImg2 = _VectorOfMatCreate()

        $iArrImg2Size = UBound($matImg2)
        For $i = 0 To $iArrImg2Size - 1
            _VectorOfMatPush($vectorOfMatImg2, $matImg2[$i])
        Next

        $iArrImg2 = _cveInputArrayFromVectorOfMat($vectorOfMatImg2)
    Else
        $iArrImg2 = _cveInputArrayFromMat($matImg2)
    EndIf

    Local $iArrWeights1, $vectorOfMatWeights1, $iArrWeights1Size
    Local $bWeights1IsArray = VarGetType($matWeights1) == "Array"

    If $bWeights1IsArray Then
        $vectorOfMatWeights1 = _VectorOfMatCreate()

        $iArrWeights1Size = UBound($matWeights1)
        For $i = 0 To $iArrWeights1Size - 1
            _VectorOfMatPush($vectorOfMatWeights1, $matWeights1[$i])
        Next

        $iArrWeights1 = _cveInputArrayFromVectorOfMat($vectorOfMatWeights1)
    Else
        $iArrWeights1 = _cveInputArrayFromMat($matWeights1)
    EndIf

    Local $iArrWeights2, $vectorOfMatWeights2, $iArrWeights2Size
    Local $bWeights2IsArray = VarGetType($matWeights2) == "Array"

    If $bWeights2IsArray Then
        $vectorOfMatWeights2 = _VectorOfMatCreate()

        $iArrWeights2Size = UBound($matWeights2)
        For $i = 0 To $iArrWeights2Size - 1
            _VectorOfMatPush($vectorOfMatWeights2, $matWeights2[$i])
        Next

        $iArrWeights2 = _cveInputArrayFromVectorOfMat($vectorOfMatWeights2)
    Else
        $iArrWeights2 = _cveInputArrayFromMat($matWeights2)
    EndIf

    Local $oArrResult, $vectorOfMatResult, $iArrResultSize
    Local $bResultIsArray = VarGetType($matResult) == "Array"

    If $bResultIsArray Then
        $vectorOfMatResult = _VectorOfMatCreate()

        $iArrResultSize = UBound($matResult)
        For $i = 0 To $iArrResultSize - 1
            _VectorOfMatPush($vectorOfMatResult, $matResult[$i])
        Next

        $oArrResult = _cveOutputArrayFromVectorOfMat($vectorOfMatResult)
    Else
        $oArrResult = _cveOutputArrayFromMat($matResult)
    EndIf

    _cudaBlendLinear($iArrImg1, $iArrImg2, $iArrWeights1, $iArrWeights2, $oArrResult, $stream)

    If $bResultIsArray Then
        _VectorOfMatRelease($vectorOfMatResult)
    EndIf

    _cveOutputArrayRelease($oArrResult)

    If $bWeights2IsArray Then
        _VectorOfMatRelease($vectorOfMatWeights2)
    EndIf

    _cveInputArrayRelease($iArrWeights2)

    If $bWeights1IsArray Then
        _VectorOfMatRelease($vectorOfMatWeights1)
    EndIf

    _cveInputArrayRelease($iArrWeights1)

    If $bImg2IsArray Then
        _VectorOfMatRelease($vectorOfMatImg2)
    EndIf

    _cveInputArrayRelease($iArrImg2)

    If $bImg1IsArray Then
        _VectorOfMatRelease($vectorOfMatImg1)
    EndIf

    _cveInputArrayRelease($iArrImg1)
EndFunc   ;==>_cudaBlendLinearMat

Func _cudaCvtColor(ByRef $src, ByRef $dst, $code, $dcn, ByRef $stream)
    ; CVAPI(void) cudaCvtColor(cv::_InputArray* src, cv::_OutputArray* dst, int code, int dcn, cv::cuda::Stream* stream);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaCvtColor", "ptr", $src, "ptr", $dst, "int", $code, "int", $dcn, "ptr", $stream), "cudaCvtColor", @error)
EndFunc   ;==>_cudaCvtColor

Func _cudaCvtColorMat(ByRef $matSrc, ByRef $matDst, $code, $dcn, ByRef $stream)
    ; cudaCvtColor using cv::Mat instead of _*Array

    Local $iArrSrc, $vectorOfMatSrc, $iArrSrcSize
    Local $bSrcIsArray = VarGetType($matSrc) == "Array"

    If $bSrcIsArray Then
        $vectorOfMatSrc = _VectorOfMatCreate()

        $iArrSrcSize = UBound($matSrc)
        For $i = 0 To $iArrSrcSize - 1
            _VectorOfMatPush($vectorOfMatSrc, $matSrc[$i])
        Next

        $iArrSrc = _cveInputArrayFromVectorOfMat($vectorOfMatSrc)
    Else
        $iArrSrc = _cveInputArrayFromMat($matSrc)
    EndIf

    Local $oArrDst, $vectorOfMatDst, $iArrDstSize
    Local $bDstIsArray = VarGetType($matDst) == "Array"

    If $bDstIsArray Then
        $vectorOfMatDst = _VectorOfMatCreate()

        $iArrDstSize = UBound($matDst)
        For $i = 0 To $iArrDstSize - 1
            _VectorOfMatPush($vectorOfMatDst, $matDst[$i])
        Next

        $oArrDst = _cveOutputArrayFromVectorOfMat($vectorOfMatDst)
    Else
        $oArrDst = _cveOutputArrayFromMat($matDst)
    EndIf

    _cudaCvtColor($iArrSrc, $oArrDst, $code, $dcn, $stream)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveOutputArrayRelease($oArrDst)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)
EndFunc   ;==>_cudaCvtColorMat

Func _cudaDemosaicing(ByRef $src, ByRef $dst, $code, $dcn, ByRef $stream)
    ; CVAPI(void) cudaDemosaicing(cv::_InputArray* src, cv::_OutputArray* dst, int code, int dcn, cv::cuda::Stream* stream);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaDemosaicing", "ptr", $src, "ptr", $dst, "int", $code, "int", $dcn, "ptr", $stream), "cudaDemosaicing", @error)
EndFunc   ;==>_cudaDemosaicing

Func _cudaDemosaicingMat(ByRef $matSrc, ByRef $matDst, $code, $dcn, ByRef $stream)
    ; cudaDemosaicing using cv::Mat instead of _*Array

    Local $iArrSrc, $vectorOfMatSrc, $iArrSrcSize
    Local $bSrcIsArray = VarGetType($matSrc) == "Array"

    If $bSrcIsArray Then
        $vectorOfMatSrc = _VectorOfMatCreate()

        $iArrSrcSize = UBound($matSrc)
        For $i = 0 To $iArrSrcSize - 1
            _VectorOfMatPush($vectorOfMatSrc, $matSrc[$i])
        Next

        $iArrSrc = _cveInputArrayFromVectorOfMat($vectorOfMatSrc)
    Else
        $iArrSrc = _cveInputArrayFromMat($matSrc)
    EndIf

    Local $oArrDst, $vectorOfMatDst, $iArrDstSize
    Local $bDstIsArray = VarGetType($matDst) == "Array"

    If $bDstIsArray Then
        $vectorOfMatDst = _VectorOfMatCreate()

        $iArrDstSize = UBound($matDst)
        For $i = 0 To $iArrDstSize - 1
            _VectorOfMatPush($vectorOfMatDst, $matDst[$i])
        Next

        $oArrDst = _cveOutputArrayFromVectorOfMat($vectorOfMatDst)
    Else
        $oArrDst = _cveOutputArrayFromMat($matDst)
    EndIf

    _cudaDemosaicing($iArrSrc, $oArrDst, $code, $dcn, $stream)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveOutputArrayRelease($oArrDst)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)
EndFunc   ;==>_cudaDemosaicingMat

Func _cudaSwapChannels(ByRef $image, $dstOrder, ByRef $stream)
    ; CVAPI(void) cudaSwapChannels(cv::_InputOutputArray* image, const int* dstOrder, cv::cuda::Stream* stream);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaSwapChannels", "ptr", $image, "const int*", $dstOrder, "ptr", $stream), "cudaSwapChannels", @error)
EndFunc   ;==>_cudaSwapChannels

Func _cudaSwapChannelsMat(ByRef $matImage, $dstOrder, ByRef $stream)
    ; cudaSwapChannels using cv::Mat instead of _*Array

    Local $ioArrImage, $vectorOfMatImage, $iArrImageSize
    Local $bImageIsArray = VarGetType($matImage) == "Array"

    If $bImageIsArray Then
        $vectorOfMatImage = _VectorOfMatCreate()

        $iArrImageSize = UBound($matImage)
        For $i = 0 To $iArrImageSize - 1
            _VectorOfMatPush($vectorOfMatImage, $matImage[$i])
        Next

        $ioArrImage = _cveInputOutputArrayFromVectorOfMat($vectorOfMatImage)
    Else
        $ioArrImage = _cveInputOutputArrayFromMat($matImage)
    EndIf

    _cudaSwapChannels($ioArrImage, $dstOrder, $stream)

    If $bImageIsArray Then
        _VectorOfMatRelease($vectorOfMatImage)
    EndIf

    _cveInputOutputArrayRelease($ioArrImage)
EndFunc   ;==>_cudaSwapChannelsMat

Func _cudaAlphaComp(ByRef $img1, ByRef $img2, ByRef $dst, $alphaOp, ByRef $stream)
    ; CVAPI(void) cudaAlphaComp(cv::_InputArray* img1, cv::_InputArray* img2, cv::_OutputArray* dst, int alphaOp, cv::cuda::Stream* stream);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaAlphaComp", "ptr", $img1, "ptr", $img2, "ptr", $dst, "int", $alphaOp, "ptr", $stream), "cudaAlphaComp", @error)
EndFunc   ;==>_cudaAlphaComp

Func _cudaAlphaCompMat(ByRef $matImg1, ByRef $matImg2, ByRef $matDst, $alphaOp, ByRef $stream)
    ; cudaAlphaComp using cv::Mat instead of _*Array

    Local $iArrImg1, $vectorOfMatImg1, $iArrImg1Size
    Local $bImg1IsArray = VarGetType($matImg1) == "Array"

    If $bImg1IsArray Then
        $vectorOfMatImg1 = _VectorOfMatCreate()

        $iArrImg1Size = UBound($matImg1)
        For $i = 0 To $iArrImg1Size - 1
            _VectorOfMatPush($vectorOfMatImg1, $matImg1[$i])
        Next

        $iArrImg1 = _cveInputArrayFromVectorOfMat($vectorOfMatImg1)
    Else
        $iArrImg1 = _cveInputArrayFromMat($matImg1)
    EndIf

    Local $iArrImg2, $vectorOfMatImg2, $iArrImg2Size
    Local $bImg2IsArray = VarGetType($matImg2) == "Array"

    If $bImg2IsArray Then
        $vectorOfMatImg2 = _VectorOfMatCreate()

        $iArrImg2Size = UBound($matImg2)
        For $i = 0 To $iArrImg2Size - 1
            _VectorOfMatPush($vectorOfMatImg2, $matImg2[$i])
        Next

        $iArrImg2 = _cveInputArrayFromVectorOfMat($vectorOfMatImg2)
    Else
        $iArrImg2 = _cveInputArrayFromMat($matImg2)
    EndIf

    Local $oArrDst, $vectorOfMatDst, $iArrDstSize
    Local $bDstIsArray = VarGetType($matDst) == "Array"

    If $bDstIsArray Then
        $vectorOfMatDst = _VectorOfMatCreate()

        $iArrDstSize = UBound($matDst)
        For $i = 0 To $iArrDstSize - 1
            _VectorOfMatPush($vectorOfMatDst, $matDst[$i])
        Next

        $oArrDst = _cveOutputArrayFromVectorOfMat($vectorOfMatDst)
    Else
        $oArrDst = _cveOutputArrayFromMat($matDst)
    EndIf

    _cudaAlphaComp($iArrImg1, $iArrImg2, $oArrDst, $alphaOp, $stream)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveOutputArrayRelease($oArrDst)

    If $bImg2IsArray Then
        _VectorOfMatRelease($vectorOfMatImg2)
    EndIf

    _cveInputArrayRelease($iArrImg2)

    If $bImg1IsArray Then
        _VectorOfMatRelease($vectorOfMatImg1)
    EndIf

    _cveInputArrayRelease($iArrImg1)
EndFunc   ;==>_cudaAlphaCompMat

Func _cudaMeanShiftFiltering(ByRef $src, ByRef $dst, $sp, $sr, ByRef $criteria, ByRef $stream)
    ; CVAPI(void) cudaMeanShiftFiltering(cv::_InputArray* src, cv::_OutputArray* dst, int sp, int sr, CvTermCriteria* criteria, cv::cuda::Stream* stream);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaMeanShiftFiltering", "ptr", $src, "ptr", $dst, "int", $sp, "int", $sr, "struct*", $criteria, "ptr", $stream), "cudaMeanShiftFiltering", @error)
EndFunc   ;==>_cudaMeanShiftFiltering

Func _cudaMeanShiftFilteringMat(ByRef $matSrc, ByRef $matDst, $sp, $sr, ByRef $criteria, ByRef $stream)
    ; cudaMeanShiftFiltering using cv::Mat instead of _*Array

    Local $iArrSrc, $vectorOfMatSrc, $iArrSrcSize
    Local $bSrcIsArray = VarGetType($matSrc) == "Array"

    If $bSrcIsArray Then
        $vectorOfMatSrc = _VectorOfMatCreate()

        $iArrSrcSize = UBound($matSrc)
        For $i = 0 To $iArrSrcSize - 1
            _VectorOfMatPush($vectorOfMatSrc, $matSrc[$i])
        Next

        $iArrSrc = _cveInputArrayFromVectorOfMat($vectorOfMatSrc)
    Else
        $iArrSrc = _cveInputArrayFromMat($matSrc)
    EndIf

    Local $oArrDst, $vectorOfMatDst, $iArrDstSize
    Local $bDstIsArray = VarGetType($matDst) == "Array"

    If $bDstIsArray Then
        $vectorOfMatDst = _VectorOfMatCreate()

        $iArrDstSize = UBound($matDst)
        For $i = 0 To $iArrDstSize - 1
            _VectorOfMatPush($vectorOfMatDst, $matDst[$i])
        Next

        $oArrDst = _cveOutputArrayFromVectorOfMat($vectorOfMatDst)
    Else
        $oArrDst = _cveOutputArrayFromMat($matDst)
    EndIf

    _cudaMeanShiftFiltering($iArrSrc, $oArrDst, $sp, $sr, $criteria, $stream)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveOutputArrayRelease($oArrDst)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)
EndFunc   ;==>_cudaMeanShiftFilteringMat

Func _cudaMeanShiftProc(ByRef $src, ByRef $dstr, ByRef $dstsp, $sp, $sr, ByRef $criteria, ByRef $stream)
    ; CVAPI(void) cudaMeanShiftProc(cv::_InputArray* src, cv::_OutputArray* dstr, cv::_OutputArray* dstsp, int sp, int sr, CvTermCriteria* criteria, cv::cuda::Stream* stream);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaMeanShiftProc", "ptr", $src, "ptr", $dstr, "ptr", $dstsp, "int", $sp, "int", $sr, "struct*", $criteria, "ptr", $stream), "cudaMeanShiftProc", @error)
EndFunc   ;==>_cudaMeanShiftProc

Func _cudaMeanShiftProcMat(ByRef $matSrc, ByRef $matDstr, ByRef $matDstsp, $sp, $sr, ByRef $criteria, ByRef $stream)
    ; cudaMeanShiftProc using cv::Mat instead of _*Array

    Local $iArrSrc, $vectorOfMatSrc, $iArrSrcSize
    Local $bSrcIsArray = VarGetType($matSrc) == "Array"

    If $bSrcIsArray Then
        $vectorOfMatSrc = _VectorOfMatCreate()

        $iArrSrcSize = UBound($matSrc)
        For $i = 0 To $iArrSrcSize - 1
            _VectorOfMatPush($vectorOfMatSrc, $matSrc[$i])
        Next

        $iArrSrc = _cveInputArrayFromVectorOfMat($vectorOfMatSrc)
    Else
        $iArrSrc = _cveInputArrayFromMat($matSrc)
    EndIf

    Local $oArrDstr, $vectorOfMatDstr, $iArrDstrSize
    Local $bDstrIsArray = VarGetType($matDstr) == "Array"

    If $bDstrIsArray Then
        $vectorOfMatDstr = _VectorOfMatCreate()

        $iArrDstrSize = UBound($matDstr)
        For $i = 0 To $iArrDstrSize - 1
            _VectorOfMatPush($vectorOfMatDstr, $matDstr[$i])
        Next

        $oArrDstr = _cveOutputArrayFromVectorOfMat($vectorOfMatDstr)
    Else
        $oArrDstr = _cveOutputArrayFromMat($matDstr)
    EndIf

    Local $oArrDstsp, $vectorOfMatDstsp, $iArrDstspSize
    Local $bDstspIsArray = VarGetType($matDstsp) == "Array"

    If $bDstspIsArray Then
        $vectorOfMatDstsp = _VectorOfMatCreate()

        $iArrDstspSize = UBound($matDstsp)
        For $i = 0 To $iArrDstspSize - 1
            _VectorOfMatPush($vectorOfMatDstsp, $matDstsp[$i])
        Next

        $oArrDstsp = _cveOutputArrayFromVectorOfMat($vectorOfMatDstsp)
    Else
        $oArrDstsp = _cveOutputArrayFromMat($matDstsp)
    EndIf

    _cudaMeanShiftProc($iArrSrc, $oArrDstr, $oArrDstsp, $sp, $sr, $criteria, $stream)

    If $bDstspIsArray Then
        _VectorOfMatRelease($vectorOfMatDstsp)
    EndIf

    _cveOutputArrayRelease($oArrDstsp)

    If $bDstrIsArray Then
        _VectorOfMatRelease($vectorOfMatDstr)
    EndIf

    _cveOutputArrayRelease($oArrDstr)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)
EndFunc   ;==>_cudaMeanShiftProcMat

Func _cudaMeanShiftSegmentation(ByRef $src, ByRef $dst, $sp, $sr, $minsize, ByRef $criteria, ByRef $stream)
    ; CVAPI(void) cudaMeanShiftSegmentation(cv::_InputArray* src, cv::_OutputArray* dst, int sp, int sr, int minsize, CvTermCriteria* criteria, cv::cuda::Stream* stream);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaMeanShiftSegmentation", "ptr", $src, "ptr", $dst, "int", $sp, "int", $sr, "int", $minsize, "struct*", $criteria, "ptr", $stream), "cudaMeanShiftSegmentation", @error)
EndFunc   ;==>_cudaMeanShiftSegmentation

Func _cudaMeanShiftSegmentationMat(ByRef $matSrc, ByRef $matDst, $sp, $sr, $minsize, ByRef $criteria, ByRef $stream)
    ; cudaMeanShiftSegmentation using cv::Mat instead of _*Array

    Local $iArrSrc, $vectorOfMatSrc, $iArrSrcSize
    Local $bSrcIsArray = VarGetType($matSrc) == "Array"

    If $bSrcIsArray Then
        $vectorOfMatSrc = _VectorOfMatCreate()

        $iArrSrcSize = UBound($matSrc)
        For $i = 0 To $iArrSrcSize - 1
            _VectorOfMatPush($vectorOfMatSrc, $matSrc[$i])
        Next

        $iArrSrc = _cveInputArrayFromVectorOfMat($vectorOfMatSrc)
    Else
        $iArrSrc = _cveInputArrayFromMat($matSrc)
    EndIf

    Local $oArrDst, $vectorOfMatDst, $iArrDstSize
    Local $bDstIsArray = VarGetType($matDst) == "Array"

    If $bDstIsArray Then
        $vectorOfMatDst = _VectorOfMatCreate()

        $iArrDstSize = UBound($matDst)
        For $i = 0 To $iArrDstSize - 1
            _VectorOfMatPush($vectorOfMatDst, $matDst[$i])
        Next

        $oArrDst = _cveOutputArrayFromVectorOfMat($vectorOfMatDst)
    Else
        $oArrDst = _cveOutputArrayFromMat($matDst)
    EndIf

    _cudaMeanShiftSegmentation($iArrSrc, $oArrDst, $sp, $sr, $minsize, $criteria, $stream)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveOutputArrayRelease($oArrDst)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)
EndFunc   ;==>_cudaMeanShiftSegmentationMat

Func _cudaCalcHist(ByRef $src, ByRef $hist, ByRef $stream)
    ; CVAPI(void) cudaCalcHist(cv::_InputArray* src, cv::_OutputArray* hist, cv::cuda::Stream* stream);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaCalcHist", "ptr", $src, "ptr", $hist, "ptr", $stream), "cudaCalcHist", @error)
EndFunc   ;==>_cudaCalcHist

Func _cudaCalcHistMat(ByRef $matSrc, ByRef $matHist, ByRef $stream)
    ; cudaCalcHist using cv::Mat instead of _*Array

    Local $iArrSrc, $vectorOfMatSrc, $iArrSrcSize
    Local $bSrcIsArray = VarGetType($matSrc) == "Array"

    If $bSrcIsArray Then
        $vectorOfMatSrc = _VectorOfMatCreate()

        $iArrSrcSize = UBound($matSrc)
        For $i = 0 To $iArrSrcSize - 1
            _VectorOfMatPush($vectorOfMatSrc, $matSrc[$i])
        Next

        $iArrSrc = _cveInputArrayFromVectorOfMat($vectorOfMatSrc)
    Else
        $iArrSrc = _cveInputArrayFromMat($matSrc)
    EndIf

    Local $oArrHist, $vectorOfMatHist, $iArrHistSize
    Local $bHistIsArray = VarGetType($matHist) == "Array"

    If $bHistIsArray Then
        $vectorOfMatHist = _VectorOfMatCreate()

        $iArrHistSize = UBound($matHist)
        For $i = 0 To $iArrHistSize - 1
            _VectorOfMatPush($vectorOfMatHist, $matHist[$i])
        Next

        $oArrHist = _cveOutputArrayFromVectorOfMat($vectorOfMatHist)
    Else
        $oArrHist = _cveOutputArrayFromMat($matHist)
    EndIf

    _cudaCalcHist($iArrSrc, $oArrHist, $stream)

    If $bHistIsArray Then
        _VectorOfMatRelease($vectorOfMatHist)
    EndIf

    _cveOutputArrayRelease($oArrHist)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)
EndFunc   ;==>_cudaCalcHistMat

Func _cudaEqualizeHist(ByRef $src, ByRef $dst, ByRef $stream)
    ; CVAPI(void) cudaEqualizeHist(cv::_InputArray* src, cv::_OutputArray* dst, cv::cuda::Stream* stream);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaEqualizeHist", "ptr", $src, "ptr", $dst, "ptr", $stream), "cudaEqualizeHist", @error)
EndFunc   ;==>_cudaEqualizeHist

Func _cudaEqualizeHistMat(ByRef $matSrc, ByRef $matDst, ByRef $stream)
    ; cudaEqualizeHist using cv::Mat instead of _*Array

    Local $iArrSrc, $vectorOfMatSrc, $iArrSrcSize
    Local $bSrcIsArray = VarGetType($matSrc) == "Array"

    If $bSrcIsArray Then
        $vectorOfMatSrc = _VectorOfMatCreate()

        $iArrSrcSize = UBound($matSrc)
        For $i = 0 To $iArrSrcSize - 1
            _VectorOfMatPush($vectorOfMatSrc, $matSrc[$i])
        Next

        $iArrSrc = _cveInputArrayFromVectorOfMat($vectorOfMatSrc)
    Else
        $iArrSrc = _cveInputArrayFromMat($matSrc)
    EndIf

    Local $oArrDst, $vectorOfMatDst, $iArrDstSize
    Local $bDstIsArray = VarGetType($matDst) == "Array"

    If $bDstIsArray Then
        $vectorOfMatDst = _VectorOfMatCreate()

        $iArrDstSize = UBound($matDst)
        For $i = 0 To $iArrDstSize - 1
            _VectorOfMatPush($vectorOfMatDst, $matDst[$i])
        Next

        $oArrDst = _cveOutputArrayFromVectorOfMat($vectorOfMatDst)
    Else
        $oArrDst = _cveOutputArrayFromMat($matDst)
    EndIf

    _cudaEqualizeHist($iArrSrc, $oArrDst, $stream)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveOutputArrayRelease($oArrDst)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)
EndFunc   ;==>_cudaEqualizeHistMat

Func _cudaHistEven(ByRef $src, ByRef $hist, $histSize, $lowerLevel, $upperLevel, ByRef $stream)
    ; CVAPI(void) cudaHistEven(cv::_InputArray* src, cv::_OutputArray* hist, int histSize, int lowerLevel, int upperLevel, cv::cuda::Stream* stream);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaHistEven", "ptr", $src, "ptr", $hist, "int", $histSize, "int", $lowerLevel, "int", $upperLevel, "ptr", $stream), "cudaHistEven", @error)
EndFunc   ;==>_cudaHistEven

Func _cudaHistEvenMat(ByRef $matSrc, ByRef $matHist, $histSize, $lowerLevel, $upperLevel, ByRef $stream)
    ; cudaHistEven using cv::Mat instead of _*Array

    Local $iArrSrc, $vectorOfMatSrc, $iArrSrcSize
    Local $bSrcIsArray = VarGetType($matSrc) == "Array"

    If $bSrcIsArray Then
        $vectorOfMatSrc = _VectorOfMatCreate()

        $iArrSrcSize = UBound($matSrc)
        For $i = 0 To $iArrSrcSize - 1
            _VectorOfMatPush($vectorOfMatSrc, $matSrc[$i])
        Next

        $iArrSrc = _cveInputArrayFromVectorOfMat($vectorOfMatSrc)
    Else
        $iArrSrc = _cveInputArrayFromMat($matSrc)
    EndIf

    Local $oArrHist, $vectorOfMatHist, $iArrHistSize
    Local $bHistIsArray = VarGetType($matHist) == "Array"

    If $bHistIsArray Then
        $vectorOfMatHist = _VectorOfMatCreate()

        $iArrHistSize = UBound($matHist)
        For $i = 0 To $iArrHistSize - 1
            _VectorOfMatPush($vectorOfMatHist, $matHist[$i])
        Next

        $oArrHist = _cveOutputArrayFromVectorOfMat($vectorOfMatHist)
    Else
        $oArrHist = _cveOutputArrayFromMat($matHist)
    EndIf

    _cudaHistEven($iArrSrc, $oArrHist, $histSize, $lowerLevel, $upperLevel, $stream)

    If $bHistIsArray Then
        _VectorOfMatRelease($vectorOfMatHist)
    EndIf

    _cveOutputArrayRelease($oArrHist)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)
EndFunc   ;==>_cudaHistEvenMat

Func _cudaHistRange(ByRef $src, ByRef $hist, ByRef $levels, ByRef $stream)
    ; CVAPI(void) cudaHistRange(cv::_InputArray* src, cv::_OutputArray* hist, cv::_InputArray* levels, cv::cuda::Stream* stream);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaHistRange", "ptr", $src, "ptr", $hist, "ptr", $levels, "ptr", $stream), "cudaHistRange", @error)
EndFunc   ;==>_cudaHistRange

Func _cudaHistRangeMat(ByRef $matSrc, ByRef $matHist, ByRef $matLevels, ByRef $stream)
    ; cudaHistRange using cv::Mat instead of _*Array

    Local $iArrSrc, $vectorOfMatSrc, $iArrSrcSize
    Local $bSrcIsArray = VarGetType($matSrc) == "Array"

    If $bSrcIsArray Then
        $vectorOfMatSrc = _VectorOfMatCreate()

        $iArrSrcSize = UBound($matSrc)
        For $i = 0 To $iArrSrcSize - 1
            _VectorOfMatPush($vectorOfMatSrc, $matSrc[$i])
        Next

        $iArrSrc = _cveInputArrayFromVectorOfMat($vectorOfMatSrc)
    Else
        $iArrSrc = _cveInputArrayFromMat($matSrc)
    EndIf

    Local $oArrHist, $vectorOfMatHist, $iArrHistSize
    Local $bHistIsArray = VarGetType($matHist) == "Array"

    If $bHistIsArray Then
        $vectorOfMatHist = _VectorOfMatCreate()

        $iArrHistSize = UBound($matHist)
        For $i = 0 To $iArrHistSize - 1
            _VectorOfMatPush($vectorOfMatHist, $matHist[$i])
        Next

        $oArrHist = _cveOutputArrayFromVectorOfMat($vectorOfMatHist)
    Else
        $oArrHist = _cveOutputArrayFromMat($matHist)
    EndIf

    Local $iArrLevels, $vectorOfMatLevels, $iArrLevelsSize
    Local $bLevelsIsArray = VarGetType($matLevels) == "Array"

    If $bLevelsIsArray Then
        $vectorOfMatLevels = _VectorOfMatCreate()

        $iArrLevelsSize = UBound($matLevels)
        For $i = 0 To $iArrLevelsSize - 1
            _VectorOfMatPush($vectorOfMatLevels, $matLevels[$i])
        Next

        $iArrLevels = _cveInputArrayFromVectorOfMat($vectorOfMatLevels)
    Else
        $iArrLevels = _cveInputArrayFromMat($matLevels)
    EndIf

    _cudaHistRange($iArrSrc, $oArrHist, $iArrLevels, $stream)

    If $bLevelsIsArray Then
        _VectorOfMatRelease($vectorOfMatLevels)
    EndIf

    _cveInputArrayRelease($iArrLevels)

    If $bHistIsArray Then
        _VectorOfMatRelease($vectorOfMatHist)
    EndIf

    _cveOutputArrayRelease($oArrHist)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)
EndFunc   ;==>_cudaHistRangeMat

Func _cudaBilateralFilter(ByRef $src, ByRef $dst, $kernelSize, $sigmaColor, $sigmaSpatial, $borderMode, ByRef $stream)
    ; CVAPI(void) cudaBilateralFilter(cv::_InputArray* src, cv::_OutputArray* dst, int kernelSize, float sigmaColor, float sigmaSpatial, int borderMode, cv::cuda::Stream* stream);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaBilateralFilter", "ptr", $src, "ptr", $dst, "int", $kernelSize, "float", $sigmaColor, "float", $sigmaSpatial, "int", $borderMode, "ptr", $stream), "cudaBilateralFilter", @error)
EndFunc   ;==>_cudaBilateralFilter

Func _cudaBilateralFilterMat(ByRef $matSrc, ByRef $matDst, $kernelSize, $sigmaColor, $sigmaSpatial, $borderMode, ByRef $stream)
    ; cudaBilateralFilter using cv::Mat instead of _*Array

    Local $iArrSrc, $vectorOfMatSrc, $iArrSrcSize
    Local $bSrcIsArray = VarGetType($matSrc) == "Array"

    If $bSrcIsArray Then
        $vectorOfMatSrc = _VectorOfMatCreate()

        $iArrSrcSize = UBound($matSrc)
        For $i = 0 To $iArrSrcSize - 1
            _VectorOfMatPush($vectorOfMatSrc, $matSrc[$i])
        Next

        $iArrSrc = _cveInputArrayFromVectorOfMat($vectorOfMatSrc)
    Else
        $iArrSrc = _cveInputArrayFromMat($matSrc)
    EndIf

    Local $oArrDst, $vectorOfMatDst, $iArrDstSize
    Local $bDstIsArray = VarGetType($matDst) == "Array"

    If $bDstIsArray Then
        $vectorOfMatDst = _VectorOfMatCreate()

        $iArrDstSize = UBound($matDst)
        For $i = 0 To $iArrDstSize - 1
            _VectorOfMatPush($vectorOfMatDst, $matDst[$i])
        Next

        $oArrDst = _cveOutputArrayFromVectorOfMat($vectorOfMatDst)
    Else
        $oArrDst = _cveOutputArrayFromMat($matDst)
    EndIf

    _cudaBilateralFilter($iArrSrc, $oArrDst, $kernelSize, $sigmaColor, $sigmaSpatial, $borderMode, $stream)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveOutputArrayRelease($oArrDst)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)
EndFunc   ;==>_cudaBilateralFilterMat

Func _cudaCreateHarrisCorner($srcType, $blockSize, $ksize, $k, $borderType, ByRef $sharedPtr)
    ; CVAPI(cv::cuda::CornernessCriteria*) cudaCreateHarrisCorner(int srcType, int blockSize, int ksize, double k, int borderType, cv::Ptr<cv::cuda::CornernessCriteria>** sharedPtr);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cudaCreateHarrisCorner", "int", $srcType, "int", $blockSize, "int", $ksize, "double", $k, "int", $borderType, "ptr*", $sharedPtr), "cudaCreateHarrisCorner", @error)
EndFunc   ;==>_cudaCreateHarrisCorner

Func _cudaCreateMinEigenValCorner($srcType, $blockSize, $ksize, $borderType, ByRef $sharedPtr)
    ; CVAPI(cv::cuda::CornernessCriteria*) cudaCreateMinEigenValCorner(int srcType, int blockSize, int ksize, int borderType, cv::Ptr<cv::cuda::CornernessCriteria>** sharedPtr);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cudaCreateMinEigenValCorner", "int", $srcType, "int", $blockSize, "int", $ksize, "int", $borderType, "ptr*", $sharedPtr), "cudaCreateMinEigenValCorner", @error)
EndFunc   ;==>_cudaCreateMinEigenValCorner

Func _cudaCornernessCriteriaCompute(ByRef $detector, ByRef $src, ByRef $dst, ByRef $stream)
    ; CVAPI(void) cudaCornernessCriteriaCompute(cv::Ptr<cv::cuda::CornernessCriteria>* detector, cv::_InputArray* src, cv::_OutputArray* dst, cv::cuda::Stream* stream);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaCornernessCriteriaCompute", "ptr", $detector, "ptr", $src, "ptr", $dst, "ptr", $stream), "cudaCornernessCriteriaCompute", @error)
EndFunc   ;==>_cudaCornernessCriteriaCompute

Func _cudaCornernessCriteriaComputeMat(ByRef $detector, ByRef $matSrc, ByRef $matDst, ByRef $stream)
    ; cudaCornernessCriteriaCompute using cv::Mat instead of _*Array

    Local $iArrSrc, $vectorOfMatSrc, $iArrSrcSize
    Local $bSrcIsArray = VarGetType($matSrc) == "Array"

    If $bSrcIsArray Then
        $vectorOfMatSrc = _VectorOfMatCreate()

        $iArrSrcSize = UBound($matSrc)
        For $i = 0 To $iArrSrcSize - 1
            _VectorOfMatPush($vectorOfMatSrc, $matSrc[$i])
        Next

        $iArrSrc = _cveInputArrayFromVectorOfMat($vectorOfMatSrc)
    Else
        $iArrSrc = _cveInputArrayFromMat($matSrc)
    EndIf

    Local $oArrDst, $vectorOfMatDst, $iArrDstSize
    Local $bDstIsArray = VarGetType($matDst) == "Array"

    If $bDstIsArray Then
        $vectorOfMatDst = _VectorOfMatCreate()

        $iArrDstSize = UBound($matDst)
        For $i = 0 To $iArrDstSize - 1
            _VectorOfMatPush($vectorOfMatDst, $matDst[$i])
        Next

        $oArrDst = _cveOutputArrayFromVectorOfMat($vectorOfMatDst)
    Else
        $oArrDst = _cveOutputArrayFromMat($matDst)
    EndIf

    _cudaCornernessCriteriaCompute($detector, $iArrSrc, $oArrDst, $stream)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveOutputArrayRelease($oArrDst)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)
EndFunc   ;==>_cudaCornernessCriteriaComputeMat

Func _cudaCornernessCriteriaRelease(ByRef $detector)
    ; CVAPI(void) cudaCornernessCriteriaRelease(cv::Ptr<cv::cuda::CornernessCriteria>** detector);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaCornernessCriteriaRelease", "ptr*", $detector), "cudaCornernessCriteriaRelease", @error)
EndFunc   ;==>_cudaCornernessCriteriaRelease

Func _cudaCLAHECreate($clipLimit, ByRef $tileGridSize, ByRef $sharedPtr)
    ; CVAPI(cv::cuda::CLAHE*) cudaCLAHECreate(double clipLimit, CvSize* tileGridSize, cv::Ptr<cv::cuda::CLAHE>** sharedPtr);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cudaCLAHECreate", "double", $clipLimit, "struct*", $tileGridSize, "ptr*", $sharedPtr), "cudaCLAHECreate", @error)
EndFunc   ;==>_cudaCLAHECreate

Func _cudaCLAHEApply(ByRef $clahe, ByRef $src, ByRef $dst, ByRef $stream)
    ; CVAPI(void) cudaCLAHEApply(cv::cuda::CLAHE* clahe, cv::_InputArray* src, cv::_OutputArray* dst, cv::cuda::Stream* stream);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaCLAHEApply", "ptr", $clahe, "ptr", $src, "ptr", $dst, "ptr", $stream), "cudaCLAHEApply", @error)
EndFunc   ;==>_cudaCLAHEApply

Func _cudaCLAHEApplyMat(ByRef $clahe, ByRef $matSrc, ByRef $matDst, ByRef $stream)
    ; cudaCLAHEApply using cv::Mat instead of _*Array

    Local $iArrSrc, $vectorOfMatSrc, $iArrSrcSize
    Local $bSrcIsArray = VarGetType($matSrc) == "Array"

    If $bSrcIsArray Then
        $vectorOfMatSrc = _VectorOfMatCreate()

        $iArrSrcSize = UBound($matSrc)
        For $i = 0 To $iArrSrcSize - 1
            _VectorOfMatPush($vectorOfMatSrc, $matSrc[$i])
        Next

        $iArrSrc = _cveInputArrayFromVectorOfMat($vectorOfMatSrc)
    Else
        $iArrSrc = _cveInputArrayFromMat($matSrc)
    EndIf

    Local $oArrDst, $vectorOfMatDst, $iArrDstSize
    Local $bDstIsArray = VarGetType($matDst) == "Array"

    If $bDstIsArray Then
        $vectorOfMatDst = _VectorOfMatCreate()

        $iArrDstSize = UBound($matDst)
        For $i = 0 To $iArrDstSize - 1
            _VectorOfMatPush($vectorOfMatDst, $matDst[$i])
        Next

        $oArrDst = _cveOutputArrayFromVectorOfMat($vectorOfMatDst)
    Else
        $oArrDst = _cveOutputArrayFromMat($matDst)
    EndIf

    _cudaCLAHEApply($clahe, $iArrSrc, $oArrDst, $stream)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveOutputArrayRelease($oArrDst)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)
EndFunc   ;==>_cudaCLAHEApplyMat

Func _cudaCLAHERelease(ByRef $clahe)
    ; CVAPI(void) cudaCLAHERelease(cv::Ptr<cv::cuda::CLAHE>** clahe);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaCLAHERelease", "ptr*", $clahe), "cudaCLAHERelease", @error)
EndFunc   ;==>_cudaCLAHERelease

Func _cudaCreateCannyEdgeDetector($lowThreshold, $highThreshold, $apertureSize, $L2gradient, ByRef $sharedPtr)
    ; CVAPI(cv::cuda::CannyEdgeDetector*) cudaCreateCannyEdgeDetector(double lowThreshold, double highThreshold, int apertureSize, bool L2gradient, cv::Ptr<cv::cuda::CannyEdgeDetector>** sharedPtr);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cudaCreateCannyEdgeDetector", "double", $lowThreshold, "double", $highThreshold, "int", $apertureSize, "boolean", $L2gradient, "ptr*", $sharedPtr), "cudaCreateCannyEdgeDetector", @error)
EndFunc   ;==>_cudaCreateCannyEdgeDetector

Func _cudaCannyEdgeDetectorDetect(ByRef $detector, ByRef $src, ByRef $edges, ByRef $stream)
    ; CVAPI(void) cudaCannyEdgeDetectorDetect(cv::cuda::CannyEdgeDetector* detector, cv::_InputArray* src, cv::_OutputArray* edges, cv::cuda::Stream* stream);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaCannyEdgeDetectorDetect", "ptr", $detector, "ptr", $src, "ptr", $edges, "ptr", $stream), "cudaCannyEdgeDetectorDetect", @error)
EndFunc   ;==>_cudaCannyEdgeDetectorDetect

Func _cudaCannyEdgeDetectorDetectMat(ByRef $detector, ByRef $matSrc, ByRef $matEdges, ByRef $stream)
    ; cudaCannyEdgeDetectorDetect using cv::Mat instead of _*Array

    Local $iArrSrc, $vectorOfMatSrc, $iArrSrcSize
    Local $bSrcIsArray = VarGetType($matSrc) == "Array"

    If $bSrcIsArray Then
        $vectorOfMatSrc = _VectorOfMatCreate()

        $iArrSrcSize = UBound($matSrc)
        For $i = 0 To $iArrSrcSize - 1
            _VectorOfMatPush($vectorOfMatSrc, $matSrc[$i])
        Next

        $iArrSrc = _cveInputArrayFromVectorOfMat($vectorOfMatSrc)
    Else
        $iArrSrc = _cveInputArrayFromMat($matSrc)
    EndIf

    Local $oArrEdges, $vectorOfMatEdges, $iArrEdgesSize
    Local $bEdgesIsArray = VarGetType($matEdges) == "Array"

    If $bEdgesIsArray Then
        $vectorOfMatEdges = _VectorOfMatCreate()

        $iArrEdgesSize = UBound($matEdges)
        For $i = 0 To $iArrEdgesSize - 1
            _VectorOfMatPush($vectorOfMatEdges, $matEdges[$i])
        Next

        $oArrEdges = _cveOutputArrayFromVectorOfMat($vectorOfMatEdges)
    Else
        $oArrEdges = _cveOutputArrayFromMat($matEdges)
    EndIf

    _cudaCannyEdgeDetectorDetect($detector, $iArrSrc, $oArrEdges, $stream)

    If $bEdgesIsArray Then
        _VectorOfMatRelease($vectorOfMatEdges)
    EndIf

    _cveOutputArrayRelease($oArrEdges)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)
EndFunc   ;==>_cudaCannyEdgeDetectorDetectMat

Func _cudaCannyEdgeDetectorRelease(ByRef $detector)
    ; CVAPI(void) cudaCannyEdgeDetectorRelease(cv::Ptr<cv::cuda::CannyEdgeDetector>** detector);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaCannyEdgeDetectorRelease", "ptr*", $detector), "cudaCannyEdgeDetectorRelease", @error)
EndFunc   ;==>_cudaCannyEdgeDetectorRelease

Func _cudaGoodFeaturesToTrackDetectorCreate($srcType, $maxCorners, $qualityLevel, $minDistance, $blockSize, $useHarrisDetector, $harrisK, ByRef $sharedPtr)
    ; CVAPI(cv::cuda::CornersDetector*) cudaGoodFeaturesToTrackDetectorCreate(int srcType, int maxCorners, double qualityLevel, double minDistance, int blockSize, bool useHarrisDetector, double harrisK, cv::Ptr<cv::cuda::CornersDetector>** sharedPtr);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cudaGoodFeaturesToTrackDetectorCreate", "int", $srcType, "int", $maxCorners, "double", $qualityLevel, "double", $minDistance, "int", $blockSize, "boolean", $useHarrisDetector, "double", $harrisK, "ptr*", $sharedPtr), "cudaGoodFeaturesToTrackDetectorCreate", @error)
EndFunc   ;==>_cudaGoodFeaturesToTrackDetectorCreate

Func _cudaCornersDetectorDetect(ByRef $detector, ByRef $image, ByRef $corners, ByRef $mask, ByRef $stream)
    ; CVAPI(void) cudaCornersDetectorDetect(cv::cuda::CornersDetector* detector, cv::_InputArray* image, cv::_OutputArray* corners, cv::_InputArray* mask, cv::cuda::Stream* stream);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaCornersDetectorDetect", "ptr", $detector, "ptr", $image, "ptr", $corners, "ptr", $mask, "ptr", $stream), "cudaCornersDetectorDetect", @error)
EndFunc   ;==>_cudaCornersDetectorDetect

Func _cudaCornersDetectorDetectMat(ByRef $detector, ByRef $matImage, ByRef $matCorners, ByRef $matMask, ByRef $stream)
    ; cudaCornersDetectorDetect using cv::Mat instead of _*Array

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

    Local $oArrCorners, $vectorOfMatCorners, $iArrCornersSize
    Local $bCornersIsArray = VarGetType($matCorners) == "Array"

    If $bCornersIsArray Then
        $vectorOfMatCorners = _VectorOfMatCreate()

        $iArrCornersSize = UBound($matCorners)
        For $i = 0 To $iArrCornersSize - 1
            _VectorOfMatPush($vectorOfMatCorners, $matCorners[$i])
        Next

        $oArrCorners = _cveOutputArrayFromVectorOfMat($vectorOfMatCorners)
    Else
        $oArrCorners = _cveOutputArrayFromMat($matCorners)
    EndIf

    Local $iArrMask, $vectorOfMatMask, $iArrMaskSize
    Local $bMaskIsArray = VarGetType($matMask) == "Array"

    If $bMaskIsArray Then
        $vectorOfMatMask = _VectorOfMatCreate()

        $iArrMaskSize = UBound($matMask)
        For $i = 0 To $iArrMaskSize - 1
            _VectorOfMatPush($vectorOfMatMask, $matMask[$i])
        Next

        $iArrMask = _cveInputArrayFromVectorOfMat($vectorOfMatMask)
    Else
        $iArrMask = _cveInputArrayFromMat($matMask)
    EndIf

    _cudaCornersDetectorDetect($detector, $iArrImage, $oArrCorners, $iArrMask, $stream)

    If $bMaskIsArray Then
        _VectorOfMatRelease($vectorOfMatMask)
    EndIf

    _cveInputArrayRelease($iArrMask)

    If $bCornersIsArray Then
        _VectorOfMatRelease($vectorOfMatCorners)
    EndIf

    _cveOutputArrayRelease($oArrCorners)

    If $bImageIsArray Then
        _VectorOfMatRelease($vectorOfMatImage)
    EndIf

    _cveInputArrayRelease($iArrImage)
EndFunc   ;==>_cudaCornersDetectorDetectMat

Func _cudaCornersDetectorRelease(ByRef $detector)
    ; CVAPI(void) cudaCornersDetectorRelease(cv::Ptr<cv::cuda::CornersDetector>** detector);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaCornersDetectorRelease", "ptr*", $detector), "cudaCornersDetectorRelease", @error)
EndFunc   ;==>_cudaCornersDetectorRelease

Func _cudaTemplateMatchingCreate($srcType, $method, ByRef $blockSize, ByRef $sharedPtr)
    ; CVAPI(cv::cuda::TemplateMatching*) cudaTemplateMatchingCreate(int srcType, int method, CvSize* blockSize, cv::Ptr<cv::cuda::TemplateMatching>** sharedPtr);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cudaTemplateMatchingCreate", "int", $srcType, "int", $method, "struct*", $blockSize, "ptr*", $sharedPtr), "cudaTemplateMatchingCreate", @error)
EndFunc   ;==>_cudaTemplateMatchingCreate

Func _cudaTemplateMatchingRelease(ByRef $tm)
    ; CVAPI(void) cudaTemplateMatchingRelease(cv::Ptr<cv::cuda::TemplateMatching>** tm);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaTemplateMatchingRelease", "ptr*", $tm), "cudaTemplateMatchingRelease", @error)
EndFunc   ;==>_cudaTemplateMatchingRelease

Func _cudaTemplateMatchingMatch(ByRef $tm, ByRef $image, ByRef $templ, ByRef $result, ByRef $stream)
    ; CVAPI(void) cudaTemplateMatchingMatch(cv::cuda::TemplateMatching* tm, cv::_InputArray* image, cv::_InputArray* templ, cv::_OutputArray* result, cv::cuda::Stream* stream);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaTemplateMatchingMatch", "ptr", $tm, "ptr", $image, "ptr", $templ, "ptr", $result, "ptr", $stream), "cudaTemplateMatchingMatch", @error)
EndFunc   ;==>_cudaTemplateMatchingMatch

Func _cudaTemplateMatchingMatchMat(ByRef $tm, ByRef $matImage, ByRef $matTempl, ByRef $matResult, ByRef $stream)
    ; cudaTemplateMatchingMatch using cv::Mat instead of _*Array

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

    Local $iArrTempl, $vectorOfMatTempl, $iArrTemplSize
    Local $bTemplIsArray = VarGetType($matTempl) == "Array"

    If $bTemplIsArray Then
        $vectorOfMatTempl = _VectorOfMatCreate()

        $iArrTemplSize = UBound($matTempl)
        For $i = 0 To $iArrTemplSize - 1
            _VectorOfMatPush($vectorOfMatTempl, $matTempl[$i])
        Next

        $iArrTempl = _cveInputArrayFromVectorOfMat($vectorOfMatTempl)
    Else
        $iArrTempl = _cveInputArrayFromMat($matTempl)
    EndIf

    Local $oArrResult, $vectorOfMatResult, $iArrResultSize
    Local $bResultIsArray = VarGetType($matResult) == "Array"

    If $bResultIsArray Then
        $vectorOfMatResult = _VectorOfMatCreate()

        $iArrResultSize = UBound($matResult)
        For $i = 0 To $iArrResultSize - 1
            _VectorOfMatPush($vectorOfMatResult, $matResult[$i])
        Next

        $oArrResult = _cveOutputArrayFromVectorOfMat($vectorOfMatResult)
    Else
        $oArrResult = _cveOutputArrayFromMat($matResult)
    EndIf

    _cudaTemplateMatchingMatch($tm, $iArrImage, $iArrTempl, $oArrResult, $stream)

    If $bResultIsArray Then
        _VectorOfMatRelease($vectorOfMatResult)
    EndIf

    _cveOutputArrayRelease($oArrResult)

    If $bTemplIsArray Then
        _VectorOfMatRelease($vectorOfMatTempl)
    EndIf

    _cveInputArrayRelease($iArrTempl)

    If $bImageIsArray Then
        _VectorOfMatRelease($vectorOfMatImage)
    EndIf

    _cveInputArrayRelease($iArrImage)
EndFunc   ;==>_cudaTemplateMatchingMatchMat

Func _cudaHoughLinesDetectorCreate($rho, $theta, $threshold, $doSort, $maxLines, ByRef $sharedPtr)
    ; CVAPI(cv::cuda::HoughLinesDetector*) cudaHoughLinesDetectorCreate(float rho, float theta, int threshold, bool doSort, int maxLines, cv::Ptr<cv::cuda::HoughLinesDetector>** sharedPtr);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cudaHoughLinesDetectorCreate", "float", $rho, "float", $theta, "int", $threshold, "boolean", $doSort, "int", $maxLines, "ptr*", $sharedPtr), "cudaHoughLinesDetectorCreate", @error)
EndFunc   ;==>_cudaHoughLinesDetectorCreate

Func _cudaHoughLinesDetectorDetect(ByRef $detector, ByRef $src, ByRef $lines, ByRef $stream)
    ; CVAPI(void) cudaHoughLinesDetectorDetect(cv::cuda::HoughLinesDetector* detector, cv::_InputArray* src, cv::_OutputArray* lines, cv::cuda::Stream* stream);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaHoughLinesDetectorDetect", "ptr", $detector, "ptr", $src, "ptr", $lines, "ptr", $stream), "cudaHoughLinesDetectorDetect", @error)
EndFunc   ;==>_cudaHoughLinesDetectorDetect

Func _cudaHoughLinesDetectorDetectMat(ByRef $detector, ByRef $matSrc, ByRef $matLines, ByRef $stream)
    ; cudaHoughLinesDetectorDetect using cv::Mat instead of _*Array

    Local $iArrSrc, $vectorOfMatSrc, $iArrSrcSize
    Local $bSrcIsArray = VarGetType($matSrc) == "Array"

    If $bSrcIsArray Then
        $vectorOfMatSrc = _VectorOfMatCreate()

        $iArrSrcSize = UBound($matSrc)
        For $i = 0 To $iArrSrcSize - 1
            _VectorOfMatPush($vectorOfMatSrc, $matSrc[$i])
        Next

        $iArrSrc = _cveInputArrayFromVectorOfMat($vectorOfMatSrc)
    Else
        $iArrSrc = _cveInputArrayFromMat($matSrc)
    EndIf

    Local $oArrLines, $vectorOfMatLines, $iArrLinesSize
    Local $bLinesIsArray = VarGetType($matLines) == "Array"

    If $bLinesIsArray Then
        $vectorOfMatLines = _VectorOfMatCreate()

        $iArrLinesSize = UBound($matLines)
        For $i = 0 To $iArrLinesSize - 1
            _VectorOfMatPush($vectorOfMatLines, $matLines[$i])
        Next

        $oArrLines = _cveOutputArrayFromVectorOfMat($vectorOfMatLines)
    Else
        $oArrLines = _cveOutputArrayFromMat($matLines)
    EndIf

    _cudaHoughLinesDetectorDetect($detector, $iArrSrc, $oArrLines, $stream)

    If $bLinesIsArray Then
        _VectorOfMatRelease($vectorOfMatLines)
    EndIf

    _cveOutputArrayRelease($oArrLines)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)
EndFunc   ;==>_cudaHoughLinesDetectorDetectMat

Func _cudaHoughLinesDetectorRelease(ByRef $detector)
    ; CVAPI(void) cudaHoughLinesDetectorRelease(cv::Ptr<cv::cuda::HoughLinesDetector>** detector);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaHoughLinesDetectorRelease", "ptr*", $detector), "cudaHoughLinesDetectorRelease", @error)
EndFunc   ;==>_cudaHoughLinesDetectorRelease

Func _cudaHoughSegmentDetectorCreate($rho, $theta, $minLineLength, $maxLineGap, $maxLines, ByRef $sharedPtr)
    ; CVAPI(cv::cuda::HoughSegmentDetector*) cudaHoughSegmentDetectorCreate(float rho, float theta, int minLineLength, int maxLineGap, int maxLines, cv::Ptr<cv::cuda::HoughSegmentDetector>** sharedPtr);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cudaHoughSegmentDetectorCreate", "float", $rho, "float", $theta, "int", $minLineLength, "int", $maxLineGap, "int", $maxLines, "ptr*", $sharedPtr), "cudaHoughSegmentDetectorCreate", @error)
EndFunc   ;==>_cudaHoughSegmentDetectorCreate

Func _cudaHoughSegmentDetectorDetect(ByRef $detector, ByRef $src, ByRef $lines, ByRef $stream)
    ; CVAPI(void) cudaHoughSegmentDetectorDetect(cv::cuda::HoughSegmentDetector* detector, cv::_InputArray* src, cv::_OutputArray* lines, cv::cuda::Stream* stream);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaHoughSegmentDetectorDetect", "ptr", $detector, "ptr", $src, "ptr", $lines, "ptr", $stream), "cudaHoughSegmentDetectorDetect", @error)
EndFunc   ;==>_cudaHoughSegmentDetectorDetect

Func _cudaHoughSegmentDetectorDetectMat(ByRef $detector, ByRef $matSrc, ByRef $matLines, ByRef $stream)
    ; cudaHoughSegmentDetectorDetect using cv::Mat instead of _*Array

    Local $iArrSrc, $vectorOfMatSrc, $iArrSrcSize
    Local $bSrcIsArray = VarGetType($matSrc) == "Array"

    If $bSrcIsArray Then
        $vectorOfMatSrc = _VectorOfMatCreate()

        $iArrSrcSize = UBound($matSrc)
        For $i = 0 To $iArrSrcSize - 1
            _VectorOfMatPush($vectorOfMatSrc, $matSrc[$i])
        Next

        $iArrSrc = _cveInputArrayFromVectorOfMat($vectorOfMatSrc)
    Else
        $iArrSrc = _cveInputArrayFromMat($matSrc)
    EndIf

    Local $oArrLines, $vectorOfMatLines, $iArrLinesSize
    Local $bLinesIsArray = VarGetType($matLines) == "Array"

    If $bLinesIsArray Then
        $vectorOfMatLines = _VectorOfMatCreate()

        $iArrLinesSize = UBound($matLines)
        For $i = 0 To $iArrLinesSize - 1
            _VectorOfMatPush($vectorOfMatLines, $matLines[$i])
        Next

        $oArrLines = _cveOutputArrayFromVectorOfMat($vectorOfMatLines)
    Else
        $oArrLines = _cveOutputArrayFromMat($matLines)
    EndIf

    _cudaHoughSegmentDetectorDetect($detector, $iArrSrc, $oArrLines, $stream)

    If $bLinesIsArray Then
        _VectorOfMatRelease($vectorOfMatLines)
    EndIf

    _cveOutputArrayRelease($oArrLines)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)
EndFunc   ;==>_cudaHoughSegmentDetectorDetectMat

Func _cudaHoughSegmentDetectorRelease(ByRef $detector)
    ; CVAPI(void) cudaHoughSegmentDetectorRelease(cv::Ptr<cv::cuda::HoughSegmentDetector>** detector);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaHoughSegmentDetectorRelease", "ptr*", $detector), "cudaHoughSegmentDetectorRelease", @error)
EndFunc   ;==>_cudaHoughSegmentDetectorRelease

Func _cudaHoughCirclesDetectorCreate($dp, $minDist, $cannyThreshold, $votesThreshold, $minRadius, $maxRadius, $maxCircles, ByRef $sharedPtr)
    ; CVAPI(cv::cuda::HoughCirclesDetector*) cudaHoughCirclesDetectorCreate(float dp, float minDist, int cannyThreshold, int votesThreshold, int minRadius, int maxRadius, int maxCircles, cv::Ptr<cv::cuda::HoughCirclesDetector>** sharedPtr);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cudaHoughCirclesDetectorCreate", "float", $dp, "float", $minDist, "int", $cannyThreshold, "int", $votesThreshold, "int", $minRadius, "int", $maxRadius, "int", $maxCircles, "ptr*", $sharedPtr), "cudaHoughCirclesDetectorCreate", @error)
EndFunc   ;==>_cudaHoughCirclesDetectorCreate

Func _cudaHoughCirclesDetectorDetect(ByRef $detector, ByRef $src, ByRef $circles, ByRef $stream)
    ; CVAPI(void) cudaHoughCirclesDetectorDetect(cv::cuda::HoughCirclesDetector* detector, cv::_InputArray* src, cv::_OutputArray* circles, cv::cuda::Stream* stream);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaHoughCirclesDetectorDetect", "ptr", $detector, "ptr", $src, "ptr", $circles, "ptr", $stream), "cudaHoughCirclesDetectorDetect", @error)
EndFunc   ;==>_cudaHoughCirclesDetectorDetect

Func _cudaHoughCirclesDetectorDetectMat(ByRef $detector, ByRef $matSrc, ByRef $matCircles, ByRef $stream)
    ; cudaHoughCirclesDetectorDetect using cv::Mat instead of _*Array

    Local $iArrSrc, $vectorOfMatSrc, $iArrSrcSize
    Local $bSrcIsArray = VarGetType($matSrc) == "Array"

    If $bSrcIsArray Then
        $vectorOfMatSrc = _VectorOfMatCreate()

        $iArrSrcSize = UBound($matSrc)
        For $i = 0 To $iArrSrcSize - 1
            _VectorOfMatPush($vectorOfMatSrc, $matSrc[$i])
        Next

        $iArrSrc = _cveInputArrayFromVectorOfMat($vectorOfMatSrc)
    Else
        $iArrSrc = _cveInputArrayFromMat($matSrc)
    EndIf

    Local $oArrCircles, $vectorOfMatCircles, $iArrCirclesSize
    Local $bCirclesIsArray = VarGetType($matCircles) == "Array"

    If $bCirclesIsArray Then
        $vectorOfMatCircles = _VectorOfMatCreate()

        $iArrCirclesSize = UBound($matCircles)
        For $i = 0 To $iArrCirclesSize - 1
            _VectorOfMatPush($vectorOfMatCircles, $matCircles[$i])
        Next

        $oArrCircles = _cveOutputArrayFromVectorOfMat($vectorOfMatCircles)
    Else
        $oArrCircles = _cveOutputArrayFromMat($matCircles)
    EndIf

    _cudaHoughCirclesDetectorDetect($detector, $iArrSrc, $oArrCircles, $stream)

    If $bCirclesIsArray Then
        _VectorOfMatRelease($vectorOfMatCircles)
    EndIf

    _cveOutputArrayRelease($oArrCircles)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)
EndFunc   ;==>_cudaHoughCirclesDetectorDetectMat

Func _cudaHoughCirclesDetectorRelease(ByRef $detector)
    ; CVAPI(void) cudaHoughCirclesDetectorRelease(cv::Ptr<cv::cuda::HoughCirclesDetector>** detector);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaHoughCirclesDetectorRelease", "ptr*", $detector), "cudaHoughCirclesDetectorRelease", @error)
EndFunc   ;==>_cudaHoughCirclesDetectorRelease

Func _cudaGammaCorrection(ByRef $src, ByRef $dst, $forward, ByRef $stream)
    ; CVAPI(void) cudaGammaCorrection(cv::_InputArray* src, cv::_OutputArray* dst, bool forward, cv::cuda::Stream* stream);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cudaGammaCorrection", "ptr", $src, "ptr", $dst, "boolean", $forward, "ptr", $stream), "cudaGammaCorrection", @error)
EndFunc   ;==>_cudaGammaCorrection

Func _cudaGammaCorrectionMat(ByRef $matSrc, ByRef $matDst, $forward, ByRef $stream)
    ; cudaGammaCorrection using cv::Mat instead of _*Array

    Local $iArrSrc, $vectorOfMatSrc, $iArrSrcSize
    Local $bSrcIsArray = VarGetType($matSrc) == "Array"

    If $bSrcIsArray Then
        $vectorOfMatSrc = _VectorOfMatCreate()

        $iArrSrcSize = UBound($matSrc)
        For $i = 0 To $iArrSrcSize - 1
            _VectorOfMatPush($vectorOfMatSrc, $matSrc[$i])
        Next

        $iArrSrc = _cveInputArrayFromVectorOfMat($vectorOfMatSrc)
    Else
        $iArrSrc = _cveInputArrayFromMat($matSrc)
    EndIf

    Local $oArrDst, $vectorOfMatDst, $iArrDstSize
    Local $bDstIsArray = VarGetType($matDst) == "Array"

    If $bDstIsArray Then
        $vectorOfMatDst = _VectorOfMatCreate()

        $iArrDstSize = UBound($matDst)
        For $i = 0 To $iArrDstSize - 1
            _VectorOfMatPush($vectorOfMatDst, $matDst[$i])
        Next

        $oArrDst = _cveOutputArrayFromVectorOfMat($vectorOfMatDst)
    Else
        $oArrDst = _cveOutputArrayFromMat($matDst)
    EndIf

    _cudaGammaCorrection($iArrSrc, $oArrDst, $forward, $stream)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveOutputArrayRelease($oArrDst)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)
EndFunc   ;==>_cudaGammaCorrectionMat