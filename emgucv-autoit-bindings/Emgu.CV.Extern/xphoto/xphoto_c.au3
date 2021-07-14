#include-once
#include <..\..\CVEUtils.au3>

Func _cveWhiteBalancerBalanceWhite(ByRef $whiteBalancer, ByRef $src, ByRef $dst)
    ; CVAPI(void) cveWhiteBalancerBalanceWhite(cv::xphoto::WhiteBalancer* whiteBalancer, cv::_InputArray* src, cv::_OutputArray* dst);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveWhiteBalancerBalanceWhite", "ptr", $whiteBalancer, "ptr", $src, "ptr", $dst), "cveWhiteBalancerBalanceWhite", @error)
EndFunc   ;==>_cveWhiteBalancerBalanceWhite

Func _cveWhiteBalancerBalanceWhiteMat(ByRef $whiteBalancer, ByRef $matSrc, ByRef $matDst)
    ; cveWhiteBalancerBalanceWhite using cv::Mat instead of _*Array

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

    _cveWhiteBalancerBalanceWhite($whiteBalancer, $iArrSrc, $oArrDst)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveOutputArrayRelease($oArrDst)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)
EndFunc   ;==>_cveWhiteBalancerBalanceWhiteMat

Func _cveSimpleWBCreate(ByRef $whiteBalancer, ByRef $sharedPtr)
    ; CVAPI(cv::xphoto::SimpleWB*) cveSimpleWBCreate(cv::xphoto::WhiteBalancer** whiteBalancer, cv::Ptr<cv::xphoto::SimpleWB>** sharedPtr);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveSimpleWBCreate", "ptr*", $whiteBalancer, "ptr*", $sharedPtr), "cveSimpleWBCreate", @error)
EndFunc   ;==>_cveSimpleWBCreate

Func _cveSimpleWBRelease(ByRef $sharedPtr)
    ; CVAPI(void) cveSimpleWBRelease(cv::Ptr<cv::xphoto::SimpleWB>** sharedPtr);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSimpleWBRelease", "ptr*", $sharedPtr), "cveSimpleWBRelease", @error)
EndFunc   ;==>_cveSimpleWBRelease

Func _cveGrayworldWBCreate(ByRef $whiteBalancer, ByRef $sharedPtr)
    ; CVAPI(cv::xphoto::GrayworldWB*) cveGrayworldWBCreate(cv::xphoto::WhiteBalancer** whiteBalancer, cv::Ptr<cv::xphoto::GrayworldWB>** sharedPtr);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGrayworldWBCreate", "ptr*", $whiteBalancer, "ptr*", $sharedPtr), "cveGrayworldWBCreate", @error)
EndFunc   ;==>_cveGrayworldWBCreate

Func _cveGrayworldWBRelease(ByRef $sharedPtr)
    ; CVAPI(void) cveGrayworldWBRelease(cv::Ptr<cv::xphoto::GrayworldWB>** sharedPtr);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveGrayworldWBRelease", "ptr*", $sharedPtr), "cveGrayworldWBRelease", @error)
EndFunc   ;==>_cveGrayworldWBRelease

Func _cveLearningBasedWBCreate(ByRef $whiteBalancer, ByRef $sharedPtr)
    ; CVAPI(cv::xphoto::LearningBasedWB*) cveLearningBasedWBCreate(cv::xphoto::WhiteBalancer** whiteBalancer, cv::Ptr<cv::xphoto::LearningBasedWB>** sharedPtr);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveLearningBasedWBCreate", "ptr*", $whiteBalancer, "ptr*", $sharedPtr), "cveLearningBasedWBCreate", @error)
EndFunc   ;==>_cveLearningBasedWBCreate

Func _cveLearningBasedWBRelease(ByRef $sharedPtr)
    ; CVAPI(void) cveLearningBasedWBRelease(cv::Ptr<cv::xphoto::LearningBasedWB>** sharedPtr);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveLearningBasedWBRelease", "ptr*", $sharedPtr), "cveLearningBasedWBRelease", @error)
EndFunc   ;==>_cveLearningBasedWBRelease

Func _cveApplyChannelGains(ByRef $src, ByRef $dst, $gainB, $gainG, $gainR)
    ; CVAPI(void) cveApplyChannelGains(cv::_InputArray* src, cv::_OutputArray* dst, float gainB, float gainG, float gainR);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveApplyChannelGains", "ptr", $src, "ptr", $dst, "float", $gainB, "float", $gainG, "float", $gainR), "cveApplyChannelGains", @error)
EndFunc   ;==>_cveApplyChannelGains

Func _cveApplyChannelGainsMat(ByRef $matSrc, ByRef $matDst, $gainB, $gainG, $gainR)
    ; cveApplyChannelGains using cv::Mat instead of _*Array

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

    _cveApplyChannelGains($iArrSrc, $oArrDst, $gainB, $gainG, $gainR)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveOutputArrayRelease($oArrDst)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)
EndFunc   ;==>_cveApplyChannelGainsMat

Func _cveDctDenoising($src, ByRef $dst, $sigma, $psize)
    ; CVAPI(void) cveDctDenoising(const cv::Mat* src, cv::Mat* dst, const double sigma, const int psize);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDctDenoising", "ptr", $src, "ptr", $dst, "const double", $sigma, "const int", $psize), "cveDctDenoising", @error)
EndFunc   ;==>_cveDctDenoising

Func _cveXInpaint($src, $mask, ByRef $dst, $algorithmType)
    ; CVAPI(void) cveXInpaint(const cv::Mat* src, const cv::Mat* mask, cv::Mat* dst, const int algorithmType);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveXInpaint", "ptr", $src, "ptr", $mask, "ptr", $dst, "const int", $algorithmType), "cveXInpaint", @error)
EndFunc   ;==>_cveXInpaint

Func _cveBm3dDenoising1(ByRef $src, ByRef $dstStep1, ByRef $dstStep2, $h, $templateWindowSize, $searchWindowSize, $blockMatchingStep1, $blockMatchingStep2, $groupSize, $slidingStep, $beta, $normType, $step, $transformType)
    ; CVAPI(void) cveBm3dDenoising1(cv::_InputArray* src, cv::_InputOutputArray* dstStep1, cv::_OutputArray* dstStep2, float h, int templateWindowSize, int searchWindowSize, int blockMatchingStep1, int blockMatchingStep2, int groupSize, int slidingStep, float beta, int normType, int step, int transformType);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBm3dDenoising1", "ptr", $src, "ptr", $dstStep1, "ptr", $dstStep2, "float", $h, "int", $templateWindowSize, "int", $searchWindowSize, "int", $blockMatchingStep1, "int", $blockMatchingStep2, "int", $groupSize, "int", $slidingStep, "float", $beta, "int", $normType, "int", $step, "int", $transformType), "cveBm3dDenoising1", @error)
EndFunc   ;==>_cveBm3dDenoising1

Func _cveBm3dDenoising1Mat(ByRef $matSrc, ByRef $matDstStep1, ByRef $matDstStep2, $h, $templateWindowSize, $searchWindowSize, $blockMatchingStep1, $blockMatchingStep2, $groupSize, $slidingStep, $beta, $normType, $step, $transformType)
    ; cveBm3dDenoising1 using cv::Mat instead of _*Array

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

    Local $ioArrDstStep1, $vectorOfMatDstStep1, $iArrDstStep1Size
    Local $bDstStep1IsArray = VarGetType($matDstStep1) == "Array"

    If $bDstStep1IsArray Then
        $vectorOfMatDstStep1 = _VectorOfMatCreate()

        $iArrDstStep1Size = UBound($matDstStep1)
        For $i = 0 To $iArrDstStep1Size - 1
            _VectorOfMatPush($vectorOfMatDstStep1, $matDstStep1[$i])
        Next

        $ioArrDstStep1 = _cveInputOutputArrayFromVectorOfMat($vectorOfMatDstStep1)
    Else
        $ioArrDstStep1 = _cveInputOutputArrayFromMat($matDstStep1)
    EndIf

    Local $oArrDstStep2, $vectorOfMatDstStep2, $iArrDstStep2Size
    Local $bDstStep2IsArray = VarGetType($matDstStep2) == "Array"

    If $bDstStep2IsArray Then
        $vectorOfMatDstStep2 = _VectorOfMatCreate()

        $iArrDstStep2Size = UBound($matDstStep2)
        For $i = 0 To $iArrDstStep2Size - 1
            _VectorOfMatPush($vectorOfMatDstStep2, $matDstStep2[$i])
        Next

        $oArrDstStep2 = _cveOutputArrayFromVectorOfMat($vectorOfMatDstStep2)
    Else
        $oArrDstStep2 = _cveOutputArrayFromMat($matDstStep2)
    EndIf

    _cveBm3dDenoising1($iArrSrc, $ioArrDstStep1, $oArrDstStep2, $h, $templateWindowSize, $searchWindowSize, $blockMatchingStep1, $blockMatchingStep2, $groupSize, $slidingStep, $beta, $normType, $step, $transformType)

    If $bDstStep2IsArray Then
        _VectorOfMatRelease($vectorOfMatDstStep2)
    EndIf

    _cveOutputArrayRelease($oArrDstStep2)

    If $bDstStep1IsArray Then
        _VectorOfMatRelease($vectorOfMatDstStep1)
    EndIf

    _cveInputOutputArrayRelease($ioArrDstStep1)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)
EndFunc   ;==>_cveBm3dDenoising1Mat

Func _cveBm3dDenoising2(ByRef $src, ByRef $dst, $h, $templateWindowSize, $searchWindowSize, $blockMatchingStep1, $blockMatchingStep2, $groupSize, $slidingStep, $beta, $normType, $step, $transformType)
    ; CVAPI(void) cveBm3dDenoising2(cv::_InputArray* src, cv::_OutputArray* dst, float h, int templateWindowSize, int searchWindowSize, int blockMatchingStep1, int blockMatchingStep2, int groupSize, int slidingStep, float beta, int normType, int step, int transformType);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBm3dDenoising2", "ptr", $src, "ptr", $dst, "float", $h, "int", $templateWindowSize, "int", $searchWindowSize, "int", $blockMatchingStep1, "int", $blockMatchingStep2, "int", $groupSize, "int", $slidingStep, "float", $beta, "int", $normType, "int", $step, "int", $transformType), "cveBm3dDenoising2", @error)
EndFunc   ;==>_cveBm3dDenoising2

Func _cveBm3dDenoising2Mat(ByRef $matSrc, ByRef $matDst, $h, $templateWindowSize, $searchWindowSize, $blockMatchingStep1, $blockMatchingStep2, $groupSize, $slidingStep, $beta, $normType, $step, $transformType)
    ; cveBm3dDenoising2 using cv::Mat instead of _*Array

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

    _cveBm3dDenoising2($iArrSrc, $oArrDst, $h, $templateWindowSize, $searchWindowSize, $blockMatchingStep1, $blockMatchingStep2, $groupSize, $slidingStep, $beta, $normType, $step, $transformType)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveOutputArrayRelease($oArrDst)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)
EndFunc   ;==>_cveBm3dDenoising2Mat

Func _cveOilPainting(ByRef $src, ByRef $dst, $size, $dynRatio, $code)
    ; CVAPI(void) cveOilPainting(cv::_InputArray* src, cv::_OutputArray* dst, int size, int dynRatio, int code);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveOilPainting", "ptr", $src, "ptr", $dst, "int", $size, "int", $dynRatio, "int", $code), "cveOilPainting", @error)
EndFunc   ;==>_cveOilPainting

Func _cveOilPaintingMat(ByRef $matSrc, ByRef $matDst, $size, $dynRatio, $code)
    ; cveOilPainting using cv::Mat instead of _*Array

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

    _cveOilPainting($iArrSrc, $oArrDst, $size, $dynRatio, $code)

    If $bDstIsArray Then
        _VectorOfMatRelease($vectorOfMatDst)
    EndIf

    _cveOutputArrayRelease($oArrDst)

    If $bSrcIsArray Then
        _VectorOfMatRelease($vectorOfMatSrc)
    EndIf

    _cveInputArrayRelease($iArrSrc)
EndFunc   ;==>_cveOilPaintingMat

Func _cveTonemapDurandCreate($gamma, $contrast, $saturation, $sigmaSpace, $sigmaColor, ByRef $tonemap, ByRef $algorithm, ByRef $sharedPtr)
    ; CVAPI(cv::xphoto::TonemapDurand*) cveTonemapDurandCreate(float gamma, float contrast, float saturation, float sigmaSpace, float sigmaColor, cv::Tonemap** tonemap, cv::Algorithm** algorithm, cv::Ptr<cv::xphoto::TonemapDurand>** sharedPtr);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveTonemapDurandCreate", "float", $gamma, "float", $contrast, "float", $saturation, "float", $sigmaSpace, "float", $sigmaColor, "ptr*", $tonemap, "ptr*", $algorithm, "ptr*", $sharedPtr), "cveTonemapDurandCreate", @error)
EndFunc   ;==>_cveTonemapDurandCreate

Func _cveTonemapDurandRelease(ByRef $sharedPtr)
    ; CVAPI(void) cveTonemapDurandRelease(cv::Ptr<cv::xphoto::TonemapDurand>** sharedPtr);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveTonemapDurandRelease", "ptr*", $sharedPtr), "cveTonemapDurandRelease", @error)
EndFunc   ;==>_cveTonemapDurandRelease