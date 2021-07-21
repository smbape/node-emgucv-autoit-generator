#include-once
#include "..\..\CVEUtils.au3"

Func _cveWhiteBalancerBalanceWhite($whiteBalancer, $src, $dst)
    ; CVAPI(void) cveWhiteBalancerBalanceWhite(cv::xphoto::WhiteBalancer* whiteBalancer, cv::_InputArray* src, cv::_OutputArray* dst);

    Local $bWhiteBalancerDllType
    If VarGetType($whiteBalancer) == "DLLStruct" Then
        $bWhiteBalancerDllType = "struct*"
    Else
        $bWhiteBalancerDllType = "ptr"
    EndIf

    Local $bSrcDllType
    If VarGetType($src) == "DLLStruct" Then
        $bSrcDllType = "struct*"
    Else
        $bSrcDllType = "ptr"
    EndIf

    Local $bDstDllType
    If VarGetType($dst) == "DLLStruct" Then
        $bDstDllType = "struct*"
    Else
        $bDstDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveWhiteBalancerBalanceWhite", $bWhiteBalancerDllType, $whiteBalancer, $bSrcDllType, $src, $bDstDllType, $dst), "cveWhiteBalancerBalanceWhite", @error)
EndFunc   ;==>_cveWhiteBalancerBalanceWhite

Func _cveWhiteBalancerBalanceWhiteMat($whiteBalancer, $matSrc, $matDst)
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

Func _cveSimpleWBCreate($whiteBalancer, $sharedPtr)
    ; CVAPI(cv::xphoto::SimpleWB*) cveSimpleWBCreate(cv::xphoto::WhiteBalancer** whiteBalancer, cv::Ptr<cv::xphoto::SimpleWB>** sharedPtr);

    Local $bWhiteBalancerDllType
    If VarGetType($whiteBalancer) == "DLLStruct" Then
        $bWhiteBalancerDllType = "struct*"
    Else
        $bWhiteBalancerDllType = "ptr*"
    EndIf

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveSimpleWBCreate", $bWhiteBalancerDllType, $whiteBalancer, $bSharedPtrDllType, $sharedPtr), "cveSimpleWBCreate", @error)
EndFunc   ;==>_cveSimpleWBCreate

Func _cveSimpleWBRelease($sharedPtr)
    ; CVAPI(void) cveSimpleWBRelease(cv::Ptr<cv::xphoto::SimpleWB>** sharedPtr);

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSimpleWBRelease", $bSharedPtrDllType, $sharedPtr), "cveSimpleWBRelease", @error)
EndFunc   ;==>_cveSimpleWBRelease

Func _cveGrayworldWBCreate($whiteBalancer, $sharedPtr)
    ; CVAPI(cv::xphoto::GrayworldWB*) cveGrayworldWBCreate(cv::xphoto::WhiteBalancer** whiteBalancer, cv::Ptr<cv::xphoto::GrayworldWB>** sharedPtr);

    Local $bWhiteBalancerDllType
    If VarGetType($whiteBalancer) == "DLLStruct" Then
        $bWhiteBalancerDllType = "struct*"
    Else
        $bWhiteBalancerDllType = "ptr*"
    EndIf

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGrayworldWBCreate", $bWhiteBalancerDllType, $whiteBalancer, $bSharedPtrDllType, $sharedPtr), "cveGrayworldWBCreate", @error)
EndFunc   ;==>_cveGrayworldWBCreate

Func _cveGrayworldWBRelease($sharedPtr)
    ; CVAPI(void) cveGrayworldWBRelease(cv::Ptr<cv::xphoto::GrayworldWB>** sharedPtr);

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveGrayworldWBRelease", $bSharedPtrDllType, $sharedPtr), "cveGrayworldWBRelease", @error)
EndFunc   ;==>_cveGrayworldWBRelease

Func _cveLearningBasedWBCreate($whiteBalancer, $sharedPtr)
    ; CVAPI(cv::xphoto::LearningBasedWB*) cveLearningBasedWBCreate(cv::xphoto::WhiteBalancer** whiteBalancer, cv::Ptr<cv::xphoto::LearningBasedWB>** sharedPtr);

    Local $bWhiteBalancerDllType
    If VarGetType($whiteBalancer) == "DLLStruct" Then
        $bWhiteBalancerDllType = "struct*"
    Else
        $bWhiteBalancerDllType = "ptr*"
    EndIf

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveLearningBasedWBCreate", $bWhiteBalancerDllType, $whiteBalancer, $bSharedPtrDllType, $sharedPtr), "cveLearningBasedWBCreate", @error)
EndFunc   ;==>_cveLearningBasedWBCreate

Func _cveLearningBasedWBRelease($sharedPtr)
    ; CVAPI(void) cveLearningBasedWBRelease(cv::Ptr<cv::xphoto::LearningBasedWB>** sharedPtr);

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveLearningBasedWBRelease", $bSharedPtrDllType, $sharedPtr), "cveLearningBasedWBRelease", @error)
EndFunc   ;==>_cveLearningBasedWBRelease

Func _cveApplyChannelGains($src, $dst, $gainB, $gainG, $gainR)
    ; CVAPI(void) cveApplyChannelGains(cv::_InputArray* src, cv::_OutputArray* dst, float gainB, float gainG, float gainR);

    Local $bSrcDllType
    If VarGetType($src) == "DLLStruct" Then
        $bSrcDllType = "struct*"
    Else
        $bSrcDllType = "ptr"
    EndIf

    Local $bDstDllType
    If VarGetType($dst) == "DLLStruct" Then
        $bDstDllType = "struct*"
    Else
        $bDstDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveApplyChannelGains", $bSrcDllType, $src, $bDstDllType, $dst, "float", $gainB, "float", $gainG, "float", $gainR), "cveApplyChannelGains", @error)
EndFunc   ;==>_cveApplyChannelGains

Func _cveApplyChannelGainsMat($matSrc, $matDst, $gainB, $gainG, $gainR)
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

Func _cveDctDenoising($src, $dst, $sigma, $psize)
    ; CVAPI(void) cveDctDenoising(const cv::Mat* src, cv::Mat* dst, const double sigma, const int psize);

    Local $bSrcDllType
    If VarGetType($src) == "DLLStruct" Then
        $bSrcDllType = "struct*"
    Else
        $bSrcDllType = "ptr"
    EndIf

    Local $bDstDllType
    If VarGetType($dst) == "DLLStruct" Then
        $bDstDllType = "struct*"
    Else
        $bDstDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDctDenoising", $bSrcDllType, $src, $bDstDllType, $dst, "double", $sigma, "int", $psize), "cveDctDenoising", @error)
EndFunc   ;==>_cveDctDenoising

Func _cveXInpaint($src, $mask, $dst, $algorithmType)
    ; CVAPI(void) cveXInpaint(const cv::Mat* src, const cv::Mat* mask, cv::Mat* dst, const int algorithmType);

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

    Local $bDstDllType
    If VarGetType($dst) == "DLLStruct" Then
        $bDstDllType = "struct*"
    Else
        $bDstDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveXInpaint", $bSrcDllType, $src, $bMaskDllType, $mask, $bDstDllType, $dst, "int", $algorithmType), "cveXInpaint", @error)
EndFunc   ;==>_cveXInpaint

Func _cveBm3dDenoising1($src, $dstStep1, $dstStep2, $h, $templateWindowSize, $searchWindowSize, $blockMatchingStep1, $blockMatchingStep2, $groupSize, $slidingStep, $beta, $normType, $step, $transformType)
    ; CVAPI(void) cveBm3dDenoising1(cv::_InputArray* src, cv::_InputOutputArray* dstStep1, cv::_OutputArray* dstStep2, float h, int templateWindowSize, int searchWindowSize, int blockMatchingStep1, int blockMatchingStep2, int groupSize, int slidingStep, float beta, int normType, int step, int transformType);

    Local $bSrcDllType
    If VarGetType($src) == "DLLStruct" Then
        $bSrcDllType = "struct*"
    Else
        $bSrcDllType = "ptr"
    EndIf

    Local $bDstStep1DllType
    If VarGetType($dstStep1) == "DLLStruct" Then
        $bDstStep1DllType = "struct*"
    Else
        $bDstStep1DllType = "ptr"
    EndIf

    Local $bDstStep2DllType
    If VarGetType($dstStep2) == "DLLStruct" Then
        $bDstStep2DllType = "struct*"
    Else
        $bDstStep2DllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBm3dDenoising1", $bSrcDllType, $src, $bDstStep1DllType, $dstStep1, $bDstStep2DllType, $dstStep2, "float", $h, "int", $templateWindowSize, "int", $searchWindowSize, "int", $blockMatchingStep1, "int", $blockMatchingStep2, "int", $groupSize, "int", $slidingStep, "float", $beta, "int", $normType, "int", $step, "int", $transformType), "cveBm3dDenoising1", @error)
EndFunc   ;==>_cveBm3dDenoising1

Func _cveBm3dDenoising1Mat($matSrc, $matDstStep1, $matDstStep2, $h, $templateWindowSize, $searchWindowSize, $blockMatchingStep1, $blockMatchingStep2, $groupSize, $slidingStep, $beta, $normType, $step, $transformType)
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

Func _cveBm3dDenoising2($src, $dst, $h, $templateWindowSize, $searchWindowSize, $blockMatchingStep1, $blockMatchingStep2, $groupSize, $slidingStep, $beta, $normType, $step, $transformType)
    ; CVAPI(void) cveBm3dDenoising2(cv::_InputArray* src, cv::_OutputArray* dst, float h, int templateWindowSize, int searchWindowSize, int blockMatchingStep1, int blockMatchingStep2, int groupSize, int slidingStep, float beta, int normType, int step, int transformType);

    Local $bSrcDllType
    If VarGetType($src) == "DLLStruct" Then
        $bSrcDllType = "struct*"
    Else
        $bSrcDllType = "ptr"
    EndIf

    Local $bDstDllType
    If VarGetType($dst) == "DLLStruct" Then
        $bDstDllType = "struct*"
    Else
        $bDstDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBm3dDenoising2", $bSrcDllType, $src, $bDstDllType, $dst, "float", $h, "int", $templateWindowSize, "int", $searchWindowSize, "int", $blockMatchingStep1, "int", $blockMatchingStep2, "int", $groupSize, "int", $slidingStep, "float", $beta, "int", $normType, "int", $step, "int", $transformType), "cveBm3dDenoising2", @error)
EndFunc   ;==>_cveBm3dDenoising2

Func _cveBm3dDenoising2Mat($matSrc, $matDst, $h, $templateWindowSize, $searchWindowSize, $blockMatchingStep1, $blockMatchingStep2, $groupSize, $slidingStep, $beta, $normType, $step, $transformType)
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

Func _cveOilPainting($src, $dst, $size, $dynRatio, $code)
    ; CVAPI(void) cveOilPainting(cv::_InputArray* src, cv::_OutputArray* dst, int size, int dynRatio, int code);

    Local $bSrcDllType
    If VarGetType($src) == "DLLStruct" Then
        $bSrcDllType = "struct*"
    Else
        $bSrcDllType = "ptr"
    EndIf

    Local $bDstDllType
    If VarGetType($dst) == "DLLStruct" Then
        $bDstDllType = "struct*"
    Else
        $bDstDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveOilPainting", $bSrcDllType, $src, $bDstDllType, $dst, "int", $size, "int", $dynRatio, "int", $code), "cveOilPainting", @error)
EndFunc   ;==>_cveOilPainting

Func _cveOilPaintingMat($matSrc, $matDst, $size, $dynRatio, $code)
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

Func _cveTonemapDurandCreate($gamma, $contrast, $saturation, $sigmaSpace, $sigmaColor, $tonemap, $algorithm, $sharedPtr)
    ; CVAPI(cv::xphoto::TonemapDurand*) cveTonemapDurandCreate(float gamma, float contrast, float saturation, float sigmaSpace, float sigmaColor, cv::Tonemap** tonemap, cv::Algorithm** algorithm, cv::Ptr<cv::xphoto::TonemapDurand>** sharedPtr);

    Local $bTonemapDllType
    If VarGetType($tonemap) == "DLLStruct" Then
        $bTonemapDllType = "struct*"
    Else
        $bTonemapDllType = "ptr*"
    EndIf

    Local $bAlgorithmDllType
    If VarGetType($algorithm) == "DLLStruct" Then
        $bAlgorithmDllType = "struct*"
    Else
        $bAlgorithmDllType = "ptr*"
    EndIf

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveTonemapDurandCreate", "float", $gamma, "float", $contrast, "float", $saturation, "float", $sigmaSpace, "float", $sigmaColor, $bTonemapDllType, $tonemap, $bAlgorithmDllType, $algorithm, $bSharedPtrDllType, $sharedPtr), "cveTonemapDurandCreate", @error)
EndFunc   ;==>_cveTonemapDurandCreate

Func _cveTonemapDurandRelease($sharedPtr)
    ; CVAPI(void) cveTonemapDurandRelease(cv::Ptr<cv::xphoto::TonemapDurand>** sharedPtr);

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveTonemapDurandRelease", $bSharedPtrDllType, $sharedPtr), "cveTonemapDurandRelease", @error)
EndFunc   ;==>_cveTonemapDurandRelease