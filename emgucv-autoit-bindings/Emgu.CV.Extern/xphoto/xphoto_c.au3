#include-once
#include "..\..\CVEUtils.au3"

Func _cveWhiteBalancerBalanceWhite($whiteBalancer, $src, $dst)
    ; CVAPI(void) cveWhiteBalancerBalanceWhite(cv::xphoto::WhiteBalancer* whiteBalancer, cv::_InputArray* src, cv::_OutputArray* dst);

    Local $sWhiteBalancerDllType
    If IsDllStruct($whiteBalancer) Then
        $sWhiteBalancerDllType = "struct*"
    Else
        $sWhiteBalancerDllType = "ptr"
    EndIf

    Local $sSrcDllType
    If IsDllStruct($src) Then
        $sSrcDllType = "struct*"
    Else
        $sSrcDllType = "ptr"
    EndIf

    Local $sDstDllType
    If IsDllStruct($dst) Then
        $sDstDllType = "struct*"
    Else
        $sDstDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveWhiteBalancerBalanceWhite", $sWhiteBalancerDllType, $whiteBalancer, $sSrcDllType, $src, $sDstDllType, $dst), "cveWhiteBalancerBalanceWhite", @error)
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

    Local $sWhiteBalancerDllType
    If IsDllStruct($whiteBalancer) Then
        $sWhiteBalancerDllType = "struct*"
    ElseIf $whiteBalancer == Null Then
        $sWhiteBalancerDllType = "ptr"
    Else
        $sWhiteBalancerDllType = "ptr*"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveSimpleWBCreate", $sWhiteBalancerDllType, $whiteBalancer, $sSharedPtrDllType, $sharedPtr), "cveSimpleWBCreate", @error)
EndFunc   ;==>_cveSimpleWBCreate

Func _cveSimpleWBRelease($sharedPtr)
    ; CVAPI(void) cveSimpleWBRelease(cv::Ptr<cv::xphoto::SimpleWB>** sharedPtr);

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSimpleWBRelease", $sSharedPtrDllType, $sharedPtr), "cveSimpleWBRelease", @error)
EndFunc   ;==>_cveSimpleWBRelease

Func _cveGrayworldWBCreate($whiteBalancer, $sharedPtr)
    ; CVAPI(cv::xphoto::GrayworldWB*) cveGrayworldWBCreate(cv::xphoto::WhiteBalancer** whiteBalancer, cv::Ptr<cv::xphoto::GrayworldWB>** sharedPtr);

    Local $sWhiteBalancerDllType
    If IsDllStruct($whiteBalancer) Then
        $sWhiteBalancerDllType = "struct*"
    ElseIf $whiteBalancer == Null Then
        $sWhiteBalancerDllType = "ptr"
    Else
        $sWhiteBalancerDllType = "ptr*"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGrayworldWBCreate", $sWhiteBalancerDllType, $whiteBalancer, $sSharedPtrDllType, $sharedPtr), "cveGrayworldWBCreate", @error)
EndFunc   ;==>_cveGrayworldWBCreate

Func _cveGrayworldWBRelease($sharedPtr)
    ; CVAPI(void) cveGrayworldWBRelease(cv::Ptr<cv::xphoto::GrayworldWB>** sharedPtr);

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveGrayworldWBRelease", $sSharedPtrDllType, $sharedPtr), "cveGrayworldWBRelease", @error)
EndFunc   ;==>_cveGrayworldWBRelease

Func _cveLearningBasedWBCreate($whiteBalancer, $sharedPtr)
    ; CVAPI(cv::xphoto::LearningBasedWB*) cveLearningBasedWBCreate(cv::xphoto::WhiteBalancer** whiteBalancer, cv::Ptr<cv::xphoto::LearningBasedWB>** sharedPtr);

    Local $sWhiteBalancerDllType
    If IsDllStruct($whiteBalancer) Then
        $sWhiteBalancerDllType = "struct*"
    ElseIf $whiteBalancer == Null Then
        $sWhiteBalancerDllType = "ptr"
    Else
        $sWhiteBalancerDllType = "ptr*"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveLearningBasedWBCreate", $sWhiteBalancerDllType, $whiteBalancer, $sSharedPtrDllType, $sharedPtr), "cveLearningBasedWBCreate", @error)
EndFunc   ;==>_cveLearningBasedWBCreate

Func _cveLearningBasedWBRelease($sharedPtr)
    ; CVAPI(void) cveLearningBasedWBRelease(cv::Ptr<cv::xphoto::LearningBasedWB>** sharedPtr);

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveLearningBasedWBRelease", $sSharedPtrDllType, $sharedPtr), "cveLearningBasedWBRelease", @error)
EndFunc   ;==>_cveLearningBasedWBRelease

Func _cveApplyChannelGains($src, $dst, $gainB, $gainG, $gainR)
    ; CVAPI(void) cveApplyChannelGains(cv::_InputArray* src, cv::_OutputArray* dst, float gainB, float gainG, float gainR);

    Local $sSrcDllType
    If IsDllStruct($src) Then
        $sSrcDllType = "struct*"
    Else
        $sSrcDllType = "ptr"
    EndIf

    Local $sDstDllType
    If IsDllStruct($dst) Then
        $sDstDllType = "struct*"
    Else
        $sDstDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveApplyChannelGains", $sSrcDllType, $src, $sDstDllType, $dst, "float", $gainB, "float", $gainG, "float", $gainR), "cveApplyChannelGains", @error)
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

    Local $sSrcDllType
    If IsDllStruct($src) Then
        $sSrcDllType = "struct*"
    Else
        $sSrcDllType = "ptr"
    EndIf

    Local $sDstDllType
    If IsDllStruct($dst) Then
        $sDstDllType = "struct*"
    Else
        $sDstDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDctDenoising", $sSrcDllType, $src, $sDstDllType, $dst, "double", $sigma, "int", $psize), "cveDctDenoising", @error)
EndFunc   ;==>_cveDctDenoising

Func _cveXInpaint($src, $mask, $dst, $algorithmType)
    ; CVAPI(void) cveXInpaint(const cv::Mat* src, const cv::Mat* mask, cv::Mat* dst, const int algorithmType);

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

    Local $sDstDllType
    If IsDllStruct($dst) Then
        $sDstDllType = "struct*"
    Else
        $sDstDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveXInpaint", $sSrcDllType, $src, $sMaskDllType, $mask, $sDstDllType, $dst, "int", $algorithmType), "cveXInpaint", @error)
EndFunc   ;==>_cveXInpaint

Func _cveBm3dDenoising1($src, $dstStep1, $dstStep2, $h, $templateWindowSize, $searchWindowSize, $blockMatchingStep1, $blockMatchingStep2, $groupSize, $slidingStep, $beta, $normType, $step, $transformType)
    ; CVAPI(void) cveBm3dDenoising1(cv::_InputArray* src, cv::_InputOutputArray* dstStep1, cv::_OutputArray* dstStep2, float h, int templateWindowSize, int searchWindowSize, int blockMatchingStep1, int blockMatchingStep2, int groupSize, int slidingStep, float beta, int normType, int step, int transformType);

    Local $sSrcDllType
    If IsDllStruct($src) Then
        $sSrcDllType = "struct*"
    Else
        $sSrcDllType = "ptr"
    EndIf

    Local $sDstStep1DllType
    If IsDllStruct($dstStep1) Then
        $sDstStep1DllType = "struct*"
    Else
        $sDstStep1DllType = "ptr"
    EndIf

    Local $sDstStep2DllType
    If IsDllStruct($dstStep2) Then
        $sDstStep2DllType = "struct*"
    Else
        $sDstStep2DllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBm3dDenoising1", $sSrcDllType, $src, $sDstStep1DllType, $dstStep1, $sDstStep2DllType, $dstStep2, "float", $h, "int", $templateWindowSize, "int", $searchWindowSize, "int", $blockMatchingStep1, "int", $blockMatchingStep2, "int", $groupSize, "int", $slidingStep, "float", $beta, "int", $normType, "int", $step, "int", $transformType), "cveBm3dDenoising1", @error)
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

    Local $sSrcDllType
    If IsDllStruct($src) Then
        $sSrcDllType = "struct*"
    Else
        $sSrcDllType = "ptr"
    EndIf

    Local $sDstDllType
    If IsDllStruct($dst) Then
        $sDstDllType = "struct*"
    Else
        $sDstDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBm3dDenoising2", $sSrcDllType, $src, $sDstDllType, $dst, "float", $h, "int", $templateWindowSize, "int", $searchWindowSize, "int", $blockMatchingStep1, "int", $blockMatchingStep2, "int", $groupSize, "int", $slidingStep, "float", $beta, "int", $normType, "int", $step, "int", $transformType), "cveBm3dDenoising2", @error)
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

    Local $sSrcDllType
    If IsDllStruct($src) Then
        $sSrcDllType = "struct*"
    Else
        $sSrcDllType = "ptr"
    EndIf

    Local $sDstDllType
    If IsDllStruct($dst) Then
        $sDstDllType = "struct*"
    Else
        $sDstDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveOilPainting", $sSrcDllType, $src, $sDstDllType, $dst, "int", $size, "int", $dynRatio, "int", $code), "cveOilPainting", @error)
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

    Local $sTonemapDllType
    If IsDllStruct($tonemap) Then
        $sTonemapDllType = "struct*"
    ElseIf $tonemap == Null Then
        $sTonemapDllType = "ptr"
    Else
        $sTonemapDllType = "ptr*"
    EndIf

    Local $sAlgorithmDllType
    If IsDllStruct($algorithm) Then
        $sAlgorithmDllType = "struct*"
    ElseIf $algorithm == Null Then
        $sAlgorithmDllType = "ptr"
    Else
        $sAlgorithmDllType = "ptr*"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveTonemapDurandCreate", "float", $gamma, "float", $contrast, "float", $saturation, "float", $sigmaSpace, "float", $sigmaColor, $sTonemapDllType, $tonemap, $sAlgorithmDllType, $algorithm, $sSharedPtrDllType, $sharedPtr), "cveTonemapDurandCreate", @error)
EndFunc   ;==>_cveTonemapDurandCreate

Func _cveTonemapDurandRelease($sharedPtr)
    ; CVAPI(void) cveTonemapDurandRelease(cv::Ptr<cv::xphoto::TonemapDurand>** sharedPtr);

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveTonemapDurandRelease", $sSharedPtrDllType, $sharedPtr), "cveTonemapDurandRelease", @error)
EndFunc   ;==>_cveTonemapDurandRelease