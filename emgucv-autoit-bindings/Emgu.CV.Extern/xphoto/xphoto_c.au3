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

Func _cveWhiteBalancerBalanceWhiteTyped($whiteBalancer, $typeOfSrc, $src, $typeOfDst, $dst)

    Local $iArrSrc, $vectorSrc, $iArrSrcSize
    Local $bSrcIsArray = IsArray($src)
    Local $bSrcCreate = IsDllStruct($src) And $typeOfSrc == "Scalar"

    If $typeOfSrc == Default Then
        $iArrSrc = $src
    ElseIf $bSrcIsArray Then
        $vectorSrc = Call("_VectorOf" & $typeOfSrc & "Create")

        $iArrSrcSize = UBound($src)
        For $i = 0 To $iArrSrcSize - 1
            Call("_VectorOf" & $typeOfSrc & "Push", $vectorSrc, $src[$i])
        Next

        $iArrSrc = Call("_cveInputArrayFromVectorOf" & $typeOfSrc, $vectorSrc)
    Else
        If $bSrcCreate Then
            $src = Call("_cve" & $typeOfSrc & "Create", $src)
        EndIf
        $iArrSrc = Call("_cveInputArrayFrom" & $typeOfSrc, $src)
    EndIf

    Local $oArrDst, $vectorDst, $iArrDstSize
    Local $bDstIsArray = IsArray($dst)
    Local $bDstCreate = IsDllStruct($dst) And $typeOfDst == "Scalar"

    If $typeOfDst == Default Then
        $oArrDst = $dst
    ElseIf $bDstIsArray Then
        $vectorDst = Call("_VectorOf" & $typeOfDst & "Create")

        $iArrDstSize = UBound($dst)
        For $i = 0 To $iArrDstSize - 1
            Call("_VectorOf" & $typeOfDst & "Push", $vectorDst, $dst[$i])
        Next

        $oArrDst = Call("_cveOutputArrayFromVectorOf" & $typeOfDst, $vectorDst)
    Else
        If $bDstCreate Then
            $dst = Call("_cve" & $typeOfDst & "Create", $dst)
        EndIf
        $oArrDst = Call("_cveOutputArrayFrom" & $typeOfDst, $dst)
    EndIf

    _cveWhiteBalancerBalanceWhite($whiteBalancer, $iArrSrc, $oArrDst)

    If $bDstIsArray Then
        Call("_VectorOf" & $typeOfDst & "Release", $vectorDst)
    EndIf

    If $typeOfDst <> Default Then
        _cveOutputArrayRelease($oArrDst)
        If $bDstCreate Then
            Call("_cve" & $typeOfDst & "Release", $dst)
        EndIf
    EndIf

    If $bSrcIsArray Then
        Call("_VectorOf" & $typeOfSrc & "Release", $vectorSrc)
    EndIf

    If $typeOfSrc <> Default Then
        _cveInputArrayRelease($iArrSrc)
        If $bSrcCreate Then
            Call("_cve" & $typeOfSrc & "Release", $src)
        EndIf
    EndIf
EndFunc   ;==>_cveWhiteBalancerBalanceWhiteTyped

Func _cveWhiteBalancerBalanceWhiteMat($whiteBalancer, $src, $dst)
    ; cveWhiteBalancerBalanceWhite using cv::Mat instead of _*Array
    _cveWhiteBalancerBalanceWhiteTyped($whiteBalancer, "Mat", $src, "Mat", $dst)
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

Func _cveApplyChannelGainsTyped($typeOfSrc, $src, $typeOfDst, $dst, $gainB, $gainG, $gainR)

    Local $iArrSrc, $vectorSrc, $iArrSrcSize
    Local $bSrcIsArray = IsArray($src)
    Local $bSrcCreate = IsDllStruct($src) And $typeOfSrc == "Scalar"

    If $typeOfSrc == Default Then
        $iArrSrc = $src
    ElseIf $bSrcIsArray Then
        $vectorSrc = Call("_VectorOf" & $typeOfSrc & "Create")

        $iArrSrcSize = UBound($src)
        For $i = 0 To $iArrSrcSize - 1
            Call("_VectorOf" & $typeOfSrc & "Push", $vectorSrc, $src[$i])
        Next

        $iArrSrc = Call("_cveInputArrayFromVectorOf" & $typeOfSrc, $vectorSrc)
    Else
        If $bSrcCreate Then
            $src = Call("_cve" & $typeOfSrc & "Create", $src)
        EndIf
        $iArrSrc = Call("_cveInputArrayFrom" & $typeOfSrc, $src)
    EndIf

    Local $oArrDst, $vectorDst, $iArrDstSize
    Local $bDstIsArray = IsArray($dst)
    Local $bDstCreate = IsDllStruct($dst) And $typeOfDst == "Scalar"

    If $typeOfDst == Default Then
        $oArrDst = $dst
    ElseIf $bDstIsArray Then
        $vectorDst = Call("_VectorOf" & $typeOfDst & "Create")

        $iArrDstSize = UBound($dst)
        For $i = 0 To $iArrDstSize - 1
            Call("_VectorOf" & $typeOfDst & "Push", $vectorDst, $dst[$i])
        Next

        $oArrDst = Call("_cveOutputArrayFromVectorOf" & $typeOfDst, $vectorDst)
    Else
        If $bDstCreate Then
            $dst = Call("_cve" & $typeOfDst & "Create", $dst)
        EndIf
        $oArrDst = Call("_cveOutputArrayFrom" & $typeOfDst, $dst)
    EndIf

    _cveApplyChannelGains($iArrSrc, $oArrDst, $gainB, $gainG, $gainR)

    If $bDstIsArray Then
        Call("_VectorOf" & $typeOfDst & "Release", $vectorDst)
    EndIf

    If $typeOfDst <> Default Then
        _cveOutputArrayRelease($oArrDst)
        If $bDstCreate Then
            Call("_cve" & $typeOfDst & "Release", $dst)
        EndIf
    EndIf

    If $bSrcIsArray Then
        Call("_VectorOf" & $typeOfSrc & "Release", $vectorSrc)
    EndIf

    If $typeOfSrc <> Default Then
        _cveInputArrayRelease($iArrSrc)
        If $bSrcCreate Then
            Call("_cve" & $typeOfSrc & "Release", $src)
        EndIf
    EndIf
EndFunc   ;==>_cveApplyChannelGainsTyped

Func _cveApplyChannelGainsMat($src, $dst, $gainB, $gainG, $gainR)
    ; cveApplyChannelGains using cv::Mat instead of _*Array
    _cveApplyChannelGainsTyped("Mat", $src, "Mat", $dst, $gainB, $gainG, $gainR)
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

Func _cveBm3dDenoising1Typed($typeOfSrc, $src, $typeOfDstStep1, $dstStep1, $typeOfDstStep2, $dstStep2, $h, $templateWindowSize, $searchWindowSize, $blockMatchingStep1, $blockMatchingStep2, $groupSize, $slidingStep, $beta, $normType, $step, $transformType)

    Local $iArrSrc, $vectorSrc, $iArrSrcSize
    Local $bSrcIsArray = IsArray($src)
    Local $bSrcCreate = IsDllStruct($src) And $typeOfSrc == "Scalar"

    If $typeOfSrc == Default Then
        $iArrSrc = $src
    ElseIf $bSrcIsArray Then
        $vectorSrc = Call("_VectorOf" & $typeOfSrc & "Create")

        $iArrSrcSize = UBound($src)
        For $i = 0 To $iArrSrcSize - 1
            Call("_VectorOf" & $typeOfSrc & "Push", $vectorSrc, $src[$i])
        Next

        $iArrSrc = Call("_cveInputArrayFromVectorOf" & $typeOfSrc, $vectorSrc)
    Else
        If $bSrcCreate Then
            $src = Call("_cve" & $typeOfSrc & "Create", $src)
        EndIf
        $iArrSrc = Call("_cveInputArrayFrom" & $typeOfSrc, $src)
    EndIf

    Local $ioArrDstStep1, $vectorDstStep1, $iArrDstStep1Size
    Local $bDstStep1IsArray = IsArray($dstStep1)
    Local $bDstStep1Create = IsDllStruct($dstStep1) And $typeOfDstStep1 == "Scalar"

    If $typeOfDstStep1 == Default Then
        $ioArrDstStep1 = $dstStep1
    ElseIf $bDstStep1IsArray Then
        $vectorDstStep1 = Call("_VectorOf" & $typeOfDstStep1 & "Create")

        $iArrDstStep1Size = UBound($dstStep1)
        For $i = 0 To $iArrDstStep1Size - 1
            Call("_VectorOf" & $typeOfDstStep1 & "Push", $vectorDstStep1, $dstStep1[$i])
        Next

        $ioArrDstStep1 = Call("_cveInputOutputArrayFromVectorOf" & $typeOfDstStep1, $vectorDstStep1)
    Else
        If $bDstStep1Create Then
            $dstStep1 = Call("_cve" & $typeOfDstStep1 & "Create", $dstStep1)
        EndIf
        $ioArrDstStep1 = Call("_cveInputOutputArrayFrom" & $typeOfDstStep1, $dstStep1)
    EndIf

    Local $oArrDstStep2, $vectorDstStep2, $iArrDstStep2Size
    Local $bDstStep2IsArray = IsArray($dstStep2)
    Local $bDstStep2Create = IsDllStruct($dstStep2) And $typeOfDstStep2 == "Scalar"

    If $typeOfDstStep2 == Default Then
        $oArrDstStep2 = $dstStep2
    ElseIf $bDstStep2IsArray Then
        $vectorDstStep2 = Call("_VectorOf" & $typeOfDstStep2 & "Create")

        $iArrDstStep2Size = UBound($dstStep2)
        For $i = 0 To $iArrDstStep2Size - 1
            Call("_VectorOf" & $typeOfDstStep2 & "Push", $vectorDstStep2, $dstStep2[$i])
        Next

        $oArrDstStep2 = Call("_cveOutputArrayFromVectorOf" & $typeOfDstStep2, $vectorDstStep2)
    Else
        If $bDstStep2Create Then
            $dstStep2 = Call("_cve" & $typeOfDstStep2 & "Create", $dstStep2)
        EndIf
        $oArrDstStep2 = Call("_cveOutputArrayFrom" & $typeOfDstStep2, $dstStep2)
    EndIf

    _cveBm3dDenoising1($iArrSrc, $ioArrDstStep1, $oArrDstStep2, $h, $templateWindowSize, $searchWindowSize, $blockMatchingStep1, $blockMatchingStep2, $groupSize, $slidingStep, $beta, $normType, $step, $transformType)

    If $bDstStep2IsArray Then
        Call("_VectorOf" & $typeOfDstStep2 & "Release", $vectorDstStep2)
    EndIf

    If $typeOfDstStep2 <> Default Then
        _cveOutputArrayRelease($oArrDstStep2)
        If $bDstStep2Create Then
            Call("_cve" & $typeOfDstStep2 & "Release", $dstStep2)
        EndIf
    EndIf

    If $bDstStep1IsArray Then
        Call("_VectorOf" & $typeOfDstStep1 & "Release", $vectorDstStep1)
    EndIf

    If $typeOfDstStep1 <> Default Then
        _cveInputOutputArrayRelease($ioArrDstStep1)
        If $bDstStep1Create Then
            Call("_cve" & $typeOfDstStep1 & "Release", $dstStep1)
        EndIf
    EndIf

    If $bSrcIsArray Then
        Call("_VectorOf" & $typeOfSrc & "Release", $vectorSrc)
    EndIf

    If $typeOfSrc <> Default Then
        _cveInputArrayRelease($iArrSrc)
        If $bSrcCreate Then
            Call("_cve" & $typeOfSrc & "Release", $src)
        EndIf
    EndIf
EndFunc   ;==>_cveBm3dDenoising1Typed

Func _cveBm3dDenoising1Mat($src, $dstStep1, $dstStep2, $h, $templateWindowSize, $searchWindowSize, $blockMatchingStep1, $blockMatchingStep2, $groupSize, $slidingStep, $beta, $normType, $step, $transformType)
    ; cveBm3dDenoising1 using cv::Mat instead of _*Array
    _cveBm3dDenoising1Typed("Mat", $src, "Mat", $dstStep1, "Mat", $dstStep2, $h, $templateWindowSize, $searchWindowSize, $blockMatchingStep1, $blockMatchingStep2, $groupSize, $slidingStep, $beta, $normType, $step, $transformType)
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

Func _cveBm3dDenoising2Typed($typeOfSrc, $src, $typeOfDst, $dst, $h, $templateWindowSize, $searchWindowSize, $blockMatchingStep1, $blockMatchingStep2, $groupSize, $slidingStep, $beta, $normType, $step, $transformType)

    Local $iArrSrc, $vectorSrc, $iArrSrcSize
    Local $bSrcIsArray = IsArray($src)
    Local $bSrcCreate = IsDllStruct($src) And $typeOfSrc == "Scalar"

    If $typeOfSrc == Default Then
        $iArrSrc = $src
    ElseIf $bSrcIsArray Then
        $vectorSrc = Call("_VectorOf" & $typeOfSrc & "Create")

        $iArrSrcSize = UBound($src)
        For $i = 0 To $iArrSrcSize - 1
            Call("_VectorOf" & $typeOfSrc & "Push", $vectorSrc, $src[$i])
        Next

        $iArrSrc = Call("_cveInputArrayFromVectorOf" & $typeOfSrc, $vectorSrc)
    Else
        If $bSrcCreate Then
            $src = Call("_cve" & $typeOfSrc & "Create", $src)
        EndIf
        $iArrSrc = Call("_cveInputArrayFrom" & $typeOfSrc, $src)
    EndIf

    Local $oArrDst, $vectorDst, $iArrDstSize
    Local $bDstIsArray = IsArray($dst)
    Local $bDstCreate = IsDllStruct($dst) And $typeOfDst == "Scalar"

    If $typeOfDst == Default Then
        $oArrDst = $dst
    ElseIf $bDstIsArray Then
        $vectorDst = Call("_VectorOf" & $typeOfDst & "Create")

        $iArrDstSize = UBound($dst)
        For $i = 0 To $iArrDstSize - 1
            Call("_VectorOf" & $typeOfDst & "Push", $vectorDst, $dst[$i])
        Next

        $oArrDst = Call("_cveOutputArrayFromVectorOf" & $typeOfDst, $vectorDst)
    Else
        If $bDstCreate Then
            $dst = Call("_cve" & $typeOfDst & "Create", $dst)
        EndIf
        $oArrDst = Call("_cveOutputArrayFrom" & $typeOfDst, $dst)
    EndIf

    _cveBm3dDenoising2($iArrSrc, $oArrDst, $h, $templateWindowSize, $searchWindowSize, $blockMatchingStep1, $blockMatchingStep2, $groupSize, $slidingStep, $beta, $normType, $step, $transformType)

    If $bDstIsArray Then
        Call("_VectorOf" & $typeOfDst & "Release", $vectorDst)
    EndIf

    If $typeOfDst <> Default Then
        _cveOutputArrayRelease($oArrDst)
        If $bDstCreate Then
            Call("_cve" & $typeOfDst & "Release", $dst)
        EndIf
    EndIf

    If $bSrcIsArray Then
        Call("_VectorOf" & $typeOfSrc & "Release", $vectorSrc)
    EndIf

    If $typeOfSrc <> Default Then
        _cveInputArrayRelease($iArrSrc)
        If $bSrcCreate Then
            Call("_cve" & $typeOfSrc & "Release", $src)
        EndIf
    EndIf
EndFunc   ;==>_cveBm3dDenoising2Typed

Func _cveBm3dDenoising2Mat($src, $dst, $h, $templateWindowSize, $searchWindowSize, $blockMatchingStep1, $blockMatchingStep2, $groupSize, $slidingStep, $beta, $normType, $step, $transformType)
    ; cveBm3dDenoising2 using cv::Mat instead of _*Array
    _cveBm3dDenoising2Typed("Mat", $src, "Mat", $dst, $h, $templateWindowSize, $searchWindowSize, $blockMatchingStep1, $blockMatchingStep2, $groupSize, $slidingStep, $beta, $normType, $step, $transformType)
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

Func _cveOilPaintingTyped($typeOfSrc, $src, $typeOfDst, $dst, $size, $dynRatio, $code)

    Local $iArrSrc, $vectorSrc, $iArrSrcSize
    Local $bSrcIsArray = IsArray($src)
    Local $bSrcCreate = IsDllStruct($src) And $typeOfSrc == "Scalar"

    If $typeOfSrc == Default Then
        $iArrSrc = $src
    ElseIf $bSrcIsArray Then
        $vectorSrc = Call("_VectorOf" & $typeOfSrc & "Create")

        $iArrSrcSize = UBound($src)
        For $i = 0 To $iArrSrcSize - 1
            Call("_VectorOf" & $typeOfSrc & "Push", $vectorSrc, $src[$i])
        Next

        $iArrSrc = Call("_cveInputArrayFromVectorOf" & $typeOfSrc, $vectorSrc)
    Else
        If $bSrcCreate Then
            $src = Call("_cve" & $typeOfSrc & "Create", $src)
        EndIf
        $iArrSrc = Call("_cveInputArrayFrom" & $typeOfSrc, $src)
    EndIf

    Local $oArrDst, $vectorDst, $iArrDstSize
    Local $bDstIsArray = IsArray($dst)
    Local $bDstCreate = IsDllStruct($dst) And $typeOfDst == "Scalar"

    If $typeOfDst == Default Then
        $oArrDst = $dst
    ElseIf $bDstIsArray Then
        $vectorDst = Call("_VectorOf" & $typeOfDst & "Create")

        $iArrDstSize = UBound($dst)
        For $i = 0 To $iArrDstSize - 1
            Call("_VectorOf" & $typeOfDst & "Push", $vectorDst, $dst[$i])
        Next

        $oArrDst = Call("_cveOutputArrayFromVectorOf" & $typeOfDst, $vectorDst)
    Else
        If $bDstCreate Then
            $dst = Call("_cve" & $typeOfDst & "Create", $dst)
        EndIf
        $oArrDst = Call("_cveOutputArrayFrom" & $typeOfDst, $dst)
    EndIf

    _cveOilPainting($iArrSrc, $oArrDst, $size, $dynRatio, $code)

    If $bDstIsArray Then
        Call("_VectorOf" & $typeOfDst & "Release", $vectorDst)
    EndIf

    If $typeOfDst <> Default Then
        _cveOutputArrayRelease($oArrDst)
        If $bDstCreate Then
            Call("_cve" & $typeOfDst & "Release", $dst)
        EndIf
    EndIf

    If $bSrcIsArray Then
        Call("_VectorOf" & $typeOfSrc & "Release", $vectorSrc)
    EndIf

    If $typeOfSrc <> Default Then
        _cveInputArrayRelease($iArrSrc)
        If $bSrcCreate Then
            Call("_cve" & $typeOfSrc & "Release", $src)
        EndIf
    EndIf
EndFunc   ;==>_cveOilPaintingTyped

Func _cveOilPaintingMat($src, $dst, $size, $dynRatio, $code)
    ; cveOilPainting using cv::Mat instead of _*Array
    _cveOilPaintingTyped("Mat", $src, "Mat", $dst, $size, $dynRatio, $code)
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