#include-once
#include "..\..\CVEUtils.au3"

Func _cveBackgroundSubtractorMOGCreate($history, $nmixtures, $backgroundRatio, $noiseSigma, $bgSubtractor, $algorithm, $sharedPtr)
    ; CVAPI(cv::bgsegm::BackgroundSubtractorMOG*) cveBackgroundSubtractorMOGCreate(int history, int nmixtures, double backgroundRatio, double noiseSigma, cv::BackgroundSubtractor** bgSubtractor, cv::Algorithm** algorithm, cv::Ptr<cv::bgsegm::BackgroundSubtractorMOG>** sharedPtr);

    Local $sBgSubtractorDllType
    If IsDllStruct($bgSubtractor) Then
        $sBgSubtractorDllType = "struct*"
    ElseIf $bgSubtractor == Null Then
        $sBgSubtractorDllType = "ptr"
    Else
        $sBgSubtractorDllType = "ptr*"
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
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveBackgroundSubtractorMOGCreate", "int", $history, "int", $nmixtures, "double", $backgroundRatio, "double", $noiseSigma, $sBgSubtractorDllType, $bgSubtractor, $sAlgorithmDllType, $algorithm, $sSharedPtrDllType, $sharedPtr), "cveBackgroundSubtractorMOGCreate", @error)
EndFunc   ;==>_cveBackgroundSubtractorMOGCreate

Func _cveBackgroundSubtractorMOGRelease($bgSubtractor, $sharedPtr)
    ; CVAPI(void) cveBackgroundSubtractorMOGRelease(cv::bgsegm::BackgroundSubtractorMOG** bgSubtractor, cv::Ptr<cv::bgsegm::BackgroundSubtractorMOG>** sharedPtr);

    Local $sBgSubtractorDllType
    If IsDllStruct($bgSubtractor) Then
        $sBgSubtractorDllType = "struct*"
    ElseIf $bgSubtractor == Null Then
        $sBgSubtractorDllType = "ptr"
    Else
        $sBgSubtractorDllType = "ptr*"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBackgroundSubtractorMOGRelease", $sBgSubtractorDllType, $bgSubtractor, $sSharedPtrDllType, $sharedPtr), "cveBackgroundSubtractorMOGRelease", @error)
EndFunc   ;==>_cveBackgroundSubtractorMOGRelease

Func _cveBackgroundSubtractorGMGCreate($initializationFrames, $decisionThreshold, $bgSubtractor, $algorithm, $sharedPtr)
    ; CVAPI(cv::bgsegm::BackgroundSubtractorGMG*) cveBackgroundSubtractorGMGCreate(int initializationFrames, double decisionThreshold, cv::BackgroundSubtractor** bgSubtractor, cv::Algorithm** algorithm, cv::Ptr<cv::bgsegm::BackgroundSubtractorGMG>** sharedPtr);

    Local $sBgSubtractorDllType
    If IsDllStruct($bgSubtractor) Then
        $sBgSubtractorDllType = "struct*"
    ElseIf $bgSubtractor == Null Then
        $sBgSubtractorDllType = "ptr"
    Else
        $sBgSubtractorDllType = "ptr*"
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
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveBackgroundSubtractorGMGCreate", "int", $initializationFrames, "double", $decisionThreshold, $sBgSubtractorDllType, $bgSubtractor, $sAlgorithmDllType, $algorithm, $sSharedPtrDllType, $sharedPtr), "cveBackgroundSubtractorGMGCreate", @error)
EndFunc   ;==>_cveBackgroundSubtractorGMGCreate

Func _cveBackgroundSubtractorGMGRelease($bgSubtractor, $sharedPtr)
    ; CVAPI(void) cveBackgroundSubtractorGMGRelease(cv::bgsegm::BackgroundSubtractorGMG** bgSubtractor, cv::Ptr<cv::bgsegm::BackgroundSubtractorGMG>** sharedPtr);

    Local $sBgSubtractorDllType
    If IsDllStruct($bgSubtractor) Then
        $sBgSubtractorDllType = "struct*"
    ElseIf $bgSubtractor == Null Then
        $sBgSubtractorDllType = "ptr"
    Else
        $sBgSubtractorDllType = "ptr*"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBackgroundSubtractorGMGRelease", $sBgSubtractorDllType, $bgSubtractor, $sSharedPtrDllType, $sharedPtr), "cveBackgroundSubtractorGMGRelease", @error)
EndFunc   ;==>_cveBackgroundSubtractorGMGRelease

Func _cveBackgroundSubtractorCNTCreate($minPixelStability, $useHistory, $maxPixelStability, $isParallel, $bgSubtractor, $algorithm, $sharedPtr)
    ; CVAPI(cv::bgsegm::BackgroundSubtractorCNT*) cveBackgroundSubtractorCNTCreate(int minPixelStability, bool useHistory, int maxPixelStability, bool isParallel, cv::BackgroundSubtractor** bgSubtractor, cv::Algorithm** algorithm, cv::Ptr<cv::bgsegm::BackgroundSubtractorCNT>** sharedPtr);

    Local $sBgSubtractorDllType
    If IsDllStruct($bgSubtractor) Then
        $sBgSubtractorDllType = "struct*"
    ElseIf $bgSubtractor == Null Then
        $sBgSubtractorDllType = "ptr"
    Else
        $sBgSubtractorDllType = "ptr*"
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
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveBackgroundSubtractorCNTCreate", "int", $minPixelStability, "boolean", $useHistory, "int", $maxPixelStability, "boolean", $isParallel, $sBgSubtractorDllType, $bgSubtractor, $sAlgorithmDllType, $algorithm, $sSharedPtrDllType, $sharedPtr), "cveBackgroundSubtractorCNTCreate", @error)
EndFunc   ;==>_cveBackgroundSubtractorCNTCreate

Func _cveBackgroundSubtractorCNTRelease($bgSubtractor, $sharedPtr)
    ; CVAPI(void) cveBackgroundSubtractorCNTRelease(cv::bgsegm::BackgroundSubtractorCNT** bgSubtractor, cv::Ptr<cv::bgsegm::BackgroundSubtractorCNT>** sharedPtr);

    Local $sBgSubtractorDllType
    If IsDllStruct($bgSubtractor) Then
        $sBgSubtractorDllType = "struct*"
    ElseIf $bgSubtractor == Null Then
        $sBgSubtractorDllType = "ptr"
    Else
        $sBgSubtractorDllType = "ptr*"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBackgroundSubtractorCNTRelease", $sBgSubtractorDllType, $bgSubtractor, $sSharedPtrDllType, $sharedPtr), "cveBackgroundSubtractorCNTRelease", @error)
EndFunc   ;==>_cveBackgroundSubtractorCNTRelease

Func _cveBackgroundSubtractorGSOCCreate($mc, $nSamples, $replaceRate, $propagationRate, $hitsThreshold, $alpha, $beta, $blinkingSupressionDecay, $blinkingSupressionMultiplier, $noiseRemovalThresholdFacBG, $noiseRemovalThresholdFacFG, $bgSubtractor, $algorithm, $sharedPtr)
    ; CVAPI(cv::bgsegm::BackgroundSubtractorGSOC*) cveBackgroundSubtractorGSOCCreate(int mc, int nSamples, float replaceRate, float propagationRate, int hitsThreshold, float alpha, float beta, float blinkingSupressionDecay, float blinkingSupressionMultiplier, float noiseRemovalThresholdFacBG, float noiseRemovalThresholdFacFG, cv::BackgroundSubtractor** bgSubtractor, cv::Algorithm** algorithm, cv::Ptr<cv::bgsegm::BackgroundSubtractorGSOC>** sharedPtr);

    Local $sBgSubtractorDllType
    If IsDllStruct($bgSubtractor) Then
        $sBgSubtractorDllType = "struct*"
    ElseIf $bgSubtractor == Null Then
        $sBgSubtractorDllType = "ptr"
    Else
        $sBgSubtractorDllType = "ptr*"
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
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveBackgroundSubtractorGSOCCreate", "int", $mc, "int", $nSamples, "float", $replaceRate, "float", $propagationRate, "int", $hitsThreshold, "float", $alpha, "float", $beta, "float", $blinkingSupressionDecay, "float", $blinkingSupressionMultiplier, "float", $noiseRemovalThresholdFacBG, "float", $noiseRemovalThresholdFacFG, $sBgSubtractorDllType, $bgSubtractor, $sAlgorithmDllType, $algorithm, $sSharedPtrDllType, $sharedPtr), "cveBackgroundSubtractorGSOCCreate", @error)
EndFunc   ;==>_cveBackgroundSubtractorGSOCCreate

Func _cveBackgroundSubtractorGSOCRelease($bgSubtractor, $sharedPtr)
    ; CVAPI(void) cveBackgroundSubtractorGSOCRelease(cv::bgsegm::BackgroundSubtractorGSOC** bgSubtractor, cv::Ptr<cv::bgsegm::BackgroundSubtractorGSOC>** sharedPtr);

    Local $sBgSubtractorDllType
    If IsDllStruct($bgSubtractor) Then
        $sBgSubtractorDllType = "struct*"
    ElseIf $bgSubtractor == Null Then
        $sBgSubtractorDllType = "ptr"
    Else
        $sBgSubtractorDllType = "ptr*"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBackgroundSubtractorGSOCRelease", $sBgSubtractorDllType, $bgSubtractor, $sSharedPtrDllType, $sharedPtr), "cveBackgroundSubtractorGSOCRelease", @error)
EndFunc   ;==>_cveBackgroundSubtractorGSOCRelease

Func _cveBackgroundSubtractorLSBPCreate($mc, $nSamples, $LSBPRadius, $tlower, $tupper, $tinc, $tdec, $rscale, $rincdec, $noiseRemovalThresholdFacBG, $noiseRemovalThresholdFacFG, $LSBPthreshold, $minCount, $bgSubtractor, $algorithm, $sharedPtr)
    ; CVAPI(cv::bgsegm::BackgroundSubtractorLSBP*) cveBackgroundSubtractorLSBPCreate(int mc, int nSamples, int LSBPRadius, float tlower, float tupper, float tinc, float tdec, float rscale, float rincdec, float noiseRemovalThresholdFacBG, float noiseRemovalThresholdFacFG, int LSBPthreshold, int minCount, cv::BackgroundSubtractor** bgSubtractor, cv::Algorithm** algorithm, cv::Ptr<cv::bgsegm::BackgroundSubtractorLSBP>** sharedPtr);

    Local $sBgSubtractorDllType
    If IsDllStruct($bgSubtractor) Then
        $sBgSubtractorDllType = "struct*"
    ElseIf $bgSubtractor == Null Then
        $sBgSubtractorDllType = "ptr"
    Else
        $sBgSubtractorDllType = "ptr*"
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
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveBackgroundSubtractorLSBPCreate", "int", $mc, "int", $nSamples, "int", $LSBPRadius, "float", $tlower, "float", $tupper, "float", $tinc, "float", $tdec, "float", $rscale, "float", $rincdec, "float", $noiseRemovalThresholdFacBG, "float", $noiseRemovalThresholdFacFG, "int", $LSBPthreshold, "int", $minCount, $sBgSubtractorDllType, $bgSubtractor, $sAlgorithmDllType, $algorithm, $sSharedPtrDllType, $sharedPtr), "cveBackgroundSubtractorLSBPCreate", @error)
EndFunc   ;==>_cveBackgroundSubtractorLSBPCreate

Func _cveBackgroundSubtractorLSBPRelease($bgSubtractor, $sharedPtr)
    ; CVAPI(void) cveBackgroundSubtractorLSBPRelease(cv::bgsegm::BackgroundSubtractorLSBP** bgSubtractor, cv::Ptr<cv::bgsegm::BackgroundSubtractorLSBP>** sharedPtr);

    Local $sBgSubtractorDllType
    If IsDllStruct($bgSubtractor) Then
        $sBgSubtractorDllType = "struct*"
    ElseIf $bgSubtractor == Null Then
        $sBgSubtractorDllType = "ptr"
    Else
        $sBgSubtractorDllType = "ptr*"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBackgroundSubtractorLSBPRelease", $sBgSubtractorDllType, $bgSubtractor, $sSharedPtrDllType, $sharedPtr), "cveBackgroundSubtractorLSBPRelease", @error)
EndFunc   ;==>_cveBackgroundSubtractorLSBPRelease