#include-once
#include "..\..\CVEUtils.au3"

Func _cveBackgroundSubtractorMOGCreate($history, $nmixtures, $backgroundRatio, $noiseSigma, $bgSubtractor, $algorithm, $sharedPtr)
    ; CVAPI(cv::bgsegm::BackgroundSubtractorMOG*) cveBackgroundSubtractorMOGCreate(int history, int nmixtures, double backgroundRatio, double noiseSigma, cv::BackgroundSubtractor** bgSubtractor, cv::Algorithm** algorithm, cv::Ptr<cv::bgsegm::BackgroundSubtractorMOG>** sharedPtr);

    Local $bBgSubtractorDllType
    If VarGetType($bgSubtractor) == "DLLStruct" Then
        $bBgSubtractorDllType = "struct*"
    Else
        $bBgSubtractorDllType = "ptr*"
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
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveBackgroundSubtractorMOGCreate", "int", $history, "int", $nmixtures, "double", $backgroundRatio, "double", $noiseSigma, $bBgSubtractorDllType, $bgSubtractor, $bAlgorithmDllType, $algorithm, $bSharedPtrDllType, $sharedPtr), "cveBackgroundSubtractorMOGCreate", @error)
EndFunc   ;==>_cveBackgroundSubtractorMOGCreate

Func _cveBackgroundSubtractorMOGRelease($bgSubtractor, $sharedPtr)
    ; CVAPI(void) cveBackgroundSubtractorMOGRelease(cv::bgsegm::BackgroundSubtractorMOG** bgSubtractor, cv::Ptr<cv::bgsegm::BackgroundSubtractorMOG>** sharedPtr);

    Local $bBgSubtractorDllType
    If VarGetType($bgSubtractor) == "DLLStruct" Then
        $bBgSubtractorDllType = "struct*"
    Else
        $bBgSubtractorDllType = "ptr*"
    EndIf

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBackgroundSubtractorMOGRelease", $bBgSubtractorDllType, $bgSubtractor, $bSharedPtrDllType, $sharedPtr), "cveBackgroundSubtractorMOGRelease", @error)
EndFunc   ;==>_cveBackgroundSubtractorMOGRelease

Func _cveBackgroundSubtractorGMGCreate($initializationFrames, $decisionThreshold, $bgSubtractor, $algorithm, $sharedPtr)
    ; CVAPI(cv::bgsegm::BackgroundSubtractorGMG*) cveBackgroundSubtractorGMGCreate(int initializationFrames, double decisionThreshold, cv::BackgroundSubtractor** bgSubtractor, cv::Algorithm** algorithm, cv::Ptr<cv::bgsegm::BackgroundSubtractorGMG>** sharedPtr);

    Local $bBgSubtractorDllType
    If VarGetType($bgSubtractor) == "DLLStruct" Then
        $bBgSubtractorDllType = "struct*"
    Else
        $bBgSubtractorDllType = "ptr*"
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
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveBackgroundSubtractorGMGCreate", "int", $initializationFrames, "double", $decisionThreshold, $bBgSubtractorDllType, $bgSubtractor, $bAlgorithmDllType, $algorithm, $bSharedPtrDllType, $sharedPtr), "cveBackgroundSubtractorGMGCreate", @error)
EndFunc   ;==>_cveBackgroundSubtractorGMGCreate

Func _cveBackgroundSubtractorGMGRelease($bgSubtractor, $sharedPtr)
    ; CVAPI(void) cveBackgroundSubtractorGMGRelease(cv::bgsegm::BackgroundSubtractorGMG** bgSubtractor, cv::Ptr<cv::bgsegm::BackgroundSubtractorGMG>** sharedPtr);

    Local $bBgSubtractorDllType
    If VarGetType($bgSubtractor) == "DLLStruct" Then
        $bBgSubtractorDllType = "struct*"
    Else
        $bBgSubtractorDllType = "ptr*"
    EndIf

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBackgroundSubtractorGMGRelease", $bBgSubtractorDllType, $bgSubtractor, $bSharedPtrDllType, $sharedPtr), "cveBackgroundSubtractorGMGRelease", @error)
EndFunc   ;==>_cveBackgroundSubtractorGMGRelease

Func _cveBackgroundSubtractorCNTCreate($minPixelStability, $useHistory, $maxPixelStability, $isParallel, $bgSubtractor, $algorithm, $sharedPtr)
    ; CVAPI(cv::bgsegm::BackgroundSubtractorCNT*) cveBackgroundSubtractorCNTCreate(int minPixelStability, bool useHistory, int maxPixelStability, bool isParallel, cv::BackgroundSubtractor** bgSubtractor, cv::Algorithm** algorithm, cv::Ptr<cv::bgsegm::BackgroundSubtractorCNT>** sharedPtr);

    Local $bBgSubtractorDllType
    If VarGetType($bgSubtractor) == "DLLStruct" Then
        $bBgSubtractorDllType = "struct*"
    Else
        $bBgSubtractorDllType = "ptr*"
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
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveBackgroundSubtractorCNTCreate", "int", $minPixelStability, "boolean", $useHistory, "int", $maxPixelStability, "boolean", $isParallel, $bBgSubtractorDllType, $bgSubtractor, $bAlgorithmDllType, $algorithm, $bSharedPtrDllType, $sharedPtr), "cveBackgroundSubtractorCNTCreate", @error)
EndFunc   ;==>_cveBackgroundSubtractorCNTCreate

Func _cveBackgroundSubtractorCNTRelease($bgSubtractor, $sharedPtr)
    ; CVAPI(void) cveBackgroundSubtractorCNTRelease(cv::bgsegm::BackgroundSubtractorCNT** bgSubtractor, cv::Ptr<cv::bgsegm::BackgroundSubtractorCNT>** sharedPtr);

    Local $bBgSubtractorDllType
    If VarGetType($bgSubtractor) == "DLLStruct" Then
        $bBgSubtractorDllType = "struct*"
    Else
        $bBgSubtractorDllType = "ptr*"
    EndIf

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBackgroundSubtractorCNTRelease", $bBgSubtractorDllType, $bgSubtractor, $bSharedPtrDllType, $sharedPtr), "cveBackgroundSubtractorCNTRelease", @error)
EndFunc   ;==>_cveBackgroundSubtractorCNTRelease

Func _cveBackgroundSubtractorGSOCCreate($mc, $nSamples, $replaceRate, $propagationRate, $hitsThreshold, $alpha, $beta, $blinkingSupressionDecay, $blinkingSupressionMultiplier, $noiseRemovalThresholdFacBG, $noiseRemovalThresholdFacFG, $bgSubtractor, $algorithm, $sharedPtr)
    ; CVAPI(cv::bgsegm::BackgroundSubtractorGSOC*) cveBackgroundSubtractorGSOCCreate(int mc, int nSamples, float replaceRate, float propagationRate, int hitsThreshold, float alpha, float beta, float blinkingSupressionDecay, float blinkingSupressionMultiplier, float noiseRemovalThresholdFacBG, float noiseRemovalThresholdFacFG, cv::BackgroundSubtractor** bgSubtractor, cv::Algorithm** algorithm, cv::Ptr<cv::bgsegm::BackgroundSubtractorGSOC>** sharedPtr);

    Local $bBgSubtractorDllType
    If VarGetType($bgSubtractor) == "DLLStruct" Then
        $bBgSubtractorDllType = "struct*"
    Else
        $bBgSubtractorDllType = "ptr*"
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
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveBackgroundSubtractorGSOCCreate", "int", $mc, "int", $nSamples, "float", $replaceRate, "float", $propagationRate, "int", $hitsThreshold, "float", $alpha, "float", $beta, "float", $blinkingSupressionDecay, "float", $blinkingSupressionMultiplier, "float", $noiseRemovalThresholdFacBG, "float", $noiseRemovalThresholdFacFG, $bBgSubtractorDllType, $bgSubtractor, $bAlgorithmDllType, $algorithm, $bSharedPtrDllType, $sharedPtr), "cveBackgroundSubtractorGSOCCreate", @error)
EndFunc   ;==>_cveBackgroundSubtractorGSOCCreate

Func _cveBackgroundSubtractorGSOCRelease($bgSubtractor, $sharedPtr)
    ; CVAPI(void) cveBackgroundSubtractorGSOCRelease(cv::bgsegm::BackgroundSubtractorGSOC** bgSubtractor, cv::Ptr<cv::bgsegm::BackgroundSubtractorGSOC>** sharedPtr);

    Local $bBgSubtractorDllType
    If VarGetType($bgSubtractor) == "DLLStruct" Then
        $bBgSubtractorDllType = "struct*"
    Else
        $bBgSubtractorDllType = "ptr*"
    EndIf

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBackgroundSubtractorGSOCRelease", $bBgSubtractorDllType, $bgSubtractor, $bSharedPtrDllType, $sharedPtr), "cveBackgroundSubtractorGSOCRelease", @error)
EndFunc   ;==>_cveBackgroundSubtractorGSOCRelease

Func _cveBackgroundSubtractorLSBPCreate($mc, $nSamples, $LSBPRadius, $tlower, $tupper, $tinc, $tdec, $rscale, $rincdec, $noiseRemovalThresholdFacBG, $noiseRemovalThresholdFacFG, $LSBPthreshold, $minCount, $bgSubtractor, $algorithm, $sharedPtr)
    ; CVAPI(cv::bgsegm::BackgroundSubtractorLSBP*) cveBackgroundSubtractorLSBPCreate(int mc, int nSamples, int LSBPRadius, float tlower, float tupper, float tinc, float tdec, float rscale, float rincdec, float noiseRemovalThresholdFacBG, float noiseRemovalThresholdFacFG, int LSBPthreshold, int minCount, cv::BackgroundSubtractor** bgSubtractor, cv::Algorithm** algorithm, cv::Ptr<cv::bgsegm::BackgroundSubtractorLSBP>** sharedPtr);

    Local $bBgSubtractorDllType
    If VarGetType($bgSubtractor) == "DLLStruct" Then
        $bBgSubtractorDllType = "struct*"
    Else
        $bBgSubtractorDllType = "ptr*"
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
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveBackgroundSubtractorLSBPCreate", "int", $mc, "int", $nSamples, "int", $LSBPRadius, "float", $tlower, "float", $tupper, "float", $tinc, "float", $tdec, "float", $rscale, "float", $rincdec, "float", $noiseRemovalThresholdFacBG, "float", $noiseRemovalThresholdFacFG, "int", $LSBPthreshold, "int", $minCount, $bBgSubtractorDllType, $bgSubtractor, $bAlgorithmDllType, $algorithm, $bSharedPtrDllType, $sharedPtr), "cveBackgroundSubtractorLSBPCreate", @error)
EndFunc   ;==>_cveBackgroundSubtractorLSBPCreate

Func _cveBackgroundSubtractorLSBPRelease($bgSubtractor, $sharedPtr)
    ; CVAPI(void) cveBackgroundSubtractorLSBPRelease(cv::bgsegm::BackgroundSubtractorLSBP** bgSubtractor, cv::Ptr<cv::bgsegm::BackgroundSubtractorLSBP>** sharedPtr);

    Local $bBgSubtractorDllType
    If VarGetType($bgSubtractor) == "DLLStruct" Then
        $bBgSubtractorDllType = "struct*"
    Else
        $bBgSubtractorDllType = "ptr*"
    EndIf

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBackgroundSubtractorLSBPRelease", $bBgSubtractorDllType, $bgSubtractor, $bSharedPtrDllType, $sharedPtr), "cveBackgroundSubtractorLSBPRelease", @error)
EndFunc   ;==>_cveBackgroundSubtractorLSBPRelease