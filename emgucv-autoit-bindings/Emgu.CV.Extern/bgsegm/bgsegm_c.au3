#include-once
#include <..\..\CVEUtils.au3>

Func _cveBackgroundSubtractorMOGCreate($history, $nmixtures, $backgroundRatio, $noiseSigma, ByRef $bgSubtractor, ByRef $algorithm, ByRef $sharedPtr)
    ; CVAPI(cv::bgsegm::BackgroundSubtractorMOG*) cveBackgroundSubtractorMOGCreate(int history, int nmixtures, double backgroundRatio, double noiseSigma, cv::BackgroundSubtractor** bgSubtractor, cv::Algorithm** algorithm, cv::Ptr<cv::bgsegm::BackgroundSubtractorMOG>** sharedPtr);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveBackgroundSubtractorMOGCreate", "int", $history, "int", $nmixtures, "double", $backgroundRatio, "double", $noiseSigma, "ptr*", $bgSubtractor, "ptr*", $algorithm, "ptr*", $sharedPtr), "cveBackgroundSubtractorMOGCreate", @error)
EndFunc   ;==>_cveBackgroundSubtractorMOGCreate

Func _cveBackgroundSubtractorMOGRelease(ByRef $bgSubtractor, ByRef $sharedPtr)
    ; CVAPI(void) cveBackgroundSubtractorMOGRelease(cv::bgsegm::BackgroundSubtractorMOG** bgSubtractor, cv::Ptr<cv::bgsegm::BackgroundSubtractorMOG>** sharedPtr);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBackgroundSubtractorMOGRelease", "ptr*", $bgSubtractor, "ptr*", $sharedPtr), "cveBackgroundSubtractorMOGRelease", @error)
EndFunc   ;==>_cveBackgroundSubtractorMOGRelease

Func _cveBackgroundSubtractorGMGCreate($initializationFrames, $decisionThreshold, ByRef $bgSubtractor, ByRef $algorithm, ByRef $sharedPtr)
    ; CVAPI(cv::bgsegm::BackgroundSubtractorGMG*) cveBackgroundSubtractorGMGCreate(int initializationFrames, double decisionThreshold, cv::BackgroundSubtractor** bgSubtractor, cv::Algorithm** algorithm, cv::Ptr<cv::bgsegm::BackgroundSubtractorGMG>** sharedPtr);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveBackgroundSubtractorGMGCreate", "int", $initializationFrames, "double", $decisionThreshold, "ptr*", $bgSubtractor, "ptr*", $algorithm, "ptr*", $sharedPtr), "cveBackgroundSubtractorGMGCreate", @error)
EndFunc   ;==>_cveBackgroundSubtractorGMGCreate

Func _cveBackgroundSubtractorGMGRelease(ByRef $bgSubtractor, ByRef $sharedPtr)
    ; CVAPI(void) cveBackgroundSubtractorGMGRelease(cv::bgsegm::BackgroundSubtractorGMG** bgSubtractor, cv::Ptr<cv::bgsegm::BackgroundSubtractorGMG>** sharedPtr);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBackgroundSubtractorGMGRelease", "ptr*", $bgSubtractor, "ptr*", $sharedPtr), "cveBackgroundSubtractorGMGRelease", @error)
EndFunc   ;==>_cveBackgroundSubtractorGMGRelease

Func _cveBackgroundSubtractorCNTCreate($minPixelStability, $useHistory, $maxPixelStability, $isParallel, ByRef $bgSubtractor, ByRef $algorithm, ByRef $sharedPtr)
    ; CVAPI(cv::bgsegm::BackgroundSubtractorCNT*) cveBackgroundSubtractorCNTCreate(int minPixelStability, bool useHistory, int maxPixelStability, bool isParallel, cv::BackgroundSubtractor** bgSubtractor, cv::Algorithm** algorithm, cv::Ptr<cv::bgsegm::BackgroundSubtractorCNT>** sharedPtr);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveBackgroundSubtractorCNTCreate", "int", $minPixelStability, "boolean", $useHistory, "int", $maxPixelStability, "boolean", $isParallel, "ptr*", $bgSubtractor, "ptr*", $algorithm, "ptr*", $sharedPtr), "cveBackgroundSubtractorCNTCreate", @error)
EndFunc   ;==>_cveBackgroundSubtractorCNTCreate

Func _cveBackgroundSubtractorCNTRelease(ByRef $bgSubtractor, ByRef $sharedPtr)
    ; CVAPI(void) cveBackgroundSubtractorCNTRelease(cv::bgsegm::BackgroundSubtractorCNT** bgSubtractor, cv::Ptr<cv::bgsegm::BackgroundSubtractorCNT>** sharedPtr);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBackgroundSubtractorCNTRelease", "ptr*", $bgSubtractor, "ptr*", $sharedPtr), "cveBackgroundSubtractorCNTRelease", @error)
EndFunc   ;==>_cveBackgroundSubtractorCNTRelease

Func _cveBackgroundSubtractorGSOCCreate($mc, $nSamples, $replaceRate, $propagationRate, $hitsThreshold, $alpha, $beta, $blinkingSupressionDecay, $blinkingSupressionMultiplier, $noiseRemovalThresholdFacBG, $noiseRemovalThresholdFacFG, ByRef $bgSubtractor, ByRef $algorithm, ByRef $sharedPtr)
    ; CVAPI(cv::bgsegm::BackgroundSubtractorGSOC*) cveBackgroundSubtractorGSOCCreate(int mc, int nSamples, float replaceRate, float propagationRate, int hitsThreshold, float alpha, float beta, float blinkingSupressionDecay, float blinkingSupressionMultiplier, float noiseRemovalThresholdFacBG, float noiseRemovalThresholdFacFG, cv::BackgroundSubtractor** bgSubtractor, cv::Algorithm** algorithm, cv::Ptr<cv::bgsegm::BackgroundSubtractorGSOC>** sharedPtr);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveBackgroundSubtractorGSOCCreate", "int", $mc, "int", $nSamples, "float", $replaceRate, "float", $propagationRate, "int", $hitsThreshold, "float", $alpha, "float", $beta, "float", $blinkingSupressionDecay, "float", $blinkingSupressionMultiplier, "float", $noiseRemovalThresholdFacBG, "float", $noiseRemovalThresholdFacFG, "ptr*", $bgSubtractor, "ptr*", $algorithm, "ptr*", $sharedPtr), "cveBackgroundSubtractorGSOCCreate", @error)
EndFunc   ;==>_cveBackgroundSubtractorGSOCCreate

Func _cveBackgroundSubtractorGSOCRelease(ByRef $bgSubtractor, ByRef $sharedPtr)
    ; CVAPI(void) cveBackgroundSubtractorGSOCRelease(cv::bgsegm::BackgroundSubtractorGSOC** bgSubtractor, cv::Ptr<cv::bgsegm::BackgroundSubtractorGSOC>** sharedPtr);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBackgroundSubtractorGSOCRelease", "ptr*", $bgSubtractor, "ptr*", $sharedPtr), "cveBackgroundSubtractorGSOCRelease", @error)
EndFunc   ;==>_cveBackgroundSubtractorGSOCRelease

Func _cveBackgroundSubtractorLSBPCreate($mc, $nSamples, $LSBPRadius, $tlower, $tupper, $tinc, $tdec, $rscale, $rincdec, $noiseRemovalThresholdFacBG, $noiseRemovalThresholdFacFG, $LSBPthreshold, $minCount, ByRef $bgSubtractor, ByRef $algorithm, ByRef $sharedPtr)
    ; CVAPI(cv::bgsegm::BackgroundSubtractorLSBP*) cveBackgroundSubtractorLSBPCreate(int mc, int nSamples, int LSBPRadius, float tlower, float tupper, float tinc, float tdec, float rscale, float rincdec, float noiseRemovalThresholdFacBG, float noiseRemovalThresholdFacFG, int LSBPthreshold, int minCount, cv::BackgroundSubtractor** bgSubtractor, cv::Algorithm** algorithm, cv::Ptr<cv::bgsegm::BackgroundSubtractorLSBP>** sharedPtr);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveBackgroundSubtractorLSBPCreate", "int", $mc, "int", $nSamples, "int", $LSBPRadius, "float", $tlower, "float", $tupper, "float", $tinc, "float", $tdec, "float", $rscale, "float", $rincdec, "float", $noiseRemovalThresholdFacBG, "float", $noiseRemovalThresholdFacFG, "int", $LSBPthreshold, "int", $minCount, "ptr*", $bgSubtractor, "ptr*", $algorithm, "ptr*", $sharedPtr), "cveBackgroundSubtractorLSBPCreate", @error)
EndFunc   ;==>_cveBackgroundSubtractorLSBPCreate

Func _cveBackgroundSubtractorLSBPRelease(ByRef $bgSubtractor, ByRef $sharedPtr)
    ; CVAPI(void) cveBackgroundSubtractorLSBPRelease(cv::bgsegm::BackgroundSubtractorLSBP** bgSubtractor, cv::Ptr<cv::bgsegm::BackgroundSubtractorLSBP>** sharedPtr);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveBackgroundSubtractorLSBPRelease", "ptr*", $bgSubtractor, "ptr*", $sharedPtr), "cveBackgroundSubtractorLSBPRelease", @error)
EndFunc   ;==>_cveBackgroundSubtractorLSBPRelease