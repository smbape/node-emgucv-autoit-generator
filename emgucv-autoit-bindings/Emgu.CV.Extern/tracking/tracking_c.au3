#include-once
#include "..\..\CVEUtils.au3"

Func _cveTrackerKCFCreate($detect_thresh, $sigma, $lambda, $interp_factor, $output_sigma_factor, $pca_learning_rate, $resize, $split_coeff, $wrap_kernel, $compress_feature, $max_patch_size, $compressed_size, $desc_pca, $desc_npca, $tracker, $sharedPtr)
    ; CVAPI(cv::TrackerKCF*) cveTrackerKCFCreate(float detect_thresh, float sigma, float lambda, float interp_factor, float output_sigma_factor, float pca_learning_rate, bool resize, bool split_coeff, bool wrap_kernel, bool compress_feature, int max_patch_size, int compressed_size, int desc_pca, int desc_npca, cv::Tracker** tracker, cv::Ptr<cv::TrackerKCF>** sharedPtr);

    Local $bTrackerDllType
    If VarGetType($tracker) == "DLLStruct" Then
        $bTrackerDllType = "struct*"
    Else
        $bTrackerDllType = "ptr*"
    EndIf

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveTrackerKCFCreate", "float", $detect_thresh, "float", $sigma, "float", $lambda, "float", $interp_factor, "float", $output_sigma_factor, "float", $pca_learning_rate, "boolean", $resize, "boolean", $split_coeff, "boolean", $wrap_kernel, "boolean", $compress_feature, "int", $max_patch_size, "int", $compressed_size, "int", $desc_pca, "int", $desc_npca, $bTrackerDllType, $tracker, $bSharedPtrDllType, $sharedPtr), "cveTrackerKCFCreate", @error)
EndFunc   ;==>_cveTrackerKCFCreate

Func _cveTrackerKCFRelease($tracker, $sharedPtr)
    ; CVAPI(void) cveTrackerKCFRelease(cv::TrackerKCF** tracker, cv::Ptr<cv::TrackerKCF>** sharedPtr);

    Local $bTrackerDllType
    If VarGetType($tracker) == "DLLStruct" Then
        $bTrackerDllType = "struct*"
    Else
        $bTrackerDllType = "ptr*"
    EndIf

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveTrackerKCFRelease", $bTrackerDllType, $tracker, $bSharedPtrDllType, $sharedPtr), "cveTrackerKCFRelease", @error)
EndFunc   ;==>_cveTrackerKCFRelease

Func _cveTrackerCSRTCreate($use_hog, $use_color_names, $use_gray, $use_rgb, $use_channel_weights, $use_segmentation, $window_function, $kaiser_alpha, $cheb_attenuation, $template_size, $gsl_sigma, $hog_orientations, $hog_clip, $padding, $filter_lr, $weights_lr, $num_hog_channels_used, $admm_iterations, $histogram_bins, $histogram_lr, $background_ratio, $number_of_scales, $scale_sigma_factor, $scale_model_max_area, $scale_lr, $scale_step, $tracker, $sharedPtr)
    ; CVAPI(cv::TrackerCSRT*) cveTrackerCSRTCreate(bool use_hog, bool use_color_names, bool use_gray, bool use_rgb, bool use_channel_weights, bool use_segmentation, cv::String* window_function, float kaiser_alpha, float cheb_attenuation, float template_size, float gsl_sigma, float hog_orientations, float hog_clip, float padding, float filter_lr, float weights_lr, int num_hog_channels_used, int admm_iterations, int histogram_bins, float histogram_lr, int background_ratio, int number_of_scales, float scale_sigma_factor, float scale_model_max_area, float scale_lr, float scale_step, cv::Tracker** tracker, cv::Ptr<cv::TrackerCSRT>** sharedPtr);

    Local $bWindow_functionIsString = VarGetType($window_function) == "String"
    If $bWindow_functionIsString Then
        $window_function = _cveStringCreateFromStr($window_function)
    EndIf

    Local $bWindow_functionDllType
    If VarGetType($window_function) == "DLLStruct" Then
        $bWindow_functionDllType = "struct*"
    Else
        $bWindow_functionDllType = "ptr"
    EndIf

    Local $bTrackerDllType
    If VarGetType($tracker) == "DLLStruct" Then
        $bTrackerDllType = "struct*"
    Else
        $bTrackerDllType = "ptr*"
    EndIf

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveTrackerCSRTCreate", "boolean", $use_hog, "boolean", $use_color_names, "boolean", $use_gray, "boolean", $use_rgb, "boolean", $use_channel_weights, "boolean", $use_segmentation, $bWindow_functionDllType, $window_function, "float", $kaiser_alpha, "float", $cheb_attenuation, "float", $template_size, "float", $gsl_sigma, "float", $hog_orientations, "float", $hog_clip, "float", $padding, "float", $filter_lr, "float", $weights_lr, "int", $num_hog_channels_used, "int", $admm_iterations, "int", $histogram_bins, "float", $histogram_lr, "int", $background_ratio, "int", $number_of_scales, "float", $scale_sigma_factor, "float", $scale_model_max_area, "float", $scale_lr, "float", $scale_step, $bTrackerDllType, $tracker, $bSharedPtrDllType, $sharedPtr), "cveTrackerCSRTCreate", @error)

    If $bWindow_functionIsString Then
        _cveStringRelease($window_function)
    EndIf

    Return $retval
EndFunc   ;==>_cveTrackerCSRTCreate

Func _cveTrackerCSRTRelease($tracker, $sharedPtr)
    ; CVAPI(void) cveTrackerCSRTRelease(cv::TrackerCSRT** tracker, cv::Ptr<cv::TrackerCSRT>** sharedPtr);

    Local $bTrackerDllType
    If VarGetType($tracker) == "DLLStruct" Then
        $bTrackerDllType = "struct*"
    Else
        $bTrackerDllType = "ptr*"
    EndIf

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveTrackerCSRTRelease", $bTrackerDllType, $tracker, $bSharedPtrDllType, $sharedPtr), "cveTrackerCSRTRelease", @error)
EndFunc   ;==>_cveTrackerCSRTRelease

Func _cveLegacyTrackerInit($tracker, $image, $boundingBox)
    ; CVAPI(bool) cveLegacyTrackerInit(cv::legacy::Tracker* tracker, cv::Mat* image, CvRect* boundingBox);

    Local $bTrackerDllType
    If VarGetType($tracker) == "DLLStruct" Then
        $bTrackerDllType = "struct*"
    Else
        $bTrackerDllType = "ptr"
    EndIf

    Local $bImageDllType
    If VarGetType($image) == "DLLStruct" Then
        $bImageDllType = "struct*"
    Else
        $bImageDllType = "ptr"
    EndIf

    Local $bBoundingBoxDllType
    If VarGetType($boundingBox) == "DLLStruct" Then
        $bBoundingBoxDllType = "struct*"
    Else
        $bBoundingBoxDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveLegacyTrackerInit", $bTrackerDllType, $tracker, $bImageDllType, $image, $bBoundingBoxDllType, $boundingBox), "cveLegacyTrackerInit", @error)
EndFunc   ;==>_cveLegacyTrackerInit

Func _cveLegacyTrackerUpdate($tracker, $image, $boundingBox)
    ; CVAPI(bool) cveLegacyTrackerUpdate(cv::legacy::Tracker* tracker, cv::Mat* image, CvRect* boundingBox);

    Local $bTrackerDllType
    If VarGetType($tracker) == "DLLStruct" Then
        $bTrackerDllType = "struct*"
    Else
        $bTrackerDllType = "ptr"
    EndIf

    Local $bImageDllType
    If VarGetType($image) == "DLLStruct" Then
        $bImageDllType = "struct*"
    Else
        $bImageDllType = "ptr"
    EndIf

    Local $bBoundingBoxDllType
    If VarGetType($boundingBox) == "DLLStruct" Then
        $bBoundingBoxDllType = "struct*"
    Else
        $bBoundingBoxDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveLegacyTrackerUpdate", $bTrackerDllType, $tracker, $bImageDllType, $image, $bBoundingBoxDllType, $boundingBox), "cveLegacyTrackerUpdate", @error)
EndFunc   ;==>_cveLegacyTrackerUpdate

Func _cveTrackerBoostingCreate($numClassifiers, $samplerOverlap, $samplerSearchFactor, $iterationInit, $featureSetNumFeatures, $tracker, $sharedPtr)
    ; CVAPI(cv::legacy::TrackerBoosting*) cveTrackerBoostingCreate(int numClassifiers, float samplerOverlap, float samplerSearchFactor, int iterationInit, int featureSetNumFeatures, cv::legacy::Tracker** tracker, cv::Ptr<cv::legacy::TrackerBoosting>** sharedPtr);

    Local $bTrackerDllType
    If VarGetType($tracker) == "DLLStruct" Then
        $bTrackerDllType = "struct*"
    Else
        $bTrackerDllType = "ptr*"
    EndIf

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveTrackerBoostingCreate", "int", $numClassifiers, "float", $samplerOverlap, "float", $samplerSearchFactor, "int", $iterationInit, "int", $featureSetNumFeatures, $bTrackerDllType, $tracker, $bSharedPtrDllType, $sharedPtr), "cveTrackerBoostingCreate", @error)
EndFunc   ;==>_cveTrackerBoostingCreate

Func _cveTrackerBoostingRelease($tracker, $sharedPtr)
    ; CVAPI(void) cveTrackerBoostingRelease(cv::legacy::TrackerBoosting** tracker, cv::Ptr<cv::legacy::TrackerBoosting>** sharedPtr);

    Local $bTrackerDllType
    If VarGetType($tracker) == "DLLStruct" Then
        $bTrackerDllType = "struct*"
    Else
        $bTrackerDllType = "ptr*"
    EndIf

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveTrackerBoostingRelease", $bTrackerDllType, $tracker, $bSharedPtrDllType, $sharedPtr), "cveTrackerBoostingRelease", @error)
EndFunc   ;==>_cveTrackerBoostingRelease

Func _cveTrackerMedianFlowCreate($pointsInGrid, $winSize, $maxLevel, $termCriteria, $winSizeNCC, $maxMedianLengthOfDisplacementDifference, $tracker, $sharedPtr)
    ; CVAPI(cv::legacy::TrackerMedianFlow*) cveTrackerMedianFlowCreate(int pointsInGrid, CvSize* winSize, int maxLevel, CvTermCriteria* termCriteria, CvSize* winSizeNCC, double maxMedianLengthOfDisplacementDifference, cv::legacy::Tracker** tracker, cv::Ptr<cv::legacy::TrackerMedianFlow>** sharedPtr);

    Local $bWinSizeDllType
    If VarGetType($winSize) == "DLLStruct" Then
        $bWinSizeDllType = "struct*"
    Else
        $bWinSizeDllType = "ptr"
    EndIf

    Local $bTermCriteriaDllType
    If VarGetType($termCriteria) == "DLLStruct" Then
        $bTermCriteriaDllType = "struct*"
    Else
        $bTermCriteriaDllType = "ptr"
    EndIf

    Local $bWinSizeNCCDllType
    If VarGetType($winSizeNCC) == "DLLStruct" Then
        $bWinSizeNCCDllType = "struct*"
    Else
        $bWinSizeNCCDllType = "ptr"
    EndIf

    Local $bTrackerDllType
    If VarGetType($tracker) == "DLLStruct" Then
        $bTrackerDllType = "struct*"
    Else
        $bTrackerDllType = "ptr*"
    EndIf

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveTrackerMedianFlowCreate", "int", $pointsInGrid, $bWinSizeDllType, $winSize, "int", $maxLevel, $bTermCriteriaDllType, $termCriteria, $bWinSizeNCCDllType, $winSizeNCC, "double", $maxMedianLengthOfDisplacementDifference, $bTrackerDllType, $tracker, $bSharedPtrDllType, $sharedPtr), "cveTrackerMedianFlowCreate", @error)
EndFunc   ;==>_cveTrackerMedianFlowCreate

Func _cveTrackerMedianFlowRelease($tracker, $sharedPtr)
    ; CVAPI(void) cveTrackerMedianFlowRelease(cv::legacy::TrackerMedianFlow** tracker, cv::Ptr<cv::legacy::TrackerMedianFlow>** sharedPtr);

    Local $bTrackerDllType
    If VarGetType($tracker) == "DLLStruct" Then
        $bTrackerDllType = "struct*"
    Else
        $bTrackerDllType = "ptr*"
    EndIf

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveTrackerMedianFlowRelease", $bTrackerDllType, $tracker, $bSharedPtrDllType, $sharedPtr), "cveTrackerMedianFlowRelease", @error)
EndFunc   ;==>_cveTrackerMedianFlowRelease

Func _cveTrackerTLDCreate($tracker, $sharedPtr)
    ; CVAPI(cv::legacy::TrackerTLD*) cveTrackerTLDCreate(cv::legacy::Tracker** tracker, cv::Ptr<cv::legacy::TrackerTLD>** sharedPtr);

    Local $bTrackerDllType
    If VarGetType($tracker) == "DLLStruct" Then
        $bTrackerDllType = "struct*"
    Else
        $bTrackerDllType = "ptr*"
    EndIf

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveTrackerTLDCreate", $bTrackerDllType, $tracker, $bSharedPtrDllType, $sharedPtr), "cveTrackerTLDCreate", @error)
EndFunc   ;==>_cveTrackerTLDCreate

Func _cveTrackerTLDRelease($tracker, $sharedPtr)
    ; CVAPI(void) cveTrackerTLDRelease(cv::legacy::TrackerTLD** tracker, cv::Ptr<cv::legacy::TrackerTLD>** sharedPtr);

    Local $bTrackerDllType
    If VarGetType($tracker) == "DLLStruct" Then
        $bTrackerDllType = "struct*"
    Else
        $bTrackerDllType = "ptr*"
    EndIf

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveTrackerTLDRelease", $bTrackerDllType, $tracker, $bSharedPtrDllType, $sharedPtr), "cveTrackerTLDRelease", @error)
EndFunc   ;==>_cveTrackerTLDRelease

Func _cveTrackerMOSSECreate($tracker, $sharedPtr)
    ; CVAPI(cv::legacy::TrackerMOSSE*) cveTrackerMOSSECreate(cv::legacy::Tracker** tracker, cv::Ptr<cv::legacy::TrackerMOSSE>** sharedPtr);

    Local $bTrackerDllType
    If VarGetType($tracker) == "DLLStruct" Then
        $bTrackerDllType = "struct*"
    Else
        $bTrackerDllType = "ptr*"
    EndIf

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveTrackerMOSSECreate", $bTrackerDllType, $tracker, $bSharedPtrDllType, $sharedPtr), "cveTrackerMOSSECreate", @error)
EndFunc   ;==>_cveTrackerMOSSECreate

Func _cveTrackerMOSSERelease($tracker, $sharedPtr)
    ; CVAPI(void) cveTrackerMOSSERelease(cv::legacy::TrackerMOSSE** tracker, cv::Ptr<cv::legacy::TrackerMOSSE>** sharedPtr);

    Local $bTrackerDllType
    If VarGetType($tracker) == "DLLStruct" Then
        $bTrackerDllType = "struct*"
    Else
        $bTrackerDllType = "ptr*"
    EndIf

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveTrackerMOSSERelease", $bTrackerDllType, $tracker, $bSharedPtrDllType, $sharedPtr), "cveTrackerMOSSERelease", @error)
EndFunc   ;==>_cveTrackerMOSSERelease

Func _cveMultiTrackerCreate()
    ; CVAPI(cv::legacy::MultiTracker*) cveMultiTrackerCreate();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveMultiTrackerCreate"), "cveMultiTrackerCreate", @error)
EndFunc   ;==>_cveMultiTrackerCreate

Func _cveMultiTrackerAdd($multiTracker, $tracker, $image, $boundingBox)
    ; CVAPI(bool) cveMultiTrackerAdd(cv::legacy::MultiTracker* multiTracker, cv::legacy::Tracker* tracker, cv::_InputArray* image, CvRect* boundingBox);

    Local $bMultiTrackerDllType
    If VarGetType($multiTracker) == "DLLStruct" Then
        $bMultiTrackerDllType = "struct*"
    Else
        $bMultiTrackerDllType = "ptr"
    EndIf

    Local $bTrackerDllType
    If VarGetType($tracker) == "DLLStruct" Then
        $bTrackerDllType = "struct*"
    Else
        $bTrackerDllType = "ptr"
    EndIf

    Local $bImageDllType
    If VarGetType($image) == "DLLStruct" Then
        $bImageDllType = "struct*"
    Else
        $bImageDllType = "ptr"
    EndIf

    Local $bBoundingBoxDllType
    If VarGetType($boundingBox) == "DLLStruct" Then
        $bBoundingBoxDllType = "struct*"
    Else
        $bBoundingBoxDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveMultiTrackerAdd", $bMultiTrackerDllType, $multiTracker, $bTrackerDllType, $tracker, $bImageDllType, $image, $bBoundingBoxDllType, $boundingBox), "cveMultiTrackerAdd", @error)
EndFunc   ;==>_cveMultiTrackerAdd

Func _cveMultiTrackerAddMat($multiTracker, $tracker, $matImage, $boundingBox)
    ; cveMultiTrackerAdd using cv::Mat instead of _*Array

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

    Local $retval = _cveMultiTrackerAdd($multiTracker, $tracker, $iArrImage, $boundingBox)

    If $bImageIsArray Then
        _VectorOfMatRelease($vectorOfMatImage)
    EndIf

    _cveInputArrayRelease($iArrImage)

    Return $retval
EndFunc   ;==>_cveMultiTrackerAddMat

Func _cveMultiTrackerUpdate($tracker, $image, $boundingBox)
    ; CVAPI(bool) cveMultiTrackerUpdate(cv::legacy::MultiTracker* tracker, cv::Mat* image, std::vector<CvRect>* boundingBox);

    Local $bTrackerDllType
    If VarGetType($tracker) == "DLLStruct" Then
        $bTrackerDllType = "struct*"
    Else
        $bTrackerDllType = "ptr"
    EndIf

    Local $bImageDllType
    If VarGetType($image) == "DLLStruct" Then
        $bImageDllType = "struct*"
    Else
        $bImageDllType = "ptr"
    EndIf

    Local $bBoundingBoxDllType
    If VarGetType($boundingBox) == "DLLStruct" Then
        $bBoundingBoxDllType = "struct*"
    Else
        $bBoundingBoxDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveMultiTrackerUpdate", $bTrackerDllType, $tracker, $bImageDllType, $image, $bBoundingBoxDllType, $boundingBox), "cveMultiTrackerUpdate", @error)
EndFunc   ;==>_cveMultiTrackerUpdate

Func _cveMultiTrackerRelease($tracker)
    ; CVAPI(void) cveMultiTrackerRelease(cv::legacy::MultiTracker** tracker);

    Local $bTrackerDllType
    If VarGetType($tracker) == "DLLStruct" Then
        $bTrackerDllType = "struct*"
    Else
        $bTrackerDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMultiTrackerRelease", $bTrackerDllType, $tracker), "cveMultiTrackerRelease", @error)
EndFunc   ;==>_cveMultiTrackerRelease

Func _cveMultiTrackerGetObjects($tracker, $boundingBox)
    ; CVAPI(void) cveMultiTrackerGetObjects(cv::legacy::MultiTracker* tracker, std::vector<CvRect>* boundingBox);

    Local $bTrackerDllType
    If VarGetType($tracker) == "DLLStruct" Then
        $bTrackerDllType = "struct*"
    Else
        $bTrackerDllType = "ptr"
    EndIf

    Local $bBoundingBoxDllType
    If VarGetType($boundingBox) == "DLLStruct" Then
        $bBoundingBoxDllType = "struct*"
    Else
        $bBoundingBoxDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMultiTrackerGetObjects", $bTrackerDllType, $tracker, $bBoundingBoxDllType, $boundingBox), "cveMultiTrackerGetObjects", @error)
EndFunc   ;==>_cveMultiTrackerGetObjects