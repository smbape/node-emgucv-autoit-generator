#include-once
#include <..\..\CVEUtils.au3>

Func _cveTrackerKCFCreate($detect_thresh, $sigma, $lambda, $interp_factor, $output_sigma_factor, $pca_learning_rate, $resize, $split_coeff, $wrap_kernel, $compress_feature, $max_patch_size, $compressed_size, $desc_pca, $desc_npca, ByRef $tracker, ByRef $sharedPtr)
    ; CVAPI(cv::TrackerKCF*) cveTrackerKCFCreate(float detect_thresh, float sigma, float lambda, float interp_factor, float output_sigma_factor, float pca_learning_rate, bool resize, bool split_coeff, bool wrap_kernel, bool compress_feature, int max_patch_size, int compressed_size, int desc_pca, int desc_npca, cv::Tracker** tracker, cv::Ptr<cv::TrackerKCF>** sharedPtr);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveTrackerKCFCreate", "float", $detect_thresh, "float", $sigma, "float", $lambda, "float", $interp_factor, "float", $output_sigma_factor, "float", $pca_learning_rate, "boolean", $resize, "boolean", $split_coeff, "boolean", $wrap_kernel, "boolean", $compress_feature, "int", $max_patch_size, "int", $compressed_size, "int", $desc_pca, "int", $desc_npca, "ptr*", $tracker, "ptr*", $sharedPtr), "cveTrackerKCFCreate", @error)
EndFunc   ;==>_cveTrackerKCFCreate

Func _cveTrackerKCFRelease(ByRef $tracker, ByRef $sharedPtr)
    ; CVAPI(void) cveTrackerKCFRelease(cv::TrackerKCF** tracker, cv::Ptr<cv::TrackerKCF>** sharedPtr);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveTrackerKCFRelease", "ptr*", $tracker, "ptr*", $sharedPtr), "cveTrackerKCFRelease", @error)
EndFunc   ;==>_cveTrackerKCFRelease

Func _cveTrackerCSRTCreate($use_hog, $use_color_names, $use_gray, $use_rgb, $use_channel_weights, $use_segmentation, $window_function, $kaiser_alpha, $cheb_attenuation, $template_size, $gsl_sigma, $hog_orientations, $hog_clip, $padding, $filter_lr, $weights_lr, $num_hog_channels_used, $admm_iterations, $histogram_bins, $histogram_lr, $background_ratio, $number_of_scales, $scale_sigma_factor, $scale_model_max_area, $scale_lr, $scale_step, ByRef $tracker, ByRef $sharedPtr)
    ; CVAPI(cv::TrackerCSRT*) cveTrackerCSRTCreate(bool use_hog, bool use_color_names, bool use_gray, bool use_rgb, bool use_channel_weights, bool use_segmentation, cv::String* window_function, float kaiser_alpha, float cheb_attenuation, float template_size, float gsl_sigma, float hog_orientations, float hog_clip, float padding, float filter_lr, float weights_lr, int num_hog_channels_used, int admm_iterations, int histogram_bins, float histogram_lr, int background_ratio, int number_of_scales, float scale_sigma_factor, float scale_model_max_area, float scale_lr, float scale_step, cv::Tracker** tracker, cv::Ptr<cv::TrackerCSRT>** sharedPtr);

    Local $bWindow_functionIsString = VarGetType($window_function) == "String"
    If $bWindow_functionIsString Then
        $window_function = _cveStringCreateFromStr($window_function)
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveTrackerCSRTCreate", "boolean", $use_hog, "boolean", $use_color_names, "boolean", $use_gray, "boolean", $use_rgb, "boolean", $use_channel_weights, "boolean", $use_segmentation, "ptr", $window_function, "float", $kaiser_alpha, "float", $cheb_attenuation, "float", $template_size, "float", $gsl_sigma, "float", $hog_orientations, "float", $hog_clip, "float", $padding, "float", $filter_lr, "float", $weights_lr, "int", $num_hog_channels_used, "int", $admm_iterations, "int", $histogram_bins, "float", $histogram_lr, "int", $background_ratio, "int", $number_of_scales, "float", $scale_sigma_factor, "float", $scale_model_max_area, "float", $scale_lr, "float", $scale_step, "ptr*", $tracker, "ptr*", $sharedPtr), "cveTrackerCSRTCreate", @error)

    If $bWindow_functionIsString Then
        _cveStringRelease($window_function)
    EndIf

    Return $retval
EndFunc   ;==>_cveTrackerCSRTCreate

Func _cveTrackerCSRTRelease(ByRef $tracker, ByRef $sharedPtr)
    ; CVAPI(void) cveTrackerCSRTRelease(cv::TrackerCSRT** tracker, cv::Ptr<cv::TrackerCSRT>** sharedPtr);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveTrackerCSRTRelease", "ptr*", $tracker, "ptr*", $sharedPtr), "cveTrackerCSRTRelease", @error)
EndFunc   ;==>_cveTrackerCSRTRelease

Func _cveLegacyTrackerInit(ByRef $tracker, ByRef $image, ByRef $boundingBox)
    ; CVAPI(bool) cveLegacyTrackerInit(cv::legacy::Tracker* tracker, cv::Mat* image, CvRect* boundingBox);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveLegacyTrackerInit", "ptr", $tracker, "ptr", $image, "struct*", $boundingBox), "cveLegacyTrackerInit", @error)
EndFunc   ;==>_cveLegacyTrackerInit

Func _cveLegacyTrackerUpdate(ByRef $tracker, ByRef $image, ByRef $boundingBox)
    ; CVAPI(bool) cveLegacyTrackerUpdate(cv::legacy::Tracker* tracker, cv::Mat* image, CvRect* boundingBox);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveLegacyTrackerUpdate", "ptr", $tracker, "ptr", $image, "struct*", $boundingBox), "cveLegacyTrackerUpdate", @error)
EndFunc   ;==>_cveLegacyTrackerUpdate

Func _cveTrackerBoostingCreate($numClassifiers, $samplerOverlap, $samplerSearchFactor, $iterationInit, $featureSetNumFeatures, ByRef $tracker, ByRef $sharedPtr)
    ; CVAPI(cv::legacy::TrackerBoosting*) cveTrackerBoostingCreate(int numClassifiers, float samplerOverlap, float samplerSearchFactor, int iterationInit, int featureSetNumFeatures, cv::legacy::Tracker** tracker, cv::Ptr<cv::legacy::TrackerBoosting>** sharedPtr);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveTrackerBoostingCreate", "int", $numClassifiers, "float", $samplerOverlap, "float", $samplerSearchFactor, "int", $iterationInit, "int", $featureSetNumFeatures, "ptr*", $tracker, "ptr*", $sharedPtr), "cveTrackerBoostingCreate", @error)
EndFunc   ;==>_cveTrackerBoostingCreate

Func _cveTrackerBoostingRelease(ByRef $tracker, ByRef $sharedPtr)
    ; CVAPI(void) cveTrackerBoostingRelease(cv::legacy::TrackerBoosting** tracker, cv::Ptr<cv::legacy::TrackerBoosting>** sharedPtr);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveTrackerBoostingRelease", "ptr*", $tracker, "ptr*", $sharedPtr), "cveTrackerBoostingRelease", @error)
EndFunc   ;==>_cveTrackerBoostingRelease

Func _cveTrackerMedianFlowCreate($pointsInGrid, ByRef $winSize, $maxLevel, ByRef $termCriteria, ByRef $winSizeNCC, $maxMedianLengthOfDisplacementDifference, ByRef $tracker, ByRef $sharedPtr)
    ; CVAPI(cv::legacy::TrackerMedianFlow*) cveTrackerMedianFlowCreate(int pointsInGrid, CvSize* winSize, int maxLevel, CvTermCriteria* termCriteria, CvSize* winSizeNCC, double maxMedianLengthOfDisplacementDifference, cv::legacy::Tracker** tracker, cv::Ptr<cv::legacy::TrackerMedianFlow>** sharedPtr);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveTrackerMedianFlowCreate", "int", $pointsInGrid, "struct*", $winSize, "int", $maxLevel, "struct*", $termCriteria, "struct*", $winSizeNCC, "double", $maxMedianLengthOfDisplacementDifference, "ptr*", $tracker, "ptr*", $sharedPtr), "cveTrackerMedianFlowCreate", @error)
EndFunc   ;==>_cveTrackerMedianFlowCreate

Func _cveTrackerMedianFlowRelease(ByRef $tracker, ByRef $sharedPtr)
    ; CVAPI(void) cveTrackerMedianFlowRelease(cv::legacy::TrackerMedianFlow** tracker, cv::Ptr<cv::legacy::TrackerMedianFlow>** sharedPtr);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveTrackerMedianFlowRelease", "ptr*", $tracker, "ptr*", $sharedPtr), "cveTrackerMedianFlowRelease", @error)
EndFunc   ;==>_cveTrackerMedianFlowRelease

Func _cveTrackerTLDCreate(ByRef $tracker, ByRef $sharedPtr)
    ; CVAPI(cv::legacy::TrackerTLD*) cveTrackerTLDCreate(cv::legacy::Tracker** tracker, cv::Ptr<cv::legacy::TrackerTLD>** sharedPtr);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveTrackerTLDCreate", "ptr*", $tracker, "ptr*", $sharedPtr), "cveTrackerTLDCreate", @error)
EndFunc   ;==>_cveTrackerTLDCreate

Func _cveTrackerTLDRelease(ByRef $tracker, ByRef $sharedPtr)
    ; CVAPI(void) cveTrackerTLDRelease(cv::legacy::TrackerTLD** tracker, cv::Ptr<cv::legacy::TrackerTLD>** sharedPtr);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveTrackerTLDRelease", "ptr*", $tracker, "ptr*", $sharedPtr), "cveTrackerTLDRelease", @error)
EndFunc   ;==>_cveTrackerTLDRelease

Func _cveTrackerMOSSECreate(ByRef $tracker, ByRef $sharedPtr)
    ; CVAPI(cv::legacy::TrackerMOSSE*) cveTrackerMOSSECreate(cv::legacy::Tracker** tracker, cv::Ptr<cv::legacy::TrackerMOSSE>** sharedPtr);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveTrackerMOSSECreate", "ptr*", $tracker, "ptr*", $sharedPtr), "cveTrackerMOSSECreate", @error)
EndFunc   ;==>_cveTrackerMOSSECreate

Func _cveTrackerMOSSERelease(ByRef $tracker, ByRef $sharedPtr)
    ; CVAPI(void) cveTrackerMOSSERelease(cv::legacy::TrackerMOSSE** tracker, cv::Ptr<cv::legacy::TrackerMOSSE>** sharedPtr);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveTrackerMOSSERelease", "ptr*", $tracker, "ptr*", $sharedPtr), "cveTrackerMOSSERelease", @error)
EndFunc   ;==>_cveTrackerMOSSERelease

Func _cveMultiTrackerCreate()
    ; CVAPI(cv::legacy::MultiTracker*) cveMultiTrackerCreate();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveMultiTrackerCreate"), "cveMultiTrackerCreate", @error)
EndFunc   ;==>_cveMultiTrackerCreate

Func _cveMultiTrackerAdd(ByRef $multiTracker, ByRef $tracker, ByRef $image, ByRef $boundingBox)
    ; CVAPI(bool) cveMultiTrackerAdd(cv::legacy::MultiTracker* multiTracker, cv::legacy::Tracker* tracker, cv::_InputArray* image, CvRect* boundingBox);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveMultiTrackerAdd", "ptr", $multiTracker, "ptr", $tracker, "ptr", $image, "struct*", $boundingBox), "cveMultiTrackerAdd", @error)
EndFunc   ;==>_cveMultiTrackerAdd

Func _cveMultiTrackerAddMat(ByRef $multiTracker, ByRef $tracker, ByRef $matImage, ByRef $boundingBox)
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

Func _cveMultiTrackerUpdate(ByRef $tracker, ByRef $image, ByRef $boundingBox)
    ; CVAPI(bool) cveMultiTrackerUpdate(cv::legacy::MultiTracker* tracker, cv::Mat* image, std::vector<CvRect>* boundingBox);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveMultiTrackerUpdate", "ptr", $tracker, "ptr", $image, "ptr", $boundingBox), "cveMultiTrackerUpdate", @error)
EndFunc   ;==>_cveMultiTrackerUpdate

Func _cveMultiTrackerRelease(ByRef $tracker)
    ; CVAPI(void) cveMultiTrackerRelease(cv::legacy::MultiTracker** tracker);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMultiTrackerRelease", "ptr*", $tracker), "cveMultiTrackerRelease", @error)
EndFunc   ;==>_cveMultiTrackerRelease

Func _cveMultiTrackerGetObjects(ByRef $tracker, ByRef $boundingBox)
    ; CVAPI(void) cveMultiTrackerGetObjects(cv::legacy::MultiTracker* tracker, std::vector<CvRect>* boundingBox);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMultiTrackerGetObjects", "ptr", $tracker, "ptr", $boundingBox), "cveMultiTrackerGetObjects", @error)
EndFunc   ;==>_cveMultiTrackerGetObjects