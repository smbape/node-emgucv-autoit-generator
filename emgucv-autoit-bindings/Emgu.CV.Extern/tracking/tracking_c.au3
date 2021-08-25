#include-once
#include "..\..\CVEUtils.au3"

Func _cveTrackerKCFCreate($detect_thresh, $sigma, $lambda, $interp_factor, $output_sigma_factor, $pca_learning_rate, $resize, $split_coeff, $wrap_kernel, $compress_feature, $max_patch_size, $compressed_size, $desc_pca, $desc_npca, $tracker, $sharedPtr)
    ; CVAPI(cv::TrackerKCF*) cveTrackerKCFCreate(float detect_thresh, float sigma, float lambda, float interp_factor, float output_sigma_factor, float pca_learning_rate, bool resize, bool split_coeff, bool wrap_kernel, bool compress_feature, int max_patch_size, int compressed_size, int desc_pca, int desc_npca, cv::Tracker** tracker, cv::Ptr<cv::TrackerKCF>** sharedPtr);

    Local $sTrackerDllType
    If IsDllStruct($tracker) Then
        $sTrackerDllType = "struct*"
    ElseIf $tracker == Null Then
        $sTrackerDllType = "ptr"
    Else
        $sTrackerDllType = "ptr*"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveTrackerKCFCreate", "float", $detect_thresh, "float", $sigma, "float", $lambda, "float", $interp_factor, "float", $output_sigma_factor, "float", $pca_learning_rate, "boolean", $resize, "boolean", $split_coeff, "boolean", $wrap_kernel, "boolean", $compress_feature, "int", $max_patch_size, "int", $compressed_size, "int", $desc_pca, "int", $desc_npca, $sTrackerDllType, $tracker, $sSharedPtrDllType, $sharedPtr), "cveTrackerKCFCreate", @error)
EndFunc   ;==>_cveTrackerKCFCreate

Func _cveTrackerKCFRelease($tracker, $sharedPtr)
    ; CVAPI(void) cveTrackerKCFRelease(cv::TrackerKCF** tracker, cv::Ptr<cv::TrackerKCF>** sharedPtr);

    Local $sTrackerDllType
    If IsDllStruct($tracker) Then
        $sTrackerDllType = "struct*"
    ElseIf $tracker == Null Then
        $sTrackerDllType = "ptr"
    Else
        $sTrackerDllType = "ptr*"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveTrackerKCFRelease", $sTrackerDllType, $tracker, $sSharedPtrDllType, $sharedPtr), "cveTrackerKCFRelease", @error)
EndFunc   ;==>_cveTrackerKCFRelease

Func _cveTrackerCSRTCreate($use_hog, $use_color_names, $use_gray, $use_rgb, $use_channel_weights, $use_segmentation, $window_function, $kaiser_alpha, $cheb_attenuation, $template_size, $gsl_sigma, $hog_orientations, $hog_clip, $padding, $filter_lr, $weights_lr, $num_hog_channels_used, $admm_iterations, $histogram_bins, $histogram_lr, $background_ratio, $number_of_scales, $scale_sigma_factor, $scale_model_max_area, $scale_lr, $scale_step, $tracker, $sharedPtr)
    ; CVAPI(cv::TrackerCSRT*) cveTrackerCSRTCreate(bool use_hog, bool use_color_names, bool use_gray, bool use_rgb, bool use_channel_weights, bool use_segmentation, cv::String* window_function, float kaiser_alpha, float cheb_attenuation, float template_size, float gsl_sigma, float hog_orientations, float hog_clip, float padding, float filter_lr, float weights_lr, int num_hog_channels_used, int admm_iterations, int histogram_bins, float histogram_lr, int background_ratio, int number_of_scales, float scale_sigma_factor, float scale_model_max_area, float scale_lr, float scale_step, cv::Tracker** tracker, cv::Ptr<cv::TrackerCSRT>** sharedPtr);

    Local $bWindow_functionIsString = IsString($window_function)
    If $bWindow_functionIsString Then
        $window_function = _cveStringCreateFromStr($window_function)
    EndIf

    Local $sWindow_functionDllType
    If IsDllStruct($window_function) Then
        $sWindow_functionDllType = "struct*"
    Else
        $sWindow_functionDllType = "ptr"
    EndIf

    Local $sTrackerDllType
    If IsDllStruct($tracker) Then
        $sTrackerDllType = "struct*"
    ElseIf $tracker == Null Then
        $sTrackerDllType = "ptr"
    Else
        $sTrackerDllType = "ptr*"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveTrackerCSRTCreate", "boolean", $use_hog, "boolean", $use_color_names, "boolean", $use_gray, "boolean", $use_rgb, "boolean", $use_channel_weights, "boolean", $use_segmentation, $sWindow_functionDllType, $window_function, "float", $kaiser_alpha, "float", $cheb_attenuation, "float", $template_size, "float", $gsl_sigma, "float", $hog_orientations, "float", $hog_clip, "float", $padding, "float", $filter_lr, "float", $weights_lr, "int", $num_hog_channels_used, "int", $admm_iterations, "int", $histogram_bins, "float", $histogram_lr, "int", $background_ratio, "int", $number_of_scales, "float", $scale_sigma_factor, "float", $scale_model_max_area, "float", $scale_lr, "float", $scale_step, $sTrackerDllType, $tracker, $sSharedPtrDllType, $sharedPtr), "cveTrackerCSRTCreate", @error)

    If $bWindow_functionIsString Then
        _cveStringRelease($window_function)
    EndIf

    Return $retval
EndFunc   ;==>_cveTrackerCSRTCreate

Func _cveTrackerCSRTRelease($tracker, $sharedPtr)
    ; CVAPI(void) cveTrackerCSRTRelease(cv::TrackerCSRT** tracker, cv::Ptr<cv::TrackerCSRT>** sharedPtr);

    Local $sTrackerDllType
    If IsDllStruct($tracker) Then
        $sTrackerDllType = "struct*"
    ElseIf $tracker == Null Then
        $sTrackerDllType = "ptr"
    Else
        $sTrackerDllType = "ptr*"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveTrackerCSRTRelease", $sTrackerDllType, $tracker, $sSharedPtrDllType, $sharedPtr), "cveTrackerCSRTRelease", @error)
EndFunc   ;==>_cveTrackerCSRTRelease

Func _cveLegacyTrackerInit($tracker, $image, $boundingBox)
    ; CVAPI(bool) cveLegacyTrackerInit(cv::legacy::Tracker* tracker, cv::Mat* image, CvRect* boundingBox);

    Local $sTrackerDllType
    If IsDllStruct($tracker) Then
        $sTrackerDllType = "struct*"
    Else
        $sTrackerDllType = "ptr"
    EndIf

    Local $sImageDllType
    If IsDllStruct($image) Then
        $sImageDllType = "struct*"
    Else
        $sImageDllType = "ptr"
    EndIf

    Local $sBoundingBoxDllType
    If IsDllStruct($boundingBox) Then
        $sBoundingBoxDllType = "struct*"
    Else
        $sBoundingBoxDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveLegacyTrackerInit", $sTrackerDllType, $tracker, $sImageDllType, $image, $sBoundingBoxDllType, $boundingBox), "cveLegacyTrackerInit", @error)
EndFunc   ;==>_cveLegacyTrackerInit

Func _cveLegacyTrackerUpdate($tracker, $image, $boundingBox)
    ; CVAPI(bool) cveLegacyTrackerUpdate(cv::legacy::Tracker* tracker, cv::Mat* image, CvRect* boundingBox);

    Local $sTrackerDllType
    If IsDllStruct($tracker) Then
        $sTrackerDllType = "struct*"
    Else
        $sTrackerDllType = "ptr"
    EndIf

    Local $sImageDllType
    If IsDllStruct($image) Then
        $sImageDllType = "struct*"
    Else
        $sImageDllType = "ptr"
    EndIf

    Local $sBoundingBoxDllType
    If IsDllStruct($boundingBox) Then
        $sBoundingBoxDllType = "struct*"
    Else
        $sBoundingBoxDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveLegacyTrackerUpdate", $sTrackerDllType, $tracker, $sImageDllType, $image, $sBoundingBoxDllType, $boundingBox), "cveLegacyTrackerUpdate", @error)
EndFunc   ;==>_cveLegacyTrackerUpdate

Func _cveTrackerBoostingCreate($numClassifiers, $samplerOverlap, $samplerSearchFactor, $iterationInit, $featureSetNumFeatures, $tracker, $sharedPtr)
    ; CVAPI(cv::legacy::TrackerBoosting*) cveTrackerBoostingCreate(int numClassifiers, float samplerOverlap, float samplerSearchFactor, int iterationInit, int featureSetNumFeatures, cv::legacy::Tracker** tracker, cv::Ptr<cv::legacy::TrackerBoosting>** sharedPtr);

    Local $sTrackerDllType
    If IsDllStruct($tracker) Then
        $sTrackerDllType = "struct*"
    ElseIf $tracker == Null Then
        $sTrackerDllType = "ptr"
    Else
        $sTrackerDllType = "ptr*"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveTrackerBoostingCreate", "int", $numClassifiers, "float", $samplerOverlap, "float", $samplerSearchFactor, "int", $iterationInit, "int", $featureSetNumFeatures, $sTrackerDllType, $tracker, $sSharedPtrDllType, $sharedPtr), "cveTrackerBoostingCreate", @error)
EndFunc   ;==>_cveTrackerBoostingCreate

Func _cveTrackerBoostingRelease($tracker, $sharedPtr)
    ; CVAPI(void) cveTrackerBoostingRelease(cv::legacy::TrackerBoosting** tracker, cv::Ptr<cv::legacy::TrackerBoosting>** sharedPtr);

    Local $sTrackerDllType
    If IsDllStruct($tracker) Then
        $sTrackerDllType = "struct*"
    ElseIf $tracker == Null Then
        $sTrackerDllType = "ptr"
    Else
        $sTrackerDllType = "ptr*"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveTrackerBoostingRelease", $sTrackerDllType, $tracker, $sSharedPtrDllType, $sharedPtr), "cveTrackerBoostingRelease", @error)
EndFunc   ;==>_cveTrackerBoostingRelease

Func _cveTrackerMedianFlowCreate($pointsInGrid, $winSize, $maxLevel, $termCriteria, $winSizeNCC, $maxMedianLengthOfDisplacementDifference, $tracker, $sharedPtr)
    ; CVAPI(cv::legacy::TrackerMedianFlow*) cveTrackerMedianFlowCreate(int pointsInGrid, CvSize* winSize, int maxLevel, CvTermCriteria* termCriteria, CvSize* winSizeNCC, double maxMedianLengthOfDisplacementDifference, cv::legacy::Tracker** tracker, cv::Ptr<cv::legacy::TrackerMedianFlow>** sharedPtr);

    Local $sWinSizeDllType
    If IsDllStruct($winSize) Then
        $sWinSizeDllType = "struct*"
    Else
        $sWinSizeDllType = "ptr"
    EndIf

    Local $sTermCriteriaDllType
    If IsDllStruct($termCriteria) Then
        $sTermCriteriaDllType = "struct*"
    Else
        $sTermCriteriaDllType = "ptr"
    EndIf

    Local $sWinSizeNCCDllType
    If IsDllStruct($winSizeNCC) Then
        $sWinSizeNCCDllType = "struct*"
    Else
        $sWinSizeNCCDllType = "ptr"
    EndIf

    Local $sTrackerDllType
    If IsDllStruct($tracker) Then
        $sTrackerDllType = "struct*"
    ElseIf $tracker == Null Then
        $sTrackerDllType = "ptr"
    Else
        $sTrackerDllType = "ptr*"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveTrackerMedianFlowCreate", "int", $pointsInGrid, $sWinSizeDllType, $winSize, "int", $maxLevel, $sTermCriteriaDllType, $termCriteria, $sWinSizeNCCDllType, $winSizeNCC, "double", $maxMedianLengthOfDisplacementDifference, $sTrackerDllType, $tracker, $sSharedPtrDllType, $sharedPtr), "cveTrackerMedianFlowCreate", @error)
EndFunc   ;==>_cveTrackerMedianFlowCreate

Func _cveTrackerMedianFlowRelease($tracker, $sharedPtr)
    ; CVAPI(void) cveTrackerMedianFlowRelease(cv::legacy::TrackerMedianFlow** tracker, cv::Ptr<cv::legacy::TrackerMedianFlow>** sharedPtr);

    Local $sTrackerDllType
    If IsDllStruct($tracker) Then
        $sTrackerDllType = "struct*"
    ElseIf $tracker == Null Then
        $sTrackerDllType = "ptr"
    Else
        $sTrackerDllType = "ptr*"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveTrackerMedianFlowRelease", $sTrackerDllType, $tracker, $sSharedPtrDllType, $sharedPtr), "cveTrackerMedianFlowRelease", @error)
EndFunc   ;==>_cveTrackerMedianFlowRelease

Func _cveTrackerTLDCreate($tracker, $sharedPtr)
    ; CVAPI(cv::legacy::TrackerTLD*) cveTrackerTLDCreate(cv::legacy::Tracker** tracker, cv::Ptr<cv::legacy::TrackerTLD>** sharedPtr);

    Local $sTrackerDllType
    If IsDllStruct($tracker) Then
        $sTrackerDllType = "struct*"
    ElseIf $tracker == Null Then
        $sTrackerDllType = "ptr"
    Else
        $sTrackerDllType = "ptr*"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveTrackerTLDCreate", $sTrackerDllType, $tracker, $sSharedPtrDllType, $sharedPtr), "cveTrackerTLDCreate", @error)
EndFunc   ;==>_cveTrackerTLDCreate

Func _cveTrackerTLDRelease($tracker, $sharedPtr)
    ; CVAPI(void) cveTrackerTLDRelease(cv::legacy::TrackerTLD** tracker, cv::Ptr<cv::legacy::TrackerTLD>** sharedPtr);

    Local $sTrackerDllType
    If IsDllStruct($tracker) Then
        $sTrackerDllType = "struct*"
    ElseIf $tracker == Null Then
        $sTrackerDllType = "ptr"
    Else
        $sTrackerDllType = "ptr*"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveTrackerTLDRelease", $sTrackerDllType, $tracker, $sSharedPtrDllType, $sharedPtr), "cveTrackerTLDRelease", @error)
EndFunc   ;==>_cveTrackerTLDRelease

Func _cveTrackerMOSSECreate($tracker, $sharedPtr)
    ; CVAPI(cv::legacy::TrackerMOSSE*) cveTrackerMOSSECreate(cv::legacy::Tracker** tracker, cv::Ptr<cv::legacy::TrackerMOSSE>** sharedPtr);

    Local $sTrackerDllType
    If IsDllStruct($tracker) Then
        $sTrackerDllType = "struct*"
    ElseIf $tracker == Null Then
        $sTrackerDllType = "ptr"
    Else
        $sTrackerDllType = "ptr*"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveTrackerMOSSECreate", $sTrackerDllType, $tracker, $sSharedPtrDllType, $sharedPtr), "cveTrackerMOSSECreate", @error)
EndFunc   ;==>_cveTrackerMOSSECreate

Func _cveTrackerMOSSERelease($tracker, $sharedPtr)
    ; CVAPI(void) cveTrackerMOSSERelease(cv::legacy::TrackerMOSSE** tracker, cv::Ptr<cv::legacy::TrackerMOSSE>** sharedPtr);

    Local $sTrackerDllType
    If IsDllStruct($tracker) Then
        $sTrackerDllType = "struct*"
    ElseIf $tracker == Null Then
        $sTrackerDllType = "ptr"
    Else
        $sTrackerDllType = "ptr*"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveTrackerMOSSERelease", $sTrackerDllType, $tracker, $sSharedPtrDllType, $sharedPtr), "cveTrackerMOSSERelease", @error)
EndFunc   ;==>_cveTrackerMOSSERelease

Func _cveMultiTrackerCreate()
    ; CVAPI(cv::legacy::MultiTracker*) cveMultiTrackerCreate();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveMultiTrackerCreate"), "cveMultiTrackerCreate", @error)
EndFunc   ;==>_cveMultiTrackerCreate

Func _cveMultiTrackerAdd($multiTracker, $tracker, $image, $boundingBox)
    ; CVAPI(bool) cveMultiTrackerAdd(cv::legacy::MultiTracker* multiTracker, cv::legacy::Tracker* tracker, cv::_InputArray* image, CvRect* boundingBox);

    Local $sMultiTrackerDllType
    If IsDllStruct($multiTracker) Then
        $sMultiTrackerDllType = "struct*"
    Else
        $sMultiTrackerDllType = "ptr"
    EndIf

    Local $sTrackerDllType
    If IsDllStruct($tracker) Then
        $sTrackerDllType = "struct*"
    Else
        $sTrackerDllType = "ptr"
    EndIf

    Local $sImageDllType
    If IsDllStruct($image) Then
        $sImageDllType = "struct*"
    Else
        $sImageDllType = "ptr"
    EndIf

    Local $sBoundingBoxDllType
    If IsDllStruct($boundingBox) Then
        $sBoundingBoxDllType = "struct*"
    Else
        $sBoundingBoxDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveMultiTrackerAdd", $sMultiTrackerDllType, $multiTracker, $sTrackerDllType, $tracker, $sImageDllType, $image, $sBoundingBoxDllType, $boundingBox), "cveMultiTrackerAdd", @error)
EndFunc   ;==>_cveMultiTrackerAdd

Func _cveMultiTrackerAddTyped($multiTracker, $tracker, $typeOfImage, $image, $boundingBox)

    Local $iArrImage, $vectorImage, $iArrImageSize
    Local $bImageIsArray = IsArray($image)
    Local $bImageCreate = IsDllStruct($image) And $typeOfImage == "Scalar"

    If $typeOfImage == Default Then
        $iArrImage = $image
    ElseIf $bImageIsArray Then
        $vectorImage = Call("_VectorOf" & $typeOfImage & "Create")

        $iArrImageSize = UBound($image)
        For $i = 0 To $iArrImageSize - 1
            Call("_VectorOf" & $typeOfImage & "Push", $vectorImage, $image[$i])
        Next

        $iArrImage = Call("_cveInputArrayFromVectorOf" & $typeOfImage, $vectorImage)
    Else
        If $bImageCreate Then
            $image = Call("_cve" & $typeOfImage & "Create", $image)
        EndIf
        $iArrImage = Call("_cveInputArrayFrom" & $typeOfImage, $image)
    EndIf

    Local $retval = _cveMultiTrackerAdd($multiTracker, $tracker, $iArrImage, $boundingBox)

    If $bImageIsArray Then
        Call("_VectorOf" & $typeOfImage & "Release", $vectorImage)
    EndIf

    If $typeOfImage <> Default Then
        _cveInputArrayRelease($iArrImage)
        If $bImageCreate Then
            Call("_cve" & $typeOfImage & "Release", $image)
        EndIf
    EndIf

    Return $retval
EndFunc   ;==>_cveMultiTrackerAddTyped

Func _cveMultiTrackerAddMat($multiTracker, $tracker, $image, $boundingBox)
    ; cveMultiTrackerAdd using cv::Mat instead of _*Array
    Local $retval = _cveMultiTrackerAddTyped($multiTracker, $tracker, "Mat", $image, $boundingBox)

    Return $retval
EndFunc   ;==>_cveMultiTrackerAddMat

Func _cveMultiTrackerUpdate($tracker, $image, $boundingBox)
    ; CVAPI(bool) cveMultiTrackerUpdate(cv::legacy::MultiTracker* tracker, cv::Mat* image, std::vector<CvRect>* boundingBox);

    Local $sTrackerDllType
    If IsDllStruct($tracker) Then
        $sTrackerDllType = "struct*"
    Else
        $sTrackerDllType = "ptr"
    EndIf

    Local $sImageDllType
    If IsDllStruct($image) Then
        $sImageDllType = "struct*"
    Else
        $sImageDllType = "ptr"
    EndIf

    Local $sBoundingBoxDllType
    If IsDllStruct($boundingBox) Then
        $sBoundingBoxDllType = "struct*"
    Else
        $sBoundingBoxDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveMultiTrackerUpdate", $sTrackerDllType, $tracker, $sImageDllType, $image, $sBoundingBoxDllType, $boundingBox), "cveMultiTrackerUpdate", @error)
EndFunc   ;==>_cveMultiTrackerUpdate

Func _cveMultiTrackerRelease($tracker)
    ; CVAPI(void) cveMultiTrackerRelease(cv::legacy::MultiTracker** tracker);

    Local $sTrackerDllType
    If IsDllStruct($tracker) Then
        $sTrackerDllType = "struct*"
    ElseIf $tracker == Null Then
        $sTrackerDllType = "ptr"
    Else
        $sTrackerDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMultiTrackerRelease", $sTrackerDllType, $tracker), "cveMultiTrackerRelease", @error)
EndFunc   ;==>_cveMultiTrackerRelease

Func _cveMultiTrackerGetObjects($tracker, $boundingBox)
    ; CVAPI(void) cveMultiTrackerGetObjects(cv::legacy::MultiTracker* tracker, std::vector<CvRect>* boundingBox);

    Local $sTrackerDllType
    If IsDllStruct($tracker) Then
        $sTrackerDllType = "struct*"
    Else
        $sTrackerDllType = "ptr"
    EndIf

    Local $sBoundingBoxDllType
    If IsDllStruct($boundingBox) Then
        $sBoundingBoxDllType = "struct*"
    Else
        $sBoundingBoxDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMultiTrackerGetObjects", $sTrackerDllType, $tracker, $sBoundingBoxDllType, $boundingBox), "cveMultiTrackerGetObjects", @error)
EndFunc   ;==>_cveMultiTrackerGetObjects