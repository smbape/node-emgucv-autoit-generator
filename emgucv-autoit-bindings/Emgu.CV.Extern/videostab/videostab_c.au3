#include-once
#include <..\..\CVEUtils.au3>

Func _cveVideostabCaptureFrameSourceCreate(ByRef $capture, ByRef $frameSource)
    ; CVAPI(CaptureFrameSource*) cveVideostabCaptureFrameSourceCreate(cv::VideoCapture* capture, cv::videostab::IFrameSource** frameSource);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveVideostabCaptureFrameSourceCreate", "ptr", $capture, "ptr*", $frameSource), "cveVideostabCaptureFrameSourceCreate", @error)
EndFunc   ;==>_cveVideostabCaptureFrameSourceCreate

Func _cveVideostabCaptureFrameSourceRelease(ByRef $captureFrameSource)
    ; CVAPI(void) cveVideostabCaptureFrameSourceRelease(CaptureFrameSource** captureFrameSource);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveVideostabCaptureFrameSourceRelease", "ptr*", $captureFrameSource), "cveVideostabCaptureFrameSourceRelease", @error)
EndFunc   ;==>_cveVideostabCaptureFrameSourceRelease

Func _cveVideostabFrameSourceGetNextFrame(ByRef $frameSource, ByRef $nextFrame)
    ; CVAPI(bool) cveVideostabFrameSourceGetNextFrame(cv::videostab::IFrameSource* frameSource, cv::Mat* nextFrame);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveVideostabFrameSourceGetNextFrame", "ptr", $frameSource, "ptr", $nextFrame), "cveVideostabFrameSourceGetNextFrame", @error)
EndFunc   ;==>_cveVideostabFrameSourceGetNextFrame

Func _cveStabilizerBaseSetMotionEstimator(ByRef $stabilizer, ByRef $motionEstimator)
    ; CVAPI(void) cveStabilizerBaseSetMotionEstimator(cv::videostab::StabilizerBase* stabilizer, cv::videostab::ImageMotionEstimatorBase* motionEstimator);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveStabilizerBaseSetMotionEstimator", "ptr", $stabilizer, "ptr", $motionEstimator), "cveStabilizerBaseSetMotionEstimator", @error)
EndFunc   ;==>_cveStabilizerBaseSetMotionEstimator

Func _cveOnePassStabilizerCreate(ByRef $baseFrameSource, ByRef $stabilizerBase, ByRef $frameSource)
    ; CVAPI(cv::videostab::OnePassStabilizer*) cveOnePassStabilizerCreate(cv::videostab::IFrameSource* baseFrameSource, cv::videostab::StabilizerBase** stabilizerBase, cv::videostab::IFrameSource** frameSource);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveOnePassStabilizerCreate", "ptr", $baseFrameSource, "ptr*", $stabilizerBase, "ptr*", $frameSource), "cveOnePassStabilizerCreate", @error)
EndFunc   ;==>_cveOnePassStabilizerCreate

Func _cveOnePassStabilizerSetMotionFilter(ByRef $stabilizer, ByRef $motionFilter)
    ; CVAPI(void) cveOnePassStabilizerSetMotionFilter(cv::videostab::OnePassStabilizer* stabilizer, cv::videostab::MotionFilterBase* motionFilter);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveOnePassStabilizerSetMotionFilter", "ptr", $stabilizer, "ptr", $motionFilter), "cveOnePassStabilizerSetMotionFilter", @error)
EndFunc   ;==>_cveOnePassStabilizerSetMotionFilter

Func _cveOnePassStabilizerRelease(ByRef $stabilizer)
    ; CVAPI(void) cveOnePassStabilizerRelease(cv::videostab::OnePassStabilizer** stabilizer);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveOnePassStabilizerRelease", "ptr*", $stabilizer), "cveOnePassStabilizerRelease", @error)
EndFunc   ;==>_cveOnePassStabilizerRelease

Func _cveTwoPassStabilizerCreate(ByRef $baseFrameSource, ByRef $stabilizerBase, ByRef $frameSource)
    ; CVAPI(cv::videostab::TwoPassStabilizer*) cveTwoPassStabilizerCreate(cv::videostab::IFrameSource* baseFrameSource, cv::videostab::StabilizerBase** stabilizerBase, cv::videostab::IFrameSource** frameSource);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveTwoPassStabilizerCreate", "ptr", $baseFrameSource, "ptr*", $stabilizerBase, "ptr*", $frameSource), "cveTwoPassStabilizerCreate", @error)
EndFunc   ;==>_cveTwoPassStabilizerCreate

Func _cveTwoPassStabilizerRelease(ByRef $stabilizer)
    ; CVAPI(void) cveTwoPassStabilizerRelease(cv::videostab::TwoPassStabilizer** stabilizer);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveTwoPassStabilizerRelease", "ptr*", $stabilizer), "cveTwoPassStabilizerRelease", @error)
EndFunc   ;==>_cveTwoPassStabilizerRelease

Func _cveGaussianMotionFilterCreate($radius, $stdev)
    ; CVAPI(cv::videostab::GaussianMotionFilter*) cveGaussianMotionFilterCreate(int radius, float stdev);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGaussianMotionFilterCreate", "int", $radius, "float", $stdev), "cveGaussianMotionFilterCreate", @error)
EndFunc   ;==>_cveGaussianMotionFilterCreate

Func _cveGaussianMotionFilterRelease(ByRef $filter)
    ; CVAPI(void) cveGaussianMotionFilterRelease(cv::videostab::GaussianMotionFilter** filter);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveGaussianMotionFilterRelease", "ptr*", $filter), "cveGaussianMotionFilterRelease", @error)
EndFunc   ;==>_cveGaussianMotionFilterRelease

Func _cveCalcBlurriness(ByRef $frame)
    ; CVAPI(float) cveCalcBlurriness(cv::Mat* frame);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cveCalcBlurriness", "ptr", $frame), "cveCalcBlurriness", @error)
EndFunc   ;==>_cveCalcBlurriness