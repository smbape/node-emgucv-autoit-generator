#include-once
#include "..\..\CVEUtils.au3"

Func _cveVideostabCaptureFrameSourceCreate($capture, $frameSource)
    ; CVAPI(CaptureFrameSource*) cveVideostabCaptureFrameSourceCreate(cv::VideoCapture* capture, cv::videostab::IFrameSource** frameSource);

    Local $sCaptureDllType
    If IsDllStruct($capture) Then
        $sCaptureDllType = "struct*"
    Else
        $sCaptureDllType = "ptr"
    EndIf

    Local $sFrameSourceDllType
    If IsDllStruct($frameSource) Then
        $sFrameSourceDllType = "struct*"
    ElseIf $frameSource == Null Then
        $sFrameSourceDllType = "ptr"
    Else
        $sFrameSourceDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveVideostabCaptureFrameSourceCreate", $sCaptureDllType, $capture, $sFrameSourceDllType, $frameSource), "cveVideostabCaptureFrameSourceCreate", @error)
EndFunc   ;==>_cveVideostabCaptureFrameSourceCreate

Func _cveVideostabCaptureFrameSourceRelease($captureFrameSource)
    ; CVAPI(void) cveVideostabCaptureFrameSourceRelease(CaptureFrameSource** captureFrameSource);

    Local $sCaptureFrameSourceDllType
    If IsDllStruct($captureFrameSource) Then
        $sCaptureFrameSourceDllType = "struct*"
    ElseIf $captureFrameSource == Null Then
        $sCaptureFrameSourceDllType = "ptr"
    Else
        $sCaptureFrameSourceDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveVideostabCaptureFrameSourceRelease", $sCaptureFrameSourceDllType, $captureFrameSource), "cveVideostabCaptureFrameSourceRelease", @error)
EndFunc   ;==>_cveVideostabCaptureFrameSourceRelease

Func _cveVideostabFrameSourceGetNextFrame($frameSource, $nextFrame)
    ; CVAPI(bool) cveVideostabFrameSourceGetNextFrame(cv::videostab::IFrameSource* frameSource, cv::Mat* nextFrame);

    Local $sFrameSourceDllType
    If IsDllStruct($frameSource) Then
        $sFrameSourceDllType = "struct*"
    Else
        $sFrameSourceDllType = "ptr"
    EndIf

    Local $sNextFrameDllType
    If IsDllStruct($nextFrame) Then
        $sNextFrameDllType = "struct*"
    Else
        $sNextFrameDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveVideostabFrameSourceGetNextFrame", $sFrameSourceDllType, $frameSource, $sNextFrameDllType, $nextFrame), "cveVideostabFrameSourceGetNextFrame", @error)
EndFunc   ;==>_cveVideostabFrameSourceGetNextFrame

Func _cveStabilizerBaseSetMotionEstimator($stabilizer, $motionEstimator)
    ; CVAPI(void) cveStabilizerBaseSetMotionEstimator(cv::videostab::StabilizerBase* stabilizer, cv::videostab::ImageMotionEstimatorBase* motionEstimator);

    Local $sStabilizerDllType
    If IsDllStruct($stabilizer) Then
        $sStabilizerDllType = "struct*"
    Else
        $sStabilizerDllType = "ptr"
    EndIf

    Local $sMotionEstimatorDllType
    If IsDllStruct($motionEstimator) Then
        $sMotionEstimatorDllType = "struct*"
    Else
        $sMotionEstimatorDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveStabilizerBaseSetMotionEstimator", $sStabilizerDllType, $stabilizer, $sMotionEstimatorDllType, $motionEstimator), "cveStabilizerBaseSetMotionEstimator", @error)
EndFunc   ;==>_cveStabilizerBaseSetMotionEstimator

Func _cveOnePassStabilizerCreate($baseFrameSource, $stabilizerBase, $frameSource)
    ; CVAPI(cv::videostab::OnePassStabilizer*) cveOnePassStabilizerCreate(cv::videostab::IFrameSource* baseFrameSource, cv::videostab::StabilizerBase** stabilizerBase, cv::videostab::IFrameSource** frameSource);

    Local $sBaseFrameSourceDllType
    If IsDllStruct($baseFrameSource) Then
        $sBaseFrameSourceDllType = "struct*"
    Else
        $sBaseFrameSourceDllType = "ptr"
    EndIf

    Local $sStabilizerBaseDllType
    If IsDllStruct($stabilizerBase) Then
        $sStabilizerBaseDllType = "struct*"
    ElseIf $stabilizerBase == Null Then
        $sStabilizerBaseDllType = "ptr"
    Else
        $sStabilizerBaseDllType = "ptr*"
    EndIf

    Local $sFrameSourceDllType
    If IsDllStruct($frameSource) Then
        $sFrameSourceDllType = "struct*"
    ElseIf $frameSource == Null Then
        $sFrameSourceDllType = "ptr"
    Else
        $sFrameSourceDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveOnePassStabilizerCreate", $sBaseFrameSourceDllType, $baseFrameSource, $sStabilizerBaseDllType, $stabilizerBase, $sFrameSourceDllType, $frameSource), "cveOnePassStabilizerCreate", @error)
EndFunc   ;==>_cveOnePassStabilizerCreate

Func _cveOnePassStabilizerSetMotionFilter($stabilizer, $motionFilter)
    ; CVAPI(void) cveOnePassStabilizerSetMotionFilter(cv::videostab::OnePassStabilizer* stabilizer, cv::videostab::MotionFilterBase* motionFilter);

    Local $sStabilizerDllType
    If IsDllStruct($stabilizer) Then
        $sStabilizerDllType = "struct*"
    Else
        $sStabilizerDllType = "ptr"
    EndIf

    Local $sMotionFilterDllType
    If IsDllStruct($motionFilter) Then
        $sMotionFilterDllType = "struct*"
    Else
        $sMotionFilterDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveOnePassStabilizerSetMotionFilter", $sStabilizerDllType, $stabilizer, $sMotionFilterDllType, $motionFilter), "cveOnePassStabilizerSetMotionFilter", @error)
EndFunc   ;==>_cveOnePassStabilizerSetMotionFilter

Func _cveOnePassStabilizerRelease($stabilizer)
    ; CVAPI(void) cveOnePassStabilizerRelease(cv::videostab::OnePassStabilizer** stabilizer);

    Local $sStabilizerDllType
    If IsDllStruct($stabilizer) Then
        $sStabilizerDllType = "struct*"
    ElseIf $stabilizer == Null Then
        $sStabilizerDllType = "ptr"
    Else
        $sStabilizerDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveOnePassStabilizerRelease", $sStabilizerDllType, $stabilizer), "cveOnePassStabilizerRelease", @error)
EndFunc   ;==>_cveOnePassStabilizerRelease

Func _cveTwoPassStabilizerCreate($baseFrameSource, $stabilizerBase, $frameSource)
    ; CVAPI(cv::videostab::TwoPassStabilizer*) cveTwoPassStabilizerCreate(cv::videostab::IFrameSource* baseFrameSource, cv::videostab::StabilizerBase** stabilizerBase, cv::videostab::IFrameSource** frameSource);

    Local $sBaseFrameSourceDllType
    If IsDllStruct($baseFrameSource) Then
        $sBaseFrameSourceDllType = "struct*"
    Else
        $sBaseFrameSourceDllType = "ptr"
    EndIf

    Local $sStabilizerBaseDllType
    If IsDllStruct($stabilizerBase) Then
        $sStabilizerBaseDllType = "struct*"
    ElseIf $stabilizerBase == Null Then
        $sStabilizerBaseDllType = "ptr"
    Else
        $sStabilizerBaseDllType = "ptr*"
    EndIf

    Local $sFrameSourceDllType
    If IsDllStruct($frameSource) Then
        $sFrameSourceDllType = "struct*"
    ElseIf $frameSource == Null Then
        $sFrameSourceDllType = "ptr"
    Else
        $sFrameSourceDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveTwoPassStabilizerCreate", $sBaseFrameSourceDllType, $baseFrameSource, $sStabilizerBaseDllType, $stabilizerBase, $sFrameSourceDllType, $frameSource), "cveTwoPassStabilizerCreate", @error)
EndFunc   ;==>_cveTwoPassStabilizerCreate

Func _cveTwoPassStabilizerRelease($stabilizer)
    ; CVAPI(void) cveTwoPassStabilizerRelease(cv::videostab::TwoPassStabilizer** stabilizer);

    Local $sStabilizerDllType
    If IsDllStruct($stabilizer) Then
        $sStabilizerDllType = "struct*"
    ElseIf $stabilizer == Null Then
        $sStabilizerDllType = "ptr"
    Else
        $sStabilizerDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveTwoPassStabilizerRelease", $sStabilizerDllType, $stabilizer), "cveTwoPassStabilizerRelease", @error)
EndFunc   ;==>_cveTwoPassStabilizerRelease

Func _cveGaussianMotionFilterCreate($radius, $stdev)
    ; CVAPI(cv::videostab::GaussianMotionFilter*) cveGaussianMotionFilterCreate(int radius, float stdev);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGaussianMotionFilterCreate", "int", $radius, "float", $stdev), "cveGaussianMotionFilterCreate", @error)
EndFunc   ;==>_cveGaussianMotionFilterCreate

Func _cveGaussianMotionFilterRelease($filter)
    ; CVAPI(void) cveGaussianMotionFilterRelease(cv::videostab::GaussianMotionFilter** filter);

    Local $sFilterDllType
    If IsDllStruct($filter) Then
        $sFilterDllType = "struct*"
    ElseIf $filter == Null Then
        $sFilterDllType = "ptr"
    Else
        $sFilterDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveGaussianMotionFilterRelease", $sFilterDllType, $filter), "cveGaussianMotionFilterRelease", @error)
EndFunc   ;==>_cveGaussianMotionFilterRelease

Func _cveCalcBlurriness($frame)
    ; CVAPI(float) cveCalcBlurriness(cv::Mat* frame);

    Local $sFrameDllType
    If IsDllStruct($frame) Then
        $sFrameDllType = "struct*"
    Else
        $sFrameDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cveCalcBlurriness", $sFrameDllType, $frame), "cveCalcBlurriness", @error)
EndFunc   ;==>_cveCalcBlurriness