#include-once
#include "..\..\CVEUtils.au3"

Func _cveVideostabCaptureFrameSourceCreate($capture, $frameSource)
    ; CVAPI(CaptureFrameSource*) cveVideostabCaptureFrameSourceCreate(cv::VideoCapture* capture, cv::videostab::IFrameSource** frameSource);

    Local $bCaptureDllType
    If VarGetType($capture) == "DLLStruct" Then
        $bCaptureDllType = "struct*"
    Else
        $bCaptureDllType = "ptr"
    EndIf

    Local $bFrameSourceDllType
    If VarGetType($frameSource) == "DLLStruct" Then
        $bFrameSourceDllType = "struct*"
    Else
        $bFrameSourceDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveVideostabCaptureFrameSourceCreate", $bCaptureDllType, $capture, $bFrameSourceDllType, $frameSource), "cveVideostabCaptureFrameSourceCreate", @error)
EndFunc   ;==>_cveVideostabCaptureFrameSourceCreate

Func _cveVideostabCaptureFrameSourceRelease($captureFrameSource)
    ; CVAPI(void) cveVideostabCaptureFrameSourceRelease(CaptureFrameSource** captureFrameSource);

    Local $bCaptureFrameSourceDllType
    If VarGetType($captureFrameSource) == "DLLStruct" Then
        $bCaptureFrameSourceDllType = "struct*"
    Else
        $bCaptureFrameSourceDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveVideostabCaptureFrameSourceRelease", $bCaptureFrameSourceDllType, $captureFrameSource), "cveVideostabCaptureFrameSourceRelease", @error)
EndFunc   ;==>_cveVideostabCaptureFrameSourceRelease

Func _cveVideostabFrameSourceGetNextFrame($frameSource, $nextFrame)
    ; CVAPI(bool) cveVideostabFrameSourceGetNextFrame(cv::videostab::IFrameSource* frameSource, cv::Mat* nextFrame);

    Local $bFrameSourceDllType
    If VarGetType($frameSource) == "DLLStruct" Then
        $bFrameSourceDllType = "struct*"
    Else
        $bFrameSourceDllType = "ptr"
    EndIf

    Local $bNextFrameDllType
    If VarGetType($nextFrame) == "DLLStruct" Then
        $bNextFrameDllType = "struct*"
    Else
        $bNextFrameDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveVideostabFrameSourceGetNextFrame", $bFrameSourceDllType, $frameSource, $bNextFrameDllType, $nextFrame), "cveVideostabFrameSourceGetNextFrame", @error)
EndFunc   ;==>_cveVideostabFrameSourceGetNextFrame

Func _cveStabilizerBaseSetMotionEstimator($stabilizer, $motionEstimator)
    ; CVAPI(void) cveStabilizerBaseSetMotionEstimator(cv::videostab::StabilizerBase* stabilizer, cv::videostab::ImageMotionEstimatorBase* motionEstimator);

    Local $bStabilizerDllType
    If VarGetType($stabilizer) == "DLLStruct" Then
        $bStabilizerDllType = "struct*"
    Else
        $bStabilizerDllType = "ptr"
    EndIf

    Local $bMotionEstimatorDllType
    If VarGetType($motionEstimator) == "DLLStruct" Then
        $bMotionEstimatorDllType = "struct*"
    Else
        $bMotionEstimatorDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveStabilizerBaseSetMotionEstimator", $bStabilizerDllType, $stabilizer, $bMotionEstimatorDllType, $motionEstimator), "cveStabilizerBaseSetMotionEstimator", @error)
EndFunc   ;==>_cveStabilizerBaseSetMotionEstimator

Func _cveOnePassStabilizerCreate($baseFrameSource, $stabilizerBase, $frameSource)
    ; CVAPI(cv::videostab::OnePassStabilizer*) cveOnePassStabilizerCreate(cv::videostab::IFrameSource* baseFrameSource, cv::videostab::StabilizerBase** stabilizerBase, cv::videostab::IFrameSource** frameSource);

    Local $bBaseFrameSourceDllType
    If VarGetType($baseFrameSource) == "DLLStruct" Then
        $bBaseFrameSourceDllType = "struct*"
    Else
        $bBaseFrameSourceDllType = "ptr"
    EndIf

    Local $bStabilizerBaseDllType
    If VarGetType($stabilizerBase) == "DLLStruct" Then
        $bStabilizerBaseDllType = "struct*"
    Else
        $bStabilizerBaseDllType = "ptr*"
    EndIf

    Local $bFrameSourceDllType
    If VarGetType($frameSource) == "DLLStruct" Then
        $bFrameSourceDllType = "struct*"
    Else
        $bFrameSourceDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveOnePassStabilizerCreate", $bBaseFrameSourceDllType, $baseFrameSource, $bStabilizerBaseDllType, $stabilizerBase, $bFrameSourceDllType, $frameSource), "cveOnePassStabilizerCreate", @error)
EndFunc   ;==>_cveOnePassStabilizerCreate

Func _cveOnePassStabilizerSetMotionFilter($stabilizer, $motionFilter)
    ; CVAPI(void) cveOnePassStabilizerSetMotionFilter(cv::videostab::OnePassStabilizer* stabilizer, cv::videostab::MotionFilterBase* motionFilter);

    Local $bStabilizerDllType
    If VarGetType($stabilizer) == "DLLStruct" Then
        $bStabilizerDllType = "struct*"
    Else
        $bStabilizerDllType = "ptr"
    EndIf

    Local $bMotionFilterDllType
    If VarGetType($motionFilter) == "DLLStruct" Then
        $bMotionFilterDllType = "struct*"
    Else
        $bMotionFilterDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveOnePassStabilizerSetMotionFilter", $bStabilizerDllType, $stabilizer, $bMotionFilterDllType, $motionFilter), "cveOnePassStabilizerSetMotionFilter", @error)
EndFunc   ;==>_cveOnePassStabilizerSetMotionFilter

Func _cveOnePassStabilizerRelease($stabilizer)
    ; CVAPI(void) cveOnePassStabilizerRelease(cv::videostab::OnePassStabilizer** stabilizer);

    Local $bStabilizerDllType
    If VarGetType($stabilizer) == "DLLStruct" Then
        $bStabilizerDllType = "struct*"
    Else
        $bStabilizerDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveOnePassStabilizerRelease", $bStabilizerDllType, $stabilizer), "cveOnePassStabilizerRelease", @error)
EndFunc   ;==>_cveOnePassStabilizerRelease

Func _cveTwoPassStabilizerCreate($baseFrameSource, $stabilizerBase, $frameSource)
    ; CVAPI(cv::videostab::TwoPassStabilizer*) cveTwoPassStabilizerCreate(cv::videostab::IFrameSource* baseFrameSource, cv::videostab::StabilizerBase** stabilizerBase, cv::videostab::IFrameSource** frameSource);

    Local $bBaseFrameSourceDllType
    If VarGetType($baseFrameSource) == "DLLStruct" Then
        $bBaseFrameSourceDllType = "struct*"
    Else
        $bBaseFrameSourceDllType = "ptr"
    EndIf

    Local $bStabilizerBaseDllType
    If VarGetType($stabilizerBase) == "DLLStruct" Then
        $bStabilizerBaseDllType = "struct*"
    Else
        $bStabilizerBaseDllType = "ptr*"
    EndIf

    Local $bFrameSourceDllType
    If VarGetType($frameSource) == "DLLStruct" Then
        $bFrameSourceDllType = "struct*"
    Else
        $bFrameSourceDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveTwoPassStabilizerCreate", $bBaseFrameSourceDllType, $baseFrameSource, $bStabilizerBaseDllType, $stabilizerBase, $bFrameSourceDllType, $frameSource), "cveTwoPassStabilizerCreate", @error)
EndFunc   ;==>_cveTwoPassStabilizerCreate

Func _cveTwoPassStabilizerRelease($stabilizer)
    ; CVAPI(void) cveTwoPassStabilizerRelease(cv::videostab::TwoPassStabilizer** stabilizer);

    Local $bStabilizerDllType
    If VarGetType($stabilizer) == "DLLStruct" Then
        $bStabilizerDllType = "struct*"
    Else
        $bStabilizerDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveTwoPassStabilizerRelease", $bStabilizerDllType, $stabilizer), "cveTwoPassStabilizerRelease", @error)
EndFunc   ;==>_cveTwoPassStabilizerRelease

Func _cveGaussianMotionFilterCreate($radius, $stdev)
    ; CVAPI(cv::videostab::GaussianMotionFilter*) cveGaussianMotionFilterCreate(int radius, float stdev);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveGaussianMotionFilterCreate", "int", $radius, "float", $stdev), "cveGaussianMotionFilterCreate", @error)
EndFunc   ;==>_cveGaussianMotionFilterCreate

Func _cveGaussianMotionFilterRelease($filter)
    ; CVAPI(void) cveGaussianMotionFilterRelease(cv::videostab::GaussianMotionFilter** filter);

    Local $bFilterDllType
    If VarGetType($filter) == "DLLStruct" Then
        $bFilterDllType = "struct*"
    Else
        $bFilterDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveGaussianMotionFilterRelease", $bFilterDllType, $filter), "cveGaussianMotionFilterRelease", @error)
EndFunc   ;==>_cveGaussianMotionFilterRelease

Func _cveCalcBlurriness($frame)
    ; CVAPI(float) cveCalcBlurriness(cv::Mat* frame);

    Local $bFrameDllType
    If VarGetType($frame) == "DLLStruct" Then
        $bFrameDllType = "struct*"
    Else
        $bFrameDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cveCalcBlurriness", $bFrameDllType, $frame), "cveCalcBlurriness", @error)
EndFunc   ;==>_cveCalcBlurriness