#include-once
#include "..\..\CVEUtils.au3"

Func _cveSURFCreate($hessianThresh, $nOctaves, $nOctaveLayers, $extended, $upright, ByRef $feature2D, ByRef $sharedPtr)
    ; CVAPI(cv::xfeatures2d::SURF*) cveSURFCreate(double hessianThresh, int nOctaves, int nOctaveLayers, bool extended, bool upright, cv::Feature2D** feature2D, cv::Ptr<cv::xfeatures2d::SURF>** sharedPtr);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveSURFCreate", "double", $hessianThresh, "int", $nOctaves, "int", $nOctaveLayers, "boolean", $extended, "boolean", $upright, "ptr*", $feature2D, "ptr*", $sharedPtr), "cveSURFCreate", @error)
EndFunc   ;==>_cveSURFCreate

Func _cveSURFRelease(ByRef $sharedPtr)
    ; CVAPI(void) cveSURFRelease(cv::Ptr<cv::xfeatures2d::SURF>** sharedPtr);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSURFRelease", "ptr*", $sharedPtr), "cveSURFRelease", @error)
EndFunc   ;==>_cveSURFRelease