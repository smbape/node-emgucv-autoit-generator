#include-once
#include "..\..\CVEUtils.au3"

Func _cveSURFCreate($hessianThresh, $nOctaves, $nOctaveLayers, $extended, $upright, $feature2D, $sharedPtr)
    ; CVAPI(cv::xfeatures2d::SURF*) cveSURFCreate(double hessianThresh, int nOctaves, int nOctaveLayers, bool extended, bool upright, cv::Feature2D** feature2D, cv::Ptr<cv::xfeatures2d::SURF>** sharedPtr);

    Local $bFeature2DDllType
    If VarGetType($feature2D) == "DLLStruct" Then
        $bFeature2DDllType = "struct*"
    Else
        $bFeature2DDllType = "ptr*"
    EndIf

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveSURFCreate", "double", $hessianThresh, "int", $nOctaves, "int", $nOctaveLayers, "boolean", $extended, "boolean", $upright, $bFeature2DDllType, $feature2D, $bSharedPtrDllType, $sharedPtr), "cveSURFCreate", @error)
EndFunc   ;==>_cveSURFCreate

Func _cveSURFRelease($sharedPtr)
    ; CVAPI(void) cveSURFRelease(cv::Ptr<cv::xfeatures2d::SURF>** sharedPtr);

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSURFRelease", $bSharedPtrDllType, $sharedPtr), "cveSURFRelease", @error)
EndFunc   ;==>_cveSURFRelease