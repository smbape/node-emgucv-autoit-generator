#include-once
#include "..\..\CVEUtils.au3"

Func _cveSURFCreate($hessianThresh, $nOctaves, $nOctaveLayers, $extended, $upright, $feature2D, $sharedPtr)
    ; CVAPI(cv::xfeatures2d::SURF*) cveSURFCreate(double hessianThresh, int nOctaves, int nOctaveLayers, bool extended, bool upright, cv::Feature2D** feature2D, cv::Ptr<cv::xfeatures2d::SURF>** sharedPtr);

    Local $sFeature2DDllType
    If IsDllStruct($feature2D) Then
        $sFeature2DDllType = "struct*"
    ElseIf $feature2D == Null Then
        $sFeature2DDllType = "ptr"
    Else
        $sFeature2DDllType = "ptr*"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveSURFCreate", "double", $hessianThresh, "int", $nOctaves, "int", $nOctaveLayers, "boolean", $extended, "boolean", $upright, $sFeature2DDllType, $feature2D, $sSharedPtrDllType, $sharedPtr), "cveSURFCreate", @error)
EndFunc   ;==>_cveSURFCreate

Func _cveSURFRelease($sharedPtr)
    ; CVAPI(void) cveSURFRelease(cv::Ptr<cv::xfeatures2d::SURF>** sharedPtr);

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSURFRelease", $sSharedPtrDllType, $sharedPtr), "cveSURFRelease", @error)
EndFunc   ;==>_cveSURFRelease