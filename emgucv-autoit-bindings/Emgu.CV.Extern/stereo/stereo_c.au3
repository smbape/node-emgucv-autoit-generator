#include-once
#include "..\..\CVEUtils.au3"

Func _cveQuasiDenseStereoCreate($monoImgSize, $paramFilepath, $sharedPtr)
    ; CVAPI(cv::stereo::QuasiDenseStereo*) cveQuasiDenseStereoCreate(CvSize* monoImgSize, cv::String* paramFilepath, cv::Ptr<cv::stereo::QuasiDenseStereo>** sharedPtr);

    Local $bParamFilepathIsString = VarGetType($paramFilepath) == "String"
    If $bParamFilepathIsString Then
        $paramFilepath = _cveStringCreateFromStr($paramFilepath)
    EndIf

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveQuasiDenseStereoCreate", "struct*", $monoImgSize, "ptr", $paramFilepath, $bSharedPtrDllType, $sharedPtr), "cveQuasiDenseStereoCreate", @error)

    If $bParamFilepathIsString Then
        _cveStringRelease($paramFilepath)
    EndIf

    Return $retval
EndFunc   ;==>_cveQuasiDenseStereoCreate

Func _cveQuasiDenseStereoRelease($sharedPtr)
    ; CVAPI(void) cveQuasiDenseStereoRelease(cv::Ptr<cv::stereo::QuasiDenseStereo>** sharedPtr);

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveQuasiDenseStereoRelease", $bSharedPtrDllType, $sharedPtr), "cveQuasiDenseStereoRelease", @error)
EndFunc   ;==>_cveQuasiDenseStereoRelease

Func _cveQuasiDenseStereoProcess($stereo, $imgLeft, $imgRight)
    ; CVAPI(void) cveQuasiDenseStereoProcess(cv::stereo::QuasiDenseStereo* stereo, cv::Mat* imgLeft, cv::Mat* imgRight);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveQuasiDenseStereoProcess", "ptr", $stereo, "ptr", $imgLeft, "ptr", $imgRight), "cveQuasiDenseStereoProcess", @error)
EndFunc   ;==>_cveQuasiDenseStereoProcess

Func _cveQuasiDenseStereoGetDisparity($stereo, $disparity)
    ; CVAPI(void) cveQuasiDenseStereoGetDisparity(cv::stereo::QuasiDenseStereo* stereo, cv::Mat* disparity);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveQuasiDenseStereoGetDisparity", "ptr", $stereo, "ptr", $disparity), "cveQuasiDenseStereoGetDisparity", @error)
EndFunc   ;==>_cveQuasiDenseStereoGetDisparity