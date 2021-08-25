#include-once
#include "..\..\CVEUtils.au3"

Func _cveQuasiDenseStereoCreate($monoImgSize, $paramFilepath, $sharedPtr)
    ; CVAPI(cv::stereo::QuasiDenseStereo*) cveQuasiDenseStereoCreate(CvSize* monoImgSize, cv::String* paramFilepath, cv::Ptr<cv::stereo::QuasiDenseStereo>** sharedPtr);

    Local $sMonoImgSizeDllType
    If IsDllStruct($monoImgSize) Then
        $sMonoImgSizeDllType = "struct*"
    Else
        $sMonoImgSizeDllType = "ptr"
    EndIf

    Local $bParamFilepathIsString = IsString($paramFilepath)
    If $bParamFilepathIsString Then
        $paramFilepath = _cveStringCreateFromStr($paramFilepath)
    EndIf

    Local $sParamFilepathDllType
    If IsDllStruct($paramFilepath) Then
        $sParamFilepathDllType = "struct*"
    Else
        $sParamFilepathDllType = "ptr"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveQuasiDenseStereoCreate", $sMonoImgSizeDllType, $monoImgSize, $sParamFilepathDllType, $paramFilepath, $sSharedPtrDllType, $sharedPtr), "cveQuasiDenseStereoCreate", @error)

    If $bParamFilepathIsString Then
        _cveStringRelease($paramFilepath)
    EndIf

    Return $retval
EndFunc   ;==>_cveQuasiDenseStereoCreate

Func _cveQuasiDenseStereoRelease($sharedPtr)
    ; CVAPI(void) cveQuasiDenseStereoRelease(cv::Ptr<cv::stereo::QuasiDenseStereo>** sharedPtr);

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveQuasiDenseStereoRelease", $sSharedPtrDllType, $sharedPtr), "cveQuasiDenseStereoRelease", @error)
EndFunc   ;==>_cveQuasiDenseStereoRelease

Func _cveQuasiDenseStereoProcess($stereo, $imgLeft, $imgRight)
    ; CVAPI(void) cveQuasiDenseStereoProcess(cv::stereo::QuasiDenseStereo* stereo, cv::Mat* imgLeft, cv::Mat* imgRight);

    Local $sStereoDllType
    If IsDllStruct($stereo) Then
        $sStereoDllType = "struct*"
    Else
        $sStereoDllType = "ptr"
    EndIf

    Local $sImgLeftDllType
    If IsDllStruct($imgLeft) Then
        $sImgLeftDllType = "struct*"
    Else
        $sImgLeftDllType = "ptr"
    EndIf

    Local $sImgRightDllType
    If IsDllStruct($imgRight) Then
        $sImgRightDllType = "struct*"
    Else
        $sImgRightDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveQuasiDenseStereoProcess", $sStereoDllType, $stereo, $sImgLeftDllType, $imgLeft, $sImgRightDllType, $imgRight), "cveQuasiDenseStereoProcess", @error)
EndFunc   ;==>_cveQuasiDenseStereoProcess

Func _cveQuasiDenseStereoGetDisparity($stereo, $disparity)
    ; CVAPI(void) cveQuasiDenseStereoGetDisparity(cv::stereo::QuasiDenseStereo* stereo, cv::Mat* disparity);

    Local $sStereoDllType
    If IsDllStruct($stereo) Then
        $sStereoDllType = "struct*"
    Else
        $sStereoDllType = "ptr"
    EndIf

    Local $sDisparityDllType
    If IsDllStruct($disparity) Then
        $sDisparityDllType = "struct*"
    Else
        $sDisparityDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveQuasiDenseStereoGetDisparity", $sStereoDllType, $stereo, $sDisparityDllType, $disparity), "cveQuasiDenseStereoGetDisparity", @error)
EndFunc   ;==>_cveQuasiDenseStereoGetDisparity