#include-once
#include "..\..\CVEUtils.au3"

Func _cveQuasiDenseStereoCreate($monoImgSize, $paramFilepath, $sharedPtr)
    ; CVAPI(cv::stereo::QuasiDenseStereo*) cveQuasiDenseStereoCreate(CvSize* monoImgSize, cv::String* paramFilepath, cv::Ptr<cv::stereo::QuasiDenseStereo>** sharedPtr);

    Local $bMonoImgSizeDllType
    If VarGetType($monoImgSize) == "DLLStruct" Then
        $bMonoImgSizeDllType = "struct*"
    Else
        $bMonoImgSizeDllType = "ptr"
    EndIf

    Local $bParamFilepathIsString = VarGetType($paramFilepath) == "String"
    If $bParamFilepathIsString Then
        $paramFilepath = _cveStringCreateFromStr($paramFilepath)
    EndIf

    Local $bParamFilepathDllType
    If VarGetType($paramFilepath) == "DLLStruct" Then
        $bParamFilepathDllType = "struct*"
    Else
        $bParamFilepathDllType = "ptr"
    EndIf

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveQuasiDenseStereoCreate", $bMonoImgSizeDllType, $monoImgSize, $bParamFilepathDllType, $paramFilepath, $bSharedPtrDllType, $sharedPtr), "cveQuasiDenseStereoCreate", @error)

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

    Local $bStereoDllType
    If VarGetType($stereo) == "DLLStruct" Then
        $bStereoDllType = "struct*"
    Else
        $bStereoDllType = "ptr"
    EndIf

    Local $bImgLeftDllType
    If VarGetType($imgLeft) == "DLLStruct" Then
        $bImgLeftDllType = "struct*"
    Else
        $bImgLeftDllType = "ptr"
    EndIf

    Local $bImgRightDllType
    If VarGetType($imgRight) == "DLLStruct" Then
        $bImgRightDllType = "struct*"
    Else
        $bImgRightDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveQuasiDenseStereoProcess", $bStereoDllType, $stereo, $bImgLeftDllType, $imgLeft, $bImgRightDllType, $imgRight), "cveQuasiDenseStereoProcess", @error)
EndFunc   ;==>_cveQuasiDenseStereoProcess

Func _cveQuasiDenseStereoGetDisparity($stereo, $disparity)
    ; CVAPI(void) cveQuasiDenseStereoGetDisparity(cv::stereo::QuasiDenseStereo* stereo, cv::Mat* disparity);

    Local $bStereoDllType
    If VarGetType($stereo) == "DLLStruct" Then
        $bStereoDllType = "struct*"
    Else
        $bStereoDllType = "ptr"
    EndIf

    Local $bDisparityDllType
    If VarGetType($disparity) == "DLLStruct" Then
        $bDisparityDllType = "struct*"
    Else
        $bDisparityDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveQuasiDenseStereoGetDisparity", $bStereoDllType, $stereo, $bDisparityDllType, $disparity), "cveQuasiDenseStereoGetDisparity", @error)
EndFunc   ;==>_cveQuasiDenseStereoGetDisparity