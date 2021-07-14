#include-once
#include "..\..\CVEUtils.au3"

Func _cvePlatformInfoName(ByRef $obj, $str)
    ; CVAPI(void) cvePlatformInfoName(cv::ocl::PlatformInfo* obj, cv::String* str);

    Local $bStrIsString = VarGetType($str) == "String"
    If $bStrIsString Then
        $str = _cveStringCreateFromStr($str)
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cvePlatformInfoName", "ptr", $obj, "ptr", $str), "cvePlatformInfoName", @error)

    If $bStrIsString Then
        _cveStringRelease($str)
    EndIf
EndFunc   ;==>_cvePlatformInfoName

Func _cvePlatformInfoVersion(ByRef $obj, $str)
    ; CVAPI(void) cvePlatformInfoVersion(cv::ocl::PlatformInfo* obj, cv::String* str);

    Local $bStrIsString = VarGetType($str) == "String"
    If $bStrIsString Then
        $str = _cveStringCreateFromStr($str)
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cvePlatformInfoVersion", "ptr", $obj, "ptr", $str), "cvePlatformInfoVersion", @error)

    If $bStrIsString Then
        _cveStringRelease($str)
    EndIf
EndFunc   ;==>_cvePlatformInfoVersion

Func _cvePlatformInfoVendor(ByRef $obj, $str)
    ; CVAPI(void) cvePlatformInfoVendor(cv::ocl::PlatformInfo* obj, cv::String* str);

    Local $bStrIsString = VarGetType($str) == "String"
    If $bStrIsString Then
        $str = _cveStringCreateFromStr($str)
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cvePlatformInfoVendor", "ptr", $obj, "ptr", $str), "cvePlatformInfoVendor", @error)

    If $bStrIsString Then
        _cveStringRelease($str)
    EndIf
EndFunc   ;==>_cvePlatformInfoVendor

Func _cvePlatformInfoDeviceNumber(ByRef $obj)
    ; CVAPI(int) cvePlatformInfoDeviceNumber(cv::ocl::PlatformInfo* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cvePlatformInfoDeviceNumber", "ptr", $obj), "cvePlatformInfoDeviceNumber", @error)
EndFunc   ;==>_cvePlatformInfoDeviceNumber