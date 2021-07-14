#include-once
#include <..\..\CVEUtils.au3>

Func _cveDeviceIsNVidia(ByRef $obj)
    ; CVAPI(bool) cveDeviceIsNVidia(cv::ocl::Device* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveDeviceIsNVidia", "ptr", $obj), "cveDeviceIsNVidia", @error)
EndFunc   ;==>_cveDeviceIsNVidia

Func _cveDeviceIsIntel(ByRef $obj)
    ; CVAPI(bool) cveDeviceIsIntel(cv::ocl::Device* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveDeviceIsIntel", "ptr", $obj), "cveDeviceIsIntel", @error)
EndFunc   ;==>_cveDeviceIsIntel

Func _cveDeviceIsAMD(ByRef $obj)
    ; CVAPI(bool) cveDeviceIsAMD(cv::ocl::Device* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveDeviceIsAMD", "ptr", $obj), "cveDeviceIsAMD", @error)
EndFunc   ;==>_cveDeviceIsAMD

Func _cveDeviceAddressBits(ByRef $obj)
    ; CVAPI(int) cveDeviceAddressBits(cv::ocl::Device* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveDeviceAddressBits", "ptr", $obj), "cveDeviceAddressBits", @error)
EndFunc   ;==>_cveDeviceAddressBits

Func _cveDeviceLinkerAvailable(ByRef $obj)
    ; CVAPI(bool) cveDeviceLinkerAvailable(cv::ocl::Device* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveDeviceLinkerAvailable", "ptr", $obj), "cveDeviceLinkerAvailable", @error)
EndFunc   ;==>_cveDeviceLinkerAvailable

Func _cveDeviceCompilerAvailable(ByRef $obj)
    ; CVAPI(bool) cveDeviceCompilerAvailable(cv::ocl::Device* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveDeviceCompilerAvailable", "ptr", $obj), "cveDeviceCompilerAvailable", @error)
EndFunc   ;==>_cveDeviceCompilerAvailable

Func _cveDeviceAvailable(ByRef $obj)
    ; CVAPI(bool) cveDeviceAvailable(cv::ocl::Device* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveDeviceAvailable", "ptr", $obj), "cveDeviceAvailable", @error)
EndFunc   ;==>_cveDeviceAvailable

Func _cveDeviceMaxWorkGroupSize(ByRef $obj)
    ; CVAPI(int) cveDeviceMaxWorkGroupSize(cv::ocl::Device* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveDeviceMaxWorkGroupSize", "ptr", $obj), "cveDeviceMaxWorkGroupSize", @error)
EndFunc   ;==>_cveDeviceMaxWorkGroupSize

Func _cveDeviceMaxComputeUnits(ByRef $obj)
    ; CVAPI(int) cveDeviceMaxComputeUnits(cv::ocl::Device* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveDeviceMaxComputeUnits", "ptr", $obj), "cveDeviceMaxComputeUnits", @error)
EndFunc   ;==>_cveDeviceMaxComputeUnits

Func _cveDeviceLocalMemSize(ByRef $obj)
    ; CVAPI(int) cveDeviceLocalMemSize(cv::ocl::Device* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveDeviceLocalMemSize", "ptr", $obj), "cveDeviceLocalMemSize", @error)
EndFunc   ;==>_cveDeviceLocalMemSize

Func _cveDeviceMaxMemAllocSize(ByRef $obj)
    ; CVAPI(int) cveDeviceMaxMemAllocSize(cv::ocl::Device* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveDeviceMaxMemAllocSize", "ptr", $obj), "cveDeviceMaxMemAllocSize", @error)
EndFunc   ;==>_cveDeviceMaxMemAllocSize

Func _cveDeviceDeviceVersionMajor(ByRef $obj)
    ; CVAPI(int) cveDeviceDeviceVersionMajor(cv::ocl::Device* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveDeviceDeviceVersionMajor", "ptr", $obj), "cveDeviceDeviceVersionMajor", @error)
EndFunc   ;==>_cveDeviceDeviceVersionMajor

Func _cveDeviceDeviceVersionMinor(ByRef $obj)
    ; CVAPI(int) cveDeviceDeviceVersionMinor(cv::ocl::Device* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveDeviceDeviceVersionMinor", "ptr", $obj), "cveDeviceDeviceVersionMinor", @error)
EndFunc   ;==>_cveDeviceDeviceVersionMinor

Func _cveDeviceHalfFPConfig(ByRef $obj)
    ; CVAPI(int) cveDeviceHalfFPConfig(cv::ocl::Device* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveDeviceHalfFPConfig", "ptr", $obj), "cveDeviceHalfFPConfig", @error)
EndFunc   ;==>_cveDeviceHalfFPConfig

Func _cveDeviceSingleFPConfig(ByRef $obj)
    ; CVAPI(int) cveDeviceSingleFPConfig(cv::ocl::Device* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveDeviceSingleFPConfig", "ptr", $obj), "cveDeviceSingleFPConfig", @error)
EndFunc   ;==>_cveDeviceSingleFPConfig

Func _cveDeviceDoubleFPConfig(ByRef $obj)
    ; CVAPI(int) cveDeviceDoubleFPConfig(cv::ocl::Device* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveDeviceDoubleFPConfig", "ptr", $obj), "cveDeviceDoubleFPConfig", @error)
EndFunc   ;==>_cveDeviceDoubleFPConfig

Func _cveDeviceHostUnifiedMemory(ByRef $obj)
    ; CVAPI(bool) cveDeviceHostUnifiedMemory(cv::ocl::Device* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveDeviceHostUnifiedMemory", "ptr", $obj), "cveDeviceHostUnifiedMemory", @error)
EndFunc   ;==>_cveDeviceHostUnifiedMemory

Func _cveDeviceGlobalMemSize(ByRef $obj)
    ; CVAPI(size_t) cveDeviceGlobalMemSize(cv::ocl::Device* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ulong_ptr:cdecl", "cveDeviceGlobalMemSize", "ptr", $obj), "cveDeviceGlobalMemSize", @error)
EndFunc   ;==>_cveDeviceGlobalMemSize

Func _cveDeviceImage2DMaxWidth(ByRef $obj)
    ; CVAPI(int) cveDeviceImage2DMaxWidth(cv::ocl::Device* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveDeviceImage2DMaxWidth", "ptr", $obj), "cveDeviceImage2DMaxWidth", @error)
EndFunc   ;==>_cveDeviceImage2DMaxWidth

Func _cveDeviceImage2DMaxHeight(ByRef $obj)
    ; CVAPI(int) cveDeviceImage2DMaxHeight(cv::ocl::Device* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveDeviceImage2DMaxHeight", "ptr", $obj), "cveDeviceImage2DMaxHeight", @error)
EndFunc   ;==>_cveDeviceImage2DMaxHeight

Func _cveDeviceType(ByRef $obj)
    ; CVAPI(int) cveDeviceType(cv::ocl::Device* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveDeviceType", "ptr", $obj), "cveDeviceType", @error)
EndFunc   ;==>_cveDeviceType

Func _cveDeviceName(ByRef $obj, $str)
    ; CVAPI(void) cveDeviceName(cv::ocl::Device* obj, cv::String* str);

    Local $bStrIsString = VarGetType($str) == "String"
    If $bStrIsString Then
        $str = _cveStringCreateFromStr($str)
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDeviceName", "ptr", $obj, "ptr", $str), "cveDeviceName", @error)

    If $bStrIsString Then
        _cveStringRelease($str)
    EndIf
EndFunc   ;==>_cveDeviceName

Func _cveDeviceVersion(ByRef $obj, $str)
    ; CVAPI(void) cveDeviceVersion(cv::ocl::Device* obj, cv::String* str);

    Local $bStrIsString = VarGetType($str) == "String"
    If $bStrIsString Then
        $str = _cveStringCreateFromStr($str)
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDeviceVersion", "ptr", $obj, "ptr", $str), "cveDeviceVersion", @error)

    If $bStrIsString Then
        _cveStringRelease($str)
    EndIf
EndFunc   ;==>_cveDeviceVersion

Func _cveDeviceVendorName(ByRef $obj, $str)
    ; CVAPI(void) cveDeviceVendorName(cv::ocl::Device* obj, cv::String* str);

    Local $bStrIsString = VarGetType($str) == "String"
    If $bStrIsString Then
        $str = _cveStringCreateFromStr($str)
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDeviceVendorName", "ptr", $obj, "ptr", $str), "cveDeviceVendorName", @error)

    If $bStrIsString Then
        _cveStringRelease($str)
    EndIf
EndFunc   ;==>_cveDeviceVendorName

Func _cveDeviceDriverVersion(ByRef $obj, $str)
    ; CVAPI(void) cveDeviceDriverVersion(cv::ocl::Device* obj, cv::String* str);

    Local $bStrIsString = VarGetType($str) == "String"
    If $bStrIsString Then
        $str = _cveStringCreateFromStr($str)
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDeviceDriverVersion", "ptr", $obj, "ptr", $str), "cveDeviceDriverVersion", @error)

    If $bStrIsString Then
        _cveStringRelease($str)
    EndIf
EndFunc   ;==>_cveDeviceDriverVersion

Func _cveDeviceExtensions(ByRef $obj, $str)
    ; CVAPI(void) cveDeviceExtensions(cv::ocl::Device* obj, cv::String* str);

    Local $bStrIsString = VarGetType($str) == "String"
    If $bStrIsString Then
        $str = _cveStringCreateFromStr($str)
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDeviceExtensions", "ptr", $obj, "ptr", $str), "cveDeviceExtensions", @error)

    If $bStrIsString Then
        _cveStringRelease($str)
    EndIf
EndFunc   ;==>_cveDeviceExtensions

Func _cveDeviceOpenCLVersion(ByRef $obj, $str)
    ; CVAPI(void) cveDeviceOpenCLVersion(cv::ocl::Device* obj, cv::String* str);

    Local $bStrIsString = VarGetType($str) == "String"
    If $bStrIsString Then
        $str = _cveStringCreateFromStr($str)
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDeviceOpenCLVersion", "ptr", $obj, "ptr", $str), "cveDeviceOpenCLVersion", @error)

    If $bStrIsString Then
        _cveStringRelease($str)
    EndIf
EndFunc   ;==>_cveDeviceOpenCLVersion

Func _cveDeviceOpenCLCVersion(ByRef $obj, $str)
    ; CVAPI(void) cveDeviceOpenCLCVersion(cv::ocl::Device* obj, cv::String* str);

    Local $bStrIsString = VarGetType($str) == "String"
    If $bStrIsString Then
        $str = _cveStringCreateFromStr($str)
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDeviceOpenCLCVersion", "ptr", $obj, "ptr", $str), "cveDeviceOpenCLCVersion", @error)

    If $bStrIsString Then
        _cveStringRelease($str)
    EndIf
EndFunc   ;==>_cveDeviceOpenCLCVersion