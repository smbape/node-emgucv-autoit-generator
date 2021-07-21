#include-once
#include "..\..\CVEUtils.au3"

Func _cveDeviceIsNVidia($obj)
    ; CVAPI(bool) cveDeviceIsNVidia(cv::ocl::Device* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveDeviceIsNVidia", $bObjDllType, $obj), "cveDeviceIsNVidia", @error)
EndFunc   ;==>_cveDeviceIsNVidia

Func _cveDeviceIsIntel($obj)
    ; CVAPI(bool) cveDeviceIsIntel(cv::ocl::Device* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveDeviceIsIntel", $bObjDllType, $obj), "cveDeviceIsIntel", @error)
EndFunc   ;==>_cveDeviceIsIntel

Func _cveDeviceIsAMD($obj)
    ; CVAPI(bool) cveDeviceIsAMD(cv::ocl::Device* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveDeviceIsAMD", $bObjDllType, $obj), "cveDeviceIsAMD", @error)
EndFunc   ;==>_cveDeviceIsAMD

Func _cveDeviceAddressBits($obj)
    ; CVAPI(int) cveDeviceAddressBits(cv::ocl::Device* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveDeviceAddressBits", $bObjDllType, $obj), "cveDeviceAddressBits", @error)
EndFunc   ;==>_cveDeviceAddressBits

Func _cveDeviceLinkerAvailable($obj)
    ; CVAPI(bool) cveDeviceLinkerAvailable(cv::ocl::Device* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveDeviceLinkerAvailable", $bObjDllType, $obj), "cveDeviceLinkerAvailable", @error)
EndFunc   ;==>_cveDeviceLinkerAvailable

Func _cveDeviceCompilerAvailable($obj)
    ; CVAPI(bool) cveDeviceCompilerAvailable(cv::ocl::Device* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveDeviceCompilerAvailable", $bObjDllType, $obj), "cveDeviceCompilerAvailable", @error)
EndFunc   ;==>_cveDeviceCompilerAvailable

Func _cveDeviceAvailable($obj)
    ; CVAPI(bool) cveDeviceAvailable(cv::ocl::Device* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveDeviceAvailable", $bObjDllType, $obj), "cveDeviceAvailable", @error)
EndFunc   ;==>_cveDeviceAvailable

Func _cveDeviceMaxWorkGroupSize($obj)
    ; CVAPI(int) cveDeviceMaxWorkGroupSize(cv::ocl::Device* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveDeviceMaxWorkGroupSize", $bObjDllType, $obj), "cveDeviceMaxWorkGroupSize", @error)
EndFunc   ;==>_cveDeviceMaxWorkGroupSize

Func _cveDeviceMaxComputeUnits($obj)
    ; CVAPI(int) cveDeviceMaxComputeUnits(cv::ocl::Device* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveDeviceMaxComputeUnits", $bObjDllType, $obj), "cveDeviceMaxComputeUnits", @error)
EndFunc   ;==>_cveDeviceMaxComputeUnits

Func _cveDeviceLocalMemSize($obj)
    ; CVAPI(int) cveDeviceLocalMemSize(cv::ocl::Device* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveDeviceLocalMemSize", $bObjDllType, $obj), "cveDeviceLocalMemSize", @error)
EndFunc   ;==>_cveDeviceLocalMemSize

Func _cveDeviceMaxMemAllocSize($obj)
    ; CVAPI(int) cveDeviceMaxMemAllocSize(cv::ocl::Device* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveDeviceMaxMemAllocSize", $bObjDllType, $obj), "cveDeviceMaxMemAllocSize", @error)
EndFunc   ;==>_cveDeviceMaxMemAllocSize

Func _cveDeviceDeviceVersionMajor($obj)
    ; CVAPI(int) cveDeviceDeviceVersionMajor(cv::ocl::Device* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveDeviceDeviceVersionMajor", $bObjDllType, $obj), "cveDeviceDeviceVersionMajor", @error)
EndFunc   ;==>_cveDeviceDeviceVersionMajor

Func _cveDeviceDeviceVersionMinor($obj)
    ; CVAPI(int) cveDeviceDeviceVersionMinor(cv::ocl::Device* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveDeviceDeviceVersionMinor", $bObjDllType, $obj), "cveDeviceDeviceVersionMinor", @error)
EndFunc   ;==>_cveDeviceDeviceVersionMinor

Func _cveDeviceHalfFPConfig($obj)
    ; CVAPI(int) cveDeviceHalfFPConfig(cv::ocl::Device* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveDeviceHalfFPConfig", $bObjDllType, $obj), "cveDeviceHalfFPConfig", @error)
EndFunc   ;==>_cveDeviceHalfFPConfig

Func _cveDeviceSingleFPConfig($obj)
    ; CVAPI(int) cveDeviceSingleFPConfig(cv::ocl::Device* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveDeviceSingleFPConfig", $bObjDllType, $obj), "cveDeviceSingleFPConfig", @error)
EndFunc   ;==>_cveDeviceSingleFPConfig

Func _cveDeviceDoubleFPConfig($obj)
    ; CVAPI(int) cveDeviceDoubleFPConfig(cv::ocl::Device* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveDeviceDoubleFPConfig", $bObjDllType, $obj), "cveDeviceDoubleFPConfig", @error)
EndFunc   ;==>_cveDeviceDoubleFPConfig

Func _cveDeviceHostUnifiedMemory($obj)
    ; CVAPI(bool) cveDeviceHostUnifiedMemory(cv::ocl::Device* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveDeviceHostUnifiedMemory", $bObjDllType, $obj), "cveDeviceHostUnifiedMemory", @error)
EndFunc   ;==>_cveDeviceHostUnifiedMemory

Func _cveDeviceGlobalMemSize($obj)
    ; CVAPI(size_t) cveDeviceGlobalMemSize(cv::ocl::Device* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ulong_ptr:cdecl", "cveDeviceGlobalMemSize", $bObjDllType, $obj), "cveDeviceGlobalMemSize", @error)
EndFunc   ;==>_cveDeviceGlobalMemSize

Func _cveDeviceImage2DMaxWidth($obj)
    ; CVAPI(int) cveDeviceImage2DMaxWidth(cv::ocl::Device* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveDeviceImage2DMaxWidth", $bObjDllType, $obj), "cveDeviceImage2DMaxWidth", @error)
EndFunc   ;==>_cveDeviceImage2DMaxWidth

Func _cveDeviceImage2DMaxHeight($obj)
    ; CVAPI(int) cveDeviceImage2DMaxHeight(cv::ocl::Device* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveDeviceImage2DMaxHeight", $bObjDllType, $obj), "cveDeviceImage2DMaxHeight", @error)
EndFunc   ;==>_cveDeviceImage2DMaxHeight

Func _cveDeviceType($obj)
    ; CVAPI(int) cveDeviceType(cv::ocl::Device* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveDeviceType", $bObjDllType, $obj), "cveDeviceType", @error)
EndFunc   ;==>_cveDeviceType

Func _cveDeviceName($obj, $str)
    ; CVAPI(void) cveDeviceName(cv::ocl::Device* obj, cv::String* str);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    Local $bStrIsString = VarGetType($str) == "String"
    If $bStrIsString Then
        $str = _cveStringCreateFromStr($str)
    EndIf

    Local $bStrDllType
    If VarGetType($str) == "DLLStruct" Then
        $bStrDllType = "struct*"
    Else
        $bStrDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDeviceName", $bObjDllType, $obj, $bStrDllType, $str), "cveDeviceName", @error)

    If $bStrIsString Then
        _cveStringRelease($str)
    EndIf
EndFunc   ;==>_cveDeviceName

Func _cveDeviceVersion($obj, $str)
    ; CVAPI(void) cveDeviceVersion(cv::ocl::Device* obj, cv::String* str);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    Local $bStrIsString = VarGetType($str) == "String"
    If $bStrIsString Then
        $str = _cveStringCreateFromStr($str)
    EndIf

    Local $bStrDllType
    If VarGetType($str) == "DLLStruct" Then
        $bStrDllType = "struct*"
    Else
        $bStrDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDeviceVersion", $bObjDllType, $obj, $bStrDllType, $str), "cveDeviceVersion", @error)

    If $bStrIsString Then
        _cveStringRelease($str)
    EndIf
EndFunc   ;==>_cveDeviceVersion

Func _cveDeviceVendorName($obj, $str)
    ; CVAPI(void) cveDeviceVendorName(cv::ocl::Device* obj, cv::String* str);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    Local $bStrIsString = VarGetType($str) == "String"
    If $bStrIsString Then
        $str = _cveStringCreateFromStr($str)
    EndIf

    Local $bStrDllType
    If VarGetType($str) == "DLLStruct" Then
        $bStrDllType = "struct*"
    Else
        $bStrDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDeviceVendorName", $bObjDllType, $obj, $bStrDllType, $str), "cveDeviceVendorName", @error)

    If $bStrIsString Then
        _cveStringRelease($str)
    EndIf
EndFunc   ;==>_cveDeviceVendorName

Func _cveDeviceDriverVersion($obj, $str)
    ; CVAPI(void) cveDeviceDriverVersion(cv::ocl::Device* obj, cv::String* str);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    Local $bStrIsString = VarGetType($str) == "String"
    If $bStrIsString Then
        $str = _cveStringCreateFromStr($str)
    EndIf

    Local $bStrDllType
    If VarGetType($str) == "DLLStruct" Then
        $bStrDllType = "struct*"
    Else
        $bStrDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDeviceDriverVersion", $bObjDllType, $obj, $bStrDllType, $str), "cveDeviceDriverVersion", @error)

    If $bStrIsString Then
        _cveStringRelease($str)
    EndIf
EndFunc   ;==>_cveDeviceDriverVersion

Func _cveDeviceExtensions($obj, $str)
    ; CVAPI(void) cveDeviceExtensions(cv::ocl::Device* obj, cv::String* str);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    Local $bStrIsString = VarGetType($str) == "String"
    If $bStrIsString Then
        $str = _cveStringCreateFromStr($str)
    EndIf

    Local $bStrDllType
    If VarGetType($str) == "DLLStruct" Then
        $bStrDllType = "struct*"
    Else
        $bStrDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDeviceExtensions", $bObjDllType, $obj, $bStrDllType, $str), "cveDeviceExtensions", @error)

    If $bStrIsString Then
        _cveStringRelease($str)
    EndIf
EndFunc   ;==>_cveDeviceExtensions

Func _cveDeviceOpenCLVersion($obj, $str)
    ; CVAPI(void) cveDeviceOpenCLVersion(cv::ocl::Device* obj, cv::String* str);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    Local $bStrIsString = VarGetType($str) == "String"
    If $bStrIsString Then
        $str = _cveStringCreateFromStr($str)
    EndIf

    Local $bStrDllType
    If VarGetType($str) == "DLLStruct" Then
        $bStrDllType = "struct*"
    Else
        $bStrDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDeviceOpenCLVersion", $bObjDllType, $obj, $bStrDllType, $str), "cveDeviceOpenCLVersion", @error)

    If $bStrIsString Then
        _cveStringRelease($str)
    EndIf
EndFunc   ;==>_cveDeviceOpenCLVersion

Func _cveDeviceOpenCLCVersion($obj, $str)
    ; CVAPI(void) cveDeviceOpenCLCVersion(cv::ocl::Device* obj, cv::String* str);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    Local $bStrIsString = VarGetType($str) == "String"
    If $bStrIsString Then
        $str = _cveStringCreateFromStr($str)
    EndIf

    Local $bStrDllType
    If VarGetType($str) == "DLLStruct" Then
        $bStrDllType = "struct*"
    Else
        $bStrDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDeviceOpenCLCVersion", $bObjDllType, $obj, $bStrDllType, $str), "cveDeviceOpenCLCVersion", @error)

    If $bStrIsString Then
        _cveStringRelease($str)
    EndIf
EndFunc   ;==>_cveDeviceOpenCLCVersion