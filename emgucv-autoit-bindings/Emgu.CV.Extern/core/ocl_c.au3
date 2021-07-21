#include-once
#include "..\..\CVEUtils.au3"

Func _oclGetPlatformsInfo($oclPlatforms)
    ; CVAPI(void) oclGetPlatformsInfo(std::vector<cv::ocl::PlatformInfo>* oclPlatforms);

    Local $vecOclPlatforms, $iArrOclPlatformsSize
    Local $bOclPlatformsIsArray = VarGetType($oclPlatforms) == "Array"

    If $bOclPlatformsIsArray Then
        $vecOclPlatforms = _VectorOfOclPlatformInfoCreate()

        $iArrOclPlatformsSize = UBound($oclPlatforms)
        For $i = 0 To $iArrOclPlatformsSize - 1
            _VectorOfOclPlatformInfoPush($vecOclPlatforms, $oclPlatforms[$i])
        Next
    Else
        $vecOclPlatforms = $oclPlatforms
    EndIf

    Local $bOclPlatformsDllType
    If VarGetType($oclPlatforms) == "DLLStruct" Then
        $bOclPlatformsDllType = "struct*"
    Else
        $bOclPlatformsDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "oclGetPlatformsInfo", $bOclPlatformsDllType, $vecOclPlatforms), "oclGetPlatformsInfo", @error)

    If $bOclPlatformsIsArray Then
        _VectorOfOclPlatformInfoRelease($vecOclPlatforms)
    EndIf
EndFunc   ;==>_oclGetPlatformsInfo

Func _cveHaveOpenCL()
    ; CVAPI(bool) cveHaveOpenCL();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveHaveOpenCL"), "cveHaveOpenCL", @error)
EndFunc   ;==>_cveHaveOpenCL

Func _cveUseOpenCL()
    ; CVAPI(bool) cveUseOpenCL();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveUseOpenCL"), "cveUseOpenCL", @error)
EndFunc   ;==>_cveUseOpenCL

Func _cveSetUseOpenCL($flag)
    ; CVAPI(void) cveSetUseOpenCL(bool flag);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSetUseOpenCL", "boolean", $flag), "cveSetUseOpenCL", @error)
EndFunc   ;==>_cveSetUseOpenCL

Func _cveOclFinish()
    ; CVAPI(void) cveOclFinish();
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveOclFinish"), "cveOclFinish", @error)
EndFunc   ;==>_cveOclFinish

Func _oclPlatformInfoGetProperties($oclPlatformInfo, $platformVersion, $platformName, $platformVendor)
    ; CVAPI(void) oclPlatformInfoGetProperties(cv::ocl::PlatformInfo* oclPlatformInfo, const char** platformVersion, const char** platformName, const char** platformVendor);

    Local $bOclPlatformInfoDllType
    If VarGetType($oclPlatformInfo) == "DLLStruct" Then
        $bOclPlatformInfoDllType = "struct*"
    Else
        $bOclPlatformInfoDllType = "ptr"
    EndIf

    Local $bPlatformVersionDllType
    If VarGetType($platformVersion) == "DLLStruct" Then
        $bPlatformVersionDllType = "struct*"
    Else
        $bPlatformVersionDllType = "ptr*"
    EndIf

    Local $bPlatformNameDllType
    If VarGetType($platformName) == "DLLStruct" Then
        $bPlatformNameDllType = "struct*"
    Else
        $bPlatformNameDllType = "ptr*"
    EndIf

    Local $bPlatformVendorDllType
    If VarGetType($platformVendor) == "DLLStruct" Then
        $bPlatformVendorDllType = "struct*"
    Else
        $bPlatformVendorDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "oclPlatformInfoGetProperties", $bOclPlatformInfoDllType, $oclPlatformInfo, $bPlatformVersionDllType, $platformVersion, $bPlatformNameDllType, $platformName, $bPlatformVendorDllType, $platformVendor), "oclPlatformInfoGetProperties", @error)
EndFunc   ;==>_oclPlatformInfoGetProperties

Func _oclPlatformInfoGetVersion($oclPlatformInfo, $platformVersion)
    ; CVAPI(void) oclPlatformInfoGetVersion(cv::ocl::PlatformInfo* oclPlatformInfo, cv::String* platformVersion);

    Local $bOclPlatformInfoDllType
    If VarGetType($oclPlatformInfo) == "DLLStruct" Then
        $bOclPlatformInfoDllType = "struct*"
    Else
        $bOclPlatformInfoDllType = "ptr"
    EndIf

    Local $bPlatformVersionIsString = VarGetType($platformVersion) == "String"
    If $bPlatformVersionIsString Then
        $platformVersion = _cveStringCreateFromStr($platformVersion)
    EndIf

    Local $bPlatformVersionDllType
    If VarGetType($platformVersion) == "DLLStruct" Then
        $bPlatformVersionDllType = "struct*"
    Else
        $bPlatformVersionDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "oclPlatformInfoGetVersion", $bOclPlatformInfoDllType, $oclPlatformInfo, $bPlatformVersionDllType, $platformVersion), "oclPlatformInfoGetVersion", @error)

    If $bPlatformVersionIsString Then
        _cveStringRelease($platformVersion)
    EndIf
EndFunc   ;==>_oclPlatformInfoGetVersion

Func _oclPlatformInfoGetName($oclPlatformInfo, $platformName)
    ; CVAPI(void) oclPlatformInfoGetName(cv::ocl::PlatformInfo* oclPlatformInfo, cv::String* platformName);

    Local $bOclPlatformInfoDllType
    If VarGetType($oclPlatformInfo) == "DLLStruct" Then
        $bOclPlatformInfoDllType = "struct*"
    Else
        $bOclPlatformInfoDllType = "ptr"
    EndIf

    Local $bPlatformNameIsString = VarGetType($platformName) == "String"
    If $bPlatformNameIsString Then
        $platformName = _cveStringCreateFromStr($platformName)
    EndIf

    Local $bPlatformNameDllType
    If VarGetType($platformName) == "DLLStruct" Then
        $bPlatformNameDllType = "struct*"
    Else
        $bPlatformNameDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "oclPlatformInfoGetName", $bOclPlatformInfoDllType, $oclPlatformInfo, $bPlatformNameDllType, $platformName), "oclPlatformInfoGetName", @error)

    If $bPlatformNameIsString Then
        _cveStringRelease($platformName)
    EndIf
EndFunc   ;==>_oclPlatformInfoGetName

Func _oclPlatformInfoGetVender($oclPlatformInfo, $platformVender)
    ; CVAPI(void) oclPlatformInfoGetVender(cv::ocl::PlatformInfo* oclPlatformInfo, cv::String* platformVender);

    Local $bOclPlatformInfoDllType
    If VarGetType($oclPlatformInfo) == "DLLStruct" Then
        $bOclPlatformInfoDllType = "struct*"
    Else
        $bOclPlatformInfoDllType = "ptr"
    EndIf

    Local $bPlatformVenderIsString = VarGetType($platformVender) == "String"
    If $bPlatformVenderIsString Then
        $platformVender = _cveStringCreateFromStr($platformVender)
    EndIf

    Local $bPlatformVenderDllType
    If VarGetType($platformVender) == "DLLStruct" Then
        $bPlatformVenderDllType = "struct*"
    Else
        $bPlatformVenderDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "oclPlatformInfoGetVender", $bOclPlatformInfoDllType, $oclPlatformInfo, $bPlatformVenderDllType, $platformVender), "oclPlatformInfoGetVender", @error)

    If $bPlatformVenderIsString Then
        _cveStringRelease($platformVender)
    EndIf
EndFunc   ;==>_oclPlatformInfoGetVender

Func _oclPlatformInfoDeviceNumber($platformInfo)
    ; CVAPI(int) oclPlatformInfoDeviceNumber(cv::ocl::PlatformInfo* platformInfo);

    Local $bPlatformInfoDllType
    If VarGetType($platformInfo) == "DLLStruct" Then
        $bPlatformInfoDllType = "struct*"
    Else
        $bPlatformInfoDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "oclPlatformInfoDeviceNumber", $bPlatformInfoDllType, $platformInfo), "oclPlatformInfoDeviceNumber", @error)
EndFunc   ;==>_oclPlatformInfoDeviceNumber

Func _oclPlatformInfoGetDevice($platformInfo, $device, $d)
    ; CVAPI(void) oclPlatformInfoGetDevice(cv::ocl::PlatformInfo* platformInfo, cv::ocl::Device* device, int d);

    Local $bPlatformInfoDllType
    If VarGetType($platformInfo) == "DLLStruct" Then
        $bPlatformInfoDllType = "struct*"
    Else
        $bPlatformInfoDllType = "ptr"
    EndIf

    Local $bDeviceDllType
    If VarGetType($device) == "DLLStruct" Then
        $bDeviceDllType = "struct*"
    Else
        $bDeviceDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "oclPlatformInfoGetDevice", $bPlatformInfoDllType, $platformInfo, $bDeviceDllType, $device, "int", $d), "oclPlatformInfoGetDevice", @error)
EndFunc   ;==>_oclPlatformInfoGetDevice

Func _oclPlatformInfoRelease($platformInfo)
    ; CVAPI(void) oclPlatformInfoRelease(cv::ocl::PlatformInfo** platformInfo);

    Local $bPlatformInfoDllType
    If VarGetType($platformInfo) == "DLLStruct" Then
        $bPlatformInfoDllType = "struct*"
    Else
        $bPlatformInfoDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "oclPlatformInfoRelease", $bPlatformInfoDllType, $platformInfo), "oclPlatformInfoRelease", @error)
EndFunc   ;==>_oclPlatformInfoRelease

Func _oclDeviceCreate()
    ; CVAPI(cv::ocl::Device*) oclDeviceCreate();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "oclDeviceCreate"), "oclDeviceCreate", @error)
EndFunc   ;==>_oclDeviceCreate

Func _oclDeviceSet($device, $p)
    ; CVAPI(void) oclDeviceSet(cv::ocl::Device* device, void* p);

    Local $bDeviceDllType
    If VarGetType($device) == "DLLStruct" Then
        $bDeviceDllType = "struct*"
    Else
        $bDeviceDllType = "ptr"
    EndIf

    Local $bPDllType
    If VarGetType($p) == "DLLStruct" Then
        $bPDllType = "struct*"
    Else
        $bPDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "oclDeviceSet", $bDeviceDllType, $device, $bPDllType, $p), "oclDeviceSet", @error)
EndFunc   ;==>_oclDeviceSet

Func _oclDeviceGetDefault()
    ; CVAPI(const cv::ocl::Device*) oclDeviceGetDefault();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "oclDeviceGetDefault"), "oclDeviceGetDefault", @error)
EndFunc   ;==>_oclDeviceGetDefault

Func _oclDeviceRelease($device)
    ; CVAPI(void) oclDeviceRelease(cv::ocl::Device** device);

    Local $bDeviceDllType
    If VarGetType($device) == "DLLStruct" Then
        $bDeviceDllType = "struct*"
    Else
        $bDeviceDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "oclDeviceRelease", $bDeviceDllType, $device), "oclDeviceRelease", @error)
EndFunc   ;==>_oclDeviceRelease

Func _oclDeviceGetPtr($device)
    ; CVAPI(void*) oclDeviceGetPtr(cv::ocl::Device* device);

    Local $bDeviceDllType
    If VarGetType($device) == "DLLStruct" Then
        $bDeviceDllType = "struct*"
    Else
        $bDeviceDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "oclDeviceGetPtr", $bDeviceDllType, $device), "oclDeviceGetPtr", @error)
EndFunc   ;==>_oclDeviceGetPtr

Func _oclContextCreate()
    ; CVAPI(cv::ocl::Context*) oclContextCreate();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "oclContextCreate"), "oclContextCreate", @error)
EndFunc   ;==>_oclContextCreate

Func _oclContextGetDefault($initialize)
    ; CVAPI(const cv::ocl::Context*) oclContextGetDefault(bool initialize);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "oclContextGetDefault", "boolean", $initialize), "oclContextGetDefault", @error)
EndFunc   ;==>_oclContextGetDefault

Func _oclContextRelease($context)
    ; CVAPI(void) oclContextRelease(cv::ocl::Context** context);

    Local $bContextDllType
    If VarGetType($context) == "DLLStruct" Then
        $bContextDllType = "struct*"
    Else
        $bContextDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "oclContextRelease", $bContextDllType, $context), "oclContextRelease", @error)
EndFunc   ;==>_oclContextRelease

Func _oclContextGetProg($context, $prog, $buildopt, $errmsg)
    ; CVAPI(const cv::ocl::Program*) oclContextGetProg(cv::ocl::Context* context, cv::ocl::ProgramSource* prog, cv::String* buildopt, cv::String* errmsg);

    Local $bContextDllType
    If VarGetType($context) == "DLLStruct" Then
        $bContextDllType = "struct*"
    Else
        $bContextDllType = "ptr"
    EndIf

    Local $bProgDllType
    If VarGetType($prog) == "DLLStruct" Then
        $bProgDllType = "struct*"
    Else
        $bProgDllType = "ptr"
    EndIf

    Local $bBuildoptIsString = VarGetType($buildopt) == "String"
    If $bBuildoptIsString Then
        $buildopt = _cveStringCreateFromStr($buildopt)
    EndIf

    Local $bBuildoptDllType
    If VarGetType($buildopt) == "DLLStruct" Then
        $bBuildoptDllType = "struct*"
    Else
        $bBuildoptDllType = "ptr"
    EndIf

    Local $bErrmsgIsString = VarGetType($errmsg) == "String"
    If $bErrmsgIsString Then
        $errmsg = _cveStringCreateFromStr($errmsg)
    EndIf

    Local $bErrmsgDllType
    If VarGetType($errmsg) == "DLLStruct" Then
        $bErrmsgDllType = "struct*"
    Else
        $bErrmsgDllType = "ptr"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "oclContextGetProg", $bContextDllType, $context, $bProgDllType, $prog, $bBuildoptDllType, $buildopt, $bErrmsgDllType, $errmsg), "oclContextGetProg", @error)

    If $bErrmsgIsString Then
        _cveStringRelease($errmsg)
    EndIf

    If $bBuildoptIsString Then
        _cveStringRelease($buildopt)
    EndIf

    Return $retval
EndFunc   ;==>_oclContextGetProg

Func _oclProgramCreate()
    ; CVAPI(cv::ocl::Program*) oclProgramCreate();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "oclProgramCreate"), "oclProgramCreate", @error)
EndFunc   ;==>_oclProgramCreate

Func _oclProgramRelease($program)
    ; CVAPI(void) oclProgramRelease(cv::ocl::Program** program);

    Local $bProgramDllType
    If VarGetType($program) == "DLLStruct" Then
        $bProgramDllType = "struct*"
    Else
        $bProgramDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "oclProgramRelease", $bProgramDllType, $program), "oclProgramRelease", @error)
EndFunc   ;==>_oclProgramRelease

Func _oclProgramGetBinary($program, $binary)
    ; CVAPI(void) oclProgramGetBinary(cv::ocl::Program* program, std::vector<char>* binary);

    Local $bProgramDllType
    If VarGetType($program) == "DLLStruct" Then
        $bProgramDllType = "struct*"
    Else
        $bProgramDllType = "ptr"
    EndIf

    Local $bBinaryDllType
    If VarGetType($binary) == "DLLStruct" Then
        $bBinaryDllType = "struct*"
    Else
        $bBinaryDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "oclProgramGetBinary", $bProgramDllType, $program, $bBinaryDllType, $binary), "oclProgramGetBinary", @error)
EndFunc   ;==>_oclProgramGetBinary

Func _oclProgramSourceCreate($source)
    ; CVAPI(cv::ocl::ProgramSource*) oclProgramSourceCreate(cv::String* source);

    Local $bSourceIsString = VarGetType($source) == "String"
    If $bSourceIsString Then
        $source = _cveStringCreateFromStr($source)
    EndIf

    Local $bSourceDllType
    If VarGetType($source) == "DLLStruct" Then
        $bSourceDllType = "struct*"
    Else
        $bSourceDllType = "ptr"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "oclProgramSourceCreate", $bSourceDllType, $source), "oclProgramSourceCreate", @error)

    If $bSourceIsString Then
        _cveStringRelease($source)
    EndIf

    Return $retval
EndFunc   ;==>_oclProgramSourceCreate

Func _oclProgramSourceRelease($programSource)
    ; CVAPI(void) oclProgramSourceRelease(cv::ocl::ProgramSource** programSource);

    Local $bProgramSourceDllType
    If VarGetType($programSource) == "DLLStruct" Then
        $bProgramSourceDllType = "struct*"
    Else
        $bProgramSourceDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "oclProgramSourceRelease", $bProgramSourceDllType, $programSource), "oclProgramSourceRelease", @error)
EndFunc   ;==>_oclProgramSourceRelease

Func _oclProgramSourceGetSource($programSource)
    ; CVAPI(const cv::String*) oclProgramSourceGetSource(cv::ocl::ProgramSource* programSource);

    Local $bProgramSourceDllType
    If VarGetType($programSource) == "DLLStruct" Then
        $bProgramSourceDllType = "struct*"
    Else
        $bProgramSourceDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "oclProgramSourceGetSource", $bProgramSourceDllType, $programSource), "oclProgramSourceGetSource", @error)
EndFunc   ;==>_oclProgramSourceGetSource

Func _oclKernelCreateDefault()
    ; CVAPI(cv::ocl::Kernel*) oclKernelCreateDefault();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "oclKernelCreateDefault"), "oclKernelCreateDefault", @error)
EndFunc   ;==>_oclKernelCreateDefault

Func _oclKernelCreate($kernel, $kname, $source, $buildOpts, $errmsg)
    ; CVAPI(bool) oclKernelCreate(cv::ocl::Kernel* kernel, cv::String* kname, cv::ocl::ProgramSource* source, cv::String* buildOpts, cv::String* errmsg);

    Local $bKernelDllType
    If VarGetType($kernel) == "DLLStruct" Then
        $bKernelDllType = "struct*"
    Else
        $bKernelDllType = "ptr"
    EndIf

    Local $bKnameIsString = VarGetType($kname) == "String"
    If $bKnameIsString Then
        $kname = _cveStringCreateFromStr($kname)
    EndIf

    Local $bKnameDllType
    If VarGetType($kname) == "DLLStruct" Then
        $bKnameDllType = "struct*"
    Else
        $bKnameDllType = "ptr"
    EndIf

    Local $bSourceDllType
    If VarGetType($source) == "DLLStruct" Then
        $bSourceDllType = "struct*"
    Else
        $bSourceDllType = "ptr"
    EndIf

    Local $bBuildOptsIsString = VarGetType($buildOpts) == "String"
    If $bBuildOptsIsString Then
        $buildOpts = _cveStringCreateFromStr($buildOpts)
    EndIf

    Local $bBuildOptsDllType
    If VarGetType($buildOpts) == "DLLStruct" Then
        $bBuildOptsDllType = "struct*"
    Else
        $bBuildOptsDllType = "ptr"
    EndIf

    Local $bErrmsgIsString = VarGetType($errmsg) == "String"
    If $bErrmsgIsString Then
        $errmsg = _cveStringCreateFromStr($errmsg)
    EndIf

    Local $bErrmsgDllType
    If VarGetType($errmsg) == "DLLStruct" Then
        $bErrmsgDllType = "struct*"
    Else
        $bErrmsgDllType = "ptr"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "oclKernelCreate", $bKernelDllType, $kernel, $bKnameDllType, $kname, $bSourceDllType, $source, $bBuildOptsDllType, $buildOpts, $bErrmsgDllType, $errmsg), "oclKernelCreate", @error)

    If $bErrmsgIsString Then
        _cveStringRelease($errmsg)
    EndIf

    If $bBuildOptsIsString Then
        _cveStringRelease($buildOpts)
    EndIf

    If $bKnameIsString Then
        _cveStringRelease($kname)
    EndIf

    Return $retval
EndFunc   ;==>_oclKernelCreate

Func _oclKernelRelease($kernel)
    ; CVAPI(void) oclKernelRelease(cv::ocl::Kernel** kernel);

    Local $bKernelDllType
    If VarGetType($kernel) == "DLLStruct" Then
        $bKernelDllType = "struct*"
    Else
        $bKernelDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "oclKernelRelease", $bKernelDllType, $kernel), "oclKernelRelease", @error)
EndFunc   ;==>_oclKernelRelease

Func _oclKernelSetImage2D($kernel, $i, $image2D)
    ; CVAPI(int) oclKernelSetImage2D(cv::ocl::Kernel* kernel, int i, cv::ocl::Image2D* image2D);

    Local $bKernelDllType
    If VarGetType($kernel) == "DLLStruct" Then
        $bKernelDllType = "struct*"
    Else
        $bKernelDllType = "ptr"
    EndIf

    Local $bImage2DDllType
    If VarGetType($image2D) == "DLLStruct" Then
        $bImage2DDllType = "struct*"
    Else
        $bImage2DDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "oclKernelSetImage2D", $bKernelDllType, $kernel, "int", $i, $bImage2DDllType, $image2D), "oclKernelSetImage2D", @error)
EndFunc   ;==>_oclKernelSetImage2D

Func _oclKernelSetUMat($kernel, $i, $umat)
    ; CVAPI(int) oclKernelSetUMat(cv::ocl::Kernel* kernel, int i, cv::UMat* umat);

    Local $bKernelDllType
    If VarGetType($kernel) == "DLLStruct" Then
        $bKernelDllType = "struct*"
    Else
        $bKernelDllType = "ptr"
    EndIf

    Local $bUmatDllType
    If VarGetType($umat) == "DLLStruct" Then
        $bUmatDllType = "struct*"
    Else
        $bUmatDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "oclKernelSetUMat", $bKernelDllType, $kernel, "int", $i, $bUmatDllType, $umat), "oclKernelSetUMat", @error)
EndFunc   ;==>_oclKernelSetUMat

Func _oclKernelSet($kernel, $i, $value, $size)
    ; CVAPI(int) oclKernelSet(cv::ocl::Kernel* kernel, int i, void* value, int size);

    Local $bKernelDllType
    If VarGetType($kernel) == "DLLStruct" Then
        $bKernelDllType = "struct*"
    Else
        $bKernelDllType = "ptr"
    EndIf

    Local $bValueDllType
    If VarGetType($value) == "DLLStruct" Then
        $bValueDllType = "struct*"
    Else
        $bValueDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "oclKernelSet", $bKernelDllType, $kernel, "int", $i, $bValueDllType, $value, "int", $size), "oclKernelSet", @error)
EndFunc   ;==>_oclKernelSet

Func _oclKernelSetKernelArg($kernel, $i, $kernelArg)
    ; CVAPI(int) oclKernelSetKernelArg(cv::ocl::Kernel* kernel, int i, cv::ocl::KernelArg* kernelArg);

    Local $bKernelDllType
    If VarGetType($kernel) == "DLLStruct" Then
        $bKernelDllType = "struct*"
    Else
        $bKernelDllType = "ptr"
    EndIf

    Local $bKernelArgDllType
    If VarGetType($kernelArg) == "DLLStruct" Then
        $bKernelArgDllType = "struct*"
    Else
        $bKernelArgDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "oclKernelSetKernelArg", $bKernelDllType, $kernel, "int", $i, $bKernelArgDllType, $kernelArg), "oclKernelSetKernelArg", @error)
EndFunc   ;==>_oclKernelSetKernelArg

Func _oclKernelRun($kernel, $dims, $globalsize, $localsize, $sync, $q)
    ; CVAPI(bool) oclKernelRun(cv::ocl::Kernel* kernel, int dims, size_t* globalsize, size_t* localsize, bool sync, cv::ocl::Queue* q);

    Local $bKernelDllType
    If VarGetType($kernel) == "DLLStruct" Then
        $bKernelDllType = "struct*"
    Else
        $bKernelDllType = "ptr"
    EndIf

    Local $bGlobalsizeDllType
    If VarGetType($globalsize) == "DLLStruct" Then
        $bGlobalsizeDllType = "struct*"
    Else
        $bGlobalsizeDllType = "ptr"
    EndIf

    Local $bLocalsizeDllType
    If VarGetType($localsize) == "DLLStruct" Then
        $bLocalsizeDllType = "struct*"
    Else
        $bLocalsizeDllType = "ptr"
    EndIf

    Local $bQDllType
    If VarGetType($q) == "DLLStruct" Then
        $bQDllType = "struct*"
    Else
        $bQDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "oclKernelRun", $bKernelDllType, $kernel, "int", $dims, $bGlobalsizeDllType, $globalsize, $bLocalsizeDllType, $localsize, "boolean", $sync, $bQDllType, $q), "oclKernelRun", @error)
EndFunc   ;==>_oclKernelRun

Func _oclImage2DFromUMat($src, $norm, $alias)
    ; CVAPI(cv::ocl::Image2D*) oclImage2DFromUMat(cv::UMat* src, bool norm, bool alias);

    Local $bSrcDllType
    If VarGetType($src) == "DLLStruct" Then
        $bSrcDllType = "struct*"
    Else
        $bSrcDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "oclImage2DFromUMat", $bSrcDllType, $src, "boolean", $norm, "boolean", $alias), "oclImage2DFromUMat", @error)
EndFunc   ;==>_oclImage2DFromUMat

Func _oclImage2DRelease($image2D)
    ; CVAPI(void) oclImage2DRelease(cv::ocl::Image2D** image2D);

    Local $bImage2DDllType
    If VarGetType($image2D) == "DLLStruct" Then
        $bImage2DDllType = "struct*"
    Else
        $bImage2DDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "oclImage2DRelease", $bImage2DDllType, $image2D), "oclImage2DRelease", @error)
EndFunc   ;==>_oclImage2DRelease

Func _oclKernelArgCreate($flags, $m, $wscale, $iwscale, $obj, $sz)
    ; CVAPI(cv::ocl::KernelArg*) oclKernelArgCreate(int flags, cv::UMat* m, int wscale, int iwscale, const void* obj, size_t sz);

    Local $bMDllType
    If VarGetType($m) == "DLLStruct" Then
        $bMDllType = "struct*"
    Else
        $bMDllType = "ptr"
    EndIf

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "oclKernelArgCreate", "int", $flags, $bMDllType, $m, "int", $wscale, "int", $iwscale, $bObjDllType, $obj, "ulong_ptr", $sz), "oclKernelArgCreate", @error)
EndFunc   ;==>_oclKernelArgCreate

Func _oclKernelArgRelease($k)
    ; CVAPI(void) oclKernelArgRelease(cv::ocl::KernelArg** k);

    Local $bKDllType
    If VarGetType($k) == "DLLStruct" Then
        $bKDllType = "struct*"
    Else
        $bKDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "oclKernelArgRelease", $bKDllType, $k), "oclKernelArgRelease", @error)
EndFunc   ;==>_oclKernelArgRelease

Func _oclQueueCreate()
    ; CVAPI(cv::ocl::Queue*) oclQueueCreate();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "oclQueueCreate"), "oclQueueCreate", @error)
EndFunc   ;==>_oclQueueCreate

Func _oclQueueFinish($queue)
    ; CVAPI(void) oclQueueFinish(cv::ocl::Queue* queue);

    Local $bQueueDllType
    If VarGetType($queue) == "DLLStruct" Then
        $bQueueDllType = "struct*"
    Else
        $bQueueDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "oclQueueFinish", $bQueueDllType, $queue), "oclQueueFinish", @error)
EndFunc   ;==>_oclQueueFinish

Func _oclQueueRelease($queue)
    ; CVAPI(void) oclQueueRelease(cv::ocl::Queue** queue);

    Local $bQueueDllType
    If VarGetType($queue) == "DLLStruct" Then
        $bQueueDllType = "struct*"
    Else
        $bQueueDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "oclQueueRelease", $bQueueDllType, $queue), "oclQueueRelease", @error)
EndFunc   ;==>_oclQueueRelease

Func _oclTypeToString($type, $str)
    ; CVAPI(void) oclTypeToString(int type, cv::String* str);

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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "oclTypeToString", "int", $type, $bStrDllType, $str), "oclTypeToString", @error)

    If $bStrIsString Then
        _cveStringRelease($str)
    EndIf
EndFunc   ;==>_oclTypeToString