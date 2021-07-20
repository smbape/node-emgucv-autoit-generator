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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "oclGetPlatformsInfo", "ptr", $vecOclPlatforms), "oclGetPlatformsInfo", @error)

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
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "oclPlatformInfoGetProperties", "ptr", $oclPlatformInfo, "struct*", $platformVersion, "struct*", $platformName, "struct*", $platformVendor), "oclPlatformInfoGetProperties", @error)
EndFunc   ;==>_oclPlatformInfoGetProperties

Func _oclPlatformInfoGetVersion($oclPlatformInfo, $platformVersion)
    ; CVAPI(void) oclPlatformInfoGetVersion(cv::ocl::PlatformInfo* oclPlatformInfo, cv::String* platformVersion);

    Local $bPlatformVersionIsString = VarGetType($platformVersion) == "String"
    If $bPlatformVersionIsString Then
        $platformVersion = _cveStringCreateFromStr($platformVersion)
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "oclPlatformInfoGetVersion", "ptr", $oclPlatformInfo, "ptr", $platformVersion), "oclPlatformInfoGetVersion", @error)

    If $bPlatformVersionIsString Then
        _cveStringRelease($platformVersion)
    EndIf
EndFunc   ;==>_oclPlatformInfoGetVersion

Func _oclPlatformInfoGetName($oclPlatformInfo, $platformName)
    ; CVAPI(void) oclPlatformInfoGetName(cv::ocl::PlatformInfo* oclPlatformInfo, cv::String* platformName);

    Local $bPlatformNameIsString = VarGetType($platformName) == "String"
    If $bPlatformNameIsString Then
        $platformName = _cveStringCreateFromStr($platformName)
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "oclPlatformInfoGetName", "ptr", $oclPlatformInfo, "ptr", $platformName), "oclPlatformInfoGetName", @error)

    If $bPlatformNameIsString Then
        _cveStringRelease($platformName)
    EndIf
EndFunc   ;==>_oclPlatformInfoGetName

Func _oclPlatformInfoGetVender($oclPlatformInfo, $platformVender)
    ; CVAPI(void) oclPlatformInfoGetVender(cv::ocl::PlatformInfo* oclPlatformInfo, cv::String* platformVender);

    Local $bPlatformVenderIsString = VarGetType($platformVender) == "String"
    If $bPlatformVenderIsString Then
        $platformVender = _cveStringCreateFromStr($platformVender)
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "oclPlatformInfoGetVender", "ptr", $oclPlatformInfo, "ptr", $platformVender), "oclPlatformInfoGetVender", @error)

    If $bPlatformVenderIsString Then
        _cveStringRelease($platformVender)
    EndIf
EndFunc   ;==>_oclPlatformInfoGetVender

Func _oclPlatformInfoDeviceNumber($platformInfo)
    ; CVAPI(int) oclPlatformInfoDeviceNumber(cv::ocl::PlatformInfo* platformInfo);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "oclPlatformInfoDeviceNumber", "ptr", $platformInfo), "oclPlatformInfoDeviceNumber", @error)
EndFunc   ;==>_oclPlatformInfoDeviceNumber

Func _oclPlatformInfoGetDevice($platformInfo, $device, $d)
    ; CVAPI(void) oclPlatformInfoGetDevice(cv::ocl::PlatformInfo* platformInfo, cv::ocl::Device* device, int d);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "oclPlatformInfoGetDevice", "ptr", $platformInfo, "ptr", $device, "int", $d), "oclPlatformInfoGetDevice", @error)
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
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "oclDeviceSet", "ptr", $device, "struct*", $p), "oclDeviceSet", @error)
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
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "oclDeviceGetPtr", "ptr", $device), "oclDeviceGetPtr", @error)
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

    Local $bBuildoptIsString = VarGetType($buildopt) == "String"
    If $bBuildoptIsString Then
        $buildopt = _cveStringCreateFromStr($buildopt)
    EndIf

    Local $bErrmsgIsString = VarGetType($errmsg) == "String"
    If $bErrmsgIsString Then
        $errmsg = _cveStringCreateFromStr($errmsg)
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "oclContextGetProg", "ptr", $context, "ptr", $prog, "ptr", $buildopt, "ptr", $errmsg), "oclContextGetProg", @error)

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
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "oclProgramGetBinary", "ptr", $program, "ptr", $binary), "oclProgramGetBinary", @error)
EndFunc   ;==>_oclProgramGetBinary

Func _oclProgramSourceCreate($source)
    ; CVAPI(cv::ocl::ProgramSource*) oclProgramSourceCreate(cv::String* source);

    Local $bSourceIsString = VarGetType($source) == "String"
    If $bSourceIsString Then
        $source = _cveStringCreateFromStr($source)
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "oclProgramSourceCreate", "ptr", $source), "oclProgramSourceCreate", @error)

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
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "oclProgramSourceGetSource", "ptr", $programSource), "oclProgramSourceGetSource", @error)
EndFunc   ;==>_oclProgramSourceGetSource

Func _oclKernelCreateDefault()
    ; CVAPI(cv::ocl::Kernel*) oclKernelCreateDefault();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "oclKernelCreateDefault"), "oclKernelCreateDefault", @error)
EndFunc   ;==>_oclKernelCreateDefault

Func _oclKernelCreate($kernel, $kname, $source, $buildOpts, $errmsg)
    ; CVAPI(bool) oclKernelCreate(cv::ocl::Kernel* kernel, cv::String* kname, cv::ocl::ProgramSource* source, cv::String* buildOpts, cv::String* errmsg);

    Local $bKnameIsString = VarGetType($kname) == "String"
    If $bKnameIsString Then
        $kname = _cveStringCreateFromStr($kname)
    EndIf

    Local $bBuildOptsIsString = VarGetType($buildOpts) == "String"
    If $bBuildOptsIsString Then
        $buildOpts = _cveStringCreateFromStr($buildOpts)
    EndIf

    Local $bErrmsgIsString = VarGetType($errmsg) == "String"
    If $bErrmsgIsString Then
        $errmsg = _cveStringCreateFromStr($errmsg)
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "oclKernelCreate", "ptr", $kernel, "ptr", $kname, "ptr", $source, "ptr", $buildOpts, "ptr", $errmsg), "oclKernelCreate", @error)

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
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "oclKernelSetImage2D", "ptr", $kernel, "int", $i, "ptr", $image2D), "oclKernelSetImage2D", @error)
EndFunc   ;==>_oclKernelSetImage2D

Func _oclKernelSetUMat($kernel, $i, $umat)
    ; CVAPI(int) oclKernelSetUMat(cv::ocl::Kernel* kernel, int i, cv::UMat* umat);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "oclKernelSetUMat", "ptr", $kernel, "int", $i, "ptr", $umat), "oclKernelSetUMat", @error)
EndFunc   ;==>_oclKernelSetUMat

Func _oclKernelSet($kernel, $i, $value, $size)
    ; CVAPI(int) oclKernelSet(cv::ocl::Kernel* kernel, int i, void* value, int size);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "oclKernelSet", "ptr", $kernel, "int", $i, "struct*", $value, "int", $size), "oclKernelSet", @error)
EndFunc   ;==>_oclKernelSet

Func _oclKernelSetKernelArg($kernel, $i, $kernelArg)
    ; CVAPI(int) oclKernelSetKernelArg(cv::ocl::Kernel* kernel, int i, cv::ocl::KernelArg* kernelArg);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "oclKernelSetKernelArg", "ptr", $kernel, "int", $i, "ptr", $kernelArg), "oclKernelSetKernelArg", @error)
EndFunc   ;==>_oclKernelSetKernelArg

Func _oclKernelRun($kernel, $dims, $globalsize, $localsize, $sync, $q)
    ; CVAPI(bool) oclKernelRun(cv::ocl::Kernel* kernel, int dims, size_t* globalsize, size_t* localsize, bool sync, cv::ocl::Queue* q);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "oclKernelRun", "ptr", $kernel, "int", $dims, "struct*", $globalsize, "struct*", $localsize, "boolean", $sync, "ptr", $q), "oclKernelRun", @error)
EndFunc   ;==>_oclKernelRun

Func _oclImage2DFromUMat($src, $norm, $alias)
    ; CVAPI(cv::ocl::Image2D*) oclImage2DFromUMat(cv::UMat* src, bool norm, bool alias);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "oclImage2DFromUMat", "ptr", $src, "boolean", $norm, "boolean", $alias), "oclImage2DFromUMat", @error)
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
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "oclKernelArgCreate", "int", $flags, "ptr", $m, "int", $wscale, "int", $iwscale, "ptr", $obj, "ulong_ptr", $sz), "oclKernelArgCreate", @error)
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
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "oclQueueFinish", "ptr", $queue), "oclQueueFinish", @error)
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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "oclTypeToString", "int", $type, "ptr", $str), "oclTypeToString", @error)

    If $bStrIsString Then
        _cveStringRelease($str)
    EndIf
EndFunc   ;==>_oclTypeToString