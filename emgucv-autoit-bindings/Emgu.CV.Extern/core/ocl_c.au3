#include-once
#include "..\..\CVEUtils.au3"

Func _oclGetPlatformsInfo($oclPlatforms)
    ; CVAPI(void) oclGetPlatformsInfo(std::vector<cv::ocl::PlatformInfo>* oclPlatforms);

    Local $vecOclPlatforms, $iArrOclPlatformsSize
    Local $bOclPlatformsIsArray = IsArray($oclPlatforms)

    If $bOclPlatformsIsArray Then
        $vecOclPlatforms = _VectorOfOclPlatformInfoCreate()

        $iArrOclPlatformsSize = UBound($oclPlatforms)
        For $i = 0 To $iArrOclPlatformsSize - 1
            _VectorOfOclPlatformInfoPush($vecOclPlatforms, $oclPlatforms[$i])
        Next
    Else
        $vecOclPlatforms = $oclPlatforms
    EndIf

    Local $sOclPlatformsDllType
    If IsDllStruct($oclPlatforms) Then
        $sOclPlatformsDllType = "struct*"
    Else
        $sOclPlatformsDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "oclGetPlatformsInfo", $sOclPlatformsDllType, $vecOclPlatforms), "oclGetPlatformsInfo", @error)

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

    Local $sOclPlatformInfoDllType
    If IsDllStruct($oclPlatformInfo) Then
        $sOclPlatformInfoDllType = "struct*"
    Else
        $sOclPlatformInfoDllType = "ptr"
    EndIf

    Local $sPlatformVersionDllType
    If IsDllStruct($platformVersion) Then
        $sPlatformVersionDllType = "struct*"
    ElseIf $platformVersion == Null Then
        $sPlatformVersionDllType = "ptr"
    Else
        $sPlatformVersionDllType = "ptr*"
    EndIf

    Local $sPlatformNameDllType
    If IsDllStruct($platformName) Then
        $sPlatformNameDllType = "struct*"
    ElseIf $platformName == Null Then
        $sPlatformNameDllType = "ptr"
    Else
        $sPlatformNameDllType = "ptr*"
    EndIf

    Local $sPlatformVendorDllType
    If IsDllStruct($platformVendor) Then
        $sPlatformVendorDllType = "struct*"
    ElseIf $platformVendor == Null Then
        $sPlatformVendorDllType = "ptr"
    Else
        $sPlatformVendorDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "oclPlatformInfoGetProperties", $sOclPlatformInfoDllType, $oclPlatformInfo, $sPlatformVersionDllType, $platformVersion, $sPlatformNameDllType, $platformName, $sPlatformVendorDllType, $platformVendor), "oclPlatformInfoGetProperties", @error)
EndFunc   ;==>_oclPlatformInfoGetProperties

Func _oclPlatformInfoGetVersion($oclPlatformInfo, $platformVersion)
    ; CVAPI(void) oclPlatformInfoGetVersion(cv::ocl::PlatformInfo* oclPlatformInfo, cv::String* platformVersion);

    Local $sOclPlatformInfoDllType
    If IsDllStruct($oclPlatformInfo) Then
        $sOclPlatformInfoDllType = "struct*"
    Else
        $sOclPlatformInfoDllType = "ptr"
    EndIf

    Local $bPlatformVersionIsString = IsString($platformVersion)
    If $bPlatformVersionIsString Then
        $platformVersion = _cveStringCreateFromStr($platformVersion)
    EndIf

    Local $sPlatformVersionDllType
    If IsDllStruct($platformVersion) Then
        $sPlatformVersionDllType = "struct*"
    Else
        $sPlatformVersionDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "oclPlatformInfoGetVersion", $sOclPlatformInfoDllType, $oclPlatformInfo, $sPlatformVersionDllType, $platformVersion), "oclPlatformInfoGetVersion", @error)

    If $bPlatformVersionIsString Then
        _cveStringRelease($platformVersion)
    EndIf
EndFunc   ;==>_oclPlatformInfoGetVersion

Func _oclPlatformInfoGetName($oclPlatformInfo, $platformName)
    ; CVAPI(void) oclPlatformInfoGetName(cv::ocl::PlatformInfo* oclPlatformInfo, cv::String* platformName);

    Local $sOclPlatformInfoDllType
    If IsDllStruct($oclPlatformInfo) Then
        $sOclPlatformInfoDllType = "struct*"
    Else
        $sOclPlatformInfoDllType = "ptr"
    EndIf

    Local $bPlatformNameIsString = IsString($platformName)
    If $bPlatformNameIsString Then
        $platformName = _cveStringCreateFromStr($platformName)
    EndIf

    Local $sPlatformNameDllType
    If IsDllStruct($platformName) Then
        $sPlatformNameDllType = "struct*"
    Else
        $sPlatformNameDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "oclPlatformInfoGetName", $sOclPlatformInfoDllType, $oclPlatformInfo, $sPlatformNameDllType, $platformName), "oclPlatformInfoGetName", @error)

    If $bPlatformNameIsString Then
        _cveStringRelease($platformName)
    EndIf
EndFunc   ;==>_oclPlatformInfoGetName

Func _oclPlatformInfoGetVender($oclPlatformInfo, $platformVender)
    ; CVAPI(void) oclPlatformInfoGetVender(cv::ocl::PlatformInfo* oclPlatformInfo, cv::String* platformVender);

    Local $sOclPlatformInfoDllType
    If IsDllStruct($oclPlatformInfo) Then
        $sOclPlatformInfoDllType = "struct*"
    Else
        $sOclPlatformInfoDllType = "ptr"
    EndIf

    Local $bPlatformVenderIsString = IsString($platformVender)
    If $bPlatformVenderIsString Then
        $platformVender = _cveStringCreateFromStr($platformVender)
    EndIf

    Local $sPlatformVenderDllType
    If IsDllStruct($platformVender) Then
        $sPlatformVenderDllType = "struct*"
    Else
        $sPlatformVenderDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "oclPlatformInfoGetVender", $sOclPlatformInfoDllType, $oclPlatformInfo, $sPlatformVenderDllType, $platformVender), "oclPlatformInfoGetVender", @error)

    If $bPlatformVenderIsString Then
        _cveStringRelease($platformVender)
    EndIf
EndFunc   ;==>_oclPlatformInfoGetVender

Func _oclPlatformInfoDeviceNumber($platformInfo)
    ; CVAPI(int) oclPlatformInfoDeviceNumber(cv::ocl::PlatformInfo* platformInfo);

    Local $sPlatformInfoDllType
    If IsDllStruct($platformInfo) Then
        $sPlatformInfoDllType = "struct*"
    Else
        $sPlatformInfoDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "oclPlatformInfoDeviceNumber", $sPlatformInfoDllType, $platformInfo), "oclPlatformInfoDeviceNumber", @error)
EndFunc   ;==>_oclPlatformInfoDeviceNumber

Func _oclPlatformInfoGetDevice($platformInfo, $device, $d)
    ; CVAPI(void) oclPlatformInfoGetDevice(cv::ocl::PlatformInfo* platformInfo, cv::ocl::Device* device, int d);

    Local $sPlatformInfoDllType
    If IsDllStruct($platformInfo) Then
        $sPlatformInfoDllType = "struct*"
    Else
        $sPlatformInfoDllType = "ptr"
    EndIf

    Local $sDeviceDllType
    If IsDllStruct($device) Then
        $sDeviceDllType = "struct*"
    Else
        $sDeviceDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "oclPlatformInfoGetDevice", $sPlatformInfoDllType, $platformInfo, $sDeviceDllType, $device, "int", $d), "oclPlatformInfoGetDevice", @error)
EndFunc   ;==>_oclPlatformInfoGetDevice

Func _oclPlatformInfoRelease($platformInfo)
    ; CVAPI(void) oclPlatformInfoRelease(cv::ocl::PlatformInfo** platformInfo);

    Local $sPlatformInfoDllType
    If IsDllStruct($platformInfo) Then
        $sPlatformInfoDllType = "struct*"
    ElseIf $platformInfo == Null Then
        $sPlatformInfoDllType = "ptr"
    Else
        $sPlatformInfoDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "oclPlatformInfoRelease", $sPlatformInfoDllType, $platformInfo), "oclPlatformInfoRelease", @error)
EndFunc   ;==>_oclPlatformInfoRelease

Func _oclDeviceCreate()
    ; CVAPI(cv::ocl::Device*) oclDeviceCreate();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "oclDeviceCreate"), "oclDeviceCreate", @error)
EndFunc   ;==>_oclDeviceCreate

Func _oclDeviceSet($device, $p)
    ; CVAPI(void) oclDeviceSet(cv::ocl::Device* device, void* p);

    Local $sDeviceDllType
    If IsDllStruct($device) Then
        $sDeviceDllType = "struct*"
    Else
        $sDeviceDllType = "ptr"
    EndIf

    Local $sPDllType
    If IsDllStruct($p) Then
        $sPDllType = "struct*"
    Else
        $sPDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "oclDeviceSet", $sDeviceDllType, $device, $sPDllType, $p), "oclDeviceSet", @error)
EndFunc   ;==>_oclDeviceSet

Func _oclDeviceGetDefault()
    ; CVAPI(const cv::ocl::Device*) oclDeviceGetDefault();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "oclDeviceGetDefault"), "oclDeviceGetDefault", @error)
EndFunc   ;==>_oclDeviceGetDefault

Func _oclDeviceRelease($device)
    ; CVAPI(void) oclDeviceRelease(cv::ocl::Device** device);

    Local $sDeviceDllType
    If IsDllStruct($device) Then
        $sDeviceDllType = "struct*"
    ElseIf $device == Null Then
        $sDeviceDllType = "ptr"
    Else
        $sDeviceDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "oclDeviceRelease", $sDeviceDllType, $device), "oclDeviceRelease", @error)
EndFunc   ;==>_oclDeviceRelease

Func _oclDeviceGetPtr($device)
    ; CVAPI(void*) oclDeviceGetPtr(cv::ocl::Device* device);

    Local $sDeviceDllType
    If IsDllStruct($device) Then
        $sDeviceDllType = "struct*"
    Else
        $sDeviceDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "oclDeviceGetPtr", $sDeviceDllType, $device), "oclDeviceGetPtr", @error)
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

    Local $sContextDllType
    If IsDllStruct($context) Then
        $sContextDllType = "struct*"
    ElseIf $context == Null Then
        $sContextDllType = "ptr"
    Else
        $sContextDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "oclContextRelease", $sContextDllType, $context), "oclContextRelease", @error)
EndFunc   ;==>_oclContextRelease

Func _oclContextGetProg($context, $prog, $buildopt, $errmsg)
    ; CVAPI(const cv::ocl::Program*) oclContextGetProg(cv::ocl::Context* context, cv::ocl::ProgramSource* prog, cv::String* buildopt, cv::String* errmsg);

    Local $sContextDllType
    If IsDllStruct($context) Then
        $sContextDllType = "struct*"
    Else
        $sContextDllType = "ptr"
    EndIf

    Local $sProgDllType
    If IsDllStruct($prog) Then
        $sProgDllType = "struct*"
    Else
        $sProgDllType = "ptr"
    EndIf

    Local $bBuildoptIsString = IsString($buildopt)
    If $bBuildoptIsString Then
        $buildopt = _cveStringCreateFromStr($buildopt)
    EndIf

    Local $sBuildoptDllType
    If IsDllStruct($buildopt) Then
        $sBuildoptDllType = "struct*"
    Else
        $sBuildoptDllType = "ptr"
    EndIf

    Local $bErrmsgIsString = IsString($errmsg)
    If $bErrmsgIsString Then
        $errmsg = _cveStringCreateFromStr($errmsg)
    EndIf

    Local $sErrmsgDllType
    If IsDllStruct($errmsg) Then
        $sErrmsgDllType = "struct*"
    Else
        $sErrmsgDllType = "ptr"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "oclContextGetProg", $sContextDllType, $context, $sProgDllType, $prog, $sBuildoptDllType, $buildopt, $sErrmsgDllType, $errmsg), "oclContextGetProg", @error)

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

    Local $sProgramDllType
    If IsDllStruct($program) Then
        $sProgramDllType = "struct*"
    ElseIf $program == Null Then
        $sProgramDllType = "ptr"
    Else
        $sProgramDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "oclProgramRelease", $sProgramDllType, $program), "oclProgramRelease", @error)
EndFunc   ;==>_oclProgramRelease

Func _oclProgramGetBinary($program, $binary)
    ; CVAPI(void) oclProgramGetBinary(cv::ocl::Program* program, std::vector<char>* binary);

    Local $sProgramDllType
    If IsDllStruct($program) Then
        $sProgramDllType = "struct*"
    Else
        $sProgramDllType = "ptr"
    EndIf

    Local $sBinaryDllType
    If IsDllStruct($binary) Then
        $sBinaryDllType = "struct*"
    Else
        $sBinaryDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "oclProgramGetBinary", $sProgramDllType, $program, $sBinaryDllType, $binary), "oclProgramGetBinary", @error)
EndFunc   ;==>_oclProgramGetBinary

Func _oclProgramSourceCreate($source)
    ; CVAPI(cv::ocl::ProgramSource*) oclProgramSourceCreate(cv::String* source);

    Local $bSourceIsString = IsString($source)
    If $bSourceIsString Then
        $source = _cveStringCreateFromStr($source)
    EndIf

    Local $sSourceDllType
    If IsDllStruct($source) Then
        $sSourceDllType = "struct*"
    Else
        $sSourceDllType = "ptr"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "oclProgramSourceCreate", $sSourceDllType, $source), "oclProgramSourceCreate", @error)

    If $bSourceIsString Then
        _cveStringRelease($source)
    EndIf

    Return $retval
EndFunc   ;==>_oclProgramSourceCreate

Func _oclProgramSourceRelease($programSource)
    ; CVAPI(void) oclProgramSourceRelease(cv::ocl::ProgramSource** programSource);

    Local $sProgramSourceDllType
    If IsDllStruct($programSource) Then
        $sProgramSourceDllType = "struct*"
    ElseIf $programSource == Null Then
        $sProgramSourceDllType = "ptr"
    Else
        $sProgramSourceDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "oclProgramSourceRelease", $sProgramSourceDllType, $programSource), "oclProgramSourceRelease", @error)
EndFunc   ;==>_oclProgramSourceRelease

Func _oclProgramSourceGetSource($programSource)
    ; CVAPI(const cv::String*) oclProgramSourceGetSource(cv::ocl::ProgramSource* programSource);

    Local $sProgramSourceDllType
    If IsDllStruct($programSource) Then
        $sProgramSourceDllType = "struct*"
    Else
        $sProgramSourceDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "oclProgramSourceGetSource", $sProgramSourceDllType, $programSource), "oclProgramSourceGetSource", @error)
EndFunc   ;==>_oclProgramSourceGetSource

Func _oclKernelCreateDefault()
    ; CVAPI(cv::ocl::Kernel*) oclKernelCreateDefault();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "oclKernelCreateDefault"), "oclKernelCreateDefault", @error)
EndFunc   ;==>_oclKernelCreateDefault

Func _oclKernelCreate($kernel, $kname, $source, $buildOpts, $errmsg)
    ; CVAPI(bool) oclKernelCreate(cv::ocl::Kernel* kernel, cv::String* kname, cv::ocl::ProgramSource* source, cv::String* buildOpts, cv::String* errmsg);

    Local $sKernelDllType
    If IsDllStruct($kernel) Then
        $sKernelDllType = "struct*"
    Else
        $sKernelDllType = "ptr"
    EndIf

    Local $bKnameIsString = IsString($kname)
    If $bKnameIsString Then
        $kname = _cveStringCreateFromStr($kname)
    EndIf

    Local $sKnameDllType
    If IsDllStruct($kname) Then
        $sKnameDllType = "struct*"
    Else
        $sKnameDllType = "ptr"
    EndIf

    Local $sSourceDllType
    If IsDllStruct($source) Then
        $sSourceDllType = "struct*"
    Else
        $sSourceDllType = "ptr"
    EndIf

    Local $bBuildOptsIsString = IsString($buildOpts)
    If $bBuildOptsIsString Then
        $buildOpts = _cveStringCreateFromStr($buildOpts)
    EndIf

    Local $sBuildOptsDllType
    If IsDllStruct($buildOpts) Then
        $sBuildOptsDllType = "struct*"
    Else
        $sBuildOptsDllType = "ptr"
    EndIf

    Local $bErrmsgIsString = IsString($errmsg)
    If $bErrmsgIsString Then
        $errmsg = _cveStringCreateFromStr($errmsg)
    EndIf

    Local $sErrmsgDllType
    If IsDllStruct($errmsg) Then
        $sErrmsgDllType = "struct*"
    Else
        $sErrmsgDllType = "ptr"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "oclKernelCreate", $sKernelDllType, $kernel, $sKnameDllType, $kname, $sSourceDllType, $source, $sBuildOptsDllType, $buildOpts, $sErrmsgDllType, $errmsg), "oclKernelCreate", @error)

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

    Local $sKernelDllType
    If IsDllStruct($kernel) Then
        $sKernelDllType = "struct*"
    ElseIf $kernel == Null Then
        $sKernelDllType = "ptr"
    Else
        $sKernelDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "oclKernelRelease", $sKernelDllType, $kernel), "oclKernelRelease", @error)
EndFunc   ;==>_oclKernelRelease

Func _oclKernelSetImage2D($kernel, $i, $image2D)
    ; CVAPI(int) oclKernelSetImage2D(cv::ocl::Kernel* kernel, int i, cv::ocl::Image2D* image2D);

    Local $sKernelDllType
    If IsDllStruct($kernel) Then
        $sKernelDllType = "struct*"
    Else
        $sKernelDllType = "ptr"
    EndIf

    Local $sImage2DDllType
    If IsDllStruct($image2D) Then
        $sImage2DDllType = "struct*"
    Else
        $sImage2DDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "oclKernelSetImage2D", $sKernelDllType, $kernel, "int", $i, $sImage2DDllType, $image2D), "oclKernelSetImage2D", @error)
EndFunc   ;==>_oclKernelSetImage2D

Func _oclKernelSetUMat($kernel, $i, $umat)
    ; CVAPI(int) oclKernelSetUMat(cv::ocl::Kernel* kernel, int i, cv::UMat* umat);

    Local $sKernelDllType
    If IsDllStruct($kernel) Then
        $sKernelDllType = "struct*"
    Else
        $sKernelDllType = "ptr"
    EndIf

    Local $sUmatDllType
    If IsDllStruct($umat) Then
        $sUmatDllType = "struct*"
    Else
        $sUmatDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "oclKernelSetUMat", $sKernelDllType, $kernel, "int", $i, $sUmatDllType, $umat), "oclKernelSetUMat", @error)
EndFunc   ;==>_oclKernelSetUMat

Func _oclKernelSet($kernel, $i, $value, $size)
    ; CVAPI(int) oclKernelSet(cv::ocl::Kernel* kernel, int i, void* value, int size);

    Local $sKernelDllType
    If IsDllStruct($kernel) Then
        $sKernelDllType = "struct*"
    Else
        $sKernelDllType = "ptr"
    EndIf

    Local $sValueDllType
    If IsDllStruct($value) Then
        $sValueDllType = "struct*"
    Else
        $sValueDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "oclKernelSet", $sKernelDllType, $kernel, "int", $i, $sValueDllType, $value, "int", $size), "oclKernelSet", @error)
EndFunc   ;==>_oclKernelSet

Func _oclKernelSetKernelArg($kernel, $i, $kernelArg)
    ; CVAPI(int) oclKernelSetKernelArg(cv::ocl::Kernel* kernel, int i, cv::ocl::KernelArg* kernelArg);

    Local $sKernelDllType
    If IsDllStruct($kernel) Then
        $sKernelDllType = "struct*"
    Else
        $sKernelDllType = "ptr"
    EndIf

    Local $sKernelArgDllType
    If IsDllStruct($kernelArg) Then
        $sKernelArgDllType = "struct*"
    Else
        $sKernelArgDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "oclKernelSetKernelArg", $sKernelDllType, $kernel, "int", $i, $sKernelArgDllType, $kernelArg), "oclKernelSetKernelArg", @error)
EndFunc   ;==>_oclKernelSetKernelArg

Func _oclKernelRun($kernel, $dims, $globalsize, $localsize, $sync, $q)
    ; CVAPI(bool) oclKernelRun(cv::ocl::Kernel* kernel, int dims, size_t* globalsize, size_t* localsize, bool sync, cv::ocl::Queue* q);

    Local $sKernelDllType
    If IsDllStruct($kernel) Then
        $sKernelDllType = "struct*"
    Else
        $sKernelDllType = "ptr"
    EndIf

    Local $sGlobalsizeDllType
    If IsDllStruct($globalsize) Then
        $sGlobalsizeDllType = "struct*"
    Else
        $sGlobalsizeDllType = "ptr"
    EndIf

    Local $sLocalsizeDllType
    If IsDllStruct($localsize) Then
        $sLocalsizeDllType = "struct*"
    Else
        $sLocalsizeDllType = "ptr"
    EndIf

    Local $sQDllType
    If IsDllStruct($q) Then
        $sQDllType = "struct*"
    Else
        $sQDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "oclKernelRun", $sKernelDllType, $kernel, "int", $dims, $sGlobalsizeDllType, $globalsize, $sLocalsizeDllType, $localsize, "boolean", $sync, $sQDllType, $q), "oclKernelRun", @error)
EndFunc   ;==>_oclKernelRun

Func _oclImage2DFromUMat($src, $norm, $alias)
    ; CVAPI(cv::ocl::Image2D*) oclImage2DFromUMat(cv::UMat* src, bool norm, bool alias);

    Local $sSrcDllType
    If IsDllStruct($src) Then
        $sSrcDllType = "struct*"
    Else
        $sSrcDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "oclImage2DFromUMat", $sSrcDllType, $src, "boolean", $norm, "boolean", $alias), "oclImage2DFromUMat", @error)
EndFunc   ;==>_oclImage2DFromUMat

Func _oclImage2DRelease($image2D)
    ; CVAPI(void) oclImage2DRelease(cv::ocl::Image2D** image2D);

    Local $sImage2DDllType
    If IsDllStruct($image2D) Then
        $sImage2DDllType = "struct*"
    ElseIf $image2D == Null Then
        $sImage2DDllType = "ptr"
    Else
        $sImage2DDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "oclImage2DRelease", $sImage2DDllType, $image2D), "oclImage2DRelease", @error)
EndFunc   ;==>_oclImage2DRelease

Func _oclKernelArgCreate($flags, $m, $wscale, $iwscale, $obj, $sz)
    ; CVAPI(cv::ocl::KernelArg*) oclKernelArgCreate(int flags, cv::UMat* m, int wscale, int iwscale, const void* obj, size_t sz);

    Local $sMDllType
    If IsDllStruct($m) Then
        $sMDllType = "struct*"
    Else
        $sMDllType = "ptr"
    EndIf

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "oclKernelArgCreate", "int", $flags, $sMDllType, $m, "int", $wscale, "int", $iwscale, $sObjDllType, $obj, "ulong_ptr", $sz), "oclKernelArgCreate", @error)
EndFunc   ;==>_oclKernelArgCreate

Func _oclKernelArgRelease($k)
    ; CVAPI(void) oclKernelArgRelease(cv::ocl::KernelArg** k);

    Local $sKDllType
    If IsDllStruct($k) Then
        $sKDllType = "struct*"
    ElseIf $k == Null Then
        $sKDllType = "ptr"
    Else
        $sKDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "oclKernelArgRelease", $sKDllType, $k), "oclKernelArgRelease", @error)
EndFunc   ;==>_oclKernelArgRelease

Func _oclQueueCreate()
    ; CVAPI(cv::ocl::Queue*) oclQueueCreate();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "oclQueueCreate"), "oclQueueCreate", @error)
EndFunc   ;==>_oclQueueCreate

Func _oclQueueFinish($queue)
    ; CVAPI(void) oclQueueFinish(cv::ocl::Queue* queue);

    Local $sQueueDllType
    If IsDllStruct($queue) Then
        $sQueueDllType = "struct*"
    Else
        $sQueueDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "oclQueueFinish", $sQueueDllType, $queue), "oclQueueFinish", @error)
EndFunc   ;==>_oclQueueFinish

Func _oclQueueRelease($queue)
    ; CVAPI(void) oclQueueRelease(cv::ocl::Queue** queue);

    Local $sQueueDllType
    If IsDllStruct($queue) Then
        $sQueueDllType = "struct*"
    ElseIf $queue == Null Then
        $sQueueDllType = "ptr"
    Else
        $sQueueDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "oclQueueRelease", $sQueueDllType, $queue), "oclQueueRelease", @error)
EndFunc   ;==>_oclQueueRelease

Func _oclTypeToString($type, $str)
    ; CVAPI(void) oclTypeToString(int type, cv::String* str);

    Local $bStrIsString = IsString($str)
    If $bStrIsString Then
        $str = _cveStringCreateFromStr($str)
    EndIf

    Local $sStrDllType
    If IsDllStruct($str) Then
        $sStrDllType = "struct*"
    Else
        $sStrDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "oclTypeToString", "int", $type, $sStrDllType, $str), "oclTypeToString", @error)

    If $bStrIsString Then
        _cveStringRelease($str)
    EndIf
EndFunc   ;==>_oclTypeToString