#include "ocl_c.h"
CVAPI(bool) cveDeviceIsNVidia(cv::ocl::Device* obj);  
     
CVAPI(bool) cveDeviceIsIntel(cv::ocl::Device* obj);  
     
CVAPI(bool) cveDeviceIsAMD(cv::ocl::Device* obj);  
     
CVAPI(int) cveDeviceAddressBits(cv::ocl::Device* obj);  
     
CVAPI(bool) cveDeviceLinkerAvailable(cv::ocl::Device* obj);  
     
CVAPI(bool) cveDeviceCompilerAvailable(cv::ocl::Device* obj);  
     
CVAPI(bool) cveDeviceAvailable(cv::ocl::Device* obj);  
     
CVAPI(int) cveDeviceMaxWorkGroupSize(cv::ocl::Device* obj);  
     
CVAPI(int) cveDeviceMaxComputeUnits(cv::ocl::Device* obj);  
     
CVAPI(int) cveDeviceLocalMemSize(cv::ocl::Device* obj);  
     
CVAPI(int) cveDeviceMaxMemAllocSize(cv::ocl::Device* obj);  
     
CVAPI(int) cveDeviceDeviceVersionMajor(cv::ocl::Device* obj);  
     
CVAPI(int) cveDeviceDeviceVersionMinor(cv::ocl::Device* obj);  
     
CVAPI(int) cveDeviceHalfFPConfig(cv::ocl::Device* obj);  
     
CVAPI(int) cveDeviceSingleFPConfig(cv::ocl::Device* obj);  
     
CVAPI(int) cveDeviceDoubleFPConfig(cv::ocl::Device* obj);  
     
CVAPI(bool) cveDeviceHostUnifiedMemory(cv::ocl::Device* obj);  
     
CVAPI(size_t) cveDeviceGlobalMemSize(cv::ocl::Device* obj);  
     
CVAPI(int) cveDeviceImage2DMaxWidth(cv::ocl::Device* obj);  
     
CVAPI(int) cveDeviceImage2DMaxHeight(cv::ocl::Device* obj);  
     
CVAPI(int) cveDeviceType(cv::ocl::Device* obj);  
     
CVAPI(void) cveDeviceName(cv::ocl::Device* obj, cv::String* str);  
     
CVAPI(void) cveDeviceVersion(cv::ocl::Device* obj, cv::String* str);  
     
CVAPI(void) cveDeviceVendorName(cv::ocl::Device* obj, cv::String* str);  
     
CVAPI(void) cveDeviceDriverVersion(cv::ocl::Device* obj, cv::String* str);  
     
CVAPI(void) cveDeviceExtensions(cv::ocl::Device* obj, cv::String* str);  
     
CVAPI(void) cveDeviceOpenCLVersion(cv::ocl::Device* obj, cv::String* str);  
     
CVAPI(void) cveDeviceOpenCLCVersion(cv::ocl::Device* obj, cv::String* str);  
     