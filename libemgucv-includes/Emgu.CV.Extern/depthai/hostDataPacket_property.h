#include "depthai_c.h"
CVAPI(void) cveHostDataPacketGetStreamName(HostDataPacket* obj, cv::String* str);   
     
CVAPI(int) cveHostDataPacketSize(HostDataPacket* obj);  
     
CVAPI(const unsigned char*) cveHostDataPacketGetData(HostDataPacket* obj);  
     
CVAPI(int) cveHostDataPacketGetElemSize(HostDataPacket* obj);
     