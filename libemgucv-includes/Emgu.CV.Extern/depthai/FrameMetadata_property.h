#include "depthai_c.h"
CVAPI(void) cveFrameMetadataGetCameraName(FrameMetadata* obj, cv::String* val);  
     
CVAPI(int) cveFrameMetadataGetSequenceNum(FrameMetadata* obj);  
     
CVAPI(int) cveFrameMetadataGetInstanceNum(FrameMetadata* obj);  
     
CVAPI(int) cveFrameMetadataGetCategory(FrameMetadata* obj);  
     
CVAPI(unsigned int) cveFrameMetadataGetStride(FrameMetadata* obj);  
     
CVAPI(unsigned int) cveFrameMetadataGetFrameBytesPP(FrameMetadata* obj);  
     
CVAPI(unsigned int) cveFrameMetadataGetFrameHeight(FrameMetadata* obj);  
     
CVAPI(unsigned int) cveFrameMetadataGetFrameWidth(FrameMetadata* obj);  
     
CVAPI(int) cveFrameMetadataGetFrameType(FrameMetadata* obj);  
     
CVAPI(double) cveFrameMetadataGetTimestamp(FrameMetadata* obj);  
     
CVAPI(bool) cveFrameMetadataIsValid(FrameMetadata* obj);  
     