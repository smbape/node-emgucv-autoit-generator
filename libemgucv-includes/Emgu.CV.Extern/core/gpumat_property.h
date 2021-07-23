#include "opencv2/core/cuda.hpp"
	#include "opencv2/core/types_c.h"
CVAPI(bool) cveGpuMatIsContinuous(cv::cuda::GpuMat* obj);  
     
CVAPI(int) cveGpuMatDepth(cv::cuda::GpuMat* obj);  
     
CVAPI(bool) cveGpuMatIsEmpty(cv::cuda::GpuMat* obj);  
     
CVAPI(int) cveGpuMatNumberOfChannels(cv::cuda::GpuMat* obj);  
     