#include-once
#include "Emgu.CV.Extern\alphamat\alphamat_c.au3"
#include "Emgu.CV.Extern\aruco\aruco_c.au3"
#include "Emgu.CV.Extern\bgsegm\bgsegm_c.au3"
#include "Emgu.CV.Extern\bioinspired\bioinspired_c.au3"
#include "Emgu.CV.Extern\calib3d\calib3d_c.au3"
#include "Emgu.CV.Extern\core\core_cuda_c.au3"
#include "Emgu.CV.Extern\core\core_c_extra.au3"
#include "Emgu.CV.Extern\core\file_node_property.au3"
#include "Emgu.CV.Extern\core\gpumat_property.au3"
#include "Emgu.CV.Extern\core\input_array_property.au3"
#include "Emgu.CV.Extern\core\mat_c.au3"
#include "Emgu.CV.Extern\core\mat_property.au3"
#include "Emgu.CV.Extern\core\moments_property.au3"
#include "Emgu.CV.Extern\core\ocl_c.au3"
#include "Emgu.CV.Extern\core\ocl_device_property.au3"
#include "Emgu.CV.Extern\core\ocl_kernel_property.au3"
#include "Emgu.CV.Extern\core\ocl_platform_info_property.au3"
#include "Emgu.CV.Extern\core\optim_c.au3"
#include "Emgu.CV.Extern\core\output_array_property.au3"
#include "Emgu.CV.Extern\core\umat_c.au3"
#include "Emgu.CV.Extern\core\umat_property.au3"
#include "Emgu.CV.Extern\dataLogger.au3"
#include "Emgu.CV.Extern\depthai\depthai_c.au3"
#include "Emgu.CV.Extern\depthai\device_property.au3"
#include "Emgu.CV.Extern\depthai\FrameMetadata_property.au3"
#include "Emgu.CV.Extern\depthai\hostDataPacket_property.au3"
#include "Emgu.CV.Extern\dnn_objdetect\dnn_objdetect_c.au3"
#include "Emgu.CV.Extern\dnn_superres\dnn_superres_c.au3"
#include "Emgu.CV.Extern\doubleOps.au3"
#include "Emgu.CV.Extern\dpm\dpm_c.au3"
#include "Emgu.CV.Extern\emgu_c.au3"
#include "Emgu.CV.Extern\face\facemarkaam_params_property.au3"
#include "Emgu.CV.Extern\face\facemarklbf_params_property.au3"
#include "Emgu.CV.Extern\face\face_c.au3"
#include "Emgu.CV.Extern\features2d\features2d_c.au3"
#include "Emgu.CV.Extern\features2d\MSER_property.au3"
#include "Emgu.CV.Extern\features2d\SimpleBlobDetector_property.au3"
#include "Emgu.CV.Extern\flann\flann_c.au3"
#include "Emgu.CV.Extern\freetype\freetype_c.au3"
#include "Emgu.CV.Extern\fuzzy\fuzzy_c.au3"
#include "Emgu.CV.Extern\gapi\gapi_c.au3"
#include "Emgu.CV.Extern\hdf\hdf_c.au3"
#include "Emgu.CV.Extern\hfs\hfs_c.au3"
#include "Emgu.CV.Extern\highgui\highgui_c_extra.au3"
#include "Emgu.CV.Extern\imgcodecs\imgcodecs_c_extra.au3"
#include "Emgu.CV.Extern\imgproc\imgproc_c.au3"
#include "Emgu.CV.Extern\imgproc\IntelligentScissorsMB_property.au3"
#include "Emgu.CV.Extern\imgproc\LineIterator_property.au3"
#include "Emgu.CV.Extern\img_hash\img_hash_c_extra.au3"
#include "Emgu.CV.Extern\intensity_transform\intensity_transform_c.au3"
#include "Emgu.CV.Extern\line_descriptor\line_descriptor_c.au3"
#include "Emgu.CV.Extern\mcc\CChecker_property.au3"
#include "Emgu.CV.Extern\mcc\DetectorParameters_property.au3"
#include "Emgu.CV.Extern\mcc\mcc_c.au3"
#include "Emgu.CV.Extern\phase_unwrapping\phase_unwrapping_c.au3"
#include "Emgu.CV.Extern\photo_edit.au3"
#include "Emgu.CV.Extern\plane3D.au3"
#include "Emgu.CV.Extern\plot\plot2d_property.au3"
#include "Emgu.CV.Extern\plot\plot_c.au3"
#include "Emgu.CV.Extern\pointUtil.au3"
#include "Emgu.CV.Extern\quality\quality_c.au3"
#include "Emgu.CV.Extern\quaternions.au3"
#include "Emgu.CV.Extern\rapid\rapid_c.au3"
#include "Emgu.CV.Extern\saliency\MotionSaliencyBinWangApr2014_property.au3"
#include "Emgu.CV.Extern\saliency\ObjectnessBING_property.au3"
#include "Emgu.CV.Extern\saliency\saliency_c.au3"
#include "Emgu.CV.Extern\shape\ShapeContextDistanceExtractor_property.au3"
#include "Emgu.CV.Extern\shape\shape_c.au3"
#include "Emgu.CV.Extern\sse.au3"
#include "Emgu.CV.Extern\stereo\quasi_dense_stereo_property.au3"
#include "Emgu.CV.Extern\stereo\stereo_c.au3"
#include "Emgu.CV.Extern\stitching\stitching_c.au3"
#include "Emgu.CV.Extern\stitching\stitching_property.au3"
#include "Emgu.CV.Extern\superres\superres_c.au3"
#include "Emgu.CV.Extern\surface_matching\surface_matching_c.au3"
#include "Emgu.CV.Extern\text\text_c.au3"
#include "Emgu.CV.Extern\tiffio_c.au3"
#include "Emgu.CV.Extern\tracking\tracking_c.au3"
#include "Emgu.CV.Extern\vectors_c.au3"
#include "Emgu.CV.Extern\vector_Byte.au3"
#include "Emgu.CV.Extern\vector_ColorPoint.au3"
#include "Emgu.CV.Extern\vector_CvString.au3"
#include "Emgu.CV.Extern\vector_DMatch.au3"
#include "Emgu.CV.Extern\vector_Double.au3"
#include "Emgu.CV.Extern\vector_ERStat.au3"
#include "Emgu.CV.Extern\vector_Float.au3"
#include "Emgu.CV.Extern\vector_GMat.au3"
#include "Emgu.CV.Extern\vector_GpuMat.au3"
#include "Emgu.CV.Extern\vector_Int.au3"
#include "Emgu.CV.Extern\vector_KeyLine.au3"
#include "Emgu.CV.Extern\vector_KeyPoint.au3"
#include "Emgu.CV.Extern\vector_Mat.au3"
#include "Emgu.CV.Extern\vector_OclPlatformInfo.au3"
#include "Emgu.CV.Extern\vector_Point.au3"
#include "Emgu.CV.Extern\vector_Point3D32F.au3"
#include "Emgu.CV.Extern\vector_PointF.au3"
#include "Emgu.CV.Extern\vector_Rect.au3"
#include "Emgu.CV.Extern\vector_RotatedRect.au3"
#include "Emgu.CV.Extern\vector_Size.au3"
#include "Emgu.CV.Extern\vector_TesseractResult.au3"
#include "Emgu.CV.Extern\vector_Triangle2DF.au3"
#include "Emgu.CV.Extern\vector_UMat.au3"
#include "Emgu.CV.Extern\vector_VectorOfByte.au3"
#include "Emgu.CV.Extern\vector_VectorOfDMatch.au3"
#include "Emgu.CV.Extern\vector_VectorOfERStat.au3"
#include "Emgu.CV.Extern\vector_VectorOfInt.au3"
#include "Emgu.CV.Extern\vector_VectorOfPoint.au3"
#include "Emgu.CV.Extern\vector_VectorOfPoint3D32F.au3"
#include "Emgu.CV.Extern\vector_VectorOfPointF.au3"
#include "Emgu.CV.Extern\vector_VectorOfRect.au3"
#include "Emgu.CV.Extern\vector_VideoCapture.au3"
#include "Emgu.CV.Extern\video\BackgroundSubtractorKNN_property.au3"
#include "Emgu.CV.Extern\video\BackgroundSubtractorMOG2_property.au3"
#include "Emgu.CV.Extern\video\disopticalflow_property.au3"
#include "Emgu.CV.Extern\video\kalmanfilter_property.au3"
#include "Emgu.CV.Extern\video\variational_refinement_property.au3"
#include "Emgu.CV.Extern\video\video_c.au3"
#include "Emgu.CV.Extern\videoio\videoio_c_extra.au3"
#include "Emgu.CV.Extern\videoio\video_capture_property.au3"
#include "Emgu.CV.Extern\videostab\videostab_c.au3"
#include "Emgu.CV.Extern\viz\viz_c.au3"
#include "Emgu.CV.Extern\wechat_qrcode\wechat_qrcode_c.au3"
#include "Emgu.CV.Extern\xfeatures2d\nonfree_c.au3"
#include "Emgu.CV.Extern\xfeatures2d\pct_compute_signature_property.au3"
#include "Emgu.CV.Extern\xfeatures2d\xfeatures2d_c.au3"
#include "Emgu.CV.Extern\ximgproc\ximgproc_c.au3"
#include "Emgu.CV.Extern\xobjdetect\xobjdetect_c.au3"
#include "Emgu.CV.Extern\xphoto\grayworldwb_property.au3"
#include "Emgu.CV.Extern\xphoto\learningbasedwb_property.au3"
#include "Emgu.CV.Extern\xphoto\simplewb_property.au3"
#include "Emgu.CV.Extern\xphoto\TonemapDurand_property.au3"
#include "Emgu.CV.Extern\xphoto\xphoto_c.au3"
#include "Emgu.CV.Extern\zlibCompression.au3"