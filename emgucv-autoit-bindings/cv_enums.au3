#include-once
#include "cv_interface.au3"

#Region ..\opencv\modules\calib3d\include\opencv2\calib3d.hpp
; anonymous
Global Const $CV_LMEDS = 4
Global Const $CV_RANSAC = 8
Global Const $CV_RHO = 16
Global Const $CV_USAC_DEFAULT = 32
Global Const $CV_USAC_PARALLEL = 33
Global Const $CV_USAC_FM_8PTS = 34
Global Const $CV_USAC_FAST = 35
Global Const $CV_USAC_ACCURATE = 36
Global Const $CV_USAC_PROSAC = 37
Global Const $CV_USAC_MAGSAC = 38
Global Const $CV_CALIB_CB_ADAPTIVE_THRESH = 1
Global Const $CV_CALIB_CB_NORMALIZE_IMAGE = 2
Global Const $CV_CALIB_CB_FILTER_QUADS = 4
Global Const $CV_CALIB_CB_FAST_CHECK = 8
Global Const $CV_CALIB_CB_EXHAUSTIVE = 16
Global Const $CV_CALIB_CB_ACCURACY = 32
Global Const $CV_CALIB_CB_LARGER = 64
Global Const $CV_CALIB_CB_MARKER = 128
Global Const $CV_CALIB_CB_SYMMETRIC_GRID = 1
Global Const $CV_CALIB_CB_ASYMMETRIC_GRID = 2
Global Const $CV_CALIB_CB_CLUSTERING = 4
Global Const $CV_CALIB_NINTRINSIC = 18
Global Const $CV_CALIB_USE_INTRINSIC_GUESS = 0x00001
Global Const $CV_CALIB_FIX_ASPECT_RATIO = 0x00002
Global Const $CV_CALIB_FIX_PRINCIPAL_POINT = 0x00004
Global Const $CV_CALIB_ZERO_TANGENT_DIST = 0x00008
Global Const $CV_CALIB_FIX_FOCAL_LENGTH = 0x00010
Global Const $CV_CALIB_FIX_K1 = 0x00020
Global Const $CV_CALIB_FIX_K2 = 0x00040
Global Const $CV_CALIB_FIX_K3 = 0x00080
Global Const $CV_CALIB_FIX_K4 = 0x00800
Global Const $CV_CALIB_FIX_K5 = 0x01000
Global Const $CV_CALIB_FIX_K6 = 0x02000
Global Const $CV_CALIB_RATIONAL_MODEL = 0x04000
Global Const $CV_CALIB_THIN_PRISM_MODEL = 0x08000
Global Const $CV_CALIB_FIX_S1_S2_S3_S4 = 0x10000
Global Const $CV_CALIB_TILTED_MODEL = 0x40000
Global Const $CV_CALIB_FIX_TAUX_TAUY = 0x80000
Global Const $CV_CALIB_USE_QR = 0x100000
Global Const $CV_CALIB_FIX_TANGENT_DIST = 0x200000
Global Const $CV_CALIB_FIX_INTRINSIC = 0x00100
Global Const $CV_CALIB_SAME_FOCAL_LENGTH = 0x00200
Global Const $CV_CALIB_ZERO_DISPARITY = 0x00400
Global Const $CV_CALIB_USE_LU = (BitShift(1, -17))
Global Const $CV_CALIB_USE_EXTRINSIC_GUESS = (BitShift(1, -22))
Global Const $CV_FM_7POINT = 1
Global Const $CV_FM_8POINT = 2
Global Const $CV_FM_LMEDS = 4
Global Const $CV_FM_RANSAC = 8

; SolvePnPMethod
Global Const $CV_SOLVEPNP_ITERATIVE = 0
Global Const $CV_SOLVEPNP_EPNP = 1
Global Const $CV_SOLVEPNP_P3P = 2
Global Const $CV_SOLVEPNP_DLS = 3
Global Const $CV_SOLVEPNP_UPNP = 4
Global Const $CV_SOLVEPNP_AP3P = 5
Global Const $CV_SOLVEPNP_IPPE = 6
Global Const $CV_SOLVEPNP_IPPE_SQUARE = 7
Global Const $CV_SOLVEPNP_SQPNP = 8

; HandEyeCalibrationMethod
Global Const $CV_CALIB_HAND_EYE_TSAI = 0
Global Const $CV_CALIB_HAND_EYE_PARK = 1
Global Const $CV_CALIB_HAND_EYE_HORAUD = 2
Global Const $CV_CALIB_HAND_EYE_ANDREFF = 3
Global Const $CV_CALIB_HAND_EYE_DANIILIDIS = 4

; RobotWorldHandEyeCalibrationMethod
Global Const $CV_CALIB_ROBOT_WORLD_HAND_EYE_SHAH = 0
Global Const $CV_CALIB_ROBOT_WORLD_HAND_EYE_LI = 1

; SamplingMethod
Global Const $CV_SAMPLING_UNIFORM = 0
Global Const $CV_SAMPLING_PROGRESSIVE_NAPSAC = 1
Global Const $CV_SAMPLING_NAPSAC = 2
Global Const $CV_SAMPLING_PROSAC = 3

; LocalOptimMethod
Global Const $CV_LOCAL_OPTIM_NULL = 0
Global Const $CV_LOCAL_OPTIM_INNER_LO = 1
Global Const $CV_LOCAL_OPTIM_INNER_AND_ITER_LO = 2
Global Const $CV_LOCAL_OPTIM_GC = 3
Global Const $CV_LOCAL_OPTIM_SIGMA = 4

; ScoreMethod
Global Const $CV_SCORE_METHOD_RANSAC = 0
Global Const $CV_SCORE_METHOD_MSAC = 1
Global Const $CV_SCORE_METHOD_MAGSAC = 2
Global Const $CV_SCORE_METHOD_LMEDS = 3

; NeighborSearchMethod
Global Const $CV_NEIGH_FLANN_KNN = 0
Global Const $CV_NEIGH_GRID = 1
Global Const $CV_NEIGH_FLANN_RADIUS = 2

; anonymous
Global Const $CV_STEREO_MATCHER_DISP_SHIFT = 4
Global Const $CV_STEREO_MATCHER_DISP_SCALE = (BitShift(1, -$CV_STEREO_MATCHER_DISP_SHIFT))

; anonymous
Global Const $CV_STEREO_BM_PREFILTER_NORMALIZED_RESPONSE = 0
Global Const $CV_STEREO_BM_PREFILTER_XSOBEL = 1

; anonymous
Global Const $CV_STEREO_SGBM_MODE_SGBM = 0
Global Const $CV_STEREO_SGBM_MODE_HH = 1
Global Const $CV_STEREO_SGBM_MODE_SGBM_3WAY = 2
Global Const $CV_STEREO_SGBM_MODE_HH4 = 3

; UndistortTypes
Global Const $CV_PROJ_SPHERICAL_ORTHO = 0
Global Const $CV_PROJ_SPHERICAL_EQRECT = 1

; anonymous

Global Const $CV_CALIB_RECOMPUTE_EXTRINSIC = (BitShift(1, -1))
Global Const $CV_CALIB_CHECK_COND = (BitShift(1, -2))
Global Const $CV_CALIB_FIX_SKEW = (BitShift(1, -3))
#EndRegion ..\opencv\modules\calib3d\include\opencv2\calib3d.hpp



#Region ..\opencv\modules\calib3d\include\opencv2\calib3d\calib3d_c.h
; anonymous
Global Const $_CV_CV_LEV_MARQ_DONE = 0
Global Const $_CV_CV_LEV_MARQ_STARTED = 1
Global Const $_CV_CV_LEV_MARQ_CALC_J = 2
Global Const $_CV_CV_LEV_MARQ_CHECK_ERR = 3
#EndRegion ..\opencv\modules\calib3d\include\opencv2\calib3d\calib3d_c.h



#Region ..\opencv\modules\core\include\opencv2\core.hpp
; SortFlags
Global Const $CV_SORT_EVERY_ROW = 0
Global Const $CV_SORT_EVERY_COLUMN = 1
Global Const $CV_SORT_ASCENDING = 0
Global Const $CV_SORT_DESCENDING = 16

; CovarFlags
Global Const $CV_COVAR_SCRAMBLED = 0
Global Const $CV_COVAR_NORMAL = 1
Global Const $CV_COVAR_USE_AVG = 2
Global Const $CV_COVAR_SCALE = 4
Global Const $CV_COVAR_ROWS = 8
Global Const $CV_COVAR_COLS = 16

; KmeansFlags
Global Const $CV_KMEANS_RANDOM_CENTERS = 0
Global Const $CV_KMEANS_PP_CENTERS = 2
Global Const $CV_KMEANS_USE_INITIAL_LABELS = 1

; ReduceTypes
Global Const $CV_REDUCE_SUM = 0
Global Const $CV_REDUCE_AVG = 1
Global Const $CV_REDUCE_MAX = 2
Global Const $CV_REDUCE_MIN = 3

; RotateFlags
Global Const $CV_ROTATE_90_CLOCKWISE = 0
Global Const $CV_ROTATE_180 = 1
Global Const $CV_ROTATE_90_COUNTERCLOCKWISE = 2

; Flags
Global Const $CV_PCA_DATA_AS_ROW = 0
Global Const $CV_PCA_DATA_AS_COL = 1
Global Const $CV_PCA_USE_AVG = 2

; Flags
Global Const $CV_SVD_MODIFY_A = 1
Global Const $CV_SVD_NO_UV = 2
Global Const $CV_SVD_FULL_UV = 4

; anonymous
Global Const $CV_RNG_UNIFORM = 0
Global Const $CV_RNG_NORMAL = 1

; PeriodParameters
Global Const $CV_RNG_MT19937_N = 624
Global Const $CV_RNG_MT19937_M = 397

; FormatType
Global Const $CV_FORMATTER_FMT_DEFAULT = 0
Global Const $CV_FORMATTER_FMT_MATLAB = 1
Global Const $CV_FORMATTER_FMT_CSV = 2
Global Const $CV_FORMATTER_FMT_PYTHON = 3
Global Const $CV_FORMATTER_FMT_NUMPY = 4
Global Const $CV_FORMATTER_FMT_C = 5

; anonymous
Global Const $CV_PARAM_INT = 0
Global Const $CV_PARAM_BOOLEAN = 1
Global Const $CV_PARAM_REAL = 2
Global Const $CV_PARAM_STRING = 3
Global Const $CV_PARAM_MAT = 4
Global Const $CV_PARAM_MAT_VECTOR = 5
Global Const $CV_PARAM_ALGORITHM = 6
Global Const $CV_PARAM_FLOAT = 7
Global Const $CV_PARAM_UNSIGNED_INT = 8
Global Const $CV_PARAM_UINT64 = 9
Global Const $CV_PARAM_UCHAR = 11
Global Const $CV_PARAM_SCALAR = 12
#EndRegion ..\opencv\modules\core\include\opencv2\core.hpp



#Region ..\opencv\modules\core\include\opencv2\core\base.hpp
; Code
Global Const $CV_ERROR_StsOk = 0
Global Const $CV_ERROR_StsBackTrace = -1
Global Const $CV_ERROR_StsError = -2
Global Const $CV_ERROR_StsInternal = -3
Global Const $CV_ERROR_StsNoMem = -4
Global Const $CV_ERROR_StsBadArg = -5
Global Const $CV_ERROR_StsBadFunc = -6
Global Const $CV_ERROR_StsNoConv = -7
Global Const $CV_ERROR_StsAutoTrace = -8
Global Const $CV_ERROR_HeaderIsNull = -9
Global Const $CV_ERROR_BadImageSize = -10
Global Const $CV_ERROR_BadOffset = -11
Global Const $CV_ERROR_BadDataPtr = -12
Global Const $CV_ERROR_BadStep = -13
Global Const $CV_ERROR_BadModelOrChSeq = -14
Global Const $CV_ERROR_BadNumChannels = -15
Global Const $CV_ERROR_BadNumChannel1U = -16
Global Const $CV_ERROR_BadDepth = -17
Global Const $CV_ERROR_BadAlphaChannel = -18
Global Const $CV_ERROR_BadOrder = -19
Global Const $CV_ERROR_BadOrigin = -20
Global Const $CV_ERROR_BadAlign = -21
Global Const $CV_ERROR_BadCallBack = -22
Global Const $CV_ERROR_BadTileSize = -23
Global Const $CV_ERROR_BadCOI = -24
Global Const $CV_ERROR_BadROISize = -25
Global Const $CV_ERROR_MaskIsTiled = -26
Global Const $CV_ERROR_StsNullPtr = -27
Global Const $CV_ERROR_StsVecLengthErr = -28
Global Const $CV_ERROR_StsFilterStructContentErr = -29
Global Const $CV_ERROR_StsKernelStructContentErr = -30
Global Const $CV_ERROR_StsFilterOffsetErr = -31
Global Const $CV_ERROR_StsBadSize = -201
Global Const $CV_ERROR_StsDivByZero = -202
Global Const $CV_ERROR_StsInplaceNotSupported = -203
Global Const $CV_ERROR_StsObjectNotFound = -204
Global Const $CV_ERROR_StsUnmatchedFormats = -205
Global Const $CV_ERROR_StsBadFlag = -206
Global Const $CV_ERROR_StsBadPoint = -207
Global Const $CV_ERROR_StsBadMask = -208
Global Const $CV_ERROR_StsUnmatchedSizes = -209
Global Const $CV_ERROR_StsUnsupportedFormat = -210
Global Const $CV_ERROR_StsOutOfRange = -211
Global Const $CV_ERROR_StsParseError = -212
Global Const $CV_ERROR_StsNotImplemented = -213
Global Const $CV_ERROR_StsBadMemBlock = -214
Global Const $CV_ERROR_StsAssert = -215
Global Const $CV_ERROR_GpuNotSupported = -216
Global Const $CV_ERROR_GpuApiCallError = -217
Global Const $CV_ERROR_OpenGlNotSupported = -218
Global Const $CV_ERROR_OpenGlApiCallError = -219
Global Const $CV_ERROR_OpenCLApiCallError = -220
Global Const $CV_ERROR_OpenCLDoubleNotSupported = -221
Global Const $CV_ERROR_OpenCLInitError = -222
Global Const $CV_ERROR_OpenCLNoAMDBlasFft = -223

; DecompTypes
Global Const $CV_DECOMP_LU = 0
Global Const $CV_DECOMP_SVD = 1
Global Const $CV_DECOMP_EIG = 2
Global Const $CV_DECOMP_CHOLESKY = 3
Global Const $CV_DECOMP_QR = 4
Global Const $CV_DECOMP_NORMAL = 16

; NormTypes
Global Const $CV_NORM_INF = 1
Global Const $CV_NORM_L1 = 2
Global Const $CV_NORM_L2 = 4
Global Const $CV_NORM_L2SQR = 5
Global Const $CV_NORM_HAMMING = 6
Global Const $CV_NORM_HAMMING2 = 7
Global Const $CV_NORM_TYPE_MASK = 7
Global Const $CV_NORM_RELATIVE = 8
Global Const $CV_NORM_MINMAX = 32

; CmpTypes
Global Const $CV_CMP_EQ = 0
Global Const $CV_CMP_GT = 1
Global Const $CV_CMP_GE = 2
Global Const $CV_CMP_LT = 3
Global Const $CV_CMP_LE = 4
Global Const $CV_CMP_NE = 5

; GemmFlags
Global Const $CV_GEMM_1_T = 1
Global Const $CV_GEMM_2_T = 2
Global Const $CV_GEMM_3_T = 4

; DftFlags
Global Const $CV_DFT_INVERSE = 1
Global Const $CV_DFT_SCALE = 2
Global Const $CV_DFT_ROWS = 4
Global Const $CV_DFT_COMPLEX_OUTPUT = 16
Global Const $CV_DFT_REAL_OUTPUT = 32
Global Const $CV_DFT_COMPLEX_INPUT = 64
Global Const $CV_DCT_INVERSE = $CV_DFT_INVERSE
Global Const $CV_DCT_ROWS = $CV_DFT_ROWS

; BorderTypes
Global Const $CV_BORDER_CONSTANT = 0
Global Const $CV_BORDER_REPLICATE = 1
Global Const $CV_BORDER_REFLECT = 2
Global Const $CV_BORDER_WRAP = 3
Global Const $CV_BORDER_REFLECT_101 = 4
Global Const $CV_BORDER_TRANSPARENT = 5
Global Const $CV_BORDER_REFLECT101 = $CV_BORDER_REFLECT_101
Global Const $CV_BORDER_DEFAULT = $CV_BORDER_REFLECT_101
Global Const $CV_BORDER_ISOLATED = 16
#EndRegion ..\opencv\modules\core\include\opencv2\core\base.hpp



#Region ..\opencv\modules\core\include\opencv2\core\cuda.hpp
; AllocType
Global Const $CV_HOST_MEM_PAGE_LOCKED = 1
Global Const $CV_HOST_MEM_SHARED = 2
Global Const $CV_HOST_MEM_WRITE_COMBINED = 4

; CreateFlags
Global Const $CV_EVENT_DEFAULT = 0x00
Global Const $CV_EVENT_BLOCKING_SYNC = 0x01
Global Const $CV_EVENT_DISABLE_TIMING = 0x02
Global Const $CV_EVENT_INTERPROCESS = 0x04

; FeatureSet
Global Const $CV_FEATURE_SET_COMPUTE_10 = 10
Global Const $CV_FEATURE_SET_COMPUTE_11 = 11
Global Const $CV_FEATURE_SET_COMPUTE_12 = 12
Global Const $CV_FEATURE_SET_COMPUTE_13 = 13
Global Const $CV_FEATURE_SET_COMPUTE_20 = 20
Global Const $CV_FEATURE_SET_COMPUTE_21 = 21
Global Const $CV_FEATURE_SET_COMPUTE_30 = 30
Global Const $CV_FEATURE_SET_COMPUTE_32 = 32
Global Const $CV_FEATURE_SET_COMPUTE_35 = 35
Global Const $CV_FEATURE_SET_COMPUTE_50 = 50
Global Const $CV_GLOBAL_ATOMICS = $CV_FEATURE_SET_COMPUTE_11
Global Const $CV_SHARED_ATOMICS = $CV_FEATURE_SET_COMPUTE_12
Global Const $CV_NATIVE_DOUBLE = $CV_FEATURE_SET_COMPUTE_13
Global Const $CV_WARP_SHUFFLE_FUNCTIONS = $CV_FEATURE_SET_COMPUTE_30
Global Const $CV_DYNAMIC_PARALLELISM = $CV_FEATURE_SET_COMPUTE_35

; ComputeMode
Global Const $CV_DEVICE_INFO_ComputeModeDefault = 0
Global Const $CV_DEVICE_INFO_ComputeModeExclusive = 1
Global Const $CV_DEVICE_INFO_ComputeModeProhibited = 2
Global Const $CV_DEVICE_INFO_ComputeModeExclusiveProcess = 3
#EndRegion ..\opencv\modules\core\include\opencv2\core\cuda.hpp



#Region ..\opencv\modules\core\include\opencv2\core\hal\intrin.hpp
; StoreMode
Global Const $_CV_STORE_UNALIGNED = 0
Global Const $_CV_STORE_ALIGNED = 1
Global Const $_CV_STORE_ALIGNED_NOCACHE = 2
#EndRegion ..\opencv\modules\core\include\opencv2\core\hal\intrin.hpp



#Region ..\opencv\modules\core\include\opencv2\core\mat.hpp
; AccessFlag
Global Const $CV_ACCESS_READ = (BitShift(1, -24))
Global Const $CV_ACCESS_WRITE = (BitShift(1, -25))
Global Const $CV_ACCESS_RW = (BitShift(3, -24))
Global Const $CV_ACCESS_MASK = $CV_ACCESS_RW
Global Const $CV_ACCESS_FAST = (BitShift(1, -26))

; KindFlag
Global Const $CV__INPUT_ARRAY_KIND_SHIFT = 16
Global Const $CV__INPUT_ARRAY_FIXED_TYPE = (BitShift(0x8000, -$CV__INPUT_ARRAY_KIND_SHIFT))
Global Const $CV__INPUT_ARRAY_FIXED_SIZE = (BitShift(0x4000, -$CV__INPUT_ARRAY_KIND_SHIFT))
Global Const $CV__INPUT_ARRAY_KIND_MASK = (BitShift(31, -$CV__INPUT_ARRAY_KIND_SHIFT))
Global Const $CV__INPUT_ARRAY_NONE = (BitShift(0, -$CV__INPUT_ARRAY_KIND_SHIFT))
Global Const $CV__INPUT_ARRAY_MAT = (BitShift(1, -$CV__INPUT_ARRAY_KIND_SHIFT))
Global Const $CV__INPUT_ARRAY_MATX = (BitShift(2, -$CV__INPUT_ARRAY_KIND_SHIFT))
Global Const $CV__INPUT_ARRAY_STD_VECTOR = (BitShift(3, -$CV__INPUT_ARRAY_KIND_SHIFT))
Global Const $CV__INPUT_ARRAY_STD_VECTOR_VECTOR = (BitShift(4, -$CV__INPUT_ARRAY_KIND_SHIFT))
Global Const $CV__INPUT_ARRAY_STD_VECTOR_MAT = (BitShift(5, -$CV__INPUT_ARRAY_KIND_SHIFT))
Global Const $CV__INPUT_ARRAY_OPENGL_BUFFER = (BitShift(7, -$CV__INPUT_ARRAY_KIND_SHIFT))
Global Const $CV__INPUT_ARRAY_CUDA_HOST_MEM = (BitShift(8, -$CV__INPUT_ARRAY_KIND_SHIFT))
Global Const $CV__INPUT_ARRAY_CUDA_GPU_MAT = (BitShift(9, -$CV__INPUT_ARRAY_KIND_SHIFT))
Global Const $CV__INPUT_ARRAY_UMAT = (BitShift(10, -$CV__INPUT_ARRAY_KIND_SHIFT))
Global Const $CV__INPUT_ARRAY_STD_VECTOR_UMAT = (BitShift(11, -$CV__INPUT_ARRAY_KIND_SHIFT))
Global Const $CV__INPUT_ARRAY_STD_BOOL_VECTOR = (BitShift(12, -$CV__INPUT_ARRAY_KIND_SHIFT))
Global Const $CV__INPUT_ARRAY_STD_VECTOR_CUDA_GPU_MAT = (BitShift(13, -$CV__INPUT_ARRAY_KIND_SHIFT))
Global Const $CV__INPUT_ARRAY_STD_ARRAY_MAT = (BitShift(15, -$CV__INPUT_ARRAY_KIND_SHIFT))

; DepthMask
Global Const $CV__OUTPUT_ARRAY_DEPTH_MASK_8U = (BitShift(1, -$CV_8U))
Global Const $CV__OUTPUT_ARRAY_DEPTH_MASK_8S = (BitShift(1, -$CV_8S))
Global Const $CV__OUTPUT_ARRAY_DEPTH_MASK_16U = (BitShift(1, -$CV_16U))
Global Const $CV__OUTPUT_ARRAY_DEPTH_MASK_16S = (BitShift(1, -$CV_16S))
Global Const $CV__OUTPUT_ARRAY_DEPTH_MASK_32S = (BitShift(1, -$CV_32S))
Global Const $CV__OUTPUT_ARRAY_DEPTH_MASK_32F = (BitShift(1, -$CV_32F))
Global Const $CV__OUTPUT_ARRAY_DEPTH_MASK_64F = (BitShift(1, -$CV_64F))
Global Const $CV__OUTPUT_ARRAY_DEPTH_MASK_16F = (BitShift(1, -$CV_16F))
Global Const $CV__OUTPUT_ARRAY_DEPTH_MASK_ALL = (BitShift($CV__OUTPUT_ARRAY_DEPTH_MASK_64F, -1))-1
Global Const $CV__OUTPUT_ARRAY_DEPTH_MASK_ALL_BUT_8S = (BitAND($CV__OUTPUT_ARRAY_DEPTH_MASK_ALL, (BitNOT($CV__OUTPUT_ARRAY_DEPTH_MASK_8S))))
Global Const $CV__OUTPUT_ARRAY_DEPTH_MASK_ALL_16F = (BitShift($CV__OUTPUT_ARRAY_DEPTH_MASK_16F, -1))-1
Global Const $CV__OUTPUT_ARRAY_DEPTH_MASK_FLT = $CV__OUTPUT_ARRAY_DEPTH_MASK_32F + $CV__OUTPUT_ARRAY_DEPTH_MASK_64F

; UMatUsageFlags
Global Const $CV_USAGE_DEFAULT = 0
Global Const $CV_USAGE_ALLOCATE_HOST_MEMORY = (BitShift(1, -0))
Global Const $CV_USAGE_ALLOCATE_DEVICE_MEMORY = (BitShift(1, -1))
Global Const $CV_USAGE_ALLOCATE_SHARED_MEMORY = (BitShift(1, -2))
Global Const $CV___UMAT_USAGE_FLAGS_32BIT = 0x7fffffff

; anonymous
Global Const $CV_MAT_MAGIC_VAL = 0x42FF0000
Global Const $CV_MAT_AUTO_STEP = 0
Global Const $CV_MAT_CONTINUOUS_FLAG = $CV_MAT_CONT_FLAG
Global Const $CV_MAT_SUBMATRIX_FLAG = $CV_SUBMAT_FLAG
Global Const $CV_MAT_MAGIC_MASK = 0xFFFF0000



; anonymous
Global Const $CV_UMAT_MAGIC_VAL = 0x42FF0000
Global Const $CV_UMAT_AUTO_STEP = 0
Global Const $CV_UMAT_CONTINUOUS_FLAG = $CV_MAT_CONT_FLAG
Global Const $CV_UMAT_SUBMATRIX_FLAG = $CV_SUBMAT_FLAG
Global Const $CV_UMAT_MAGIC_MASK = 0xFFFF0000
Global Const $CV_UMAT_TYPE_MASK = 0x00000FFF
Global Const $CV_UMAT_DEPTH_MASK = 7

; anonymous
Global Const $CV_SPARSE_MAT_MAGIC_VAL = 0x42FD0000
Global Const $CV_SPARSE_MAT_MAX_DIM = 32
Global Const $CV_SPARSE_MAT_HASH_SCALE = 0x5bd1e995
Global Const $CV_SPARSE_MAT_HASH_BIT = 0x80000000
#EndRegion ..\opencv\modules\core\include\opencv2\core\mat.hpp



#Region ..\opencv\modules\core\include\opencv2\core\ocl.hpp
; anonymous
Global Const $CV_DEVICE_TYPE_DEFAULT = (BitShift(1, -0))
Global Const $CV_DEVICE_TYPE_CPU = (BitShift(1, -1))
Global Const $CV_DEVICE_TYPE_GPU = (BitShift(1, -2))
Global Const $CV_DEVICE_TYPE_ACCELERATOR = (BitShift(1, -3))
Global Const $CV_DEVICE_TYPE_DGPU = $CV_DEVICE_TYPE_GPU + (BitShift(1, -16))
Global Const $CV_DEVICE_TYPE_IGPU = $CV_DEVICE_TYPE_GPU + (BitShift(1, -17))
Global Const $CV_DEVICE_TYPE_ALL = 0xFFFFFFFF
Global Const $CV_DEVICE_FP_DENORM = (BitShift(1, -0))
Global Const $CV_DEVICE_FP_INF_NAN = (BitShift(1, -1))
Global Const $CV_DEVICE_FP_ROUND_TO_NEAREST = (BitShift(1, -2))
Global Const $CV_DEVICE_FP_ROUND_TO_ZERO = (BitShift(1, -3))
Global Const $CV_DEVICE_FP_ROUND_TO_INF = (BitShift(1, -4))
Global Const $CV_DEVICE_FP_FMA = (BitShift(1, -5))
Global Const $CV_DEVICE_FP_SOFT_FLOAT = (BitShift(1, -6))
Global Const $CV_DEVICE_FP_CORRECTLY_ROUNDED_DIVIDE_SQRT = (BitShift(1, -7))
Global Const $CV_DEVICE_EXEC_KERNEL = (BitShift(1, -0))
Global Const $CV_DEVICE_EXEC_NATIVE_KERNEL = (BitShift(1, -1))
Global Const $CV_DEVICE_NO_CACHE = 0
Global Const $CV_DEVICE_READ_ONLY_CACHE = 1
Global Const $CV_DEVICE_READ_WRITE_CACHE = 2
Global Const $CV_DEVICE_NO_LOCAL_MEM = 0
Global Const $CV_DEVICE_LOCAL_IS_LOCAL = 1
Global Const $CV_DEVICE_LOCAL_IS_GLOBAL = 2
Global Const $CV_DEVICE_UNKNOWN_VENDOR = 0
Global Const $CV_DEVICE_VENDOR_AMD = 1
Global Const $CV_DEVICE_VENDOR_INTEL = 2
Global Const $CV_DEVICE_VENDOR_NVIDIA = 3

; anonymous
Global Const $CV_KERNEL_ARG_LOCAL = 1
Global Const $CV_KERNEL_ARG_READ_ONLY = 2
Global Const $CV_KERNEL_ARG_WRITE_ONLY = 4
Global Const $CV_KERNEL_ARG_READ_WRITE = 6
Global Const $CV_KERNEL_ARG_CONSTANT = 8
Global Const $CV_KERNEL_ARG_PTR_ONLY = 16
Global Const $CV_KERNEL_ARG_NO_SIZE = 256

; OclVectorStrategy
Global Const $CV_OCL_VECTOR_OWN = 0
Global Const $CV_OCL_VECTOR_MAX = 1
Global Const $CV_OCL_VECTOR_DEFAULT = $CV_OCL_VECTOR_OWN
#EndRegion ..\opencv\modules\core\include\opencv2\core\ocl.hpp



#Region ..\opencv\modules\core\include\opencv2\core\opengl.hpp
; Target
Global Const $CV_BUFFER_ARRAY_BUFFER = 0x8892
Global Const $CV_BUFFER_ELEMENT_ARRAY_BUFFER = 0x8893
Global Const $CV_BUFFER_PIXEL_PACK_BUFFER = 0x88EB
Global Const $CV_BUFFER_PIXEL_UNPACK_BUFFER = 0x88EC

; Access
Global Const $CV_BUFFER_READ_ONLY = 0x88B8
Global Const $CV_BUFFER_WRITE_ONLY = 0x88B9
Global Const $CV_BUFFER_READ_WRITE = 0x88BA

; Format
Global Const $CV_TEXTURE2D_NONE = 0
Global Const $CV_TEXTURE2D_DEPTH_COMPONENT = 0x1902
Global Const $CV_TEXTURE2D_RGB = 0x1907
Global Const $CV_TEXTURE2D_RGBA = 0x1908

; RenderModes
Global Const $CV_POINTS = 0x0000
Global Const $CV_LINES = 0x0001
Global Const $CV_LINE_LOOP = 0x0002
Global Const $CV_LINE_STRIP = 0x0003
Global Const $CV_TRIANGLES = 0x0004
Global Const $CV_TRIANGLE_STRIP = 0x0005
Global Const $CV_TRIANGLE_FAN = 0x0006
Global Const $CV_QUADS = 0x0007
Global Const $CV_QUAD_STRIP = 0x0008
Global Const $CV_POLYGON = 0x0009
#EndRegion ..\opencv\modules\core\include\opencv2\core\opengl.hpp



#Region ..\opencv\modules\core\include\opencv2\core\optim.hpp
; SolveLPResult
Global Const $CV_SOLVELP_UNBOUNDED = -2
Global Const $CV_SOLVELP_UNFEASIBLE = -1
Global Const $CV_SOLVELP_SINGLE = 0
Global Const $CV_SOLVELP_MULTI = 1
#EndRegion ..\opencv\modules\core\include\opencv2\core\optim.hpp



#Region ..\opencv\modules\core\include\opencv2\core\persistence.hpp
; Mode
Global Const $CV_FILE_STORAGE_READ = 0
Global Const $CV_FILE_STORAGE_WRITE = 1
Global Const $CV_FILE_STORAGE_APPEND = 2
Global Const $CV_FILE_STORAGE_MEMORY = 4
Global Const $CV_FILE_STORAGE_FORMAT_MASK = (BitShift(7, -3))
Global Const $CV_FILE_STORAGE_FORMAT_AUTO = 0
Global Const $CV_FILE_STORAGE_FORMAT_XML = (BitShift(1, -3))
Global Const $CV_FILE_STORAGE_FORMAT_YAML = (BitShift(2, -3))
Global Const $CV_FILE_STORAGE_FORMAT_JSON = (BitShift(3, -3))
Global Const $CV_FILE_STORAGE_BASE64 = 64
Global Const $CV_FILE_STORAGE_WRITE_BASE64 = (BitOR($CV_FILE_STORAGE_BASE64, $CV_FILE_STORAGE_WRITE))

; State
Global Const $CV_FILE_STORAGE_UNDEFINED = 0
Global Const $CV_FILE_STORAGE_VALUE_EXPECTED = 1
Global Const $CV_FILE_STORAGE_NAME_EXPECTED = 2
Global Const $CV_FILE_STORAGE_INSIDE_MAP = 4

; anonymous
Global Const $CV_FILE_NODE_NONE = 0
Global Const $CV_FILE_NODE_INT = 1
Global Const $CV_FILE_NODE_REAL = 2
Global Const $CV_FILE_NODE_FLOAT = $CV_FILE_NODE_REAL
Global Const $CV_FILE_NODE_STR = 3
Global Const $CV_FILE_NODE_STRING = $CV_FILE_NODE_STR
Global Const $CV_FILE_NODE_SEQ = 4
Global Const $CV_FILE_NODE_MAP = 5
Global Const $CV_FILE_NODE_TYPE_MASK = 7
Global Const $CV_FILE_NODE_FLOW = 8
Global Const $CV_FILE_NODE_UNIFORM = 8
Global Const $CV_FILE_NODE_EMPTY = 16
Global Const $CV_FILE_NODE_NAMED = 32
#EndRegion ..\opencv\modules\core\include\opencv2\core\persistence.hpp



#Region ..\opencv\modules\core\include\opencv2\core\quaternion.hpp
; QuatAssumeType
Global Const $CV_QUAT_ASSUME_NOT_UNIT = 0
Global Const $CV_QUAT_ASSUME_UNIT = 1

; EulerAnglesType
Global Const $CV_QUAT_ENUM_INT_XYZ = 0
Global Const $CV_QUAT_ENUM_INT_XZY = 1
Global Const $CV_QUAT_ENUM_INT_YXZ = 2
Global Const $CV_QUAT_ENUM_INT_YZX = 3
Global Const $CV_QUAT_ENUM_INT_ZXY = 4
Global Const $CV_QUAT_ENUM_INT_ZYX = 5
Global Const $CV_QUAT_ENUM_INT_XYX = 6
Global Const $CV_QUAT_ENUM_INT_XZX = 7
Global Const $CV_QUAT_ENUM_INT_YXY = 8
Global Const $CV_QUAT_ENUM_INT_YZY = 9
Global Const $CV_QUAT_ENUM_INT_ZXZ = 10
Global Const $CV_QUAT_ENUM_INT_ZYZ = 11
Global Const $CV_QUAT_ENUM_EXT_XYZ = 12
Global Const $CV_QUAT_ENUM_EXT_XZY = 13
Global Const $CV_QUAT_ENUM_EXT_YXZ = 14
Global Const $CV_QUAT_ENUM_EXT_YZX = 15
Global Const $CV_QUAT_ENUM_EXT_ZXY = 16
Global Const $CV_QUAT_ENUM_EXT_ZYX = 17
Global Const $CV_QUAT_ENUM_EXT_XYX = 18
Global Const $CV_QUAT_ENUM_EXT_XZX = 19
Global Const $CV_QUAT_ENUM_EXT_YXY = 20
Global Const $CV_QUAT_ENUM_EXT_YZY = 21
Global Const $CV_QUAT_ENUM_EXT_ZXZ = 22
Global Const $CV_QUAT_ENUM_EXT_ZYZ = 23
#EndRegion ..\opencv\modules\core\include\opencv2\core\quaternion.hpp



#Region ..\opencv\modules\core\include\opencv2\core\types.hpp
; Type
Global Const $CV_TERM_CRITERIA_COUNT = 1
Global Const $CV_TERM_CRITERIA_MAX_ITER = $CV_TERM_CRITERIA_COUNT
Global Const $CV_TERM_CRITERIA_EPS = 2
#EndRegion ..\opencv\modules\core\include\opencv2\core\types.hpp



#Region ..\opencv\modules\dnn\include\opencv2\dnn\dnn.hpp
; Backend
Global Const $CV_DNN_BACKEND_DEFAULT = 0
Global Const $CV_DNN_BACKEND_HALIDE = 1
Global Const $CV_DNN_BACKEND_INFERENCE_ENGINE = 2
Global Const $CV_DNN_BACKEND_OPENCV = 3
Global Const $CV_DNN_BACKEND_VKCOM = 4
Global Const $CV_DNN_BACKEND_CUDA = 5

; Target
Global Const $CV_DNN_TARGET_CPU = 0
Global Const $CV_DNN_TARGET_OPENCL = 1
Global Const $CV_DNN_TARGET_OPENCL_FP16 = 2
Global Const $CV_DNN_TARGET_MYRIAD = 3
Global Const $CV_DNN_TARGET_VULKAN = 4
Global Const $CV_DNN_TARGET_FPGA = 5
Global Const $CV_DNN_TARGET_CUDA = 6
Global Const $CV_DNN_TARGET_CUDA_FP16 = 7
Global Const $CV_DNN_TARGET_HDDL = 8
#EndRegion ..\opencv\modules\dnn\include\opencv2\dnn\dnn.hpp



#Region ..\opencv\modules\features2d\include\opencv2\features2d.hpp
; ScoreType
Global Const $CV_ORB_HARRIS_SCORE = 0
Global Const $CV_ORB_FAST_SCORE = 1

; DetectorType
Global Const $CV_FAST_FEATURE_DETECTOR_TYPE_5_8 = 0
Global Const $CV_FAST_FEATURE_DETECTOR_TYPE_7_12 = 1
Global Const $CV_FAST_FEATURE_DETECTOR_TYPE_9_16 = 2

; anonymous
Global Const $CV_FAST_FEATURE_DETECTOR_THRESHOLD = 10000
Global Const $CV_FAST_FEATURE_DETECTOR_NONMAX_SUPPRESSION = 10001
Global Const $CV_FAST_FEATURE_DETECTOR_FAST_N = 10002

; DetectorType
Global Const $CV_AGAST_FEATURE_DETECTOR_AGAST_5_8 = 0
Global Const $CV_AGAST_FEATURE_DETECTOR_AGAST_7_12d = 1
Global Const $CV_AGAST_FEATURE_DETECTOR_AGAST_7_12s = 2
Global Const $CV_AGAST_FEATURE_DETECTOR_OAST_9_16 = 3

; anonymous
Global Const $CV_AGAST_FEATURE_DETECTOR_THRESHOLD = 10000
Global Const $CV_AGAST_FEATURE_DETECTOR_NONMAX_SUPPRESSION = 10001

; DiffusivityType
Global Const $CV_KAZE_DIFF_PM_G1 = 0
Global Const $CV_KAZE_DIFF_PM_G2 = 1
Global Const $CV_KAZE_DIFF_WEICKERT = 2
Global Const $CV_KAZE_DIFF_CHARBONNIER = 3

; DescriptorType
Global Const $CV_AKAZE_DESCRIPTOR_KAZE_UPRIGHT = 2
Global Const $CV_AKAZE_DESCRIPTOR_KAZE = 3
Global Const $CV_AKAZE_DESCRIPTOR_MLDB_UPRIGHT = 4
Global Const $CV_AKAZE_DESCRIPTOR_MLDB = 5

; MatcherType
Global Const $CV_DESCRIPTOR_MATCHER_FLANNBASED = 1
Global Const $CV_DESCRIPTOR_MATCHER_BRUTEFORCE = 2
Global Const $CV_DESCRIPTOR_MATCHER_BRUTEFORCE_L1 = 3
Global Const $CV_DESCRIPTOR_MATCHER_BRUTEFORCE_HAMMING = 4
Global Const $CV_DESCRIPTOR_MATCHER_BRUTEFORCE_HAMMINGLUT = 5
Global Const $CV_DESCRIPTOR_MATCHER_BRUTEFORCE_SL2 = 6

; anonymous
Global Const $CV_DRAW_MATCHES_FLAGS_DEFAULT = 0
Global Const $CV_DRAW_MATCHES_FLAGS_DRAW_OVER_OUTIMG = 1
Global Const $CV_DRAW_MATCHES_FLAGS_NOT_DRAW_SINGLE_POINTS = 2
Global Const $CV_DRAW_MATCHES_FLAGS_DRAW_RICH_KEYPOINTS = 4
#EndRegion ..\opencv\modules\features2d\include\opencv2\features2d.hpp



#Region ..\opencv\modules\flann\include\opencv2\flann\defines.h
; flann_algorithm_t
Global Const $_CV_FLANN_INDEX_LINEAR = 0
Global Const $_CV_FLANN_INDEX_KDTREE = 1
Global Const $_CV_FLANN_INDEX_KMEANS = 2
Global Const $_CV_FLANN_INDEX_COMPOSITE = 3
Global Const $_CV_FLANN_INDEX_KDTREE_SINGLE = 4
Global Const $_CV_FLANN_INDEX_HIERARCHICAL = 5
Global Const $_CV_FLANN_INDEX_LSH = 6
Global Const $_CV_FLANN_INDEX_SAVED = 254
Global Const $_CV_FLANN_INDEX_AUTOTUNED = 255
Global Const $_CV_LINEAR = 0
Global Const $_CV_KDTREE = 1
Global Const $_CV_KMEANS = 2
Global Const $_CV_COMPOSITE = 3
Global Const $_CV_KDTREE_SINGLE = 4
Global Const $_CV_SAVED = 254
Global Const $_CV_AUTOTUNED = 255

; flann_centers_init_t
Global Const $_CV_FLANN_CENTERS_RANDOM = 0
Global Const $_CV_FLANN_CENTERS_GONZALES = 1
Global Const $_CV_FLANN_CENTERS_KMEANSPP = 2
Global Const $_CV_FLANN_CENTERS_GROUPWISE = 3
Global Const $_CV_CENTERS_RANDOM = 0
Global Const $_CV_CENTERS_GONZALES = 1
Global Const $_CV_CENTERS_KMEANSPP = 2

; flann_log_level_t
Global Const $_CV_FLANN_LOG_NONE = 0
Global Const $_CV_FLANN_LOG_FATAL = 1
Global Const $_CV_FLANN_LOG_ERROR = 2
Global Const $_CV_FLANN_LOG_WARN = 3
Global Const $_CV_FLANN_LOG_INFO = 4

; flann_distance_t
Global Const $_CV_FLANN_DIST_EUCLIDEAN = 1
Global Const $_CV_FLANN_DIST_L2 = 1
Global Const $_CV_FLANN_DIST_MANHATTAN = 2
Global Const $_CV_FLANN_DIST_L1 = 2
Global Const $_CV_FLANN_DIST_MINKOWSKI = 3
Global Const $_CV_FLANN_DIST_MAX = 4
Global Const $_CV_FLANN_DIST_HIST_INTERSECT = 5
Global Const $_CV_FLANN_DIST_HELLINGER = 6
Global Const $_CV_FLANN_DIST_CHI_SQUARE = 7
Global Const $_CV_FLANN_DIST_CS = 7
Global Const $_CV_FLANN_DIST_KULLBACK_LEIBLER = 8
Global Const $_CV_FLANN_DIST_KL = 8
Global Const $_CV_FLANN_DIST_HAMMING = 9
Global Const $_CV_FLANN_DIST_DNAMMING = 10
Global Const $_CV_EUCLIDEAN = 1
Global Const $_CV_MANHATTAN = 2
Global Const $_CV_MINKOWSKI = 3
Global Const $_CV_MAX_DIST = 4
Global Const $_CV_HIST_INTERSECT = 5
Global Const $_CV_HELLINGER = 6
Global Const $_CV_CS = 7
Global Const $_CV_KL = 8
Global Const $_CV_KULLBACK_LEIBLER = 8

; flann_datatype_t
Global Const $_CV_FLANN_INT8 = 0
Global Const $_CV_FLANN_INT16 = 1
Global Const $_CV_FLANN_INT32 = 2
Global Const $_CV_FLANN_INT64 = 3
Global Const $_CV_FLANN_UINT8 = 4
Global Const $_CV_FLANN_UINT16 = 5
Global Const $_CV_FLANN_UINT32 = 6
Global Const $_CV_FLANN_UINT64 = 7
Global Const $_CV_FLANN_FLOAT32 = 8
Global Const $_CV_FLANN_FLOAT64 = 9

; anonymous
Global Const $_CV_FLANN_CHECKS_UNLIMITED = -1
Global Const $_CV_FLANN_CHECKS_AUTOTUNED = -2
#EndRegion ..\opencv\modules\flann\include\opencv2\flann\defines.h



#Region ..\opencv\modules\flann\include\opencv2\flann\kdtree_index.h
; anonymous
Global Const $_CV_KDTREE_INDEX_SAMPLE_MEAN = 100
Global Const $_CV_KDTREE_INDEX_RAND_DIM = 5
#EndRegion ..\opencv\modules\flann\include\opencv2\flann\kdtree_index.h



#Region ..\opencv\modules\flann\include\opencv2\flann\lsh_table.h
; SpeedLevel
Global Const $_CV_LSH_TABLE_kArray = 0
Global Const $_CV_LSH_TABLE_kBitsetHash = 1
Global Const $_CV_LSH_TABLE_kHash = 2
#EndRegion ..\opencv\modules\flann\include\opencv2\flann\lsh_table.h



#Region ..\opencv\modules\gapi\include\opencv2\gapi\video.hpp
; BackgroundSubtractorType
Global Const $CV_TYPE_BS_MOG2 = 0
Global Const $CV_TYPE_BS_KNN = 1
#EndRegion ..\opencv\modules\gapi\include\opencv2\gapi\video.hpp



#Region ..\opencv\modules\highgui\include\opencv2\highgui.hpp
; WindowFlags
Global Const $CV_WINDOW_NORMAL = 0x00000000
Global Const $CV_WINDOW_AUTOSIZE = 0x00000001
Global Const $CV_WINDOW_OPENGL = 0x00001000
Global Const $CV_WINDOW_FULLSCREEN = 1
Global Const $CV_WINDOW_FREERATIO = 0x00000100
Global Const $CV_WINDOW_KEEPRATIO = 0x00000000
Global Const $CV_WINDOW_GUI_EXPANDED = 0x00000000
Global Const $CV_WINDOW_GUI_NORMAL = 0x00000010

; WindowPropertyFlags
Global Const $CV_WND_PROP_FULLSCREEN = 0
Global Const $CV_WND_PROP_AUTOSIZE = 1
Global Const $CV_WND_PROP_ASPECT_RATIO = 2
Global Const $CV_WND_PROP_OPENGL = 3
Global Const $CV_WND_PROP_VISIBLE = 4
Global Const $CV_WND_PROP_TOPMOST = 5
Global Const $CV_WND_PROP_VSYNC = 6

; MouseEventTypes
Global Const $CV_EVENT_MOUSEMOVE = 0
Global Const $CV_EVENT_LBUTTONDOWN = 1
Global Const $CV_EVENT_RBUTTONDOWN = 2
Global Const $CV_EVENT_MBUTTONDOWN = 3
Global Const $CV_EVENT_LBUTTONUP = 4
Global Const $CV_EVENT_RBUTTONUP = 5
Global Const $CV_EVENT_MBUTTONUP = 6
Global Const $CV_EVENT_LBUTTONDBLCLK = 7
Global Const $CV_EVENT_RBUTTONDBLCLK = 8
Global Const $CV_EVENT_MBUTTONDBLCLK = 9
Global Const $CV_EVENT_MOUSEWHEEL = 10
Global Const $CV_EVENT_MOUSEHWHEEL = 11

; MouseEventFlags
Global Const $CV_EVENT_FLAG_LBUTTON = 1
Global Const $CV_EVENT_FLAG_RBUTTON = 2
Global Const $CV_EVENT_FLAG_MBUTTON = 4
Global Const $CV_EVENT_FLAG_CTRLKEY = 8
Global Const $CV_EVENT_FLAG_SHIFTKEY = 16
Global Const $CV_EVENT_FLAG_ALTKEY = 32

; QtFontWeights
Global Const $CV_QT_FONT_LIGHT = 25
Global Const $CV_QT_FONT_NORMAL = 50
Global Const $CV_QT_FONT_DEMIBOLD = 63
Global Const $CV_QT_FONT_BOLD = 75
Global Const $CV_QT_FONT_BLACK = 87

; QtFontStyles
Global Const $CV_QT_STYLE_NORMAL = 0
Global Const $CV_QT_STYLE_ITALIC = 1
Global Const $CV_QT_STYLE_OBLIQUE = 2

; QtButtonTypes
Global Const $CV_QT_PUSH_BUTTON = 0
Global Const $CV_QT_CHECKBOX = 1
Global Const $CV_QT_RADIOBOX = 2
Global Const $CV_QT_NEW_BUTTONBAR = 1024
#EndRegion ..\opencv\modules\highgui\include\opencv2\highgui.hpp



#Region ..\opencv\modules\imgcodecs\include\opencv2\imgcodecs.hpp
; ImreadModes
Global Const $CV_IMREAD_UNCHANGED = -1
Global Const $CV_IMREAD_GRAYSCALE = 0
Global Const $CV_IMREAD_COLOR = 1
Global Const $CV_IMREAD_ANYDEPTH = 2
Global Const $CV_IMREAD_ANYCOLOR = 4
Global Const $CV_IMREAD_LOAD_GDAL = 8
Global Const $CV_IMREAD_REDUCED_GRAYSCALE_2 = 16
Global Const $CV_IMREAD_REDUCED_COLOR_2 = 17
Global Const $CV_IMREAD_REDUCED_GRAYSCALE_4 = 32
Global Const $CV_IMREAD_REDUCED_COLOR_4 = 33
Global Const $CV_IMREAD_REDUCED_GRAYSCALE_8 = 64
Global Const $CV_IMREAD_REDUCED_COLOR_8 = 65
Global Const $CV_IMREAD_IGNORE_ORIENTATION = 128

; ImwriteFlags
Global Const $CV_IMWRITE_JPEG_QUALITY = 1
Global Const $CV_IMWRITE_JPEG_PROGRESSIVE = 2
Global Const $CV_IMWRITE_JPEG_OPTIMIZE = 3
Global Const $CV_IMWRITE_JPEG_RST_INTERVAL = 4
Global Const $CV_IMWRITE_JPEG_LUMA_QUALITY = 5
Global Const $CV_IMWRITE_JPEG_CHROMA_QUALITY = 6
Global Const $CV_IMWRITE_PNG_COMPRESSION = 16
Global Const $CV_IMWRITE_PNG_STRATEGY = 17
Global Const $CV_IMWRITE_PNG_BILEVEL = 18
Global Const $CV_IMWRITE_PXM_BINARY = 32
Global Const $CV_IMWRITE_EXR_TYPE = (BitShift(3, -4)) + 0
Global Const $CV_IMWRITE_EXR_COMPRESSION = (BitShift(3, -4)) + 1
Global Const $CV_IMWRITE_WEBP_QUALITY = 64
Global Const $CV_IMWRITE_PAM_TUPLETYPE = 128
Global Const $CV_IMWRITE_TIFF_RESUNIT = 256
Global Const $CV_IMWRITE_TIFF_XDPI = 257
Global Const $CV_IMWRITE_TIFF_YDPI = 258
Global Const $CV_IMWRITE_TIFF_COMPRESSION = 259
Global Const $CV_IMWRITE_JPEG2000_COMPRESSION_X1000 = 272

; ImwriteEXRTypeFlags
Global Const $CV_IMWRITE_EXR_TYPE_HALF = 1
Global Const $CV_IMWRITE_EXR_TYPE_FLOAT = 2

; ImwriteEXRCompressionFlags
Global Const $CV_IMWRITE_EXR_COMPRESSION_NO = 0
Global Const $CV_IMWRITE_EXR_COMPRESSION_RLE = 1
Global Const $CV_IMWRITE_EXR_COMPRESSION_ZIPS = 2
Global Const $CV_IMWRITE_EXR_COMPRESSION_ZIP = 3
Global Const $CV_IMWRITE_EXR_COMPRESSION_PIZ = 4
Global Const $CV_IMWRITE_EXR_COMPRESSION_PXR24 = 5
Global Const $CV_IMWRITE_EXR_COMPRESSION_B44 = 6
Global Const $CV_IMWRITE_EXR_COMPRESSION_B44A = 7
Global Const $CV_IMWRITE_EXR_COMPRESSION_DWAA = 8
Global Const $CV_IMWRITE_EXR_COMPRESSION_DWAB = 9

; ImwritePNGFlags
Global Const $CV_IMWRITE_PNG_STRATEGY_DEFAULT = 0
Global Const $CV_IMWRITE_PNG_STRATEGY_FILTERED = 1
Global Const $CV_IMWRITE_PNG_STRATEGY_HUFFMAN_ONLY = 2
Global Const $CV_IMWRITE_PNG_STRATEGY_RLE = 3
Global Const $CV_IMWRITE_PNG_STRATEGY_FIXED = 4

; ImwritePAMFlags
Global Const $CV_IMWRITE_PAM_FORMAT_NULL = 0
Global Const $CV_IMWRITE_PAM_FORMAT_BLACKANDWHITE = 1
Global Const $CV_IMWRITE_PAM_FORMAT_GRAYSCALE = 2
Global Const $CV_IMWRITE_PAM_FORMAT_GRAYSCALE_ALPHA = 3
Global Const $CV_IMWRITE_PAM_FORMAT_RGB = 4
Global Const $CV_IMWRITE_PAM_FORMAT_RGB_ALPHA = 5
#EndRegion ..\opencv\modules\imgcodecs\include\opencv2\imgcodecs.hpp



#Region ..\opencv\modules\imgproc\include\opencv2\imgproc.hpp
; SpecialFilter
Global Const $CV_FILTER_SCHARR = -1

; MorphTypes
Global Const $CV_MORPH_ERODE = 0
Global Const $CV_MORPH_DILATE = 1
Global Const $CV_MORPH_OPEN = 2
Global Const $CV_MORPH_CLOSE = 3
Global Const $CV_MORPH_GRADIENT = 4
Global Const $CV_MORPH_TOPHAT = 5
Global Const $CV_MORPH_BLACKHAT = 6
Global Const $CV_MORPH_HITMISS = 7

; MorphShapes
Global Const $CV_MORPH_RECT = 0
Global Const $CV_MORPH_CROSS = 1
Global Const $CV_MORPH_ELLIPSE = 2

; InterpolationFlags
Global Const $CV_INTER_NEAREST = 0
Global Const $CV_INTER_LINEAR = 1
Global Const $CV_INTER_CUBIC = 2
Global Const $CV_INTER_AREA = 3
Global Const $CV_INTER_LANCZOS4 = 4
Global Const $CV_INTER_LINEAR_EXACT = 5
Global Const $CV_INTER_NEAREST_EXACT = 6
Global Const $CV_INTER_MAX = 7
Global Const $CV_WARP_FILL_OUTLIERS = 8
Global Const $CV_WARP_INVERSE_MAP = 16

; WarpPolarMode
Global Const $CV_WARP_POLAR_LINEAR = 0
Global Const $CV_WARP_POLAR_LOG = 256

; InterpolationMasks
Global Const $CV_INTER_BITS = 5
Global Const $CV_INTER_BITS2 = $CV_INTER_BITS * 2
Global Const $CV_INTER_TAB_SIZE = (BitShift(1, -$CV_INTER_BITS))
Global Const $CV_INTER_TAB_SIZE2 = $CV_INTER_TAB_SIZE * $CV_INTER_TAB_SIZE

; DistanceTypes
Global Const $CV_DIST_USER = -1
Global Const $CV_DIST_L1 = 1
Global Const $CV_DIST_L2 = 2
Global Const $CV_DIST_C = 3
Global Const $CV_DIST_L12 = 4
Global Const $CV_DIST_FAIR = 5
Global Const $CV_DIST_WELSCH = 6
Global Const $CV_DIST_HUBER = 7

; DistanceTransformMasks
Global Const $CV_DIST_MASK_3 = 3
Global Const $CV_DIST_MASK_5 = 5
Global Const $CV_DIST_MASK_PRECISE = 0

; ThresholdTypes
Global Const $CV_THRESH_BINARY = 0
Global Const $CV_THRESH_BINARY_INV = 1
Global Const $CV_THRESH_TRUNC = 2
Global Const $CV_THRESH_TOZERO = 3
Global Const $CV_THRESH_TOZERO_INV = 4
Global Const $CV_THRESH_MASK = 7
Global Const $CV_THRESH_OTSU = 8
Global Const $CV_THRESH_TRIANGLE = 16

; AdaptiveThresholdTypes
Global Const $CV_ADAPTIVE_THRESH_MEAN_C = 0
Global Const $CV_ADAPTIVE_THRESH_GAUSSIAN_C = 1

; GrabCutClasses
Global Const $CV_GC_BGD = 0
Global Const $CV_GC_FGD = 1
Global Const $CV_GC_PR_BGD = 2
Global Const $CV_GC_PR_FGD = 3

; GrabCutModes
Global Const $CV_GC_INIT_WITH_RECT = 0
Global Const $CV_GC_INIT_WITH_MASK = 1
Global Const $CV_GC_EVAL = 2
Global Const $CV_GC_EVAL_FREEZE_MODEL = 3

; DistanceTransformLabelTypes
Global Const $CV_DIST_LABEL_CCOMP = 0
Global Const $CV_DIST_LABEL_PIXEL = 1

; FloodFillFlags
Global Const $CV_FLOODFILL_FIXED_RANGE = (BitShift(1, -16))
Global Const $CV_FLOODFILL_MASK_ONLY = (BitShift(1, -17))

; ConnectedComponentsTypes
Global Const $CV_CC_STAT_LEFT = 0
Global Const $CV_CC_STAT_TOP = 1
Global Const $CV_CC_STAT_WIDTH = 2
Global Const $CV_CC_STAT_HEIGHT = 3
Global Const $CV_CC_STAT_AREA = 4

; ConnectedComponentsAlgorithmsTypes
Global Const $CV_CCL_DEFAULT = -1
Global Const $CV_CCL_WU = 0
Global Const $CV_CCL_GRANA = 1
Global Const $CV_CCL_BOLELLI = 2
Global Const $CV_CCL_SAUF = 3
Global Const $CV_CCL_BBDT = 4
Global Const $CV_CCL_SPAGHETTI = 5

; RetrievalModes
Global Const $CV_RETR_EXTERNAL = 0
Global Const $CV_RETR_LIST = 1
Global Const $CV_RETR_CCOMP = 2
Global Const $CV_RETR_TREE = 3
Global Const $CV_RETR_FLOODFILL = 4

; ContourApproximationModes
Global Const $CV_CHAIN_APPROX_NONE = 1
Global Const $CV_CHAIN_APPROX_SIMPLE = 2
Global Const $CV_CHAIN_APPROX_TC89_L1 = 3
Global Const $CV_CHAIN_APPROX_TC89_KCOS = 4

; ShapeMatchModes
Global Const $CV_CONTOURS_MATCH_I1 = 1
Global Const $CV_CONTOURS_MATCH_I2 = 2
Global Const $CV_CONTOURS_MATCH_I3 = 3

; HoughModes
Global Const $CV_HOUGH_STANDARD = 0
Global Const $CV_HOUGH_PROBABILISTIC = 1
Global Const $CV_HOUGH_MULTI_SCALE = 2
Global Const $CV_HOUGH_GRADIENT = 3
Global Const $CV_HOUGH_GRADIENT_ALT = 4

; LineSegmentDetectorModes
Global Const $CV_LSD_REFINE_NONE = 0
Global Const $CV_LSD_REFINE_STD = 1
Global Const $CV_LSD_REFINE_ADV = 2

; HistCompMethods
Global Const $CV_HISTCMP_CORREL = 0
Global Const $CV_HISTCMP_CHISQR = 1
Global Const $CV_HISTCMP_INTERSECT = 2
Global Const $CV_HISTCMP_BHATTACHARYYA = 3
Global Const $CV_HISTCMP_HELLINGER = $CV_HISTCMP_BHATTACHARYYA
Global Const $CV_HISTCMP_CHISQR_ALT = 4
Global Const $CV_HISTCMP_KL_DIV = 5

; ColorConversionCodes
Global Const $CV_COLOR_BGR2BGRA = 0
Global Const $CV_COLOR_RGB2RGBA = $CV_COLOR_BGR2BGRA
Global Const $CV_COLOR_BGRA2BGR = 1
Global Const $CV_COLOR_RGBA2RGB = $CV_COLOR_BGRA2BGR
Global Const $CV_COLOR_BGR2RGBA = 2
Global Const $CV_COLOR_RGB2BGRA = $CV_COLOR_BGR2RGBA
Global Const $CV_COLOR_RGBA2BGR = 3
Global Const $CV_COLOR_BGRA2RGB = $CV_COLOR_RGBA2BGR
Global Const $CV_COLOR_BGR2RGB = 4
Global Const $CV_COLOR_RGB2BGR = $CV_COLOR_BGR2RGB
Global Const $CV_COLOR_BGRA2RGBA = 5
Global Const $CV_COLOR_RGBA2BGRA = $CV_COLOR_BGRA2RGBA
Global Const $CV_COLOR_BGR2GRAY = 6
Global Const $CV_COLOR_RGB2GRAY = 7
Global Const $CV_COLOR_GRAY2BGR = 8
Global Const $CV_COLOR_GRAY2RGB = $CV_COLOR_GRAY2BGR
Global Const $CV_COLOR_GRAY2BGRA = 9
Global Const $CV_COLOR_GRAY2RGBA = $CV_COLOR_GRAY2BGRA
Global Const $CV_COLOR_BGRA2GRAY = 10
Global Const $CV_COLOR_RGBA2GRAY = 11
Global Const $CV_COLOR_BGR2BGR565 = 12
Global Const $CV_COLOR_RGB2BGR565 = 13
Global Const $CV_COLOR_BGR5652BGR = 14
Global Const $CV_COLOR_BGR5652RGB = 15
Global Const $CV_COLOR_BGRA2BGR565 = 16
Global Const $CV_COLOR_RGBA2BGR565 = 17
Global Const $CV_COLOR_BGR5652BGRA = 18
Global Const $CV_COLOR_BGR5652RGBA = 19
Global Const $CV_COLOR_GRAY2BGR565 = 20
Global Const $CV_COLOR_BGR5652GRAY = 21
Global Const $CV_COLOR_BGR2BGR555 = 22
Global Const $CV_COLOR_RGB2BGR555 = 23
Global Const $CV_COLOR_BGR5552BGR = 24
Global Const $CV_COLOR_BGR5552RGB = 25
Global Const $CV_COLOR_BGRA2BGR555 = 26
Global Const $CV_COLOR_RGBA2BGR555 = 27
Global Const $CV_COLOR_BGR5552BGRA = 28
Global Const $CV_COLOR_BGR5552RGBA = 29
Global Const $CV_COLOR_GRAY2BGR555 = 30
Global Const $CV_COLOR_BGR5552GRAY = 31
Global Const $CV_COLOR_BGR2XYZ = 32
Global Const $CV_COLOR_RGB2XYZ = 33
Global Const $CV_COLOR_XYZ2BGR = 34
Global Const $CV_COLOR_XYZ2RGB = 35
Global Const $CV_COLOR_BGR2YCrCb = 36
Global Const $CV_COLOR_RGB2YCrCb = 37
Global Const $CV_COLOR_YCrCb2BGR = 38
Global Const $CV_COLOR_YCrCb2RGB = 39
Global Const $CV_COLOR_BGR2HSV = 40
Global Const $CV_COLOR_RGB2HSV = 41
Global Const $CV_COLOR_BGR2Lab = 44
Global Const $CV_COLOR_RGB2Lab = 45
Global Const $CV_COLOR_BGR2Luv = 50
Global Const $CV_COLOR_RGB2Luv = 51
Global Const $CV_COLOR_BGR2HLS = 52
Global Const $CV_COLOR_RGB2HLS = 53
Global Const $CV_COLOR_HSV2BGR = 54
Global Const $CV_COLOR_HSV2RGB = 55
Global Const $CV_COLOR_Lab2BGR = 56
Global Const $CV_COLOR_Lab2RGB = 57
Global Const $CV_COLOR_Luv2BGR = 58
Global Const $CV_COLOR_Luv2RGB = 59
Global Const $CV_COLOR_HLS2BGR = 60
Global Const $CV_COLOR_HLS2RGB = 61
Global Const $CV_COLOR_BGR2HSV_FULL = 66
Global Const $CV_COLOR_RGB2HSV_FULL = 67
Global Const $CV_COLOR_BGR2HLS_FULL = 68
Global Const $CV_COLOR_RGB2HLS_FULL = 69
Global Const $CV_COLOR_HSV2BGR_FULL = 70
Global Const $CV_COLOR_HSV2RGB_FULL = 71
Global Const $CV_COLOR_HLS2BGR_FULL = 72
Global Const $CV_COLOR_HLS2RGB_FULL = 73
Global Const $CV_COLOR_LBGR2Lab = 74
Global Const $CV_COLOR_LRGB2Lab = 75
Global Const $CV_COLOR_LBGR2Luv = 76
Global Const $CV_COLOR_LRGB2Luv = 77
Global Const $CV_COLOR_Lab2LBGR = 78
Global Const $CV_COLOR_Lab2LRGB = 79
Global Const $CV_COLOR_Luv2LBGR = 80
Global Const $CV_COLOR_Luv2LRGB = 81
Global Const $CV_COLOR_BGR2YUV = 82
Global Const $CV_COLOR_RGB2YUV = 83
Global Const $CV_COLOR_YUV2BGR = 84
Global Const $CV_COLOR_YUV2RGB = 85
Global Const $CV_COLOR_YUV2RGB_NV12 = 90
Global Const $CV_COLOR_YUV2BGR_NV12 = 91
Global Const $CV_COLOR_YUV2RGB_NV21 = 92
Global Const $CV_COLOR_YUV2BGR_NV21 = 93
Global Const $CV_COLOR_YUV420sp2RGB = $CV_COLOR_YUV2RGB_NV21
Global Const $CV_COLOR_YUV420sp2BGR = $CV_COLOR_YUV2BGR_NV21
Global Const $CV_COLOR_YUV2RGBA_NV12 = 94
Global Const $CV_COLOR_YUV2BGRA_NV12 = 95
Global Const $CV_COLOR_YUV2RGBA_NV21 = 96
Global Const $CV_COLOR_YUV2BGRA_NV21 = 97
Global Const $CV_COLOR_YUV420sp2RGBA = $CV_COLOR_YUV2RGBA_NV21
Global Const $CV_COLOR_YUV420sp2BGRA = $CV_COLOR_YUV2BGRA_NV21
Global Const $CV_COLOR_YUV2RGB_YV12 = 98
Global Const $CV_COLOR_YUV2BGR_YV12 = 99
Global Const $CV_COLOR_YUV2RGB_IYUV = 100
Global Const $CV_COLOR_YUV2BGR_IYUV = 101
Global Const $CV_COLOR_YUV2RGB_I420 = $CV_COLOR_YUV2RGB_IYUV
Global Const $CV_COLOR_YUV2BGR_I420 = $CV_COLOR_YUV2BGR_IYUV
Global Const $CV_COLOR_YUV420p2RGB = $CV_COLOR_YUV2RGB_YV12
Global Const $CV_COLOR_YUV420p2BGR = $CV_COLOR_YUV2BGR_YV12
Global Const $CV_COLOR_YUV2RGBA_YV12 = 102
Global Const $CV_COLOR_YUV2BGRA_YV12 = 103
Global Const $CV_COLOR_YUV2RGBA_IYUV = 104
Global Const $CV_COLOR_YUV2BGRA_IYUV = 105
Global Const $CV_COLOR_YUV2RGBA_I420 = $CV_COLOR_YUV2RGBA_IYUV
Global Const $CV_COLOR_YUV2BGRA_I420 = $CV_COLOR_YUV2BGRA_IYUV
Global Const $CV_COLOR_YUV420p2RGBA = $CV_COLOR_YUV2RGBA_YV12
Global Const $CV_COLOR_YUV420p2BGRA = $CV_COLOR_YUV2BGRA_YV12
Global Const $CV_COLOR_YUV2GRAY_420 = 106
Global Const $CV_COLOR_YUV2GRAY_NV21 = $CV_COLOR_YUV2GRAY_420
Global Const $CV_COLOR_YUV2GRAY_NV12 = $CV_COLOR_YUV2GRAY_420
Global Const $CV_COLOR_YUV2GRAY_YV12 = $CV_COLOR_YUV2GRAY_420
Global Const $CV_COLOR_YUV2GRAY_IYUV = $CV_COLOR_YUV2GRAY_420
Global Const $CV_COLOR_YUV2GRAY_I420 = $CV_COLOR_YUV2GRAY_420
Global Const $CV_COLOR_YUV420sp2GRAY = $CV_COLOR_YUV2GRAY_420
Global Const $CV_COLOR_YUV420p2GRAY = $CV_COLOR_YUV2GRAY_420
Global Const $CV_COLOR_YUV2RGB_UYVY = 107
Global Const $CV_COLOR_YUV2BGR_UYVY = 108
Global Const $CV_COLOR_YUV2RGB_Y422 = $CV_COLOR_YUV2RGB_UYVY
Global Const $CV_COLOR_YUV2BGR_Y422 = $CV_COLOR_YUV2BGR_UYVY
Global Const $CV_COLOR_YUV2RGB_UYNV = $CV_COLOR_YUV2RGB_UYVY
Global Const $CV_COLOR_YUV2BGR_UYNV = $CV_COLOR_YUV2BGR_UYVY
Global Const $CV_COLOR_YUV2RGBA_UYVY = 111
Global Const $CV_COLOR_YUV2BGRA_UYVY = 112
Global Const $CV_COLOR_YUV2RGBA_Y422 = $CV_COLOR_YUV2RGBA_UYVY
Global Const $CV_COLOR_YUV2BGRA_Y422 = $CV_COLOR_YUV2BGRA_UYVY
Global Const $CV_COLOR_YUV2RGBA_UYNV = $CV_COLOR_YUV2RGBA_UYVY
Global Const $CV_COLOR_YUV2BGRA_UYNV = $CV_COLOR_YUV2BGRA_UYVY
Global Const $CV_COLOR_YUV2RGB_YUY2 = 115
Global Const $CV_COLOR_YUV2BGR_YUY2 = 116
Global Const $CV_COLOR_YUV2RGB_YVYU = 117
Global Const $CV_COLOR_YUV2BGR_YVYU = 118
Global Const $CV_COLOR_YUV2RGB_YUYV = $CV_COLOR_YUV2RGB_YUY2
Global Const $CV_COLOR_YUV2BGR_YUYV = $CV_COLOR_YUV2BGR_YUY2
Global Const $CV_COLOR_YUV2RGB_YUNV = $CV_COLOR_YUV2RGB_YUY2
Global Const $CV_COLOR_YUV2BGR_YUNV = $CV_COLOR_YUV2BGR_YUY2
Global Const $CV_COLOR_YUV2RGBA_YUY2 = 119
Global Const $CV_COLOR_YUV2BGRA_YUY2 = 120
Global Const $CV_COLOR_YUV2RGBA_YVYU = 121
Global Const $CV_COLOR_YUV2BGRA_YVYU = 122
Global Const $CV_COLOR_YUV2RGBA_YUYV = $CV_COLOR_YUV2RGBA_YUY2
Global Const $CV_COLOR_YUV2BGRA_YUYV = $CV_COLOR_YUV2BGRA_YUY2
Global Const $CV_COLOR_YUV2RGBA_YUNV = $CV_COLOR_YUV2RGBA_YUY2
Global Const $CV_COLOR_YUV2BGRA_YUNV = $CV_COLOR_YUV2BGRA_YUY2
Global Const $CV_COLOR_YUV2GRAY_UYVY = 123
Global Const $CV_COLOR_YUV2GRAY_YUY2 = 124
Global Const $CV_COLOR_YUV2GRAY_Y422 = $CV_COLOR_YUV2GRAY_UYVY
Global Const $CV_COLOR_YUV2GRAY_UYNV = $CV_COLOR_YUV2GRAY_UYVY
Global Const $CV_COLOR_YUV2GRAY_YVYU = $CV_COLOR_YUV2GRAY_YUY2
Global Const $CV_COLOR_YUV2GRAY_YUYV = $CV_COLOR_YUV2GRAY_YUY2
Global Const $CV_COLOR_YUV2GRAY_YUNV = $CV_COLOR_YUV2GRAY_YUY2
Global Const $CV_COLOR_RGBA2mRGBA = 125
Global Const $CV_COLOR_mRGBA2RGBA = 126
Global Const $CV_COLOR_RGB2YUV_I420 = 127
Global Const $CV_COLOR_BGR2YUV_I420 = 128
Global Const $CV_COLOR_RGB2YUV_IYUV = $CV_COLOR_RGB2YUV_I420
Global Const $CV_COLOR_BGR2YUV_IYUV = $CV_COLOR_BGR2YUV_I420
Global Const $CV_COLOR_RGBA2YUV_I420 = 129
Global Const $CV_COLOR_BGRA2YUV_I420 = 130
Global Const $CV_COLOR_RGBA2YUV_IYUV = $CV_COLOR_RGBA2YUV_I420
Global Const $CV_COLOR_BGRA2YUV_IYUV = $CV_COLOR_BGRA2YUV_I420
Global Const $CV_COLOR_RGB2YUV_YV12 = 131
Global Const $CV_COLOR_BGR2YUV_YV12 = 132
Global Const $CV_COLOR_RGBA2YUV_YV12 = 133
Global Const $CV_COLOR_BGRA2YUV_YV12 = 134
Global Const $CV_COLOR_BayerBG2BGR = 46
Global Const $CV_COLOR_BayerGB2BGR = 47
Global Const $CV_COLOR_BayerRG2BGR = 48
Global Const $CV_COLOR_BayerGR2BGR = 49
Global Const $CV_COLOR_BayerBG2RGB = $CV_COLOR_BayerRG2BGR
Global Const $CV_COLOR_BayerGB2RGB = $CV_COLOR_BayerGR2BGR
Global Const $CV_COLOR_BayerRG2RGB = $CV_COLOR_BayerBG2BGR
Global Const $CV_COLOR_BayerGR2RGB = $CV_COLOR_BayerGB2BGR
Global Const $CV_COLOR_BayerBG2GRAY = 86
Global Const $CV_COLOR_BayerGB2GRAY = 87
Global Const $CV_COLOR_BayerRG2GRAY = 88
Global Const $CV_COLOR_BayerGR2GRAY = 89
Global Const $CV_COLOR_BayerBG2BGR_VNG = 62
Global Const $CV_COLOR_BayerGB2BGR_VNG = 63
Global Const $CV_COLOR_BayerRG2BGR_VNG = 64
Global Const $CV_COLOR_BayerGR2BGR_VNG = 65
Global Const $CV_COLOR_BayerBG2RGB_VNG = $CV_COLOR_BayerRG2BGR_VNG
Global Const $CV_COLOR_BayerGB2RGB_VNG = $CV_COLOR_BayerGR2BGR_VNG
Global Const $CV_COLOR_BayerRG2RGB_VNG = $CV_COLOR_BayerBG2BGR_VNG
Global Const $CV_COLOR_BayerGR2RGB_VNG = $CV_COLOR_BayerGB2BGR_VNG
Global Const $CV_COLOR_BayerBG2BGR_EA = 135
Global Const $CV_COLOR_BayerGB2BGR_EA = 136
Global Const $CV_COLOR_BayerRG2BGR_EA = 137
Global Const $CV_COLOR_BayerGR2BGR_EA = 138
Global Const $CV_COLOR_BayerBG2RGB_EA = $CV_COLOR_BayerRG2BGR_EA
Global Const $CV_COLOR_BayerGB2RGB_EA = $CV_COLOR_BayerGR2BGR_EA
Global Const $CV_COLOR_BayerRG2RGB_EA = $CV_COLOR_BayerBG2BGR_EA
Global Const $CV_COLOR_BayerGR2RGB_EA = $CV_COLOR_BayerGB2BGR_EA
Global Const $CV_COLOR_BayerBG2BGRA = 139
Global Const $CV_COLOR_BayerGB2BGRA = 140
Global Const $CV_COLOR_BayerRG2BGRA = 141
Global Const $CV_COLOR_BayerGR2BGRA = 142
Global Const $CV_COLOR_BayerBG2RGBA = $CV_COLOR_BayerRG2BGRA
Global Const $CV_COLOR_BayerGB2RGBA = $CV_COLOR_BayerGR2BGRA
Global Const $CV_COLOR_BayerRG2RGBA = $CV_COLOR_BayerBG2BGRA
Global Const $CV_COLOR_BayerGR2RGBA = $CV_COLOR_BayerGB2BGRA
Global Const $CV_COLOR_COLORCVT_MAX = 143

; RectanglesIntersectTypes
Global Const $CV_INTERSECT_NONE = 0
Global Const $CV_INTERSECT_PARTIAL = 1
Global Const $CV_INTERSECT_FULL = 2

; LineTypes
Global Const $CV_FILLED = -1
Global Const $CV_LINE_4 = 4
Global Const $CV_LINE_8 = 8
Global Const $CV_LINE_AA = 16

; HersheyFonts
Global Const $CV_FONT_HERSHEY_SIMPLEX = 0
Global Const $CV_FONT_HERSHEY_PLAIN = 1
Global Const $CV_FONT_HERSHEY_DUPLEX = 2
Global Const $CV_FONT_HERSHEY_COMPLEX = 3
Global Const $CV_FONT_HERSHEY_TRIPLEX = 4
Global Const $CV_FONT_HERSHEY_COMPLEX_SMALL = 5
Global Const $CV_FONT_HERSHEY_SCRIPT_SIMPLEX = 6
Global Const $CV_FONT_HERSHEY_SCRIPT_COMPLEX = 7
Global Const $CV_FONT_ITALIC = 16

; MarkerTypes
Global Const $CV_MARKER_CROSS = 0
Global Const $CV_MARKER_TILTED_CROSS = 1
Global Const $CV_MARKER_STAR = 2
Global Const $CV_MARKER_DIAMOND = 3
Global Const $CV_MARKER_SQUARE = 4
Global Const $CV_MARKER_TRIANGLE_UP = 5
Global Const $CV_MARKER_TRIANGLE_DOWN = 6

; anonymous
Global Const $CV_SUBDIV2D_PTLOC_ERROR = -2
Global Const $CV_SUBDIV2D_PTLOC_OUTSIDE_RECT = -1
Global Const $CV_SUBDIV2D_PTLOC_INSIDE = 0
Global Const $CV_SUBDIV2D_PTLOC_VERTEX = 1
Global Const $CV_SUBDIV2D_PTLOC_ON_EDGE = 2
Global Const $CV_SUBDIV2D_NEXT_AROUND_ORG = 0x00
Global Const $CV_SUBDIV2D_NEXT_AROUND_DST = 0x22
Global Const $CV_SUBDIV2D_PREV_AROUND_ORG = 0x11
Global Const $CV_SUBDIV2D_PREV_AROUND_DST = 0x33
Global Const $CV_SUBDIV2D_NEXT_AROUND_LEFT = 0x13
Global Const $CV_SUBDIV2D_NEXT_AROUND_RIGHT = 0x31
Global Const $CV_SUBDIV2D_PREV_AROUND_LEFT = 0x20
Global Const $CV_SUBDIV2D_PREV_AROUND_RIGHT = 0x02

; TemplateMatchModes
Global Const $CV_TM_SQDIFF = 0
Global Const $CV_TM_SQDIFF_NORMED = 1
Global Const $CV_TM_CCORR = 2
Global Const $CV_TM_CCORR_NORMED = 3
Global Const $CV_TM_CCOEFF = 4
Global Const $CV_TM_CCOEFF_NORMED = 5

; ColormapTypes
Global Const $CV_COLORMAP_AUTUMN = 0
Global Const $CV_COLORMAP_BONE = 1
Global Const $CV_COLORMAP_JET = 2
Global Const $CV_COLORMAP_WINTER = 3
Global Const $CV_COLORMAP_RAINBOW = 4
Global Const $CV_COLORMAP_OCEAN = 5
Global Const $CV_COLORMAP_SUMMER = 6
Global Const $CV_COLORMAP_SPRING = 7
Global Const $CV_COLORMAP_COOL = 8
Global Const $CV_COLORMAP_HSV = 9
Global Const $CV_COLORMAP_PINK = 10
Global Const $CV_COLORMAP_HOT = 11
Global Const $CV_COLORMAP_PARULA = 12
Global Const $CV_COLORMAP_MAGMA = 13
Global Const $CV_COLORMAP_INFERNO = 14
Global Const $CV_COLORMAP_PLASMA = 15
Global Const $CV_COLORMAP_VIRIDIS = 16
Global Const $CV_COLORMAP_CIVIDIS = 17
Global Const $CV_COLORMAP_TWILIGHT = 18
Global Const $CV_COLORMAP_TWILIGHT_SHIFTED = 19
Global Const $CV_COLORMAP_TURBO = 20
Global Const $CV_COLORMAP_DEEPGREEN = 21
#EndRegion ..\opencv\modules\imgproc\include\opencv2\imgproc.hpp



#Region ..\opencv\modules\ml\include\opencv2\ml.hpp
; VariableTypes
Global Const $CV_VAR_NUMERICAL = 0
Global Const $CV_VAR_ORDERED = 0
Global Const $CV_VAR_CATEGORICAL = 1

; ErrorTypes
Global Const $CV_TEST_ERROR = 0
Global Const $CV_TRAIN_ERROR = 1

; SampleTypes
Global Const $CV_ROW_SAMPLE = 0
Global Const $CV_COL_SAMPLE = 1

; Flags
Global Const $CV_STAT_MODEL_UPDATE_MODEL = 1
Global Const $CV_STAT_MODEL_RAW_OUTPUT = 1
Global Const $CV_STAT_MODEL_COMPRESSED_INPUT = 2
Global Const $CV_STAT_MODEL_PREPROCESSED_INPUT = 4

; Types
Global Const $CV_KNEAREST_BRUTE_FORCE = 1
Global Const $CV_KNEAREST_KDTREE = 2

; Types
Global Const $CV_SVM_C_SVC = 100
Global Const $CV_SVM_NU_SVC = 101
Global Const $CV_SVM_ONE_CLASS = 102
Global Const $CV_SVM_EPS_SVR = 103
Global Const $CV_SVM_NU_SVR = 104

; KernelTypes
Global Const $CV_SVM_CUSTOM = -1
Global Const $CV_SVM_LINEAR = 0
Global Const $CV_SVM_POLY = 1
Global Const $CV_SVM_RBF = 2
Global Const $CV_SVM_SIGMOID = 3
Global Const $CV_SVM_CHI2 = 4
Global Const $CV_SVM_INTER = 5

; ParamTypes
Global Const $CV_SVM_C = 0
Global Const $CV_SVM_GAMMA = 1
Global Const $CV_SVM_P = 2
Global Const $CV_SVM_NU = 3
Global Const $CV_SVM_COEF = 4
Global Const $CV_SVM_DEGREE = 5

; Types
Global Const $CV_EM_COV_MAT_SPHERICAL = 0
Global Const $CV_EM_COV_MAT_DIAGONAL = 1
Global Const $CV_EM_COV_MAT_GENERIC = 2
Global Const $CV_EM_COV_MAT_DEFAULT = $CV_EM_COV_MAT_DIAGONAL

; anonymous
Global Const $CV_EM_DEFAULT_NCLUSTERS = 5
Global Const $CV_EM_DEFAULT_MAX_ITERS = 100
Global Const $CV_EM_START_E_STEP = 1
Global Const $CV_EM_START_M_STEP = 2
Global Const $CV_EM_START_AUTO_STEP = 0

; Flags
Global Const $CV_DTREES_PREDICT_AUTO = 0
Global Const $CV_DTREES_PREDICT_SUM = (BitShift(1, -8))
Global Const $CV_DTREES_PREDICT_MAX_VOTE = (BitShift(2, -8))
Global Const $CV_DTREES_PREDICT_MASK = (BitShift(3, -8))

; Types
Global Const $CV_BOOST_DISCRETE = 0
Global Const $CV_BOOST_REAL = 1
Global Const $CV_BOOST_LOGIT = 2
Global Const $CV_BOOST_GENTLE = 3

; TrainingMethods
Global Const $CV_ANN_MLP_BACKPROP = 0
Global Const $CV_ANN_MLP_RPROP = 1
Global Const $CV_ANN_MLP_ANNEAL = 2

; ActivationFunctions
Global Const $CV_ANN_MLP_IDENTITY = 0
Global Const $CV_ANN_MLP_SIGMOID_SYM = 1
Global Const $CV_ANN_MLP_GAUSSIAN = 2
Global Const $CV_ANN_MLP_RELU = 3
Global Const $CV_ANN_MLP_LEAKYRELU = 4

; TrainFlags
Global Const $CV_ANN_MLP_UPDATE_WEIGHTS = 1
Global Const $CV_ANN_MLP_NO_INPUT_SCALE = 2
Global Const $CV_ANN_MLP_NO_OUTPUT_SCALE = 4

; RegKinds
Global Const $CV_LOGISTIC_REGRESSION_REG_DISABLE = -1
Global Const $CV_LOGISTIC_REGRESSION_REG_L1 = 0
Global Const $CV_LOGISTIC_REGRESSION_REG_L2 = 1

; Methods
Global Const $CV_LOGISTIC_REGRESSION_BATCH = 0
Global Const $CV_LOGISTIC_REGRESSION_MINI_BATCH = 1

; SvmsgdType
Global Const $CV_SVMSGD_SGD = 0
Global Const $CV_SVMSGD_ASGD = 1

; MarginType
Global Const $CV_SVMSGD_SOFT_MARGIN = 0
Global Const $CV_SVMSGD_HARD_MARGIN = 1
#EndRegion ..\opencv\modules\ml\include\opencv2\ml.hpp



#Region ..\opencv\modules\objdetect\include\opencv2\objdetect.hpp
; anonymous
Global Const $CV_CASCADE_DO_CANNY_PRUNING = 1
Global Const $CV_CASCADE_SCALE_IMAGE = 2
Global Const $CV_CASCADE_FIND_BIGGEST_OBJECT = 4
Global Const $CV_CASCADE_DO_ROUGH_SEARCH = 8
#EndRegion ..\opencv\modules\objdetect\include\opencv2\objdetect.hpp



#Region ..\opencv\modules\objdetect\include\opencv2\objdetect\detection_based_tracker.hpp
; ObjectStatus
Global Const $CV_DETECTION_BASED_TRACKER_DETECTED_NOT_SHOWN_YET = 0
Global Const $CV_DETECTION_BASED_TRACKER_DETECTED = 1
Global Const $CV_DETECTION_BASED_TRACKER_DETECTED_TEMPORARY_LOST = 2
Global Const $CV_DETECTION_BASED_TRACKER_WRONG_OBJECT = 3
#EndRegion ..\opencv\modules\objdetect\include\opencv2\objdetect\detection_based_tracker.hpp



#Region ..\opencv\modules\photo\include\opencv2\photo.hpp
; anonymous
Global Const $CV_INPAINT_NS = 0
Global Const $CV_INPAINT_TELEA = 1
Global Const $CV_LDR_SIZE = 256
Global Const $CV_NORMAL_CLONE = 1
Global Const $CV_MIXED_CLONE = 2
Global Const $CV_MONOCHROME_TRANSFER = 3
Global Const $CV_RECURS_FILTER = 1
Global Const $CV_NORMCONV_FILTER = 2
#EndRegion ..\opencv\modules\photo\include\opencv2\photo.hpp



#Region ..\opencv\modules\stitching\include\opencv2\stitching.hpp
; Status
Global Const $CV_STITCHER_OK = 0
Global Const $CV_STITCHER_ERR_NEED_MORE_IMGS = 1
Global Const $CV_STITCHER_ERR_HOMOGRAPHY_EST_FAIL = 2
Global Const $CV_STITCHER_ERR_CAMERA_PARAMS_ADJUST_FAIL = 3

; Mode
Global Const $CV_STITCHER_PANORAMA = 0
Global Const $CV_STITCHER_SCANS = 1
#EndRegion ..\opencv\modules\stitching\include\opencv2\stitching.hpp



#Region ..\opencv\modules\stitching\include\opencv2\stitching\detail\blenders.hpp
; anonymous
Global Const $CV_BLENDER_NO = 0
Global Const $CV_BLENDER_FEATHER = 1
Global Const $CV_BLENDER_MULTI_BAND = 2
#EndRegion ..\opencv\modules\stitching\include\opencv2\stitching\detail\blenders.hpp



#Region ..\opencv\modules\stitching\include\opencv2\stitching\detail\exposure_compensate.hpp
; anonymous
Global Const $CV_EXPOSURE_COMPENSATOR_NO = 0
Global Const $CV_EXPOSURE_COMPENSATOR_GAIN = 1
Global Const $CV_EXPOSURE_COMPENSATOR_GAIN_BLOCKS = 2
Global Const $CV_EXPOSURE_COMPENSATOR_CHANNELS = 3
Global Const $CV_EXPOSURE_COMPENSATOR_CHANNELS_BLOCKS = 4
#EndRegion ..\opencv\modules\stitching\include\opencv2\stitching\detail\exposure_compensate.hpp



#Region ..\opencv\modules\stitching\include\opencv2\stitching\detail\motion_estimators.hpp
; WaveCorrectKind
Global Const $CV_WAVE_CORRECT_HORIZ = 0
Global Const $CV_WAVE_CORRECT_VERT = 1
Global Const $CV_WAVE_CORRECT_AUTO = 2
#EndRegion ..\opencv\modules\stitching\include\opencv2\stitching\detail\motion_estimators.hpp



#Region ..\opencv\modules\stitching\include\opencv2\stitching\detail\seam_finders.hpp
; anonymous
Global Const $CV_SEAM_FINDER_NO = 0
Global Const $CV_SEAM_FINDER_VORONOI_SEAM = 1
Global Const $CV_SEAM_FINDER_DP_SEAM = 2

; CostFunction
Global Const $CV_DP_SEAM_FINDER_COLOR = 0
Global Const $CV_DP_SEAM_FINDER_COLOR_GRAD = 1

; ComponentState
Global Const $CV_DP_SEAM_FINDER_FIRST = 1
Global Const $CV_DP_SEAM_FINDER_SECOND = 2
Global Const $CV_DP_SEAM_FINDER_INTERS = 4
Global Const $CV_DP_SEAM_FINDER_INTERS_FIRST = (BitOR($CV_DP_SEAM_FINDER_INTERS, $CV_DP_SEAM_FINDER_FIRST))
Global Const $CV_DP_SEAM_FINDER_INTERS_SECOND = (BitOR($CV_DP_SEAM_FINDER_INTERS, $CV_DP_SEAM_FINDER_SECOND))

; CostType
Global Const $CV_GRAPH_CUT_SEAM_FINDER_BASE_COST_COLOR = 0
Global Const $CV_GRAPH_CUT_SEAM_FINDER_BASE_COST_COLOR_GRAD = 1
#EndRegion ..\opencv\modules\stitching\include\opencv2\stitching\detail\seam_finders.hpp



#Region ..\opencv\modules\stitching\include\opencv2\stitching\detail\timelapsers.hpp
; anonymous
Global Const $CV_TIMELAPSER_AS_IS = 0
Global Const $CV_TIMELAPSER_CROP = 1
#EndRegion ..\opencv\modules\stitching\include\opencv2\stitching\detail\timelapsers.hpp



#Region ..\opencv\modules\video\include\opencv2\video\detail\tracking.detail.hpp
; MODE
Global Const $CV_TRACKER_SAMPLER_CSC_MODE_INIT_POS = 1
Global Const $CV_TRACKER_SAMPLER_CSC_MODE_INIT_NEG = 2
Global Const $CV_TRACKER_SAMPLER_CSC_MODE_TRACK_POS = 3
Global Const $CV_TRACKER_SAMPLER_CSC_MODE_TRACK_NEG = 4
Global Const $CV_TRACKER_SAMPLER_CSC_MODE_DETECT = 5
#EndRegion ..\opencv\modules\video\include\opencv2\video\detail\tracking.detail.hpp



#Region ..\opencv\modules\video\include\opencv2\video\tracking.hpp
; anonymous
Global Const $CV_OPTFLOW_USE_INITIAL_FLOW = 4
Global Const $CV_OPTFLOW_LK_GET_MIN_EIGENVALS = 8
Global Const $CV_OPTFLOW_FARNEBACK_GAUSSIAN = 256
Global Const $CV_MOTION_TRANSLATION = 0
Global Const $CV_MOTION_EUCLIDEAN = 1
Global Const $CV_MOTION_AFFINE = 2
Global Const $CV_MOTION_HOMOGRAPHY = 3

; anonymous
Global Const $CV_DISOPTICAL_FLOW_PRESET_ULTRAFAST = 0
Global Const $CV_DISOPTICAL_FLOW_PRESET_FAST = 1
Global Const $CV_DISOPTICAL_FLOW_PRESET_MEDIUM = 2
#EndRegion ..\opencv\modules\video\include\opencv2\video\tracking.hpp



#Region ..\opencv\modules\videoio\include\opencv2\videoio.hpp
; VideoCaptureAPIs
Global Const $CV_CAP_ANY = 0
Global Const $CV_CAP_VFW = 200
Global Const $CV_CAP_V4L = 200
Global Const $CV_CAP_V4L2 = $CV_CAP_V4L
Global Const $CV_CAP_FIREWIRE = 300
Global Const $CV_CAP_FIREWARE = $CV_CAP_FIREWIRE
Global Const $CV_CAP_IEEE1394 = $CV_CAP_FIREWIRE
Global Const $CV_CAP_DC1394 = $CV_CAP_FIREWIRE
Global Const $CV_CAP_CMU1394 = $CV_CAP_FIREWIRE
Global Const $CV_CAP_QT = 500
Global Const $CV_CAP_UNICAP = 600
Global Const $CV_CAP_DSHOW = 700
Global Const $CV_CAP_PVAPI = 800
Global Const $CV_CAP_OPENNI = 900
Global Const $CV_CAP_OPENNI_ASUS = 910
Global Const $CV_CAP_ANDROID = 1000
Global Const $CV_CAP_XIAPI = 1100
Global Const $CV_CAP_AVFOUNDATION = 1200
Global Const $CV_CAP_GIGANETIX = 1300
Global Const $CV_CAP_MSMF = 1400
Global Const $CV_CAP_WINRT = 1410
Global Const $CV_CAP_INTELPERC = 1500
Global Const $CV_CAP_REALSENSE = 1500
Global Const $CV_CAP_OPENNI2 = 1600
Global Const $CV_CAP_OPENNI2_ASUS = 1610
Global Const $CV_CAP_OPENNI2_ASTRA = 1620
Global Const $CV_CAP_GPHOTO2 = 1700
Global Const $CV_CAP_GSTREAMER = 1800
Global Const $CV_CAP_FFMPEG = 1900
Global Const $CV_CAP_IMAGES = 2000
Global Const $CV_CAP_ARAVIS = 2100
Global Const $CV_CAP_OPENCV_MJPEG = 2200
Global Const $CV_CAP_INTEL_MFX = 2300
Global Const $CV_CAP_XINE = 2400
Global Const $CV_CAP_UEYE = 2500

; VideoCaptureProperties
Global Const $CV_CAP_PROP_POS_MSEC = 0
Global Const $CV_CAP_PROP_POS_FRAMES = 1
Global Const $CV_CAP_PROP_POS_AVI_RATIO = 2
Global Const $CV_CAP_PROP_FRAME_WIDTH = 3
Global Const $CV_CAP_PROP_FRAME_HEIGHT = 4
Global Const $CV_CAP_PROP_FPS = 5
Global Const $CV_CAP_PROP_FOURCC = 6
Global Const $CV_CAP_PROP_FRAME_COUNT = 7
Global Const $CV_CAP_PROP_FORMAT = 8
Global Const $CV_CAP_PROP_MODE = 9
Global Const $CV_CAP_PROP_BRIGHTNESS = 10
Global Const $CV_CAP_PROP_CONTRAST = 11
Global Const $CV_CAP_PROP_SATURATION = 12
Global Const $CV_CAP_PROP_HUE = 13
Global Const $CV_CAP_PROP_GAIN = 14
Global Const $CV_CAP_PROP_EXPOSURE = 15
Global Const $CV_CAP_PROP_CONVERT_RGB = 16
Global Const $CV_CAP_PROP_WHITE_BALANCE_BLUE_U = 17
Global Const $CV_CAP_PROP_RECTIFICATION = 18
Global Const $CV_CAP_PROP_MONOCHROME = 19
Global Const $CV_CAP_PROP_SHARPNESS = 20
Global Const $CV_CAP_PROP_AUTO_EXPOSURE = 21
Global Const $CV_CAP_PROP_GAMMA = 22
Global Const $CV_CAP_PROP_TEMPERATURE = 23
Global Const $CV_CAP_PROP_TRIGGER = 24
Global Const $CV_CAP_PROP_TRIGGER_DELAY = 25
Global Const $CV_CAP_PROP_WHITE_BALANCE_RED_V = 26
Global Const $CV_CAP_PROP_ZOOM = 27
Global Const $CV_CAP_PROP_FOCUS = 28
Global Const $CV_CAP_PROP_GUID = 29
Global Const $CV_CAP_PROP_ISO_SPEED = 30
Global Const $CV_CAP_PROP_BACKLIGHT = 32
Global Const $CV_CAP_PROP_PAN = 33
Global Const $CV_CAP_PROP_TILT = 34
Global Const $CV_CAP_PROP_ROLL = 35
Global Const $CV_CAP_PROP_IRIS = 36
Global Const $CV_CAP_PROP_SETTINGS = 37
Global Const $CV_CAP_PROP_BUFFERSIZE = 38
Global Const $CV_CAP_PROP_AUTOFOCUS = 39
Global Const $CV_CAP_PROP_SAR_NUM = 40
Global Const $CV_CAP_PROP_SAR_DEN = 41
Global Const $CV_CAP_PROP_BACKEND = 42
Global Const $CV_CAP_PROP_CHANNEL = 43
Global Const $CV_CAP_PROP_AUTO_WB = 44
Global Const $CV_CAP_PROP_WB_TEMPERATURE = 45
Global Const $CV_CAP_PROP_CODEC_PIXEL_FORMAT = 46
Global Const $CV_CAP_PROP_BITRATE = 47
Global Const $CV_CAP_PROP_ORIENTATION_META = 48
Global Const $CV_CAP_PROP_ORIENTATION_AUTO = 49
Global Const $CV_CAP_PROP_HW_ACCELERATION = 50
Global Const $CV_CAP_PROP_HW_DEVICE = 51
Global Const $CV_CAP_PROP_HW_ACCELERATION_USE_OPENCL = 52

; VideoWriterProperties
Global Const $CV_VIDEOWRITER_PROP_QUALITY = 1
Global Const $CV_VIDEOWRITER_PROP_FRAMEBYTES = 2
Global Const $CV_VIDEOWRITER_PROP_NSTRIPES = 3
Global Const $CV_VIDEOWRITER_PROP_IS_COLOR = 4
Global Const $CV_VIDEOWRITER_PROP_DEPTH = 5
Global Const $CV_VIDEOWRITER_PROP_HW_ACCELERATION = 6
Global Const $CV_VIDEOWRITER_PROP_HW_DEVICE = 7
Global Const $CV_VIDEOWRITER_PROP_HW_ACCELERATION_USE_OPENCL = 8

; VideoAccelerationType
Global Const $CV_VIDEO_ACCELERATION_NONE = 0
Global Const $CV_VIDEO_ACCELERATION_ANY = 1
Global Const $CV_VIDEO_ACCELERATION_D3D11 = 2
Global Const $CV_VIDEO_ACCELERATION_VAAPI = 3
Global Const $CV_VIDEO_ACCELERATION_MFX = 4

; anonymous
Global Const $CV_CAP_PROP_DC1394_OFF = -4
Global Const $CV_CAP_PROP_DC1394_MODE_MANUAL = -3
Global Const $CV_CAP_PROP_DC1394_MODE_AUTO = -2
Global Const $CV_CAP_PROP_DC1394_MODE_ONE_PUSH_AUTO = -1
Global Const $CV_CAP_PROP_DC1394_MAX = 31
Global Const $CV_CAP_OPENNI_DEPTH_GENERATOR = (BitShift(1, -31))
Global Const $CV_CAP_OPENNI_IMAGE_GENERATOR = (BitShift(1, -30))
Global Const $CV_CAP_OPENNI_IR_GENERATOR = (BitShift(1, -29))
Global Const $CV_CAP_OPENNI_GENERATORS_MASK = $CV_CAP_OPENNI_DEPTH_GENERATOR + $CV_CAP_OPENNI_IMAGE_GENERATOR + $CV_CAP_OPENNI_IR_GENERATOR
Global Const $CV_CAP_PROP_OPENNI_OUTPUT_MODE = 100
Global Const $CV_CAP_PROP_OPENNI_FRAME_MAX_DEPTH = 101
Global Const $CV_CAP_PROP_OPENNI_BASELINE = 102
Global Const $CV_CAP_PROP_OPENNI_FOCAL_LENGTH = 103
Global Const $CV_CAP_PROP_OPENNI_REGISTRATION = 104
Global Const $CV_CAP_PROP_OPENNI_REGISTRATION_ON = $CV_CAP_PROP_OPENNI_REGISTRATION
Global Const $CV_CAP_PROP_OPENNI_APPROX_FRAME_SYNC = 105
Global Const $CV_CAP_PROP_OPENNI_MAX_BUFFER_SIZE = 106
Global Const $CV_CAP_PROP_OPENNI_CIRCLE_BUFFER = 107
Global Const $CV_CAP_PROP_OPENNI_MAX_TIME_DURATION = 108
Global Const $CV_CAP_PROP_OPENNI_GENERATOR_PRESENT = 109
Global Const $CV_CAP_PROP_OPENNI2_SYNC = 110
Global Const $CV_CAP_PROP_OPENNI2_MIRROR = 111
Global Const $CV_CAP_OPENNI_IMAGE_GENERATOR_PRESENT = $CV_CAP_OPENNI_IMAGE_GENERATOR + $CV_CAP_PROP_OPENNI_GENERATOR_PRESENT
Global Const $CV_CAP_OPENNI_IMAGE_GENERATOR_OUTPUT_MODE = $CV_CAP_OPENNI_IMAGE_GENERATOR + $CV_CAP_PROP_OPENNI_OUTPUT_MODE
Global Const $CV_CAP_OPENNI_DEPTH_GENERATOR_PRESENT = $CV_CAP_OPENNI_DEPTH_GENERATOR + $CV_CAP_PROP_OPENNI_GENERATOR_PRESENT
Global Const $CV_CAP_OPENNI_DEPTH_GENERATOR_BASELINE = $CV_CAP_OPENNI_DEPTH_GENERATOR + $CV_CAP_PROP_OPENNI_BASELINE
Global Const $CV_CAP_OPENNI_DEPTH_GENERATOR_FOCAL_LENGTH = $CV_CAP_OPENNI_DEPTH_GENERATOR + $CV_CAP_PROP_OPENNI_FOCAL_LENGTH
Global Const $CV_CAP_OPENNI_DEPTH_GENERATOR_REGISTRATION = $CV_CAP_OPENNI_DEPTH_GENERATOR + $CV_CAP_PROP_OPENNI_REGISTRATION
Global Const $CV_CAP_OPENNI_DEPTH_GENERATOR_REGISTRATION_ON = $CV_CAP_OPENNI_DEPTH_GENERATOR_REGISTRATION
Global Const $CV_CAP_OPENNI_IR_GENERATOR_PRESENT = $CV_CAP_OPENNI_IR_GENERATOR + $CV_CAP_PROP_OPENNI_GENERATOR_PRESENT
Global Const $CV_CAP_OPENNI_DEPTH_MAP = 0
Global Const $CV_CAP_OPENNI_POINT_CLOUD_MAP = 1
Global Const $CV_CAP_OPENNI_DISPARITY_MAP = 2
Global Const $CV_CAP_OPENNI_DISPARITY_MAP_32F = 3
Global Const $CV_CAP_OPENNI_VALID_DEPTH_MASK = 4
Global Const $CV_CAP_OPENNI_BGR_IMAGE = 5
Global Const $CV_CAP_OPENNI_GRAY_IMAGE = 6
Global Const $CV_CAP_OPENNI_IR_IMAGE = 7
Global Const $CV_CAP_OPENNI_VGA_30HZ = 0
Global Const $CV_CAP_OPENNI_SXGA_15HZ = 1
Global Const $CV_CAP_OPENNI_SXGA_30HZ = 2
Global Const $CV_CAP_OPENNI_QVGA_30HZ = 3
Global Const $CV_CAP_OPENNI_QVGA_60HZ = 4
Global Const $CV_CAP_PROP_GSTREAMER_QUEUE_LENGTH = 200
Global Const $CV_CAP_PROP_PVAPI_MULTICASTIP = 300
Global Const $CV_CAP_PROP_PVAPI_FRAMESTARTTRIGGERMODE = 301
Global Const $CV_CAP_PROP_PVAPI_DECIMATIONHORIZONTAL = 302
Global Const $CV_CAP_PROP_PVAPI_DECIMATIONVERTICAL = 303
Global Const $CV_CAP_PROP_PVAPI_BINNINGX = 304
Global Const $CV_CAP_PROP_PVAPI_BINNINGY = 305
Global Const $CV_CAP_PROP_PVAPI_PIXELFORMAT = 306
Global Const $CV_CAP_PVAPI_FSTRIGMODE_FREERUN = 0
Global Const $CV_CAP_PVAPI_FSTRIGMODE_SYNCIN1 = 1
Global Const $CV_CAP_PVAPI_FSTRIGMODE_SYNCIN2 = 2
Global Const $CV_CAP_PVAPI_FSTRIGMODE_FIXEDRATE = 3
Global Const $CV_CAP_PVAPI_FSTRIGMODE_SOFTWARE = 4
Global Const $CV_CAP_PVAPI_DECIMATION_OFF = 1
Global Const $CV_CAP_PVAPI_DECIMATION_2OUTOF4 = 2
Global Const $CV_CAP_PVAPI_DECIMATION_2OUTOF8 = 4
Global Const $CV_CAP_PVAPI_DECIMATION_2OUTOF16 = 8
Global Const $CV_CAP_PVAPI_PIXELFORMAT_MONO8 = 1
Global Const $CV_CAP_PVAPI_PIXELFORMAT_MONO16 = 2
Global Const $CV_CAP_PVAPI_PIXELFORMAT_BAYER8 = 3
Global Const $CV_CAP_PVAPI_PIXELFORMAT_BAYER16 = 4
Global Const $CV_CAP_PVAPI_PIXELFORMAT_RGB24 = 5
Global Const $CV_CAP_PVAPI_PIXELFORMAT_BGR24 = 6
Global Const $CV_CAP_PVAPI_PIXELFORMAT_RGBA32 = 7
Global Const $CV_CAP_PVAPI_PIXELFORMAT_BGRA32 = 8
Global Const $CV_CAP_PROP_XI_DOWNSAMPLING = 400
Global Const $CV_CAP_PROP_XI_DATA_FORMAT = 401
Global Const $CV_CAP_PROP_XI_OFFSET_X = 402
Global Const $CV_CAP_PROP_XI_OFFSET_Y = 403
Global Const $CV_CAP_PROP_XI_TRG_SOURCE = 404
Global Const $CV_CAP_PROP_XI_TRG_SOFTWARE = 405
Global Const $CV_CAP_PROP_XI_GPI_SELECTOR = 406
Global Const $CV_CAP_PROP_XI_GPI_MODE = 407
Global Const $CV_CAP_PROP_XI_GPI_LEVEL = 408
Global Const $CV_CAP_PROP_XI_GPO_SELECTOR = 409
Global Const $CV_CAP_PROP_XI_GPO_MODE = 410
Global Const $CV_CAP_PROP_XI_LED_SELECTOR = 411
Global Const $CV_CAP_PROP_XI_LED_MODE = 412
Global Const $CV_CAP_PROP_XI_MANUAL_WB = 413
Global Const $CV_CAP_PROP_XI_AUTO_WB = 414
Global Const $CV_CAP_PROP_XI_AEAG = 415
Global Const $CV_CAP_PROP_XI_EXP_PRIORITY = 416
Global Const $CV_CAP_PROP_XI_AE_MAX_LIMIT = 417
Global Const $CV_CAP_PROP_XI_AG_MAX_LIMIT = 418
Global Const $CV_CAP_PROP_XI_AEAG_LEVEL = 419
Global Const $CV_CAP_PROP_XI_TIMEOUT = 420
Global Const $CV_CAP_PROP_XI_EXPOSURE = 421
Global Const $CV_CAP_PROP_XI_EXPOSURE_BURST_COUNT = 422
Global Const $CV_CAP_PROP_XI_GAIN_SELECTOR = 423
Global Const $CV_CAP_PROP_XI_GAIN = 424
Global Const $CV_CAP_PROP_XI_DOWNSAMPLING_TYPE = 426
Global Const $CV_CAP_PROP_XI_BINNING_SELECTOR = 427
Global Const $CV_CAP_PROP_XI_BINNING_VERTICAL = 428
Global Const $CV_CAP_PROP_XI_BINNING_HORIZONTAL = 429
Global Const $CV_CAP_PROP_XI_BINNING_PATTERN = 430
Global Const $CV_CAP_PROP_XI_DECIMATION_SELECTOR = 431
Global Const $CV_CAP_PROP_XI_DECIMATION_VERTICAL = 432
Global Const $CV_CAP_PROP_XI_DECIMATION_HORIZONTAL = 433
Global Const $CV_CAP_PROP_XI_DECIMATION_PATTERN = 434
Global Const $CV_CAP_PROP_XI_TEST_PATTERN_GENERATOR_SELECTOR = 587
Global Const $CV_CAP_PROP_XI_TEST_PATTERN = 588
Global Const $CV_CAP_PROP_XI_IMAGE_DATA_FORMAT = 435
Global Const $CV_CAP_PROP_XI_SHUTTER_TYPE = 436
Global Const $CV_CAP_PROP_XI_SENSOR_TAPS = 437
Global Const $CV_CAP_PROP_XI_AEAG_ROI_OFFSET_X = 439
Global Const $CV_CAP_PROP_XI_AEAG_ROI_OFFSET_Y = 440
Global Const $CV_CAP_PROP_XI_AEAG_ROI_WIDTH = 441
Global Const $CV_CAP_PROP_XI_AEAG_ROI_HEIGHT = 442
Global Const $CV_CAP_PROP_XI_BPC = 445
Global Const $CV_CAP_PROP_XI_WB_KR = 448
Global Const $CV_CAP_PROP_XI_WB_KG = 449
Global Const $CV_CAP_PROP_XI_WB_KB = 450
Global Const $CV_CAP_PROP_XI_WIDTH = 451
Global Const $CV_CAP_PROP_XI_HEIGHT = 452
Global Const $CV_CAP_PROP_XI_REGION_SELECTOR = 589
Global Const $CV_CAP_PROP_XI_REGION_MODE = 595
Global Const $CV_CAP_PROP_XI_LIMIT_BANDWIDTH = 459
Global Const $CV_CAP_PROP_XI_SENSOR_DATA_BIT_DEPTH = 460
Global Const $CV_CAP_PROP_XI_OUTPUT_DATA_BIT_DEPTH = 461
Global Const $CV_CAP_PROP_XI_IMAGE_DATA_BIT_DEPTH = 462
Global Const $CV_CAP_PROP_XI_OUTPUT_DATA_PACKING = 463
Global Const $CV_CAP_PROP_XI_OUTPUT_DATA_PACKING_TYPE = 464
Global Const $CV_CAP_PROP_XI_IS_COOLED = 465
Global Const $CV_CAP_PROP_XI_COOLING = 466
Global Const $CV_CAP_PROP_XI_TARGET_TEMP = 467
Global Const $CV_CAP_PROP_XI_CHIP_TEMP = 468
Global Const $CV_CAP_PROP_XI_HOUS_TEMP = 469
Global Const $CV_CAP_PROP_XI_HOUS_BACK_SIDE_TEMP = 590
Global Const $CV_CAP_PROP_XI_SENSOR_BOARD_TEMP = 596
Global Const $CV_CAP_PROP_XI_CMS = 470
Global Const $CV_CAP_PROP_XI_APPLY_CMS = 471
Global Const $CV_CAP_PROP_XI_IMAGE_IS_COLOR = 474
Global Const $CV_CAP_PROP_XI_COLOR_FILTER_ARRAY = 475
Global Const $CV_CAP_PROP_XI_GAMMAY = 476
Global Const $CV_CAP_PROP_XI_GAMMAC = 477
Global Const $CV_CAP_PROP_XI_SHARPNESS = 478
Global Const $CV_CAP_PROP_XI_CC_MATRIX_00 = 479
Global Const $CV_CAP_PROP_XI_CC_MATRIX_01 = 480
Global Const $CV_CAP_PROP_XI_CC_MATRIX_02 = 481
Global Const $CV_CAP_PROP_XI_CC_MATRIX_03 = 482
Global Const $CV_CAP_PROP_XI_CC_MATRIX_10 = 483
Global Const $CV_CAP_PROP_XI_CC_MATRIX_11 = 484
Global Const $CV_CAP_PROP_XI_CC_MATRIX_12 = 485
Global Const $CV_CAP_PROP_XI_CC_MATRIX_13 = 486
Global Const $CV_CAP_PROP_XI_CC_MATRIX_20 = 487
Global Const $CV_CAP_PROP_XI_CC_MATRIX_21 = 488
Global Const $CV_CAP_PROP_XI_CC_MATRIX_22 = 489
Global Const $CV_CAP_PROP_XI_CC_MATRIX_23 = 490
Global Const $CV_CAP_PROP_XI_CC_MATRIX_30 = 491
Global Const $CV_CAP_PROP_XI_CC_MATRIX_31 = 492
Global Const $CV_CAP_PROP_XI_CC_MATRIX_32 = 493
Global Const $CV_CAP_PROP_XI_CC_MATRIX_33 = 494
Global Const $CV_CAP_PROP_XI_DEFAULT_CC_MATRIX = 495
Global Const $CV_CAP_PROP_XI_TRG_SELECTOR = 498
Global Const $CV_CAP_PROP_XI_ACQ_FRAME_BURST_COUNT = 499
Global Const $CV_CAP_PROP_XI_DEBOUNCE_EN = 507
Global Const $CV_CAP_PROP_XI_DEBOUNCE_T0 = 508
Global Const $CV_CAP_PROP_XI_DEBOUNCE_T1 = 509
Global Const $CV_CAP_PROP_XI_DEBOUNCE_POL = 510
Global Const $CV_CAP_PROP_XI_LENS_MODE = 511
Global Const $CV_CAP_PROP_XI_LENS_APERTURE_VALUE = 512
Global Const $CV_CAP_PROP_XI_LENS_FOCUS_MOVEMENT_VALUE = 513
Global Const $CV_CAP_PROP_XI_LENS_FOCUS_MOVE = 514
Global Const $CV_CAP_PROP_XI_LENS_FOCUS_DISTANCE = 515
Global Const $CV_CAP_PROP_XI_LENS_FOCAL_LENGTH = 516
Global Const $CV_CAP_PROP_XI_LENS_FEATURE_SELECTOR = 517
Global Const $CV_CAP_PROP_XI_LENS_FEATURE = 518
Global Const $CV_CAP_PROP_XI_DEVICE_MODEL_ID = 521
Global Const $CV_CAP_PROP_XI_DEVICE_SN = 522
Global Const $CV_CAP_PROP_XI_IMAGE_DATA_FORMAT_RGB32_ALPHA = 529
Global Const $CV_CAP_PROP_XI_IMAGE_PAYLOAD_SIZE = 530
Global Const $CV_CAP_PROP_XI_TRANSPORT_PIXEL_FORMAT = 531
Global Const $CV_CAP_PROP_XI_SENSOR_CLOCK_FREQ_HZ = 532
Global Const $CV_CAP_PROP_XI_SENSOR_CLOCK_FREQ_INDEX = 533
Global Const $CV_CAP_PROP_XI_SENSOR_OUTPUT_CHANNEL_COUNT = 534
Global Const $CV_CAP_PROP_XI_FRAMERATE = 535
Global Const $CV_CAP_PROP_XI_COUNTER_SELECTOR = 536
Global Const $CV_CAP_PROP_XI_COUNTER_VALUE = 537
Global Const $CV_CAP_PROP_XI_ACQ_TIMING_MODE = 538
Global Const $CV_CAP_PROP_XI_AVAILABLE_BANDWIDTH = 539
Global Const $CV_CAP_PROP_XI_BUFFER_POLICY = 540
Global Const $CV_CAP_PROP_XI_LUT_EN = 541
Global Const $CV_CAP_PROP_XI_LUT_INDEX = 542
Global Const $CV_CAP_PROP_XI_LUT_VALUE = 543
Global Const $CV_CAP_PROP_XI_TRG_DELAY = 544
Global Const $CV_CAP_PROP_XI_TS_RST_MODE = 545
Global Const $CV_CAP_PROP_XI_TS_RST_SOURCE = 546
Global Const $CV_CAP_PROP_XI_IS_DEVICE_EXIST = 547
Global Const $CV_CAP_PROP_XI_ACQ_BUFFER_SIZE = 548
Global Const $CV_CAP_PROP_XI_ACQ_BUFFER_SIZE_UNIT = 549
Global Const $CV_CAP_PROP_XI_ACQ_TRANSPORT_BUFFER_SIZE = 550
Global Const $CV_CAP_PROP_XI_BUFFERS_QUEUE_SIZE = 551
Global Const $CV_CAP_PROP_XI_ACQ_TRANSPORT_BUFFER_COMMIT = 552
Global Const $CV_CAP_PROP_XI_RECENT_FRAME = 553
Global Const $CV_CAP_PROP_XI_DEVICE_RESET = 554
Global Const $CV_CAP_PROP_XI_COLUMN_FPN_CORRECTION = 555
Global Const $CV_CAP_PROP_XI_ROW_FPN_CORRECTION = 591
Global Const $CV_CAP_PROP_XI_SENSOR_MODE = 558
Global Const $CV_CAP_PROP_XI_HDR = 559
Global Const $CV_CAP_PROP_XI_HDR_KNEEPOINT_COUNT = 560
Global Const $CV_CAP_PROP_XI_HDR_T1 = 561
Global Const $CV_CAP_PROP_XI_HDR_T2 = 562
Global Const $CV_CAP_PROP_XI_KNEEPOINT1 = 563
Global Const $CV_CAP_PROP_XI_KNEEPOINT2 = 564
Global Const $CV_CAP_PROP_XI_IMAGE_BLACK_LEVEL = 565
Global Const $CV_CAP_PROP_XI_HW_REVISION = 571
Global Const $CV_CAP_PROP_XI_DEBUG_LEVEL = 572
Global Const $CV_CAP_PROP_XI_AUTO_BANDWIDTH_CALCULATION = 573
Global Const $CV_CAP_PROP_XI_FFS_FILE_ID = 594
Global Const $CV_CAP_PROP_XI_FFS_FILE_SIZE = 580
Global Const $CV_CAP_PROP_XI_FREE_FFS_SIZE = 581
Global Const $CV_CAP_PROP_XI_USED_FFS_SIZE = 582
Global Const $CV_CAP_PROP_XI_FFS_ACCESS_KEY = 583
Global Const $CV_CAP_PROP_XI_SENSOR_FEATURE_SELECTOR = 585
Global Const $CV_CAP_PROP_XI_SENSOR_FEATURE_VALUE = 586
Global Const $CV_CAP_PROP_ARAVIS_AUTOTRIGGER = 600
Global Const $CV_CAP_PROP_IOS_DEVICE_FOCUS = 9001
Global Const $CV_CAP_PROP_IOS_DEVICE_EXPOSURE = 9002
Global Const $CV_CAP_PROP_IOS_DEVICE_FLASH = 9003
Global Const $CV_CAP_PROP_IOS_DEVICE_WHITEBALANCE = 9004
Global Const $CV_CAP_PROP_IOS_DEVICE_TORCH = 9005
Global Const $CV_CAP_PROP_GIGA_FRAME_OFFSET_X = 10001
Global Const $CV_CAP_PROP_GIGA_FRAME_OFFSET_Y = 10002
Global Const $CV_CAP_PROP_GIGA_FRAME_WIDTH_MAX = 10003
Global Const $CV_CAP_PROP_GIGA_FRAME_HEIGH_MAX = 10004
Global Const $CV_CAP_PROP_GIGA_FRAME_SENS_WIDTH = 10005
Global Const $CV_CAP_PROP_GIGA_FRAME_SENS_HEIGH = 10006
Global Const $CV_CAP_PROP_INTELPERC_PROFILE_COUNT = 11001
Global Const $CV_CAP_PROP_INTELPERC_PROFILE_IDX = 11002
Global Const $CV_CAP_PROP_INTELPERC_DEPTH_LOW_CONFIDENCE_VALUE = 11003
Global Const $CV_CAP_PROP_INTELPERC_DEPTH_SATURATION_VALUE = 11004
Global Const $CV_CAP_PROP_INTELPERC_DEPTH_CONFIDENCE_THRESHOLD = 11005
Global Const $CV_CAP_PROP_INTELPERC_DEPTH_FOCAL_LENGTH_HORZ = 11006
Global Const $CV_CAP_PROP_INTELPERC_DEPTH_FOCAL_LENGTH_VERT = 11007
Global Const $CV_CAP_INTELPERC_DEPTH_GENERATOR = (BitShift(1, -29))
Global Const $CV_CAP_INTELPERC_IMAGE_GENERATOR = (BitShift(1, -28))
Global Const $CV_CAP_INTELPERC_IR_GENERATOR = (BitShift(1, -27))
Global Const $CV_CAP_INTELPERC_GENERATORS_MASK = $CV_CAP_INTELPERC_DEPTH_GENERATOR + $CV_CAP_INTELPERC_IMAGE_GENERATOR + $CV_CAP_INTELPERC_IR_GENERATOR
Global Const $CV_CAP_INTELPERC_DEPTH_MAP = 0
Global Const $CV_CAP_INTELPERC_UVDEPTH_MAP = 1
Global Const $CV_CAP_INTELPERC_IR_MAP = 2
Global Const $CV_CAP_INTELPERC_IMAGE = 3
Global Const $CV_CAP_PROP_GPHOTO2_PREVIEW = 17001
Global Const $CV_CAP_PROP_GPHOTO2_WIDGET_ENUMERATE = 17002
Global Const $CV_CAP_PROP_GPHOTO2_RELOAD_CONFIG = 17003
Global Const $CV_CAP_PROP_GPHOTO2_RELOAD_ON_CHANGE = 17004
Global Const $CV_CAP_PROP_GPHOTO2_COLLECT_MSGS = 17005
Global Const $CV_CAP_PROP_GPHOTO2_FLUSH_MSGS = 17006
Global Const $CV_CAP_PROP_SPEED = 17007
Global Const $CV_CAP_PROP_APERTURE = 17008
Global Const $CV_CAP_PROP_EXPOSUREPROGRAM = 17009
Global Const $CV_CAP_PROP_VIEWFINDER = 17010
Global Const $CV_CAP_PROP_IMAGES_BASE = 18000
Global Const $CV_CAP_PROP_IMAGES_LAST = 19000
#EndRegion ..\opencv\modules\videoio\include\opencv2\videoio.hpp



#Region ..\opencv\modules\videoio\include\opencv2\videoio\cap_winrt.hpp
; anonymous
Global Const $CV_OPEN_CAMERA = 300
Global Const $CV_CLOSE_CAMERA = 1
Global Const $CV_UPDATE_IMAGE_ELEMENT = 2
Global Const $CV_SHOW_TRACKBAR = 3
#EndRegion ..\opencv\modules\videoio\include\opencv2\videoio\cap_winrt.hpp



#Region ..\opencv\modules\videoio\include\opencv2\videoio\container_avi.private.hpp
; Codecs
Global Const $CV_MJPEG = 0

; anonymous
Global Const $CV_COLORSPACE_GRAY = 0
Global Const $CV_COLORSPACE_RGBA = 1
Global Const $CV_COLORSPACE_BGR = 2
Global Const $CV_COLORSPACE_YUV444P = 3
#EndRegion ..\opencv\modules\videoio\include\opencv2\videoio\container_avi.private.hpp



#Region ..\opencv_contrib\modules\aruco\include\opencv2\aruco.hpp
; CornerRefineMethod
Global Const $CV_CORNER_REFINE_NONE = 0
Global Const $CV_CORNER_REFINE_SUBPIX = 1
Global Const $CV_CORNER_REFINE_CONTOUR = 2
Global Const $CV_CORNER_REFINE_APRILTAG = 3
#EndRegion ..\opencv_contrib\modules\aruco\include\opencv2\aruco.hpp



#Region ..\opencv_contrib\modules\aruco\include\opencv2\aruco\dictionary.hpp
; PREDEFINED_DICTIONARY_NAME
Global Const $CV_DICT_4X4_50 = 0
Global Const $CV_DICT_4X4_100 = 1
Global Const $CV_DICT_4X4_250 = 2
Global Const $CV_DICT_4X4_1000 = 3
Global Const $CV_DICT_5X5_50 = 4
Global Const $CV_DICT_5X5_100 = 5
Global Const $CV_DICT_5X5_250 = 6
Global Const $CV_DICT_5X5_1000 = 7
Global Const $CV_DICT_6X6_50 = 8
Global Const $CV_DICT_6X6_100 = 9
Global Const $CV_DICT_6X6_250 = 10
Global Const $CV_DICT_6X6_1000 = 11
Global Const $CV_DICT_7X7_50 = 12
Global Const $CV_DICT_7X7_100 = 13
Global Const $CV_DICT_7X7_250 = 14
Global Const $CV_DICT_7X7_1000 = 15
Global Const $CV_DICT_ARUCO_ORIGINAL = 16
Global Const $CV_DICT_APRILTAG_16h5 = 17
Global Const $CV_DICT_APRILTAG_25h9 = 18
Global Const $CV_DICT_APRILTAG_36h10 = 19
Global Const $CV_DICT_APRILTAG_36h11 = 20
#EndRegion ..\opencv_contrib\modules\aruco\include\opencv2\aruco\dictionary.hpp



#Region ..\opencv_contrib\modules\barcode\include\opencv2\barcode.hpp
; BarcodeType
Global Const $CV_NONE = 0
Global Const $CV_EAN_8 = 1
Global Const $CV_EAN_13 = 2
Global Const $CV_UPC_A = 3
Global Const $CV_UPC_E = 4
Global Const $CV_UPC_EAN_EXTENSION = 5
#EndRegion ..\opencv_contrib\modules\barcode\include\opencv2\barcode.hpp



#Region ..\opencv_contrib\modules\bgsegm\include\opencv2\bgsegm.hpp
; LSBPCameraMotionCompensation
Global Const $CV_LSBP_CAMERA_MOTION_COMPENSATION_NONE = 0
Global Const $CV_LSBP_CAMERA_MOTION_COMPENSATION_LK = 1
#EndRegion ..\opencv_contrib\modules\bgsegm\include\opencv2\bgsegm.hpp



#Region ..\opencv_contrib\modules\bioinspired\include\opencv2\bioinspired\retina.hpp
; anonymous
Global Const $CV_RETINA_COLOR_RANDOM = 0
Global Const $CV_RETINA_COLOR_DIAGONAL = 1
Global Const $CV_RETINA_COLOR_BAYER = 2
#EndRegion ..\opencv_contrib\modules\bioinspired\include\opencv2\bioinspired\retina.hpp



#Region ..\opencv_contrib\modules\fuzzy\include\opencv2\fuzzy\types.hpp
; anonymous
Global Const $CV_LINEAR = 1
Global Const $CV_SINUS = 2
Global Const $CV_ONE_STEP = 1
Global Const $CV_MULTI_STEP = 2
Global Const $CV_ITERATIVE = 3
#EndRegion ..\opencv_contrib\modules\fuzzy\include\opencv2\fuzzy\types.hpp



#Region ..\opencv_contrib\modules\hdf\include\opencv2\hdf\hdf5.hpp
; anonymous
Global Const $CV_HDF5_H5_UNLIMITED = -1
Global Const $CV_HDF5_H5_NONE = -1
Global Const $CV_HDF5_H5_GETDIMS = 100
Global Const $CV_HDF5_H5_GETMAXDIMS = 101
Global Const $CV_HDF5_H5_GETCHUNKDIMS = 102
#EndRegion ..\opencv_contrib\modules\hdf\include\opencv2\hdf\hdf5.hpp



#Region ..\opencv_contrib\modules\img_hash\include\opencv2\img_hash\block_mean_hash.hpp
; BlockMeanHashMode
Global Const $CV_IMG_HASH_BLOCK_MEAN_HASH_MODE_0 = 0
Global Const $CV_IMG_HASH_BLOCK_MEAN_HASH_MODE_1 = 1
#EndRegion ..\opencv_contrib\modules\img_hash\include\opencv2\img_hash\block_mean_hash.hpp



#Region ..\opencv_contrib\modules\mcc\include\opencv2\mcc\ccm.hpp
; CCM_TYPE
Global Const $CV_CCM_3x3 = 0
Global Const $CV_CCM_4x3 = 1

; INITIAL_METHOD_TYPE
Global Const $CV_INITIAL_METHOD_WHITE_BALANCE = 0
Global Const $CV_INITIAL_METHOD_LEAST_SQUARE = 1

; CONST_COLOR
Global Const $CV_COLORCHECKER_Macbeth = 0
Global Const $CV_COLORCHECKER_Vinyl = 1
Global Const $CV_COLORCHECKER_DigitalSG = 2

; COLOR_SPACE
Global Const $CV_COLOR_SPACE_sRGB = 0
Global Const $CV_COLOR_SPACE_sRGBL = 1
Global Const $CV_COLOR_SPACE_AdobeRGB = 2
Global Const $CV_COLOR_SPACE_AdobeRGBL = 3
Global Const $CV_COLOR_SPACE_WideGamutRGB = 4
Global Const $CV_COLOR_SPACE_WideGamutRGBL = 5
Global Const $CV_COLOR_SPACE_ProPhotoRGB = 6
Global Const $CV_COLOR_SPACE_ProPhotoRGBL = 7
Global Const $CV_COLOR_SPACE_DCI_P3_RGB = 8
Global Const $CV_COLOR_SPACE_DCI_P3_RGBL = 9
Global Const $CV_COLOR_SPACE_AppleRGB = 10
Global Const $CV_COLOR_SPACE_AppleRGBL = 11
Global Const $CV_COLOR_SPACE_REC_709_RGB = 12
Global Const $CV_COLOR_SPACE_REC_709_RGBL = 13
Global Const $CV_COLOR_SPACE_REC_2020_RGB = 14
Global Const $CV_COLOR_SPACE_REC_2020_RGBL = 15
Global Const $CV_COLOR_SPACE_XYZ_D65_2 = 16
Global Const $CV_COLOR_SPACE_XYZ_D65_10 = 17
Global Const $CV_COLOR_SPACE_XYZ_D50_2 = 18
Global Const $CV_COLOR_SPACE_XYZ_D50_10 = 19
Global Const $CV_COLOR_SPACE_XYZ_A_2 = 20
Global Const $CV_COLOR_SPACE_XYZ_A_10 = 21
Global Const $CV_COLOR_SPACE_XYZ_D55_2 = 22
Global Const $CV_COLOR_SPACE_XYZ_D55_10 = 23
Global Const $CV_COLOR_SPACE_XYZ_D75_2 = 24
Global Const $CV_COLOR_SPACE_XYZ_D75_10 = 25
Global Const $CV_COLOR_SPACE_XYZ_E_2 = 26
Global Const $CV_COLOR_SPACE_XYZ_E_10 = 27
Global Const $CV_COLOR_SPACE_Lab_D65_2 = 28
Global Const $CV_COLOR_SPACE_Lab_D65_10 = 29
Global Const $CV_COLOR_SPACE_Lab_D50_2 = 30
Global Const $CV_COLOR_SPACE_Lab_D50_10 = 31
Global Const $CV_COLOR_SPACE_Lab_A_2 = 32
Global Const $CV_COLOR_SPACE_Lab_A_10 = 33
Global Const $CV_COLOR_SPACE_Lab_D55_2 = 34
Global Const $CV_COLOR_SPACE_Lab_D55_10 = 35
Global Const $CV_COLOR_SPACE_Lab_D75_2 = 36
Global Const $CV_COLOR_SPACE_Lab_D75_10 = 37
Global Const $CV_COLOR_SPACE_Lab_E_2 = 38
Global Const $CV_COLOR_SPACE_Lab_E_10 = 39

; LINEAR_TYPE
Global Const $CV_LINEARIZATION_IDENTITY = 0
Global Const $CV_LINEARIZATION_GAMMA = 1
Global Const $CV_LINEARIZATION_COLORPOLYFIT = 2
Global Const $CV_LINEARIZATION_COLORLOGPOLYFIT = 3
Global Const $CV_LINEARIZATION_GRAYPOLYFIT = 4
Global Const $CV_LINEARIZATION_GRAYLOGPOLYFIT = 5

; DISTANCE_TYPE
Global Const $CV_DISTANCE_CIE76 = 0
Global Const $CV_DISTANCE_CIE94_GRAPHIC_ARTS = 1
Global Const $CV_DISTANCE_CIE94_TEXTILES = 2
Global Const $CV_DISTANCE_CIE2000 = 3
Global Const $CV_DISTANCE_CMC_1TO1 = 4
Global Const $CV_DISTANCE_CMC_2TO1 = 5
Global Const $CV_DISTANCE_RGB = 6
Global Const $CV_DISTANCE_RGBL = 7
#EndRegion ..\opencv_contrib\modules\mcc\include\opencv2\mcc\ccm.hpp



#Region ..\opencv_contrib\modules\mcc\include\opencv2\mcc\checker_model.hpp
; TYPECHART
Global Const $CV_MCC24 = 0
Global Const $CV_SG140 = 1
Global Const $CV_VINYL18 = 2
#EndRegion ..\opencv_contrib\modules\mcc\include\opencv2\mcc\checker_model.hpp



#Region ..\opencv_contrib\modules\optflow\include\opencv2\optflow\rlofflow.hpp
; SupportRegionType
Global Const $CV_SR_FIXED = 0
Global Const $CV_SR_CROSS = 1

; SolverType
Global Const $CV_ST_STANDART = 0
Global Const $CV_ST_BILINEAR = 1

; InterpolationType
Global Const $CV_INTERP_GEO = 0
Global Const $CV_INTERP_EPIC = 1
Global Const $CV_INTERP_RIC = 2
#EndRegion ..\opencv_contrib\modules\optflow\include\opencv2\optflow\rlofflow.hpp



#Region ..\opencv_contrib\modules\optflow\include\opencv2\optflow\sparse_matching_gpc.hpp
; GPCDescType
Global Const $CV_GPC_DESCRIPTOR_DCT = 0
Global Const $CV_GPC_DESCRIPTOR_WHT = 1
#EndRegion ..\opencv_contrib\modules\optflow\include\opencv2\optflow\sparse_matching_gpc.hpp



#Region ..\opencv_contrib\modules\saliency\include\opencv2\saliency\saliencySpecializedClasses.hpp
; anonymous
Global Const $CV_OBJECTNESS_BING_MAXBGR = 0
Global Const $CV_OBJECTNESS_BING_HSV = 1
Global Const $CV_OBJECTNESS_BING_G = 2
#EndRegion ..\opencv_contrib\modules\saliency\include\opencv2\saliency\saliencySpecializedClasses.hpp



#Region ..\opencv_contrib\modules\stereo\include\opencv2\stereo.hpp
; anonymous



; anonymous
Global Const $CV_CV_SPECKLE_REMOVAL_ALGORITHM = 0
Global Const $CV_CV_SPECKLE_REMOVAL_AVG_ALGORITHM = 1
Global Const $CV_CV_QUADRATIC_INTERPOLATION = 2
Global Const $CV_CV_SIMETRICV_INTERPOLATION = 3

; anonymous
Global Const $CV_STEREO_BINARY_BM_PREFILTER_NORMALIZED_RESPONSE = 0
Global Const $CV_STEREO_BINARY_BM_PREFILTER_XSOBEL = 1

; anonymous
Global Const $CV_STEREO_BINARY_SGBM_MODE_SGBM = 0
Global Const $CV_STEREO_BINARY_SGBM_MODE_HH = 1
#EndRegion ..\opencv_contrib\modules\stereo\include\opencv2\stereo.hpp



#Region ..\opencv_contrib\modules\stereo\include\opencv2\stereo\descriptor.hpp
; anonymous
Global Const $CV_CV_DENSE_CENSUS = 0
Global Const $CV_CV_SPARSE_CENSUS = 1
Global Const $CV_CV_CS_CENSUS = 2
Global Const $CV_CV_MODIFIED_CS_CENSUS = 3
Global Const $CV_CV_MODIFIED_CENSUS_TRANSFORM = 4
Global Const $CV_CV_MEAN_VARIATION = 5
Global Const $CV_CV_STAR_KERNEL = 6
#EndRegion ..\opencv_contrib\modules\stereo\include\opencv2\stereo\descriptor.hpp



#Region ..\opencv_contrib\modules\surface_matching\include\opencv2\surface_matching\icp.hpp
; anonymous
Global Const $CV_PPF_MATCH_3D_ICP_ICP_SAMPLING_TYPE_UNIFORM = 0
Global Const $CV_PPF_MATCH_3D_ICP_ICP_SAMPLING_TYPE_GELFAND = 1
#EndRegion ..\opencv_contrib\modules\surface_matching\include\opencv2\surface_matching\icp.hpp



#Region ..\opencv_contrib\modules\text\include\opencv2\text\erfilter.hpp
; anonymous
Global Const $CV_ERFILTER_NM_RGBLGrad = 0
Global Const $CV_ERFILTER_NM_IHSGrad = 1

; erGrouping_Modes
Global Const $CV_ERGROUPING_ORIENTATION_HORIZ = 0
Global Const $CV_ERGROUPING_ORIENTATION_ANY = 1
#EndRegion ..\opencv_contrib\modules\text\include\opencv2\text\erfilter.hpp



#Region ..\opencv_contrib\modules\text\include\opencv2\text\ocr.hpp
; anonymous
Global Const $CV_OCR_LEVEL_WORD = 0
Global Const $CV_OCR_LEVEL_TEXTLINE = 1

; page_seg_mode
Global Const $CV_PSM_OSD_ONLY = 0
Global Const $CV_PSM_AUTO_OSD = 1
Global Const $CV_PSM_AUTO_ONLY = 2
Global Const $CV_PSM_AUTO = 3
Global Const $CV_PSM_SINGLE_COLUMN = 4
Global Const $CV_PSM_SINGLE_BLOCK_VERT_TEXT = 5
Global Const $CV_PSM_SINGLE_BLOCK = 6
Global Const $CV_PSM_SINGLE_LINE = 7
Global Const $CV_PSM_SINGLE_WORD = 8
Global Const $CV_PSM_CIRCLE_WORD = 9
Global Const $CV_PSM_SINGLE_CHAR = 10

; ocr_engine_mode
Global Const $CV_OEM_TESSERACT_ONLY = 0
Global Const $CV_OEM_CUBE_ONLY = 1
Global Const $CV_OEM_TESSERACT_CUBE_COMBINED = 2
Global Const $CV_OEM_DEFAULT = 3

; decoder_mode
Global Const $CV_OCR_DECODER_VITERBI = 0

; classifier_type
Global Const $CV_OCR_KNN_CLASSIFIER = 0
Global Const $CV_OCR_CNN_CLASSIFIER = 1
#EndRegion ..\opencv_contrib\modules\text\include\opencv2\text\ocr.hpp



#Region ..\opencv_contrib\modules\tracking\include\opencv2\tracking.hpp
; MODE
Global Const $CV_TRACKER_KCF_GRAY = (BitShift(1, -0))
Global Const $CV_TRACKER_KCF_CN = (BitShift(1, -1))
Global Const $CV_TRACKER_KCF_CUSTOM = (BitShift(1, -2))
#EndRegion ..\opencv_contrib\modules\tracking\include\opencv2\tracking.hpp



#Region ..\opencv_contrib\modules\tracking\include\opencv2\tracking\feature.hpp
; FeatureType
Global Const $CV_CONTRIB_FEATURE_CV_FEATURE_PARAMS_HAAR = 0
Global Const $CV_CONTRIB_FEATURE_CV_FEATURE_PARAMS_LBP = 1
Global Const $CV_CONTRIB_FEATURE_CV_FEATURE_PARAMS_HOG = 2
#EndRegion ..\opencv_contrib\modules\tracking\include\opencv2\tracking\feature.hpp



#Region ..\opencv_contrib\modules\tracking\include\opencv2\tracking\tracking_internals.hpp
; anonymous
Global Const $CV_TRACKER_CONTRIB_SAMPLER_CSC_MODE_INIT_POS = 1
Global Const $CV_TRACKER_CONTRIB_SAMPLER_CSC_MODE_INIT_NEG = 2
Global Const $CV_TRACKER_CONTRIB_SAMPLER_CSC_MODE_TRACK_POS = 3
Global Const $CV_TRACKER_CONTRIB_SAMPLER_CSC_MODE_TRACK_NEG = 4
Global Const $CV_TRACKER_CONTRIB_SAMPLER_CSC_MODE_DETECT = 5

; anonymous
Global Const $CV_TRACKER_SAMPLER_CS_MODE_POSITIVE = 1
Global Const $CV_TRACKER_SAMPLER_CS_MODE_NEGATIVE = 2
Global Const $CV_TRACKER_SAMPLER_CS_MODE_CLASSIFY = 3
#EndRegion ..\opencv_contrib\modules\tracking\include\opencv2\tracking\tracking_internals.hpp



#Region ..\opencv_contrib\modules\videostab\include\opencv2\videostab\fast_marching.hpp
; anonymous
Global Const $CV_FAST_MARCHING_METHOD_INSIDE = 0
Global Const $CV_FAST_MARCHING_METHOD_BAND = 1
Global Const $CV_FAST_MARCHING_METHOD_KNOWN = 255
#EndRegion ..\opencv_contrib\modules\videostab\include\opencv2\videostab\fast_marching.hpp



#Region ..\opencv_contrib\modules\videostab\include\opencv2\videostab\motion_core.hpp
; MotionModel
Global Const $CV_MM_TRANSLATION = 0
Global Const $CV_MM_TRANSLATION_AND_SCALE = 1
Global Const $CV_MM_ROTATION = 2
Global Const $CV_MM_RIGID = 3
Global Const $CV_MM_SIMILARITY = 4
Global Const $CV_MM_AFFINE = 5
Global Const $CV_MM_HOMOGRAPHY = 6
Global Const $CV_MM_UNKNOWN = 7
#EndRegion ..\opencv_contrib\modules\videostab\include\opencv2\videostab\motion_core.hpp



#Region ..\opencv_contrib\modules\viz\include\opencv2\viz\types.hpp
; anonymous
Global Const $CV_MESH_LOAD_AUTO = 0
Global Const $CV_MESH_LOAD_PLY = 1
Global Const $CV_MESH_LOAD_OBJ = 2

; anonymous
Global Const $CV_KEYBOARD_EVENT_NONE = 0
Global Const $CV_KEYBOARD_EVENT_ALT = 1
Global Const $CV_KEYBOARD_EVENT_CTRL = 2
Global Const $CV_KEYBOARD_EVENT_SHIFT = 4

; Action
Global Const $CV_KEYBOARD_EVENT_KEY_UP = 0
Global Const $CV_KEYBOARD_EVENT_KEY_DOWN = 1

; Type
Global Const $CV_MOUSE_EVENT_MouseMove = 1
Global Const $CV_MOUSE_EVENT_MouseButtonPress = 1
Global Const $CV_MOUSE_EVENT_MouseButtonRelease = 2
Global Const $CV_MOUSE_EVENT_MouseScrollDown = 3
Global Const $CV_MOUSE_EVENT_MouseScrollUp = 4
Global Const $CV_MOUSE_EVENT_MouseDblClick = 5

; MouseButton
Global Const $CV_MOUSE_EVENT_NoButton = 0
Global Const $CV_MOUSE_EVENT_LeftButton = 1
Global Const $CV_MOUSE_EVENT_MiddleButton = 2
Global Const $CV_MOUSE_EVENT_RightButton = 3
Global Const $CV_MOUSE_EVENT_VScroll = 4
#EndRegion ..\opencv_contrib\modules\viz\include\opencv2\viz\types.hpp



#Region ..\opencv_contrib\modules\viz\include\opencv2\viz\widgets.hpp
; RenderingProperties
Global Const $CV_POINT_SIZE = 0
Global Const $CV_OPACITY = 1
Global Const $CV_LINE_WIDTH = 2
Global Const $CV_FONT_SIZE = 3
Global Const $CV_REPRESENTATION = 4
Global Const $CV_IMMEDIATE_RENDERING = 5
Global Const $CV_SHADING = 6
Global Const $CV_AMBIENT = 7
Global Const $CV_LIGHTING = 8

; RepresentationValues
Global Const $CV_REPRESENTATION_POINTS = 0
Global Const $CV_REPRESENTATION_WIREFRAME = 1
Global Const $CV_REPRESENTATION_SURFACE = 2

; ShadingValues
Global Const $CV_SHADING_FLAT = 0
Global Const $CV_SHADING_GOURAUD = 1
Global Const $CV_SHADING_PHONG = 2

; anonymous
Global Const $CV_WTRAJECTORY_FRAMES = 1
Global Const $CV_WTRAJECTORY_PATH = 2
Global Const $CV_WTRAJECTORY_BOTH = $CV_WTRAJECTORY_FRAMES + $CV_WTRAJECTORY_PATH
#EndRegion ..\opencv_contrib\modules\viz\include\opencv2\viz\widgets.hpp



#Region ..\opencv_contrib\modules\xfeatures2d\include\opencv2\xfeatures2d.hpp
; BeblidSize
Global Const $CV_XFEATURES2D_BEBLID_SIZE_512_BITS = 100
Global Const $CV_XFEATURES2D_BEBLID_SIZE_256_BITS = 101

; NormalizationType
Global Const $CV_XFEATURES2D_DAISY_NRM_NONE = 100
Global Const $CV_XFEATURES2D_DAISY_NRM_PARTIAL = 101
Global Const $CV_XFEATURES2D_DAISY_NRM_FULL = 102
Global Const $CV_XFEATURES2D_DAISY_NRM_SIFT = 103

; anonymous
Global Const $CV_XFEATURES2D_VGG_VGG_120 = 100
Global Const $CV_XFEATURES2D_VGG_VGG_80 = 101
Global Const $CV_XFEATURES2D_VGG_VGG_64 = 102
Global Const $CV_XFEATURES2D_VGG_VGG_48 = 103

; anonymous
Global Const $CV_XFEATURES2D_BOOST_DESC_BGM = 100
Global Const $CV_XFEATURES2D_BOOST_DESC_BGM_HARD = 101
Global Const $CV_XFEATURES2D_BOOST_DESC_BGM_BILINEAR = 102
Global Const $CV_XFEATURES2D_BOOST_DESC_LBGM = 200
Global Const $CV_XFEATURES2D_BOOST_DESC_BINBOOST_64 = 300
Global Const $CV_XFEATURES2D_BOOST_DESC_BINBOOST_128 = 301
Global Const $CV_XFEATURES2D_BOOST_DESC_BINBOOST_256 = 302

; DistanceFunction
Global Const $CV_XFEATURES2D_PCTSIGNATURES_L0_25 = 0
Global Const $CV_XFEATURES2D_PCTSIGNATURES_L0_5 = 1
Global Const $CV_XFEATURES2D_PCTSIGNATURES_L1 = 2
Global Const $CV_XFEATURES2D_PCTSIGNATURES_L2 = 3
Global Const $CV_XFEATURES2D_PCTSIGNATURES_L2SQUARED = 4
Global Const $CV_XFEATURES2D_PCTSIGNATURES_L5 = 5
Global Const $CV_XFEATURES2D_PCTSIGNATURES_L_INFINITY = 6

; PointDistribution
Global Const $CV_XFEATURES2D_PCTSIGNATURES_UNIFORM = 0
Global Const $CV_XFEATURES2D_PCTSIGNATURES_REGULAR = 1
Global Const $CV_XFEATURES2D_PCTSIGNATURES_NORMAL = 2

; SimilarityFunction
Global Const $CV_XFEATURES2D_PCTSIGNATURES_MINUS = 0
Global Const $CV_XFEATURES2D_PCTSIGNATURES_GAUSSIAN = 1
Global Const $CV_XFEATURES2D_PCTSIGNATURES_HEURISTIC = 2
#EndRegion ..\opencv_contrib\modules\xfeatures2d\include\opencv2\xfeatures2d.hpp



#Region ..\opencv_contrib\modules\xfeatures2d\include\opencv2\xfeatures2d\cuda.hpp
; KeypointLayout
Global Const $CV_SURF_CUDA_X_ROW = 0
Global Const $CV_SURF_CUDA_Y_ROW = 1
Global Const $CV_SURF_CUDA_LAPLACIAN_ROW = 2
Global Const $CV_SURF_CUDA_OCTAVE_ROW = 3
Global Const $CV_SURF_CUDA_SIZE_ROW = 4
Global Const $CV_SURF_CUDA_ANGLE_ROW = 5
Global Const $CV_SURF_CUDA_HESSIAN_ROW = 6
Global Const $CV_SURF_CUDA_ROWS_COUNT = 7
#EndRegion ..\opencv_contrib\modules\xfeatures2d\include\opencv2\xfeatures2d\cuda.hpp



#Region ..\opencv_contrib\modules\ximgproc\include\opencv2\ximgproc.hpp
; ThinningTypes
Global Const $CV_THINNING_ZHANGSUEN = 0
Global Const $CV_THINNING_GUOHALL = 1

; LocalBinarizationMethods
Global Const $CV_BINARIZATION_NIBLACK = 0
Global Const $CV_BINARIZATION_SAUVOLA = 1
Global Const $CV_BINARIZATION_WOLF = 2
Global Const $CV_BINARIZATION_NICK = 3
#EndRegion ..\opencv_contrib\modules\ximgproc\include\opencv2\ximgproc.hpp



#Region ..\opencv_contrib\modules\ximgproc\include\opencv2\ximgproc\edge_drawing.hpp
; GradientOperator
Global Const $CV_EDGE_DRAWING_PREWITT = 0
Global Const $CV_EDGE_DRAWING_SOBEL = 1
Global Const $CV_EDGE_DRAWING_SCHARR = 2
Global Const $CV_EDGE_DRAWING_LSD = 3
#EndRegion ..\opencv_contrib\modules\ximgproc\include\opencv2\ximgproc\edge_drawing.hpp



#Region ..\opencv_contrib\modules\ximgproc\include\opencv2\ximgproc\edge_filter.hpp
; EdgeAwareFiltersList
Global Const $CV_DTF_NC = 0
Global Const $CV_DTF_IC = 1
Global Const $CV_DTF_RF = 2
Global Const $CV_GUIDED_FILTER = 3
Global Const $CV_AM_FILTER = 4
#EndRegion ..\opencv_contrib\modules\ximgproc\include\opencv2\ximgproc\edge_filter.hpp



#Region ..\opencv_contrib\modules\ximgproc\include\opencv2\ximgproc\fast_hough_transform.hpp
; AngleRangeOption
Global Const $CV_ARO_0_45 = 0
Global Const $CV_ARO_45_90 = 1
Global Const $CV_ARO_90_135 = 2
Global Const $CV_ARO_315_0 = 3
Global Const $CV_ARO_315_45 = 4
Global Const $CV_ARO_45_135 = 5
Global Const $CV_ARO_315_135 = 6
Global Const $CV_ARO_CTR_HOR = 7
Global Const $CV_ARO_CTR_VER = 8

; HoughOp
Global Const $CV_FHT_MIN = 0
Global Const $CV_FHT_MAX = 1
Global Const $CV_FHT_ADD = 2
Global Const $CV_FHT_AVE = 3

; HoughDeskewOption
Global Const $CV_HDO_RAW = 0
Global Const $CV_HDO_DESKEW = 1

; RulesOption
Global Const $CV_RO_STRICT = 0x00
Global Const $CV_RO_IGNORE_BORDERS = 0x01
#EndRegion ..\opencv_contrib\modules\ximgproc\include\opencv2\ximgproc\fast_hough_transform.hpp



#Region ..\opencv_contrib\modules\ximgproc\include\opencv2\ximgproc\slic.hpp
; SLICType
Global Const $CV_SLIC = 100
Global Const $CV_SLICO = 101
Global Const $CV_MSLIC = 102
#EndRegion ..\opencv_contrib\modules\ximgproc\include\opencv2\ximgproc\slic.hpp



#Region ..\opencv_contrib\modules\ximgproc\include\opencv2\ximgproc\weighted_median_filter.hpp
; WMFWeightType
Global Const $CV_WMF_EXP = 1
Global Const $CV_WMF_IV1 = (BitShift(1, -1))
Global Const $CV_WMF_IV2 = (BitShift(1, -2))
Global Const $CV_WMF_COS = (BitShift(1, -3))
Global Const $CV_WMF_JAC = (BitShift(1, -4))
Global Const $CV_WMF_OFF = (BitShift(1, -5))
#EndRegion ..\opencv_contrib\modules\ximgproc\include\opencv2\ximgproc\weighted_median_filter.hpp



#Region ..\opencv_contrib\modules\xphoto\include\opencv2\xphoto\bm3d_image_denoising.hpp
; TransformTypes
Global Const $CV_HAAR = 0

; Bm3dSteps
Global Const $CV_BM3D_STEPALL = 0
Global Const $CV_BM3D_STEP1 = 1
Global Const $CV_BM3D_STEP2 = 2
#EndRegion ..\opencv_contrib\modules\xphoto\include\opencv2\xphoto\bm3d_image_denoising.hpp



#Region ..\opencv_contrib\modules\xphoto\include\opencv2\xphoto\inpainting.hpp
; InpaintTypes
Global Const $CV_INPAINT_SHIFTMAP = 0
Global Const $CV_INPAINT_FSR_BEST = 1
Global Const $CV_INPAINT_FSR_FAST = 2
#EndRegion ..\opencv_contrib\modules\xphoto\include\opencv2\xphoto\inpainting.hpp