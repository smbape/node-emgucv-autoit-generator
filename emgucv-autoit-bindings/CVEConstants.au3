#include-once
#include <CVConstants.au3>

;~ opencv\sources\modules\imgcodecs\include\opencv2\imgcodecs.hpp : enum ImreadModes {
Global Const $CV_IMREAD_UNCHANGED = -1              ; If set, return the loaded image as is (with alpha channel, otherwise it gets cropped). Ignore EXIF orientation.
Global Const $CV_IMREAD_GRAYSCALE = 0               ; If set, always convert image to the single channel grayscale image (codec internal conversion).
Global Const $CV_IMREAD_COLOR = 1                   ; If set, always convert image to the 3 channel BGR color image.
Global Const $CV_IMREAD_ANYDEPTH = 2                ; If set, return 16-bit/32-bit image when the input has the corresponding depth, otherwise convert it to 8-bit.
Global Const $CV_IMREAD_ANYCOLOR = 4                ; If set, the image is read in any possible color format.
Global Const $CV_IMREAD_LOAD_GDAL = 8               ; If set, use the gdal driver for loading the image.
Global Const $CV_IMREAD_REDUCED_GRAYSCALE_2 = 16    ; If set, always convert image to the single channel grayscale image and the image size reduced 1/2.
Global Const $CV_IMREAD_REDUCED_COLOR_2 = 17        ; If set, always convert image to the 3 channel BGR color image and the image size reduced 1/2.
Global Const $CV_IMREAD_REDUCED_GRAYSCALE_4 = 32    ; If set, always convert image to the single channel grayscale image and the image size reduced 1/4.
Global Const $CV_IMREAD_REDUCED_COLOR_4 = 33        ; If set, always convert image to the 3 channel BGR color image and the image size reduced 1/4.
Global Const $CV_IMREAD_REDUCED_GRAYSCALE_8 = 64    ; If set, always convert image to the single channel grayscale image and the image size reduced 1/8.
Global Const $CV_IMREAD_REDUCED_COLOR_8 = 65        ; If set, always convert image to the 3 channel BGR color image and the image size reduced 1/8.
Global Const $CV_IMREAD_IGNORE_ORIENTATION = 128    ; If set, do not rotate the image according to EXIF's orientation flag.

;~ opencv\sources\modules\core\include\opencv2\core\base.hpp : enum NormTypes {
Global Const $CV_NORM_INF = 1
Global Const $CV_NORM_L1 = 2
Global Const $CV_NORM_L2 = 4
Global Const $CV_NORM_L2SQR = 5
Global Const $CV_NORM_HAMMING = 6
Global Const $CV_NORM_HAMMING2 = 7
Global Const $CV_NORM_TYPE_MASK = 7
Global Const $CV_NORM_RELATIVE = 8
Global Const $CV_NORM_MINMAX = 32

;~ opencv\sources\modules\imgproc\include\opencv2\imgproc.hpp
Global Const $CV_FILLED = -1
Global Const $CV_LINE_4 = 4  ; 4-connected line
Global Const $CV_LINE_8 = 8  ; 8-connected line
Global Const $CV_LINE_AA = 16 ; antialiased line


#cs
the color conversion codes
@see @ref imgproc_color_conversions
@ingroup imgproc_color_conversions
#ce
; enum ColorConversionCodes {
Global Const $CV_COLOR_BGR2BGRA = 0     ; !< add alpha channel to RGB or BGR image
Global Const $CV_COLOR_RGB2RGBA = $CV_COLOR_BGR2BGRA

Global Const $CV_COLOR_BGRA2BGR = 1     ; !< remove alpha channel from RGB or BGR image
Global Const $CV_COLOR_RGBA2RGB = $CV_COLOR_BGRA2BGR

Global Const $CV_COLOR_BGR2RGBA = 2     ; !< convert between RGB and BGR color spaces (with or without alpha channel)
Global Const $CV_COLOR_RGB2BGRA = $CV_COLOR_BGR2RGBA

Global Const $CV_COLOR_RGBA2BGR = 3
Global Const $CV_COLOR_BGRA2RGB = $CV_COLOR_RGBA2BGR

Global Const $CV_COLOR_BGR2RGB = 4
Global Const $CV_COLOR_RGB2BGR = $CV_COLOR_BGR2RGB

Global Const $CV_COLOR_BGRA2RGBA = 5
Global Const $CV_COLOR_RGBA2BGRA = $CV_COLOR_BGRA2RGBA

Global Const $CV_COLOR_BGR2GRAY = 6     ; !< convert between RGB/BGR and grayscale, @ref color_convert_rgb_gray "color conversions"
Global Const $CV_COLOR_RGB2GRAY = 7
Global Const $CV_COLOR_GRAY2BGR = 8
Global Const $CV_COLOR_GRAY2RGB = $CV_COLOR_GRAY2BGR
Global Const $CV_COLOR_GRAY2BGRA = 9
Global Const $CV_COLOR_GRAY2RGBA = $CV_COLOR_GRAY2BGRA
Global Const $CV_COLOR_BGRA2GRAY = 10
Global Const $CV_COLOR_RGBA2GRAY = 11

Global Const $CV_COLOR_BGR2BGR565 = 12   ; !< convert between RGB/BGR and BGR565 (16-bit images)
Global Const $CV_COLOR_RGB2BGR565 = 13
Global Const $CV_COLOR_BGR5652BGR = 14
Global Const $CV_COLOR_BGR5652RGB = 15
Global Const $CV_COLOR_BGRA2BGR565 = 16
Global Const $CV_COLOR_RGBA2BGR565 = 17
Global Const $CV_COLOR_BGR5652BGRA = 18
Global Const $CV_COLOR_BGR5652RGBA = 19

Global Const $CV_COLOR_GRAY2BGR565 = 20  ; !< convert between grayscale to BGR565 (16-bit images)
Global Const $CV_COLOR_BGR5652GRAY = 21

Global Const $CV_COLOR_BGR2BGR555 = 22    ; !< convert between RGB/BGR and BGR555 (16-bit images)
Global Const $CV_COLOR_RGB2BGR555 = 23
Global Const $CV_COLOR_BGR5552BGR = 24
Global Const $CV_COLOR_BGR5552RGB = 25
Global Const $CV_COLOR_BGRA2BGR555 = 26
Global Const $CV_COLOR_RGBA2BGR555 = 27
Global Const $CV_COLOR_BGR5552BGRA = 28
Global Const $CV_COLOR_BGR5552RGBA = 29

Global Const $CV_COLOR_GRAY2BGR555 = 30  ; !< convert between grayscale and BGR555 (16-bit images)
Global Const $CV_COLOR_BGR5552GRAY = 31

Global Const $CV_COLOR_BGR2XYZ = 32      ; !< convert RGB/BGR to CIE XYZ, @ref color_convert_rgb_xyz "color conversions"
Global Const $CV_COLOR_RGB2XYZ = 33
Global Const $CV_COLOR_XYZ2BGR = 34
Global Const $CV_COLOR_XYZ2RGB = 35

Global Const $CV_COLOR_BGR2YCrCb = 36    ; !< convert RGB/BGR to luma-chroma (aka YCC), @ref color_convert_rgb_ycrcb "color conversions"
Global Const $CV_COLOR_RGB2YCrCb = 37
Global Const $CV_COLOR_YCrCb2BGR = 38
Global Const $CV_COLOR_YCrCb2RGB = 39

Global Const $CV_COLOR_BGR2HSV = 40      ; !< convert RGB/BGR to HSV (hue saturation value) with H range 0..180 if 8 bit image, @ref color_convert_rgb_hsv "color conversions"
Global Const $CV_COLOR_RGB2HSV = 41

Global Const $CV_COLOR_BGR2Lab = 44      ; !< convert RGB/BGR to CIE Lab, @ref color_convert_rgb_lab "color conversions"
Global Const $CV_COLOR_RGB2Lab = 45

Global Const $CV_COLOR_BGR2Luv = 50      ; !< convert RGB/BGR to CIE Luv, @ref color_convert_rgb_luv "color conversions"
Global Const $CV_COLOR_RGB2Luv = 51
Global Const $CV_COLOR_BGR2HLS = 52      ; !< convert RGB/BGR to HLS (hue lightness saturation) with H range 0..180 if 8 bit image, @ref color_convert_rgb_hls "color conversions"
Global Const $CV_COLOR_RGB2HLS = 53

Global Const $CV_COLOR_HSV2BGR = 54      ; !< backward conversions HSV to RGB/BGR with H range 0..180 if 8 bit image
Global Const $CV_COLOR_HSV2RGB = 55

Global Const $CV_COLOR_Lab2BGR = 56
Global Const $CV_COLOR_Lab2RGB = 57
Global Const $CV_COLOR_Luv2BGR = 58
Global Const $CV_COLOR_Luv2RGB = 59
Global Const $CV_COLOR_HLS2BGR = 60      ; !< backward conversions HLS to RGB/BGR with H range 0..180 if 8 bit image
Global Const $CV_COLOR_HLS2RGB = 61

Global Const $CV_COLOR_BGR2HSV_FULL = 66 ; !< convert RGB/BGR to HSV (hue saturation value) with H range 0..255 if 8 bit image, @ref color_convert_rgb_hsv "color conversions"
Global Const $CV_COLOR_RGB2HSV_FULL = 67
Global Const $CV_COLOR_BGR2HLS_FULL = 68 ; !< convert RGB/BGR to HLS (hue lightness saturation) with H range 0..255 if 8 bit image, @ref color_convert_rgb_hls "color conversions"
Global Const $CV_COLOR_RGB2HLS_FULL = 69

Global Const $CV_COLOR_HSV2BGR_FULL = 70 ; !< backward conversions HSV to RGB/BGR with H range 0..255 if 8 bit image
Global Const $CV_COLOR_HSV2RGB_FULL = 71
Global Const $CV_COLOR_HLS2BGR_FULL = 72 ; !< backward conversions HLS to RGB/BGR with H range 0..255 if 8 bit image
Global Const $CV_COLOR_HLS2RGB_FULL = 73

Global Const $CV_COLOR_LBGR2Lab = 74
Global Const $CV_COLOR_LRGB2Lab = 75
Global Const $CV_COLOR_LBGR2Luv = 76
Global Const $CV_COLOR_LRGB2Luv = 77

Global Const $CV_COLOR_Lab2LBGR = 78
Global Const $CV_COLOR_Lab2LRGB = 79
Global Const $CV_COLOR_Luv2LBGR = 80
Global Const $CV_COLOR_Luv2LRGB = 81

Global Const $CV_COLOR_BGR2YUV = 82      ; !< convert between RGB/BGR and YUV
Global Const $CV_COLOR_RGB2YUV = 83
Global Const $CV_COLOR_YUV2BGR = 84
Global Const $CV_COLOR_YUV2RGB = 85

; ! YUV 4:2:0 family to RGB
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

; ! YUV 4:2:2 family to RGB
Global Const $CV_COLOR_YUV2RGB_UYVY = 107
Global Const $CV_COLOR_YUV2BGR_UYVY = 108
; $CV_COLOR_YUV2RGB_VYUY = 109
; $CV_COLOR_YUV2BGR_VYUY = 110
Global Const $CV_COLOR_YUV2RGB_Y422 = $CV_COLOR_YUV2RGB_UYVY
Global Const $CV_COLOR_YUV2BGR_Y422 = $CV_COLOR_YUV2BGR_UYVY
Global Const $CV_COLOR_YUV2RGB_UYNV = $CV_COLOR_YUV2RGB_UYVY
Global Const $CV_COLOR_YUV2BGR_UYNV = $CV_COLOR_YUV2BGR_UYVY

Global Const $CV_COLOR_YUV2RGBA_UYVY = 111
Global Const $CV_COLOR_YUV2BGRA_UYVY = 112
; $CV_COLOR_YUV2RGBA_VYUY = 113
; $CV_COLOR_YUV2BGRA_VYUY = 114
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
; CV_YUV2GRAY_VYUY    = CV_YUV2GRAY_UYVY
Global Const $CV_COLOR_YUV2GRAY_Y422 = $CV_COLOR_YUV2GRAY_UYVY
Global Const $CV_COLOR_YUV2GRAY_UYNV = $CV_COLOR_YUV2GRAY_UYVY
Global Const $CV_COLOR_YUV2GRAY_YVYU = $CV_COLOR_YUV2GRAY_YUY2
Global Const $CV_COLOR_YUV2GRAY_YUYV = $CV_COLOR_YUV2GRAY_YUY2
Global Const $CV_COLOR_YUV2GRAY_YUNV = $CV_COLOR_YUV2GRAY_YUY2

; ! alpha premultiplication
Global Const $CV_COLOR_RGBA2mRGBA = 125
Global Const $CV_COLOR_mRGBA2RGBA = 126

; ! RGB to YUV 4:2:0 family
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

; ! Demosaicing
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

; ! Demosaicing using Variable Number of Gradients
Global Const $CV_COLOR_BayerBG2BGR_VNG = 62
Global Const $CV_COLOR_BayerGB2BGR_VNG = 63
Global Const $CV_COLOR_BayerRG2BGR_VNG = 64
Global Const $CV_COLOR_BayerGR2BGR_VNG = 65

Global Const $CV_COLOR_BayerBG2RGB_VNG = $CV_COLOR_BayerRG2BGR_VNG
Global Const $CV_COLOR_BayerGB2RGB_VNG = $CV_COLOR_BayerGR2BGR_VNG
Global Const $CV_COLOR_BayerRG2RGB_VNG = $CV_COLOR_BayerBG2BGR_VNG
Global Const $CV_COLOR_BayerGR2RGB_VNG = $CV_COLOR_BayerGB2BGR_VNG

; ! Edge-Aware Demosaicing
Global Const $CV_COLOR_BayerBG2BGR_EA = 135
Global Const $CV_COLOR_BayerGB2BGR_EA = 136
Global Const $CV_COLOR_BayerRG2BGR_EA = 137
Global Const $CV_COLOR_BayerGR2BGR_EA = 138

Global Const $CV_COLOR_BayerBG2RGB_EA = $CV_COLOR_BayerRG2BGR_EA
Global Const $CV_COLOR_BayerGB2RGB_EA = $CV_COLOR_BayerGR2BGR_EA
Global Const $CV_COLOR_BayerRG2RGB_EA = $CV_COLOR_BayerBG2BGR_EA
Global Const $CV_COLOR_BayerGR2RGB_EA = $CV_COLOR_BayerGB2BGR_EA

; ! Demosaicing with alpha channel
Global Const $CV_COLOR_BayerBG2BGRA = 139
Global Const $CV_COLOR_BayerGB2BGRA = 140
Global Const $CV_COLOR_BayerRG2BGRA = 141
Global Const $CV_COLOR_BayerGR2BGRA = 142

Global Const $CV_COLOR_BayerBG2RGBA = $CV_COLOR_BayerRG2BGRA
Global Const $CV_COLOR_BayerGB2RGBA = $CV_COLOR_BayerGR2BGRA
Global Const $CV_COLOR_BayerRG2RGBA = $CV_COLOR_BayerBG2BGRA
Global Const $CV_COLOR_BayerGR2RGBA = $CV_COLOR_BayerGB2BGRA

Global Const $CV_COLOR_COLORCVT_MAX = 143
; };


; enum HistCompMethods {
#cs
Correlation
\f[d(H_1,H_2) =  \frac{\sum_I (H_1(I) - \bar{H_1}) (H_2(I) - \bar{H_2})}{\sqrt{\sum_I(H_1(I) - \bar{H_1})^2 \sum_I(H_2(I) - \bar{H_2})^2}}\f]
where
\f[\bar{H_k} =  \frac{1}{N} \sum _J H_k(J)\f]
and \f$N\f$ is a total number of histogram bins.
#ce
Global Const $CV_HISTCMP_CORREL = 0
#cs
Chi-Square
\f[d(H_1,H_2) =  \sum _I  \frac{\left(H_1(I)-H_2(I)\right)^2}{H_1(I)}\f]
#ce
Global Const $CV_HISTCMP_CHISQR = 1
#cs
Intersection
\f[d(H_1,H_2) =  \sum _I  \min (H_1(I), H_2(I))\f]
#ce
Global Const $CV_HISTCMP_INTERSECT = 2
#cs
Bhattacharyya distance
(In fact, OpenCV computes Hellinger distance, which is related to Bhattacharyya coefficient.)
\f[d(H_1,H_2) =  \sqrt{1 - \frac{1}{\sqrt{\bar{H_1} \bar{H_2} N^2}} \sum_I \sqrt{H_1(I) \cdot H_2(I)}}\f]
#ce
Global Const $CV_HISTCMP_BHATTACHARYYA = 3
Global Const $CV_HISTCMP_HELLINGER = $CV_HISTCMP_BHATTACHARYYA     ; !< Synonym for HISTCMP_BHATTACHARYYA
#cs
Alternative Chi-Square
\f[d(H_1,H_2) =  2 * \sum _I  \frac{\left(H_1(I)-H_2(I)\right)^2}{H_1(I)+H_2(I)}\f]
This alternative formula is regularly used for texture comparison. See e.g. @cite Puzicha1997
#ce
Global Const $CV_HISTCMP_CHISQR_ALT = 4
#cs
Kullback-Leibler divergence
\f[d(H_1,H_2) = \sum _I H_1(I) \log \left(\frac{H_1(I)}{H_2(I)}\right)\f]
#ce
Global Const $CV_HISTCMP_KL_DIV = 5
; };
