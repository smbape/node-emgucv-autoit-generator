#include "opencv2/core/mat.hpp"
#include "core/core_c_extra.h"
#include "imgproc/imgproc_c.h"

#ifndef ADDON_H
#define ADDON_H

#ifdef __cplusplus
extern "C" {
#endif

	AUTOIT_EXPORTS void draw(cv::Mat* histImage, int histSize, int bin_w, int hist_h, cv::Mat* b_hist, cv::Mat* g_hist, cv::Mat* r_hist);

#ifdef __cplusplus
}
#endif

#endif //ADDON_H
