#include "opencv2/core/mat.hpp"
#include "core/core_c_extra.h"
#include "imgproc/imgproc_c.h"

#ifdef __cplusplus
extern "C" {
#endif

	AUTOIT_EXPORTS void draw(cv::Mat* histImage, int histSize, int hist_w, int hist_h, cv::Mat* b_hist, cv::Mat* g_hist, cv::Mat* r_hist) {
		int bin_w = cvRound((double)hist_w / histSize);

		//! [Draw for each channel]
		auto ioArrImg = cveInputOutputArrayFromMat(histImage);
		CvPoint p1, p2;
		CvScalar bleu = cvScalar(255, 0, 0);
		CvScalar green = cvScalar(0, 255, 0);
		CvScalar red = cvScalar(0, 0, 255);

		for (int i = 1; i < histSize; i++)
		{
			p1.x = bin_w * i - 1;
			p2.x = bin_w * i;

			p1.y = hist_h - cvRound(b_hist->at<float>(i - 1));
			p2.y = hist_h - cvRound(b_hist->at<float>(i));
			cveLine(ioArrImg, &p1, &p2, &bleu, 2, 8, 0);

			p1.y = hist_h - cvRound(g_hist->at<float>(i - 1));
			p2.y = hist_h - cvRound(g_hist->at<float>(i));
			cveLine(ioArrImg, &p1, &p2, &green, 2, 8, 0);

			p1.y = hist_h - cvRound(r_hist->at<float>(i - 1));
			p2.y = hist_h - cvRound(r_hist->at<float>(i));
			cveLine(ioArrImg, &p1, &p2, &red, 2, 8, 0);
		}

		cveInputOutputArrayRelease(&ioArrImg);
		//! [Draw for each channel]

	}
#ifdef __cplusplus
}
#endif
