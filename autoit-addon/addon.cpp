#include "opencv2/core/mat.hpp"
#include "core/core_c_extra.h"
#include "core/mat_c.h"
#include "imgproc/imgproc_c.h"
#include "autoitdef.h"

using namespace std;
using namespace cv;

static _InputOutputArray _none;
InputOutputArray _noArray() { return _none; }

AUTOITAPI(void) calcHist_Demo_draw(Mat &histImage, int histSize, int hist_w, int hist_h, Mat &b_hist, Mat &g_hist, Mat &r_hist) {
    int bin_w = cvRound((double)hist_w / histSize);

    //! [Draw for each channel]
    auto ioArrImg = cveInputOutputArrayFromMat(&histImage);
    CvPoint p1, p2;
    CvScalar bleu = cvScalar(255, 0, 0);
    CvScalar green = cvScalar(0, 255, 0);
    CvScalar red = cvScalar(0, 0, 255);

    for (int i = 1; i < histSize; i++)
    {
        p1.x = bin_w * i - 1;
        p2.x = bin_w * i;

        p1.y = hist_h - cvRound(b_hist.at<float>(i - 1));
        p2.y = hist_h - cvRound(b_hist.at<float>(i));
        cveLine(ioArrImg, &p1, &p2, &bleu, 2, 8, 0);

        p1.y = hist_h - cvRound(g_hist.at<float>(i - 1));
        p2.y = hist_h - cvRound(g_hist.at<float>(i));
        cveLine(ioArrImg, &p1, &p2, &green, 2, 8, 0);

        p1.y = hist_h - cvRound(r_hist.at<float>(i - 1));
        p2.y = hist_h - cvRound(r_hist.at<float>(i));
        cveLine(ioArrImg, &p1, &p2, &red, 2, 8, 0);
    }

    cveInputOutputArrayRelease(&ioArrImg);
    //! [Draw for each channel]
}

AUTOITAPI(void) AKAZE_match_ratio_test_filtering(
	vector<KeyPoint> &matched1,
	vector<KeyPoint> &kpts1,
	vector<KeyPoint> &matched2,
	vector<KeyPoint> &kpts2,
	vector<vector<DMatch>> &nn_matches,
	const float nn_match_ratio
) {
	//! [ratio test filtering]
	for (size_t i = 0; i < nn_matches.size(); i++) {
		DMatch first = nn_matches[i][0];
		float dist1 = nn_matches[i][0].distance;
		float dist2 = nn_matches[i][1].distance;

		if (dist1 < nn_match_ratio * dist2) {
			matched1.push_back(kpts1[first.queryIdx]);
			matched2.push_back(kpts2[first.trainIdx]);
		}
	}
	//! [ratio test filtering]
}

AUTOITAPI(void) AKAZE_homograpy_check(
	Mat &homography,
	vector<KeyPoint> &matched1,
	vector<KeyPoint> &inliers1,
	vector<KeyPoint> &matched2,
	vector<KeyPoint> &inliers2,
	const float inlier_threshold,
	vector<DMatch> &good_matches
) {
	for (size_t i = 0; i < matched1.size(); i++) {
		Mat* col = cveMatCreate();
		cveMatOnes(3, 1, CV_64F, col);
		col->at<double>(0) = matched1[i].pt.x;
		col->at<double>(1) = matched1[i].pt.y;

		Mat* col_mul = cveMatCreate();
		cveMatCreateData(col_mul, homography.rows, col->cols, CV_64FC1);
		auto src1 = cveInputArrayFromMat(&homography);
		auto src2 = cveInputArrayFromMat(col);
		auto src3 = static_cast<cv::InputArray>(_noArray());
		auto dst = cveOutputArrayFromMat(col_mul);
		cveGemm(src1, src2, 1.0, &src3, 0.0, dst, 0);
		cveOutputArrayRelease(&dst);
		cveInputArrayRelease(&src2);
		cveInputArrayRelease(&src1);
		cveMatRelease(&col);
		col = col_mul;

		dst = cveOutputArrayFromMat(col);
		cveMatConvertTo(col, dst, -1, 1 / col->at<double>(2), 0.0);
		cveOutputArrayRelease(&dst);

		double dist = sqrt(pow(col->at<double>(0) - matched2[i].pt.x, 2) +
			pow(col->at<double>(1) - matched2[i].pt.y, 2));

		if (dist < inlier_threshold) {
			int new_i = static_cast<int>(inliers1.size());
			inliers1.push_back(matched1[i]);
			inliers2.push_back(matched2[i]);
			good_matches.push_back(DMatch(new_i, new_i, 0));
		}
	}
}
