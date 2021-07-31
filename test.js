const fs = require("fs");
const sysPath = require("path");
const eachOfLimit = require("async/eachOfLimit");

const ExportsParser = require("./src/ExportsParser");
const EnumParser = require("./src/EnumParser");
const options = require("./src/options");

[
    "CVAPI(void) VectorOfDoublePushVector(std::vector< double >* v, std::vector< double >* other);",
    "CVAPI(std::vector< double >*) VectorOfDoubleCreate();",
    "CVAPI(void) VectorOfDoubleGetItemPtr(std::vector<  double >* vec, int index,  double** element);",
    "CVAPI(void) setPlane3D(Plane3D* plane, const CvPoint3D64f* unitNormal, const CvPoint3D64f* pointInPlane);",
    "CVAPI(void) VectorOfDMatchPushMatrix(std::vector<cv::DMatch>* matches, const CvMat* trainIdx, const CvMat* distance = 0, const CvMat* mask = 0);",
    "CVAPI(std::vector< unsigned char >*) VectorOfByteCreateSize(int size);",
    "CVAPI(void) cudaCartToPolar(cv::_InputArray* x, cv::_InputArray* y, cv::_OutputArray* magnitude, cv::_OutputArray* angle, bool angleInDegrees, cv::cuda::Stream* stream);",
    "CVAPI(void) cveDetectorParametersSetMinGroupSize(cv::mcc::DetectorParameters* obj, unsigned value);     ",
    `CVAPI(void) OpenniGetColorPoints(
                                 CvCapture* capture, // must be an openni capture
                                 std::vector<ColorPoint>* points, // sequence of ColorPoint
                                 IplImage* mask // CV_8UC1
                                 );`,
].forEach(expr => {
    const parser = new ExportsParser(false, options);
    parser.parse(expr, 0);
    console.log(parser.returnType, parser.name, parser.args);
});

[
    "CV_EXPORTS_W int waitKey(int delay = 0);",
    `CV_EXPORTS_W void resize( InputArray src, OutputArray dst,
                          Size dsize, double fx = 0, double fy = 0,
                          int interpolation = INTER_LINEAR );`,
    `CV_EXPORTS_W void accumulateWeighted( InputArray src, InputOutputArray dst,
                                      double alpha, InputArray mask = noArray() );`,
    `CV_EXPORTS_W void add(InputArray src1, InputArray src2, OutputArray dst,
                      InputArray mask = noArray(), int dtype = -1);`,
    "CV_EXPORTS_W double PSNR(InputArray src1, InputArray src2, double R=255.);",
    `CV_EXPORTS_W void minMaxLoc(InputArray src, CV_OUT double* minVal,
                            CV_OUT double* maxVal = 0, CV_OUT Point* minLoc = 0,
                            CV_OUT Point* maxLoc = 0, InputArray mask = noArray());`,
    "CV_EXPORTS_W void setIdentity(InputOutputArray mtx, const Scalar& s = Scalar(1));",
    `CV_EXPORTS_W void drawKeypoints( InputArray image, const std::vector<KeyPoint>& keypoints, InputOutputArray outImage,
                               const Scalar& color=Scalar::all(-1), DrawMatchesFlags flags=DrawMatchesFlags::DEFAULT );`,
].forEach(expr => {
    const parser = new ExportsParser(false, options);
    expr = expr.replace(/CV_(?:IN|OUT|IN_OUT) /g, "").replace(/CV_EXPORTS_W inline/g, "CV_NOT_EXPORTS_W");
    parser.options.exports.start = "CV_EXPORTS_W ";
    parser.options.exports.end = " ";
    parser.init(parser.options);
    parser.parse(expr, 0);
    console.log(parser.returnType, parser.name, parser.args);
});

eachOfLimit([
    sysPath.join(__dirname, "emgucv\\opencv\\modules\\core\\include\\opencv2\\core.hpp"),
    sysPath.join(__dirname, "emgucv\\opencv\\modules\\imgproc\\include\\opencv2\\imgproc.hpp"),
    sysPath.join(__dirname, "emgucv\\opencv\\modules\\features2d\\include\\opencv2\\features2d.hpp"),
    sysPath.join(__dirname, "emgucv\\opencv\\modules\\calib3d\\include\\opencv2\\calib3d.hpp"),
    sysPath.join(__dirname, "emgucv\\opencv\\modules\\core\\include\\opencv2\\core\\mat.hpp"),
], 1, (localFile, i, next) => {
    const parser = new ExportsParser(true, options);
    parser.options.exports.start = "CV_EXPORTS_W ";
    parser.options.exports.end = " ";
    parser.init(parser.options);

    fs.readFile(localFile, (err, buffer) => {
        if (err) {
            next(err);
            return;
        }
        buffer = buffer.toString().replace(/CV_(?:IN|OUT|IN_OUT) /g, "").replace(/CV_EXPORTS_W inline/g, "CV_NOT_EXPORTS_W");
        const api = parser.parseFile(buffer);

        if (parser.lastError) {
            console.log("reading", localFile, "error");
            next(parser.lastError);
            return;
        }

        for (const [returnType, name, args] of api) {
            console.log(returnType, name, args);
        }

        next();
    });
}, err => {
    if (err) {
        throw err;
    }
});

eachOfLimit([
    sysPath.join(__dirname, "emgucv\\Emgu.CV.Extern\\depthai-core\\shared\\depthai-shared\\include\\depthai-shared\\metadata\\camera_control.hpp"),
    sysPath.join(__dirname, "emgucv\\opencv\\modules\\calib3d\\include\\opencv2\\calib3d.hpp"),
    sysPath.join(__dirname, "emgucv\\opencv\\modules\\core\\include\\opencv2\\core\\affine.hpp"),
    sysPath.join(__dirname, "emgucv\\opencv\\modules\\core\\include\\opencv2\\core\\base.hpp"),
    sysPath.join(__dirname, "emgucv\\opencv\\modules\\core\\include\\opencv2\\core\\check.hpp"),
    sysPath.join(__dirname, "emgucv\\opencv\\modules\\core\\include\\opencv2\\core\\cuda.hpp"),
    sysPath.join(__dirname, "emgucv\\opencv\\modules\\core\\include\\opencv2\\core\\cuda\\detail\\type_traits_detail.hpp"),
    sysPath.join(__dirname, "emgucv\\opencv\\modules\\core\\include\\opencv2\\core\\mat.hpp"),
    sysPath.join(__dirname, "emgucv\\opencv\\modules\\core\\include\\opencv2\\core\\types.hpp"),
    sysPath.join(__dirname, "emgucv\\opencv\\modules\\features2d\\include\\opencv2\\features2d.hpp"),
    sysPath.join(__dirname, "emgucv\\opencv\\modules\\imgcodecs\\include\\opencv2\\imgcodecs.hpp"),
    sysPath.join(__dirname, "emgucv\\opencv\\modules\\imgproc\\include\\opencv2\\imgproc.hpp"),
    sysPath.join(__dirname, "emgucv\\opencv_contrib\\modules\\ximgproc\\include\\opencv2\\ximgproc\\weighted_median_filter.hpp"),
], 1, (localFile, i, next) => {
    const parser = new EnumParser();

    fs.readFile(localFile, (err, buffer) => {
        if (err) {
            next(err);
            return;
        }

        const ast = parser.parse(buffer);

        if (parser.lastError) {
            console.log("reading", localFile, "error");
            next(parser.lastError);
            return;
        }

        next();
    });
}, err => {
    if (err) {
        throw err;
    }
});
