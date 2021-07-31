#include-once

; #INDEX# =======================================================================================================================
; Title .........: CVTag
; AutoIt Version : 3.3.10.2
; Language ......: English
; Description ...: Tags for OpenCV
; Author(s) .....: Mylise
; ===============================================================================================================================
;
; Local $v"name of variable" = DllStructCreate($tag"name of tag")
; use --> DllStructSetData($v"name of variable", "item# or name of item" , value)
;
; use --> Local $p"name of variable" = DllStructGetPtr($v"name of variable")
; use in DLLcall --> "ptr", $p"name of variable"
;
; Local $v"name of variable" = DllStructCreate($tag"name of tag", pointer of "variable")
; use --> Local value = DllStructGetData($v"name of variable", "item# or name of item") ;; #Tags# ======================================================================================================================

Global Const $tagCvPoint = _
	"int x;" & _
	"int y;"

Global Const $tagCvPoint2D32f = _
	"float x;" & _
	"float y;"

Global Const $tagCvPoint3D32f = _
	"float x;" & _
	"float y;" & _
	"float z;"

Global Const $tagCvPoint2D64f = _
	"double x;" & _
	"double y;"

Global Const $tagCvPoint3D64f = _
	"double x;" & _
	"double y;" & _
	"double z;"

Global Const $tagCvSize = _
	"int width;" & _
	"int height;"

Global Const $tagCvSize2D32f = _
	"float width;" & _
	"float height;"

Global Const $tagCvScalar = _
	"double val1;" & _
	"double val2;" & _
	"double val3;" & _
	"double val4;"

Global Const $tagCvRect = _
	"int x;" & _
	"int y;" & _
	"int width;" & _
	"int height;"

Global Const $tagCvBox2D = _
	"struct;" & $tagCvPoint2D32f & "endstruct;" & _ ;/**< Center of the box.                          */
	"struct;" & $tagCvSize2D32f  & "endstruct;" & _ ;/**< Box width and length.                       */
	"float angle;"                                  ;/**< Angle between the horizontal axis           */
													;/**< and the first side (i.e. length) in degrees */

Global Const $tagCvMat = _
	"int flags;"        & _ ; includes several bit-fields: the magic signature, continuity flag, depth, number of channels
	"int dims;"         & _ ; the matrix dimensionality, >= 2
	"int rows;"         & _ ; the number of rows and columns or (-1, -1) when the matrix has more than 2 dimensions
	"int cols;"         & _
	"ptr data;"         & _ ; pointer to the data
	"ptr datastart;"    & _ ; helper fields used in locateROI and adjustROI
	"ptr dataend;"      & _
	"ptr datalimit;"    & _
	"ptr allocator;"    & _ ; custom allocator
	"ptr u;"            & _ ; interaction with UMat
	"ptr size;"         & _
	"ptr p;"            & _
	"ulong_ptr buf[2];"

Global Const $tagCvTermCriteria = _
	"int type;"         & _ ; the type of termination criteria: COUNT, EPS or COUNT + EPS
	"int max_iter;"     & _ ; the maximum number of iterations/elements
	"double epsilon;"       ; the desired accuracy

Global Const $tagIplImage = _
	"int  nSize;"           & _ ;/* sizeof(IplImage) */
	"int  ID;"              & _ ;/* version (=0)*/
	"int  nChannels;"       & _ ;/* Most of OpenCV functions support 1,2,3 or 4 channels */
	"int  alphaChannel;"    & _ ;/* Ignored by OpenCV */
	"int  depth;"           & _ ;/* Pixel depth in bits: IPL_DEPTH_8U, IPL_DEPTH_8S, IPL_DEPTH_16S, IPL_DEPTH_32S, IPL_DEPTH_32F and IPL_DEPTH_64F are supported.  */
	"byte colorModel[4];"   & _ ;/* Ignored by OpenCV */
	"byte channelSeq[4];"   & _ ;/* ditto */
	"int  dataOrder;"       & _ ;/* 0 - interleaved color channels, 1 - separate color channels.cvCreateImage can only create interleaved images */
	"int  origin;"          & _ ;/* 0 - top-left origin,1 - bottom-left origin (Windows bitmaps style).  */
	"int  align;"           & _ ;/* Alignment of image rows (4 or 8). OpenCV ignores it and uses widthStep instead.    */
	"int  width;"           & _ ;/* Image width in pixels.                           */
	"int  height;"          & _ ;/* Image height in pixels.                          */
	"ptr  IplROI;"          & _ ;/* Image ROI. If NULL, the whole image is selected. */
	"ptr  maskROI;"         & _ ;/* Must be NULL. */
	"ptr  imageId;"         & _ ;/* "           " */
	"ptr  tileInfo;"        & _ ;/* "           " */
	"int  imageSize;"       & _ ;/* Image data size in bytes (==image->height*image->widthStep in case of interleaved data)*/
	"ptr  imageData;"       & _ ;/* Pointer to aligned image data.         */
	"int  widthStep;"       & _ ;/* Size of aligned image row in bytes.    */
	"int  BorderMode[4];"   & _ ;/* Ignored by OpenCV.                     */
	"int  BorderConst[4];"  & _ ;/* Ditto.                                 */
	"ptr  imageDataOrigin;"     ;/* Pointer to very origin of image data (not necessarily aligned) - needed for correct deallocation */

Global Const $tagIplROI = _
	"int  coi;"     & _ ; /* 0 - no COI (all channels are selected), 1 - 0th channel is selected ...*/
	"int  xOffset;" & _
	"int  yOffset;" & _
	"int  width;"   & _
	"int  height;"

Global Const $tagCvSeq = _
	"int flags;"        & _ ;sequence flags, including the sequence signature (CV_SEQ_MAGIC_VAL or CV_SET_MAGIC_VAL), type of the elements and some other information about the sequence.
	"int header_size;"  & _ ;size of the sequence header. It should be sizeof(CvSeq) at minimum. See CreateSeq().
	"ptr h_next;"       & _
	"ptr h_prev;"       & _
	"ptr v_next;"       & _
	"ptr v_prev;"       & _ ;pointers to another sequences in a sequence tree. Sequence trees are used to store hierarchical contour structures, retrieved by FindContours()
	"int total;"        & _ ;the number of sequence elements
	"int elem_size;"    & _ ;size of each sequence element in bytes
	"ptr block_max;"    & _ ;memory storage where the sequence resides. It can be a NULL pointer.
	"ptr w_ptr;"        & _;pointer to the first data block
	"int delta_elems;"  & _
	"ptr storage;"      & _
	"ptr free_blocks;"  & _
	"ptr first;"        & _
	"int padding1;"     & _
	"int padding2;"

Global Const $tagCvContour = _
	"int flags;"        & _ ;sequence flags, including the sequence signature (CV_SEQ_MAGIC_VAL or CV_SET_MAGIC_VAL), type of the elements and some other information about the sequence.
	"int header_size;"  & _ ;size of the sequence header. It should be sizeof(CvSeq) at minimum. See CreateSeq().
	"ptr h_next;"       & _
	"ptr h_prev;"       & _
	"ptr v_next;"       & _
	"ptr v_prev;"       & _ ;pointers to another sequences in a sequence tree. Sequence trees are used to store hierarchical contour structures, retrieved by FindContours()
	"int total;"        & _ ;the number of sequence elements
	"int elem_size;"    & _ ;size of each sequence element in bytes
	"ptr block_max;"    & _ ;memory storage where the sequence resides. It can be a NULL pointer.
	"ptr w_ptr;"        & _ ;pointer to the first data block
	"int delta_elems;"  & _
	"ptr storage;"      & _
	"ptr free_blocks;"  & _
	"ptr first;"        & _
	"int x;"            & _
	"int y;"            & _
	"int width;"        & _
	"int height;"       & _
	"int color;"        & _
	"int reserved1;"    & _
	"int reserved2;"    & _
	"int reserved3;"    & _
	"int padding1;"     & _
	"int padding2;"

Global Const $tagCvSeqBlock = _
	"ptr next;"         & _
	"ptr prev;"         & _
	"int start_index;"  & _
	"int count;"        & _ ;the number of sequence elements
	"ptr data;"         & _ ;memory storage where the sequence resides. It can be a NULL pointer.
	"int delimiter;"        ;pointer to the first data block

Global Const $tagCvSlice = _
	"int start_index;" & _
	"int end_index;"

Global Const $tagCvKeyPoint = _
	"struct;" & $tagCvPoint2D32f & "endstruct;" & _ ; coordinates of the keypoints
	"float size;"       & _ ; diameter of the meaningful keypoint neighborhood
	"float angle;"      & _ ; computed orientation of the keypoint (-1 if not applicable); it's in [0,360) degrees and measured relative to image coordinate system, ie in clockwise.
	"float response;"   & _ ; the response by which the most strong keypoints have been selected. Can be used for the further sorting or subsampling
	"int octave;"       & _ ; octave (pyramid layer) from which the keypoint has been extracted
	"int class_id;"         ; object class (if the keypoints need to be clustered by an object they belong to)

Global Const $tagCvDMatch = _
	"int queryIdx;" & _ ; query descriptor index
	"int trainIdx;" & _ ; train descriptor index
	"int imgIdx;"   & _ ; train image index
	"float distance;"
