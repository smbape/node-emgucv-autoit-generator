#Region ;**** Directives created by AutoIt3Wrapper_GUI ****
#AutoIt3Wrapper_UseX64=y
#EndRegion ;**** Directives created by AutoIt3Wrapper_GUI ****

Opt("MustDeclareVars", 1)

#include <ButtonConstants.au3>
#include <ComboConstants.au3>
#include <EditConstants.au3>
#include <File.au3>
#include <FileConstants.au3>
#include <GDIPlus.au3>
#include <GuiComboBox.au3>
#include <GUIConstantsEx.au3>
#include <Math.au3>
#include <StaticConstants.au3>
#include <WindowsConstants.au3>
#include "..\..\..\..\emgucv-autoit-bindings\cve_extra.au3"

;~ Sources:
;~     https://docs.opencv.org/4.5.2/d7/dff/tutorial_feature_homography.html
;~     https://github.com/opencv/opencv/tree/master/samples/cpp/tutorial_code/features2D/feature_homography/SURF_FLANN_matching_homography_Demo.cpp

Local Const $OPENCV_SAMPLES_DATA_PATH = _PathFull(@ScriptDir & "\..\..\..\data")

#Region ### START Koda GUI section ### Form=
Local $FormGUI = GUICreate("Features2D + Homography to find a known object", 1000, 707, 192, 95)

Local $InputObject = GUICtrlCreateInput($OPENCV_SAMPLES_DATA_PATH & "\box.png", 230, 16, 449, 21)
Local $BtnObject = GUICtrlCreateButton("Object", 689, 14, 75, 25)

Local $InputScene = GUICtrlCreateInput($OPENCV_SAMPLES_DATA_PATH & "\box_in_scene.png", 230, 52, 449, 21)
Local $BtnScene = GUICtrlCreateButton("Scene", 689, 50, 75, 25)

Local $LabelMatchType = GUICtrlCreateLabel("Match type", 414, 92, 79, 20)
GUICtrlSetFont(-1, 10, 800, 0, "MS Sans Serif")
Local $ComboMatchType = GUICtrlCreateCombo("", 502, 92, 177, 25, BitOR($GUI_SS_DEFAULT_COMBO, $CBS_SIMPLE))
GUICtrlSetData(-1, "BruteForce|BruteForce-L1|BruteForce-Hamming|BruteForce-HammingLUT|BruteForce-Hamming(2)|BruteForce-SL2")

Local $BtnExec = GUICtrlCreateButton("Execute", 832, 48, 75, 25)

Local $LabelMatches = GUICtrlCreateLabel("Good Matches & Object detection", 377, 144, 245, 20)
GUICtrlSetFont(-1, 10, 800, 0, "MS Sans Serif")
Local $GroupMatches = GUICtrlCreateGroup("", 20, 166, 958, 532)
Local $PicMatches = GUICtrlCreatePic("", 25, 177, 948, 516)
GUICtrlCreateGroup("", -99, -99, 1, 1)

GUISetState(@SW_SHOW)
#EndRegion ### END Koda GUI section ###

Local $aMatchTypes[6] = [ _
	$CV_NORM_L2, _
	$CV_NORM_L1, _
	$CV_NORM_HAMMING, _
	$CV_NORM_HAMMING, _
	$CV_NORM_HAMMING2, _
	$CV_NORM_L2SQR _
]
_GUICtrlComboBox_SetCurSel($ComboMatchType, 2)

_GDIPlus_Startup()
_OpenCV_DLLOpen(@ScriptDir & "\..\..\..\..\libemgucv-windesktop-4.5.2.4673\libs\x64\cvextern.dll")

Local $img_object, $img_scene
Local $nMsg
Local $sObject, $sScene
Local $tBackgroundColor = _cvRGB(0xF0, 0xF0, 0xF0)

Main()

While 1
	$nMsg = GUIGetMsg()
	Switch $nMsg
		Case $GUI_EVENT_CLOSE
			Exit
		Case $BtnObject
			$sObject = ControlGetText($FormGUI, "", $InputObject)
			$sObject = FileOpenDialog("Select an image", $OPENCV_SAMPLES_DATA_PATH, "Image files (*.bmp;*.jpg;*.jpeg;*.png;*.gif)", $FD_FILEMUSTEXIST, $sObject)
			If @error Then
				$sObject = ""
			Else
				ControlSetText($FormGUI, "", $InputObject, $sObject)
			EndIf
		Case $BtnScene
			$sScene = ControlGetText($FormGUI, "", $InputScene)
			$sScene = FileOpenDialog("Select an image", $OPENCV_SAMPLES_DATA_PATH, "Image files (*.bmp;*.jpg;*.jpeg;*.png;*.gif)", $FD_FILEMUSTEXIST, $sScene)
			If @error Then
				$sScene = ""
			Else
				ControlSetText($FormGUI, "", $InputScene, $sScene)
			EndIf
		Case $ComboMatchType
			Detect()
		Case $BtnExec
			Clean()
			Main()
	EndSwitch
WEnd

_Opencv_DLLClose()
_GDIPlus_Shutdown()

Func Main()
	;;! [load_image]
	;;/ Load object and scene
	$sObject = ControlGetText($FormGUI, "", $InputObject)
	$img_object = _cveImreadAndCheck($sObject, $CV_IMREAD_GRAYSCALE)
	If @error Then
		$sObject = ""
		Return
	EndIf

	$sScene = ControlGetText($FormGUI, "", $InputScene)
	$img_scene = _cveImreadAndCheck($sScene, $CV_IMREAD_GRAYSCALE)
	If @error Then
		_cveMatRelease($img_object)
		$sObject = ""
		$sScene = ""
		Return
	EndIf
	;;! [load_image]

	Detect()
EndFunc   ;==>Main

Func Clean()
	If $sObject == "" Then Return

	_cveMatRelease($img_object)
	_cveMatRelease($img_scene)

	$sObject = ""
EndFunc   ;==>Clean

Func Detect()
	Local $match_type = $aMatchTypes[_GUICtrlComboBox_GetCurSel($ComboMatchType)]

	;;-- Step 1: Detect the keypoints using ORB Detector, compute the descriptors
	Local $numberOfFeatures = 500 ;
	Local $tFeature2DPtr = DllStructCreate("ptr value")
	Local $tSharedPtr = DllStructCreate("ptr")
	_cveOrbCreate($numberOfFeatures, 1.2, 8, 31, 0, 2, $CV_ORB_HARRIS_SCORE, 31, 20, $tFeature2DPtr, $tSharedPtr)
	Local $detector = $tFeature2DPtr.value
	Local $keypoints_object = _VectorOfKeyPointCreate()
	Local $keypoints_scene = _VectorOfKeyPointCreate()
	Local $descriptors_object = _cveMatCreate()
	Local $descriptors_scene = _cveMatCreate()
	_CvFeature2DDetectAndComputeMat($detector, $img_object, _cveNoArrayMat(), $keypoints_object, $descriptors_object, False) ;
	_CvFeature2DDetectAndComputeMat($detector, $img_scene, _cveNoArrayMat(), $keypoints_scene, $descriptors_scene, False) ;

	;;-- Step 2: Matching descriptor vectors with a BruteForce based matcher
	;; Since ORB is a floating-point descriptor NORM_L2 is used
	Local $tMatcherPtr = DllStructCreate("ptr value")
	Local $bf_matcher = _cveBFMatcherCreate($match_type, False, $tMatcherPtr) ;
	Local $matcher = $tMatcherPtr.value
	Local $knn_matches = _VectorOfVectorOfDMatchCreate() ;
	_cveDescriptorMatcherKnnMatch1Mat($matcher, $descriptors_object, $descriptors_scene, $knn_matches, 2, _cveNoArrayMat(), False) ;

	;;-- Filter matches using the Lowe's ratio test
	Local $ratio_thresh = 0.75 ;
	Local $good_matches = _VectorOfDMatchCreate() ;
	Local $tVectorDMatchPtr = DllStructCreate("ptr value")
	Local $tDMatchPtr0 = DllStructCreate("ptr value")
	Local $tDMatchPtr1 = DllStructCreate("ptr value")

	For $i = 0 To _VectorOfVectorOfDMatchGetSize($knn_matches) - 1
		_VectorOfVectorOfDMatchGetItemPtr($knn_matches, $i, $tVectorDMatchPtr)

		_VectorOfDMatchGetItemPtr($tVectorDMatchPtr.value, 0, $tDMatchPtr0)
		Local $tDMatch0 = DllStructCreate($tagCvDMatch, $tDMatchPtr0.value)

		_VectorOfDMatchGetItemPtr($tVectorDMatchPtr.value, 1, $tDMatchPtr1)
		Local $tDMatch1 = DllStructCreate($tagCvDMatch, $tDMatchPtr1.value)

		If $tDMatch0.distance < $ratio_thresh * $tDMatch1.distance Then
			_VectorOfDMatchPush($good_matches, $tDMatch0)
		EndIf
	Next

	;;-- Draw matches
	Local $img_matches = _cveMatCreate() ;
	Local $matchesMask = _VectorOfByteCreate()
	_drawMatchedFeatures1Mat($img_object, $keypoints_object, $img_scene, $keypoints_scene, $good_matches, $img_matches, _cvScalarAll(-1), _
			_cvScalarAll(-1), $matchesMask, $CV_DRAW_MATCHES_FLAGS_NOT_DRAW_SINGLE_POINTS) ;

	;;-- Localize the object
	Local $obj = _VectorOfPointFCreate() ;
	Local $scene = _VectorOfPointFCreate() ;
	Local $tObjectKeyPointPtr = DllStructCreate("ptr value")
	Local $tSceneKeyPointPtr = DllStructCreate("ptr value")

	For $i = 0 To _VectorOfDMatchGetSize($good_matches) - 1
		;;-- Get the keypoints from the good matches
		_VectorOfDMatchGetItemPtr($good_matches, $i, $tDMatchPtr0)
		Local $tDMatch0 = DllStructCreate($tagCvDMatch, $tDMatchPtr0.value)

		_VectorOfKeyPointGetItemPtr($keypoints_object, $tDMatch0.queryIdx, $tObjectKeyPointPtr)
		Local $tObjectKeyPoint = DllStructCreate($tagCvKeyPoint, $tObjectKeyPointPtr.value)
		_VectorOfPointFPush($obj, $tObjectKeyPoint)

		_VectorOfKeyPointGetItemPtr($keypoints_scene, $tDMatch0.trainIdx, $tSceneKeyPointPtr)
		Local $tSceneKeyPoint = DllStructCreate($tagCvKeyPoint, $tSceneKeyPointPtr.value)
		_VectorOfPointFPush($scene, $tSceneKeyPoint)
	Next

	Local $H = _cveMatCreate()
	Local $i_arr_H = _cveInputArrayFromMat($H)
	Local $o_arr_H = _cveOutputArrayFromMat($H)
	Local $i_arr_obj = _cveInputArrayFromVectorOfPointF($obj)
	Local $i_arr_scene = _cveInputArrayFromVectorOfPointF($scene)
	Local $resultMask = _cveMatCreate()
	Local $o_arr_resultMask = _cveOutputArrayFromMat($resultMask)
	_cveFindHomography($i_arr_obj, $i_arr_scene, $o_arr_H, $CV_RANSAC, 3, $o_arr_resultMask) ;
	_cveOutputArrayRelease($o_arr_resultMask)
	_cveMatRelease($resultMask)

	If Not _cveMatIsEmpty($H) Then
		;;-- Get the corners from the image_1 ( the object to be "detected" )
		Local $img_object_size = _cvSize()
		_cveMatGetSize($img_object, $img_object_size)

		Local $obj_corners = _VectorOfPointFCreate()
		_VectorOfPointFPush($obj_corners, _cvPoint2f(0, 0))
		_VectorOfPointFPush($obj_corners, _cvPoint2f($img_object_size.width, 0))
		_VectorOfPointFPush($obj_corners, _cvPoint2f($img_object_size.width, $img_object_size.height))
		_VectorOfPointFPush($obj_corners, _cvPoint2f(0, $img_object_size.height))

		Local $scene_corners = _VectorOfPointFCreateSize(4)

		Local $i_arr_obj_corners = _cveInputArrayFromVectorOfPointF($obj_corners)
		Local $o_arr_scene_corners = _cveOutputArrayFromVectorOfPointF($scene_corners)

		_cvePerspectiveTransform($i_arr_obj_corners, $o_arr_scene_corners, $i_arr_H) ;

		Local $tPointFPtr = DllStructCreate("ptr value")

		_VectorOfPointFGetItemPtr($scene_corners, 0, $tPointFPtr)
		Local $scene_corners_0 = DllStructCreate($tagCvPoint2D32f, $tPointFPtr.value)

		_VectorOfPointFGetItemPtr($scene_corners, 1, $tPointFPtr)
		Local $scene_corners_1 = DllStructCreate($tagCvPoint2D32f, $tPointFPtr.value)

		_VectorOfPointFGetItemPtr($scene_corners, 2, $tPointFPtr)
		Local $scene_corners_2 = DllStructCreate($tagCvPoint2D32f, $tPointFPtr.value)

		_VectorOfPointFGetItemPtr($scene_corners, 3, $tPointFPtr)
		Local $scene_corners_3 = DllStructCreate($tagCvPoint2D32f, $tPointFPtr.value)

		;;-- Draw lines between the corners (the mapped object in the scene - image_2 )
		_cveLineMat($img_matches, _cvPoint($scene_corners_0.x + $img_object_size.width, $scene_corners_0.y), _
				_cvPoint($scene_corners_1.x + $img_object_size.width, $scene_corners_1.y), _cvScalar(0, 255, 0), 4) ;

		_cveLineMat($img_matches, _cvPoint($scene_corners_1.x + $img_object_size.width, $scene_corners_1.y), _
				_cvPoint($scene_corners_2.x + $img_object_size.width, $scene_corners_2.y), _cvScalar(0, 255, 0), 4) ;

		_cveLineMat($img_matches, _cvPoint($scene_corners_2.x + $img_object_size.width, $scene_corners_2.y), _
				_cvPoint($scene_corners_3.x + $img_object_size.width, $scene_corners_3.y), _cvScalar(0, 255, 0), 4) ;

		_cveLineMat($img_matches, _cvPoint($scene_corners_3.x + $img_object_size.width, $scene_corners_3.y), _
				_cvPoint($scene_corners_0.x + $img_object_size.width, $scene_corners_0.y), _cvScalar(0, 255, 0), 4) ;

		_cveOutputArrayRelease($o_arr_scene_corners)
		_cveInputArrayRelease($i_arr_obj_corners)
		_VectorOfPointFRelease($scene_corners)
		_VectorOfPointFRelease($obj_corners)
	EndIf

	_cveInputArrayRelease($i_arr_scene)
	_cveInputArrayRelease($i_arr_obj)
	_cveOutputArrayRelease($o_arr_H)
	_cveInputArrayRelease($i_arr_H)
	_cveMatRelease($H)
	_VectorOfPointFRelease($scene)
	_VectorOfPointFRelease($obj)

	;-- Show detected matches
	; _cveImshowMat("Good Matches & Object detection", $img_matches) ;
	_cveImshowControlPic($img_matches, $FormGUI, $PicMatches, $tBackgroundColor)

	_VectorOfByteRelease($matchesMask)
	_cveMatRelease($img_matches)
	_VectorOfDMatchRelease($good_matches)
	_VectorOfVectorOfDMatchRelease($knn_matches)
	_cveBFMatcherRelease($bf_matcher)
	_cveMatRelease($descriptors_scene)
	_cveMatRelease($descriptors_object)
	_VectorOfKeyPointRelease($keypoints_scene)
	_VectorOfKeyPointRelease($keypoints_object)
	_cveOrbRelease($tSharedPtr)
EndFunc   ;==>Detect
