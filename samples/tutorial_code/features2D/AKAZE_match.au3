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
#include <StringConstants.au3>
#include <WindowsConstants.au3>
#include "..\..\..\emgucv-autoit-bindings\cve_extra.au3"

;~ Sources:
;~     https://docs.opencv.org/4.5.3/db/d70/tutorial_akaze_matching.html
;~     https://github.com/opencv/opencv/tree/master/samples/cpp/tutorial_code/features2D/AKAZE_match.cpp

Local Const $OPENCV_SAMPLES_DATA_PATH = _PathFull(@ScriptDir & "\..\..\data")

#Region ### START Koda GUI section ### Form=
Local $FormGUI = GUICreate("AKAZE local features matching", 1000, 707, 192, 95)

Local $InputImg1 = GUICtrlCreateInput($OPENCV_SAMPLES_DATA_PATH & "\graf1.png", 230, 16, 449, 21)
Local $BtnImg1 = GUICtrlCreateButton("Image 1", 689, 14, 75, 25)

Local $InputImg2 = GUICtrlCreateInput($OPENCV_SAMPLES_DATA_PATH & "\graf3.png", 230, 52, 449, 21)
Local $BtnImg2 = GUICtrlCreateButton("Image 2", 689, 50, 75, 25)

Local $InputHomography = GUICtrlCreateInput($OPENCV_SAMPLES_DATA_PATH & "\H1to3p.xml", 230, 92, 449, 21)
Local $BtnHomography = GUICtrlCreateButton("Homography matrix", 689, 90, 115, 25)

Local $BtnExec = GUICtrlCreateButton("Execute", 832, 48, 75, 25)

Local $LabelMatches = GUICtrlCreateLabel("Result", 377, 144, 245, 20)
GUICtrlSetFont(-1, 10, 800, 0, "MS Sans Serif")
Local $GroupMatches = GUICtrlCreateGroup("", 20, 166, 958, 532)
Local $PicMatches = GUICtrlCreatePic("", 25, 177, 948, 516)
GUICtrlCreateGroup("", -99, -99, 1, 1)

GUISetState(@SW_SHOW)
#EndRegion ### END Koda GUI section ###

_GDIPlus_Startup()
_OpenCV_DLLOpen(_OpenCV_FindDLL(@ScriptDir))

Local $img1, $img2, $homography, $homography_size
Local $nMsg, $hTimer
Local $sImg1, $sImg2, $sHomography
Local $tBackgroundColor = _cvRGB(0xF0, 0xF0, 0xF0)

Local $addon_dll = ""
Local $aSearchDirs[3] = [@ScriptDir, @ScriptDir & "\..\..\..\autoit-addon\build_x64\Release", @ScriptDir & "\..\..\..\autoit-addon\build_x64\Debug"]
For $i = 0 To UBound($aSearchDirs) - 1
	$addon_dll = $aSearchDirs[$i] & "\autoit_addon.dll"
	If FileExists($addon_dll) Then ExitLoop
	$addon_dll = ""
Next

Main()

While 1
	$nMsg = GUIGetMsg()
	Switch $nMsg
		Case $GUI_EVENT_CLOSE
			Exit
		Case $BtnImg1
			$sImg1 = ControlGetText($FormGUI, "", $InputImg1)
			$sImg1 = FileOpenDialog("Select an image", $OPENCV_SAMPLES_DATA_PATH, "Image files (*.bmp;*.jpg;*.jpeg;*.png;*.gif)", $FD_FILEMUSTEXIST, $sImg1)
			If @error Then
				$sImg1 = ""
			Else
				ControlSetText($FormGUI, "", $InputImg1, $sImg1)
			EndIf
		Case $BtnImg2
			$sImg2 = ControlGetText($FormGUI, "", $InputImg2)
			$sImg2 = FileOpenDialog("Select an image", $OPENCV_SAMPLES_DATA_PATH, "Image files (*.bmp;*.jpg;*.jpeg;*.png;*.gif)", $FD_FILEMUSTEXIST, $sImg2)
			If @error Then
				$sImg2 = ""
			Else
				ControlSetText($FormGUI, "", $InputImg2, $sImg2)
			EndIf
		Case $BtnHomography
			$sHomography = ControlGetText($FormGUI, "", $InputHomography)
			$sHomography = FileOpenDialog("Select an xml", $OPENCV_SAMPLES_DATA_PATH, "XML files (*.xml)", $FD_FILEMUSTEXIST, $sHomography)
			If @error Then
				$sHomography = ""
			Else
				ControlSetText($FormGUI, "", $InputHomography, $sHomography)
			EndIf
		Case $BtnExec
			Clean(False)
			Main()
	EndSwitch
WEnd

_Opencv_DLLClose()
_GDIPlus_Shutdown()

Func Main()
	;;! [load]
	If StringCompare($sImg1, ControlGetText($FormGUI, "", $InputImg1), $STR_NOCASESENSE) <> 0 Then
		$sImg1 = ControlGetText($FormGUI, "", $InputImg1)
		$img1 = _cveImreadAndCheck($sImg1, $CV_IMREAD_GRAYSCALE)
		If @error Then
			$sImg1 = ""
			Return
		EndIf
	EndIf

	If StringCompare($sImg2, ControlGetText($FormGUI, "", $InputImg2), $STR_NOCASESENSE) <> 0 Then
		$sImg2 = ControlGetText($FormGUI, "", $InputImg2)
		$img2 = _cveImreadAndCheck($sImg2, $CV_IMREAD_GRAYSCALE)
		If @error Then
			$sImg2 = ""
			Return
		EndIf
	EndIf

	If StringCompare($sHomography, ControlGetText($FormGUI, "", $InputHomography), $STR_NOCASESENSE) <> 0 Then
		$sHomography = ControlGetText($FormGUI, "", $InputHomography)
		Local $fs = _cveFileStorageCreate($sHomography, $CV_FILE_STORAGE_READ, "")
		$homography = _cveMatCreate()
		Local $node = _cveFileStorageGetFirstTopLevelNode($fs)
		_cveFileNodeReadMat($node, $homography, _cveNoArrayMat())
		_cveFileStorageRelease($fs)

		If _cveInputArrayIsEmptyMat($homography) Then
			ConsoleWriteError("!>Error: The xml file " & $sHomography & " could not be loaded." & @CRLF)
			_cveMatRelease($homography)
			$sHomography = ""
			Return
		EndIf

		$homography_size = _cvSize()
		_cveMatGetSize($homography, $homography_size)
	EndIf
	;;! [load]

	Detect()
EndFunc   ;==>Main

Func Clean($force = True)
	If $sImg1 <> "" And ($force Or StringCompare($sImg1, ControlGetText($FormGUI, "", $InputImg1), $STR_NOCASESENSE) <> 0) Then
		_cveMatRelease($img1)
		$sImg1 = ""
	EndIf

	If $sImg2 <> "" And ($force Or StringCompare($sImg2, ControlGetText($FormGUI, "", $InputImg2), $STR_NOCASESENSE) <> 0) Then
		_cveMatRelease($img2)
		$sImg2 = ""
	EndIf

	If $sHomography <> "" And ($force Or StringCompare($sHomography, ControlGetText($FormGUI, "", $InputHomography), $STR_NOCASESENSE) <> 0) Then
		_cveMatRelease($homography)
		$sHomography = ""
	EndIf
EndFunc   ;==>Clean

Func Detect()
	If $sImg1 == "" Or $sImg2 == "" Or $sHomography == "" Then Return

	Local $inlier_threshold = 2.5 ; // Distance threshold to identify inliers with homography check
	Local $nn_match_ratio = 0.8 ;   // Nearest neighbor matching ratio

	;;! [AKAZE]
	$hTimer = TimerInit()
	Local $kpts1 = _VectorOfKeyPointCreate()
	Local $kpts2 = _VectorOfKeyPointCreate()
	Local $desc1 = _cveMatCreate()
	Local $desc2 = _cveMatCreate()

	Local $tFeature2DPtr = DllStructCreate("ptr value")
	Local $tSharedPtr = DllStructCreate("ptr")
	_cveAKAZEDetectorCreate($CV_AKAZE_DESCRIPTOR_MLDB, 0, 3, 0.001, 4, 4, $CV_KAZE_DIFF_PM_G2, $tFeature2DPtr, $tSharedPtr)
	Local $akaze = $tFeature2DPtr.value

	_CvFeature2DDetectAndComputeMat($akaze, $img1, _cveNoArrayMat(), $kpts1, $desc1, False) ;
	_CvFeature2DDetectAndComputeMat($akaze, $img2, _cveNoArrayMat(), $kpts2, $desc2, False) ;
	ConsoleWrite("_CvFeature2DDetectAndComputeMat " & TimerDiff($hTimer) & "ms" & @CRLF)
	;;! [AKAZE]

	;;! [2-nn matching]
	$hTimer = TimerInit()
	Local $tMatcherPtr = DllStructCreate("ptr value")
	Local $bf_matcher = _cveBFMatcherCreate($CV_NORM_HAMMING, False, $tMatcherPtr) ;
	Local $matcher = $tMatcherPtr.value
	Local $nn_matches = _VectorOfVectorOfDMatchCreate() ;
	_cveDescriptorMatcherKnnMatch1Mat($matcher, $desc1, $desc2, $nn_matches, 2, _cveNoArrayMat(), False) ;
	ConsoleWrite("_cveDescriptorMatcherKnnMatch1Mat " & TimerDiff($hTimer) & "ms" & @CRLF)
	;;! [2-nn matching]

	;;! [ratio test filtering]
	Local $matched1 = _VectorOfKeyPointCreate()
	Local $matched2 = _VectorOfKeyPointCreate()

	Local $tVectorDMatchPtr = DllStructCreate("ptr value")
	Local $tDMatchPtr0 = DllStructCreate("ptr value")
	Local $tDMatchPtr1 = DllStructCreate("ptr value")
	Local $tKpt1Ptr = DllStructCreate("ptr value")
	Local $tKpt2Ptr = DllStructCreate("ptr value")

	If $addon_dll == "" Then
		; Inefficient
		$hTimer = TimerInit()
		For $i = 0 To _VectorOfVectorOfDMatchGetSize($nn_matches) - 1
			_VectorOfVectorOfDMatchGetItemPtr($nn_matches, $i, $tVectorDMatchPtr)

			_VectorOfDMatchGetItemPtr($tVectorDMatchPtr.value, 0, $tDMatchPtr0)
			Local $tDMatch0 = DllStructCreate($tagCvDMatch, $tDMatchPtr0.value)

			_VectorOfDMatchGetItemPtr($tVectorDMatchPtr.value, 1, $tDMatchPtr1)
			Local $tDMatch1 = DllStructCreate($tagCvDMatch, $tDMatchPtr1.value)

			Local $dist1 = $tDMatch0.distance ;
			Local $dist2 = $tDMatch1.distance ;

			If $dist1 < $nn_match_ratio * $dist2 Then
				_VectorOfKeyPointGetItemPtr($kpts1, $tDMatch0.queryIdx, $tKpt1Ptr)
				Local $tKpt1 = DllStructCreate($tagCvKeyPoint, $tKpt1Ptr.value)
				_VectorOfKeyPointPush($matched1, $tKpt1)

				_VectorOfKeyPointGetItemPtr($kpts2, $tDMatch0.trainIdx, $tKpt2Ptr)
				Local $tKpt2 = DllStructCreate($tagCvKeyPoint, $tKpt2Ptr.value)
				_VectorOfKeyPointPush($matched2, $tKpt2)
			EndIf
		Next
		ConsoleWrite("AutoIt AKAZE_match_ratio_test_filtering " & TimerDiff($hTimer) & "ms" & @CRLF)
	Else
		;;: [doing the loop in a compiled code is way faster than doing it in autoit]
		$hTimer = TimerInit()
		CVEDllCallResult(DllCall($addon_dll, "none:cdecl", "AKAZE_match_ratio_test_filtering", _
			"ptr", $matched1, _
			"ptr", $kpts1, _
			"ptr", $matched2, _
			"ptr", $kpts2, _
			"ptr", $nn_matches, _
			"float", $nn_match_ratio _
		), "AKAZE_match_ratio_test_filtering", @error)
		ConsoleWrite("DllCall AKAZE_match_ratio_test_filtering " & TimerDiff($hTimer) & "ms" & @CRLF)
		;;: [doing the loop in a compiled code is way faster than doing it in autoit]
	EndIf
	;;! [ratio test filtering]

	;;! [homography check]
	Local $inliers1 = _VectorOfKeyPointCreate()
	Local $inliers2 = _VectorOfKeyPointCreate()

	Local $good_matches[_VectorOfKeyPointGetSize($matched1)] ;

	If $addon_dll == "" Then
		; Inefficient
		$hTimer = TimerInit()
		For $i = 0 To _VectorOfKeyPointGetSize($matched1) - 1
			_VectorOfKeyPointGetItemPtr($matched1, $i, $tKpt1Ptr)
			Local $tKpt1 = DllStructCreate($tagCvKeyPoint, $tKpt1Ptr.value)

			_VectorOfKeyPointGetItemPtr($matched2, $i, $tKpt2Ptr)
			Local $tKpt2 = DllStructCreate($tagCvKeyPoint, $tKpt2Ptr.value)

			Local $col = _cveMatCreate()
			_cveMatOnes(3, 1, $CV_64F, $col)
			_cveMatSetAt("double", $col, _cvPoint(0, 0), $tKpt1.x)
			_cveMatSetAt("double", $col, _cvPoint(0, 1), $tKpt1.y)

			Local $col_mul = _cveMatCreate()
			_cveMatCreateData($col_mul, $homography_size.height, _cveMatGetWidth($col), $CV_64FC1)
			_cveGemmMat($homography, $col, 1.0, _cveNoArrayMat(), 0.0, $col_mul, 0)
			_cveMatRelease($col)
			$col = $col_mul

			_cveMatConvertToMat($col, $col, -1, 1 / _cveMatGetAt("double", $col, _cvPoint(0, 2)), 0.0)

			Local $dist = Sqrt(((_cveMatGetAt("double", $col, _cvPoint(0, 0)) - $tKpt2.x) ^ 2) + _
					((_cveMatGetAt("double", $col, _cvPoint(0, 1)) - $tKpt2.y) ^ 2))            ;

			If $dist < $inlier_threshold Then
				Local $new_i = _VectorOfKeyPointGetSize($inliers1) ;
				_VectorOfKeyPointPush($inliers1, $tKpt1)
				_VectorOfKeyPointPush($inliers2, $tKpt2)
				$good_matches[$new_i] = DllStructCreate($tagCvDMatch)
				$good_matches[$new_i].queryIdx = $new_i
				$good_matches[$new_i].trainIdx = $new_i
				$good_matches[$new_i].distance = 0
			EndIf

			_cveMatRelease($col)
		Next

		ReDim $good_matches[_VectorOfKeyPointGetSize($inliers1)]
		ConsoleWrite("AutoIt AKAZE_homograpy_check " & TimerDiff($hTimer) & "ms" & @CRLF)
	Else
		;;: [doing the loop in a compiled code is way faster than doing it in autoit]
		$hTimer = TimerInit()
		$good_matches = _VectorOfDMatchCreate()
		CVEDllCallResult(DllCall($addon_dll, "none:cdecl", "AKAZE_homograpy_check", _
			"ptr", $homography, _
			"ptr", $matched1, _
			"ptr", $inliers1, _
			"ptr", $matched2, _
			"ptr", $inliers2, _
			"float", $inlier_threshold, _
			"ptr", $good_matches _
		), "AKAZE_homograpy_check", @error)
		ConsoleWrite("DllCall AKAZE_homograpy_check " & TimerDiff($hTimer) & "ms" & @CRLF)
		;;: [doing the loop in a compiled code is way faster than doing it in autoit]
	EndIf
	ConsoleWrite(@CRLF)
	;;! [homography check]

	;;! [draw final matches]
	Local $res = _cveMatCreate() ;
	Local $matchesMask = _VectorOfByteCreate()
	_drawMatchedFeatures1Mat($img1, $inliers1, $img2, $inliers2, $good_matches, $res, _cvScalarAll(-1), _
			_cvScalarAll(-1), $matchesMask, $CV_DRAW_MATCHES_FLAGS_DEFAULT) ;

	Local $inlier_ratio = _VectorOfKeyPointGetSize($inliers1) / _VectorOfKeyPointGetSize($matched1) ;
	ConsoleWrite("A-KAZE Matching Results" & @CRLF) ;
	ConsoleWrite("*******************************" & @CRLF) ;
	ConsoleWrite("# Keypoints 1:                        " & @TAB & _VectorOfKeyPointGetSize($kpts1) & @CRLF) ;
	ConsoleWrite("# Keypoints 2:                        " & @TAB & _VectorOfKeyPointGetSize($kpts2) & @CRLF) ;
	ConsoleWrite("# Matches:                            " & @TAB & _VectorOfKeyPointGetSize($matched1) & @CRLF) ;
	ConsoleWrite("# Inliers:                            " & @TAB & _VectorOfKeyPointGetSize($inliers1) & @CRLF) ;
	ConsoleWrite("# Inliers Ratio:                      " & @TAB & $inlier_ratio & @CRLF) ;
	ConsoleWrite(@CRLF) ;

	; _cveImshowMat("result", $res);
	; waitKey();
	_cveImshowControlPic($res, $FormGUI, $PicMatches, $tBackgroundColor)
	;;! [draw final matches]

	_VectorOfByteRelease($matchesMask)
	_cveMatRelease($res)
	_VectorOfKeyPointRelease($inliers2)
	_VectorOfKeyPointRelease($inliers1)
	_VectorOfKeyPointRelease($matched2)
	_VectorOfKeyPointRelease($matched1)
	_VectorOfVectorOfDMatchRelease($nn_matches)
	_cveBFMatcherRelease($bf_matcher)
	_cveAKAZEDetectorRelease($tSharedPtr)
	_cveMatRelease($desc2)
	_cveMatRelease($desc1)
	_VectorOfKeyPointRelease($kpts2)
	_VectorOfKeyPointRelease($kpts1)

EndFunc   ;==>Detect
