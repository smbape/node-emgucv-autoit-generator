#Region ;**** Directives created by AutoIt3Wrapper_GUI ****
#AutoIt3Wrapper_UseX64=y
#EndRegion ;**** Directives created by AutoIt3Wrapper_GUI ****

Opt("MustDeclareVars", 1)

#include <ButtonConstants.au3>
#include <EditConstants.au3>
#include <File.au3>
#include <FileConstants.au3>
#include <GDIPlus.au3>
#include <GUIConstantsEx.au3>
#include <Math.au3>
#include <StaticConstants.au3>
#include <WindowsConstants.au3>
#include "..\..\..\..\emgucv-autoit-bindings\cve_extra.au3"

;~ Sources:
;~     https://docs.opencv.org/4.5.3/d8/d01/tutorial_discrete_fourier_transform.html
;~     https://github.com/opencv/opencv/blob/4.5.3/samples/cpp/tutorial_code/core/discrete_fourier_transform/discrete_fourier_transform.cpp

Local Const $OPENCV_SAMPLES_DATA_PATH = _OpenCV_FindFile("samples\data")

#Region ### START Koda GUI section ### Form=
Local $FormGUI = GUICreate("Discrete Fourier Transform", 1065, 617, 192, 124)

Local $InputSource = GUICtrlCreateInput($OPENCV_SAMPLES_DATA_PATH & "\lena.jpg", 264, 24, 449, 21)
GUICtrlSetState(-1, $GUI_DISABLE)
Local $BtnSource = GUICtrlCreateButton("Open", 723, 22, 75, 25)

Local $LabelSource = GUICtrlCreateLabel("Input Image", 231, 60, 100, 20)
GUICtrlSetFont(-1, 10, 800, 0, "MS Sans Serif")
Local $GroupSource = GUICtrlCreateGroup("", 20, 83, 510, 516)
Local $PicSource = GUICtrlCreatePic("", 25, 94, 500, 500)
GUICtrlCreateGroup("", -99, -99, 1, 1)

Local $LabelResult = GUICtrlCreateLabel("spectrum magnitude", 735, 60, 148, 20)
GUICtrlSetFont(-1, 10, 800, 0, "MS Sans Serif")
Local $GroupResult = GUICtrlCreateGroup("", 532, 83, 510, 516)
Local $PicResult = GUICtrlCreatePic("", 537, 94, 500, 500)
GUICtrlCreateGroup("", -99, -99, 1, 1)

GUISetState(@SW_SHOW)
#EndRegion ### END Koda GUI section ###

_GDIPlus_Startup()
_OpenCV_DLLOpen(_OpenCV_FindDLL())

Local $sImage = ""
Local $nMsg

Main()

While 1
	$nMsg = GUIGetMsg()
	Switch $nMsg
		Case $GUI_EVENT_CLOSE
			Exit
		Case $BtnSource
			Clean()
			$sImage = ControlGetText($FormGUI, "", $InputSource)
			$sImage = FileOpenDialog("Select an image", $OPENCV_SAMPLES_DATA_PATH, "Image files (*.bmp;*.jpg;*.jpeg;*.png;*.gif)", $FD_FILEMUSTEXIST, $sImage)
			If @error Then
				$sImage = ""
			Else
				ControlSetText($FormGUI, "", $InputSource, $sImage)
				Main()
			EndIf
	EndSwitch
WEnd

Clean()

_Opencv_DLLClose()
_GDIPlus_Shutdown()

Func Main()
	$sImage = ControlGetText($FormGUI, "", $InputSource)
	If $sImage == "" Then Return

	;;! [Load image]
	Local $I = _cveImreadAndCheck($sImage, $CV_IMREAD_GRAYSCALE)
	If @error Then
		$sImage = ""
		Return
	EndIf
	;;! [Load image]

	Local $tSize = _cvSize()
	_cveMatGetSize($I, $tSize)

	;;! [expand]
	Local $padded = _cveMatCreate();                            ;;expand input image to optimal size
	Local $m = _cveGetOptimalDFTSize( $tSize.height );
	Local $n = _cveGetOptimalDFTSize( $tSize.width ); ; on the border add zero values
	_cveCopyMakeBorderMat($I, $padded, 0, $m - $tSize.height, 0, $n - $tSize.width, $CV_BORDER_CONSTANT, _cvScalarAll(0));
	;;! [expand]

	;;! [complex_and_real]
	Local $planes[2] = [_cveMatCreate(), _cveMatCreate()]
	_cveMatConvertToMat($padded, $planes[0], $CV_32F, 1.0, 0.0)
	_cveMatGetSize($padded, $tSize)
	_cveMatOnes($tSize.height, $tSize.width, $CV_32F, $planes[1])
	Local $complexI = _cveMatCreate();
	_cveMergeMat($planes, $complexI);         ; Add to the expanded another plane with zeros
	;;! [complex_and_real]

	;;! [dft]
	_cveDftMat($complexI, $complexI);            ; this way the result may fit in the source matrix
	;;! [dft]

	; compute the magnitude and switch to logarithmic scale
	; => log(1 + sqrt(Re(DFT(I))^2 + Im(DFT(I))^2))
	;;! [magnitude]
	Local $magI = _cveMatCreate()
	Local $angleI = _cveMatCreate()
	_cveSplitMat($complexI, $planes);                   ; planes[0] = Re(DFT(I), planes[1] = Im(DFT(I))
	_cveCartToPolarMat($planes[0], $planes[1], $magI, $angleI);
	_cveMatRelease($angleI)
	;;! [magnitude]

	;;! [log]
	_cveAddTyped("Mat", $magI, "Scalar", _cvScalarAll(1), "Mat", $magI) ; switch to logarithmic scale
	_cveLogMat($magI, $magI);
	;;! [log]

	;;! [crop_rearrange]
	; crop the spectrum, if it has an odd number of rows or columns
	_cveMatGetSize($magI, $tSize)
	Local $tRect = _cvRect(0, 0, BitAND($tSize.width, -2), BitAND($tSize.height, -2))
	Local $_magI = $magI
	$magI = _cveMatCreateFromRect($_magI, $tRect)

	; rearrange the quadrants of Fourier image  so that the origin is at the image center
	_cveMatGetSize($magI, $tSize)
	Local $cx = $tSize.width / 2;
	Local $cy = $tSize.height / 2;

	Local $q0 = _cveMatCreateFromRect($magI, _cvRect(0, 0, $cx, $cy));     ; Top-Left - Create a ROI per quadrant
	Local $q1 = _cveMatCreateFromRect($magI, _cvRect($cx, 0, $cx, $cy));   ; Top-Right
	Local $q2 = _cveMatCreateFromRect($magI, _cvRect(0, $cy, $cx, $cy));   ; Bottom-Left
	Local $q3 = _cveMatCreateFromRect($magI, _cvRect($cx, $cy, $cx, $cy)); ; Bottom-Right

	Local $tmp = _cveMatCreate();                  ; swap quadrants (Top-Left with Bottom-Right)
	_cveMatCopyToMat($q0, $tmp, _cveNoArrayMat());
	_cveMatCopyToMat($q3, $q0, _cveNoArrayMat());
	_cveMatCopyToMat($tmp, $q3, _cveNoArrayMat());

	_cveMatCopyToMat($q1, $tmp, _cveNoArrayMat()); ; swap quadrant (Top-Right with Bottom-Left)
	_cveMatCopyToMat($q2, $q1, _cveNoArrayMat());
	_cveMatCopyToMat($tmp, $q2, _cveNoArrayMat());
	;;! [crop_rearrange]

	;;! [normalize]
	_cveNormalizeMat($magI, $magI, 0, 1, $CV_NORM_MINMAX); ; Transform the matrix with float values into a
											; viewable image form (float between values 0 and 1).
	;;! [normalize]

	;;! [Display]
	_cveImshowControlPic($I, $FormGUI, $PicSource)
	_cveImshowControlPic($magI, $FormGUI, $PicResult)
	;;! [Display]

	_cveMatRelease($tmp)
	_cveMatRelease($q0)
	_cveMatRelease($q1)
	_cveMatRelease($q2)
	_cveMatRelease($q3)
	_cveMatRelease($magI)
	_cveMatRelease($_magI)
	_cveMatRelease($complexI)
	_cveMatRelease($planes[1])
	_cveMatRelease($planes[0])
	_cveMatRelease($padded)
	_cveMatRelease($I)
EndFunc   ;==>Main

Func Clean()
	If $sImage == "" Then Return

	$sImage = ""
EndFunc   ;==>Clean
