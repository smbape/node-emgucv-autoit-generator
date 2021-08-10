#Region ;**** Directives created by AutoIt3Wrapper_GUI ****
#AutoIt3Wrapper_UseX64=y
#EndRegion ;**** Directives created by AutoIt3Wrapper_GUI ****

Opt("MustDeclareVars", 1)

#include "..\emgucv-autoit-bindings\cve_extra.au3"

; Open the library
_OpenCV_DLLOpen("..\libemgucv-windesktop-4.5.3.4721\libs\x64\cvextern.dll")

Local $iLeft = 200
Local $iTop = 200
Local $iWidth = 400
Local $iHeight = 400

Local $tRect = DllStructCreate($tagRECT)
$tRect.Left = $iLeft
$tRect.Top = $iTop
$tRect.Right = $iLeft + $iWidth
$tRect.Bottom = $iTop + $iHeight

Local $tBits = _cveGetDesktopScreenBits($tRect)
Local $img = _cveMatCreateWithData($iHeight, $iWidth, $CV_8UC4, $tBits, $CV_MAT_AUTO_STEP)

_cveImshowMat("Screen capture", $img)
_cveWaitKey()

; always release resources to avoid memory leaks on long running processes
_cveMatRelease($img)
_cveDestroyAllWindows()

; Close the library
_Opencv_DLLClose()
