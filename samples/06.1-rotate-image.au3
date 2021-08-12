#Region ;**** Directives created by AutoIt3Wrapper_GUI ****
#AutoIt3Wrapper_UseX64=y
#EndRegion ;**** Directives created by AutoIt3Wrapper_GUI ****

Opt("MustDeclareVars", 1)

#include "..\emgucv-autoit-bindings\cve_extra.au3"

; Open the library
_OpenCV_DLLOpen("..\libemgucv-windesktop-4.5.3.4721\libs\x64\cvextern.dll")

Local $img = _cveImreadAndCheck("data\lena.jpg")
Local $angle = 20
Local $scale = 1

Local $size = _cvSize()
_cveMatGetSize($img, $size)
Local $center = DllStructCreate($tagCvPoint2D32f)
$center.x = $size.width / 2
$center.y = $size.height / 2

Local $M = _cveMatCreate()
_cveGetRotationMatrix2DMat($center, -$angle, $scale, $M)

Local $rotated = _cveMatCreate()
_cveWarpAffineMat($img, $rotated, $M, $size, $CV_INTER_LINEAR)

_cveImshowMat("Rotation", $rotated)
_cveWaitKey()

; always release resources to avoid memory leaks on long running processes
_cveMatRelease($rotated)
_cveMatRelease($M)
_cveMatRelease($img)
_cveDestroyAllWindows()

; Close the library
_Opencv_DLLClose()
