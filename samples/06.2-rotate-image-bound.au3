#Region ;**** Directives created by AutoIt3Wrapper_GUI ****
#AutoIt3Wrapper_UseX64=y
#EndRegion ;**** Directives created by AutoIt3Wrapper_GUI ****

Opt("MustDeclareVars", 1)

#include "..\emgucv-autoit-bindings\cve_extra.au3"

; Open the library
_OpenCV_DLLOpen("..\libemgucv-windesktop-4.5.3.4721\libs\x64\cvextern.dll")

Local $img = _cveImreadAndCheck("data\lena.jpg")
Local $angle = 20
Local $scale = 0.8

Local $rotated = _cveRotateBound($img, $angle, $scale)

_cveImshowMat("Bound Rotation", $rotated)
_cveWaitKey()

; always release resources to avoid memory leaks on long running processes
_cveMatRelease($rotated)
_cveMatRelease($img)
_cveDestroyAllWindows()

; Close the library
_Opencv_DLLClose()
