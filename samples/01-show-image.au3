#Region ;**** Directives created by AutoIt3Wrapper_GUI ****
#AutoIt3Wrapper_UseX64=y
#EndRegion ;**** Directives created by AutoIt3Wrapper_GUI ****

Opt("MustDeclareVars", 1)

#include "..\emgucv-autoit-bindings\cve_extra.au3"

; Open the library
_OpenCV_DLLOpen("..\libemgucv-windesktop-4.5.3.4721\libs\x64\cvextern.dll")

Local $img = _cveImreadAndCheck("data\lena.jpg")
_cveImshowMat("Image", $img)
_cveWaitKey()

; always release resources to avoid memory leaks on long running processes
_cveMatRelease($img)
_cveDestroyAllWindows()

; Close the library
_Opencv_DLLClose()
