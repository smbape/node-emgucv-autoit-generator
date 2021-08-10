#Region ;**** Directives created by AutoIt3Wrapper_GUI ****
#AutoIt3Wrapper_UseX64=y
#EndRegion ;**** Directives created by AutoIt3Wrapper_GUI ****

Opt("MustDeclareVars", 1)

#include "..\emgucv-autoit-bindings\cve_extra.au3"

; Open the library
_OpenCV_DLLOpen("..\libemgucv-windesktop-4.5.3.4721\libs\x64\cvextern.dll")

Local $img = _cveImreadAndCheck("data\mario.png", $CV_IMREAD_COLOR)
Local $tmpl = _cveImreadAndCheck("data\mario_coin.png", $CV_IMREAD_COLOR)

; The higher the value, the higher the match is exact
Local $threshold = 0.8

Local $aMatches = _cveFindTemplate($img, $tmpl, $threshold)

Local $tRedColor = _cvRGB(255, 0, 0)
Local $w = _cveMatGetWidth($tmpl)
Local $h = _cveMatGetHeight($tmpl)
Local $tMatchRect = _cvRect(0, 0, $w, $h)

For $i = 0 To UBound($aMatches) - 1
    $tMatchRect.x = $aMatches[$i][0]
    $tMatchRect.y = $aMatches[$i][1]

    ; Draw a red rectangle around the matched position
    _cveRectangleMat($img, $tMatchRect, $tRedColor, 1, $CV_LINE_8, 0)
Next

_cveImshowMat("Find template example", $img)
_cveWaitKey()

; always release resources to avoid memory leaks on long running processes
_cveMatRelease($img)
_cveDestroyAllWindows()

; Close the library
_Opencv_DLLClose()
