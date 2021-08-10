#Region ;**** Directives created by AutoIt3Wrapper_GUI ****
#AutoIt3Wrapper_UseX64=y
#EndRegion ;**** Directives created by AutoIt3Wrapper_GUI ****

Opt("MustDeclareVars", 1)

#include <Misc.au3>
#include "..\emgucv-autoit-bindings\cve_extra.au3"

; Open the library
_OpenCV_DLLOpen("..\libemgucv-windesktop-4.5.3.4721\libs\x64\cvextern.dll")

Local $iCamId = 0
Local $cap = _cveVideoCaptureCreateFromDevice($iCamId, $CV_CAP_ANY, 0)
If Not _cveVideoCaptureIsOpened($cap) Then
    ConsoleWriteError("!>Error: cannot open the camera." & @CRLF)
    Exit
EndIf

Local $frame = _cveMatCreate()
Local $frame_flipped = _cveMatCreate()

While 1
    If _IsPressed("1B") Or _IsPressed(Hex(Asc("Q"))) Then
        ExitLoop
    EndIf

    _cveVideoCaptureReadMat($cap, $frame)

    If _cveInputArrayIsEmptyMat($frame) Then
        ConsoleWriteError("!>Error: cannot read the camera." & @CRLF)
    Else
        ;; Flip the image horizontally to give the mirror impression
        _cveFlipMat($frame, $frame_flipped, 1)
        _cveImshowMat("capture camera", $frame_flipped)
    EndIf

    Sleep(30)
WEnd

_cveWaitKey()

; always release resources to avoid memory leaks on long running processes
_cveMatRelease($frame_flipped)
_cveMatRelease($frame)
_cveVideoCaptureRelease($cap)
_cveDestroyAllWindows()

; Close the library
_Opencv_DLLClose()
