#Region ;**** Directives created by AutoIt3Wrapper_GUI ****
#AutoIt3Wrapper_UseX64=y
#EndRegion ;**** Directives created by AutoIt3Wrapper_GUI ****

Opt("MustDeclareVars", 1)

#include <Misc.au3>
#include "..\emgucv-autoit-bindings\cve_extra.au3"

; Open the library
_OpenCV_DLLOpen("..\libemgucv-windesktop-4.5.3.4721\libs\x64\cvextern.dll")

Local $cap = _cveVideoCaptureCreateFromFile("data\vtest.avi", $CV_CAP_ANY, 0)
If Not _cveVideoCaptureIsOpened($cap) Then
    ConsoleWriteError("!>Error: cannot open the video file." & @CRLF)
    Exit
EndIf

Local $frame = _cveMatCreate()

While 1
    If _IsPressed("1B") Or _IsPressed(Hex(Asc("Q"))) Then
        ExitLoop
    EndIf

    _cveVideoCaptureReadMat($cap, $frame)
    If _cveInputArrayIsEmptyMat($frame) Then
        ConsoleWriteError("!>Error: cannot read the video or end of the video." & @CRLF)
        ExitLoop
    EndIf

    _cveImshowMat("capture video file", $frame)

    Sleep(30)
WEnd

_cveWaitKey()

; always release resources to avoid memory leaks on long running processes
_cveMatRelease($frame)
_cveVideoCaptureRelease($cap)
_cveDestroyAllWindows()

; Close the library
_Opencv_DLLClose()
