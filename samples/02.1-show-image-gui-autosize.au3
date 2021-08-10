#Region ;**** Directives created by AutoIt3Wrapper_GUI ****
#AutoIt3Wrapper_UseX64=y
#EndRegion ;**** Directives created by AutoIt3Wrapper_GUI ****

Opt("MustDeclareVars", 1)

#include <GUIConstantsEx.au3>
#include <StaticConstants.au3>
#include <WindowsConstants.au3>
#include "..\emgucv-autoit-bindings\cve_extra.au3"

#Region ### START Koda GUI section ### Form=
Local $FormGUI = GUICreate("show image in autoit gui [WINDOW_AUTOSIZE]", 400, 400, 200, 200)
Local $Pic = GUICtrlCreatePic("", 0, 0, 400, 400)
GUISetState(@SW_SHOW)
#EndRegion ### END Koda GUI section ###

; Open the library
_OpenCV_DLLOpen("..\libemgucv-windesktop-4.5.3.4721\libs\x64\cvextern.dll")

Local $img = _cveImreadAndCheck("data\lena.jpg")

; get the image size and resize the GUI and the PIC control
Local $tSize = _cvSize()
_cveMatGetSize($img, $tSize)
WinMove($FormGUI, "", Default, Default, $tSize.width, $tSize.height)
GUICtrlSetPos($Pic, Default, Default, $tSize.width, $tSize.height)

_cveImshowControlPic($img, $FormGUI, $Pic)

Local $nMsg
While 1
    $nMsg = GUIGetMsg()
    Switch $nMsg
        Case $GUI_EVENT_CLOSE
            Exit
    EndSwitch
WEnd

; always release resources to avoid memory leaks on long running processes
_cveMatRelease($img)
_cveDestroyAllWindows()

; Close the library
_Opencv_DLLClose()
