#include-once
#include "../emgucv-autoit-bindings/CVEUtils.au3"

Global $addon_dll = ""

Global Const $tagAddonDeviceInfo = _
    "long WaveInID;" & _
    "ptr FriendlyName;" & _
    "ulong_ptr FriendlyNameLen;" & _
    "ptr DevicePath;" & _
    "ulong_ptr DevicePathLen;"

Func _Addon_FindDLL($sDir = @ScriptDir, $sDll = "autoit_addon.dll")
    Local $aFileList
    Local $s_addon_dll = ""
    Local $sDrive = "", $sFileName = "", $sExtension = ""

    While 1
        $aFileList = _FileListToArray($sDir, "*.*")

        If @error <> 0 And @error <> 4 Then
            ExitLoop
        EndIf

        For $i = 1 To UBound($aFileList) - 1
            Local $aSearchDirs[10] = [ _
                "", _
                "\Release", _
                "\Debug", _
                "\build_x64\Release", _
                "\build_x64\Debug", _
                "\autoit-addon", _
                "\autoit-addon\Release", _
                "\autoit-addon\Debug", _
                "\autoit-addon\build_x64\Release", _
                "\autoit-addon\build_x64\Debug" _
            ]

            For $j = 0 To UBound($aSearchDirs) - 1
                $s_addon_dll = $sDir & "\" & $aFileList[$i] & $aSearchDirs[$j] & "\" & $sDll
                If FileExists($s_addon_dll) Then
                    _cveDebugMsg("Found " & $s_addon_dll & @CRLF)
                    ExitLoop 3
                EndIf
                $s_addon_dll = ""
            Next
        Next

        _PathSplit($sDir, $sDrive, $sDir, $sFileName, $sExtension)
        If $sDir == "" Then
            ExitLoop
        EndIf
        $sDir = $sDrive & StringLeft($sDir, StringLen($sDir) - 1)
    WEnd

    Return $s_addon_dll
EndFunc

Func _Addon_DLLOpen($s_addon_dll)
    $addon_dll = _OpenCV_LoadDLL($s_addon_dll)
    Return $addon_dll <> -1
EndFunc   ;==>_Addon_DLLOpen

Func _Addon_DLLClose()
    If $addon_dll == -1 Then Return False
    DllClose($addon_dll)
    Return True
    $addon_dll = ""
EndFunc   ;==>_Addon_DLLClose
