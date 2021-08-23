#include-once
#include "..\..\CVEUtils.au3"

Func _cveImshow($winname, $mat)
    ; CVAPI(void) cveImshow(cv::String* winname, cv::_InputArray* mat);

    Local $bWinnameIsString = VarGetType($winname) == "String"
    If $bWinnameIsString Then
        $winname = _cveStringCreateFromStr($winname)
    EndIf

    Local $sWinnameDllType
    If IsDllStruct($winname) Then
        $sWinnameDllType = "struct*"
    Else
        $sWinnameDllType = "ptr"
    EndIf

    Local $sMatDllType
    If IsDllStruct($mat) Then
        $sMatDllType = "struct*"
    Else
        $sMatDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveImshow", $sWinnameDllType, $winname, $sMatDllType, $mat), "cveImshow", @error)

    If $bWinnameIsString Then
        _cveStringRelease($winname)
    EndIf
EndFunc   ;==>_cveImshow

Func _cveImshowMat($winname, $matMat)
    ; cveImshow using cv::Mat instead of _*Array

    Local $iArrMat, $vectorOfMatMat, $iArrMatSize
    Local $bMatIsArray = VarGetType($matMat) == "Array"

    If $bMatIsArray Then
        $vectorOfMatMat = _VectorOfMatCreate()

        $iArrMatSize = UBound($matMat)
        For $i = 0 To $iArrMatSize - 1
            _VectorOfMatPush($vectorOfMatMat, $matMat[$i])
        Next

        $iArrMat = _cveInputArrayFromVectorOfMat($vectorOfMatMat)
    Else
        $iArrMat = _cveInputArrayFromMat($matMat)
    EndIf

    _cveImshow($winname, $iArrMat)

    If $bMatIsArray Then
        _VectorOfMatRelease($vectorOfMatMat)
    EndIf

    _cveInputArrayRelease($iArrMat)
EndFunc   ;==>_cveImshowMat

Func _cveNamedWindow($winname, $flags = $CV_WINDOW_AUTOSIZE)
    ; CVAPI(void) cveNamedWindow(cv::String* winname, int flags);

    Local $bWinnameIsString = VarGetType($winname) == "String"
    If $bWinnameIsString Then
        $winname = _cveStringCreateFromStr($winname)
    EndIf

    Local $sWinnameDllType
    If IsDllStruct($winname) Then
        $sWinnameDllType = "struct*"
    Else
        $sWinnameDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveNamedWindow", $sWinnameDllType, $winname, "int", $flags), "cveNamedWindow", @error)

    If $bWinnameIsString Then
        _cveStringRelease($winname)
    EndIf
EndFunc   ;==>_cveNamedWindow

Func _cveSetWindowProperty($winname, $propId, $propValue)
    ; CVAPI(void) cveSetWindowProperty(cv::String* winname, int propId, double propValue);

    Local $bWinnameIsString = VarGetType($winname) == "String"
    If $bWinnameIsString Then
        $winname = _cveStringCreateFromStr($winname)
    EndIf

    Local $sWinnameDllType
    If IsDllStruct($winname) Then
        $sWinnameDllType = "struct*"
    Else
        $sWinnameDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSetWindowProperty", $sWinnameDllType, $winname, "int", $propId, "double", $propValue), "cveSetWindowProperty", @error)

    If $bWinnameIsString Then
        _cveStringRelease($winname)
    EndIf
EndFunc   ;==>_cveSetWindowProperty

Func _cveSetWindowTitle($winname, $title)
    ; CVAPI(void) cveSetWindowTitle(cv::String* winname, cv::String* title);

    Local $bWinnameIsString = VarGetType($winname) == "String"
    If $bWinnameIsString Then
        $winname = _cveStringCreateFromStr($winname)
    EndIf

    Local $sWinnameDllType
    If IsDllStruct($winname) Then
        $sWinnameDllType = "struct*"
    Else
        $sWinnameDllType = "ptr"
    EndIf

    Local $bTitleIsString = VarGetType($title) == "String"
    If $bTitleIsString Then
        $title = _cveStringCreateFromStr($title)
    EndIf

    Local $sTitleDllType
    If IsDllStruct($title) Then
        $sTitleDllType = "struct*"
    Else
        $sTitleDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSetWindowTitle", $sWinnameDllType, $winname, $sTitleDllType, $title), "cveSetWindowTitle", @error)

    If $bTitleIsString Then
        _cveStringRelease($title)
    EndIf

    If $bWinnameIsString Then
        _cveStringRelease($winname)
    EndIf
EndFunc   ;==>_cveSetWindowTitle

Func _cveGetWindowProperty($winname, $propId)
    ; CVAPI(double) cveGetWindowProperty(cv::String* winname, int propId);

    Local $bWinnameIsString = VarGetType($winname) == "String"
    If $bWinnameIsString Then
        $winname = _cveStringCreateFromStr($winname)
    EndIf

    Local $sWinnameDllType
    If IsDllStruct($winname) Then
        $sWinnameDllType = "struct*"
    Else
        $sWinnameDllType = "ptr"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveGetWindowProperty", $sWinnameDllType, $winname, "int", $propId), "cveGetWindowProperty", @error)

    If $bWinnameIsString Then
        _cveStringRelease($winname)
    EndIf

    Return $retval
EndFunc   ;==>_cveGetWindowProperty

Func _cveDestroyWindow($winname)
    ; CVAPI(void) cveDestroyWindow(cv::String* winname);

    Local $bWinnameIsString = VarGetType($winname) == "String"
    If $bWinnameIsString Then
        $winname = _cveStringCreateFromStr($winname)
    EndIf

    Local $sWinnameDllType
    If IsDllStruct($winname) Then
        $sWinnameDllType = "struct*"
    Else
        $sWinnameDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDestroyWindow", $sWinnameDllType, $winname), "cveDestroyWindow", @error)

    If $bWinnameIsString Then
        _cveStringRelease($winname)
    EndIf
EndFunc   ;==>_cveDestroyWindow

Func _cveDestroyAllWindows()
    ; CVAPI(void) cveDestroyAllWindows();
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDestroyAllWindows"), "cveDestroyAllWindows", @error)
EndFunc   ;==>_cveDestroyAllWindows

Func _cveWaitKey($delay = 0)
    ; CVAPI(int) cveWaitKey(int delay);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveWaitKey", "int", $delay), "cveWaitKey", @error)
EndFunc   ;==>_cveWaitKey

Func _cvePollKey()
    ; CVAPI(int) cvePollKey();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cvePollKey"), "cvePollKey", @error)
EndFunc   ;==>_cvePollKey

Func _cveSelectROI($windowName, $img, $showCrosshair, $fromCenter, $roi)
    ; CVAPI(void) cveSelectROI(cv::String* windowName, cv::_InputArray* img, bool showCrosshair, bool fromCenter, CvRect* roi);

    Local $bWindowNameIsString = VarGetType($windowName) == "String"
    If $bWindowNameIsString Then
        $windowName = _cveStringCreateFromStr($windowName)
    EndIf

    Local $sWindowNameDllType
    If IsDllStruct($windowName) Then
        $sWindowNameDllType = "struct*"
    Else
        $sWindowNameDllType = "ptr"
    EndIf

    Local $sImgDllType
    If IsDllStruct($img) Then
        $sImgDllType = "struct*"
    Else
        $sImgDllType = "ptr"
    EndIf

    Local $sRoiDllType
    If IsDllStruct($roi) Then
        $sRoiDllType = "struct*"
    Else
        $sRoiDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSelectROI", $sWindowNameDllType, $windowName, $sImgDllType, $img, "boolean", $showCrosshair, "boolean", $fromCenter, $sRoiDllType, $roi), "cveSelectROI", @error)

    If $bWindowNameIsString Then
        _cveStringRelease($windowName)
    EndIf
EndFunc   ;==>_cveSelectROI

Func _cveSelectROIMat($windowName, $matImg, $showCrosshair, $fromCenter, $roi)
    ; cveSelectROI using cv::Mat instead of _*Array

    Local $iArrImg, $vectorOfMatImg, $iArrImgSize
    Local $bImgIsArray = VarGetType($matImg) == "Array"

    If $bImgIsArray Then
        $vectorOfMatImg = _VectorOfMatCreate()

        $iArrImgSize = UBound($matImg)
        For $i = 0 To $iArrImgSize - 1
            _VectorOfMatPush($vectorOfMatImg, $matImg[$i])
        Next

        $iArrImg = _cveInputArrayFromVectorOfMat($vectorOfMatImg)
    Else
        $iArrImg = _cveInputArrayFromMat($matImg)
    EndIf

    _cveSelectROI($windowName, $iArrImg, $showCrosshair, $fromCenter, $roi)

    If $bImgIsArray Then
        _VectorOfMatRelease($vectorOfMatImg)
    EndIf

    _cveInputArrayRelease($iArrImg)
EndFunc   ;==>_cveSelectROIMat

Func _cveSelectROIs($windowName, $img, $boundingBoxs, $showCrosshair = true, $fromCenter = false)
    ; CVAPI(void) cveSelectROIs(cv::String* windowName, cv::_InputArray* img, std::vector<cv::Rect>* boundingBoxs, bool showCrosshair, bool fromCenter);

    Local $bWindowNameIsString = VarGetType($windowName) == "String"
    If $bWindowNameIsString Then
        $windowName = _cveStringCreateFromStr($windowName)
    EndIf

    Local $sWindowNameDllType
    If IsDllStruct($windowName) Then
        $sWindowNameDllType = "struct*"
    Else
        $sWindowNameDllType = "ptr"
    EndIf

    Local $sImgDllType
    If IsDllStruct($img) Then
        $sImgDllType = "struct*"
    Else
        $sImgDllType = "ptr"
    EndIf

    Local $vecBoundingBoxs, $iArrBoundingBoxsSize
    Local $bBoundingBoxsIsArray = VarGetType($boundingBoxs) == "Array"

    If $bBoundingBoxsIsArray Then
        $vecBoundingBoxs = _VectorOfRectCreate()

        $iArrBoundingBoxsSize = UBound($boundingBoxs)
        For $i = 0 To $iArrBoundingBoxsSize - 1
            _VectorOfRectPush($vecBoundingBoxs, $boundingBoxs[$i])
        Next
    Else
        $vecBoundingBoxs = $boundingBoxs
    EndIf

    Local $sBoundingBoxsDllType
    If IsDllStruct($boundingBoxs) Then
        $sBoundingBoxsDllType = "struct*"
    Else
        $sBoundingBoxsDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSelectROIs", $sWindowNameDllType, $windowName, $sImgDllType, $img, $sBoundingBoxsDllType, $vecBoundingBoxs, "boolean", $showCrosshair, "boolean", $fromCenter), "cveSelectROIs", @error)

    If $bBoundingBoxsIsArray Then
        _VectorOfRectRelease($vecBoundingBoxs)
    EndIf

    If $bWindowNameIsString Then
        _cveStringRelease($windowName)
    EndIf
EndFunc   ;==>_cveSelectROIs

Func _cveSelectROIsMat($windowName, $matImg, $boundingBoxs, $showCrosshair = true, $fromCenter = false)
    ; cveSelectROIs using cv::Mat instead of _*Array

    Local $iArrImg, $vectorOfMatImg, $iArrImgSize
    Local $bImgIsArray = VarGetType($matImg) == "Array"

    If $bImgIsArray Then
        $vectorOfMatImg = _VectorOfMatCreate()

        $iArrImgSize = UBound($matImg)
        For $i = 0 To $iArrImgSize - 1
            _VectorOfMatPush($vectorOfMatImg, $matImg[$i])
        Next

        $iArrImg = _cveInputArrayFromVectorOfMat($vectorOfMatImg)
    Else
        $iArrImg = _cveInputArrayFromMat($matImg)
    EndIf

    _cveSelectROIs($windowName, $iArrImg, $boundingBoxs, $showCrosshair, $fromCenter)

    If $bImgIsArray Then
        _VectorOfMatRelease($vectorOfMatImg)
    EndIf

    _cveInputArrayRelease($iArrImg)
EndFunc   ;==>_cveSelectROIsMat