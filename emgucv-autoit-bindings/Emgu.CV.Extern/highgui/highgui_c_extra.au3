#include-once
#include "..\..\CVEUtils.au3"

Func _cveImshow($winname, $mat)
    ; CVAPI(void) cveImshow(cv::String* winname, cv::_InputArray* mat);

    Local $bWinnameIsString = VarGetType($winname) == "String"
    If $bWinnameIsString Then
        $winname = _cveStringCreateFromStr($winname)
    EndIf

    Local $bWinnameDllType
    If VarGetType($winname) == "DLLStruct" Then
        $bWinnameDllType = "struct*"
    Else
        $bWinnameDllType = "ptr"
    EndIf

    Local $bMatDllType
    If VarGetType($mat) == "DLLStruct" Then
        $bMatDllType = "struct*"
    Else
        $bMatDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveImshow", $bWinnameDllType, $winname, $bMatDllType, $mat), "cveImshow", @error)

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

    Local $bWinnameDllType
    If VarGetType($winname) == "DLLStruct" Then
        $bWinnameDllType = "struct*"
    Else
        $bWinnameDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveNamedWindow", $bWinnameDllType, $winname, "int", $flags), "cveNamedWindow", @error)

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

    Local $bWinnameDllType
    If VarGetType($winname) == "DLLStruct" Then
        $bWinnameDllType = "struct*"
    Else
        $bWinnameDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSetWindowProperty", $bWinnameDllType, $winname, "int", $propId, "double", $propValue), "cveSetWindowProperty", @error)

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

    Local $bWinnameDllType
    If VarGetType($winname) == "DLLStruct" Then
        $bWinnameDllType = "struct*"
    Else
        $bWinnameDllType = "ptr"
    EndIf

    Local $bTitleIsString = VarGetType($title) == "String"
    If $bTitleIsString Then
        $title = _cveStringCreateFromStr($title)
    EndIf

    Local $bTitleDllType
    If VarGetType($title) == "DLLStruct" Then
        $bTitleDllType = "struct*"
    Else
        $bTitleDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSetWindowTitle", $bWinnameDllType, $winname, $bTitleDllType, $title), "cveSetWindowTitle", @error)

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

    Local $bWinnameDllType
    If VarGetType($winname) == "DLLStruct" Then
        $bWinnameDllType = "struct*"
    Else
        $bWinnameDllType = "ptr"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveGetWindowProperty", $bWinnameDllType, $winname, "int", $propId), "cveGetWindowProperty", @error)

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

    Local $bWinnameDllType
    If VarGetType($winname) == "DLLStruct" Then
        $bWinnameDllType = "struct*"
    Else
        $bWinnameDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDestroyWindow", $bWinnameDllType, $winname), "cveDestroyWindow", @error)

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

    Local $bWindowNameDllType
    If VarGetType($windowName) == "DLLStruct" Then
        $bWindowNameDllType = "struct*"
    Else
        $bWindowNameDllType = "ptr"
    EndIf

    Local $bImgDllType
    If VarGetType($img) == "DLLStruct" Then
        $bImgDllType = "struct*"
    Else
        $bImgDllType = "ptr"
    EndIf

    Local $bRoiDllType
    If VarGetType($roi) == "DLLStruct" Then
        $bRoiDllType = "struct*"
    Else
        $bRoiDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSelectROI", $bWindowNameDllType, $windowName, $bImgDllType, $img, "boolean", $showCrosshair, "boolean", $fromCenter, $bRoiDllType, $roi), "cveSelectROI", @error)

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

    Local $bWindowNameDllType
    If VarGetType($windowName) == "DLLStruct" Then
        $bWindowNameDllType = "struct*"
    Else
        $bWindowNameDllType = "ptr"
    EndIf

    Local $bImgDllType
    If VarGetType($img) == "DLLStruct" Then
        $bImgDllType = "struct*"
    Else
        $bImgDllType = "ptr"
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

    Local $bBoundingBoxsDllType
    If VarGetType($boundingBoxs) == "DLLStruct" Then
        $bBoundingBoxsDllType = "struct*"
    Else
        $bBoundingBoxsDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSelectROIs", $bWindowNameDllType, $windowName, $bImgDllType, $img, $bBoundingBoxsDllType, $vecBoundingBoxs, "boolean", $showCrosshair, "boolean", $fromCenter), "cveSelectROIs", @error)

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