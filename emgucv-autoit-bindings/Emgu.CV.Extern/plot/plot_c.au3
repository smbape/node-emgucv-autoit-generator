#include-once
#include "..\..\CVEUtils.au3"

Func _cvePlot2dCreateFrom($data, $sharedPtr)
    ; CVAPI(cv::plot::Plot2d*) cvePlot2dCreateFrom(cv::_InputArray* data, cv::Ptr<cv::plot::Plot2d>** sharedPtr);

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cvePlot2dCreateFrom", "ptr", $data, $bSharedPtrDllType, $sharedPtr), "cvePlot2dCreateFrom", @error)
EndFunc   ;==>_cvePlot2dCreateFrom

Func _cvePlot2dCreateFromMat($matData, $sharedPtr)
    ; cvePlot2dCreateFrom using cv::Mat instead of _*Array

    Local $iArrData, $vectorOfMatData, $iArrDataSize
    Local $bDataIsArray = VarGetType($matData) == "Array"

    If $bDataIsArray Then
        $vectorOfMatData = _VectorOfMatCreate()

        $iArrDataSize = UBound($matData)
        For $i = 0 To $iArrDataSize - 1
            _VectorOfMatPush($vectorOfMatData, $matData[$i])
        Next

        $iArrData = _cveInputArrayFromVectorOfMat($vectorOfMatData)
    Else
        $iArrData = _cveInputArrayFromMat($matData)
    EndIf

    Local $retval = _cvePlot2dCreateFrom($iArrData, $sharedPtr)

    If $bDataIsArray Then
        _VectorOfMatRelease($vectorOfMatData)
    EndIf

    _cveInputArrayRelease($iArrData)

    Return $retval
EndFunc   ;==>_cvePlot2dCreateFromMat

Func _cvePlot2dCreateFromXY($dataX, $dataY, $sharedPtr)
    ; CVAPI(cv::plot::Plot2d*) cvePlot2dCreateFromXY(cv::_InputArray* dataX, cv::_InputArray* dataY, cv::Ptr<cv::plot::Plot2d>** sharedPtr);

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cvePlot2dCreateFromXY", "ptr", $dataX, "ptr", $dataY, $bSharedPtrDllType, $sharedPtr), "cvePlot2dCreateFromXY", @error)
EndFunc   ;==>_cvePlot2dCreateFromXY

Func _cvePlot2dCreateFromXYMat($matDataX, $matDataY, $sharedPtr)
    ; cvePlot2dCreateFromXY using cv::Mat instead of _*Array

    Local $iArrDataX, $vectorOfMatDataX, $iArrDataXSize
    Local $bDataXIsArray = VarGetType($matDataX) == "Array"

    If $bDataXIsArray Then
        $vectorOfMatDataX = _VectorOfMatCreate()

        $iArrDataXSize = UBound($matDataX)
        For $i = 0 To $iArrDataXSize - 1
            _VectorOfMatPush($vectorOfMatDataX, $matDataX[$i])
        Next

        $iArrDataX = _cveInputArrayFromVectorOfMat($vectorOfMatDataX)
    Else
        $iArrDataX = _cveInputArrayFromMat($matDataX)
    EndIf

    Local $iArrDataY, $vectorOfMatDataY, $iArrDataYSize
    Local $bDataYIsArray = VarGetType($matDataY) == "Array"

    If $bDataYIsArray Then
        $vectorOfMatDataY = _VectorOfMatCreate()

        $iArrDataYSize = UBound($matDataY)
        For $i = 0 To $iArrDataYSize - 1
            _VectorOfMatPush($vectorOfMatDataY, $matDataY[$i])
        Next

        $iArrDataY = _cveInputArrayFromVectorOfMat($vectorOfMatDataY)
    Else
        $iArrDataY = _cveInputArrayFromMat($matDataY)
    EndIf

    Local $retval = _cvePlot2dCreateFromXY($iArrDataX, $iArrDataY, $sharedPtr)

    If $bDataYIsArray Then
        _VectorOfMatRelease($vectorOfMatDataY)
    EndIf

    _cveInputArrayRelease($iArrDataY)

    If $bDataXIsArray Then
        _VectorOfMatRelease($vectorOfMatDataX)
    EndIf

    _cveInputArrayRelease($iArrDataX)

    Return $retval
EndFunc   ;==>_cvePlot2dCreateFromXYMat

Func _cvePlot2dRender($plot, $result)
    ; CVAPI(void) cvePlot2dRender(cv::plot::Plot2d* plot, cv::_OutputArray* result);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cvePlot2dRender", "ptr", $plot, "ptr", $result), "cvePlot2dRender", @error)
EndFunc   ;==>_cvePlot2dRender

Func _cvePlot2dRenderMat($plot, $matResult)
    ; cvePlot2dRender using cv::Mat instead of _*Array

    Local $oArrResult, $vectorOfMatResult, $iArrResultSize
    Local $bResultIsArray = VarGetType($matResult) == "Array"

    If $bResultIsArray Then
        $vectorOfMatResult = _VectorOfMatCreate()

        $iArrResultSize = UBound($matResult)
        For $i = 0 To $iArrResultSize - 1
            _VectorOfMatPush($vectorOfMatResult, $matResult[$i])
        Next

        $oArrResult = _cveOutputArrayFromVectorOfMat($vectorOfMatResult)
    Else
        $oArrResult = _cveOutputArrayFromMat($matResult)
    EndIf

    _cvePlot2dRender($plot, $oArrResult)

    If $bResultIsArray Then
        _VectorOfMatRelease($vectorOfMatResult)
    EndIf

    _cveOutputArrayRelease($oArrResult)
EndFunc   ;==>_cvePlot2dRenderMat

Func _cvePlot2dRelease($plot, $sharedPtr)
    ; CVAPI(void) cvePlot2dRelease(cv::plot::Plot2d** plot, cv::Ptr<cv::plot::Plot2d>** sharedPtr);

    Local $bPlotDllType
    If VarGetType($plot) == "DLLStruct" Then
        $bPlotDllType = "struct*"
    Else
        $bPlotDllType = "ptr*"
    EndIf

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cvePlot2dRelease", $bPlotDllType, $plot, $bSharedPtrDllType, $sharedPtr), "cvePlot2dRelease", @error)
EndFunc   ;==>_cvePlot2dRelease

Func _cvePlot2dSetPlotLineColor($plot, $plotLineColor)
    ; CVAPI(void) cvePlot2dSetPlotLineColor(cv::plot::Plot2d* plot, CvScalar* plotLineColor);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cvePlot2dSetPlotLineColor", "ptr", $plot, "struct*", $plotLineColor), "cvePlot2dSetPlotLineColor", @error)
EndFunc   ;==>_cvePlot2dSetPlotLineColor

Func _cvePlot2dSetPlotBackgroundColor($plot, $plotBackgroundColor)
    ; CVAPI(void) cvePlot2dSetPlotBackgroundColor(cv::plot::Plot2d* plot, CvScalar* plotBackgroundColor);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cvePlot2dSetPlotBackgroundColor", "ptr", $plot, "struct*", $plotBackgroundColor), "cvePlot2dSetPlotBackgroundColor", @error)
EndFunc   ;==>_cvePlot2dSetPlotBackgroundColor

Func _cvePlot2dSetPlotAxisColor($plot, $plotAxisColor)
    ; CVAPI(void) cvePlot2dSetPlotAxisColor(cv::plot::Plot2d* plot, CvScalar* plotAxisColor);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cvePlot2dSetPlotAxisColor", "ptr", $plot, "struct*", $plotAxisColor), "cvePlot2dSetPlotAxisColor", @error)
EndFunc   ;==>_cvePlot2dSetPlotAxisColor

Func _cvePlot2dSetPlotGridColor($plot, $plotGridColor)
    ; CVAPI(void) cvePlot2dSetPlotGridColor(cv::plot::Plot2d* plot, CvScalar* plotGridColor);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cvePlot2dSetPlotGridColor", "ptr", $plot, "struct*", $plotGridColor), "cvePlot2dSetPlotGridColor", @error)
EndFunc   ;==>_cvePlot2dSetPlotGridColor

Func _cvePlot2dSetPlotTextColor($plot, $plotTextColor)
    ; CVAPI(void) cvePlot2dSetPlotTextColor(cv::plot::Plot2d* plot, CvScalar* plotTextColor);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cvePlot2dSetPlotTextColor", "ptr", $plot, "struct*", $plotTextColor), "cvePlot2dSetPlotTextColor", @error)
EndFunc   ;==>_cvePlot2dSetPlotTextColor

Func _cvePlot2dSetPlotSize($plot, $plotSizeWidth, $plotSizeHeight)
    ; CVAPI(void) cvePlot2dSetPlotSize(cv::plot::Plot2d* plot, int plotSizeWidth, int plotSizeHeight);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cvePlot2dSetPlotSize", "ptr", $plot, "int", $plotSizeWidth, "int", $plotSizeHeight), "cvePlot2dSetPlotSize", @error)
EndFunc   ;==>_cvePlot2dSetPlotSize