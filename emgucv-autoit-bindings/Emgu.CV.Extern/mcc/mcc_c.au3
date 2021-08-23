#include-once
#include "..\..\CVEUtils.au3"

Func _cveCCheckerCreate($sharedPtr)
    ; CVAPI(cv::mcc::CChecker*) cveCCheckerCreate(cv::Ptr<cv::mcc::CChecker>** sharedPtr);

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveCCheckerCreate", $sSharedPtrDllType, $sharedPtr), "cveCCheckerCreate", @error)
EndFunc   ;==>_cveCCheckerCreate

Func _cveCCheckerGetBox($checker, $box)
    ; CVAPI(void) cveCCheckerGetBox(cv::mcc::CChecker* checker, std::vector<cv::Point2f>* box);

    Local $sCheckerDllType
    If IsDllStruct($checker) Then
        $sCheckerDllType = "struct*"
    Else
        $sCheckerDllType = "ptr"
    EndIf

    Local $vecBox, $iArrBoxSize
    Local $bBoxIsArray = VarGetType($box) == "Array"

    If $bBoxIsArray Then
        $vecBox = _VectorOfPointFCreate()

        $iArrBoxSize = UBound($box)
        For $i = 0 To $iArrBoxSize - 1
            _VectorOfPointFPush($vecBox, $box[$i])
        Next
    Else
        $vecBox = $box
    EndIf

    Local $sBoxDllType
    If IsDllStruct($box) Then
        $sBoxDllType = "struct*"
    Else
        $sBoxDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCCheckerGetBox", $sCheckerDllType, $checker, $sBoxDllType, $vecBox), "cveCCheckerGetBox", @error)

    If $bBoxIsArray Then
        _VectorOfPointFRelease($vecBox)
    EndIf
EndFunc   ;==>_cveCCheckerGetBox

Func _cveCCheckerSetBox($checker, $box)
    ; CVAPI(void) cveCCheckerSetBox(cv::mcc::CChecker* checker, std::vector<cv::Point2f>* box);

    Local $sCheckerDllType
    If IsDllStruct($checker) Then
        $sCheckerDllType = "struct*"
    Else
        $sCheckerDllType = "ptr"
    EndIf

    Local $vecBox, $iArrBoxSize
    Local $bBoxIsArray = VarGetType($box) == "Array"

    If $bBoxIsArray Then
        $vecBox = _VectorOfPointFCreate()

        $iArrBoxSize = UBound($box)
        For $i = 0 To $iArrBoxSize - 1
            _VectorOfPointFPush($vecBox, $box[$i])
        Next
    Else
        $vecBox = $box
    EndIf

    Local $sBoxDllType
    If IsDllStruct($box) Then
        $sBoxDllType = "struct*"
    Else
        $sBoxDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCCheckerSetBox", $sCheckerDllType, $checker, $sBoxDllType, $vecBox), "cveCCheckerSetBox", @error)

    If $bBoxIsArray Then
        _VectorOfPointFRelease($vecBox)
    EndIf
EndFunc   ;==>_cveCCheckerSetBox

Func _cveCCheckerGetCenter($checker, $center)
    ; CVAPI(void) cveCCheckerGetCenter(cv::mcc::CChecker* checker, CvPoint2D32f* center);

    Local $sCheckerDllType
    If IsDllStruct($checker) Then
        $sCheckerDllType = "struct*"
    Else
        $sCheckerDllType = "ptr"
    EndIf

    Local $sCenterDllType
    If IsDllStruct($center) Then
        $sCenterDllType = "struct*"
    Else
        $sCenterDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCCheckerGetCenter", $sCheckerDllType, $checker, $sCenterDllType, $center), "cveCCheckerGetCenter", @error)
EndFunc   ;==>_cveCCheckerGetCenter

Func _cveCCheckerSetCenter($checker, $center)
    ; CVAPI(void) cveCCheckerSetCenter(cv::mcc::CChecker* checker, CvPoint2D32f* center);

    Local $sCheckerDllType
    If IsDllStruct($checker) Then
        $sCheckerDllType = "struct*"
    Else
        $sCheckerDllType = "ptr"
    EndIf

    Local $sCenterDllType
    If IsDllStruct($center) Then
        $sCenterDllType = "struct*"
    Else
        $sCenterDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCCheckerSetCenter", $sCheckerDllType, $checker, $sCenterDllType, $center), "cveCCheckerSetCenter", @error)
EndFunc   ;==>_cveCCheckerSetCenter

Func _cveCCheckerRelease($sharedPtr)
    ; CVAPI(void) cveCCheckerRelease(cv::Ptr<cv::mcc::CChecker>** sharedPtr);

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCCheckerRelease", $sSharedPtrDllType, $sharedPtr), "cveCCheckerRelease", @error)
EndFunc   ;==>_cveCCheckerRelease

Func _cveCCheckerDrawCreate($pChecker, $color, $thickness, $sharedPtr)
    ; CVAPI(cv::mcc::CCheckerDraw*) cveCCheckerDrawCreate(cv::mcc::CChecker* pChecker, CvScalar* color, int thickness, cv::Ptr<cv::mcc::CCheckerDraw>** sharedPtr);

    Local $sPCheckerDllType
    If IsDllStruct($pChecker) Then
        $sPCheckerDllType = "struct*"
    Else
        $sPCheckerDllType = "ptr"
    EndIf

    Local $sColorDllType
    If IsDllStruct($color) Then
        $sColorDllType = "struct*"
    Else
        $sColorDllType = "ptr"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveCCheckerDrawCreate", $sPCheckerDllType, $pChecker, $sColorDllType, $color, "int", $thickness, $sSharedPtrDllType, $sharedPtr), "cveCCheckerDrawCreate", @error)
EndFunc   ;==>_cveCCheckerDrawCreate

Func _cveCCheckerDrawDraw($ccheckerDraw, $img)
    ; CVAPI(void) cveCCheckerDrawDraw(cv::mcc::CCheckerDraw* ccheckerDraw, cv::_InputOutputArray* img);

    Local $sCcheckerDrawDllType
    If IsDllStruct($ccheckerDraw) Then
        $sCcheckerDrawDllType = "struct*"
    Else
        $sCcheckerDrawDllType = "ptr"
    EndIf

    Local $sImgDllType
    If IsDllStruct($img) Then
        $sImgDllType = "struct*"
    Else
        $sImgDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCCheckerDrawDraw", $sCcheckerDrawDllType, $ccheckerDraw, $sImgDllType, $img), "cveCCheckerDrawDraw", @error)
EndFunc   ;==>_cveCCheckerDrawDraw

Func _cveCCheckerDrawDrawMat($ccheckerDraw, $matImg)
    ; cveCCheckerDrawDraw using cv::Mat instead of _*Array

    Local $ioArrImg, $vectorOfMatImg, $iArrImgSize
    Local $bImgIsArray = VarGetType($matImg) == "Array"

    If $bImgIsArray Then
        $vectorOfMatImg = _VectorOfMatCreate()

        $iArrImgSize = UBound($matImg)
        For $i = 0 To $iArrImgSize - 1
            _VectorOfMatPush($vectorOfMatImg, $matImg[$i])
        Next

        $ioArrImg = _cveInputOutputArrayFromVectorOfMat($vectorOfMatImg)
    Else
        $ioArrImg = _cveInputOutputArrayFromMat($matImg)
    EndIf

    _cveCCheckerDrawDraw($ccheckerDraw, $ioArrImg)

    If $bImgIsArray Then
        _VectorOfMatRelease($vectorOfMatImg)
    EndIf

    _cveInputOutputArrayRelease($ioArrImg)
EndFunc   ;==>_cveCCheckerDrawDrawMat

Func _cveCCheckerDrawRelease($sharedPtr)
    ; CVAPI(void) cveCCheckerDrawRelease(cv::Ptr<cv::mcc::CCheckerDraw>** sharedPtr);

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCCheckerDrawRelease", $sSharedPtrDllType, $sharedPtr), "cveCCheckerDrawRelease", @error)
EndFunc   ;==>_cveCCheckerDrawRelease

Func _cveCCheckerDetectorCreate($algorithm, $sharedPtr)
    ; CVAPI(cv::mcc::CCheckerDetector*) cveCCheckerDetectorCreate(cv::Algorithm** algorithm, cv::Ptr<cv::mcc::CCheckerDetector>** sharedPtr);

    Local $sAlgorithmDllType
    If IsDllStruct($algorithm) Then
        $sAlgorithmDllType = "struct*"
    ElseIf $algorithm == Null Then
        $sAlgorithmDllType = "ptr"
    Else
        $sAlgorithmDllType = "ptr*"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveCCheckerDetectorCreate", $sAlgorithmDllType, $algorithm, $sSharedPtrDllType, $sharedPtr), "cveCCheckerDetectorCreate", @error)
EndFunc   ;==>_cveCCheckerDetectorCreate

Func _cveCCheckerDetectorProcess($detector, $image, $chartType, $nc, $useNet, $param)
    ; CVAPI(bool) cveCCheckerDetectorProcess(cv::mcc::CCheckerDetector* detector, cv::_InputArray* image, const cv::mcc::TYPECHART chartType, const int nc, bool useNet, cv::mcc::DetectorParameters* param);

    Local $sDetectorDllType
    If IsDllStruct($detector) Then
        $sDetectorDllType = "struct*"
    Else
        $sDetectorDllType = "ptr"
    EndIf

    Local $sImageDllType
    If IsDllStruct($image) Then
        $sImageDllType = "struct*"
    Else
        $sImageDllType = "ptr"
    EndIf

    Local $sParamDllType
    If IsDllStruct($param) Then
        $sParamDllType = "struct*"
    Else
        $sParamDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveCCheckerDetectorProcess", $sDetectorDllType, $detector, $sImageDllType, $image, "int", $chartType, "int", $nc, "boolean", $useNet, $sParamDllType, $param), "cveCCheckerDetectorProcess", @error)
EndFunc   ;==>_cveCCheckerDetectorProcess

Func _cveCCheckerDetectorProcessMat($detector, $matImage, $chartType, $nc, $useNet, $param)
    ; cveCCheckerDetectorProcess using cv::Mat instead of _*Array

    Local $iArrImage, $vectorOfMatImage, $iArrImageSize
    Local $bImageIsArray = VarGetType($matImage) == "Array"

    If $bImageIsArray Then
        $vectorOfMatImage = _VectorOfMatCreate()

        $iArrImageSize = UBound($matImage)
        For $i = 0 To $iArrImageSize - 1
            _VectorOfMatPush($vectorOfMatImage, $matImage[$i])
        Next

        $iArrImage = _cveInputArrayFromVectorOfMat($vectorOfMatImage)
    Else
        $iArrImage = _cveInputArrayFromMat($matImage)
    EndIf

    Local $retval = _cveCCheckerDetectorProcess($detector, $iArrImage, $chartType, $nc, $useNet, $param)

    If $bImageIsArray Then
        _VectorOfMatRelease($vectorOfMatImage)
    EndIf

    _cveInputArrayRelease($iArrImage)

    Return $retval
EndFunc   ;==>_cveCCheckerDetectorProcessMat

Func _cveCCheckerDetectorGetBestColorChecker($detector)
    ; CVAPI(cv::mcc::CChecker*) cveCCheckerDetectorGetBestColorChecker(cv::mcc::CCheckerDetector* detector);

    Local $sDetectorDllType
    If IsDllStruct($detector) Then
        $sDetectorDllType = "struct*"
    Else
        $sDetectorDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveCCheckerDetectorGetBestColorChecker", $sDetectorDllType, $detector), "cveCCheckerDetectorGetBestColorChecker", @error)
EndFunc   ;==>_cveCCheckerDetectorGetBestColorChecker

Func _cveCCheckerDetectorRelease($sharedPtr)
    ; CVAPI(void) cveCCheckerDetectorRelease(cv::Ptr<cv::mcc::CCheckerDetector>** sharedPtr);

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCCheckerDetectorRelease", $sSharedPtrDllType, $sharedPtr), "cveCCheckerDetectorRelease", @error)
EndFunc   ;==>_cveCCheckerDetectorRelease

Func _cveCCheckerDetectorParametersCreate()
    ; CVAPI(cv::mcc::DetectorParameters*) cveCCheckerDetectorParametersCreate();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveCCheckerDetectorParametersCreate"), "cveCCheckerDetectorParametersCreate", @error)
EndFunc   ;==>_cveCCheckerDetectorParametersCreate

Func _cveCCheckerDetectorParametersRelease($parameters)
    ; CVAPI(void) cveCCheckerDetectorParametersRelease(cv::mcc::DetectorParameters** parameters);

    Local $sParametersDllType
    If IsDllStruct($parameters) Then
        $sParametersDllType = "struct*"
    ElseIf $parameters == Null Then
        $sParametersDllType = "ptr"
    Else
        $sParametersDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCCheckerDetectorParametersRelease", $sParametersDllType, $parameters), "cveCCheckerDetectorParametersRelease", @error)
EndFunc   ;==>_cveCCheckerDetectorParametersRelease