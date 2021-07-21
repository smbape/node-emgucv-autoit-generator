#include-once
#include "..\..\CVEUtils.au3"

Func _cveCCheckerCreate($sharedPtr)
    ; CVAPI(cv::mcc::CChecker*) cveCCheckerCreate(cv::Ptr<cv::mcc::CChecker>** sharedPtr);

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveCCheckerCreate", $bSharedPtrDllType, $sharedPtr), "cveCCheckerCreate", @error)
EndFunc   ;==>_cveCCheckerCreate

Func _cveCCheckerGetBox($checker, $box)
    ; CVAPI(void) cveCCheckerGetBox(cv::mcc::CChecker* checker, std::vector< cv::Point2f >* box);

    Local $bCheckerDllType
    If VarGetType($checker) == "DLLStruct" Then
        $bCheckerDllType = "struct*"
    Else
        $bCheckerDllType = "ptr"
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

    Local $bBoxDllType
    If VarGetType($box) == "DLLStruct" Then
        $bBoxDllType = "struct*"
    Else
        $bBoxDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCCheckerGetBox", $bCheckerDllType, $checker, $bBoxDllType, $vecBox), "cveCCheckerGetBox", @error)

    If $bBoxIsArray Then
        _VectorOfPointFRelease($vecBox)
    EndIf
EndFunc   ;==>_cveCCheckerGetBox

Func _cveCCheckerSetBox($checker, $box)
    ; CVAPI(void) cveCCheckerSetBox(cv::mcc::CChecker* checker, std::vector< cv::Point2f >* box);

    Local $bCheckerDllType
    If VarGetType($checker) == "DLLStruct" Then
        $bCheckerDllType = "struct*"
    Else
        $bCheckerDllType = "ptr"
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

    Local $bBoxDllType
    If VarGetType($box) == "DLLStruct" Then
        $bBoxDllType = "struct*"
    Else
        $bBoxDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCCheckerSetBox", $bCheckerDllType, $checker, $bBoxDllType, $vecBox), "cveCCheckerSetBox", @error)

    If $bBoxIsArray Then
        _VectorOfPointFRelease($vecBox)
    EndIf
EndFunc   ;==>_cveCCheckerSetBox

Func _cveCCheckerGetCenter($checker, $center)
    ; CVAPI(void) cveCCheckerGetCenter(cv::mcc::CChecker* checker, CvPoint2D32f* center);

    Local $bCheckerDllType
    If VarGetType($checker) == "DLLStruct" Then
        $bCheckerDllType = "struct*"
    Else
        $bCheckerDllType = "ptr"
    EndIf

    Local $bCenterDllType
    If VarGetType($center) == "DLLStruct" Then
        $bCenterDllType = "struct*"
    Else
        $bCenterDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCCheckerGetCenter", $bCheckerDllType, $checker, $bCenterDllType, $center), "cveCCheckerGetCenter", @error)
EndFunc   ;==>_cveCCheckerGetCenter

Func _cveCCheckerSetCenter($checker, $center)
    ; CVAPI(void) cveCCheckerSetCenter(cv::mcc::CChecker* checker, CvPoint2D32f* center);

    Local $bCheckerDllType
    If VarGetType($checker) == "DLLStruct" Then
        $bCheckerDllType = "struct*"
    Else
        $bCheckerDllType = "ptr"
    EndIf

    Local $bCenterDllType
    If VarGetType($center) == "DLLStruct" Then
        $bCenterDllType = "struct*"
    Else
        $bCenterDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCCheckerSetCenter", $bCheckerDllType, $checker, $bCenterDllType, $center), "cveCCheckerSetCenter", @error)
EndFunc   ;==>_cveCCheckerSetCenter

Func _cveCCheckerRelease($sharedPtr)
    ; CVAPI(void) cveCCheckerRelease(cv::Ptr<cv::mcc::CChecker>** sharedPtr);

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCCheckerRelease", $bSharedPtrDllType, $sharedPtr), "cveCCheckerRelease", @error)
EndFunc   ;==>_cveCCheckerRelease

Func _cveCCheckerDrawCreate($pChecker, $color, $thickness, $sharedPtr)
    ; CVAPI(cv::mcc::CCheckerDraw*) cveCCheckerDrawCreate(cv::mcc::CChecker* pChecker, CvScalar* color, int thickness, cv::Ptr<cv::mcc::CCheckerDraw>** sharedPtr);

    Local $bPCheckerDllType
    If VarGetType($pChecker) == "DLLStruct" Then
        $bPCheckerDllType = "struct*"
    Else
        $bPCheckerDllType = "ptr"
    EndIf

    Local $bColorDllType
    If VarGetType($color) == "DLLStruct" Then
        $bColorDllType = "struct*"
    Else
        $bColorDllType = "ptr"
    EndIf

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveCCheckerDrawCreate", $bPCheckerDllType, $pChecker, $bColorDllType, $color, "int", $thickness, $bSharedPtrDllType, $sharedPtr), "cveCCheckerDrawCreate", @error)
EndFunc   ;==>_cveCCheckerDrawCreate

Func _cveCCheckerDrawDraw($ccheckerDraw, $img)
    ; CVAPI(void) cveCCheckerDrawDraw(cv::mcc::CCheckerDraw* ccheckerDraw, cv::_InputOutputArray* img);

    Local $bCcheckerDrawDllType
    If VarGetType($ccheckerDraw) == "DLLStruct" Then
        $bCcheckerDrawDllType = "struct*"
    Else
        $bCcheckerDrawDllType = "ptr"
    EndIf

    Local $bImgDllType
    If VarGetType($img) == "DLLStruct" Then
        $bImgDllType = "struct*"
    Else
        $bImgDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCCheckerDrawDraw", $bCcheckerDrawDllType, $ccheckerDraw, $bImgDllType, $img), "cveCCheckerDrawDraw", @error)
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

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCCheckerDrawRelease", $bSharedPtrDllType, $sharedPtr), "cveCCheckerDrawRelease", @error)
EndFunc   ;==>_cveCCheckerDrawRelease

Func _cveCCheckerDetectorCreate($algorithm, $sharedPtr)
    ; CVAPI(cv::mcc::CCheckerDetector*) cveCCheckerDetectorCreate(cv::Algorithm** algorithm, cv::Ptr<cv::mcc::CCheckerDetector>** sharedPtr);

    Local $bAlgorithmDllType
    If VarGetType($algorithm) == "DLLStruct" Then
        $bAlgorithmDllType = "struct*"
    Else
        $bAlgorithmDllType = "ptr*"
    EndIf

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveCCheckerDetectorCreate", $bAlgorithmDllType, $algorithm, $bSharedPtrDllType, $sharedPtr), "cveCCheckerDetectorCreate", @error)
EndFunc   ;==>_cveCCheckerDetectorCreate

Func _cveCCheckerDetectorProcess($detector, $image, $chartType, $nc, $useNet, $param)
    ; CVAPI(bool) cveCCheckerDetectorProcess(cv::mcc::CCheckerDetector* detector, cv::_InputArray* image, const cv::mcc::TYPECHART chartType, const int nc, bool useNet, cv::mcc::DetectorParameters* param);

    Local $bDetectorDllType
    If VarGetType($detector) == "DLLStruct" Then
        $bDetectorDllType = "struct*"
    Else
        $bDetectorDllType = "ptr"
    EndIf

    Local $bImageDllType
    If VarGetType($image) == "DLLStruct" Then
        $bImageDllType = "struct*"
    Else
        $bImageDllType = "ptr"
    EndIf

    Local $bParamDllType
    If VarGetType($param) == "DLLStruct" Then
        $bParamDllType = "struct*"
    Else
        $bParamDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveCCheckerDetectorProcess", $bDetectorDllType, $detector, $bImageDllType, $image, "cv::mcc::TYPECHART", $chartType, "int", $nc, "boolean", $useNet, $bParamDllType, $param), "cveCCheckerDetectorProcess", @error)
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

    Local $bDetectorDllType
    If VarGetType($detector) == "DLLStruct" Then
        $bDetectorDllType = "struct*"
    Else
        $bDetectorDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveCCheckerDetectorGetBestColorChecker", $bDetectorDllType, $detector), "cveCCheckerDetectorGetBestColorChecker", @error)
EndFunc   ;==>_cveCCheckerDetectorGetBestColorChecker

Func _cveCCheckerDetectorRelease($sharedPtr)
    ; CVAPI(void) cveCCheckerDetectorRelease(cv::Ptr<cv::mcc::CCheckerDetector>** sharedPtr);

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCCheckerDetectorRelease", $bSharedPtrDllType, $sharedPtr), "cveCCheckerDetectorRelease", @error)
EndFunc   ;==>_cveCCheckerDetectorRelease

Func _cveCCheckerDetectorParametersCreate()
    ; CVAPI(cv::mcc::DetectorParameters*) cveCCheckerDetectorParametersCreate();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveCCheckerDetectorParametersCreate"), "cveCCheckerDetectorParametersCreate", @error)
EndFunc   ;==>_cveCCheckerDetectorParametersCreate

Func _cveCCheckerDetectorParametersRelease($parameters)
    ; CVAPI(void) cveCCheckerDetectorParametersRelease(cv::mcc::DetectorParameters** parameters);

    Local $bParametersDllType
    If VarGetType($parameters) == "DLLStruct" Then
        $bParametersDllType = "struct*"
    Else
        $bParametersDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCCheckerDetectorParametersRelease", $bParametersDllType, $parameters), "cveCCheckerDetectorParametersRelease", @error)
EndFunc   ;==>_cveCCheckerDetectorParametersRelease