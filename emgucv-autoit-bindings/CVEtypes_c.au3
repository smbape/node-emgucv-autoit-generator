#include-once
#include <CVTag.au3>

;~ opencv\sources\modules\core\include\opencv2\core\types_c.h
Func _cvSize($width, $height)
	Local $cvSize = DllStructCreate($tagCvSize)
	DllStructSetData($cvSize, "width", $width)
	DllStructSetData($cvSize, "height", $height)
	Return $cvSize
EndFunc   ;==>_cvSize

Func _cvRange($start, $end)
	Local $cvRange = DllStructCreate("int start; int end")
	DllStructSetData($cvRange, "start", $start)
	DllStructSetData($cvRange, "end", $end)
	Return $cvRange
EndFunc   ;==>_cvRange

Func _cvPoint($x, $y)
	Local $cvPoint = DllStructCreate($tagCvPoint)
	DllStructSetData($cvPoint, "x", $x)
	DllStructSetData($cvPoint, "y", $y)
	Return $cvPoint
EndFunc   ;==>_cvPoint

Func _cvScalar($value)
	Local $cvScalar = DllStructCreate($tagCvScalar)

	If VarGetType($value) = "Array" Then
		DllStructSetData($cvScalar, 1, $value[0])
		DllStructSetData($cvScalar, 2, $value[1])
		DllStructSetData($cvScalar, 3, $value[2])
		DllStructSetData($cvScalar, 4, $value[3])
	Else
		DllStructSetData($cvScalar, 1, $value)
		DllStructSetData($cvScalar, 2, $value)
		DllStructSetData($cvScalar, 3, $value)
		DllStructSetData($cvScalar, 4, $value)
	EndIf

	Return $cvScalar
EndFunc   ;==>_cvScalar

Func _cvRect($x, $y, $width, $height)
	Local $cvRect = DllStructCreate($tagCvRect)
	DllStructSetData($cvRect, "x", $x)
	DllStructSetData($cvRect, "y", $y)
	DllStructSetData($cvRect, "width", $width)
	DllStructSetData($cvRect, "height", $height)
	Return $cvRect
EndFunc   ;==>_cvRect

Func _cvRGB($cvRed, $cvGreen, $cvBlue)
	Local $cvScalar = DllStructCreate($tagCvScalar)

	DllStructSetData($cvScalar, 1, $cvBlue)
	DllStructSetData($cvScalar, 2, $cvGreen)
	DllStructSetData($cvScalar, 3, $cvRed)
	DllStructSetData($cvScalar, 4, 0)

	Return $cvScalar
EndFunc   ;==>_cvRGB

Func _cvNativeType($type, $value)
	Local $tStruct = DllStructCreate($type)
	DllStructSetData($tStruct, 1, $value)
	Return $tStruct
EndFunc   ;==>_cvNativeType
