#include-once
#include "CVTag.au3"

;~ opencv\sources\modules\core\include\opencv2\core\types_c.h
Func _cvSize($width = 0, $height = 0)
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

Func _cvPoint($x = 0, $y = 0)
	Local $cvPoint = DllStructCreate($tagCvPoint)
	DllStructSetData($cvPoint, "x", $x)
	DllStructSetData($cvPoint, "y", $y)
	Return $cvPoint
EndFunc   ;==>_cvPoint

Func _cvPoint2f($x = 0, $y = 0)
	Local $cvPoint2f = DllStructCreate($tagCvPoint2D32f)
	DllStructSetData($cvPoint2f, "x", $x)
	DllStructSetData($cvPoint2f, "y", $y)
	Return $cvPoint2f
EndFunc   ;==>_cvPoint2f

Func _cvPoint3f($x = 0, $y = 0, $z = 0)
	Local $cvPoint3f = DllStructCreate($tagCvPoint3D32f)
	DllStructSetData($cvPoint3f, "x", $x)
	DllStructSetData($cvPoint3f, "y", $y)
	DllStructSetData($cvPoint3f, "z", $z)
	Return $cvPoint3f
EndFunc   ;==>_cvPoint3f

Func _cvScalar($v0 = 0, $v1 = 0, $v2 = 0, $v3 = 0)
	Local $cvScalar = DllStructCreate($tagCvScalar)
	DllStructSetData($cvScalar, 1, $v0)
	DllStructSetData($cvScalar, 2, $v1)
	DllStructSetData($cvScalar, 3, $v2)
	DllStructSetData($cvScalar, 4, $v3)
	Return $cvScalar
EndFunc   ;==>_cvScalar

Func _cvScalarAll($v0)
	Return _cvScalar($v0, $v0, $v0, $v0)
EndFunc   ;==>_cvScalarAll

Func _cvRect($x = 0, $y = 0, $width = 0, $height = 0)
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
	DllStructSetData($cvScalar, 4, 0xFF)

	Return $cvScalar
EndFunc   ;==>_cvRGB

Func _cvNativeType($type, $value)
	Local $tStruct = DllStructCreate($type)
	DllStructSetData($tStruct, 1, $value)
	Return $tStruct
EndFunc   ;==>_cvNativeType

Func _cvTermCriteria($type, $max_iter, $epsilon)
	Local $tStruct = DllStructCreate($tagCvTermCriteria)
	DllStructSetData($tStruct, "type", $type)
	DllStructSetData($tStruct, "max_iter", $max_iter)
	DllStructSetData($tStruct, "epsilon", $epsilon)
	Return $tStruct
EndFunc   ;==>_cvTermCriteria
