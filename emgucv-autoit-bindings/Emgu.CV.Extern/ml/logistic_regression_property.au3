#include-once
#include "..\..\CVEUtils.au3"

Func _cveLogisticRegressionGetLearningRate($obj)
    ; CVAPI(double) cveLogisticRegressionGetLearningRate(cv::ml::LogisticRegression* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveLogisticRegressionGetLearningRate", $bObjDllType, $obj), "cveLogisticRegressionGetLearningRate", @error)
EndFunc   ;==>_cveLogisticRegressionGetLearningRate

Func _cveLogisticRegressionSetLearningRate($obj, $value)
    ; CVAPI(void) cveLogisticRegressionSetLearningRate(cv::ml::LogisticRegression* obj, double value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveLogisticRegressionSetLearningRate", $bObjDllType, $obj, "double", $value), "cveLogisticRegressionSetLearningRate", @error)
EndFunc   ;==>_cveLogisticRegressionSetLearningRate

Func _cveLogisticRegressionGetIterations($obj)
    ; CVAPI(int) cveLogisticRegressionGetIterations(cv::ml::LogisticRegression* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveLogisticRegressionGetIterations", $bObjDllType, $obj), "cveLogisticRegressionGetIterations", @error)
EndFunc   ;==>_cveLogisticRegressionGetIterations

Func _cveLogisticRegressionSetIterations($obj, $value)
    ; CVAPI(void) cveLogisticRegressionSetIterations(cv::ml::LogisticRegression* obj, int value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveLogisticRegressionSetIterations", $bObjDllType, $obj, "int", $value), "cveLogisticRegressionSetIterations", @error)
EndFunc   ;==>_cveLogisticRegressionSetIterations

Func _cveLogisticRegressionGetRegularization($obj)
    ; CVAPI(int) cveLogisticRegressionGetRegularization(cv::ml::LogisticRegression* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveLogisticRegressionGetRegularization", $bObjDllType, $obj), "cveLogisticRegressionGetRegularization", @error)
EndFunc   ;==>_cveLogisticRegressionGetRegularization

Func _cveLogisticRegressionSetRegularization($obj, $value)
    ; CVAPI(void) cveLogisticRegressionSetRegularization(cv::ml::LogisticRegression* obj, int value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveLogisticRegressionSetRegularization", $bObjDllType, $obj, "int", $value), "cveLogisticRegressionSetRegularization", @error)
EndFunc   ;==>_cveLogisticRegressionSetRegularization

Func _cveLogisticRegressionGetTrainMethod($obj)
    ; CVAPI(int) cveLogisticRegressionGetTrainMethod(cv::ml::LogisticRegression* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveLogisticRegressionGetTrainMethod", $bObjDllType, $obj), "cveLogisticRegressionGetTrainMethod", @error)
EndFunc   ;==>_cveLogisticRegressionGetTrainMethod

Func _cveLogisticRegressionSetTrainMethod($obj, $value)
    ; CVAPI(void) cveLogisticRegressionSetTrainMethod(cv::ml::LogisticRegression* obj, int value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveLogisticRegressionSetTrainMethod", $bObjDllType, $obj, "int", $value), "cveLogisticRegressionSetTrainMethod", @error)
EndFunc   ;==>_cveLogisticRegressionSetTrainMethod

Func _cveLogisticRegressionGetMiniBatchSize($obj)
    ; CVAPI(int) cveLogisticRegressionGetMiniBatchSize(cv::ml::LogisticRegression* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveLogisticRegressionGetMiniBatchSize", $bObjDllType, $obj), "cveLogisticRegressionGetMiniBatchSize", @error)
EndFunc   ;==>_cveLogisticRegressionGetMiniBatchSize

Func _cveLogisticRegressionSetMiniBatchSize($obj, $value)
    ; CVAPI(void) cveLogisticRegressionSetMiniBatchSize(cv::ml::LogisticRegression* obj, int value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveLogisticRegressionSetMiniBatchSize", $bObjDllType, $obj, "int", $value), "cveLogisticRegressionSetMiniBatchSize", @error)
EndFunc   ;==>_cveLogisticRegressionSetMiniBatchSize

Func _cveLogisticRegressionGetTermCriteria($obj, $value)
    ; CVAPI(void) cveLogisticRegressionGetTermCriteria(cv::ml::LogisticRegression* obj, CvTermCriteria* value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    Local $bValueDllType
    If VarGetType($value) == "DLLStruct" Then
        $bValueDllType = "struct*"
    Else
        $bValueDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveLogisticRegressionGetTermCriteria", $bObjDllType, $obj, $bValueDllType, $value), "cveLogisticRegressionGetTermCriteria", @error)
EndFunc   ;==>_cveLogisticRegressionGetTermCriteria

Func _cveLogisticRegressionSetTermCriteria($obj, $value)
    ; CVAPI(void) cveLogisticRegressionSetTermCriteria(cv::ml::LogisticRegression* obj, CvTermCriteria* value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    Local $bValueDllType
    If VarGetType($value) == "DLLStruct" Then
        $bValueDllType = "struct*"
    Else
        $bValueDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveLogisticRegressionSetTermCriteria", $bObjDllType, $obj, $bValueDllType, $value), "cveLogisticRegressionSetTermCriteria", @error)
EndFunc   ;==>_cveLogisticRegressionSetTermCriteria