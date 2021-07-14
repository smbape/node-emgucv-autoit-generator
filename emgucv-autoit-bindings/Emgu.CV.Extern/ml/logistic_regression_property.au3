#include-once
#include "..\..\CVEUtils.au3"

Func _cveLogisticRegressionGetLearningRate(ByRef $obj)
    ; CVAPI(double) cveLogisticRegressionGetLearningRate(cv::ml::LogisticRegression* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveLogisticRegressionGetLearningRate", "ptr", $obj), "cveLogisticRegressionGetLearningRate", @error)
EndFunc   ;==>_cveLogisticRegressionGetLearningRate

Func _cveLogisticRegressionSetLearningRate(ByRef $obj, $value)
    ; CVAPI(void) cveLogisticRegressionSetLearningRate(cv::ml::LogisticRegression* obj, double value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveLogisticRegressionSetLearningRate", "ptr", $obj, "double", $value), "cveLogisticRegressionSetLearningRate", @error)
EndFunc   ;==>_cveLogisticRegressionSetLearningRate

Func _cveLogisticRegressionGetIterations(ByRef $obj)
    ; CVAPI(int) cveLogisticRegressionGetIterations(cv::ml::LogisticRegression* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveLogisticRegressionGetIterations", "ptr", $obj), "cveLogisticRegressionGetIterations", @error)
EndFunc   ;==>_cveLogisticRegressionGetIterations

Func _cveLogisticRegressionSetIterations(ByRef $obj, $value)
    ; CVAPI(void) cveLogisticRegressionSetIterations(cv::ml::LogisticRegression* obj, int value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveLogisticRegressionSetIterations", "ptr", $obj, "int", $value), "cveLogisticRegressionSetIterations", @error)
EndFunc   ;==>_cveLogisticRegressionSetIterations

Func _cveLogisticRegressionGetRegularization(ByRef $obj)
    ; CVAPI(int) cveLogisticRegressionGetRegularization(cv::ml::LogisticRegression* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveLogisticRegressionGetRegularization", "ptr", $obj), "cveLogisticRegressionGetRegularization", @error)
EndFunc   ;==>_cveLogisticRegressionGetRegularization

Func _cveLogisticRegressionSetRegularization(ByRef $obj, $value)
    ; CVAPI(void) cveLogisticRegressionSetRegularization(cv::ml::LogisticRegression* obj, int value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveLogisticRegressionSetRegularization", "ptr", $obj, "int", $value), "cveLogisticRegressionSetRegularization", @error)
EndFunc   ;==>_cveLogisticRegressionSetRegularization

Func _cveLogisticRegressionGetTrainMethod(ByRef $obj)
    ; CVAPI(int) cveLogisticRegressionGetTrainMethod(cv::ml::LogisticRegression* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveLogisticRegressionGetTrainMethod", "ptr", $obj), "cveLogisticRegressionGetTrainMethod", @error)
EndFunc   ;==>_cveLogisticRegressionGetTrainMethod

Func _cveLogisticRegressionSetTrainMethod(ByRef $obj, $value)
    ; CVAPI(void) cveLogisticRegressionSetTrainMethod(cv::ml::LogisticRegression* obj, int value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveLogisticRegressionSetTrainMethod", "ptr", $obj, "int", $value), "cveLogisticRegressionSetTrainMethod", @error)
EndFunc   ;==>_cveLogisticRegressionSetTrainMethod

Func _cveLogisticRegressionGetMiniBatchSize(ByRef $obj)
    ; CVAPI(int) cveLogisticRegressionGetMiniBatchSize(cv::ml::LogisticRegression* obj);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveLogisticRegressionGetMiniBatchSize", "ptr", $obj), "cveLogisticRegressionGetMiniBatchSize", @error)
EndFunc   ;==>_cveLogisticRegressionGetMiniBatchSize

Func _cveLogisticRegressionSetMiniBatchSize(ByRef $obj, $value)
    ; CVAPI(void) cveLogisticRegressionSetMiniBatchSize(cv::ml::LogisticRegression* obj, int value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveLogisticRegressionSetMiniBatchSize", "ptr", $obj, "int", $value), "cveLogisticRegressionSetMiniBatchSize", @error)
EndFunc   ;==>_cveLogisticRegressionSetMiniBatchSize

Func _cveLogisticRegressionGetTermCriteria(ByRef $obj, ByRef $value)
    ; CVAPI(void) cveLogisticRegressionGetTermCriteria(cv::ml::LogisticRegression* obj, CvTermCriteria* value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveLogisticRegressionGetTermCriteria", "ptr", $obj, "struct*", $value), "cveLogisticRegressionGetTermCriteria", @error)
EndFunc   ;==>_cveLogisticRegressionGetTermCriteria

Func _cveLogisticRegressionSetTermCriteria(ByRef $obj, ByRef $value)
    ; CVAPI(void) cveLogisticRegressionSetTermCriteria(cv::ml::LogisticRegression* obj, CvTermCriteria* value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveLogisticRegressionSetTermCriteria", "ptr", $obj, "struct*", $value), "cveLogisticRegressionSetTermCriteria", @error)
EndFunc   ;==>_cveLogisticRegressionSetTermCriteria