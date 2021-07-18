#include-once

#Region C:\Program Files (x86)\Windows Kits\10\Include\10.0.18362.0\ucrt\float.h
;;-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
;;
;; Constants
;;
;;-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
Global Const $CV_DBL_DECIMAL_DIG =  17                      ;; # of decimal digits of rounding precision
Global Const $CV_DBL_DIG =          15                      ;; # of decimal digits of precision
Global Const $CV_DBL_EPSILON =      2.2204460492503131e-016 ;; smallest such that 1.0+DBL_EPSILON != 1.0
Global Const $CV_DBL_HAS_SUBNORM =  1                       ;; type does support subnormal numbers
Global Const $CV_DBL_MANT_DIG =     53                      ;; # of bits in mantissa
Global Const $CV_DBL_MAX =          1.7976931348623158e+308 ;; max value
Global Const $CV_DBL_MAX_10_EXP =   308                     ;; max decimal exponent
Global Const $CV_DBL_MAX_EXP =      1024                    ;; max binary exponent
Global Const $CV_DBL_MIN =          2.2250738585072014e-308 ;; min positive value
Global Const $CV_DBL_MIN_10_EXP =   (-307)                  ;; min decimal exponent
Global Const $CV_DBL_MIN_EXP =      (-1021)                 ;; min binary exponent
Global Const $CV__DBL_RADIX =       2                       ;; exponent radix
Global Const $CV_DBL_TRUE_MIN =     4.9406564584124654e-324 ;; min positive value

Global Const $CV_FLT_DECIMAL_DIG =  9                       ;; # of decimal digits of rounding precision
Global Const $CV_FLT_DIG =          6                       ;; # of decimal digits of precision
Global Const $CV_FLT_EPSILON =      1.192092896e-07         ;; smallest such that 1.0+FLT_EPSILON != 1.0
Global Const $CV_FLT_HAS_SUBNORM =  1                       ;; type does support subnormal numbers
Global Const $CV_FLT_GUARD =        0
Global Const $CV_FLT_MANT_DIG =     24                      ;; # of bits in mantissa
Global Const $CV_FLT_MAX =          3.402823466e+38         ;; max value
Global Const $CV_FLT_MAX_10_EXP =   38                      ;; max decimal exponent
Global Const $CV_FLT_MAX_EXP =      128                     ;; max binary exponent
Global Const $CV_FLT_MIN =          1.175494351e-38         ;; min normalized positive value
Global Const $CV_FLT_MIN_10_EXP =   (-37)                   ;; min decimal exponent
Global Const $CV_FLT_MIN_EXP =      (-125)                  ;; min binary exponent
Global Const $CV_FLT_NORMALIZE =    0
Global Const $CV_FLT_RADIX =        2                       ;; exponent radix
Global Const $CV_FLT_TRUE_MIN =     1.401298464e-45         ;; min positive value

Global Const $CV_LDBL_DIG =         $CV_DBL_DIG                 ;; # of decimal digits of precision
Global Const $CV_LDBL_EPSILON =     $CV_DBL_EPSILON             ;; smallest such that 1.0+LDBL_EPSILON != 1.0
Global Const $CV_LDBL_HAS_SUBNORM = $CV_DBL_HAS_SUBNORM         ;; type does support subnormal numbers
Global Const $CV_LDBL_MANT_DIG =    $CV_DBL_MANT_DIG            ;; # of bits in mantissa
Global Const $CV_LDBL_MAX =         $CV_DBL_MAX                 ;; max value
Global Const $CV_LDBL_MAX_10_EXP =  $CV_DBL_MAX_10_EXP          ;; max decimal exponent
Global Const $CV_LDBL_MAX_EXP =     $CV_DBL_MAX_EXP             ;; max binary exponent
Global Const $CV_LDBL_MIN =         $CV_DBL_MIN                 ;; min normalized positive value
Global Const $CV_LDBL_MIN_10_EXP =  $CV_DBL_MIN_10_EXP          ;; min decimal exponent
Global Const $CV_LDBL_MIN_EXP =     $CV_DBL_MIN_EXP             ;; min binary exponent
Global Const $CV__LDBL_RADIX =      $CV__DBL_RADIX              ;; exponent radix
Global Const $CV_LDBL_TRUE_MIN =    $CV_DBL_TRUE_MIN            ;; min positive value

Global Const $CV_DECIMAL_DIG =      $CV_DBL_DECIMAL_DIG
#EndRegion C:\Program Files (x86)\Windows Kits\10\Include\10.0.18362.0\ucrt\float.h

#Region C:\Program Files (x86)\Microsoft Visual Studio\2019\Enterprise\VC\Tools\MSVC\14.23.28105\include\limits.h
Global Const $CV_MB_LEN_MAX =    5             ;; max. # bytes in multibyte char
Global Const $CV_SHRT_MIN =    (-32768)        ;; minimum (signed) short value
Global Const $CV_SHRT_MAX =      32767         ;; maximum (signed) short value
Global Const $CV_USHRT_MAX =     0xffff        ;; maximum unsigned short value
Global Const $CV_INT_MIN =     (-2147483647 - 1) ;; minimum (signed) int value
Global Const $CV_INT_MAX =       2147483647    ;; maximum (signed) int value
Global Const $CV_UINT_MAX =      0xffffffff    ;; maximum unsigned int value
Global Const $CV_LONG_MIN =    (-2147483647 - 1) ;; minimum (signed) long value
Global Const $CV_LONG_MAX =      2147483647    ;; maximum (signed) long value
Global Const $CV_ULONG_MAX =     0xffffffff    ;; maximum unsigned long value
Global Const $CV_LLONG_MAX =     9223372036854775807       ;; maximum signed long long int value
Global Const $CV_LLONG_MIN =   (-9223372036854775807 - 1)  ;; minimum signed long long int value
Global Const $CV_ULLONG_MAX =    0xffffffffffffffff        ;; maximum unsigned long long int value
#EndRegion C:\Program Files (x86)\Microsoft Visual Studio\2019\Enterprise\VC\Tools\MSVC\14.23.28105\include\limits.h
