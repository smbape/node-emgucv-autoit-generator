const fs = require("fs");
const sysPath = require("path");
const {explore} = require("fs-explorer");
const eachOfLimit = require("async/eachOfLimit");
const waterfall = require("async/waterfall");
const mkdirp = require("mkdirp");
const eol = require("eol");

const ExportsParser = require("./ExportsParser");
const EnumParser = require("./EnumParser");
const { convertToAutoIt } = require("./autoit-converter");

const normalizeVectType = type => {
    return type.replace(/^const /, "").replace(/ *< */g, "<").replace(/ *> */g, ">");
};

const {hasOwnProperty: hasProp} = Object.prototype;

const convertFile = (localFile, remoteFile, remotePath, remoteBaseDir, remoteSep, parser, options, cb) => {
    const remoteFileDir = sysPath.dirname(remoteFile);

    waterfall([
        next => {
            fs.readFile(localFile, next);
        },

        (buffer, next) => {
            const api = parser.parseFile(buffer);

            if (parser.lastError) {
                console.log("reading", localFile, "error");
                next(parser.lastError);
                return;
            }

            mkdirp(remoteFileDir).then(next.bind(null, null, api), next);
        },

        (api, performed, next) => {
            const header = `
                #include-once
                #include "${ sysPath.relative(remoteFileDir, remoteBaseDir) }\\CVEUtils.au3"
            `.replace(/^ +/mg, "").trim();

            const body = convertToAutoIt(api, options);
            const content = eol.crlf(`${ header }\n\n${ body }`);

            fs.writeFile(remoteFile, content, err => {
                next(err, body);
            });
        }
    ], cb);
};

const getSourceFiles = (vcxproj, type) => {
    const included = [];
    const INCLUDE_START = `<Cl${ type } Include=`;
    let lastIndex = 0;
    let index;
    while ((index = vcxproj.indexOf(INCLUDE_START, lastIndex)) !== -1) {
        const start = index + INCLUDE_START.length + 1;
        const end = vcxproj.indexOf("\"", start);
        included.push(vcxproj.slice(start, end).toString());
        lastIndex = end + 1;
    }
    return included;
};

const getIncludedFiles = (vcxproj, options, cb) => {
    const included = getSourceFiles(vcxproj, "Include");
    const vectors = included.filter(path => path.indexOf("vector_") !== -1);
    const vectmap = {};

    eachOfLimit(vectors, 1, (file, i, next) => {
        waterfall([
            next => {
                fs.readFile(file, next);
            },
            (buffer, next) => {
                // CVAPI(std::vector< ColorPoint >*) VectorOfColorPointCreate();
                const start = buffer.indexOf("CVAPI(") + "CVAPI(".length;
                const end = buffer.indexOf(") VectorOf");
                const type = normalizeVectType(buffer.slice(start, end).toString());
                const mend = buffer.indexOf("Create", end + ") VectorOf".length);
                const method = buffer.slice(end + ") ".length, mend).toString();
                vectmap[type] = method;
                next();
            }
        ], next);
    }, err => {
        options.vectmap = vectmap;
        cb(err, included);
    });
};

const coerceDefaultValue = (defaultValue, {vectmap}) => {
    if (defaultValue === undefined) {
        return defaultValue;
    }

    if (defaultValue === "cv::noArray()" || defaultValue === "noArray()") {
        return "_cveNoArray()";
    }

    if (defaultValue === "morphologyDefaultBorderValue()") {
        return "_cveMorphologyDefaultBorderValue()";
    }

    if (defaultValue === "String()") {
        return "\"\"";
    }

    defaultValue = defaultValue
        .replace(/\s+/g, " ")
        .replace(/\bstd::vector\s*<\s*char\s*>/g, "std::vector<unsigned char>")
        .replace(/\bDrawMatchesFlags::/g, "$CV_DRAW_MATCHES_FLAGS_")
        .replace(/\bTermCriteria\(/g, "_cvTermCriteria(")
        .replace(/\bTermCriteria::/g, "$CV_TERM_CRITERIA_")
        // .replace(/\b(?<!\$)(DBL|DECOMP|CALIB|CV|FLT|SOLVEPNP)_/g, "$$$1_")
        .replace(/\b(?<!\$)(?=CV_)/g, "$")
        .replace(/\bcv::(?=[A-Z]{2,})/g, "$CV_")
        .replace(/\b(?<!\$)(?=[A-Z]{2,})/g, "$CV_")
        .replace(/(\d\.)(?!\d)/g, "$10")
        .replace(/(\d\.\d*)f/g, "$1");

    if (defaultValue.startsWith("_cvTermCriteria(")) {
        return defaultValue;
    }

    if (defaultValue.startsWith("std::vector")) {
        const vecttype = `${ normalizeVectType(defaultValue.slice(0, -2)) }*`;

        if (hasProp.call(vectmap, vecttype)) {
            const method = vectmap[vecttype];
            return `_${ method }Create()`;
        }

        return undefined;
    }

    const struct = defaultValue.match(/^(?:Point|Scalar|Size)/);
    if (struct !== null) {
        return `_cv${ defaultValue }`.replace("_cvScalar::all", "_cvScalarAll");
    }

    const CAST_AS_FLOAT = "(float)";
    if (defaultValue.startsWith(CAST_AS_FLOAT)) {
        defaultValue = defaultValue.slice(CAST_AS_FLOAT.length).trim();
    }

    if (/[(:)]/.test(defaultValue)) {
        return undefined;
    }

    return defaultValue;
};

const coerceExpression = (value, options) => {
    let pos = value.indexOf("<<");
    if (pos !== -1) {
        let start = pos - 1;
        while (start >= 0 && value[start] !== "(") {
            start--;
        }

        let end = pos + "<<".length;
        while (end < value.length && value[end] !== ")") {
            end++;
        }

        const sstart = value.slice(0, start === -1 ? 0 : start);
        const left = value.slice(start + 1, pos).trim();
        const right = value.slice(pos + "<<".length, end).trim();
        const ssend = value.slice(end + 1);
        value = `${ sstart }(BitShift(${ left }, -${ right }))${ ssend }`;
    }

    pos = value.indexOf("|");
    if (pos !== -1) {
        let start = pos - 1;
        while (start >= 0 && value[start] !== "(") {
            start--;
        }

        let end = pos + "|".length;
        while (end < value.length && value[end] !== ")") {
            end++;
        }

        const sstart = value.slice(0, start === -1 ? 0 : start);
        const left = value.slice(start + 1, pos).trim();
        const right = value.slice(pos + "|".length, end).trim();
        const ssend = value.slice(end + 1);
        value = `${ sstart }(BitOR(${ left }, ${ right }))${ ssend }`;
    }

    pos = value.indexOf("&");
    if (pos !== -1) {
        let start = pos - 1;
        while (start >= 0 && value[start] !== "(") {
            start--;
        }

        let end = pos + "&".length;
        while (end < value.length && value[end] !== ")") {
            end++;
        }

        const sstart = value.slice(0, start === -1 ? 0 : start);
        const left = value.slice(start + 1, pos).trim();
        const right = value.slice(pos + "&".length, end).trim();
        const ssend = value.slice(end + 1);
        value = `${ sstart }(BitAND(${ left }, ${ right }))${ ssend }`;
    }

    pos = value.indexOf("~");
    if (pos !== -1) {
        const start = pos++;
        if (pos !== value.length && value[pos] === "(") {
            let opened = 1;
            pos++;
            while (opened !== 0 && pos !== value.length) {
                if (value[pos] === "(") {
                    opened++;
                } else if (value[pos] === ")") {
                    opened--;
                }
                pos++;
            }
        } else {
            while (pos !== value.length && /\w/.test(value[pos])) {
                pos++;
            }
        }

        const sstart = value.slice(0, start);
        const left = value.slice(start + 1, pos).trim();
        const ssend = value.slice(pos);
        value = `${ sstart }(BitNOT(${ left }))${ ssend }`;
    }

    return value.replace(/\b(?<!\$)(?=CV_)/g, "$");
};

const readAdditionalIncludeDirectories = (localPath, remotePath, vcxproj, options, cb) => {
    const INCLUDE_START = "<AdditionalIncludeDirectories>";
    const INCLUDE_END = "</AdditionalIncludeDirectories>";

    const start = vcxproj.indexOf(INCLUDE_START) + INCLUDE_START.length;
    const end = vcxproj.indexOf(INCLUDE_END, start);
    const included = vcxproj.slice(start, end).toString().split(";");

    // const compiled = getSourceFiles(vcxproj, "Compile");

    const defaults = {};

    const hoptions = Object.assign({}, options, {
        exports: {
            start: "CV_EXPORTS_W ",
            end: " "
        }
    });

    const hparser = new ExportsParser(true, hoptions);
    let hasError = false;

    const additionalIncludes = [];
    const excluded = [
        sysPath.join("opencv", "modules", "core", "include", "opencv2", "core", "utils"),
        sysPath.join("opencv", "modules", "gapi", "include", "opencv2", "gapi", "own"),
        "tesseract",
    ];

    const xfiles = [
        "check.hpp",
        "color_detail.hpp",
        "miniflann.hpp",
        "traits.hpp",
    ];

    const seen = new Set();

    eachOfLimit(included, 1, (directory, i, next) => {
        explore(directory, (localFile, stats, next) => {
            if (seen.has(localFile)) {
                next();
                return;
            }
            seen.add(localFile);

            if (hasError || xfiles.some(xfile => localFile.endsWith(xfile)) || (!localFile.endsWith(".hpp") && !localFile.endsWith(".h"))) {
                next();
                return;
            }

            waterfall([
                next => {
                    fs.readFile(localFile, next);
                },

                (buffer, next) => {
                    // if (/\benum\s+(?:\w+\s*)?{/.test(buffer)) {
                    //     console.log(localFile, "has enum");
                    // }

                    buffer = buffer.toString().replace(/CV_(?:IN|OUT|IN_OUT) /g, "").replace(/CV_EXPORTS_W inline/g, "CV_NOT_EXPORTS_W");
                    const api = hparser.parseFile(buffer);

                    if (hparser.lastError) {
                        console.log("reading", localFile, "error");
                        next(hparser.lastError);
                        return;
                    }

                    for (const [, name, args] of api) {
                        const cveName = `cve${ name[0].toUpperCase() }${ name.slice(1) }`;

                        for (const arg of args) {
                            const [, argName] = arg;

                            const defaultValue = coerceDefaultValue(arg[2], options);
                            if (defaultValue === undefined) {
                                if (arg[2] !== undefined) {
                                    console.log("Unable to use default value", name, "(", argName, " = ", arg[2], ")");
                                }
                                continue;
                            }

                            const functions = [name, cveName];

                            // if (name === "drawMatches") {
                            //     functions.push("drawMatchedFeatures1");
                            //     functions.push("drawMatchedFeatures2");
                            //     functions.push("drawMatchedFeatures3");
                            // }

                            for (const fname of functions) {
                                if (!hasProp.call(defaults, fname)) {
                                    defaults[fname] = {};
                                }
                                defaults[fname][argName] = defaultValue;
                            }
                        }
                    }

                    next(null, buffer);
                },

                (buffer, next) => {
                    const parser = new EnumParser(true);
                    const ast = parser.parse(buffer);

                    const ast_enum = Object.assign({}, ast.enum);

                    // enum structs are accessible trough the struct
                    // adding :: will namespace the enum keys
                    for (const key in ast["enum struct"]) {
                        ast_enum[`${ key }::`] = ast["enum struct"][key];
                    }

                    // keep only enums that are in a namespace
                    const enums = Object.keys(ast_enum).filter(key => key.indexOf("::") !== -1 && key.indexOf("<") === -1);

                    if (enums.length === 0) {
                        next(null, false, false);
                        return;
                    }

                    const text = enums.map(key => {
                        const parts = key.split("::");

                        // enums that are outside the cv namespace will be putted in the _cv namespace
                        if (parts[0] !== "cv") {
                            parts.unshift("_cv");
                        }

                        const name = parts.pop() || "anonymous";
                        const prefix = parts.join("_").replace(/[a-z][A-Z]/g, match => `${ match[0] }_${ match[1] }`).toUpperCase();
                        const values = ast_enum[key];
                        const variables = Object.keys(values).filter(vkey => !!values[vkey] && !/^[a-z_]+$/.test(vkey));

                        if (variables.length === 0) {
                            return null;
                        }

                        const expansionRe = new RegExp(`\\b(?:${ variables.join("|") })\\b`, "g");

                        const getVariableName = vname => {
                            return hasProp.call(values, vname) ? `$${ prefix }_${ vname }` : vname;
                        };

                        return `; ${ name }\n${ variables.map(vkey => {
                            const value = coerceExpression(values[vkey], options).replace(expansionRe, getVariableName);
                            return `Global Const ${ getVariableName(vkey) } = ${ value }`;
                        }).join("\n") }`;
                    }).join("\n\n").trim();

                    if (text.length === 0) {
                        next(null, false, false);
                        return;
                    }

                    const src = sysPath.relative(localPath, localFile);
                    const dst = sysPath.resolve(remotePath, src).replace(".hpp", ".au3");
                    additionalIncludes.push([src, dst, text]);
                    next();
                },
            ], err => {
                if (err) {
                    hasError = true;
                }
                next(err);
            });
        }, (dir, stats, files, state, next) => {
            if (seen.has(dir)) {
                next(null, true);
                return;
            }
            seen.add(dir);

            const parts = dir.split(sysPath.sep);
            const skip = hasError
                || !["Emgu.CV.Extern", "opencv"].some(lib => parts.indexOf(lib) !== -1)
                || excluded.some(exclude => dir.endsWith(exclude) || dir.startsWith(localPath, exclude));
            next(null, skip);
        }, {
            limit: 1
        }, err => {
            next(!hasError && err && err.code === "ENOENT" ? null : err);
        });
    }, err => {
        options.additionalIncludes = additionalIncludes;
        options.defaults = defaults;
        cb(err);
    });
};

const DECLARATION_MAP = {
    "cv::String*": (autoItArgName, [argType, argName, defaultValue], declarations, destructors, entry, options) => {
        const capitalCasedName = argName[0].toUpperCase() + argName.slice(1);

        declarations.push(""); // new line
        declarations.push(...`
            Local $b${ capitalCasedName }IsString = VarGetType(${ autoItArgName }) == "String"
            If $b${ capitalCasedName }IsString Then
                ${ autoItArgName } = _cveStringCreateFromStr(${ autoItArgName })
            EndIf
        `.replace(/^ {12}/mg, "").trim().split("\n"));

        destructors.unshift(...`
            If $b${ capitalCasedName }IsString Then
                _cveStringRelease(${ autoItArgName })
            EndIf
        `.replace(/^ {12}/mg, "").trim().split("\n"));
        destructors.unshift(""); // new line
    },

    vector: (autoItArgName, [argType, argName, defaultValue], declarations, destructors, entry, options) => {
        const {vectmap} = options;
        const isPointer = argType.endsWith("**");
        const vecttype = normalizeVectType(isPointer ? argType.slice(0, -1) : argType);

        if (!hasProp.call(vectmap, vecttype)) {
            console.log(entry[1], "cannot bind", argType);
            return null;
        }

        const method = vectmap[vecttype];
        const capitalCasedName = argName[0].toUpperCase() + argName.slice(1);
        const vector = `$vec${ capitalCasedName }`;
        const size = `$iArr${ capitalCasedName }Size`;

        declarations.push(""); // new line
        declarations.push(...`
            Local ${ vector }, ${ size }
            Local $b${ capitalCasedName }IsArray = VarGetType(${ autoItArgName }) == "Array"

            If $b${ capitalCasedName }IsArray Then
                ${ vector } = _${ method }Create()

                ${ size } = UBound(${ autoItArgName })
                For $i = 0 To ${ size } - 1
                    _${ method }Push(${ vector }, ${ autoItArgName }[$i])
                Next
            Else
                ${ vector } = ${ autoItArgName }
            EndIf
        `.replace(/^ {12}/mg, "").trim().split("\n"));

        destructors.unshift(...`
            If $b${ capitalCasedName }IsArray Then
                _${ method }Release(${ vector })
            EndIf
        `.replace(/^ {12}/mg, "").trim().split("\n"));
        destructors.unshift(""); // new line

        return vector;
    },
};

const OVERRIDE_MAP = {
    cveImread(entry, declarations, destructors, options) {
        const args = entry[2];

        for (const arg of args) {
            const [, argName] = arg;

            if (argName === "result") {
                arg[2] = "Null";
                arg[3] = false;

                declarations.push(""); // new line
                declarations.push(...`
                    If $result == Null Then
                        $result = _cveMatCreate()
                    EndIf
                `.replace(/^ {20}/mg, "").trim().split("\n"));

                destructors.push("Return $result");
                destructors.unshift(""); // new line
            }
        }
    },
};

const options = {
    exports: {
        start: "CVAPI(",
        end: ")",
    },
    cdecl: true,

    defaults: {
        // cveWaitKey: {
        //     delay: "0",
        // },
        // cveImread: {
        //     flags: "$CV_IMREAD_UNCHANGED",
        // },
        // cveNamedWindow: {
        //     flags: "$CV_WINDOW_AUTOSIZE",
        // },
        // cveCvtColor: {
        //     dstCn: "0",
        // },
        // cveCanny: {
        //     apertureSize: "3",
        //     L2gradient: "False",
        // },
        // cveResize: {
        //     fx: "0",
        //     fy: "0",
        //     interpolation: "$CV_INTER_LINEAR",
        // },
        // cveNormalize: {
        //     alpha: "1.0",
        //     beta: "0.0",
        //     normType: "$CV_L2",
        //     dType: "-1",
        // }
    },

    isbyref(argType) {
        return argType !== "cv::String*" && argType.endsWith("*") && !argType.startsWith("const ");
    },

    overrides(...args) {
        const name = args[0][1];

        if (hasProp.call(OVERRIDE_MAP, name)) {
            OVERRIDE_MAP[name](...args);
        }
    },

    dllvar: "$_h_cvextern_dll",

    retwrap(retval, [, name], _options) {
        return `CVEDllCallResult(${ retval }, "${ name }", @error)`;
    },

    getAutoItType(autoItType, isNativeType, [argType, argName, defaultValue], [returnType, name, args], _options) {
        if (!isNativeType || !/^VectorOf\w+Push$/.test(name)) {
            return autoItType;
        }
        return `"${ argType }"`;
    },

    rettype(returnType, entry, _options) {
        return `CVAPI(${ returnType })`;
    },

    declaration(...args) {
        const [argType] = args[1];
        if (hasProp.call(DECLARATION_MAP, argType)) {
            return DECLARATION_MAP[argType](...args);
        }

        if (/(?:const )?std::vector/.test(argType)) {
            return DECLARATION_MAP.vector(...args);
        }

        return null;
    },

    fnwrap(func, fnname, entry, _options) {
        const [returnType, , args] = entry;
        const autoItArgs = [];
        const funcArgs = [];
        const declarations = [];
        const destructors = [];
        const {isbyref} = _options;

        for (const arg of args) {
            const [argType, argName, defaultValue, , canDefault] = arg;

            let byRef = arg[3];
            if (byRef === undefined) {
                byRef = typeof isbyref === "function" ? isbyref(argType, arg, entry, options) : argType.endsWith("*") && !argType.startsWith("const ");
            }

            const match = /cv::_(Input|Output|InputOutput)Array\*/.exec(argType);

            if (match === null) {
                const autoItArgName = `$${ argName }`;
                const isString = /^const char\*$/.test(argType);

                if (canDefault !== false && defaultValue !== undefined) {
                    autoItArgs.push(`${ autoItArgName } = ${ defaultValue === "_cveNoArray()" ? "_cveNoArrayMat()" : defaultValue }`);
                } else {
                    autoItArgs.push(autoItArgName);
                }

                funcArgs.push(autoItArgName);
                continue;
            }

            const capitalCasedName = argName[0].toUpperCase() + argName.slice(1);
            const arrType = match[1];
            const autoItArgName = `$mat${ capitalCasedName }`;
            const vector = `$vectorOfMat${ capitalCasedName }`;
            const size = `$iArr${ capitalCasedName }Size`;

            const ARRAY_PREFIXES = {
                Input: "iArr",
                Output: "oArr",
                InputOutput: "ioArr",
            };

            const arrArgName = `$${ ARRAY_PREFIXES[arrType] }${ capitalCasedName }`;

            if (canDefault !== false && defaultValue === "_cveNoArray()") {
                autoItArgs.push(`${ autoItArgName } = _cveNoArrayMat()`);
            } else {
                autoItArgs.push(autoItArgName);
            }

            funcArgs.push(arrArgName);

            declarations.push(""); // new line
            declarations.push(...`
                Local ${ arrArgName }, ${ vector }, ${ size }
                Local $b${ capitalCasedName }IsArray = VarGetType(${ autoItArgName }) == "Array"

                If $b${ capitalCasedName }IsArray Then
                    ${ vector } = _VectorOfMatCreate()

                    ${ size } = UBound(${ autoItArgName })
                    For $i = 0 To ${ size } - 1
                        _VectorOfMatPush(${ vector }, ${ autoItArgName }[$i])
                    Next

                    ${ arrArgName } = _cve${ arrType }ArrayFromVectorOfMat(${ vector })
                Else
                    ${ arrArgName } = _cve${ arrType }ArrayFromMat(${ autoItArgName })
                EndIf
            `.replace(/^ {16}/mg, "").trim().split("\n"));

            destructors.unshift(...`
                If $b${ capitalCasedName }IsArray Then
                    _VectorOfMatRelease(${ vector })
                EndIf

                _cve${ arrType }ArrayRelease(${ arrArgName })
            `.replace(/^ {16}/mg, "").trim().split("\n"));
            destructors.unshift(""); // new line
        }

        if (declarations.length === 0) {
            return func;
        }

        const indent = " ".repeat(16);
        const retval = returnType === "void" ? "" : "Local $retval = ";
        const ret = returnType === "void" ? "" : `\n\n${ indent }Return $retval`;
        const body = [];
        body.push(`; ${ fnname } using cv::Mat instead of _*Array`);
        body.push(...declarations);
        body.push(""); // new line
        body.push(`${ retval }_${ fnname }(${ funcArgs.join(", ") })`);
        body.push(...destructors);

        const added = `
            Func _${ fnname }Mat(${ autoItArgs.join(", ") })
                ${ body.join(`\n${ indent }`) }${ ret }
            EndFunc   ;==>_${ fnname }Mat
        `.replace(/^ {12}/mg, "").trim();

        return `${ func }\n\n${ added }`;
    }
};

const parser = new ExportsParser(true, options);

// [
//     "CVAPI(void) VectorOfDoublePushVector(std::vector< double >* v, std::vector< double >* other);",
//     "CVAPI(std::vector< double >*) VectorOfDoubleCreate();",
//     "CVAPI(void) VectorOfDoubleGetItemPtr(std::vector<  double >* vec, int index,  double** element);",
//     "CVAPI(void) setPlane3D(Plane3D* plane, const CvPoint3D64f* unitNormal, const CvPoint3D64f* pointInPlane);",
//     "CVAPI(void) VectorOfDMatchPushMatrix(std::vector<cv::DMatch>* matches, const CvMat* trainIdx, const CvMat* distance = 0, const CvMat* mask = 0);",
//     "CVAPI(std::vector< unsigned char >*) VectorOfByteCreateSize(int size);",
//     "CVAPI(void) cudaCartToPolar(cv::_InputArray* x, cv::_InputArray* y, cv::_OutputArray* magnitude, cv::_OutputArray* angle, bool angleInDegrees, cv::cuda::Stream* stream);",
//     "CVAPI(void) cveDetectorParametersSetMinGroupSize(cv::mcc::DetectorParameters* obj, unsigned value);     ",
//     `CVAPI(void) OpenniGetColorPoints(
//                                  CvCapture* capture, // must be an openni capture
//                                  std::vector<ColorPoint>* points, // sequence of ColorPoint
//                                  IplImage* mask // CV_8UC1
//                                  );`,
// ].forEach(expr => {
//     parser.noexception = false;
//     parser.parse(expr, 0);
//     console.log(parser.returnType, parser.name, parser.args);
// });

// [
//     "CV_EXPORTS_W int waitKey(int delay = 0);",
//     `CV_EXPORTS_W void resize( InputArray src, OutputArray dst,
//                           Size dsize, double fx = 0, double fy = 0,
//                           int interpolation = INTER_LINEAR );`,
//     `CV_EXPORTS_W void accumulateWeighted( InputArray src, InputOutputArray dst,
//                                       double alpha, InputArray mask = noArray() );`,
//     `CV_EXPORTS_W void add(InputArray src1, InputArray src2, OutputArray dst,
//                       InputArray mask = noArray(), int dtype = -1);`,
//     "CV_EXPORTS_W double PSNR(InputArray src1, InputArray src2, double R=255.);",
//     `CV_EXPORTS_W void minMaxLoc(InputArray src, CV_OUT double* minVal,
//                             CV_OUT double* maxVal = 0, CV_OUT Point* minLoc = 0,
//                             CV_OUT Point* maxLoc = 0, InputArray mask = noArray());`,
//     "CV_EXPORTS_W void setIdentity(InputOutputArray mtx, const Scalar& s = Scalar(1));",
//     `CV_EXPORTS_W void drawKeypoints( InputArray image, const std::vector<KeyPoint>& keypoints, InputOutputArray outImage,
//                                const Scalar& color=Scalar::all(-1), DrawMatchesFlags flags=DrawMatchesFlags::DEFAULT );`,
// ].forEach(expr => {
//     expr = expr.replace(/CV_(?:IN|OUT|IN_OUT) /g, "").replace(/CV_EXPORTS_W inline/g, "CV_NOT_EXPORTS_W");
//     parser.noexception = false;
//     parser.options.exports.start = "CV_EXPORTS_W ";
//     parser.options.exports.end = " ";
//     parser.init(parser.options);
//     parser.parse(expr, 0);
//     console.log(parser.returnType, parser.name, parser.args);
// });

// eachOfLimit([
//     "E:\\development\\git\\emgucv\\opencv\\modules\\core\\include\\opencv2\\core.hpp",
//     "E:\\development\\git\\emgucv\\opencv\\modules\\imgproc\\include\\opencv2\\imgproc.hpp",
//     "E:\\development\\git\\emgucv\\opencv\\modules\\features2d\\include\\opencv2\\features2d.hpp",
//     "E:\\development\\git\\emgucv\\opencv\\modules\\calib3d\\include\\opencv2\\calib3d.hpp",
// ], 1, (localFile, i, next) => {
//     parser.noexception = true;
//     parser.options.exports.start = "CV_EXPORTS_W ";
//     parser.options.exports.end = " ";
//     parser.init(parser.options);

//     fs.readFile(localFile, (err, buffer) => {
//         if (err) {
//             next(err);
//             return;
//         }
//         buffer = buffer.toString().replace(/CV_(?:IN|OUT|IN_OUT) /g, "").replace(/CV_EXPORTS_W inline/g, "CV_NOT_EXPORTS_W");
//         const api = parser.parseFile(buffer);

//         if (parser.lastError) {
//             console.log("reading", localFile, "error");
//             next(parser.lastError);
//             return;
//         }

//         for (const [returnType, name, args] of api) {
//             console.log(returnType, name, args);
//         }

//         next();
//     });
// }, err => {
//     if (err) {
//         throw err;
//     }
// });

// eachOfLimit([
//     "E:\\development\\git\\emgucv\\Emgu.CV.Extern\\depthai-core\\shared\\depthai-shared\\include\\depthai-shared\\metadata\\camera_control.hpp",
//     "E:\\development\\git\\emgucv\\opencv\\modules\\calib3d\\include\\opencv2\\calib3d.hpp",
//     "E:\\development\\git\\emgucv\\opencv\\modules\\core\\include\\opencv2\\core\\affine.hpp",
//     "E:\\development\\git\\emgucv\\opencv\\modules\\core\\include\\opencv2\\core\\base.hpp",
//     "E:\\development\\git\\emgucv\\opencv\\modules\\core\\include\\opencv2\\core\\check.hpp",
//     "E:\\development\\git\\emgucv\\opencv\\modules\\core\\include\\opencv2\\core\\cuda.hpp",
//     "E:\\development\\git\\emgucv\\opencv\\modules\\core\\include\\opencv2\\core\\cuda\\detail\\type_traits_detail.hpp",
//     "E:\\development\\git\\emgucv\\opencv\\modules\\core\\include\\opencv2\\core\\mat.hpp",
//     "E:\\development\\git\\emgucv\\opencv\\modules\\core\\include\\opencv2\\core\\types.hpp",
//     "E:\\development\\git\\emgucv\\opencv\\modules\\features2d\\include\\opencv2\\features2d.hpp",
//     "E:\\development\\git\\emgucv\\opencv\\modules\\imgcodecs\\include\\opencv2\\imgcodecs.hpp",
//     "E:\\development\\git\\emgucv\\opencv\\modules\\imgproc\\include\\opencv2\\imgproc.hpp",
// ], 1, (localFile, i, next) => {
//     const parser = new EnumParser();

//     fs.readFile(localFile, (err, buffer) => {
//         if (err) {
//             next(err);
//             return;
//         }

//         const ast = parser.parse(buffer);

//         next();
//     });
// }, err => {
//     if (err) {
//         throw err;
//     }
// });

// return;

const vcxprojPath = "E:\\development\\git\\emgucv\\build_x64\\Emgu.CV.Extern\\cvextern.vcxproj";

// const localPath = "E:\\development\\git\\emgucv\\Emgu.CV.Extern\\imgproc";
const localPath = "E:\\development\\git\\emgucv\\Emgu.CV.Extern";

// const remotePath = sysPath.join(__dirname, "emgucv-autoIt-bindings\\Emgu.CV.Extern\\imgproc");
const remotePath = sysPath.join(__dirname, "emgucv-autoIt-bindings\\Emgu.CV.Extern");

const remoteBaseDir = sysPath.dirname(remotePath);
const remoteBase = sysPath.basename(remotePath);

const localSep = sysPath.sep;
const remoteSep = sysPath.sep;
const localIndex = localPath.length + 1;
const remoteIndex = remotePath.length + 1;

const maxdepth = -1;

let hasError = false;

const world = ["#include-once"];
const core = ["#include-once"];
const single = [
    "#include-once",
    "#include \"CVEUtils.au3\"",
    ""
];


const core_excluded = [
    /^cuda/,
    "dnn",
    "libgeotiff",
    "ml",
    "nonfree",
    "objdetect",
    "optflow",
    "photo",
    "tesseract"
];

waterfall([
    next => {
        fs.readFile(vcxprojPath, next);
    },

    (vcxproj, next) => {
        getIncludedFiles(vcxproj, options, (err, included) => {
            next(err, vcxproj, included);
        });
    },

    (vcxproj, included, next) => {
        readAdditionalIncludeDirectories(localPath, remotePath, vcxproj, options, (err, defaults) => {
            next(err, vcxproj, included);
        });
    },

    (vcxproj, included, next) => {
        explore(localPath, (localFile, stats, next) => {
            if (hasError || !localFile.endsWith(".h") || included.indexOf(localFile) === -1) {
                next();
                return;
            }

            const localBaseFile = localFile.slice(localIndex);
            const fileparts = localBaseFile.split(localSep);
            const remoteFile = [remotePath].concat(fileparts).join(remoteSep).replace(".h", ".au3");

            const include = `#include "${ remoteBase }\\${ remoteFile.slice(remoteIndex) }"`;

            if (!core_excluded.some(value => {
                if (typeof value === "string") {
                    return fileparts[0] === value;
                }
                return value.test(fileparts[0]);
            })) {
                core.push(include);
            }

            world.push(include);

            convertFile(localFile, remoteFile, remotePath, remoteBaseDir, remoteSep, parser, options, (err, body) => {
                if (err) {
                    hasError = true;
                } else {
                    single.push(...[
                        `#Region ${ localBaseFile }`,
                        body,
                        `#EndRegion ${ localBaseFile }`,
                        "",
                    ]);
                }
                next(err);
            });
        }, (localDir, stats, files, state, next) => {
            if (state !== "begin") {
                next();
                return;
            }

            let skip = hasError;
            const localBaseDir = localDir.slice(localIndex);

            if (!skip && maxdepth >= 0) {
                const depth = localBaseDir.length === 0 ? 0 : localBaseDir.split(localSep).length;

                if (depth >= maxdepth) {
                    skip = true;
                }
            }

            next(null, skip);
        }, {
            limit: 1
        }, next);
    }
], err => {
    if (err) {
        throw err;
    }

    waterfall([
        next => {
            fs.writeFile(sysPath.join(remoteBaseDir, "cve_world.au3"), eol.crlf(world.join("\n")), next);
        },

        next => {
            fs.writeFile(sysPath.join(remoteBaseDir, "cve_core.au3"), eol.crlf(core.join("\n")), next);
        },

        // next => {
        //     fs.writeFile(sysPath.join(remoteBaseDir, "cve_single.au3"), eol.crlf(single.join("\n")), next);
        // },

        next => {
            const {additionalIncludes} = options;
            const include = `
            #include-once
            #include "cv_interface.au3"

            ${ additionalIncludes.map(([src, dst, text]) => {
                return `
                #Region ${ src }
                ${ text }
                #EndRegion ${ src }
                `;
            }).join("\n\n").trim() }`.replace(/^ +/mg, "").trim();
            fs.writeFile(sysPath.join(remoteBaseDir, "cv_enums.au3"), eol.crlf(include), next);
        }
    ], err => {
        if (err) {
            throw err;
        }

        console.log("done");
    });
});
