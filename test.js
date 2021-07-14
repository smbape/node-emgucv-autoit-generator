const fs = require("fs");
const sysPath = require("path");
const {explore} = require("fs-explorer");
const eachOfLimit = require("async/eachOfLimit");
const waterfall = require("async/waterfall");
const mkdirp = require("mkdirp");
const eol = require("eol");

const ExportsParser = require("./ExportsParser");
const { convertToAutoIt } = require("./autoit-converter");

const normalizeVectType = type => {
    return type.replace(/^const /, "").replace(/ *< */g, "<").replace(/ *> */g, ">");
};

const {hasOwnProperty: hasProp} = Object.prototype;

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
        cveWaitKey: {
            delay: "0",
        },
        cveImread: {
            flags: "$CV_IMREAD_UNCHANGED",
        },
        cveNamedWindow: {
            flags: "$CV_WINDOW_AUTOSIZE",
        },
        cveCvtColor: {
            dstCn: "0",
        },
        cveCanny: {
            apertureSize: "3",
            L2gradient: "False",
        },
        cveResize: {
            fx: "0",
            fy: "0",
            interpolation: "$CV_INTER_LINEAR",
        },
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
        return `${ argType }`;
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
            const [argType, argName, defaultValue] = arg;

            let byRef = arg[3];
            if (byRef === undefined) {
                byRef = typeof isbyref === "function" ? isbyref(argType, arg, entry, options) : argType.endsWith("*") && !argType.startsWith("const ");
            }

            const match = /cv::_(Input|Output|InputOutput)Array\*/.exec(argType);

            if (match === null) {
                const autoItArgName = `$${ argName }`;
                const isString = /^const char\*$/.test(argType);
                autoItArgs.push((byRef && !isString ? "ByRef " : "") + autoItArgName);

                if (defaultValue !== undefined && !byRef) {
                    autoItArgs[autoItArgs.length - 1] += ` = ${ defaultValue }`;
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

            autoItArgs.push(`ByRef ${ autoItArgName }`);
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
        body.push(`; ${ fnname } using cv::Mat instead of _*Array`)
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
//     parser.parse(Buffer.from(expr), 0);
//     console.log(parser.returnType, parser.name, parser.args);
// });
// return;

const convertFile = (localFile, remoteFile, remotePath, remoteBaseDir, remoteSep, cb) => {
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
                #include <${ sysPath.relative(remoteFileDir, remoteBaseDir) }\\CVEUtils.au3>
            `.replace(/^ +/mg, "").trim();
            fs.writeFile(remoteFile, eol.crlf(`${ header }\n\n${ convertToAutoIt(api, options) }`), next);
        }
    ], cb);
};

const getVectorMap = (files, cb) => {
    const vectors = files.filter(path => path.indexOf("vector_") !== -1);
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
        cb(err, vectmap);
    });
};

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
        const included = (() => {
            const files = [];
            const INCLUDE_START = "<ClInclude Include=";
            let lastIndex = 0;
            let index;
            while ((index = vcxproj.indexOf(INCLUDE_START, lastIndex)) !== -1) {
                const start = index + INCLUDE_START.length + 1;
                const end = vcxproj.indexOf("\"", start);
                files.push(vcxproj.slice(start, end).toString());
                lastIndex = end + 1;
            }
            return files;
        })();

        getVectorMap(included, (err, vectmap) => {
            next(err, included, vectmap);
        });
    },

    (included, vectmap, next) => {
        options.vectmap = vectmap;

        explore(localPath, (localFile, stats, next) => {
            if (hasError || !localFile.endsWith(".h") || included.indexOf(localFile) === -1) {
                next();
                return;
            }

            const localBaseFile = localFile.slice(localIndex);
            const fileparts = localBaseFile.split(localSep);
            const remoteFile = [remotePath].concat(fileparts).join(remoteSep).replace(".h", ".au3");

            const include = `#include <${ remoteBase }\\${ remoteFile.slice(remoteIndex) }>`;

            if (!core_excluded.some(value => {
                if (typeof value === "string") {
                    return fileparts[0] === value;
                }
                return value.test(fileparts[0]);
            })) {
                core.push(include);
            }

            world.push(include);

            convertFile(localFile, remoteFile, remotePath, remoteBaseDir, remoteSep, err => {
                if (err) {
                    hasError = true;
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
        }
    ], err => {
        if (err) {
            throw err;
        }

        console.log("done");
    });
});
