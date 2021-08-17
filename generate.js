const fs = require("fs");
const sysPath = require("path");
const {explore} = require("fs-explorer");
const eachOfLimit = require("async/eachOfLimit");
const waterfall = require("async/waterfall");
const mkdirp = require("mkdirp");
const eol = require("eol");

const ExportsParser = require("./src/ExportsParser");
const EnumParser = require("./src/EnumParser");
const { convertToAutoIt } = require("./src/autoit-converter");

const {hasOwnProperty: hasProp} = Object.prototype;

const regexEscape = str => {
    return str.replace(/[-/\\^$*+?.()|[\]{}]/g, "\\$&");
};

const normalizeVectType = type => {
    return type.replace(/^const /, "").replace(/ *< */g, "<").replace(/ *> */g, ">");
};

const isFileIncluded = (files, file) => {
    return files.some(include => {
        return include.length > file.length ? include.startsWith(file) : file.startsWith(include);
    });
};

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

            let body;
            try {
                body = convertToAutoIt(api, options);
            } catch(err) {
                next(err);
                return;
            }

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
        .replace(/\b(?<!\$)(?=CV_)/g, "$")
        .replace(/\bcv::(?=[A-Z]{2,})/g, "$CV_")
        .replace(/\b(?<!\$)(?=[A-Z]{2,})/g, "$CV_")
        .replace(/(\d\.)(?!\d)/g, "$10")
        .replace(/(\d\.\d*)f/g, "$1");

    if (defaultValue.startsWith("_cvTermCriteria(")) {
        return defaultValue;
    }

    if (defaultValue.startsWith("std::vector") && defaultValue.endsWith("()")) {
        const vecttype = `${ normalizeVectType(defaultValue.slice(0, -"()".length)) }*`;

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

    // explore include directories from the deepesth
    // to have a correct cppRemoteIncludeFolder
    // otherwise will be taken from the top directory
    const included = vcxproj.slice(start, end).toString().split(";").map(dir => sysPath.resolve(dir)).sort((a, b) => {
        if (a.startsWith(b)) {
            return -1;
        }

        if (b.startsWith(a)) {
            return 1;
        }

        return a > b ? 1 : a < b ? -1 : 0;
    });

    // const compiled = getSourceFiles(vcxproj, "Compile");

    const defaults = {};
    options.enums = {};

    const hoptions = Object.assign({}, options, {
        exports: {
            start: "CV_EXPORTS_W ",
            end: " "
        }
    });

    const hparser = new ExportsParser(true, hoptions);
    let hasError = false;

    const emgucvGitRepo = sysPath.dirname(localPath);

    const apiFiles = [
        sysPath.join(emgucvGitRepo, "Emgu.CV.Extern"),
        sysPath.join(emgucvGitRepo, "opencv"),
        sysPath.join(emgucvGitRepo, "opencv_contrib"),
    ];

    const headerFiles = [
        sysPath.join(emgucvGitRepo, "build_x64", "install", "include", "freetype2"),
        sysPath.join(emgucvGitRepo, "build_x64", "install", "include", "harfbuzz"),
        sysPath.join(emgucvGitRepo, "build_x64", "opencv", "3rdparty", "libtiff"),
        sysPath.join(emgucvGitRepo, "build_x64", "opencv", "3rdparty", "zlib"),
        sysPath.join(emgucvGitRepo, "build_x64", "opencv2"),
    ];

    const excludedFiles = [];

    const excludedParsedHeaders = [
        sysPath.join(emgucvGitRepo, "opencv", "modules", "core", "include", "opencv2", "core", "check.hpp"),
        sysPath.join(emgucvGitRepo, "opencv", "modules", "core", "include", "opencv2", "core", "cuda", "detail", "color_detail.hpp"),
        sysPath.join(emgucvGitRepo, "opencv", "modules", "core", "include", "opencv2", "core", "cuda", "scan.hpp"),
        sysPath.join(emgucvGitRepo, "opencv", "modules", "core", "include", "opencv2", "core", "hal", "intrin_avx.hpp"),
        sysPath.join(emgucvGitRepo, "opencv", "modules", "core", "include", "opencv2", "core", "hal", "intrin_avx512.hpp"),
        sysPath.join(emgucvGitRepo, "opencv", "modules", "core", "include", "opencv2", "core", "hal", "intrin_cpp.hpp"),
        sysPath.join(emgucvGitRepo, "opencv", "modules", "core", "include", "opencv2", "core", "hal", "intrin_vsx.hpp"),
        sysPath.join(emgucvGitRepo, "opencv", "modules", "core", "include", "opencv2", "core", "quaternion.inl.hpp"),
        sysPath.join(emgucvGitRepo, "opencv", "modules", "core", "include", "opencv2", "core", "traits.hpp"),
        sysPath.join(emgucvGitRepo, "opencv", "modules", "core", "include", "opencv2", "core", "utils"),
        sysPath.join(emgucvGitRepo, "opencv", "modules", "flann", "include", "opencv2", "flann", "miniflann.hpp"),
        sysPath.join(emgucvGitRepo, "opencv", "modules", "gapi", "include", "opencv2", "gapi", "own"),
        sysPath.join(emgucvGitRepo, "Emgu.CV.Extern", "tesseract"),
    ];

    const buildFolder = sysPath.join(emgucvGitRepo, "build_x64");

    const additionalIncludes = [];
    const globals = new Set(["$CV_MAT_DEPTH_MASK", "$CV_MAT_TYPE_MASK"]);

    const seen = new Set();
    eachOfLimit(included, 1, (directory, _i, next) => {
        let cppLocalIncludeFolder = directory;
        let cppRemoteIncludeFolder = sysPath.join(__dirname, "libemgucv-includes");

        if (directory === buildFolder) {
            cppRemoteIncludeFolder = sysPath.join(cppRemoteIncludeFolder, sysPath.basename(directory));
        } else if (directory.startsWith(buildFolder) || directory.indexOf("3rdparty") !== -1) {
            cppRemoteIncludeFolder = sysPath.join(cppRemoteIncludeFolder, "3rdparty", sysPath.basename(directory));
        } else if (directory.indexOf("3rdparty") !== -1) {
            cppRemoteIncludeFolder = sysPath.join(cppRemoteIncludeFolder, "3rdparty", sysPath.basename(directory));
        } else if (directory.startsWith(localPath)) {
            cppLocalIncludeFolder = localPath;
            cppRemoteIncludeFolder = sysPath.join(cppRemoteIncludeFolder, sysPath.basename(localPath));
        } else {
            const relpath = sysPath.relative(sysPath.dirname(localPath), directory);
            const parts = relpath.split(sysPath.sep);
            cppRemoteIncludeFolder = sysPath.join(cppRemoteIncludeFolder, parts[0]);
        }

        explore(directory, (localFile, stats, next) => {
            if (seen.has(localFile)) {
                next();
                return;
            }
            seen.add(localFile);

            if (hasError
                || isFileIncluded(excludedFiles, localFile)
                || (!localFile.endsWith(".hpp") && !localFile.endsWith(".h"))
                || (!isFileIncluded(apiFiles, localFile) && !isFileIncluded(headerFiles, localFile))
            ) {
                next();
                return;
            }

            waterfall([
                next => {
                    if (isFileIncluded(excludedParsedHeaders, localFile)) {
                        next(null, null);
                    } else {
                        fs.readFile(localFile, next);
                    }
                },

                (buffer, next) => {
                    if (buffer === null) {
                        next(null, buffer);
                        return;
                    }

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
                                defaults[fname][argName.toLowerCase()] = defaultValue;
                            }
                        }
                    }

                    next(null, buffer);
                },

                (buffer, next) => {
                    if (buffer === null) {
                        next();
                        return;
                    }

                    const parser = new EnumParser(true);
                    const ast = parser.parse(buffer);

                    const ast_enum = Object.assign({}, ast.enum);

                    // enum structs are accessible trough the struct
                    // adding :: will namespace the enum keys
                    for (const key in ast["enum struct"]) { // eslint-disable-line guard-for-in
                        ast_enum[`${ key }::`] = ast["enum struct"][key];
                    }

                    // keep only enums that are in a namespace
                    const enums = Object.keys(ast_enum).filter(key => key.indexOf("::") !== -1 && key.indexOf("<") === -1);

                    if (enums.length === 0) {
                        next();
                        return;
                    }

                    const text = enums.map(key => {
                        const parts = key.split("::");

                        const id = parts.filter(part => !!part).join("::");
                        options.enums[id] = 1;

                        // enums that are outside the cv namespace will be putted in the _cv namespace
                        if (parts[0] !== "cv") {
                            parts.unshift("_cv");
                        }

                        // remove nested namespaces
                        for (let i = parts.length - 1; i > 0; i--) {
                            if (/^[a-z]+$/.test(parts[i])) {
                                parts.splice(i, 1);
                            }
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
                            const vname = getVariableName(vkey);
                            if (globals.has(vname)) {
                                console.log("skip already defined global", vname);
                                return null;
                            }

                            globals.add(vname);
                            const value = coerceExpression(values[vkey], options).replace(expansionRe, getVariableName);
                            return `Global Const ${ vname } = ${ value }`;
                        }).join("\n") }`;
                    }).join("\n\n").trim();

                    if (text.length === 0) {
                        next();
                        return;
                    }

                    const src = sysPath.relative(localPath, localFile);
                    const dst = sysPath.resolve(remotePath, src).replace(".hpp", ".au3");
                    additionalIncludes.push([src, dst, text]);
                    next();
                },

                next => {
                    const src_inc = sysPath.relative(cppLocalIncludeFolder, localFile);
                    const dst_inc = sysPath.resolve(cppRemoteIncludeFolder, src_inc);

                    mkdirp(sysPath.dirname(dst_inc)).then(performed => {
                        fs.copyFile(localFile, dst_inc, next);
                    }, next);
                }
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

            const skip = hasError
                || isFileIncluded(excludedFiles, dir)
                || (!isFileIncluded(apiFiles, dir) && !isFileIncluded(headerFiles, dir));

            next(null, skip);
        }, {
            limit: 1
        }, err => {
            next(!hasError && err && err.code === "ENOENT" ? null : err);
        });
    }, err => {
        options.additionalIncludes = additionalIncludes.sort(([a], [b]) => (a > b ? 1 : a < b ? -1 : 0));
        options.defaults = (fname, argName, defaultValue) => {
            argName = argName.toLowerCase();
            return hasProp.call(defaults, fname) && hasProp.call(defaults[fname], argName) ? defaults[fname][argName] : defaultValue;
        };
        cb(err);
    });
};

const options = require("./src/options");
const parser = new ExportsParser(true, options);

const vcxprojPath = fs.realpathSync(sysPath.join(__dirname, "emgucv\\build_x64\\Emgu.CV.Extern\\cvextern.vcxproj"));
const localPath = fs.realpathSync(sysPath.join(__dirname, "emgucv\\Emgu.CV.Extern"));
const remotePath = fs.realpathSync(sysPath.join(__dirname, "emgucv-autoit-bindings\\Emgu.CV.Extern"));

const emgucv = sysPath.join(__dirname, "emgucv");
const emgucv_extern = sysPath.join(__dirname, "emgucv\\Emgu.CV.Extern");
const remgucv = fs.realpathSync(emgucv);
const remgucv_extern = fs.realpathSync(emgucv_extern);

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
        // handle cases where emgucv is a symlink and vcxproj containes symlink paths not real paths
        vcxproj = vcxproj.toString().replace(new RegExp(regexEscape(emgucv_extern), "g"), remgucv_extern).replace(new RegExp(regexEscape(emgucv), "g"), remgucv);

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

        console.log("exported", Object.keys(options.exported).length, "functions");
    });
});
