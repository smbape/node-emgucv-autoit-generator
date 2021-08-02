const {hasOwnProperty: hasProp} = Object.prototype;

const normalizeVectType = type => {
    return type.replace(/^const /, "").replace(/ *< */g, "<").replace(/ *> */g, ">");
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

module.exports = {
    exports: {
        start: "CVAPI(",
        end: ")",
    },
    cdecl: true,

    defaults: {},

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

    retwrap(retval, [, name], options) {
        return `CVEDllCallResult(${ retval }, "${ name }", @error)`;
    },

    getAutoItType(autoItType, isNativeType, [argType, argName, defaultValue], [returnType, name, args], options) {
        if (!isNativeType || !/^VectorOf\w+Push$/.test(name)) {
            return autoItType;
        }
        return `"${ argType }"`;
    },

    rettype(returnType, entry, options) {
        return `CVAPI(${ returnType })`;
    },

    declaration(...args) {
        const argType = args[1][0].replace("const ", "");

        if (hasProp.call(DECLARATION_MAP, argType)) {
            return DECLARATION_MAP[argType](...args);
        }

        if (/(?:const )?std::vector/.test(argType)) {
            return DECLARATION_MAP.vector(...args);
        }

        return null;
    },

    fnwrap(func, fnname, entry, options) {
        const [returnType, , args] = entry;
        const autoItArgs = [];
        const funcArgs = [];
        const declarations = [];
        const destructors = [];
        const {isbyref} = options;

        for (const arg of args) {
            const [argType, argName, defaultValue, , canDefault] = arg;

            let byRef = arg[3];
            if (byRef === undefined) {
                byRef = typeof isbyref === "function" ? isbyref(argType, arg, entry, options) : argType.endsWith("*") && !argType.startsWith("const ");
            }

            const match = /cv::_(Input|Output|InputOutput)Array\*/.exec(argType);

            if (match === null) {
                const autoItArgName = `$${ argName }`;
                // const isString = /^const char\*$/.test(argType);

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
