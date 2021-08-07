const {hasOwnProperty: hasProp} = Object.prototype;

const AUTOIT_TYPE_MAP = {
    bool: "boolean",
    void: "none",
    size_t: "ulong_ptr",
    "unsigned short": "ushort",
    "unsigned int": "uint",
    "unsigned long": "ulong",
};

const NATIVE_TYPES_REG = new RegExp(`^(?:const )?(?:${ [
    "boolean",
    "bool",
    "short",
    "ushort",
    "int",
    "uint",
    "long",
    "ulong",
    "float",
    "double",
].join("|") })\\*?`);

const getAutoItType = (type, native = false) => {
    const byRef = type.endsWith("*");

    if (!native && byRef) {
        return "ptr";
    }

    if (hasProp.call(AUTOIT_TYPE_MAP, type)) {
        return AUTOIT_TYPE_MAP[type];
    }

    if (native && byRef && hasProp.call(AUTOIT_TYPE_MAP, type.slice(0, -1))) {
        return `${ AUTOIT_TYPE_MAP[type] }*`;
    }

    return type.replace(/^const /, "");
};

const getAutoItFunctionDefinition = (entry, options = {}) => {
    let returnType = entry[0];
    const [, name, args] = entry;
    const {cdecl, defaults, isbyref, overrides, retwrap, rettype, fnwrap, declaration, getAutoItType: _getAutoItType} = options;

    const isVoid = returnType === "void";
    const autoItReturnType = getAutoItType(returnType);

    const autoItArgs = [];
    const declArgs = [];
    const dllArgs = [cdecl ? `"${ autoItReturnType }:cdecl"` : `"${ autoItReturnType }"`, `"${ name }"`];
    const declarations = [];
    const destructors = [];

    if (typeof overrides === "function") {
        overrides(entry, declarations, destructors, options);
    }

    for (const arg of args) {
        const [argType, argName, defaultValue] = arg;
        const capitalCasedName = argName[0].toUpperCase() + argName.slice(1);

        let byRef = arg[3];
        if (byRef === undefined) {
            byRef = typeof isbyref === "function" ? isbyref(argType, arg, entry, options) : argType.endsWith("*") && !argType.startsWith("const ");
            arg[3] = byRef;
        }

        const isString = /^const char\*\*?$/.test(argType);
        const isNativeType = NATIVE_TYPES_REG.test(argType);

        declArgs.push(`${ argType } ${ argName }`);

        if (defaultValue !== undefined) {
            declArgs[declArgs.length - 1] += ` = ${ defaultValue }`;
        }

        const autoItArgName = `$${ argName }`;
        let dllArgName = autoItArgName;

        if (typeof defaults === "function") {
            arg[2] = defaults(name, argName, defaultValue);
        } else if (defaults !== null && typeof defaults === "object" && hasProp.call(defaults, name)) {
            if (typeof defaults[name] === "function") {
                arg[2] = defaults[name](argName, defaultValue);
            } else if (defaults[name] !== null && typeof defaults[name] === "object" && hasProp.call(defaults[name], argName)) {
                arg[2] = defaults[name][argName];
            }
        }

        if (typeof declaration === "function") {
            const newDllArgName = declaration(dllArgName, arg, declarations, destructors, entry, options);
            if (typeof newDllArgName === "string") {
                dllArgName = newDllArgName;
            }
        }

        if (arg[2] !== undefined) {
            autoItArgs.push(`${ autoItArgName } = ${ arg[2] }`);
        } else {
            autoItArgs.push(autoItArgName);
        }

        let autoItDllType;

        if (byRef || argType.endsWith("*")) {
            if (argType.endsWith("**")) {
                autoItDllType = "ptr*";
            } else if (isString) {
                autoItDllType = "str";
            } else if (isNativeType) {
                autoItDllType = getAutoItType(argType, isNativeType);
            } else {
                autoItDllType = "ptr";
            }

            declarations.push(""); // new line
            declarations.push(...`
                Local $b${ capitalCasedName }DllType
                If VarGetType(${ autoItArgName }) == "DLLStruct" Then
                    $b${ capitalCasedName }DllType = "struct*"
                Else
                    $b${ capitalCasedName }DllType = "${ autoItDllType }"
                EndIf
            `.replace(/^ {16}/mg, "").trim().split("\n"));
            autoItDllType = `$b${ capitalCasedName }DllType`;
        } else {
            autoItDllType = `"${ getAutoItType(argType, isNativeType) }"`;
        }

        if (typeof _getAutoItType === "function") {
            autoItDllType = _getAutoItType(autoItDllType, isNativeType, arg, entry, options);
        }

        dllArgs.push(autoItDllType, dllArgName);
    }


    for (let i = autoItArgs.length - 1, canDefault = true; i >= 0; i--) {
        const arg = args[i];
        // const [argType] = arg;
        const value = autoItArgs[i];
        const pos = value.indexOf(" = ");
        const hasDefault = pos !== -1;

        if (canDefault) {
            canDefault = hasDefault;
        } else if (hasDefault) {
            autoItArgs[i] = value.slice(0, pos);
            arg[4] = false;
        }
    }

    const dllvar = typeof options.dllvar === "function" ? options.dllvar(entry, options) : options.dllvar;
    let retval = `DllCall(${ dllvar }, ${ dllArgs.join(", ") })`;

    if (typeof retwrap === "function") {
        retval = retwrap(retval, entry, options);
    }

    if (typeof rettype === "function") {
        returnType = rettype(returnType, entry, options);
    }

    const indent = " ".repeat(12);
    const hasDesctructor = destructors.length !== 0;

    const body = [];
    body.push(`; ${ returnType } ${ name }(${ declArgs.join(", ") });`);
    body.push(...declarations);

    if (isVoid) {
        if (declarations.length !== 0) {
            body.push(""); // new line
        }
        body.push(retval);
    } else if (hasDesctructor) {
        if (declarations.length !== 0) {
            body.push(""); // new line
        }
        body.push(`Local $retval = ${ retval }`);
    } else {
        body.push(`Return ${ retval }`);
    }

    body.push(...destructors);

    if (!isVoid && hasDesctructor) {
        body.push(""); // new line
        body.push("Return $retval");
    }

    let func = `
        Func _${ name }(${ autoItArgs.join(", ") })
            ${ body.join(`\n${ indent }`) }
        EndFunc   ;==>_${ name }
    `.replace(/^ {8}/mg, "").trim();

    if (typeof fnwrap === "function") {
        func = fnwrap(func, name, entry, options);
    }

    return func.replace(/[^\S\n]+(?=\r?\n)/mg, "");
};

const convertToAutoIt = (api, options = {}) => {
    const seen = new Set();
    const text = [];

    for (const entry of api) {
        const name = entry[1];
        if (seen.has(name)) {
            continue;
        }
        seen.add(name);
        text.push(getAutoItFunctionDefinition(entry, options));
    }

    return text.join("\n\n");
};

Object.assign(exports, {
    getAutoItType,
    getAutoItFunctionDefinition,
    convertToAutoIt,
});
