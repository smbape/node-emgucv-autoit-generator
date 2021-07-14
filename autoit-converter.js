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

    return type;
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

        let byRef = arg[3];
        if (byRef === undefined) {
            byRef = typeof isbyref === "function" ? isbyref(argType, arg, entry, options) : argType.endsWith("*") && !argType.startsWith("const ");
        }

        const isString = /^const char\*\*?$/.test(argType);
        const isNativeType = NATIVE_TYPES_REG.test(argType);

        declArgs.push(`${ argType } ${ argName }`);

        if (defaultValue !== undefined) {
            declArgs[declArgs.length - 1] += ` = ${ defaultValue }`;
        }

        const autoItArgName = `$${ argName }`;
        let dllArgName = autoItArgName;

        autoItArgs.push((byRef && !isString ? "ByRef " : "") + autoItArgName);

        if (name === "cveCvtColor" && argName === "dstCn") {
            debugger;
        }

        if (defaults !== null && typeof defaults === "object" && hasProp.call(defaults, name) && hasProp.call(defaults[name], argName)) {
            arg[2] = defaults[name][argName];
        }

        if (typeof declaration === "function") {
            const newDllArgName = declaration(dllArgName, arg, declarations, destructors, entry, options);
            if (typeof newDllArgName === "string") {
                dllArgName = newDllArgName;
            }
        }

        if (!byRef && arg[2] !== undefined) {
            autoItArgs[autoItArgs.length - 1] += ` = ${ arg[2] }`;
        }

        let autoItDllType;

        if (isString) {
            autoItDllType = argType.endsWith("**") ? "struct*" : "str";
        } else if (byRef) {
            if (argType.endsWith("**")) {
                autoItDllType = "ptr*";
            } else if (isString) {
                autoItDllType = "str";
            } else if (/^\w+\*$/.test(argType)) {
                autoItDllType = "struct*";
            } else {
                autoItDllType = "ptr";
            }
        } else {
            autoItDllType = getAutoItType(argType, isNativeType);
        }

        if (typeof _getAutoItType === "function") {
            autoItDllType = _getAutoItType(autoItDllType, isNativeType, arg, entry, options);
        }

        dllArgs.push(`"${ autoItDllType }"`);
        dllArgs.push(dllArgName);
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
    const hasDeclarationOrDesctructor = declarations.length !== 0 || destructors.length !== 0;

    const body = [];
    body.push(`; ${ returnType } ${ name }(${ declArgs.join(", ") });`);
    body.push(...declarations);

    if (isVoid) {
        if (declarations.length !== 0) {
            body.push(""); // new line
        }
        body.push(retval);
    } else if (hasDeclarationOrDesctructor) {
        if (declarations.length !== 0) {
            body.push(""); // new line
        }
        body.push(`Local $retval = ${ retval }`);
    } else {
        body.push(`Return ${ retval }`);
    }

    body.push(...destructors);

    if (!isVoid && hasDeclarationOrDesctructor) {
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
