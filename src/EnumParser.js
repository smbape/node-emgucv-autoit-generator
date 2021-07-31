const LF = "\n";
const PREPROCESS_IF = "#if";
const PREPROCESS_ENDIF = "#endif";
const BLOC_COMMENT_START = "/*";
const BLOC_COMMENT_END = "*/";
const OPEN_PARENTHESIS = "(";
const CLOSE_PARENTHESIS = ")";

const NAMESPACE = "namespace";
const CLASS = "class";
const TEMPLATE = "template";
const ENUM = "enum";
const ENUM_CLASS = "enum class";
const ENUM_STRUCT = "enum struct";
const STRUCT = "struct";
const BLOCK_START = "{";
const BLOCK_END = "}";

class EnumParser {
    constructor(noexception = false, options = {}) {
        this.noexception = noexception;
        this.init(options);
    }

    init(options) {
        this.options = options;
        const {lf} = options;
        this.lf = lf || LF;
    }

    parse(input, offset = 0) {
        if (Buffer.isBuffer(input)) {
            input = input.toString();
        }

        const tokenizer = new RegExp(`(?:/[/*]|^${ [ PREPROCESS_IF ].join("|") }|[${ [
            BLOCK_START,
            BLOCK_END,
            OPEN_PARENTHESIS,
            CLOSE_PARENTHESIS,
        ].join("") }]|\\b(?:${ [
            NAMESPACE,
            CLASS,
            TEMPLATE,
            ENUM_CLASS,
            ENUM_STRUCT,
            ENUM,
            STRUCT,
        ].join("|") })\\b)`, "mg");

        tokenizer.lastIndex = offset;

        const state = {
            blocks: [],
            path: [],
            level: [],
        };

        const ast = {
            namespace: {},
            class: {},
            template: {},
            enum: {},
            "enum class": {},
            "enum struct": {},
            struct: {},
        };

        let blocks = 0;
        let parenthesis = 0;
        let match, name, pos;
        let preprocessed = false;
        let assignment = null;
        let topened = 0;

        while ((match = tokenizer.exec(input)) !== null) {
            if (this.mayBeLineComment(input, tokenizer, match.index) || this.mayBeBlockComment(input, tokenizer, match.index)) {
                continue;
            }

            switch (match[0]) {
                case PREPROCESS_IF:
                    // ignore the first #ifndef XXX_HPP
                    if (!preprocessed || input.startsWith("#ifdef __cplusplus", match.index)) {
                        preprocessed = true;
                        break;
                    }

                    tokenizer.lastIndex = input.indexOf(PREPROCESS_ENDIF, match.index) + PREPROCESS_ENDIF.length;
                    if (tokenizer.lastIndex - PREPROCESS_ENDIF.length === -1) {
                        tokenizer.lastIndex = input.length;
                    }
                    break;

                case TEMPLATE:
                    pos = tokenizer.lastIndex;

                    while (pos !== input.length && /\s/.test(input[pos])) {
                        pos++;
                    }

                    if (pos !== input.length && input[pos] === "<") {
                        pos++;
                        topened = 1;
                        while (topened !== 0 && pos !== input.length) {
                            if (input[pos] === ">") {
                                topened--;
                            } else if (input[pos] === "<") {
                                topened++;
                            }
                            pos++;
                        }
                        tokenizer.lastIndex = pos;
                    }

                    break;

                case NAMESPACE:
                case CLASS:
                case ENUM:
                case ENUM_CLASS:
                case ENUM_STRUCT:
                case STRUCT:
                    if (parenthesis === 0) {
                        ([name, pos] = this.parseBlockName(input, tokenizer.lastIndex));
                        if (pos !== input.length && input[pos] !== ";") {
                            state.blocks.push(match[0]);
                            state.path.push(name);
                            state.level.push(blocks);
                        }
                        tokenizer.lastIndex = pos;
                    }
                    break;

                case BLOCK_START:
                    if (parenthesis === 0
                        && state.blocks.length !== 0
                        && (state.blocks[state.blocks.length - 1] === ENUM || state.blocks[state.blocks.length - 1] === ENUM_STRUCT)
                        && state.blocks.indexOf(TEMPLATE) === -1
                        && state.blocks.indexOf(STRUCT) === -1
                    ) {
                        ([assignment, pos] = this.parseAssignment(input, tokenizer.lastIndex));
                    }
                    blocks++;
                    break;

                case BLOCK_END:
                    // if (blocks === 0) {
                    //     debugger;
                    // }
                    blocks--;
                    if (state.blocks.length !== 0 && state.level[state.level.length - 1] === blocks) {
                        name = state.blocks.pop();
                        if (assignment !== null) {
                            ast[name][state.path.join("::")] = Object.assign({}, ast[name][state.path.join("::")], assignment);
                            assignment = null;
                        }
                        state.path.pop();
                        state.level.pop();
                    }
                    break;

                case OPEN_PARENTHESIS:
                    parenthesis++;
                    break;

                case CLOSE_PARENTHESIS:
                    // if (parenthesis === 0) {
                    //     debugger;
                    // }
                    parenthesis--;
                    break;

                default:
                    // continue
            }
        }

        return ast;
    }

    parseBlockName(input, offset = 0) {
        let start = offset;
        let end = offset;
        let match;
        let opened = 0;

        const blockNameTokenizer = /(?:[{:;]|\s+|[^{:\s;]+)/mg;
        blockNameTokenizer.lastIndex = offset;

        while ((match = blockNameTokenizer.exec(input)) !== null) {
            if (match[0] === "{" || match[0] === ":" || match[0] === ";") {
                blockNameTokenizer.lastIndex = match.index;
                break;
            }

            if (/^\s/.test(match[0])) {
                continue;
            }

            start = match.index;
            end = match.index + match[0].length;

            if (input[end - 1] === "<") {
                opened++;
                while (opened !== 0 && end !== input.length) {
                    if (input[end] === ">") {
                        opened--;
                    } else if (input[end] === "<") {
                        opened++;
                    }
                    end++;
                }
            }

            blockNameTokenizer.lastIndex = end;
        }

        if (blockNameTokenizer.lastIndex < offset) {
            blockNameTokenizer.lastIndex = input.length;
        }

        const name = input.slice(start, end);
        return [name, blockNameTokenizer.lastIndex];
    }

    parseAssignment(input, offset = 0) {
        const assignment = {};
        const assignmentTokenizer = /(?:[}=,()]|\/[/*]|\s+|\w+|#if)/mg;
        assignmentTokenizer.lastIndex = offset;

        let match;
        let name = null;
        let assign = -1;
        let parenthesis = 0;

        while ((match = assignmentTokenizer.exec(input)) !== null) {
            if (match[0] === "}") {
                if (name !== null) {
                    assignment[name] = input.slice(assign, match.index).trim();
                    assign = -1;
                    name = null;
                }
                assignmentTokenizer.lastIndex = match.index;
                break;
            }

            if (this.mayBeLineComment(input, assignmentTokenizer, match.index) || this.mayBeBlockComment(input, assignmentTokenizer, match.index)) {
                if (name !== null) {
                    assignment[name] = input.slice(assign, match.index).trim();
                    assign = -1;
                    name = null;
                }
                continue;
            }

            if (match[0] === PREPROCESS_IF) {
                assignmentTokenizer.lastIndex = input.indexOf(PREPROCESS_ENDIF, match.index) + PREPROCESS_ENDIF.length;
                if (assignmentTokenizer.lastIndex - PREPROCESS_ENDIF.length === -1) {
                    assignmentTokenizer.lastIndex = input.length;
                }
                continue;
            }

            if (match[0] === "(") {
                parenthesis++;
                continue;
            }

            if (match[0] === ")") {
                parenthesis--;
                continue;
            }

            if (parenthesis !== 0 || /^\s/.test(match[0])) {
                continue;
            }

            if (match[0] === "=") {
                assign = assignmentTokenizer.lastIndex;
                continue;
            }

            if (match[0] === ",") {
                assignment[name] = input.slice(assign, match.index).trim();
                assign = -1;
                name = null;
                continue;
            }

            if (assign === -1) {
                // if (name !== null) {
                //     debugger;
                // }
                name = match[0];
            }
        }

        if (assignmentTokenizer.lastIndex < offset) {
            assignmentTokenizer.lastIndex = input.length;
        }

        return [assignment, assignmentTokenizer.lastIndex];
    }

    mayBeLineComment(input, tokenizer, offset = 0) {
        if (!input.startsWith("//", offset)) {
            return false;
        }

        let pos = input.indexOf(this.lf, offset + "//".length) + this.lf.length;
        if (pos - this.lf.length === -1) {
            pos = input.length;
        }
        tokenizer.lastIndex = pos;
        return true;
    }

    mayBeBlockComment(input, tokenizer, offset = 0) {
        if (!input.startsWith(BLOC_COMMENT_START, offset)) {
            return false;
        }

        let pos = input.indexOf(BLOC_COMMENT_END, offset + BLOC_COMMENT_START.length) + BLOC_COMMENT_END.length;
        if (pos - BLOC_COMMENT_END.length === -1) {
            pos = input.length;
        }

        tokenizer.lastIndex = pos;
        return true;
    }
}

module.exports = EnumParser;
