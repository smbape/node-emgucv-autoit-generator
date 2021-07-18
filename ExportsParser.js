const LF = "\n";
const IF_DEF_WINAPI_FAMILY = "#if WINAPI_FAMILY";
const ENDIF = "#endif";
const BLOC_COMMENT_START = "/*";
const BLOC_COMMENT_END = "*/";
const OPEN_PARENTHESIS = "(";
const CLOSE_PARENTHESIS = ")";
const COLON = ":";
const COMMA = ",";
const AMPERS_GT = ">";
const AMPERS_LT = "<";
const SEMICOLON = ";";
const STAR = "*";
const EQUALS = "=";
const SLASH = "/";
const AMPERS_AND = "&";
// const MINUS = "-";
// const DOT = ".";

const crlfRe = /[\r\n]/mg;
const notSpaceRe = /\S/mg;
const notIdenvifierRe = /\W/mg;

const UNSINED_TYPES = [
    "char",
    "short",
    "short int",
    "int",
    "long",
    "long int",
    "long long",
    "long long int",
].sort(({length: a}, {length: b}) => b - a);

class ExportsParser {
    constructor(noexception = false, options = {}) {
        this.noexception = noexception;
        this.init(options);
    }

    init(options) {
        this.options = options;
        const {lf} = options;
        const {start: export_start, end: export_end} = options.exports;
        this.lf = lf || LF;
        this.export_start = export_start;
        this.export_end = export_end;
        this.export_end_is_space = !notSpaceRe.test(export_end);
        this.tokenizer = new RegExp(`(?:^/[/*]|^${ export_start.replace(/[-/\\^$*+?.()|[\]{}]/g, "\\$&") }|#if WINAPI_FAMILY)`, "mg");
    }

    parseFile(input, offset = 0) {
        if (Buffer.isBuffer(input)) {
            input = input.toString();
        }

        const {tokenizer} = this;

        let match;

        tokenizer.lastIndex = offset;

        const api = [];

        while ((match = tokenizer.exec(input)) !== null) {
            if (match[0] === "//") {
                tokenizer.lastIndex = input.indexOf(this.lf, match.index) + this.lf.length;
                if (tokenizer.lastIndex - this.lf.length === -1) {
                    tokenizer.lastIndex = input.length;
                }
                continue;
            }

            if (match[0] === BLOC_COMMENT_START) {
                tokenizer.lastIndex = input.indexOf(BLOC_COMMENT_END, match.index) + BLOC_COMMENT_END.length;
                if (tokenizer.lastIndex - BLOC_COMMENT_END.length === -1) {
                    tokenizer.lastIndex = input.length;
                }
                continue;
            }

            if (match[0] === IF_DEF_WINAPI_FAMILY) {
                tokenizer.lastIndex = input.indexOf(ENDIF, match.index) + ENDIF.length;
                if (tokenizer.lastIndex - ENDIF.length === -1) {
                    tokenizer.lastIndex = input.length;
                }
                continue;
            }

            this.parse(input, match.index);

            if (this.lastError) {
                return null;
            }

            api.push([this.returnType, this.name, this.args]);
        }

        return api;
    }

    parse(input, pos) {
        if (Buffer.isBuffer(input)) {
            input = input.toString();
        }

        this.start = pos;
        pos += this.export_start.length;

        this.input = input;
        this.length = this.input.length;

        this.lastError = undefined;
        this.returnType = undefined;
        this.name = undefined;
        this.args = [];
        this.pos = pos;

        // CVAPI(void) VectorOfDoublePushVector(std::vector< double >* v, std::vector< double >* other);

        // void)
        if (!this.mayBeReturnType()) {
            this.unexpected();
            return;
        }

        this.returnType = this._lastType;
        pos = this.pos;

        // VectorOfDoublePushVector
        if (!this.mayBeIdentifier()) {
            this.unexpected();
            return;
        }

        this.name = this._lastIdentifier;
        pos = this.pos;

        // (std::vector< double >* v, std::vector< double >* other);
        if (!this.mayBeParameters() || !this.mayBeEnd()) {
            this.unexpected();
        }
    }

    unexpected() {
        crlfRe.lastIndex = this.pos;
        const match = crlfRe.exec(this.input);
        const eof = match === null ? this.length : match.index;
        const win = 40;
        const start = Math.max(this.start, this.pos - win);
        const end = Math.min(eof, this.pos + win);
        const msg = `Unexpected token ${ this.input.slice(start, end) }`;
        const pad = `${ " ".repeat("Error: Unexpected token ".length + (this.pos - start)) }^`;

        const error = new Error(`${ msg }\n${ pad }`);
        error.pos = this.pos;

        if (this.noexception) {
            this.lastError = error;
        } else {
            throw error;
        }
    }

    isEndOfExports() {
        if (this.export_end_is_space) {
            return this.pos - 1 !== -1 && !notSpaceRe.test(this.input[this.pos - 1]);
        }

        if (!this.input.slice(this.pos, this.pos + this.export_end.length) === this.export_end) {
            return false;
        }

        this.pos++;
        return true;
    }

    mayBeReturnType() {
        if (this.pos === this.length) {
            return false;
        }

        const {pos} = this;

        this.mayBeType();
        this.mayBeSpace();

        if (this.pos < this.length && this.isEndOfExports()) {
            return true;
        }

        this.pos = pos;
        return false;
    }

    mayBeSpace() {
        if (this.pos === this.length) {
            return false;
        }

        const {pos} = this;
        notSpaceRe.lastIndex = pos;

        let trim = true;

        while (trim) {
            const match = notSpaceRe.exec(this.input);
            this.pos = match === null ? this.length : match.index;
            trim = false;

            if (this.pos + 1 < this.length && this.input[this.pos] === SLASH) {
                if (this.input[this.pos + 1] === SLASH) {
                    this.pos = this.input.indexOf(this.lf, this.pos + 2) + 1;
                    if (this.pos === 0) {
                        this.pos = this.length;
                    } else {
                        notSpaceRe.lastIndex = this.pos;
                        trim = true;
                    }
                } else if (this.input[this.pos + 1] === STAR) {
                    this.pos = this.input.indexOf(BLOC_COMMENT_END, this.pos + 2) + 2;
                    if (this.pos === 0) {
                        this.pos = this.length;
                    } else {
                        notSpaceRe.lastIndex = this.pos;
                        trim = true;
                    }
                }
            }
        }

        return this.pos !== pos;
    }

    mayBeIdentifier() {
        this._lastIdentifier = undefined;

        if (this.pos === this.length) {
            return false;
        }

        const {pos} = this;

        this.mayBeSpace();
        const start = this.pos;
        notIdenvifierRe.lastIndex = this.pos;
        const match = notIdenvifierRe.exec(this.input);
        this.pos = match === null ? this.length : match.index;

        if (this.pos !== start) {
            this._lastIdentifier = this.input.slice(start, this.pos);
            return true;
        }

        this.pos = pos;
        return false;
    }

    mayBeExpression() {
        this._lastExpression = undefined;

        if (this.pos === this.length) {
            return false;
        }

        const {pos} = this;

        this.mayBeSpace();
        const start = this.pos;

        while (this.pos < this.length && this.input[this.pos] !== COMMA && this.input[this.pos] !== CLOSE_PARENTHESIS) {
            if (this.input[this.pos] === OPEN_PARENTHESIS) {
                this.pos++;

                let opened = 1;
                while (opened !== 0 && this.pos < this.length) {
                    if (this.input[this.pos] === OPEN_PARENTHESIS) {
                        opened++;
                    } else if (this.input[this.pos] === CLOSE_PARENTHESIS) {
                        opened--;
                    }
                    this.pos++;
                }

                if (opened !== 0) {
                    this.pos = pos;
                    return false;
                }

                this.pos--;
            }

            this.pos++;
        }

        if (this.pos !== start) {
            this._lastExpression = this.input.slice(start, this.pos).trim();
            return true;
        }

        this.pos = pos;
        return false;
    }

    mayBeParameters() {
        if (this.pos === this.length) {
            return false;
        }

        const {pos} = this;

        // (std::vector< double >* v, std::vector< double >* other)
        this.mayBeSpace();

        if (this.pos === this.length || this.input[this.pos++] !== OPEN_PARENTHESIS) {
            this.pos = pos;
            return false;
        }

        this.mayBeSpace();
        let hasMore = this.input[this.pos] !== CLOSE_PARENTHESIS;

        while (hasMore) {
            if (!this.mayBeType() || !this.mayBeIdentifier()) {
                break;
            }

            hasMore = false;

            const arg = [this._lastType, this._lastIdentifier];
            this.args.push(arg);

            this.mayBeSpace();

            if (this.pos < this.length && this.input[this.pos] === EQUALS) {
                this.pos++;
                this.mayBeSpace();
                if (!this.mayBeExpression()) {
                    break;
                }
                arg.push(this._lastExpression);
            }

            if (this.pos < this.length && this.input[this.pos] === COMMA) {
                this.pos++;
                hasMore = true;
            }
        }

        if (!hasMore) {
            this.mayBeSpace();
            if (this.pos === this.length || this.input[this.pos++] !== CLOSE_PARENTHESIS) {
                hasMore = true;
            }
        }

        if (!hasMore) {
            return true;
        }

        this.pos = pos;
        return false;
    }

    mayBeEnd() {
        this.mayBeSpace();

        if (this.pos === this.length || this.input[this.pos] !== SEMICOLON) {
            return false;
        }

        this.pos++;
        return true;
    }

    mayBeType() {
        this._lastType = undefined;

        if (this.pos === this.length) {
            return false;
        }

        const {pos} = this;

        this.mayBeSpace();

        const start = this.pos;

        if (!this.mayBeIdentifier()) {
            this.pos = pos;
            return false;
        }

        if (this._lastIdentifier === "const") {
            this.mayBeSpace();

            if (!this.mayBeIdentifier()) {
                this.pos = pos;
                return false;
            }
        }

        let end = this.pos;
        this.mayBeSpace();

        if (this.pos < this.length && this._lastIdentifier === "unsigned") {
            for (const type of UNSINED_TYPES) {
                if (this.input.startsWith(type, this.pos)) {
                    this.pos += type.length;
                    break;
                }
            }
        }

        if (this.input[this.pos] === COLON) {
            this.pos++;
            if (this.pos === this.length || this.input[this.pos++] !== COLON || !this.mayBeType()) {
                this.pos = pos;
                return false;
            }

            end = this.pos;
        } else if (this.input[this.pos] === AMPERS_LT) {
            this.pos++;
            if (!this.mayBeType()) {
                this.pos = pos;
                return false;
            }

            this.mayBeSpace();

            if (this.pos === this.length || this.input[this.pos++] !== AMPERS_GT) {
                this.pos = pos;
                return false;
            }

            end = this.pos;
        }

        this.mayBeSpace();

        if (this.pos < this.length && this.input[this.pos] === STAR) {
            end = ++this.pos;
            this.mayBeSpace();

            if (this.pos < this.length && this.input[this.pos] === STAR) {
                end = ++this.pos;
            }
        } else if (this.pos < this.length && this.input[this.pos] === AMPERS_AND) {
            end = ++this.pos;
            this.mayBeSpace();
        }

        this._lastType = this.input.slice(start, end).trim();
        return true;
    }
}

module.exports = ExportsParser;
