const LF = "\n";
const IF_DEF_WINAPI_FAMILY = "#if WINAPI_FAMILY";
const ENDIF = "#endif";
const BLOC_COMMENT_START = "/*";
const BLOC_COMMENT_END = "*/";
const OPEN_PARENTHESIS = "(".charCodeAt(0);
const CLOSE_PARENTHESIS = ")".charCodeAt(0);
const COLON = ":".charCodeAt(0);
const COMMA = ",".charCodeAt(0);
const GT = ">".charCodeAt(0);
const LT = "<".charCodeAt(0);
const SEMICOLON = ";".charCodeAt(0);
const STAR = "*".charCodeAt(0);
const EQUALS = "=".charCodeAt(0);
const SLASH = "/".charCodeAt(0);


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
].sort(({length: a}, {length: b}) => b - a).map(type => Buffer.from(type));

class ExportsParser {
    constructor(noexception = false, options = {}) {
        this.noexception = noexception;
        this.init(options);
    }

    init(options) {
        this.options = options;
        const {start: export_start, end: export_end} = options.exports;
        this.export_start = export_start;
        this.export_end = Buffer.from(export_end);
        this.export_end_is_space = !notSpaceRe.test(export_end);
        this.tokenizer = new RegExp(`(?:^/[/*]|^${ export_start.replace(/[-/\\^$*+?.()|[\]{}]/g, "\\$&") }|#if WINAPI_FAMILY)`, "mg");
    }

    parseFile(buffer, offset = 0) {
        const {tokenizer} = this;

        let match;

        tokenizer.lastIndex = offset;

        const api = [];

        while ((match = tokenizer.exec(buffer)) !== null) {
            if (match[0] === "//") {
                tokenizer.lastIndex = buffer.indexOf(LF, match.index) + LF.length;
                if (tokenizer.lastIndex - LF.length === -1) {
                    tokenizer.lastIndex = buffer.length;
                }
                continue;
            }

            if (match[0] === BLOC_COMMENT_START) {
                tokenizer.lastIndex = buffer.indexOf(BLOC_COMMENT_END, match.index) + BLOC_COMMENT_END.length;
                if (tokenizer.lastIndex - BLOC_COMMENT_END.length === -1) {
                    tokenizer.lastIndex = buffer.length;
                }
                continue;
            }

            if (match[0] === IF_DEF_WINAPI_FAMILY) {
                tokenizer.lastIndex = buffer.indexOf(ENDIF, match.index) + ENDIF.length;
                if (tokenizer.lastIndex - ENDIF.length === -1) {
                    tokenizer.lastIndex = buffer.length;
                }
                continue;
            }

            this.parse(buffer, match.index);

            if (this.lastError) {
                return null;
            }

            api.push([this.returnType, this.name, this.args]);
        }

        return api;
    }

    parse(buffer, pos) {
        this.start = pos;
        pos += this.export_start.length;

        this.buffer = buffer;
        this.length = this.buffer.length;

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
        const match = crlfRe.exec(this.buffer);
        const eof = match === null ? this.length : match.index;
        const win = 40;
        const start = Math.max(this.start, this.pos - win);
        const end = Math.min(eof, this.pos + win);
        const msg = `Unexpected token ${ this.buffer.slice(start, end).toString() }`;
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
            return this.pos - 1 !== -1 && !notSpaceRe.test(this.buffer[this.pos - 1]);
        }
        
        if (!this.buffer.slice(this.pos, this.pos + this.export_end.length).equals(this.export_end)) {
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
            const match = notSpaceRe.exec(this.buffer);
            this.pos = match === null ? this.length : match.index;
            trim = false;

            if (this.pos + 1 < this.length && this.buffer[this.pos] === SLASH) {
                if (this.buffer[this.pos + 1] === SLASH) {
                    this.pos = this.buffer.indexOf(LF, this.pos + 2) + 1;
                    if (this.pos === 0) {
                        this.pos = this.length;
                    } else {
                        notSpaceRe.lastIndex = this.pos;
                        trim = true;
                    }
                } else if (this.buffer[this.pos + 1] === STAR) {
                    this.pos = this.buffer.indexOf(BLOC_COMMENT_END, this.pos + 2) + 2;
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
        const match = notIdenvifierRe.exec(this.buffer);
        this.pos = match === null ? this.length : match.index;

        if (this.pos !== start) {
            this._lastIdentifier = this.buffer.slice(start, this.pos).toString();
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

        if (this.pos === this.length || this.buffer[this.pos++] !== OPEN_PARENTHESIS) {
            this.pos = pos;
            return false;
        }

        this.mayBeSpace();
        let hasMore = this.buffer[this.pos] !== CLOSE_PARENTHESIS;

        while (hasMore) {
            if (!this.mayBeType() || !this.mayBeIdentifier()) {
                break;
            }

            hasMore = false;

            const arg = [this._lastType, this._lastIdentifier];
            this.args.push(arg);

            this.mayBeSpace();

            if (this.pos < this.length && this.buffer[this.pos] === EQUALS) {
                this.pos++;
                this.mayBeSpace();
                if (!this.mayBeIdentifier()) {
                    break;
                }
                arg.push(this._lastIdentifier);
            }

            if (this.pos < this.length && this.buffer[this.pos] === COMMA) {
                this.pos++;
                hasMore = true;
            }
        }

        if (!hasMore) {
            this.mayBeSpace();
            if (this.pos === this.length || this.buffer[this.pos++] !== CLOSE_PARENTHESIS) {
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

        if (this.pos === this.length || this.buffer[this.pos] !== SEMICOLON) {
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
                if (this.pos + type.length <= this.length && type.compare(this.buffer, this.pos, this.pos + type.length) === 0) {
                    this.pos += type.length;
                    break;
                }
            }
        }

        if (this.buffer[this.pos] === COLON) {
            this.pos++;
            if (this.pos === this.length || this.buffer[this.pos++] !== COLON || !this.mayBeType()) {
                this.pos = pos;
                return false;
            }

            end = this.pos;
        } else if (this.buffer[this.pos] === LT) {
            this.pos++;
            if (!this.mayBeType()) {
                this.pos = pos;
                return false;
            }

            this.mayBeSpace();

            if (this.pos === this.length || this.buffer[this.pos++] !== GT) {
                this.pos = pos;
                return false;
            }

            end = this.pos;
        }

        this.mayBeSpace();

        if (this.pos < this.length && this.buffer[this.pos] === STAR) {
            end = ++this.pos;
            this.mayBeSpace();

            if (this.pos < this.length && this.buffer[this.pos] === STAR) {
                end = ++this.pos;
            }
        }

        this._lastType = this.buffer.slice(start, end).toString().trim();
        return true;
    }
}

module.exports = ExportsParser;
