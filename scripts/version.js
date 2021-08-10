const { spawn } = require("child_process");
const sysPath = require("path");
const fs = require("fs");
const series = require("async/series");

const regexEscape = str => {
    return str.replace(/[-/\\^$*+?.()|[\]{}]/g, "\\$&");
};

const version = process.env.npm_package_version || require("./package.json").version;
const readme = sysPath.join(__dirname, "README.md");

series([
    next => {
        const oldReadmeContent = fs.readFileSync(readme).toString();
        const pos = oldReadmeContent.indexOf("emgucv-autoit-bindings-v");
        const oldVersion = oldReadmeContent.slice(pos + "emgucv-autoit-bindings-v".length, oldReadmeContent.indexOf(".zip", pos));
        const newReadmeContent = oldReadmeContent.replace(new RegExp(regexEscape(oldVersion), "g"), version);

        if (newReadmeContent === oldReadmeContent) {
            next();
            return;
        }

        fs.writeFile(readme, newReadmeContent, next);
    },

    next => {
        const child = spawn("git", ["add", readme], {
            stdio: "inherit"
        });

        child.on("error", next);
        child.on("close", next);
    }
], err => {
    if (err) {
        throw err;
    }
});
