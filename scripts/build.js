const { spawn } = require("child_process");
const sysPath = require("path");

const version = process.env.npm_package_version || require("./package.json").version;

spawn("7z", ["a", sysPath.join(__dirname, `emgucv-autoit-bindings-v${ version }.zip`), "*"], {
    cwd: sysPath.join(__dirname, "emgucv-autoit-bindings"),
    stdio: "inherit"
});
