const { spawn } = require("child_process");
const sysPath = require("path");

const version = process.env.npm_package_version || require("../package.json").version;
const sources = sysPath.resolve(__dirname, "..");

spawn("7z", ["a", sysPath.join(sources, `emgucv-autoit-bindings-v${ version }.zip`), "*"], {
    cwd: sysPath.join(sources, "emgucv-autoit-bindings"),
    stdio: "inherit"
});
