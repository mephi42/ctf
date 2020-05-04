var magikarp = [
    [0, 0, 0, 0],
    [1, 0, 0, 1],
    [1, 1, 1, 1],
    [0, 1, 0, 0],
    [1, 0, 0, 0],
    [0, 0, 1, 0],
    [1, 1, 0, 0],
    [0, 0, 0, 1],
    [0, 1, 0, 1],
    [1, 0, 1, 0],
    [1, 0, 1, 1],
    [1, 1, 0, 1],
    [0, 1, 1, 1],
    [0, 1, 1, 0],
    [1, 1, 1, 0],
    [0, 0, 1, 1],
    [0, 0, 0, 0],
];
var goldeen = magikarp.map(function (x) { return parseInt(x.join(""), 2).toString(16); }).join("");
var stunfisk = "";
for (var i_1 = 0; i_1 < 1000000; i_1++) {
    stunfisk = require("crypto").createHash("sha512").update(stunfisk).update(goldeen).digest("hex");
}
var feebas = Buffer.from(stunfisk, "hex");
var reLessid = Buffer.from("0ac503f1627b0c4f03be24bc38db102e39f13d40d33e8f87f1ff1a48f63a02541dc71d37edb35e8afe58f31d72510eafe042c06b33d2e037e8f93cd31cba07d7", "hex");
for (var i = 0; i < 64; i++) {
    feebas[i] ^= reLessid[i];
}
console.log(feebas.toString("utf-8"));
