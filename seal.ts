// Recomputes the CSP hashes for the inline <style> and <script> blocks.
//   bun seal.ts index.html                       reseal in place
//   bun seal.ts index.html styles/x.css out.html  swap the style block, write a copy
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";

const [input, cssFile, output = input] = process.argv.slice(2);
if (!input) throw new Error("usage: bun seal.ts <page.html> [style.css] [out.html]");

let html = readFileSync(input, "utf8");
if (cssFile) {
  const css = readFileSync(cssFile, "utf8");
  html = html.replace(/<style>[\s\S]*?<\/style>/, () => `<style>\n${css}</style>`);
}

const hashOf = (tag: string) => {
  const body = html.match(new RegExp(`<${tag}>([\\s\\S]*?)</${tag}>`))![1];
  return "sha256-" + createHash("sha256").update(body).digest("base64");
};
html = html
  .replace(/script-src 'sha256-[^']*'/, `script-src '${hashOf("script")}'`)
  .replace(/style-src 'sha256-[^']*'/, `style-src '${hashOf("style")}'`);

writeFileSync(output, html);
console.log(`${output}: sha256 ${createHash("sha256").update(html).digest("hex")}`);
