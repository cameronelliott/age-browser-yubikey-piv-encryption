// Checks the hand-written crypto in index.html against typage and the noble
// libraries. The page runs in headless Chromium, loaded from disk with its real
// CSP; bun only drives the browser and decrypts. None of the page code runs in bun.
import { test, expect, describe, beforeAll, afterAll } from "bun:test";
import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import * as age from "age-encryption";
import { bech32 } from "bech32";
import { p256 } from "@noble/curves/nist.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { chacha20poly1305 } from "@noble/ciphers/chacha.js";

const pageUrl = new URL("index.html", import.meta.url);
const html = readFileSync(pageUrl, "utf8");
const script = html.match(/<script>([\s\S]*?)<\/script>/)![1];
const style = html.match(/<style>([\s\S]*?)<\/style>/)![1];

// ---------- a minimal DevTools-protocol client ----------

let browser: ReturnType<typeof Bun.spawn>;
let profile: string;
let socket: WebSocket;
let nextId = 1;
const pending = new Map<number, (msg: any) => void>();

function send(method: string, params: object = {}): Promise<any> {
  const id = nextId++;
  socket.send(JSON.stringify({ id, method, params }));
  return new Promise((resolve) => pending.set(id, resolve));
}

// Evaluates a JS expression in the page and returns its (awaited) value.
async function run(expression: string): Promise<any> {
  const { result } = await send("Runtime.evaluate", { expression, awaitPromise: true, returnByValue: true });
  if (result.exceptionDetails) {
    const e = result.exceptionDetails.exception;
    throw new Error(e?.description ?? e?.value ?? result.exceptionDetails.text);
  }
  return result.result.value;
}

// Byte arrays cross the boundary as base64. B() writes one into an expression,
// runBytes() reads one back.
const B = (bytes: Uint8Array) => `Uint8Array.from(atob("${Buffer.from(bytes).toString("base64")}"), (c) => c.charCodeAt(0))`;
const S = (s: string) => JSON.stringify(s);
async function runBytes(expression: string) {
  const b64 = await run(`(async () => btoa(Array.from(await (${expression}), (b) => String.fromCharCode(b)).join("")))()`);
  return Uint8Array.from(Buffer.from(b64, "base64"));
}

// Picks a file in an <input type="file">, the way the file dialog would.
async function chooseFile(inputId: string, name: string, content: string | Uint8Array) {
  const path = join(profile, name);
  writeFileSync(path, content);
  const { result } = await send("Runtime.evaluate", { expression: `el(${S(inputId)})` });
  await send("DOM.setFileInputFiles", { files: [path], objectId: result.result.objectId });
}

beforeAll(async () => {
  profile = mkdtempSync(join(tmpdir(), "age-page-test-"));
  browser = Bun.spawn(
    ["chromium", "--headless=new", "--remote-debugging-port=0", `--user-data-dir=${profile}`, pageUrl.href],
    { stderr: "pipe", stdout: "ignore" },
  );
  let log = "";
  const decoder = new TextDecoder();
  for await (const chunk of browser.stderr as ReadableStream<Uint8Array>) {
    log += decoder.decode(chunk);
    if (/DevTools listening on ws:\/\/[^\s]+/.test(log)) break;
  }
  const port = log.match(/DevTools listening on ws:\/\/[^:]+:(\d+)/)![1];
  let target: any;
  for (let i = 0; i < 100 && !target; i++) {
    const targets = (await (await fetch(`http://127.0.0.1:${port}/json/list`)).json()) as any[];
    target = targets.find((t) => t.type === "page" && t.url === pageUrl.href);
    if (!target) await Bun.sleep(50);
  }
  socket = new WebSocket(target.webSocketDebuggerUrl);
  socket.onmessage = (event) => {
    const msg = JSON.parse(String(event.data));
    pending.get(msg.id)?.({ result: msg.result ?? {}, error: msg.error });
    pending.delete(msg.id);
  };
  await new Promise((resolve) => (socket.onopen = resolve));
  while ((await run("document.readyState")) !== "complete") await Bun.sleep(50);
});

afterAll(() => {
  socket?.close();
  browser?.kill();
  rmSync(profile, { recursive: true, force: true });
});

const unhex = (s: string) => Uint8Array.from(Buffer.from(s.replace(/\s/g, ""), "hex"));
const text = (s: string) => new TextEncoder().encode(s);
const random = (n: number) => {
  const out = new Uint8Array(n);
  for (let off = 0; off < n; off += 65536) crypto.getRandomValues(out.subarray(off, off + 65536));
  return out;
};

// Test-only decrypting side of age-plugin-yubikey, built on noble.
class SoftwareYubikey implements age.Identity {
  secret = p256.utils.randomSecretKey();
  publicKey = p256.getPublicKey(this.secret, true);
  recipient = bech32.encode("age1yubikey", bech32.toWords(this.publicKey), 1023);
  tag = Buffer.from(sha256(this.publicKey).subarray(0, 4)).toString("base64").replace(/=+$/, "");

  unwrapFileKey(stanzas: age.Stanza[]) {
    for (const s of stanzas) {
      if (s.args[0] !== "piv-p256" || s.args[1] !== this.tag) continue;
      const share = Uint8Array.from(Buffer.from(s.args[2], "base64"));
      const shared = p256.getSharedSecret(this.secret, share, true).subarray(1);
      const salt = new Uint8Array([...share, ...this.publicKey]);
      const key = hkdf(sha256, shared, salt, text("piv-p256"), 32);
      return chacha20poly1305(key, new Uint8Array(12)).decrypt(s.body);
    }
    return null;
  }
}

async function decrypt(file: Uint8Array, identity: string | age.Identity) {
  const d = new age.Decrypter();
  d.addIdentity(identity);
  return d.decrypt(file);
}

// Encrypts in the page, to a recipients list in the same text form the page takes.
const pageEncrypt = (recipients: string, msg: Uint8Array) =>
  runBytes(`parseRecipients(${S(recipients)}).then((r) => ageEncrypt(r, ${B(msg)}))`);

describe("primitives", () => {
  test("chacha20 matches RFC 8439 section 2.4.2", async () => {
    const key = unhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    const nonce = unhex("000000000000004a00000000");
    const msg = text("Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.");
    const expected = unhex(`
      6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0b
      f91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d8
      07ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab7793736
      5af90bbf74a35be6b40b8eedf2785e42874d`);
    expect(await runBytes(`chacha20Xor(${B(key)}, ${B(nonce)}, 1, ${B(msg)})`)).toEqual(expected);
  });

  test("poly1305 matches RFC 8439 section 2.5.2", async () => {
    const key = unhex("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b");
    const msg = text("Cryptographic Forum Research Group");
    expect(await runBytes(`poly1305(${B(key)}, ${B(msg)})`)).toEqual(unhex("a8061dc1305136c6c22b8baf0c0127a9"));
  });

  test("chacha20poly1305 matches noble for many lengths", async () => {
    for (const n of [0, 1, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129, 1000, 65536, 65537]) {
      const key = random(32), nonce = random(12), msg = random(n);
      const got = await runBytes(`chacha20poly1305Seal(${B(key)}, ${B(nonce)}, ${B(msg)})`);
      expect(got).toEqual(chacha20poly1305(key, nonce).encrypt(msg));
    }
  });

  test("bech32 decode matches the bech32 package", async () => {
    const x = await age.identityToRecipient(await age.generateX25519Identity());
    for (const s of [x, new SoftwareYubikey().recipient]) {
      const ref = bech32.decode(s, 1023);
      expect(await run(`bech32Decode(${S(s)}).hrp`)).toBe(ref.prefix);
      expect(await runBytes(`bech32Decode(${S(s)}).bytes`)).toEqual(Uint8Array.from(bech32.fromWords(ref.words)));
    }
  });

  test("bech32 decode rejects a corrupted string", async () => {
    const good = new SoftwareYubikey().recipient;
    const bad = good.slice(0, -1) + (good.endsWith("q") ? "p" : "q");
    await expect(run(`bech32Decode(${S(bad)})`)).rejects.toThrow("bad checksum");
    await expect(run(`bech32Decode(${S(good.toUpperCase())})`)).rejects.toThrow("lower case");
  });

  test("p256 decompress matches noble", async () => {
    for (let i = 0; i < 50; i++) {
      const secret = p256.utils.randomSecretKey();
      const got = await runBytes(`p256Decompress(${B(p256.getPublicKey(secret, true))})`);
      expect(got).toEqual(p256.getPublicKey(secret, false));
    }
  });

  test("p256 decompress rejects an x that is not on the curve", async () => {
    // Roughly half of all x values have no matching y; find one.
    const point = p256.getPublicKey(p256.utils.randomSecretKey(), true);
    for (;;) {
      point[32]++;
      try { p256.Point.fromBytes(point); } catch { break; }
    }
    await expect(run(`p256Decompress(${B(point)})`)).rejects.toThrow("not a P-256 point");
  });
});

describe("age files", () => {
  const sizes = [0, 1, 300, 65535, 65536, 65537, 131072, 200000];

  test("typage decrypts files made for an age1 recipient", async () => {
    const identity = await age.generateX25519Identity();
    const recipient = await age.identityToRecipient(identity);
    expect(await run(`parseRecipient(${S(recipient)}).then((r) => r.kind)`)).toBe("X25519");
    for (const n of sizes) {
      const msg = random(n);
      expect(await decrypt(await pageEncrypt(recipient, msg), identity)).toEqual(msg);
    }
  });

  test("typage decrypts files made for an age1yubikey1 recipient", async () => {
    const yubikey = new SoftwareYubikey();
    expect(await run(`parseRecipient(${S(yubikey.recipient)}).then((r) => r.kind)`)).toBe("YubiKey");
    for (const n of sizes) {
      const msg = random(n);
      expect(await decrypt(await pageEncrypt(yubikey.recipient, msg), yubikey)).toEqual(msg);
    }
  });

  test("every recipient of a mixed list can decrypt", async () => {
    const identity = await age.generateX25519Identity();
    const yubikeys = [new SoftwareYubikey(), new SoftwareYubikey()];
    const list = ["# a comment", await age.identityToRecipient(identity), "", ...yubikeys.map((y) => y.recipient)].join("\n");
    expect(await run(`parseRecipients(${S(list)}).then((r) => r.length)`)).toBe(3);

    const msg = text("hunter2\nuser: me\n");
    const file = await pageEncrypt(list, msg);
    for (const who of [identity, ...yubikeys]) expect(await decrypt(file, who)).toEqual(msg);
    await expect(decrypt(file, new SoftwareYubikey())).rejects.toThrow();
  });

  test("the yubikey id is the name age-plugin-yubikey gives the identity", async () => {
    // A throwaway key made for this test; its private half was discarded.
    const r = "age1yubikey1qweykhzlwtangswznc6p80uxkcwsefarsqt9ux5lzw507w9nzn9fsyf6864";
    expect(await run(`parseRecipient(${S(r)}).then((r) => r.id)`)).toBe("9f0be82b");
  });

  test("bad input is refused", async () => {
    await expect(pageEncrypt("# ok\nage1nonsense", random(1))).rejects.toThrow("recipients line 2");
    await expect(pageEncrypt("# nobody", random(1))).rejects.toThrow("no recipients");
  });

  test("armor matches typage", async () => {
    for (const n of [0, 1, 47, 48, 49, 1000]) {
      const file = random(n);
      expect(await run(`armor(${B(file)})`)).toBe(age.armor.encode(file));
    }
  });

  test("padding only adds trailing newlines, up to a multiple of 256", async () => {
    for (const n of [0, 1, 255, 256, 257, 1000]) {
      const msg = random(n).map((b) => b || 1);
      const padded = await runBytes(`padPlaintext(${B(msg)})`);
      expect(padded.length % 256).toBe(0);
      expect(padded.length).toBeGreaterThanOrEqual(Math.max(n, 256));
      expect(padded.length - n).toBeLessThanOrEqual(256);
      expect(padded.subarray(0, n)).toEqual(msg);
      expect(padded.subarray(n).every((b) => b === 10)).toBe(true);
    }
  });
});

describe("the page itself", () => {
  test("no recipients are built in", async () => {
    expect(html).not.toContain("age1yubikey1q");
    expect(await run(`el("recipients").value`)).toBe("");
    expect(await run(`el("recipient-status").textContent`)).toBe("0 recipient(s)");
  });

  test("the form encrypts, clears the secret, and the result decrypts", async () => {
    const identity = await age.generateX25519Identity();
    const yubikey = new SoftwareYubikey();
    const recipients = `${await age.identityToRecipient(identity)}\n# hardware\n${yubikey.recipient}\n`;
    const secret = "correct horse\nuser: me";
    await run(`
      el("recipients").value = ${S(recipients)};
      el("label").value = "bank-test";
      el("secret").value = ${S(secret)};
      el("encrypt").click();`);
    while (!(await run(`el("status").textContent`))) await Bun.sleep(20);

    expect(await run(`el("status").textContent`)).toStartWith("Encrypted bank-test.age to 2 recipient(s)");
    expect(await run(`el("secret").value`)).toBe("");
    expect(await run(`el("download").disabled || el("copy").disabled`)).toBe(false);
    expect(await run(`result.name`)).toBe("bank-test.age");

    const file = age.armor.decode(await run(`el("output").value`));
    const expected = text(secret.padEnd(256, "\n"));
    expect(await decrypt(file, identity)).toEqual(expected);
    expect(await decrypt(file, yubikey)).toEqual(expected);
  });

  test("the form refuses a label that is not a plain file name", async () => {
    await run(`el("label").value = "../x"; el("secret").value = "s"; el("status").textContent = ""; el("encrypt").click();`);
    while (!(await run(`el("status").textContent`))) await Bun.sleep(20);
    expect(await run(`el("status").textContent`)).toStartWith("Error: label");
    expect(await run(`el("secret").value`)).toBe("s");
  });

  test("recipients load from a file", async () => {
    const yubikey = new SoftwareYubikey();
    const list = `# from a file\n${yubikey.recipient}\n`;
    await chooseFile("recipients-file", "recipients.txt", list);
    while ((await run(`el("recipients").value`)) !== list) await Bun.sleep(20);
    while (!(await run(`el("recipient-status").textContent`)).startsWith("1 recipient(s): YubiKey")) await Bun.sleep(20);
  });

  test("a secret file is encrypted byte for byte and then dropped", async () => {
    const yubikey = new SoftwareYubikey();
    const bytes = new Uint8Array([...random(1000), 13, 10, 0, 255, 13, 10]);
    await chooseFile("secret-file", "recovery codes.bin", bytes);
    await run(`el("recipients").value = ${S(yubikey.recipient)}; el("label").value = ""; el("secret").value = "";
      el("status").textContent = ""; el("encrypt").click();`);
    while (!(await run(`el("status").textContent`))) await Bun.sleep(20);
    expect(await run(`el("status").textContent`)).toStartWith("Error: label"); // the file name has a space

    await run(`el("label").value = "codes"; el("secret").value = "typed too"; el("status").textContent = ""; el("encrypt").click();`);
    while (!(await run(`el("status").textContent`))) await Bun.sleep(20);
    expect(await run(`el("status").textContent`)).toStartWith("Error: a file is chosen and a secret is typed");

    await run(`el("secret").value = ""; el("status").textContent = ""; el("encrypt").click();`);
    while (!(await run(`el("status").textContent`))) await Bun.sleep(20);
    expect(await run(`el("status").textContent`)).toStartWith("Encrypted codes.age to 1 recipient(s)");
    expect(await run(`el("secret-file").files.length`)).toBe(0);
    expect(await decrypt(age.armor.decode(await run(`el("output").value`)), yubikey)).toEqual(bytes);
  });

  test("a file name that is a plain name becomes the label", async () => {
    const yubikey = new SoftwareYubikey();
    await chooseFile("secret-file", "notes.txt", "line one\r\nline two");
    await run(`el("recipients").value = ${S(yubikey.recipient)}; el("label").value = ""; el("status").textContent = ""; el("encrypt").click();`);
    while (!(await run(`el("status").textContent`))) await Bun.sleep(20);
    expect(await run(`result.name`)).toBe("notes.txt.age");
    expect(await decrypt(age.armor.decode(await run(`el("output").value`)), yubikey)).toEqual(text("line one\r\nline two"));
  });

  test("download asks where to save, and falls back to a plain download", async () => {
    const yubikey = new SoftwareYubikey();
    await run(`el("recipients").value = ${S(yubikey.recipient)}; el("label").value = "save-test"; el("secret").value = "s";
      el("status").textContent = ""; el("encrypt").click();`);
    while (!(await run(`el("status").textContent`))) await Bun.sleep(20);
    const output = await run(`el("output").value`);

    // Stand-ins for the native save dialog and for the download link, so nothing touches the disk.
    await run(`
      var picker = "save", saved = null, downloads = [];
      window.showSaveFilePicker = async (options) => {
        if (picker !== "save") throw new DOMException("no", picker);
        return { name: options.suggestedName, createWritable: async () => ({ write: async (data) => { saved = data; }, close: async () => {} }) };
      };
      HTMLAnchorElement.prototype.click = function () { downloads.push(this.download); };`);
    const click = async () => {
      await run(`el("status").textContent = ""; el("download").click()`);
      await Bun.sleep(50);
      return run(`({ status: el("status").textContent, saved, downloads })`);
    };

    expect(await click()).toEqual({ status: "Saved save-test.age.", saved: output, downloads: [] });

    await run(`picker = "AbortError"; saved = null`);
    expect(await click()).toEqual({ status: "", saved: null, downloads: [] });

    await run(`picker = "SecurityError"`);
    expect(await click()).toEqual({ status: "", saved: null, downloads: ["save-test.age"] });

    await run(`window.showSaveFilePicker = undefined`);
    expect((await click()).downloads).toEqual(["save-test.age", "save-test.age"]);
  });

  test("the light / dark switch flips the colors without script", async () => {
    const background = () => run(`getComputedStyle(document.body).backgroundColor`);
    const before = await background();
    await run(`el("theme").click()`);
    expect(await background()).not.toBe(before);
    await run(`el("theme").click()`);
    expect(await background()).toBe(before);
    expect(script).not.toContain("theme");
  });

  test("the browser enforces the CSP: network requests are blocked", async () => {
    const violated = await run(`new Promise((resolve) => {
      document.addEventListener("securitypolicyviolation", (e) => resolve(e.effectiveDirective), { once: true });
      fetch("https://example.invalid/").catch(() => {});
    })`);
    expect(violated).toBe("connect-src");
  });
});

describe("page hygiene", () => {
  test("the CSP hashes match the inline blocks", () => {
    const hash = (s: string) => "sha256-" + createHash("sha256").update(s).digest("base64");
    expect(html).toContain(`script-src '${hash(script)}'`);
    expect(html).toContain(`style-src '${hash(style)}'`);
    expect(html).toContain("default-src 'none'");
  });

  test("there is exactly one script and no external resources", () => {
    expect(html.match(/<script/g)!.length).toBe(1);
    expect(html.match(/<style/g)!.length).toBe(1);
    const markup = html.replace(script, "").replace(style, "").replace(/<meta http-equiv[^>]*>/, "");
    expect(markup).not.toMatch(/<(link|iframe|img|form|object|embed|base|a)\b/i);
    expect(markup).not.toMatch(/\b(src|href|action|style|on[a-z]+)\s*=/i);
    expect(html).not.toMatch(/https?:/);
  });

  // A tripwire, not a proof: none of the ways to move data off the page, keep
  // it around, or run other code should appear anywhere in the script.
  test("the script uses no network, storage or dynamic code APIs", () => {
    const banned = [
      "fetch", "XMLHttpRequest", "WebSocket", "EventSource", "sendBeacon", "RTCPeerConnection",
      "location", "open", "navigate", "history", "postMessage", "Worker", "serviceWorker",
      "localStorage", "sessionStorage", "indexedDB", "cookie", "caches",
      "eval", "Function", "import", "setTimeout", "setInterval",
      "innerHTML", "outerHTML", "insertAdjacentHTML", "writeln", "src", "window", "globalThis", "self", "top", "parent",
    ];
    expect(banned.filter((word) => new RegExp(`\\b${word}\\b`).test(script))).toEqual([]);
    // The only write is to the file chosen in the save dialog.
    expect(script.match(/\bwrite\b/g)).toEqual(["write"]);
    expect(script).toContain("await stream.write(text);");
    expect(script.match(/createElement\(/g)!.length).toBe(1);
    expect(script).toContain('createElement("a")');
    expect(script).not.toMatch(/[\w)\]]\[\s*["'`]/); // no obj["name"] access to dodge the list
  });
});
