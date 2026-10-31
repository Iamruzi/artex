#!/usr/bin/env node

import fs from "node:fs";
import { spawnSync } from "node:child_process";
import { createRequire } from "node:module";
import os from "node:os";
import path from "node:path";
import process from "node:process";
import { fileURLToPath, pathToFileURL } from "node:url";

const MAX_IMAGE_BYTES = 10 * 1024 * 1024;
const ALLOWED_EXTENSIONS = new Set([".png", ".jpg", ".jpeg", ".webp", ".bmp", ".tif", ".tiff"]);

function fail(message, code = 1) {
  process.stderr.write(`${JSON.stringify({ ok: false, error: message })}\n`);
  process.exit(code);
}

if (process.argv.includes("--help") || process.argv.includes("-h")) {
  process.stdout.write("Usage: node ocr-image.mjs <local-image-path> [language=eng]\n");
  process.exit(0);
}

const imageArg = process.argv[2];
const language = (process.argv[3] || "eng").trim();
if (!imageArg) fail("missing local image path", 2);
if (!/^[A-Za-z0-9_+.-]{2,32}$/.test(language)) fail("invalid language identifier", 2);

const imagePath = path.resolve(imageArg);
if (!ALLOWED_EXTENSIONS.has(path.extname(imagePath).toLowerCase())) {
  fail("unsupported image extension", 2);
}

let stat;
try {
  stat = fs.statSync(imagePath);
} catch {
  fail("image does not exist or is not readable", 2);
}
if (!stat.isFile()) fail("image path is not a file", 2);
if (stat.size <= 0 || stat.size > MAX_IMAGE_BYTES) fail("image must be between 1 byte and 10 MiB", 2);

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const runtimeRoot = path.resolve(
  process.env.ARTEX_OCR_RUNTIME_DIR ||
    (process.env.LOCALAPPDATA
      ? path.join(process.env.LOCALAPPDATA, "ARTEX", "node-runtime", "browser-challenge-testing")
      : path.join(os.homedir(), ".cache", "artex", "node-runtime", "browser-challenge-testing")),
);

function resolveTesseract() {
  try {
    const runtimeRequire = createRequire(path.join(runtimeRoot, "loader.cjs"));
    return runtimeRequire.resolve("tesseract.js");
  } catch {
    return "";
  }
}

let tesseractEntry = resolveTesseract();
if (!tesseractEntry) {
  fs.mkdirSync(runtimeRoot, { recursive: true });
  for (const name of ["package.json", "package-lock.json"]) {
    fs.copyFileSync(path.join(scriptDir, name), path.join(runtimeRoot, name));
  }
  process.stderr.write(`${JSON.stringify({ ok: true, status: "installing OCR runtime", runtime: runtimeRoot })}\n`);
  const npmArgs = ["ci", "--ignore-scripts", "--no-audit", "--no-fund"];
  const installCommand = process.platform === "win32" ? process.env.ComSpec || "cmd.exe" : "npm";
  const installArgs = process.platform === "win32" ? ["/d", "/s", "/c", "npm.cmd", ...npmArgs] : npmArgs;
  const install = spawnSync(installCommand, installArgs, {
    cwd: runtimeRoot,
    stdio: "inherit",
    windowsHide: true,
  });
  if (install.error || install.status !== 0) {
    const detail = install.error?.message || `exit ${install.status}${install.signal ? ` signal ${install.signal}` : ""}`;
    fail(`failed to install locked tesseract.js runtime in ${runtimeRoot}: ${detail}`, 3);
  }
  tesseractEntry = resolveTesseract();
  if (!tesseractEntry) fail("tesseract.js installation completed but the module is still unavailable", 3);
}

let createWorker;
try {
  ({ createWorker } = await import(pathToFileURL(tesseractEntry).href));
} catch {
  fail("tesseract.js runtime could not be loaded", 3);
}

let worker;
try {
  const cacheRoot = process.env.LOCALAPPDATA
    ? path.join(process.env.LOCALAPPDATA, "ARTEX", "tesseract-cache")
    : path.join(os.homedir(), ".cache", "artex", "tesseract-cache");
  fs.mkdirSync(cacheRoot, { recursive: true });
  worker = await createWorker(language, 1, { cachePath: cacheRoot });
  const result = await worker.recognize(imagePath);
  const text = String(result?.data?.text || "").replace(/\r\n/g, "\n").trim();
  const confidence = Number(result?.data?.confidence);
  process.stdout.write(`${JSON.stringify({
    ok: true,
    file: imagePath,
    language,
    text,
    confidence: Number.isFinite(confidence) ? confidence : null,
  })}\n`);
} catch (error) {
  fail(`OCR failed: ${error instanceof Error ? error.message : String(error)}`);
} finally {
  if (worker) {
    try {
      await worker.terminate();
    } catch {
      // Process is exiting; termination is best-effort.
    }
  }
}
