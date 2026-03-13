'use strict';

const https = require('https');
const http  = require('http');
const zlib  = require('zlib');
const fs    = require('fs');
const path  = require('path');
const os    = require('os');

/**
 * Downloader
 * cli.js에서 분리 — tarball 다운로드 + tar 추출 전담
 * cli.js가 이걸 직접 들고 있을 이유가 없음
 */

/**
 * URL 다운로드 → 파일 저장
 * @param {string} url
 * @param {string} destPath
 */
function download(url, destPath) {
  return new Promise((resolve, reject) => {
    const file = fs.createWriteStream(destPath);

    const request = (u) => {
      const protocol = u.startsWith('https') ? https : http;
      protocol.get(u, (res) => {
        // 리다이렉트 처리
        if (res.statusCode === 301 || res.statusCode === 302) {
          return request(res.headers.location);
        }
        if (res.statusCode !== 200) {
          reject(new Error(`Download failed: HTTP ${res.statusCode} for ${u}`));
          res.resume();
          return;
        }
        res.pipe(file);
        file.on('finish', () => file.close(resolve));
        file.on('error', (err) => {
          fs.unlink(destPath, () => {});
          reject(err);
        });
      }).on('error', (err) => {
        fs.unlink(destPath, () => {});
        reject(err);
      });
    };

    request(url);
  });
}

/**
 * .tgz 압축 해제
 * @param {string} tarballPath
 * @param {string} destPath
 */
function extract(tarballPath, destPath) {
  return new Promise((resolve, reject) => {
    if (!fs.existsSync(destPath)) {
      fs.mkdirSync(destPath, { recursive: true });
    }

    const input  = fs.createReadStream(tarballPath);
    const gunzip = zlib.createGunzip();
    let buffer   = Buffer.alloc(0);

    gunzip.on('data',  (chunk) => { buffer = Buffer.concat([buffer, chunk]); });
    gunzip.on('end',   () => {
      try {
        parseTar(buffer, destPath);
        resolve();
      } catch (e) {
        reject(e);
      }
    });
    gunzip.on('error', reject);
    input.on('error',  reject);
    input.pipe(gunzip);
  });
}

/**
 * TAR 파싱 — 순수 JS (외부 의존성 없음)
 * @param {Buffer} buffer
 * @param {string} destPath
 */
function parseTar(buffer, destPath) {
  let offset = 0;

  while (offset + 512 <= buffer.length) {
    const header = buffer.slice(offset, offset + 512);

    // 빈 블록 = 끝
    if (header.every(b => b === 0)) break;

    const name     = header.slice(0,   100).toString('utf-8').replace(/\0/g, '');
    const sizeOctal = header.slice(124, 136).toString('utf-8').replace(/\0/g, '').trim();
    const typeFlag  = header.slice(156, 157).toString('utf-8');
    const size      = parseInt(sizeOctal, 8) || 0;

    offset += 512;

    if (!name) {
      offset += Math.ceil(size / 512) * 512;
      continue;
    }

    const fullPath = path.join(destPath, name);
    // 경로 순회 공격 방어 (path traversal)
    if (!fullPath.startsWith(path.resolve(destPath))) {
      offset += Math.ceil(size / 512) * 512;
      continue;
    }

    const dir = typeFlag === '5' ? fullPath : path.dirname(fullPath);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });

    if (typeFlag !== '5' && size > 0) {
      fs.writeFileSync(fullPath, buffer.slice(offset, offset + size));
    }

    offset += Math.ceil(size / 512) * 512;
  }
}

/**
 * 패키지 다운로드 + 추출 원스톱
 * @param {string} pkgName
 * @param {string} version
 * @param {string} tarballUrl
 * @returns {string} extractPath
 */
async function downloadAndExtract(pkgName, version, tarballUrl) {
  const safeName  = pkgName.replace(/[@/]/g, '_');
  const tmpDir    = os.tmpdir();
  const tarballPath = path.join(tmpDir, `${safeName}-${version}.tgz`);
  const extractPath = path.join(tmpDir, `dryinstall-extract-${safeName}-${Date.now()}`);

  await download(tarballUrl, tarballPath);
  await extract(tarballPath, extractPath);

  // tarball 정리
  try { fs.unlinkSync(tarballPath); } catch {}

  return extractPath;
}

/**
 * 임시 추출 폴더 정리
 * @param {string} extractPath
 */
function cleanup(extractPath) {
  try {
    fs.rmSync(extractPath, { recursive: true, force: true });
  } catch {}
}

module.exports = { download, extract, downloadAndExtract, cleanup };
