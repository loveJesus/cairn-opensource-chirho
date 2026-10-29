// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16
//
// Fetch and run a public RuntimePackageChirho artifact through the tiny bytes-ABI host.

import { runNodeChirho } from "./host-chirho.js";

const BLAKE3_IV_CHIRHO = [
  0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
  0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];
const BLAKE3_MSG_PERMUTATION_CHIRHO = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8];
const BLAKE3_BLOCK_LEN_CHIRHO = 64;
const BLAKE3_CHUNK_LEN_CHIRHO = 1024;
const BLAKE3_CHUNK_START_CHIRHO = 1;
const BLAKE3_CHUNK_END_CHIRHO = 2;
const BLAKE3_PARENT_CHIRHO = 4;
const BLAKE3_ROOT_CHIRHO = 8;
const CONTENT_HASH_HEX_CHIRHO = /^[0-9a-f]{64}$/;

function add32Chirho(aChirho, bChirho) {
  return (aChirho + bChirho) >>> 0;
}

function rotr32Chirho(valueChirho, bitsChirho) {
  return ((valueChirho >>> bitsChirho) | (valueChirho << (32 - bitsChirho))) >>> 0;
}

function gChirho(stateChirho, aChirho, bChirho, cChirho, dChirho, xChirho, yChirho) {
  stateChirho[aChirho] = add32Chirho(add32Chirho(stateChirho[aChirho], stateChirho[bChirho]), xChirho);
  stateChirho[dChirho] = rotr32Chirho(stateChirho[dChirho] ^ stateChirho[aChirho], 16);
  stateChirho[cChirho] = add32Chirho(stateChirho[cChirho], stateChirho[dChirho]);
  stateChirho[bChirho] = rotr32Chirho(stateChirho[bChirho] ^ stateChirho[cChirho], 12);
  stateChirho[aChirho] = add32Chirho(add32Chirho(stateChirho[aChirho], stateChirho[bChirho]), yChirho);
  stateChirho[dChirho] = rotr32Chirho(stateChirho[dChirho] ^ stateChirho[aChirho], 8);
  stateChirho[cChirho] = add32Chirho(stateChirho[cChirho], stateChirho[dChirho]);
  stateChirho[bChirho] = rotr32Chirho(stateChirho[bChirho] ^ stateChirho[cChirho], 7);
}

function roundChirho(stateChirho, messageChirho) {
  gChirho(stateChirho, 0, 4, 8, 12, messageChirho[0], messageChirho[1]);
  gChirho(stateChirho, 1, 5, 9, 13, messageChirho[2], messageChirho[3]);
  gChirho(stateChirho, 2, 6, 10, 14, messageChirho[4], messageChirho[5]);
  gChirho(stateChirho, 3, 7, 11, 15, messageChirho[6], messageChirho[7]);
  gChirho(stateChirho, 0, 5, 10, 15, messageChirho[8], messageChirho[9]);
  gChirho(stateChirho, 1, 6, 11, 12, messageChirho[10], messageChirho[11]);
  gChirho(stateChirho, 2, 7, 8, 13, messageChirho[12], messageChirho[13]);
  gChirho(stateChirho, 3, 4, 9, 14, messageChirho[14], messageChirho[15]);
}

function permuteChirho(wordsChirho) {
  return BLAKE3_MSG_PERMUTATION_CHIRHO.map((indexChirho) => wordsChirho[indexChirho]);
}

function wordsFromBlockChirho(blockChirho) {
  const wordsChirho = new Array(16).fill(0);
  for (let iChirho = 0; iChirho < blockChirho.length; iChirho += 1) {
    wordsChirho[iChirho >> 2] |= blockChirho[iChirho] << ((iChirho & 3) * 8);
  }
  return wordsChirho.map((wordChirho) => wordChirho >>> 0);
}

function compressChirho(cvChirho, blockWordsChirho, counterChirho, blockLenChirho, flagsChirho) {
  const stateChirho = [
    ...cvChirho,
    BLAKE3_IV_CHIRHO[0], BLAKE3_IV_CHIRHO[1], BLAKE3_IV_CHIRHO[2], BLAKE3_IV_CHIRHO[3],
    counterChirho >>> 0,
    Math.floor(counterChirho / 0x100000000) >>> 0,
    blockLenChirho,
    flagsChirho,
  ];
  let messageChirho = blockWordsChirho.slice();
  for (let roundChirhoIndex = 0; roundChirhoIndex < 7; roundChirhoIndex += 1) {
    roundChirho(stateChirho, messageChirho);
    messageChirho = permuteChirho(messageChirho);
  }
  const outputChirho = new Array(16);
  for (let iChirho = 0; iChirho < 8; iChirho += 1) {
    outputChirho[iChirho] = (stateChirho[iChirho] ^ stateChirho[iChirho + 8]) >>> 0;
    outputChirho[iChirho + 8] = (stateChirho[iChirho + 8] ^ cvChirho[iChirho]) >>> 0;
  }
  return outputChirho;
}

function chunkOutputChirho(bytesChirho, chunkCounterChirho) {
  let cvChirho = BLAKE3_IV_CHIRHO.slice();
  const blockCountChirho = Math.max(1, Math.ceil(bytesChirho.length / BLAKE3_BLOCK_LEN_CHIRHO));
  for (let blockIndexChirho = 0; blockIndexChirho < blockCountChirho; blockIndexChirho += 1) {
    const blockStartChirho = blockIndexChirho * BLAKE3_BLOCK_LEN_CHIRHO;
    const blockChirho = bytesChirho.slice(blockStartChirho, blockStartChirho + BLAKE3_BLOCK_LEN_CHIRHO);
    let flagsChirho = 0;
    if (blockIndexChirho === 0) flagsChirho |= BLAKE3_CHUNK_START_CHIRHO;
    if (blockIndexChirho === blockCountChirho - 1) {
      flagsChirho |= BLAKE3_CHUNK_END_CHIRHO;
      return {
        cv_chirho: cvChirho,
        block_words_chirho: wordsFromBlockChirho(blockChirho),
        counter_chirho: chunkCounterChirho,
        block_len_chirho: blockChirho.length,
        flags_chirho: flagsChirho,
      };
    }
    cvChirho = compressChirho(
      cvChirho,
      wordsFromBlockChirho(blockChirho),
      chunkCounterChirho,
      BLAKE3_BLOCK_LEN_CHIRHO,
      flagsChirho,
    ).slice(0, 8);
  }
  throw new Error("unreachable BLAKE3 chunk state");
}

function outputChainingValueChirho(outputChirho) {
  return compressChirho(
    outputChirho.cv_chirho,
    outputChirho.block_words_chirho,
    outputChirho.counter_chirho,
    outputChirho.block_len_chirho,
    outputChirho.flags_chirho,
  ).slice(0, 8);
}

function parentOutputChirho(leftCvChirho, rightCvChirho) {
  return {
    cv_chirho: BLAKE3_IV_CHIRHO.slice(),
    block_words_chirho: [...leftCvChirho, ...rightCvChirho],
    counter_chirho: 0,
    block_len_chirho: BLAKE3_BLOCK_LEN_CHIRHO,
    flags_chirho: BLAKE3_PARENT_CHIRHO,
  };
}

function largestPowerOfTwoLessThanChirho(valueChirho) {
  let powerChirho = 1;
  while (powerChirho * 2 < valueChirho) powerChirho *= 2;
  return powerChirho;
}

function subtreeChainingValueChirho(chunkOutputsChirho, startChirho, countChirho) {
  if (countChirho === 1) {
    return outputChainingValueChirho(chunkOutputsChirho[startChirho]);
  }
  const leftCountChirho = largestPowerOfTwoLessThanChirho(countChirho);
  const leftCvChirho = subtreeChainingValueChirho(chunkOutputsChirho, startChirho, leftCountChirho);
  const rightCvChirho = subtreeChainingValueChirho(
    chunkOutputsChirho,
    startChirho + leftCountChirho,
    countChirho - leftCountChirho,
  );
  return outputChainingValueChirho(parentOutputChirho(leftCvChirho, rightCvChirho));
}

function rootBytesFromOutputChirho(outputChirho) {
  const wordsChirho = compressChirho(
    outputChirho.cv_chirho,
    outputChirho.block_words_chirho,
    outputChirho.counter_chirho,
    outputChirho.block_len_chirho,
    outputChirho.flags_chirho | BLAKE3_ROOT_CHIRHO,
  ).slice(0, 8);
  const bytesChirho = new Uint8Array(32);
  for (let iChirho = 0; iChirho < wordsChirho.length; iChirho += 1) {
    const wordChirho = wordsChirho[iChirho];
    bytesChirho[iChirho * 4] = wordChirho & 0xff;
    bytesChirho[iChirho * 4 + 1] = (wordChirho >>> 8) & 0xff;
    bytesChirho[iChirho * 4 + 2] = (wordChirho >>> 16) & 0xff;
    bytesChirho[iChirho * 4 + 3] = (wordChirho >>> 24) & 0xff;
  }
  return bytesChirho;
}

export function blake3HexChirho(bytesChirho) {
  const inputChirho = bytesChirho instanceof Uint8Array ? bytesChirho : new Uint8Array(bytesChirho);
  const chunkOutputsChirho = [];
  const chunkCountChirho = Math.max(1, Math.ceil(inputChirho.length / BLAKE3_CHUNK_LEN_CHIRHO));
  for (let chunkIndexChirho = 0; chunkIndexChirho < chunkCountChirho; chunkIndexChirho += 1) {
    const chunkStartChirho = chunkIndexChirho * BLAKE3_CHUNK_LEN_CHIRHO;
    chunkOutputsChirho.push(
      chunkOutputChirho(
        inputChirho.slice(chunkStartChirho, chunkStartChirho + BLAKE3_CHUNK_LEN_CHIRHO),
        chunkIndexChirho,
      ),
    );
  }
  const rootOutputChirho = chunkOutputsChirho.length === 1
    ? chunkOutputsChirho[0]
    : parentOutputChirho(
        subtreeChainingValueChirho(chunkOutputsChirho, 0, largestPowerOfTwoLessThanChirho(chunkOutputsChirho.length)),
        subtreeChainingValueChirho(
          chunkOutputsChirho,
          largestPowerOfTwoLessThanChirho(chunkOutputsChirho.length),
          chunkOutputsChirho.length - largestPowerOfTwoLessThanChirho(chunkOutputsChirho.length),
        ),
      );
  return Array.from(rootBytesFromOutputChirho(rootOutputChirho))
    .map((byteChirho) => byteChirho.toString(16).padStart(2, "0"))
    .join("");
}

function runtimePackageHashFieldChirho(valueChirho, labelChirho) {
  if (typeof valueChirho !== "string" || !CONTENT_HASH_HEX_CHIRHO.test(valueChirho)) {
    throw new Error(`runtime package manifest ${labelChirho} is not a cairn content hash`);
  }
  return valueChirho;
}

export function validateRuntimePackageManifestForBrowserChirho(manifestChirho) {
  if (manifestChirho.abi_chirho !== "bytes-abi-v1-chirho") {
    throw new Error(`unsupported runtime package ABI '${manifestChirho.abi_chirho}'`);
  }
  if (
    manifestChirho.profile_chirho !== "BrowserChirho"
    && manifestChirho.profile_chirho !== "EmbeddedChirho"
  ) {
    throw new Error(`runtime package profile '${manifestChirho.profile_chirho}' is not public`);
  }
  if (!manifestChirho.entry_chirho) {
    throw new Error("runtime package manifest is missing entry_chirho");
  }
  const executableHashChirho = runtimePackageHashFieldChirho(
    manifestChirho.executable_chirho,
    "executable_chirho",
  );
  if (!Array.isArray(manifestChirho.capabilities_chirho) || manifestChirho.capabilities_chirho.length !== 0) {
    throw new Error("runtime package manifest is not capability-free");
  }
  if (
    !Array.isArray(manifestChirho.object_hashes_chirho)
    || manifestChirho.object_hashes_chirho.length !== 1
    || manifestChirho.object_hashes_chirho[0] !== executableHashChirho
  ) {
    throw new Error("runtime package manifest does not expose exactly the executable object");
  }
  return executableHashChirho;
}

export function verifyRuntimePackageExecutableHashChirho(manifestChirho, executableChirho) {
  const expectedHashChirho = validateRuntimePackageManifestForBrowserChirho(manifestChirho);
  const actualHashChirho = blake3HexChirho(executableChirho);
  if (actualHashChirho !== expectedHashChirho) {
    throw new Error(
      `runtime package executable hash ${actualHashChirho} does not match manifest executable ${expectedHashChirho}`,
    );
  }
  return actualHashChirho;
}

export async function fetchRuntimePackageChirho(packageChirho, optionsChirho = {}) {
  const baseUrlChirho = (optionsChirho.baseUrlChirho || "").replace(/\/$/, "");
  const packageRefChirho = encodeURIComponent(packageChirho);
  const manifestUrlChirho =
    `${baseUrlChirho}/runtime-package-chirho/${packageRefChirho}/manifest-chirho`;
  const executableUrlChirho =
    `${baseUrlChirho}/runtime-package-chirho/${packageRefChirho}/executable-chirho`;

  const manifestResponseChirho = await fetch(manifestUrlChirho);
  if (!manifestResponseChirho.ok) {
    throw new Error(
      `runtime package manifest fetch failed: ${manifestResponseChirho.status}`,
    );
  }
  const manifestContentTypeChirho = manifestResponseChirho.headers.get("content-type") || "";
  if (!manifestContentTypeChirho.startsWith("application/json")) {
    throw new Error(
      `runtime package manifest content-type '${manifestContentTypeChirho}' is not application/json`,
    );
  }
  const manifestChirho = await manifestResponseChirho.json();
  validateRuntimePackageManifestForBrowserChirho(manifestChirho);

  const executableResponseChirho = await fetch(executableUrlChirho);
  if (!executableResponseChirho.ok) {
    throw new Error(
      `runtime package executable fetch failed: ${executableResponseChirho.status}`,
    );
  }
  const executableContentTypeChirho = executableResponseChirho.headers.get("content-type") || "";
  if (executableContentTypeChirho !== "application/wasm") {
    throw new Error(
      `runtime package executable content-type '${executableContentTypeChirho}' is not application/wasm`,
    );
  }
  const executableChirho = new Uint8Array(await executableResponseChirho.arrayBuffer());
  const executableHashChirho = verifyRuntimePackageExecutableHashChirho(
    manifestChirho,
    executableChirho,
  );
  return {
    manifest_chirho: manifestChirho,
    executable_chirho: executableChirho,
    executable_hash_chirho: executableHashChirho,
    manifest_url_chirho: manifestUrlChirho,
    executable_url_chirho: executableUrlChirho,
  };
}

export async function runRuntimePackageChirho(packageChirho, inputBytesChirho, optionsChirho = {}) {
  const packageArtifactChirho = await fetchRuntimePackageChirho(packageChirho, optionsChirho);
  const outputChirho = await runNodeChirho(
    packageArtifactChirho.executable_chirho,
    packageArtifactChirho.manifest_chirho.entry_chirho,
    inputBytesChirho,
    optionsChirho.hostEffectsChirho || {},
  );
  return {
    ...packageArtifactChirho,
    output_chirho: outputChirho,
  };
}

export async function runRuntimePackageTextChirho(packageChirho, inputChirho, optionsChirho = {}) {
  const inputBytesChirho = new TextEncoder().encode(inputChirho);
  const resultChirho = await runRuntimePackageChirho(
    packageChirho,
    inputBytesChirho,
    optionsChirho,
  );
  return new TextDecoder().decode(resultChirho.output_chirho);
}
