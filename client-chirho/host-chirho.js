// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16
//
// cairn-chirho client host (bytes ABI). Loads a compiled cairn wasm artifact and runs a node:
// alloc the input in the module's memory, call the entry (ptr,len)->packed (out_ptr<<32|out_len),
// read the output back. This is the tiny client runtime — no cairn interpreter ships to the
// browser; the module's imports are its capabilities, enforced by the wasm sandbox.
//
// Pure nodes need no imports. Effect nodes import the blessed browser effects (dom_patch,
// read_input, post...) which this host provides — the import IS the capability.

export async function runNodeChirho(wasmBytesChirho, entryChirho, inputBytesChirho, hostEffectsChirho = {}) {
  // The module's memory is an export, available only after instantiate; the effect-import
  // closures below capture it via this holder so they can read the module's bytes when called.
  let memoryChirho;
  const importsChirho = {
    cairn_chirho: {
      // dom_patch_chirho(ptr,len): a blessed browser render effect. The host reads the bytes and
      // applies them (set the DOM, log, ...). Supplied even to pure modules (unused there).
      dom_patch_chirho: (ptrChirho, lenChirho) => {
        const bytesChirho = new Uint8Array(memoryChirho.buffer, ptrChirho, lenChirho).slice();
        if (hostEffectsChirho.dom_patch_chirho) hostEffectsChirho.dom_patch_chirho(bytesChirho);
      },
    },
  };
  const { instance: instanceChirho } = await WebAssembly.instantiate(wasmBytesChirho, importsChirho);
  const exportsChirho = instanceChirho.exports;
  memoryChirho = exportsChirho.memory;

  const inputLenChirho = inputBytesChirho.length;
  const inputPtrChirho = exportsChirho.alloc_chirho(inputLenChirho);
  new Uint8Array(memoryChirho.buffer, inputPtrChirho, inputLenChirho).set(inputBytesChirho);

  // The entry returns an i64 (BigInt): (out_ptr << 32) | out_len.
  const packedChirho = BigInt.asUintN(64, exportsChirho[entryChirho](inputPtrChirho, inputLenChirho));
  const outPtrChirho = Number(packedChirho >> 32n);
  const outLenChirho = Number(packedChirho & 0xffffffffn);
  return new Uint8Array(memoryChirho.buffer, outPtrChirho, outLenChirho).slice();
}
