;; For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16
;;
;; inc_u64_chirho — a pure cairn node under the bytes ABI: read the input as a little-endian
;; u64 (0 if the input is shorter than 8 bytes), add 1, write the result as 8 little-endian
;; bytes to a fresh buffer, and return (out_ptr << 32) | 8. The counter's increment step.
(module
  (memory (export "memory") 1)
  (global $heap_chirho (mut i32) (i32.const 1024))

  (func (export "alloc_chirho") (param $len i32) (result i32)
    (local $p i32)
    global.get $heap_chirho
    local.set $p
    global.get $heap_chirho
    local.get $len
    i32.add
    global.set $heap_chirho
    local.get $p)

  (func (export "inc_u64_chirho") (param $ptr i32) (param $len i32) (result i64)
    (local $cur i64)
    (local $out i32)
    ;; cur = (len >= 8) ? load_le_u64(ptr) : 0
    (if (i32.ge_u (local.get $len) (i32.const 8))
      (then (local.set $cur (i64.load (local.get $ptr))))
      (else (local.set $cur (i64.const 0))))
    ;; out = alloc(8) (inline bump)
    global.get $heap_chirho
    local.set $out
    global.get $heap_chirho
    i32.const 8
    i32.add
    global.set $heap_chirho
    ;; mem[out .. out+8] = cur + 1  (i64.store writes 8 little-endian bytes)
    local.get $out
    local.get $cur
    i64.const 1
    i64.add
    i64.store
    ;; return (out << 32) | 8
    (i64.or
      (i64.shl (i64.extend_i32_u (local.get $out)) (i64.const 32))
      (i64.const 8))))
