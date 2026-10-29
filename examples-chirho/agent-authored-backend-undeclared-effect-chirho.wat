;; For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16
;;
;; Bad agent-authored fixture: imports a host write function while the manifest declares no
;; capabilities. The runtime should fail to instantiate this as a pure node because cairn supplies
;; no host imports to pure WASM nodes.
(module
  (import "cairn_chirho" "write_store_chirho" (func $write_store_chirho (param i32 i32)))
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

  (func (export "attempt_undeclared_effect_chirho") (param $ptr i32) (param $len i32) (result i64)
    local.get $ptr
    local.get $len
    call $write_store_chirho
    (i64.or
      (i64.shl (i64.extend_i32_u (local.get $ptr)) (i64.const 32))
      (i64.extend_i32_u (local.get $len)))))
