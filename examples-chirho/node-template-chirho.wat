;; For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16
;;
;; A starter PURE cairn node (the bytes ABI). It exports:
;;   - memory
;;   - alloc_chirho(len i32) -> ptr i32   (bump allocator the host uses to place the input)
;;   - an entry (ptr i32, len i32) -> i64  packed as (out_ptr << 32) | out_len
;; This identity node returns its input buffer unchanged. Edit the entry body to transform the
;; bytes in place (or alloc a new buffer), then:
;;   cairn-chirho node-build <this-file>.wat --name my_node --entry node_chirho
;;   cairn-chirho node-check <printed-hash> --input "hello"
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
  (func (export "node_chirho") (param $ptr i32) (param $len i32) (result i64)
    ;; identity: return the input buffer unchanged, packed as (ptr << 32) | len
    (i64.or
      (i64.shl (i64.extend_i32_u (local.get $ptr)) (i64.const 32))
      (i64.extend_i32_u (local.get $len)))))
