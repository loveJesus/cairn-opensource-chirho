;; For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16
;;
;; Composable EFFECT step FRAGMENT (a func body, not a standalone module): call the host-provided
;; import $dom_patch_chirho(ptr,len) with the current buffer (a blessed browser effect — render),
;; then leave the buffer's packed (ptr<<32)|len on the stack unchanged (passthrough, like reify).
;; The import is the capability: a pure module has none; this effectful module declares exactly
;; the one it uses, and the JS host (or wasmtime) must supply it. See compile_chirho.rs.
local.get $ptr
local.get $len
call $dom_patch_chirho
(i64.or
  (i64.shl (i64.extend_i32_u (local.get $ptr)) (i64.const 32))
  (i64.extend_i32_u (local.get $len)))
