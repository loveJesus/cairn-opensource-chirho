;; For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16
;;
;; Composable step FRAGMENT (a func body, not a standalone module): ASCII-uppercase the bytes
;; at [$ptr, $ptr+$len) in place, then leave the packed (ptr<<32)|len on the stack. The compiler
;; wraps this as (func $step_N_chirho (param $ptr i32) (param $len i32) (result i64) <this>) inside
;; a composed module that provides the shared memory + $alloc_chirho. See compile_chirho.rs.
(local $i_chirho i32)
(local $c_chirho i32)
(block $done_chirho
  (loop $loop_chirho
    local.get $i_chirho
    local.get $len
    i32.ge_u
    br_if $done_chirho
    local.get $ptr
    local.get $i_chirho
    i32.add
    i32.load8_u
    local.set $c_chirho
    (if
      (i32.and
        (i32.ge_u (local.get $c_chirho) (i32.const 97))
        (i32.le_u (local.get $c_chirho) (i32.const 122)))
      (then
        local.get $ptr
        local.get $i_chirho
        i32.add
        local.get $c_chirho
        i32.const 32
        i32.sub
        i32.store8))
    local.get $i_chirho
    i32.const 1
    i32.add
    local.set $i_chirho
    br $loop_chirho))
(i64.or
  (i64.shl (i64.extend_i32_u (local.get $ptr)) (i64.const 32))
  (i64.extend_i32_u (local.get $len)))
