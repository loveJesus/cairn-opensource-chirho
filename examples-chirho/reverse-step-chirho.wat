;; For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16
;;
;; Composable step FRAGMENT (a func body, not a standalone module): reverse the bytes at
;; [$ptr, $ptr+$len) in place, then leave the packed (ptr<<32)|len on the stack. The compiler
;; wraps this as (func $step_N_chirho (param $ptr i32) (param $len i32) (result i64) <this>) inside
;; a composed module providing the shared memory + $alloc_chirho.
(local $i_chirho i32)
(local $j_chirho i32)
(local $a_chirho i32)
(local $b_chirho i32)
local.get $ptr
local.set $i_chirho
local.get $ptr
local.get $len
i32.add
i32.const 1
i32.sub
local.set $j_chirho
(block $done_chirho
  (loop $loop_chirho
    local.get $i_chirho
    local.get $j_chirho
    i32.ge_s
    br_if $done_chirho
    local.get $i_chirho
    i32.load8_u
    local.set $a_chirho
    local.get $j_chirho
    i32.load8_u
    local.set $b_chirho
    local.get $i_chirho
    local.get $b_chirho
    i32.store8
    local.get $j_chirho
    local.get $a_chirho
    i32.store8
    local.get $i_chirho
    i32.const 1
    i32.add
    local.set $i_chirho
    local.get $j_chirho
    i32.const 1
    i32.sub
    local.set $j_chirho
    br $loop_chirho))
(i64.or
  (i64.shl (i64.extend_i32_u (local.get $ptr)) (i64.const 32))
  (i64.extend_i32_u (local.get $len)))
