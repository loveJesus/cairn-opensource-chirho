;; For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16
;;
;; reverse_chirho — a pure cairn node under the bytes ABI: reverse the bytes in place.
;; Exports: memory, alloc_chirho(len)->ptr (bump allocator), reverse_chirho(ptr,len)->packed.
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

  (func (export "reverse_chirho") (param $ptr i32) (param $len i32) (result i64)
    (local $i i32)
    (local $j i32)
    (local $a i32)
    (local $b i32)
    ;; i = ptr; j = ptr + len - 1
    local.get $ptr
    local.set $i
    local.get $ptr
    local.get $len
    i32.add
    i32.const 1
    i32.sub
    local.set $j
    (block $done
      (loop $loop
        ;; while i < j  (signed: handles len 0 where j = ptr - 1)
        local.get $i
        local.get $j
        i32.ge_s
        br_if $done
        ;; a = mem[i]; b = mem[j]
        local.get $i
        i32.load8_u
        local.set $a
        local.get $j
        i32.load8_u
        local.set $b
        ;; mem[i] = b; mem[j] = a
        local.get $i
        local.get $b
        i32.store8
        local.get $j
        local.get $a
        i32.store8
        ;; i++; j--
        local.get $i
        i32.const 1
        i32.add
        local.set $i
        local.get $j
        i32.const 1
        i32.sub
        local.set $j
        br $loop))
    ;; return (ptr << 32) | len
    (i64.or
      (i64.shl (i64.extend_i32_u (local.get $ptr)) (i64.const 32))
      (i64.extend_i32_u (local.get $len)))))
