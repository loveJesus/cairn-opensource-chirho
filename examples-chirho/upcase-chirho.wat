;; For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16
;;
;; upcase_chirho — a pure cairn node under the bytes ABI: ASCII-uppercase each byte in place.
;; Exports: memory, alloc_chirho(len)->ptr (bump allocator), upcase_chirho(ptr,len)->packed.
(module
  (memory (export "memory") 1)
  (global $heap_chirho (mut i32) (i32.const 1024))   ;; bump pointer; first 1KiB reserved scratch

  (func (export "alloc_chirho") (param $len i32) (result i32)
    (local $p i32)
    global.get $heap_chirho
    local.set $p
    global.get $heap_chirho
    local.get $len
    i32.add
    global.set $heap_chirho
    local.get $p)

  (func (export "upcase_chirho") (param $ptr i32) (param $len i32) (result i64)
    (local $i i32)
    (local $c i32)
    (block $done
      (loop $loop
        local.get $i
        local.get $len
        i32.ge_u
        br_if $done
        ;; c = mem[ptr + i]
        local.get $ptr
        local.get $i
        i32.add
        i32.load8_u
        local.set $c
        ;; if 'a'(97) <= c <= 'z'(122): mem[ptr+i] = c - 32
        (if
          (i32.and
            (i32.ge_u (local.get $c) (i32.const 97))
            (i32.le_u (local.get $c) (i32.const 122)))
          (then
            local.get $ptr
            local.get $i
            i32.add
            local.get $c
            i32.const 32
            i32.sub
            i32.store8))
        local.get $i
        i32.const 1
        i32.add
        local.set $i
        br $loop))
    ;; return (ptr << 32) | len
    (i64.or
      (i64.shl (i64.extend_i32_u (local.get $ptr)) (i64.const 32))
      (i64.extend_i32_u (local.get $len)))))
