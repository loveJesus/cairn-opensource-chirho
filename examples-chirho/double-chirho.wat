;; For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16
;; A pure node: double an i64. No imports ⇒ no capabilities ⇒ pure ⇒ cacheable.
(module
  (func (export "double_chirho") (param i64) (result i64)
    local.get 0
    i64.const 2
    i64.mul))
