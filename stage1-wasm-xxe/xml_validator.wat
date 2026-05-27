;; ============================================================
;; QA CTF Stage 1: XML Validator WebAssembly Module
;; HEAVILY OBFUSCATED — Level 3 Wasm Obfuscation
;; ============================================================
;; Technique layers:
;;   1. Name mangling with misleading names
;;   2. Control flow flattening with opaque predicates
;;   3. Multi-layer string encryption (Caesar + XOR + byte-swap)
;;   4. Dead code injection (decoy functions)
;;   5. Custom memory allocator
;;   6. Anti-debug timing + canary checks
;;   7. Polymorphic self-modifying decode
;;   8. Red herring: get_flag() function (decoy)
;; ============================================================

(module
  ;; ============================================================
  ;; Memory: 2 pages (128KB)
  ;; ============================================================
  (memory (export "memory") 2)

  ;; ============================================================
  ;; Imports for anti-debug timing
  ;; ============================================================
  (import "env" "performance_now" (func $env.performance_now (result f64)))

  ;; ============================================================
  ;; Global state
  ;; ============================================================
  (global $canary_value (mut i32) (i32.const 0xDEADBEEF))
  (global $init_done (mut i32) (i32.const 0))
  (global $timing_base (mut f64) (f64.const 0.0))
  (global $decoy_state (mut i32) (i32.const 0))  ;; red herring state

  ;; ============================================================
  ;; DATA SEGMENTS — Encrypted XML tag names & schema hints
  ;; Layout:
  ;;   0x0000 - 0x00FF: Key material (layer1 key, layer2 key, layer3 key)
  ;;   0x0100 - 0x07FF: Encrypted XML tag strings
  ;;   0x0800 - 0x0FFF: Working buffer for polymorphic decode
  ;;   0x1000 - 0x1FFF: Custom heap area
  ;;   0x2000 - 0x2FFF: Decoy/fake data (red herrings)
  ;; ============================================================

  ;; Layer keys — each XOR'd with constant to hide real values
  ;; Real key1 = 0x37, Real key2 = 0xAB, Real key3 = 0x5C
  (data (i32.const 0x0000) "\x06\x93\x6b")  ;; XOR with 0x31 → 0x37, 0xA2→0xAB wait, let me fix
  ;; Actually store: key1=0x37^0xAA, key2=0xAB^0x55, key3=0x5C^0xFF
  ;; Decrypted at runtime: XOR with mask
  (data (i32.const 0x0000) "\x9d\xfe\xa3")  ;; 0x37^0xAA=0x9D, 0xAB^0x55=0xFE, 0x5C^0xFF=0xA3
  ;; Key masks (used to recover real keys)
  (data (i32.const 0x0010) "\xaa\x55\xff")

  ;; ============================================================
  ;; ENCRYPTED XML TAG STRINGS (offset 0x0100)
  ;; Encryption: Layer1=Caesar(shift=index%7), Layer2=XOR(0xAB), Layer3=ByteSwap
  ;;
  ;; Valid XML tags: <data>, <query>, <param>, <input>, <request>
  ;; Also: DOCTYPE, ENTITY (for XXE hint)
  ;; ============================================================

  ;; "data" encrypted:
  ;;   Original: d(0x64) a(0x61) t(0x74) a(0x61)
  ;;   L1 Caesar(index%7): 0x64+0=0x64, 0x61+1=0x62, 0x74+2=0x76, 0x61+3=0x64
  ;;   L2 XOR(0xAB): 0x64^0xAB=0xCF, 0x62^0xAB=0xC9, 0x76^0xAB=0xDD, 0x64^0xAB=0xCF
  ;;   L3 ByteSwap(swap pairs): 0xC9 0xCF 0xCF 0xDD
  (data (i32.const 0x0100) "\xc9\xcf\xcf\xdd")

  ;; "query" encrypted:
  ;;   q(0x71) u(0x75) e(0x65) r(0x72) y(0x79)
  ;;   L1: 0x71+0=0x71, 0x75+1=0x76, 0x65+2=0x67, 0x72+3=0x75, 0x79+4=0x7D
  ;;   L2: 0x71^0xAB=0xDA, 0x76^0xAB=0xDD, 0x67^0xAB=0xCC, 0x75^0xAB=0xDE, 0x7D^0xAB=0xD6
  ;;   L3 ByteSwap: 0xDD 0xDA 0xDE 0xCC 0xD6
  (data (i32.const 0x0110) "\xdd\xda\xde\xcc\xd6")

  ;; "param" encrypted:
  ;;   p(0x70) a(0x61) r(0x72) a(0x61) m(0x6D)
  ;;   L1: 0x70, 0x62, 0x74, 0x64, 0x71
  ;;   L2: 0xDB, 0xC9, 0xDF, 0xCF, 0xDA
  ;;   L3: 0xC9 0xDB 0xCF 0xDF 0xDA
  (data (i32.const 0x0120) "\xc9\xdb\xcf\xdf\xda")

  ;; "input" encrypted:
  ;;   i(0x69) n(0x6E) p(0x70) u(0x75) t(0x74)
  ;;   L1: 0x69, 0x70, 0x74, 0x78, 0x78
  ;;   L2: 0xC2, 0xDB, 0xDF, 0xD3, 0xD3
  ;;   L3: 0xDB 0xC2 0xD3 0xDF 0xD3
  (data (i32.const 0x0130) "\xdb\xc2\xd3\xdf\xd3")

  ;; "request" encrypted:
  ;;   r(0x72) e(0x65) q(0x71) u(0x75) e(0x65) s(0x73) t(0x74)
  ;;   L1: 0x72, 0x66, 0x73, 0x78, 0x69, 0x78, 0x76
  ;;   L2: 0xD9, 0xCD, 0xD8, 0xDE, 0xCC, 0xD8, 0xDF
  ;;   L3: 0xCD 0xD9 0xDE 0xD8 0xCC 0xD8 0xDF
  (data (i32.const 0x0140) "\xcd\xd9\xde\xd8\xcc\xd8\xdf")

  ;; String length table (at 0x0180)
  (data (i32.const 0x0180) "\x04\x05\x05\x05\x07")  ;; lengths of data,query,param,input,request

  ;; Tag name offsets table (at 0x0190)
  (data (i32.const 0x0190) "\x00\x01\x00\x00\x00")  ;; offset 0x0100
  (data (i32.const 0x0194) "\x10\x01\x00\x00")       ;; offset 0x0110
  (data (i32.const 0x0198) "\x20\x01\x00\x00")       ;; offset 0x0120
  (data (i32.const 0x019c) "\x30\x01\x00\x00")       ;; offset 0x0130
  (data (i32.const 0x01a0) "\x40\x01\x00\x00")       ;; offset 0x0140

  ;; ============================================================
  ;; DECOY DATA (offset 0x2000) — Red Herrings
  ;; Fake encrypted strings that look like they might be tags
  ;; ============================================================
  (data (i32.const 0x2000) "flag_placeholder_not_real")
  (data (i32.const 0x2020) "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")
  (data (i32.const 0x2040) "admin_debug_panel")
  (data (i32.const 0x2060) "super_secret_backdoor_key=AAAA-BBBB-CCCC-DDDD")
  (data (i32.const 0x2080) "wasm_internal_cache_v2")

  ;; ============================================================
  ;; WORKING BUFFER for polymorphic decode (0x0800-0x0FFF)
  ;; At init time, the real XML schema is assembled here
  ;; ============================================================

  ;; ============================================================
  ;; CUSTOM HEAP (0x1000-0x1FFF)
  ;; Simple bump allocator with obfuscated metadata
  ;; ============================================================
  (global $heap_ptr (mut i32) (i32.const 0x1000))

  ;; ============================================================
  ;; ANTI-DEBUG: Canary check
  ;; ============================================================
  (func $helper_trim_space (export "helper_trim_space") (result i32)
    ;; Name is misleading — this is actually the canary verifier
    ;; Returns 1 if canary intact, 0 if tampered (debugger detected)
    (local $saved i32)
    (local.set $saved (global.get $canary_value))
    ;; Write canary to memory offset 0x0F00
    (i32.store (i32.const 0x0F00) (local.get $saved))
    ;; Read it back
    (i32.eq (i32.load (i32.const 0x0F00)) (local.get $saved))
  )

  ;; ============================================================
  ;; ANTI-DEBUG: Timing check
  ;; ============================================================
  (func $util_format_date (export "util_format_date") (result i32)
    ;; Name is misleading — this is actually the timing check
    ;; Returns 1 if no debugger detected, 0 if debugger present
    (local $t1 f64)
    (local $t2 f64)
    (local $delta f64)

    (local.set $t1 (call $env.performance_now))

    ;; Do some dummy computation that takes predictable time
    (drop (i32.add (i32.const 1) (i32.const 2)))
    (drop (i32.mul (i32.const 3) (i32.const 4)))
    (drop (i32.xor (i32.const 0xFF) (i32.const 0xAA)))

    (local.set $t2 (call $env.performance_now))
    (local.set $delta (f64.sub (local.get $t2) (local.get $t1)))

    ;; If delta > 5ms, likely being debugged
    (if (result i32) (f64.gt (local.get $delta) (f64.const 5.0))
      (then (i32.const 0))  ;; debugger detected → return 0
      (else (i32.const 1))  ;; normal → return 1
    )
  )

  ;; ============================================================
  ;; STRING DECRYPTOR — Multi-layer (3 layers)
  ;; ============================================================

  ;; Layer 3: Byte swap (swap adjacent byte pairs)
  (func $logger_write_buf (export "logger_write_buf") (param $src i32) (param $len i32) (param $dst i32)
    ;; Name is misleading — this is Layer 3 byte swap decrypt
    ;; Swaps adjacent byte pairs in buffer
    (local $i i32)
    (local $tmp i32)

    (local.set $i (i32.const 0))
    (block $break
      (loop $loop
        (br_if $break (i32.ge_u (local.get $i) (local.get $len)))

        ;; Only swap if we have a pair
        (if (i32.lt_u (i32.add (local.get $i) (i32.const 1))) (local.get $len))
          (then
            ;; Swap bytes at i and i+1
            (local.set $tmp (i32.load8_u (i32.add (local.get $src) (local.get $i))))
            (i32.store8 (i32.add (local.get $dst) (local.get $i))
              (i32.load8_u (i32.add (local.get $src) (i32.add (local.get $i) (i32.const 1)))))
            (i32.store8 (i32.add (local.get $dst) (i32.add (local.get $i) (i32.const 1)))
              (local.get $tmp))
          )
          (else
            ;; Odd byte — just copy
            (i32.store8 (i32.add (local.get $dst) (local.get $i))
              (i32.load8_u (i32.add (local.get $src) (local.get $i))))
          )
        )

        (local.set $i (i32.add (local.get $i) (i32.const 2)))
        (br $loop)
      )
    )
  )

  ;; Layer 2: XOR with key
  (func $cache_invalidate (export "cache_invalidate") (param $src i32) (param $len i32) (param $dst i32) (param $key i32)
    ;; Name is misleading — this is Layer 2 XOR decrypt
    (local $i i32)
    (local.set $i (i32.const 0))
    (block $break
      (loop $loop
        (br_if $break (i32.ge_u (local.get $i) (local.get $len)))
        (i32.store8 (i32.add (local.get $dst) (local.get $i))
          (i32.xor
            (i32.load8_u (i32.add (local.get $src) (local.get $i)))
            (local.get $key)))
        (local.set $i (i32.add (local.get $i) (i32.const 1)))
        (br $loop)
      )
    )
  )

  ;; Layer 1: Caesar shift (shift = index % 7, then subtract shift)
  (func $data_pipeline_flush (export "data_pipeline_flush") (param $src i32) (param $len i32) (param $dst i32)
    ;; Name is misleading — this is Layer 1 Caesar decrypt
    (local $i i32)
    (local $shift i32)
    (local $byte i32)

    (local.set $i (i32.const 0))
    (block $break
      (loop $loop
        (br_if $break (i32.ge_u (local.get $i) (local.get $len)))
        (local.set $shift (i32.rem_u (local.get $i) (i32.const 7)))
        (local.set $byte (i32.load8_u (i32.add (local.get $src) (local.get $i))))
        ;; Subtract the shift (undo Caesar)
        (i32.store8 (i32.add (local.get $dst) (local.get $i))
          (i32.sub (local.get $byte) (local.get $shift)))
        (local.set $i (i32.add (local.get $i) (i32.const 1)))
        (br $loop)
      )
    )
  )

  ;; ============================================================
  ;; KEY RECOVERY — Reconstructs real XOR key from obfuscated storage
  ;; ============================================================
  (func $metrics_aggregate (export "metrics_aggregate") (result i32)
    ;; Name is misleading — this recovers the Layer 2 XOR key
    ;; key = data[0] ^ mask[0]
    (i32.xor
      (i32.load8_u (i32.const 0x0000))
      (i32.load8_u (i32.const 0x0010)))
  )

  ;; ============================================================
  ;; POLYMORPHIC DECODE — Assembles XML schema at runtime
  ;; Writes decrypted tag names to working buffer (0x0800)
  ;; ============================================================
  (func $session_cleanup (export "session_cleanup")
    ;; Name is misleading — this is the polymorphic decode that
    ;; assembles the valid XML schema in memory at runtime
    (local $key i32)
    (local $tag_idx i32)
    (local $tag_len i32)
    (local $tag_src i32)
    (local $dst_base i32)
    (local $dst_offset i32)

    ;; Check canary first — if tampered, write garbage
    (if (i32.eqz (call $helper_trim_space))
      (then
        ;; Anti-debug: write decoy data instead
        (call $write_decoy_schema)
        (return)
      )
    )

    ;; Check timing — if debugger present, write garbage
    (if (i32.eqz (call $util_format_date))
      (then
        ;; Anti-debug: use decoy key
        (call $write_decoy_schema)
        (return)
      )
    )

    ;; Recover real key
    (local.set $key (call $metrics_aggregate))

    ;; Decrypt each tag and write to working buffer
    (local.set $tag_idx (i32.const 0))
    (local.set $dst_offset (i32.const 0))

    (block $tag_break
      (loop $tag_loop
        (br_if $tag_break (i32.ge_u (local.get $tag_idx) (i32.const 5)))

        ;; Get tag length from length table
        (local.set $tag_len (i32.load8_u (i32.add (i32.const 0x0180) (local.get $tag_idx))))

        ;; Get tag source offset from offset table
        (local.set $tag_src (i32.load (i32.add (i32.const 0x0190) (i32.mul (local.get $tag_idx) (i32.const 4)))))

        ;; dst_base = 0x0800 + dst_offset
        (local.set $dst_base (i32.add (i32.const 0x0800) (local.get $dst_offset)))

        ;; 3-layer decrypt: L3(byte swap) → L2(XOR) → L1(Caesar)
        ;; Step 1: Layer 3 — byte swap from src to temp buffer (0x0C00)
        (call $logger_write_buf (local.get $tag_src) (local.get $tag_len) (i32.const 0x0C00))

        ;; Step 2: Layer 2 — XOR from temp to another temp (0x0D00)
        (call $cache_invalidate (i32.const 0x0C00) (local.get $tag_len) (i32.const 0x0D00) (local.get $key))

        ;; Step 3: Layer 1 — Caesar from temp to final destination
        (call $data_pipeline_flush (i32.const 0x0D00) (local.get $tag_len) (local.get $dst_base))

        ;; Store tag length at 0x0900 + tag_idx*8
        (i32.store (i32.add (i32.const 0x0900) (i32.mul (local.get $tag_idx) (i32.const 8))) (local.get $tag_len))

        ;; Store tag offset at 0x0904 + tag_idx*8
        (i32.store (i32.add (i32.const 0x0904) (i32.mul (local.get $tag_idx) (i32.const 8))) (local.get $dst_base))

        ;; Advance destination offset
        (local.set $dst_offset (i32.add (local.get $dst_offset) (i32.add (local.get $tag_len) (i32.const 1))))

        (local.set $tag_idx (i32.add (local.get $tag_idx) (i32.const 1)))
        (br $tag_loop)
      )
    )

    ;; Mark init as done
    (global.set $init_done (i32.const 1))
  )

  ;; ============================================================
  ;; DECOY SCHEMA — Written when anti-debug triggers
  ;; ============================================================
  (func $write_decoy_schema
    ;; Writes fake tags: "flag", "admin", "token", "debug", "root"
    (i32.store8 (i32.const 0x0800) (i32.const 0x66))  ;; 'f'
    (i32.store8 (i32.const 0x0801) (i32.const 0x6C))  ;; 'l'
    (i32.store8 (i32.const 0x0802) (i32.const 0x61))  ;; 'a'
    (i32.store8 (i32.const 0x0803) (i32.const 0x67))  ;; 'g'
    ;; ... more fake tags
    (global.set $init_done (i32.const 2))  ;; Mark as decoy
  )

  ;; ============================================================
  ;; RED HERRING: get_flag function — DOES NOTHING USEFUL
  ;; Player who finds this will waste time
  ;; ============================================================
  (func $get_flag (export "get_flag") (param $buf i32) (result i32)
    ;; Returns fake flag string length
    ;; This is a decoy — the real challenge path is through XXE
    (local $i i32)
    (local.set $i (i32.const 0))
    (block $break
      (loop $loop
        (br_if $break (i32.ge_u (local.get $i) (i32.const 28)))
        ;; Copy "QA{this_is_not_the_flag_nice}" (decoy)
        (i32.store8 (i32.add (local.get $buf) (local.get $i))
          (i32.load8_u (i32.add (i32.const 0x2000) (local.get $i))))
        (local.set $i (i32.add (local.get $i) (i32.const 1)))
        (br $loop)
      )
    )
    (i32.const 28)
  )

  ;; ============================================================
  ;; CUSTOM HEAP ALLOCATOR (obfuscated)
  ;; ============================================================
  (func $heap_alloc (export "heap_alloc") (param $size i32) (result i32)
    (local $ptr i32)
    (local.set $ptr (global.get $heap_ptr))
    ;; Align to 16 bytes
    (global.set $heap_ptr
      (i32.add
        (i32.add (global.get $heap_ptr) (local.get $size))
        (i32.and
          (i32.sub (i32.const 16) (i32.rem_u (i32.add (global.get $heap_ptr) (local.get $size)) (i32.const 16)))
          (i32.const 15))))
    (local.get $ptr)
  )

  ;; ============================================================
  ;; OPAQUE PREDICATES — Always true/false but look dynamic
  ;; ============================================================
  (func $opaque_true (result i32)
    ;; (x * 0) XOR 0 = 0, so this always equals 0 (false condition)
    ;; But it looks dynamic to static analyzers
    (i32.eqz
      (i32.xor
        (i32.mul (i32.const 0x1A2B) (i32.const 0))
        (i32.const 0)))
  )

  (func $opaque_false (result i32)
    ;; Always false: (2*2 - 4) == 1 → 0
    (i32.eq
      (i32.sub (i32.mul (i32.const 2) (i32.const 2)) (i32.const 4))
      (i32.const 1))
  )

  ;; ============================================================
  ;; MAIN XML VALIDATOR — Control Flow Flattened
  ;; Uses dispatcher pattern to obscure real logic
  ;; ============================================================
  (func $validate_xml_tag (export "validate_xml_tag") (param $tag_ptr i32) (param $tag_len i32) (result i32)
    ;; Returns: 1 if valid tag, 0 if invalid
    ;; Control flow flattened with opaque predicates

    (local $state i32)        ;; dispatcher state
    (local $result i32)       ;; comparison result
    (local $tag_idx i32)      ;; current tag being checked
    (local $char_idx i32)     ;; current character
    (local $match i32)        ;; match flag
    (local $valid_tag_len i32)
    (local $valid_tag_ptr i32)

    ;; Initialize: ensure schema is decoded
    (if (i32.eqz (global.get $init_done))
      (then (call $session_cleanup))
    )

    ;; If init_done == 2 (decoy mode), always return 0
    (if (i32.eq (global.get $init_done) (i32.const 2))
      (then (return (i32.const 0)))
    )

    ;; Dispatcher states:
    ;; 0 → init loop
    ;; 1 → compare chars
    ;; 2 → check match
    ;; 3 → next tag
    ;; 4 → found match
    ;; 5 → not found
    ;; 6 → dead code (opaque predicate branch, never taken)
    ;; 7 → more dead code

    (local.set $state (i32.const 0))
    (local.set $tag_idx (i32.const 0))
    (local.set $match (i32.const 0))

    (block $dispatch_break
      (loop $dispatch_loop
        (br_if $dispatch_break (i32.ge_u (local.get $state) (i32.const 8)))

        ;; Opaque predicate check — adds dead branch
        (if (call $opaque_false)
          (then (local.set $state (i32.const 6)))  ;; never reached
        )

        (block $case_break
          ;; State 0: Initialize tag comparison
          (if (i32.eq (local.get $state) (i32.const 0))
            (then
              (if (i32.ge_u (local.get $tag_idx) (i32.const 5))
                (then (local.set $state (i32.const 5)) (br $case_break))
              )
              ;; Get valid tag length
              (local.set $valid_tag_len
                (i32.load (i32.add (i32.const 0x0900) (i32.mul (local.get $tag_idx) (i32.const 8)))))
              ;; Get valid tag pointer
              (local.set $valid_tag_ptr
                (i32.load (i32.add (i32.const 0x0904) (i32.mul (local.get $tag_idx) (i32.const 8)))))
              ;; Check length match first
              (if (i32.ne (local.get $tag_len) (local.get $valid_tag_len))
                (then
                  (local.set $tag_idx (i32.add (local.get $tag_idx) (i32.const 1)))
                  (local.set $state (i32.const 0))  ;; restart with next tag
                  (br $case_break)
                )
              )
              (local.set $char_idx (i32.const 0))
              (local.set $match (i32.const 1))
              (local.set $state (i32.const 1))
              (br $case_break)
            )
          )

          ;; State 1: Compare characters
          (if (i32.eq (local.get $state) (i32.const 1))
            (then
              (if (i32.ge_u (local.get $char_idx) (local.get $tag_len))
                (then (local.set $state (i32.const 2)) (br $case_break))
              )
              ;; Compare byte
              (if (i32.ne
                (i32.load8_u (i32.add (local.get $tag_ptr) (local.get $char_idx)))
                (i32.load8_u (i32.add (local.get $valid_tag_ptr) (local.get $char_idx))))
                (then
                  (local.set $match (i32.const 0))
                  (local.set $state (i32.const 3))  ;; next tag
                  (br $case_break)
                )
              )
              (local.set $char_idx (i32.add (local.get $char_idx) (i32.const 1)))
              (local.set $state (i32.const 1))  ;; continue comparing
              (br $case_break)
            )
          )

          ;; State 2: Check if matched
          (if (i32.eq (local.get $state) (i32.const 2))
            (then
              (if (local.get $match)
                (then (local.set $state (i32.const 4)))
                (else (local.set $state (i32.const 3)))
              )
              (br $case_break)
            )
          )

          ;; State 3: Next tag
          (if (i32.eq (local.get $state) (i32.const 3))
            (then
              (local.set $tag_idx (i32.add (local.get $tag_idx) (i32.const 1)))
              (local.set $state (i32.const 0))
              (br $case_break)
            )
          )

          ;; State 4: Found match!
          (if (i32.eq (local.get $state) (i32.const 4))
            (then
              (local.set $result (i32.const 1))
              (local.set $state (i32.const 8))  ;; exit
              (br $case_break)
            )
          )

          ;; State 5: Not found
          (if (i32.eq (local.get $state) (i32.const 5))
            (then
              (local.set $result (i32.const 0))
              (local.set $state (i32.const 8))
              (br $case_break)
            )
          )

          ;; State 6 & 7: Dead code (never reached due to opaque predicates)
          (local.set $state (i32.add (local.get $state) (i32.const 1)))
        )

        ;; Another opaque predicate dead branch
        (if (call $opaque_true)
          (then
            ;; This always executes — just continues the loop
            nop
          )
          (else
            ;; Never reached
            (local.set $state (i32.const 7))
          )
        )

        (br $dispatch_loop)
      )
    )

    (local.get $result)
  )

  ;; ============================================================
  ;; DEAD CODE — Decoy functions to confuse reversers
  ;; ============================================================

  ;; Looks like XML processing but does nothing useful
  (func $xml_sanitize_input (export "xml_sanitize_input") (param $ptr i32) (param $len i32) (result i32)
    (local $i i32)
    (local.set $i (i32.const 0))
    (block $b
      (loop $l
        (br_if $b (i32.ge_u (local.get $i) (local.get $len)))
        ;; Do nothing useful — just waste time
        (drop (i32.add (local.get $i) (i32.const 1)))
        (local.set $i (i32.add (local.get $i) (i32.const 1)))
        (br $l)
      )
    )
    (local.get $len)
  )

  ;; Looks like a token generator but returns random data
  (func $generate_csrf_token (export "generate_csrf_token") (param $buf i32) (result i32)
    (local $i i32)
    (local.set $i (i32.const 0))
    (block $b
      (loop $l
        (br_if $b (i32.ge_u (local.get $i) (i32.const 32)))
        ;; Fill with pseudo-random garbage
        (i32.store8 (i32.add (local.get $buf) (local.get $i))
          (i32.rem_u
            (i32.add (i32.mul (local.get $i) (i32.const 127)) (i32.const 42))
            (i32.const 256)))
        (local.set $i (i32.add (local.get $i) (i32.const 1)))
        (br $l)
      )
    )
    (i32.const 32)
  )

  ;; Looks like HMAC but is useless
  (func $verify_hmac_signature (export "verify_hmac_signature") (param $a i32) (param $b i32) (result i32)
    (i32.const 0)
  )

  ;; Red herring — looks like base64 decoder
  (func $base64_decode (export "base64_decode") (param $src i32) (param $len i32) (param $dst i32) (result i32)
    ;; Intentionally broken base64 that just copies bytes
    (local $i i32)
    (local.set $i (i32.const 0))
    (block $b
      (loop $l
        (br_if $b (i32.ge_u (local.get $i) (local.get $len)))
        (i32.store8 (i32.add (local.get $dst) (local.get $i))
          (i32.load8_u (i32.add (local.get $src) (local.get $i))))
        (local.set $i (i32.add (local.get $i) (i32.const 1)))
        (br $l)
      )
    )
    (local.get $len)
  )

  ;; Red herring — looks like AES decryption
  (func $aes_decrypt_ecb (export "aes_decrypt_ecb") (param $key i32) (param $data i32) (param $out i32) (result i32)
    ;; Just returns garbage
    (i32.const 0)
  )

  ;; ============================================================
  ;; INITIALIZATION — Runs canary setup
  ;; ============================================================
  (func $init (export "init")
    ;; Set initial canary value
    (global.set $canary_value (i32.const 0xDEADBEEF))
    ;; Store canary at known location
    (i32.store (i32.const 0x0F00) (global.get $canary_value))
    ;; Reset init state
    (global.set $init_done (i32.const 0))
  )
)
