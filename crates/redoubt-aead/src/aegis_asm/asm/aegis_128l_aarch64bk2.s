// AEGIS-128L AEAD Cipher - ARM64/AArch64 Implementation (Optimized)
//
// Esta versión elimina el spilling de key/nonce al stack usando macros inline.
// Todo el state, key y nonce permanecen en registros SIMD durante la inicialización.
//
// Registros ARM64 disponibles:
//   v0-v7   : caller-saved (usamos para state S0-S7)
//   v8-v15  : callee-saved (usamos v8=key, v9=nonce, v10=C0, v11=C1)
//   v16-v31 : caller-saved (usamos para temporales en update)
//
// References:
// - AEGIS: A Fast Authenticated Encryption Algorithm (v1.1)
// - RFC: https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-aegis-aead-17

// ============================================================================
// Platform-specific symbol naming
// ============================================================================

#if defined(__APPLE__)
    #define FUNC(name) _##name
    #define HIDDEN_FUNC(name) .private_extern _##name
#elif defined(_WIN32) || defined(_WIN64)
    #define FUNC(name) name
    #define HIDDEN_FUNC(name)
#else
    #define FUNC(name) name
    #define HIDDEN_FUNC(name) .hidden name
#endif

// ============================================================================
// AEGIS-128L Update Macro (INLINE - sin memory spilling)
// ============================================================================
//
// Realiza un round de update completamente en registros.
//
// Inputs (registros):
//   S0-S7 en v0-v7
//   M0 en \m0_reg
//   M1 en \m1_reg
//
// Outputs:
//   S0-S7 actualizados in-place en v0-v7
//
// Temporales usados: v16-v23, v31
//
// Update algorithm:
//   S'0 = AESRound(S7, S0 ^ M0)
//   S'1 = AESRound(S0, S1)
//   S'2 = AESRound(S1, S2)
//   S'3 = AESRound(S2, S3)
//   S'4 = AESRound(S3, S4 ^ M1)
//   S'5 = AESRound(S4, S5)
//   S'6 = AESRound(S5, S6)
//   S'7 = AESRound(S6, S7)
//
.macro AEGIS_UPDATE m0_reg, m1_reg
    // Zero para aese (AddRoundKey con zero = no-op)
    movi v31.16b, #0

    // Calcular nuevo state en v16-v23 (sin sobreescribir v0-v7 hasta el final)

    // S'0 = AESRound(S7, S0 ^ M0)
    mov v16.16b, v7.16b              // v16 = S7
    aese v16.16b, v31.16b            // SubBytes + ShiftRows
    aesmc v16.16b, v16.16b           // MixColumns
    eor v24.16b, v0.16b, \m0_reg\().16b  // v24 = S0 ^ M0
    eor v16.16b, v16.16b, v24.16b    // S'0 = result ^ (S0 ^ M0)

    // S'1 = AESRound(S0, S1)
    mov v17.16b, v0.16b
    aese v17.16b, v31.16b
    aesmc v17.16b, v17.16b
    eor v17.16b, v17.16b, v1.16b

    // S'2 = AESRound(S1, S2)
    mov v18.16b, v1.16b
    aese v18.16b, v31.16b
    aesmc v18.16b, v18.16b
    eor v18.16b, v18.16b, v2.16b

    // S'3 = AESRound(S2, S3)
    mov v19.16b, v2.16b
    aese v19.16b, v31.16b
    aesmc v19.16b, v19.16b
    eor v19.16b, v19.16b, v3.16b

    // S'4 = AESRound(S3, S4 ^ M1)
    mov v20.16b, v3.16b
    aese v20.16b, v31.16b
    aesmc v20.16b, v20.16b
    eor v25.16b, v4.16b, \m1_reg\().16b  // v25 = S4 ^ M1
    eor v20.16b, v20.16b, v25.16b

    // S'5 = AESRound(S4, S5)
    mov v21.16b, v4.16b
    aese v21.16b, v31.16b
    aesmc v21.16b, v21.16b
    eor v21.16b, v21.16b, v5.16b

    // S'6 = AESRound(S5, S6)
    mov v22.16b, v5.16b
    aese v22.16b, v31.16b
    aesmc v22.16b, v22.16b
    eor v22.16b, v22.16b, v6.16b

    // S'7 = AESRound(S6, S7)
    mov v23.16b, v6.16b
    aese v23.16b, v31.16b
    aesmc v23.16b, v23.16b
    eor v23.16b, v23.16b, v7.16b

    // Mover nuevo state a v0-v7
    mov v0.16b, v16.16b
    mov v1.16b, v17.16b
    mov v2.16b, v18.16b
    mov v3.16b, v19.16b
    mov v4.16b, v20.16b
    mov v5.16b, v21.16b
    mov v6.16b, v22.16b
    mov v7.16b, v23.16b
.endm

// ============================================================================
// Constants
// ============================================================================

#if defined(__APPLE__)
.const_data
#else
.section .rodata
#endif
.p2align 4
AEGIS_C0:
    .byte 0x00, 0x01, 0x01, 0x02, 0x03, 0x05, 0x08, 0x0d
    .byte 0x15, 0x22, 0x37, 0x59, 0x90, 0xe9, 0x79, 0x62

.p2align 4
AEGIS_C1:
    .byte 0xdb, 0x3d, 0x18, 0x55, 0x6d, 0xc2, 0x2f, 0xf1
    .byte 0x20, 0x11, 0x31, 0x42, 0x73, 0xb5, 0x28, 0xdd

.text

// ============================================================================
// AEGIS-128L State Initialization (SIN SPILLING)
// ============================================================================
//
// Register allocation (todo en registros, sin stack para key/nonce):
//   v0-v7   = S0-S7 (state)
//   v8      = key       (callee-saved, preservado)
//   v9      = nonce     (callee-saved, preservado)
//   v10     = C0        (callee-saved)
//   v11     = C1        (callee-saved)
//   v16-v25 = temporales para update
//   v31     = zero
//
// Parameters:
//   x0 = pointer to state output (128 bytes)
//   x1 = pointer to key (16 bytes)
//   x2 = pointer to nonce (16 bytes)
//
.global FUNC(aegis128l_init)
HIDDEN_FUNC(aegis128l_init)
#if !defined(__APPLE__) && !defined(_WIN32) && !defined(_WIN64)
.type FUNC(aegis128l_init), @function
#endif
.p2align 4
FUNC(aegis128l_init):
    // Prologue: guardar callee-saved SIMD registers que usamos (v8-v11)
    stp d8, d9, [sp, #-32]!
    stp d10, d11, [sp, #16]

    // Guardar state pointer
    mov x3, x0

    // Cargar key y nonce a registros (única lectura de memoria para estos)
    ld1 {v8.16b}, [x1]               // v8 = key
    ld1 {v9.16b}, [x2]               // v9 = nonce

    // Cargar constantes C0 y C1
#if defined(__APPLE__)
    adrp x4, AEGIS_C0@PAGE
    add x4, x4, AEGIS_C0@PAGEOFF
    ld1 {v10.16b}, [x4]

    adrp x4, AEGIS_C1@PAGE
    add x4, x4, AEGIS_C1@PAGEOFF
    ld1 {v11.16b}, [x4]
#else
    adrp x4, AEGIS_C0
    add x4, x4, :lo12:AEGIS_C0
    ld1 {v10.16b}, [x4]

    adrp x4, AEGIS_C1
    add x4, x4, :lo12:AEGIS_C1
    ld1 {v11.16b}, [x4]
#endif

    // Inicializar state en registros v0-v7
    eor v0.16b, v8.16b, v9.16b       // S0 = key ^ nonce
    mov v1.16b, v11.16b              // S1 = C1
    mov v2.16b, v10.16b              // S2 = C0
    mov v3.16b, v11.16b              // S3 = C1
    eor v4.16b, v8.16b, v9.16b       // S4 = key ^ nonce
    eor v5.16b, v8.16b, v10.16b      // S5 = key ^ C0
    eor v6.16b, v8.16b, v11.16b      // S6 = key ^ C1
    eor v7.16b, v8.16b, v10.16b      // S7 = key ^ C0

    // 10 rounds de update con (nonce, key) - TODO EN REGISTROS, SIN SPILLING
    // M0 = nonce (v9), M1 = key (v8)
    AEGIS_UPDATE v9, v8              // Round 1
    AEGIS_UPDATE v9, v8              // Round 2
    AEGIS_UPDATE v9, v8              // Round 3
    AEGIS_UPDATE v9, v8              // Round 4
    AEGIS_UPDATE v9, v8              // Round 5
    AEGIS_UPDATE v9, v8              // Round 6
    AEGIS_UPDATE v9, v8              // Round 7
    AEGIS_UPDATE v9, v8              // Round 8
    AEGIS_UPDATE v9, v8              // Round 9
    AEGIS_UPDATE v9, v8              // Round 10

    // Escribir state final a memoria (única escritura necesaria)
    st1 {v0.16b-v3.16b}, [x3], #64
    st1 {v4.16b-v7.16b}, [x3]

    // Zeroizar key y nonce de registros (seguridad)
    movi v8.16b, #0
    movi v9.16b, #0

    // Epilogue: restaurar callee-saved registers
    ldp d10, d11, [sp, #16]
    ldp d8, d9, [sp], #32
    ret

#if !defined(__APPLE__) && !defined(_WIN32) && !defined(_WIN64)
.size FUNC(aegis128l_init), .-FUNC(aegis128l_init)
#endif

// ============================================================================
// AEGIS-128L Update Function (versión con punteros, para uso externo)
// ============================================================================
//
// Esta versión existe para compatibilidad con código que necesita la interfaz
// con punteros. Internamente, la init usa la macro inline.
//
.global FUNC(aegis128l_update)
HIDDEN_FUNC(aegis128l_update)
#if !defined(__APPLE__) && !defined(_WIN32) && !defined(_WIN64)
.type FUNC(aegis128l_update), @function
#endif
.p2align 4
FUNC(aegis128l_update):
    // Cargar state
    ld1 {v0.16b-v3.16b}, [x0], #64
    ld1 {v4.16b-v7.16b}, [x0]
    sub x0, x0, #64

    // Cargar M0, M1 a registros temporales
    ld1 {v12.16b}, [x1]              // v12 = M0
    ld1 {v13.16b}, [x2]              // v13 = M1

    // Update inline
    AEGIS_UPDATE v12, v13

    // Guardar state
    st1 {v0.16b-v3.16b}, [x0], #64
    st1 {v4.16b-v7.16b}, [x0]

    ret

#if !defined(__APPLE__) && !defined(_WIN32) && !defined(_WIN64)
.size FUNC(aegis128l_update), .-FUNC(aegis128l_update)
#endif

// ============================================================================
// AEGIS-128L Encryption (Optimized)
// ============================================================================
//
// Usa la macro inline para evitar spilling durante el procesamiento.
//
.global FUNC(aegis128l_encrypt)
HIDDEN_FUNC(aegis128l_encrypt)
#if !defined(__APPLE__) && !defined(_WIN32) && !defined(_WIN64)
.type FUNC(aegis128l_encrypt), @function
#endif
.p2align 4
FUNC(aegis128l_encrypt):
    // Prologue
    stp x29, x30, [sp, #-96]!
    mov x29, sp
    stp x19, x20, [sp, #16]
    stp x21, x22, [sp, #32]
    stp x23, x24, [sp, #48]
    stp x25, x26, [sp, #64]
    stp d8, d9, [sp, #80]            // Guardar v8-v9 (callee-saved SIMD)

    // Guardar parámetros
    mov x19, x0                      // key
    mov x20, x1                      // nonce
    mov x21, x2                      // AAD
    mov x22, x3                      // AAD len
    mov x23, x4                      // plaintext
    mov x24, x5                      // plaintext len
    mov x25, x6                      // ciphertext
    mov x26, x7                      // tag

    // === Fase 1: Init (inline, sin llamada a función) ===
    // Cargar key y nonce
    ld1 {v8.16b}, [x19]              // v8 = key
    ld1 {v9.16b}, [x20]              // v9 = nonce

    // Cargar constantes
#if defined(__APPLE__)
    adrp x10, AEGIS_C0@PAGE
    add x10, x10, AEGIS_C0@PAGEOFF
    ld1 {v10.16b}, [x10]
    adrp x10, AEGIS_C1@PAGE
    add x10, x10, AEGIS_C1@PAGEOFF
    ld1 {v11.16b}, [x10]
#else
    adrp x10, AEGIS_C0
    add x10, x10, :lo12:AEGIS_C0
    ld1 {v10.16b}, [x10]
    adrp x10, AEGIS_C1
    add x10, x10, :lo12:AEGIS_C1
    ld1 {v11.16b}, [x10]
#endif

    // Init state en registros
    eor v0.16b, v8.16b, v9.16b       // S0 = key ^ nonce
    mov v1.16b, v11.16b              // S1 = C1
    mov v2.16b, v10.16b              // S2 = C0
    mov v3.16b, v11.16b              // S3 = C1
    eor v4.16b, v8.16b, v9.16b       // S4 = key ^ nonce
    eor v5.16b, v8.16b, v10.16b      // S5 = key ^ C0
    eor v6.16b, v8.16b, v11.16b      // S6 = key ^ C1
    eor v7.16b, v8.16b, v10.16b      // S7 = key ^ C0

    // 10 init rounds (todo en registros)
    AEGIS_UPDATE v9, v8
    AEGIS_UPDATE v9, v8
    AEGIS_UPDATE v9, v8
    AEGIS_UPDATE v9, v8
    AEGIS_UPDATE v9, v8
    AEGIS_UPDATE v9, v8
    AEGIS_UPDATE v9, v8
    AEGIS_UPDATE v9, v8
    AEGIS_UPDATE v9, v8
    AEGIS_UPDATE v9, v8

    // === Fase 2: Procesar AAD ===
    mov x10, x21                     // AAD ptr
    mov x11, x22                     // AAD remaining

.Laad_loop_opt:
    cmp x11, #32
    b.lt .Laad_done_opt

    // Cargar AAD block a registros temporales
    ld1 {v12.16b}, [x10], #16        // M0
    ld1 {v13.16b}, [x10], #16        // M1

    // Update con AAD (inline)
    AEGIS_UPDATE v12, v13

    sub x11, x11, #32
    b .Laad_loop_opt

.Laad_done_opt:
    // TODO: handle partial AAD

    // === Fase 3: Encrypt ===
    mov x10, x23                     // plaintext ptr
    mov x11, x24                     // plaintext remaining

.Lenc_loop_opt:
    cmp x11, #32
    b.lt .Lenc_done_opt

    // Generar keystream (en v12, v13)
    // keystream0 = S1 ^ S4 ^ S5 ^ (S2 & S3)
    and v12.16b, v2.16b, v3.16b
    eor v12.16b, v12.16b, v1.16b
    eor v12.16b, v12.16b, v4.16b
    eor v12.16b, v12.16b, v5.16b

    // keystream1 = S2 ^ S5 ^ S6 ^ (S3 & S4)
    and v13.16b, v3.16b, v4.16b
    eor v13.16b, v13.16b, v2.16b
    eor v13.16b, v13.16b, v5.16b
    eor v13.16b, v13.16b, v6.16b

    // Cargar plaintext
    ld1 {v14.16b}, [x10], #16
    ld1 {v15.16b}, [x10], #16

    // XOR para ciphertext
    eor v26.16b, v14.16b, v12.16b
    eor v27.16b, v15.16b, v13.16b

    // Guardar ciphertext
    st1 {v26.16b}, [x25], #16
    st1 {v27.16b}, [x25], #16

    // Update con plaintext (v14, v15 ya contienen el plaintext)
    AEGIS_UPDATE v14, v15

    sub x11, x11, #32
    b .Lenc_loop_opt

.Lenc_done_opt:
    // TODO: handle partial block
    // TODO: finalization

    // Zeroizar key/nonce de registros
    movi v8.16b, #0
    movi v9.16b, #0

    // Epilogue
    ldp d8, d9, [sp, #80]
    ldp x25, x26, [sp, #64]
    ldp x23, x24, [sp, #48]
    ldp x21, x22, [sp, #32]
    ldp x19, x20, [sp, #16]
    ldp x29, x30, [sp], #96
    ret

#if !defined(__APPLE__) && !defined(_WIN32) && !defined(_WIN64)
.size FUNC(aegis128l_encrypt), .-FUNC(aegis128l_encrypt)
#endif
