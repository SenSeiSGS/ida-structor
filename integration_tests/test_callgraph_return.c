#include <stdint.h>
#include <stdio.h>

static volatile uint64_t sink;

#define OFF_MAGIC 0x00  // uint64_t
#define OFF_FLAGS 0x08  // uint32_t / float (intentional conflict)
#define OFF_MODE  0x0C  // uint16_t
#define OFF_SCORE 0x10  // double
#define OFF_KIND  0x18  // uint8_t
#define OFF_SELF  0x20  // void*
#define OFF_COUNT 0x28  // uint32_t
#define OFF_ARR0  0x30  // uint64_t[3]
#define OFF_ARR1  0x38
#define OFF_ARR2  0x40
#define OFF_CRC   0x48  // uint32_t
#define OFF_BYTES 0x50  // uint8_t[8]
#define OFF_SUB   0x60  // sub-struct base

#define SUB_TAG   0x00  // uint32_t
#define SUB_VALUE 0x08  // uint64_t
#define SUB_STATE 0x10  // uint8_t

__attribute__((noinline))
void init_root(void *p) {
    uint8_t *b = (uint8_t *)p;
    *(uint64_t *)(b + OFF_MAGIC) = 0x1122334455667788ULL;
    *(uint32_t *)(b + OFF_FLAGS) = 0xAABBCCDDU;
    *(uint16_t *)(b + OFF_MODE) = 0x3344U;
    *(double *)(b + OFF_SCORE) = 3.14159;
    *(uint8_t *)(b + OFF_KIND) = 0x7FU;
    *(void **)(b + OFF_SELF) = p;
    *(uint32_t *)(b + OFF_COUNT) = 3U;

    *(uint64_t *)(b + OFF_ARR0) = 0x1111111111111111ULL;
    *(uint64_t *)(b + OFF_ARR1) = 0x2222222222222222ULL;
    *(uint64_t *)(b + OFF_ARR2) = 0x3333333333333333ULL;

    *(uint32_t *)(b + OFF_CRC) = 0xDEADBEAFU;

    b[OFF_BYTES + 0] = 0x10;
    b[OFF_BYTES + 1] = 0x20;
    b[OFF_BYTES + 2] = 0x30;
    b[OFF_BYTES + 3] = 0x40;

    // Sub-struct at base + OFF_SUB
    uint8_t *s = b + OFF_SUB;
    *(uint32_t *)(s + SUB_TAG) = 0x1234U;
    *(uint64_t *)(s + SUB_VALUE) = 0xCAFEBABECAFED00DULL;
    *(uint8_t *)(s + SUB_STATE) = 0x5AU;
}

__attribute__((noinline))
void process_root(void *p) {
    uint8_t *b = (uint8_t *)p;
    sink ^= *(uint64_t *)(b + OFF_MAGIC);
    sink ^= *(uint32_t *)(b + OFF_FLAGS);
    sink ^= *(uint16_t *)(b + OFF_MODE);
    sink ^= (uint64_t)(*(uint8_t *)(b + OFF_KIND));
    sink ^= *(uint64_t *)(b + OFF_ARR1);
    sink ^= *(uint32_t *)(b + OFF_CRC);
}

__attribute__((noinline))
void conflict_reader(void *p) {
    uint8_t *b = (uint8_t *)p;
    float f = *(float *)(b + OFF_FLAGS);
    sink ^= (uint64_t)(*(uint32_t *)&f);
}

__attribute__((noinline))
void sibling_reader(void *p) {
    uint8_t *b = (uint8_t *)p;
    sink ^= (uint64_t)(*(uint8_t *)(b + OFF_BYTES + 1));
    sink ^= *(uint64_t *)(b + OFF_ARR2);
}

__attribute__((noinline))
void process_sub(void *sub) {
    uint8_t *s = (uint8_t *)sub;
    sink ^= *(uint32_t *)(s + SUB_TAG);
    sink ^= *(uint64_t *)(s + SUB_VALUE);
    sink ^= (uint64_t)(*(uint8_t *)(s + SUB_STATE));
}

__attribute__((noinline))
void wrapper_chain(void *p) {
    process_root(p);
    process_sub((uint8_t *)p + OFF_SUB);
}

__attribute__((noinline))
void alias_forward(void *p) {
    void *alias = p;
    process_root(alias);
}

__attribute__((noinline))
void *make_root(void) {
    static uint8_t storage[0x80];
    init_root(storage);
    return storage;
}

__attribute__((noinline))
void *make_sub(void *p) {
    return (uint8_t *)p + OFF_SUB;
}

__attribute__((noinline))
void chain_from_return(void) {
    void *p = make_root();
    process_root(p);
    conflict_reader(p);
    sibling_reader(p);

    void *sub = make_sub(p);
    process_sub(sub);
}

int main(void) {
    uint8_t buf[0x80];

    // Address-of pass to exercise cot_ref argument matching.
    init_root(&buf);

    wrapper_chain(buf);
    sibling_reader(buf);
    alias_forward(buf);
    conflict_reader(buf);

    chain_from_return();

    printf("sink=%llx\n", (unsigned long long)sink);
    return 0;
}
