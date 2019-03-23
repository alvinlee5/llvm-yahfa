#include "jni.h"
#include <string.h>
#include <sys/mman.h>
#include <stdlib.h>

#include "common.h"
#include "trampoline.h"

static unsigned char *trampolineCode; // place where trampolines are saved
static unsigned int trampolineSize; // trampoline size required for each hook

unsigned int hookCap = 0;
unsigned int hookCount = 0;

// trampoline:
// 1. set eax/r0/x0 to the hook ArtMethod addr
// 2. jump into its entry point
#if defined(__i386__)
// b8 78 56 34 12 ; mov eax, 0x12345678 (addr of the hook method)
// ff 70 20 ; push DWORD PTR [eax + 0x20]
// c3 ; ret
unsigned char trampoline[] = {
        0xb8, 0x78, 0x56, 0x34, 0x12,
        0xff, 0x70, 0x20,
        0xc3
};

#elif defined(__x86_64__)
// 48 bf 78 56 34 12 78 56 34 12 ; movabs rdi, 0x1234567812345678
// ff 77 20 ; push QWORD PTR [rdi + 0x20]
// c3 ; ret
unsigned char trampoline[] = {
    0x48, 0xbf, 0x78, 0x56, 0x34, 0x12, 0x78, 0x56, 0x34, 0x12,
    0xff, 0x77, 0x20,
    0xc3
};

#elif defined(__arm__)
// 00 00 9F E5 ; ldr r0, [pc, #0]
// 20 F0 90 E5 ; ldr pc, [r0, 0x20]
// 78 56 34 12 ; 0x12345678 (addr of the hook method)
unsigned char trampoline[] = {
        0x00, 0x00, 0x9f, 0xe5,
        0x20, 0xf0, 0x90, 0xe5,
        0x78, 0x56, 0x34, 0x12
};

#elif defined(__aarch64__)
// 60 00 00 58 ; ldr x0, 12
// 10 00 40 F8 ; ldr x16, [x0, #0x00]
// 00 02 1f d6 ; br x16
// 78 56 34 12
// 89 67 45 23 ; 0x2345678912345678 (addr of the hook method)
unsigned char trampoline[] = {
        0x60, 0x00, 0x00, 0x58,
        0x10, 0x00, 0x40, 0xf8,
        0x00, 0x02, 0x1f, 0xd6,
        0x78, 0x56, 0x34, 0x12,
        0x89, 0x67, 0x45, 0x23
};
#endif
static unsigned int trampolineSize = roundUpToPtrSize(sizeof(trampoline));

void *genTrampoline(void *hookMethod) {
    int llvm = 1;
    LOGI("DEBUG: targetAddr: %p", &llvm);
    LOGI("DEBUG: targetAddr: %d", llvm);

    void *targetAddr;
    targetAddr = trampolineCode + trampolineSize * hookCount;
    memcpy(targetAddr, trampoline,
           sizeof(trampoline)); // do not use trampolineSize since it's a rounded size

    // replace with the actual ArtMethod addr
#if defined(__i386__)
    memcpy(targetAddr+1, &hookMethod, pointer_size);

#elif defined(__x86_64__)
    memcpy((char*)targetAddr + 2, &hookMethod, pointer_size);

#elif defined(__arm__)
    memcpy(targetAddr+8, &hookMethod, pointer_size);

#elif defined(__aarch64__)
    memcpy(targetAddr + 12, &hookMethod, pointer_size);

#else
#error Unsupported architecture
#endif

    return targetAddr;
}

void setupTrampoline() {
    int llvm = 2;
    LOGI("DEBUG: ADDR: %p", &llvm);
    LOGI("DEBUG: VAL: %d", llvm);
#if defined(__i386__)
    trampoline[7] = (unsigned char)OFFSET_entry_point_from_quick_compiled_code_in_ArtMethod;
#elif defined(__x86_64__)
    trampoline[12] = (unsigned char)OFFSET_entry_point_from_quick_compiled_code_in_ArtMethod;
#elif defined(__arm__)
    trampoline[4] = (unsigned char)OFFSET_entry_point_from_quick_compiled_code_in_ArtMethod;
#elif defined(__aarch64__)
    trampoline[5] |=
            ((unsigned char) OFFSET_entry_point_from_quick_compiled_code_in_ArtMethod) << 4;
    trampoline[6] |=
            ((unsigned char) OFFSET_entry_point_from_quick_compiled_code_in_ArtMethod) >> 4;
#else
#error Unsupported architecture
#endif
}

int doInitHookCap(unsigned int cap) {
    int llvm = 3;
    LOGI("DEBUG: ADDR: %p", &llvm);
    LOGI("DEBUG: VAL: %d", llvm);
    if (cap == 0) {
        LOGE("invalid capacity: %d", cap);
        return 1;
    }
    if (hookCap) {
        LOGW("allocating new space for trampoline code");
    }
    unsigned int allSize = trampolineSize * cap;
    LOGI("DEBUG: cap val: %d", cap);
    unsigned char *buf = mmap(NULL, allSize, PROT_READ | PROT_WRITE | PROT_EXEC,
                              MAP_ANON | MAP_PRIVATE, -1, 0);
    if (buf == MAP_FAILED) {
        LOGE("mmap failed");
        return 1;
    }
    hookCap = cap;
    hookCount = 0;
    trampolineCode = buf;
    return 0;
}

int SDKVersion;
static int OFFSET_entry_point_from_interpreter_in_ArtMethod;
int OFFSET_entry_point_from_quick_compiled_code_in_ArtMethod;
static int OFFSET_dex_method_index_in_ArtMethod;
static int OFFSET_dex_cache_resolved_methods_in_ArtMethod;
static int OFFSET_array_in_PointerArray;
static int OFFSET_ArtMehod_in_Object;
static int OFFSET_access_flags_in_ArtMethod;
static size_t ArtMethodSize;
static int kAccNative = 0x0100;
static int kAccCompileDontBother = 0x01000000;
static size_t kDexCacheMethodCacheSize = 1024;

static inline uint32_t read32(void *addr) {
    return *((uint32_t *) addr);
}

static inline uint64_t read64(void *addr) {
    return *((uint64_t *) addr);
}

static inline void* readAddr(void *addr) {
    return *((void**) addr);
}

void Java_lab_galaxy_yahfa_HookMain_init(JNIEnv *env, jclass clazz, jint sdkVersion) {
    int llvm = 4;
    LOGI("DEBUG: ADDR: %p", &llvm);
    LOGI("DEBUG: VAL: %d", llvm);
    int i;
    SDKVersion = sdkVersion;
    LOGI("init to SDK %d", sdkVersion);
    switch (sdkVersion) {
        case __ANDROID_API_P__:
            kAccCompileDontBother = 0x02000000;
            OFFSET_ArtMehod_in_Object = 0;
            OFFSET_access_flags_in_ArtMethod = 4;
            //OFFSET_dex_method_index_in_ArtMethod = 4*3;
            OFFSET_entry_point_from_quick_compiled_code_in_ArtMethod =
                    roundUpToPtrSize(4 * 4 + 2 * 2) + pointer_size;
            ArtMethodSize = roundUpToPtrSize(4 * 4 + 2 * 2) + pointer_size * 2;
            break;
        case __ANDROID_API_O_MR1__:
            kAccCompileDontBother = 0x02000000;
        case __ANDROID_API_O__:
            OFFSET_ArtMehod_in_Object = 0;
            OFFSET_access_flags_in_ArtMethod = 4;
            OFFSET_dex_method_index_in_ArtMethod = 4 * 3;
            OFFSET_dex_cache_resolved_methods_in_ArtMethod = roundUpToPtrSize(4 * 4 + 2 * 2);
            OFFSET_array_in_PointerArray = 0;
            OFFSET_entry_point_from_quick_compiled_code_in_ArtMethod =
                    roundUpToPtrSize(4 * 4 + 2 * 2) + pointer_size * 2;
            ArtMethodSize = roundUpToPtrSize(4 * 4 + 2 * 2) + pointer_size * 3;
            break;
        case __ANDROID_API_N_MR1__:
        case __ANDROID_API_N__:
            OFFSET_ArtMehod_in_Object = 0;
            OFFSET_access_flags_in_ArtMethod = 4; // sizeof(GcRoot<mirror::Class>) = 4
            OFFSET_dex_method_index_in_ArtMethod = 4 * 3;
            OFFSET_dex_cache_resolved_methods_in_ArtMethod = roundUpToPtrSize(4 * 4 + 2 * 2);
            OFFSET_array_in_PointerArray = 0;

            // ptr_sized_fields_ is rounded up to pointer_size in ArtMethod
            OFFSET_entry_point_from_quick_compiled_code_in_ArtMethod =
                    roundUpToPtrSize(4 * 4 + 2 * 2) + pointer_size * 3;

            ArtMethodSize = roundUpToPtrSize(4 * 4 + 2 * 2) + pointer_size * 4;
            break;
        case __ANDROID_API_M__:
            OFFSET_ArtMehod_in_Object = 0;
            OFFSET_entry_point_from_interpreter_in_ArtMethod = roundUpToPtrSize(4 * 7);
            OFFSET_entry_point_from_quick_compiled_code_in_ArtMethod =
                    OFFSET_entry_point_from_interpreter_in_ArtMethod + pointer_size * 2;
            OFFSET_dex_method_index_in_ArtMethod = 4 * 5;
            OFFSET_dex_cache_resolved_methods_in_ArtMethod = 4;
            OFFSET_array_in_PointerArray = 4 * 3;
            ArtMethodSize = roundUpToPtrSize(4 * 7) + pointer_size * 3;
            break;
        case __ANDROID_API_L_MR1__:
            OFFSET_ArtMehod_in_Object = 4 * 2;
            OFFSET_entry_point_from_interpreter_in_ArtMethod = roundUpToPtrSize(
                    OFFSET_ArtMehod_in_Object + 4 * 7);
            OFFSET_entry_point_from_quick_compiled_code_in_ArtMethod =
                    OFFSET_entry_point_from_interpreter_in_ArtMethod + pointer_size * 2;
            OFFSET_dex_method_index_in_ArtMethod = OFFSET_ArtMehod_in_Object + 4 * 5;
            OFFSET_dex_cache_resolved_methods_in_ArtMethod = OFFSET_ArtMehod_in_Object + 4;
            OFFSET_array_in_PointerArray = 12;
            ArtMethodSize = OFFSET_entry_point_from_interpreter_in_ArtMethod + pointer_size * 3;
            break;
        case __ANDROID_API_L__:
            OFFSET_ArtMehod_in_Object = 4 * 2;
            OFFSET_entry_point_from_interpreter_in_ArtMethod = OFFSET_ArtMehod_in_Object + 4 * 4;
            OFFSET_entry_point_from_quick_compiled_code_in_ArtMethod =
                    OFFSET_entry_point_from_interpreter_in_ArtMethod + 8 * 2;
            OFFSET_dex_method_index_in_ArtMethod =
                    OFFSET_ArtMehod_in_Object + 4 * 4 + 8 * 4 + 4 * 2;
            OFFSET_dex_cache_resolved_methods_in_ArtMethod = OFFSET_ArtMehod_in_Object + 4;
            OFFSET_array_in_PointerArray = 12;
            ArtMethodSize = OFFSET_ArtMehod_in_Object + 4 * 4 + 8 * 4 + 4 * 4;
            break;
        default:
            LOGE("not compatible with SDK %d", sdkVersion);
            break;
    }

    setupTrampoline();
}

static void setNonCompilable(void *method) {
    int llvm = 5;
    LOGI("DEBUG: ADDR: %p", &llvm);
    LOGI("DEBUG: VAL: %d", llvm);
    int access_flags = read32((char *) method + OFFSET_access_flags_in_ArtMethod);
    LOGI("setNonCompilable: access flags is 0x%x", access_flags);
    access_flags |= kAccCompileDontBother;
    memcpy(
            (char *) method + OFFSET_access_flags_in_ArtMethod,
            &access_flags,
            4
    );
}

static int doBackupAndHook(void *targetMethod, void *hookMethod, void *backupMethod) {
    int llvm = 6;
    int llvm2;
    LOGI("DEBUG: ADDR: %p", &llvm);
    LOGI("DEBUG: VAL: %d", llvm);
    if (hookCount >= hookCap) {
        LOGW("not enough capacity. Allocating...");
        if (doInitHookCap(DEFAULT_CAP)) {
            LOGE("cannot hook method");
            return 1;
        }
        LOGI("Allocating done");
    }

    LOGI("target method is at %p, hook method is at %p, backup method is at %p",
         targetMethod, hookMethod, backupMethod);


    // set kAccCompileDontBother for a method we do not want the compiler to compile
    // so that we don't need to worry about hotness_count_
    if (SDKVersion >= __ANDROID_API_N__) {
        setNonCompilable(targetMethod);
        setNonCompilable(hookMethod);
    }

    if (backupMethod) {// do method backup

        // have to copy the whole target ArtMethod here
        // if the target method calls other methods which are to be resolved
        // then ToDexPC would be invoked for the caller(origin method)
        // in which case ToDexPC would use the entrypoint as a base for mapping pc to dex offset
        // so any changes to the target method's entrypoint would result in a wrong dex offset
        // and artQuickResolutionTrampoline would fail for methods called by the origin method
        memcpy((void*)&llvm2, (void*)&llvm, sizeof(int));
        LOGI("DEBUG: ADDR: %p", &llvm2);
        LOGI("DEBUG: VAL: %d", llvm2);

        LOGI("DEBUG: BACKUPMETHOD: %p", backupMethod);
        int val = memcmp(backupMethod, targetMethod, ArtMethodSize);
        if (val == 0)
        {
            LOGI("DEBUG: ALL SAME");
        }
        else
        {
            LOGI("DEBUG: DIFFERENT");
        }
        memcpy(backupMethod, targetMethod, ArtMethodSize);
        val = memcmp(backupMethod, targetMethod, ArtMethodSize);
        if (val == 0)
        {
            LOGI("DEBUG - AFTER MEMCPY: ALL SAME");
        }
        else
        {
            LOGI("DEBUG - AFTER MEMCPY: DIFFERENT");
        }
    }

    // replace entry point
    void *newEntrypoint = genTrampoline(hookMethod);
    LOGI("origin ep is %p, new ep is %p",
         readAddr((char *) targetMethod + OFFSET_entry_point_from_quick_compiled_code_in_ArtMethod),
         newEntrypoint
    );
    if (newEntrypoint) {
        memcpy((char *) targetMethod + OFFSET_entry_point_from_quick_compiled_code_in_ArtMethod,
               &newEntrypoint,
               pointer_size);
    } else {
        LOGW("failed to allocate space for trampoline of target method");
        return 1;
    }

    if (OFFSET_entry_point_from_interpreter_in_ArtMethod != 0) {
        memcpy((char *) targetMethod + OFFSET_entry_point_from_interpreter_in_ArtMethod,
               (char *) hookMethod + OFFSET_entry_point_from_interpreter_in_ArtMethod,
               pointer_size);
    }

    // set the target method to native so that Android O wouldn't invoke it with interpreter
    if (SDKVersion >= __ANDROID_API_O__) {
        int access_flags = read32((char *) targetMethod + OFFSET_access_flags_in_ArtMethod);
        access_flags |= kAccNative;
        memcpy(
                (char *) targetMethod + OFFSET_access_flags_in_ArtMethod,
                &access_flags,
                4
        );
        LOGI("access flags is 0x%x", access_flags);
    }

    LOGI("hook and backup done");
    hookCount += 1;
    return 0;
}

static void ensureMethodCached(void *hookMethod, void *backupMethod) {
    int llvm = 7;
    LOGI("DEBUG: ADDR: %p", &llvm);
    LOGI("DEBUG: VAL: %d", llvm);
    if (SDKVersion <= __ANDROID_API_O_MR1__) {
        // update the cached method manually
        // first we find the array of cached methods
        void *dexCacheResolvedMethods = (void *) readAddr(
                (void *) ((char *) hookMethod +
                          OFFSET_dex_cache_resolved_methods_in_ArtMethod));

        // then we get the dex method index of the static backup method
        unsigned int methodIndex = read32(
                (void *) ((char *) backupMethod + OFFSET_dex_method_index_in_ArtMethod));

        // finally the addr of backup method is put at the corresponding location in cached methods array
        if (SDKVersion == __ANDROID_API_O_MR1__) {
            // array of MethodDexCacheType is used as dexCacheResolvedMethods in Android 8.1
            // struct:
            // struct NativeDexCachePair<T> = { T*, size_t idx }
            // MethodDexCachePair = NativeDexCachePair<ArtMethod> = { ArtMethod*, size_t idx }
            // MethodDexCacheType = std::atomic<MethodDexCachePair>

            // https://github.com/rk700/YAHFA/issues/91
            // for Android 8.1, the MethodDexCacheType array is of limited size
            // the remainder of method index mod array size is used for indexing
            size_t slotIndex = methodIndex % kDexCacheMethodCacheSize;
            LOGI("method index is %d, slot index id %zd", methodIndex, slotIndex);

            // any element could be overwritten since the array is of limited size
            // so just malloc a new buffer used as cached methods array for hookMethod to resolve backupMethod
            void *newCachedMethodsArray = calloc(kDexCacheMethodCacheSize, pointer_size * 2);

            // the 0th entry of the array has method index as 1
            unsigned int one = 1;
            memcpy(newCachedMethodsArray + pointer_size, &one, 4);

            // update the backupMethod addr in cached methods array
            memcpy(newCachedMethodsArray + pointer_size * 2 * slotIndex,
                   (&backupMethod),
                   pointer_size
            );
            // update the backupMethod index in cached methods array
            memcpy(newCachedMethodsArray + pointer_size * 2 * slotIndex + pointer_size,
                   &methodIndex,
                   4
            );

            // use the new buffer as cached methods array for hookMethod
            memcpy(((char *) hookMethod) + OFFSET_dex_cache_resolved_methods_in_ArtMethod,
                   (&newCachedMethodsArray),
                   pointer_size);

        } else {
                memcpy((char *) dexCacheResolvedMethods + OFFSET_array_in_PointerArray +
                       pointer_size * methodIndex,
                       (&backupMethod),
                       pointer_size);
        }
    }
}

jobject Java_lab_galaxy_yahfa_HookMain_findMethodNative(JNIEnv *env, jclass clazz,
                                                        jclass targetClass, jstring methodName,
                                                        jstring methodSig) {
    int llvm = 8;
    LOGI("DEBUG: ADDR: %p", &llvm);
    LOGI("DEBUG: VAL: %d", llvm);
    //(*env)->GetStringUTFChars(env, methodName, NULL);
    const char *c_methodName = (*env)->GetStringUTFChars(env, methodName, NULL);
    const char *c_methodSig = (*env)->GetStringUTFChars(env, methodSig, NULL);
    jobject ret = NULL;


    //Try both GetMethodID and GetStaticMethodID -- Whatever works :)
    jmethodID method = (*env)->GetMethodID(env, targetClass, c_methodName, c_methodSig);
    if (!(*env)->ExceptionCheck(env)) {
        ret = (*env)->ToReflectedMethod(env, targetClass, method, JNI_FALSE);
    } else {
        (*env)->ExceptionClear(env);
        method = (*env)->GetStaticMethodID(env, targetClass, c_methodName, c_methodSig);
        if (!(*env)->ExceptionCheck(env)) {
            ret = (*env)->ToReflectedMethod(env, targetClass, method, JNI_TRUE);
        }
    }

    (*env)->ReleaseStringUTFChars(env, methodName, c_methodName);
    (*env)->ReleaseStringUTFChars(env, methodSig, c_methodSig);
    return ret;
    //return NULL;
}

jboolean Java_lab_galaxy_yahfa_HookMain_backupAndHookNative(JNIEnv *env, jclass clazz,
                                                            jobject target, jobject hook,
                                                            jobject backup) {
    int llvm = 9;
    LOGI("DEBUG: ADDR: %p", &llvm);
    LOGI("DEBUG: VAL: %d", llvm);

    if (!doBackupAndHook(
            (void *) (*env)->FromReflectedMethod(env, target),
            (void *) (*env)->FromReflectedMethod(env, hook),
            backup == NULL ? NULL : (void *) (*env)->FromReflectedMethod(env, backup)
    )) {
        (*env)->NewGlobalRef(env,
                             hook); // keep a global ref so that the hook method would not be GCed
        return JNI_TRUE;
    } else {
        return JNI_FALSE;
    }
}


void Java_lab_galaxy_yahfa_HookMain_ensureMethodCached(JNIEnv *env, jclass clazz,
                                                           jobject hook,
                                                           jobject backup) {
    int llvm = 10;
    LOGI("DEBUG: ADDR: %p", &llvm);
    LOGI("DEBUG: VAL: %d", llvm);
    ensureMethodCached((void *) (*env)->FromReflectedMethod(env, hook), backup == NULL ? NULL : (void *) (*env)->FromReflectedMethod(env, backup));
}
