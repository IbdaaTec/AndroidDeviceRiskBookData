// JVMTI 实现内存漫游功能源码
using PluginInitializationFunction = bool (*)();
static const char *PLUGIN_INITIALIZATION_FUNCTION_NAME = "ArtPlugin_Initialize";
static jvmtiEnv *gJvmTi = nullptr;
static bool isInit  = false;

jvmtiEnv *JvmTi::init(JavaVM *vm) {
    if (isInit) return gJvmTi;
    auto handler =
            xdl_open("libopenjdkjvmti.so", XDL_TRY_FORCE_LOAD);
    if (handler == nullptr) {
        LOG(ERROR) << "ZhenxiRuntime::JvmTi::init xdl_open ERROR ";
        return nullptr;
    }
    auto sym = xdl_sym(handler,
                       PLUGIN_INITIALIZATION_FUNCTION_NAME, nullptr);
    if (sym == nullptr) {
        sym = xdl_dsym(handler,
                       PLUGIN_INITIALIZATION_FUNCTION_NAME, nullptr);
    }
    if(sym == nullptr){
        LOG(INFO)<< "JvmTi::init ArtPlugin_Initialize == null " ;
        return nullptr;
    }
    auto init = reinterpret_cast<PluginInitializationFunction>(sym);
    if (init != nullptr) {
        auto init_ret = init();
        if (init_ret) {
            LOG(INFO) << "ZhenxiRuntime::JvmTi::init success ! ";
        } else {
            LOG(ERROR) << "ZhenxiRuntime::JvmTi::init fail ! ";
        }
    }

    jvmtiEnv *jvmti = nullptr;
    if (vm->GetEnv((void **) &jvmti, 0x30010200) != JNI_OK) {
        if (vm->GetEnv((void **) &jvmti, 0x70010200) != JNI_OK) {
            LOG(ERROR) << "get jvmtiEnv error ";
            return nullptr;
        }
    }
    if (jvmti != nullptr) {
        gJvmTi = jvmti;
        const jvmtiCapabilities REQUIRED_CAPABILITIES = {
                .can_tag_objects = 1,
                .can_get_bytecodes = 1,
        };
        if (jvmti->AddCapabilities(&REQUIRED_CAPABILITIES) != JVMTI_ERROR_NONE) {
            LOGE("jvmti init error setting capabilities.");
            jvmti->DisposeEnvironment();
            return nullptr;
        }
        isInit = true;
        LOG(ERROR) << "ZhenxiRuntime::JvmTi::init success finish ! ";
    } else {
        LOG(ERROR) << "ZhenxiRuntime::JvmTi::init fail ! ";
    }
    return gJvmTi;
}

jlong myTag = 0x12345;
jvmtiIterationControl callback_1(jlong class_tag, jlong size, jlong* tag_ptr, void* user_data)
{
    //给遍历的class设置标签
    *tag_ptr = myTag;
    return JVMTI_ITERATION_CONTINUE;
}

jint callback_2(jlong class_tag, jlong size, jlong* tag_ptr, jint length, void* user_data)
{
    *tag_ptr = myTag;
    return JVMTI_VISIT_OBJECTS;
}

std::string getJClassName(JNIEnv* env, jclass clazz) {
    jclass classClass = env->GetObjectClass(clazz);
    jmethodID getNameMethod = env->GetMethodID(classClass, "getName", "()Ljava/lang/String;");
    jstring classNameJString = (jstring)env->CallObjectMethod(clazz, getNameMethod);
    return env->GetStringUTFChars(classNameJString, nullptr);
}

/**
 * Gets all instances of the specified class in the memory
 * @param env
 * @param clazz
 * @return
 */
jobjectArray Runtime::JvmTi::Choose(JNIEnv *env, jclass clazz) {
    if (clazz == nullptr) {
        LOG(ERROR) << "Runtime::JvmTi::Choose clazz == null ";
        return nullptr;
    }
    jvmtiEnv *jvmTiPtr = JvmTi::init(mVm);
    if (jvmTiPtr == nullptr) {
        LOG(ERROR) << "Runtime::JvmTi::init fail ";
        return nullptr;
    }

    jvmtiError e = jvmTiPtr->
            IterateOverInstancesOfClass(clazz, JVMTI_HEAP_OBJECT_EITHER, callback_1, nullptr);
    if (e != JVMTI_ERROR_NONE) {
        jvmtiHeapCallbacks callbacks = {0};
        callbacks.heap_iteration_callback = &callback_2;
        //IterateThroughHeap的行为和高版本一样, 不遍历子类实例。
        e = jvmTiPtr->IterateThroughHeap(0, clazz, &callbacks, nullptr);
        if(e != JVMTI_ERROR_NONE){
            LOGE("jvmti IterateThroughHeap error %d", e);
            return nullptr;
        }
    }

    jint objectCount = 0;
    jobject *results = nullptr;
    jlong *tags = nullptr;
    auto jvmtiErrorObj = jvmTiPtr->GetObjectsWithTags(1, &myTag, &objectCount, &results, &tags);
    if (jvmtiErrorObj != JVMTI_ERROR_NONE) {
        LOGE("jvmti GetObjectsWithTags error %d", jvmtiErrorObj)
        return nullptr;
    }
    jclass obj_clazz = env->FindClass("java/lang/Object");
    jobjectArray objectArray = env->NewObjectArray(objectCount, obj_clazz, nullptr);

    //jobjectArray objectArray = env->NewObjectArray(objectCount, clazz, nullptr);
    //LOGE("jvmti get results size  %d ",objectCount)
    for (int i = 0; i < objectCount; i++) {
        jobject obj = results[i];
        if(obj == nullptr || env->IsSameObject(obj, nullptr)) continue;
        if (env->IsInstanceOf(obj, clazz)) {
            //LOGE("jvmti SetObjectArrayElement  %s ",getJClassName(env,env->GetObjectClass(results[i])).c_str())
            env->SetObjectArrayElement(objectArray, i, obj);
        }
    }

    if (results)
        jvmTiPtr->Deallocate((unsigned char *) results);
    if (tags)
        jvmTiPtr->Deallocate((unsigned char *) tags);
    return objectArray;
}

jint Runtime::JvmTi::getMethodByteCode(JNIEnv *env, jmethodID jmethodId) {
    if (jmethodId == nullptr) {
        return 0;
    }
    jvmtiEnv *jvmTiPtr = JvmTi::init(mVm);
    if (jvmTiPtr == nullptr) {
        return 0;
    }
    jint ret = 0;
    unsigned char* byteptr = nullptr;
    auto jvmtiErrorObj = jvmTiPtr->GetBytecodes(jmethodId,&ret,&byteptr);
    if (jvmtiErrorObj != JVMTI_ERROR_NONE) {
        LOGE("jvmti GetObjectsWithTags error %d", jvmtiErrorObj)
        return 0;
    }
    return ret;
}

jlong QuoteTag = 0x56789;

jvmtiIterationControl QuoteCallBack(jvmtiObjectReferenceKind reference_kind,
                                    jlong class_tag, jlong size,
                                    jlong* tag_ptr, jlong referrer_tag,
                                    jint referrer_index, void* user_data){
    if(reference_kind == JVMTI_REFERENCE_CLASS||reference_kind == JVMTI_REFERENCE_FIELD){
        *tag_ptr = myTag;
    }
    return JVMTI_ITERATION_CONTINUE;
}

jobjectArray Runtime::JvmTi::getObjectQuote(JNIEnv *env, jobject obj) {
    if (obj == nullptr) {
        return 0;
    }
    jvmtiEnv *jvmTiPtr = JvmTi::init(mVm);
    if (jvmTiPtr == nullptr) {
        return 0;
    }
    auto jvmtiErrorObj = jvmTiPtr->
            IterateOverObjectsReachableFromObject(obj,QuoteCallBack, nullptr);
    if (jvmtiErrorObj != JVMTI_ERROR_NONE) {
        LOGE("jvmti getObjectQuote error %d", jvmtiErrorObj)
        return 0;
    }

    jint objectCount = 0;
    jobject *results = nullptr;
    jlong *tags = nullptr;
    jvmtiErrorObj = jvmTiPtr->GetObjectsWithTags(1, &myTag, &objectCount, &results, &tags);
    if (jvmtiErrorObj != JVMTI_ERROR_NONE) {
        LOGE("jvmti GetObjectsWithTags error %d", jvmtiErrorObj)
        return nullptr;
    }
    jclass obj_clazz = env->FindClass("java/lang/Object");
    jobjectArray objectArray = env->NewObjectArray(objectCount, obj_clazz, nullptr);

    //jobjectArray objectArray = env->NewObjectArray(objectCount, clazz, nullptr);
    //LOGE("jvmti get results size  %d ",objectCount)
    for (int i = 0; i < objectCount; i++) {
        jobject temp_obj = results[i];
        if (temp_obj == nullptr || env->IsSameObject(temp_obj, nullptr)) continue;
        env->SetObjectArrayElement(objectArray, i, temp_obj);
    }
    if (results)
        jvmTiPtr->Deallocate((unsigned char *) results);
    if (tags)
        jvmTiPtr->Deallocate((unsigned char *) tags);
    return objectArray;
}