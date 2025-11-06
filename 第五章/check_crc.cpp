static inline
bool write_pid(pid_t pid,void *localData,void* remoteData,size_t size){
    struct iovec local{nullptr};
    struct iovec remote{nullptr};
    local.iov_base = localData;
    local.iov_len = size;
    remote.iov_base = remoteData;
    remote.iov_len = size;
    long ret = syscall(__NR_process_vm_writev, pid, &local, 1, &remote, 1, 0);
    if(ret==size){
        return true;
    }
    LOG(INFO) << ">>>>>>>>>>>> __NR_process_vm_writev error  pid->  "<< pid << " size: " << size<<" "<<ret;
    return false;
}

void *detect_ptrace_loop_main() {
    pid_t threadId = gettid();
    LOGI("detect_ptrace_loop_main tid -> %d ", threadId)
    //往主线程写入对应的数据,标识当前线程被启动
    bool isSuccess = write_pid(getpid(),
                               &threadId,
                               &mainTracerId, sizeof(pid_t));
    LOGE("detect_ptrace_loop_main write tid success  %d  %s ",
         threadId, isSuccess ? "true" : "false")
    JNIEnv *env = ensureEnvCreated();
    if (env == nullptr) {
        LOGE("detect_ptrace_loop get env == null")
        KILL_PROCESS
    }
    LOGE("detect_ptrace_loop get env success %d ", getpid())
    int isPtrace;
    //while true
    while (true) {
        if (isDestroy) {
            break;
        }
        //check libart.so
        isPtrace = checkLibArtCheckSum();
        if (isPtrace == 0) {
            //check libc.so
            isPtrace = checkLibcCheckSum();
            if (isPtrace == 0) {
                //check my hunter.so
                isPtrace = checkMySoCheckSum(hunterSoPath.c_str());
            }
        }
        if (isPtrace == 1) {
            //find elf is hooked 
            crc_error_callback();
        } else if (isPtrace == -1) {
            //check error 
            crc_error_callback(error_msg);
        }
        struct timespec timeSpec{};
        timeSpec.tv_sec = 5;
        timeSpec.tv_nsec = 0;
        //sleep 
        my_nanosleep(&timeSpec, nullptr);
    }
    return nullptr;
}

typedef struct stExecSection {
    int execSectionCount{};
    unsigned long offset[2]{};
    unsigned long memsize[2]{};
    unsigned long checksum[2]{};
    unsigned long startAddrinMem{};
    bool isSuccess = false;
} execSection;

execSection fetch_checksum_of_library(const char *filePath) {
    if (filePath == nullptr || my_strlen(filePath) == 0) {
        LOGE("fetch_checksum_of_library filePath == null %s ", getprogname())
    }

    execSection section = {0};
    section.isSuccess = false;
    Elf_Ehdr ehdr;
    Elf_Shdr sectHdr;
    int fd;
    int execSectionCount = 0;
    //根据路径，打开本地文件，只读即可。
    fd = my_openat(AT_FDCWD, filePath, O_RDONLY, 0);
    if (fd < 0) {
        LOG(INFO) << " open file error " << filePath << " " << strerror(errno);
        return section;
    }

    my_read(fd, &ehdr, sizeof(Elf_Ehdr));
    my_lseek(fd, (off_t) ehdr.e_shoff, SEEK_SET);

    unsigned long memSize[2] = {0};
    unsigned long offset[2] = {0};

    //查找section的plt和text开始位置和长度
    for (int i = 0; i < ehdr.e_shnum; i++) {
        my_memset(&sectHdr, 0, sizeof(Elf_Shdr));
        my_read(fd, &sectHdr, sizeof(Elf_Shdr));
        //通常 PLT and Text 一般都是可执行段(SHF_EXECINSTR)
        if (sectHdr.sh_flags & SHF_EXECINSTR) {
            //保存当前section offset偏移量
            offset[execSectionCount] = sectHdr.sh_offset;
            //保存当前section对应的长度
            memSize[execSectionCount] = sectHdr.sh_size;
            execSectionCount++;
            if (execSectionCount == 2) {
                break;
            }
        }
    }
    //not find SHF_EXECINSTR ?
    if (execSectionCount == 0) {
        LOG(INFO) << "get elf section error " << filePath;
        my_close(fd);
        return section;
    }
    //记录个数
    section.execSectionCount = execSectionCount;
    section.startAddrinMem = 0;
    for (int i = 0; i < execSectionCount; i++) {
        my_lseek(fd, (off_t) offset[i], SEEK_SET);
        //存放text或者plt全部的数据内容,不同的SO文件大小不一样,有的SO文件可能很大,为了兼容小内存手机。
        //所以放在堆里面,而不是栈里面，如果直接分配数组作为Buff缓存，可能在部分低内存手机出现Bug 。
        auto buffer = (void *) calloc(1, memSize[i] * sizeof(uint8_t));
        if (buffer == nullptr) {
            free(buffer);
            return section;
        }
        my_read(fd, buffer, memSize[i]);
        section.offset[i] = offset[i];
        section.memsize[i] = memSize[i];
        //计算内存CRC
        section.checksum[i] = checksum(buffer, memSize[i]);
        free(buffer);
    }
    section.isSuccess = true;
    my_close(fd);
    if (used_cache) {
        (*sectionCache)[pathStr] = section;
    }
    return section;
}

static unsigned long checksum(void *buffer, size_t len) {
    if (buffer == nullptr) {
        return 0;
    }
    unsigned long seed = 0;
    auto *buf = (uint8_t *) buffer;
    for (size_t i = 0; i < len; ++i) {
        auto inode = (unsigned long) (buf[i]);
        if (inode == 0) continue;
        seed += inode;
    }
    return seed;
}


int detect_elf_checksum(const char *soPath, execSection *pSection) {
    if (pSection == nullptr) {
        error_msg.append("detect_elf_checksum execSection == null").append("\n");
        LOGE("detect_elf_checksum execSection == null  ")
        return -1;
    }
    int checkSum = -1;
    bool cache_is_find = false;
    int fd = my_openat(AT_FDCWD, PROC_MAPS, O_RDONLY, 0);
        if (fd <= 0) {
            error_msg.append("open maps error <").append(strerror(errno)).append(">").append("\n"); 
        }
        bool isFindMathPath = false;
        char map[MAX_LINE] = {0};
        while ((read_one_line(fd, map, MAX_LINE)) > 0) {
            if (my_strstr(map, soPath) != nullptr) {
                isFindMathPath = true;
                unsigned long start, end;
                char buf[MAX_LINE] = "";
                char path[MAX_LENGTH] = "";
                char tmp[100] = "";
                sscanf(map, "%lx-%lx %s %s %s %s %s", &start, &end, buf, tmp, tmp, tmp, path);
                //根据开始地址&结束地址，本地计算出来的偏移等信息计算内存CRC
                checkSum = scan_executable_segments(start, end, buf, pSection, soPath);
                //LOGI("detect_elf_checksum cache after -> %d [%s] %s ",checkSum, soPath,getProcessName().c_str())
                if (checkSum == 1) {
                    break;
                }
            }
        }
        my_close(fd);
        if (!isFindMathPath) {
            LOGE("detect_elf_checksum find in map not find %s ", soPath)
    }

    return checkSum;
}

int scan_executable_segments(unsigned long start,
                             unsigned long end,
                             const char buf[512],
                             execSection *section,
                             const char *libraryName) {
    //标识当前是否是android 10                         
    bool isAndroid10 = false;
    if (get_sdk_level() == ANDROID_Q) {
        isAndroid10 = true;
    }
    //rwx 三种同时存在,正常so不可能存在这种情况,直接认定当前内存被修改。
    if (buf[0] == 'r' && buf[1] == 'w' && buf[2] == 'x') {
        return 1;
    }
    bool isReadRx = false;
    if (buf[2] == 'x') {
        if (buf[0] == 'r') {
            auto *buffer = (uint8_t *) start;
            for (int i = 0; i < section->execSectionCount; i++) {
                if (start + section->offset[i] + section->memsize[i] > end) {
                    if (section->startAddrinMem != 0) {
                        buffer = (uint8_t *) section->startAddrinMem;
                        section->startAddrinMem = 0;
                        break;
                    }
                }
            }

            for (int i = 0; i < section->execSectionCount; i++) {
                auto begin = (void *) (buffer + section->offset[i]);
                unsigned long size = section->memsize[i];
                //计算内存crc
                unsigned long loction_checksum = checksum(begin, size);
                //和本地crc进行对比,不相等则认为被hook
                if (loction_checksum != section->checksum[i]) {
                    return 1;
                }
                if (gSectiong.isSuccess) {
                    if (loction_checksum != gSectiong.checksum[i]
                        || gSectiong.checksum[i] != section->checksum[i]) {
                        return 1;
                    }
                }

            }
        }
        return 0;
    } else {
        if (buf[0] == 'r') {
            section->startAddrinMem = start;
        }
    }

    return 0;
}