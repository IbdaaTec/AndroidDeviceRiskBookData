void check_hardware(JNIEnv *env, pid_t pid,
                    HardwareCheckCallback call_back) {
    LOGE("check_hardware_breakpoints start %d", pid);
    prctl(PR_SET_DUMPABLE, 1, 0, 0, 0);
    prctl(PR_SET_PTRACER, pid, 0, 0, 0);

    int pipefd[2];
    if (pipe(pipefd) == -1) {
        LOGE("Failed to create pipe: %s", strerror(errno));
        return;
    }

    pid_t child_pid = fork();
    if (child_pid == -1) {
        LOGE("check_hardware_breakpoints fork error %s ", strerror(errno));
        close(pipefd[0]);
        close(pipefd[1]);
        return;
    }
    if (child_pid == 0) {
        prctl(PR_SET_NAME, "hunter_check_hardware_process");
        close(pipefd[0]);
        LOGE("check_hardware_breakpoints in child process");
        string error_msg = {};
        string success_msg = {};
        bool isDetected = false;

        if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1) {
            error_msg = string("ptrace attach error : ").append(strerror(errno));
            LOGE("check_hardware_breakpoints ptrace attach error %s", strerror(errno));
            write_info(pipefd, isDetected, error_msg, success_msg);
            close(pipefd[1]);
            _exit(0); // 使用 _exit 退出子进程
        }

        LOGE("check_hardware_breakpoints ptrace attach succeeded");

        if (waitpid(pid, nullptr, 0) == -1) {
            error_msg = string("waitpid error after ptrace attach: ").append(strerror(errno));
            LOGE("check_hardware_breakpoints waitpid error after ptrace attach %s",
                 strerror(errno));
            ptrace(PTRACE_DETACH, pid, NULL, NULL);
            write_info(pipefd, isDetected, error_msg, success_msg);
            close(pipefd[1]);
            _exit(0); // 使用 _exit 退出子进程
        }
        LOGE("check_hardware_breakpoints waitpid succeeded");
        LOGI(">>>>>>>>>>>> 1，start check hardware_breakpoints base !")
        //1，基础硬件断点检测
        if (check_hardware_breakpoints(pid, NT_ARM_HW_BREAK, error_msg)) {
            // 检测到硬件断点
            LOGE("check_hardware_breakpoints breakpoints detected\n");
            success_msg = "check_hardware_breakpoints breakpoints detected ";
            isDetected = true;
        }
        if (check_hardware_breakpoints(pid, NT_ARM_HW_WATCH, error_msg)) {
            // 检测到硬件监控点
            LOGE("check_hardware_breakpoints watchpoints detected\n");
            success_msg = "check_hardware_breakpoints watchpoints detected ";
            isDetected = true;
        }
        //2，返回值检测,判断内核是否hook返回值
        if (!isDetected) {
            LOGI(">>>>>>>>>>>> 2，start check PTRACE_SETREGSET ret ")
            // 检测硬件断点环境是否被hook
            // 这种方式主要是为了验证,当前环境是否异常,攻击者可能在内核里面直接hook ptrace
            // 获取到的硬件断点个数永远是0,所以先测试当前内核是否被hook,或者内核是否被定制化
            // 新增的验证逻辑,判断当前环境是否存在非成功情况
            int suspicious_ret_break = test_invalid_hw_breakpoint(pid, NT_ARM_HW_BREAK, error_msg);
            if (suspicious_ret_break == 1) {
                isDetected = true;
                success_msg = "Suspected kernel hook on breakpoints (invalid set returned success)";
            }

            int suspicious_ret_watch = test_invalid_hw_breakpoint(pid, NT_ARM_HW_WATCH, error_msg);
            if (suspicious_ret_watch == 1) {
                isDetected = true;
                success_msg = "Suspected kernel hook on watchpoints (invalid set returned success)";
            }
        }
        //3，同时max占坑检测硬件断点
        if (!isDetected) {
            LOGE(">>>>>>>>>>>> 3，start occupying hardware breakpoint detection ")
            auto bp_check_ret = set_hw_breakpoint(pid, NT_ARM_HW_BREAK, error_msg);
            if (bp_check_ret != 0) {
                // 无法设置硬件断点，资源已被占用
                LOGE("check_hardware_breakpoints Detected existing hardware breakpoints.\n");
                success_msg += "check_hardware_breakpoints Detected "
                               "existing hardware [breakpoints] ret-> " +
                               to_string(bp_check_ret) + " " + strerror(errno) + "[" +
                               to_string(errno) + "]";
                isDetected = true;
            }
            auto wp_check_ret = set_hw_breakpoint(pid, NT_ARM_HW_WATCH, error_msg);
            if (wp_check_ret != 0) {
                // 无法设置硬件监控点，资源已被占用
                LOGE("check_hardware_breakpoints Detected existing hardware watchpoints.\n");
                success_msg += "check_hardware_breakpoints Detected "
                               "existing hardware [watchpoints] ret-> " +
                               to_string(wp_check_ret) + " " + strerror(errno) + "[" +
                               to_string(errno) + "]";
                isDetected = true;
            }
        }
        //4，逐一设置硬件断点
        if (!isDetected) {
            LOGE(">>>>>>>>>>>> 4，start foreach occupying hardware breakpoint detection ")
            auto bp_check_ret = set_hw_breakpoint_foreach(pid, NT_ARM_HW_BREAK, error_msg);
            if (bp_check_ret != 0) {
                // 无法设置硬件断点，资源已被占用
                LOGE("set_hw_breakpoint_foreach Detected existing hardware breakpoints.\n");
                success_msg += "set_hw_breakpoint_foreach Detected "
                               "existing hardware [breakpoints] ret-> " +
                               to_string(bp_check_ret) + " " + strerror(errno) + "[" +
                               to_string(errno) + "]\n";
                isDetected = true;
            }
            auto wp_check_ret = set_hw_breakpoint_foreach(pid, NT_ARM_HW_WATCH, error_msg);
            if (wp_check_ret != 0) {
                // 无法设置硬件监控点，资源已被占用
                LOGE("set_hw_breakpoint_foreach Detected existing hardware watchpoints.\n");
                success_msg += "set_hw_breakpoint_foreach Detected "
                               "existing hardware [watchpoints] ret-> " +
                               to_string(wp_check_ret) + " " + strerror(errno) + "[" +
                               to_string(errno) + "]\n";
                isDetected = true;
            }
        }

        if (ptrace(PTRACE_DETACH, pid, NULL, NULL) == -1) {
            error_msg = string("ptrace detach error:  ").append(strerror(errno));
            LOGE("check_hardware_breakpoints ptrace detach error %s", strerror(errno));
        }
//        LOGE("check_hardware_breakpoints ptrace detach succeeded");
//        LOGE("check_hardware_breakpoints write -> [%s] [%s] ",error_msg.c_str(),success_msg.c_str());

        write_info(pipefd, isDetected, error_msg, success_msg);

        close(pipefd[1]);
        _exit(0);
    } else {
        // 父进程
        close(pipefd[1]); // 关闭写入端
        int status;
        LOGE("check_hardware_breakpoints waiting for child process");
        if (waitpid(child_pid, &status, 0) == -1) {
            LOGE("check_hardware_breakpoints waitpid error %s ", strerror(errno));
            close(pipefd[0]);
            return;
        }
        if (WIFEXITED(status)) {
            int ret = WEXITSTATUS(status);
            if (ret != 0) {
                LOGE("check_hardware_breakpoints child process exited with error code %d", ret);
            }
        } else {
            LOGE("check_hardware_breakpoints child process did not exit normally");
        }
        // 从管道中读取子进程的检测结果
        bool isDetected;
        read(pipefd[0], &isDetected, sizeof(isDetected));

        uint32_t len;
        read(pipefd[0], &len, sizeof(len));

        string error_msg;
        if (len > 0) {
            char *buf = new char[len + 1];
            read(pipefd[0], buf, len);
            buf[len] = '\0';
            error_msg = buf;
            delete[] buf;
        }
        LOGE("check_hardware_breakpoints read error_msg %s ", error_msg.c_str())
        string success_msg;
        read(pipefd[0], &len, sizeof(len));
        if (len > 0) {
            char *buf = new char[len + 1];
            read(pipefd[0], buf, len);
            buf[len] = '\0';
            success_msg = buf;
            delete[] buf;
        }
        LOGE("check_hardware_breakpoints read success_msg %s ", success_msg.c_str())

        close(pipefd[0]); // 关闭读取端
        // 在父进程中调用回调函数
        call_back(env, error_msg, success_msg, isDetected);
        prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
    }
    LOGE("check_hardware_breakpoints finished successfully");
}

bool check_hardware_breakpoints(pid_t pid, int type, string error_msg) {
    struct iovec iov = {};
    struct my_user_hwdebug_state hwdebug_state = {};
    int i;

    // 初始化 iovec 结构
    iov.iov_base = &hwdebug_state;
    iov.iov_len = sizeof(hwdebug_state);

    if (ptrace(PTRACE_GETREGSET, pid, (void *) type, &iov) == -1) {
        LOGE("check_hardware_breakpoints PTRACE_GETREGSET error %s %d ",strerror(errno),errno)
        return false;
    }

    // 检查断点寄存器的值
    unsigned int version = hwdebug_state.dbg_info >> 8;
    unsigned int count = hwdebug_state.dbg_info & 0xFF;
    LOGE("Hardware debug [%s] version: %d, valid count: %d\n",
         type == NT_ARM_HW_BREAK ? "breakpoint" : "watchpoint", version, count);

    int all_zero = 1;
    for (i = 0; i < count; i++) {
        LOGD("check_hardware_breakpoints %s(%d): addr: 0x%llx, ctrl: 0x%x\n",
             type == NT_ARM_HW_BREAK ? "BP" : "WP", i,
             hwdebug_state.dbg_regs[i].addr, hwdebug_state.dbg_regs[i].ctrl);
        if (hwdebug_state.dbg_regs[i].addr != 0 || hwdebug_state.dbg_regs[i].ctrl != 0) {
            all_zero = 0;
        }
    }

    return !all_zero;
}

/**
 * 循环遍历每个断点,一个一个尝试占坑,而不是一起占坑。
 * 占坑全部成功返回0,占坑失败的话返回-1 。
 * 这个方法可能存在问题,因为在正常已经设置了硬件断点的情况,一个一个设置还是可能会出现返回成功的情况 。
 */
int set_hw_breakpoint_foreach(pid_t child, int type, string error_msg) {
    LOGE("Setting hardware breakpoint/watchpoint for pid %d, type %d %d \n", child, type, errno);
    struct iovec iov = {};
    struct my_user_hwdebug_state hwdebug = {};
    struct arch_hw_breakpoint_ctrl ctrl{
            .len = 1, // ARM_BREAKPOINT_LEN_1
            .type = 0, // ARM_BREAKPOINT_EXECUTE
            .privilege = 2, // AARCH64_BREAKPOINT_EL0
            .enabled = 0,
    };

    if (type == NT_ARM_HW_WATCH) {
        ctrl.type = 1; // ARM_BREAKPOINT_LOAD
    } else {
        ctrl.type = 0; // ARM_BREAKPOINT_EXECUTE
    }

    memset(&hwdebug, 0, sizeof(hwdebug));
    iov.iov_base = &hwdebug;
    iov.iov_len = sizeof(hwdebug);

    if (ptrace(PTRACE_GETREGSET, child, (void *) type, &iov) == -1) {
        LOGE("ptrace(PTRACE_GETREGSET) failed: error %s ", strerror(errno));
        return 0;
    }

    int max = type == NT_ARM_HW_BREAK ? MAX_BREAKPOINTS : MAX_WATCHPOINTS;
    int success_count = 0;
    for (int i = 0; i < max; i++) {
        // 逐一设置每个断点
        hwdebug.dbg_regs[i].addr = (uint64_t) (0x400000 + i * 8);
        hwdebug.dbg_regs[i].ctrl = encode_ctrl_reg(ctrl);

        // 每次只设置一个断点
        iov.iov_len = offsetof(struct my_user_hwdebug_state, dbg_regs)
        + (i + 1) * sizeof(hwdebug.dbg_regs[0]);
        LOGE("set_hw_breakpoint_foreach item size %lu iov_len-> %lu",sizeof(hwdebug.dbg_regs[0]),iov.iov_len)
        auto ret = ptrace(PTRACE_SETREGSET, child, (void *) type, &iov);

        LOGD("ptrace(PTRACE_SETREGSET) for breakpoint %d ret %ld ", i, ret);
        if (ret == -1) {
            error_msg = string("ptrace(PTRACE_SETREGSET) failed: ").append(strerror(errno));
            // 空间不足时退出循环
            if (errno == ENOSPC) {
                break;
            }
            LOGE("ptrace(PTRACE_SETREGSET) find other errno %d %s", errno, strerror(errno));
            // 其他错误时直接返回 -1
            return -1;
        }
        else {
            success_count++;
        }
    }

    // 打印断点的总数和成功设置的数量
    LOGE("Total breakpoints: %d, Successfully set: %d", max, success_count);

    // 如果所有断点设置成功，返回 0，否则返回 -1
    return (success_count == max) ? 0 : -1;
}


/**
 * 设置硬件断点,多个断点一起设置判断是否成功。
 */
[[maybe_unused]]
int set_hw_breakpoint(pid_t child, int type, string error_msg) {
    LOGE("Setting hardware breakpoint/watchpoint for pid %d, type %d\n", child, type);
    struct iovec get_iov = {};
    struct iovec set_iov = {};

    struct my_user_hwdebug_state hwdebug = {};
    memset(&hwdebug, 0, sizeof(hwdebug));

    get_iov.iov_base = &hwdebug;
    get_iov.iov_len = sizeof(hwdebug);

    if (ptrace(PTRACE_GETREGSET, child, (void *) type, &get_iov) == -1) {
        LOGE("ptrace(PTRACE_GETREGSET) failed: error %s ", strerror(errno))
        return 0;
    }

    unsigned int supported_count = hwdebug.dbg_info & 0xFF;
    if (supported_count == 0) {
        LOGE("No hardware breakpoints or watchpoints supported");
        return 0;
    }
    // 想设置的数量
    int max = (type == NT_ARM_HW_BREAK) ? MAX_BREAKPOINTS : MAX_WATCHPOINTS;
    if ((unsigned int)max > supported_count) {
        max = (int)supported_count; // 不能超过硬件支持数量
    }
    LOGD("supported_count %d max %d ",supported_count,max)

    struct arch_hw_breakpoint_ctrl ctrl{
            .len = 1, // ARM_BREAKPOINT_LEN_1
            .type = 0, // ARM_BREAKPOINT_EXECUTE
            .privilege = 2, // AARCH64_BREAKPOINT_EL0
            .enabled = 1,   // 通常需要enabled = 1来实际启用断点
    };

    if (type == NT_ARM_HW_WATCH) {
        ctrl.type = 1; // ARM_BREAKPOINT_LOAD
    } else {
        ctrl.type = 0; // ARM_BREAKPOINT_EXECUTE
    }

    // 设置前 max 个断点信息
    for (int i = 0; i < max; i++) {
        hwdebug.dbg_regs[i].addr = (uint64_t) (0x400000 + i * 8);
        hwdebug.dbg_regs[i].ctrl = encode_ctrl_reg(ctrl);
    }

    // 计算需要传递给内核的数据大小：dbg_info + pad + max个dbg_regs
    size_t required_size = offsetof(struct my_user_hwdebug_state, dbg_regs)
    + max * sizeof(hwdebug.dbg_regs[0]);

    set_iov.iov_base = &hwdebug;
    set_iov.iov_len = required_size;

    LOGE("set_hw_breakpoint iov_len info %zu ", set_iov.iov_len)
    auto ret = ptrace(PTRACE_SETREGSET, child, (void *) type, &set_iov);
    if (ret == -1) {
        LOGE("ptrace(PTRACE_SETREGSET) ret %ld %d %s ", ret, errno,strerror(errno))
        error_msg += string("ptrace(PTRACE_SETREGSET) failed: ").append(strerror(errno)).append("\n");
        if (errno == ENOSPC) {
            // 超过硬件支持数量
            return -1;
        }
    } else {
        // 重置断点
        for (int i = 0; i < max; i++) {
            hwdebug.dbg_regs[i].addr = 0;
            hwdebug.dbg_regs[i].ctrl = 0;
        }
        // 重置时也要使用同样的length（因为reset同样需要告诉内核多少个dbg_regs在使用）
        ret = ptrace(PTRACE_SETREGSET, child, (void *) type, &set_iov);
        if (ret == -1) {
            error_msg += "set_hw_breakpoint Failed to revert breakpoints: " + std::string(strerror(errno)) + "\n";
        }
        LOGI("revert breakpoints success !")
    }
    return 0;
}

int test_invalid_hw_breakpoint(pid_t child, int type, string &error_msg) {
    struct iovec iov = {};
    struct my_user_hwdebug_state test_hwdebug = {};
    memset(&test_hwdebug, 0, sizeof(test_hwdebug));

    iov.iov_base = &test_hwdebug;
    iov.iov_len = sizeof(test_hwdebug);

    // 获取当前硬件断点/监视点信息
    if (ptrace(PTRACE_GETREGSET, child, (void *) type, &iov) == -1) {
        LOGE("test_invalid_hw_breakpoint PTRACE_GETREGSET error %s ", strerror(errno))
        return 0; // 获取失败就没法检测，返回0表示未发现异常
    }

    int max_regs = (int)(sizeof(test_hwdebug.dbg_regs) / sizeof(test_hwdebug.dbg_regs[0]));
    unsigned int count = test_hwdebug.dbg_info & 0xFF; // 硬件实际支持的断点/监视点数
    int actual_max = (count < (unsigned) max_regs) ? (int) count : max_regs;

    // 如果硬件不支持额外增加断点（已经满了结构大小），无法测试超出数量的情况。
    if (actual_max >= max_regs) {
        // 已经达到数组上限，无法超限测试，直接返回0
        LOGD("Hardware supports as many breakpoints as our array size, can't test invalid scenario.");
        return 0;
    }

    // test_count = 硬件支持数量 + 1, 尝试超出硬件支持范围
    int test_count = actual_max + 1;

    // 设置断点信息
    struct arch_hw_breakpoint_ctrl ctrl{
            .len = 1,
            .type = (type == NT_ARM_HW_WATCH) ? 1 : 0,
            .privilege = 2,
            .enabled = 1 // 启用断点，使其更接近真实情境
    };

    for (int i = 0; i < test_count; i++) {
        test_hwdebug.dbg_regs[i].addr = (uint64_t)(0x500000 + i * 8);
        test_hwdebug.dbg_regs[i].ctrl = encode_ctrl_reg(ctrl);
    }

    // 计算需要提交的大小：包括 dbg_info, pad, 和 test_count 个 dbg_regs 的空间
    size_t required_size = offsetof(struct my_user_hwdebug_state, dbg_regs)
    + test_count * sizeof(test_hwdebug.dbg_regs[0]);

    struct iovec set_iov = {};
    set_iov.iov_base = &test_hwdebug;
    set_iov.iov_len = required_size;

    errno = 0;
    int ret = ptrace(PTRACE_SETREGSET, child, (void *) type, &set_iov);

    if (ret == -1 && errno == ENOSPC) {
        // 尝试超出硬件支持数量设置断点，内核正确返回ENOSPC，表示无异常
        LOGD("test_invalid_hw_breakpoint normal: ENOSPC as expected")
        return 0;
    } else if (ret == 0) {
        // 成功超额设置，表示可能内核行为被Hook（预期应ENOSPC却成功）
        error_msg = "Suspicious: Setting invalid HW breakpoints succeeded unexpectedly.";
        return 1;
    } else {
        // 其他错误类型，非预期
        error_msg = "Unexpected error: " + string(strerror(errno));
        return -1;
    }
}