jobject getAPKSign(JNIEnv *env,
                   [[maybe_unused]] jclass engine,
                   jobject context) {

    const char *path = getAPKPath(env, context);
    if(path == nullptr){
        return getItemData(env, "APK签名验证失败",
                           "getAPKPath == null", true, RISK_LEAVE_DEADLY, TAG_REPACKAGE);
    }
    int fd = my_openat(AT_FDCWD, reinterpret_cast<const char *>(path),
                       O_RDONLY | O_CLOEXEC,
                       0640);
    if(fd < 0){
        return getItemData(env, "APK签名验证失败",
                           string ("getAPKSign open error \n")+path, true, RISK_LEAVE_DEADLY, TAG_REPACKAGE);
    }
#define TEMP_APK_SIGN_STR "xxxxxx"
    //GET svc APK sign
    auto svc_APK_sign = Base64Utils::VTEncode(read_certificate(fd)).substr(0, 10);
    LOG(INFO) << "getAPKSign APK sign  " << svc_APK_sign;
    //1，check svc get sign match
    if (svc_APK_sign == Base64Utils::VTDecode(TEMP_APK_SIGN_STR)) {
        //2，check APK sign for open fd
        auto base_fd_list = getBaseAPKFd(path);
        if(!base_fd_list.empty()){
            //disabled fdsan
            change_fdsan_error_level();
            for(int temp_fd:base_fd_list){
                auto APK_sign_fd = checkSign(env, temp_fd).substr(0, 10);
                LOG(INFO) << "get open fd APK sign  " << APK_sign_fd;
                if(svc_APK_sign != Base64Utils::VTDecode(TEMP_APK_SIGN_STR)){
                    if(fd>0){
                        close(fd);
                    }
                    return getItemData(env, "APK签名验证失败",
                                       "open fd cache  error", false,
                                       RISK_LEAVE_DEADLY, TAG_REPACKAGE);
                }
            }
        }
        //3，check APK path
        char buff[PATH_MAX] = {0};
        std::string fdPath("/proc/");
        fdPath.append(to_string(getpid())).append("/fd/").append(to_string(fd));
        long len = raw_syscall(__NR_readlinkat, AT_FDCWD, fdPath.c_str(), buff, PATH_MAX);
        if (len < 0) {
            if(fd>0){
                close(fd);
            }
            return getItemData(env, "APK签名验证失败",
                               "readlinkat error", true,
                               RISK_LEAVE_DEADLY, TAG_REPACKAGE);
        }
        //4，截断,如果攻击者hook了readlinkat,只修改了参数,没修改返回值也可以检测出来。
        buff[len] = '\0';
        LOG(INFO) << "check APK sign path " << buff;
        if (my_strcmp(path, buff) == 0) {
            LOG(INFO) << "check APK sign path success ";
            //start check memory&location inode
            struct stat statBuff = {0};
            long stat = raw_syscall(__NR_fstat, fd, &statBuff);
            if (stat < 0) {
                if(fd>0){
                    close(fd);
                }
                LOG(ERROR) << "check APK sign path fail __NR_fstat<0";
                return getItemData(env, "APK签名验证失败",
                                   "fstat error", true, RISK_LEAVE_DEADLY, TAG_REPACKAGE);
            }
            //5，check uid&gid (1000 = system group)
            if (statBuff.st_uid != 1000 && statBuff.st_gid != 1000) {
                if(fd>0){
                    close(fd);
                }
                LOG(ERROR) << "check APK sign gid&uid fail ";
                return getItemData(env, "APK签名验证失败",
                                   nullptr, true, RISK_LEAVE_DEADLY, TAG_REPACKAGE);
            }
            //6，check Inode
            size_t inode = getFileInMapsInode(path);
            if (statBuff.st_ino != inode) {
                if(fd>0){
                    close(fd);
                }
                LOG(ERROR) << "check APK sign inode fail " << statBuff.st_ino << " maps ->"
                           << inode;
                return getItemData(env, "APK签名验证失败",
                                   nullptr, true, RISK_LEAVE_DEADLY, TAG_REPACKAGE);
            }
            LOG(ERROR) << ">>>>>>>>>> check APK sign success! uid-> " << statBuff.st_uid
                       << " gid-> "
                       << statBuff.st_gid;
        } else {
            if(fd>0){
                close(fd);
            }
            LOG(ERROR) << "check APK sign path fail ";
            return getItemData(env, "APK签名验证失败",
                               nullptr, true, RISK_LEAVE_DEADLY, TAG_REPACKAGE);

        }
        LOG(INFO) << "check APK sign success";
        if(fd>0){
            close(fd);
        }
        return nullptr;
    }
    else {
        if(fd>0){
            close(fd);
        }
        LOG(ERROR) << "check APK sign fail   " << svc_APK_sign;
        //check sign fail
        return getItemData(env, "APK签名验证失败",
                           nullptr, true, RISK_LEAVE_DEADLY, TAG_REPACKAGE);
    }
}