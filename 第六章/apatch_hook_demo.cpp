/*
 * /proc/mounts
 * 
 * /proc/{}/mounts
 * common/fs/proc_namespace.c
 * show_vfsmnt
 *
 * /proc/{}/mountinfo
 * common/fs/proc_namespace.c
 * show_mountinfo
 *
 * /proc/{}/mountstats
 * common/fs/proc_namespace.c
 * show_vfsstat
*/
int (*show_vfsmnt)(struct seq_file *m, struct vfsmount *mnt) = NULL;
int (*show_mountinfo)(struct seq_file *m, struct vfsmount *mnt) = NULL;
int (*show_vfsstat)(struct seq_file *m, struct vfsmount *mnt) = NULL;

/*
 * /proc/{}/maps
 * common/fs/proc/task_mmu.c
 * show_map_vma
 *
 * /proc/{}/smaps
 * common/fs/proc/task_mmu.c
 * show_smap
*/
void (*show_map)(struct seq_file *m, struct vm_area_struct *vma,bool is_pid) = NULL;
void (*show_smap)(struct seq_file *m, struct vm_area_struct *vma,bool is_pid) = NULL;

void hide_install() {
    //初始化保存hook item的方法,主要方便在hide_uninstall里面可以
    //快速对已经hook的方法进行unhook
    INIT_LIST_HEAD(&hook_cache_list);

    //初始化记录隐藏maps item的list
    INIT_LIST_HEAD(&maps_hide_list);
    //初始化记录隐藏mount item的list
    INIT_LIST_HEAD(&mount_hide_list);
    //查找show map函数,不同版本的内核可能不存在
    //所以这块也可以在内核里面的show_map_vma函数进行处理
    show_map = (typeof(show_map)) kallsyms_lookup_name("show_map");
    if (show_map == NULL) {
        show_map = (typeof(show_map)) kallsyms_lookup_name("show_map_vma");
    }
    if (show_map == NULL) {
        pr_err(" hook bg_hide_install show_map == null \n");
        return;
    }
    //show_smap 主要是为了隐藏/proc/self/smaps
    show_smap = (typeof(show_smap)) kallsyms_lookup_name("show_smap");
    if (show_map == NULL) {
        pr_err(" hook bg_hide_install show_smap  == null \n");
        return;
    }
    //挂载文件相关的初始化
    show_vfsmnt = (typeof(show_vfsmnt)) kallsyms_lookup_name("show_vfsmnt");
    if (show_vfsmnt == NULL) {
        pr_err(" hook bg_hide_install show_vfsmnt  == null \n");
        return;
    }
    show_mountinfo = (typeof(show_mountinfo)) kallsyms_lookup_name("show_mountinfo");
    if (show_mountinfo == NULL) {
        pr_err(" hook bg_hide_install show_mountinfo  == null \n");
        return;
    }
    show_vfsstat = (typeof(show_vfsstat)) kallsyms_lookup_name("show_vfsstat");
    if (show_vfsstat == NULL) {
        pr_err(" hook bg_hide_install show_vfsstat  == null \n");
        return;
    }
    //hook 对应的函数,apatch支持hook syscall也可以支持hook指定地址,可以参考上面的6.3.5章节
    //可以封装一个hook工具类用于保存hook item(每个被Hook方法的具体信息),方便在卸载模块的时候对模块里面的item进行unhook
    //防止一个方法被多次unhook
    add_hook_item(&hook_cache_list,3,(void *) show_map, before_show_map, after_show_map, 0,"show_map");
    add_hook_item(&hook_cache_list,3,(void *) show_smap, before_show_smap, after_show_smap, 0,"show_smap");
    add_hook_item(&hook_cache_list,2,(void *) show_vfsmnt, before_show_vfsmnt, after_show_vfsmnt, 0,"show_vfsmnt");
    add_hook_item(&hook_cache_list,2,(void *) show_mountinfo, before_show_mountinfo, after_show_mountinfo, 0,"show_mountinfo");
    add_hook_item(&hook_cache_list,2,(void *) show_vfsstat, before_show_vfsstat, after_show_vfsstat, 0,"show_vfsstat");
}

void hide_uninstall() {
    pr_info(">>>>>>>>>>>>> hide uninstall\n");
    unhook_all(&hook_cache_list);

    call_hide_so_del_all();
    call_hide_mnt_del_all();
    call_replace_mnt_del_all();

    pr_info(">>>>>>>>>>>>> hide finish \n");

}


static void after_hide_maps(hook_fargs2_t *args, void *udata) {
    //参数1结构体        
    struct seq_file *m = (struct seq_file *) args->arg0;
    //写入之前的count 长度
    size_t prev_count = args->local.data0;
    //当前item添加的长度,函数调用完毕以后的长度 - 写入之前的count长度
    size_t len_added = m->count - prev_count;

    // 如果没有新增内容，或 buf 不存在，则不做处理
    if (len_added == 0 || !m->buf) {
        return;
    }

    // 计算本次 show_map() 或 show_smap() 调用时，向 m->buf 中新增的那一段文本
    char *new_entry = m->buf + prev_count;

    // 分配一个临时缓冲区，把新增内容拷贝出来检查
    char *entry_buf = vmalloc(len_added + 1);
    if (!entry_buf) {
        pr_err(" kmalloc failed\n");
        return;
    }

    memcpy(entry_buf, new_entry, len_added);
    entry_buf[len_added] = '\0';

    // 判断这段文本是否需要隐藏,我们可以把需要隐藏的item放到这里面进行匹配 。
    if (isNeedHideMapsListItem(entry_buf, false)) {
        // 如果需要隐藏，就把 m->count 回退到调用前
        // 这样刚刚写进去的那段内容就被“清理掉”了
        m->count = prev_count;
    }

    kvfree(entry_buf);
}


static void before_hide_maps(hook_fargs2_t *args, void *udata) {
    //记录写入之前的count
    struct seq_file *m = (struct seq_file *) args->arg0;
    args->local.data0 = (uint64_t)(m->count);
    //pr_info(" before_show_smap  %zu\n", m->count);
}

static void before_hide_mount(hook_fargs2_t *args, char *msg_info) {
    //记录写入之前的count
    struct seq_file *m = (struct seq_file *) args->arg0;
    args->local.data0 = (uint64_t)(m->count);
    //pr_info(" before_show_smap  %zu\n", m->count);
}
void before_show_map(hook_fargs2_t *args, void *udata) {
    before_hide_maps(args,udata);
}

void after_show_map(hook_fargs2_t *args, void *udata) {
    after_hide_maps(args,udata);
}

void before_show_smap(hook_fargs2_t *args, void *udata) {
    before_hide_maps(args,udata);
}

void after_show_smap(hook_fargs2_t *args, void *udata) {
    after_hide_maps(args,udata);
}