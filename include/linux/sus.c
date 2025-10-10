#ifndef _LINUX_SUS_SLIVA
#include <linux/string.h>
#include <linux/types.h>
#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/path.h>
#include <linux/slab.h>
#include <linux/seq_file.h>
#include <linux/printk.h>
#include <linux/mount.h>
#include <linux/namei.h>
#include <linux/suspicious.h>
#define getname_safe(name) (name == NULL ? ERR_PTR(-EINVAL) : getname(name))
#define putname_safe(name) (IS_ERR(name) ? NULL : putname(name))
#define uid_matches() (getuid() >= 2000)
#include <linux/slab.h>
#include <linux/gfp.h>

#define WORDS_ARRAY_SIZE 100
#define MAX_STR_LEN 100

static char* sus_words[WORDS_ARRAY_SIZE];
static int sus_i = 0;
static char sus_tmp[MAX_STR_LEN];//временный массив для слова
static int words_N = WORDS_ARRAY_SIZE ;
static bool sus_inited = false;

    // free(words);
    // удалять локальный массив вы не имеете права, вы память для него не выделяли
    // всю память, что вы выделяли, от той и отказывайтесь
static char* suspicious_paths[] = {
	"/storage/emulated/0/TWRP",
	"/system/lib/libzygisk.so",
	"/system/lib64/libzygisk.so",
	"/dev/zygisk",
	"/system/addon.d",
	"/vendor/bin/install-recovery.sh",
	"/system/bin/install-recovery.sh"
};

static char* suspicious_mount_types[] = {
	"overlay"
};

static char* suspicious_mount_paths[] = {
	"/data/adb",
	"/data/app",
	"/apex/com.android.art/bin/dex2oat",
	"/system/apex/com.android.art/bin/dex2oat",
	"/system/etc/preloaded-classes",
	"/dev/zygisk"
};
static int sus_count = 0;
static uid_t getuid(void) {

	const struct cred* const credentials = current_cred();

	if (credentials == NULL) {
		return 0;
	}

	return credentials->uid.val;

}

int is_suspicious_path(const struct path* const file)
{
	if (!sus_inited) sus_init();
	size_t index = 0;
	size_t size = 4096;
	int res = -1;
	int status = 0;
	char* path = NULL;
	char* ptr = NULL;
	char* end = NULL;

	if (!uid_matches() || file == NULL) {
		status = 0;
		goto out;
	}

	path = kmalloc(size, GFP_KERNEL);

	if (path == NULL) {
		status = -1;
		goto out;
	}

	ptr = d_path(file, path, size);

	if (IS_ERR(ptr)) {
		status = -1;
		goto out;
	}

	end = mangle_path(path, ptr, " \t\n\\");

	if (!end) {
		status = -1;
		goto out;
	}

	res = end - path;
	path[(size_t) res] = '\0';

	for (index = 0; index < ARRAY_SIZE(suspicious_paths); index++) {
		const char* const name = suspicious_paths[index];

		if (memcmp(name, path, strlen(name)) == 0) {
			printk(KERN_INFO "suspicious-fs: file or directory access to suspicious path '%s' won't be allowed to process with UID %i\n", name, getuid());
            sus_count++;
			status = 1;
			goto out;
		}
	}
    for (index = 0; index < ARRAY_SIZE(sus_words); index++) {
		const char* const name = sus_words[index];

		if (memcmp(name, path, strlen(name)) == 0) {
			printk(KERN_INFO "suspicious-fs: file or directory access to suspicious path '%s' won't be allowed to process with UID %i\n", name, getuid());
            sus_count++;
			status = 1;
			goto out;
		}
	}

	out:
		kfree(path);

	return status;

}

int suspicious_path(const struct filename* const name)
{

	int status = 0;
	int ret = 0;
	struct path path;

	if (IS_ERR(name)) {
		return -1;
	}

	if (!uid_matches() || name == NULL) {
		return 0;
	}

	ret = kern_path(name->name, LOOKUP_FOLLOW, &path);

	if (!ret) {
		status = is_suspicious_path(&path);
		path_put(&path);
	}

	return status;

}

int is_suspicious_mount(struct vfsmount* const mnt, const struct path* const root)
{

	size_t index = 0;
	size_t size = 4096;
	int res = -1;
	int status = 0;
	char* path = NULL;
	char* ptr = NULL;
	char* end = NULL;

	struct path mnt_path = {
		.dentry = mnt->mnt_root,
		.mnt = mnt
	};

	if (!uid_matches()) {
		status = 0;
		goto out;
	}

	for (index = 0; index < ARRAY_SIZE(suspicious_mount_types); index++) {
		const char* name = suspicious_mount_types[index];

		if (strcmp(mnt->mnt_root->d_sb->s_type->name, name) == 0) {
			printk(KERN_INFO "suspicious-fs: mount point with suspicious type '%s' won't be shown to process with UID %i\n", mnt->mnt_root->d_sb->s_type->name, getuid());
            sus_count++;
			status = 1;
			goto out;
		}
	}

	path = kmalloc(size, GFP_KERNEL);

	if (path == NULL) {
		status = -1;
		goto out;
	}

	ptr = __d_path(&mnt_path, root, path, size);

	if (!ptr) {
		status = -1;
		goto out;
	}

	end = mangle_path(path, ptr, " \t\n\\");

	if (!end) {
		status = -1;
		goto out;
	}

	res = end - path;
	path[(size_t) res] = '\0';

	for (index = 0; index < ARRAY_SIZE(suspicious_mount_paths); index++) {
		const char* name = suspicious_mount_paths[index];

		if (memcmp(path, name, strlen(name)) == 0) {
			printk(KERN_INFO "suspicious-fs: mount point with suspicious path '%s' won't be shown to process with UID %i\n", path, getuid());
            sus_count++;
			status = 1;
			goto out;
		}
	}

	out:
		kfree(path);

	return status;

}
int get_sus_count() {
    return sus_count;
}
int set_suspicious_path(char * sus_paths,int index) {
	strcpy(sus_words[index],sus_paths);
	return 10;
}
int sus_init() {
    for (sus_i = 0; sus_i < WORDS_ARRAY_SIZE; sus_i++) {
		sus_words[sus_i] = NULL;
	}
    for (sus_i = 0; sus_i < WORDS_ARRAY_SIZE ; sus_i++){
		strcpy(sus_tmp,"my/big/ball/s");
		if (strlen(sus_tmp) == 1 && sus_tmp[0] == 'X')  {
        words_N = sus_i ;
        break;  
	}
    sus_words[sus_i] = (char *)kmalloc(sizeof(char)*(strlen(sus_tmp) + 1),GFP_KERNEL);
    strcpy(sus_words[sus_i],sus_tmp);
	sus_inited = true;
	return 1;
}
#define _LINUX_SUS_SLIVA
#endif
