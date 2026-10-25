#ifndef __KSU_H_UID_OBSERVER
#define __KSU_H_UID_OBSERVER

struct list_head;

void ksu_throne_tracker_init(void);

void ksu_throne_tracker_exit(void);

void track_throne(bool prune_only);

// Search one app tree for an APK carrying the manager signature and crown the
// matching package. system_root selects the preinstalled-app layout (any *.apk,
// no /data/app path or filesystem assumptions) instead of the /data/app one.
void search_manager_in(const char *path, int depth, bool system_root, struct list_head *uid_data);

#endif
