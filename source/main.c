// Include the most common headers from the C standard library
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <dirent.h>
#include <sys/stat.h>
#include <limits.h>

#include <sys/socket.h>
#include <arpa/inet.h>

// Include the main libnx system header, for Switch development
#include <switch.h>

#include <libconfig.h>

#include "delivery.h"

// qlaunch handles Eula for sysupdates, however we won't.

typedef enum {
    UpdateType_None        = -1,
    UpdateType_Download    =  0,
    UpdateType_Card        =  1,
    UpdateType_Send        =  2,
    UpdateType_Receive     =  3,
} UpdateType;

struct ManagerContentTransferState {
    FILE *f;
};

Result managerHandlerMetaLoad(void* userdata, struct DeliveryContentEntry *entry, const char* filepath, void** outbuf_ptr, size_t *out_filesize) {
    Result rc=0, rc2=0;
    NcmContentStorage *storage = (NcmContentStorage*)userdata;
    NcmPlaceHolderId placeholder_id={0};
    FsFileSystem tmpfs={0};
    FILE *f = NULL;
    u8 *tmpbuf = NULL;
    char tmpstr[FS_MAX_PATH];

    memset(tmpstr, 0, sizeof(tmpstr));

    f = fopen(filepath, "rb");
    if (f == NULL) rc = MAKERESULT(Module_Libnx, LibnxError_NotFound);

    if (R_SUCCEEDED(rc)) {
        tmpbuf = (u8*)malloc(entry->filesize);
        if (tmpbuf) memset(tmpbuf, 0, entry->filesize);
        else rc = MAKERESULT(Module_Libnx, LibnxError_OutOfMemory);
    }

    if (R_SUCCEEDED(rc)) {
        if (fread(tmpbuf, 1, entry->filesize, f) != entry->filesize) rc = MAKERESULT(Module_Libnx, LibnxError_IoError);
    }

    if (R_SUCCEEDED(rc)) {
        rc = ncmContentStorageGeneratePlaceHolderId(storage, &placeholder_id);
        if (R_SUCCEEDED(rc)) rc = ncmContentStorageCreatePlaceHolder(storage, &entry->content_info.info.content_id, &placeholder_id, entry->filesize);
        if (R_SUCCEEDED(rc)) {
            rc = ncmContentStorageWritePlaceHolder(storage, &placeholder_id, 0, tmpbuf, entry->filesize);
            if (R_SUCCEEDED(rc)) rc = ncmContentStorageGetPlaceHolderPath(storage, tmpstr, sizeof(tmpstr), &placeholder_id);

            if (R_SUCCEEDED(rc)) rc = fsOpenFileSystemWithId(&tmpfs, 0, FsFileSystemType_ContentMeta, tmpstr);

            if (R_SUCCEEDED(rc)) {
                if (fsdevMountDevice("meta", tmpfs)==-1) rc = MAKERESULT(Module_Libnx, LibnxError_IoError);
                if (R_SUCCEEDED(rc)) {
                    rc = deliveryManagerLoadMetaFromFs("meta:/", outbuf_ptr, out_filesize, false);
                    fsdevUnmountDevice("meta");
                }
            }
            rc2 = ncmContentStorageDeletePlaceHolder(storage, &placeholder_id);
            if (R_SUCCEEDED(rc)) rc = rc2;
        }
    }

    if (tmpbuf) {
        memset(tmpbuf, 0, entry->filesize);
        free(tmpbuf);
    }
    if (f) fclose(f);

    return rc;
}

Result managerHandlerMetaRecord(void* userdata, NcmPackagedContentInfo* record, const NcmContentMetaKey* content_meta_key) {
    Result rc=0;
    struct DeliveryContentEntry *entry = NULL;

    rc = deliveryManagerGetContentEntry((DeliveryManager*)userdata, &entry, content_meta_key, NULL);
    if (R_SUCCEEDED(rc)) memcpy(record, &entry->content_info, sizeof(NcmPackagedContentInfo));
    return rc;
}

// These don't handle client-mode other than just returning 0.
Result managerContentTransferInit(struct DeliveryGetContentDataTransferState* state, s64* content_size) {
    Result rc=0;
    struct ManagerContentTransferState *user_state = (struct ManagerContentTransferState*)state->userdata;
    struct DeliveryContentEntry *entry = NULL;

    if (state->manager->server) {
        rc = deliveryManagerGetContentEntry(state->manager, &entry, NULL, &state->arg->content_id);
        if (R_SUCCEEDED(rc)) {
            user_state->f = fopen(entry->filepath, "rb");
            if (user_state->f == NULL) rc = MAKERESULT(Module_Libnx, LibnxError_NotFound);
        }
        if (R_SUCCEEDED(rc)) *content_size = entry->filesize;
    }

    return rc;
}

void managerContentTransferExit(struct DeliveryGetContentDataTransferState* state) {
    struct ManagerContentTransferState *user_state = (struct ManagerContentTransferState*)state->userdata;
    if (user_state->f) {
        fclose(user_state->f);
        user_state->f = NULL;
    }
}

Result managerContentTransfer(struct DeliveryGetContentDataTransferState* state, void* buffer, u64 size, s64 offset) {
    Result rc=0;
    struct ManagerContentTransferState *user_state = (struct ManagerContentTransferState*)state->userdata;

    if (state->manager->server) {
        if (fseek(user_state->f, offset, SEEK_SET)==-1) rc = MAKERESULT(Module_Libnx, LibnxError_IoError);
        if (R_SUCCEEDED(rc)) {
            if (fread(buffer, 1, size, user_state->f) != size) rc = MAKERESULT(Module_Libnx, LibnxError_IoError);
        }
    }

    return rc;
}

Result managerSetup(DeliveryManager *manager, struct in_addr *nxaddr, u16 port, FILE *log_file, struct ManagerContentTransferState *transfer_state, const char *datadir, s32 depth) {
    Result rc=0;
    NcmContentStorage storage={0};

    rc = deliveryManagerCreate(manager, true, nxaddr, port);
    if (R_FAILED(rc)) printf("deliveryManagerCreate() failed: 0x%x\n", rc);
    if (R_SUCCEEDED(rc)) {
        if (log_file) deliveryManagerSetLogFile(manager, log_file);
        deliveryManagerSetHandlerGetMetaContentRecord(manager, managerHandlerMetaRecord, manager);
        deliveryManagerSetHandlersGetContent(manager, transfer_state, managerContentTransferInit, managerContentTransferExit, managerContentTransfer);

        rc = ncmInitialize();
        if (R_FAILED(rc)) printf("ncmInitialize() failed: 0x%x\n", rc);

        if (R_SUCCEEDED(rc)) {
            rc = ncmOpenContentStorage(&storage, NcmStorageId_BuiltInSystem);
            if (R_FAILED(rc)) printf("ncmOpenContentStorage failed: 0x%x\n", rc);
        }

        if (R_SUCCEEDED(rc)) {
            printf("Scanning datadir...\n");
            consoleUpdate(NULL);
            rc = deliveryManagerScanDataDir(manager, datadir, depth, managerHandlerMetaLoad, &storage);
            if (R_FAILED(rc)) printf("deliveryManagerScanDataDir() failed: 0x%x\n", rc);
        }

        ncmContentStorageClose(&storage);
        ncmExit();

        if (R_SUCCEEDED(rc)) {
            rc = deliveryManagerRequestRun(manager);
            if (R_FAILED(rc)) printf("deliveryManagerRequestRun() failed: 0x%x\n", rc);
        }

        if (R_SUCCEEDED(rc)) printf("Server started.\n");
        consoleUpdate(NULL);
    }

    return rc;
}

Result sukeyLocate(u8 *out_key, NsSystemDeliveryInfo *delivery_info) {
    Result rc=0;
    Handle debughandle=0;
    bool found=0;
    u64 pid=0;
    u64 pos=0;
    u64 cur_addr=0, cur_module_size=0;
    u8 *rosection_buf = NULL;
    u64 rosection_size=0;
    s32 total_out=0;
    u32 pageinfo=0;
    MemoryInfo meminfo={0};
    LoaderModuleInfo module_infos[1]={0};
    u8 calc_hash[SHA256_HASH_SIZE]={0};

    if (!envIsSyscallHinted(0x60) || !envIsSyscallHinted(0x69) || !envIsSyscallHinted(0x6A)) {
        printf("Debug SVCs aren't available, make sure you're running the latest hbloader release.\n");
        rc = MAKERESULT(Module_Libnx, LibnxError_NotFound);
    }

    // Get the PID for ns.
    if (R_SUCCEEDED(rc)) {
        rc = pmdmntInitialize();
        if (R_FAILED(rc)) printf("pmdmntInitialize(): 0x%x\n", rc);
    }

    if (R_SUCCEEDED(rc)) {
        rc = pmdmntGetProcessId(&pid, 0x010000000000001F);
        if (R_FAILED(rc)) printf("pmdmntGetProcessId(): 0x%x\n", rc);
        pmdmntExit();
    }

    // Get the LoaderModuleInfo for ns.
    if (R_SUCCEEDED(rc)) {
        rc = ldrDmntInitialize();
        if (R_FAILED(rc)) printf("ldrDmntInitialize(): 0x%x\n", rc);

        if (R_SUCCEEDED(rc)) {
            rc = ldrDmntGetProcessModuleInfo(pid, module_infos, 1, &total_out);
            if (R_FAILED(rc)) printf("ldrDmntGetProcessModuleInfo(): 0x%x\n", rc);
            if (R_SUCCEEDED(rc) && total_out!=1) {
                printf("total_out from ldrDmntGetProcessModuleInfo() is invalid: %d.\n", total_out);
                rc = MAKERESULT(Module_Libnx, LibnxError_BadInput);
            }
            ldrDmntExit();
        }
    }

    // Locate the RO section and read it into rosection_buf.
    if (R_SUCCEEDED(rc)) {
        cur_addr = module_infos[0].base_address;
        cur_module_size = module_infos[0].size;

        rc = svcDebugActiveProcess(&debughandle, pid);
        if (R_FAILED(rc)) printf("svcDebugActiveProcess(): 0x%x\n", rc);

        if (R_SUCCEEDED(rc)) {
            while (R_SUCCEEDED(rc) && cur_module_size>0) {
                rc = svcQueryDebugProcessMemory(&meminfo, &pageinfo, debughandle, cur_addr);
                if (R_FAILED(rc)) printf("svcQueryDebugProcessMemory(): 0x%x\n", rc);

                if (R_SUCCEEDED(rc)) {
                    if (meminfo.size > cur_module_size) break;
                    if (meminfo.perm == Perm_R) {
                        found = 1;
                        break;
                    }

                    cur_addr+= meminfo.size;
                    cur_module_size-= meminfo.size;
                }
            }

            if (R_SUCCEEDED(rc) && !found) {
                printf("Failed to find the R-- section in ns.\n");
                rc = MAKERESULT(Module_Libnx, LibnxError_NotFound);
            }

            if (R_SUCCEEDED(rc)) {
                rosection_size = meminfo.size;
                rosection_buf = (u8*)malloc(rosection_size);
                if (rosection_buf==NULL) {
                    printf("Failed to allocate memory for rosection_buf.\n");
                    rc = MAKERESULT(Module_Libnx, LibnxError_OutOfMemory);
                }
                else
                    memset(rosection_buf, 0, rosection_size);
            }

            if (R_SUCCEEDED(rc)) {
                rc = svcReadDebugProcessMemory(rosection_buf, debughandle, cur_addr, rosection_size);
                if (R_FAILED(rc)) printf("svcReadDebugProcessMemory(): 0x%x\n", rc);
            }

            svcCloseHandle(debughandle);
        }
    }

    // Locate the key in the RO section by looping through it and using it as the key.
    if (R_SUCCEEDED(rc)) {
        found = 0;
        for (pos=0; pos<rosection_size-SHA256_HASH_SIZE; pos++) {
            hmacSha256CalculateMac(calc_hash, &rosection_buf[pos], SHA256_HASH_SIZE, &delivery_info->data, sizeof(delivery_info->data));

            if (memcmp(calc_hash, delivery_info->hmac, sizeof(calc_hash))==0) {
                found = 1;
                break;
            }
        }

        if (!found) {
            printf("Failed to find the hmac key.\n");
            rc = MAKERESULT(Module_Libnx, LibnxError_NotFound);
        }

        if (R_SUCCEEDED(rc)) {
            memcpy(out_key, &rosection_buf[pos], SHA256_HASH_SIZE);
        }
    }

    if (rosection_buf) {
        memset(rosection_buf, 0, rosection_size);
        free(rosection_buf);
    }

    return rc;
}

void sukeySignSystemDeliveryInfo(const u8 *key, NsSystemDeliveryInfo *delivery_info) {
    hmacSha256CalculateMac(delivery_info->hmac, key, SHA256_HASH_SIZE, &delivery_info->data, sizeof(delivery_info->data));
}

bool configassocWrite(const char *config_path, const char *app_path, const char *extension) {
    int ret=CONFIG_TRUE;
    config_t cfg={0};
    config_setting_t *setting = NULL;
    config_setting_t *tmpsetting = NULL;

    config_init(&cfg);

    setting = config_root_setting(&cfg);
    if (setting != NULL) {
        setting = config_setting_add(setting, "fileassoc", CONFIG_TYPE_GROUP);
        if (setting != NULL) {
            tmpsetting = config_setting_add(setting, "app_path", CONFIG_TYPE_STRING);
            if (tmpsetting) ret = config_setting_set_string(tmpsetting, app_path);

            if (tmpsetting && ret==CONFIG_TRUE) {
                tmpsetting = config_setting_add(setting, "targets", CONFIG_TYPE_LIST);
                if (tmpsetting) {
                    tmpsetting = config_setting_add(tmpsetting, NULL, CONFIG_TYPE_GROUP);
                    if (tmpsetting) {
                        tmpsetting = config_setting_add(tmpsetting, "file_extension", CONFIG_TYPE_STRING);
                        if (tmpsetting) ret = config_setting_set_string(tmpsetting, extension);
                    }
                }
            }
        }
    }
    if (ret==CONFIG_TRUE && (setting == NULL || tmpsetting == NULL)) ret=CONFIG_FALSE;

    if (ret==CONFIG_TRUE) ret = config_write_file(&cfg, config_path);
    config_destroy(&cfg);

    return ret==CONFIG_TRUE;
}

// Main program entrypoint
int main(int argc, char* argv[])
{
    Result rc=0;
    Result sleeprc=0;

    u32 state=0;
    bool tmpflag=0;
    bool sleepflag=0;
    bool sysver_flag = hosversionAtLeast(4,0,0);
    UpdateType updatetype=UpdateType_None;
    u64 keymask=0;

    FILE *log_file = NULL;
    NsSystemUpdateControl sucontrol={0};
    AsyncResult asyncres={0};
    u8 sysdeliveryinfo_key[SHA256_HASH_SIZE]={0};
    DeliveryManager manager={0};
    struct ManagerContentTransferState transfer_state={0};

    u16 port=55556;
    u32 ipaddr = ntohl(__nxlink_host.s_addr); // TODO: Should specifiying ipaddr via other means be supported?
    u32 system_version=0;                     // TODO: Same TODO as above.

    char datadir[PATH_MAX];
    s32 depth=3;

    appletLockExit();

    sleeprc = appletIsAutoSleepDisabled(&sleepflag);
    if (R_SUCCEEDED(sleeprc)) sleeprc = appletSetAutoSleepDisabled(true);
    socketInitializeDefault();

    consoleInit(NULL);

    printf("nssu-updater\n");

    memset(datadir, 0, sizeof(datadir));

    if (!configassocWrite("/config/nx-hbmenu/fileassoc/nssu-updater.cfg", "/switch/nssu_updater.nro", ".nssu-update")) // TODO: Update nro path.
        printf("Failed to write the hbmenu config.\n");

    if (argc > 1) {
        char *argptr = argv[1];
        char *endarg = NULL;
        char *optarg = argptr;
        struct stat tmpstat;

        if(stat(optarg, &tmpstat)==0) {
            bool entrytype = (tmpstat.st_mode & S_IFMT) != S_IFREG;
            size_t pathlen = strlen(argptr);

            optarg = strrchr(optarg, '/');
            if (optarg && optarg[0]=='/') {
                optarg++;

                if (!entrytype) {
                    while (pathlen && argptr[pathlen]!='/') pathlen--;
                }
            }
            if (optarg == NULL) optarg = argptr;

            if (pathlen > sizeof(datadir)-1) pathlen = sizeof(datadir)-1;
            if (pathlen) strncpy(datadir, argptr, pathlen);

            ipaddr = INADDR_LOOPBACK;
        }

        errno = 0;
        if (optarg[0] == 'v') optarg++;
        system_version = strtoul(optarg, &endarg, 0);
        if (endarg == optarg) errno = EINVAL;
        if (errno != 0) {
            system_version = 0;
            printf("Invalid input arg for system-version.\n");
        }
        else
            printf("Using system-version from arg: v%u\n", system_version);

        if (datadir[0]) printf("Using datadir from arg: %s\n", datadir);
    }

    if (!sysver_flag) printf("The following are not available since [4.0.0+] is required: Send/Receive and nssuControlSetupCardUpdateViaSystemUpdater.\n");

    // TODO: Disable unneeded buttons with fileassoc-arg.
    printf("Press - to install update downloaded from CDN.\n");
    printf("Press A to install update with nssuControlSetupCardUpdate.\n");
    if (sysver_flag) printf("Press B to install update with nssuControlSetupCardUpdateViaSystemUpdater.\n");
    else keymask |= KEY_B;
    if (sysver_flag && ipaddr) {
        printf("Press X to Send the sysupdate.\n");
        if (system_version) printf("Press Y to Receive the sysupdate.\n");
        else keymask |= KEY_Y;
    }
    else keymask |= (KEY_X|KEY_Y);
    printf("Press + exit, aborting any operations prior to the final stage.\n");

    rc = nssuInitialize();
    if (R_FAILED(rc)) printf("nssuInitialize(): 0x%x\n", rc);

    if (R_SUCCEEDED(rc)) { // TODO: Should this be used with more than just deliveryManager?
        log_file = fopen("nssu-updater.log", "w");
        if (log_file==NULL) {
            rc = MAKERESULT(Module_Libnx, LibnxError_IoError);
            printf("Failed to open the log file.\n");
        }
    }

    u32 cnt=0;

    // TODO: UI warning / user-confirmation.

    // Main loop
    while (appletMainLoop())
    {
        // Scan all the inputs. This should be done once for each frame
        hidScanInput();

        // hidKeysDown returns information about which buttons have been
        // just pressed in this frame compared to the previous one
        u64 kDown = hidKeysDown(CONTROLLER_P1_AUTO) & ~keymask;

        if (kDown & KEY_PLUS)
            break; // break in order to return to hbmenu

        if (R_SUCCEEDED(rc)) {
            if (state==0 && (kDown & (KEY_MINUS|KEY_A|KEY_B|KEY_X|KEY_Y))) {
                if (kDown & (KEY_MINUS|KEY_A|KEY_B|KEY_Y)) {
                    rc = nssuOpenSystemUpdateControl(&sucontrol);
                    printf("nssuOpenSystemUpdateControl(): 0x%x\n", rc);
                }

                if (kDown & KEY_MINUS) {
                    updatetype = UpdateType_Download;
                    rc = nssuControlRequestDownloadLatestUpdate(&sucontrol, &asyncres);
                    printf("nssuControlRequestDownloadLatestUpdate(): 0x%x\n", rc);
                }
                else if (kDown & (KEY_A|KEY_B)) {
                    updatetype = UpdateType_Card;
                    if (R_SUCCEEDED(rc)) {
                        if (kDown & KEY_A) {
                            rc = nssuControlSetupCardUpdate(&sucontrol, NULL, NSSU_CARDUPDATE_TMEM_SIZE_DEFAULT);
                            printf("nssuControlSetupCardUpdate(): 0x%x\n", rc);
                        }
                        else if (kDown & KEY_B) {
                            rc = nssuControlSetupCardUpdateViaSystemUpdater(&sucontrol, NULL, NSSU_CARDUPDATE_TMEM_SIZE_DEFAULT);
                            printf("nssuControlSetupCardUpdateViaSystemUpdater(): 0x%x\n", rc);
                        }
                    }

                    if (R_SUCCEEDED(rc)) {
                        rc = nssuControlHasPreparedCardUpdate(&sucontrol, &tmpflag);
                        printf("nssuControlHasPreparedCardUpdate(): 0x%x, %d\n", rc, tmpflag);
                        if (R_SUCCEEDED(rc) && tmpflag) {
                            printf("Update was already Prepared, aborting.\n");
                            rc = 1;
                        }
                    }

                    if (R_SUCCEEDED(rc)) {
                        rc = nssuControlRequestPrepareCardUpdate(&sucontrol, &asyncres);
                        printf("nssuControlRequestPrepareCardUpdate(): 0x%x\n", rc);
                    }
                }
                else if (kDown & (KEY_X|KEY_Y)) {
                    updatetype=UpdateType_Send;

                    NsSystemDeliveryInfo deliveryinfo={0};
                    rc = nsInitialize();
                    if (R_FAILED(rc)) printf("nsInitialize(): 0x%x\n", rc);

                    if (R_SUCCEEDED(rc)) {
                        rc = nsGetSystemDeliveryInfo(&deliveryinfo);
                        printf("nsGetSystemDeliveryInfo(): 0x%x\n", rc);

                        nsExit();
                    }

                    if (R_SUCCEEDED(rc) && (kDown & KEY_Y)) {
                        rc = sukeyLocate(sysdeliveryinfo_key, &deliveryinfo);
                        printf("sukeyLocate(): 0x%x\n", rc);

                        if (R_SUCCEEDED(rc)) {
                            deliveryinfo.data.system_update_meta_version = system_version;
                            sukeySignSystemDeliveryInfo(sysdeliveryinfo_key, &deliveryinfo);
                        }
                        memset(sysdeliveryinfo_key, 0, sizeof(sysdeliveryinfo_key));
                    }

                    if (R_SUCCEEDED(rc) && (kDown & KEY_X)) {
                        rc = nssuRequestSendSystemUpdate(&asyncres, ipaddr, port, &deliveryinfo);
                        printf("nssuRequestSendSystemUpdate(): 0x%x\n", rc);
                    }
                    else if (R_SUCCEEDED(rc) && (kDown & KEY_Y)) {
                        if (datadir[0]) {
                            struct in_addr nxaddr = {.s_addr = htonl(INADDR_LOOPBACK)};
                            rc = managerSetup(&manager, &nxaddr, port, log_file, &transfer_state, datadir, depth);
                            printf("managerSetup(): 0x%x\n", rc);
                        }

                        if (R_SUCCEEDED(rc)) {
                            rc = nssuControlSetupToReceiveSystemUpdate(&sucontrol);
                            printf("nssuControlSetupToReceiveSystemUpdate(): 0x%x\n", rc);
                        }

                        if (R_SUCCEEDED(rc)) {
                            rc = nssuControlRequestReceiveSystemUpdate(&sucontrol, &asyncres, ipaddr, port, &deliveryinfo);
                            printf("nssuControlRequestReceiveSystemUpdate(): 0x%x\n", rc);
                        }

                        updatetype=UpdateType_Receive;
                    }
                }

                if (R_SUCCEEDED(rc)) state=1;
            }
            else if(state==1) {
                NsSystemUpdateProgress progress={0};
                if (updatetype==UpdateType_Download)
                    rc = nssuControlGetDownloadProgress(&sucontrol, &progress);
                else if (updatetype==UpdateType_Card)
                    rc = nssuControlGetPrepareCardUpdateProgress(&sucontrol, &progress);
                else if (updatetype==UpdateType_Send)
                    rc = nssuGetSendSystemUpdateProgress(&progress);
                else if (updatetype==UpdateType_Receive)
                    rc = nssuControlGetReceiveProgress(&sucontrol, &progress);
                consoleClear();
                float percent = 0.0f;
                if (progress.total_size > 0) percent = (((float)progress.current_size) / ((float)progress.total_size)) * 100.0f;
                if (percent > 100.0f) percent = 100.0f;
                printf("Get*Progress(): 0x%x, 0x%lx of 0x%lx, %f%%\n", rc, progress.current_size, progress.total_size, percent);

                cnt++;
                if (cnt>=60) {
                    for (u32 cnti=0; cnti<cnt/60; cnti++) printf(".");
                    printf("\n");
                }
                if (cnt >= 60*10) cnt=0;
                consoleUpdate(NULL);

                if (R_SUCCEEDED(rc)) {
                    Result rc2=0;

                    if (updatetype==UpdateType_Receive && deliveryManagerCheckFinished(&manager)) {
                        rc2 = deliveryManagerGetResult(&manager);
                        deliveryManagerClose(&manager);
                        if (R_FAILED(rc2)) printf("deliveryManagerGetResult(): 0x%x\n", rc2);
                    }

                    rc2 = asyncResultWait(&asyncres, 0);
                    if (R_SUCCEEDED(rc2)) {
                        printf("Operation finished.\n");

                        printf("asyncResultGet...\n");
                        consoleUpdate(NULL);
                        rc = asyncResultGet(&asyncres);
                        printf("asyncResultGet(): 0x%x\n", rc);
                        consoleUpdate(NULL);

                        if (R_SUCCEEDED(rc)) {
                            printf("asyncResultClose...\n");
                            consoleUpdate(NULL);
                            asyncResultClose(&asyncres);
                        }
                    }

                    if (R_SUCCEEDED(rc2))  {
                        if (R_SUCCEEDED(rc) && updatetype!=UpdateType_Send) {
                            if (updatetype==UpdateType_Download) {
                                rc = nssuControlHasDownloaded(&sucontrol, &tmpflag);
                                printf("nssuControlHasDownloaded(): 0x%x, %d\n", rc, tmpflag);
                            }
                            else if (updatetype==UpdateType_Card) {
                                rc = nssuControlHasPreparedCardUpdate(&sucontrol, &tmpflag);
                                printf("nssuControlHasPreparedCardUpdate(): 0x%x, %d\n", rc, tmpflag);
                            }
                            else if (updatetype==UpdateType_Receive) {
                                rc = nssuControlHasReceived(&sucontrol, &tmpflag);
                                printf("nssuControlHasReceived(): 0x%x, %d\n", rc, tmpflag);
                            }

                            if (R_SUCCEEDED(rc) && !tmpflag) {
                                printf("Update is not ready, aborting.\n");
                                rc = 1;
                            }
                            consoleUpdate(NULL);
                        }

                        if (R_SUCCEEDED(rc) && updatetype!=UpdateType_Send) {
                            printf("Applying update...\n");
                            consoleUpdate(NULL);

                            if (updatetype==UpdateType_Download) {
                                rc = nssuControlApplyDownloadedUpdate(&sucontrol);
                                printf("nssuControlApplyDownloadedUpdate(): 0x%x\n", rc);
                            }
                            else if (updatetype==UpdateType_Card) {
                                rc = nssuControlApplyCardUpdate(&sucontrol);
                                printf("nssuControlApplyCardUpdate(): 0x%x\n", rc);
                            }
                            else if (updatetype==UpdateType_Receive) {
                                rc = nssuControlApplyReceivedUpdate(&sucontrol);
                                printf("nssuControlApplyReceivedUpdate(): 0x%x\n", rc);
                            }
                        }

                        if (R_SUCCEEDED(rc)) {
                            printf("The update has finished. Press + to exit%s.\n", updatetype!=UpdateType_Send ? " and reboot" : "");
                            state=2;
                        }
                     }
                }
            }
        }

        // Update the console, sending a new frame to the display
        consoleUpdate(NULL);
    }

    printf("asyncResultClose...\n");
    consoleUpdate(NULL);
    asyncResultClose(&asyncres);

    nssuControlClose(&sucontrol);
    nssuExit();

    printf("deliveryManagerClose()...\n");
    consoleUpdate(NULL);
    deliveryManagerClose(&manager);

    if (log_file) fclose(log_file);

    if (state==2 && updatetype!=UpdateType_Send) {
        printf("Rebooting...\n");
        consoleUpdate(NULL);
        rc = appletRequestToReboot();
        printf("appletRequestToReboot(): 0x%x\n", rc);
        consoleUpdate(NULL);
    }

    // Deinitialize and clean up resources used by the console (important!)
    consoleExit(NULL);
    socketExit();
    if (R_SUCCEEDED(sleeprc)) sleeprc = appletSetAutoSleepDisabled(sleepflag);
    appletUnlockExit();
    return 0;
}
