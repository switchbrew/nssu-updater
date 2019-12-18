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

#define TRACE(_f,fmt,...) if (_f) fprintf(_f, "%s: " fmt, __PRETTY_FUNCTION__, ## __VA_ARGS__)
#define TRACE_PRINT(_f,fmt,...) {if (_f) fprintf(_f, "%s: " fmt, __PRETTY_FUNCTION__, ## __VA_ARGS__); printf(fmt, ## __VA_ARGS__);}

// qlaunch handles Eula for sysupdates, however we won't.

typedef enum {
    UpdateType_None,
    UpdateType_Download,
    UpdateType_Card,
    UpdateType_CardViaSystemUpdater,
    UpdateType_Send,
    UpdateType_Receive,
    UpdateType_Server,
} UpdateType;

typedef enum {
    UpdateState_Initial,
    UpdateState_Confirm,
    UpdateState_InProgress,
    UpdateState_Done,
} UpdateState;

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

Result managerHandlerMetaPackagedContentInfo(void* userdata, NcmPackagedContentInfo* meta_content_info, const NcmContentMetaKey* content_meta_key) {
    Result rc=0;
    struct DeliveryContentEntry *entry = NULL;

    rc = deliveryManagerGetContentEntry((DeliveryManager*)userdata, &entry, content_meta_key, NULL);
    if (R_SUCCEEDED(rc)) memcpy(meta_content_info, &entry->content_info, sizeof(NcmPackagedContentInfo));
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
    if (R_FAILED(rc)) TRACE_PRINT(log_file, "deliveryManagerCreate() failed: 0x%x\n", rc)
    if (R_SUCCEEDED(rc)) {
        if (log_file) deliveryManagerSetLogFile(manager, log_file);
        deliveryManagerSetHandlerGetMetaPackagedContentInfo(manager, managerHandlerMetaPackagedContentInfo, manager);
        deliveryManagerSetHandlersGetContent(manager, transfer_state, managerContentTransferInit, managerContentTransferExit, managerContentTransfer);

        rc = ncmInitialize();
        if (R_FAILED(rc)) TRACE_PRINT(log_file, "ncmInitialize() failed: 0x%x\n", rc)

        if (R_SUCCEEDED(rc)) {
            rc = ncmOpenContentStorage(&storage, NcmStorageId_BuiltInSystem);
            if (R_FAILED(rc)) TRACE_PRINT(log_file, "ncmOpenContentStorage failed: 0x%x\n", rc)
        }

        if (R_SUCCEEDED(rc)) {
            TRACE_PRINT(log_file, "Scanning datadir...\n")
            consoleUpdate(NULL);
            rc = deliveryManagerScanDataDir(manager, datadir, depth, managerHandlerMetaLoad, &storage);
            if (R_FAILED(rc)) TRACE_PRINT(log_file, "deliveryManagerScanDataDir() failed: 0x%x\n", rc)
        }

        ncmContentStorageClose(&storage);
        ncmExit();

        if (R_SUCCEEDED(rc)) {
            rc = deliveryManagerRequestRun(manager);
            if (R_FAILED(rc)) TRACE_PRINT(log_file, "deliveryManagerRequestRun() failed: 0x%x\n", rc)
        }

        if (R_SUCCEEDED(rc)) TRACE_PRINT(log_file, "Server started.\n")
        consoleUpdate(NULL);
    }

    return rc;
}

Result managerParseSystemVersion(const char *verstr, u32 *system_version) {
    Result rc=0;
    char *endarg = NULL;

    errno = 0;
    if (verstr[0] == 'v') verstr++;
    *system_version = strtoul(verstr, &endarg, 0);
    if (endarg == verstr) errno = EINVAL;
    if (errno != 0) {
        *system_version = 0;
        rc = MAKERESULT(Module_Libnx, LibnxError_BadInput);
    }

    return rc;
}

SwkbdTextCheckResult managerShowKbdValidateText(char* tmp_string, size_t tmp_string_size) {
    struct in_addr tmpaddr={0};
    if (inet_pton(AF_INET, tmp_string, &tmpaddr)!=1) {
        strncpy(tmp_string, "Bad IPv4 address.", tmp_string_size);
        return SwkbdTextCheckResult_Bad;
    }

    return SwkbdTextCheckResult_OK;
}

Result managerShowKbd(FILE *log_file, bool select_ipaddr, const char *msg, char *out_str, size_t outstr_size) {
    Result rc=0;
    SwkbdConfig kbd;
    rc = swkbdCreate(&kbd, 0);
    if (R_FAILED(rc)) TRACE_PRINT(log_file, "swkbdCreate(): 0x%x\n", rc)

    if (R_SUCCEEDED(rc)) {
        swkbdConfigMakePresetDefault(&kbd);

        swkbdConfigSetType(&kbd, SwkbdType_NumPad);
        swkbdConfigSetTextDrawType(&kbd, SwkbdTextDrawType_Line);

        swkbdConfigSetStringLenMax(&kbd, select_ipaddr ? 15 : 10);
        if (select_ipaddr) {
            swkbdConfigSetLeftOptionalSymbolKey(&kbd, ".");
            swkbdConfigSetTextCheckCallback(&kbd, managerShowKbdValidateText);
        }

        swkbdConfigSetHeaderText(&kbd, msg);

        rc = swkbdShow(&kbd, out_str, outstr_size);
        if (R_FAILED(rc)) TRACE_PRINT(log_file, "swkbdShow(): 0x%x\n", rc)

        swkbdClose(&kbd);
    }

    return rc;
}

Result sukeyLocate(FILE *log_file, u8 *out_key, NsSystemDeliveryInfo *delivery_info) {
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
        TRACE_PRINT(log_file, "Debug SVCs aren't available, make sure you're running the latest hbloader release.\n")
        rc = MAKERESULT(Module_Libnx, LibnxError_NotFound);
    }

    // Get the PID for ns.
    if (R_SUCCEEDED(rc)) {
        rc = pmdmntInitialize();
        if (R_FAILED(rc)) TRACE_PRINT(log_file, "pmdmntInitialize(): 0x%x\n", rc)
    }

    if (R_SUCCEEDED(rc)) {
        rc = pmdmntGetProcessId(&pid, 0x010000000000001F);
        if (R_FAILED(rc)) TRACE_PRINT(log_file, "pmdmntGetProcessId(): 0x%x\n", rc)
        pmdmntExit();
    }

    // Get the LoaderModuleInfo for ns.
    if (R_SUCCEEDED(rc)) {
        rc = ldrDmntInitialize();
        if (R_FAILED(rc)) TRACE_PRINT(log_file, "ldrDmntInitialize(): 0x%x\n", rc)

        if (R_SUCCEEDED(rc)) {
            rc = ldrDmntGetProcessModuleInfo(pid, module_infos, 1, &total_out);
            if (R_FAILED(rc)) TRACE_PRINT(log_file, "ldrDmntGetProcessModuleInfo(): 0x%x\n", rc)
            if (R_SUCCEEDED(rc) && total_out!=1) {
                TRACE_PRINT(log_file, "total_out from ldrDmntGetProcessModuleInfo() is invalid: %d.\n", total_out)
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
        if (R_FAILED(rc)) TRACE_PRINT(log_file, "svcDebugActiveProcess(): 0x%x\n", rc)

        if (R_SUCCEEDED(rc)) {
            while (R_SUCCEEDED(rc) && cur_module_size>0) {
                rc = svcQueryDebugProcessMemory(&meminfo, &pageinfo, debughandle, cur_addr);
                if (R_FAILED(rc)) TRACE_PRINT(log_file, "svcQueryDebugProcessMemory(): 0x%x\n", rc)

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
                TRACE_PRINT(log_file, "Failed to find the R-- section in ns.\n")
                rc = MAKERESULT(Module_Libnx, LibnxError_NotFound);
            }

            if (R_SUCCEEDED(rc)) {
                rosection_size = meminfo.size;
                rosection_buf = (u8*)malloc(rosection_size);
                if (rosection_buf==NULL) {
                    TRACE_PRINT(log_file, "Failed to allocate memory for rosection_buf.\n")
                    rc = MAKERESULT(Module_Libnx, LibnxError_OutOfMemory);
                }
                else
                    memset(rosection_buf, 0, rosection_size);
            }

            if (R_SUCCEEDED(rc)) {
                rc = svcReadDebugProcessMemory(rosection_buf, debughandle, cur_addr, rosection_size);
                if (R_FAILED(rc)) TRACE_PRINT(log_file, "svcReadDebugProcessMemory(): 0x%x\n", rc)
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
            TRACE_PRINT(log_file, "Failed to find the hmac key.\n")
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

    UpdateState state=UpdateState_Initial;
    bool tmpflag=0;
    bool sleepflag=0;
    bool sysver_flag = hosversionAtLeast(4,0,0);
    UpdateType updatetype=UpdateType_None;
    u64 keymask=0, keymask_allbuttons=(KEY_MINUS|KEY_A|KEY_B|KEY_X|KEY_Y|KEY_DDOWN);

    FILE *log_file = NULL;
    NsSystemUpdateControl sucontrol={0};
    AsyncResult asyncres={0};
    u8 sysdeliveryinfo_key[SHA256_HASH_SIZE]={0};
    DeliveryManager manager={0};
    struct ManagerContentTransferState transfer_state={0};

    u16 port=55556;
    u32 ipaddr = ntohl(__nxlink_host.s_addr);
    u32 system_version=0;

    char datadir[PATH_MAX];
    s32 depth=3;
    bool manager_enabled=0, manager_setup=0;

    appletLockExit();

    sleeprc = appletIsAutoSleepDisabled(&sleepflag);
    if (R_SUCCEEDED(sleeprc)) sleeprc = appletSetAutoSleepDisabled(true);
    socketInitializeDefault();

    consoleInit(NULL);

    memset(datadir, 0, sizeof(datadir));

    if (R_SUCCEEDED(rc)) {
        log_file = fopen("nssu-updater.log", "w");
        if (log_file==NULL) {
            rc = MAKERESULT(Module_Libnx, LibnxError_IoError);
            printf("Failed to open the log file.\n");
        }
    }

    TRACE_PRINT(log_file, "nssu-updater %s\n", VERSION)

    if (R_SUCCEEDED(rc) && !configassocWrite("/config/nx-hbmenu/fileassoc/nssu-updater.cfg", "/switch/nssu-updater/nssu-updater.nro", ".nssu-update"))
        TRACE_PRINT(log_file, "Failed to write the hbmenu config.\n")

    if (R_SUCCEEDED(rc) && argc > 1) {
        char *argptr = argv[1];
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

        rc = managerParseSystemVersion(optarg, &system_version);
        if (R_FAILED(rc))
            TRACE_PRINT(log_file, "Invalid input arg for system-version.\n")
        else
            TRACE_PRINT(log_file, "Using system-version from arg: v%u\n", system_version)

        if (datadir[0]) TRACE_PRINT(log_file, "Using datadir from arg: %s\n", datadir)

        if (system_version && datadir[0]) manager_enabled = true;
    }

    if (R_SUCCEEDED(rc)) {
        rc = nssuInitialize();
        if (R_FAILED(rc)) TRACE_PRINT(log_file, "nssuInitialize(): 0x%x\n", rc)
    }

    if (R_SUCCEEDED(rc)) {
        if (!sysver_flag) TRACE_PRINT(log_file, "The following are not available since [4.0.0+] is required: Send/Receive and nssuControlSetupCardUpdateViaSystemUpdater.\n")

        if (!system_version) {
            printf("Press - to install update downloaded from CDN.\n");
            printf("Press A to install update with nssuControlSetupCardUpdate.\n");
            if (sysver_flag) printf("Press B to install update with nssuControlSetupCardUpdateViaSystemUpdater.\n");
            else keymask |= KEY_B;
        }
        else keymask |= KEY_MINUS|KEY_A|KEY_B;
        if (sysver_flag) {
            if (!manager_enabled) printf("Press X to Send the sysupdate.\n");
            else keymask |= KEY_X;
            printf("Press Y to Receive the sysupdate.\n");
        }
        else keymask |= (KEY_X|KEY_Y);
        if (manager_enabled) {
            printf("Press DPad-Down for server-mode.\n");
        }
        else keymask |= KEY_DDOWN;
    }

    printf("Press + exit, aborting the operation prior to applying the update.\n");

    u32 cnt=0;

    // Main loop
    while (appletMainLoop())
    {
        // Scan all the inputs. This should be done once for each frame
        hidScanInput();

        // hidKeysDown returns information about which buttons have been
        // just pressed in this frame compared to the previous one
        u64 kDown = hidKeysDown(CONTROLLER_P1_AUTO) & ~keymask;
        u64 kHeld = hidKeysHeld(CONTROLLER_P1_AUTO);

        if (kDown & KEY_PLUS)
            break; // break in order to return to hbmenu

        if (R_SUCCEEDED(rc)) {
            if (state==UpdateState_Initial && (kDown & keymask_allbuttons)) {
                char *updatedesc = "";
                char tmpstr[256];
                char tmpoutstr[32];

                if (kDown & KEY_MINUS) {
                    updatetype = UpdateType_Download;
                    updatedesc = "CDN, roughly equivalent to installing the latest sysupdate with System Settings";
                }
                else if (kDown & KEY_A) {
                    updatetype = UpdateType_Card;
                    updatedesc = "Gamecard";
                }
                else if (kDown & KEY_B) {
                    updatetype = UpdateType_CardViaSystemUpdater;
                    updatedesc = "CardViaSystemUpdater";
                }
                else if (kDown & KEY_X) {
                    updatetype = UpdateType_Send;
                    updatedesc = "Send";
                }
                else if (kDown & KEY_Y) {
                    updatetype = UpdateType_Receive;
                    memset(tmpstr, 0, sizeof(tmpstr));
                    snprintf(tmpstr, sizeof(tmpstr)-1, "Receive, %s", manager_enabled ? "sysupdate will be installed with the above local datadir + version" : "sysupdate will be installed with the above remote IP addr + version");
                    updatedesc = tmpstr;
                }
                else if (kDown & KEY_DDOWN) {
                    updatetype = UpdateType_Server;
                    updatedesc = "Server, sysupdate from the above datadir will be sent to a client\nover the network";
                }

                if ((updatetype==UpdateType_Receive && !manager_enabled) || updatetype==UpdateType_Send || updatetype==UpdateType_Server) {
                    struct in_addr tmpaddr = {.s_addr = htonl(ipaddr)};
                    if (updatetype==UpdateType_Server) tmpaddr.s_addr = gethostid();

                    if ((updatetype==UpdateType_Receive || updatetype==UpdateType_Send) && !ipaddr) {
                        const char *msgstr = updatetype==UpdateType_Receive ? "Enter the server IPv4 address for Receive." : "Enter the client IPv4 address for Send.";

                        memset(tmpoutstr, 0, sizeof(tmpoutstr));
                        rc = managerShowKbd(log_file, true, msgstr, tmpoutstr, sizeof(tmpoutstr));

                        if (R_SUCCEEDED(rc) && inet_pton(AF_INET, tmpoutstr, &tmpaddr)!=1) {
                            TRACE_PRINT(log_file, "Bad IPv4 address.\n");
                            rc = MAKERESULT(Module_Libnx, LibnxError_BadInput);
                        }

                        if (R_SUCCEEDED(rc)) ipaddr = ntohl(tmpaddr.s_addr);
                    }

                    if (R_SUCCEEDED(rc) && updatetype==UpdateType_Receive && !system_version) {
                        memset(tmpoutstr, 0, sizeof(tmpoutstr));
                        rc = managerShowKbd(log_file, false, "Enter the SystemUpdate Meta version for Receive.", tmpoutstr, sizeof(tmpoutstr));

                        if (R_SUCCEEDED(rc)) {
                            rc = managerParseSystemVersion(tmpoutstr, &system_version);
                            if (R_FAILED(rc))
                                TRACE_PRINT(log_file, "Invalid system-version.\n")
                            else
                                TRACE_PRINT(log_file, "Using system-version: v%u\n", system_version)
                        }
                    }

                    if (R_SUCCEEDED(rc)) TRACE_PRINT(log_file, "%s: %s\n", updatetype!=UpdateType_Server ? "Using remote IP address" : "Console (server) IP address", inet_ntoa(tmpaddr));
                }

                if (R_SUCCEEDED(rc)) TRACE(log_file, "You selected update-type: %s.\n", updatedesc);

                if (R_SUCCEEDED(rc)) printf(    CONSOLE_ESC(31;1m) /* Set color to red */
                "You selected update-type:\n%s.\n"
                "%s"
                "Do not continue if the console is low on battery,\nunless the console is charging.\n"
                "Are you sure you want to continue?\nPress the following buttons at the same time to confirm:\nA, B, X, Y, DPad-Up.\n"
                "If you want to exit instead, press the + button.\n"
                CONSOLE_ESC(0m) /* revert attributes*/
                , updatedesc, updatetype!=UpdateType_Send ? "Backup your nandimage if you haven't already done so prior to running this.\nBricking may occur if the input sysupdate is corrupted.\n" : "");

                if (R_SUCCEEDED(rc)) state = UpdateState_Confirm;
            }
            else if (state==UpdateState_Confirm && (kHeld == (KEY_A|KEY_B|KEY_X|KEY_Y|KEY_DUP))) {
                if (updatetype==UpdateType_Download || updatetype==UpdateType_Card || updatetype==UpdateType_CardViaSystemUpdater || updatetype==UpdateType_Receive) {
                    rc = nssuOpenSystemUpdateControl(&sucontrol);
                    TRACE_PRINT(log_file, "nssuOpenSystemUpdateControl(): 0x%x\n", rc)
                }

                if (R_SUCCEEDED(rc)) {
                    if (updatetype==UpdateType_Download) {
                        rc = nssuControlRequestDownloadLatestUpdate(&sucontrol, &asyncres);
                        TRACE_PRINT(log_file, "nssuControlRequestDownloadLatestUpdate(): 0x%x\n", rc)
                    }
                    else if (updatetype==UpdateType_Card || updatetype==UpdateType_CardViaSystemUpdater) {
                        if (R_SUCCEEDED(rc)) {
                            if (updatetype==UpdateType_Card) {
                                rc = nssuControlSetupCardUpdate(&sucontrol, NULL, NSSU_CARDUPDATE_TMEM_SIZE_DEFAULT);
                                TRACE_PRINT(log_file, "nssuControlSetupCardUpdate(): 0x%x\n", rc)
                            }
                            else if (updatetype==UpdateType_CardViaSystemUpdater) {
                                rc = nssuControlSetupCardUpdateViaSystemUpdater(&sucontrol, NULL, NSSU_CARDUPDATE_TMEM_SIZE_DEFAULT);
                                TRACE_PRINT(log_file, "nssuControlSetupCardUpdateViaSystemUpdater(): 0x%x\n", rc)
                            }
                        }

                        if (R_SUCCEEDED(rc)) {
                            rc = nssuControlHasPreparedCardUpdate(&sucontrol, &tmpflag);
                            TRACE_PRINT(log_file, "nssuControlHasPreparedCardUpdate(): 0x%x, %d\n", rc, tmpflag)
                            if (R_SUCCEEDED(rc) && tmpflag) {
                                TRACE_PRINT(log_file, "Update was already Prepared, aborting.\n")
                                rc = 1;
                            }
                        }

                        if (R_SUCCEEDED(rc)) {
                            rc = nssuControlRequestPrepareCardUpdate(&sucontrol, &asyncres);
                            TRACE_PRINT(log_file, "nssuControlRequestPrepareCardUpdate(): 0x%x\n", rc)
                        }
                    }
                    else if (updatetype==UpdateType_Send || updatetype==UpdateType_Receive || updatetype==UpdateType_Server) {
                        NsSystemDeliveryInfo deliveryinfo={0};
                        if (updatetype==UpdateType_Send || updatetype==UpdateType_Receive) {
                            rc = nsInitialize();
                            if (R_FAILED(rc)) TRACE_PRINT(log_file, "nsInitialize(): 0x%x\n", rc)

                            if (R_SUCCEEDED(rc)) {
                                rc = nsGetSystemDeliveryInfo(&deliveryinfo);
                                TRACE_PRINT(log_file, "nsGetSystemDeliveryInfo(): 0x%x\n", rc)

                                nsExit();
                            }
                        }

                        if (R_SUCCEEDED(rc) && updatetype==UpdateType_Receive) {
                            rc = sukeyLocate(log_file, sysdeliveryinfo_key, &deliveryinfo);
                            TRACE_PRINT(log_file, "sukeyLocate(): 0x%x\n", rc)

                            if (R_SUCCEEDED(rc)) {
                                deliveryinfo.data.system_update_meta_version = system_version;
                                sukeySignSystemDeliveryInfo(sysdeliveryinfo_key, &deliveryinfo);
                            }
                            memset(sysdeliveryinfo_key, 0, sizeof(sysdeliveryinfo_key));
                        }

                        if (R_SUCCEEDED(rc) && updatetype==UpdateType_Send) {
                            rc = nssuRequestSendSystemUpdate(&asyncres, ipaddr, port, &deliveryinfo);
                            TRACE_PRINT(log_file, "nssuRequestSendSystemUpdate(): 0x%x\n", rc)
                        }
                        else if (R_SUCCEEDED(rc) && (updatetype==UpdateType_Receive || updatetype==UpdateType_Server)) {
                            if ((updatetype==UpdateType_Receive && manager_enabled) || updatetype==UpdateType_Server) {
                                struct in_addr nxaddr = {.s_addr = htonl(updatetype==UpdateType_Receive ? INADDR_LOOPBACK : INADDR_ANY)};
                                rc = managerSetup(&manager, &nxaddr, port, log_file, &transfer_state, datadir, depth);
                                TRACE_PRINT(log_file, "managerSetup(): 0x%x\n", rc)

                                manager_setup = true;
                            }

                            if (R_SUCCEEDED(rc) && updatetype==UpdateType_Receive) {
                                rc = nssuControlSetupToReceiveSystemUpdate(&sucontrol);
                                TRACE_PRINT(log_file, "nssuControlSetupToReceiveSystemUpdate(): 0x%x\n", rc)
                            }

                            if (R_SUCCEEDED(rc) && updatetype==UpdateType_Receive) {
                                rc = nssuControlRequestReceiveSystemUpdate(&sucontrol, &asyncres, ipaddr, port, &deliveryinfo);
                                TRACE_PRINT(log_file, "nssuControlRequestReceiveSystemUpdate(): 0x%x\n", rc)
                            }
                        }
                    }
                }

                if (R_SUCCEEDED(rc)) state = UpdateState_InProgress;
            }
            else if (state==UpdateState_InProgress) {
                NsSystemUpdateProgress progress={0};
                if (updatetype==UpdateType_Download)
                    rc = nssuControlGetDownloadProgress(&sucontrol, &progress);
                else if (updatetype==UpdateType_Card || updatetype==UpdateType_CardViaSystemUpdater)
                    rc = nssuControlGetPrepareCardUpdateProgress(&sucontrol, &progress);
                else if (updatetype==UpdateType_Send)
                    rc = nssuGetSendSystemUpdateProgress(&progress);
                else if (updatetype==UpdateType_Receive)
                    rc = nssuControlGetReceiveProgress(&sucontrol, &progress);
                else if (updatetype==UpdateType_Server)
                    deliveryManagerGetProgress(&manager, &progress.current_size, &progress.total_size);
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

                    if (updatetype==UpdateType_Server) rc2 = 1;
                    if (manager_setup && deliveryManagerCheckFinished(&manager)) {
                        if (updatetype==UpdateType_Server) printf("Operation finished.\n");
                        rc2 = deliveryManagerGetResult(&manager);
                        deliveryManagerClose(&manager);
                        TRACE_PRINT(log_file, "deliveryManagerGetResult(): 0x%x\n", rc2)
                        if (updatetype==UpdateType_Server) rc = rc2;
                    }

                    if (updatetype!=UpdateType_Server) {
                        rc2 = asyncResultWait(&asyncres, 0);
                        if (R_SUCCEEDED(rc2)) {
                            printf("Operation finished.\n");

                            printf("asyncResultGet...\n");
                            consoleUpdate(NULL);
                            rc = asyncResultGet(&asyncres);
                            TRACE_PRINT(log_file, "asyncResultGet(): 0x%x\n", rc)
                            consoleUpdate(NULL);
                        }
                    }

                    if (R_SUCCEEDED(rc2) && updatetype!=UpdateType_Server) {
                        if (R_SUCCEEDED(rc) && updatetype!=UpdateType_Send) {
                            if (updatetype==UpdateType_Download) {
                                rc = nssuControlHasDownloaded(&sucontrol, &tmpflag);
                                TRACE_PRINT(log_file, "nssuControlHasDownloaded(): 0x%x, %d\n", rc, tmpflag)
                            }
                            else if (updatetype==UpdateType_Card || updatetype==UpdateType_CardViaSystemUpdater) {
                                rc = nssuControlHasPreparedCardUpdate(&sucontrol, &tmpflag);
                                TRACE_PRINT(log_file, "nssuControlHasPreparedCardUpdate(): 0x%x, %d\n", rc, tmpflag)
                            }
                            else if (updatetype==UpdateType_Receive) {
                                rc = nssuControlHasReceived(&sucontrol, &tmpflag);
                                TRACE_PRINT(log_file, "nssuControlHasReceived(): 0x%x, %d\n", rc, tmpflag)
                            }

                            if (R_SUCCEEDED(rc) && !tmpflag) {
                                TRACE_PRINT(log_file, "Update is not ready, aborting.\n")
                                rc = 1;
                            }
                            consoleUpdate(NULL);
                        }

                        if (R_SUCCEEDED(rc) && updatetype!=UpdateType_Send) {
                            TRACE_PRINT(log_file, "Applying update...\n")
                            consoleUpdate(NULL);

                            if (updatetype==UpdateType_Download) {
                                rc = nssuControlApplyDownloadedUpdate(&sucontrol);
                                TRACE_PRINT(log_file, "nssuControlApplyDownloadedUpdate(): 0x%x\n", rc)
                            }
                            else if (updatetype==UpdateType_Card || updatetype==UpdateType_CardViaSystemUpdater) {
                                rc = nssuControlApplyCardUpdate(&sucontrol);
                                TRACE_PRINT(log_file, "nssuControlApplyCardUpdate(): 0x%x\n", rc)
                            }
                            else if (updatetype==UpdateType_Receive) {
                                rc = nssuControlApplyReceivedUpdate(&sucontrol);
                                TRACE_PRINT(log_file, "nssuControlApplyReceivedUpdate(): 0x%x\n", rc)
                            }
                        }
                    }

                    if (R_SUCCEEDED(rc2) && R_SUCCEEDED(rc)) {
                        TRACE_PRINT(log_file, "The update has finished. Press + to exit%s.\n", updatetype!=UpdateType_Send && updatetype!=UpdateType_Server ? " and reboot" : "")
                        state = UpdateState_Done;
                    }
                }
            }
        }

        // Update the console, sending a new frame to the display
        consoleUpdate(NULL);
    }

    TRACE(log_file, "Exiting...\n");

    printf("asyncResultClose...\n");
    consoleUpdate(NULL);
    asyncResultClose(&asyncres);

    nssuControlClose(&sucontrol);
    nssuExit();

    if (manager_setup) {
        printf("deliveryManagerClose()...\n");
        consoleUpdate(NULL);
        deliveryManagerClose(&manager);
    }

    if (log_file) fclose(log_file);

    if (state==UpdateState_Done && updatetype!=UpdateType_Send && updatetype!=UpdateType_Server) {
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
