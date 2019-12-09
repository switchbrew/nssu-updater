// Include the most common headers from the C standard library
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include <sys/socket.h>
#include <arpa/inet.h>

// Include the main libnx system header, for Switch development
#include <switch.h>

// qlaunch handles Eula for sysupdates, however we won't.

typedef enum {
    UpdateType_None        = -1,
    UpdateType_Download    =  0,
    UpdateType_Card        =  1,
    UpdateType_Send        =  2,
    UpdateType_Receive     =  3,
} UpdateType;

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

// Main program entrypoint
int main(int argc, char* argv[])
{
    Result rc=0;
    NsSystemUpdateControl sucontrol={0};
    AsyncResult asyncres={0};
    u8 sysdeliveryinfo_key[SHA256_HASH_SIZE]={0};
    u32 state=0;
    bool tmpflag=0;
    bool sleepflag=0;
    Result sleeprc=0;
    UpdateType updatetype=UpdateType_None;
    u32 ipaddr = ntohl(__nxlink_host.s_addr); // TODO: Should specifiying ipaddr via other means be supported?
    u32 system_version=0;                     // TODO: Same TODO as above.

    appletLockExit();

    sleeprc = appletIsAutoSleepDisabled(&sleepflag);
    if (R_SUCCEEDED(sleeprc)) sleeprc = appletSetAutoSleepDisabled(true);

    consoleInit(NULL);

    printf("nssu_updater\n");

    if (argc > 1) {
        char *endarg = NULL;
        char *optarg = argv[1];
        if (optarg[0] == 'v') optarg++;

        errno = 0;
        system_version = strtoul(optarg, &endarg, 0);
        if (endarg == optarg) errno = EINVAL;
        if (errno != 0) {
            system_version = 0;
            printf("Invalid input arg for system-version.\n");
        }
    }

    printf("Press - to install update downloaded from CDN.\n");
    printf("Press A to install update with nssuControlSetupCardUpdate.\n");
    printf("Press B to install update with nssuControlSetupCardUpdateViaSystemUpdater.\n");
    if (ipaddr) {
        printf("Press X to Send the sysupdate.\n");
        if (system_version) printf("Press Y to Receive the sysupdate.\n");
    }
    printf("Press + exit, aborting any operations prior to the final stage.\n");

    rc = nssuInitialize();
    printf("nssuInitialize(): 0x%x\n", rc);

    if (ipaddr) printf("Using IP addr from nxlink: %s\n", inet_ntoa(__nxlink_host));

    u32 cnt=0;

    // Main loop
    while (appletMainLoop())
    {
        // Scan all the inputs. This should be done once for each frame
        hidScanInput();

        // hidKeysDown returns information about which buttons have been
        // just pressed in this frame compared to the previous one
        u64 kDown = hidKeysDown(CONTROLLER_P1_AUTO);

        if (kDown & KEY_PLUS)
            break; // break in order to return to hbmenu

        if (R_SUCCEEDED(rc)) {
            if (state==0 && R_SUCCEEDED(rc) && ((kDown & (KEY_MINUS|KEY_A|KEY_B))
                || (ipaddr && (kDown & KEY_X))
                || (ipaddr && system_version && (kDown & KEY_Y)))) {
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
                        rc = nssuRequestSendSystemUpdate(&asyncres, ipaddr, 55556, &deliveryinfo);
                        printf("nssuRequestSendSystemUpdate(): 0x%x\n", rc);
                    }
                    else if (R_SUCCEEDED(rc) && (kDown & KEY_Y)) {
                        rc = nssuControlSetupToReceiveSystemUpdate(&sucontrol);
                        printf("nssuControlSetupToReceiveSystemUpdate(): 0x%x\n", rc);

                        if (R_SUCCEEDED(rc)) {
                            rc = nssuControlRequestReceiveSystemUpdate(&sucontrol, &asyncres, ipaddr, 55556, &deliveryinfo);
                            printf("nssuControlRequestReceiveSystemUpdate(): 0x%x\n", rc);
                        }

                        updatetype=UpdateType_Receive;
                    }
                }

                if (R_SUCCEEDED(rc)) state=1;
            }
            else if(state==1 && R_SUCCEEDED(rc)) {
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
                    Result rc2 = asyncResultWait(&asyncres, 0);
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

    if (state==2 && updatetype!=UpdateType_Send) {
        printf("Rebooting...\n");
        consoleUpdate(NULL);
        rc = appletRequestToReboot();
        printf("appletRequestToReboot(): 0x%x\n", rc);
        consoleUpdate(NULL);
    }

    // Deinitialize and clean up resources used by the console (important!)
    consoleExit(NULL);
    if (R_SUCCEEDED(sleeprc)) sleeprc = appletSetAutoSleepDisabled(sleepflag);
    appletUnlockExit();
    return 0;
}
