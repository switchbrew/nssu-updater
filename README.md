# nssu-updater
Nintendo Switch homebrew app for installing sysupdates with the ns:su service.

### Usage
When the app is started a menu is displayed for selecting what update-type to use, what update-types are available depend on the running system-version and what args the app was launched with. These are:

* When a system-version wasn't specified via arg:
  * Button '-': Installs sysupdate downloaded from CDN. This is equivalent to installing a sysupdate with System Settings, however this just installs the latest update with nssuControlRequestDownloadLatestUpdate. Whether a sysupdate is needed is not checked (nssuControlRequestCheckLatestUpdate), and previously downloaded CDN updates are not handled either (BackgroundNetworkUpdate).
  * Button 'A': nssuControlSetupCardUpdate, installs sysupdate from gamecard.
  * [4.0.0+] Button 'B': [nssuControlSetupCardUpdateViaSystemUpdater](https://switchbrew.org/wiki/NS_Services#SetupCardUpdateViaSystemUpdater). This requires HostIO, and DebugMode must be enabled.
* [4.0.0+] Button 'X', when system-version and datadir wasn't specified via arg: Send.
* [4.0.0+] Button 'Y': Receive.
* Button DPad-Down, when system-version and datadir was specified via arg: Server-mode.

A log is stored in the current-working-directory as `nssu-updater.log`, with releases this is located at `/switch/nssu-updater/nssu-updater.log`. Check this log when issues occur. For error-codes, see [switchbrew](https://switchbrew.org/wiki/Error_codes).

### Download
The latest release is available from the [releases](https://github.com/switchbrew/nssu-updater/releases/latest) page.

### Building
Clone with `git clone --recurse-submodules {...}`: this uses [contents-delivery-manager](https://github.com/switchbrew/contents-delivery-manager) as a submodule.

With the [toolchain](https://switchbrew.org/wiki/Setting_up_Development_Environment) setup, just run `make`.

Building releases via `make dist-bin RELEASE=1` requires `zip`.

The following [pacman packages](https://devkitpro.org/wiki/devkitPro_pacman) are required:
- `switch-dev`
- `switch-libconfig`
