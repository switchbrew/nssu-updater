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
* Button DPad-Down, when system-version and datadir were specified via arg: Server-mode.

This app can be launched with an optional arg: `[v]{version}` or `{datadir}/[v]{version}[remaining non-numeric characters are ignored].nssu-update`. The former is intended for nxlink (however the latter can be used with nxlink too if wanted), while the latter is intended for hbmenu [file-associations](https://switchbrew.org/wiki/Homebrew_Menu#File_Associations). The file-association config is automatically created during app startup. The previously mentioned version is for the SystemUpdate Meta (0100000000000816), see [ninupdates](https://yls8.mtheall.com/ninupdates/reports.php).

Example [nxlink](https://switchbrew.org/wiki/Homebrew_Menu) command: `nxlink nssu-updater.nro [v]{version}`.

The [datadir](https://github.com/switchbrew/contents-delivery-manager) is the directory containing the sysupdate content data which will be used for local installation (update-type Receive), or with server-mode for sending to another system. The above `.nssu-update` file is located in this directory, multiple `.nssu-update` files can exist in the same directory if wanted. The content of these files doesn't matter, it can be empty. This file is selected by [navigating](https://switchbrew.org/wiki/Homebrew_Menu) to it with hbmenu.

When used, the datadir is scanned recursively with a maximum depth of 3. See [contents-delivery-manager](https://github.com/switchbrew/contents-delivery-manager) for content filenames in the datadir. During Meta loading with datadir-scanning the Meta content is temporarily "installed" into PlaceHolder content, this is deleted immediately after it's done using the content.

The Send/Receive update-types require an IPv4 address (with Receive this only applies when version+datadir wasn't specified via arg). When launched with nxlink the address from nxlink is used, otherwise the software-keyboard applet will be shown for entering the address. This applet will also be shown for entering the version with Receive, if not specified via the arg.

The Send/Receive update-types use [contents-delivery](https://switchbrew.org/wiki/NIM_services#Contents_Delivery). Receive connects to a server to install the sysupdate, while Send starts a server for sending the currently-installed sysupdate to a client. Send is unusable while connected to a normal wifi network due to a check done by nim, use server-mode instead. The server-mode update-type is a reimplementation of Send using [contents-delivery-manager](https://github.com/switchbrew/contents-delivery-manager), with the source sysupdate being the above specified datadir. When a datadir is specified with Receive, it will connect to a [server](https://github.com/switchbrew/contents-delivery-manager) running locally to install the sysupdate from the datadir, otherwise it will connect to the remote [server](https://github.com/switchbrew/contents-delivery-manager) with the above IP address (the remote server can also be another system running server-mode).

The sysupdate must be compatible with the system installing it. This can't be used for downgrading.

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
