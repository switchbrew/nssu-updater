# nssu-updater
Nintendo Switch homebrew app for installing sysupdates with the ns:su service.

### Usage

### Download
The latest release is available from the [releases](https://github.com/switchbrew/nssu-updater/releases/latest) page.

### Building
Clone with `git clone --recurse-submodules {...}`: this uses [contents-delivery-manager](https://github.com/switchbrew/contents-delivery-manager) as a submodule.

With the [toolchain](https://switchbrew.org/wiki/Setting_up_Development_Environment) setup, just run `make`.

Building releases via `make dist-bin RELEASE=1` requires `zip`.

The following [pacman packages](https://devkitpro.org/wiki/devkitPro_pacman) are required:
- `switch-dev`
- `switch-libconfig`
