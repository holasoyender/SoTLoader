# SoTLoader, DLL Injector for the game Sea of Thieves
### [Español](docs/README-es.md) | [Русский](docs/README-ru.md)

This is a simple DLL injector for the game **Sea of Thieves** that has been reverse engineered from a post on `UnknownCheats`. The injector is based on the `CreateRemoteThread` method and it uses the `LoadLibrary` function to load the DLL into the game process (The game does not have any anti-cheat).

This software is intended to be used for educational purposes only. I am not responsible for any damage/ban caused by it.

### Warning
This software is provided "as is" without warranty of any kind. The author is not responsible for any damage caused by this software.

## Localizations
This injector automatically detects the language of the user, and it will show strings in the following languages:
- English
- Spanish
- Russian (thanks to exzyyy)

Feel free to contribute with more localizations.

## How to use
1. Download the latest release from the [releases page](https://github.com/holasoyender/SoTLoader/releases)
2. Extract the zip file
3. Move the DLL file(s) you want to inject to the `libs` folder (create it if it doesn't exist)
4. Run the executable, if you move more than one DLL file to the folder, you will be asked which one you want to inject

## Unloading the DLL
If you want to unload the DLL, run the executable again and you will be asked if you want to unload the DLL.

## How to compile
1. Clone the repository
2. Open the solution file with Visual Studio 2022 or newer
3. Compile the project for `Release x64`

## Credits
Copyright (C) 2023 holasoyender, under the [GPL-3.0 License](LICENSE)