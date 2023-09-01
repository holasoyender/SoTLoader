# SoTLoader, Inyector DLL para el juego Sea of Thieves

Este es un simple inyector DLL para el juego **Sea of Thieves** que ha sido creado a partir de un post en `UnknownCheats`. El inyector se basa en el método `CreateRemoteThread` y utiliza la función `LoadLibrary` para cargar la DLL en el proceso del juego (El juego no tiene ningún anti-cheat).

Este software está destinado a ser utilizado sólo con fines educativos. No me hago responsable de cualquier daño/ban causado por el mismo.

### Advertencia
Este software se proporciona "tal cual" sin garantía de ningún tipo. El autor no se hace responsable de ningún daño causado por este software.

## Localización
Este inyector detecta automáticamente el idioma del usuario, y mostrará las cadenas en los siguientes idiomas:
- English
- Español
- Русский (gracias a exzyyy)

Siéntete libre de contribuir con más idiomas.

## Modo de empleo
1. Descarga la última versión desde la [página de versiones](https://github.com/holasoyender/SoTLoader/releases)
2. Extrae el archivo zip
3. Mueve el archivo o archivos DLL que quieras inyectar a la carpeta `libs` (créala si no existe)
4. Ejecute el ejecutable, si mueve más de un archivo DLL a la carpeta, se le preguntará cuál desea inyectar

## Descargar la DLL
Si desea descargar la DLL, ejecute de nuevo el ejecutable y se le preguntará si desea descargar la DLL.

## Cómo compilar
1. Clonar el repositorio
2. Abre el archivo de la solución con Visual Studio 2022 o más reciente
3. Compilar el proyecto para `Release x64`.

## Créditos
Copyright (C) 2023 holasoyender, under the [GPL-3.0 License](../LICENSE)