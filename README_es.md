# Cargadores de Sega para Ghidra

Cargadores y módulo de análisis para Ghidra dirigido a imágenes de cartucho y de disco de Sega: Mega
Drive / Genesis y Sega 32X, con hueco para la ventana de programa del Sega CD cuando la imagen la trae,
Master System y Game Gear, y los dos procesadores 68000 de un disco Sega CD. Cada uno reconstruye el
espacio de direcciones de la consola a partir de la cabecera del ROM o del disco, pone nombre a los
registros del hardware, aplica las estructuras de cabecera y de tabla de vectores, y puede desensamblar
el programa mientras el código se ejecuta de verdad en el emulador BlastEm.

Parte del cargador original de **Dr. MefistO** ([lab313ru/ghidra_sega_ldr](https://github.com/lab313ru/ghidra_sega_ldr));
ver [Créditos](#créditos) para la autoría y para lo que cambia este fork.

**English:** [README.md](README.md).

---

## Índice

- [Qué construye el cargador](#qué-construye-el-cargador)
- [Master System y Game Gear](#master-system-y-game-gear)
- [Sega CD](#sega-cd)
- [Opciones de importación](#opciones-de-importación)
- [Verificación de la cabecera](#verificación-de-la-cabecera)
- [Analizador: variables con offset negativo](#analizador-variables-con-offset-negativo)
- [Desensamblado en vivo con BlastEm](#desensamblado-en-vivo-con-blastem)
- [La ventana BlastEm Live](#la-ventana-blastem-live)
- [Requisitos y objetivos admitidos](#requisitos-y-objetivos-admitidos)
- [Compilación](#compilación)
- [Instalación](#instalación)
- [Scripts](#scripts)
- [Estructura del repositorio](#estructura-del-repositorio)
- [Límites conocidos](#límites-conocidos)
- [Créditos](#créditos)
- [Lo que cambia este fork](#lo-que-cambia-este-fork)

---

## Qué construye el cargador

El módulo instala un cargador por familia, y uno por procesador cuando una máquina ejecuta dos: el
formato de ejecutable que queda grabado en un programa es el nombre del cargador, y cada consola
necesita su propio lenguaje y su propio espacio de direcciones.

| Cargador | Reconocer el objetivo | Lenguaje |
| --- | --- | --- |
| `SegaLoader` — *Sega Mega Drive / Genesis Loader* | `SEGA` en `0x100` | `68000:BE:32:MC68020` |
| | un cartucho de 32X lleva además `MARS CHECK MODE` en `0x3C0`, y se ofrece una segunda vez | `SuperH:BE:32:SH-2` |
| `SegaSmsLoader` — *Sega Master System / Game Gear Loader* | `TMR SEGA` en `0x7FF0`, si no en `0x3FF0`, si no en `0x1FF0` | `z80:LE:16:default` |
| `SegaCdMainLoader` — *Sega CD Loader (Main 68000)* | `SEGADISCSYSTEM` en `0x0` o en `0x10` de la imagen, o una hoja `.cue` cuyo volcado lo lleve | `68000:BE:32:MC68020` |
| `SegaCdSubLoader` — *Sega CD Loader (Sub 68000)* | el mismo disco, y hay que pedirlo por nombre | `68000:BE:32:MC68020` |
| `SegaCdMmdLoader` — *Sega CD Loader (Disc Member)* | un fichero del volumen de ese disco, que hay que nombrar, con la dirección en la que se coloca | `68000:BE:32:MC68020` |

Todo lo que hay bajo este epígrafe se crea durante la importación, antes de que corra ningún análisis, y
cubre las máquinas de 68000. Las de 8 bits tienen su propio epígrafe:
[Master System y Game Gear](#master-system-y-game-gear), y el disco también: [Sega CD](#sega-cd).

### Memoria del cartucho y del sistema

| Bloque | Dirección | Contenido | Observaciones |
| --- | --- | --- | --- |
| `ROM` | `0x000000` | la imagen | con el tamaño que sale de la cabecera, nunca menor que el fichero; legible, ejecutable, no escribible |
| `EPA` | `0x400000` | segunda ventana de 4 MiB | zona de programa del Sega CD; contiene datos del fichero a partir de `0x400000` cuando la imagen llega a tanto; se crea solo si se pide |
| `RAM` | `0xFF0000` | 64 KiB | RAM de trabajo, legible, escribible y ejecutable, para que se pueda seguir el código que el juego copia ahí; llega con los bloques de registros |
| `RAM` | `0x00FF0000` | — | espejo con mapa de bytes del bloque de arriba, el alias que el 68000 también acepta |
| `BACKUP_RAM` | de la cabecera | hasta 128 KiB | ver [Opciones de importación](#opciones-de-importación); volátil, no ejecutable |
| `WORK_RAM` | de la cabecera | — | solo cuando la cabecera declara algo distinto de `0xFF0000`–`0xFFFFFF`; no ejecutable |

### Registros del hardware

Los bloques de registros se marcan como volátiles, así que Ghidra no descarta como código muerto una
escritura en el hardware (la ventana ancha del `Z80` y `RAM` se quedan sin esa marca). Los nombres
siguen la documentación del hardware y las etiquetas que usan las cadenas de herramientas de homebrew
para esos mismos registros.

| Bloque | Dirección | Datos nombrados |
| --- | --- | --- |
| `Z80` | `0xA00000` (64 KiB) | `Z80_YM2612` en `0xA04000` |
| `SYS1` | `0xA10000` | `IO_PCBVER`, `IO_CT1_DATA`, `IO_CT2_DATA`, `IO_EXT_DATA`, `IO_CT1_CTRL`, `IO_CT2_CTRL`, `IO_EXT_CTRL`, `IO_CT1_RX`, `IO_CT1_TX`, `IO_CT1_SMODE`, `IO_CT2_RX`, `IO_CT2_TX`, `IO_CT2_SMODE`, `IO_EXT_RX`, `IO_EXT_TX`, `IO_EXT_SMODE` |
| `SYS2` | `0xA11000` | `IO_RAMMODE` |
| `Z802` | `0xA11100` | `IO_Z80BUS` |
| `Z803` | `0xA11200` | `IO_Z80RES` |
| `FDC` | `0xA12000` | `IO_FDC` (0x100 bytes); no se crea para un disco Sega CD, cuyo ASIC responde ahí en su lugar |
| `TIME` | `0xA13000` | `IO_TIME` (0x100 bytes, o 0xEC cuando hay segmentos del 32X para que `0xA130EC` se quede con el 32X) |
| `TMSS` | `0xA14000` | `IO_TMSS` |
| `VDP` | `0xC00000` | `VDP_DATA`, `VDP__DATA`, `VDP_CTRL`, `VDP__CTRL`, `VDP_CNTR`, `VDP__CNTR`, `VDP___CNTR`, `VDP____CNTR`, `VDP_PSG` |

Las variantes con `__` son el acceso al byte alto del mismo registro, al que el código 68000 llega
sumando 1 a la dirección.

### Sega 32X

Con los segmentos del 32X activados, el 68000 ve lo siguiente, y cada registro está nombrado y tipado:

| Bloque | Dirección | Contenido |
| --- | --- | --- |
| `32X_PRIV` | `0x800000` | 256 KiB |
| `32X_DRAM` | `0x840000` | 128 KiB |
| `32X_OWIMG` | `0x860000` | 128 KiB |
| `32X_ROM_FIXED` | `0x880000` | los primeros 512 KiB de la imagen |
| `32X_ROM_BANK0`…`32X_ROM_BANK3` | `0x900000` + | 1 MiB cada uno, hasta donde llegue el fichero |
| `32X_ID` | `0xA130EC` | `IO_32X_ID` |
| `32X_BANK_SET_REG` | `0xA130F1` | `IO_32X_BANK_SET_REG`, 15 palabras |
| `32X_SYS_REG` | `0xA15100` | `IO_32X_VDP_CTRL`, `IO_32X_ADAPTER_CTRL`, `IO_32X_SH2_INT_CTRL`, `IO_32X_BANK_CTRL`, `IO_32X_DREQ_CTRL`, `IO_32X_68K_SH2_DREQ_SRC`, `IO_32X_68K_SH2_DREQ_DEST`, `IO_32X_68K_SH2_DREQ_LEN`, `IO_32X_68K_SH2_DREQ_FIFO`, `IO_32X_SEGA_TV_REG`, `IO_32X_COMM`, `IO_32X_PWM_CTRL`, `IO_32X_CYCLE_REG`, `IO_32X_L_CH_PULSE_REG`, `IO_32X_R_CH_PULSE_REG`, `IO_32X_MONO_PULSE_REG` |
| `32X_VDP_REG` | `0xA15180` | `IO_32X_VDP_REG`, 0x80 bytes |
| `32X_PAL` | `0xA15200` | `IO_32X_PAL`, 256 palabras |

La segunda tabla de saltos de una imagen de 32X, que va justo detrás de la tabla de vectores y no tiene
punto de entrada propio, se desensambla como parte de la importación (`0x200`–`0x3C0`).

Cargado como SH-2, el mismo fichero produce en su lugar el mapa propio del núcleo: `SH2_BOOT_ROM` en
`0x00000000`, `SH2_SYS_REG` en `0x00004000` con los registros de interrupción, DREQ, comunicación y PWM
nombrados, `SH2_VDP_REG` en `0x00004100`, `SH2_PAL` en `0x00004200`, `SH2_ROM` en `0x02000000`,
`SH2_DRAM` en `0x04000000`, `SH2_OWIMG` en `0x04020000` y `SH2_SDRAM` en `0x06000000`, cada uno con su
alias cache-through en `+0x20000000`. La cabecera de usuario MARS (nombre del módulo, versión, dirección
de origen y de destino, tamaño, y las cuatro direcciones de inicio y de vectores de los SH-2) se aplica
en `0x8803C0`, y `SHM_entry` y `SHS_entry` se crean en las direcciones de inicio del maestro y del
esclavo que declara.

### Estructuras aplicadas al listado

- **`VectorsTable`** en `0x000`: los 64 longwords de la tabla de excepciones e interrupciones, con cada
  campo nombrado (`SSP`, `Reset`, `BusErr`, `AdrErr`, `InvOpCode`, `DivBy0`, `Check`, `TrapV`, `GPF`,
  `Trace`, `BadInt`, `BadIRQ`, `IRQ1`, `EXT`, `IRQ3`, `HBLANK`, `IRQ5`, `VBLANK`, `IRQ7`,
  `Trap0`…`Trap15`, y las posiciones reservadas).
- **`GameHeader`** en `0x100`: `ConsoleName`, `ReleaseDate`, `DomesticName`, `InternationalName`,
  `Version`, `Checksum`, `IoSupport`, `RomStart`, `RomEnd`, `RamStart`, `RamEnd`, `SramCode`,
  `SramStart`, `SramEnd`, `Notes`, más la etiqueta `GAME_HEADER`, un comentario de placa con el título,
  la versión, la fecha, las regiones y los controles, y ese mismo título como comentario del bloque
  `ROM`.

La tabla de vectores además siembra las primeras funciones: cada vector cuyo destino cae en memoria
inicializada, ejecutable y no volátil se convierte en una función con el nombre del vector. Un vector que
apunta a la RAM de trabajo, a una constante o a la nada se deja como está y recibe un comentario de fin
de línea diciendo a dónde apunta, que es lo que las imágenes comerciales suelen hacer con las entradas
reservadas y sin uso.

## Master System y Game Gear

Las dos máquinas de 8 bits comparten cabecera de cartucho y espacio de direcciones, así que un solo
cargador las cubre a las dos; el nibble de región de la cabecera decide qué puertos se construyen. La
imagen se carga desde la posición 0 y el Z80 ve 64 KiB, así que las páginas de un cartucho grande no se
pueden colocar todas a la vez.

### Páginas del cartucho

| Bloque | Dirección | Contenido |
| --- | --- | --- |
| `ROM` | `0x0000`–`0x7FFF` | las dos primeras páginas del fichero, donde arranca la consola; legible, ejecutable |
| `ROM_BANK2` | `0x8000`–`0xBFFF` | página 2: la ventana que el mapper mueve, dejada en su sitio hasta que el juego escribe en `0xFFFC` |
| `ROM_BANK3`… | `0x8000`–`0xBFFF`, como superposiciones | cada página adicional de 16 KiB, una superposición por página, con su posición en el fichero en el comentario del bloque |
| `RAM` | `0xC000`–`0xDFFF` | los 8 KiB de RAM del sistema, que la consola duplica sobre `0xC000`–`0xFFFF`; volátil, no ejecutable |
| `RAM_ECHO` | `0xE000`–`0xFFFB` | espejo con mapa de bytes de la parte alta de esa RAM |
| `MAPPER` | `0xFFFC`–`0xFFFF` | `MAPPER_PAGE1`, `MAPPER_PAGE2`, `MAPPER_PAGE3`: el número de banco de las tres ventanas, escrito como bytes; volátil |
| `CART_RAM` | `0x8000`–`0xBFFF`, como superposición | solo con un fichero de partida guardada: la RAM con pila o extra de un cartucho vive en la ventana que el mapper mueve |

Una imagen de 32 KiB no necesita mapper y produce el bloque `ROM` por sí solo; una más corta se carga
igual y el log dice cuánto del duplicado no puede rellenar el fichero.

Las superposiciones son lo único aquí que es un compromiso con Ghidra y no una propiedad del hardware: la
consola mantiene una página en esa ventana a la vez, y la ventana del mapa de memoria es donde se elige la
que había cargado un juego en ejecución.

### Puertos

Los bloques de puertos viven en el espacio `io` del lenguaje Z80 y son volátiles. El decodificador
convierte un número de puerto inmediato en una constante, así que estos bloques no recogen referencias del
código; lo que dan a un puerto al que se llega por un registro, o que se encuentra a mano, es un nombre y
un tipo.

| Bloque | Puertos | Nombrados |
| --- | --- | --- |
| `VDP` | `0x80`–`0xBF` | `VDP_DATA` en `0xBE`, `VDP_CTRL` en `0xBF` — datos en direcciones pares, control y estado en impares |
| `PSG` | `0x40`–`0x7F` | `PSG_WRITE` en `0x7F`, `HV_COUNTER_H` en `0x40`, `HV_COUNTER_V` en `0x41` — las escrituras llegan al generador de tono, las lecturas devuelven la posición de barrido retenida |
| `CONTROLLER` | `0xC0`–`0xFF` | `IO_DATA_AB` en `0xDC`, `IO_CTRL` en `0xDD`, y la misma pareja en `0xC0` y `0xC1` |
| `IO_CONTROL` | `0x00`–`0x3F`, o `0x08`–`0x3F` en Game Gear | el retén que hace que se actualicen las líneas del mando y la posición de barrido |
| `GG_IO` | `0x00`–`0x06`, solo en Game Gear | `GG_START_REGION`, `GG_IO_DATA`, `GG_IO_CTRL`, `GG_SERIAL_OUT`, `GG_SERIAL_RX`, `GG_SERIAL_CTRL`, `PSG_PAN` |

### Cabecera y puntos de entrada

- **`SmsHeader`** en la posición que llevaba la firma — etiqueta `SMS_HEADER`, y un comentario de placa
  con la región, la versión, el código de producto, el checksum declarado y su rango, y el tamaño de la
  imagen en páginas. Esa misma región y código de producto van al comentario del bloque `ROM`.
- **El programa** se desensambla desde `0x0000`: el vector de reset de estas consolas no lleva más que un
  salto y el lenguaje Z80 lo sigue. `NMI_ISR` se crea en `0x66` y `RST_08` … `RST_38` en las direcciones de
  rearranque.
- **`-loader-verify`** añade las comprobaciones de [Verificación de la cabecera](#verificación-de-la-cabecera)
  para este formato: el tamaño que el nibble de región describe contra el fichero, el checksum de Sega, y
  el de Codemasters cuando el cartucho lo lleva.

El checksum de Sega es una suma de bytes sobre `0x0000` hasta la cabecera y luego sobre `0x8000` hasta el
tamaño que describe el nibble de rango, plegada a 16 bits. Los cartuchos de Codemasters usan una cabecera
propia justo antes de la de Sega —una suma de palabras sobre todo el fichero menos la cabecera de Sega, y
un checksum que se calcula paginando con escrituras en `0x0000`, `0x4000` y `0x8000` en lugar de con
`0xFFFC`–`0xFFFF`. Los dos se informan, y ninguno aborta la importación: solo la BIOS del Master System de
exportación se niega a arrancar un juego cuyo checksum no cuadra, así que una imagen de Game Gear o
japonesa suele llevar un campo que la consola nunca lee.

## Sega CD

Un disco son dos programas en dos procesadores 68000 que llegan a las mismas memorias a través de un solo
ASIC, y cada uno ve esas memorias en una dirección distinta. Así que un disco tiene dos vistas, y lo que
decide entre ellas es el cargador que la importación nombre.

### Dos cargadores, un disco

| Vista | Cargador | Lo que recibe |
| --- | --- | --- |
| la consola | `SegaCdMainLoader` — *Sega CD Loader (Main 68000)* | la ROM de arranque del CD donde se coloca un cartucho, la RAM de programa por la ventana que alcanza la consola, la RAM de palabras y la imagen de celdas, la región de puertos con el ASIC dentro, y la RAM de trabajo con el programa que arrancó con el disco |
| la unidad | `SegaCdSubLoader` — *Sega CD Loader (Sub 68000)* | los 512 KiB enteros de RAM de programa con el programa propio del disco dentro, la RAM de palabras por sus dos ventanas, la RAM con pila, la memoria de sonido y el ASIC en lo alto del espacio de direcciones |

Una importación que no nombra ningún cargador cae en la vista del procesador que ejecuta la consola,
porque es ese el para el que está escrito un programa del disco. La vista propia de la unidad se pide
con `-loader SegaCdSubLoader`, o se escoge de la lista de cargadores del diálogo de importación. Un
programa en Ghidra es un procesador, así que las dos vistas de un disco significan importar la imagen dos
veces.

Un tercer cargador, `SegaCdMmdLoader`, hace un programa de un *fichero* del disco en lugar del disco: ver
[Miembros del disco](#miembros-del-disco).

### El disco, y lo que se lee de él

Una imagen se acepta cuando sus primeros bytes, o los dieciséis que vienen después, son
`SEGADISCSYSTEM`: una pista de sectores de 2048 bytes, o un volcado en crudo de sectores de 2352. Una
hoja `.cue` también se acepta, empiece como empiece — delante puede ir un número `CATALOG`, un comentario
`REM`, un género o una fecha — y reparta el disco como lo reparta: se abre cada `FILE` de bytes
almacenados que la hoja nombra, con los nombres entrecomillados que lleven espacios y paréntesis, y la
leída es la pista cuyo volcado lleva la firma. Su `INDEX 01` dice dónde empieza la pista; cuando los bytes
no están de acuerdo con la hoja, lo que se cree es la firma, y el registro de la importación dice a qué
distancia estaban uno de otro. Las pistas de audio se pasan por alto, y también un volcado guardado como
hoja `MOTOROLA` en vez de bytes almacenados, que no se puede leer sector a sector.

Lo que el cargador saca del disco son tres cosas pequeñas y fijas, y una que no es ninguna de las dos:

- el **primer sector**, `0x800` bytes de cabecera, leídos por sus campos de dispositivo y región, su
  versión, su fecha de publicación y sus dos zonas de programa;
- el **programa de la unidad**, desde la dirección del disco y la longitud del primer par (`0x40` y
  `0x44`), colocado donde ese procesador lo ejecuta;
- el **programa de la consola**, que no es una promesa que el disco haga: la etapa de arranque siempre
  toma 1,5 KiB de `0x200` del disco y los pone en el fondo de la RAM de trabajo, desde donde piden a la
  unidad el resto del juego;
- la **lista de los ficheros** que el disco lleva en su volumen, que toda importación de un disco escribe
  en su registro, con el sector y la longitud de cada uno, directorios incluidos — ver
  [Miembros del disco](#miembros-del-disco).

El segundo par de la cabecera (`0x48` y `0x4c`) se lee, y se dice en voz alta siempre que está vacío o
lleva un sitio distinto de ese: ninguna hoja hace que la consola lea desde donde ese par dice, así que de
un disco se avisa y no se le cree más allá.

### Miembros del disco

Debajo de sus programas, un disco de Sega CD es un volumen ISO-9660, y dentro de ese volumen un juego
guarda programitas para el 68000 de la consola: los ficheros llamados `.MMD` que carga en RAM y ejecuta,
junto a los datos `.BIN`, las pistas `.STM` y los `.TXT` del mismo volumen.

`SegaCdMmdLoader` importa uno de esos ficheros como programa propio, sobre el mapa de la consola — los
bloques que describe [Vista del lado del cartucho](#vista-del-lado-del-cartucho), para que las
referencias que el miembro hace a las memorias de alrededor recaigan en un nombre:

```bash
analyzeHeadless proj name -import game.cue -loader SegaCdMmdLoader \
    -loader-cd-mmd ATTACK.MMD -loader-cd-mmd-address 0xFF2000
```

**El disco no dice dónde se carga un miembro.** La cabeza de un `.MMD` no es una tabla de vectores, y las
direcciones de su interior nombran a la vez la RAM de trabajo, la RAM de palabras, el cartucho y la
unidad: nada de lo que el disco guarda fija el sitio, así que la dirección se pide, y el registro dice, con
todas esas letras, que la que salió es la que se dio. Se lee como `ff2000`, `0xff2000` o `$ff2000`, y no
tiene que llegar más allá de `0xFFFFFF`. El nombre se casa como un volumen lo escribe: en mayúsculas, sin
el `;1`, con la extensión solo cuando nada más contesta al mismo tronco, y con el directorio por delante
cuando dos ficheros comparten nombre.

El diálogo pide lo mismo, y el programa propio del disco no es donde un miembro aparece: con la `.cue`
escogida, se cambia **Format** de *Sega CD Loader (Main 68000)* a *Sega CD Loader (Disc Member)* y se
pulsa `Options…`; los dos campos que muestra bajo *The member of the volume* contestan por el disco —
el del nombre se abre con los ficheros que el volumen lleva, puesto en el primer `.MMD` de ellos, y el
de la dirección es lo que queda por escribir. El **Format** primero y `Options…` después: el diálogo
vacía lo que se hubiera escrito en cuanto cambia el cargador, y lo que se contestó vuelve para la
siguiente importación del mismo proyecto. Una importación que no nombra ningún fichero toma aquel en
el que la caja está puesta, y dice cuál en el registro. Un miembro es un programa propio, así que cien
ficheros son cien importaciones, y los nombres que valen la pena escoger son los que toda importación de
un Sega CD escribe en su registro. Un fichero sacado del disco por delante no es una vía de entrada: un
`.MMD` no lleva nada que diga qué es, así que hay que leerlo a través del disco del que vino.

Lo que llega es un bloque llamado como el fichero, con una función en su primer byte, y cada ventana de
memoria que lo contenía queda cortada a las partes que sobran — `WORK_RAM_FREE` pasa a ser dos bloques,
por decir algo — así que nunca se crea nada encima del miembro. Un fichero se lee hasta 1 MiB y se reporta
la longitud que quedó fuera de eso. Un miembro puesto sobre registros, en `0xA12000` por ejemplo, se nombra
con todos los bloques en los que entra y se coloca igualmente, como superposición: lo que se pidió en la
importación no es cosa del cargador negarlo.

Nada de esto llega al disco importado antes, y no está pensado para ello: la RAM de trabajo de ese mapa se
crea sin bytes, porque el disco no dice qué lleva un juego ahí, y un listado de `??` sobre `WORK_RAM_FREE`
es eso mismo dicho en voz alta. Los bytes de esas direcciones salen de la RAM del emulador, que ninguna
versión de este módulo puede entregar todavía.

### Vista del lado del cartucho

| Bloque | Dirección | Contenido |
| --- | --- | --- |
| `BIOS_ROM` | `0x000000`–`0x01FFFF` | la ROM de arranque, 128 KiB; bytes de `-loader-cd-bios`, un agujero del mismo tamaño sin ellos |
| `BIOS_ROM` | `0x040000`–`0x05FFFF` | el alias de esa misma ROM, solo cuando se le dieron sus bytes |
| `PROGRAM_RAM` | `0x020000`–`0x025FFF` | la RAM de programa baja por la ventana que se le da a este procesador |
| `DISC_PROGRAM` | `0x026000` + | el programa de la unidad, los mismos bytes que muestra la vista propia de la unidad |
| `PROGRAM_RAM_FREE` | … – `0x03FFFF` | el resto de esa ventana |
| `WORD_RAM` | `0x200000`–`0x21FFFF` | 128 KiB de la RAM de palabras del ASIC, el banco que selecciona el `GATE_ARRAY` |
| `CELL_IMAGE` | `0x220000`–`0x23FFFF` | la ventana de esa RAM de la que el ASIC dibuja su tipografía en pantalla |
| `GATE_ARRAY` | `0xA12000` | los registros del ASIC, donde un cartucho pone un controlador de disquetera |
| `BOOT_PROGRAM` | `0xFF0000`–`0xFF05FF` | el programa que arrancó con el disco, y `BOOT_entry` en su primer byte |
| `WORK_RAM_FREE` | `0xFF0600`–`0xFFFFFF` | la RAM de trabajo después de él, en tantos bloques como haga falta por los miembros del volumen |

Los bloques de Genesis de [Registros del hardware](#registros-del-hardware) llegan con esta vista —
`Z80`, `SYS1`, `SYS2`, `Z802`, `Z803`, `TIME`, `TMSS`, `VDP` — menos `FDC`, cuya dirección se la queda el
ASIC.

### Vista del lado de la unidad

| Bloque | Dirección | Contenido |
| --- | --- | --- |
| `PROGRAM_RAM` | `0x000000`–`0x005FFF` | la RAM de programa baja, donde la etapa de arranque guarda los vectores y el espacio de trabajo de este procesador |
| `DISC_PROGRAM` | `0x006000` + | el programa del disco, desde la dirección que declara su cabecera |
| `PROGRAM_RAM_FREE` | … – `0x07FFFF` | el resto de los 512 KiB de los que dispone este procesador |
| `WORD_RAM` | `0x080000`–`0x0BFFFF` | 256 KiB, la RAM de palabras entera del ASIC |
| `WORD_RAM_1M` | `0x0C0000`–`0x0DFFFF` | esa misma RAM por la ventana que solo enseña su primera mitad |
| `BACKUP_RAM` | `0xFE0000`– | 8 KiB de RAM con pila, respondidos en las direcciones impares de una ventana de 64 KiB; bytes de `-loader-cd-bram` |
| `BACKUP_RAM_FREE` | … – `0xFEFFFF` | el resto de esa ventana, cuando la partida guardada no la llena |
| `PCM` | `0xFF0000`–`0xFF7FFF` | la memoria de sonido del RF5C164, respondida en direcciones impares |
| `GATE_ARRAY` | `0xFF8000` | los registros del ASIC |

### El ASIC, el chip de sonido y sus nombres

Una sola tabla de registros sirve a las dos vistas, a doble del índice de palabra contando desde la base
del bloque: `0xA12000` para la consola, `0xFF8000` para la unidad.

| Dirección | Registro |
| --- | --- |
| `+0x00` | `GA_SUB_CPU_CTRL`, `GA_MEM_MODE`, `GA_CDC_CTRL`, `GA_CDC_REG_DATA`, `GA_CDC_HOST_DATA`, `GA_CDC_DMA_ADDR`, `GA_STOP_WATCH`, `GA_COMM_FLAG` |
| `+0x10` | `GA_COMM_CMD0`…`GA_COMM_CMD7` — las palabras que la consola pone delante de la unidad |
| `+0x20` | `GA_COMM_STATUS0`…`GA_COMM_STATUS7` — las palabras con las que se le responde |
| `+0x30` | `GA_TIMER`, `GA_INT_MASK`, `GA_CDD_FADER`, `GA_CDD_CTRL` |
| `+0x38` | `GA_CDD_STATUS0`…`GA_CDD_STATUS4`, y después `GA_CDD_CMD0`…`GA_CDD_CMD4` |
| `+0x4C` | `GA_FONT_COLOR`, `GA_FONT_BITS`, `GA_FONT_DATA0`…`GA_FONT_DATA3` |
| `+0x100` | `GA_SUBCODE`, la cola de bytes de subcódigo leídos del disco; `GA_SUBCODE_MIRROR` marca la repetición del fichero entero en `+0x180` |

Al chip de sonido solo llega la unidad, solo por direcciones de byte impares, y sus ocho canales comparten
un juego de registros elegido por una escritura en el puerto de control: `PCM_CHANNEL_ENVELOPE`,
`PCM_CHANNEL_PAN`, `PCM_CHANNEL_FREQ_LOW`, `PCM_CHANNEL_FREQ_HIGH`, `PCM_CHANNEL_LOOP_LOW`,
`PCM_CHANNEL_LOOP_HIGH`, `PCM_CHANNEL_START` en `0xFF0001` hasta `0xFF000D`, y después `PCM_CONTROL` en
`0xFF000F` y `PCM_CHANNEL_ENABLE` en `0xFF0011`. `PCM_WAVE_RAM` marca las muestras por encima de ellos, en
`0xFF2001`.

### Lo que el cargador nombra en cualquiera de las dos vistas

- **La cabecera del disco** no se coloca en memoria —es el sector que lee la etapa de arranque antes de
  que exista ningún programa—, pero toda su placa de texto va al comentario de cada bloque de programa que
  describe, y al registro de la importación.
- **Las entradas de la etapa de arranque** se etiquetan donde las pone el hardware, en la RAM de programa
  baja para la unidad (`bios_common_work` en `0x5E80`, y luego `_setjmptbl`, `_waitvsync`, `_buram`,
  `_cdboot`, `_cdbios`, `_usercall0`–`_usercall3`, `_adrerr`, `_coderr`, `_diverr`, `_chkerr`, `_trperr`,
  `_spverr`, `_trace`, `_nocod0`, `_nocod1` y `_slevel1`–`_slevel3` hasta `0x5F82`) y en la ROM de arranque
  para la consola, cuando se dio su fichero: las entradas `_bios_*` de `0x280` a `0x368`, que es cómo una
  llamada de la interfaz de programación de aplicaciones del CD se convierte en un nombre del listado.
- **`-loader-verify`** informa de un primer sector que no abre con `SEGADISCSYSTEM`, y de un programa de la
  unidad declarado dentro del propio sector de cabecera o más allá de lo que el disco guarda. Ninguno de
  ellos aborta la importación.

## Opciones de importación

Cada elección es una opción real del cargador. Aparece en el diálogo de importación con el valor que se
indica aquí y se puede fijar desde una línea de comandos, así que una importación no necesita ninguna
interacción.

| Cargador | Opción | Etiqueta en el diálogo | Por defecto | Efecto |
| --- | --- | --- | --- | --- |
| Genesis | `-loader-32x` | Create Sega 32X segments | activada en un cartucho de 32X o una carga SH-2, desactivada en lo demás | los bloques y registros del 32X de arriba |
| Genesis | `-loader-sega-cd` | Create Sega CD (EPA) segment | desactivada | la ventana `EPA` de `0x400000` |
| todos | `-loader-hw-registers` | Create hardware register blocks | activada | `Z80`, `SYS*`, `FDC`, `TIME`, `TMSS`, `VDP`, `RAM` y su espejo, los bloques `VDP`, `PSG`, `CONTROLLER`, `IO_CONTROL` y `MAPPER` de las máquinas de 8 bits, o los registros del `GATE_ARRAY` y de sonido de un disco |
| todos | `-loader-verify` | Verify the ROM header | activada | las comprobaciones de [Verificación de la cabecera](#verificación-de-la-cabecera) |
| Genesis | `-loader-sram-file <ruta>` | Backup RAM contents file (.srm / .sram) | vacía | rellena `BACKUP_RAM` con un fichero de partida guardada |
| SMS / GG | `-loader-cart-ram-file <ruta>` | Cartridge RAM contents file (.sav / .sms) | vacía | rellena la superposición `CART_RAM` de `0x8000` con un fichero de partida guardada |
| Sega CD | `-loader-cd-bios <ruta>` | CD BIOS image the console runs before the disc (.bin) | vacía | rellena `BIOS_ROM` y su alias en la vista de la consola |
| Sega CD | `-loader-cd-bram <ruta>` | Backup RAM contents file (.brm / .bkr) | vacía | rellena `BACKUP_RAM` en la vista de la unidad, repartido por las direcciones impares de su ventana |
| Miembro del disco | `-loader-cd-mmd <nombre>` | Disc member to import (ISO-9660 name) | el primer `.MMD` del volumen | el fichero del volumen que se importa; en el diálogo es una caja con los ficheros que el disco lleva, y un nombre que no sea uno de ellos se contesta con la lista |
| Miembro del disco | `-loader-cd-mmd-address <dirección>` | Address the member is loaded at | vacía | dónde van esos bytes, `0xFF2000` para la RAM de trabajo; hace falta porque ningún disco la dice |

Las dos opciones de fichero de un disco se comprueban en la importación, y una ruta que no es un fichero
para la importación con el motivo en vez de cargar media máquina.

```bash
analyzeHeadless /tmp/proj nombre -import game.bin -loader SegaLoader \
    -loader-32x true -loader-hw-registers true -loader-verify true \
    -loader-sram-file guardado.srm

analyzeHeadless /tmp/proj nombre -import game.sms -loader SegaSmsLoader \
    -loader-hw-registers true -loader-verify true

analyzeHeadless /tmp/proj nombre -import game.cue -loader SegaCdMainLoader \
    -loader-cd-bios bios_CD_E.bin -loader-hw-registers true -loader-verify true

analyzeHeadless /tmp/proj nombre -import game.cue -loader SegaCdSubLoader \
    -loader-cd-bram guardado.brm -loader-hw-registers true
```

El tamaño de la partida guardada no tiene por qué coincidir con el que declara la cabecera. El bloque se
crea con el tamaño declarado y rellenado a ceros, el fichero se copia encima, y cualquier diferencia se
informa. Cuando la RAM de respaldo declarada comparte su ventana con el ROM, que es como la mapean la
mayoría de los cartuchos, el bloque solo se crea si se indica un fichero de guardado; si no, la dirección
sigue mostrando el programa y recibe una etiqueta `BACKUP_RAM`. Una partida de Game Gear o Master System
ocupa hasta 32 KiB y siempre va a la ventana paginada, así que el bloque `CART_RAM` es una superposición
también cuando el fichero es más corto que una página.

## Verificación de la cabecera

`-loader-verify` informa, sin abortar la importación:

- de la ausencia de la firma `SEGA` en `0x100`;
- de un inicio de ROM declarado distinto de `0`;
- de una longitud de ROM declarada que no cuadra con el fichero;
- de un código de región ausente o desconocido en `0x1F0`;
- del checksum en `0x18E`, comparado contra **las dos** reglas en uso: la suma de palabras de 16 bits de
  Sega con el acarreo reincorporado, y el XOR de palabras que escriben los proyectos de SGDK. Cuando la
  imagen encaja con alguna, el log dice cuál. Cuando no encaja con ninguna, el campo recibe un
  comentario previo con el valor declarado y los dos calculados, más un marcador de aviso. Un ROM
  parcheado suele conservar el checksum de la imagen de la que se recortó, así que esto es información y
  no un error.

Para una imagen de Master System o Game Gear la misma opción compara el tamaño que implica el nibble de
región con el fichero, y las dos reglas de checksum que usan esos cartuchos; las dos están explicadas en
[Cabecera y puntos de entrada](#cabecera-y-puntos-de-entrada).

Para un disco Sega CD comprueba la firma del primer sector y la zona de programa que la cabecera declara
para la unidad, e informa del par del que no lee; eso está explicado en
[Lo que el cargador nombra en cualquiera de las dos vistas](#lo-que-el-cargador-nombra-en-cualquiera-de-las-dos-vistas).
Un disco no lleva ningún checksum que verificar.

```bash
analyzeHeadless /tmp/proj nombre -process game.bin -noanalysis \
    -scriptPath ghidra_scripts -postScript SegaFixChecksum.java
```

`SegaFixChecksum` imprime el valor declarado y los dos candidatos, espera la elección y la escribe en
`0x18E`. Lee la cabecera de 16 bits, así que una imagen de Master System o Game Gear la deja como está.

## Analizador: variables con offset negativo

`Negative Offset Variables` (analizador de funciones, del módulo original) toma referencias de la forma
`-$XXXX(Ax)` y las fija a una dirección absoluta, que es como el código 68000 de este hardware alcanza
la RAM de trabajo. Dos opciones: el registro base al que aplicar, y la dirección base (`0xFF8000` por
defecto).

## Desensamblado en vivo con BlastEm

El plugin `BlastEm Live` dirige el emulador y convierte en código del programa abierto lo que este
ejecuta, mientras se juega. Se apoya en el `-l` del propio BlastEm: el emulador escribe su traza en la
carpeta desde la que arrancó, con una dirección hexadecimal por cada bloque del 68000 que traduce —
`address.log` para el procesador del cartucho, `address_sub.log` para el propio de la unidad en un disco—.
El plugin lee ese fichero mientras crece y desensambla cada lote.

BlastEm instrumenta sus núcleos de 68000 y nada más. El Z80 del Master System, Game Gear, SG-1000 y
SC-3000 no registra direcciones, y tampoco lo hacen el reproductor multimedia de Sega (que no tiene CPU)
ni el procesador NEC del LaserActive, así que la traza en vivo cubre `gen`, `32x`, `32xcd`, `pico`,
`copera` y un disco de Sega CD detectado.

Cada lote se aplica en una sola transacción fuera del hilo de la interfaz, y la ventana cuenta lo que ha
pasado: direcciones alcanzadas, instrucciones nuevas, funciones creadas, direcciones que ya eran código,
direcciones fuera del mapa de memoria y direcciones en bloques que todavía no tienen bytes.

## La ventana BlastEm Live

`Window -> BlastEm Live`, en la herramienta que tenga el programa. Si la herramienta no lo lleva,
activa antes el plugin en `File -> Configure`.

| Campo | Qué significa |
| --- | --- |
| `ROM` | la imagen que ejecuta el emulador; viene rellena con el fichero del que se importó este programa —en un disco, con su hoja `.cue` en vez de con la pista desde la que se construyó el programa, salvo que esa hoja reparta el disco entre varios ficheros, caso en el que la ventana no la arranca—, y la sesión se niega a arrancar con ninguna distinta |
| `BlastEm` | el binario del emulador; viene relleno con el primer `blastem` que encuentre en el PATH |
| `Machine` | la consola a emular, pasada como `-m`; arranca en *Detect from the image* y la lista, con lo que da cada una, está más abajo |
| `Disassemble` | cómo se convierte en código un lote de direcciones; ver abajo |
| `Trace folder` | el directorio donde BlastEm se ejecuta, y por tanto el que contiene la traza que la ventana lee |
| `Extra args` | todo lo demás para el emulador, partido como lo partiría una shell |
| `RAM too` | toma también las direcciones que caen en la RAM de trabajo o la de respaldo; útil para parches y rutinas que el juego carga en RAM, ruidoso en cualquier otro caso |
| `follow the PC` | mueve el cursor del listado a la última dirección a la que llegó el emulador |
| `pause` | deja el emulador corriendo y sigue contando, sin tocar el programa |
| `Start` / `Stop` | empiezan o terminan la sesión; Stop entrega a los analizadores todo lo que la sesión creó fuera de su cola |
| `Ingest log…` | elige una traza dejada por una ejecución anterior y la desensambla entera |

El emulador se arranca como `blastem [-m machine] -l [extra args] <rom>` en la carpeta de la traza; el
`-m` se omite en la primera fila de la lista de abajo. El comando exacto se escribe en el registro de la
ventana, y también el código de salida cada vez que el proceso muere antes de pulsar Stop. Stop lo
termina, y lo mismo hacen cerrar el programa, cambiarse a otro programa o salir de la herramienta, así que
no queda ningún proceso huérfano.

| Máquina (diálogo) | `-m` | Traza |
| --- | --- | --- |
| Detect from the image | *(se omite el interruptor)* | sí, siempre que la imagen use un 68000 |
| Mega Drive / Genesis (68000) | `gen` | sí |
| 32X (68000 + dos SH-2) | `32x` | sí, solo el 68000 |
| 32X sobre un disco de Sega CD | `32xcd` | sí, solo el 68000 |
| Pico (68000) | `pico` | sí |
| Copera (68000) | `copera` | sí |
| Master System (Z80) | `sms` | no |
| Game Gear (Z80) | `gg` | no |
| SG-1000 (Z80) | `sg` | no |
| SC-3000 (Z80) | `sc` | no |
| Reproductor multimedia (VGM / WAV / FLAC, sin CPU que trazar) | `media` | no |
| LaserActive (NEC UPD78K237, sin traza) | `laser` | no |

Un disco de Sega CD no tiene identificador propio: BlastEm lo reconoce por la cabecera
`SEGADISCSYSTEM`, así que la primera fila es la única forma de llegar a él. Sobre un disco, el 68000
principal escribe `address.log` y la sub CPU escribe `address_sub.log`, y la ventana lee la que
corresponda a la vista que se está rellenando —el programa de la unidad se traza en la segunda, el de la
consola en la primera—. Un programa hecho de un miembro del volumen también es de la consola, y se traza
por tanto en `address.log`, el mismo del que se rellena el programa que arrancó con el disco. El emulador
necesita la hoja, no el volcado de la pista con el que se construyó el programa, y el campo `ROM` ya
contiene la hoja cuando el programa vino de una. El soporte de Sega CD en esta ventana es
experimental, y una hoja que reparte el disco entre varios ficheros —como lo hace un volcado preparado
para grabar— no se ejecuta: `Start` queda apagado y el registro dice por qué. Lleva el disco a una sola
imagen de su pista de datos, un `.iso` hecho desde la hoja, y apunta el campo a esa: BlastEm lee una
imagen así por su cabecera `SEGADISCSYSTEM`, y el cargador también. Una traza del disco repartido, hecha
en una ejecución ajena, entra igualmente por `Ingest log…`. La detección también
distingue Master System de Game Gear por la extensión del fichero, así que deja una imagen de Game Gear
llamada `.gg`.

La elección de máquina solo alimenta `-m`: quien decide el lenguaje y el mapa de memoria del programa que
se está rellenando es el cargador, así que lo que se ejecuta tiene que ser la misma consola con la que se
importó el programa, y un formato al que todavía no llega ningún cargador —un cartucho de SG-1000, por
ejemplo— no tiene dónde caiga la traza.

**Disassemble** se lee una sola vez, al pulsar Start:

- **auto analysis** (por defecto): cada lote entra en la cola del analizador y el listado se rellena en
  cuanto la herramienta queda libre. El resultado más completo —funciones, referencias, tipos de
  variables y cadenas de llamadas llegan solas— y el más lento de ver mientras se juega.
- **immediate (experimental)**: el lote se desensambla dentro de su propia transacción, así que las
  instrucciones aparecen al instante, y los analizadores reciben todas las direcciones nuevas en una
  sola pasada al pulsar Stop.
- **disassemble only (experimental)**: igual de rápido, y no se pide nada a los analizadores; lanza
  `Analyze` tú cuando termine la sesión.

La cola del primer modo solo se vacía donde hay una herramienta escuchando, así que una ejecución sin
interfaz toma siempre el camino inmediato y deja el resto para una pasada de análisis posterior.

Las direcciones que caen en la RAM de trabajo o en la de respaldo se ignoran salvo que **RAM too** esté
activada, e incluso entonces solo se convierten en código una vez que la RAM del emulador se ha cargado
en el programa: Ghidra no puede desensamblar un bloque que no tiene bytes.

Inicia la sesión cuando haya terminado el autoanálisis. El analizador y la traza quieren el programa
bloqueado para escritura, y ejecutarlos a la vez es más lento que hacerlo por separado.

El mismo trabajo se puede hacer sin conexión, sobre el log de cualquier ejecución anterior, sin abrir la
ventana del plugin:

```bash
analyzeHeadless /tmp/proj nombre -process game.bin -noanalysis \
    -scriptPath ghidra_scripts -postScript SegaIngestAddressLog.java address.log
```

## Requisitos y objetivos admitidos

- Ghidra **12.1.4**, la versión cuya API de cargadores implementa este módulo. Objetivos: cualquier
  imagen cuya cabecera diga `SEGA`, lo que cubre cartuchos de Mega Drive / Genesis, cartuchos de 32X en
  cualquiera de las dos arquitecturas, e imágenes lo bastante largas para llevar una zona de programa de
  Sega CD; cualquier imagen que lleve la cabecera de cartucho `TMR SEGA` de un juego de Master System o
  Game Gear; y un disco Sega CD, como una pista de sectores de 2048 o 2352 bytes, o como la hoja `.cue`
  que describe una. La BIOS de la unidad y la partida guardada de un disco son ficheros aparte, dados por
  las opciones de [Opciones de importación](#opciones-de-importación).
- Un JDK, para compilar. Ghidra 12.1.4 apunta a Java 21, y el módulo se compila para esa versión.
- BlastEm, solo para el desensamblado en vivo. La ventana lo arranca como proceso hijo, así que necesita
  una pantalla que el emulador pueda abrir.

## Compilación

La compilación necesita saber dónde está Ghidra, y lo toma del entorno o de un `gradle.properties` sin
seguimiento junto a `build.gradle`:

```properties
GHIDRA_INSTALL_DIR=/ruta/a/Ghidra
```

```bash
GHIDRA_INSTALL_DIR=/ruta/a/Ghidra ./gradlew buildExtension   # -> dist/ghidra_<versión>_<fecha>_Sega.zip
```

La compilación resuelve todas las dependencias contra esa instalación y no necesita acceso a la red;
añade `--offline` si quieres que Gradle ni siquiera compruebe.

Para iterar sobre el código sin el ida y vuelta del zip:

```bash
./scripts/dev-install.sh              # compila e instala una copia suelta; reinicia Ghidra para cargarla
./scripts/dev-install.sh --uninstall  # quita esa copia
```

La copia suelta va a `~/.config/ghidra/ghidra_<versión>_PUBLIC/Extensions/Sega` y declara la versión de
la instalación de Ghidra contra la que se compiló, así que aparece en la lista de extensiones exactamente
igual que una instalada.

Los ficheros de proyecto de Eclipse del módulo original se fueron: la forma de compilar es el build de
Gradle, y GhidraDev se puede seguir usando enlazando este directorio como proyecto Gradle.

## Instalación

1. Compila el zip del módulo como arriba.
2. `File -> Install Extensions`, pulsa `+`, elige el zip.
3. Acepta el reinicio que Ghidra pide.

Para usar la ventana en vivo, abre `File -> Configure` en la herramienta que tenga tu programa y activa
`BlastEm Live` entre los plugins de depuración si no lo lleva ya.

## Scripts

| Script | Qué hace |
| --- | --- |
| `ghidra_scripts/SegaFixChecksum.java` | muestra el checksum que declara la cabecera y los dos calculados, y escribe el que elijas; quiere la cabecera de 16 bits y rechaza una imagen sin `SEGA` en `0x100` |
| `ghidra_scripts/SegaIngestAddressLog.java` | desensambla todas las direcciones de un `address.log` de BlastEm en el programa abierto |

## Estructura del repositorio

```
src/main/java/sega/      cargadores, cabeceras, estructuras, checksum, analizador
src/main/java/sega/live/ la traza en vivo: proceso del emulador, lector del log, comandos de ingesta, plugin y ventana
ghidra_scripts/          scripts que se distribuyen con el módulo
data/                    reservado a datos de ejecución (especificaciones Sleigh, archivos de tipos de dato)
src/main/help/           tema de ayuda de Ghidra
scripts/                 instalación de desarrollo
build.gradle             compilación del módulo
```

## Límites conocidos

- Las imágenes de SG-1000 y SC-3000 todavía no se reconocen: sus cartuchos no llevan cabecera, así que un
  cargador para ellos habría que elegirlo a mano y darle el tamaño de la imagen.
- De un disco Sega CD el cargador lee el sector de cabecera y los dos programas que la cabecera coloca, que
  es hasta donde llega la propia etapa de arranque antes de que haya un juego en memoria, y la lista de los
  ficheros que el volumen del disco lleva. Todo lo demás —los datos de un juego, y el resto de lo que su
  primer programa pide a la unidad mientras corre— se queda en el disco hasta que un miembro se importa por
  su nombre o la traza en vivo lo alcanza. Un disco que además lleve un programa de Sega 32X recibe el mapa
  de la consola sin la parte del 32X, porque el 32X de un disco así no está en lo que la cabecera señala.
- El volumen de un disco se busca en los sectores de 2048 bytes que una pista mode 1 da: un disco cuyos
  datos están encuadrados de otra manera no tiene descriptor que encontrar, y entonces la importación dice
  que sus ficheros no se pueden listar y sigue exactamente como lo hacía antes. Un volumen que lleve un
  descriptor suplementario y ninguno primario se informa y no se recorre. Los ficheros repartidos en más de
  un extent se listan y se dice de ellos, no se cosen, y los nombres escritos con las escapadas de otro
  estándar —Joliet— se listan tal como se leen.
- Un miembro de un volumen se lee hasta 1 MiB, y el sitio donde su dirección lo pone es asunto de quien
  importa: el disco no dice nada de eso, y todas las líneas del registro sobre un miembro lo repiten.
- De una hoja `.cue` el cargador lee la única pista que lleva programa: el volcado que contenga
  `SEGADISCSYSTEM`, esté en su propio fichero o en uno que comparta con el resto del disco, buscado junto a
  la hoja. Una pista de audio no lleva nada que ejecute un procesador, un volcado de un modo distinto de
  `MODE1` no tiene zona de programa, y un fichero `MOTOROLA` es hexadecimal impreso en vez de bytes
  almacenados, así que no se puede leer sector a sector. El encuadre de modo 2 y de CD-XA no se reconoce.
- La traza en vivo de un disco es la de un procesador cada vez: la ventana sigue la traza que escribe el
  núcleo del que el programa abierto es la vista, así que las dos partes de un disco significan una sesión
  para cada una.
- El soporte de Sega CD en la ventana en vivo es experimental, y no ejecuta un disco cuyo `.cue` lo
  reparta entre varios ficheros: la ventana deja esa hoja en paz. Convierte el disco a un solo `.iso` de su
  pista de datos, importa el `.iso` y arranca la sesión desde él, o toma por `Ingest log…` una traza del
  disco repartido hecha en una ejecución ajena.
- En Master System y Game Gear la traza en vivo es imposible, no está sin terminar: BlastEm no registra
  direcciones de su Z80. Sobre esas imágenes usa `SegaIngestAddressLog` y los analizadores, y juega con el
  emulador como siempre.
- En esas dos máquinas solo son visibles a la vez las tres primeras páginas de 16 KiB del cartucho, porque
  el espacio del Z80 es de 64 KiB y el resto llega como superposiciones de la ventana en `0x8000`. El
  código de una página que no has seleccionado no es alcanzable para los analizadores.
- El desensamblado en vivo cubre solo el 68000, y lo cubre bloque traducido a bloque: lo que BlastEm
  informa es la primera dirección de cada bloque, así que una instrucción con la que el emulador nunca
  empezó a traducir no se pide.
- El código que corre desde la RAM de trabajo se cuenta pero no se desensambla hasta que la RAM del
  emulador esté en el programa, porque Ghidra necesita bytes para desensamblar.
- La traza dice dónde empieza el código, no qué hace: las funciones, las referencias y los tipos siguen
  saliendo de los analizadores, y por eso *auto analysis* da el listado más completo.
- Un checksum que no cuadra nunca falla la importación. Un ROM parcheado o recortado conserva el valor de
  la imagen de la que salió, y el cargador informa los dos candidatos en lugar de adivinar.

## Créditos

- **Dr. MefistO** ([lab313ru](https://github.com/lab313ru)) — autor del cargador y del analizador
  originales, sobre los que está hecho todo esto.
  *Gracias por todo tu grandioso trabajo.* Gracias por todo el trabajo magnífico que has hecho: este
  módulo existe porque el tuyo existía, y poder apoyarse en él es un privilegio.
- **qufb** — el soporte de Sega 32X heredado del proyecto original.
- **BlastEm** — el emulador cuya traza `-l` hace posible el desensamblado en vivo, y cuyo código resolvió
  varias preguntas sobre las ventanas de hardware que este cargador mapea.

## Lo que cambia este fork

- Adaptado a la API de cargadores de Ghidra 12.x (12.1.4), incluida la compilación con Gradle del módulo
  y un script de instalación de desarrollo.
- Las elecciones del diálogo de importación pasaron a ser opciones reales del cargador, así que las
  importaciones funcionan sin interfaz.
- Bloques de RAM de respaldo y de trabajo derivados de la cabecera, con la opción de cargar una partida
  guardada real.
- El tamaño del bloque `ROM` sale de la cabecera en lugar de solo de la longitud del fichero.
- Verificación de la cabecera y del checksum, con las dos reglas en uso, y `SegaFixChecksum`.
- Las funciones de la tabla de vectores solo se crean donde el vector alcanza código ejecutable.
- Un cargador de Master System y Game Gear: la cabecera `TMR SEGA`, las ventanas paginadas del cartucho,
  los registros del mapper, los puertos de la consola y las reglas de checksum que usan esos cartuchos.
- Los cargadores de los dos procesadores de un disco Sega CD: el disco y su hoja leídos por los programas
  que declara la cabecera, el espacio de direcciones de cada procesador como lo enseña el ASIC, los
  nombres del `GATE_ARRAY`, de la memoria de sonido y de la RAM con pila, y las entradas de la etapa de
  arranque etiquetadas.
- El volumen de ficheros que un disco lleva también se lee: se encuentran sus descriptores, se recorren sus
  directorios y sus ficheros se escriben en el registro de toda importación de un Sega CD, así que lo que
  hay dentro del disco se sabe sin montarlo. Un cargador importa uno de esos ficheros como programa propio,
  con el mapa de la consola alrededor y las ventanas de memoria cortadas en torno a él.
- El plugin `BlastEm Live`, el lector del log y los comandos de ingesta por lote que hay detrás, y
  `SegaIngestAddressLog` para trabajar sin el emulador delante.
