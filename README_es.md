# Cargadores de Sega para Ghidra

Cargadores y módulo de análisis para Ghidra dirigido a imágenes de cartucho de Sega: Mega Drive /
Genesis y Sega 32X, con hueco para la ventana de programa del Sega CD cuando la imagen la trae, y
Master System y Game Gear. Cada uno reconstruye el espacio de direcciones de la consola a partir de la
cabecera del ROM, pone nombre a los registros del hardware, aplica las estructuras de cabecera y de
tabla de vectores, y puede desensamblar el programa mientras el código se ejecuta de verdad en el
emulador BlastEm.

Parte del cargador original de **Dr. MefistO** ([lab313ru/ghidra_sega_ldr](https://github.com/lab313ru/ghidra_sega_ldr));
ver [Créditos](#créditos) para la autoría y para lo que cambia este fork.

**English:** [README.md](README.md).

---

## Índice

- [Qué construye el cargador](#qué-construye-el-cargador)
- [Master System y Game Gear](#master-system-y-game-gear)
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

El módulo instala un cargador por familia: el formato de ejecutable que queda grabado en un programa es
el nombre del cargador, y cada consola necesita su propio lenguaje y su propio espacio de direcciones.

| Cargador | Reconocer el objetivo | Lenguaje |
| --- | --- | --- |
| `SegaLoader` — *Sega Mega Drive / Genesis Loader* | `SEGA` en `0x100` | `68000:BE:32:MC68020` |
| | un cartucho de 32X lleva además `MARS CHECK MODE` en `0x3C0`, y se ofrece una segunda vez | `SuperH:BE:32:SH-2` |
| `SegaSmsLoader` — *Sega Master System / Game Gear Loader* | `TMR SEGA` en `0x7FF0`, si no en `0x3FF0`, si no en `0x1FF0` | `z80:LE:16:default` |

Todo lo que hay bajo este epígrafe se crea durante la importación, antes de que corra ningún análisis, y
cubre las máquinas de 68000. Las de 8 bits tienen su propio epígrafe:
[Master System y Game Gear](#master-system-y-game-gear).

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
| `FDC` | `0xA12000` | `IO_FDC` (0x100 bytes) |
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

## Opciones de importación

Cada elección es una opción real del cargador. Aparece en el diálogo de importación con el valor que se
indica aquí y se puede fijar desde una línea de comandos, así que una importación no necesita ninguna
interacción.

| Cargador | Opción | Etiqueta en el diálogo | Por defecto | Efecto |
| --- | --- | --- | --- | --- |
| Genesis | `-loader-32x` | Create Sega 32X segments | activada en un cartucho de 32X o una carga SH-2, desactivada en lo demás | los bloques y registros del 32X de arriba |
| Genesis | `-loader-sega-cd` | Create Sega CD (EPA) segment | desactivada | la ventana `EPA` de `0x400000` |
| los dos | `-loader-hw-registers` | Create hardware register blocks | activada | `Z80`, `SYS*`, `FDC`, `TIME`, `TMSS`, `VDP`, `RAM` y su espejo, o los bloques `VDP`, `PSG`, `CONTROLLER`, `IO_CONTROL` y `MAPPER` de las máquinas de 8 bits |
| los dos | `-loader-verify` | Verify the ROM header | activada | las comprobaciones de [Verificación de la cabecera](#verificación-de-la-cabecera) |
| Genesis | `-loader-sram-file <ruta>` | Backup RAM contents file (.srm / .sram) | vacía | rellena `BACKUP_RAM` con un fichero de partida guardada |
| SMS / GG | `-loader-cart-ram-file <ruta>` | Cartridge RAM contents file (.sav / .sms) | vacía | rellena la superposición `CART_RAM` de `0x8000` con un fichero de partida guardada |

```bash
analyzeHeadless /tmp/proj nombre -import game.bin -loader SegaLoader \
    -loader-32x true -loader-hw-registers true -loader-verify true \
    -loader-sram-file guardado.srm

analyzeHeadless /tmp/proj nombre -import game.sms -loader SegaSmsLoader \
    -loader-hw-registers true -loader-verify true
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
ejecuta, mientras se juega. Se apoya en el `-l` del propio BlastEm: el emulador escribe `address.log` en
la carpeta desde la que arrancó, con una dirección hexadecimal por cada bloque del 68000 que traduce. El
plugin lee ese fichero mientras crece y desensambla cada lote.

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
| `ROM` | la imagen que ejecuta el emulador; viene rellena con el fichero del que se importó este programa, y la sesión se niega a arrancar con ninguno distinto |
| `BlastEm` | el binario del emulador; viene relleno con el primer `blastem` que encuentre en el PATH |
| `Machine` | la consola a emular, pasada como `-m`; arranca en *Detect from the image* y la lista, con lo que da cada una, está más abajo |
| `Disassemble` | cómo se convierte en código un lote de direcciones; ver abajo |
| `Trace folder` | el directorio donde BlastEm se ejecuta, y por tanto el que contiene `address.log` |
| `Extra args` | todo lo demás para el emulador, partido como lo partiría una shell |
| `RAM too` | toma también las direcciones que caen en la RAM de trabajo o la de respaldo; útil para parches y rutinas que el juego carga en RAM, ruidoso en cualquier otro caso |
| `follow the PC` | mueve el cursor del listado a la última dirección a la que llegó el emulador |
| `pause` | deja el emulador corriendo y sigue contando, sin tocar el programa |
| `Start` / `Stop` | empiezan o terminan la sesión; Stop entrega a los analizadores todo lo que la sesión creó fuera de su cola |
| `Ingest log…` | elige un `address.log` dejado por una ejecución anterior y lo desensambla entero |

El emulador se arranca como `blastem [-m machine] -l [extra args] <rom>` en la carpeta de la traza; el
`-m` se omite en la primera fila de la lista de abajo. Stop lo termina, y lo mismo hacen cerrar el
programa, cambiarse a otro programa o salir de la herramienta, así que no queda ningún proceso huérfano.

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
principal escribe `address.log` y la sub CPU escribe `address_sub.log`, y la ventana lee el primero. La
detección también distingue Master System de Game Gear por la extensión del fichero, así que deja una
imagen de Game Gear llamada `.gg`.

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
  Sega CD; y cualquier imagen que lleve la cabecera de cartucho `TMR SEGA` de un juego de Master System o
  Game Gear.
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
  cargador para ellos habría que elegirlo a mano y darle el tamaño de la imagen. El soporte de Sega CD se
  limita a la ventana `EPA` de una imagen de cartucho larga: las zonas de programa del CD que describe una
  pista `.cue` o `.bin` no se interpretan.
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
- El plugin `BlastEm Live`, el lector del log y los comandos de ingesta por lote que hay detrás, y
  `SegaIngestAddressLog` para trabajar sin el emulador delante.
