; =============================================================================
; CodeGuard - paquete instalador (Inno Setup 6)
; Un solo CodeGuard-Setup.exe: asistente grafico, desinstalador registrado en
; "Aplicaciones instaladas" y modo silencioso (/VERYSILENT) para reparto
; masivo. Instala PER-USUARIO, jamas pide admin (hardening 13).
;
; Compilar:  dist\build-dist.ps1 lo hace solo si encuentra ISCC.exe
; Firmar  :  cuando llegue el certificado (Q5), firmar ESTE .exe y publicarlo
;            en winget. SignTool se engancha aqui con [Setup] SignTool=...
; =============================================================================

#define MyAppName "CodeGuard"
#define MyAppVersion "1.0.0-rc3"
; reglas.iss lo genera build-dist.ps1 contando el rulepack: el numero que se le
; promete al usuario no se escribe a mano (llego a decir 112 con 119 instaladas)
#include "reglas.iss"
; motores.iss lo genera build-dist.ps1 desde el inventario REAL del producto:
; cuantos motores hay, cuantos provisiona este paquete y cuales NO. El texto
; de bienvenida llego a prometer 16 con 22 en el producto y a callar cinco.
#include "motores.iss"
; rulepacks-limpieza.iss tambien lo genera build-dist.ps1: una entrada
; [InstallDelete] por cada version que viaja en el paquete. Sin esto, Inno
; copia archivo-por-archivo sobre una version ya instalada y FUSIONA dos
; contenidos bajo el mismo nombre (la divergencia 130-vs-161 reglas medida el
; 2026-08-23). Las versiones que el paquete no trae se conservan: son el
; last-known-good implicito. Un corte a media copia deja un arbol parcial que
; la verificacion del manifiesto firmado RECHAZA con nombre al primer uso.
#include "rulepacks-limpieza.iss"
#define MyAppExe "codeguard.exe"
#define MyDaemonExe "codeguard-daemon.exe"
; MyDirPorDefecto es UNA sola fuente de verdad para dónde se instala.
; La usan DefaultDirName y el código: {app} NO existe todavía en
; InitializeSetup —Inno la inicializa después— y expandirla allí es un error
; fatal que impide arrancar el instalador entero.
#define MyDirPorDefecto "{localappdata}\CodeGuard"

[Setup]
AppId={{8F4E2C7A-1B3D-4A69-9E5C-2D7F0B1C4A88}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher=CodeGuard
DefaultDirName={#MyDirPorDefecto}
DisableDirPage=yes
DisableProgramGroupPage=yes
; consentimiento: pagina "Que es CodeGuard" con aceptacion obligatoria antes
; de que nada toque el equipo
LicenseFile=acuerdo.txt
DisableReadyPage=no
; per-usuario, cero elevacion: todo bajo %LOCALAPPDATA%
PrivilegesRequired=lowest
ArchitecturesInstallIn64BitMode=x64compatible
OutputDir=.
OutputBaseFilename=CodeGuard-Setup
SetupIconFile=codeguard.ico
UninstallDisplayIcon={app}\bin\{#MyAppExe}
UninstallDisplayName={#MyAppName}
WizardStyle=modern
; estetica DUNA: banner y emblema generados por build-wizard-art.ps1
WizardImageFile=wizard-banner.bmp
WizardSmallImageFile=wizard-small.bmp
WizardImageStretch=yes
WizardSizePercent=110
; [Code] modifica el PATH del usuario. Inno notifica a Explorer al terminar
; para que las terminales nuevas hereden el valor sin cerrar sesion.
ChangesEnvironment=yes
; Debe aparecer en Aplicaciones instaladas. Desactivar esta clave dejaba un
; unins000.exe huérfano que sólo podía encontrar quien conociera la ruta.
CreateUninstallRegKey=yes
Compression=lzma2
SolidCompression=yes

[Languages]
Name: "spanish"; MessagesFile: "compiler:Languages\Spanish.isl"

[Messages]
; copy minimo: el asistente habla claro y corto
spanish.WelcomeLabel1=CodeGuard
spanish.WelcomeLabel2=El agente local de análisis pre-commit.%nRevisa lo que estás a punto de commitear y bloquea sólo lo que el CI también rechazaría.%n%nSe instalará para tu usuario, bajo %%LOCALAPPDATA%%\CodeGuard, sin permisos de administrador.%n%nCodeGuard trae {#MyMotorTotal} motores y {#MyRuleCount} reglas. De esos motores:%n%n  •  {#MyMotorInstala} los instala este asistente. gitleaks, trivy y los de Java se%n     verifican contra la identidad de sus releases oficiales; semgrep, squawk,%n     ruff, mypy y bandit llegan en un wheelhouse de PyPI oficial cerrado por%n     SHA-256 y se instalan sin red; los motores Go se COMPILAN desde módulos y%n     sumas fijados usando proxy.golang.org y sum.golang.org. Eso último tarda%n     un par de minutos.%n%n  •  {#MyMotorTuyos} usan herramientas que YA tienes: Go, el SDK de .NET, Java, y el%n     node_modules de tu propio proyecto para tsc y eslint, y el módulo%n     PSScriptAnalyzer de PowerShell si quieres la capa de .ps1. Para tsc y%n     eslint es%n     deliberado: se usa la versión de tu repo, que es la que corre en tu CI —%n     imponer la nuestra rompería la paridad en vez de defenderla.%n%n  •  {#MyMotorFaltanFrase}%n%nNada de esto sale a la red durante un análisis salvo los dos motores que lo%ndeclaran (govulncheck y dotnet-vuln). Ninguna telemetría se envía a nadie.
spanish.FinishedHeadingLabel=Listo.
spanish.FinishedLabelNoIcons=CodeGuard quedó instalado. Siguiente paso, en cada repositorio:%n%ncodeguard init
spanish.FinishedLabel=CodeGuard quedó instalado. Siguiente paso, en cada repositorio:%n%ncodeguard init
spanish.ClickFinish=
; la pagina de licencia se reetiqueta como lo que es: informacion y permiso
spanish.WizardLicense=Qué es CodeGuard
spanish.LicenseLabel=
spanish.LicenseLabel3=Lee qué es CodeGuard, qué instala y qué cambia en tu equipo. Para continuar necesitas aceptarlo expresamente.
spanish.LicenseAccepted=&Acepto que CodeGuard se instale en mi equipo
spanish.LicenseNotAccepted=&No lo acepto todavía

[Files]
Source: "{#MyAppExe}"; DestDir: "{app}\bin"; Flags: ignoreversion
Source: "{#MyDaemonExe}"; DestDir: "{app}\bin"; Flags: ignoreversion
Source: "org-llm.yaml"; DestDir: "{app}\bin"; Flags: ignoreversion
; el binario busca rulepacks junto a si mismo, y tambien en la raiz
Source: "rulepacks\*"; DestDir: "{app}\bin\rulepacks"; Flags: ignoreversion recursesubdirs
Source: "rulepacks\*"; DestDir: "{app}\rulepacks"; Flags: ignoreversion recursesubdirs
; motores.json es la fuente de verdad de hashes; engines.ps1 la lee
Source: "engines.ps1"; DestDir: "{app}"; Flags: ignoreversion
Source: "motores.json"; DestDir: "{app}"; Flags: ignoreversion
; Cierre Python completo: lock con hashes + wheels de PyPI oficial. El script
; instala con --no-index, asi que la maquina destino no resuelve ni descarga.
Source: "python\*"; DestDir: "{app}\python"; Flags: ignoreversion recursesubdirs
; el modulo de herramientas: staticcheck/govulncheck se compilan desde aqui,
; con las dependencias fijadas por nuestro go.sum (no por los pisos upstream)
Source: "tools\*"; DestDir: "{app}\tools"; Flags: ignoreversion recursesubdirs
; runner oculto: el setup lo lanza sin ventana y muestra su log en vivo
Source: "instalar-motores.ps1"; DestDir: "{app}"; Flags: ignoreversion
; fotogramas del splash animado (se extraen a {tmp} solo durante el setup)
Source: "splash\*.bmp"; Flags: dontcopy
; fondo full-bleed de la pagina de bienvenida
Source: "welcome-bg.bmp"; Flags: dontcopy

[Registry]
; EL RESIDUO QUE DUPLICABA EL AGENTE, Y CON EL, EL ORBE.
;
; Las versiones que se instalaban con install.ps1 dejaban el autoarranque en
; HKCU\...\Run. Este paquete pasó a usar el acceso directo de Inicio, pero
; NUNCA borró el valor viejo — install.ps1 sí lo hace; el .exe, que es el que
; se publica, no. Resultado en la máquina de Héctor, medido el 2026-08-26:
; Explorer lanzaba los DOS al iniciar sesión y quedaban dos daemons vivos, con
; dos orbes visibles en el mismo rectángulo exacto. El de encima era el que no
; consiguió el pipe: un indicador de seguridad pintado y sordo.
;
; Se borra aquí, en HKCU, sin necesidad de admin (hardening 13). Una
; actualización migra sola; una instalación limpia no encuentra nada y no
; falla. La otra mitad del arreglo vive en el daemon, que ahora se retira si ya
; hay otro (cmd/daemon/instancia_windows.go): hacen falta las dos, porque esta
; sola no protege de un segundo arranque a mano.
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; \
    ValueType: none; ValueName: "CodeGuard"; Flags: deletevalue

[Icons]
; Sin Parameters: el daemon NO lee argumentos (cmd/daemon/main.go no parsea
; ninguno), así que el «--tray» que llevaba aquí era decorativo y sugería una
; opción que no existe.
Name: "{userstartup}\CodeGuard"; Filename: "{app}\bin\{#MyDaemonExe}"; \
    WorkingDir: "{app}\bin"; IconFilename: "{app}\bin\{#MyDaemonExe}"
Name: "{userprograms}\CodeGuard\Desinstalar CodeGuard"; Filename: "{uninstallexe}"

; [Run] ya no existe, y es deliberado.
;
; Tenía dos entradas: una con «postinstall skipifsilent», o sea una CASILLA que
; el usuario podía desmarcar y que sólo se disparaba al pulsar Finalizar, y
; otra para el reparto silencioso. Entre las dos dejaban tres huecos:
;
;   1. En interactivo nadie comprobaba nada: ArrancarYVerificarDaemon salía por
;      la puerta de atrás con un `exit` si había ventana, confiando en que «el
;      usuario LO VE». Héctor no lo veía, y el asistente decía «Listo» igual.
;   2. Arrancar desde [Run] ocurre DESPUÉS del último paso del código, así que
;      la página final no podía decir si el agente había quedado vivo.
;   3. `runhidden` sobre un binario compilado con -H windowsgui no esconde
;      nada: no hay consola que esconder.
;
; Ahora arranca ArrancarYVerificarDaemon, una sola vez, desde el código, y la
; página final dice lo que de verdad se comprobó.

; [UninstallRun] ya no mata al daemon: lo hace InitializeUninstall ([Code]),
; que ademas ESPERA a que el proceso muera de verdad. El taskkill suelto de
; aqui tenia dos fallos medidos: (1) un proceso fusilado no quita su icono de
; la bandeja (orbe fantasma), y (2) taskkill devuelve 0 cuando Windows ACEPTA
; la orden, no cuando solto el ejecutable — 110 ms despues el borrado de
; codeguard-daemon.exe fallaba con "in use (5)", el desinstalador no
; reintentaba, y aun asi reportaba exito dejando 23.7 MB huerfanos.

[UninstallDelete]
; Inno sólo conoce los archivos empacados. engines.ps1 crea además un venv
; versionado, launchers y motores compilados/extraídos; si no se enumeran aquí,
; “desinstalar” deja cientos de MB de ejecutables activos en la ruta antigua.
; Los datos del usuario (codeguard.db, repos.json, confianza.json y logs) se
; conservan deliberadamente para una reinstalación; payload y ejecutables no.
Type: filesandordirs; Name: "{app}\engines"
Type: filesandordirs; Name: "{app}\descargas"
Type: filesandordirs; Name: "{app}\semgrep"
Type: filesandordirs; Name: "{app}\wv_*"
Type: files; Name: "{app}\.motores.lock"
Type: files; Name: "{app}\.motores.*"

[Code]
const
  SplashFrames = 80;   // debe coincidir con build-wizard-art.ps1

function GetSystemMetrics(nIndex: Integer): Integer;
  external 'GetSystemMetrics@user32.dll stdcall';
function DwmSetWindowAttribute(hWnd: THandle; dwAttribute: Integer;
  var pvAttribute: Integer; cbAttribute: Integer): Integer;
  external 'DwmSetWindowAttribute@dwmapi.dll stdcall delayload';

// ── splash cinematografico: el orbe DUNA respira antes del asistente ─────
// 46 fotogramas pre-renderizados a ~25 fps con fundido de entrada y salida.
procedure MostrarSplash();
var
  Splash: TSetupForm;
  Img: TBitmapImage;
  i, Esquinas: Integer;
begin
  for i := 0 to SplashFrames - 1 do
    ExtractTemporaryFile(Format('splash-%.2d.bmp', [i]));

  Splash := CreateCustomForm(300, 340, False, False);
  try
    Splash.BorderStyle := bsNone;
    // esquinas redondeadas nativas (Win11): DWMWCP_ROUND sobre el atributo 33
    Esquinas := 2;
    DwmSetWindowAttribute(Splash.Handle, 33, Esquinas, 4);
    Splash.ClientWidth := 300;
    Splash.ClientHeight := 340;
    Splash.Color := $0A0806;  // casi negro pizarra: sin destello al aparecer
    Splash.Left := (GetSystemMetrics(0) - Splash.Width) div 2;
    Splash.Top := (GetSystemMetrics(1) - Splash.Height) div 2;

    Img := TBitmapImage.Create(Splash);
    Img.Parent := Splash;
    Img.SetBounds(0, 0, Splash.ClientWidth, Splash.ClientHeight);
    Img.Stretch := False;
    Img.Bitmap.LoadFromFile(ExpandConstant('{tmp}\splash-00.bmp'));

    Splash.Show;
    Splash.Refresh;
    for i := 0 to SplashFrames - 1 do
    begin
      Img.Bitmap.LoadFromFile(ExpandConstant('{tmp}\') + Format('splash-%.2d.bmp', [i]));
      Img.Refresh;
      Sleep(40);
    end;
  finally
    Splash.Free;
  end;
end;

var
  EsActualizacion: Boolean;
  // Identifica ESTA corrida. Sale del nombre del directorio temporal que Inno
  // crea para el setup (is-XXXXX.tmp), que ya es único por ejecución: no hace
  // falta inventar aleatoriedad ni leer el reloj, que además no están
  // disponibles de forma fiable en el script.
  IdCorrida: String;
  // Lo que de verdad se comprobó del agente, para que la página final no
  // afirme de más. Ver ArrancarYVerificarDaemon.
  DaemonVerificado: Boolean;

function InitializeSetup(): Boolean;
begin
  // ya instalado antes = actualizacion: se actualiza encima, sin borrar nada;
  // los motores con hash verificado se conservan y no se vuelven a descargar
  // OJO: aqui NO se puede usar {app} — InitializeSetup corre ANTES de que
  // Inno la inicialice, y expandirla revienta el instalador entero con «An
  // attempt was made to expand the "app" constant before it was
  // initialized», sin llegar a pintar una sola pantalla. Se mira el
  // directorio por defecto, que es donde se instala siempre (DisableDirPage).
  EsActualizacion := FileExists(ExpandConstant('{#MyDirPorDefecto}\bin\{#MyDaemonExe}'));

  // El identificador de esta corrida sale del directorio temporal que Inno
  // crea para el setup (is-XXXXX.tmp): ya es único por ejecución, así que no
  // hace falta inventarse aleatoriedad. Se expande aquí, antes que nada, para
  // que valga igual en interactivo y en /VERYSILENT — expandir {tmp} lo crea
  // si todavía no existe.
  IdCorrida := ExtractFileName(RemoveBackslashUnlessRoot(ExpandConstant('{tmp}')));
  StringChangeEx(IdCorrida, '.', '', True);
  if IdCorrida = '' then
    IdCorrida := 'corrida';

  if not WizardSilent() then
    MostrarSplash();
  Result := True;
end;

// ── bienvenida full-bleed ────────────────────────────────────────────────
// El texto por defecto del wizard se oculta; la imagen se estira a toda la
// pagina como fondo y el texto va en etiquetas nativas: nitidas en cualquier
// DPI (el texto horneado en un BMP estirado se ve borroso).
const
  ColTinta   = $2C2722;  // #22272c en BGR
  ColBruma   = $70655A;  // #5a6570
  ColGrafito = $48413A;  // #3a4148

function LineaBienvenida(const Texto, Fuente: String; Tam, ColorTx, Y: Integer): TNewStaticText;
begin
  Result := TNewStaticText.Create(WizardForm);
  Result.Parent := WizardForm.WelcomePage;
  Result.AutoSize := True;
  Result.Caption := Texto;
  Result.Font.Name := Fuente;
  Result.Font.Size := Tam;
  Result.Font.Color := ColorTx;
  Result.Color := clWhite;   // el fondo bajo el texto es blanco plano
  Result.Top := Y;
  Result.Left := (WizardForm.WelcomePage.Width - Result.Width) div 2;
end;

procedure InitializeWizard();
var
  Y, Salto: Integer;
  L: TNewStaticText;
begin
  ExtractTemporaryFile('welcome-bg.bmp');
  WizardForm.WizardBitmapImage.Bitmap.LoadFromFile(ExpandConstant('{tmp}\welcome-bg.bmp'));
  WizardForm.WizardBitmapImage.Stretch := True;
  WizardForm.WizardBitmapImage.Width := WizardForm.WizardBitmapImage.Parent.Width;
  WizardForm.WizardBitmapImage.Height := WizardForm.WizardBitmapImage.Parent.Height;
  WizardForm.WelcomeLabel1.Visible := False;
  WizardForm.WelcomeLabel2.Visible := False;
  // cabecera limpia: sin la estampita de la esquina, que se veia pegada
  WizardForm.WizardSmallBitmapImage.Visible := False;

  Salto := ScaleY(21);
  Y := (WizardForm.WelcomePage.Height * 42) div 100;

  L := LineaBienvenida('C O D E G U A R D', 'Segoe UI Semibold', 15, ColTinta, Y);
  Y := L.Top + L.Height + ScaleY(4);
  L := LineaBienvenida('si el commit pasa aquí, pasa allá', 'Segoe UI', 10, ColBruma, Y);
  Y := L.Top + L.Height + ScaleY(22);

  L := LineaBienvenida('Se instalará para tu usuario, sin permisos de administrador:', 'Segoe UI Semibold', 9, ColGrafito, Y);
  Y := L.Top + Salto;
  L := LineaBienvenida('CodeGuard — CLI, orbe y sus {#MyRuleCount} reglas', 'Segoe UI', 9, ColGrafito, Y);
  Y := L.Top + Salto;
  L := LineaBienvenida('gitleaks y trivy, verificados contra el checksum de sus autores', 'Segoe UI', 9, ColGrafito, Y);
  Y := L.Top + Salto;
  L := LineaBienvenida('semgrep, squawk y ruff', 'Segoe UI', 9, ColGrafito, Y);
  Y := L.Top + Salto;
  L := LineaBienvenida('govulncheck y staticcheck, que se compilan: un par de minutos', 'Segoe UI', 9, ColGrafito, Y);
  Y := L.Top + Salto + ScaleY(10);

  LineaBienvenida('Todos los motores son necesarios: sin ellos se rompe la paridad con el CI.', 'Segoe UI', 8, ColBruma, Y);
end;



// ── el daemon no puede estar corriendo mientras se reemplaza su .exe ─────
//
// DetenerDaemon lo comparten instalar y desinstalar, y hace TRES cosas que el
// taskkill suelto de antes no hacia, las tres medidas:
//
//  1. PRIMERO PIDE: `codeguard daemon-stop` apaga por el mismo camino que el
//     boton "Salir de CodeGuard" del menu, que desmonta el icono de la bandeja
//     antes de morir. Un proceso fusilado con taskkill deja el icono PINTADO
//     —el orbe fantasma— y en la bandeja de Windows 11 solo lo limpia
//     reiniciar Explorer. Con un daemon viejo (< 1.13.1) o colgado el comando
//     no surte efecto y se cae al taskkill de siempre.
//  2. LUEGO ESPERA a que el proceso MUERA DE VERDAD. taskkill devuelve 0
//     cuando Windows acepta la orden, no cuando solto el ejecutable: 110 ms
//     despues, el borrado de codeguard-daemon.exe fallaba con "in use (5)",
//     el desinstalador no reintentaba y aun asi decia "succeeded" — dejando
//     23.7 MB huerfanos para siempre. El sondeo con tasklist|find espera al
//     hecho, no a la promesa (find sale 1 cuando ya no esta).
//  3. Y UN MARGEN FINAL: entre que el proceso desaparece de la lista y Windows
//     libera el mapeo del .exe pasan unos milisegundos mas.
procedure DetenerDaemon();
var
  R, Intento: Integer;
begin
  // Por las buenas. En una instalacion desde cero el exe aun no existe y
  // Exec simplemente falla: no hay daemon que apagar.
  Exec(ExpandConstant('{app}\bin\{#MyAppExe}'), 'daemon-stop', '',
       SW_HIDE, ewWaitUntilTerminated, R);
  // Por las malas, para el daemon viejo o colgado.
  Exec(ExpandConstant('{sys}\taskkill.exe'), '/F /IM {#MyDaemonExe}', '',
       SW_HIDE, ewWaitUntilTerminated, R);
  // Y esperar al HECHO: hasta 5 s sondeando la lista de procesos.
  for Intento := 1 to 25 do
  begin
    Exec(ExpandConstant('{cmd}'),
         '/c tasklist /FI "IMAGENAME eq {#MyDaemonExe}" | find /I "{#MyDaemonExe}" >nul',
         '', SW_HIDE, ewWaitUntilTerminated, R);
    if R <> 0 then break;
    Sleep(200);
  end;
  Sleep(300);
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
begin
  DetenerDaemon();
  Result := '';
end;

// ── PATH de usuario: alta idempotente y desinstalación simétrica ─────────
// RC2 decía «ejecuta codeguard init» pero el setup visual no añadía el CLI al
// PATH: sólo funcionaba si una versión antigua había dejado esas entradas. El
// mismo residuo sobrevivía a la desinstalación. Las dos transiciones viven aquí.
//
// Se conserva cada entrada ajena tal cual y sólo se retiran las dos identidades
// de CodeGuard. Nunca se borra el valor PATH entero salvo que no contuviera
// ninguna otra entrada.
function RutaPathNormalizada(S: String): String;
begin
  S := Trim(S);
  if (Length(S) >= 2) and (Copy(S, 1, 1) = '"') and
     (Copy(S, Length(S), 1) = '"') then
    S := Copy(S, 2, Length(S) - 2);
  StringChangeEx(S, '/', '\', True);
  while (Length(S) > 3) and (Copy(S, Length(S), 1) = '\') do
    Delete(S, Length(S), 1);
  Result := Lowercase(S);
end;

function EsRutaPathDeCodeGuard(const Entrada: String): Boolean;
var
  N: String;
begin
  N := RutaPathNormalizada(Entrada);
  Result :=
    (N = RutaPathNormalizada(ExpandConstant('{app}\bin'))) or
    (N = RutaPathNormalizada(ExpandConstant('{app}\engines'))) or
    (N = '%localappdata%\codeguard\bin') or
    (N = '%localappdata%\codeguard\engines');
end;

function ActualizarPathCodeGuard(Instalar: Boolean): Boolean;
var
  Actual, Resto, Entrada, Nuevo, BinDir, EnginesDir: String;
  P: Integer;
begin
  Actual := '';
  RegQueryStringValue(HKEY_CURRENT_USER, 'Environment', 'Path', Actual);
  Resto := Actual + ';';
  Nuevo := '';

  while Length(Resto) > 0 do
  begin
    P := Pos(';', Resto);
    if P = 0 then break;
    Entrada := Copy(Resto, 1, P - 1);
    Delete(Resto, 1, P);
    if (Trim(Entrada) <> '') and (not EsRutaPathDeCodeGuard(Entrada)) then
    begin
      if Nuevo <> '' then Nuevo := Nuevo + ';';
      Nuevo := Nuevo + Entrada;
    end;
  end;

  if Instalar then
  begin
    BinDir := ExpandConstant('{app}\bin');
    EnginesDir := ExpandConstant('{app}\engines');
    if Nuevo <> '' then Nuevo := Nuevo + ';';
    Nuevo := Nuevo + BinDir + ';' + EnginesDir;
  end;

  if Nuevo = '' then
  begin
    if RegValueExists(HKEY_CURRENT_USER, 'Environment', 'Path') then
      Result := RegDeleteValue(HKEY_CURRENT_USER, 'Environment', 'Path')
    else
      Result := True;
  end
  else
    Result := RegWriteExpandStringValue(
      HKEY_CURRENT_USER, 'Environment', 'Path', Nuevo);
end;

// El desinstalador tenia el mismo agujero por su propio camino ([UninstallRun]
// con taskkill suelto): aqui se cierra con la misma funcion.
function InitializeUninstall(): Boolean;
begin
  DetenerDaemon();
  Result := ActualizarPathCodeGuard(False);
  if not Result then
    MsgBox('No se pudo retirar CodeGuard del PATH del usuario. La desinstalación ' +
           'se detuvo para no afirmar que terminó dejando una ruta activa.',
           mbError, MB_OK);
end;

// ── motores dentro del asistente: sin consolas ───────────────────────────
// Lanza instalar-motores.ps1 OCULTO y va mostrando la ultima linea de su log
// en la propia pagina de instalacion. El .done marca el final y trae el
// codigo de salida. Si algo falla, degrada y avisa: jamas rompe el setup (P4).
// Estado escribe el progreso donde exista: en el asistente si hay ventana, y
// SIEMPRE en el log de Inno. Bajo /VERYSILENT el WizardForm NO se crea, y
// tocarlo revienta el reparto desatendido — cada acceso pasa por aquí.
procedure Estado(const S: String);
begin
  Log('CodeGuard: ' + S);
  if not WizardSilent() then
  begin
    WizardForm.StatusLabel.Caption := S;
    WizardForm.StatusLabel.Refresh;
  end;
end;

// ── Los cuatro archivos de esta corrida ─────────────────────────────────────
// Llevan el identificador de la ejecución dentro del nombre. Antes eran fijos
// y dos instalaciones simultáneas se pisaban: la segunda leía el .done de la
// primera y anunciaba un resultado que no era suyo.
function ArchivoDeCorrida(const Extension: String): String;
begin
  Result := ExpandConstant('{%TEMP}') + '\codeguard-motores-' + IdCorrida + Extension;
end;

// ── El protocolo CGP ────────────────────────────────────────────────────────
// Una línea por cada cambio de estado de un motor:
//     CGP|<seq>|<hechos>|<total>|<motor>|<estado>
// Lo escribe engines.ps1 (ver «El contrato CGP» allí). Aquí sólo se lee.
//
// Devuelve False ante cualquier línea que no tenga la forma EXACTA. Importa:
// el runner escribe mientras el asistente lee, así que se puede leer una línea
// a medio escribir. Una línea rota se ignora; jamás mueve la barra a un sitio
// inventado.
function ParsearCGP(S: String; var Hechos, Total: Integer; var Motor, Estado: String): Boolean;
var
  Campos: array[0..5] of String;
  i, p: Integer;
begin
  Result := False;
  for i := 0 to 4 do
  begin
    p := Pos('|', S);
    if p = 0 then exit;
    Campos[i] := Copy(S, 1, p - 1);
    Delete(S, 1, p);
  end;
  Campos[5] := S;
  if Campos[0] <> 'CGP' then exit;
  // Una línea truncada a la mitad puede tener las cinco barras y un número
  // incompleto detrás: si no convierte, se descarta igual.
  Hechos := StrToIntDef(Campos[2], -1);
  Total := StrToIntDef(Campos[3], -1);
  if (Hechos < 0) or (Total <= 0) or (Hechos > Total) then exit;
  Motor := Campos[4];
  Estado := Campos[5];
  Result := True;
end;

// ── La línea de detalle que se le enseña al usuario ─────────────────────────
// La última línea NO vale tal cual. Cuando algo escribe en el flujo de error,
// PowerShell suelta un bloque de cinco o seis líneas de andamiaje —la ruta del
// script, «At C:\...:5 char:1», los «+ ~~~~», CategoryInfo,
// FullyQualifiedErrorId— y la última de todas es siempre la menos informativa.
// Medido: con un solo Write-Error, lo que quedaba en la ventana era
// «+ FullyQualifiedErrorId : ...». Se camina hacia atrás hasta la última línea
// que de verdad dice algo.
function UltimaLineaUtil(const Lineas: TArrayOfString): String;
var
  N: Integer;
  L: String;
begin
  Result := '';
  N := GetArrayLength(Lineas) - 1;
  while N >= 0 do
  begin
    L := Trim(Lineas[N]);
    if (L <> '') and (Copy(L, 1, 1) <> '+') and (Copy(L, 1, 3) <> 'At ')
       and (Pos('FullyQualifiedErrorId', L) = 0) and (Pos('CategoryInfo', L) = 0) then
    begin
      Result := L;
      exit;
    end;
    N := N - 1;
  end;
end;

// ArrancarYVerificarDaemon arranca el agente UNA vez y comprueba que quedó
// vivo preguntándole por el pipe con `codeguard doctor --global` (exit 0 =
// healthy). Corre igual en interactivo y en silencioso.
//
// Antes salía por la puerta de atrás en cuanto había ventana —«interactivo: lo
// lanza la casilla postinstall y el usuario LO VE»—, que es exactamente la
// suposición que Héctor desmintió: el asistente terminaba diciendo «Listo» sin
// haber comprobado absolutamente nada.
//
// Y la ruta llevaba un byte 0x08 (backspace) incrustado donde debía decir
// \bin\: alguien escribió la ruta con un \b y quedó como carácter de control
// en el archivo fuente. La ruta expandida no existía, así que Exec fallaba
// SIEMPRE y el rastro del reparto masivo decía «daemon SIN verificar» en todas
// las máquinas. El artefacto que lo delató: «doctor exit 2», y 2 es
// ERROR_FILE_NOT_FOUND — Inno pone el código de error de Windows en
// ResultCode cuando no consigue arrancar el proceso.
procedure ArrancarYVerificarDaemon();
var
  Lanzado: Boolean;
  R, Intentos: Integer;
  EstadoTxt, RastroTxt: String;
begin
  Estado('Iniciando el agente local de CodeGuard...');

  // SW_SHOWNORMAL y no SW_HIDE: el daemon se compila con -H windowsgui y no
  // tiene consola que esconder. Sus ventanas las gobierna él.
  //
  // Si ya hay un daemon de este usuario en marcha, el que se lanza aquí se
  // retira solo (instancia única) y doctor valida al que ya estaba: sigue
  // habiendo un solo agente y un solo orbe.
  Lanzado := Exec(ExpandConstant('{app}\bin\{#MyDaemonExe}'), '',
                  ExpandConstant('{app}\bin'), SW_SHOWNORMAL, ewNoWait, R);

  R := -1;
  if Lanzado then
    for Intentos := 1 to 30 do
    begin
      if Exec(ExpandConstant('{app}\bin\{#MyAppExe}'), 'doctor --global', '',
              SW_HIDE, ewWaitUntilTerminated, R) and (R = 0) then
        break;
      Sleep(500);
    end;

  DaemonVerificado := Lanzado and (R = 0);

  // ── Lo que el código de salida de doctor SIGNIFICA, medido ────────────────
  //
  // 0 = healthy, 1 = degraded, 2 = failed. Y el reparto NO es el que parece:
  // en cmd/codeguard/doctorcmd.go sólo el chequeo de la BD marca `fallo`, así
  // que un esquema de BD divergente da 2 CON EL DAEMON RESPONDIENDO al ping,
  // mientras que un daemon caído se queda en 1.
  //
  // Medido el 2026-08-26 en la máquina de Héctor: `doctor --global` salía 2
  // con la línea «✓ daemon codeguard-daemon 1.0.0-rc2» delante. Un asistente
  // que tradujera ese 2 a «el agente no respondió» estaría mintiendo, y en la
  // dirección pesimista — mandando al usuario a arreglar algo que no está roto.
  //
  // Así que sólo el 0 se afirma. Lo demás se cuenta como lo que es: el
  // diagnóstico no salió limpio, y aquí está el comando para verlo. No se
  // nombra al daemon ni para bien ni para mal, porque con el código de salida
  // solo NO se puede distinguir cuál de los dos chequeos cayó.
  if not Lanzado then
  begin
    EstadoTxt := 'no se pudo lanzar el agente (Exec error ' + IntToStr(R) + ')';
    RastroTxt := EstadoTxt;
  end
  else if DaemonVerificado then
  begin
    EstadoTxt := 'agente verificado: doctor --global healthy';
    RastroTxt := EstadoTxt;
  end
  else
  begin
    EstadoTxt := 'agente arrancado, pero doctor --global no salió limpio (exit ' +
                 IntToStr(R) + '): revisa con codeguard doctor --global';
    // El rastro del archivo va en ASCII y el de pantalla con su acento:
    // SaveStringToFile escribe ANSI, y «salió» llegaba roto al archivo mientras
    // se veía bien en la ventana. Un rastro que lee una herramienta de reparto
    // no puede depender de la página de códigos de la máquina. (SaveStringToUTF8File
    // no existe en Inno 6 y la variante en plural pide un array: no compensa.)
    RastroTxt := 'agente arrancado, pero doctor --global no salio limpio (exit ' +
                 IntToStr(R) + '): revisa con codeguard doctor --global';
  end;
  Estado(EstadoTxt);
  // El texto se construye en una variable y no se lee de WizardForm: bajo
  // /VERYSILENT no hay etiquetas que consultar, y el reparto masivo necesita
  // este rastro igual.
  SaveStringToFile(ExpandConstant('{%TEMP}\codeguard-daemon.estado'), RastroTxt + #13#10, False);
end;

procedure EjecutarMotores();
var
  LogFile, FlagFile, ProgFile, Linea, Codigo, Detalle: String;
  Motor, EstadoMotor, UltimoPintado: String;
  Lineas: TArrayOfString;
  R, Espera, N, Hechos, Total, HechosVistos: Integer;
  TotalCuadra: Boolean;
begin
  LogFile := ArchivoDeCorrida('.log');
  FlagFile := ArchivoDeCorrida('.done');
  ProgFile := ArchivoDeCorrida('.progress');
  DeleteFile(FlagFile);

  Exec('powershell.exe',
       '-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File "' +
       ExpandConstant('{app}\instalar-motores.ps1') + '" -Id "' + IdCorrida + '"',
       '', SW_HIDE, ewNoWait, R);

  // ── La barra deja de ser un adorno ────────────────────────────────────────
  // Inno llena su barra durante la COPIA de archivos, que dura segundos. Todo
  // el trabajo real —130 MB de descargas y cuatro motores que se COMPILAN—
  // ocurre aquí, después, y podía durar una hora con la barra al 100% y
  // quieta. Para el usuario eso no informa de nada: es una barra verde.
  //
  // Ahora la barra representa MOTORES RESUELTOS de un total conocido. Vuelve a
  // cero al empezar esta fase, y el texto cambia en el mismo momento para
  // explicar por qué: una barra que retrocede sin decir nada asusta más que
  // una quieta.
  HechosVistos := -1;
  UltimoPintado := '';
  TotalCuadra := True;
  if not WizardSilent() then
  begin
    WizardForm.ProgressGauge.Min := 0;
    WizardForm.ProgressGauge.Max := {#MyMotorInstala};
    WizardForm.ProgressGauge.Position := 0;
  end;

  if EsActualizacion then
    Estado('Actualizando CodeGuard — los motores ya verificados se conservan...')
  else
    // Ya no se nombran los motores a mano aquí: la lista escrita a mano se
    // quedó sin mypy, sin shellcheck y sin los de Java, y envejecía sola. El
    // motor concreto lo dice el protocolo, con el número real de esta versión.
    Estado('Preparando motores — 0 de {#MyMotorInstala} resueltos...');

  // El tope era de 15 minutos y era el verdadero fallo de las dos
  // instalaciones que salieron "incompletas": en una red corporativa lenta el
  // zip de trivy (60 MB a 8-35 KB/s) necesita cuarenta y pico minutos, así que
  // el asistente se rendía, anunciaba que los motores no habían quedado, y el
  // trabajo SEGUÍA corriendo debajo — llegando a terminar bien un rato después.
  //
  // Un asistente que afirma un fracaso que no ha comprobado es peor que uno
  // lento: manda al usuario a commitear creyendo que le faltan compuertas, o a
  // reinstalar encima de una instalación que iba bien.
  //
  // Ahora espera una hora, y si se agota NO dice que falló: dice lo único que
  // le consta, que sigue en marcha, y cómo comprobarlo.
  Espera := 0;
  while (not FileExists(FlagFile)) and (Espera < 14400) do  // tope: 60 min
  begin
    // ── Progreso: del protocolo, nunca del log ──────────────────────────────
    // Se toma la ÚLTIMA línea válida, no se cuentan líneas: el propio runner
    // lleva el contador y garantiza un estado terminal por motor. Contar aquí
    // volvería a partir el invariante en dos sitios.
    if LoadStringsFromFile(ProgFile, Lineas) then
    begin
      N := GetArrayLength(Lineas) - 1;
      while N >= 0 do
      begin
        if ParsearCGP(Trim(Lineas[N]), Hechos, Total, Motor, EstadoMotor) then
        begin
          // El total del runtime contra el que este paquete anunció en su
          // pantalla de bienvenida. Si divergen, el inventario y el instalador
          // se han desincronizado: se registra y NO se pinta una fracción, que
          // sería un número falso en la cara del usuario.
          if Total <> {#MyMotorInstala} then
          begin
            if TotalCuadra then
              Log('CodeGuard: contrato de progreso roto: el runner declara ' +
                  IntToStr(Total) + ' motores y el paquete anunció {#MyMotorInstala}');
            TotalCuadra := False;
          end;
          if (Hechos <> HechosVistos) and TotalCuadra then
          begin
            HechosVistos := Hechos;
            if not WizardSilent() then
              WizardForm.ProgressGauge.Position := Hechos;
            Estado('Preparando motores — ' + IntToStr(Hechos) + ' de ' +
                   IntToStr(Total) + ' resueltos; faltan ' + IntToStr(Total - Hechos));
          end;
          break;
        end;
        N := N - 1;
      end;
    end;

    // El detalle humano sí sale del log: es donde se dice cuántos MB llevan
    // bajados o que un motor está compilando.
    if LoadStringsFromFile(LogFile, Lineas) then
    begin
      Linea := UltimaLineaUtil(Lineas);
      if (Linea <> '') and (Motor <> '') and (EstadoMotor = 'working') then
        Linea := Motor + ' — ' + Linea;
      // Bajo silencioso no hay WizardForm que tocar; el log de motores ya
      // queda en %TEMP% para quien reparta en masa.
      if (not WizardSilent()) and (Linea <> UltimoPintado) then
      begin
        UltimoPintado := Linea;
        WizardForm.FilenameLabel.Caption := Linea;
        WizardForm.FilenameLabel.Refresh;
      end;
    end;
    Sleep(250);
    Espera := Espera + 1;
  end;

  Codigo := '';
  if FileExists(FlagFile) then
  begin
    if LoadStringsFromFile(FlagFile, Lineas) and (GetArrayLength(Lineas) > 0) then
      Codigo := Trim(Lineas[0]);
  end;
  if not WizardSilent() then
    WizardForm.FilenameLabel.Caption := '';
  if Codigo = '' then
  begin
    // Se agotó la espera SIN que el runner dejara su .done: no ha fallado, no
    // ha terminado. Decir cualquiera de las dos cosas sería inventarse un dato.
    Estado('Los motores siguen instalándose en segundo plano.');
    if not WizardSilent() then
    MsgBox('Los motores TODAVÍA se están instalando.' + #13#10#13#10 +
           'La descarga va lenta en esta red, pero sigue en marcha: puedes cerrar' + #13#10 +
           'este asistente sin cortarla.' + #13#10#13#10 +
           'Para ver cómo va:      codeguard status' + #13#10 +
           'Si algo quedó a medias: codeguard repair  (reanuda, no reempieza)',
           mbInformation, MB_OK);
  end
  else if Codigo = '0' then
  begin
    if not WizardSilent() then
      WizardForm.ProgressGauge.Position := WizardForm.ProgressGauge.Max;
    Estado('Motores instalados y verificados.');
  end
  else
  begin
    Estado('Motores incompletos — CodeGuard degrada, no bloquea.');
    // Qué falta y qué deja de revisarse, no "algún motor".
    //
    // El mensaje anterior no decía cuál, ni qué compuerta se apagaba, ni si
    // reintentar servía de algo. El usuario se iba a commitear creyendo que
    // tenía un producto entero. engines.ps1 deja el detalle escrito aquí.
    Detalle := '';
    if LoadStringsFromFile(ArchivoDeCorrida('.faltan'), Lineas) then
    begin
      for N := 0 to GetArrayLength(Lineas) - 1 do
        Detalle := Detalle + Lineas[N] + #13#10;
    end;
    if Detalle = '' then
      Detalle := 'Detalle: ' + LogFile + #13#10 +
                 'Reintenta con: codeguard repair' + #13#10;
    if not WizardSilent() then
      MsgBox('La instalación quedó INCOMPLETA.' + #13#10#13#10 + Detalle,
             mbInformation, MB_OK);
  end;
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then
  begin
    if not ActualizarPathCodeGuard(True) then
      RaiseException('No se pudo añadir CodeGuard al PATH del usuario; la instalación no puede declararse completa.');
    EjecutarMotores();
    ArrancarYVerificarDaemon();
  end;
end;

// La página final dice lo que se comprobó, no lo que se espera.
//
// El texto era fijo: «CodeGuard quedó instalado». Ahora hay dos, y el que se
// pinta depende de si el agente respondió de verdad por el pipe. Ninguno de
// los dos afirma que el orbe esté visible: eso no se ha comprobado.
procedure CurPageChanged(CurPageID: Integer);
begin
  if CurPageID <> wpFinished then
    exit;
  if DaemonVerificado then
    WizardForm.FinishedLabel.Caption :=
      'CodeGuard quedó instalado y el agente local respondió.' + #13#10#13#10 +
      'Busca el orbe abajo a la derecha.' + #13#10#13#10 +
      'Siguiente paso, en cada repositorio:' + #13#10 +
      'codeguard init'
  else
    // Ni «no respondió» ni «falló»: el código de salida de doctor no permite
    // saber cuál de sus chequeos cayó (ver ArrancarYVerificarDaemon). Se dice
    // lo único que consta y se manda al comando que sí lo detalla.
    WizardForm.FinishedLabel.Caption :=
      'CodeGuard quedó instalado, pero el diagnóstico no salió limpio.' + #13#10#13#10 +
      'Ejecuta esto para ver qué falta:' + #13#10 +
      'codeguard doctor --global' + #13#10#13#10 +
      'Siguiente paso, en cada repositorio:' + #13#10 +
      'codeguard init';
end;
