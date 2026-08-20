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
#define MyAppVersion "1.14.0"
; reglas.iss lo genera build-dist.ps1 contando el rulepack: el numero que se le
; promete al usuario no se escribe a mano (llego a decir 112 con 119 instaladas)
#include "reglas.iss"
#define MyAppExe "codeguard.exe"
#define MyDaemonExe "codeguard-daemon.exe"

[Setup]
AppId={{8F4E2C7A-1B3D-4A69-9E5C-2D7F0B1C4A88}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher=CodeGuard
DefaultDirName={localappdata}\CodeGuard
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
; avisa a Windows que el PATH cambio (las terminales nuevas lo heredan)
ChangesEnvironment=no
CreateUninstallRegKey=no
Compression=lzma2
SolidCompression=yes

[Languages]
Name: "spanish"; MessagesFile: "compiler:Languages\Spanish.isl"

[Messages]
; copy minimo: el asistente habla claro y corto
spanish.WelcomeLabel1=CodeGuard
spanish.WelcomeLabel2=El agente local de análisis pre-commit.%nRevisa lo que estás a punto de commitear y bloquea sólo lo que el CI también rechazaría.%n%nSe instalará para tu usuario, sin permisos de administrador:%n%n  •  CodeGuard (CLI + orbe) y sus {#MyRuleCount} reglas%n  •  gitleaks y trivy, verificados contra el checksum de sus autores%n  •  semgrep, squawk, ruff y mypy (vía pip)%n  •  govulncheck y staticcheck, que se COMPILAN: un par de minutos%n%nSon 9 de los 16 motores. gofmt va dentro de CodeGuard, y los 6 restantes%n(go vet, tsc, eslint y los tres de .NET) usan las herramientas que YA tienes:%nGo, Node y el SDK de .NET. Para tsc y eslint es deliberado — se usa la versión%nde tu proyecto, que es la que corre en el CI; imponer la nuestra rompería la%nparidad en vez de defenderla. Si a tu repo le falta alguna, el agente te lo%ndice en cada análisis en vez de callárselo.
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
; runner oculto: el setup lo lanza sin ventana y muestra su log en vivo
Source: "instalar-motores.ps1"; DestDir: "{app}"; Flags: ignoreversion
; fotogramas del splash animado (se extraen a {tmp} solo durante el setup)
Source: "splash\*.bmp"; Flags: dontcopy
; fondo full-bleed de la pagina de bienvenida
Source: "welcome-bg.bmp"; Flags: dontcopy

[Icons]
Name: "{userstartup}\CodeGuard"; Filename: "{app}\bin\{#MyDaemonExe}"; \
    Parameters: "--tray"; WorkingDir: "{app}\bin"; IconFilename: "{app}\bin\{#MyDaemonExe}"
Name: "{userprograms}\CodeGuard\Desinstalar CodeGuard"; Filename: "{uninstallexe}"

[Run]
Filename: "{app}\bin\{#MyDaemonExe}"; \
    Parameters: "--tray"; \
    Description: "Iniciar CodeGuard ahora (el orbe)"; \
    Flags: nowait postinstall skipifsilent runhidden

; [UninstallRun] ya no mata al daemon: lo hace InitializeUninstall ([Code]),
; que ademas ESPERA a que el proceso muera de verdad. El taskkill suelto de
; aqui tenia dos fallos medidos: (1) un proceso fusilado no quita su icono de
; la bandeja (orbe fantasma), y (2) taskkill devuelve 0 cuando Windows ACEPTA
; la orden, no cuando solto el ejecutable — 110 ms despues el borrado de
; codeguard-daemon.exe fallaba con "in use (5)", el desinstalador no
; reintentaba, y aun asi reportaba exito dejando 23.7 MB huerfanos.

[UninstallDelete]
; Los motores NO se borran, y es deliberado.
;
; Se borraban, y cada reinstalación volvía a bajar 60 MB de trivy. En una red
; corporativa lenta eso fue una hora y una instalación incompleta: la descarga
; se truncó, el checksum no cuadró —correctamente— y el equipo quedó sin la
; compuerta de CVE.
;
; Borrarlos no aporta nada de seguridad: cada instalación verifica el SHA-256 de
; lo que encuentra contra motores.json ANTES de darlo por bueno, y lo reemplaza
; si no coincide. O sea que conservar un binario ya verificado es exactamente
; igual de seguro y muchísimo más rápido.
;
; Se conservan por el mismo criterio que la base de datos y la configuración:
; desinstalar el agente no tiene por qué costarle al usuario una hora de red.
; Para dejarlo del todo limpio: borrar %LOCALAPPDATA%\CodeGuard a mano.
;
; Sí se van los zips a medias: no sirven para nada si no se va a reinstalar.
Type: filesandordirs; Name: "{app}\descargas"

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

function InitializeSetup(): Boolean;
begin
  // ya instalado antes = actualizacion: se actualiza encima, sin borrar nada;
  // los motores con hash verificado se conservan y no se vuelven a descargar
  EsActualizacion := FileExists(ExpandConstant('{app}\bin\{#MyDaemonExe}'));
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

// El desinstalador tenia el mismo agujero por su propio camino ([UninstallRun]
// con taskkill suelto): aqui se cierra con la misma funcion.
function InitializeUninstall(): Boolean;
begin
  DetenerDaemon();
  Result := True;
end;

// ── motores dentro del asistente: sin consolas ───────────────────────────
// Lanza instalar-motores.ps1 OCULTO y va mostrando la ultima linea de su log
// en la propia pagina de instalacion. El .done marca el final y trae el
// codigo de salida. Si algo falla, degrada y avisa: jamas rompe el setup (P4).
procedure EjecutarMotores();
var
  LogFile, FlagFile, Linea, Codigo, Detalle: String;
  Lineas: TArrayOfString;
  R, Espera, N: Integer;
begin
  LogFile := ExpandConstant('{%TEMP}\codeguard-motores.log');
  FlagFile := ExpandConstant('{%TEMP}\codeguard-motores.done');
  DeleteFile(FlagFile);

  Exec('powershell.exe',
       '-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File "' +
       ExpandConstant('{app}\instalar-motores.ps1') + '"',
       '', SW_HIDE, ewNoWait, R);

  if EsActualizacion then
    WizardForm.StatusLabel.Caption := 'Actualizando CodeGuard — los motores ya verificados se conservan...'
  else
    // Se nombran TODOS, y se avisa de los que compilan: son los que tardan y
    // los que hacían parecer que el asistente se había colgado.
    WizardForm.StatusLabel.Caption := 'Instalando motores (gitleaks, trivy, semgrep, squawk, ruff) y compilando govulncheck y staticcheck...';
  WizardForm.StatusLabel.Refresh;

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
    if LoadStringsFromFile(LogFile, Lineas) then
    begin
      N := GetArrayLength(Lineas) - 1;
      while (N >= 0) and (Trim(Lineas[N]) = '') do
        N := N - 1;
      if N >= 0 then
      begin
        Linea := Trim(Lineas[N]);
        if WizardForm.FilenameLabel.Caption <> Linea then
        begin
          WizardForm.FilenameLabel.Caption := Linea;
          WizardForm.FilenameLabel.Refresh;
        end;
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
  WizardForm.FilenameLabel.Caption := '';
  if Codigo = '' then
  begin
    // Se agotó la espera SIN que el runner dejara su .done: no ha fallado, no
    // ha terminado. Decir cualquiera de las dos cosas sería inventarse un dato.
    WizardForm.StatusLabel.Caption := 'Los motores siguen instalándose en segundo plano.';
    MsgBox('Los motores TODAVÍA se están instalando.' + #13#10#13#10 +
           'La descarga va lenta en esta red, pero sigue en marcha: puedes cerrar' + #13#10 +
           'este asistente sin cortarla.' + #13#10#13#10 +
           'Para ver cómo va:      codeguard status' + #13#10 +
           'Si algo quedó a medias: codeguard repair  (reanuda, no reempieza)',
           mbInformation, MB_OK);
  end
  else if Codigo = '0' then
    WizardForm.StatusLabel.Caption := 'Motores instalados y verificados.'
  else
  begin
    WizardForm.StatusLabel.Caption := 'Motores incompletos — CodeGuard degrada, no bloquea.';
    // Qué falta y qué deja de revisarse, no "algún motor".
    //
    // El mensaje anterior no decía cuál, ni qué compuerta se apagaba, ni si
    // reintentar servía de algo. El usuario se iba a commitear creyendo que
    // tenía un producto entero. engines.ps1 deja el detalle escrito aquí.
    Detalle := '';
    if LoadStringsFromFile(ExpandConstant('{%TEMP}\codeguard-motores.faltan'), Lineas) then
    begin
      for N := 0 to GetArrayLength(Lineas) - 1 do
        Detalle := Detalle + Lineas[N] + #13#10;
    end;
    if Detalle = '' then
      Detalle := 'Detalle: %TEMP%\codeguard-motores.log' + #13#10 +
                 'Reintenta con: codeguard repair' + #13#10;
    MsgBox('La instalación quedó INCOMPLETA.' + #13#10#13#10 + Detalle,
           mbInformation, MB_OK);
  end;
  WizardForm.StatusLabel.Refresh;
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then
  begin
    EjecutarMotores();
  end;
end;
