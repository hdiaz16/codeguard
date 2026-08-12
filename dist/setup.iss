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
#define MyAppVersion "1.5.2"
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
ChangesEnvironment=yes
Compression=lzma2
SolidCompression=yes

[Languages]
Name: "spanish"; MessagesFile: "compiler:Languages\Spanish.isl"

[Messages]
; copy minimo: el asistente habla claro y corto
spanish.WelcomeLabel1=CodeGuard
spanish.WelcomeLabel2=El agente local de análisis pre-commit.%nRevisa lo que estás a punto de commitear y bloquea sólo lo que el CI también rechazaría.%n%nSe instalará para tu usuario, sin permisos de administrador:%n%n  •  CodeGuard (CLI + orbe) y sus 112 reglas%n  •  gitleaks y trivy, verificados contra el checksum de sus autores%n  •  semgrep, squawk y ruff (vía pip)%n%nTodos los motores son necesarios: sin ellos la paridad con el CI se rompe.
spanish.FinishedHeadingLabel=Listo.
spanish.FinishedLabelNoIcons=CodeGuard quedó instalado. Siguiente paso, en cada repositorio:%n%ncodeguard init%n%n(abre una terminal nueva para heredar el PATH)
spanish.FinishedLabel=CodeGuard quedó instalado. Siguiente paso, en cada repositorio:%n%ncodeguard init%n%n(abre una terminal nueva para heredar el PATH)
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

[Registry]
; el daemon arranca con la sesion; la clave se borra al desinstalar
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; \
    ValueType: string; ValueName: "CodeGuard"; \
    ValueData: """{app}\bin\{#MyDaemonExe}"""; Flags: uninsdeletevalue

[Run]
; Los motores NO van aqui: [Run] abriria consolas. Los corre EjecutarMotores
; ([Code]) con powershell oculto, mostrando el avance dentro del asistente.
Filename: "powershell.exe"; \
    Parameters: "-NoProfile -WindowStyle Hidden -Command ""$env:PATH = [Environment]::GetEnvironmentVariable('PATH','User') + ';' + $env:PATH; Start-Process '{app}\bin\{#MyDaemonExe}'"""; \
    Description: "Iniciar CodeGuard ahora (el orbe)"; \
    Flags: nowait postinstall skipifsilent runhidden

[UninstallRun]
Filename: "taskkill.exe"; Parameters: "/F /IM {#MyDaemonExe}"; \
    Flags: runhidden; RunOnceId: "PararDaemon"

[UninstallDelete]
; lo que engines.ps1 descargo despues de instalar
Type: filesandordirs; Name: "{app}\engines"

[Code]
const
  EnvKey = 'Environment';
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
  EsActualizacion := RegKeyExists(HKCU,
    'Software\Microsoft\Windows\CurrentVersion\Uninstall\{8F4E2C7A-1B3D-4A69-9E5C-2D7F0B1C4A88}_is1');
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
  L := LineaBienvenida('CodeGuard — CLI, orbe y sus 112 reglas', 'Segoe UI', 9, ColGrafito, Y);
  Y := L.Top + Salto;
  L := LineaBienvenida('gitleaks y trivy, verificados contra el checksum de sus autores', 'Segoe UI', 9, ColGrafito, Y);
  Y := L.Top + Salto;
  L := LineaBienvenida('semgrep, squawk y ruff', 'Segoe UI', 9, ColGrafito, Y);
  Y := L.Top + Salto + ScaleY(10);

  LineaBienvenida('Todos los motores son necesarios: sin ellos se rompe la paridad con el CI.', 'Segoe UI', 8, ColBruma, Y);
end;

// ── PATH de usuario: alta idempotente y baja limpia ──────────────────────
procedure EnvAddPath(const Ruta: string);
var
  Paths: string;
begin
  if not RegQueryStringValue(HKCU, EnvKey, 'Path', Paths) then
    Paths := '';
  if Pos(';' + Uppercase(Ruta) + ';', ';' + Uppercase(Paths) + ';') > 0 then
    exit;
  if Paths = '' then
    Paths := Ruta
  else
    Paths := Ruta + ';' + Paths;
  RegWriteStringValue(HKCU, EnvKey, 'Path', Paths);
end;

procedure EnvRemovePath(const Ruta: string);
var
  Paths: string;
  P: Integer;
begin
  if not RegQueryStringValue(HKCU, EnvKey, 'Path', Paths) then
    exit;
  P := Pos(';' + Uppercase(Ruta) + ';', ';' + Uppercase(Paths) + ';');
  if P = 0 then
    exit;
  if P = 1 then
    Delete(Paths, 1, Length(Ruta) + 1)   // al inicio: quita "ruta;"
  else
    Delete(Paths, P - 1, Length(Ruta) + 1); // en medio/final: quita ";ruta"
  RegWriteStringValue(HKCU, EnvKey, 'Path', Paths);
end;

// ── el daemon no puede estar corriendo mientras se reemplaza su .exe ─────
function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  R: Integer;
begin
  Exec(ExpandConstant('{sys}\taskkill.exe'), '/F /IM {#MyDaemonExe}', '',
       SW_HIDE, ewWaitUntilTerminated, R);
  Result := '';
end;

// ── motores dentro del asistente: sin consolas ───────────────────────────
// Lanza instalar-motores.ps1 OCULTO y va mostrando la ultima linea de su log
// en la propia pagina de instalacion. El .done marca el final y trae el
// codigo de salida. Si algo falla, degrada y avisa: jamas rompe el setup (P4).
procedure EjecutarMotores();
var
  LogFile, FlagFile, Linea, Codigo: String;
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
    WizardForm.StatusLabel.Caption := 'Instalando motores de análisis (gitleaks, trivy, semgrep, squawk, ruff)...';
  WizardForm.StatusLabel.Refresh;

  Espera := 0;
  while (not FileExists(FlagFile)) and (Espera < 3600) do  // tope: 15 min
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
  if Codigo = '0' then
    WizardForm.StatusLabel.Caption := 'Motores instalados y verificados.'
  else
  begin
    WizardForm.StatusLabel.Caption := 'Motores incompletos — CodeGuard degrada, no bloquea.';
    MsgBox('Algún motor no quedó completo. CodeGuard funcionará degradado.' + #13#10 +
           'Detalle: %TEMP%\codeguard-motores.log' + #13#10 +
           'Reintenta cuando quieras con: codeguard repair', mbInformation, MB_OK);
  end;
  WizardForm.StatusLabel.Refresh;
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then
  begin
    EnvAddPath(ExpandConstant('{app}\bin'));
    EnvAddPath(ExpandConstant('{app}\engines'));
    EjecutarMotores();
  end;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usPostUninstall then
  begin
    EnvRemovePath(ExpandConstant('{app}\bin'));
    EnvRemovePath(ExpandConstant('{app}\engines'));
  end;
end;
