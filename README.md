# URInspector

Inventory Windows custom URI scheme handlers, and resolve what each one actually launches.

For every registered URL protocol (from `HKCU`/`HKLM` and the per-user defaults), it prints the resolved handler:

- the **command line**, or
- the **`DelegateExecute`** COM server, and
- for packaged apps, the declared **package and executable**.

## Usage

```powershell
python URInspector.py

python URInspector.py > handlers.txt
```

## Example output

```
claude
    DelegateExecute: {A56A841F-E974-45C1-8001-7E3F8A085917}
    Declared executable: C:\Program Files\WindowsApps\Claude_..._x64__pzs8sxrjxfjjc\app\Claude.exe

docker-desktop
    Command: "C:\Program Files\Docker\Docker\resources\Docker Desktop.exe" "%1"

ms-settings
    DelegateExecute: {4ed3a719-cea8-4bd9-910d-e252f997afc2}
    Declared executable: C:\Windows\ImmersiveControlPanel\SystemSettings.exe
```
