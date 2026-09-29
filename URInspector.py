import ctypes
from ctypes import wintypes
from functools import lru_cache
import os
import re
import sys
import xml.etree.ElementTree as ET

if sys.platform != "win32":
    raise SystemExit("This script only runs on Windows.")

import winreg

ROOTS = (("HKCU", winreg.HKEY_CURRENT_USER), ("HKLM", winreg.HKEY_LOCAL_MACHINE))
SCHEME = re.compile(r"[a-z][a-z0-9+.-]*", re.I)
ASSOCF_IS_PROTOCOL = 0x1000
ASSOCF_NOTRUNCATE = 0x20
ASSOCSTR = {"progid": 20, "command": 1, "delegate": 18, "appid": 21}
query_string = ctypes.WinDLL("shlwapi").AssocQueryStringW
query_string.argtypes = [wintypes.DWORD, ctypes.c_int, wintypes.LPCWSTR,
                         wintypes.LPCWSTR, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)]
query_string.restype = ctypes.c_long
WARNINGS = set()


def warn(message):
    WARNINGS.add(message)


def values(hive, path):
    result = {}
    try:
        with winreg.OpenKey(hive, path) as key:
            for i in range(winreg.QueryInfoKey(key)[1]):
                name, value, _ = winreg.EnumValue(key, i)
                result[name.lower()] = value
    except FileNotFoundError:
        pass
    except OSError as error:
        warn(f"Incomplete registry read: {path} ({error.winerror})")
    return result


def subkeys(hive, path):
    try:
        with winreg.OpenKey(hive, path) as key:
            return [winreg.EnumKey(key, i) for i in range(winreg.QueryInfoKey(key)[0])]
    except FileNotFoundError:
        return []
    except OSError as error:
        warn(f"Incomplete registry enumeration: {path} ({error.winerror})")
        return []


def association_string(scheme, field):
    length = wintypes.DWORD(512)
    for _ in range(3):
        buffer = ctypes.create_unicode_buffer(length.value)
        hr = query_string(ASSOCF_IS_PROTOCOL | ASSOCF_NOTRUNCATE, field, scheme, "open", buffer, ctypes.byref(length))
        status = hr & 0xffffffff
        if status == 0:
            return buffer.value
        if status in (1, 0x80004003, 0x8007007A) and 0 < length.value <= 1048576:
            continue
        if status not in (0x80070483, 0x80070002, 0x80070003, 0x80070490):
            warn(f"Association {scheme}, property {field}: 0x{status:08X}")
        return ""
    warn(f"Association {scheme}: unstable result size")
    return ""


get_package_path = ctypes.WinDLL("kernel32").GetPackagePathByFullName
get_package_path.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(wintypes.DWORD), wintypes.LPWSTR]
get_package_path.restype = ctypes.c_long
get_family_packages = ctypes.WinDLL("kernel32").GetPackagesByPackageFamily
get_family_packages.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(wintypes.DWORD),
                               ctypes.POINTER(wintypes.LPWSTR), ctypes.POINTER(wintypes.DWORD), wintypes.LPWSTR]
get_family_packages.restype = ctypes.c_long


@lru_cache(maxsize=None)
def package_path(package):
    length = wintypes.DWORD(32768)
    buffer = ctypes.create_unicode_buffer(length.value)
    if get_package_path(package, ctypes.byref(length), buffer) == 0:
        return buffer.value
    return ""


@lru_cache(maxsize=None)
def family_packages(family):
    count, length = wintypes.DWORD(), wintypes.DWORD()
    status = get_family_packages(family, ctypes.byref(count), None, ctypes.byref(length), None)
    if status != 122 or not count.value:
        return []
    for _ in range(3):
        names = (wintypes.LPWSTR * count.value)()
        buffer = ctypes.create_unicode_buffer(length.value)
        status = get_family_packages(family, ctypes.byref(count), names, ctypes.byref(length), buffer)
        if status == 0:
            return [names[i] for i in range(count.value)]
        if status != 122:
            break
    return []


@lru_cache(maxsize=None)
def manifest(root):
    try:
        return ET.parse(os.path.join(root, "AppxManifest.xml")).getroot()
    except (OSError, ET.ParseError):
        return None


def manifest_executables(root, app_id, scheme):
    document = manifest(root)
    if document is None or not app_id:
        return []
    for app in document.findall("./{*}Applications/{*}Application"):
        if app.get("Id") != app_id:
            continue
        matches = []
        for extension in app.findall("./{*}Extensions/{*}Extension"):
            if extension.get("Category") == "windows.protocol" and any(
                child.tag.rsplit("}", 1)[-1] == "Protocol" and child.get("Name", "").lower() == scheme
                for child in extension
            ):
                matches.append(extension.get("Executable", app.get("Executable", "")))
        return matches or [app.get("Executable", "")]
    return []


def discover():
    names = {}
    explicit = set()
    referenced = set()

    def add(name, origin, declared=False):
        if SCHEME.fullmatch(name):
            name = name.lower()
            names.setdefault(name, set()).add(origin)
            if declared:
                explicit.add(name)

    for label, hive in ROOTS:
        for name in subkeys(hive, r"Software\Classes"):
            if "url protocol" in values(hive, rf"Software\Classes\{name}"):
                add(name, label)
        applications = values(hive, r"Software\RegisteredApplications")
        for path in applications.values():
            if not isinstance(path, str):
                continue
            for scheme, progid in values(hive, path + r"\URLAssociations").items():
                add(scheme, label, True)
                if isinstance(progid, str):
                    referenced.add(progid.lower())
    choices = r"Software\Microsoft\Windows\Shell\Associations\UrlAssociations"
    for scheme in subkeys(winreg.HKEY_CURRENT_USER, choices):
        add(scheme, "HKCU", True)
    return names, explicit, referenced


@lru_cache(maxsize=None)
def com_registration(clsid):
    servers = []
    seen = set()
    while clsid:
        if clsid.lower() in seen:
            return servers + ["TreatAs loop"]
        seen.add(clsid.lower())
        path = rf"CLSID\{clsid}"
        replacement = values(winreg.HKEY_CLASSES_ROOT, path + r"\TreatAs").get("")
        if replacement:
            servers.append(f"TreatAs: {replacement}")
            clsid = replacement
            continue
        appid = values(winreg.HKEY_CLASSES_ROOT, path).get("appid")
        registration = values(winreg.HKEY_CLASSES_ROOT, rf"AppID\{appid}") if appid else {}
        service = registration.get("localservice")
        for kind in ("InprocServer32", "LocalServer32"):
            server = values(winreg.HKEY_CLASSES_ROOT, path + "\\" + kind).get("")
            if server:
                suffix = " (declared LocalService)" if kind == "LocalServer32" and service else ""
                servers.append(f"{kind}: {os.path.expandvars(server)}{suffix}")
        if appid:
            if service:
                service_path = rf"SYSTEM\CurrentControlSet\Services\{service}"
                binary = values(winreg.HKEY_LOCAL_MACHINE, service_path).get("imagepath", "")
                servers.append(f"LocalService: {service} ({os.path.expandvars(binary)})")
            if "dllsurrogate" in registration:
                surrogate = registration["dllsurrogate"] or "dllhost.exe"
                servers.append(f"DllSurrogate: {os.path.expandvars(surrogate)}")
        break
    return servers


def resolve(scheme, association):
    progid = association["progid"]
    metadata = values(winreg.HKEY_CLASSES_ROOT, rf"{progid}\shell\open") if progid else {}
    app = values(winreg.HKEY_CLASSES_ROOT, rf"{progid}\Application") if progid else {}
    aumid = metadata.get("appusermodelid") or app.get("appusermodelid") or association["appid"]
    family, _, app_id = aumid.partition("!")
    package_id = metadata.get("packageid", "")
    packages = [package_id] if package_id else (family_packages(family) if app_id else [])
    targets = set()
    if association["delegate"]:
        for package in packages:
            root = package_path(package)
            if not root:
                continue
            executable = metadata.get("packagerelativeexecutable", "")
            paths = [executable] if executable else manifest_executables(root, app_id, scheme)
            for path in paths:
                if path and "$(" not in path:
                    targets.add(os.path.normpath(os.path.join(root, path)))
    return dict(association, scheme=scheme, targets=sorted(targets),
                package=bool(package_id or app_id),
                com=com_registration(association["delegate"]) if association["delegate"] else [])


def handlers():
    names, explicit, referenced = discover()
    associations = {name: {key: association_string(name, field) for key, field in ASSOCSTR.items()}
                    for name in sorted(names)}
    for name, association in associations.items():
        if association["progid"] and association["progid"].lower() != name:
            referenced.add(association["progid"].lower())
    for name, association in associations.items():
        if name in referenced and name not in explicit:
            continue
        yield resolve(name, association)


def show_list(rows):
    print(f"{len(rows)} candidate entries; current user associations, "
          f"{ctypes.sizeof(ctypes.c_void_p) * 8}-bit view")
    for row in rows:
        print()
        print(row["scheme"])
        if row["command"]:
            print(f"    Command: {row['command']}")
        if row["delegate"]:
            print(f"    DelegateExecute: {row['delegate']}")
            if row["targets"]:
                label = "Declared executable" if len(row["targets"]) == 1 else "Possible target"
                for target in row["targets"]:
                    print(f"    {label}: {target}")
            else:
                for server in row["com"]:
                    print(f"    COM: {server}")
                if row["package"]:
                    print("    Package executable not resolved")
                elif not row["com"]:
                    print("    COM server not resolved")
        if not row["command"] and not row["delegate"]:
            print("    Handler not resolved")


def main():
    show_list(list(handlers()))
    for message in sorted(WARNINGS):
        print(message, file=sys.stderr)


if __name__ == "__main__":
    try:
        main()
    except BrokenPipeError:
        sys.stdout = open(os.devnull, "w")
