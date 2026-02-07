#!/usr/bin/env python3
"""
NetExec module: onec_conf_fetcher
Collects 1C Enterprise configuration files from Windows targets.

Usage:
    nxc smb <target> -u <user> -p <pass> -M onec_conf_fetcher
    nxc smb <target> -u <user> -p <pass> -M onec_conf_fetcher -o EXPORT=true OUTPUT=/tmp/out

Source: https://github.com/HexArchy/onec-conf-fetcher
"""

from __future__ import annotations

__version__ = "0.1.0"

import contextlib
import json
import re
from abc import ABC, abstractmethod
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum, auto
from io import BytesIO
from pathlib import Path, PureWindowsPath
from typing import TYPE_CHECKING, Any, Protocol

if TYPE_CHECKING:
    from collections.abc import Iterator

# NetExec imports
try:
    from nxc.helpers.misc import CATEGORY
    from nxc.paths import TMP_PATH
except ImportError:
    TMP_PATH = Path("/tmp/nxc")
    CATEGORY = None

# impacket imports
try:
    from impacket.dcerpc.v5 import rrp
    from impacket.dcerpc.v5.rpcrt import DCERPCException
    from impacket.examples.secretsdump import RemoteOperations

    HAS_IMPACKET = True
except ImportError:
    rrp = None  # type: ignore[assignment]
    DCERPCException = Exception  # type: ignore[misc,assignment]
    RemoteOperations = None  # type: ignore[misc,assignment]
    HAS_IMPACKET = False

# System users to skip during enumeration
SYSTEM_USERS: frozenset[str] = frozenset(
    {
        "Default",
        "Default User",
        "Public",
        "All Users",
        "Default.migrated",
    }
)

# Profile base directories per Windows version
# Vista/Server 2008+: Users, XP/Server 2003: Documents and Settings
USER_PROFILE_BASES: tuple[str, ...] = (
    "Users",
    "Documents and Settings",
)

# 1C server installation directories (x64 / x86)
SERVER_INSTALL_BASES: tuple[str, ...] = (
    "Program Files\\1cv8",
    "Program Files (x86)\\1cv8",
)


# === Models ===


class ConfigType(StrEnum):
    """Type of 1C configuration file."""

    IBASES = auto()
    LAUNCHER = auto()
    USER = auto()
    CONNECTION = auto()
    SERVERS = auto()
    LICENSE = auto()


@dataclass(slots=True, frozen=True)
class ConfigFile:
    """1C configuration file metadata."""

    name: str
    paths: tuple[str, ...]  # relative paths to try (modern first, legacy second)
    encoding: str | None
    config_type: ConfigType
    priority: int = 99


@dataclass(slots=True)
class CollectedConfig:
    """Collected configuration file with content."""

    config: ConfigFile
    content: bytes
    username: str
    profile_path: str


@dataclass(slots=True, frozen=True)
class OneCDatabase:
    """Parsed 1C database entry from ibases.v8i."""

    name: str
    connection_type: str | None = None  # "server" or "file"
    server: str | None = None
    port: str | None = None
    database: str | None = None
    file_path: str | None = None  # path for file-based databases
    connect_string: str | None = None
    id: str | None = None
    version: str | None = None
    app: str | None = None

    def to_dict(self) -> dict[str, str | None]:
        """Convert to dictionary for JSON serialization."""
        return {
            "name": self.name,
            "connection_type": self.connection_type,
            "server": self.server,
            "port": self.port,
            "database": self.database,
            "file_path": self.file_path,
            "connect_string": self.connect_string,
            "id": self.id,
            "version": self.version,
            "app": self.app,
        }


def _1c_paths(relative: str) -> tuple[str, ...]:
    """Build config path variants for modern and legacy Windows."""
    # Vista+: AppData\Roaming\..., XP: Application Data\...
    return (
        f"AppData\\Roaming\\{relative}",
        f"Application Data\\{relative}",
    )


# Per-user 1C configuration files
ONEC_CONFIG_FILES: tuple[ConfigFile, ...] = (
    ConfigFile("ibases.v8i", _1c_paths(r"1C\1CEStart\ibases.v8i"), "utf-8-sig", ConfigType.IBASES, 1),
    ConfigFile("1cestart.cfg", _1c_paths(r"1C\1CEStart\1cestart.cfg"), "utf-16-le", ConfigType.LAUNCHER, 2),
    ConfigFile("def.usr", _1c_paths(r"1C\1cv8\def.usr"), None, ConfigType.USER, 3),
    ConfigFile("1cv8conn.pfl", _1c_paths(r"1C\1cv8\1cv8conn.pfl"), None, ConfigType.CONNECTION, 4),
    ConfigFile("appsrvrs.lst", _1c_paths(r"1C\1cv8\appsrvrs.lst"), "utf-8", ConfigType.SERVERS, 5),
    ConfigFile("nethasp.ini", _1c_paths(r"1C\1cv8\conf\nethasp.ini"), "utf-8", ConfigType.LICENSE, 6),
)


# === Protocols ===


class Logger(Protocol):
    """Protocol for logging interface."""

    def display(self, msg: str) -> None: ...
    def success(self, msg: str) -> None: ...
    def fail(self, msg: str) -> None: ...
    def highlight(self, msg: str) -> None: ...
    def debug(self, msg: str) -> None: ...


class SharedFile(Protocol):
    """Protocol for impacket SharedFile."""

    def get_longname(self) -> str: ...
    def is_directory(self) -> bool: ...


class SMBConnectionProtocol(Protocol):
    """Protocol for SMB connection interface."""

    def getFile(self, shareName: str, pathName: str, callback: Callable[[bytes], int | None]) -> None: ...
    def listPath(self, shareName: str, path: str) -> Sequence[SharedFile]: ...


class NetExecConnection(Protocol):
    """Protocol for NetExec connection object."""

    conn: SMBConnectionProtocol
    username: str
    kerberos: bool
    host: str


# === Parsers ===


class ConfigParser(ABC):
    """Abstract base class for configuration file parsers."""

    @property
    @abstractmethod
    def supported_configs(self) -> frozenset[str]: ...

    @abstractmethod
    def parse(self, content: bytes, config: ConfigFile) -> Iterator[Any]: ...


class IbasesParser(ConfigParser):
    """Parser for ibases.v8i file format.

    Handles both server-based (Srvr=) and file-based (File=) databases.
    """

    _section_re = re.compile(r"^\[(.+)\]$")
    _connect_re = re.compile(r"^Connect=(.+)$", re.IGNORECASE)
    _srvr_re = re.compile(r'Srvr="([^"]+)"', re.IGNORECASE)
    _ref_re = re.compile(r'Ref="([^"]+)"', re.IGNORECASE)
    _file_re = re.compile(r'File="([^"]+)"', re.IGNORECASE)
    _id_re = re.compile(r"^ID=(.+)$", re.IGNORECASE)
    _version_re = re.compile(r"^Version=(.+)$", re.IGNORECASE)
    _app_re = re.compile(r"^App=(.+)$", re.IGNORECASE)

    @property
    def supported_configs(self) -> frozenset[str]:
        return frozenset({"ibases.v8i"})

    def parse(self, content: bytes, config: ConfigFile) -> Iterator[OneCDatabase]:
        text = content.decode(config.encoding or "utf-8-sig", errors="replace")
        yield from self._parse_text(text)

    @staticmethod
    def _empty_entry(name: str) -> dict[str, str | None]:
        return {
            "name": name,
            "connection_type": None,
            "server": None,
            "port": None,
            "database": None,
            "file_path": None,
            "connect_string": None,
            "id": None,
            "version": None,
            "app": None,
        }

    def _parse_text(self, text: str) -> Iterator[OneCDatabase]:
        current: dict[str, str | None] = {}

        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith(";"):
                continue

            if m := self._section_re.match(line):
                if current.get("name"):
                    yield OneCDatabase(**current)  # type: ignore[arg-type]
                current = self._empty_entry(m.group(1))
                continue

            if not current:
                continue

            if m := self._connect_re.match(line):
                connect_str = m.group(1)
                current["connect_string"] = connect_str

                if srvr := self._srvr_re.search(connect_str):
                    current["connection_type"] = "server"
                    server_full = srvr.group(1)
                    if ":" in server_full:
                        host, port = server_full.rsplit(":", 1)
                        current["server"] = host
                        current["port"] = port
                    else:
                        current["server"] = server_full
                    if ref := self._ref_re.search(connect_str):
                        current["database"] = ref.group(1)

                elif file_m := self._file_re.search(connect_str):
                    current["connection_type"] = "file"
                    current["file_path"] = file_m.group(1)

                continue

            if m := self._id_re.match(line):
                current["id"] = m.group(1)
            elif m := self._version_re.match(line):
                current["version"] = m.group(1)
            elif m := self._app_re.match(line):
                current["app"] = m.group(1)

        if current.get("name"):
            yield OneCDatabase(**current)  # type: ignore[arg-type]


class LauncherParser(ConfigParser):
    """Parser for 1cestart.cfg (launcher settings)."""

    @property
    def supported_configs(self) -> frozenset[str]:
        return frozenset({"1cestart.cfg"})

    def parse(self, content: bytes, config: ConfigFile) -> Iterator[dict[str, str]]:
        text = content.decode(config.encoding or "utf-16-le", errors="replace")
        settings: dict[str, str] = {}
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith(";") or line.startswith("#"):
                continue
            if "=" in line:
                key, _, value = line.partition("=")
                settings[key.strip()] = value.strip()
        if settings:
            yield settings


class ServersParser(ConfigParser):
    """Parser for appsrvrs.lst (application servers list)."""

    _addr_re = re.compile(r'"([^"]+)"')

    @property
    def supported_configs(self) -> frozenset[str]:
        return frozenset({"appsrvrs.lst"})

    def parse(self, content: bytes, config: ConfigFile) -> Iterator[str]:
        text = content.decode(config.encoding or "utf-8", errors="replace")
        seen: set[str] = set()
        for m in self._addr_re.finditer(text):
            value = m.group(1)
            if ("." in value or ":" in value) and value not in seen:
                seen.add(value)
                yield value


class DefUsrParser(ConfigParser):
    """Parser for def.usr (last logged-in 1C username)."""

    @property
    def supported_configs(self) -> frozenset[str]:
        return frozenset({"def.usr"})

    def parse(self, content: bytes, config: ConfigFile) -> Iterator[str]:
        if not content:
            return
        for enc in ("utf-8-sig", "utf-8", "cp1251", "utf-16-le"):
            try:
                text = content.decode(enc).strip()
                if text and all(c.isprintable() or c in "\r\n" for c in text):
                    first_line = text.splitlines()[0].strip()
                    if first_line:
                        yield first_line
                    return
            except (UnicodeDecodeError, ValueError):
                continue


class NethaspParser(ConfigParser):
    """Parser for nethasp.ini (HASP license server config).

    Extracts license server addresses from NH_SERVER_ADDR.
    """

    _addr_re = re.compile(r"^\s*NH_SERVER_ADDR\s*=\s*(.+)$", re.IGNORECASE | re.MULTILINE)

    @property
    def supported_configs(self) -> frozenset[str]:
        return frozenset({"nethasp.ini"})

    def parse(self, content: bytes, config: ConfigFile) -> Iterator[str]:
        text = content.decode(config.encoding or "utf-8", errors="replace")
        for m in self._addr_re.finditer(text):
            value = m.group(1).split(";")[0]  # strip inline INI comment
            for addr in value.split(","):
                addr = addr.strip()
                if addr:
                    yield addr


def parse_ibases_content(text: str) -> Iterator[OneCDatabase]:
    """Parse ibases.v8i text content directly."""
    parser = IbasesParser()
    config = ConfigFile("ibases.v8i", ("",), "utf-8", ConfigType.IBASES)
    yield from parser.parse(text.encode("utf-8"), config)


# === Collectors ===


class Collector(ABC):
    """Abstract base class for configuration collectors."""

    def __init__(self, connection: NetExecConnection, logger: Logger | None = None) -> None:
        self.connection = connection
        self.logger = logger

    def log(self, level: str, msg: str) -> None:
        if self.logger:
            getattr(self.logger, level, self.logger.display)(msg)

    @abstractmethod
    def collect(self, username: str, profile_path: str, configs: list[ConfigFile]) -> list[CollectedConfig]: ...


class SMBCollector(Collector):
    """Collector that uses SMB to read configuration files."""

    def collect(self, username: str, profile_path: str, configs: list[ConfigFile]) -> list[CollectedConfig]:
        collected: list[CollectedConfig] = []

        for config in configs:
            content = self._try_read_config(profile_path, config)
            if content:
                collected.append(CollectedConfig(config, content, username, profile_path))
                self.log("success", f"  Found: {config.name}")
            else:
                self.log("debug", f"  {config.name}: not found")

        return collected

    def _try_read_config(self, profile_path: str, config: ConfigFile) -> bytes | None:
        """Try each candidate path for a config file, return first hit."""
        for rel_path in config.paths:
            full_path = str(PureWindowsPath(profile_path) / rel_path)
            try:
                content = self._read_file(full_path)
                if content:
                    return content
            except OSError:
                continue
        return None

    @staticmethod
    def _split_unc(file_path: str) -> tuple[str, str]:
        """Extract SMB share and relative path from a Windows path."""
        win_path = PureWindowsPath(file_path)
        drive = win_path.drive.rstrip(":")
        share = f"{drive}$"
        smb_path = "/".join(win_path.parts[1:])
        return share, smb_path

    def _read_file(self, file_path: str) -> bytes | None:
        share, smb_path = self._split_unc(file_path)
        buffer = BytesIO()
        try:
            self.connection.conn.getFile(share, smb_path, buffer.write)
            return buffer.getvalue()
        except Exception as e:
            raise OSError(f"Failed to read {share}/{smb_path}") from e

    def enumerate_users(self) -> dict[str, str]:
        """Enumerate user profiles via SMB, trying modern and legacy paths."""
        user_profiles: dict[str, str] = {}
        for base in USER_PROFILE_BASES:
            try:
                entries = self.connection.conn.listPath("C$", f"\\{base}\\*")
                for entry in entries:
                    name = entry.get_longname()
                    if name in (".", "..") or not entry.is_directory():
                        continue
                    if name in SYSTEM_USERS or name.startswith("$"):
                        continue
                    if name not in user_profiles:
                        user_profiles[name] = f"C:\\{base}\\{name}"
            except Exception:
                continue
        if not user_profiles:
            self.log("fail", "SMB user enumeration failed")
        return user_profiles

    def find_user_profile(self, username: str) -> str | None:
        """Locate a specific user's profile directory."""
        for base in USER_PROFILE_BASES:
            path = f"C:\\{base}\\{username}"
            if self.check_profile_exists(path):
                return path
        return None

    def check_profile_exists(self, profile_path: str) -> bool:
        try:
            share, smb_path = self._split_unc(profile_path)
            self.connection.conn.listPath(share, smb_path.replace("/", "\\") + "\\*")
            return True
        except Exception:
            return False

    def collect_server_configs(self) -> tuple[list[CollectedConfig], bool]:
        """Collect 1C server-side configs from Program Files. Returns (configs, server_detected)."""
        collected: list[CollectedConfig] = []
        server_detected = False

        for base in SERVER_INSTALL_BASES:
            srvinfo = f"C:\\{base}\\srvinfo"
            if self.check_profile_exists(srvinfo):
                server_detected = True

            for fname, enc, ctype in [
                ("nethasp.ini", "utf-8", ConfigType.LICENSE),
                ("conf.cfg", "utf-8", ConfigType.SERVERS),
            ]:
                full_path = f"C:\\{base}\\conf\\{fname}"
                try:
                    content = self._read_file(full_path)
                    if content:
                        cfg = ConfigFile(f"server_{fname}", (f"{base}\\conf\\{fname}",), enc, ctype)
                        collected.append(CollectedConfig(cfg, content, "_server_", f"C:\\{base}"))
                        self.log("success", f"  Found server config: {fname}")
                except OSError:
                    continue

        return collected, server_detected


class RegistryProfileEnumerator:
    """Enumerates user profiles via Windows Registry."""

    def __init__(self, connection: Any, logger: Logger | None = None) -> None:
        self.connection = connection
        self.logger = logger
        self._remote_ops: Any = None

    def log(self, level: str, msg: str) -> None:
        if self.logger:
            getattr(self.logger, level, self.logger.display)(msg)

    def enable(self) -> bool:
        if not HAS_IMPACKET:
            return False
        try:
            self._remote_ops = RemoteOperations(
                self.connection.conn,
                self.connection.kerberos,
                getattr(self.connection, "kdcHost", None),
            )
            self._remote_ops.enableRegistry()
            return True
        except Exception as e:
            self.log("debug", f"Failed to enable remote registry: {e}")
            return False

    def disable(self) -> None:
        if self._remote_ops:
            with contextlib.suppress(Exception):
                self._remote_ops.finish()
            self._remote_ops = None

    def enumerate(self) -> dict[str, str]:
        if not self._remote_ops or not HAS_IMPACKET:
            return {}

        user_profiles: dict[str, str] = {}
        try:
            dce = self._remote_ops.getRRP()
            ans = rrp.hOpenLocalMachine(dce)
            hklm_handle = ans["phKey"]

            profile_list_path = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"
            ans = rrp.hBaseRegOpenKey(
                dce,
                hklm_handle,
                profile_list_path,
                samDesired=rrp.MAXIMUM_ALLOWED | rrp.KEY_ENUMERATE_SUB_KEYS | rrp.KEY_QUERY_VALUE,
            )
            profile_list_handle = ans["phkResult"]

            i = 0
            while True:
                try:
                    subkey = rrp.hBaseRegEnumKey(dce, profile_list_handle, i)
                    sid = subkey["lpNameOut"].rstrip("\x00")
                    if sid.startswith("S-1-5-21-") and not sid.endswith("_Classes"):
                        profile_path = self._get_profile_path(dce, hklm_handle, sid)
                        if profile_path:
                            username = PureWindowsPath(profile_path).name
                            if username not in SYSTEM_USERS and not username.startswith("$"):
                                user_profiles[username] = profile_path
                    i += 1
                except DCERPCException:
                    break

            rrp.hBaseRegCloseKey(dce, profile_list_handle)
            rrp.hBaseRegCloseKey(dce, hklm_handle)
        except Exception as e:
            self.log("debug", f"Registry enumeration error: {e}")

        return user_profiles

    def _get_profile_path(self, dce: Any, hklm_handle: Any, sid: str) -> str | None:
        try:
            path = rf"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\{sid}"
            ans = rrp.hBaseRegOpenKey(
                dce,
                hklm_handle,
                path,
                samDesired=rrp.MAXIMUM_ALLOWED | rrp.KEY_QUERY_VALUE,
            )
            sid_handle = ans["phkResult"]
            ans = rrp.hBaseRegQueryValue(dce, sid_handle, "ProfileImagePath")
            profile_path: str = ans[1].rstrip("\x00")
            profile_path = re.sub(r"%systemdrive%", "C:", profile_path, flags=re.IGNORECASE)
            rrp.hBaseRegCloseKey(dce, sid_handle)
            return profile_path
        except Exception:
            return None

    def __enter__(self) -> RegistryProfileEnumerator:
        return self

    def __exit__(self, *args: object) -> None:
        self.disable()


# === Exporter ===


class ConfigExporter:
    """Exports collected configurations to local files."""

    def __init__(self, output_dir: Path, logger: Logger | None = None) -> None:
        self.output_dir = output_dir
        self.logger = logger

    def log(self, level: str, msg: str) -> None:
        if self.logger:
            getattr(self.logger, level, self.logger.display)(msg)

    def export(
        self,
        host_info: dict[str, Any],
        collected: list[CollectedConfig],
        databases: dict[str, list[OneCDatabase]] | None = None,
        user_profiles: dict[str, str] | None = None,
        launcher_settings: dict[str, dict[str, str]] | None = None,
        app_servers: dict[str, list[str]] | None = None,
        onec_users: dict[str, str] | None = None,
        license_servers: list[str] | None = None,
    ) -> Path:
        host = host_info.get("ip") or "unknown"
        target_dir = self.output_dir / host
        target_dir.mkdir(parents=True, exist_ok=True)

        by_user: dict[str, list[CollectedConfig]] = {}
        for item in collected:
            if item.username == "_server_":
                server_dir = target_dir / "_server_"
                server_dir.mkdir(exist_ok=True)
                (server_dir / item.config.name).write_bytes(item.content)
                self.log("display", f"  Exported: {server_dir / item.config.name}")
                continue
            by_user.setdefault(item.username, []).append(item)

        for username, configs in by_user.items():
            user_dir = target_dir / username
            user_dir.mkdir(exist_ok=True)
            for item in configs:
                (user_dir / item.config.name).write_bytes(item.content)
                self.log("display", f"  Exported: {user_dir / item.config.name}")

        self._export_host_summary(
            target_dir,
            host_info,
            by_user,
            databases,
            user_profiles,
            launcher_settings,
            app_servers,
            onec_users,
            license_servers,
        )
        self.log("highlight", f"Configs exported to: {target_dir.resolve()}")
        return target_dir

    def _export_host_summary(
        self,
        target_dir: Path,
        host_info: dict[str, Any],
        by_user: dict[str, list[CollectedConfig]],
        databases: dict[str, list[OneCDatabase]] | None,
        user_profiles: dict[str, str] | None,
        launcher_settings: dict[str, dict[str, str]] | None,
        app_servers: dict[str, list[str]] | None,
        onec_users: dict[str, str] | None,
        license_servers: list[str] | None,
    ) -> None:
        all_dbs = databases or {}
        all_db_list = [db for dbs in all_dbs.values() for db in dbs]
        all_users = sorted((user_profiles or {}).keys())
        users_with_configs = sorted(by_user.keys())

        unique_servers = sorted({db.server for db in all_db_list if db.server})
        unique_databases = self._build_unique_databases(all_dbs)

        server_dbs = [d for d in unique_databases if d.get("connection_type") == "server"]
        file_dbs = [d for d in unique_databases if d.get("connection_type") == "file"]

        users_info: list[dict[str, Any]] = []
        for username, configs in by_user.items():
            user_dbs = all_dbs.get(username, [])
            entry: dict[str, Any] = {
                "username": username,
                "files_collected": [c.config.name for c in configs],
                "databases": [db.to_dict() for db in user_dbs],
            }
            if onec_users and username in onec_users:
                entry["last_1c_user"] = onec_users[username]
            users_info.append(entry)

        summary: dict[str, Any] = {
            "host": host_info.get("ip"),
            "hostname": host_info.get("hostname"),
            "domain": host_info.get("domain"),
            "collected_at": datetime.now(UTC).isoformat(),
            "server_detected": host_info.get("server_detected", False),
            "users_enumerated": all_users,
            "users_with_configs": users_with_configs,
            "files_total": sum(len(c) for c in by_user.values()),
            "databases_total": len(all_db_list),
            "unique_servers": unique_servers,
            "unique_databases": server_dbs,
        }

        if file_dbs:
            summary["file_databases"] = file_dbs
        if onec_users:
            summary["onec_users"] = onec_users
        if license_servers:
            summary["license_servers"] = license_servers
        if launcher_settings:
            summary["launcher_settings"] = launcher_settings
        if app_servers:
            summary["app_servers"] = app_servers

        summary["users"] = users_info

        (target_dir / "host_summary.json").write_text(
            json.dumps(summary, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        self.log("display", f"  Summary: {target_dir / 'host_summary.json'}")

    @staticmethod
    def _build_unique_databases(
        databases: dict[str, list[OneCDatabase]],
    ) -> list[dict[str, Any]]:
        seen: dict[tuple[str | None, str | None, str | None], dict[str, Any]] = {}
        for username, dbs in databases.items():
            for db in dbs:
                key = (db.server, db.database, db.file_path)
                if key not in seen:
                    seen[key] = {
                        "connection_type": db.connection_type,
                        "server": db.server,
                        "port": db.port,
                        "database": db.database,
                        "file_path": db.file_path,
                        "name": db.name,
                        "version": db.version,
                        "users": [],
                    }
                if username not in seen[key]["users"]:
                    seen[key]["users"].append(username)
        return list(seen.values())


# === NetExec Module ===


class NXCModule:
    """NetExec module for 1C Enterprise configuration collection."""

    name = "onec_conf_fetcher"
    description = "Collects 1C Enterprise configuration files (ibases.v8i, etc.)"
    supported_protocols = ["smb"]
    opsec_safe = True
    multiple_hosts = True
    category = CATEGORY.ENUMERATION if CATEGORY else "enumeration"

    def __init__(self, context: Any = None, module_options: dict[str, str] | None = None) -> None:
        self.context = context
        self.module_options = module_options or {}
        self.export: bool = False
        self.output_dir: Path = Path(TMP_PATH) / "onec_conf_fetcher"
        self._ibases_parser = IbasesParser()
        self._launcher_parser = LauncherParser()
        self._servers_parser = ServersParser()
        self._defusr_parser = DefUsrParser()
        self._nethasp_parser = NethaspParser()
        self._configs = list(ONEC_CONFIG_FILES)

    def options(self, context: Any, module_options: dict[str, str]) -> None:
        self.context = context
        self.export = module_options.get("EXPORT", "").lower() in ("true", "1", "yes")
        if "OUTPUT" in module_options:
            self.output_dir = Path(module_options["OUTPUT"])

    def on_admin_login(self, context: Any, connection: Any) -> None:
        self.context = context
        context.log.display("Running as admin - enumerating all user profiles")

        with RegistryProfileEnumerator(connection, context.log) as enumerator:
            if enumerator.enable():
                user_profiles = enumerator.enumerate()
            else:
                user_profiles = {}

        if not user_profiles:
            context.log.display("Registry unavailable, using SMB enumeration")
            collector = SMBCollector(connection, context.log)
            user_profiles = collector.enumerate_users()

        if not user_profiles:
            context.log.fail("No user profiles found")
            return

        context.log.success(f"Found {len(user_profiles)} user profile(s)")
        self._collect_and_process(context, connection, user_profiles)

    def on_login(self, context: Any, connection: Any) -> None:
        self.context = context
        if getattr(connection, "admin_privs", False):
            return
        context.log.display("Running as non-admin - accessing current user profile only")

        username = self._extract_username(connection.username)
        collector = SMBCollector(connection, context.log)

        profile_path = collector.find_user_profile(username)
        if profile_path:
            context.log.display(f"Found profile: {profile_path}")
            self._collect_and_process(context, connection, {username: profile_path})
        else:
            context.log.fail(f"Could not locate profile for user: {username}")

    @staticmethod
    def _extract_username(full_username: str) -> str:
        if "\\" in full_username:
            return full_username.split("\\")[-1]
        if "@" in full_username:
            return full_username.split("@")[0]
        return full_username

    def _collect_and_process(self, context: Any, connection: Any, user_profiles: dict[str, str]) -> None:
        collector = SMBCollector(connection, context.log)
        all_collected: list[CollectedConfig] = []
        all_databases: dict[str, list[OneCDatabase]] = {}
        all_launcher: dict[str, dict[str, str]] = {}
        all_servers: dict[str, list[str]] = {}
        all_onec_users: dict[str, str] = {}
        all_license_servers: list[str] = []
        server_detected = False

        # Per-user collection
        for username, profile_path in user_profiles.items():
            context.log.display(f"Collecting from: {username}")
            collected = collector.collect(username, profile_path, self._configs)
            all_collected.extend(collected)

            databases = self._parse_databases(context, collected, username)
            if databases:
                all_databases[username] = databases

            launcher = self._parse_launcher(collected)
            if launcher:
                all_launcher[username] = launcher

            servers = self._parse_app_servers(collected)
            if servers:
                all_servers[username] = servers

            onec_user = self._parse_def_usr(collected)
            if onec_user:
                all_onec_users[username] = onec_user
                context.log.display(f"  Last 1C user: {onec_user}")

            license_addrs = self._parse_nethasp(collected)
            all_license_servers.extend(a for a in license_addrs if a not in all_license_servers)

        # Server-side detection (admin only)
        if getattr(connection, "admin_privs", False):
            context.log.display("Checking for 1C Server components...")
            srv_configs, srv_detected = collector.collect_server_configs()
            if srv_detected:
                server_detected = True
                context.log.highlight("  1C Application Server detected on this host")
            all_collected.extend(srv_configs)

            srv_license = self._parse_server_nethasp(srv_configs)
            all_license_servers.extend(a for a in srv_license if a not in all_license_servers)

        if all_license_servers:
            context.log.highlight(f"  License servers: {', '.join(all_license_servers)}")

        if not all_collected:
            context.log.display("No 1C configuration files found")
            return

        if self.export:
            try:
                exporter = ConfigExporter(self.output_dir, context.log)
                host_info: dict[str, Any] = {
                    "ip": getattr(connection, "host", "unknown"),
                    "hostname": getattr(connection, "hostname", None),
                    "domain": getattr(connection, "domain", None),
                    "server_detected": server_detected,
                }
                exporter.export(
                    host_info=host_info,
                    collected=all_collected,
                    databases=all_databases,
                    user_profiles=user_profiles,
                    launcher_settings=all_launcher or None,
                    app_servers=all_servers or None,
                    onec_users=all_onec_users or None,
                    license_servers=all_license_servers or None,
                )
            except Exception as e:
                context.log.fail(f"Export failed: {e}")

    def _parse_databases(
        self,
        context: Any,
        collected: Sequence[CollectedConfig],
        username: str,
    ) -> list[OneCDatabase]:
        databases: list[OneCDatabase] = []
        ibases_configs = [c for c in collected if c.config.config_type == ConfigType.IBASES]

        if not ibases_configs:
            return databases

        try:
            for config in ibases_configs:
                parsed = list(self._ibases_parser.parse(config.content, config.config))
                databases.extend(parsed)

            if databases:
                context.log.display(f"  1C Databases for {username}:")
                for db in databases:
                    if db.connection_type == "server":
                        server_str = f"{db.server}:{db.port}" if db.port else db.server
                        context.log.highlight(f"    Server: {server_str}")
                        if db.database:
                            context.log.highlight(f"    Database: {db.database}")
                    elif db.connection_type == "file":
                        context.log.highlight(f"    File: {db.file_path}")
                    name_str = db.name
                    if db.version:
                        name_str += f" (v{db.version})"
                    context.log.display(f"    Name: {name_str}")
                    context.log.display("    ---")
        except Exception as e:
            context.log.fail(f"Parse error for {username}: {e}")

        return databases

    def _parse_launcher(self, collected: Sequence[CollectedConfig]) -> dict[str, str] | None:
        for c in collected:
            if c.config.config_type == ConfigType.LAUNCHER:
                try:
                    settings = list(self._launcher_parser.parse(c.content, c.config))
                    return settings[0] if settings else None
                except Exception:
                    return None
        return None

    def _parse_app_servers(self, collected: Sequence[CollectedConfig]) -> list[str] | None:
        for c in collected:
            if c.config.config_type == ConfigType.SERVERS:
                try:
                    servers = list(self._servers_parser.parse(c.content, c.config))
                    return servers or None
                except Exception:
                    return None
        return None

    def _parse_def_usr(self, collected: Sequence[CollectedConfig]) -> str | None:
        for c in collected:
            if c.config.config_type == ConfigType.USER:
                try:
                    users = list(self._defusr_parser.parse(c.content, c.config))
                    return users[0] if users else None
                except Exception:
                    return None
        return None

    def _parse_nethasp(self, collected: Sequence[CollectedConfig]) -> list[str]:
        addrs: list[str] = []
        for c in collected:
            if c.config.config_type == ConfigType.LICENSE:
                with contextlib.suppress(Exception):
                    addrs.extend(self._nethasp_parser.parse(c.content, c.config))
        return addrs

    def _parse_server_nethasp(self, collected: Sequence[CollectedConfig]) -> list[str]:
        return self._parse_nethasp(collected)
