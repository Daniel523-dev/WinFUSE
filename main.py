import os, time, ctypes, shutil, stat, uuid, threading, sqlite3
from dataclasses import dataclass
from ctypes import wintypes
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
MOUNT_DIR = None
RESET_MOUNT = False
JOURNAL_PATH = ".\\sync_journal.db"
REFRESH_INTERVAL = 5
PROVIDER_NAME = "PythonCfApiMirror"
PROVIDER_VERSION = "1.0"
ACTIVE_BACKING_STORE = None
@dataclass(frozen=True)
class BackingStat:
    is_directory: bool
    size: int
    creation_time: float
    access_time: float
    modified_time: float
class BackingStore:
    def initialize(self):pass
    def listdir(self, relative_path):raise NotImplementedError
    def stat(self, relative_path):raise NotImplementedError
    def open_read(self, relative_path):raise NotImplementedError
    def write_file_from_local(self, source_path, relative_path):raise NotImplementedError
    def make_directory(self, relative_path):raise NotImplementedError
    def lexists(self, relative_path):raise NotImplementedError
    def delete(self, relative_path, is_directory):raise NotImplementedError
    def move(self, source_relative_path, destination_relative_path):raise NotImplementedError
    def describe(self):return type(self).__name__
cldapi = ctypes.WinDLL("cldapi.dll", use_last_error=True)
kernel32 = ctypes.WinDLL("kernel32.dll", use_last_error=True)
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
PAGE_READWRITE = 0x04
MEM_RELEASE = 0x8000
FILE_ATTRIBUTE_NORMAL = 0x00000080
FILE_ATTRIBUTE_DIRECTORY = 0x00000010
INVALID_FILE_ATTRIBUTES = 0xFFFFFFFF
FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400
CF_CALLBACK_TYPE_FETCH_DATA = 0
CF_CALLBACK_TYPE_VALIDATE_DATA = 1
CF_CALLBACK_TYPE_CANCEL_FETCH_DATA = 2
CF_CALLBACK_TYPE_FETCH_PLACEHOLDERS = 3
CF_CALLBACK_TYPE_CANCEL_FETCH_PLACEHOLDERS = 4
CF_CALLBACK_TYPE_NONE = 0xFFFFFFFF
CF_OPERATION_TYPE_TRANSFER_DATA = 0
CF_OPERATION_TYPE_TRANSFER_PLACEHOLDERS = 4
CF_HYDRATION_POLICY_PARTIAL = 0
CF_HYDRATION_POLICY_PROGRESSIVE = 1
CF_HYDRATION_POLICY_FULL = 2
CF_HYDRATION_POLICY_ALWAYS_FULL = 3
CF_POPULATION_POLICY_PARTIAL = 0
CF_POPULATION_POLICY_FULL = 2
CF_POPULATION_POLICY_ALWAYS_FULL = 3
CF_PLACEHOLDER_CREATE_FLAG_NONE = 0x00000000
CF_PLACEHOLDER_CREATE_FLAG_DISABLE_ON_DEMAND_POPULATION = 0x00000001
CF_PLACEHOLDER_CREATE_FLAG_MARK_IN_SYNC = 0x00000002
CF_PLACEHOLDER_CREATE_FLAG_ALWAYS_FULL = 0x00000004
CF_CREATE_FLAG_NONE = 0x00000000
CF_CREATE_FLAG_STOP_ON_ERROR = 0x00000001
CF_CONNECT_FLAG_NONE = 0x00000000
CF_CONNECT_FLAG_REQUIRE_PROCESS_INFO = 0x00000002
CF_CONNECT_FLAG_REQUIRE_FULL_FILE_PATH = 0x00000004
STATUS_SUCCESS = 0
STATUS_UNSUCCESSFUL = -1073741823
HYDRATION_POLICY = CF_HYDRATION_POLICY_FULL
POPULATION_POLICY = CF_POPULATION_POLICY_ALWAYS_FULL
def hresult_unsigned(hr):return int(hr) & 0xFFFFFFFF
def hresult_hex(hr):return f"0x{hresult_unsigned(hr):08X}"
def check_hresult(hr, operation):
    hr_int = int(hr)
    if hr_int != 0:raise OSError(f"{operation} failed with HRESULT {hresult_hex(hr_int)}")
kernel32.VirtualAlloc.argtypes = [ctypes.c_void_p,ctypes.c_size_t,wintypes.DWORD,wintypes.DWORD,]
kernel32.VirtualAlloc.restype = ctypes.c_void_p
kernel32.VirtualFree.argtypes = [ctypes.c_void_p,ctypes.c_size_t,wintypes.DWORD,]
kernel32.VirtualFree.restype = wintypes.BOOL
kernel32.GetFileAttributesW.argtypes = [wintypes.LPCWSTR]
kernel32.GetFileAttributesW.restype = wintypes.DWORD
kernel32.DeleteFileW.argtypes = [wintypes.LPCWSTR]
kernel32.DeleteFileW.restype = wintypes.BOOL
kernel32.RemoveDirectoryW.argtypes = [wintypes.LPCWSTR]
kernel32.RemoveDirectoryW.restype = wintypes.BOOL
cldapi.CfRegisterSyncRoot.argtypes = [wintypes.LPCWSTR,ctypes.c_void_p,ctypes.c_void_p,wintypes.DWORD,]
cldapi.CfRegisterSyncRoot.restype = ctypes.HRESULT
cldapi.CfUnregisterSyncRoot.argtypes = [wintypes.LPCWSTR]
cldapi.CfUnregisterSyncRoot.restype = ctypes.HRESULT
cldapi.CfConnectSyncRoot.argtypes = [wintypes.LPCWSTR,ctypes.c_void_p,ctypes.c_void_p,wintypes.DWORD,ctypes.POINTER(ctypes.c_int64),]
cldapi.CfConnectSyncRoot.restype = ctypes.HRESULT
cldapi.CfDisconnectSyncRoot.argtypes = [ctypes.c_int64]
cldapi.CfDisconnectSyncRoot.restype = ctypes.HRESULT
cldapi.CfExecute.argtypes = [ctypes.c_void_p,ctypes.c_void_p,]
cldapi.CfExecute.restype = ctypes.HRESULT
class GUID(ctypes.Structure):_fields_ = [("Data1", wintypes.DWORD),("Data2", wintypes.WORD),("Data3", wintypes.WORD),("Data4", ctypes.c_ubyte * 8),]
class LARGE_INTEGER(ctypes.Union):_fields_ = [("LowPart", wintypes.DWORD),("HighPart", wintypes.LONG),("QuadPart", ctypes.c_int64),]
class FILE_BASIC_INFO(ctypes.Structure):_fields_ = [("CreationTime", LARGE_INTEGER),("LastAccessTime", LARGE_INTEGER),("LastWriteTime", LARGE_INTEGER),("ChangeTime", LARGE_INTEGER),("FileAttributes", wintypes.DWORD),("Reserved", wintypes.DWORD),]
class CF_FS_METADATA(ctypes.Structure):_fields_ = [("BasicInfo", FILE_BASIC_INFO),("FileSize", LARGE_INTEGER),]
class CF_PLACEHOLDER_CREATE_INFO(ctypes.Structure):_fields_ = [("RelativeFileName", wintypes.LPCWSTR),("FsMetadata", CF_FS_METADATA),("FileIdentity", ctypes.c_void_p),("FileIdentityLength", wintypes.DWORD),("Flags", wintypes.DWORD),("Result", wintypes.LONG),("CreateUsn", ctypes.c_int64),]
class CF_HYDRATION_POLICY(ctypes.Structure):_fields_ = [("Primary", wintypes.USHORT),("Modifier", wintypes.USHORT),]
class CF_POPULATION_POLICY(ctypes.Structure):_fields_ = [("Primary", wintypes.USHORT),("Modifier", wintypes.USHORT),]
class CF_SYNC_POLICIES(ctypes.Structure):_fields_ = [("StructSize", wintypes.ULONG),("Hydration", CF_HYDRATION_POLICY),("Population", CF_POPULATION_POLICY),("InSync", wintypes.ULONG),("HardLink", wintypes.ULONG),("PlaceholderManagement", wintypes.ULONG),]
class CF_SYNC_REGISTRATION(ctypes.Structure):_fields_ = [("StructSize", wintypes.ULONG),("ProviderName", wintypes.LPCWSTR),("ProviderVersion", wintypes.LPCWSTR),("SyncRootIdentity", ctypes.c_void_p),("SyncRootIdentityLength", wintypes.DWORD),("FileIdentity", ctypes.c_void_p),("FileIdentityLength", wintypes.DWORD),("ProviderId", GUID),]
class CF_CALLBACK_REGISTRATION(ctypes.Structure):_fields_ = [("Type", wintypes.DWORD),("Callback", ctypes.c_void_p),]
class CF_CALLBACK_INFO(ctypes.Structure):_fields_ = [("StructSize", wintypes.DWORD),("ConnectionKey", ctypes.c_int64),("CallbackContext", ctypes.c_void_p),("VolumeGuidName", wintypes.LPCWSTR),("VolumeDosName", wintypes.LPCWSTR),("VolumeSerialNumber", wintypes.DWORD),("SyncRootFileId", LARGE_INTEGER),("SyncRootIdentity", ctypes.c_void_p),("SyncRootIdentityLength", wintypes.DWORD),("FileId", LARGE_INTEGER),("FileSize", LARGE_INTEGER),("FileIdentity", ctypes.c_void_p),("FileIdentityLength", wintypes.DWORD),("NormalizedPath", wintypes.LPCWSTR),("TransferKey", ctypes.c_int64),("PriorityHint", ctypes.c_ubyte),("CorrelationVector", ctypes.c_void_p),("ProcessInfo", ctypes.c_void_p),("RequestKey", ctypes.c_int64),]
class _FETCH_DATA_PARAMS(ctypes.Structure):_fields_ = [("Flags", wintypes.DWORD),("Padding", wintypes.DWORD),("RequiredFileOffset", LARGE_INTEGER),("RequiredLength", LARGE_INTEGER),("OptionalFileOffset", LARGE_INTEGER),("OptionalLength", LARGE_INTEGER),("LastDehydrationTime", LARGE_INTEGER),("LastDehydrationReason", wintypes.DWORD),]
class _CF_CALLBACK_PARAMETERS_UNION(ctypes.Union):_fields_ = [("FetchData", _FETCH_DATA_PARAMS),]
class CF_CALLBACK_PARAMETERS(ctypes.Structure):_fields_ = [("ParamSize", wintypes.ULONG),("Union", _CF_CALLBACK_PARAMETERS_UNION),]
class _TRANSFER_DATA(ctypes.Structure):_fields_ = [("Flags", wintypes.DWORD),("CompletionStatus", wintypes.LONG),("Buffer", ctypes.c_void_p),("Offset", LARGE_INTEGER),("Length", LARGE_INTEGER),]
class _CF_OPERATION_PARAMETERS_UNION(ctypes.Union):_fields_ = [("TransferData", _TRANSFER_DATA),]
class CF_OPERATION_PARAMETERS(ctypes.Structure):_fields_ = [("ParamSize", wintypes.ULONG),("Union", _CF_OPERATION_PARAMETERS_UNION),]
class CF_OPERATION_INFO(ctypes.Structure):_fields_ = [("StructSize", wintypes.ULONG),("Type", wintypes.ULONG),("ConnectionKey", ctypes.c_int64),("TransferKey", ctypes.c_int64),("CorrelationVector", ctypes.c_void_p),("SyncStatus", ctypes.c_void_p),("RequestKey", ctypes.c_int64),]
TRANSFER_DATA_PARAM_SIZE = (CF_OPERATION_PARAMETERS.Union.offset + ctypes.sizeof(_TRANSFER_DATA))
cldapi.CfCreatePlaceholders.argtypes = [wintypes.LPCWSTR,ctypes.POINTER(CF_PLACEHOLDER_CREATE_INFO),wintypes.DWORD,wintypes.DWORD,ctypes.POINTER(wintypes.DWORD),]
cldapi.CfCreatePlaceholders.restype = ctypes.HRESULT
CF_CALLBACK_FUNC = ctypes.WINFUNCTYPE(None,ctypes.c_void_p,ctypes.c_void_p,)
def create_guid():
    value = uuid.uuid4()
    guid = GUID()
    ctypes.memmove(ctypes.byref(guid),value.bytes_le,ctypes.sizeof(GUID),)
    return guid
def unix_time_to_filetime(value):return int(value * 10_000_000 + 116_444_736_000_000_000)
def make_large_integer(value):
    li = LARGE_INTEGER()
    li.QuadPart = int(value)
    return li
def get_win_attributes(path):
    attrs = kernel32.GetFileAttributesW(path)
    if attrs == INVALID_FILE_ATTRIBUTES:return None
    return attrs
def make_identity(relative_path):
    relative_path = relative_path.replace("/", "\\")
    buffer = ctypes.create_unicode_buffer(relative_path)
    length = ((len(relative_path) + 1) * ctypes.sizeof(ctypes.c_wchar))
    return buffer, length
def join_backend_path(parent, child):return child if not parent else f"{parent}/{child}"
def mount_path_to_backend_path(mount_path):
    mount_path = os.path.abspath(os.path.normpath(mount_path))
    mount_root = os.path.abspath(os.path.normpath(MOUNT_DIR))
    try:relative = os.path.relpath(mount_path, mount_root)
    except ValueError:return None
    if relative == ".":return ""
    if relative == ".." or relative.startswith(".." + os.sep) or os.path.isabs(relative):return None
    return relative.replace(os.sep, "/")
def callback_path_to_backend_path(info):
    volume = info.VolumeDosName
    normalized = info.NormalizedPath
    if not volume or not normalized:
        print("[Path] Missing callback path information:")
        print(f"       VolumeDosName={volume!r}")
        print(f"       NormalizedPath={normalized!r}")
        return None
    full_mount_path = os.path.normpath(volume + normalized)
    return mount_path_to_backend_path(full_mount_path)
def reset_mount_directory():
    if os.path.exists(MOUNT_DIR):shutil.rmtree(MOUNT_DIR,ignore_errors=True)
    os.makedirs(MOUNT_DIR, exist_ok=True)
def build_placeholder_info(backend_directory, entry_name, st):
    is_directory = st.is_directory
    placeholder = CF_PLACEHOLDER_CREATE_INFO()
    name_buffer = ctypes.create_unicode_buffer(entry_name)
    placeholder.RelativeFileName = ctypes.cast(name_buffer,wintypes.LPCWSTR,)
    placeholder.FsMetadata.BasicInfo.CreationTime = make_large_integer(unix_time_to_filetime(st.creation_time))
    placeholder.FsMetadata.BasicInfo.LastAccessTime = make_large_integer(unix_time_to_filetime(st.access_time))
    placeholder.FsMetadata.BasicInfo.LastWriteTime = make_large_integer(unix_time_to_filetime(st.modified_time))
    placeholder.FsMetadata.BasicInfo.ChangeTime = make_large_integer(unix_time_to_filetime(st.modified_time))
    placeholder.FsMetadata.BasicInfo.FileAttributes = (FILE_ATTRIBUTE_DIRECTORY
        if is_directory
        else FILE_ATTRIBUTE_NORMAL)
    placeholder.FsMetadata.BasicInfo.Reserved = 0
    placeholder.FsMetadata.FileSize = make_large_integer(0 if is_directory else st.size)
    relative_identity = join_backend_path(backend_directory,entry_name,)
    identity_buffer, identity_length = make_identity(relative_identity)
    placeholder.FileIdentity = ctypes.cast(identity_buffer,ctypes.c_void_p,)
    placeholder.FileIdentityLength = identity_length
    placeholder.Flags = CF_PLACEHOLDER_CREATE_FLAG_MARK_IN_SYNC
    if is_directory:
        placeholder.Flags |= (CF_PLACEHOLDER_CREATE_FLAG_DISABLE_ON_DEMAND_POPULATION)
    placeholder.Result = 0
    placeholder.CreateUsn = 0
    return (placeholder,name_buffer,identity_buffer,relative_identity,)
def create_placeholders_in_directory(backend,backend_directory,mount_directory,):
    os.makedirs(mount_directory, exist_ok=True)
    entries = []
    keep_alive = []
    for entry_name in sorted(backend.listdir(backend_directory)):
        backend_path = join_backend_path(backend_directory,entry_name,)
        try:
            st = backend.stat(backend_path)
        except OSError as exc:
            print(f"[Placeholder] stat failed for {backend_path!r}: {exc}")
            continue
        (placeholder,name_buffer,identity_buffer,relative_identity,) = build_placeholder_info(backend_directory,entry_name,st,)
        entries.append(placeholder)
        keep_alive.append(name_buffer)
        keep_alive.append(identity_buffer)
    if not entries:return
    array_type = CF_PLACEHOLDER_CREATE_INFO * len(entries)
    placeholder_array = array_type()
    for index, item in enumerate(entries):
        placeholder_array[index] = item
    processed = wintypes.DWORD(0)
    hr = cldapi.CfCreatePlaceholders(ctypes.c_wchar_p(mount_directory),placeholder_array,len(entries),CF_CREATE_FLAG_NONE,ctypes.byref(processed),)
    check_hresult(hr,f"CfCreatePlaceholders({mount_directory})",)
    for entry_name in sorted(backend.listdir(backend_directory)):
        backend_path = join_backend_path(backend_directory,entry_name,)
        if not backend.stat(backend_path).is_directory:
            continue
        child_mount_directory = os.path.join(mount_directory,entry_name,)
        if not os.path.isdir(child_mount_directory):
            print(f"[Placeholder] Expected directory was not created: {child_mount_directory}")
            continue
        create_placeholders_in_directory(backend,backend_path,child_mount_directory,)
def create_single_placeholder(backend, backend_directory, entry_name, mount_directory):
    backend_path = join_backend_path(backend_directory, entry_name)
    st = backend.stat(backend_path)
    placeholder, name_buffer, identity_buffer, relative_identity = build_placeholder_info(backend_directory, entry_name, st)
    array_type = CF_PLACEHOLDER_CREATE_INFO * 1
    placeholder_array = array_type(placeholder)
    processed = wintypes.DWORD(0)
    hr = cldapi.CfCreatePlaceholders(ctypes.c_wchar_p(mount_directory),placeholder_array,1,CF_CREATE_FLAG_NONE,ctypes.byref(processed))
    check_hresult(hr, f"CfCreatePlaceholders({mount_directory})")
def remove_stale_mount_entry(path, mark_internal=None):
    path = os.path.abspath(path)
    try:
        attrs = get_win_attributes(path)
        if attrs is None:return True
        if mark_internal is not None:mark_internal(path)
        if attrs & FILE_ATTRIBUTE_DIRECTORY:
            try:children = os.listdir(path)
            except OSError as exc:
                print(f"[Refresh] Could not enumerate stale directory {path!r}: {exc}")
                return False
            success = True
            for name in children:
                if not remove_stale_mount_entry(os.path.join(path, name), mark_internal):success = False
            if not success:return False
            ok = kernel32.RemoveDirectoryW(path)
        else:ok = kernel32.DeleteFileW(path)
        if ok:
            print(f"[Refresh] Removed stale cloud entry: {path}")
            return True
        error = ctypes.get_last_error()
        print(f"[Refresh] Failed to remove stale cloud entry {path!r}: Win32 error {error}")
        return False
    except FileNotFoundError:return True
    except Exception as exc:
        print(f"[Refresh] Failed to remove stale entry {path!r}: {exc}")
        return False
def refresh_directory(backend, backend_directory, mount_directory, is_busy, mark_internal=None):
    if is_busy(backend_directory):return
    os.makedirs(mount_directory, exist_ok=True)
    try:backend_names = set(backend.listdir(backend_directory))
    except OSError as exc:
        print(f"[Refresh] Failed to list {backend_directory!r}: {exc}")
        return
    try:mount_names = set(os.listdir(mount_directory))
    except OSError as exc:
        print(f"[Refresh] Failed to list mount {mount_directory!r}: {exc}")
        return
    for name in sorted(backend_names - mount_names):
        if is_busy(join_backend_path(backend_directory, name)):continue
        try:create_single_placeholder(backend,backend_directory,name,mount_directory)
        except Exception as exc:print(f"[Refresh] Failed to create {name!r}: {exc}")
    for name in sorted(mount_names - backend_names):
        backend_path = join_backend_path(backend_directory, name)
        if is_busy(backend_path):continue
        remove_stale_mount_entry(os.path.join(mount_directory, name), mark_internal)
    for name in sorted(backend_names & mount_names):
        backend_path = join_backend_path(backend_directory, name)
        try:st = backend.stat(backend_path)
        except OSError:continue
        if not st.is_directory:continue
        child_mount = os.path.join(mount_directory, name)
        if is_busy(backend_path):continue
        refresh_directory(backend,backend_path,child_mount,is_busy,mark_internal)
def refresh_mount(backend, mount_directory, is_busy, mark_internal=None):refresh_directory(backend, "", mount_directory, is_busy, mark_internal)
def create_initial_namespace(backend):create_placeholders_in_directory(backend,"",MOUNT_DIR,)
FETCH_CHUNK_SIZE = 16 * 1024 * 1024
def on_fetch_data(callback_info_ptr, callback_parameters_ptr):
    info = ctypes.cast(callback_info_ptr,ctypes.POINTER(CF_CALLBACK_INFO),).contents
    params = ctypes.cast(callback_parameters_ptr,ctypes.POINTER(CF_CALLBACK_PARAMETERS),).contents
    offset = (params.Union.FetchData.RequiredFileOffset.QuadPart)
    length = (params.Union.FetchData.RequiredLength.QuadPart)
    backend = ACTIVE_BACKING_STORE
    if backend is None:
        print("[Fetch] No backing store is active.")
        return
    backend_path = callback_path_to_backend_path(info)
    if backend_path is None:
        print("[Fetch] Could not resolve backing path.")
        return
    connection_key = info.ConnectionKey
    transfer_key = info.TransferKey
    request_key = info.RequestKey
    def worker():
        try:
            file_size = backend.stat(backend_path).size
            if offset < 0 or length < 0 or offset > file_size:raise ValueError(f"Invalid fetch range: offset={offset}, length={length}, size={file_size}")
            end_offset = min(offset + length, file_size)
            with backend.open_read(backend_path) as f:
                current_offset = offset
                while current_offset < end_offset:
                    remaining = end_offset - current_offset
                    chunk_size = min(FETCH_CHUNK_SIZE, remaining)
                    if current_offset + chunk_size < end_offset:chunk_size &= ~0xFFF
                    if chunk_size <= 0:raise ValueError(f"Invalid chunk size at offset {current_offset}")
                    f.seek(current_offset)
                    data = f.read(chunk_size)
                    if len(data) != chunk_size:raise IOError(f"Short read: wanted {chunk_size}, got {len(data)}")
                    data_len = len(data)
                    alloc_size = (data_len + 4095) & ~4095
                    buffer_ptr = kernel32.VirtualAlloc(None,alloc_size,MEM_COMMIT | MEM_RESERVE,PAGE_READWRITE,)
                    if not buffer_ptr:raise MemoryError("VirtualAlloc failed")
                    try:
                        ctypes.memmove(buffer_ptr,data,data_len,)
                        op_info = CF_OPERATION_INFO()
                        op_info.StructSize = ctypes.sizeof(CF_OPERATION_INFO)
                        op_info.Type = CF_OPERATION_TYPE_TRANSFER_DATA
                        op_info.ConnectionKey = connection_key
                        op_info.TransferKey = transfer_key
                        op_info.CorrelationVector = None
                        op_info.SyncStatus = None
                        op_info.RequestKey = request_key
                        op_params = CF_OPERATION_PARAMETERS()
                        op_params.ParamSize = TRANSFER_DATA_PARAM_SIZE
                        op_params.Union.TransferData.Flags = 0
                        op_params.Union.TransferData.CompletionStatus = (STATUS_SUCCESS)
                        op_params.Union.TransferData.Buffer = buffer_ptr
                        op_params.Union.TransferData.Offset = make_large_integer(current_offset)
                        op_params.Union.TransferData.Length = make_large_integer(data_len)
                        hr = cldapi.CfExecute(ctypes.byref(op_info),ctypes.byref(op_params),)
                        if hr != 0:raise OSError(f"CfExecute failed: {hresult_hex(hr)}")
                    finally:kernel32.VirtualFree(buffer_ptr,0,MEM_RELEASE,)
                    current_offset += data_len
        except Exception as exc:
            print(f"[Fetch] Worker error: {exc}")
            try:
                op_info = CF_OPERATION_INFO()
                op_info.StructSize = ctypes.sizeof(CF_OPERATION_INFO)
                op_info.Type = CF_OPERATION_TYPE_TRANSFER_DATA
                op_info.ConnectionKey = connection_key
                op_info.TransferKey = transfer_key
                op_info.CorrelationVector = None
                op_info.SyncStatus = None
                op_info.RequestKey = request_key
                op_params = CF_OPERATION_PARAMETERS()
                op_params.ParamSize = TRANSFER_DATA_PARAM_SIZE
                op_params.Union.TransferData.Flags = 0
                op_params.Union.TransferData.CompletionStatus = (STATUS_UNSUCCESSFUL)
                op_params.Union.TransferData.Buffer = None
                op_params.Union.TransferData.Offset = make_large_integer(offset)
                op_params.Union.TransferData.Length = make_large_integer(0)
                hr = cldapi.CfExecute(ctypes.byref(op_info),ctypes.byref(op_params),)
                print(f"[Fetch] Failure response -> {hresult_hex(hr)}")
            except Exception as fail_exc:print(f"[Fetch] Failed to report error: {fail_exc}")
    threading.Thread(target=worker,name="CfFetchData",daemon=True,).start()
cb_fetch_data = CF_CALLBACK_FUNC(on_fetch_data)
CALLBACK_REGISTRATIONS = (CF_CALLBACK_REGISTRATION * 2)()
CALLBACK_REGISTRATIONS[0].Callback = ctypes.cast(cb_fetch_data,ctypes.c_void_p,)
CALLBACK_REGISTRATIONS[1].Type = CF_CALLBACK_TYPE_NONE
CALLBACK_REGISTRATIONS[1].Callback = None
def is_temporary_file(path):
    name = os.path.basename(path).lower()
    return (name.endswith(".tmp") or "~rf" in name)
class SyncJournal:
    def __init__(self, path):
        self.path = os.path.abspath(path)
        self._lock = threading.RLock()
        self._db = None
    def initialize(self):
        os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
        self._db = sqlite3.connect(self.path, check_same_thread=False)
        self._db.execute("CREATE TABLE IF NOT EXISTS operations (id INTEGER PRIMARY KEY AUTOINCREMENT, operation TEXT NOT NULL, source_path TEXT, destination_path TEXT, backend_path TEXT, is_directory INTEGER NOT NULL DEFAULT 0, created_at REAL NOT NULL)")
        self._db.commit()
    def cancel_writes_for(self, source_path=None, backend_path=None):
        with self._lock:
            conditions = []
            values = []
            if source_path is not None:
                conditions.append("source_path=?")
                values.append(os.path.abspath(source_path))
            if backend_path is not None:
                conditions.append("backend_path=?")
                values.append(backend_path.replace("\\", "/"))
            if not conditions:return
            self._db.execute(f"DELETE FROM operations WHERE operation='write' AND ({' OR '.join(conditions)}) ",values)
            self._db.commit()
    def add(self, operation, source_path=None, destination_path=None,backend_path=None, is_directory=False):
        with self._lock:
            cursor = self._db.execute("INSERT INTO operations (operation, source_path, destination_path, backend_path,is_directory, created_at) VALUES (?, ?, ?, ?, ?, ?)",(operation, source_path, destination_path, backend_path,int(is_directory), time.time()))
            self._db.commit()
            return cursor.lastrowid
    def remove(self, operation_id):
        with self._lock:
            self._db.execute("DELETE FROM operations WHERE id=?", (operation_id,))
            self._db.commit()
    def pending(self):
        with self._lock:rows = self._db.execute("SELECT id, operation, source_path, destination_path, backend_path, is_directory FROM operations ORDER BY id").fetchall()
        return [{"id": row[0], "operation": row[1], "source_path": row[2], "destination_path": row[3], "backend_path": row[4], "is_directory": bool(row[5])} for row in rows]
    def close(self):
        with self._lock:
            if self._db is not None:
                self._db.close()
                self._db = None
class MountSyncHandler(FileSystemEventHandler):
    def __init__(self, mount_dir, backing_store, journal):
        super().__init__()
        self.mount_dir = os.path.abspath(mount_dir)
        self.backing_store = backing_store
        self.journal = journal
        self._lock = threading.RLock()
        self._active_folders = set()
        self._internal_paths = {}
    def _get_backend_path(self, mount_path):return mount_path_to_backend_path(mount_path)
    def _folder_for(self, backend_path):return os.path.dirname(backend_path).replace("\\", "/")
    def _mark_internal(self, path):
        with self._lock:self._internal_paths[os.path.abspath(path)] = time.monotonic() + 2.0
    def _is_internal(self, path):
        path = os.path.abspath(path)
        now = time.monotonic()
        with self._lock:
            expired = [p for p, expiry in self._internal_paths.items() if expiry <= now]
            for p in expired:del self._internal_paths[p]
            for internal_path in self._internal_paths:
                if (path == internal_path or path.startswith(internal_path + os.sep)):return True
        return False
    def _begin_operation(self, folders):
        folders = {folder.replace("\\", "/").rstrip("/") for folder in folders if folder is not None}
        with self._lock:self._active_folders.update(folders)
        return folders
    def _end_operation(self, folders):
        with self._lock:
            for folder in folders:self._active_folders.discard(folder)
    def is_folder_busy(self, backend_path):
        backend_path = backend_path.replace("\\", "/").rstrip("/")
        with self._lock:
            for folder in self._active_folders:
                if not folder:return True
                if backend_path == folder or backend_path.startswith(folder + "/") or folder.startswith(backend_path + "/"):return True
        return False
    def _run_journaled(self, operation, folders, **kwargs):
        journal_id = self.journal.add(operation, **kwargs)
        active = self._begin_operation(folders)
        try:
            if operation == "write":self._copy_file_now(kwargs["source_path"],kwargs["backend_path"])
            elif operation == "mkdir":self.backing_store.make_directory(kwargs["backend_path"])
            elif operation == "delete":self.backing_store.delete(kwargs["backend_path"],kwargs["is_directory"])
            elif operation == "move":self.backing_store.move(kwargs["source_path"],kwargs["destination_path"])
            else:raise ValueError(f"Unknown journal operation: {operation}")
            self.journal.remove(journal_id)
        finally:self._end_operation(active)
    def _copy_file_now(self, source_path, backend_path):
        for attempt in range(10):
            try:
                if not os.path.isfile(source_path):raise FileNotFoundError(source_path)
                time.sleep(0.05)
                self.backing_store.write_file_from_local(source_path,backend_path)
                return
            except (PermissionError, OSError) as exc:
                if attempt == 9:raise
                time.sleep(0.10 * (attempt + 1))
    def _copy_file(self, source_path, backend_path):
        folder = self._folder_for(backend_path)
        try:self._run_journaled("write",{folder},source_path=os.path.abspath(source_path),backend_path=backend_path)
        except Exception as exc:print(f"[Sync] Failed to store {source_path!r} -> {backend_path!r}: {exc}")
    def on_created(self, event):
        if self._is_internal(event.src_path):return
        if not event.is_directory and is_temporary_file(event.src_path):return
        backend_path = self._get_backend_path(event.src_path)
        if backend_path is None:return
        if event.is_directory:
            try:self._run_journaled("mkdir",{backend_path},backend_path=backend_path,is_directory=True)
            except Exception as exc:print(f"[Sync] Directory creation failed: {exc}")
            return
        self._copy_file(event.src_path, backend_path)
    def on_modified(self, event):
        if event.is_directory or self._is_internal(event.src_path):return
        backend_path = self._get_backend_path(event.src_path)
        if backend_path is None:return
        self._copy_file(event.src_path, backend_path)
    def on_deleted(self, event):
        if self._is_internal(event.src_path):return
        backend_path = self._get_backend_path(event.src_path)
        if backend_path is None:return
        self.journal.cancel_writes_for(source_path=event.src_path, backend_path=backend_path)
        if not self.backing_store.lexists(backend_path):return
        try:
            folder = self._folder_for(backend_path)
            self._run_journaled("delete",{folder},backend_path=backend_path,is_directory=event.is_directory)
        except Exception as exc:print(f"[Sync] Delete failed: {exc}")
    def on_moved(self, event):
        if self._is_internal(event.src_path) or self._is_internal(event.dest_path):return
        source_backend = self._get_backend_path(event.src_path)
        destination_backend = self._get_backend_path(event.dest_path)
        if source_backend is None or destination_backend is None:return
        source_folder = self._folder_for(source_backend)
        destination_folder = self._folder_for(destination_backend)
        if not self.backing_store.lexists(source_backend):
            if not event.is_directory:self._copy_file(event.dest_path, destination_backend)
            return
        try:self._run_journaled("move",{source_folder, destination_folder},source_path=source_backend,destination_path=destination_backend,is_directory=event.is_directory)
        except Exception as exc:print(f"[Sync] Move failed: {exc}")
def register_sync_root():
    registration = CF_SYNC_REGISTRATION()
    registration.StructSize = ctypes.sizeof(CF_SYNC_REGISTRATION)
    registration.ProviderName = ctypes.c_wchar_p(PROVIDER_NAME)
    registration.ProviderVersion = ctypes.c_wchar_p(PROVIDER_VERSION)
    registration.SyncRootIdentity = None
    registration.SyncRootIdentityLength = 0
    registration.FileIdentity = None
    registration.FileIdentityLength = 0
    registration.ProviderId = create_guid()
    policies = CF_SYNC_POLICIES()
    policies.StructSize = ctypes.sizeof(CF_SYNC_POLICIES)
    policies.Hydration.Primary = HYDRATION_POLICY
    policies.Hydration.Modifier = 0
    policies.Population.Primary = POPULATION_POLICY
    policies.Population.Modifier = 0
    policies.InSync = 0
    policies.HardLink = 0
    policies.PlaceholderManagement = 0
    hr = cldapi.CfRegisterSyncRoot(ctypes.c_wchar_p(MOUNT_DIR),ctypes.byref(registration),ctypes.byref(policies),0,)
    check_hresult(hr, "CfRegisterSyncRoot")
def unregister_sync_root():
    try:
        hr = cldapi.CfUnregisterSyncRoot(ctypes.c_wchar_p(MOUNT_DIR))
        if hr != 0:print("[*] Sync root was not registered: {hresult_hex(hr)}")
    except Exception as exc:
        err=f"[!] Unregister error: {exc}"
        if "-2147024506" not in err:print(err)
def connect_sync_root():
    connection_key = ctypes.c_int64(0)
    connect_flags = (CF_CONNECT_FLAG_REQUIRE_PROCESS_INFO | CF_CONNECT_FLAG_REQUIRE_FULL_FILE_PATH)
    hr = cldapi.CfConnectSyncRoot(ctypes.c_wchar_p(MOUNT_DIR),ctypes.byref(CALLBACK_REGISTRATIONS),None,connect_flags,ctypes.byref(connection_key),)
    check_hresult(hr, "CfConnectSyncRoot")
    return connection_key.value
def replay_journal(journal, backing_store):
    pending = journal.pending()
    if not pending:
        print("[Journal] No pending operations.")
        return
    print(f"[Journal] Resuming {len(pending)} pending operation(s)...")
    for item in pending:
        operation_id = item["id"]
        operation = item["operation"]
        try:
            if operation == "write":
                source_path = item["source_path"]
                if not os.path.isfile(source_path):
                    print(f"[Journal] Source no longer exists, {source_path!r}")
                    journal.remove(operation_id)
                    continue
                backing_store.write_file_from_local(source_path,item["backend_path"])
            elif operation == "mkdir":backing_store.make_directory(item["backend_path"])
            elif operation == "delete":
                if backing_store.lexists(item["backend_path"]):backing_store.delete(item["backend_path"],item["is_directory"])
            elif operation == "move":
                source = item["source_path"]
                destination = item["destination_path"]
                if backing_store.lexists(source):backing_store.move(source, destination)
            else:
                print(f"[Journal] Unknown operation #{operation_id}: {operation!r}")
                continue
            journal.remove(operation_id)
            print(f"[Journal] Resumed operation #{operation_id}: {operation}")
        except Exception as exc:print(f"[Journal] Operation #{operation_id} failed again: {exc}")
def main(backing_store, mount_dir):
    global ACTIVE_BACKING_STORE, MOUNT_DIR
    MOUNT_DIR = os.path.abspath(mount_dir)
    if os.name != "nt":raise RuntimeError("This program requires Windows.")
    if backing_store is None:raise ValueError("A backing store is required.")
    if ACTIVE_BACKING_STORE is not None:raise RuntimeError("A Cloud Files mirror is already running.")
    ACTIVE_BACKING_STORE = backing_store
    backing_store.initialize()
    os.makedirs(MOUNT_DIR, exist_ok=True)
    journal = SyncJournal(JOURNAL_PATH)
    journal.initialize()
    connection_key = None
    observer = None
    refresh_thread = None
    stop_event = threading.Event()
    try:
        unregister_sync_root()
        os.makedirs(MOUNT_DIR, exist_ok=True)
        replay_journal(journal, backing_store)
        register_sync_root()
        refresh_mount(backing_store,MOUNT_DIR,lambda path: False)
        connection_key = connect_sync_root()
        event_handler = MountSyncHandler(MOUNT_DIR,backing_store,journal)
        refresh_mount(backing_store,MOUNT_DIR,event_handler.is_folder_busy,event_handler._mark_internal)
        observer = Observer()
        observer.schedule(event_handler,MOUNT_DIR,recursive=True)
        observer.start()
        def refresh_worker():
            while not stop_event.wait(REFRESH_INTERVAL):
                try:refresh_mount(backing_store,MOUNT_DIR,event_handler.is_folder_busy,event_handler._mark_internal)
                except Exception as exc:print(f"[Refresh] Error: {exc}")
        refresh_thread = threading.Thread(target=refresh_worker,name="MountRefresh",daemon=True)
        refresh_thread.start()
        print(f"[*] Mount: {MOUNT_DIR}")
        print(f"[*] Journal: {os.path.abspath(JOURNAL_PATH)}")
        print(f"[*] Namespace refresh: every {REFRESH_INTERVAL}s")
        while True:time.sleep(10)
    except KeyboardInterrupt:pass
    except Exception as exc:
        print()
        print("[!] FATAL ERROR:")
        print(f"    {exc}")
        print()
        raise
    finally:
        stop_event.set()
        if refresh_thread is not None:refresh_thread.join(timeout=2)
        if observer is not None:
            try:
                observer.stop()
                observer.join()
            except Exception as exc:print(f"[!] Watchdog shutdown error: {exc}")
        if connection_key is not None:
            try:
                hr = cldapi.CfDisconnectSyncRoot(connection_key)
                if hr != 0:print(f"[!] Disconnect failed: {hresult_hex(hr)}")
            except Exception as exc:print(f"[!] Disconnect error: {exc}")
        unregister_sync_root()
        journal.close()
        ACTIVE_BACKING_STORE = None
if __name__ == "__main__":
    class LocalStorageBackend(BackingStore):
        def __init__(self, root_directory):self.root_directory = os.path.abspath(root_directory)
        def _full_path(self, relative_path):
            if not relative_path:return self.root_directory
            relative_path = relative_path.replace("/",os.sep,)
            full_path = os.path.abspath(os.path.join(self.root_directory,relative_path,))
            try:common = os.path.commonpath([self.root_directory,full_path,])
            except ValueError:raise ValueError(f"Invalid backing path: {relative_path!r}")
            if os.path.normcase(common) != os.path.normcase(self.root_directory):raise ValueError(f"Backing path escapes root: {relative_path!r}")
            return full_path
        def initialize(self):os.makedirs(self.root_directory,exist_ok=True,)
        def listdir(self, relative_path):return os.listdir(self._full_path(relative_path))
        def stat(self, relative_path):
            st = os.stat(self._full_path(relative_path))
            return BackingStat(is_directory=stat.S_ISDIR(st.st_mode),size=st.st_size,creation_time=st.st_ctime,access_time=st.st_atime,modified_time=st.st_mtime,)
        def open_read(self, relative_path):return open(self._full_path(relative_path),"rb",)
        def write_file_from_local(self,source_path,relative_path,):
            destination_path = self._full_path(relative_path)
            os.makedirs(os.path.dirname(destination_path),exist_ok=True,)
            temporary_path = (destination_path + f".tmp.{os.getpid()}" + f".{threading.get_ident()}")
            try:
                for attempt in range(10):
                    try:
                        if not os.path.isfile(source_path):return
                        time.sleep(0.05)
                        shutil.copy2(source_path,temporary_path,)
                        os.replace(temporary_path,destination_path,)
                        return
                    except (PermissionError, OSError):
                        if attempt == 9:raise
                        time.sleep(0.10 * (attempt + 1))
            finally:
                if os.path.exists(temporary_path):
                    try:os.remove(temporary_path)
                    except OSError:pass
        def make_directory(self, relative_path):os.makedirs(self._full_path(relative_path),exist_ok=True,)
        def lexists(self, relative_path):return os.path.lexists(self._full_path(relative_path))
        def delete(self, relative_path, is_directory):
            path = self._full_path(relative_path)
            if not os.path.lexists(path):return
            if is_directory:shutil.rmtree(path,ignore_errors=True,)
            else:
                try:os.remove(path)
                except FileNotFoundError:pass
        def move(self,source_relative_path,destination_relative_path,):
            source_path = self._full_path(source_relative_path)
            destination_path = self._full_path(destination_relative_path)
            os.makedirs(os.path.dirname(destination_path),exist_ok=True,)
            if os.path.lexists(destination_path):
                if os.path.isdir(destination_path):shutil.rmtree(destination_path,ignore_errors=True,)
                else:os.remove(destination_path)
            shutil.move(source_path,destination_path,)
    main(LocalStorageBackend(".\\storage"),'.\\mount')
