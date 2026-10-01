import os, time, ctypes, shutil, stat, uuid, threading
from dataclasses import dataclass
from ctypes import wintypes
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
MOUNT_DIR = None
RESET_MOUNT = True
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
def unix_time_to_filetime(value):
    return int(value * 10_000_000 + 116_444_736_000_000_000)
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
def join_backend_path(parent, child):
    return child if not parent else f"{parent}/{child}"
def mount_path_to_backend_path(mount_path):
    mount_path = os.path.abspath(os.path.normpath(mount_path))
    mount_root = os.path.abspath(os.path.normpath(MOUNT_DIR))
    try:relative = os.path.relpath(mount_path, mount_root)
    except ValueError:return None
    if relative == ".":return ""
    if (relative == ".."
        or relative.startswith(".." + os.sep)
        or os.path.isabs(relative)):
        return None
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
    if not os.path.exists(MOUNT_DIR):
        os.makedirs(MOUNT_DIR, exist_ok=True)
        return
    for entry in os.scandir(MOUNT_DIR):
        path = entry.path
        try:
            if entry.is_dir(follow_symlinks=False):shutil.rmtree(path, ignore_errors=False)
            else:os.unlink(path)
        except Exception as exc:
            raise RuntimeError(f"Could not remove old mount entry {path!r}: {exc}\nClose every Explorer window pointing at ./mount and try again.") from exc
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
    if not entries:
        return
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
def create_initial_namespace(backend):create_placeholders_in_directory(backend,"",MOUNT_DIR,)
FETCH_CHUNK_SIZE = 1024 * 1024
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
            if offset < 0 or length < 0 or offset > file_size:
                raise ValueError(f"Invalid fetch range: offset={offset}, length={length}, size={file_size}")
            end_offset = min(offset + length, file_size)
            with backend.open_read(backend_path) as f:
                current_offset = offset
                while current_offset < end_offset:
                    remaining = end_offset - current_offset
                    chunk_size = min(FETCH_CHUNK_SIZE, remaining)
                    if current_offset + chunk_size < end_offset:
                        chunk_size &= ~0xFFF
                    if chunk_size <= 0:
                        raise ValueError(f"Invalid chunk size at offset {current_offset}")
                    f.seek(current_offset)
                    data = f.read(chunk_size)
                    if len(data) != chunk_size:
                        raise IOError(f"Short read: wanted {chunk_size}, got {len(data)}")
                    data_len = len(data)
                    alloc_size = (data_len + 4095) & ~4095
                    buffer_ptr = kernel32.VirtualAlloc(None,alloc_size,MEM_COMMIT | MEM_RESERVE,PAGE_READWRITE,)
                    if not buffer_ptr:
                        raise MemoryError("VirtualAlloc failed")
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
                        if hr != 0:
                            raise OSError(f"CfExecute failed: {hresult_hex(hr)}")
                    finally:
                        kernel32.VirtualFree(buffer_ptr,0,MEM_RELEASE,)
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
            except Exception as fail_exc:
                print(f"[Fetch] Failed to report error: {fail_exc}")
    threading.Thread(target=worker,name="CfFetchData",daemon=True,).start()
cb_fetch_data = CF_CALLBACK_FUNC(on_fetch_data)
CALLBACK_REGISTRATIONS = CF_CALLBACK_REGISTRATION * 2
CALLBACK_REGISTRATIONS = (CF_CALLBACK_REGISTRATION * 2)()
CALLBACK_REGISTRATIONS[0].Callback = ctypes.cast(cb_fetch_data,ctypes.c_void_p,)
CALLBACK_REGISTRATIONS[1].Type = CF_CALLBACK_TYPE_NONE
CALLBACK_REGISTRATIONS[1].Callback = None
class MountSyncHandler(FileSystemEventHandler):
    def __init__(self, mount_dir, backing_store):
        super().__init__()
        self.mount_dir = os.path.abspath(mount_dir)
        self.backing_store = backing_store
        self._lock = threading.RLock()
        self._pending = {}
    def _get_backend_path(self, mount_path):
        return mount_path_to_backend_path(mount_path)
    def _copy_file(self, source_path, backend_path):
        for attempt in range(10):
            try:
                if not os.path.isfile(source_path):
                    return
                time.sleep(0.05)
                self.backing_store.write_file_from_local(source_path,backend_path,)
                return
            except (PermissionError, OSError) as exc:
                if attempt == 9:
                    print(f"[Sync] Failed to store {source_path!r} -> {backend_path!r}: {exc}")
                    return
                time.sleep(0.10 * (attempt + 1))
    def on_created(self, event):
        backend_path = self._get_backend_path(event.src_path)
        if backend_path is None:
            return
        if event.is_directory:
            try:
                self.backing_store.make_directory(backend_path)
            except Exception as exc:
                print(f"[Sync] Directory creation failed: {exc}")
            return
        self._copy_file(event.src_path,backend_path,)
    def on_modified(self, event):
        if event.is_directory:
            return
        backend_path = self._get_backend_path(event.src_path)
        if backend_path is None:
            return
        self._copy_file(event.src_path,backend_path,)
    def on_deleted(self, event):
        backend_path = self._get_backend_path(event.src_path)
        if backend_path is None:
            return
        if not self.backing_store.lexists(backend_path):
            return
        try:
            self.backing_store.delete(backend_path,event.is_directory,)
        except Exception as exc:
            print(f"[Sync] Delete failed for {backend_path!r}: {exc}")
    def on_moved(self, event):
        source_backend = self._get_backend_path(event.src_path)
        destination_backend = self._get_backend_path(event.dest_path)
        if source_backend is None or destination_backend is None:
            return
        if not self.backing_store.lexists(source_backend):
            if not event.is_directory:
                self._copy_file(event.dest_path,destination_backend,)
            return
        try:
            self.backing_store.move(source_backend,destination_backend,)
        except Exception as exc:
            print(f"[Sync] Move failed: {exc}")
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
def main(backing_store, mount_dir):
    global ACTIVE_BACKING_STORE, MOUNT_DIR
    MOUNT_DIR = mount_dir
    if os.name != "nt":
        raise RuntimeError("This program requires Windows.")
    if backing_store is None:
        raise ValueError("A backing store is required.")
    if ACTIVE_BACKING_STORE is not None:
        raise RuntimeError("A Cloud Files mirror is already running.")
    ACTIVE_BACKING_STORE = backing_store
    backing_store.initialize()
    os.makedirs(MOUNT_DIR, exist_ok=True)
    unregister_sync_root()
    if RESET_MOUNT:reset_mount_directory()
    os.makedirs(MOUNT_DIR, exist_ok=True)
    connection_key = None
    observer = None
    try:
        register_sync_root()
        create_initial_namespace(backing_store)
        connection_key = connect_sync_root()
        event_handler = MountSyncHandler(MOUNT_DIR,backing_store,)
        observer = Observer()
        observer.schedule(event_handler,MOUNT_DIR,recursive=True,)
        observer.start()
        while True:time.sleep(10)
    except KeyboardInterrupt:pass
    except Exception as exc:
        print()
        print("[!] FATAL ERROR:")
        print(f"    {exc}")
        print()
        raise
    finally:
        if observer is not None:
            try:
                observer.stop()
                observer.join()
            except Exception as exc:
                print(f"[!] Watchdog shutdown error: {exc}")
        if connection_key is not None:
            try:
                hr = cldapi.CfDisconnectSyncRoot(connection_key)
                if hr != 0:
                    print("[!] Disconnect failed: {hresult_hex(hr)}")
            except Exception as exc:
                print(f"[!] Disconnect error: {exc}")
        unregister_sync_root()
        ACTIVE_BACKING_STORE = None
if __name__ == "__main__":
    class LocalStorageBackend(BackingStore):
        def __init__(self, root_directory):
            self.root_directory = os.path.abspath(root_directory)
        def _full_path(self, relative_path):
            if not relative_path:
                return self.root_directory
            relative_path = relative_path.replace("/",os.sep,)
            full_path = os.path.abspath(os.path.join(self.root_directory,relative_path,))
            try:
                common = os.path.commonpath([self.root_directory,full_path,])
            except ValueError:
                raise ValueError(f"Invalid backing path: {relative_path!r}")
            if os.path.normcase(common) != os.path.normcase(self.root_directory):
                raise ValueError(f"Backing path escapes root: {relative_path!r}")
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
            if is_directory:shutil.rmtree(path,ignore_errors=True,)
            else:os.remove(path)
        def move(self,source_relative_path,destination_relative_path,):
            source_path = self._full_path(source_relative_path)
            destination_path = self._full_path(destination_relative_path)
            os.makedirs(os.path.dirname(destination_path),exist_ok=True,)
            if os.path.lexists(destination_path):
                if os.path.isdir(destination_path):shutil.rmtree(destination_path,ignore_errors=True,)
                else:os.remove(destination_path)
            shutil.move(source_path,destination_path,)
    main(LocalStorageBackend(".\\storage"),'.\\mount')
