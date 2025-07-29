import pefile
import os

def is_cfg_enabled(pe):
    CFG_FLAG = 0x4000  # Control Flow Guard flag in DllCharacteristics
    return (pe.OPTIONAL_HEADER.DllCharacteristics & CFG_FLAG) != 0

def has_exported_functions(pe):
    # Check if the DLL has an Export Directory
    return hasattr(pe, 'DIRECTORY_ENTRY_EXPORT') and pe.DIRECTORY_ENTRY_EXPORT.symbols

def check_dlls_in_system32():
    system32_path = os.path.join(os.environ.get("SystemRoot", "C:\\Windows"), "System32")
    no_cfg_dlls = []

    for filename in os.listdir(system32_path):
        if filename.lower().endswith(".dll"):
            dll_path = os.path.join(system32_path, filename)
            try:
                pe = pefile.PE(dll_path)
                if not is_cfg_enabled(pe) and has_exported_functions(pe):
                    print(dll_path)
            except Exception as e:
                print(f"Could not process {dll_path}: {e}")
    
    # Print DLLs without CFG enabled that have exported functions
    print("DLLs in System32 without CFG enabled and exporting functions:")
# Run the check
check_dlls_in_system32()
