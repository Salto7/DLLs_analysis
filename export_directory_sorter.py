import pefile

def list_and_sort_exports(module_path):
    # Load the module
    pe = pefile.PE(module_path)

    # Ensure the PE file has an export directory
    if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
        exports = []

        # Iterate over exported symbols
        for export in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            # Store the name and RVA of each function
            name = export.name.decode() if export.name else None
            rva = export.address
            exports.append((name, rva))

        # Sort the exports by RVA
        sorted_exports = sorted(exports, key=lambda x: x[1])

        # Print the sorted export functions
        for name, rva in sorted_exports:
            print(f"Function: {name}, RVA: {rva}")

    else:
        print("No exports found.")

# Example usage
module_path = 'C:\\Windows\\System32\\chakra.dll'
list_and_sort_exports(module_path)
