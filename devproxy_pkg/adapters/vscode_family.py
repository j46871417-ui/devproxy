from .base import ApplicationAdapter


class VSCodeFamilyAdapter(ApplicationAdapter):
    def __init__(self, app_id, display_name, folder_name, bin_names, install_folders=()):
        super().__init__(app_id, display_name, bin_names, install_folders or (folder_name, display_name),
                         electron=True, config_folder=folder_name)


class VSCodeAdapter(VSCodeFamilyAdapter):
    def __init__(self):
        super().__init__("vscode", "Visual Studio Code", "Code", ["Code", "code"],
                         ["Microsoft VS Code", "Microsoft VS Code Insiders"])


class CursorAdapter(VSCodeFamilyAdapter):
    def __init__(self):
        super().__init__("cursor", "Cursor", "Cursor", ["Cursor", "cursor"])


class WindsurfAdapter(VSCodeFamilyAdapter):
    def __init__(self):
        super().__init__("windsurf", "Windsurf", "Windsurf", ["Windsurf", "windsurf"])


class VSCodiumAdapter(VSCodeFamilyAdapter):
    def __init__(self):
        super().__init__("vscodium", "VSCodium", "VSCodium", ["VSCodium", "codium"])
