"""Windows application catalog; all adapters share the same routing core."""
from .base import ApplicationAdapter


def extra_adapters():
    specs = [
        ("vscode-insiders", "VS Code Insiders", ["Code - Insiders"], ["Microsoft VS Code Insiders"], True, []),
        ("visualstudio", "Visual Studio", ["devenv"], [], False, ["Microsoft Visual Studio/*/*/Common7/IDE/devenv.exe"]),
        ("idea", "IntelliJ IDEA", ["idea64", "idea"], [], False, ["JetBrains/IntelliJ IDEA*/bin/idea64.exe"]),
        ("pycharm", "PyCharm", ["pycharm64", "pycharm"], [], False, ["JetBrains/PyCharm*/bin/pycharm64.exe"]),
        ("webstorm", "WebStorm", ["webstorm64", "webstorm"], [], False, ["JetBrains/WebStorm*/bin/webstorm64.exe"]),
        ("rider", "JetBrains Rider", ["rider64", "rider"], [], False, ["JetBrains/JetBrains Rider*/bin/rider64.exe", "JetBrains/Rider*/bin/rider64.exe"]),
        ("goland", "GoLand", ["goland64", "goland"], [], False, ["JetBrains/GoLand*/bin/goland64.exe"]),
        ("clion", "CLion", ["clion64", "clion"], [], False, ["JetBrains/CLion*/bin/clion64.exe"]),
        ("phpstorm", "PhpStorm", ["phpstorm64", "phpstorm"], [], False, ["JetBrains/PhpStorm*/bin/phpstorm64.exe"]),
        ("rubymine", "RubyMine", ["rubymine64", "rubymine"], [], False, ["JetBrains/RubyMine*/bin/rubymine64.exe"]),
        ("datagrip", "DataGrip", ["datagrip64", "datagrip"], [], False, ["JetBrains/DataGrip*/bin/datagrip64.exe"]),
        ("rustrover", "RustRover", ["rustrover64", "rustrover"], [], False, ["JetBrains/RustRover*/bin/rustrover64.exe"]),
        ("fleet", "JetBrains Fleet", ["Fleet"], ["JetBrains/Fleet"], False, []),
        ("androidstudio", "Android Studio", ["studio64"], ["Android/Android Studio/bin"], False, []),
        ("zed", "Zed", ["zed"], ["Zed"], False, []),
        ("sublime", "Sublime Text", ["sublime_text"], ["Sublime Text", "Sublime Text 3"], False, []),
        ("notepadpp", "Notepad++", ["notepad++"], ["Notepad++"], False, []),
        ("claude", "Claude Code", ["claude"], [], False, []),
        ("git", "Git", ["git"], ["Git/cmd", "Git/bin"], False, []),
    ]
    result = []
    for app_id, label, names, folders, electron, patterns in specs:
        adapter = ApplicationAdapter(app_id, label, names, folders, electron)
        adapter.path_patterns = patterns
        result.append(adapter)
    return result
