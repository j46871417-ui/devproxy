import sys
from devproxy_pkg.ui import main

if __name__ == "__main__":
    if "--self-test" in sys.argv:
        from devproxy_pkg.ui import smoke_test
        smoke_test()
    elif "--launch-app" in sys.argv:
        from devproxy_pkg.core.agent_ipc import request_with_start
        from devproxy_pkg.core.shortcuts import app_command
        from tkinter import messagebox
        from devproxy_pkg.core.user_errors import describe_error
        try:
            index = sys.argv.index("--launch-app")
            app_id = sys.argv[index + 1]
            arguments = sys.argv[sys.argv.index("--") + 1:] if "--" in sys.argv else []
            request_with_start({"command": "launch", "app_id": app_id, "arguments": arguments}, app_command())
        except Exception as error:
            messagebox.showerror("Приложение не запущено", describe_error(error))
            sys.exit(1)
    else:
        main(background="--background" in sys.argv)
