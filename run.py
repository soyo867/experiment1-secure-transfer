"""SecureBridge GUI and server entry point."""
import argparse
import sys
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description="SecureBridge — 实验 1B 安全文件传输")
    sub = parser.add_subparsers(dest="command")
    gui = sub.add_parser("gui",help="启动图形化客户端")
    gui.add_argument("--profile",default=str(Path(__file__).parent/"runtime/alice.json"))
    server = sub.add_parser("server",help="启动安全文件服务器")
    server.add_argument("--config",required=True)
    args = parser.parse_args()
    if args.command == "server":
        from securetransfer.server import main as server_main
        return server_main(["--config",args.config])
    from securetransfer.gui import launch
    launch(args.profile if args.command == "gui" else None)
    return 0


if __name__ == "__main__":
    if hasattr(sys.stdout,"reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    raise SystemExit(main())
