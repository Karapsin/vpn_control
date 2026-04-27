#!/usr/bin/env python3
import argparse
import http.server
import os
import pathlib
import shutil
import socketserver
import sys
import urllib.parse


class ThreadingHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True


def main() -> int:
    parser = argparse.ArgumentParser(description="Serve a VM input file and receive one uploaded result file.")
    parser.add_argument("--bind", required=True)
    parser.add_argument("--port", required=True, type=int)
    parser.add_argument("--repo-zip", required=True)
    parser.add_argument("--upload-dir", required=True)
    parser.add_argument("--upload-name", default="windows-package-result.zip")
    args = parser.parse_args()

    repo_zip = pathlib.Path(args.repo_zip).resolve()
    upload_dir = pathlib.Path(args.upload_dir).resolve()
    upload_dir.mkdir(parents=True, exist_ok=True)
    upload_path = upload_dir / args.upload_name

    if not repo_zip.is_file():
        print(f"repo zip does not exist: {repo_zip}", file=sys.stderr)
        return 2

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, fmt: str, *fmt_args) -> None:
            print(f"[vm-file-bridge] {self.address_string()} - {fmt % fmt_args}", flush=True)

        def do_GET(self) -> None:
            parsed = urllib.parse.urlparse(self.path)
            if parsed.path != "/repo.zip":
                self.send_error(404)
                return
            self.send_response(200)
            self.send_header("Content-Type", "application/zip")
            self.send_header("Content-Length", str(repo_zip.stat().st_size))
            self.end_headers()
            with repo_zip.open("rb") as source:
                shutil.copyfileobj(source, self.wfile)

        def do_PUT(self) -> None:
            self._handle_upload()

        def do_POST(self) -> None:
            self._handle_upload()

        def _handle_upload(self) -> None:
            parsed = urllib.parse.urlparse(self.path)
            if parsed.path != f"/upload/{args.upload_name}":
                self.send_error(404)
                return
            length_raw = self.headers.get("Content-Length")
            if not length_raw:
                self.send_error(411)
                return
            remaining = int(length_raw)
            temp_path = upload_path.with_suffix(upload_path.suffix + ".tmp")
            with temp_path.open("wb") as target:
                while remaining > 0:
                    chunk = self.rfile.read(min(1024 * 1024, remaining))
                    if not chunk:
                        break
                    target.write(chunk)
                    remaining -= len(chunk)
            os.replace(temp_path, upload_path)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok\n")

    server = ThreadingHTTPServer((args.bind, args.port), Handler)
    print(f"[vm-file-bridge] serving {repo_zip} at http://{args.bind}:{args.port}/repo.zip", flush=True)
    print(f"[vm-file-bridge] accepting upload at /upload/{args.upload_name}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        return 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
