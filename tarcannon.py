#!/usr/bin/env python3
import argparse
import base64
import functools
import http
import http.server
import logging
import pathlib
import socket
import sys
import tarfile
import typing
import urllib.parse

logger = logging.getLogger(__name__)

type AuthPredicate = typing.Callable[[str], bool]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description='Serve a directory as a tarball. Only supports HTTP/1.0. Does not support HTTPS.')
    parser.add_argument(
        '-d', '--dir', metavar='<path>', type=pathlib.Path, default='.',
        help='Base directory to serve, default CWD')
    parser.add_argument(
        '-b', '--bind', metavar='<host-or-address>', default='0.0.0.0',
        help="Hostname or address to bind, default is 0.0.0.0 ('any')")
    parser.add_argument(
        '-o', '--port', metavar='<port>', type=int, default=80,
        help='Bind port, default 80')
    parser.add_argument(
        '-u', '--username', metavar='<username>', default='user',
        help="Username for auth, default 'user'")
    parser.add_argument(
        '-p', '--password', metavar='<path>', type=pathlib.Path,
        help="Path to password file (do not serve this in the -d directory). "
             "Default no password.")
    parser.add_argument(
        '-l', '--log-level', metavar='<1-60>', type=int, default=logging.INFO,
        help='Logging level, 1=verbose, 60=none, default=20')
    return parser.parse_args()


def load_auth(
    username: str | None, password_path: pathlib.Path | None, serve_path: pathlib.Path,
) -> AuthPredicate | None:
    if password_path is None:
        return None
    if serve_path in password_path.parents:
        raise PermissionError('Not serving directory that contains the password file')

    secret = (username + ':').encode() + password_path.read_bytes()
    header = 'Basic ' + base64.b64encode(secret).decode()
    return header.__eq__


def stream(path: pathlib.Path, wfile: typing.BinaryIO) -> None:
    tar_log = max(0, min(3, int(4.5 - 0.1*logger.root.level)))

    # https://docs.python.org/3/library/tarfile.html#tarfile.open
    # w| means uncompressed block stream with no random access allowed.
    with tarfile.open(
        fileobj=wfile, mode='w|', format=tarfile.PAX_FORMAT, stream=True, debug=tar_log,
    ) as tar:
        tar.add(name=path, arcname=path.name)
        logger.info('%d members, %d inodes, %d MiB',
                    len(tar.members), len(tar.inodes), tar.offset//0x100000)
    # Don't close wfile: handle_one_request() is going to flush() it


class Handler(http.server.BaseHTTPRequestHandler):
    def __init__(
        self,
        # Base args
        request: socket.socket, client_address: tuple[str, int], server: http.server.ThreadingHTTPServer,
        # Our args
        serve_path: pathlib.Path, auth: AuthPredicate | None,
    ) -> None:
        # https://docs.python.org/3/library/http.server.html#http.server.BaseHTTPRequestHandler.protocol_version
        # Because we don't know Content-Length, use /1.0 rather than /1.1.
        self.protocol_version = 'HTTP/1.0'
        self.serve_path = serve_path
        self.auth = auth
        super().__init__(request, client_address, server)

    def send_response(self, code, message = None):
        """
        Unconditional headers need to go here. Stupidly, send_error() injects the response string
        into the header buffer regardless of whether there's already content there.
        """
        super().send_response(code, message)
        # Security hole: basic authentication is vulnerable to interception since we don't have HTTPS
        # If you care, use CHAP instead.
        self.send_header('WWW-Authenticate', 'Basic realm="tarcannon", charset="UTF-8"')

    def do_GET(self) -> None:
        if self.auth is not None:
            auth = self.headers.get('Authorization')
            if auth is None or not self.auth(auth):
                self.send_error(http.HTTPStatus.UNAUTHORIZED)
                return

        path = self.serve_path / urllib.parse.unquote(self.path).strip('/')
        if not path.is_dir():
            self.send_error(http.HTTPStatus.NOT_FOUND)
            return
        mangled = path.name + '.tar'
        logger.info('Streaming %s to %s', path, mangled)

        self.send_response(http.HTTPStatus.OK)
        # There is no official MIME type for tar. Pick one anyway.
        self.send_header('Content-Type', 'application/tar')
        self.send_header('Content-Disposition', f'attachment; filename="{mangled}"')
        self.end_headers()
        stream(path, self.wfile)


def main() -> None:
    args = parse_args()
    handler = logging.StreamHandler()
    logger.root.setLevel(args.log_level)
    logger.root.addHandler(handler)

    if not args.dir.is_dir():
        raise FileNotFoundError('Serve directory does not exist')
    auth = load_auth(args.username, args.password, args.dir)

    logger.info('listening on %s:%d', args.bind, args.port)

    # Security hole: this is not HTTPS; it isn't guarded against interception.
    with http.server.ThreadingHTTPServer(
        server_address=(args.bind, args.port), bind_and_activate=True,
        RequestHandlerClass=functools.partial(Handler, serve_path=args.dir, auth=auth),
    ) as server:
        server.serve_forever()


if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        print(e, file=sys.stderr)
        exit(1)
    except KeyboardInterrupt:
        pass
