# tarcannon

*Let the tar flow...*

Tarcannon is an HTTP file server.
Like a regular HTTP server, it serves all of the files in a directory tree.
*Unlike* a regular HTTP server, if a directory is requested, instead of returning index.html or an automatically generated index, it returns a *tar archive* of the requested directory.

The tar archive is generated on the fly.
On one hand, this means there are no temporary files on the server side.
On the other hand, it means the server can't tell the client when the download will be finished.
There is no good solution to this.
Moving on.

## Example
Suppose there is a directory full of music files in `/var/www/music/Billy Joel`.
Start the server:
```
> ./tarcannon.py --port 10080 --dir /var/www
```
Meanwhile in another terminal:
```
> curl http://localhost:10080/music/Billy%20Joel/ | tar x
```
This downloads the whole folder, saving it to `Billy Joel` in the current directory.

## Reverse Proxy
The intention is for the tarcannon mini-daemon to be combined with a reverse proxy like nginx.
Here's an example configuration.
This goes in a `server{}` block.
```
location /tarcannon/ {
    rewrite ^/tarcannon(.*)$ $1 break;
    proxy_pass http://127.0.0.1:10080;
}
```
This reverse proxies, for example, `https://your.host.name/tarcannon/music/Billy%20Joel/` to `http://localhost:10080/music/Billy%20Joel/`.
