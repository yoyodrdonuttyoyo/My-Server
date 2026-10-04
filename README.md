# Loop Server

This Python backend is only needed when deploying a shared Loop server. It does not run as part of the Windows client. The client itself is the standalone C# `Loop.exe` in the parent folder.

Deploy this folder as a Docker web service with persistent storage mounted at `/var/data`. The supplied `Dockerfile` and `render.yaml` configure the service and its SQLite database/uploads. The Render blueprint requests a persistent disk, which may have a hosting charge; check current provider pricing before deploying. After deployment, copy the HTTPS service address provided by your backend host (not a separate website's URL) into Loop's **Loop Chat Backend URL** field.

Vercel serverless functions cannot keep the Socket.IO connections needed for live chat. Use a host that supports long-lived WebSocket/polling connections, HTTPS, and persistent storage. Once deployed, enter its `https://...` address on Loop's sign-in screen.

Messages and uploaded files are stored on the server and are not end-to-end encrypted. The starter SQLite deployment is intended for a small private community, not large-scale public traffic.