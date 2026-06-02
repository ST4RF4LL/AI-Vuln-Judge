# Demo Application Threat Model

`app.py` exposes an administrative command endpoint. The command handler is a
high-risk module because it can access host process privileges and customer
maintenance data.
