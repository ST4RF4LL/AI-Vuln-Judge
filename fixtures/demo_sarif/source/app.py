import os


def run_admin_command(request):
    cmd = request.args["cmd"]
    os.system(cmd)
    return "ok"
