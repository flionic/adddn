import threading

from adddn import fb_checker

# TODO: python flask runnable cmd

try:
    if True not in [i.isDaemon() for i in threading.enumerate()]:
        a = threading.Thread(target=fb_checker)
        a.setName('FbChecker')
        a.start()
except Exception as e:
    print(e)