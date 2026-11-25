# Pod Stuck in CrashLoopBackOff

Demo stand-in for the DaVinci runbook of the same path. Read the previous
container's logs and its last terminated reason (OOMKilled, Error) before
restarting anything: the crash is in the instance that died.
