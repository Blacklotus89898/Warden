# Pod OOMKilled (Exit Code 137)

Demo stand-in for the DaVinci runbook of the same path. The container went
past resources.limits.memory and the kernel killed it (OOMKilled, exit 137).
Compare the working set with the limit before and after the last deploy;
raise the limit in git, or find what holds the memory.
