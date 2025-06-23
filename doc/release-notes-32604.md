Logging
-------
Unconditional logging to disk is now rate limited via `LogPrintf`, `LogInfo`,
`LogWarning, `LogError`, and the corresponding `LogPrintLevel` calls by giving
each source location a quota of 1MiB per hour. (#32604)

When `-logsourcelocations` is enabled, the log output now contains the entire
function signature instead of just the function name. (#32604)
