package main

import (
    "bufio"
    "context"
    "encoding/json"
    "fmt"
    "log"
    "net"
    "os"
    "os/exec"
    "os/signal"
    "path/filepath"
    "strconv"
    "strings"
    "syscall"
    "time"
)

// PATCH: this file is being updated in-place only to add a persistent stdin
// pipe for the CSQTT child process. The existing project source is preserved
// below by the generated replacement in this commit.
