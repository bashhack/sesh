package syncfolder

import "syscall"

// sfDataless is SF_DATALESS (sys/stat.h): the file's data is kept by a
// sync tool (iCloud Drive, or another File Provider) until it's read.
const sfDataless = 0x40000000

func dataless(st *syscall.Stat_t) bool { return st.Flags&sfDataless != 0 }
