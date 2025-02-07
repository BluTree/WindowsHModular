/*
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Copyright (c) Arvid Gerstmann. All rights reserved.
 */

/*
 * This are the macros from the original windows.h.
 * Defining them will prevent inclusion of this enormous header file.
 */
#ifndef _WINDOWS_
#define _WINDOWS_

#ifndef _INC_WINDOWS
#define _INC_WINDOWS

#ifndef WINDOWS_H
#define WINDOWS_H

/* ========================================================================== */
/* BASE                                                                       */
/* ========================================================================== */
#include "windows_base.h"



/* ========================================================================== */
/* Atomic                                                                     */
/* ========================================================================== */
#include "atomic.h"

/* ========================================================================== */
/* Encryption                                                                 */
/* ========================================================================== */
#include "crypt.h"

/* ========================================================================= */
/* DbgHelp                                                                   */
/* ========================================================================= */
#include "dbghelp.h"

/* ========================================================================= */
/* DDS                                                                       */
/* ========================================================================= */
#include "dds.h"

/* ========================================================================== */
/* File I/O                                                                   */
/* ========================================================================== */
#include "file.h"

/* ========================================================================== */
/* GDI                                                                        */
/* ========================================================================== */
#include "gdi.h"

/* ========================================================================== */
/* I/O                                                                        */
/* ========================================================================== */
#include "io.h"

/* ========================================================================== */
/* Misc                                                                       */
/* ========================================================================== */
#include "misc.h"

/* ========================================================================== */
/* Process                                                                    */
/* ========================================================================== */
#include "process.h"

/* ========================================================================== */
/* SysInfo                                                                    */
/* ========================================================================== */
#include "sysinfo.h"

/* ========================================================================== */
/* Threads                                                                    */
/* ========================================================================== */
#include "threads.h"

/* ========================================================================== */
/* Window                                                                     */
/* ========================================================================== */
#include "window.h"


#endif /* WINDOWS_H */
#endif /* _INC_WINDOWS */
#endif /* _WINDOWS_ */

