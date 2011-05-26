// Copyright 2010 The W32 Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package w32

import (
    "unsafe"
)

type (
    BOOL      int
    ATOM      uint16
    HANDLE    uintptr
    HINSTANCE HANDLE
    HACCEL    HANDLE
    HCURSOR   HANDLE
    HDWP      HANDLE
    HICON     HANDLE
    HMENU     HANDLE
    HWND      HANDLE
    HBRUSH    HANDLE
    HRESULT   uint32
    HFONT     HANDLE
    HDC       HANDLE
    HGDIOBJ   HANDLE
)

type POINT struct {
    X, Y int
}

type RECT struct {
    Left, Top, Right, Bottom int
}

type WNDCLASSEX struct {
    Size       uint
    Style      uint
    WndProc    uintptr
    ClsExtra   int
    WndExtra   int
    Instance   HINSTANCE
    Icon       HICON
    Cursor     HCURSOR
    Background HBRUSH
    MenuName   *uint16
    ClassName  *uint16
    IconSm     HICON
}

type MSG struct {
    Hwnd    HWND
    Message uint
    WParam  uintptr
    LParam  uintptr
    Time    uint
    Pt      POINT
}

type LOGFONT struct {
    Height         int
    Width          int
    Escapement     int
    Orientation    int
    Weight         int
    Italic         byte
    Underline      byte
    StrikeOut      byte
    CharSet        byte
    OutPrecision   byte
    ClipPrecision  byte
    Quality        byte
    PitchAndFamily byte
    FaceName       [LF_FACESIZE]uint16
}

type OPENFILENAME struct {
    StructSize      uint
    Owner           HWND
    Instance        HINSTANCE
    Filter          *uint16
    CustomFilter    *uint16
    MaxCustomFilter uint
    FilterIndex     uint
    File            *uint16
    MaxFile         uint
    FileTitle       *uint16
    MaxFileTitle    uint
    InitialDir      *uint16
    Title           *uint16
    Flags           uint
    FileOffset      uint16
    FileExtension   uint16
    DefExt          *uint16
    CustData        uintptr
    FnHook          uintptr
    TemplateName    *uint16
    PvReserved      unsafe.Pointer
    DwReserved      uint
    FlagsEx         uint
}

type BROWSEINFO struct {
    Owner        HWND
    Root         *uint16
    DisplayName  *uint16
    Title        *uint16
    Flags        uint
    CallbackFunc uintptr
    LParam       uintptr
    Image        int
}