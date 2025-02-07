/*
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Copyright (c) Arvid Gerstmann. All rights reserved.
 */
#ifndef _WINDOWS_
#ifndef WINDOWS_HTTP_H
#define WINDOWS_HTTP_H

#include "windows_base.h"

/* Disable all warnings */
#if defined(_MSC_VER)
    #pragma warning(push, 0)
#endif
#if defined(__cplusplus)
extern "C" {
#endif

/* InternetOpen.dwAccessType Values: */
#define INTERNET_OPEN_TYPE_PRECONFIG                    0   // use registry configuration
#define INTERNET_OPEN_TYPE_DIRECT                       1   // direct to net
#define INTERNET_OPEN_TYPE_PROXY                        3   // via named proxy
#define INTERNET_OPEN_TYPE_PRECONFIG_WITH_NO_AUTOPROXY  4   // prevent using java/script/INS

/* InternetCrackUrl Flags: */
#define ICU_DECODE      0x10000000  // Convert %XX escape sequences to characters
#define ICU_ESCAPE      0x80000000  // (un)escape URL characters

/* Default Server Ports: */
#define INTERNET_INVALID_PORT_NUMBER    0           // use the protocol-specific default
#define INTERNET_DEFAULT_FTP_PORT       21          // default for FTP servers
#define INTERNET_DEFAULT_GOPHER_PORT    70          //    "     "  gopher "
#define INTERNET_DEFAULT_HTTP_PORT      80          //    "     "  HTTP   "
#define INTERNET_DEFAULT_HTTPS_PORT     443         //    "     "  HTTPS  "
#define INTERNET_DEFAULT_SOCKS_PORT     1080        // default for SOCKS firewall servers.

/* Internet Service Types: */
#define INTERNET_SERVICE_FTP    1
#define INTERNET_SERVICE_GOPHER 2
#define INTERNET_SERVICE_HTTP   3

/* WinINet flags: */
#define INTERNET_FLAG_IDN_DIRECT               0x00000001  // IDN enabled for direct connections
#define INTERNET_FLAG_IDN_PROXY                0x00000002  // IDN enabled for proxy
#define INTERNET_FLAG_RELOAD                   0x80000000  // retrieve the original item
#define INTERNET_FLAG_RAW_DATA                 0x40000000  // FTP/gopher find: receive the item as raw (structured) data
#define INTERNET_FLAG_EXISTING_CONNECT         0x20000000  // FTP: use existing InternetConnect handle for server if possible
#define INTERNET_FLAG_ASYNC                    0x10000000  // this request is asynchronous (where supported)
#define INTERNET_FLAG_PASSIVE                  0x08000000  // used for FTP connections
#define INTERNET_FLAG_NO_CACHE_WRITE           0x04000000  // don't write this item to the cache
#define INTERNET_FLAG_DONT_CACHE               INTERNET_FLAG_NO_CACHE_WRITE
#define INTERNET_FLAG_MAKE_PERSISTENT          0x02000000  // make this item persistent in cache
#define INTERNET_FLAG_FROM_CACHE               0x01000000  // use offline semantics
#define INTERNET_FLAG_OFFLINE                  INTERNET_FLAG_FROM_CACHE
#define INTERNET_FLAG_SECURE                   0x00800000  // use PCT/SSL if applicable (HTTP)
#define INTERNET_FLAG_KEEP_CONNECTION          0x00400000  // use keep-alive semantics
#define INTERNET_FLAG_NO_AUTO_REDIRECT         0x00200000  // don't handle redirections automatically
#define INTERNET_FLAG_READ_PREFETCH            0x00100000  // do background read prefetch
#define INTERNET_FLAG_NO_COOKIES               0x00080000  // no automatic cookie handling
#define INTERNET_FLAG_NO_AUTH                  0x00040000  // no automatic authentication handling
#define INTERNET_FLAG_RESTRICTED_ZONE          0x00020000  // apply restricted zone policies for cookies, auth
#define INTERNET_FLAG_CACHE_IF_NET_FAIL        0x00010000  // return cache file if net request fails
#define INTERNET_FLAG_IGNORE_REDIRECT_TO_HTTP  0x00008000 // ex: https:// to http://
#define INTERNET_FLAG_IGNORE_REDIRECT_TO_HTTPS 0x00004000 // ex: http:// to https://
#define INTERNET_FLAG_IGNORE_CERT_DATE_INVALID 0x00002000 // expired X509 Cert.
#define INTERNET_FLAG_IGNORE_CERT_CN_INVALID   0x00001000 // bad common name in X509 Cert.
#define INTERNET_FLAG_RESYNCHRONIZE            0x00000800  // asking wininet to update an item if it is newer
#define INTERNET_FLAG_HYPERLINK                0x00000400  // asking wininet to do hyperlinking semantic which works right for scripts
#define INTERNET_FLAG_NO_UI                    0x00000200  // no cookie popup
#define INTERNET_FLAG_PRAGMA_NOCACHE           0x00000100  // asking wininet to add "pragma: no-cache"
#define INTERNET_FLAG_CACHE_ASYNC              0x00000080  // ok to perform lazy cache-write
#define INTERNET_FLAG_FORMS_SUBMIT             0x00000040  // this is a forms submit
#define INTERNET_FLAG_FWD_BACK                 0x00000020  // fwd-back button op
#define INTERNET_FLAG_NEED_FILE                0x00000010  // need a file for this request
#define INTERNET_FLAG_MUST_CACHE_REQUEST       INTERNET_FLAG_NEED_FILE
#define INTERNET_FLAG_TRANSFER_ASCII           FTP_TRANSFER_TYPE_ASCII     // 0x00000001
#define INTERNET_FLAG_TRANSFER_BINARY          FTP_TRANSFER_TYPE_BINARY    // 0x00000002

#define SECURITY_INTERNET_MASK  (INTERNET_FLAG_IGNORE_CERT_CN_INVALID    |  \
                                 INTERNET_FLAG_IGNORE_CERT_DATE_INVALID  |  \
                                 INTERNET_FLAG_IGNORE_REDIRECT_TO_HTTPS  |  \
                                 INTERNET_FLAG_IGNORE_REDIRECT_TO_HTTP   )

#define SECURITY_IGNORE_ERROR_MASK  (INTERNET_FLAG_IGNORE_CERT_CN_INVALID   |  \
                                     INTERNET_FLAG_IGNORE_CERT_DATE_INVALID |  \
                                     SECURITY_FLAG_IGNORE_UNKNOWN_CA        |  \
                                     SECURITY_FLAG_IGNORE_REVOCATION        |  \
                                     SECURITY_FLAG_IGNORE_WEAK_SIGNATURE)

#define INTERNET_FLAGS_MASK     (INTERNET_FLAG_RELOAD               \
                                | INTERNET_FLAG_RAW_DATA            \
                                | INTERNET_FLAG_EXISTING_CONNECT    \
                                | INTERNET_FLAG_ASYNC               \
                                | INTERNET_FLAG_PASSIVE             \
                                | INTERNET_FLAG_NO_CACHE_WRITE      \
                                | INTERNET_FLAG_MAKE_PERSISTENT     \
                                | INTERNET_FLAG_FROM_CACHE          \
                                | INTERNET_FLAG_SECURE              \
                                | INTERNET_FLAG_KEEP_CONNECTION     \
                                | INTERNET_FLAG_NO_AUTO_REDIRECT    \
                                | INTERNET_FLAG_READ_PREFETCH       \
                                | INTERNET_FLAG_NO_COOKIES          \
                                | INTERNET_FLAG_NO_AUTH             \
                                | INTERNET_FLAG_CACHE_IF_NET_FAIL   \
                                | SECURITY_INTERNET_MASK            \
                                | INTERNET_FLAG_RESYNCHRONIZE       \
                                | INTERNET_FLAG_HYPERLINK           \
                                | INTERNET_FLAG_NO_UI               \
                                | INTERNET_FLAG_PRAGMA_NOCACHE      \
                                | INTERNET_FLAG_CACHE_ASYNC         \
                                | INTERNET_FLAG_FORMS_SUBMIT        \
                                | INTERNET_FLAG_NEED_FILE           \
                                | INTERNET_FLAG_RESTRICTED_ZONE     \
                                | INTERNET_FLAG_TRANSFER_BINARY     \
                                | INTERNET_FLAG_TRANSFER_ASCII      \
                                | INTERNET_FLAG_FWD_BACK            \
                                | INTERNET_FLAG_BGUPDATE            \
                                )


/* Query Info Flags: */
#define HTTP_QUERY_MIME_VERSION                 0
#define HTTP_QUERY_CONTENT_TYPE                 1
#define HTTP_QUERY_CONTENT_TRANSFER_ENCODING    2
#define HTTP_QUERY_CONTENT_ID                   3
#define HTTP_QUERY_CONTENT_DESCRIPTION          4
#define HTTP_QUERY_CONTENT_LENGTH               5
#define HTTP_QUERY_CONTENT_LANGUAGE             6
#define HTTP_QUERY_ALLOW                        7
#define HTTP_QUERY_PUBLIC                       8
#define HTTP_QUERY_DATE                         9
#define HTTP_QUERY_EXPIRES                      10
#define HTTP_QUERY_LAST_MODIFIED                11
#define HTTP_QUERY_MESSAGE_ID                   12
#define HTTP_QUERY_URI                          13
#define HTTP_QUERY_DERIVED_FROM                 14
#define HTTP_QUERY_COST                         15
#define HTTP_QUERY_LINK                         16
#define HTTP_QUERY_PRAGMA                       17
#define HTTP_QUERY_VERSION                      18  // special: part of status line
#define HTTP_QUERY_STATUS_CODE                  19  // special: part of status line
#define HTTP_QUERY_STATUS_TEXT                  20  // special: part of status line
#define HTTP_QUERY_RAW_HEADERS                  21  // special: all headers as ASCIIZ
#define HTTP_QUERY_RAW_HEADERS_CRLF             22  // special: all headers
#define HTTP_QUERY_CONNECTION                   23
#define HTTP_QUERY_ACCEPT                       24
#define HTTP_QUERY_ACCEPT_CHARSET               25
#define HTTP_QUERY_ACCEPT_ENCODING              26
#define HTTP_QUERY_ACCEPT_LANGUAGE              27
#define HTTP_QUERY_AUTHORIZATION                28
#define HTTP_QUERY_CONTENT_ENCODING             29
#define HTTP_QUERY_FORWARDED                    30
#define HTTP_QUERY_FROM                         31
#define HTTP_QUERY_IF_MODIFIED_SINCE            32
#define HTTP_QUERY_LOCATION                     33
#define HTTP_QUERY_ORIG_URI                     34
#define HTTP_QUERY_REFERER                      35
#define HTTP_QUERY_RETRY_AFTER                  36
#define HTTP_QUERY_SERVER                       37
#define HTTP_QUERY_TITLE                        38
#define HTTP_QUERY_USER_AGENT                   39
#define HTTP_QUERY_WWW_AUTHENTICATE             40
#define HTTP_QUERY_PROXY_AUTHENTICATE           41
#define HTTP_QUERY_ACCEPT_RANGES                42
#define HTTP_QUERY_SET_COOKIE                   43
#define HTTP_QUERY_COOKIE                       44
#define HTTP_QUERY_REQUEST_METHOD               45  // special: GET/POST etc.
#define HTTP_QUERY_REFRESH                      46
#define HTTP_QUERY_CONTENT_DISPOSITION          47

/* HTTP 1.1 Query Info Flags: */
#define HTTP_QUERY_AGE                          48
#define HTTP_QUERY_CACHE_CONTROL                49
#define HTTP_QUERY_CONTENT_BASE                 50
#define HTTP_QUERY_CONTENT_LOCATION             51
#define HTTP_QUERY_CONTENT_MD5                  52
#define HTTP_QUERY_CONTENT_RANGE                53
#define HTTP_QUERY_ETAG                         54
#define HTTP_QUERY_HOST                         55
#define HTTP_QUERY_IF_MATCH                     56
#define HTTP_QUERY_IF_NONE_MATCH                57
#define HTTP_QUERY_IF_RANGE                     58
#define HTTP_QUERY_IF_UNMODIFIED_SINCE          59
#define HTTP_QUERY_MAX_FORWARDS                 60
#define HTTP_QUERY_PROXY_AUTHORIZATION          61
#define HTTP_QUERY_RANGE                        62
#define HTTP_QUERY_TRANSFER_ENCODING            63
#define HTTP_QUERY_UPGRADE                      64
#define HTTP_QUERY_VARY                         65
#define HTTP_QUERY_VIA                          66
#define HTTP_QUERY_WARNING                      67
#define HTTP_QUERY_EXPECT                       68
#define HTTP_QUERY_PROXY_CONNECTION             69
#define HTTP_QUERY_UNLESS_MODIFIED_SINCE        70
#define HTTP_QUERY_ECHO_REQUEST                 71
#define HTTP_QUERY_ECHO_REPLY                   72
#define HTTP_QUERY_ECHO_HEADERS                 73
#define HTTP_QUERY_ECHO_HEADERS_CRLF            74
#define HTTP_QUERY_PROXY_SUPPORT                75
#define HTTP_QUERY_AUTHENTICATION_INFO          76
#define HTTP_QUERY_PASSPORT_URLS                77
#define HTTP_QUERY_PASSPORT_CONFIG              78
#define HTTP_QUERY_X_CONTENT_TYPE_OPTIONS       79
#define HTTP_QUERY_P3P                          80
#define HTTP_QUERY_X_P2P_PEERDIST               81
#define HTTP_QUERY_TRANSLATE                    82
#define HTTP_QUERY_X_UA_COMPATIBLE              83
#define HTTP_QUERY_DEFAULT_STYLE                84
#define HTTP_QUERY_X_FRAME_OPTIONS              85
#define HTTP_QUERY_X_XSS_PROTECTION             86
#define HTTP_QUERY_SET_COOKIE2                  87
#define HTTP_QUERY_DO_NOT_TRACK                 88
#define HTTP_QUERY_KEEP_ALIVE                   89
#define HTTP_QUERY_HTTP2_SETTINGS               90
#define HTTP_QUERY_STRICT_TRANSPORT_SECURITY    91
#define HTTP_QUERY_TOKEN_BINDING                92
#define HTTP_QUERY_INCLUDE_REFERRED_TOKEN_BINDING_ID  93
#define HTTP_QUERY_INCLUDE_REFERER_TOKEN_BINDING_ID   HTTP_QUERY_INCLUDE_REFERRED_TOKEN_BINDING_ID
#define HTTP_QUERY_PUBLIC_KEY_PINS              94
#define HTTP_QUERY_PUBLIC_KEY_PINS_REPORT_ONLY  95

typedef LPVOID HINTERNET;
typedef HINTERNET * LPHINTERNET;

typedef WORD INTERNET_PORT;
typedef INTERNET_PORT * LPINTERNET_PORT;

/* ========================================================================== */
/* Enums: */
typedef enum {
    INTERNET_SCHEME_PARTIAL = -2,
    INTERNET_SCHEME_UNKNOWN = -1,
    INTERNET_SCHEME_DEFAULT = 0,
    INTERNET_SCHEME_FTP,
    INTERNET_SCHEME_GOPHER,
    INTERNET_SCHEME_HTTP,
    INTERNET_SCHEME_HTTPS,
    INTERNET_SCHEME_FILE,
    INTERNET_SCHEME_NEWS,
    INTERNET_SCHEME_MAILTO,
    INTERNET_SCHEME_SOCKS,
    INTERNET_SCHEME_JAVASCRIPT,
    INTERNET_SCHEME_VBSCRIPT,
    INTERNET_SCHEME_RES,
    INTERNET_SCHEME_FIRST = INTERNET_SCHEME_FTP,
    INTERNET_SCHEME_LAST = INTERNET_SCHEME_RES
} INTERNET_SCHEME, * LPINTERNET_SCHEME;

/* ========================================================================== */
/* Structures: */
typedef struct {
    DWORD   dwStructSize;       // size of this structure. Used in version check
    LPWSTR  lpszScheme;         // pointer to scheme name
    DWORD   dwSchemeLength;     // length of scheme name
    INTERNET_SCHEME nScheme;    // enumerated scheme type (if known)
    LPWSTR  lpszHostName;       // pointer to host name
    DWORD   dwHostNameLength;   // length of host name
    INTERNET_PORT nPort;        // converted port number
    LPWSTR  lpszUserName;       // pointer to user name
    DWORD   dwUserNameLength;   // length of user name
    LPWSTR  lpszPassword;       // pointer to password
    DWORD   dwPasswordLength;   // length of password
    LPWSTR  lpszUrlPath;        // pointer to URL-path
    DWORD   dwUrlPathLength;    // length of URL-path
    LPWSTR  lpszExtraInfo;      // pointer to extra information (e.g. ?foo or #foo)
    DWORD   dwExtraInfoLength;  // length of extra information
} URL_COMPONENTSW, * LPURL_COMPONENTSW;

typedef struct _INTERNET_BUFFERSW {
    DWORD dwStructSize;                 // used for API versioning. Set to sizeof(INTERNET_BUFFERS)
    struct _INTERNET_BUFFERSW * Next;   // chain of buffers
    LPCWSTR  lpcszHeader;               // pointer to headers (may be NULL)
    DWORD dwHeadersLength;              // length of headers if not NULL
    DWORD dwHeadersTotal;               // size of headers if not enough buffer
    LPVOID lpvBuffer;                   // pointer to data buffer (may be NULL)
    DWORD dwBufferLength;               // length of data buffer if not NULL
    DWORD dwBufferTotal;                // total size of chunk, or content-length if not chunked
    DWORD dwOffsetLow;                  // used for read-ranges (only used in HttpSendRequest2)
    DWORD dwOffsetHigh;
} INTERNET_BUFFERSW, * LPINTERNET_BUFFERSW;

/* ========================================================================= */
/* Functions                                                                 */
BOOL WINAPI InternetCloseHandle(
    HINTERNET hInternet
    );

HINTERNET WINAPI InternetOpenW(
    LPCWSTR lpszAgent,
    DWORD dwAccessType,
    LPCWSTR lpszProxy,
    LPCWSTR lpszProxyBypass,
    DWORD dwFlags
    );

BOOL WINAPI InternetCrackUrlW(
    LPCWSTR lpszUrl,
    DWORD dwUrlLength,
    DWORD dwFlags,
    LPURL_COMPONENTSW lpUrlComponents
    );

HINTERNET WINAPI InternetConnectW(
    HINTERNET hInternet,
    LPCWSTR lpszServerName,
    INTERNET_PORT nServerPort,
    LPCWSTR lpszUserName,
    LPCWSTR lpszPassword,
    DWORD dwService,
    DWORD dwFlags,
    DWORD_PTR dwContext
    );

HINTERNET WINAPI HttpOpenRequestW(
    HINTERNET hConnect,
    LPCWSTR lpszVerb,
    LPCWSTR lpszObjectName,
    LPCWSTR lpszVersion,
    LPCWSTR lpszReferrer,
    LPCWSTR * lplpszAcceptTypes,
    DWORD dwFlags,
    DWORD_PTR dwContext
    );

BOOL WINAPI HttpSendRequestW(
    HINTERNET hRequest,
    LPCWSTR lpszHeaders,
    DWORD dwHeadersLength,
    LPVOID lpOptional,
    DWORD dwOptionalLength
    );

BOOL WINAPI HttpQueryInfoW(
    HINTERNET hRequest,
    DWORD dwInfoLevel,
    LPVOID lpBuffer,
    LPDWORD lpdwBufferLength,
    LPDWORD lpdwIndex
    );

BOOL WINAPI HttpEndRequestW(
    HINTERNET           hRequest,
    LPINTERNET_BUFFERSW lpBuffersOut,
    DWORD               dwFlags,
    DWORD_PTR           dwContext
);

BOOL WINAPI InternetQueryDataAvailable(
    HINTERNET hFile,
    LPDWORD lpdwNumberOfBytesAvailable,
    DWORD dwFlags,
    DWORD_PTR dwContext
    );

BOOL WINAPI InternetReadFile(
    HINTERNET hFile,
    LPVOID lpBuffer,
    DWORD dwNumberOfBytesToRead,
    LPDWORD lpdwNumberOfBytesRead
    );

#if defined(__cplusplus)
}
#endif
/* Enable all warnings */
#if defined(_MSC_VER)
    #pragma warning(pop)
#endif

#endif /* WINDOWS_HTTP_H */
#endif /* _WINDOWS_ */
