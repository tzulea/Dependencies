#pragma once

#include <ph.h>

typedef struct _DN_API_SET_VALUE_ENTRY_REDIRECTION_V2
{
    ULONG NameOffset;
    USHORT NameLength;
    ULONG ValueOffset;
    USHORT ValueLength;
} DN_API_SET_VALUE_ENTRY_REDIRECTION_V2;

typedef struct _DN_API_SET_VALUE_ENTRY_V2
{
    ULONG NumberOfRedirections;
    DN_API_SET_VALUE_ENTRY_REDIRECTION_V2 Redirections[ANYSIZE_ARRAY];
} DN_API_SET_VALUE_ENTRY_V2;

typedef struct _DN_API_SET_NAMESPACE_ENTRY_V2
{
    ULONG NameOffset;
    ULONG NameLength;
    ULONG DataOffset;
} DN_API_SET_NAMESPACE_ENTRY_V2;

typedef struct _DN_API_SET_NAMESPACE_V2
{
    ULONG Version;
    ULONG Count;
    DN_API_SET_NAMESPACE_ENTRY_V2 Array[ANYSIZE_ARRAY];
} DN_API_SET_NAMESPACE_V2;

typedef struct _DN_API_SET_VALUE_ENTRY_REDIRECTION_V4
{
    ULONG Flags;
    ULONG NameOffset;
    ULONG NameLength;
    ULONG ValueOffset;
    ULONG ValueLength;
} DN_API_SET_VALUE_ENTRY_REDIRECTION_V4;

typedef struct _DN_API_SET_VALUE_ENTRY_V4
{
    ULONG Flags;
    ULONG NumberOfRedirections;
    DN_API_SET_VALUE_ENTRY_REDIRECTION_V4 Redirections[ANYSIZE_ARRAY];
} DN_API_SET_VALUE_ENTRY_V4;

typedef struct _DN_API_SET_NAMESPACE_ENTRY_V4
{
    ULONG Flags;
    ULONG NameOffset;
    ULONG NameLength;
    ULONG AliasOffset;
    ULONG AliasLength;
    ULONG DataOffset;
} DN_API_SET_NAMESPACE_ENTRY_V4;

typedef struct _DN_API_SET_NAMESPACE_V4
{
    ULONG Version;
    ULONG Size;
    ULONG Flags;
    ULONG Count;
    DN_API_SET_NAMESPACE_ENTRY_V4 Array[ANYSIZE_ARRAY];
} DN_API_SET_NAMESPACE_V4;

typedef struct _DN_API_SET_HASH_ENTRY_V6
{
    ULONG Hash;
    ULONG Index;
} DN_API_SET_HASH_ENTRY_V6;

typedef struct _DN_API_SET_NAMESPACE_ENTRY_V6
{
    ULONG Flags;
    ULONG NameOffset;
    ULONG NameLength;
    ULONG HashedLength;
    ULONG ValueOffset;
    ULONG ValueCount;
} DN_API_SET_NAMESPACE_ENTRY_V6;

typedef struct _DN_API_SET_VALUE_ENTRY_V6
{
    ULONG Flags;
    ULONG NameOffset;
    ULONG NameLength;
    ULONG ValueOffset;
    ULONG ValueLength;
} DN_API_SET_VALUE_ENTRY_V6;

typedef struct _DN_API_SET_NAMESPACE_V6
{
    ULONG Version;
    ULONG Size;
    ULONG Flags;
    ULONG Count;
    ULONG EntryOffset;
    ULONG HashOffset;
    ULONG HashFactor;
} DN_API_SET_NAMESPACE_V6;

typedef struct _DN_API_SET_NAMESPACE
{
    union
    {
        ULONG Version;
        DN_API_SET_NAMESPACE_V2 ApiSetNameSpaceV2;
        DN_API_SET_NAMESPACE_V4 ApiSetNameSpaceV4;
        DN_API_SET_NAMESPACE_V6 ApiSetNameSpaceV6;
    };
} DN_API_SET_NAMESPACE, *PDN_API_SET_NAMESPACE;