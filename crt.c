#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable: 4273)
#endif

#include "crt.h"

/************************************************************
 *                                                          *
 *                        MEMORY                            *
 *                                                          *
 ************************************************************/

void* __cdecl malloc(size_t _Size){
    return HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, _Size);
}

void* __cdecl calloc(size_t _Count, size_t _Size){
    return HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, _Size * _Count);
}

void* __cdecl realloc(void* _Block,  size_t _Size){
    return HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, _Block, _Size);
}

void __cdecl free(void* _Block){
    HeapFree(GetProcessHeap(), 0, _Block);
}

void* __cdecl memset(void* _Dst, int _Val, size_t _Size){
    unsigned char *p = (unsigned char *) _Dst;
    size_t Size = _Size;
    while (_Size > 0) {
        *p = (unsigned char) _Val;
        p++;
        Size--;
    }
    return _Dst;
}

void* __cdecl memcpy(void *_Dst, void const *_Src, size_t _Size) {
    unsigned char* dest = (PBYTE) _Dst;
    const unsigned char* src = (PBYTE) _Src;
    size_t n = _Size;
    while (n--)
        *dest++ = *src++;
    return _Dst;
}

void* __cdecl memmove(void* _Dst, void const* _Src, size_t _Size){
    unsigned char* d = (unsigned char*)_Dst;
    const unsigned char* s = (const unsigned char*)_Src;
    size_t n = _Size;
    if (d < s) {
        while (n--) {
            *d++ = *s++;
        }
    } else {
        d += n;
        s += n;
        while (n--) {
            *--d = *--s;
        }
    }
    return _Dst;
}


/************************************************************
 *                                                          *
 *                        STRING                            *
 *                                                          *
 ************************************************************/


size_t __cdecl strlen(char const* _Str) {
    char* string2;
    for (string2 = (char *)_Str; *string2; ++string2);
    return (string2 - _Str);
}

size_t __cdecl wcslen(wchar_t const *_String) {
    wchar_t* String;
    for (String = (wchar_t *)_String; *String; ++String);
    return (String - _String);
}

int __cdecl strcmp(char const* _Str1, char const* _Str2){
    char const* Str1 = _Str1;
    char const* Str2 = _Str2;
    for (; *Str1 == *Str2; Str1++, Str2++){
        if (*Str1 == '\0')
            return 0;
    }

    return ((*(char*)Str1 < *(char*)Str2) ? -1 : +1);
}

int __cdecl wcscmp(wchar_t const* _Str1, wchar_t const* _Str2){
    wchar_t const* Str1 = _Str1;
    wchar_t const* Str2 = _Str2;
    for (; *Str1 == *Str2; Str1++, Str2++){
        if (*Str1 == '\0')
            return 0;
    }
    return ((*(LPCWSTR)Str1 < *(LPCWSTR)Str2) ? -1 : +1);
}

char* __cdecl strcpy(char* _Destination, char const* _Source){
    char* Destination = _Destination;
    char const* Source = _Source;
    for(; *Source; Source++, Destination++)
        *Destination = *Source;
    *Destination = '\0';
    return _Destination;
}

wchar_t* __cdecl wcscpy(wchar_t* _Destination, wchar_t const* _Source){
    wchar_t* Destination = _Destination;
    wchar_t const* Source = _Source;
    for(; *Source; Source++, Destination++)
        *Destination = *Source;
    *Destination = '\0';
    return _Destination;
}

int __cdecl tolower(int _C) {
    if (_C >= 'A' && _C <= 'Z') {
        return _C + ('a' - 'A');
    }
    return _C;
}

wchar_t __cdecl tolowerW(wchar_t _C) {
    if (_C >= L'A' && _C <= L'Z') {
        return _C + (L'a' - L'A');
    }
    return _C;
}

int __cdecl stricmp(char const* _String1, char const* _String2){
    char const* String1 = _String1;
    char const* String2 = _String2;
    for (; tolower(*String1) == tolower(*String2); String1++, String2++){
        if (*String1 == '\0')
            return 0;
    }
    return ((tolower(*(char*)String1) < tolower(*(char*)String2)) ? -1 : +1);
}

int __cdecl wcsicmp(wchar_t const* _String1, wchar_t const* _String2){
    wchar_t const* String1 = _String1;
    wchar_t const* String2 = _String2;
    for (; tolowerW(*String1) == tolowerW(*String2); String1++, String2++){
        if (*String1 == '\0')
            return 0;
    }
    return ((tolowerW(*(char*)String1) < tolowerW(*(char*)String2)) ? -1 : +1);
}

char* __cdecl strcat(char* _Destination, char const* _Source){
    strcpy(&_Destination[strlen(_Destination)], _Source);
    return _Destination;
}

wchar_t* __cdecl wcscat(wchar_t* _Destination, wchar_t const* _Source){
    wcscpy(&_Destination[wcslen(_Destination)], _Source);
    return _Destination;
}

size_t __cdecl mbstowcs(wchar_t *_Dest, const char* _Source, size_t _MaxCount){
    int length = (int) _MaxCount;
    int i = 0;
    while (--length >= 0) {
        if (!(*_Dest++ = (unsigned char) *(_Source + i)))
            return _MaxCount - length - 1;
        i++;
    }
    return _MaxCount - length;
}

size_t wcstombs(char* _Destination, wchar_t const * _Source, size_t MaxCount){
    int Length = (int)MaxCount;
    while (--Length >= 0){
        if (!(*_Destination++ = *_Source++))
            return MaxCount - Length - 1;
    }
    return MaxCount - Length;
}

int __cdecl printf(char const *const format, ...) {
    char* buffer = calloc(1025, sizeof(char));
    va_list args;
    va_start(args, format);
    int length = wvsprintf(buffer, format, args);
    va_end(args);
    buffer[length] = '\0';
    DWORD done;
    WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), buffer, strlen(buffer), &done, NULL);
    free(buffer);
    return length;
}

#ifdef _MSC_VER
#pragma warning(pop)
#endif