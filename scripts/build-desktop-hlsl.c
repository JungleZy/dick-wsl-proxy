#define COBJMACROS
#include <windows.h>
#include <d3dcompiler.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

static char *utf8(const wchar_t *value) {
    int size = WideCharToMultiByte(CP_UTF8, 0, value, -1, NULL, 0, NULL, NULL);
    char *result = malloc(size);
    if (!result || !WideCharToMultiByte(CP_UTF8, 0, value, -1, result, size, NULL, NULL)) exit(2);
    return result;
}

int wmain(int argc, wchar_t **argv) {
    const wchar_t *source = NULL, *output = NULL, *entry = NULL, *profile = NULL, *name = NULL;
    for (int i = 1; i < argc; ++i) {
        if (!wcscmp(argv[i], L"/T") && i + 1 < argc) profile = argv[++i];
        else if (!wcscmp(argv[i], L"/E") && i + 1 < argc) entry = argv[++i];
        else if (!wcscmp(argv[i], L"/Fh") && i + 1 < argc) output = argv[++i];
        else if (!wcscmp(argv[i], L"/Vn") && i + 1 < argc) name = argv[++i];
        else if (!wcscmp(argv[i], L"/O3")) {}
        else if (i == argc - 1) source = argv[i];
        else { fwprintf(stderr, L"Unsupported compiler argument: %ls\n", argv[i]); return 2; }
    }
    if (!source || !output || !entry || !profile || !name) {
        fputs("HLSL bridge requires /T profile /E entry /Fh output /Vn symbol /O3 source\n", stderr);
        return 2;
    }
    char *entry_utf8 = utf8(entry), *profile_utf8 = utf8(profile), *name_utf8 = utf8(name);
    ID3DBlob *shader = NULL, *errors = NULL;
    HRESULT result = D3DCompileFromFile(source, NULL, D3D_COMPILE_STANDARD_FILE_INCLUDE,
        entry_utf8, profile_utf8, D3DCOMPILE_OPTIMIZATION_LEVEL3, 0, &shader, &errors);
    if (errors) {
        fwrite(ID3D10Blob_GetBufferPointer(errors), 1, ID3D10Blob_GetBufferSize(errors), stderr);
        ID3D10Blob_Release(errors);
    }
    free(entry_utf8); free(profile_utf8);
    if (FAILED(result)) { fprintf(stderr, "D3DCompileFromFile failed: 0x%08lx\n", (unsigned long)result); free(name_utf8); return 1; }
    FILE *file = _wfopen(output, L"wb");
    if (!file) { perror("shader header"); ID3D10Blob_Release(shader); free(name_utf8); return 1; }
    const unsigned char *bytes = ID3D10Blob_GetBufferPointer(shader);
    size_t length = ID3D10Blob_GetBufferSize(shader);
    fprintf(file, "const BYTE %s[] = {\n", name_utf8);
    for (size_t i = 0; i < length; ++i) fprintf(file, "%u,%s", bytes[i], i % 16 == 15 ? "\n" : " ");
    fputs("\n};\n", file);
    int failed = ferror(file);
    if (fclose(file)) failed = 1;
    ID3D10Blob_Release(shader); free(name_utf8);
    return failed ? 1 : 0;
}
