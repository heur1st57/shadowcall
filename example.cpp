#include "include/shadowcalls.hpp"

int main()
{
    LoadLibraryA("user32.dll");

    shadow::call ("user32.dll"_fnv1a64, "MessageBoxA"_fnv1a64, NULL, "123",  "123", MB_OK);
}