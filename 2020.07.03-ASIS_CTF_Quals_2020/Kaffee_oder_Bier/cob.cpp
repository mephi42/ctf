#include <iostream>
#include <unordered_map>

#define _BYTE unsigned char
#define _DWORD unsigned int
#define _QWORD unsigned long
#define __int64 long
#define __fastcall

std::unordered_map<__int64, __int64> sub_197A_cache;
__int64 __fastcall sub_197A(unsigned __int64 x)
{
  unsigned int v2; // [rsp+10h] [rbp-8h]
  int i; // [rsp+14h] [rbp-4h]

  auto it = sub_197A_cache.find(x);
  if (it != sub_197A_cache.end()) return it->second;

  v2 = 0;
  for ( i = 1; x > i; ++i )
  {
    if ( !(x % i) )
      v2 ^= 1u;
  }

  sub_197A_cache[x] = v2;

  return v2;
}


__int64 __fastcall sub_19C4(unsigned __int64 a1)
{
  int v1; // eax
  int v2; // er12
  int v3; // eax
  int v4; // ebx
  int v5; // eax
  int v6; // ebx
  int v7; // eax

  v1 = sub_197A(a1);
  v2 = sub_197A(2 * a1 + v1);
  v3 = sub_197A(a1);
  v4 = (unsigned __int64)sub_197A(3 * a1 + v3) * v2;
  v5 = sub_197A(a1);
  v6 = (unsigned __int64)sub_197A(4 * a1 + v5) * v4;
  v7 = sub_197A(a1);
  return v6 * (unsigned int)sub_197A(5 * a1 + v7);
}


__int64 __fastcall sub_1A80(unsigned __int64 a1)
{
  int v1; // eax
  int v2; // er12
  int v3; // eax
  int v4; // ebx
  int v5; // eax
  int v6; // ebx
  int v7; // eax
  int v8; // ebx

  v1 = sub_197A(a1);
  v2 = sub_197A(2 * a1 + v1);
  v3 = sub_197A(a1);
  v4 = v2 + (unsigned __int64)sub_197A(3 * a1 + v3);
  v5 = sub_197A(a1);
  v6 = (unsigned __int64)sub_197A(4 * a1 + v5) + v4;
  v7 = sub_197A(a1);
  v8 = (unsigned __int64)sub_197A(5 * a1 + v7) + v6;
  return v8 + (unsigned int)sub_19C4(a1);
}


__int64 __fastcall sub_1B46(__int64 x)
{
  int v1; // eax
  int v2; // ebx
  int v3; // eax
  int v4; // ebx
  int v5; // eax
  int v6; // ebx
  int v7; // eax
  int v8; // ebx

  v1 = sub_197A(x);
  v2 = 2 * (unsigned __int64)sub_197A(2 * x + v1);
  v3 = sub_197A(x);
  v4 = 3 * (unsigned __int64)sub_197A(3 * x + v3) + v2;
  v5 = sub_197A(x);
  v6 = 4 * (unsigned __int64)sub_197A(4 * x + v5) + v4;
  v7 = sub_197A(x);
  v8 = 5 * (unsigned __int64)sub_197A(5 * x + v7) + v6;
  return v8 + (unsigned int)sub_1A80(x);
}


__int64 __fastcall sub_1C1E(unsigned __int64 a1)
{
  int i; // [rsp+Ch] [rbp-Ch]
  __int64 v3; // [rsp+10h] [rbp-8h]

  v3 = 0LL;
  for ( i = 0; a1 > i; ++i )
    v3 += (int)sub_1B46(i);
  return v3;
}


__int64 __fastcall sub_1C63(__int64 a1)
{
  int i; // [rsp+8h] [rbp-10h]
  _BYTE v3[12]; // [rsp+Ch] [rbp-Ch]

  *(_DWORD *)&v3[8] = 0;
  *(_QWORD *)v3 = (unsigned int)sub_1C1E(a1);
  for ( i = 0; i < *(_DWORD *)v3; ++i )
    *(_QWORD *)&v3[4] += sub_1C1E(i);
  return *(_QWORD *)&v3[4];
}


__int64 __fastcall sub_1CB2(__int64 x)
{
  __int64 v1; // rbx
  int v2; // eax
  __int64 v3; // rbx
  int v4; // eax
  __int64 v5; // rbx
  int v6; // eax

  v1 = x * sub_1C63(x + 1);
  v2 = sub_1B46(x);
  v3 = sub_1C1E(v2 + x) + v1;
  v4 = sub_19C4(x);
  v5 = (int)sub_1B46(v4 + x) + v3;
  v6 = sub_197A(x);
  return v5 + (int)sub_19C4(v6 + x);
}

int main() {
  for (__int64 i = 0x20; i < 0x7f; i++) {
    std::cout << i << " " << sub_1CB2(i) << std::endl;
  }
}
