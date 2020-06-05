// detours-example.cpp : 이 파일에는 'main' 함수가 포함됩니다. 거기서 프로그램 실행이 시작되고 종료됩니다.
//

#include <iostream>
#include <Windows.h>
int main()
{
    while (true) {
        MessageBox(GetFocus(), L"Hello world!", L"detours-example", MB_OK);
        std::cout << "Enter to show messagebox:";
        std::cin.get();
        system("cls");
    }
}
