// TestApp.cpp : Diese Datei enthält die Funktion "main". Hier beginnt und endet die Ausführung des Programms.
//

#include <iostream>
#include <stdio.h>
#include <Windows.h>
#include <signal.h>
#include <tchar.h>

void intHandler(int dummy) {
    exit(0);
}


int __cdecl _tmain(int argc, TCHAR* argv[])
{
    std::cout << "Hello World!\n";

    TCHAR Path[MAX_PATH];
    HANDLE hFile;
    DWORD dwRet;

    printf("\n");
    if (argc != 2)
    {
        printf("ERROR:\tIncorrect number of arguments\n\n");
        printf("%s <file_name>\n", argv[0]);
        return 0;
    }

    hFile = CreateFile(argv[1],               // file to open
        GENERIC_READ,          // open for reading
        FILE_SHARE_READ,       // share for reading
        NULL,                  // default security
        OPEN_EXISTING,         // existing file only
        FILE_ATTRIBUTE_NORMAL, // normal file
        NULL);                 // no attr. template

    if (hFile == INVALID_HANDLE_VALUE)
    {
        printf("Could not open file (error %d\n)", GetLastError());
        return 0;
    }

    dwRet = GetFinalPathNameByHandle(hFile, Path, MAX_PATH, VOLUME_NAME_NT);
    if (dwRet < MAX_PATH)
    {
        _tprintf(TEXT("\nThe final path is: %s\n"), Path);
    }
    else printf("\nThe required buffer size is %d.\n", dwRet);

    CloseHandle(hFile);

    signal(SIGINT, intHandler);

    char buffer[20];

    while (true) {
        fgets(buffer, 20, stdin);

        Sleep(1000UL);
    }

    return 0;
}

// Programm ausführen: STRG+F5 oder Menüeintrag "Debuggen" > "Starten ohne Debuggen starten"
// Programm debuggen: F5 oder "Debuggen" > Menü "Debuggen starten"

// Tipps für den Einstieg: 
//   1. Verwenden Sie das Projektmappen-Explorer-Fenster zum Hinzufügen/Verwalten von Dateien.
//   2. Verwenden Sie das Team Explorer-Fenster zum Herstellen einer Verbindung mit der Quellcodeverwaltung.
//   3. Verwenden Sie das Ausgabefenster, um die Buildausgabe und andere Nachrichten anzuzeigen.
//   4. Verwenden Sie das Fenster "Fehlerliste", um Fehler anzuzeigen.
//   5. Wechseln Sie zu "Projekt" > "Neues Element hinzufügen", um neue Codedateien zu erstellen, bzw. zu "Projekt" > "Vorhandenes Element hinzufügen", um dem Projekt vorhandene Codedateien hinzuzufügen.
//   6. Um dieses Projekt später erneut zu öffnen, wechseln Sie zu "Datei" > "Öffnen" > "Projekt", und wählen Sie die SLN-Datei aus.
